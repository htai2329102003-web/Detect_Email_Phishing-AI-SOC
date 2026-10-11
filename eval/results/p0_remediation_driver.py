"""P0 verification artifact: frozen DEV only, real local graph/IOC, no providers."""
# Standalone execution bootstraps the project path before project imports.
# ruff: noqa: E402

import argparse
import asyncio
import json
import sys
from collections import Counter
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT))

from eval.manifest import ManifestEntry
from eval.metrics import LABEL_POLICY, ratio, summarize
from eval.results.dev_baseline_driver import EXCLUDED, MeasuredIOC, ProductionTarget, sha, snapshot
from eval.run_eval import evaluate_case
from eval.schemas import EvalCase
from src.config import get_settings
from src.parsers.email_parser import EmailParseError, parse_email

ROOT = PROJECT / "data"
OUTPUT = PROJECT / "eval/results"
BUG_IDS = {"e2a_458bb17c", "e2a_804f8eff", "e2a_f41fa76e"}
MIME_IDS = {"e2a_04809eff", "e2a_77e5a36b"}


def save(name, value):
    (OUTPUT / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def source_hashes():
    return {str(p.relative_to(PROJECT)): sha(p) for folder in ("src", "config", "eval")
            for p in (PROJECT / folder).rglob("*")
            if p.suffix in {".py", ".yaml"} and "__pycache__" not in p.parts
            and ("results" not in p.parts or p.name.endswith("driver.py"))}


def inputs():
    baseline = json.loads((OUTPUT / "dev_baseline.json").read_text(encoding="utf-8"))
    rows = [json.loads(line) for line in (ROOT / "manifests/dev_manifest.jsonl").read_text(encoding="utf-8-sig").splitlines()
            if line.strip()]
    assert len(rows) == 3462 and Counter(r["expected_label"] for r in rows) == {"SAFE": 2750, "PHISHING": 712}
    assert EXCLUDED <= {r["id"] for r in rows}
    entries = {}
    for line, row in enumerate(rows, 1):
        if row["id"] in EXCLUDED:
            continue  # Do not attempt to read quarantined samples.
        path = (ROOT / row["file"]).resolve()
        assert path.is_relative_to(ROOT) and path.is_file(), row["id"]
        adapted = dict(row)
        adapted["capabilities"] = row.get("capabilities") or ["core"]
        case = EvalCase.model_validate(adapted)
        assert not case.profile and not case.injection and not case.ioc_records
        entries[case.id] = ManifestEntry(line, case.id, case=case)
    assert len(entries) == 3458
    old_failures = {r["case_id"] for r in baseline["cases"] if r["status"] == "failed"}
    assert len(old_failures) == 150 and old_failures <= entries.keys()
    malicious = {sid for sid, detail in baseline["safe_evidence"].items()
                 if any(e["type"] == "IOC_MATCH" and e["result"] == "FAIL" for e in detail["evidence"])}
    assert len(malicious) == 47
    return entries, old_failures, malicious


def recovery(entries, old_failures):
    recovered, failed = [], []
    for sid in sorted(old_failures):
        try:
            raw = (ROOT / entries[sid].case.file).read_bytes()
            parsed = parse_email(raw).raw_for_analyzers
            assert parsed["raw_bytes"] == raw
            assert parsed["partial_parse"] and parsed["parser_warnings"]
            recovered.append({"id": sid, "warnings": parsed["parser_warnings"],
                              "unavailable_headers": parsed["unavailable_headers"]})
        except EmailParseError as exc:
            failed.append({"id": sid, "code": exc.code})
    report = {"previous_failures": 150, "recovered": len(recovered), "remaining": len(failed),
              "robustness_fixed": len(BUG_IDS & {r["id"] for r in recovered}),
              "genuine_mime_rejections": len(MIME_IDS & {r["id"] for r in failed}),
              "cases": recovered, "failures": failed}
    report["passed"] = len(recovered) == 148 and {r["id"] for r in failed} == MIME_IDS
    return report


class P0Target(ProductionTarget):
    async def analyze(self, raw, case):
        observation = await super().analyze(raw, case)
        risk = observation.state["risk_result"]
        self.details[case.id].update({"coverage": risk.coverage.model_dump(mode="json"),
                                     "risk_label": risk.label_candidate, "reasons": list(risk.reasons),
                                     "parser_warnings": observation.state["parsed_email"]["parser_warnings"]})
        return observation


async def main(mode):
    settings = get_settings()
    assert not settings.external_enrichment_enabled and not settings.rag_enabled, "External/RAG must remain disabled"
    initial = snapshot()
    sources = source_hashes()
    entries, old_failures, malicious = inputs()
    recovery_report = recovery(entries, old_failures)
    save("p0_parser_recovery.json", recovery_report)
    assert recovery_report["passed"], "PARSER_RECOVERY_BLOCKED"
    groups = {
        "safe": sorted(sid for sid, e in entries.items() if e.case.expected_label == "SAFE"
                       and sid not in old_failures | malicious)[:5],
        "ordinary_phishing": sorted(sid for sid, e in entries.items() if e.case.expected_label == "PHISHING"
                                    and sid not in old_failures | malicious)[:5],
        "malicious_ioc_phishing": sorted(sid for sid in malicious if entries[sid].case.expected_label == "PHISHING")[:5],
        "recovered_parser": sorted(old_failures - MIME_IDS)[:5],
    }
    assert len(set(sum(groups.values(), []))) == 20
    if mode == "full":
        smoke = json.loads((OUTPUT / "p0_smoke.json").read_text(encoding="utf-8"))
        assert smoke["passed"] and smoke["source_hashes"] == sources, "SMOKE_REQUIRED_FOR_CURRENT_CODE"
        assert smoke["manifest_sha256"] == sha(ROOT / "manifests/dev_manifest.jsonl")
        selected = list(entries)
    else:
        selected = sum(groups.values(), [])
    ioc = MeasuredIOC(settings)
    target = P0Target(settings, ioc)
    records = []
    for index, sid in enumerate(selected, 1):
        records.append(await evaluate_case(entries[sid], target, ROOT, "offline"))
        if mode == "smoke" or index % 100 == 0 or index == len(selected):
            print("PROGRESS", mode, index, "/", len(selected), flush=True)
    stats = summarize(records)
    counts = stats["classification_counts"]
    denominator = counts["tp"] + counts["tn"] + counts["fp"] + counts["fn"]
    stats["accuracy"] = ratio(counts["tp"] + counts["tn"], denominator).model_dump()
    stats["false_negative_rate"] = ratio(counts["fn"], counts["tp"] + counts["fn"]).model_dump()
    distributions = {group: dict(Counter(r.predicted_label or "EXECUTION_ERROR" for r in records if r.case_id in ids))
                     for group, ids in groups.items()}
    malicious_records = [r for r in records if r.case_id in malicious]
    malicious_report = {"cases": len(malicious_records),
                        "labels": dict(Counter(r.predicted_label for r in malicious_records)),
                        "coverage_blocked": sum(r.predicted_label == "NEEDS_ANALYST_REVIEW" and r.score >= 70
                                                and set(target.details[r.case_id]["reasons"]) <=
                                                {"UNKNOWN_EVIDENCE", "MISSING_COVERAGE"} for r in malicious_records)}
    after = snapshot()
    changed = sorted(k for k in initial.keys() | after.keys() if initial.get(k) != after.get(k))
    unsafe_safe = [r.case_id for r in records if r.predicted_label == "SAFE" and not r.coverage_complete]
    failures = [r.case_id for r in records if r.status != "success"]
    expected_failures = MIME_IDS if mode == "full" else set()
    passed = (not changed and not unsafe_safe and not ioc.errors and set(failures) == expected_failures
              and stats["decision_coverage"]["numerator"] > 0 and malicious_report["coverage_blocked"] == 0)
    if mode == "smoke":
        passed &= distributions["malicious_ioc_phishing"].get("PHISHING", 0) > 0
    report = {"mode": mode, "passed": bool(passed), "source_hashes": sources,
              "manifest_sha256": sha(ROOT / "manifests/dev_manifest.jsonl"), "label_policy": LABEL_POLICY,
              "canonical": 3462, "defender_skipped": 4, "attempted": len(records),
              "summary": stats, "native_labels": dict(Counter(r.predicted_label or "EXECUTION_ERROR" for r in records)),
              "smoke_ids": groups, "smoke_distributions": distributions, "parser_recovery": recovery_report,
              "malicious_ioc": malicious_report, "unsafe_safe_cases": unsafe_safe,
              "data_modified": bool(changed), "data_changed_paths": changed, "test_executed": 0,
              "api_calls": 0, "llm_calls": 0, "ioc_errors": dict(ioc.errors),
              "scope": "P0 validation on DEV; selective metrics, not a production benchmark",
              "cases": [r.model_dump(mode="json") for r in records], "safe_evidence": target.details}
    save("p0_smoke.json" if mode == "smoke" else "p0_dev_baseline.json", report)
    print("RESULT", json.dumps({k: report[k] for k in ("passed", "attempted", "summary", "native_labels",
                                                      "smoke_distributions", "malicious_ioc", "data_modified")}), flush=True)
    if not passed:
        raise SystemExit("P0_VERIFICATION_BLOCKED")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("smoke", "full"))
    asyncio.run(main(parser.parse_args().mode))
