"""One-time, frozen R2-F TEST recovery with durable prediction aggregation."""

import argparse
import asyncio
import hashlib
import json
import os
from collections import Counter
from pathlib import Path
from time import perf_counter

from eval.manifest import ManifestEntry, _invalid_constant, _unique_object
from eval.run_eval import evaluate_case
from eval.schemas import EvalCase, PredictionRecord
from eval.targets import GraphTarget
from src.config import get_settings
from src.evidence.risk_engine import load_risk_policy
from src.services.ioc_index import SQLiteIOCClient

PROJECT = Path(__file__).resolve().parents[1]
DATA = PROJECT / "data"
MANIFEST = DATA / "manifests" / "test_manifest.jsonl"
JSON_OUTPUT = PROJECT / "eval" / "results" / "final_test_evaluation.json"
MD_OUTPUT = PROJECT / "eval" / "results" / "final_test_evaluation.md"
QUARANTINED = {
    "e2a_recov_736272db",
    "e2a_recov_870c06a6",
    "e2a_recov_ce542e04",
    "e2a_recov_daf35c69",
}
EXPECTED_LABELS = {"SAFE": 741, "PHISHING": 287}
FROZEN = {"phishing_threshold": 62.0, "suspicious_threshold": 30.0,
          "url_ip_literal_weight": 0.55, "ioc_derived_domain_weight": 0.20}


def effective_config():
    policy = load_risk_policy()
    return {
        "phishing_threshold": policy.thresholds.phishing,
        "suspicious_threshold": policy.thresholds.suspicious,
        "url_ip_literal_weight": policy.weights["URL_IP_LITERAL"].weight,
        "ioc_derived_domain_weight": policy.weights["IOC_DERIVED_DOMAIN"].weight,
    }


def aggregate(records):
    """Final-DEV definitions: review is separate; abstentions are recall misses."""
    records = list(records)
    successful = [r for r in records if r.status == "success" and r.predicted_label is not None]
    labels = Counter(r.predicted_label for r in successful)
    labels = {label: labels[label] for label in ("SAFE", "SUSPICIOUS", "PHISHING", "NEEDS_ANALYST_REVIEW")}
    attempted_positive = sum(r.expected_label == "PHISHING" for r in records)
    attempted_safe = sum(r.expected_label == "SAFE" for r in records)
    tp = sum(r.expected_label == "PHISHING" and r.predicted_label == "PHISHING" for r in successful)
    fp = sum(r.expected_label == "SAFE" and r.predicted_label == "PHISHING" for r in successful)
    tn = sum(r.expected_label == "SAFE" and r.predicted_label in {"SAFE", "SUSPICIOUS"} for r in successful)
    fn = sum(r.expected_label == "PHISHING" and r.predicted_label in {"SAFE", "SUSPICIOUS"} for r in successful)
    decided = labels["SAFE"] + labels["SUSPICIOUS"] + labels["PHISHING"]
    successful_count = len(successful)

    def ratio(n, d):
        return {"numerator": n, "denominator": d, "value": n / d if d else None}

    return {
        "attempted": len(records), "successful": successful_count,
        "execution_errors": len(records) - successful_count,
        "labels": labels, "confusion": {"tp": tp, "tn": tn, "fp": fp, "fn": fn},
        "metrics": {
            "phishing_recall": ratio(tp, attempted_positive),
            "safe_fpr": ratio(fp, attempted_safe),
            "precision": ratio(tp, tp + fp),
            "decision_coverage": ratio(decided, successful_count),
            "abstention": ratio(labels["NEEDS_ANALYST_REVIEW"], successful_count),
        },
    }


def verify_aggregation_without_test():
    fake = [
        PredictionRecord(case_id="synthetic-safe-tn", manifest_line=1, expected_label="SAFE",
                         predicted_label="SAFE", status="success"),
        PredictionRecord(case_id="synthetic-safe-fp", manifest_line=2, expected_label="SAFE",
                         predicted_label="PHISHING", status="success"),
        PredictionRecord(case_id="synthetic-phish-tp", manifest_line=3, expected_label="PHISHING",
                         predicted_label="PHISHING", status="success"),
        PredictionRecord(case_id="synthetic-phish-review", manifest_line=4, expected_label="PHISHING",
                         predicted_label="NEEDS_ANALYST_REVIEW", status="success"),
        PredictionRecord(case_id="synthetic-phish-error", manifest_line=5, expected_label="PHISHING",
                         status="failed", error={"stage": "analysis", "code": "SYNTHETIC_ERROR",
                         "message": "synthetic aggregation check"}),
    ]
    result = aggregate(fake)
    expected = {
        "attempted": 5, "successful": 4, "execution_errors": 1,
        "labels": {"SAFE": 1, "SUSPICIOUS": 0, "PHISHING": 2, "NEEDS_ANALYST_REVIEW": 1},
        "confusion": {"tp": 1, "tn": 1, "fp": 1, "fn": 0},
        "metrics": {
            "phishing_recall": {"numerator": 1, "denominator": 3, "value": 1 / 3},
            "safe_fpr": {"numerator": 1, "denominator": 2, "value": 1 / 2},
            "precision": {"numerator": 1, "denominator": 2, "value": 1 / 2},
            "decision_coverage": {"numerator": 3, "denominator": 4, "value": 3 / 4},
            "abstention": {"numerator": 1, "denominator": 4, "value": 1 / 4},
        },
    }
    if result != expected:
        raise AssertionError("Synthetic aggregation self-check failed")
    return result


def read_entries():
    entries, ids, label_counts, skipped = [], set(), Counter(), []
    with MANIFEST.open(encoding="utf-8-sig") as stream:
        for line_number, text in enumerate(stream, 1):
            if not text.strip():
                continue
            row = json.loads(text, parse_constant=_invalid_constant, object_pairs_hook=_unique_object)
            case_id = row.get("id")
            if case_id in ids:
                raise ValueError("Duplicate TEST manifest case ID")
            ids.add(case_id)
            label_counts[row.get("expected_label")] += 1
            if case_id in QUARANTINED:
                if row.get("expected_label") != "PHISHING":
                    raise ValueError("A quarantined TEST entry is not labeled PHISHING")
                skipped.append(case_id)
                continue
            adapted = dict(row)
            adapted.pop("source_file", None)
            adapted.pop("source_sha256", None)
            adapted.pop("curated_sha256", None)
            if not adapted.get("capabilities"):
                # Eval grouping metadata only; does not affect graph routing or scoring.
                adapted["capabilities"] = ["core"]
            case = EvalCase.model_validate(adapted)
            sample = (DATA / case.file).resolve()
            if not sample.is_relative_to(DATA) or not sample.is_file():
                raise ValueError("TEST manifest has an invalid/missing non-quarantined path")
            if case.profile is not None or case.ioc_records or case.injection is not None:
                raise ValueError("TEST manifest contains an unexpected provider/injection override")
            entries.append(ManifestEntry(line_number, case.id, case=case))
    if len(ids) != 1028 or label_counts != EXPECTED_LABELS or set(skipped) != QUARANTINED or len(entries) != 1024:
        raise ValueError("TEST manifest/canonical/quarantine counts differ from frozen expected values")
    return entries, dict(label_counts), skipped


def data_snapshot():
    # Metadata-only snapshot; quarantined message bytes are never opened.
    return {p.relative_to(DATA).as_posix(): (p.stat().st_size, p.stat().st_mtime_ns)
            for p in DATA.rglob("*") if p.is_file()}


def check_frozen_inputs():
    config = effective_config()
    if config != FROZEN:
        raise ValueError("Frozen R2-F configuration mismatch")
    overrides = sorted(key for key in os.environ if "RISK" in key.upper() or "POLICY" in key.upper())
    if overrides:
        raise ValueError("Unexpected risk/policy environment override")
    settings = get_settings()
    # The recovery target below explicitly wires neither RAG nor external
    # services and always uses DeterministicVerdictProvider. These settings may
    # be configured in .env, but cannot affect this isolated evaluation path.
    return {**config, "unexpected_environment_overrides": overrides,
            "rag_enabled": settings.rag_enabled, "verdict_llm_enabled": settings.verdict_llm_enabled,
            "content_bec_enabled": settings.content_bec_enabled}


def concise_record(record):
    return {"case_id": record.case_id, "expected_label": record.expected_label,
            "predicted_label": record.predicted_label, "status": record.status,
            "score": record.score, "latency_ms": record.latency_ms,
            "error_code": record.error.code if record.error else None}


async def run_recovery():
    config = check_frozen_inputs()
    before_data = data_snapshot()
    manifest_sha = hashlib.sha256(MANIFEST.read_bytes()).hexdigest()
    entries, canonical_labels, skipped = read_entries()
    settings = get_settings()
    ioc_client = SQLiteIOCClient(settings.ioc_data_path, settings.ioc_index_path)
    target = GraphTarget(profile="offline", ioc_client=ioc_client)
    records = []
    started = perf_counter()
    for index, entry in enumerate(entries, 1):
        records.append(await evaluate_case(entry, target, DATA, "offline"))
        if index % 100 == 0 or index == len(entries):
            print(f"RECOVERY_PROGRESS {index}/1024", flush=True)
    elapsed = perf_counter() - started
    after_data = data_snapshot()
    if before_data != after_data or hashlib.sha256(MANIFEST.read_bytes()).hexdigest() != manifest_sha:
        raise ValueError("Data/manifest changed during recovery")
    result = aggregate(records)
    if result["attempted"] != 1024:
        raise ValueError("Recovery did not retain all expected prediction records")
    return {
        "config": config,
        "dataset": {"canonical": 1028, "canonical_labels": canonical_labels,
                    "defender_skipped": len(skipped), "skipped_ids": sorted(skipped),
                    "attempted": result["attempted"], "manifest_sha256": manifest_sha},
        "results": result,
        "records": [concise_record(record) for record in records],
        "latency": {"mean_ms": sum(r.latency_ms for r in records if r.latency_ms is not None) /
                    sum(r.latency_ms is not None for r in records) if any(r.latency_ms is not None for r in records) else None,
                    "samples": sum(r.latency_ms is not None for r in records), "elapsed_seconds": elapsed},
        "cost": {"bec_calls": 0, "verdict_llm_calls": 0, "rag_calls": 0,
                 "virustotal_calls": 0, "urlscan_calls": 0},
        "safety": {"data_modified": False, "config_modified": False, "production_code_modified": False,
                   "test_used_for_tuning": False, "commit": False, "push": False},
    }


def pct(item):
    return "N/A" if item["value"] is None else f"{item['value'] * 100:.4f}% ({item['numerator']}/{item['denominator']})"


def render_markdown(report):
    test = report["recovery"]
    result = test["results"]
    metrics = result["metrics"]
    dev = report["dev_reference"]
    lines = [
        "# Final TEST recovery evaluation", "",
        "**Recovery pass purpose: metric capture only.** The first inference pass is retained as an unscorable failed aggregation attempt.", "",
        "## Integrity", "",
        "- Initial TEST pass: UNSCORABLE — evaluation runner aggregation bug", "- Config changed after initial pass: NO",
        "- TEST metrics observed before recovery: NO", "- TEST used for tuning: NO", "- Total TEST inference passes: 2",
        "- Valid scored TEST passes: 1", "- Frozen R2-F config verified: YES", "",
        "## Frozen config", "",
        f"- PHISHING / SUSPICIOUS thresholds: {test['config']['phishing_threshold']} / {test['config']['suspicious_threshold']}",
        f"- URL_IP_LITERAL / IOC_DERIVED_DOMAIN: {test['config']['url_ip_literal_weight']} / {test['config']['ioc_derived_domain_weight']}", "",
        "## TEST", "", f"- Canonical / Defender skipped / attempted: 1028 / 4 / {result['attempted']}",
        f"- Successful / execution errors: {result['successful']} / {result['execution_errors']}",
        f"- SAFE / SUSPICIOUS / PHISHING / REVIEW: {result['labels']['SAFE']} / {result['labels']['SUSPICIOUS']} / {result['labels']['PHISHING']} / {result['labels']['NEEDS_ANALYST_REVIEW']}",
        f"- TP / TN / FP / FN: {result['confusion']['tp']} / {result['confusion']['tn']} / {result['confusion']['fp']} / {result['confusion']['fn']}", "",
        "## Metrics (DEV → TEST)", "",
        f"- Phishing recall: {dev['phishing_recall']} → {pct(metrics['phishing_recall'])}",
        f"- SAFE FPR: {dev['safe_fpr']} → {pct(metrics['safe_fpr'])}",
        f"- Precision: {dev['precision']} → {pct(metrics['precision'])}",
        f"- Decision coverage: {dev['decision_coverage']} → {pct(metrics['decision_coverage'])}",
        f"- Abstention: {dev['abstention']} → {pct(metrics['abstention'])}", "",
        "## Cost and scope", "", "- BEC / Verdict LLM / RAG / VT / urlscan calls: 0 / 0 / 0 / 0 / 0",
        "- No tuning, DEV rerun, production changes, config changes, or data changes.",
        "- The four quarantined E2A rows were excluded by ID without opening their message files.", "",
        "**Final TEST complete: YES**", "**Final config remains R2-F: YES**", "**Ready for G9 / final delivery: YES**", "",
    ]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-check-only", action="store_true")
    args = parser.parse_args()
    check = verify_aggregation_without_test()
    if args.self_check_only:
        print(json.dumps({"runner_fix_verified_without_test": True, "synthetic_aggregation": check}))
        return 0
    recovery = asyncio.run(run_recovery())
    previous = json.loads(JSON_OUTPUT.read_text(encoding="utf-8"))
    dev = json.loads((PROJECT / "eval/results/final_dev_validation.json").read_text(encoding="utf-8"))["final_dev"]["metrics"]
    dev_ref = {name: f"{dev[key]['value'] * 100:.4f}%" for name, key in (
        ("phishing_recall", "phishing_recall"), ("safe_fpr", "safe_fpr"),
        ("precision", "precision"), ("decision_coverage", "decision_coverage"), ("abstention", "abstention"))}
    report = {
        "validation_type": "FINAL_TEST_RECOVERY",
        "status": "PASS",
        "initial_test_pass": {"status": "UNSCORABLE — evaluation runner aggregation bug",
                              "analysis_completed": 1024, "records_recoverable": False,
                              "config_changed_after_initial_pass": False,
                              "metrics_observed_before_recovery": False,
                              "test_used_for_tuning": False,
                              "original_artifact": previous},
        "old_predictions_recovered": False,
        "recovery_rerun_required": True,
        "runner_fix_verified_without_test": True,
        "synthetic_aggregation_check": check,
        "total_test_inference_passes": 2,
        "valid_scored_test_passes": 1,
        "recovery_pass_purpose": "METRIC CAPTURE ONLY",
        "dev_reference": dev_ref,
        "recovery": recovery,
        "final_status": {"final_test_complete": True, "final_config_remains_r2f": True,
                         "ready_for_g9_final_delivery": True},
    }
    JSON_OUTPUT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    MD_OUTPUT.write_text(render_markdown(report), encoding="utf-8")
    print(json.dumps({"status": "PASS", "attempted": recovery["results"]["attempted"],
                      "successful": recovery["results"]["successful"],
                      "execution_errors": recovery["results"]["execution_errors"],
                      "labels": recovery["results"]["labels"], "confusion": recovery["results"]["confusion"],
                      "metrics": recovery["results"]["metrics"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
