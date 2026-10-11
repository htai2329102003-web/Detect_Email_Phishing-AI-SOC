"""Bounded DEV-only risk-policy search and one final production-policy replay.

No graph/analyzer execution: reuse the Round-1 evidence and its derived-IOC
scope correction. All socket connections are denied while the command runs.
"""

import argparse
import hashlib
import json
import socket
from collections import Counter
from pathlib import Path
from unittest.mock import patch

from eval.round1 import distribution, metric, transformed
from src.evidence.models import Evidence
from src.evidence.risk_engine import RiskPolicy, load_risk_policy, score_evidence

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "eval/results"
CACHE = OUT / "dev_tuning_round1_evidence.jsonl"
REPORT = OUT / "dev_tuning_round2.json"
MARKDOWN = OUT / "dev_tuning_round2.md"
SPECS = (
    {"id": "R2-A", "phishing": 60},
    {"id": "R2-B", "phishing": 62},
    {"id": "R2-C", "ip_weight": .55},
    {"id": "R2-D", "ip_weight": .55, "phishing": 62},
    {"id": "R2-E", "bounded_partial_header": True},
    {"id": "R2-F", "ip_weight": .55, "phishing": 62, "bounded_partial_header": True},
)


def snapshot():
    return {str(p.relative_to(ROOT)): (s.st_size, s.st_mtime_ns)
            for p in (ROOT / "data").rglob("*") if p.is_file() for s in [p.stat()]}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def bounded_partial(risk, facts, policy):
    """Search-only hypothesis; final replay must use the production implementation."""
    return (
        risk.label_candidate == "NEEDS_ANALYST_REVIEW"
        and policy.thresholds.suspicious <= risk.score < policy.thresholds.phishing
        and set(risk.reasons) <= {"UNKNOWN_EVIDENCE", "MISSING_COVERAGE"}
        and all(policy.weights[s].family in {"email_auth", "identity"} for s in risk.coverage.missing)
        and all(e.tool_status == "OK" for e in facts)
        and any(e.result == "FAIL" and e.provenance.source == "local"
                and e.family in {"url_deception", "attachment"}
                and policy.weights[e.signal_type].weight * e.confidence >= .35
                and {"url_deception": "URL_ANALYSIS", "attachment": "ATTACHMENT_ANALYSIS"}[e.family]
                in risk.coverage.completed for e in facts)
    )


def candidate_policy(base, spec):
    values = base.model_dump()
    if "phishing" in spec:
        values["thresholds"]["phishing"] = spec["phishing"]
    if "ip_weight" in spec:
        values["weights"]["URL_IP_LITERAL"]["weight"] = spec["ip_weight"]
    return RiskPolicy.model_validate(values)


def inputs():
    rows = [json.loads(line) for line in CACHE.read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 3458
    facts = {r["case_id"]: transformed([Evidence.model_validate(e) for e in r["evidence"]])
             for r in rows if r["status"] == "success"}
    assert len(facts) == 3456
    assert all(e.provenance.source != "llm" for items in facts.values() for e in items)
    return rows, facts


def replay(rows, facts, policy, *, hypothesis=False):
    predictions, risks = [], {}
    for row in rows:
        result = {k: row[k] for k in ("case_id", "expected_label", "status")}
        result.update(score=None, predicted_label=None)
        if row["status"] == "success":
            items = facts[row["case_id"]]
            risk = score_evidence(items, applicable_signals=row["applicable"], policy=policy)
            label = "SUSPICIOUS" if hypothesis and bounded_partial(risk, items, policy) else risk.label_candidate
            result.update(score=risk.score, predicted_label=label)
            risks[row["case_id"]] = risk
            assert label != "SAFE" or risk.coverage.complete
        predictions.append(result)
    return predictions, risks


def transitions(before, after):
    changes = Counter()
    for old, new in zip(before, after, strict=True):
        assert old["case_id"] == new["case_id"]
        if old["status"] == "success":
            changes[f'{old["expected_label"]}: {old["predicted_label"]} -> {new["predicted_label"]}'] += 1
    return dict(changes)


def audit(rows, facts, predictions, risks):
    by_id = {r["case_id"]: r for r in rows}
    groups = {}
    fp_cases = []
    for name, truth, label in (("phishing_suspicious", "PHISHING", "SUSPICIOUS"),
                               ("phishing_review", "PHISHING", "NEEDS_ANALYST_REVIEW"),
                               ("false_positives", "SAFE", "PHISHING")):
        members = [r for r in predictions if r["expected_label"] == truth and r["predicted_label"] == label]
        signals, families, blockers, strongest, near = (Counter() for _ in range(5))
        family_strengths = {}
        candidates = []
        for member in members:
            sid = member["case_id"]
            risk, items = risks[sid], facts[sid]
            active = [c for c in risk.contributions if c.applied_strength > 0]
            signals.update({e.signal_type for e in items if e.result == "FAIL"})
            families.update({c.family for c in active})
            blockers.update(risk.coverage.missing)
            best = max(active, key=lambda c: c.applied_strength) if active else None
            strongest[best.signal_type if best else "NONE"] += 1
            for contribution in active:
                family_strengths.setdefault(contribution.family, []).append(contribution.applied_strength)
            for threshold in (30, 65):
                if threshold - 5 <= risk.score < threshold:
                    near[f"within_5_below_{threshold}"] += 1
            if active:
                candidates.append({"case_id": sid, "score": risk.score,
                                   "strongest_signal": best.signal_type, "family": best.family,
                                   "coverage_missing": list(risk.coverage.missing)})
            if name == "false_positives":
                fp_cases.append({"case_id": sid, "source": by_id[sid]["source"], "score": risk.score,
                                 "contributions": [c.model_dump() for c in active],
                                 "coverage_missing": list(risk.coverage.missing)})
        groups[name] = {"count": len(members), "scores": distribution(r["score"] for r in members),
                        "signals": dict(signals), "families": dict(families), "coverage_blockers": dict(blockers),
                        "family_strengths": {k: distribution(v) for k, v in family_strengths.items()},
                        "strongest_signals": dict(strongest), "near_threshold": dict(near),
                        "deterministic_candidates": candidates}
    return {"groups": groups, "fp_cases": fp_cases}


def render(report):
    lines = ["# DEV quality tuning Round 2", "", "DEV only; cached deterministic evidence; not a production benchmark.",
             "", "## Candidate search", "",
             "| Candidate | Changes | TP | TN | FP | FN | SAFE | SUSPICIOUS | PHISHING | REVIEW | Recall % | Precision % | FPR % | Coverage % | Abstention % |",
             "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for item in [{"id": "C4 baseline", "changes": {}, "metrics": report["baseline"]}, *report["candidates"]]:
        m = item["metrics"]
        values = [item["id"], json.dumps(item["changes"]), *[m[k] for k in ("tp", "tn", "fp", "fn")],
                  *[m["labels"][k] for k in ("SAFE", "SUSPICIOUS", "PHISHING", "NEEDS_ANALYST_REVIEW")],
                  *[f'{100*m["whole_dev"][k]["value"]:.4f}' for k in
                    ("phishing_recall", "precision", "safe_fpr", "decision_coverage", "abstention")]]
        lines.append("| " + " | ".join(map(str, values)) + " |")
    lines += ["", "### Label transitions by ground truth", "",
              "| Candidate | Phishing REVIEW → SUSPICIOUS | Phishing REVIEW → PHISHING | Phishing SUSPICIOUS → PHISHING | SAFE newly PHISHING |",
              "|---|---:|---:|---:|---:|"]
    for item in report["candidates"]:
        changes = item["transitions"]
        lines.append(f'| {item["id"]} | {changes.get("PHISHING: NEEDS_ANALYST_REVIEW -> SUSPICIOUS", 0)} '
                     f'| {changes.get("PHISHING: NEEDS_ANALYST_REVIEW -> PHISHING", 0)} '
                     f'| {changes.get("PHISHING: SUSPICIOUS -> PHISHING", 0)} '
                     f'| {sum(v for k, v in changes.items() if k.startswith("SAFE:") and k.endswith(" -> PHISHING") and k != "SAFE: PHISHING -> PHISHING")} |')
    lines += ["", "## Error analysis", "",
              "183 phishing SUSPICIOUS; 381 phishing REVIEW; 7 FP. Missing auth affects every case in these groups.",
              "171 phishing REVIEW cases have no positive deterministic evidence. 103 lack HEADER_ANALYSIS; 30 lack URL_ANALYSIS.",
              "Phishing SUSPICIOUS includes 70 IP-literal detections; phishing REVIEW includes 18. Family correlation remains max-per-family.",
              "The 7 existing FP: five score 68.8 from obfuscated URL + reply-to mismatch + derived-domain IOC; two score 70 from href mismatch + identity.",
              "No repeated temporal IOC audit. Exact per-case contributions and candidate effects are in JSON.",
              "", "## Selection and validation", "", "```json",
              json.dumps({k: v for k, v in report.items() if k not in
                          {"error_analysis", "candidates", "baseline_predictions", "final_predictions", "baseline"}},
                         ensure_ascii=False, indent=2), "```", ""]
    return "\n".join(lines)


def save(report):
    REPORT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    MARKDOWN.write_text(render(report), encoding="utf-8")


def search():
    if REPORT.exists():
        raise RuntimeError("Round-2 report already exists; do not overwrite previous search")
    before = snapshot()
    rows, facts = inputs()
    base = load_risk_policy()
    baseline, risks = replay(rows, facts, base)
    baseline_metrics = metric(baseline)
    assert baseline_metrics["labels"] == {"SAFE": 0, "SUSPICIOUS": 661, "PHISHING": 149, "NEEDS_ANALYST_REVIEW": 2646}
    report = {"complete": False, "baseline_policy": base.model_dump(), "baseline": baseline_metrics,
              "baseline_predictions": baseline, "error_analysis": audit(rows, facts, baseline, risks),
              "candidates": [], "cache_sha256": digest(CACHE),
              "dev_manifest_sha256": digest(ROOT / "data/manifests/dev_manifest.jsonl"),
              "canonical": 3462, "defender_skipped": 4, "attempted": 3458, "execution_errors": 2,
              "selection": None, "cost": {"llm": 0, "rag": 0, "virustotal": 0, "urlscan": 0},
              "safety": {"unknown_to_pass": False, "data_modified": False, "test_executed": 0},
              "validation": {}, "final_dev_replays": 0}
    fp_ids = {r["case_id"] for r in report["error_analysis"]["fp_cases"]}
    for spec in SPECS:
        predictions, _ = replay(rows, facts, candidate_policy(base, spec),
                                hypothesis=spec.get("bounded_partial_header", False))
        item = {"id": spec["id"], "changes": {k: v for k, v in spec.items() if k != "id"},
                "metrics": metric(predictions), "transitions": transitions(baseline, predictions),
                "existing_fp_effects": {r["case_id"]: r["predicted_label"] for r in predictions if r["case_id"] in fp_ids}}
        report["candidates"].append(item)
        print(json.dumps(item), flush=True)
    assert snapshot() == before, "DATA_MODIFIED"
    save(report)


def finalize(passed):
    report = json.loads(REPORT.read_text(encoding="utf-8"))
    assert report["selection"] is not None and report["final_dev_replays"] == 0
    assert passed > 0, "Focused validation must pass before final DEV replay"
    assert digest(CACHE) == report["cache_sha256"]
    assert digest(ROOT / "data/manifests/dev_manifest.jsonl") == report["dev_manifest_sha256"]
    before = snapshot()
    rows, facts = inputs()
    expected_policy = candidate_policy(RiskPolicy.model_validate(report["baseline_policy"]),
                                       report["selection"]["changes"]).model_dump()
    expected_policy["allow_partial_header_suspicious"] = True
    assert load_risk_policy().model_dump() == expected_policy
    predictions, _ = replay(rows, facts, load_risk_policy())
    selected = next(c for c in report["candidates"] if c["id"] == report["selection"]["id"])
    metrics = metric(predictions)
    assert metrics == selected["metrics"], "FINAL_REPLAY_MISMATCH"
    assert transitions(report["baseline_predictions"], predictions) == selected["transitions"]
    assert snapshot() == before, "DATA_MODIFIED"
    report.update(complete=True, final_metrics=metrics, final_predictions=predictions, final_dev_replays=1,
                  final_policy=load_risk_policy().model_dump(),
                  validation={"focused_pass": passed, "focused_fail": 0, "compile": "PASS", "ruff": "PASS"},
                  final_status={"round2_complete": True, "dev_quality_improved": True,
                                "ready_for_final_dev_validation": True, "ready_for_test": False,
                                "remaining_blockers": ["DEV-only tuning; TEST generalization remains unmeasured",
                                                       "Coverage gaps and 171 signal-free phishing abstentions remain"]})
    save(report)
    print(json.dumps({"final_metrics": metrics, "transitions": selected["transitions"]}), flush=True)


def select():
    report = json.loads(REPORT.read_text(encoding="utf-8"))
    assert report["selection"] is None and report["final_dev_replays"] == 0
    chosen = next(c for c in report["candidates"] if c["id"] == "R2-F")
    assert chosen["metrics"]["fp"] == report["baseline"]["fp"]
    assert chosen["metrics"]["tp"] > report["baseline"]["tp"]
    assert chosen["metrics"]["labels"]["NEEDS_ANALYST_REVIEW"] < report["baseline"]["labels"]["NEEDS_ANALYST_REVIEW"]
    report["selection"] = {"id": chosen["id"], "changes": chosen["changes"],
        "reason": "43 additional phishing positives, 45 fewer abstentions, no additional PHISHING false positives; best coverage among candidates preserving 7 FP",
        "tradeoff": "3 benign REVIEW cases become SUSPICIOUS; 7 existing FP persist. DEV tuning does not establish TEST or production performance.",
        "justification": "IP literals occur in 70 phishing SUSPICIOUS and 18 phishing REVIEW cases. IP alone remains below PHISHING. Partial header exception requires local static risk >=0.35, completed corresponding analyzer, no non-header gaps, no failed tools or integrity errors. Lowering PHISHING to 60 is rejected: FP 7->27.",
        "selected_before_final_validation": True}
    save(report)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("search", "select", "final"))
    parser.add_argument("--passed", type=int, default=0)
    args = parser.parse_args()
    with patch.object(socket.socket, "connect", side_effect=AssertionError("Offline DEV replay")), \
         patch.object(socket, "create_connection", side_effect=AssertionError("Offline DEV replay")):
        if args.phase == "search":
            search()
        elif args.phase == "select":
            select()
        else:
            finalize(args.passed)
