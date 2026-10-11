"""Cost-aware post-Stage7 DEV classification baseline.

This replays frozen Round-1 Gate-1 evidence, computes a mathematical BEC upper
bound, and invokes the real BEC provider only for cases whose native Risk Engine
label could change. Verdict, RAG, VT and urlscan are never called here.
"""

import argparse
import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter

from eval.metrics import percentile
from eval.results.dev_baseline_driver import snapshot
from eval.round1 import metric, transformed
from src.analyzers.content_analyzer import RedactedContent, StructuredContentAnalyzer
from src.config import get_settings
from src.evidence.models import Evidence, Gate1Result
from src.evidence.risk_engine import load_risk_policy, score_evidence
from src.parsers.email_parser import parse_email
from src.services.llm import LLMClient
from src.services.pii import RegexPIIRedactor

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
RESULTS = ROOT / "eval/results"
CACHE = RESULTS / "dev_tuning_round1_evidence.jsonl"
MANIFEST = DATA / "manifests/dev_manifest.jsonl"
JSON_OUTPUT = RESULTS / "post_stage7_dev_baseline.json"
MD_OUTPUT = RESULTS / "post_stage7_dev_baseline.md"
BUDGET = 500
LABELS = ("SAFE", "SUSPICIOUS", "PHISHING", "NEEDS_ANALYST_REVIEW")


def upper_bound_evidence(stamp: datetime) -> Evidence:
    return Evidence(
        analyzer="content_bec", tool="impact_upper_bound", signal_type="BEC_REQUEST",
        family="content_bec", indicator="redacted:content_bec", value={"upper_bound": True},
        result="FAIL", tool_status="OK", severity="low", confidence=1,
        provenance={"source": "llm", "reference": "post-stage7:upper-bound"}, collected_at=stamp,
    )


def unavailable_evidence(result) -> Evidence:
    return Evidence(
        analyzer="content_bec", tool="structured_llm", signal_type="BEC_REQUEST",
        family="content_bec", indicator="redacted:content_bec",
        value={"error_code": result.error_code or "LLM_INVALID_RESPONSE"}, result="UNKNOWN",
        tool_status=result.status if result.status != "OK" else "ERROR", severity="info", confidence=1,
        provenance={"source": "llm", "reference": "structured_bec:v1"}, collected_at=datetime.now(UTC),
    )


def load_inputs():
    rows = [json.loads(line) for line in CACHE.read_text(encoding="utf-8").splitlines() if line.strip()]
    manifest = {row["id"]: row for line in MANIFEST.read_text(encoding="utf-8-sig").splitlines()
                if line.strip() for row in [json.loads(line)]}
    if len(manifest) != 3462 or Counter(row["expected_label"] for row in manifest.values()) != {
            "SAFE": 2750, "PHISHING": 712}:
        raise ValueError("DEV_MANIFEST_CONTRACT_CHANGED")
    if len(rows) != 3458:
        raise ValueError("ROUND1_EVIDENCE_CACHE_INCOMPLETE")
    return rows, manifest


def replay_case(row, *, policy, positive=False):
    facts = transformed([Evidence.model_validate(item) for item in row["evidence"]])
    applicable = list(row["applicable"])
    if positive:
        facts.append(upper_bound_evidence(datetime.now(UTC)))
        applicable.append("BEC_REQUEST")
    return facts, score_evidence(Gate1Result(evidence=tuple(facts)), applicable_signals=applicable, policy=policy)


def impact_category(before, upper):
    if before.coverage.complete != upper.coverage.complete:
        return "BEC_COULD_CHANGE_COVERAGE"
    transition = (before.label_candidate, upper.label_candidate)
    if transition == ("NEEDS_ANALYST_REVIEW", "SUSPICIOUS"):
        return "BEC_COULD_CHANGE_REVIEW_TO_SUSPICIOUS"
    if transition == ("NEEDS_ANALYST_REVIEW", "PHISHING"):
        return "BEC_COULD_CHANGE_REVIEW_TO_PHISHING"
    if before.label_candidate != upper.label_candidate:
        return "BEC_COULD_CHANGE_SCORE_THRESHOLD"
    return "BEC_CANNOT_CHANGE_RESULT"


def render(report):
    impact = report["impact_analysis"]
    execution = report["bec_execution"]
    transitions = report["label_transitions"]
    metrics = report["post_stage7_dev"]["metrics"]
    whole = metrics["whole_dev"]
    perf = report["cost_performance"]
    def pct(item):
        return "N/A" if item["value"] is None else f'{100 * item["value"]:.4f}%'
    lines = [
        "=== POST-STAGE7 DEV BASELINE RESULT ===", "", "=== IMPACT ANALYSIS ===", "",
        f'SUCCESSFUL DEV CASES: {impact["successful_dev_cases"]}',
        f'BEC CANNOT CHANGE RESULT: {impact["categories"]["BEC_CANNOT_CHANGE_RESULT"]}',
        f'BEC POTENTIALLY IMPACTFUL: {impact["potentially_impactful"]}',
        f'SCORE-THRESHOLD IMPACT: {impact["categories"]["BEC_COULD_CHANGE_SCORE_THRESHOLD"]}',
        f'COVERAGE IMPACT: {impact["categories"]["BEC_COULD_CHANGE_COVERAGE"]}',
        f'REVIEW/SUSPICIOUS IMPACT: {impact["categories"]["BEC_COULD_CHANGE_REVIEW_TO_SUSPICIOUS"]}',
        f'REVIEW/PHISHING IMPACT: {impact["categories"]["BEC_COULD_CHANGE_REVIEW_TO_PHISHING"]}',
        "", "Coverage note: successful BEC adds one applicable and one completed check. It may change the numeric ratio,",
        "but cannot change completeness when prior missing/unknown checks remain. In incomplete coverage, the current",
        "Risk Engine excludes LLM evidence from strong-PHISHING and partial-SUSPICIOUS eligibility.",
        "", "=== API BUDGET ===", "", f'ESTIMATED BEC CALLS: {report["api_budget"]["estimated_bec_calls"]}',
        f'ACTUAL REAL BEC CALLS: {report["api_budget"]["actual_real_bec_calls"]}', "API BUDGET LIMIT: 500",
        f'BUDGET EXCEEDED: {"YES" if report["api_budget"]["budget_exceeded"] else "NO"}',
        "VERDICT LLM DEV CALLS: 0", "RAG DEV CALLS: 0", "VIRUSTOTAL CALLS: 0", "URLSCAN CALLS: 0",
        "", "=== BEC EXECUTION ===", "", f'STRUCTURED OUTPUT PASS: {execution["structured_output_pass"]}',
        f'SCHEMA FAILURES: {execution["schema_failures"]}', f'PROVIDER FAILURES: {execution["provider_failures"]}',
        f'UNKNOWN: {execution["unknown"]}', f'POSITIVE BEC EVIDENCE: {execution["positive_bec_evidence"]}',
        f'NO BEC SIGNAL: {execution["no_bec_signal"]}', f'CACHE HITS: {execution["cache_hits"]}',
        "", "=== LABEL TRANSITIONS ===", "", f'REVIEW -> SUSPICIOUS: {transitions["REVIEW -> SUSPICIOUS"]}',
        f'REVIEW -> PHISHING: {transitions["REVIEW -> PHISHING"]}',
        f'SUSPICIOUS -> PHISHING: {transitions["SUSPICIOUS -> PHISHING"]}',
        f'OTHER: {transitions["OTHER"]}', f'NO CHANGE: {transitions["NO CHANGE"]}',
        f'CHANGED GROUND TRUTH SAFE: {report["changed_ground_truth"]["SAFE"]}',
        f'CHANGED GROUND TRUTH PHISHING: {report["changed_ground_truth"]["PHISHING"]}',
        "", "=== POST-STAGE7 DEV ===", "", "CANONICAL: 3462", "DEFENDER SKIPPED: 4",
        "ATTEMPTED: 3458", "SUCCESSFUL: 3456", "EXECUTION ERRORS: 2",
        *[f'{label}: {metrics["labels"][label]}' for label in LABELS],
        f'TP: {metrics["tp"]}', f'TN: {metrics["tn"]}', f'FP: {metrics["fp"]}', f'FN: {metrics["fn"]}',
        "", "=== WHOLE-DEV METRICS ===", "", f'PHISHING RECALL: {pct(whole["phishing_recall"])}',
        f'SAFE FPR: {pct(whole["safe_fpr"])}', f'PRECISION: {pct(whole["precision"])}',
        f'DECISION COVERAGE: {pct(whole["decision_coverage"])}', f'ABSTENTION: {pct(whole["abstention"])}',
        "", "=== CHANGE VS C4 ===", "", f'PHISHING RECALL: 20.0565% -> {pct(whole["phishing_recall"])}',
        f'SAFE FPR: 0.2545% -> {pct(whole["safe_fpr"])}', f'PRECISION: 95.3020% -> {pct(whole["precision"])}',
        f'DECISION COVERAGE: 23.4375% -> {pct(whole["decision_coverage"])}',
        f'ABSTENTION: 76.5625% -> {pct(whole["abstention"])}',
        "", "=== COST / PERFORMANCE ===", "", f'BEC CALLS: {perf["bec_calls"]}',
        f'INPUT TOKENS: {perf["input_tokens"] if perf["input_tokens"] is not None else "NOT AVAILABLE"}',
        f'OUTPUT TOKENS: {perf["output_tokens"] if perf["output_tokens"] is not None else "NOT AVAILABLE"}',
        f'TOTAL API TIME: {perf["total_api_seconds"]:.6f}s',
        f'AVG LATENCY: {perf["average_latency_ms"] if perf["average_latency_ms"] is not None else "N/A"}',
        f'P50: {perf["p50_latency_ms"] if perf["p50_latency_ms"] is not None else "N/A"}',
        f'P95: {perf["p95_latency_ms"] if perf["p95_latency_ms"] is not None else "N/A"}',
        "", "=== REGRESSION ===", "", "TEST NETWORK CALLS: 0",
        f'FULL REGRESSION: PASS {report["regression"].get("full_pass", "PENDING")} / '
        f'FAIL {report["regression"].get("full_fail", "PENDING")}',
        f'COMPILE: {report["regression"].get("compile", "PENDING")}',
        f'RUFF: {report["regression"].get("ruff", "PENDING")}', "", "=== SAFETY ===", "",
        "RAW EMAIL SENT TO LLM: NO", f'DATA MODIFIED: {"YES" if report["safety"]["data_modified"] else "NO"}',
        "C4 TUNED: NO", "TEST EXECUTED: 0", "", "=== FINAL STATUS ===", "",
        f'POST-STAGE7 BASELINE COMPLETE: {"YES" if report["complete"] else "NO"}',
        f'STAGE7 CLASSIFICATION IMPACT MEASURED: {"YES" if report["complete"] else "NO"}',
        f'READY FOR ROUND-2 TUNING: {"YES" if report["complete"] else "NO"}', "READY FOR TEST: NO",
        f'BLOCKERS: {"NONE" if report["complete"] else report["blocker"]}', "",
        "Verdict LLM and RAG calls are intentionally zero because their contracts cannot alter classification.",
        "The existing Stage-7 E2E smoke is reused; production code was not changed by this evaluation.",
    ]
    return "\n".join(lines) + "\n"


def run():
    before_data = snapshot()
    policy = load_risk_policy()
    if (policy.thresholds.phishing, policy.thresholds.suspicious, policy.llm_weight_cap,
            policy.weights["IOC_DERIVED_DOMAIN"].weight) != (65, 30, .1, .2):
        raise ValueError("C4_POLICY_CHANGED")
    rows, manifest = load_inputs()
    categories = Counter()
    impact = []
    replayed = []
    for row in rows:
        if row["status"] != "success":
            replayed.append({"case_id": row["case_id"], "expected_label": row["expected_label"],
                             "status": "failed", "score": None, "predicted_label": None})
            continue
        facts, baseline = replay_case(row, policy=policy)
        _, upper = replay_case(row, policy=policy, positive=True)
        category = impact_category(baseline, upper)
        categories[category] += 1
        item = {"row": row, "facts": facts, "baseline": baseline, "upper": upper, "category": category}
        if category != "BEC_CANNOT_CHANGE_RESULT":
            impact.append(item)
        replayed.append({"case_id": row["case_id"], "expected_label": row["expected_label"],
                         "status": "success", "score": baseline.score,
                         "predicted_label": baseline.label_candidate})
    expected = {"SAFE": 0, "SUSPICIOUS": 661, "PHISHING": 149, "NEEDS_ANALYST_REVIEW": 2646}
    baseline_metrics = metric(replayed)
    if baseline_metrics["labels"] != expected or len(impact) > BUDGET:
        blocker = "C4_REPLAY_MISMATCH" if baseline_metrics["labels"] != expected else "API_BUDGET_REVIEW_REQUIRED"
        report = {"complete": False, "blocker": blocker, "impact_analysis": {
            "successful_dev_cases": 3456, "categories": {name: categories[name] for name in (
                "BEC_CANNOT_CHANGE_RESULT", "BEC_COULD_CHANGE_SCORE_THRESHOLD", "BEC_COULD_CHANGE_COVERAGE",
                "BEC_COULD_CHANGE_REVIEW_TO_SUSPICIOUS", "BEC_COULD_CHANGE_REVIEW_TO_PHISHING",
                "OTHER_POTENTIAL_IMPACT")}, "potentially_impactful": len(impact)},
            "api_budget": {"estimated_bec_calls": len(impact), "actual_real_bec_calls": 0,
                           "limit": BUDGET, "budget_exceeded": len(impact) > BUDGET}}
        JSON_OUTPUT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"impact_set_size": len(impact), "estimated_bec_calls": len(impact),
                          "status": blocker}), flush=True)
        return 2
    print(json.dumps({"impact_set_size": len(impact), "estimated_bec_calls": len(impact),
                      "api_budget_limit": BUDGET}), flush=True)

    settings = get_settings()
    analyzer = StructuredContentAnalyzer(LLMClient.from_settings(settings))
    manifest_by_id = manifest
    executions = Counter()
    latencies = []
    transitions = Counter()
    changed_truth = Counter()
    output_by_id = {row["case_id"]: row for row in replayed}
    for item in impact:
        row, facts, baseline = item["row"], item["facts"], item["baseline"]
        raw = (DATA / manifest_by_id[row["case_id"]]["file"]).read_bytes()
        parsed = parse_email(raw).raw_for_analyzers
        redacted = RegexPIIRedactor().redact(parsed)
        text = "\n".join(str(redacted.data.get(key, "")) for key in ("subject", "text_body", "html_body"))
        started = perf_counter()
        result = analyzer.analyze(RedactedContent(text=text, redaction_reference=redacted.policy))
        elapsed = (perf_counter() - started) * 1000
        latencies.append(elapsed)
        if result.status == "OK" and result.data is not None:
            executions["structured_output_pass"] += 1
            bec = list(result.data.evidence)
            positive = any(e.result == "FAIL" for e in bec)
            executions["positive_bec_evidence" if positive else "no_bec_signal"] += 1
        else:
            executions["unknown"] += 1
            if result.error_code and ("INVALID" in result.error_code or "UNGROUNDED" in result.error_code):
                executions["schema_failures"] += 1
            else:
                executions["provider_failures"] += 1
            bec = [unavailable_evidence(result)]
        after = score_evidence(Gate1Result(evidence=tuple([*facts, *bec])),
                               applicable_signals=[*row["applicable"], "BEC_REQUEST"], policy=policy)
        old, new = baseline.label_candidate, after.label_candidate
        transition = f"{old} -> {new}"
        transitions[transition if transition in {"NEEDS_ANALYST_REVIEW -> SUSPICIOUS",
                    "NEEDS_ANALYST_REVIEW -> PHISHING", "SUSPICIOUS -> PHISHING"}
                    else "NO CHANGE" if old == new else "OTHER"] += 1
        if old != new:
            changed_truth[row["expected_label"]] += 1
        output_by_id[row["case_id"]].update(score=after.score, predicted_label=after.label_candidate)
    transitions["NO CHANGE"] += 3456 - len(impact)
    final_rows = [output_by_id[row["case_id"]] for row in rows]
    metrics = metric(final_rows)
    names = ("BEC_CANNOT_CHANGE_RESULT", "BEC_COULD_CHANGE_SCORE_THRESHOLD", "BEC_COULD_CHANGE_COVERAGE",
             "BEC_COULD_CHANGE_REVIEW_TO_SUSPICIOUS", "BEC_COULD_CHANGE_REVIEW_TO_PHISHING",
             "OTHER_POTENTIAL_IMPACT")
    report = {
        "complete": True, "blocker": None, "timestamp": datetime.now(UTC).isoformat(),
        "scope": "DEV classification impact only; no TEST inference; no production benchmark claim",
        "impact_contract": {"max_bec_strength": .1, "content_family_cap": .15,
            "maximum_score_formula": "score + (100 - score) * 0.10",
            "incomplete_coverage": "LLM evidence excluded from strong PHISHING and partial SUSPICIOUS eligibility",
            "coverage": "BEC success adds one applicable and completed signal; cannot repair prior missing/unknown checks"},
        "impact_analysis": {"successful_dev_cases": 3456, "categories": {name: categories[name] for name in names},
                            "potentially_impactful": len(impact)},
        "api_budget": {"estimated_bec_calls": len(impact), "actual_real_bec_calls": len(impact),
                       "limit": BUDGET, "budget_exceeded": False,
                       "verdict_llm_dev_calls": 0, "rag_dev_calls": 0,
                       "virustotal_calls": 0, "urlscan_calls": 0},
        "bec_execution": {"structured_output_pass": executions["structured_output_pass"],
            "schema_failures": executions["schema_failures"], "provider_failures": executions["provider_failures"],
            "unknown": executions["unknown"], "positive_bec_evidence": executions["positive_bec_evidence"],
            "no_bec_signal": executions["no_bec_signal"], "cache_hits": 0},
        "label_transitions": {"REVIEW -> SUSPICIOUS": transitions["NEEDS_ANALYST_REVIEW -> SUSPICIOUS"],
            "REVIEW -> PHISHING": transitions["NEEDS_ANALYST_REVIEW -> PHISHING"],
            "SUSPICIOUS -> PHISHING": transitions["SUSPICIOUS -> PHISHING"],
            "OTHER": transitions["OTHER"], "NO CHANGE": transitions["NO CHANGE"]},
        "changed_ground_truth": {label: changed_truth[label] for label in ("SAFE", "PHISHING")},
        "post_stage7_dev": {"canonical": 3462, "defender_skipped": 4, "attempted": 3458,
                            "successful": 3456, "execution_errors": 2, "metrics": metrics},
        "cost_performance": {"bec_calls": len(impact), "input_tokens": None, "output_tokens": None,
            "total_api_seconds": sum(latencies) / 1000,
            "average_latency_ms": sum(latencies) / len(latencies) if latencies else None,
            "p50_latency_ms": percentile(latencies, .5), "p95_latency_ms": percentile(latencies, .95),
            "provider_errors": executions["provider_failures"]},
        "regression": {"test_network_calls": 0, "stage7_smoke_reused": True},
        "safety": {"raw_email_sent_to_llm": False, "data_modified": snapshot() != before_data,
                   "c4_tuned": False, "test_executed": 0},
        "case_changes": [{"case_id": item["row"]["case_id"],
                          "expected_label": item["row"]["expected_label"],
                          "before": item["baseline"].label_candidate,
                          "upper_bound": item["upper"].label_candidate,
                          "after": output_by_id[item["row"]["case_id"]]["predicted_label"]} for item in impact],
    }
    report["complete"] = not report["safety"]["data_modified"]
    report["blocker"] = None if report["complete"] else "DATA_MODIFIED"
    JSON_OUTPUT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    MD_OUTPUT.write_text(render(report), encoding="utf-8")
    print(json.dumps({"impact_set_size": len(impact), "actual_bec_calls": len(impact),
                      "labels": metrics["labels"], "complete": report["complete"]}), flush=True)
    return int(not report["complete"])


def finalize_verification(passed: int, failed: int, compile_status: str, ruff_status: str):
    report = json.loads(JSON_OUTPUT.read_text(encoding="utf-8"))
    report["regression"].update(full_pass=passed, full_fail=failed,
                                compile=compile_status, ruff=ruff_status)
    JSON_OUTPUT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    MD_OUTPUT.write_text(render(report), encoding="utf-8")
    return int(failed != 0 or compile_status != "PASS" or ruff_status != "PASS")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--finalize-verification", action="store_true")
    parser.add_argument("--passed", type=int, default=0)
    parser.add_argument("--failed", type=int, default=0)
    parser.add_argument("--compile", choices=("PASS", "FAIL"), default="PASS")
    parser.add_argument("--ruff", choices=("PASS", "FAIL"), default="PASS")
    args = parser.parse_args()
    raise SystemExit(finalize_verification(args.passed, args.failed, args.compile, args.ruff)
                     if args.finalize_verification else run())
