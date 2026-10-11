"""Bounded capability smoke only: never runs full DEV/TEST evaluation."""

import argparse
import asyncio
import json
from pathlib import Path

from eval.capability import CapabilityResult, load_catalog, verify_catalog
from eval.capability_adapters import AnalyzerAdapter
from eval.metrics import attack_success_rate, percentile, ratio
from eval.targets import GraphTarget
from src.analyzers.content_analyzer import StructuredContentAnalyzer
from src.config import get_settings
from src.services.ioc_index import SQLiteIOCClient
from src.services.llm import ConfiguredStructuredModel, LLMClient


def select_smoke(cases):
    selected = []
    for capability, labels in (("vietnamese_url", ("PHISHING", "SAFE")), ("bec", ("positive", "neutral")),
                              ("qr_analyzer", ("PHISHING", "SAFE")), ("prompt_injection", (None,)),
                              ("auth_header", (None,)), ("attachment", (None,))):
        for label in labels:
            case = next((case for case in cases if case.capability == capability and
                         case.split not in {"test", "auxiliary"} and
                         (label is None or case.expected_label == label)), None)
            if case is not None:
                selected.append(case)
    return selected


def summarize_capabilities(results: list[CapabilityResult]) -> dict:
    groups = {}
    for capability in sorted({r.case.capability for r in results}):
        rows = [r for r in results if r.case.capability == capability]
        valid = [r for r in rows if r.status not in {"ERROR", "UNAVAILABLE"}]
        outcome = {"evaluated": len(rows), "execution_errors": sum(r.status == "ERROR" for r in rows),
                   "unavailable": sum(r.status == "UNAVAILABLE" for r in rows),
                   "unknown": sum(r.status == "UNKNOWN" for r in rows)}
        outcome["failed_tool_checks"] = sum(e.tool_status != "OK" for r in rows for e in r.evidence)
        latencies = [r.latency_ms for r in valid]
        outcome.update(latency_mean_ms=sum(latencies)/len(latencies) if latencies else None,
                       latency_p50_ms=percentile(latencies, .5), latency_p95_ms=percentile(latencies, .95))
        if capability in {"vietnamese_url", "bec", "qr_analyzer"}:
            positive = {"PHISHING"} if capability != "bec" else {"positive"}
            negative = {"SAFE", "BENIGN"} if capability != "bec" else {"neutral"}
            # SPAM/MIXED/PROMPT_INJECTION and unknown predictions are excluded, never relabeled.
            decided = [r for r in valid if r.predicted_positive is not None and
                       r.case.expected_label in positive | negative]
            tp = sum(r.predicted_positive and r.case.expected_label in positive for r in decided)
            fp = sum(r.predicted_positive and r.case.expected_label in negative for r in decided)
            fn = sum(not r.predicted_positive and r.case.expected_label in positive for r in decided)
            tn = sum(not r.predicted_positive and r.case.expected_label in negative for r in decided)
            outcome.update(tp=tp, tn=tn, fp=fp, fn=fn, excluded=len(rows)-len(decided),
                precision=ratio(tp, tp+fp).model_dump(), recall=ratio(tp, tp+fn).model_dump(),
                f1=ratio(2*tp, 2*tp+fp+fn).model_dump(), false_positive_rate=ratio(fp, fp+tn).model_dump(),
                decision_coverage=ratio(len(decided), len(rows)).model_dump())
        if capability == "prompt_injection":
            attacks = [r.observations.get("attack", {}).get("attack_success") for r in rows]
            outcome["prompt_injection_asr"] = attack_success_rate(attacks).model_dump()
            outcome["inconclusive"] = sum(x is None for x in attacks)
            outcome["asr_policy"] = "existing end-to-end rule/analyzer integrity oracle; unavailable excluded"
        if capability in {"auth_header", "attachment"}:
            matches = sum(sum(r.case.expected_results.get(s, "FAIL") in
                {e.result for e in r.evidence if e.signal_type == s} for s in set(r.case.expected_signals)) for r in valid)
            denominator = sum(len(set(r.case.expected_signals)) for r in rows)
            outcome["evidence_recall"] = ratio(matches, denominator).model_dump()
            outcome["known_evidence_coverage"] = ratio(sum(e.result != "UNKNOWN" and e.tool_status == "OK"
                for r in valid for e in r.evidence), sum(len(r.evidence) for r in valid)).model_dump()
            outcome["no_evidence_oracle_cases"] = sum(not r.case.expected_signals for r in rows)
        groups[capability] = outcome
    return groups


async def run_smoke(root: Path, adapter: AnalyzerAdapter) -> dict:
    version = json.loads((root/"DATASET_VERSION_1_1_1.json").read_text(encoding="utf-8"))["version"]
    if version != "1.1.1":
        raise ValueError("DATASET_VERSION_MISMATCH")
    cases = load_catalog(root)
    verification = verify_catalog(cases, root)
    results = []
    for case in select_smoke(cases):
        if verification[case.capability]["blocked"]:
            result = CapabilityResult(case=case, execution_target="blocked before analyzer",
                status="UNAVAILABLE", error_code="CANONICAL_DATA_BLOCKED",
                observations={"blockers": verification[case.capability]["blockers"]})
        else:
            result = await adapter.evaluate(case, root)
        results.append(result)
    return {"data_version": version,
            "scope": "bounded capability smoke; NOT full DEV/TEST or production benchmark",
            "core_metrics": "SEPARATE / NOT RUN", "verification": verification,
            "capabilities": summarize_capabilities(results),
            "results": [r.model_dump(mode="json", exclude={"case": {"payload"}}) for r in results]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("data"))
    parser.add_argument("--output", type=Path, default=Path("eval/results/capability-smoke.json"))
    parser.add_argument("--bec-llm", action="store_true", help="Explicitly enable configured BEC LLM (2 samples)")
    args = parser.parse_args(argv)
    project = Path(__file__).resolve().parents[1]
    output = args.output.resolve()
    if any(output.is_relative_to(path.resolve()) for path in [args.root, *(project/name for name in
            ("data", "src", "config", "tests", "frontend"))]) or output.suffix != ".json":
        parser.error("JSON report must be outside frozen data and production/test source")
    settings = get_settings()
    client = SQLiteIOCClient(settings.ioc_data_path, settings.ioc_index_path)
    adapter = AnalyzerAdapter(ioc_client=client, security_target=GraphTarget(ioc_client=client),
        content=StructuredContentAnalyzer(LLMClient(ConfiguredStructuredModel(settings),
            timeout=settings.llm_timeout_seconds)) if args.bec_llm else None)
    try:
        report = asyncio.run(run_smoke(args.root.resolve(), adapter))
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False)+"\n", encoding="utf-8")
    except Exception as exc:
        print(json.dumps({"error": "CAPABILITY_SMOKE_FAILED", "exception_type": type(exc).__name__}))
        return 2
    print(json.dumps({"output": str(args.output), "cases": len(report["results"]),
        "verification": report["verification"], "capabilities": report["capabilities"]}))
    return int(any(r["status"] in {"ERROR", "UNAVAILABLE"} for r in report["results"]))


if __name__ == "__main__":
    raise SystemExit(main())
