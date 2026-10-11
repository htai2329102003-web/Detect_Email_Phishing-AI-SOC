"""Run JSONL cases against the real graph, with offline/fake integrations only."""

import argparse
import asyncio
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter

from eval.injection import evaluate_attack, inject_email
from eval.manifest import ManifestEntry, load_manifest
from eval.metrics import LABEL_POLICY, capability_metrics, summarize
from eval.schemas import AttackResult, EvalError, EvaluationReport, PredictionRecord
from eval.targets import AnalysisTarget, GraphTarget
from src.config import get_settings
from src.parsers.email_parser import MAX_EMAIL_BYTES, EmailParseError


def read_email(root: Path, filename: str) -> bytes:
    with (root / filename).open("rb") as stream:
        return stream.read(MAX_EMAIL_BYTES + 1)


def failure(exc: Exception, stage="analysis") -> EvalError:
    if stage == "input" and isinstance(exc, FileNotFoundError):
        return EvalError(stage="input", code="FILE_NOT_FOUND", message="Fixture path does not exist")
    if stage == "input" and isinstance(exc, OSError):
        return EvalError(
            stage="input", code="FILE_READ_ERROR", message="Unable to read fixture", exception_type=type(exc).__name__
        )
    if isinstance(exc, EmailParseError):
        return EvalError(stage="analysis", code=exc.code, message="Email parser rejected this fixture")
    return EvalError(
        stage=stage,
        code="ANALYSIS_ERROR" if stage == "analysis" else "OBSERVATION_ERROR",
        message="Evaluation target failed; sensitive exception text withheld",
        exception_type=type(exc).__name__,
    )


async def evaluate_case(entry: ManifestEntry, target: AnalysisTarget, root: Path, profile) -> PredictionRecord:
    if entry.error is not None:
        return PredictionRecord(
            case_id=entry.case_id, manifest_line=entry.line, status="failed", error=entry.error, profile=profile
        )
    case = entry.case
    base = dict(
        case_id=case.id,
        manifest_line=entry.line,
        file=case.file,
        expected_label=case.expected_label,
        expected_signals=case.expected_signals,
        expected_results=case.expected_results,
        capabilities=case.capabilities,
        language=case.language,
        source=case.source,
        metadata=case.metadata,
        profile=case.profile or profile,
    )
    duration, attack, stage = None, None, "input"
    try:
        raw = read_email(root, case.file)
        stage = "analysis"
        baseline, baseline_latency, baseline_error = None, None, None
        if case.injection is not None:
            baseline_stage = "input"
            try:
                baseline_raw = read_email(root, case.injection.baseline_file) if case.injection.baseline_file else raw
                baseline_stage = "analysis"
                started = perf_counter()
                baseline = await target.analyze(baseline_raw, case)
                baseline_latency = (perf_counter() - started) * 1000
            except Exception as exc:
                baseline_error = failure(exc, baseline_stage)
            if case.injection.payload is not None:
                raw = inject_email(raw, case.injection.payload)
        started = perf_counter()
        try:
            observed = await target.analyze(raw, case)
        finally:
            duration = (perf_counter() - started) * 1000
        response = observed.response
        stage = "observation"
        if case.expected_error is not None:
            return PredictionRecord(
                **base,
                status="failed",
                latency_ms=duration,
                error=EvalError(
                    stage="analysis",
                    code="EXPECTED_ERROR_NOT_OBSERVED",
                    message="Analysis succeeded but this case expected an error",
                ),
            )
        if case.injection is not None:
            try:
                attack = (
                    evaluate_attack(case.injection, observed, baseline)
                    if baseline is not None
                    else AttackResult(error=baseline_error)
                )
            except Exception as exc:
                attack = AttackResult(error=failure(exc, "observation"))
            attack = attack.model_copy(update={"baseline_latency_ms": baseline_latency})
        elif "prompt_injection" in case.capabilities:
            attack = AttackResult(
                detected=bool(response.guardrail_signals),
                error=EvalError(
                    stage="observation",
                    code="ATTACK_ORACLE_UNAVAILABLE",
                    message="No paired attack specification supplied",
                ),
            )
        outcomes = {}
        for item in response.evidence:
            outcomes.setdefault(item.signal_type, set()).add(item.result)
        return PredictionRecord(
            **base,
            status="success",
            predicted_label=response.label_candidate,
            assessment_label=response.assessment_label,
            score=response.score,
            analysis_scope=response.analysis_scope,
            requires_review=response.requires_review,
            produced_signals=tuple(sorted(name for name, results in outcomes.items() if "FAIL" in results)),
            signal_results={name: tuple(sorted(results)) for name, results in sorted(outcomes.items())},
            claims=response.claims,
            claim_audits=observed.claim_audits,
            total_claim_count=sum(a.total for a in observed.claim_audits) if observed.claim_audits else None,
            grounded_claim_count=sum(a.grounded for a in observed.claim_audits) if observed.claim_audits else None,
            emitted_claim_count=len(response.claims),
            latency_ms=duration,
            cost_usd=observed.cost_usd,
            cost_source=observed.cost_source,
            coverage_complete=response.coverage.complete,
            attack=attack,
        )
    except Exception as exc:
        error = failure(exc, stage)
        if case.injection is not None or "prompt_injection" in case.capabilities:
            attack = attack or AttackResult(error=error)
        return PredictionRecord(
            **base,
            status="failed",
            error=error,
            latency_ms=duration,
            attack=attack,
            expected_failure=case.expected_error == error.code,
        )


async def run_manifest(
    manifest: Path, *, root: Path, split="dev", profile="offline", target: AnalysisTarget | None = None
) -> EvaluationReport:
    entries = load_manifest(manifest)
    target = target if target is not None else GraphTarget(profile=profile)
    records = [await evaluate_case(entry, target, root, profile) for entry in entries]
    settings = get_settings()
    policy_path = Path(__file__).resolve().parents[1] / "config/risk_weights.yaml"
    return EvaluationReport(
        generated_at=datetime.now(UTC),
        split=split,
        manifest=str(manifest),
        configuration={
            "default_profile": profile,
            "external_real_apis": "NOT TESTED",
            "dataset": "caller-supplied manifest; bundled samples are synthetic dev validation only",
            "production_metrics": "NOT AVAILABLE",
            "network_providers_enabled": False,
            "risk_policy_sha256": hashlib.sha256(policy_path.read_bytes()).hexdigest(),
            "trusted_authserv_ids": settings.header_trusted_authserv_ids,
            "protected_domains": settings.url_protected_domains,
            "manifest_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
            "root": str(root),
            "analysis_timing_excludes": "file I/O, paired baseline, aggregation, serialization",
        },
        label_policy=LABEL_POLICY,
        summary=summarize(records),
        capabilities=capability_metrics(records),
        cases=tuple(records),
    )


def markdown_report(report: EvaluationReport) -> str:
    lines = [
        "# PhishHunter fixture evaluation",
        "",
        "Synthetic fixture/dev validation — NOT a production benchmark.",
        "",
        f"Split: {report.split}. Cases: {report.summary['total_cases']}; successful: {report.summary['successful_cases']}; failed: {report.summary['failed_cases']}.",
        "",
        "Binary positive=PHISHING; negative=SAFE/SUSPICIOUS; review cases are explicit abstentions.",
        "",
        "| Metric | Raw count | Value |",
        "| --- | --- | --- |",
    ]
    for key, value in report.summary.items():
        if isinstance(value, dict) and "numerator" in value:
            displayed = "unavailable" if value["value"] is None else f"{value['value']:.6f}"
            lines.append(f"| {key} | {value['numerator']}/{value['denominator']} | {displayed} |")
    lines += [
        "",
        f"Latency p50: {report.summary['latency_p50_ms']} ms; p95: {report.summary['latency_p95_ms']} ms.",
        f"Cost/email USD: {report.summary['cost_per_email_usd']} (null = unavailable).",
        "",
        "Full JSON includes all case errors, capability groups, claim attempts and attack checks.",
        "",
    ]
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="Base for relative fixture paths")
    parser.add_argument("--split", choices=("dev", "test"), default="dev")
    parser.add_argument(
        "--profile",
        choices=("offline", "fake-success", "fake-bec", "fake-timeout", "fake-unavailable", "fake-ungrounded"),
        default="offline",
    )
    parser.add_argument("--output", type=Path, default=Path("eval/results/latest.json"))
    parser.add_argument("--markdown", type=Path)
    args = parser.parse_args(argv)
    try:
        report = asyncio.run(
            run_manifest(args.manifest, root=args.root.resolve(), split=args.split, profile=args.profile)
        )
        inputs = {
            args.manifest.resolve(),
            *((args.root / record.file).resolve() for record in report.cases if record.file),
            *(
                (args.root / entry.case.injection.baseline_file).resolve()
                for entry in load_manifest(args.manifest)
                if entry.case and entry.case.injection and entry.case.injection.baseline_file
            ),
        }
        if args.output.resolve() in inputs or (args.markdown and args.markdown.resolve() in inputs):
            parser.error("Report output must not overwrite manifest or fixture inputs")
        if args.markdown and args.markdown.resolve() == args.output.resolve():
            parser.error("JSON and Markdown output paths must differ")
        production_roots = [
            (Path(__file__).resolve().parents[1] / name).resolve() for name in ("src", "frontend", "config", "tests")
        ]
        for output in (args.output, args.markdown):
            if output and any(output.resolve().is_relative_to(path) for path in production_roots):
                parser.error("Report output must not overwrite production source, config or test fixtures")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(report.model_dump_json(indent=2) + "\n", encoding="utf-8")
        if args.markdown:
            args.markdown.parent.mkdir(parents=True, exist_ok=True)
            args.markdown.write_text(markdown_report(report), encoding="utf-8")
    except (OSError, ValueError) as exc:
        print(json.dumps({"error": type(exc).__name__, "message": "Unable to load manifest or write report"}))
        return 2
    print(
        json.dumps(
            {
                "output": str(args.output),
                "split": report.split,
                "total_cases": report.summary["total_cases"],
                "successful_cases": report.summary["successful_cases"],
                "failed_cases": report.summary["failed_cases"],
                "unexpected_failures": report.summary["unexpected_failures"],
                "production_metrics": "NOT AVAILABLE",
            }
        )
    )
    return 1 if report.summary["unexpected_failures"] or not report.cases else 0


if __name__ == "__main__":
    raise SystemExit(main())
