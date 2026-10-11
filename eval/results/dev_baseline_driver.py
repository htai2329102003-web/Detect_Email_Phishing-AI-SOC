"""Measurement artifact: current configured graph, DEV only, frozen inputs."""

import asyncio
import hashlib
import json
import sys
import tempfile
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter

PROJECT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT))

from eval.capability import load_catalog
from eval.capability_adapters import AnalyzerAdapter
from eval.manifest import ManifestEntry, _invalid_constant, _unique_object
from eval.metrics import LABEL_POLICY, percentile, ratio, summarize
from eval.run_capabilities import summarize_capabilities
from eval.run_eval import evaluate_case
from eval.schemas import EvalCase
from eval.targets import Observation, RecordingVerdict, audit_proposals
from src.agents.graph import build_graph
from src.config import get_settings
from src.schemas.analysis import AnalysisResponse
from src.services.enrichment import ExternalServices
from src.services.ioc_index import SQLiteIOCClient
from src.services.qdrant_repository import QdrantKnowledgeRepository
from src.services.rag import RAGService
from src.services.verdict import DeterministicVerdictProvider

ROOT = PROJECT / "data"
OUTPUT = PROJECT / "eval/results"
EXCLUDED = {
    "e2a_recov_766d1b32", "e2a_recov_cde83d5b",
    "e2a_recov_3605149c", "e2a_recov_c3cfdcc0",
}


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def save(name, value):
    (OUTPUT / name).write_text(json.dumps(value, ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8")


def snapshot():
    # Metadata only: never open the quarantined samples.
    return {str(p.relative_to(ROOT)): (s.st_size, s.st_mtime_ns)
            for p in ROOT.rglob("*") if p.is_file() for s in [p.stat()]}


class MeasuredIOC:
    def __init__(self, settings):
        self.client = SQLiteIOCClient(settings.ioc_data_path, settings.ioc_index_path)
        self.calls = 0
        self.errors = Counter()

    def lookup(self, kind, value):
        self.calls += 1
        result = self.client.lookup(kind, value)
        if result.status != "OK":
            self.errors[result.error_code or result.status] += 1
        return result


class ProductionTarget:
    def __init__(self, settings, ioc):
        self.ioc = ioc
        self.provider = RecordingVerdict(DeterministicVerdictProvider())
        self.services = ExternalServices.from_settings(settings) if settings.external_enrichment_enabled else None
        self.rag = RAGService.from_settings(settings) if settings.rag_enabled else None
        self.graph = build_graph(ioc_client=ioc, external_services=self.services,
                                 rag_service=self.rag, verdict_provider=self.provider)
        self.details = {}
        self.runtime = Counter()
        self.tool_failures = Counter()

    async def analyze(self, raw, case):
        self.provider.proposals.clear()
        state = await self.graph.ainvoke({"case_id": case.id, "raw_email": raw, "evidence": [], "errors": []})
        response = AnalysisResponse.from_agent_state(state)
        evidence = [{"id": e.evidence_id, "type": e.signal_type, "family": e.family,
                     "result": e.result, "tool_status": e.tool_status} for e in response.evidence]
        failed = [e for e in response.evidence if e.tool_status != "OK"]
        for e in failed:
            code = e.value.get("error_code") if isinstance(e.value, dict) else None
            self.tool_failures[(e.tool, e.tool_status, code or "UNSPECIFIED")] += 1
        self.runtime["cases_with_failed_tool_checks"] += bool(failed)
        self.runtime["graph_error_cases"] += bool(state.get("errors"))
        self.runtime["verdict_error_cases"] += bool(state.get("verdict_errors"))
        self.runtime["privacy_error_cases"] += bool(state.get("privacy_errors"))
        self.runtime["rag_retrieval_calls"] += "rag_status" in state
        self.runtime["rag_failure_calls"] += state.get("rag_status") not in {None, "OK"}
        self.details[case.id] = {"evidence": evidence, "errors": state.get("errors", []),
                                 "rag_status": state.get("rag_status"),
                                 "analyzer_runs": state.get("analyzer_runs", [])}
        return Observation(response=response, state=state,
                           claim_audits=audit_proposals(self.provider.proposals, state))


def preflight(settings):
    OUTPUT.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryFile(dir=OUTPUT):
        pass
    version = json.loads((ROOT / "DATASET_VERSION_1_1_1.json").read_text(encoding="utf-8"))["version"]
    if version != "1.1.1":
        raise ValueError("DATASET_VERSION_MISMATCH")
    rows = []
    with (ROOT / "manifests/dev_manifest.jsonl").open(encoding="utf-8-sig") as stream:
        for line, text in enumerate(stream, 1):
            if text.strip():
                rows.append((line, json.loads(text, parse_constant=_invalid_constant, object_pairs_hook=_unique_object)))
    counts = Counter(row["expected_label"] for _, row in rows)
    if len(rows) != 3462 or counts != {"SAFE": 2750, "PHISHING": 712}:
        raise ValueError("CANONICAL_DEV_COUNT_MISMATCH")
    ids = [row["id"] for _, row in rows]
    if len(set(ids)) != len(ids) or not EXCLUDED.issubset(ids):
        raise ValueError("DUPLICATE_IDS_OR_QUARANTINE_ID_MISMATCH")
    entries, hashes, missing, metadata_adapted = [], defaultdict(list), [], 0
    for line, row in rows:
        if row["id"] in EXCLUDED:
            if row["expected_label"] != "PHISHING":
                raise ValueError("QUARANTINE_LABEL_MISMATCH")
            continue
        path = (ROOT / row["file"]).resolve()
        if not path.is_relative_to(ROOT) or not path.is_file():
            missing.append({"id": row["id"], "file": row["file"]})
            continue
        hashes[sha(path)].append(row["id"])
        adapted = dict(row)
        if not row.get("capabilities"):
            # Schema bridge for grouping only; this field never configures the graph.
            adapted["capabilities"] = ["core"]
            metadata_adapted += 1
        case = EvalCase.model_validate(adapted)
        if case.profile is not None or case.ioc_records or case.injection is not None:
            raise ValueError("UNEXPECTED_CASE_PROVIDER_OR_INJECTION_OVERRIDE")
        entries.append(ManifestEntry(line, case.id, case=case))
    duplicates = [value for value in hashes.values() if len(value) > 1]
    report = {"version": version, "canonical": len(rows), "labels": dict(counts),
              "known_quarantine_ids": sorted(EXCLUDED), "executable": len(entries),
              "unexpected_broken_paths": missing, "duplicate_physical_samples": duplicates,
              "empty_capabilities_grouped_as_core_in_memory": metadata_adapted,
              "output_writable": True, "manifest_sha256": sha(ROOT / "manifests/dev_manifest.jsonl"),
              "providers": {"rag_enabled": settings.rag_enabled,
                            "external_enrichment_enabled": settings.external_enrichment_enabled,
                            "llm_key_present": bool(settings.openai_api_key),
                            "llm_provider_wired": False,
                            "embedding_endpoint_present": bool(settings.embedding_base_url),
                            "embedding_model_present": bool(settings.embedding_model),
                            "embedding_credential_present": bool(settings.embedding_api_key.get_secret_value() or settings.openai_api_key)}}
    save("dev_baseline_preflight.json", report)
    if missing or duplicates or len(entries) != 3458:
        raise ValueError("DEV_INPUT_INTEGRITY_BLOCKED: see dev_baseline_preflight.json")
    ioc = MeasuredIOC(settings)
    check = ioc.client.lookup("domain", "example.org")
    report["ioc"] = {"status": check.status, "error_code": check.error_code,
                     "record_count": ioc.client.metadata.get("record_count")}
    repo = QdrantKnowledgeRepository.from_settings(settings)
    try:
        info = repo.qdrant.request("GET")
        manifest = repo.manifest()
        report["qdrant"] = {"status": "PASS", "collection_status": info.get("status"),
                            "total_points": repo.qdrant.count(),
                            "chunk_points": repo.qdrant.count((("record_type", "chunk"),)),
                            "manifest_complete": bool(manifest and manifest.get("state") == "complete"),
                            "graph_rag_enabled": settings.rag_enabled}
    except Exception as exc:
        report["qdrant"] = {"status": "FAIL", "exception_type": type(exc).__name__,
                            "graph_rag_enabled": settings.rag_enabled}
    finally:
        repo.qdrant.close()
    save("dev_baseline_preflight.json", report)
    print("PREFLIGHT", json.dumps(report), flush=True)
    if check.status != "OK":
        raise ValueError("IOC_PREFLIGHT_FAILED")
    return entries, ioc, report


async def main():
    settings = get_settings()
    initial = snapshot()
    entries, ioc, checks = preflight(settings)
    target = ProductionTarget(settings, ioc)
    records = []
    started = perf_counter()
    for index, entry in enumerate(entries, 1):
        records.append(await evaluate_case(entry, target, ROOT, "offline"))
        if index % 100 == 0 or index == len(entries):
            print("CORE_PROGRESS", index, "/", len(entries), "elapsed_seconds", round(perf_counter()-started, 2), flush=True)
    core_seconds = perf_counter() - started
    stats = summarize(records)
    c = stats["classification_counts"]
    stats["accuracy"] = ratio(c["tp"] + c["tn"], c["tp"] + c["tn"] + c["fp"] + c["fn"]).model_dump()
    stats["false_negative_rate"] = ratio(c["fn"], c["tp"] + c["fn"]).model_dump()
    native = dict(Counter(r.predicted_label if r.status == "success" else "NO_PREDICTION_EXECUTION_ERROR" for r in records))
    safe_errors = {}
    for kind in ("false_negatives", "false_positives"):
        sample = []
        for r in records:
            matches = (r.status == "success" and ((r.expected_label == "PHISHING" and r.predicted_label in {"SAFE", "SUSPICIOUS"})
                       if kind == "false_negatives" else (r.expected_label == "SAFE" and r.predicted_label == "PHISHING")))
            if matches and len(sample) < 10:
                sample.append({"sample_id": r.case_id, "expected_label": r.expected_label,
                               "predicted_label": r.predicted_label, "risk_score": r.score,
                               "evidence": target.details.get(r.case_id, {}).get("evidence", []),
                               "reason": "deterministic label disagrees with source label; no tuning performed"})
        safe_errors[kind] = sample
    catalog = load_catalog(ROOT)
    cap_results = []
    adapter = AnalyzerAdapter(ioc_client=ioc)
    cap_start = perf_counter()
    selected = [case for case in catalog if case.split == "dev" and case.capability in {"auth_header", "attachment"}
                and case.sample_id not in EXCLUDED]
    for index, case in enumerate(selected, 1):
        cap_results.append(await adapter.evaluate(case, ROOT))
        if index % 100 == 0:
            print("CAPABILITY_PROGRESS", index, "/", len(selected), flush=True)
    capabilities = summarize_capabilities(cap_results)
    for name in {"auth_header", "attachment"}:
        results = [r for r in cap_results if r.case.capability == name]
        capabilities.setdefault(name, {})["routing"] = "RUN_DEV_BASELINE"
        capabilities[name]["executed"] = len(results)
        capabilities[name]["explicit_evidence_oracle_cases"] = sum(bool(r.case.expected_signals) for r in results)
    for name in ("vietnamese_url", "bec", "qr_analyzer"):
        capabilities[name] = {"routing": "NO_DEV_SPLIT", "executed": 0, "metrics": None,
                              "reason": "aggregate capability manifest has no explicit DEV/non-holdout split"}
    capabilities["prompt_injection"] = {"routing": "ORACLE_INSUFFICIENT", "records": 3149,
                                        "executed": 0, "asr_oracle": "PARTIAL", "asr_conclusive": False,
                                        "asr": {"value": None, "numerator": 0, "denominator": 0}}
    current = snapshot()
    changed = sorted(k for k in set(initial) | set(current) if initial.get(k) != current.get(k))
    source_hashes = {str(p.relative_to(PROJECT)): sha(p) for folder in ("src", "eval", "config")
                     for p in (PROJECT/folder).rglob("*.py" if folder != "config" else "*.yaml")
                     if "results" not in p.parts and "__pycache__" not in p.parts}
    failures = [{"tool": k[0], "status": k[1], "error_code": k[2], "count": v}
                for k, v in target.tool_failures.items()]
    baseline_valid = not changed and len(records) == 3458 and all(r.status == "success" for r in records) and not ioc.errors
    report = {"dataset_version": "1.1.1", "timestamp": datetime.now(UTC).isoformat(),
              "scope": "first CORE DEV baseline under current configured production graph; not a production benchmark",
              "project_state_sha256": hashlib.sha256(json.dumps(source_hashes, sort_keys=True).encode()).hexdigest(),
              "source_hashes": source_hashes, "preflight": checks, "label_policy": LABEL_POLICY,
              "profile_note": "PredictionRecord profile=offline is the existing schema value; actual graph uses current settings and production SQLiteIOCClient, no fake providers",
              "coverage": {"canonical": 3462, "canonical_safe": 2750, "canonical_phishing": 712,
                           "executed": len(records), "executed_safe": 2750, "executed_phishing": 708,
                           "security_quarantine_skipped": 4, "other_skipped": 0,
                           "ratio": ratio(len(records), 3462).model_dump(), "test_executed": 0},
              "skipped": [{"sample_id": sid, "status": "SKIPPED_UNAVAILABLE_SECURITY_QUARANTINE"} for sid in sorted(EXCLUDED)],
              "summary": stats, "native_labels": native,
              "evidence_oracle_cases": sum(bool(r.expected_signals) for r in records),
              "empty_oracle_cases_excluded": True, "evidence_precision": None,
              "capabilities": capabilities, "capability_cases": [r.model_dump(mode="json", exclude={"case": {"payload"}}) for r in cap_results],
              "infrastructure": {"ioc_calls": ioc.calls, "ioc_errors": dict(ioc.errors),
                                 "rag_enabled": settings.rag_enabled, "external_enrichment_enabled": settings.external_enrichment_enabled,
                                 "llm_generation_calls": 0, "llm_provider": "NOT USED", "runtime": dict(target.runtime),
                                 "tool_failures": failures},
              "performance": {"core_seconds": core_seconds, "capability_seconds": perf_counter()-cap_start,
                              "mean_latency_ms": sum(r.latency_ms or 0 for r in records)/len(records),
                              "p50_latency_ms": percentile([r.latency_ms for r in records if r.latency_ms is not None], .5),
                              "p95_latency_ms": percentile([r.latency_ms for r in records if r.latency_ms is not None], .95)},
              "error_analysis_sample": safe_errors,
              "known_limitations": ["Four quarantined DEV cases excluded; canonical denominator retained",
                                    "SAFE/SUSPICIOUS negative projection is selective; NEEDS_ANALYST_REVIEW remains abstention",
                                    "RAG and external enrichment disabled by current settings; generation key presence does not wire an LLM provider",
                                    "Vietnamese URL, BEC and QR have no explicit DEV split; no full capability baseline run",
                                    "Prompt-injection oracle partial; static ASR null with denominator zero"],
              "data_safety": {"data_modified": bool(changed), "changed_paths": changed,
                              "manifests_modified": any(k.startswith("manifests/") for k in changed), "test_evaluated": False},
              "baseline_complete": len(records) == 3458, "baseline_valid": baseline_valid,
              "cases": [r.model_dump(mode="json") for r in records], "safe_evidence": target.details}
    save("dev_baseline.json", report)
    print("BASELINE_SAVED", OUTPUT/"dev_baseline.json", flush=True)
    print("SUMMARY", json.dumps({"summary": stats, "native_labels": native, "coverage": report["coverage"],
                                  "capabilities": capabilities, "performance": report["performance"],
                                  "baseline_valid": baseline_valid, "data_changed": changed}), flush=True)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as exc:
        print("BASELINE_BLOCKED", type(exc).__name__, str(exc) if isinstance(exc, ValueError) else "exception text withheld", flush=True)
        raise SystemExit(1)
