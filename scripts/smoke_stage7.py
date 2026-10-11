"""Five synthetic Stage 7 graph cases; bounded real generation and read-only RAG.

Never loads DEV/TEST manifests, ingests data, uploads files, or submits URLs.
Run explicitly: python -m scripts.smoke_stage7
"""

import argparse
import asyncio
import hashlib
import json
import sqlite3
from dataclasses import replace
from email.message import EmailMessage
from pathlib import Path

from src.agents.graph import build_graph
from src.config import get_settings
from src.schemas.analysis import AnalysisResponse
from src.services.enrichment import ExternalServices
from src.services.ioc_index import SQLiteIOCClient, resolve_path
from src.services.llm import LLMClient
from src.services.rag import RAGService
from src.services.urlscan import URLScanClient
from src.services.verdict import LLMVerdictProvider
from src.services.virustotal import VirusTotalClient

ROOT = Path(__file__).resolve().parents[1]


def inventory():
    digest = hashlib.sha256()
    for path in sorted((ROOT / "data").rglob("*")):
        if path.is_file():
            stat = path.stat()
            digest.update(f"{path.relative_to(ROOT)}:{stat.st_size}:{stat.st_mtime_ns}".encode())
    return digest.hexdigest()


def email(body, subject="Stage 7 synthetic smoke"):
    message = EmailMessage()
    message["From"], message["To"] = "support@example.test", "analyst@recipient.test"
    message["Subject"] = subject
    message.set_content(body)
    return message.as_bytes()


async def run(*, retry_failed=False):
    settings = get_settings()
    before, c4 = inventory(), (ROOT / "config/risk_weights.yaml").read_bytes()
    client = SQLiteIOCClient(settings.ioc_data_path, settings.ioc_index_path)
    services = ExternalServices.from_settings(settings)
    verdict = LLMVerdictProvider(LLMClient.from_settings(settings))
    rag = RAGService.from_settings(settings)
    report = {"scope": "five synthetic cases only; NOT DEV/TEST evaluation or production benchmark",
              "configured": {"openai": bool(settings.openai_api_key),
                             "virustotal": bool(settings.virustotal_api_key), "urlscan": bool(settings.urlscan_api_key)},
              "rag_queries": [], "external_smokes": {}, "cases": []}
    output = ROOT / "eval/results/stage7_smoke.json"
    prior = json.loads(output.read_text(encoding="utf-8")) if retry_failed else None
    if prior is not None:
        report["rag_queries"], report["external_smokes"] = prior["rag_queries"], prior["external_smokes"]
        report["initial_attempt"] = prior
    # Exactly one harmless provider lookup when a key exists; no active scan/upload.
    for provider, configured, operation in (
        ("virustotal", settings.virustotal_api_key, lambda: VirusTotalClient.from_settings(
            settings.model_copy(update={"virustotal_enabled": True})).lookup_hash(hashlib.sha256(b"").hexdigest())),
        ("urlscan", settings.urlscan_api_key, lambda: URLScanClient.from_settings(
            settings.model_copy(update={"urlscan_enabled": True})).lookup_url("https://example.com/")),
    ):
        if retry_failed:
            continue
        if configured:
            result = operation()
            report["external_smokes"][provider] = result.model_dump(mode="json")
        else:
            report["external_smokes"][provider] = {"status": "NOT RUN — KEY NOT CONFIGURED"}
    # Optional intel providers are disabled for five graph cases to respect the
    # one-lookup real-provider budget above. Their graph path is tested offline.
    services = replace(services, virustotal_enabled=False, urlscan_enabled=False)
    for source, query in (("MITRE ATT&CK", "MITRE ATT&CK T1566 phishing spearphishing email"),
                          ("NIST", "NIST incident response phishing detection containment recovery")):
        if retry_failed:
            continue
        try:
            hits = rag.repository.search(query, limit=3, source=source)
            report["rag_queries"].append({"source": source, "status": "OK",
                "hits": [{"chunk_id": h.chunk_id, "document_id": h.document_id,
                          "source": h.source, "source_url": h.source_url, "score": h.score} for h in hits]})
        except Exception as exc:
            report["rag_queries"].append({"source": source, "status": "ERROR", "exception_type": type(exc).__name__})
        print(json.dumps({"rag_smoke": source, "status": report["rag_queries"][-1]["status"]}), flush=True)
    with sqlite3.connect(resolve_path(settings.ioc_index_path).as_uri() + "?mode=ro", uri=True) as connection:
        row = connection.execute("SELECT canonical_value FROM records WHERE kind='url' AND role='MALICIOUS' "
                                 "AND canonical_value IS NOT NULL LIMIT 1").fetchone()
    fixtures = ROOT / "tests/fixtures/emails"
    cases = (
        ("local_ioc", email("This inert fixture references an IOC, never open it: " + row[0])),
        ("attachment_hash", (fixtures / "suspicious_attachment.eml").read_bytes()),
        ("bec_positive", email("I am the CEO. Urgently transfer payment to our new bank account today. "
            "Do not call me or tell anyone. Confirm with alice@example.test or 0912 345 678.", "Urgent CEO bank change")),
        ("neutral", (fixtures / "clean.eml").read_bytes()),
        ("rag_context", email("SOC analyst checklist: review phishing T1566 and NIST incident response guidance.")),
    )
    graph = build_graph(ioc_client=client, external_services=services, rag_service=rag, verdict_provider=verdict)
    baseline = build_graph(ioc_client=client)
    for name, raw in cases:
        if prior is not None:
            old = next(row for row in prior["cases"] if row["name"] == name)
            if old["gate1"] and old["gate2"] and all(e["status"] == "OK" for e in old["bec"]):
                report["cases"].append(old)
                continue
        base = await baseline.ainvoke({"raw_email": raw})
        state = await graph.ainvoke({"raw_email": raw, "case_id": "stage7-" + name})
        response = AnalysisResponse.from_agent_state(state)
        bec = [e for e in response.evidence if e.family == "content_bec"]
        row = {"name": name, "response": response.model_dump(mode="json"),
               "bec": [{"result": e.result, "status": e.tool_status, "signals": e.value} for e in bec],
               "baseline_score": base["risk_score"], "baseline_label": base["risk_result"].label_candidate,
               "gate1": not state["evidence_validation"].issues,
               "gate2": state["claims_valid"], "raw_pii_preserved": "alice@example.test" in str(state["parsed_email"])
               if name == "bec_positive" else None}
        if bec and all(e.result == "PASS" for e in bec):
            row["c4_parity"] = (response.score == base["risk_score"] and
                                response.label_candidate == base["risk_result"].label_candidate)
        report["cases"].append(row)
        print(json.dumps({"case": name, "score": response.score, "label": response.label_candidate,
                          "verdict": response.verdict_llm_status, "gate2": row["gate2"]}), flush=True)
    report["real_llm_calls"] = {
        "bec": services.content.llm.model.call_count if services.content.llm.model else 0,
        "verdict": verdict.llm.model.call_count if verdict.llm.model else 0,
    }
    report["query_embedding_calls"] = rag.repository.embedding.batch_count
    if prior is not None:
        report["real_llm_calls"] = {key: value + prior["real_llm_calls"][key]
                                    for key, value in report["real_llm_calls"].items()}
        report["query_embedding_calls"] += prior["query_embedding_calls"]
    report["qdrant"] = rag.repository.verify(dimension=1536, full=False)
    # Provider URL is configuration metadata; do not persist it in public smoke artifacts.
    report["qdrant"]["identity"].pop("embedding_provider", None)
    report["local_ioc_records"] = client.metadata.get("record_count")
    report["data_modified"] = inventory() != before
    report["c4_modified"] = (ROOT / "config/risk_weights.yaml").read_bytes() != c4
    report["test_executed"] = 0
    report["pass"] = (
        all(row["gate1"] and row["gate2"] and row.get("c4_parity", True) for row in report["cases"])
        and all(q["status"] == "OK" and q["hits"] for q in report["rag_queries"])
        and any(e["result"] == "FAIL" for row in report["cases"] if row["name"] == "bec_positive" for e in row["bec"])
        and all(e["result"] == "PASS" for row in report["cases"] if row["name"] == "neutral" for e in row["bec"])
        and not report["data_modified"] and not report["c4_modified"]
    )
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"report": str(output), "pass": report["pass"], "real_llm_calls": report["real_llm_calls"],
                      "query_embedding_calls": report["query_embedding_calls"]}), flush=True)
    return int(not report["pass"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--retry-failed", action="store_true", help="Reuse prior successes; only retry failed cases")
    raise SystemExit(asyncio.run(run(retry_failed=parser.parse_args().retry_failed)))
