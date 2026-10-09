from datetime import UTC, datetime

from src.agents.state import AgentState
from src.analyzers.content_analyzer import ContentResult, RedactedContent
from src.evidence.models import Evidence
from src.schemas.tool import ToolResult
from src.services.enrichment import ExternalServices
from src.services.external import controlled_call
from src.services.ioc_store import normalize_ioc
from src.services.rag import RetrievedChunk
from src.services.urlscan import URLReport
from src.services.virustotal import FileReputation


def external_finding(tool, signal, indicator, value, result, *, status="OK", confidence=1.0, source="external"):
    return Evidence(
        analyzer=tool,
        tool=tool,
        signal_type=signal,
        family="content_bec" if source == "llm" else "threat_intel",
        indicator=indicator,
        value=value,
        result=result,
        tool_status=status,
        severity="high" if result == "FAIL" else "info",
        confidence=confidence,
        provenance={"source": source, "reference": f"{tool}:lookup:v1"},
        collected_at=datetime.now(UTC),
    )


def checked_result(provider, operation, model):
    """Contain even an injected client's exceptions/schema mistakes."""
    wrapped = controlled_call(provider, lambda: ToolResult[model].model_validate(operation().model_dump()))
    return wrapped.data if wrapped.status == "OK" else wrapped


def enrichment_node(state: AgentState, *, services: ExternalServices) -> dict:
    output, runs = [], []
    urls, hashes = set(), set()
    # Static analyzers already canonicalize URL and attachment facts, including decoded QR URLs.
    for item in state.get("evidence", []):
        if not isinstance(item.value, dict):
            continue
        for key, kind, destination in (("canonical_url", "url", urls), ("sha256", "hash", hashes)):
            if isinstance(item.value.get(key), str):
                try:
                    destination.add(normalize_ioc(kind, item.value[key]))
                except ValueError:
                    pass
        # Benign URLs have no heuristic failure/canonical_url fact. Their exact-match
        # check still binds the URL; this includes benign QR payload URLs as well.
        if item.value.get("kind") == "url" and isinstance(item.value.get("indicator"), str):
            try:
                urls.add(normalize_ioc("url", item.value["indicator"]))
            except ValueError:
                pass

    def add_report(tool, signal, indicator, response, *, known, malicious=False):
        value = (
            response.data.model_dump(mode="json") if response.data is not None else {"error_code": response.error_code}
        )
        result = "PASS" if response.status == "OK" and known else "UNKNOWN"
        output.append(external_finding(tool, signal, indicator, value, result, status=response.status))
        if response.status == "OK" and known and malicious:
            # Exact canonical provider hit uses the existing IOC_MATCH policy, never new weights.
            output.append(
                external_finding(
                    tool,
                    "IOC_MATCH",
                    indicator,
                    {**value, "kind": "hash" if tool == "virustotal" else "url", "value": indicator},
                    "FAIL",
                    confidence=0.95,
                )
            )

    for digest in sorted(hashes)[: services.max_hashes]:
        response = checked_result("VT", lambda: services.virustotal.lookup_hash(digest), FileReputation)
        if response.data is not None and response.data.sha256 != digest:
            response = ToolResult(status="ERROR", error_code="VT_NON_EXACT_RESPONSE", latency_ms=0)
        report = response.data
        known = report is not None and report.malicious + report.suspicious + report.harmless + report.undetected > 0
        add_report(
            "virustotal",
            "ATTACHMENT_IOC_CHECK",
            digest,
            response,
            known=known,
            malicious=report is not None and report.malicious > 0,
        )
    for url in sorted(urls)[: services.max_urls]:
        response = checked_result("URLSCAN", lambda: services.urlscan.lookup_url(url), URLReport)
        if response.data is not None and response.data.scanned_url != url:
            response = ToolResult(status="ERROR", error_code="URLSCAN_NON_EXACT_RESPONSE", latency_ms=0)
        report = response.data
        add_report(
            "urlscan",
            "URL_IOC_CHECK",
            url,
            response,
            known=report is not None and report.malicious is not None,
            malicious=report is not None and report.malicious is True,
        )
    for tool, values, limit, signal in (
        ("virustotal", hashes, services.max_hashes, "ATTACHMENT_IOC_CHECK"),
        ("urlscan", urls, services.max_urls, "URL_IOC_CHECK"),
    ):
        if len(values) > limit:
            output.append(
                external_finding(
                    tool, signal, f"{tool}:budget", {"error_code": "ENRICHMENT_LIMIT"}, "UNKNOWN", status="ERROR"
                )
            )
        facts = [item for item in output if item.analyzer == tool]
        if facts:
            runs.append({"analyzer": tool, "status": "PARTIAL" if any(e.result == "UNKNOWN" for e in facts) else "OK"})

    if state.get("privacy_errors") or state.get("redacted_for_llm") is None:
        content = ToolResult(status="ERROR", error_code="PII_REDACTION_UNAVAILABLE", latency_ms=0)
    else:
        redacted = state["redacted_for_llm"]
        # Bounded redacted content, no raw headers/attachment data or binary payloads.
        text = "\n".join(str(redacted.get(key, "")) for key in ("subject", "text_body", "html_body"))
        if len(text) > 64000:
            content = ToolResult(status="ERROR", error_code="CONTENT_LIMIT", latency_ms=0)
        else:
            content = checked_result(
                "LLM",
                lambda: services.content.analyze(
                    RedactedContent(text=text, redaction_reference=state["redaction_policy"])
                ),
                ContentResult,
            )
    facts = content.data.evidence if content.status == "OK" and content.data is not None else ()
    if not facts or any(item.provenance.source != "llm" or item.signal_type != "BEC_REQUEST" for item in facts):
        status = content.status if content.status != "OK" else "ERROR"
        facts = (
            external_finding(
                "content_bec",
                "BEC_REQUEST",
                "redacted:content_bec",
                {"error_code": content.error_code or "LLM_INVALID_RESPONSE"},
                "UNKNOWN",
                status=status,
                source="llm",
            ),
        )
    output.extend(facts)
    runs.append({"analyzer": "content_bec", "status": "PARTIAL" if any(e.result == "UNKNOWN" for e in facts) else "OK"})
    return {
        "evidence": output,
        "applicable_signals": sorted({item.signal_type for item in output}),
        "analyzer_runs": runs,
        "external_enrichment": True,
    }


def rag_node(state: AgentState, *, services: ExternalServices) -> dict:
    # Query is fixed metadata from validated facts, never raw email/PII/IOC content.
    query = "SOC playbook " + " ".join(sorted({item.family for item in state.get("validated_evidence", [])}))
    response = checked_result("RAG", lambda: services.rag.retrieve(query), tuple[RetrievedChunk, ...])
    # RAGService validates chunks itself. No RAG failure changes evidence/score/coverage.
    context = response.data if response.status == "OK" and response.data is not None else ()
    return {"rag_context": context, "rag_status": response.status}
