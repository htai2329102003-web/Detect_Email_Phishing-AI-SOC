from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from src.agents.graph import build_graph
from src.analyzers.content_analyzer import RedactedContent, StructuredContentAnalyzer
from src.config import get_settings
from src.evidence.risk_engine import score_evidence
from src.schemas.analysis import AnalysisResponse
from src.services.enrichment import ExternalServices
from src.services.external import HTTPXTransport
from src.services.ioc_store import InMemoryIOCStore, IOCRecord
from src.services.llm import LLMClient
from src.services.rag import KnowledgeDocument, RAGService
from src.services.threat_intel import ThreatIntelService
from src.services.urlscan import URLScanClient
from src.services.verdict import DeterministicVerdictProvider
from src.services.virustotal import VirusTotalClient
from tests.external_fakes import FakeKnowledgeRepository, FakeStructuredModel, FakeTransport, fake_services

EMAILS = Path(__file__).parent / "fixtures/emails"
DIGEST = "a" * 64


def provider_client(provider, transport=None, key="test-only-key"):
    factory = VirusTotalClient if provider == "VT" else URLScanClient
    client = factory(api_key=key, transport=transport)
    return client.lookup_hash if provider == "VT" else client.lookup_url


@pytest.mark.parametrize("provider,value", [("VT", DIGEST), ("URLSCAN", "https://example.test/Path?q=1")])
def test_provider_success_is_normalized_and_read_only(provider, value):
    transport = FakeTransport()
    result = provider_client(provider, transport)(value)
    assert result.status == "OK" and result.data is not None
    if provider == "VT":
        assert result.data.sha256 == DIGEST and result.data.harmless == 1
        assert result.data.last_analysis_at.tzinfo is not None
    else:
        assert result.data.scanned_url == value and result.data.final_url == value
        assert result.data.malicious is False
    assert all(path.startswith(("/files/", "/search/", "/result/")) for path, _ in transport.calls)


@pytest.mark.parametrize("provider,value", [("VT", DIGEST), ("URLSCAN", "https://example.test/")])
@pytest.mark.parametrize(
    "failure,status,suffix",
    [
        ("timeout", "TIMEOUT", "TIMEOUT"),
        (429, "RATE_LIMITED", "RATE_LIMITED"),
        (401, "ERROR", "UNAUTHORIZED"),
        (403, "ERROR", "UNAUTHORIZED"),
        (503, "ERROR", "UPSTREAM_ERROR"),
        (404, "ERROR", "NOT_FOUND"),
        ("network", "ERROR", "NETWORK_ERROR"),
        ("malformed", "ERROR", "INVALID_RESPONSE"),
    ],
)
def test_provider_failures_use_toolresult_without_sensitive_exception_text(provider, value, failure, status, suffix):
    result = provider_client(provider, FakeTransport(failure=failure))(value)
    assert result.status == status and result.data is None and result.error_code == f"{provider}_{suffix}"
    assert result.latency_ms >= 0 and result.error_message is None


@pytest.mark.parametrize("provider,value", [("VT", DIGEST), ("URLSCAN", "https://example.test/")])
def test_missing_key_never_requests_provider(provider, value):
    transport = FakeTransport()
    result = provider_client(provider, transport, key="")(value)
    assert result.status == "ERROR" and result.error_code.endswith("NOT_CONFIGURED")
    assert transport.calls == []


def test_malformed_report_and_non_exact_hash_are_rejected():
    class BadTransport:
        def get(self, *args, **kwargs):
            return httpx.Response(
                200, json={"data": {"type": "file", "id": DIGEST, "attributes": {"sha256": "b" * 64}}}
            )

    result = VirusTotalClient(api_key="test-only-key", transport=BadTransport()).lookup_hash(DIGEST)
    assert result.status == "ERROR" and result.error_code == "VT_INVALID_RESPONSE"
    assert VirusTotalClient(api_key="test-only-key", transport=FakeTransport()).lookup_hash("a" * 32).status == "ERROR"


def test_urlscan_empty_and_non_exact_search_are_not_clean_reports():
    assert (
        URLScanClient(api_key="test-only-key", transport=FakeTransport(empty=True))
        .lookup_url("https://example.test/")
        .data
        is None
    )

    class NearMatch:
        def get(self, *args, **kwargs):
            return httpx.Response(200, json={"results": [{"task": {"url": "https://sub.example.test/"}}]})

    result = URLScanClient(api_key="test-only-key", transport=NearMatch()).lookup_url("https://example.test/")
    assert result.status == "OK" and result.data is None


def test_exact_ioc_facade_and_atomic_ingestion_metadata():
    store = InMemoryIOCStore()
    now = datetime.now(UTC)
    records = [
        dict(
            kind=kind,
            value=value,
            source="synthetic-feed",
            confidence=0.8,
            first_seen=now,
            last_seen=now,
            tags=["test"],
            metadata={"revision": 1},
        )
        for kind, value in (
            ("domain", "BÜCHER.test."),
            ("url", "HTTPS://EXAMPLE.test:443/Pay?q=A#x"),
            ("ip", "2001:0db8::1"),
            ("hash", DIGEST.upper()),
        )
    ]
    assert store.ingest(records).data == 4
    service = ThreatIntelService(store)
    assert service.lookup_domain("xn--bcher-kva.test").data.confidence == 0.8
    assert service.lookup_url("https://example.test/Pay?q=A").data.source == "synthetic-feed"
    assert service.lookup_ip("2001:db8::1").data.value == "2001:db8::1"
    assert service.lookup_hash(DIGEST).data.value == DIGEST
    assert service.lookup_domain("sub.xn--bcher-kva.test").data is None
    assert service.lookup_url("https://example.test/pay?q=A").data is None
    assert store.ingest([records[0], {**records[0], "value": "new.test", "last_seen": "invalid"}]).status == "ERROR"
    assert store.lookup("domain", "new.test").data is None
    assert store.ingest([{**records[3], "value": "a" * 32}]).status == "ERROR"


@pytest.mark.parametrize("empty,failure,status", [(False, False, "OK"), (True, False, "OK"), (False, True, "ERROR")])
def test_rag_fake_success_empty_and_unavailable(empty, failure, status):
    service = RAGService(FakeKnowledgeRepository(empty=empty, failure=failure))
    result = service.retrieve("payment verification")
    assert result.status == status
    assert bool(service.context("payment verification")) == (not empty and not failure)
    assert RAGService().context("payment verification") == ()
    document = KnowledgeDocument(
        document_id="playbook-1",
        title="Verify payment",
        source="test",
        section="1",
        text="Call a known contact.",
        kind="soc_playbook",
    )
    assert document.document_id == "playbook-1"


@pytest.mark.parametrize("failure,status", [(None, "OK"), ("timeout", "TIMEOUT"), ("error", "ERROR")])
def test_bec_structured_llm_is_weak_and_failure_controlled(failure, status):
    model = FakeStructuredModel(positive=True, failure=failure)
    result = StructuredContentAnalyzer(LLMClient(model)).analyze(
        RedactedContent(text="[EMAIL_1] payment request", redaction_reference="test-redacted")
    )
    assert result.status == status
    if result.data:
        evidence = result.data.evidence[0]
        assert evidence.family == "content_bec" and evidence.provenance.source == "llm"
        assert evidence.signal_type == "BEC_REQUEST" and evidence.severity == "low" and evidence.confidence == 0.9
        score = score_evidence(result.data.evidence)
        assert score.score <= 10
        assert '"trust": "untrusted"' in model.messages[0][1]["content"]
    else:
        assert result.data is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "scenario,filename,partial",
    [
        ("success", "clean.eml", False),
        ("success", "href_mismatch.eml", False),
        ("success", "suspicious_attachment.eml", True),
        ("timeout", "href_mismatch.eml", True),
        ("unavailable", "suspicious_attachment.eml", True),
        ("unavailable", "clean.eml", True),
        ("bec", "clean.eml", False),
    ],
)
async def test_pipeline_external_success_failure_scope_and_coverage(monkeypatch, scenario, filename, partial):
    monkeypatch.setattr(get_settings(), "header_trusted_authserv_ids", "mx.recipient.test")
    services, iocs = fake_services(scenario)
    state = await build_graph(ioc_client=iocs, external_services=services).ainvoke(
        {"raw_email": (EMAILS / filename).read_bytes()}
    )
    response = AnalysisResponse.from_agent_state(state)
    assert response.analysis_scope == ("static_enriched_partial" if partial else "static_enriched")
    assert response.coverage.complete is not partial
    assert response.claim_validation_status == "PASS"
    if partial:
        assert response.label_candidate == "NEEDS_ANALYST_REVIEW" and response.coverage.unknown
        assert all(item.result == "UNKNOWN" for item in response.evidence if item.tool_status != "OK")
    if scenario == "bec":
        assert response.score == 9 and response.label_candidate == "SAFE"  # Weak signal is below existing threshold.
        assert any(item.provenance.source == "llm" and item.result == "FAIL" for item in response.evidence)
    if filename == "href_mismatch.eml":
        assert any(item.signal_type == "HREF_MISMATCH" and item.result == "FAIL" for item in response.evidence)
        assert response.score == 60


@pytest.mark.asyncio
async def test_llm_never_overrides_strong_ioc_or_vt_and_rag_only_reaches_verdict(monkeypatch):
    monkeypatch.setattr(get_settings(), "header_trusted_authserv_ids", "mx.recipient.test")
    services, _ = fake_services("bec")
    store = InMemoryIOCStore((IOCRecord(kind="domain", value="other.test", source="test-snapshot"),))

    class CaptureVerdict(DeterministicVerdictProvider):
        def generate(self, request, *, feedback=()):
            self.request = request
            return super().generate(request, feedback=feedback)

    provider = CaptureVerdict()
    result = await build_graph(ioc_client=store, external_services=services, verdict_provider=provider).ainvoke(
        {"raw_email": (EMAILS / "href_mismatch.eml").read_bytes()}
    )
    assert result["risk_score"] >= 95 and result["risk_result"].label_candidate == "PHISHING"
    assert provider.request.knowledge_context[0].document_id == "test-playbook-1"
    assert not any("playbook" in str(e.value) for e in result["validated_evidence"])
    vt_services = ExternalServices(
        virustotal=VirusTotalClient(api_key="test-only-key", transport=FakeTransport(malicious=True)),
        urlscan=services.urlscan,
        content=services.content,
        rag=RAGService(),
    )
    vt = await build_graph(ioc_client=InMemoryIOCStore(), external_services=vt_services).ainvoke(
        {"raw_email": (EMAILS / "suspicious_attachment.eml").read_bytes()}
    )
    assert vt["risk_score"] >= 95 and vt["risk_result"].overrides
    # Existing fixture declares an inert executable as PNG: QR decode stays UNKNOWN.
    assert vt["risk_result"].label_candidate == "NEEDS_ANALYST_REVIEW"
    assert vt["rag_context"] == () and vt["claim_validation"].status == "PASS"


def test_provider_base_config_is_read_only_https():
    with pytest.raises(ValueError):
        HTTPXTransport("http://insecure.test")


@pytest.mark.asyncio
async def test_content_boundary_only_sees_redacted_copy_and_redaction_failure_stops_llm(monkeypatch):
    from dataclasses import replace

    monkeypatch.setattr(get_settings(), "header_trusted_authserv_ids", "mx.recipient.test")
    services, iocs = fake_services()
    model = FakeStructuredModel()
    services = replace(services, content=StructuredContentAnalyzer(LLMClient(model)))
    raw = (EMAILS / "clean.eml").read_bytes() + b"\nContact alice@example.test, 0912 345 678\n"
    result = await build_graph(ioc_client=iocs, external_services=services).ainvoke({"raw_email": raw})
    assert "alice@example.test" in result["parsed_email"]["text_body"]
    assert "alice@example.test" not in str(model.messages) and "0912 345 678" not in str(model.messages)
    assert "[EMAIL_" in str(model.messages) and "[VN_PHONE_" in str(model.messages)

    class BrokenRedactor:
        def redact(self, raw):
            raise RuntimeError("synthetic failure")

    model.messages.clear()
    failed = await build_graph(ioc_client=iocs, external_services=services, pii_redactor=BrokenRedactor()).ainvoke(
        {"raw_email": raw}
    )
    assert not model.messages
    assert failed["risk_result"].label_candidate == "NEEDS_ANALYST_REVIEW"


def test_structured_llm_cannot_inject_risk_fields():
    class InvalidModel:
        def generate(self, messages, schema, *, timeout):
            return {"signals": [], "score": 0, "label_candidate": "SAFE"}

    result = StructuredContentAnalyzer(LLMClient(InvalidModel())).analyze(
        RedactedContent(text="untrusted data", redaction_reference="test")
    )
    assert result.status == "ERROR" and result.data is None and result.error_code == "LLM_INVALID_RESPONSE"


@pytest.mark.asyncio
async def test_benign_urls_are_enriched_and_empty_scan_is_unknown(monkeypatch):
    from dataclasses import replace

    monkeypatch.setattr(get_settings(), "header_trusted_authserv_ids", "mx.recipient.test")
    services, iocs = fake_services()
    raw = (EMAILS / "clean.eml").read_bytes() + b"\nhttps://example.test/Info?q=A\n"
    result = await build_graph(ioc_client=iocs, external_services=services).ainvoke({"raw_email": raw})
    assert any(
        e.analyzer == "urlscan" and e.indicator == "https://example.test/Info?q=A" for e in result["validated_evidence"]
    )
    assert result["risk_score"] == 0 and result["risk_result"].coverage.complete
    empty = replace(services, urlscan=URLScanClient(api_key="test-only-key", transport=FakeTransport(empty=True)))
    missing = await build_graph(ioc_client=iocs, external_services=empty).ainvoke({"raw_email": raw})
    assert missing["risk_result"].label_candidate == "NEEDS_ANALYST_REVIEW"
    assert "URL_IOC_CHECK" in missing["risk_result"].coverage.unknown


def test_ingested_confidence_is_preserved_in_ioc_evidence():
    from src.analyzers.common import ioc_evidence

    record = IOCRecord(kind="domain", value="example.test", source="test-feed", confidence=0.4)
    evidence = ioc_evidence(
        "url", "example.test", [("domain", "example.test")], InMemoryIOCStore((record,)), "URL_IOC_CHECK"
    )
    matched = next(e for e in evidence if e.signal_type == "IOC_MATCH")
    assert matched.confidence == 0.4 and not score_evidence(evidence).overrides
