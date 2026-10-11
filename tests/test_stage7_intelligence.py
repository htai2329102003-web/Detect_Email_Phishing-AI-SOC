"""Focused Stage 7 checks, entirely offline; no DEV/TEST dataset inference."""

import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from src.agents.graph import build_graph, build_production_graph
from src.agents.nodes.enrichment_node import enrichment_node, external_finding
from src.analyzers.content_analyzer import BECClassification, RedactedContent, StructuredContentAnalyzer
from src.config import Settings, get_settings
from src.evidence.risk_engine import load_risk_policy
from src.services.external import LookupCache
from src.services.ioc_store import InMemoryIOCStore, IOCRecord
from src.services.llm import ConfiguredStructuredModel, LLMClient
from src.services.threat_intel import ThreatIntelService
from src.services.urlscan import URLScanClient
from src.services.verdict import LLMVerdictProvider
from src.services.virustotal import VirusTotalClient
from tests.external_fakes import FakeStructuredModel, FakeTransport, fake_services

EMAILS = Path(__file__).parent / "fixtures/emails"
DIGEST = "a" * 64


def test_configured_provider_uses_strict_schema_base_timeout_and_no_sdk_retry(monkeypatch):
    settings = Settings(_env_file=None, openai_api_key="test-only", openai_base_url="https://provider.test/v1")
    factory = MagicMock()
    client = factory.return_value.__enter__.return_value
    client.chat.completions.parse.return_value = SimpleNamespace(choices=[SimpleNamespace(
        message=SimpleNamespace(refusal=None, parsed=BECClassification(signals=())))])
    monkeypatch.setattr("src.services.llm.OpenAI", factory)
    model = ConfiguredStructuredModel(settings)
    result = LLMClient(model, timeout=12).classify(({"role": "user", "content": "redacted"},), BECClassification)
    assert result.status == "OK" and model.call_count == 1
    assert factory.call_args.kwargs["max_retries"] == 0
    assert factory.call_args.kwargs["base_url"] == settings.openai_base_url
    args = client.chat.completions.parse.call_args.kwargs
    assert args["timeout"] == 12 and args["response_format"] is BECClassification and "tools" not in args
    factory.call_args.kwargs["http_client"].close()


@pytest.mark.parametrize("reference,code", [(999, "LLM_UNGROUNDED_REFERENCE"), (-1, "LLM_INVALID_RESPONSE"), (0, None)])
def test_real_bec_requires_bound_reason_reference(reference, code):
    class Model(ConfiguredStructuredModel):
        def generate(self, *args, **kwargs):
            return {"signals": [{"kind": "payment_request", "confidence": .9, "evidence_reference": reference}]}

    analyzer = StructuredContentAnalyzer(LLMClient(Model(Settings(_env_file=None))))
    result = analyzer.analyze(RedactedContent(text="Please transfer today", redaction_reference="test-redacted"))
    if code:
        assert result.status == "ERROR" and result.error_code == code
    else:
        assert result.status == "OK" and result.data.evidence[0].result == "FAIL"
        assert result.data.evidence[0].value["signals"][0]["reason_quote"] == "Please transfer today"


def test_lookup_cache_ttl_quota_and_429_cooldown():
    now = [0.0]
    transport = FakeTransport()
    client = VirusTotalClient(api_key="test", transport=transport)
    client.cache = LookupCache(ttl=10, min_interval=2, max_entries=1, clock=lambda: now[0])
    first = client.lookup_hash(DIGEST)
    assert client.lookup_hash(DIGEST).data == first.data and len(transport.calls) == 1
    assert client.lookup_hash("b" * 64).status == "RATE_LIMITED"
    now[0] = 11
    assert client.lookup_hash(DIGEST).status == "OK" and len(transport.calls) == 2
    now[0] = 14
    transport.failure = 429
    assert client.lookup_hash("b" * 64).status == "RATE_LIMITED"
    now[0] = 30
    assert client.lookup_hash("c" * 64).status == "RATE_LIMITED" and len(transport.calls) == 3


@pytest.mark.parametrize("url", ["https://example.test/?token=secret", "https://example.test/alice@example.test",
    "https://example.test/0912345678", "https://user:pass@example.test/", "https://example.test/#secret"])
def test_urlscan_production_privacy_blocks_sensitive_queries_without_network(url):
    transport = FakeTransport()
    result = URLScanClient(api_key="test", transport=transport).lookup_url(url)
    assert result.status == "ERROR" and not transport.calls


def test_threat_intel_local_first_provenance_and_single_vendor_policy():
    store = InMemoryIOCStore((IOCRecord(kind="hash", value=DIGEST, source="test-local"),))
    transport = FakeTransport(malicious=True)
    vt = VirusTotalClient(api_key="test", transport=transport)
    service = ThreatIntelService(store, virustotal=vt)
    hit = service.enrich("hash", DIGEST)
    assert set(hit) == {"local_ioc"} and hit["local_ioc"].data.source == "test-local" and not transport.calls
    report = service.enrich("hash", "b" * 64)
    assert set(report) == {"local_ioc", "virustotal"}
    assert report["local_ioc"].data is None and report["virustotal"].data.source_reference.startswith("virustotal:")
    assert service.confirmed_file_malicious(report["virustotal"].data)
    assert not service.confirmed_file_malicious(report["virustotal"].data.model_copy(update={"malicious": 1}))


@pytest.mark.parametrize("failure,status", [("timeout", "TIMEOUT"), (429, "RATE_LIMITED"), ("missing", "ERROR")])
def test_external_failures_become_unknown_evidence(failure, status):
    services, _ = fake_services()
    key = "" if failure == "missing" else "test"
    transport = FakeTransport(failure=failure if failure != "missing" else None)
    services = replace(services, content_enabled=False, rag_enabled=False,
        virustotal=VirusTotalClient(api_key=key, transport=transport),
        urlscan=URLScanClient(api_key=key, transport=transport))
    seed = [external_finding("attachment", "ATTACHMENT_IOC_CHECK", DIGEST, {"sha256": DIGEST}, "PASS"),
            external_finding("url", "URL_IOC_CHECK", "https://example.test/",
                             {"canonical_url": "https://example.test/"}, "PASS")]
    result = enrichment_node({"evidence": seed}, services=services, ioc_client=InMemoryIOCStore())
    assert {e.analyzer for e in result["evidence"]} == {"virustotal", "urlscan"}
    assert all(e.result == "UNKNOWN" and e.tool_status == status for e in result["evidence"])


class ExplanationModel:
    def __init__(self, *, forge=False, failure=False):
        self.messages, self.forge, self.failure = [], forge, failure

    def generate(self, messages, schema, *, timeout):
        self.messages.append(messages)
        if self.failure:
            raise TimeoutError("private provider detail")
        payload = json.loads(messages[1]["content"])
        claims = payload["allowed_claims"]
        result = {"claims": claims, "recommended_actions": ["REVIEW_EVIDENCE"],
                  "analyst_summary": payload["summary_by_claim_count"][str(len(claims))]}
        if self.forge:
            result.update(score=0, label_candidate="SAFE")
        return result


@pytest.mark.asyncio
async def test_llm_verdict_and_bec_redaction_gate2_rag_risk_parity(monkeypatch):
    monkeypatch.setattr(get_settings(), "header_trusted_authserv_ids", "mx.recipient.test")
    services, store = fake_services()
    bec = FakeStructuredModel()
    services = replace(services, content=StructuredContentAnalyzer(LLMClient(bec)),
                       virustotal_enabled=False, urlscan_enabled=False)
    model = ExplanationModel()
    raw = (EMAILS / "clean.eml").read_bytes() + b"\nContact alice@example.test 0912 345 678\n"
    base = await build_graph(ioc_client=store).ainvoke({"raw_email": raw})
    state = await build_graph(ioc_client=store, external_services=services,
                             verdict_provider=LLMVerdictProvider(LLMClient(model))).ainvoke({"raw_email": raw})
    assert state["risk_score"] == base["risk_score"] and state["risk_level"] == base["risk_level"]
    assert state["claims_valid"] and state["verdict_llm_status"] == "OK" and len(model.messages) == 1
    assert all(secret not in str(bec.messages) + str(model.messages) for secret in ("alice@example.test", "0912 345 678"))
    assert "alice@example.test" in state["parsed_email"]["text_body"]
    assert not any(e.family == "knowledge_context" for e in state["validated_evidence"])


@pytest.mark.asyncio
@pytest.mark.parametrize("forge,failure", [(True, False), (False, True)])
async def test_verdict_failure_cannot_change_risk_and_is_not_retried(forge, failure):
    raw = (EMAILS / "href_mismatch.eml").read_bytes()
    model = ExplanationModel(forge=forge, failure=failure)
    baseline = await build_graph().ainvoke({"raw_email": raw})
    state = await build_graph(verdict_provider=LLMVerdictProvider(LLMClient(model))).ainvoke({"raw_email": raw})
    assert state["risk_result"] == baseline["risk_result"]
    assert not state["claims_valid"] and len(model.messages) == 1
    assert state["verdict_llm_status"] != "OK" and state["claim_validation"].assessment_label == "NEEDS_ANALYST_REVIEW"


@pytest.mark.asyncio
async def test_independent_runtime_flags_and_current_policy():
    settings = Settings(_env_file=None, content_bec_enabled=True, rag_enabled=False, openai_api_key="",
                        verdict_llm_enabled=True, virustotal_enabled=True, urlscan_enabled=True,
                        ioc_data_path="absent.jsonl", ioc_index_path="absent.sqlite3")
    graph = build_production_graph(settings)
    assert "external_enrichment" in graph.nodes and "knowledge_context" not in graph.nodes
    state = await graph.ainvoke({"raw_email": (EMAILS / "suspicious_attachment.eml").read_bytes()})
    assert not any(e.analyzer in {"virustotal", "urlscan"} for e in state["validated_evidence"])
    assert any(e.family == "content_bec" and e.result == "UNKNOWN" for e in state["validated_evidence"])
    assert state["risk_result"].label_candidate == "NEEDS_ANALYST_REVIEW"
    policy = load_risk_policy()
    assert policy.thresholds.phishing == 62 and policy.thresholds.suspicious == 30
    assert policy.weights["IOC_DERIVED_DOMAIN"].weight == .2
