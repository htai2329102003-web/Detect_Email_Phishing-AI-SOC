import io
import json
import logging
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
from fastapi import FastAPI
from pydantic import SecretStr

from src.agents.graph import build_graph, build_production_graph
from src.api.routers import health
from src.config import Settings
from src.main import app
from src.schemas.analysis import AnalysisResponse
from src.services.observability import (
    CURRENT_TRACE,
    LOGGER,
    LangfuseExporter,
    OperationalMiddleware,
    RequestTrace,
    RuntimeMetrics,
    observed_node,
)

EMAILS = Path(__file__).parent / "fixtures/emails"


def test_env_example_documents_all_settings():
    documented = {line.split("=", 1)[0] for line in (EMAILS.parents[2] / ".env.example").read_text(
        encoding="utf-8").splitlines() if "=" in line and not line.lstrip().startswith("#")}
    assert {name.upper() for name in Settings.model_fields} <= documented


@pytest.fixture
def operational_logs():
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    LOGGER.addHandler(handler)
    yield stream
    LOGGER.removeHandler(handler)


@pytest.mark.asyncio
@pytest.mark.parametrize("checks,status", [({"postgresql": "ready"}, 200), ({"postgresql": "not_ready"}, 503)])
async def test_liveness_independent_of_dependency_readiness(checks, status):
    app.dependency_overrides[health.dependency_readiness] = lambda: checks
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://test") as client:
            live = await client.get("/healthz")
            ready = await client.get("/readyz")
        assert live.status_code == 200 and ready.status_code == status
        assert ready.json()["checks"] == checks
    finally:
        app.dependency_overrides.pop(health.dependency_readiness)


def test_readiness_dependency_failure_safe_and_optional_qdrant_disabled(monkeypatch):
    settings = Settings(_env_file=None, jwt_secret=SecretStr("x" * 40))
    monkeypatch.setattr(health, "get_settings", lambda: settings)

    def unavailable():
        raise RuntimeError("secret-db-url")

    monkeypatch.setattr(health, "get_session_factory", unavailable)
    monkeypatch.setattr(health, "readiness_ioc_client", lambda *args: SimpleNamespace(
        lookup=lambda *args: SimpleNamespace(status="ERROR")))
    checks = health.dependency_readiness()
    assert checks == {"postgresql": "not_ready", "configuration": "ready", "ioc_snapshot": "not_ready"}
    assert "secret" not in json.dumps(checks)


@pytest.mark.asyncio
async def test_analysis_logs_and_traces_exclude_email_pii_and_tokens(client, operational_logs):
    secret = "G9_SECRET_CANARY_0912"
    trace = RequestTrace()
    token = CURRENT_TRACE.set(trace)
    try:
        state = await build_graph().ainvoke({"case_id": str(uuid4()), "raw_email":
            (EMAILS / "clean.eml").read_bytes() + f"\n{secret} private@example.test".encode(),
            "evidence": [], "errors": []})
    finally:
        CURRENT_TRACE.reset(token)
    response = AnalysisResponse.from_agent_state(state)
    assert response.claim_validation_status == "PASS"
    names = {span["name"] for span in trace.spans}
    assert names == {"parse", "header", "url", "attachment", "qr", "validate_evidence",
                     "score_risk", "create_verdict", "validate_claims"}
    assert all(span["parentSpanId"] == trace.root_span_id for span in trace.spans)
    result = await client.post("/api/v1/analysis?ignored=" + secret,
        headers={"X-Request-ID": secret}, files={"file": ("canary.eml",
        (EMAILS / "clean.eml").read_bytes() + f"\n{secret}".encode(), "message/rfc822")})
    assert result.status_code == 200 and result.headers["x-request-id"] != secret
    logs = operational_logs.getvalue()
    assert secret not in logs and "private@example.test" not in logs
    assert client.headers["Authorization"] not in logs
    events = [json.loads(line) for line in logs.splitlines()]
    request = next(item for item in reversed(events) if item["stage"] == "request")
    assert request["case_id"] == result.json()["case_id"]
    assert request["final_label"] == result.json()["label_candidate"]
    assert request["risk_score"] == result.json()["score"]
    assert request["latency_ms"] >= 0


@pytest.mark.asyncio
async def test_node_exception_logs_only_fixed_error_code(operational_logs):
    def broken(state):
        raise RuntimeError("secret-body-and-api-key")

    with pytest.raises(RuntimeError):
        await observed_node("parse", broken)({"raw_email": b"secret-body"})
    assert "secret-body" not in operational_logs.getvalue()
    assert json.loads(operational_logs.getvalue())["error_code"] == "NODE_FAILED"


@pytest.mark.asyncio
async def test_unexpected_request_failure_is_sanitized(operational_logs):
    application = FastAPI()
    application.add_middleware(OperationalMiddleware)

    @application.get("/broken")
    async def broken():
        raise RuntimeError("secret-token-and-email")

    async with httpx.AsyncClient(transport=httpx.ASGITransport(application), base_url="http://test") as client:
        response = await client.get("/broken")
    assert response.status_code == 500 and response.json()["detail"]["code"] == "INTERNAL_ERROR"
    assert "secret-token" not in operational_logs.getvalue()


def test_runtime_metrics_count_abstentions_failures_and_latencies():
    metrics = RuntimeMetrics()
    metrics.request(200, 10, {"label": "NEEDS_ANALYST_REVIEW", "external_tool_failures": 2})
    metrics.request(503, 20, {})
    snapshot = metrics.snapshot()
    assert snapshot["counts"] == {"requests": 2, "errors": 1, "review_abstentions": 1, "external_tool_failures": 2}
    assert snapshot["latency_ms_mean"] == 15


@pytest.mark.asyncio
async def test_metrics_requires_admin(client, database):
    from src.services.auth import issue_token

    assert (await client.get("/api/v1/metrics")).status_code == 403
    response = await client.get("/api/v1/metrics", headers={
        "Authorization": "Bearer " + issue_token(database["admin"], database["settings"])})
    assert response.status_code == 200 and response.json()["scope"] == "process_local_since_start"


@pytest.mark.asyncio
@pytest.mark.parametrize("fail", [False, True])
async def test_langfuse_otlp_export_and_outage_are_isolated(fail, operational_logs):
    requests = []

    def handle(request):
        requests.append(request)
        if fail:
            raise httpx.ConnectError("private-provider-secret")
        return httpx.Response(200, json={})

    settings = Settings(_env_file=None, langfuse_enabled=True, langfuse_public_key="test-public",
                        langfuse_secret_key="test-secret")
    exporter = LangfuseExporter(settings, httpx.MockTransport(handle))
    await exporter.export([{"name": "parse", "traceId": "a" * 32, "spanId": "b" * 16}])
    assert len(requests) == 1
    assert requests[0].url.path == "/api/public/otel/v1/traces"
    assert requests[0].headers["x-langfuse-ingestion-version"] == "4"
    assert json.loads(requests[0].content)["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["name"] == "parse"
    assert "test-secret" not in operational_logs.getvalue() and "private-provider-secret" not in operational_logs.getvalue()
    if fail:
        assert "TRACE_EXPORT_FAILED" in operational_logs.getvalue()


@pytest.mark.asyncio
async def test_langfuse_missing_keys_no_calls():
    def forbidden(request):
        raise AssertionError("Missing keys must not send any requests")

    exporter = LangfuseExporter(Settings(_env_file=None, langfuse_enabled=True), httpx.MockTransport(forbidden))
    await exporter.export([])
    assert not exporter.enabled


@pytest.mark.asyncio
async def test_optional_missing_keys_do_not_crash_and_do_not_become_safe(tmp_path):
    settings = Settings(_env_file=None, content_bec_enabled=True, verdict_llm_enabled=True, rag_enabled=True,
        external_enrichment_enabled=True, virustotal_enabled=True, urlscan_enabled=True,
        ioc_data_path=str(tmp_path / "absent.jsonl"), ioc_index_path=str(tmp_path / "absent.sqlite3"))
    state = await build_production_graph(settings).ainvoke({"case_id": str(uuid4()),
        "raw_email": (EMAILS / "clean.eml").read_bytes(), "evidence": [], "errors": []})
    response = AnalysisResponse.from_agent_state(state)
    assert response.assessment_label == "NEEDS_ANALYST_REVIEW"
    assert response.label_candidate != "SAFE"
    assert response.verdict_llm_status != "OK" and response.rag_status != "OK"
