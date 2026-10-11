"""Allowlisted operational metadata only; no prompts, email, headers or indicators."""

import asyncio
import inspect
import json
import logging
from collections import Counter
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import UTC, datetime
from threading import Lock
from time import perf_counter, time_ns
from urllib.parse import urlsplit
from uuid import UUID, uuid4

import httpx
from starlette.concurrency import run_in_threadpool
from starlette.responses import JSONResponse

LOGGER = logging.getLogger("phishhunter")
LOGGER.propagate = False
if not LOGGER.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    LOGGER.addHandler(handler)
LOGGER.setLevel(logging.INFO)


class RuntimeMetrics:
    """Bounded aggregate counters per worker; restart resets them."""

    def __init__(self):
        self.lock = Lock()
        self.counts = Counter()
        self.labels = Counter()
        self.latency_ms_sum = 0.0

    def request(self, status, latency, summary):
        with self.lock:
            self.counts["requests"] += 1
            self.counts["errors"] += status >= 400
            self.latency_ms_sum += latency
            if summary.get("label"):
                self.labels[summary["label"]] += 1
                self.counts["review_abstentions"] += summary["label"] == "NEEDS_ANALYST_REVIEW"
            self.counts["external_tool_failures"] += summary.get("external_tool_failures", 0)

    def snapshot(self):
        with self.lock:
            return {"scope": "process_local_since_start", "counts": dict(self.counts),
                    "labels": dict(self.labels), "latency_ms_sum": self.latency_ms_sum,
                    "latency_ms_mean": self.latency_ms_sum / self.counts["requests"]
                    if self.counts["requests"] else None}


METRICS = RuntimeMetrics()


@dataclass
class RequestTrace:
    request_id: str = field(default_factory=lambda: uuid4().hex)
    root_span_id: str = field(default_factory=lambda: uuid4().hex[:16])
    spans: list = field(default_factory=list)


CURRENT_TRACE: ContextVar[RequestTrace | None] = ContextVar("operational_trace", default=None)
LABELS = {"SAFE", "SUSPICIOUS", "PHISHING", "NEEDS_ANALYST_REVIEW"}
STATUSES = {"OK", "PARTIAL", "PASS", "FILTERED", "REJECTED", "ERROR", "UNKNOWN", "TIMEOUT", "RATE_LIMITED", "DISABLED"}
EXTERNAL_TOOLS = {"virustotal", "urlscan", "content_bec", "rag", "knowledge_retrieval"}


def case_identifier(value):
    try:
        return str(UUID(str(value)))
    except (ValueError, TypeError):
        return None


def event(stage, *, request_id=None, case_id=None, label=None, score=None, latency_ms=0,
          tool_status="OK", error_code=None):
    # Callers supply internal constants, never exception messages or client inputs.
    data = {"timestamp": datetime.now(UTC).isoformat(), "request_id": request_id,
            "case_id": case_identifier(case_id), "stage": stage,
            "final_label": label if label in LABELS else None, "risk_score": score,
            "latency_ms": round(latency_ms, 3),
            "tool_status": tool_status if tool_status in STATUSES else "UNKNOWN", "error_code": error_code}
    LOGGER.info(json.dumps(data, separators=(",", ":")))


def append_span(trace, stage, started_ns, ended_ns, status, *, case_id=None, label=None, score=None, root=False):
    if trace is None or len(trace.spans) >= 64:
        return
    attrs = {"langfuse.trace.name": "phishhunter.request", "langfuse.observation.type": "span",
             "request.id": trace.request_id, "phishhunter.stage": stage, "tool.status": status}
    if case_identifier(case_id):
        attrs["case.id"] = case_identifier(case_id)
    if label in LABELS:
        attrs["phishhunter.label"] = label
    if score is not None:
        attrs["phishhunter.score"] = float(score)
    attributes = [{"key": key, "value": {"doubleValue": value} if isinstance(value, float)
                   else {"stringValue": value}} for key, value in attrs.items()]
    span = {"traceId": trace.request_id, "spanId": trace.root_span_id if root else uuid4().hex[:16],
            "name": stage, "kind": 2 if root else 1, "startTimeUnixNano": str(started_ns),
            "endTimeUnixNano": str(ended_ns), "attributes": attributes,
            "status": {"code": 2 if status in {"ERROR", "TIMEOUT", "RATE_LIMITED"} else 1}}
    if not root:
        span["parentSpanId"] = trace.root_span_id
    trace.spans.append(span)


def observed_node(name, action):
    async def run(state):
        trace, started, started_ns = CURRENT_TRACE.get(), perf_counter(), time_ns()
        output, status, error = {}, "OK", None
        try:
            output = await action(state) if inspect.iscoroutinefunction(action) else await run_in_threadpool(action, state)
            runs = output.get("analyzer_runs", [])
            if any(run.get("status") != "OK" for run in runs):
                status, error = "PARTIAL", "ANALYZER_INCOMPLETE"
            if output.get("errors") or output.get("verdict_errors") or output.get("privacy_errors"):
                status, error = "ERROR", "NODE_REPORTED_ERROR"
            if output.get("rag_status") not in {None, "OK"}:
                status, error = "ERROR", "RAG_UNAVAILABLE"
            gate = output.get("claim_validation")
            if gate is not None and gate.status != "PASS":
                status, error = gate.status, "CLAIM_VALIDATION_FAILED"
            return output
        except Exception:
            status, error = "ERROR", "NODE_FAILED"
            raise
        finally:
            risk = output.get("risk_result", state.get("risk_result"))
            label, score = (risk.label_candidate, risk.score) if risk is not None else (None, None)
            event(name, request_id=trace.request_id if trace else None, case_id=state.get("case_id"),
                  label=label, score=score, latency_ms=(perf_counter() - started) * 1000,
                  tool_status=status, error_code=error)
            append_span(trace, name, started_ns, time_ns(), status,
                        case_id=state.get("case_id"), label=label, score=score)
    return run


class LangfuseExporter:
    """Bounded best-effort OTLP HTTP/JSON export; no new SDK or captured inputs."""

    def __init__(self, settings, transport=None):
        url = urlsplit(settings.langfuse_base_url)
        self.enabled = bool(settings.langfuse_enabled and settings.langfuse_public_key.get_secret_value()
                            and settings.langfuse_secret_key.get_secret_value()
                            and url.scheme in {"https", "http"} and url.hostname
                            and not (url.username or url.password or url.query or url.fragment)
                            and (url.scheme == "https" or url.hostname in {"localhost", "127.0.0.1", "langfuse"}))
        self.settings, self.transport = settings, transport
        self.queue = asyncio.Queue(maxsize=64)

    def submit(self, spans):
        if self.enabled:
            try:
                self.queue.put_nowait(list(spans))
            except asyncio.QueueFull:
                event("observability", tool_status="ERROR", error_code="TRACE_QUEUE_FULL")

    async def export(self, spans):
        if not self.enabled:
            return
        settings = self.settings
        payload = {"resourceSpans": [{"resource": {"attributes": [
            {"key": "service.name", "value": {"stringValue": "phishhunter"}}]},
            "scopeSpans": [{"scope": {"name": "phishhunter.operational"}, "spans": spans}]}]}
        try:
            async with httpx.AsyncClient(transport=self.transport, trust_env=False,
                                         timeout=settings.langfuse_timeout_seconds) as client:
                response = await client.post(settings.langfuse_base_url.rstrip("/") + "/api/public/otel/v1/traces",
                    auth=(settings.langfuse_public_key.get_secret_value(), settings.langfuse_secret_key.get_secret_value()),
                    headers={"x-langfuse-ingestion-version": "4"}, json=payload)
                response.raise_for_status()
        except Exception:
            event("observability", tool_status="ERROR", error_code="TRACE_EXPORT_FAILED")

    async def worker(self):
        while True:
            spans = await self.queue.get()
            try:
                await self.export(spans)
            finally:
                self.queue.task_done()


class OperationalMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        trace, started, started_ns = RequestTrace(), perf_counter(), time_ns()
        token = CURRENT_TRACE.set(trace)
        status, response_started = 500, False

        async def observed_send(message):
            nonlocal status, response_started
            if message["type"] == "http.response.start":
                status, response_started = message["status"], True
                message.setdefault("headers", []).append((b"x-request-id", trace.request_id.encode()))
            await send(message)

        try:
            await self.app(scope, receive, observed_send)
        except Exception:
            # Do not echo/log exception messages or traceback locals containing email/secrets.
            if not response_started:
                await JSONResponse({"detail": {"code": "INTERNAL_ERROR"}}, status_code=500)(scope, receive, observed_send)
        finally:
            summary = scope.get("state", {}).get("analysis_summary", {})
            elapsed = (perf_counter() - started) * 1000
            METRICS.request(status, elapsed, summary)
            event("request", request_id=trace.request_id, case_id=summary.get("case_id"),
                  label=summary.get("label"), score=summary.get("score"), latency_ms=elapsed,
                  tool_status="ERROR" if status >= 400 else "OK",
                  error_code=f"HTTP_{status}" if status >= 400 else None)
            append_span(trace, "request", started_ns, time_ns(), "ERROR" if status >= 400 else "OK",
                        case_id=summary.get("case_id"), label=summary.get("label"), score=summary.get("score"), root=True)
            exporter = getattr(scope["app"].state, "telemetry_exporter", None)
            if exporter:
                exporter.submit(trace.spans)
            CURRENT_TRACE.reset(token)
