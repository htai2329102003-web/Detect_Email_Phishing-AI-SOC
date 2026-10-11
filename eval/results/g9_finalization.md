# G9 Deployment and Observability Finalization

=== G9 FINALIZATION RESULT ===

DEPLOYMENT: PASS  
DOCKER: PASS  
HEALTH: PASS  
READINESS: PASS  
STRUCTURED LOGGING: PASS  
OBSERVABILITY: PASS — local request/node traces and mock-tested Langfuse export; live remote export not exercised  
ENV VALIDATION: PASS  
OPTIONAL PROVIDERS FAIL-CLOSED: YES  
FINAL SMOKE: PASS

=== SECURITY ===

RAW EMAIL LOGGED: NO  
SECRETS LOGGED: NO  
EXTERNAL FAILURE -> SAFE: NO  
AUTO DESTRUCTIVE ACTION: NO

=== VALIDATION ===

TARGETED TESTS:  
PASS: 25  
FAIL: 0  
COMPILE: PASS — changed Python files only  
RUFF: PASS — changed Python files only

=== DATA / MODEL SAFETY ===

DATA MODIFIED: NO  
RISK CONFIG MODIFIED: NO  
DEV RERUN: NO  
TEST RERUN: NO  
LLM/API CALLS: 0 real BEC, Verdict LLM, RAG/embedding, VirusTotal, urlscan, or Langfuse calls  
COMMIT/PUSH: NO

=== FINAL STATUS ===

G9 COMPLETE: YES  
READY FOR FINAL DELIVERY: YES  
REMAINING BLOCKERS: NONE for the requested deployment/observability scope.

## Deployment evidence

- Built backend and frontend images successfully; frontend build also completed TypeScript validation.
- Backend, frontend, and PostgreSQL passed Docker health checks. Qdrant remained running with its persistent volume.
- Backend runs Alembic upgrade before Uvicorn. Readiness confirms PostgreSQL connectivity and current migration heads, required JWT/risk configuration, and read-only IOC snapshot validity. Qdrant readiness is checked when RAG is enabled; readiness never calls embedding/LLM/VT/urlscan providers.
- `/healthz`, `/readyz`, existing `/api/v1/health`, HTTP login, and frontend `/login` returned 200.
- Frontend uses a standalone Next.js build. Both application containers run without root privileges. Data/runtime mounts remain read-only; PostgreSQL/Qdrant volumes remain persistent.
- Smoke used `docker compose -f docker-compose.yml -f runtime/g9-smoke.compose.yml up -d --wait --wait-timeout 120`. The temporary override disables all optional providers and Langfuse; `.env` was not edited or printed. The running stack remains in this provider-disabled smoke configuration.

## Actual HTTP smoke

Only the two small fixtures in `tests/fixtures/emails/` were analyzed; no DEV/TEST or capability evaluation ran.

| Fixture | HTTP | Score | Label candidate | Scope | Gate 2 | Review state | Automatic actions |
| --- | ---: | ---: | --- | --- | --- | --- | ---: |
| href_mismatch.eml | 200 | 60 | SUSPICIOUS | static_local_partial | PASS | PENDING | 0 |
| clean.eml, with an in-memory privacy canary | 200 | 0 | NEEDS_ANALYST_REVIEW | static_local_partial | PASS | PENDING | 0 |

Both responses validated against `PersistedAnalysisResponse`; both cases were successfully read back from PostgreSQL. The neutral result remains REVIEW because trusted-auth coverage is incomplete; it was not forced to SAFE. Case IDs: `781beec8-0b1b-4e13-901e-5e86ca8dca7b` and `b9308f97-1de9-428d-ac5e-dcc70c287179`.

The database initially had two inactive analyst accounts and no active operator. One dedicated SOC Analyst account was provisioned for this smoke, logged in through HTTP, then deactivated. Its account and audit records remain to support the persisted smoke cases; its credentials/JWT were never printed or saved in artifacts.

The analyst correctly received HTTP 403 from the admin-only metrics endpoint. Successful admin access and metric counters were verified in targeted tests.

## Logging, traces, and metrics

- Standard-library JSON logging records timestamp, server-generated request ID, UUID case ID, stage, label, score, latency, tool status, and fixed error codes.
- Request traces correlate parser, header/URL/attachment/QR branches, Gate 1, Risk Engine, verdict, and Gate 2. Optional enrichment and knowledge nodes use the same wrapper when enabled; graph outputs and risk calculations are unchanged.
- No request bodies, headers, client-supplied request IDs, query strings, filenames, email addresses, indicators, prompts, claim text, or exception messages are captured by the instrumentation. Docker Uvicorn access logging is disabled.
- Smoke logs were checked against an injected raw-body/PII canary, the actual smoke JWT/password, and configured provider/JWT secrets without printing those values. Neither fixture leaked these values. Final request metadata matched each response and all expected nodes shared its request ID.
- Admin-only `/api/v1/metrics` exposes process-local request/error counts, cumulative/mean latency, label distribution, review/abstention count, and external-tool failures. Counters reset on restart and are separate per worker; no durable monitoring platform was added.
- Steps.md explicitly requires Langfuse. A bounded, best-effort exporter uses the documented [Langfuse OTLP HTTP/JSON endpoint](https://langfuse.com/integrations/native/opentelemetry), reusing existing httpx. No new SDK/framework dependency or input/output auto-capture was added. Tests cover endpoint/auth wiring, timeout/outage isolation, and missing keys. Live remote Langfuse export remains unverified and was intentionally disabled during smoke.

## Environment and focused checks

`.env.example` documents every Settings field, including disabled-by-default Langfuse configuration. Missing optional model/provider keys do not crash graph construction. With optional features enabled but keys absent, targeted tests observe unavailable/review outcomes instead of SAFE. Existing action-authorization tests verify that human review remains required; this task added no destructive executor.

Focused command (25 passed, 0 failed):

```powershell
python -m pytest -q tests/test_observability.py tests/test_agents/test_graph.py tests/test_api/test_routes.py tests/test_case_workflow.py::test_action_authorization_requires_human_review_and_modified_allowlist tests/test_external_boundaries.py::test_missing_key_never_requests_provider
```

Compile and Ruff covered only `src/services/observability.py`, `src/main.py`, `src/api/routers/health.py`, `src/api/routers/analysis.py`, `src/agents/graph.py`, `src/config.py`, and `tests/test_observability.py`. No full regression or G8 evaluation was run.

The frontend install reported development-tool advisories; the focused `npm audit --omit=dev` check reported zero production dependency advisories. No dependency versions were changed.

Frozen R2-F values remain 62 / 30 / 0.55 / 0.20. Before/after risk-file SHA-256 and dataset file-size/mtime snapshot digests matched. No dataset file was written and final DEV/TEST artifacts were left unchanged.

## Changed files and operational limits

Created: `src/services/observability.py`, `tests/test_observability.py`, `frontend/Dockerfile`, `frontend/.dockerignore`, and this report.

Modified in this task: `Dockerfile`, `docker-compose.yml`, `.env.example`, `frontend/next.config.ts`, `src/config.py`, `src/main.py`, `src/agents/graph.py`, `src/api/routers/health.py`, `src/api/routers/analysis.py`. Earlier unrelated workspace changes were preserved. Deleted: none. Temporary smoke scripts, override, safety digest, and sanitized smoke results are under ignored `runtime/`.

Cold-start read-only IOC integrity validation is expensive on the Windows Docker bind mount: the first URL-containing upload took approximately 65 seconds; the neutral upload took approximately 109 ms afterward. These are smoke observations, not a benchmark. Existing IOC/risk behavior was retained. Langfuse remote credentials/service delivery and a persistent multi-worker metrics backend were not exercised or provisioned.
