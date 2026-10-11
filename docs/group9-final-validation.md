# GROUP 9 — Final integration / cleanup / validation

Local validation **PASS** within the available environment. Full Docker/PostgreSQL/
Qdrant runtime and PostgreSQL HITL persistence are **NOT VERIFIED**. No production
metrics or deployment-readiness claim is made. Dataset thật = **NOT USED**;
external real APIs = **NOT TESTED**; production metrics = **NOT AVAILABLE**.

## Pre-flight and preserved work

Read GROUP 9 prompt, git status/diff, Compose, Dockerfile, env examples, README,
Settings, Alembic/ORM, backend routes/services, frontend config/workflow tests, and
GROUP 8 harness. GROUP 8 changes were already present and were preserved. File lists
below are GROUP 9 deltas against the working-tree snapshot, not all uncommitted files.

No changes to `src/`, risk policy, ORM or migrations, frontend application source, or
existing evaluation code/manifests/artifacts. SHA-256 comparison of 136 existing files
under source/config/frontend source/eval found no changes. No dependency installation,
dataset ingestion, real external requests, risk tuning or architecture redesign.

Environment: Windows PowerShell, Python 3.11 venv, Node 22.19.0, npm 10.9.3,
Docker CLI 29.8.0, Compose v5.5.1. Existing frontend node_modules were available.

## Files created / modified / deleted

Created (14):

- `docs/runbook.md`
- `docs/group9-final-validation.md`
- `scripts/smoke_support.py`
- `docs/examples/group9-compose.json`
- `docs/examples/group9-migration.json`
- `docs/examples/group9-backend-http.json`
- `docs/examples/group9-workflow-response.json`
- `docs/examples/group9-external-smoke.json`
- `docs/examples/group9-browser/group6-dashboard.png`
- `docs/examples/group9-browser/group6-case-review.png`
- `eval/results/group9-dev.json`
- `eval/results/group9-dev.md`
- `eval/results/group9-test.json`
- `eval/results/group9-test.md`

Modified (12):

- `.dockerignore`: exclude nested secret envs and Node/Next/test artifacts from build context.
- `.env.example`: remove misleading unused provider suggestions; clarify frontend env/build boundary.
- `.github/workflows/ci.yml`: lint evaluation and smoke scripts as well as src/tests.
- `README.md`: actual project identity, required config, host/Compose migration instructions and runbook links.
- `scripts/setup.sh`: remove stale Chroma directory/API-key requirement; point to explicit DB/bootstrap steps.
- `scripts/seed_database.py`: unsupported seeding now fails explicitly rather than reporting successful no-op.
- `scripts/reset_local_db.py`: unsupported destructive reset fails explicitly, performs no deletion.
- `scripts/ingest_rag.py`: unsupported ingestion fails explicitly, performs no ingestion/API call.
- `scripts/smoke_group5.py`: output path selection, explicit external-disabled env, suspicious MODIFY case,
  and shared process-tree cleanup.
- `scripts/smoke_group6.py`: artifact directory selection, explicit external-disabled env and shared cleanup.
- `scripts/smoke_group7.py`: output path selection and reuse of lifecycle helpers.
- `frontend/tests/workflow.spec.ts`: optional artifact directory; browser assertions unchanged.

Deleted: **none**. Existing GROUP 5–8 artifacts remain historical; GROUP 9 results
are written separately. Screenshot basenames retain GROUP 6 workflow names inside the
new GROUP 9 directory because those tests were reused.

## Validation matrix

| Check | Result | Evidence / limit |
| --- | --- | --- |
| Compile | PASS | `python -m compileall src` |
| Pytest | PASS | 163 tests, including 18 evaluation tests |
| Ruff | PASS | src/tests plus eval and changed Python scripts |
| Frontend lint | PASS | `npm run lint`, zero warnings |
| Frontend build | PASS | `npm run build` (webpack), TypeScript/static generation complete |
| Docker Compose config | PASS | quiet validation and JSON parse with temporary private env; no secret values saved |
| Docker runtime | NOT VERIFIED | Linux-engine pipe missing; daemon unavailable |
| PostgreSQL runtime | NOT VERIFIED | No Docker DB; DATABASE_URL absent; no SQLite production fallback |
| Alembic | NOT VERIFIED on PostgreSQL; offline/test PASS | heads/history, PostgreSQL DDL rendering, isolated test migration/ORM check |
| Qdrant runtime | NOT VERIFIED | No reachable provisioned Compose service; fake retrieval is not runtime verification |
| Backend HTTP smoke | PASS | Real host Uvicorn; health/OpenAPI/docs, fail-closed missing DB; authenticated workflows on explicit test adapter |
| Frontend/browser smoke | PASS | Real production Next.js + Chromium, 5/5 workflows |
| End-to-end HITL persistence | NOT VERIFIED on PostgreSQL | HTTP/browser persistence PASS on explicit isolated SQLite test adapter only |
| Evaluation harness regression | PASS | Dev 15 cases, test 3; both exit 0 |
| Security review | PASS within inspected scope | No critical regression found; static/manual and existing security regressions |
| Placeholder/dead-code review | PASS | Intentional boundaries retained; unsupported CLIs now explicit |
| External real APIs | NOT TESTED | GROUP 7 fakes only, real transport not used |
| Dataset thật | NOT USED | Existing synthetic fixtures only |
| Production metrics | NOT AVAILABLE | No production benchmark or model security claim |

## Docker, PostgreSQL, Alembic and Qdrant

Compose has backend, PostgreSQL and Qdrant, not frontend. Backend publishes 8000 on
all interfaces; DB 5432 and Qdrant 6333/6334 publish only on loopback. PostgreSQL has
`pg_isready`, backend has HTTP liveness, Qdrant has no Compose healthcheck. Backend
depends on healthy postgres and started qdrant. Named volumes are postgres_data and
qdrant_data; backend binds ./data. Container DB hostname is postgres, Qdrant is qdrant;
host runtime uses localhost. See [sanitized config](examples/group9-compose.json).

Actual `docker info` failure:

```text
failed to connect to the docker API at npipe:////./pipe/dockerDesktopLinuxEngine
open //./pipe/dockerDesktopLinuxEngine: The system cannot find the file specified.
```

No daemon was assumed, no containers were claimed healthy and no `compose up` was
attempted after that failure. The workspace had no `.env`. Compose config was validated
using a short-lived `.env` with random validation-only credentials, removed in finally;
full interpolated config/credentials were not printed or persisted. Dockerfile was
reviewed statically (multi-stage Python, non-root user, HTTP healthcheck); image build
and container startup remain unverified without the daemon.

`alembic heads` returned `0001_group5 (head)`; `history` showed a single initial revision.
`alembic current` without DB configuration failed closed with DATABASE_NOT_CONFIGURED.
This is not evidence of a migration defect. PostgreSQL upgrade/current/schema checks,
user/login and persistence have not been exercised against a real server.

Separately, isolated SQLite migration `upgrade head` matched ORM with **0 differences**
and tables users/analysis_cases/case_actions/audit_logs/alembic_version. PostgreSQL
offline DDL rendered UUID, JSONB and TIMESTAMP WITH TIME ZONE. No unnecessary migration
was generated. [Migration evidence](examples/group9-migration.json).

Qdrant container reachability/client connection is unverified. The current RAG service
requires an explicitly provisioned repository/embedding adapter; URL/collection settings
alone do not construct one. Unconfigured/failing retrieval returns unavailable/empty
context, not fabricated claims. This fallback is regression-tested without a corpus.

## Real HTTP and browser flows

Started actual `uvicorn src.main:app` on host, production environment, no dependency
overrides and no DB/JWT/provider credentials. [HTTP artifact](examples/group9-backend-http.json):

| Request | Status / outcome |
| --- | --- |
| GET /api/v1/health | 200: status ok, service PhishHunter, env production |
| GET /openapi.json | 200, 14 API paths |
| GET /docs | 200 |
| GET /api/v1/cases without auth | 401 |
| POST /api/v1/auth/login without DB | 503 DATABASE_NOT_CONFIGURED |

For authenticated acceptance, launched the same application with the existing explicit
test DB dependency override, migrated temporary DB and random Analyst/Admin credentials.
This is not a production SQLite configuration or fallback. All calls used TCP HTTP:

- Analyst login/me: 200; analyst access to admin users: 403.
- Clean upload: 200, score 0, case PENDING; read: 200.
- APPROVE: 200, reload APPROVED; action authorization 200/AUTHORIZED; audit 200.
- REJECT: 200, reload REJECTED; authorization denied 409 and remains PROPOSED.
- Suspicious href mismatch: score 60, candidate NEEDS_ANALYST_REVIEW offline; MODIFY 200,
  reload MODIFIED, AI assessment unchanged, separate analyst SUSPICIOUS result persisted.
- Repeated final review: 409. Premature action authorization: 409. Action audit survives denial.
- Prompt injection upload retains score 60/review candidate; Gate 2 PASS. No real provider keys.

[Before/after/audit snapshots](examples/group9-workflow-response.json) contain no credentials
or bearer tokens. Reload proves test DB persistence, not PostgreSQL runtime.

Browser acceptance started production `next start` with localhost:8000 backend URL
compiled into the build. Real Chromium passed five existing scenarios: clean approve/
refresh/authorize/audit/logout; reject/stale-tab 409; suspicious modify preserving AI
and escaping/defanging XSS input; 401/403/404 and malformed/large/wrong upload handling;
admin create/update and system audit. Screenshots were also visually inspected:
[dashboard](examples/group9-browser/group6-dashboard.png),
[modified case](examples/group9-browser/group6-case-review.png).

An initial HTTP acceptance run completed flows but failed Windows temp DB cleanup.
The venv launcher can leave a Python child holding SQLite handles when only the launcher
is terminated. Reused GROUP 7 owned-process-tree shutdown/bounded cleanup retry in a
shared smoke helper; reruns of HTTP, browser and external smoke all exited 0. No
production process handling changed. Persistent cleanup failure still fails the smoke;
it is not ignored. The failed run's owned temp DB was removed; no smoke servers remain.

## External and evaluation regression

Real HTTP with injected GROUP 7 providers passed seven cases: clean, URL mismatch,
attachment metadata, decoded QR URL, fake BEC, timeout and unavailable. Every analysis
returned 200. Timeout/unavailable cases retained score 60/50 but candidate review and
partial scope/coverage; UNKNOWN did not silently become SAFE. Missing RAG/model/VT/urlscan
does not crash or invent successful results. [External artifact](examples/group9-external-smoke.json).

Sample runners used explicit fake/offline profiles only:

| Result | Dev | Test |
| --- | --- | --- |
| Cases | 15: 14 success, 1 expected MALFORMED_EMAIL | 3 success |
| Unexpected errors / exit | 0 / 0 | 0 / 0 |
| Evidence Recall | 19/19 | 4/4 |
| Grounded Claim Rate | 37/39 | 4/4 |
| Candidate Review Rate | 2/14 | 0/3 |
| Prompt Injection ASR | 0/5 | 0/1 |
| Cost / secret leak observation | null / null | null / null |

Reports: [dev JSON](../eval/results/group9-dev.json), [dev summary](../eval/results/group9-dev.md),
[test JSON](../eval/results/group9-test.json), [test summary](../eval/results/group9-test.md).
These fixtures validate the harness, not production precision/F1 or real-model security.
Existing tests verify no real transport invocation and no settings/risk policy mutation.
Risk-policy SHA-256 remains `dbed9272e335865d6ecbca077656a022731bfd6024a4e7f1ab92b34ace4df0ad`.

## Security, placeholder and configuration review

Review and regression evidence:

- No high-confidence API-key/private-key pattern matches in repository text; all 24
  Settings fields are documented in env example. Scan plus manual review is not exhaustive
  secret detection. Synthetic test credentials are labeled and separated.
- JWT secret comes from private configuration and fails closed when missing/short.
  Passwords use Argon2id; UserResponse excludes password_hash; validation errors remove inputs.
- Token/password values are absent from saved smoke reports and normal access logs;
  smoke credentials are temporary, server logs withheld and browser diagnostic output redacted.
- React renders escaped/defanged email/evidence text; no dangerouslySetInnerHTML and
  no malicious external anchors. Browser test checks XSS payload is inert.
- Attachment inspection does not execute files; archive reads have entry/depth/byte limits.
  VT only uses hash GET lookup; urlscan only searches/retrieves existing scans.
- Backend validates role using current DB user, not frontend RBAC or caller reviewer ID.
  Review saves only human fields; AI snapshot and risk values remain immutable.
- Action input rejects EXECUTED state; application/model has no execution transition.
  Audit protections are at application/ORM layer, not a guarantee against privileged raw SQL.

Pattern audit classified:

| Class | Findings / handling |
| --- | --- |
| A: intentional interfaces/boundaries | Protocol ellipses, unprovisioned LLM/RAG, unconfigured IOC; retained. Guarded pass statements for invalid URL normalization or readiness retry are intentional. Dummy password hash is randomized timing protection, not fabricated data. |
| B: development artifacts | Unused legacy vehicle-data validator is outside production/import paths; retained, not advertised as PhishHunter runtime. No-op seed/reset/ingest scripts now fail explicitly. Smoke lifecycle duplication consolidated. |
| C: integration defect | Windows smoke process/temp cleanup fixed and rerun successfully. No incomplete production path requiring source changes was found. |

Ruff found no unused imports in the checked paths. ThreatIntelService is an exact-match
facade, RAG is semantic knowledge context; neither was replaced or duplicated. Settings/
Compose/frontend env names were cross-checked. PostgreSQL/NEXT_PUBLIC fields are documented
as Compose/browser-specific, not backend Settings. Runbook explains APP_HOST/PORT CLI
binding, build-time public URL, migration/bootstrap, health limits and optional providers.

## Reproduction, blockers and optional integrations

See [runbook](runbook.md) for installation, Docker/host startup, migration/bootstrap,
frontend, authenticated flow, tests and evaluation commands. Final checks executed with
`.venv\Scripts\python.exe`:

```text
python -m compileall src
pytest -q
ruff check src tests
ruff check eval scripts/run_eval.py scripts/smoke_group5.py scripts/smoke_group6.py scripts/smoke_group7.py scripts/smoke_support.py scripts/ingest_rag.py scripts/reset_local_db.py scripts/seed_database.py
npm run lint
npm run build
docker compose config --quiet
python -m scripts.smoke_group5 --test-db --output docs/examples/group9-workflow-response.json
python -m scripts.smoke_group6 --test-db --artifacts docs/examples/group9-browser
python -m scripts.smoke_group7 --test-db --output docs/examples/group9-external-smoke.json
python -m eval.run --manifest eval/sample_manifest.jsonl --split dev --output eval/results/group9-dev.json
python -m eval.run --manifest eval/sample_test_manifest.jsonl --split test --output eval/results/group9-test.json
```

Sample evaluations additionally used trusted fixture receiver mx.recipient.test and
protected domain paypal.test in the process environment. These were not saved as
production config. Frontend build used public localhost:8000 API and disabled telemetry.

Remaining runtime blockers: Docker Desktop Linux engine unavailable; no configured
PostgreSQL DB/JWT/Compose password in workspace. When provisioned, run container startup,
migration on fresh PostgreSQL test DB, authenticated flows/audit persistence and Qdrant
reachability/client checks before claiming full runtime validation.

Remaining optional integrations: real VT/urlscan keys, structured LLM adapter, provisioned
Qdrant knowledge repository/embeddings, trusted IOC/feed/corpus ingestion, and independently
labeled datasets with proper dev/test splits and actual usage metadata. None were invoked
or implemented in this final validation group.

GROUP 9 ends here. No dataset download, API provisioning or tuning was started.
