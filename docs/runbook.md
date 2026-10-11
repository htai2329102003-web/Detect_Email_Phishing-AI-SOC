# PhishHunter local runbook

Run commands from repository root unless a step explicitly changes directory. Python
3.11, Git and Node >=20.9 are required. Auth/cases require PostgreSQL plus a persistent
JWT secret; health and graph/eval tests can run without PostgreSQL. Docker Desktop
(Linux containers) is the documented local infrastructure option. Qdrant is included
in Compose but is optional to analysis when enrichment is disabled.

External VirusTotal/urlscan keys, structured LLM adapters, Qdrant repository/embeddings,
IOC snapshots and ingestion are optional integrations. They are not required to run
static analysis, the frontend or fixture evaluations. No dataset or real API is
automatically fetched. See [final validation](group9-final-validation.md) for what
has and has not been exercised on this machine.

## Python and environment

PowerShell:

```powershell
py -3.11 -m venv .venv
& .venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item .env.example .env
```

POSIX equivalent: `python3.11 -m venv .venv`, `source .venv/bin/activate`,
`pip install -r requirements.txt`, `cp .env.example .env`. Do not overwrite an existing
configured `.env`. Edit it privately before using auth/analysis/cases.

| Setting | Required / meaning |
| --- | --- |
| `DATABASE_URL` | Host runtime: PostgreSQL URL with URL-encoded password and actual DB. Compose overrides host/port to `postgres:5432`. No SQLite fallback. |
| `POSTGRES_PASSWORD` | Required Compose interpolation; use URL-safe characters because Compose constructs the DB URL. |
| `POSTGRES_USER`, `POSTGRES_DB` | Compose defaults `phishhunter`; changing password does not reinitialize an existing volume. |
| `JWT_SECRET` | Required for auth, persistent private random secret >=32 bytes. Generate once with a cryptographic generator and store privately. Never a checked-in/default value. |
| `JWT_ACCESS_MINUTES`, `JWT_ISSUER`, `JWT_AUDIENCE` | Auth policy; defaults documented in `.env.example`/Settings. |
| `CORS_ORIGINS` | Comma-separated browser origins. Must match frontend origin, including port. |
| `HEADER_TRUSTED_AUTHSERV_IDS` | Optional trusted receiving-server IDs. Empty means auth claims UNKNOWN; never trust a sender-forged export. |
| `URL_PROTECTED_DOMAINS` | Optional local look-alike reference domains. |
| `EXTERNAL_ENRICHMENT_ENABLED` | Keep `false` for offline/static operation. |
| `VIRUSTOTAL_*`, `URLSCAN_*`, `EXTERNAL_TIMEOUT_SECONDS` | Optional read-only providers; no upload/rescan/URL submission. |
| `OPENAI_API_KEY`, `MODEL_NAME`, `LLM_TEMPERATURE` | Optional provider configuration. Keys alone do not provision the structured content/verdict adapter. |
| `QDRANT_URL`, `QDRANT_COLLECTION` | Host: `http://localhost:6333`; container: `http://qdrant:6333`. URL alone does not enable RAG; repository/embeddings must be injected explicitly. |
| `APP_ENV`, `APP_NAME`, `LOG_LEVEL` | App configuration. Uvicorn binding/logging is controlled by its CLI arguments. |
| `APP_HOST`, `APP_PORT` | Settings values; current run commands and Docker CMD use explicit Uvicorn host/port flags. |
| `NEXT_PUBLIC_API_URL` | Public browser URL, copied via `frontend/.env.example` to `frontend/.env.local`, compiled at build time. Backend `.env` is not automatically read by Next.js. |

Do not put private keys in `NEXT_PUBLIC_*`, commit env files, dump settings into logs,
or store raw bearer tokens in artifacts. `.dockerignore` excludes root/nested secret
env files, Node dependencies and Next.js/test build artifacts while keeping examples.

## Docker and infrastructure

```powershell
docker --version
docker compose version
docker info
docker compose config --quiet
docker compose up -d --build
docker compose ps
```

`config --quiet` avoids printing interpolated secrets. Missing `.env`/POSTGRES_PASSWORD
must be configured, not bypassed with a default password. If the Docker daemon pipe
is absent, start Docker Desktop and wait for Linux engine readiness before retrying.
Do not switch production storage to SQLite to work around a Docker/DB failure.

| Service | Ports | Health / dependencies | Persistence |
| --- | --- | --- | --- |
| backend | 8000:8000 | Python HTTP liveness; depends on healthy postgres and started qdrant | `./data:/app/data` |
| postgres | loopback 5432 | `pg_isready` | `postgres_data` named volume |
| qdrant | loopback 6333 HTTP, 6334 gRPC | No Compose healthcheck; inspect reachability separately | `qdrant_data` named volume |
| frontend | host default 3000 | Separate Next.js process; absent from Compose | local build |

Backend is published on all host interfaces by current Compose; use only the intended
network and provision auth before exposure. A healthy backend endpoint proves liveness,
not PostgreSQL/Qdrant readiness. There is no automatic migration or admin seeding.

```powershell
docker compose exec backend python -m alembic heads
docker compose exec backend python -m alembic history
docker compose exec backend python -m alembic upgrade head
docker compose exec backend python -m alembic current
docker compose exec backend python -m scripts.create_admin --email admin@example.test
Invoke-RestMethod http://localhost:6333/
```

Bootstrap asks for a password through `getpass`. No default users exist. Admin can create
an Analyst in the frontend or `POST /api/v1/admin/users`. Current schema head is
`0001_group5`; tables are users, analysis_cases, case_actions, audit_logs and alembic_version.
Use a newly provisioned test PostgreSQL DB for migration validation, configure its
DATABASE_URL privately, then run upgrade/current against that DB. Do not autogenerate
a migration without reviewing an actual schema difference.

Qdrant reachability and configured RAG retrieval are distinct: an empty/unprovisioned
collection/repository yields unavailable context and must not invent evidence/claims.
GROUP 9 does not ingest corpus or call embeddings. `docker compose stop` preserves
data. Do not use `down -v` or delete volumes to fix credentials; review backup/restore
and credentials for the existing database instead.

## Host backend and frontend

If only infrastructure runs in Compose (`docker compose up -d postgres qdrant`), set
host DATABASE_URL to localhost, then migrate/bootstrap and start the backend:

```powershell
& .venv\Scripts\python.exe -m alembic upgrade head
& .venv\Scripts\python.exe -m scripts.create_admin --email admin@example.test
& .venv\Scripts\python.exe -m uvicorn src.main:app --host 127.0.0.1 --port 8000
```

Health: `http://localhost:8000/api/v1/health`; Swagger: `/docs`; schema: `/openapi.json`.
Choose either host backend or Compose backend on port 8000, not both. With DB unconfigured,
health still returns 200 and login returns 503 DATABASE_NOT_CONFIGURED, as intended.

In another terminal:

```powershell
cd frontend
Copy-Item .env.example .env.local
npm ci
npm run lint
npm run build
npm start
```

Or `npm run dev` while developing. Keep a configured `.env.local` when it already exists.
The browser must reach NEXT_PUBLIC_API_URL: for local host/container backend published
on 8000 use `http://localhost:8000/api/v1`, not `http://backend:8000`. A remote browser
needs a backend URL reachable from that browser. Rebuild after changing this variable;
runtime changes alone do not change the compiled browser bundle. CORS must match
the frontend origin, normally `http://localhost:3000`.

## Analysis, HITL and actions

1. Login as an Analyst created by Admin.
2. Upload `tests/fixtures/emails/clean.eml`; open the resulting PENDING case.
3. APPROVE, reload and confirm APPROVED plus REVIEW_APPROVED audit.
4. Upload `href_mismatch.eml`; inspect evidence, candidate label and coverage. Offline
   IOC is unavailable, so score 60 can have candidate NEEDS_ANALYST_REVIEW.
5. MODIFY with reason and separate analyst assessment, or REJECT. Reload: AI snapshot,
   score and candidate label must remain unchanged; human assessment/reviewer are separate.
6. Propose an action. Pending/rejected cases cannot authorize; an approved case can,
   or a modified case only for its explicitly allowed action kinds. No action executes.

For scripted upload after obtaining an actual login token privately:

```powershell
curl.exe --fail-with-body -H "Authorization: Bearer $env:PHISHHUNTER_ACCESS_TOKEN" -F "file=@tests/fixtures/emails/clean.eml" http://localhost:8000/api/v1/analysis
```

Tokens/passwords must not be saved in logs or sample artifacts. HTTP 401 requires login,
403 means backend denies the role, 409 is final review/action conflict, 422 malformed
email/input, 503 unavailable DB/auth config. Case/audit read endpoints are authenticated.
Human identity comes from the validated token and current DB user, never request payload.

## Regression and fixtures

From repository root:

```powershell
& .venv\Scripts\python.exe -m compileall src
& .venv\Scripts\python.exe -m pytest -q
& .venv\Scripts\python.exe -m ruff check src tests eval scripts/run_eval.py scripts/smoke_group5.py scripts/smoke_group6.py scripts/smoke_group7.py scripts/smoke_support.py
& .venv\Scripts\python.exe -m scripts.smoke_group5 --test-db --output docs/examples/local-workflow.json
& .venv\Scripts\python.exe -m scripts.smoke_group6 --test-db --artifacts docs/examples/local-browser
& .venv\Scripts\python.exe -m scripts.smoke_group7 --test-db --output docs/examples/local-external.json
```

Browser smoke requires a frontend build targeting localhost:8000, port 8000 free,
and Playwright Chromium installed (`cd frontend; npx playwright install chromium` if
missing). Smoke servers use real HTTP/browser, random temporary credentials, explicit
SQLite test dependency override and temporary DBs. They do not prove PostgreSQL runtime.
External smoke uses GROUP 7 fakes; no Internet provider calls. Existing servers are
not reused or killed. Owned process trees and temporary DBs are cleaned up on exit.

Evaluation (synthetic fixture validation only):

```powershell
$env:HEADER_TRUSTED_AUTHSERV_IDS='mx.recipient.test'
$env:URL_PROTECTED_DOMAINS='paypal.test'
& .venv\Scripts\python.exe -m eval.run --manifest eval/sample_manifest.jsonl --split dev --output eval/results/local-dev.json
& .venv\Scripts\python.exe -m eval.run --manifest eval/sample_test_manifest.jsonl --split test --output eval/results/local-test.json
```

Runner does not mutate config, tune thresholds or call real providers. Keep review as
a separate label, raw counts and null unavailable metrics. Dev/test samples are not an
independent production benchmark. See [GROUP 8](group8-evaluation-harness.md).

`scripts.seed_database`, `scripts.reset_local_db`, `scripts.ingest_rag` are intentionally
unsupported and exit nonzero. Bootstrap uses `scripts.create_admin`; data ingestion,
destructive reset and real provider provisioning require separate work.
