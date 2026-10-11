# PhishHunter

PhishHunter is a SOC triage application for `.eml` files. It combines deterministic local analyzers and traceable evidence with a risk decision, a grounded verdict, and a human review workflow. It does not automatically open URLs, execute attachments, or take destructive response actions.

## Architecture and features

The FastAPI backend parses mail and runs Header, URL, Attachment, QR, and Content/BEC analyzers through LangGraph. Evidence is checked by Gate 1, scored by the deterministic Risk Engine, summarized by the Verdict layer, then checked by Gate 2 before a case is persisted for analyst review. PostgreSQL stores users, cases, reviews, actions, and audit events. The Next.js frontend provides login, analysis, and case review. Optional IOC, RAG, LLM, VirusTotal, urlscan, and Langfuse boundaries are separately configured and fail closed.

The `score` and `label_candidate` belong to the Risk Engine; verdict text cannot change them. Incomplete coverage can produce `NEEDS_ANALYST_REVIEW`. Evidence and claims retain provenance and evidence IDs. Human review is stored separately from the AI assessment.

## Repository layout

```text
src/                 FastAPI, LangGraph, analyzers, evidence, services, database
frontend/            Next.js SOC interface
tests/               tests and small local `.eml` fixtures
data/                curated dataset, manifests, IOC and RAG source files
eval/                 evaluation schemas, runners and recorded results
scripts/              local setup, IOC index and smoke utilities
docs/                 architecture, runbook, integration notes and final reports
docker-compose.yml    backend, frontend, PostgreSQL and Qdrant services
```

## Run locally with Docker

Prerequisites: Docker Desktop with Linux containers, a configured local `.env`, and the repository's prepared read-only data/IOC runtime inputs. Python 3.11 is needed for host-side utilities; Node 20.9+ is needed only for a separate frontend development server.

```powershell
Copy-Item .env.example .env
# Set private POSTGRES_PASSWORD and JWT_SECRET in .env; do not commit it.
docker compose config --quiet
docker compose up -d --build
docker compose ps
```

The Compose stack includes backend (`8000`), frontend (`3000`), PostgreSQL (`5432`, loopback), and Qdrant (`6333/6334`, loopback). The backend starts after PostgreSQL is healthy and Qdrant has started. See [the runbook](docs/runbook.md) for first-time data/index prerequisites, admin bootstrap, environment settings, and troubleshooting. `.env.example` lists supported variables; leave optional providers disabled for an offline local run. Never put secrets in `NEXT_PUBLIC_*` variables.

Liveness and readiness are distinct:

```powershell
Invoke-RestMethod http://localhost:8000/healthz
Invoke-RestMethod http://localhost:8000/readyz
```

`/healthz` confirms the process responds. `/readyz` checks PostgreSQL/migration state, required configuration, and the local IOC snapshot; Qdrant is checked when RAG is enabled. The API also exposes `GET /api/v1/health`. Open the UI at <http://localhost:3000/login> and Swagger at <http://localhost:8000/docs>.

## Analyze a local email

Create an admin and an Analyst using the steps in [the runbook](docs/runbook.md), then log in at the frontend or call `POST /api/v1/auth/login` with JSON `{"email":"...","password":"..."}`. Use the resulting bearer token to upload a local fixture:

```powershell
curl.exe --fail-with-body -H "Authorization: Bearer $env:PHISHHUNTER_ACCESS_TOKEN" -F "file=@tests/fixtures/emails/href_mismatch.eml" http://localhost:8000/api/v1/analysis
```

The endpoint accepts multipart field `file` and persists a `PENDING` case. A shortened response shape is:

```json
{
  "case_id": "<server-generated-id>",
  "status": "PENDING",
  "score": 60,
  "label_candidate": "SUSPICIOUS",
  "analysis_scope": "static_local_partial",
  "coverage": {"required": [], "applicable": [], "completed": [], "missing": [], "unknown": [], "ratio": 0.0, "complete": false},
  "evidence": [{"evidence_id": "<id>", "analyzer": "url", "tool": "static_rules", "signal_type": "HREF_MISMATCH", "family": "url_deception", "indicator": "<indicator>", "value": "<url>", "result": "FAIL", "tool_status": "OK", "severity": "medium", "confidence": 0.9, "provenance": {"source": "local", "reference": "url:static_rules:v1"}, "collected_at": "<timestamp>"}],
  "contributions": [{"evidence_id": "<id>", "signal_type": "HREF_MISMATCH", "family": "url_deception", "strength": 0.35, "applied_strength": 0.35}],
  "claims": [{"claim_type": "URL", "text": "...", "evidence_ids": ["<id>"]}],
  "claim_validation_status": "PASS"
}
```

This abbreviated response uses the score/label/scope recorded for `href_mismatch.eml` in the G9 local HTTP smoke; evidence, contribution, and claim contents are illustrative placeholders and other fields are omitted. Retrieve the case at `GET /api/v1/cases/{case_id}`. Review and audit routes are documented in [the API contract](docs/api-contract.md).

## Optional integrations

The default path is local and deterministic. IOC uses exact-match against a local normalized snapshot. RAG can supply retrieved knowledge context, but does not contribute to risk score. Content/BEC and verdict LLM adapters require explicit provisioning. VirusTotal is limited to read-only hash lookup; urlscan uses read-only lookup/results and does not submit URLs. Real provider calls were not made during final validation. Enabling a key alone does not mean that a provider or end-to-end capability has been verified. See [IOC](docs/ioc-integration.md), [RAG](docs/rag-integration.md), and [Stage 7](docs/stage7-intelligence.md).

## Evaluation snapshot

Frozen R2-F configuration: phishing threshold `62`, suspicious threshold `30`, `URL_IP_LITERAL=0.55`, and `IOC_DERIVED_DOMAIN=0.20`. DEV and final TEST results are recorded in [the final report](docs/final_report.md) and their source artifacts under `eval/results/`. Final TEST phishing recall was **25.0883%**, decision coverage **23.4375%**, and abstention **76.5625%**. Precision is calculated over predictions labeled PHISHING; it is not end-to-end accuracy. TEST was used once for final reporting and was not used for tuning. These are results on the curated evaluation split, not production metrics.

## Known limitations

The system is conservative: most analyzed mail remains `NEEDS_ANALYST_REVIEW`, and current phishing recall is about 25% on the final TEST split. Some phishing messages contain no positive deterministic signal. Many messages lack trusted Authentication-Results coverage, so SAFE decisions are intentionally constrained. BEC has weak evidence and currently does not affect classification under the frozen policy; the BEC samples are synthetic and human-validated. There is no Vietnamese email corpus or email-with-QR corpus, although separate Vietnamese URL, QR, and other capability datasets exist. Auth Header capability is partial. Eight E2A samples were unavailable on Windows after Defender quarantine and were skipped in evaluation. Real VirusTotal/urlscan providers were not verified because keys were not configured. See the [final report](docs/final_report.md) for metric denominators and validation scope.
