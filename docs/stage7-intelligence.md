# Stage 7 intelligence enrichment

Stage 7 adds optional intelligence to the existing deterministic pipeline. C4
remains unchanged: suspicious 30, phishing 65, derived-domain weight 0.20 without
an override. Local exact-match IOC lookup remains primary; no index is rebuilt
on application startup or request handling.

## Runtime configuration

`CONTENT_BEC_ENABLED`, `VERDICT_LLM_ENABLED`, and `RAG_ENABLED` independently opt
in to their production paths. They default to false in `.env.example`. Local
`.env` enables all three. `OPENAI_BASE_URL`, `OPENAI_API_KEY`, `MODEL_NAME`, and
`LLM_TIMEOUT_SECONDS` configure generation. The verified model is `gpt-4o-mini`.
Generation has no tools, uses structured JSON schemas and disables SDK retries.
The implementation follows [OpenAI structured output documentation](https://developers.openai.com/api/docs/guides/structured-outputs?api-mode=chat).

`EXTERNAL_ENRICHMENT_ENABLED` enables optional external intelligence. VT and
urlscan additionally require their individual `*_ENABLED` flags and API keys.
Local VT/urlscan flags remain false because their keys are absent. Configuring a
key alone does not disclose indicators to a provider.

Each provider has timeout, TTL, and minimum interval controls in `.env.example`.
The process-local cache holds at most 512 successful responses, including empty
search results. Errors are not cached as successes. HTTP 429 starts a cooldown
of at least 60 seconds. Requests during the interval return RATE_LIMITED without
sleeping or retrying. Each worker has its own budget; distributed quota handling
is not implemented. Per-email budgets default to two URLs and two hashes.

## Content and verdict boundaries

Content/BEC sees only the parser's separate redacted subject/text/HTML copy.
Numbered redacted segments are untrusted DATA in the user message. The structured
classifier returns signal kind, confidence, and a segment reference. The server
validates the reference and copies the supporting quote itself. Missing or
invalid references cannot become trusted evidence. Regex redaction is not a
guarantee of complete PII coverage.

Multiple correlated BEC tags produce one BEC_REQUEST evidence item, with family
`content_bec` and provenance `llm`. Existing weight and LLM cap are both 0.10;
family cap is 0.15. Missing or failed generation produces UNKNOWN evidence.

The verdict model receives validated fact metadata, immutable RiskResult,
allowed claim templates, and optional untrusted knowledge context. It does not
receive raw email, raw IOC values, or attachment bytes. Its output schema has
only claims, actions, and summary. Score/label are copied from RiskResult by
server code. Gate 2 still validates every output, including exact templates and
canonical indicator bindings. Invalid claims may retry once; provider outages
do not trigger another billable request. `verdict_llm_status` and trust warnings
expose failure separately from deterministic score and label.

## External intelligence

ThreatIntelService preserves separate local, VT, and urlscan results. Local
confirmed exact hits avoid redundant remote lookups. VT exposes only GET
`/files/{sha256}`. It never uploads or rescans files. Reports preserve hash,
lookup timestamp, analysis timestamp, source reference, and vendor statistics.
At least three malicious detections are required for the existing IOC_MATCH
policy. One/two detections or suspicious-only results remain inconclusive
UNKNOWN. This conservative rule is not a calibrated production benchmark.

urlscan searches existing scans and retrieves matching reports. It exposes no
submission or browser interface and never follows the queried URL. Production
privacy filtering blocks query strings, credentials, fragments, recognized PII,
and token-like paths. Blocking yields UNKNOWN through ToolResult rather than
silently changing the query. This deliberately excludes some legitimate URLs;
the local analyzer still inspects the original URL. `strict_privacy=False` is
used only by legacy synthetic transport tests; production configuration always
keeps the boundary enabled.

The common statuses remain OK/TIMEOUT/RATE_LIMITED/ERROR. Unavailable providers
use ERROR with a NOT_CONFIGURED error code. Non-OK results produce UNKNOWN
evidence. No data from urlscan is UNKNOWN even when the search completed with
ToolResult OK. No provider failure is a clean result.

## RAG and Docker

RAG runs after deterministic scoring. Its separate validated knowledge evidence
can support explanation claims but never enters risk aggregation or coverage.
Retrieval verifies the existing collection identity, source hashes and citation
provenance. Empty or unavailable context cannot fabricate malicious IOC evidence.

Docker mounts both `data/` and the existing `runtime/` IOC index read-only. Both
directories are excluded from the image build context. Runtime activation
requires recreating the backend with the updated image/environment; the Stage 7
verification does this without restarting PostgreSQL or Qdrant.

## Verification

```powershell
.venv\Scripts\python.exe -m compileall src
.venv\Scripts\python.exe -m pytest -q
.venv\Scripts\python.exe -m ruff check src tests
.venv\Scripts\python.exe -m scripts.smoke_stage7
```

The smoke command runs five synthetic emails, two source-filtered MITRE/NIST
queries, and at most one harmless lookup per configured external intelligence
provider. It performs no DEV/TEST evaluation or ingestion. Its report is
`eval/results/stage7_smoke.json`. `--retry-failed` retains successful results and
only retries failed cases. Historical attempts and call counts remain in the
report. Unit tests use explicit offline graphs and reject real synchronous HTTP
transports, independently of local production flags.
