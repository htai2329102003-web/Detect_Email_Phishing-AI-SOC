# GROUP 7 — External Boundaries & Mocks

Hoàn thành boundaries + fake transports theo ToolResult GROUP 1. Đã đọc code
GROUP 1–6 trước khi sửa. Không dùng key thật, upload file, submit URL, ingest feed
hoặc corpus thật, tune weights, evaluation dataset lớn, deploy hay GROUP 8.

## Thiết kế và behavior

`ExternalServices` là composition root được inject vào `build_graph`. Default
`external_services=None` giữ nguyên graph static. Production chỉ tạo optional
services khi `EXTERNAL_ENRICHMENT_ENABLED=true`; không tự bật vì thấy API key.
Không có fake client hoặc mock response trong production source/path.

```text
parse → header/url/attachment/qr → [optional external enrichment]
      → Gate 1 → Risk Engine → [optional RAG context] → Verdict → Gate 2
```

- **HTTP transport:** GET-only, HTTPS provider base URL, không follow redirect,
  không đọc/mở URL đích. Response tối đa 1 MiB, timeout mặc định 5 giây mỗi HTTP
  operation, không retry/poll khi 429 hoặc lỗi. Một URL lookup tối đa 2 GET
  (search + result). Deduplicate canonical URL/hash, tối đa 16 URL + 16 hash mỗi
  case; vượt budget thêm UNKNOWN. Không có cache sẵn trong architecture hiện tại;
  GROUP 7 chưa thêm cache hoặc distributed cache, tránh reuse report cũ như fact mới.
- **VirusTotalClient:** chỉ `/files/{sha256}`, header `x-apikey`, không upload,
  submit/rescan hoặc execution. Kiểm tra SHA-256 canonical phải khớp cả report ID
  và attributes. Normalized `FileReputation` có hash, malicious/suspicious/harmless/
  undetected counts, last_analysis_at và source_reference. Counts strict integer
  không âm; invalid JSON/schema/hash mismatch không tạo positive evidence.
- **URLScanClient:** `/search/` rồi `/result/{uuid}/`, header `api-key`; không có
  submission method. Quoted search query được đối chiếu canonical exact URL
  lần nữa ở cả search hit và result; không dùng near match làm malicious hit.
  `URLReport` gồm scanned_url, final_url, observed redirect chain, malicious flag
  nếu provider có, domains/IPs và source_reference. Empty search hoặc thiếu verdict
  là UNKNOWN ở enrichment, không chứng minh URL harmless.
- **ThreatIntelService:** lookup_domain/url/ip/hash qua `lookup_ioc`, canonical
  exact-match. Tách hoàn toàn semantic RAG. Không có match không tạo IOC_MATCH;
  miss chỉ có nghĩa không nằm trong snapshot được cấu hình.
- **IOC ingestion:** mở rộng IOCRecord bằng confidence, first_seen, last_seen,
  tags, metadata; legacy callers vẫn dùng được default. `IOCIngestRecord` bắt buộc
  source/confidence/aware timestamps, kiểm tra time ordering; hash ingestion chỉ
  nhận SHA-256. Batch tối đa 1.000 record, validate toàn bộ trước thay snapshot;
  invalid batch không thêm một phần. Domain lowercase/IDNA, URL normalization giữ
  nguyên path/query semantics, IP compressed, hash lowercase. Không download feed.
- **RAG/Qdrant:** `KnowledgeDocument`, `RetrievedChunk`, `KnowledgeRepository`,
  `RAGService`. Document kind chỉ MITRE/phishing technique/playbook/report/campaign.
  Retrieval trả ToolResult, chunks có text/source/document_id/score/metadata;
  query/limit/chunk size được giới hạn. Repository/collection unavailable hoặc
  empty trả context rỗng, không crash verdict. Query chỉ dùng family metadata,
  không gửi raw email/PII. Context chỉ vào VerdictRequest; không thành evidence,
  malicious IOC hoặc risk contribution. Gate 2 vẫn kiểm tra claims theo evidence.
- **LLM/BEC:** reuse `services/llm.py`, thêm StructuredModel/LLMClient, không tạo
  provider thứ hai. Model thật chưa provision: LLM_NOT_CONFIGURED, không dùng fake
  production result. Structured schema chỉ có tám nhóm BEC signals + confidence,
  không nhận score/label/free-form verdict. Content analyzer chỉ thấy bản sao
  redacted, không bytes/header/attachment. System instruction cố định, email là
  untrusted DATA, không tools. Redaction lỗi không gọi model.
- **BEC evidence:** một correlated `BEC_REQUEST` có tags + confidence rõ,
  family content_bec, provenance.source llm, severity low. Dùng nguyên weight
  0.10 và family cap 0.15 hiện có. Model không thể sửa risk hoặc override IOC/VT.
  Fake payment_request confidence 0.9 chỉ đóng góp 9 điểm; SAFE khi coverage đủ
  là threshold hiện có, không phải xác nhận BEC absent, và requires_review vẫn true.

## Evidence, fallback và compatibility

Giữ nguyên bốn status ToolResult: OK / TIMEOUT / RATE_LIMITED / ERROR. Không thêm
NOT_CONFIGURED vào enum; configuration missing và unauthorized là ERROR với code
riêng. Timeout → TIMEOUT; 429 → RATE_LIMITED; 401/403 → *_UNAUTHORIZED;
404/410 → *_NOT_FOUND; 5xx/HTTP lỗi → *_UPSTREAM_ERROR; invalid JSON/schema →
*_INVALID_RESPONSE; network → *_NETWORK_ERROR. Không đưa exception text, key,
request URL hay raw provider body vào error response. Injected client ném exception
hoặc trả schema sai cũng được containment.

Non-OK ToolResult luôn sinh UNKNOWN; OK nhưng không có report/verdict cũng UNKNOWN.
Static evidence được giữ lại, hợp nhất external evidence rồi mới qua Gate 1/Risk.
RAG failure chỉ bỏ context, không biến thành giả evidence. LLM missing/failure khi
enrichment bật tạo BEC_REQUEST UNKNOWN nên coverage thiếu và NEEDS_ANALYST_REVIEW.
Production exact-match IOC chưa cấu hình vẫn UNKNOWN kể cả provider khác chạy được.

Provider report exact hash/URL có malicious detection dùng signal **IOC_MATCH đã
có**, confidence mapping 0.95, family threat_intel, source external; counts và
reference được giữ trong value. Đây là adapter mapping chưa calibrated bằng dataset,
không phải xác suất accuracy. Completion dùng ATTACHMENT_IOC_CHECK/URL_IOC_CHECK.
Zero detections chỉ PASS cho provider check trong scope đó, không tự gán attachment
hay URL globally SAFE. VT suspicious count được giữ trong metadata, chưa thêm rule
scoring mới. Không sửa `config/risk_weights.yaml`, Risk Engine, Gate 1 hoặc Gate 2.

Hai thay đổi integration trong analyzer common là serialize IOC metadata bằng
`model_dump(mode="json")` để timestamps/tags đúng Evidence JsonValue, và truyền
confidence của IOC record vào IOC_MATCH. Legacy record confidence mặc định 1 nên
behavior cũ không đổi. Không sửa các rule của Header/URL/Attachment/QR Analyzer.

API thêm hai analysis_scope: **static_enriched**, **static_enriched_partial**.
Default static_local/static_local_partial giữ nguyên. Partial nếu có analyzer hoặc
requested enrichment trả UNKNOWN; RAG không thuộc evidence coverage. Scope được
persist trong AI assessment/case, không thay review/auth/action schemas. Frontend
chỉ mở rộng union type tương ứng; không đổi UI, routes hoặc session design.

## Config / env

| Variable | Default / ý nghĩa |
| --- | --- |
| EXTERNAL_ENRICHMENT_ENABLED | false, giữ behavior GROUP 1–6 |
| VIRUSTOTAL_API_KEY | rỗng, ERROR khi VT được yêu cầu |
| VIRUSTOTAL_BASE_URL | https://www.virustotal.com/api/v3 |
| URLSCAN_API_KEY | rỗng, ERROR khi urlscan được yêu cầu |
| URLSCAN_BASE_URL | https://urlscan.io/api/v1 |
| EXTERNAL_TIMEOUT_SECONDS | 5, giới hạn config (0,30] |
| QDRANT_URL | config có sẵn; env example localhost:6333 |
| QDRANT_COLLECTION | soc_knowledge |
| OPENAI_API_KEY / MODEL_NAME | dùng config LLM có sẵn, không thêm key convention |

Key/URL không tự provision Qdrant repository, embeddings hoặc structured model.
Các adapter đó cần được inject rõ sau này. Không tự dùng ChatOpenAI chỉ vì có key.
Không hardcode credentials; test key là literal synthetic, không hợp lệ ngoài tests.

## Kiểm chứng

| Check | Kết quả |
| --- | --- |
| python -m compileall src | PASS |
| pytest -q | PASS — 145 tests (103 regression + 42 GROUP 7) |
| ruff check src tests, kiểm tra thêm smoke script | PASS |
| Frontend npm run lint | PASS |
| Frontend npm run build | PASS |
| HTTP smoke qua Uvicorn/socket thật, auth/persistence thật, injected fakes | PASS — 7 uploads + case detail reads |
| Qdrant runtime | NOT VERIFIED — dùng fake repository, không có collection/corpus/embedding runtime |
| External real APIs: VT/urlscan/LLM | NOT TESTED — không dùng key thật |
| PostgreSQL runtime | NOT VERIFIED — smoke dùng SQLite TEST adapter GROUP 5 |

Smoke không mock HTTP endpoint, auth hay Risk Engine. Tests/factory inject fake
transport/model/repository vào graph thật; factory chỉ hoạt động khi APP_ENV=test
và có DB test path rõ. Migration và user login thật, password/JWT secret ngẫu nhiên;
server/DB tạm được cleanup sau chạy. Không fake production persistence.
Smoke script xử lý Windows venv child process bằng cách dừng đúng process tree
đã tạo, retry ngắn khi SQLite handle chưa nhả; lock kéo dài vẫn làm smoke fail.

| HTTP case | HTTP | Score | Label | Scope | Coverage |
| --- | --- | --- | --- | --- | --- |
| Clean + fake providers OK | 200 | 0 | SAFE | static_enriched | complete |
| URL mismatch + fake providers OK | 200 | 60 | SUSPICIOUS | static_enriched | complete |
| Suspicious attachment + fake providers OK | 200 | 50 | NEEDS_ANALYST_REVIEW | static_enriched_partial | incomplete |
| QR URL + fake providers OK | 200 | 40 | SUSPICIOUS | static_enriched | complete |
| BEC fake positive | 200 | 9 | SAFE | static_enriched | complete |
| External timeout + URL mismatch | 200 | 60 | NEEDS_ANALYST_REVIEW | static_enriched_partial | incomplete |
| All external unavailable + attachment | 200 | 50 | NEEDS_ANALYST_REVIEW | static_enriched_partial | incomplete |

Suspicious attachment fixture khai báo executable inert là PNG; QR_DECODE và
QR_ANALYSIS vẫn UNKNOWN theo behavior GROUP 3. Không sửa analyzer để ép coverage
complete. Test riêng all-unavailable + clean cũng xác nhận NEEDS_ANALYST_REVIEW.
Tests kiểm tra missing key không gọi transport, provider errors, exact-match miss,
atomic ingest, RAG empty/outage, BEC cap/source, PII separation, invalid score fields,
strong IOC/VT không bị LLM override, benign URL vẫn được enrich và no-report UNKNOWN.

Response thực đầy đủ (claims + evidence_ids + provenance + coverage + contributions):
[HTTP smoke artifact](examples/group7-http-smoke.json).

Chạy lại từ root repository, không cần key/network external:

```powershell
& .venv\Scripts\python.exe -m compileall src
& .venv\Scripts\python.exe -m pytest -q
& .venv\Scripts\python.exe -m ruff check src tests
& .venv\Scripts\python.exe -m scripts.smoke_group7 --test-db
```

Provider request shapes đã đối chiếu tài liệu chính thức:
[VT file report](https://docs.virustotal.com/reference/file-info),
[urlscan API](https://urlscan.io/docs/api/),
[urlscan search](https://urlscan.io/docs/search/).
Không coi fake fixtures là kiểm chứng live provider compatibility.

## Files created — 9

```text
src/services/external.py
src/services/enrichment.py
src/agents/nodes/enrichment_node.py
tests/external_fakes.py
tests/group7_smoke_app.py
tests/test_external_boundaries.py
scripts/smoke_group7.py
docs/group7-external-boundaries.md
docs/examples/group7-http-smoke.json
```

## Files modified — 19

```text
.env.example
README.md
docs/api-contract.md
src/config.py
src/agents/graph.py
src/agents/state.py
src/agents/nodes/verdict_node.py
src/analyzers/common.py
src/analyzers/content_analyzer.py
src/schemas/analysis.py
src/schemas/case.py
src/schemas/verdict.py
src/services/ioc_store.py
src/services/llm.py
src/services/rag.py
src/services/threat_intel.py
src/services/urlscan.py
src/services/virustotal.py
frontend/src/lib/types.ts
```

Files deleted: **0**. Không tính generated artifacts. Hash comparison trước/sau
xác nhận source Parser, Header/URL/Attachment/QR rules, Gate 1, Risk Engine/weights,
Claim Validator, PII/Guardrails, auth/cases/HITL/audit không thay đổi. Tests regression
cũ không sửa. Frontend chỉ đổi analysis_scope union.

## Phần cần provision sau này

- **DATASET:** calibration/false positive/coverage thật cho BEC/provider mappings,
  production PII samples, evaluation dataset và trusted SOC corpus. Không báo accuracy.
- **API_KEY:** VT/urlscan real lookup compatibility/quota/freshness tests chưa chạy.
- **LLM:** structured adapter thật, model/provider, timeout implementation và eval.
  Existing deterministic verdict vẫn chạy, không bypass Gate 2.
- **THREAT_FEED:** connector/scheduling, source authenticity, freshness/expiry,
  multi-source reconciliation và persistent ingestion chưa triển khai.
- **Qdrant:** runtime/collection, embedding adapter và corpus ingestion chưa xác minh.
- **PostgreSQL:** cần runtime để xác minh smoke với production DB; không có fallback
  SQLite production. In-memory IOC batch ingestion là boundary local, chưa là feed DB.

Dừng tại GROUP 7; không bắt đầu GROUP 8.
