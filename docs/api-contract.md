# PhishHunter API contract — GROUP 7

`GET /api/v1/health`: HTTP 200 liveness; không kiểm tra database hoặc external service.

Auth/analysis/cases yêu cầu PostgreSQL đã migrate, `JWT_SECRET` từ environment và user
đã provision. Không có tài khoản mặc định, public registration hoặc SQLite fallback
production. SOC_ANALYST và ADMIN dùng chung SOC case queue; không có tenant isolation
trong phạm vi này. `/health`, `/auth/status`, `/auth/login` là public; các case APIs
yêu cầu bearer access token. `/auth/status` chỉ báo implementation status.

`POST /api/v1/auth/login` nhận JSON `{email,password}`, trả access_token/token_type/
expires_in. `GET /api/v1/auth/me` trả user_id/email/role/active/created_at, không có
password hash. JWT HS256 cố định, kiểm tra exp/nbf/iat/issuer/audience/type và UUID sub;
role/active được đọc lại từ DB mỗi request. Default token TTL 30 phút. Login sai/token
sai hoặc hết hạn trả 401; thiếu quyền trả 403. Login validation không echo secret input.

`POST /api/v1/analysis`: upload file `.eml` bằng `multipart/form-data`, field `file`.
Giới hạn file 5 MiB. Tên file chỉ dùng kiểm tra extension; không lưu file xuống disk
bằng tên người dùng. MIME thực tế được parse từ nội dung; không tin Content-Type
do client gửi. JSON request skeleton cũ không còn được nhận ở endpoint này.

```powershell
curl.exe -H "Authorization: Bearer $env:PHISHHUNTER_ACCESS_TOKEN" -F "file=@tests/fixtures/emails/reply_to_mismatch.eml" http://127.0.0.1:8000/api/v1/analysis
```

Success: **HTTP 200** sau analysis và persistence transaction thành công. Response có:

| Field | Ý nghĩa |
| --- | --- |
| `case_id` | UUID của case đã persist |
| `score`, `label_candidate` | Output nguyên từ deterministic Risk Engine |
| `coverage` | Required/applicable/completed/missing/unknown, ratio, complete |
| `evidence` | Evidence đã qua Gate 1, gồm ID/provenance/timestamp |
| `contributions` | Evidence ID, signal, family, strength, applied_strength |
| `reasons` | Lý do thiếu coverage, UNKNOWN hoặc lỗi integrity |
| `analysis_scope` | `static_local` / `static_local_partial`; khi enrichment bật: `static_enriched` / `static_enriched_partial` |
| `analyzer_runs` | Trạng thái các nhánh đã chạy: OK, PARTIAL, ERROR; enrichment thêm virustotal/urlscan/content_bec khi applicable |
| `risk_score`, `risk_level` | Fields tương thích skeleton; lấy từ cùng RiskResult |
| `verdict`, `requires_review` | AI fields `pending_review`, `true`; quyết định human xem case.review_status |
| `status`, `review_status` | Cả hai PENDING ở response tạo case |
| `claims` | Claims đã qua Gate 2: claim_type, text, evidence_ids và canonical indicator references |
| `recommended_actions`, `analyst_summary` | Manual action codes có allowlist và summary đã được Gate 2 kiểm tra |
| `assessment_label` | Label sau kiểm tra trust; có thể yêu cầu review mà không sửa label_candidate |
| `claim_validation_status`, `trust_warnings` | PASS/FILTERED/REJECTED và reason codes của trust layer |
| `guardrail_signals` | Advisory prompt-injection pattern matches; không điều khiển analyzer/risk |
| `pii_redaction_counts` | Số giá trị PII khác nhau được token hóa theo loại trong request; không chứa token map |
| `verdict_attempts` | Một lần mặc định; tối đa hai lần khi inject LLM provider và Gate 2 chưa chấp nhận |

Response không chứa raw email, HTML body, text body hay attachment bytes.
Các indicator vẫn là canonical evidence data; frontend GROUP 6 phải defang khi hiển thị.
Không có executor quarantine/block/delete. Action authorization có endpoint riêng,
chỉ dành cho authenticated human, không tự chạy theo AI verdict.

Errors có JSON `detail`:

- **422**: thiếu field `file` (FastAPI validation), file rỗng hoặc email/MIME malformed.
  Parse error có `detail.code` và `detail.message`, không phản hồi nội dung email.
- **415**: extension khác `.eml` (`UNSUPPORTED_FILE`).
- **413**: file vượt 5 MiB (`EMAIL_TOO_LARGE`).
- **401/403**: chưa đăng nhập/token sai hoặc thiếu quyền.
- **503**: DATABASE_NOT_CONFIGURED, DATABASE_CONFIG_INVALID, DATABASE_UNAVAILABLE
  hoặc AUTH_NOT_CONFIGURED. Không giả lập persistence success. Health 200 không chứng
  minh DB readiness. Lỗi DB không trả connection URL/SQL parameters/driver message.

## Authentication và coverage

`HEADER_TRUSTED_AUTHSERV_IDS` mặc định rỗng. Khi chưa cấu hình, hoặc thiếu/không
tin cậy/mâu thuẫn Authentication-Results, auth evidence là UNKNOWN và label là
NEEDS_ANALYST_REVIEW. Chỉ đọc Authentication-Results đầu tiên; không tìm xuống
header phía dưới để chọn kết quả thuận lợi. Không xác minh DKIM cryptographic,
không DNS query, không external API.

Để kiểm tra các fixture synthetic có kết quả auth biết trước, chạy server mới với:

```powershell
$env:HEADER_TRUSTED_AUTHSERV_IDS = "mx.recipient.test"
& .venv\Scripts\python.exe -m uvicorn src.main:app --host 127.0.0.1 --port 8000
```

Trust cấu hình này chỉ phù hợp khi `.eml` được export từ receiver đó và receiver
đã strip header auth giả. Một file upload tự nó không chứng minh nguồn receiver.
Trong vận hành phải cấu hình receiver thực của hệ thống; không dùng domain fixture.
SAFE ở đây chỉ là assessment trong scope static local, vẫn luôn requires_review=true.

Header/URL/attachment/QR chạy fan-out, hợp nhất evidence trước Gate 1. Analyzer lỗi
trả UNKNOWN, các nhánh khác vẫn chạy. `static_local_partial` nghĩa là có nhánh lỗi
hoặc còn UNKNOWN (ví dụ IOC chưa được cấu hình, QR không decode được, archive bị limit).
Các completion markers weight 0 chỉ thể hiện check đã chạy, không tăng risk score.

URL chỉ được phân tích local, không fetch/DNS. IOC exact-match mặc định trả
`IOC_NOT_CONFIGURED`; không giả lập lookup miss. Khi email có URL hoặc attachment,
`URL_IOC_CHECK` / `ATTACHMENT_IOC_CHECK` UNKNOWN sẽ yêu cầu review dù score local cao.
Store trong bộ nhớ chỉ dùng khi được inject rõ bằng `build_graph(ioc_client=...)`;
lookup miss chỉ nghĩa là không có IOC trong snapshot đó, không chứng minh an toàn toàn cầu.

`URL_PROTECTED_DOMAINS` là danh sách domain để so sánh typo/confusable local.
Heuristic này có phạm vi giới hạn, không phải Unicode confusable database đầy đủ.
QR dùng Pillow/ZXing-C++ local từ image MIME/attachment hoặc image data URI, rồi
chuyển HTTP(S) URL cho cùng URL Analyzer. Không mở URL, không có upload bên ngoài.

GROUP 7 thêm enrichment opt-in trước Gate 1, mặc định
`EXTERNAL_ENRICHMENT_ENABLED=false` giữ nguyên static behavior. Khi bật, VT chỉ
lookup SHA-256; urlscan chỉ search/retrieve report có URL canonical exact-match,
không submit scan. Không fetch URL đích hoặc upload attachment. Thiếu key, timeout,
429/401/403/5xx, response sai hoặc report không có verdict làm check UNKNOWN;
coverage thiếu vẫn yêu cầu analyst review. Không có IOC snapshot giả trong production.

Exact malicious hash/URL report dùng signal `IOC_MATCH` đã có; completion dùng
`ATTACHMENT_IOC_CHECK` / `URL_IOC_CHECK`. Không thêm/chỉnh trọng số. Content/BEC
structured model chỉ thấy redacted copy, sinh `BEC_REQUEST`, family `content_bec`,
source `llm`, tiếp tục chịu cap 0.10 của Risk Engine. RAG chỉ đi vào
`VerdictRequest.knowledge_context`, không thành evidence hoặc thay risk; lỗi RAG
trả context rỗng. Qdrant repository/embedding và structured model thật chưa được
provision; đặt URL/key không tự tạo các adapter này. Khi enrichment bật mà model
chưa có, BEC UNKNOWN làm coverage partial. Verdict deterministic và Gate 2 vẫn chạy.

Scope mới được giữ nguyên trong persisted AI assessment và case summary/detail.
Auth/review/action/audit schemas và endpoints không đổi. Xem
[báo cáo GROUP 7](group7-external-boundaries.md) và fake HTTP smoke.

Attachment chỉ inspect bytes/metadata. ZIP có giới hạn entry/nesting/budget/ratio;
không extract xuống disk. OLE và archive không hỗ trợ/mã hóa cho UNKNOWN. PDF chỉ
đọc token metadata lexical, chưa parse mọi object stream/encryption hay giải mã script.

| Fixture | HTTP | Score | Label khi trust receiver fixture |
| --- | --- | --- | --- |
| clean.eml | 200 | 0 | SAFE |
| reply_to_mismatch.eml | 200 | 40 | SUSPICIOUS |
| auth_fail.eml | 200 | 45 | SUSPICIOUS |
| malformed.eml | 422 | — | Parse error |

SPF/DKIM/DMARC cùng family nên ba FAIL không bị cộng thành tín hiệu độc lập.
Response thật của fixture reply-to: [JSON đầy đủ](examples/group2-reply-to-response.json).

GROUP 3 response thật: [href mismatch JSON](examples/group3-url-response.json).
Fixtures mới: `href_mismatch.eml`, `lookalike.eml`, `suspicious_attachment.eml`,
`qr_url.eml`. Đây là fixture synthetic nhỏ; QR chứa IP documentation, attachment
chỉ có prefix MZ và text inert. Chúng không phải dataset/model accuracy benchmark.

## Trust layer — GROUP 4

Flow bắt buộc: evidence đã qua Gate 1 → Risk Engine → Verdict → Gate 2. Production
dùng DeterministicVerdictProvider, không gọi LLM. Provider chỉ nhận bản risk copy,
metadata facts (ID/signal/family/result) và email redacted dưới envelope untrusted DATA,
không có tools. Không nhận raw evidence values hoặc attachment bytes.

Gate 2 yêu cầu evidence IDs tồn tại, claim type đúng family/signal, text đúng factual
template và indicator references đúng canonical evidence paths/values. Không dùng
string contains để chứng minh indicator. Free-form paraphrases và summary tự do bị
reject trong phiên bản này. Claims sai bị loại; score/label sai bị từ chối và response
luôn lấy giá trị gốc từ Risk Engine. Trust failure ghi UNGROUNDED_CLAIM và nâng
`assessment_label` lên NEEDS_ANALYST_REVIEW. `label_candidate` vẫn nguyên. Khi coverage
thiếu hoặc risk đã yêu cầu review, verdict giữ nguyên trạng thái đó.

`raw_for_analyzers` của parser được giữ nguyên trong `parsed_email`; bản sao riêng
`redacted_for_llm` dùng regex offline cho email, số điện thoại VN, CCCD/CMND và số tài
khoản có nhãn. Binary attachment bị bỏ khỏi bản sao. HTML entities/URL escapes thông
dụng chỉ được decode trên bản sao trước khi redact. Redaction lỗi chặn provider,
không chặn analyzer. API evidence/indicators vẫn là raw canonical analysis output,
không phải response đã che toàn bộ PII. Không bảo đảm nhận diện mọi PII/obfuscation.

`config/guardrails.yaml` chọn local boundary. Email luôn DATA; orchestration không
cho provider thay edges, bật/tắt analyzer hoặc viết risk. Pattern matching tiếng Anh/
Việt chỉ cảnh báo; cố định flow, schema và Gate 2 vẫn bảo vệ dù pattern không match.
NeMo chưa được provision; chọn backend nemo sẽ báo NEMO_NOT_CONFIGURED, không giả lập.

HTTP response thực tế có claims/evidence IDs: [prompt-injection JSON](examples/group4-trust-response.json).
Chi tiết tests và limitations trust layer: [GROUP 4 report](group4-trust-layer.md).

## Cases, review và action authorization — GROUP 5

| Endpoint | Role | Behavior |
| --- | --- | --- |
| GET /cases | Analyst/Admin | List summaries; limit 1–100 (default 50), offset >= 0 |
| GET /cases/{case_id} | Analyst/Admin | CaseDetail, immutable ai_assessment, analyst_assessment và actions |
| POST /cases/{case_id}/review | Analyst/Admin | PENDING → APPROVED/REJECTED/MODIFIED |
| POST /cases/{case_id}/actions | Analyst/Admin | Propose ActionKind, HTTP 201, state PROPOSED |
| POST /cases/{case_id}/actions/{action_id}/authorize | Analyst/Admin | Explicit authorization; không execute |
| GET /cases/{case_id}/audit | Analyst/Admin | Audit của case, read-only, limit/offset |
| POST /admin/users | Admin | Tạo user với password >=12 ký tự và role hợp lệ; HTTP 201 |
| GET /admin/users | Admin | List public user fields, limit/offset |
| PATCH /admin/users/{user_id} | Admin | Đổi role/active, không tự bỏ quyền Admin của chính mình |
| GET /admin/audit | Admin | System audit read-only, limit/offset |

Tất cả path trên có prefix `/api/v1`. Case/action/user IDs validate UUID; missing row
trả 404, invalid ID trả 422. Extra input fields bị reject (không cho set reviewer_id,
score/ai_score/ai_assessment/action state). Các list là SOC queue, không phải owner-only.

Review JSON:

```json
{
  "decision": "MODIFY",
  "reason": "Manual evidence review",
  "analyst_assessment": {"label": "SUSPICIOUS", "summary": "Human interpretation"},
  "allowed_actions": ["QUARANTINE"]
}
```

APPROVE/REJECT nhận decision và optional reason; không nhận analyst_assessment hoặc
allowed_actions. MODIFY bắt buộc reason không rỗng và analyst_assessment (label/summary,
không có score); allowed_actions mặc định rỗng. Final case không reopen; review lại
trả 409 CASE_ALREADY_FINAL và audit REVIEW_DENIED. Reviewer luôn từ authenticated user.
`review_status`, reviewer_id, reviewed_at và updated_at phản ánh human workflow.
`ai_assessment` giữ snapshot gốc (kể cả AI status=pending/requires_review=true); root
case risk_score/label_candidate/assessment_label vẫn là AI values. Analyst label nằm
riêng trong analyst_assessment, không overwrite history hoặc score.

Action proposal JSON `{ "kind": "QUARANTINE" }`; kind cũng có BLOCK_SENDER/DELETE_EMAIL.
Không tự tạo destructive proposal từ recommended_actions. Authorize JSON cần reason.
PENDING/REJECTED không authorize; APPROVED cho phép human authorize loại đã propose;
MODIFIED chỉ cho phép kind trong allowed_actions của quyết định analyst. Authorization
luôn là request riêng. Denied/repeat authorization trả 409 ACTION_DENIED và audit;
action vẫn giữ state cũ. EXECUTED là enum dự trữ, không có API/transition/executor;
application ORM cũng chặn ghi EXECUTED. Proposal trùng kind/case trả 409.

Audit append-only tại application layer: CASE_CREATED/ANALYSIS_COMPLETED, review,
action proposed/authorized/denied, user created/updated. Audit có actor UUID, old/new
state, reason, timestamp và metadata allowlist; không có password/token. Audit/case
hoặc audit/review/action write cùng transaction. Không có update/delete audit API;
ORM/bulk Session mutation bị chặn. DB superuser vẫn ngoài boundary này. DB hỏng không
thể đảm bảo ghi audit vào chính DB đó; trả 503, rollback, không báo thành công giả.

Chi tiết setup và kiểm chứng: [GROUP 5 report](group5-hitl-database-auth.md).
[HTTP before/after review và audit thật trên TEST DB](examples/group5-workflow-response.json).
