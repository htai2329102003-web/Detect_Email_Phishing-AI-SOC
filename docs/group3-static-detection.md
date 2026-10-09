# GROUP 3 — Static Detection Expansion

Ngày thực hiện: 2026-10-09 (Asia/Saigon). Chỉ GROUP 3; không triển khai GROUP 4.

## Behavior hoàn thành

URL Analyzer chạy local: displayed URL/href mismatch, IP literal, punycode,
confusable/typo với configured protected domain, excessive labels, known shortener,
nonstandard port, userinfo/percent encoding/numeric obfuscation và normalization.
Giới hạn 256 candidates, 8192 ký tự/URL; vượt giới hạn cho UNKNOWN. Không fetch URL
hoặc DNS query. `URL_PROTECTED_DOMAINS` cấu hình domain so sánh; heuristic confusable
là tập giới hạn, không phải UTS #39 database đầy đủ. Không có target config thì
không tuyên bố đã kiểm tra mạo danh mọi thương hiệu.

IOCClient là interface exact-match cho domain/URL/IP/hash. Normalization dùng IDNA,
compressed IP, lowercase hex hash, lowercase URL scheme/host, bỏ default port và
fragment, chuẩn hoá unreserved escapes/UTF-8. Giữ path case, query order và reserved
escapes (ví dụ `%2F` không thành slash). Không fuzzy/suffix match, không semantic RAG.
InMemoryIOCStore là snapshot được inject rõ; FakeIOCClient chỉ ở tests. Production
default UnconfiguredIOCClient trả ERROR/IOC_NOT_CONFIGURED, thành UNKNOWN evidence.
Client timeout/rate limit/error hoặc record không exact-match không được hiểu là clean.
Miss chỉ nghĩa là không có trong snapshot, không phải chứng minh an toàn toàn cầu.

Attachment Analyzer nhận bytes trong raw parsed data, kiểm tra filename/extension,
MIME, magic bytes, SHA-256, executable type, double extension, filename deception,
MIME/magic mismatch. Không chạy file hoặc upload. OOXML ZIP listing có thể thấy
`vbaProject.bin`; PDF chỉ đọc lexical metadata tokens như /JavaScript, /OpenAction,
/Launch, /EmbeddedFile, không giải mã/chạy code hoặc parse mọi object stream.

ZIP chỉ listing và đọc bounded nested ZIP trong memory, không extract xuống disk.
Limits: 100 entries tổng, nesting tối đa 2, declared expanded tổng 20 MiB,
compression ratio 100, nested read mỗi entry 1 MiB và tổng 4 MiB. Archive mã hoá,
malformed, vượt limit hoặc format không hỗ trợ cho UNKNOWN. OLE được nhận diện magic
nhưng chưa parse VBA streams vì không có dependency OLE chuyên dụng. Không tuyên bố
archive/PDF/OLE đã được scan malware đầy đủ.

QR dùng Pillow + ZXing-C++ decode thật từ MIME inline/attached image và base64
image data URI. Limit mỗi image 2 MiB/4 triệu pixel, tối đa 20 images, một frame,
20 QR payloads/image, 4096 ký tự/payload. Image lỗi/không hỗ trợ/vượt limit cho UNKNOWN.
HTTP(S) URLs từ QR chuyển sang cùng URL Analyzer/IOC interface; không mở URL.
QR không tìm thấy trong ảnh decode được chỉ là kết quả decoder local.

Content/BEC chỉ có RedactedContent, ContentResult và ContentAnalyzer Protocol.
Graph reducer hỗ trợ content_bec Evidence được cung cấp, Risk Engine vẫn cap theo
GROUP 1. Chưa có content provider được gọi hoặc content claim production giả.
`redacted_for_llm` vẫn None; raw attachment bytes không được trả qua API/LLM.

Graph: parse fan-out header/url/attachment/qr → join → Gate 1 → Risk Engine → verdict
stub. Mỗi nhánh có exception boundary; nhánh lỗi tạo UNKNOWN/ERROR evidence,
nhánh còn lại vẫn chạy. Header Analyzer source và các rule/weight hiện có giữ nguyên;
chỉ node integration được bọc boundary và chuyển coverage về từng nhánh.

API có `analysis_scope=static_local` khi các nhánh chạy hoàn tất không UNKNOWN,
hoặc `static_local_partial` khi còn UNKNOWN/lỗi. `analyzer_runs` ghi OK/PARTIAL/ERROR
từng nhánh. Scope chỉ gồm static local, không LLM/BEC/reputation toàn cầu. Completion
markers weight 0 không đóng góp score. Mọi action vẫn pending review.

## Files created

- `src/analyzers/common.py`
- `src/agents/nodes/analysis_boundary.py`
- `tests/test_static_detection.py`
- `tests/fixtures/emails/href_mismatch.eml`
- `tests/fixtures/emails/lookalike.eml`
- `tests/fixtures/emails/suspicious_attachment.eml`
- `tests/fixtures/emails/qr_url.eml`
- `docs/examples/group3-url-response.json`
- `docs/group3-static-detection.md`

## Files modified

- `src/analyzers/url_analyzer.py`
- `src/analyzers/attachment_analyzer.py`
- `src/analyzers/qr_analyzer.py`
- `src/analyzers/content_analyzer.py`
- `src/services/ioc_store.py`
- `src/parsers/attachment_parser.py`
- `src/agents/nodes/header_node.py`
- `src/agents/nodes/url_node.py`
- `src/agents/nodes/attachment_node.py`
- `src/agents/nodes/qr_node.py`
- `src/agents/nodes/verdict_node.py`
- `src/agents/graph.py`
- `src/agents/state.py`
- `src/schemas/analysis.py`
- `src/api/routers/analysis.py` (docstring scope)
- `src/config.py`
- `.env.example`
- `config/risk_weights.yaml`
- `requirements.txt` (Pillow, zxing-cpp)
- `tests/test_vertical_slice.py`
- `tests/test_agents/test_graph.py`
- `docs/api-contract.md`
- `README.md`

Files deleted: không. Không Git commit/push. Không sửa Header Analyzer,
Risk Engine implementation hoặc Evidence Contract từ GROUP 1.

## Kiểm chứng thực tế

Chạy Python 3.11 của `.venv`:

- `python -m compileall src`: PASS.
- `python -m pytest -q`: PASS — 55 tests (38 regression + 17 static cases).
- `python -m ruff check src tests`: PASS.
- `python -m pip check`: PASS.
- Frontend lint/build chưa áp dụng: chưa có `frontend/package.json`.

Tests kiểm tra normalization/exact-match, fake IOC hits/misses/failures, local
URL rules và clean equivalent, attachment metadata/ZIP limits, QR decode thật/
data URI/blank image/size limit, HTTP contract, lỗi từng nhánh không crash join,
fake IOC qua graph và content_bec contract/reducer. Bốn fixture mới <2 KiB mỗi file.
Payload MZ là inert development text, QR dùng documentation IP. Không có dataset lớn.

HTTP smoke chạy Uvicorn thật với API keys trống, fixture receiver tin cậy
`mx.recipient.test`, protected domain `paypal.test`; production IOC vẫn chưa cấu hình.

| Case | HTTP | Score | Label | Scope |
| --- | --- | --- | --- | --- |
| clean.eml | 200 | 0 | SAFE | static_local |
| href_mismatch.eml | 200 | 60 | NEEDS_ANALYST_REVIEW | static_local_partial |
| suspicious_attachment.eml | 200 | 50 | NEEDS_ANALYST_REVIEW | static_local_partial |
| qr_url.eml | 200 | 40 | NEEDS_ANALYST_REVIEW | static_local_partial |
| lookalike.eml | 200 | 40 | NEEDS_ANALYST_REVIEW | static_local_partial |
| auth_fail.eml | 200 | 45 | SUSPICIOUS | static_local |
| malformed.eml | 422 | — | Parse error | — |

Các case có IOC UNKNOWN vẫn giữ score local, label review đúng coverage policy.
Attachment fixture giả MIME image còn tạo QR_DECODE UNKNOWN, đúng dữ liệu input lỗi.
Response đầy đủ: [href mismatch JSON](examples/group3-url-response.json).
Server kiểm tra đã dừng; không gọi external API/LLM.

## Chưa làm / dependencies / bước tiếp theo

Không có implementation bắt buộc GROUP 3 còn chờ API key hoặc dataset. Production
reputation chưa khả dụng vì chưa có IOC snapshot/feed thật (THREAT_FEED_REQUIRED).
VirusTotal/urlscan thật cần API key và thuộc group sau; không được gọi trong group này.
Độ chính xác/weight calibration chưa đánh giá vì chưa có dataset (DATASET_REQUIRED).
OLE macro stream parser và full PDF parser chưa thêm vì dependency chuyên dụng
không có trong baseline; các phần này là optional theo scope, giới hạn đã báo rõ.

Không triển khai Qdrant/RAG, LLM, redaction, guardrails, auth/HITL/frontend.
GROUP 4 (chưa bắt đầu): Verdict contract, Claim Validator, PII/redaction và guardrail
boundary. Dừng chờ người dùng xác nhận.
