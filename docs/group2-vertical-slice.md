# GROUP 2 — First End-to-End Vertical Slice

Ngày thực hiện: 2026-10-09 (Asia/Saigon). Không triển khai GROUP 3.

## Behavior hoàn thành

- Parser đọc RFC/MIME bytes, decoded From/Reply-To/Return-Path, Received,
  Authentication-Results, Subject, text/HTML body, URL, link text/href/forms và
  attachment metadata (filename, MIME, disposition, content ID, size, SHA-256).
  Hỗ trợ multipart/alternative, charset fallback và quoted mailbox.
- Input giới hạn 5 MiB, MIME parts 100 và nesting 20. Email rỗng, malformed,
  ambiguous singleton headers, MIME/transfer encoding lỗi được trả lỗi có kiểm soát.
  Không render HTML, tải URL, ghi attachment theo filename hoặc thực thi attachment.
- `ParsedEmail.raw_for_analyzers` giữ dữ liệu cho deterministic analyzer.
  `redacted_for_llm=None` cho đến khi có redactor thật; chưa tạo bản LLM giả chứa raw.
- Header Analyzer tạo cùng Evidence contract GROUP 1 cho reported auth, reply-to,
  return-path, explicit domain trong display-name, Received count/duplicates/order.
  Missing/ambiguous/untrusted auth là UNKNOWN. Trust policy và giới hạn của reported
  Authentication-Results được mô tả trong [API contract](api-contract.md).
- Graph chỉ chạy `parse → header → Gate 1 → Risk Engine → verdict stub`.
  Verdict giữ nguyên risk result và đánh dấu pending review, không đưa ra action.
- API nhận multipart `.eml` thật, sinh request UUID, trả đầy đủ risk/evidence/coverage/
  contributions. Chưa persistence case. Response không chứa raw HTML/email/attachment.
- URL/attachment xuất hiện làm coverage thiếu check chưa triển khai; không báo đã scan.
  Policy chỉ thêm hai header rules và hai coverage markers weight 0.

## Files

Tạo:

- `tests/fixtures/emails/clean.eml`
- `tests/fixtures/emails/reply_to_mismatch.eml`
- `tests/fixtures/emails/auth_fail.eml`
- `tests/fixtures/emails/malformed.eml`
- `tests/test_vertical_slice.py`
- `docs/examples/group2-reply-to-response.json` (response HTTP thật của fixture)
- `docs/group2-vertical-slice.md`

Sửa:

- `src/parsers/email_parser.py`
- `src/parsers/html_parser.py`
- `src/parsers/attachment_parser.py`
- `src/analyzers/header_analyzer.py`
- `src/agents/graph.py`
- `src/agents/state.py`
- `src/agents/nodes/parse_node.py`
- `src/agents/nodes/header_node.py`
- `src/agents/nodes/verdict_node.py`
- `src/api/routers/analysis.py`
- `src/schemas/analysis.py`
- `src/config.py`
- `config/risk_weights.yaml`
- `.env.example`
- `requirements.txt` (thêm python-multipart cho file upload)
- `tests/test_agents/test_graph.py`
- `tests/test_api/test_routes.py`
- `docs/api-contract.md`
- `README.md`

Không xoá file, không Git commit/push. URL/Attachment/QR analyzers giữ nguyên.

## Kiểm chứng thực tế

Chạy Python 3.11 trong `.venv`:

- `python -m compileall src`: PASS.
- `python -m pytest -q`: PASS — 38 tests, gồm tests baseline/GROUP 1.
- `python -m ruff check src tests`: PASS.
- `python -m pip check`: PASS.
- Frontend lint/build chưa áp dụng: chưa có `frontend/package.json`.

Uvicorn chạy process riêng trên localhost; gửi multipart qua HTTP thật bằng httpx.
OpenAI/VirusTotal/urlscan key đều trống; không gọi LLM hoặc external API.

| Request | HTTP | Result |
| --- | --- | --- |
| Health | 200 | status=ok |
| clean.eml, trusted fixture receiver | 200 | score=0, SAFE, coverage complete |
| reply_to_mismatch.eml, trusted fixture receiver | 200 | score=40, SUSPICIOUS |
| auth_fail.eml, trusted fixture receiver | 200 | score=45, SUSPICIOUS |
| malformed.eml | 422 | MALFORMED_EMAIL |
| Sai extension | 415 | UNSUPPORTED_FILE |
| File >5 MiB | 413 | EMAIL_TOO_LARGE |
| Thiếu field file | 422 | FastAPI validation error |
| clean.eml, default empty receiver trust | 200 | NEEDS_ANALYST_REVIEW |

Response đầy đủ: [reply-to mismatch JSON](examples/group2-reply-to-response.json).
Các server kiểm tra đã dừng. Score là output deterministic, không phải accuracy metric.

Tests bổ sung kiểm tra MIME/body/charset/link/attachment metadata, raw/LLM boundary,
Header signals, missing/untrusted/duplicate auth, comment/quoted auth parsing,
URL/attachment coverage thiếu, upload validation và graph chỉ có node GROUP 2.

## Chưa làm và group tiếp theo

Redaction thật thuộc GROUP 4; LLM input hiện không khả dụng. DKIM verifier hoàn chỉnh
không thuộc GROUP 2. Dataset/API key/LLM thật không cần để hoàn thành group này.
Không còn implementation GROUP 2 đang chờ external service.

GROUP 3 (chưa bắt đầu): URL/Attachment/QR analyzers, exact-match IOC boundary,
content interface và fan-out graph. Dừng chờ người dùng xác nhận.
