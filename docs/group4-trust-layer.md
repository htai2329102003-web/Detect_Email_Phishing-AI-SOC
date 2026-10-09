# GROUP 4 — Trust Layer

Ngày thực hiện: 2026-10-09 (Asia/Saigon). Chỉ GROUP 4. Không bắt đầu GROUP 5.

## Kết quả

Flow: parse → header/url/attachment/qr fan-out → Gate 1 → Risk Engine → Verdict →
Claim Validator (Gate 2) → response. Không có đường verdict bypass Gate 2. SHA-256
source Parser, tất cả Analyzer, Evidence Contract, Gate 1, Risk Engine và risk weights
giữ nguyên so với đầu GROUP 4. Các regression tests GROUP 1–3 vẫn PASS.

Production dùng deterministic provider tạo structured verdict từ evidence thật:
`claims[{claim_type,text,evidence_ids,indicators}]`, `recommended_actions`,
`analyst_summary`, cùng score/label echo từ Risk Engine. Không có fake LLM call hoặc
fake IOC result production. VerdictProvider interface hỗ trợ inject model; FakeModel
chỉ nằm trong test. Provider nhận risk deep copy, EvidenceFact metadata và bản email
redacted. Raw evidence values/indicator strings không được gửi trong facts cho provider.

Gate 2 kiểm tra IDs đã qua Gate 1, mapping signal/family/claim_type từ risk policy,
factual text template, canonical indicator bindings và summary. IndicatorReference
chứa evidence_id/path/value; Gate 2 tự dựng từ referenced evidence. Proposal có reference
khác canonical bị loại. Tên domain/URL/hash tự bịa trong prose cũng bị loại. Đây là
validator template bảo thủ, chưa hỗ trợ arbitrary natural-language paraphrases.

Claim lỗi bị loại riêng, giữ claim hợp lệ; ghi UNGROUNDED_CLAIM. Score/label trong
proposal khác risk bị từ chối; response dùng RiskResult gốc. `assessment_label` riêng
chuyển NEEDS_ANALYST_REVIEW khi trust fail hoặc coverage thiếu. `score` và
`label_candidate` không bị verdict/validator sửa. Summary luôn thể hiện coverage và
manual review. Action codes có allowlist, không thực thi hành động. Compatibility
fields `verdict=pending_review`, `status=pending`, `requires_review=true` giữ nguyên;
chưa có HITL workflow. LLM provider có tối đa một retry (hai attempts tổng), rồi lọc
claim sai; deterministic provider không retry. Redaction/guardrail lỗi chặn provider.

## PII và guardrails

Parser tiếp tục trả `raw_for_analyzers`, được lưu trong `parsed_email` và dùng nguyên
vẹn cho static analyzer. `redacted_for_llm` là bản sao riêng, không alias raw. Local
regex nhận diện email, VN mobile/landline, CCCD 12 số, CMND 9 số khi có nhãn và tài
khoản 8–18 số có nhãn STK/tài khoản/account number. Account không có nhãn không bị
tự kết luận là PII; CCCD 12 số vẫn có thể false positive. Token map chỉ tồn tại trong
redaction call; không gửi ra provider/API. Counts đếm giá trị khác nhau theo loại.

Binary attachment bị bỏ khỏi bản sao; base64 image data URI được bỏ. Common HTML
entities/URL escapes được decode trước regex chỉ trên bản sao. Raw URL/domain/hash
không đổi trước analyzer. Tests xác minh raw bytes và IOC vẫn nguyên, PII mẫu không
còn trong copy/provider request. API evidence vẫn raw canonical, có thể chứa PII;
redaction boundary phục vụ LLM, không tuyên bố toàn bộ API response đã được che.

PIIRedactor Protocol cho phép Presidio adapter sau này; Presidio chưa cài. Không bảo
đảm mọi PII: chưa có dataset VN, name/address/OCR recognition, exhaustive Unicode hay
multi-layer obfuscation coverage. Chưa đánh giá recall/precision trên dữ liệu thật.

GuardrailProvider/UntrustedEmail tách fixed system instruction và JSON DATA envelope,
`trust=untrusted`, `role=data`, `allow_tool_execution=false`. Email không điều khiển
graph edges, scan hoặc score/label. Pattern tiếng Anh/Việt có normalize dấu và nhận
ignore instructions / force SAFE / disable scan / reveal prompt, kể cả raw HTML
hidden/comment. Matching là advisory; bảo vệ thực tế nằm ở graph cố định, provider
không có tool/state access, risk copy và Gate 2 kiểm chứng lại mọi output. Không claim
pattern detector nhận diện toàn bộ injection, hoặc một LLM thật đã vượt attack eval.

`config/guardrails.yaml` định nghĩa local backend và retry budget 1. NeMo chưa có
runtime/config/model; bật nemo bị NEMO_NOT_CONFIGURED, không silent fallback.

## Files created

- `config/guardrails.yaml`
- `src/services/verdict.py`
- `tests/test_trust_layer.py`
- `tests/fixtures/emails/prompt_injection.eml`
- `docs/examples/group4-trust-response.json`
- `docs/group4-trust-layer.md`

## Files modified

- `src/schemas/verdict.py`
- `src/evidence/claim_validator.py`
- `src/services/pii.py`
- `src/services/guardrails.py`
- `src/agents/nodes/parse_node.py`
- `src/agents/nodes/verdict_node.py`
- `src/agents/nodes/claim_node.py`
- `src/agents/state.py`
- `src/agents/graph.py`
- `src/schemas/analysis.py`
- `tests/test_agents/test_graph.py`
- `docs/api-contract.md`
- `README.md`

Files deleted: không. Không đổi dependencies; không commit/push. Workspace có Git
chưa có tracked baseline, nên danh sách trên mô tả riêng thay đổi GROUP 4, không phải
toàn bộ untracked files của các group trước.

## Kiểm chứng

Python 3.11 `.venv`:

- `python -m compileall src`: PASS.
- `python -m pytest -q`: PASS — 79 tests (55 regression + 24 trust-layer cases).
- `python -m ruff check src tests`: PASS.

Tests gồm grounded verdict/claim, missing/empty evidence IDs, wrong claim type,
invented text/indicator, sửa score/label/summary, extra fields/action allowlist, raw
PII copy, redaction failure, retry budget và tám attack strings Anh/Việt. Attack
tests inject provider cố tình trả SAFE/sai score/sai claim; RiskResult vẫn bằng case
gốc, bốn analyzer vẫn chạy, URL mismatch vẫn được phát hiện, Gate 2 loại claim sai.

HTTP smoke dùng subprocess Uvicorn thật, loopback/random port, httpx trust_env=false,
API keys trống. Trust receiver fixture `mx.recipient.test`, protected domain
`paypal.test`; production IOC vẫn chưa cấu hình. Server đã dừng sau kiểm tra.

| Fixture | HTTP | Score | label_candidate | Scope | Gate 2 | Claims |
| --- | --- | --- | --- | --- | --- | --- |
| clean.eml | 200 | 0 | SAFE | static_local | PASS | 3 |
| href_mismatch.eml | 200 | 60 | NEEDS_ANALYST_REVIEW | static_local_partial | PASS | 5 |
| prompt_injection.eml | 200 | 60 | NEEDS_ANALYST_REVIEW | static_local_partial | PASS | 5 |
| auth_fail.eml | 200 | 45 | SUSPICIOUS | static_local | PASS | 3 |
| malformed.eml | 422 | — | Parse error | — | — | — |

`analysis_scope` giữ nghĩa analyzer static local từ GROUP 3; verdict không tự mở rộng
scope. Case URL/injection partial do IOC UNKNOWN. Injection giữ nguyên score, label,
coverage và contributions so với href mismatch. Bốn advisory signals đều xuất hiện;
PII counts: EMAIL=3, VN_PHONE=1, VN_ID=2, BANK_ACCOUNT=1. Không có trust warning ở
deterministic verdict hợp lệ. SAFE chỉ là kết quả trong scope đã chạy, vẫn review.

Trích response thật (bỏ indicator bindings trong trích đoạn cho gọn):

```json
{
  "score": 60.0,
  "label_candidate": "NEEDS_ANALYST_REVIEW",
  "analysis_scope": "static_local_partial",
  "claim_validation_status": "PASS",
  "claims": [{
    "claim_type": "URL",
    "text": "HREF_MISMATCH: FAIL.",
    "evidence_ids": ["ev_48c502b00716bb6dea81d1160c95cee9bf3da67a1931061e09cd3d4bb6612919"]
  }]
}
```

[Response đầy đủ](examples/group4-trust-response.json) chứa canonical bindings,
recommended_actions, analyst_summary, evidence, contributions, counts và signals.

## Chưa triển khai / bị giới hạn

Không có phần GROUP 4 local bắt buộc nào còn chờ API key. LLM thật chưa tích hợp/
kiểm chứng (LLM_REQUIRED/API_KEY_REQUIRED); NeMo cần runtime, policy/model config và
adapter. Presidio adapter chưa triển khai; regex là implementation offline hiện tại.
Không có dataset PII/injection thật để tuyên bố coverage hay đánh giá quality model.
IOC reputation vẫn cần feed/snapshot thật (THREAT_FEED_REQUIRED) như GROUP 3.

Không làm HITL thật, auth, database workflow, frontend, VirusTotal/urlscan, Qdrant/RAG.
Dừng tại GROUP 4; không bắt đầu GROUP 5.
