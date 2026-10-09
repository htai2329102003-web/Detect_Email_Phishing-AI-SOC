# GROUP 1 — Core Contracts

Ngày thực hiện: 2026-10-09 (Asia/Saigon). Chỉ triển khai GROUP 1.

## Contract và Gate 1

`Evidence` chứa `evidence_id`, `analyzer`, `tool`, `signal_type`, `family`,
`indicator`, `value`, `result`, `tool_status`, `severity`, `confidence`,
`provenance`, `collected_at`. PASS nghĩa là check không phát hiện risk;
FAIL nghĩa là check phát hiện risk; UNKNOWN nghĩa là chưa có kết luận.

`tool_status != OK` bắt buộc `result == UNKNOWN`. Confidence phải hữu hạn trong
0..1. Provenance có source `local`, `external` hoặc `llm` và reference không rỗng
(ví dụ rule/version, request reference hoặc model/version). Evidence có source
`llm` chỉ được thuộc family `content_bec`. Provenance là dữ liệu audit do analyzer
cung cấp, chưa phải chữ ký xác thực nguồn.

ID là SHA-256 của canonical JSON chứa các trường fact, gồm cả outcome, confidence
và provenance; không gồm ID và thời điểm thu thập. Đổi outcome tạo ID khác để giữ
lại mâu thuẫn. Gate kiểm tra ID được cung cấp và dedupe các fact giống nhau,
giữ observation mới nhất. Thứ tự key trong JSON không thay đổi ID.

Timestamp bắt buộc có timezone. Gate mặc định chấp nhận evidence không quá 7 ngày
và không vượt clock quá 5 phút; có thể truyền clock/window khi kiểm tra offline.
Schema, provenance, ID hoặc timestamp sai bị loại từng item, không làm mất các
item tốt. `Gate1Result` giữ evidence, issues (index/code) và duplicate IDs;
consumer phải chuyển cả kết quả này sang Risk Engine để giữ thông tin bị loại.
Risk Engine revalidate evidence tại thời điểm scoring.

`ToolResult[T]` là boundary chung gồm status, data, error_code, error_message,
latency_ms. Failure không được chứa success data; OK không được chứa error;
latency phải hữu hạn và không âm. Chưa thêm client VirusTotal/urlscan.

## Risk Engine

Policy được load từ `config/risk_weights.yaml` bằng YAML safe loader và schema
validation. Lỗi policy được báo rõ, không fallback sang score SAFE.
Weight/threshold hiện là policy development, chưa hiệu chỉnh bằng dataset.

Với mỗi FAIL hợp lệ:

```text
strength = min(weight * confidence, family_cap)
family_strength = max(strength trong family)
score = 100 * (1 - product(1 - family_strength))
```

LLM weight còn bị cap riêng (mặc định 0.10); content_bec family cap không quá
0.15 và không được có strong override. Contributions ghi strength của mỗi FAIL,
và applied_strength chỉ trên một evidence thắng mỗi family. Khi bằng nhau, ID
quyết định winner ổn định. Không cộng riêng SPF/DKIM/DMARC hoặc các indicator cùng
family. Ví dụ auth family 0.45 và identity 0.40 cho score 67, không phải tổng weight.

Override IOC_MATCH đặt score tối thiểu 95 khi FAIL, confidence >= 0.90 và nguồn
không phải llm. Output ghi các evidence ID đã trigger override. Thiếu coverage
vẫn trả NEEDS_ANALYST_REVIEW dù score cao.

Required coverage mặc định: SPF_FAIL, DKIM_FAIL, DMARC_FAIL (đây là tên check;
check có thể có outcome PASS). Caller phải khai báo thêm `applicable_signals`
cho các check cần chạy theo case. Các check đã xuất hiện trong evidence cũng
được tự tính là applicable. Không thể dùng danh sách applicable rỗng để bỏ required.
Các group sau phải xác định applicability từ parsed data; engine không tự đoán
email có URL/attachment hay không từ việc thiếu evidence.

Coverage chỉ hoàn tất khi mọi required/applicable check có outcome đã biết và
confidence > 0, không có UNKNOWN, evidence bị loại, signal/family chưa cấu hình
hoặc outcome PASS/FAIL mâu thuẫn trên cùng analyzer/tool/check/indicator.
Ratio là tỷ lệ check đã biết; `complete` còn xét các lỗi integrity này.

Khi coverage chưa hoàn tất: NEEDS_ANALYST_REVIEW. Khi hoàn tất: SAFE nếu score < 30,
SUSPICIOUS nếu 30 <= score < 70, PHISHING nếu score >= 70. Score làm tròn 6 chữ số
thập phân. Output gồm score, label_candidate, coverage, contributions, overrides,
reasons; các model output frozen. Không gọi LLM để tính score.

Node Gate/Risk và AgentState chỉ được nối tối thiểu để giữ Gate1Result và RiskResult.
Graph/API cũ vẫn dùng thuộc tính `level` tương thích; full result nằm ở `risk_result`
trong graph state. Không mở rộng HTTP response/routes trong GROUP 1.

## Files

Tạo:

- `src/schemas/tool.py`
- `tests/test_core_contracts.py`
- `docs/group1-core-contracts.md`

Sửa:

- `src/evidence/models.py`
- `src/evidence/validation.py`
- `src/evidence/risk_engine.py`
- `config/risk_weights.yaml`
- `requirements.txt` (khai báo trực tiếp PyYAML được dùng để load policy)
- `src/agents/state.py`
- `src/agents/nodes/evidence_node.py`
- `src/agents/nodes/risk_node.py`

Không xoá file, không commit/push. Parser/analyzer, Verdict/Gate 2 và các external
client chưa được triển khai thêm.

## Kiểm chứng

Chạy bằng Python 3.11 trong `.venv`:

- `python -m compileall src`: PASS.
- `python -m pytest -q`: PASS — 28 tests (5 baseline + 23 core cases).
- `python -m ruff check src tests`: PASS.
- `python -m pip check`: PASS.
- HTTP smoke Uvicorn: health 200 và existing analysis 202, empty evidence tiếp tục
  trả risk unknown và requires_review=true, không gọi external API.
- Frontend lint/build: chưa áp dụng, chưa có `frontend/package.json`.

Tests core chứng minh đủ 8 behavior bắt buộc, cùng lỗi provenance/timestamp,
immutability output, preservation của Gate issues, applicable coverage, conflict,
LLM cap và ToolResult failure boundary. Không cần dataset/API key/LLM thật.

## Chưa làm và group tiếp theo

Hiệu chỉnh policy bằng dữ liệu thực chưa làm vì chưa có dataset; GROUP 1 chỉ
đảm bảo contract và công thức deterministic. Không có việc triển khai GROUP 1
còn phụ thuộc secret/external service.

GROUP 2 (chưa bắt đầu): parser/raw-redacted boundary, Header Analyzer,
vertical slice và upload `.eml` qua HTTP. Dừng và chờ người dùng xác nhận.
