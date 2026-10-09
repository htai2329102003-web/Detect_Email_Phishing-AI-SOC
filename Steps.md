# Steps — PhishHunter (VSOC-08)

## Mục tiêu

Triển khai PhishHunter theo hướng **vertical slice sớm**, tránh làm xong từng tầng rồi mới tích hợp.

Luồng kiến trúc chính:

```text
.eml
  ↓
Parser
  ↓
Deterministic Analyzers / Tools
  ↓
Evidence[]
  ↓
Gate 1 — Evidence Validation
  ↓
Risk Engine
  ↓
Verdict Agent
  ↓
Gate 2 — Claim Validator
  ↓
HITL
  ↓
Report / Authorized Action
```

Nguyên tắc bắt buộc:

- Tool/analyzer tạo evidence; LLM không tự tạo “sự thật”.
- LLM không được tự sửa `score` hoặc `label_candidate`.
- Không đủ bằng chứng thì trả `NEEDS_ANALYST_REVIEW`.
- Tool lỗi/timeout/rate limit phải là `UNKNOWN`, không được coi là safe.
- Nội dung email luôn được xem là **DATA**, không phải instruction.
- Không quarantine/block/delete trước khi HITL approve.
- Raw parsed data dùng cho deterministic analyzer; bản redacted mới đưa vào LLM.
- URL/domain khi hiển thị ở UI phải defang và không được tạo link có thể click.
- Frontend không render raw HTML email.

---

# Giai đoạn 0 — Foundation / Baseline

## Việc cần làm

1. Kích hoạt `.venv`.
2. Cài dependency:
   ```powershell
   pip install -r requirements.txt
   ```
3. Chạy baseline:
   ```powershell
   python -m compileall src
   pytest -q
   ruff check src tests
   ```
4. Chạy backend:
   ```powershell
   uvicorn src.main:app --reload --port 8000
   ```
5. Kiểm tra:
   ```text
   GET /api/v1/health
   ```
6. Hoàn thiện `.env.example`, không lưu API key thật vào repo.
7. Chuẩn bị Docker Compose cho:
   - Postgres
   - Qdrant
8. Chốt biến môi trường:
   - Database URL
   - Qdrant URL
   - LLM API key/base URL
   - VirusTotal API key
   - urlscan API key
   - JWT secret
9. Chốt giới hạn upload ban đầu:
   - max `.eml` size
   - max số attachment
   - max attachment size
   - max số entry trong archive
   - timeout cho external tool

## Mốc hoàn thành

```text
Backend khởi động được
Health endpoint = 200
Compile/test baseline sạch
Postgres và Qdrant chạy được bằng compose
```

---

# Giai đoạn 1 — Core Contracts

## 1. Evidence Contract

Hoàn thiện:

```text
src/evidence/models.py
src/evidence/validation.py
src/evidence/risk_engine.py
config/risk_weights.yaml
```

Evidence nên có tối thiểu:

```text
evidence_id
analyzer
tool
signal_type
family
indicator
value
result: PASS | FAIL | UNKNOWN
tool_status: OK | TIMEOUT | RATE_LIMITED | ERROR
severity
confidence
provenance
collected_at
```

Quy tắc:

- `tool_status != OK` → `result = UNKNOWN`.
- Evidence ID phải deterministic để hỗ trợ dedupe.
- Evidence từ LLM phải được đánh dấu rõ nguồn và weight thấp.
- `PASS` không được dùng để âm điểm rủi ro một cách tùy tiện.

## 2. Gate 1 — Evidence Validation

Phải kiểm tra:

- Schema hợp lệ.
- Provenance tồn tại.
- Timestamp hợp lệ.
- Dedupe theo `evidence_id`.
- Tool lỗi → evidence `UNKNOWN`.
- Reject hoặc hạ cấp evidence không hợp lệ.

## 3. Risk Engine

Risk Engine là Python deterministic, không dùng LLM.

Output:

```text
score
label_candidate
coverage
contributions
```

Nhãn:

```text
SAFE
SUSPICIOUS
PHISHING
NEEDS_ANALYST_REVIEW
```

## 4. Correlated Signals

Thêm `family` ngay từ đầu, ví dụ:

```yaml
SPF_FAIL:
  family: email_auth
  weight: 0.20

DKIM_FAIL:
  family: email_auth
  weight: 0.25

DMARC_FAIL:
  family: email_auth
  weight: 0.30

REPLY_TO_MISMATCH:
  family: identity
  weight: 0.30

HREF_MISMATCH:
  family: url_deception
  weight: 0.60
```

Risk Engine:

```text
Evidence
  ↓
Group by family
  ↓
Cap / chọn tín hiệu mạnh nhất trong family
  ↓
Noisy-OR giữa các family
```

Mục tiêu: tránh SPF/DKIM/DMARC/Reply-To cùng một nguyên nhân nhưng cộng score quá cao.

## 5. Wrapper dùng chung cho external tools

Tạo contract chung kiểu:

```text
ToolResult
├── status
├── data
├── error_code
├── error_message
└── latency_ms
```

Tất cả VirusTotal, urlscan, WHOIS, RAG/threat intel sau này phải theo cùng convention.

## Mốc hoàn thành

```text
Evidence validate được
Duplicate bị xử lý
Tool timeout không thể thành PASS
Risk Engine chạy độc lập
Risk score có contributions
Family correlation hoạt động
```

---

# Giai đoạn 2 — First Vertical Slice

Mục tiêu: có một đường chạy end-to-end càng sớm càng tốt.

```text
.eml
  ↓
Parser
  ↓
Header Analyzer
  ↓
Gate 1
  ↓
Risk Engine
  ↓
Verdict Stub
  ↓
/api/v1/analysis
```

## 1. Email Parser

Hoàn thiện:

```text
src/parsers/email_parser.py
src/parsers/html_parser.py
src/parsers/attachment_parser.py
```

Lấy được:

- From
- Reply-To
- Return-Path
- Received
- Authentication-Results
- Subject
- text body
- HTML body
- URLs
- attachment metadata

Malformed email phải trả lỗi có kiểm soát, không crash server.

## 2. Raw và Redacted Copy

Sau parse:

```text
ParsedEmail
├── raw_for_analyzers
└── redacted_for_llm
```

Không redaction domain, URL, hash trước deterministic analyzer.

## 3. Header Analyzer

Hoàn thiện:

```text
src/analyzers/header_analyzer.py
```

Tín hiệu ban đầu:

- SPF result
- DKIM result
- DMARC result
- Reply-To mismatch
- Return-Path mismatch
- Display-name spoofing
- Received anomalies cơ bản

Mọi kết quả trả về `Evidence[]`.

## 4. LangGraph slice tối thiểu

Tích hợp thật:

```text
parse
  ↓
header
  ↓
validate_evidence
  ↓
risk
  ↓
verdict_stub
```

## 5. API tối thiểu

```text
POST /api/v1/analysis
```

Input:

```text
.eml
```

Output tối thiểu:

```json
{
  "score": 0,
  "label_candidate": "SAFE",
  "coverage": 1.0,
  "evidence": [],
  "contributions": []
}
```

## Mốc hoàn thành

```text
Một file .eml thật
→ HTTP API
→ Parser
→ Header Evidence
→ Gate 1
→ Risk Engine
→ JSON có contributions
```

Đây là milestone quan trọng nhất trước khi mở rộng analyzer.

---

# Giai đoạn 3 — Detection Expansion

Làm các analyzer còn lại trên vertical slice đã chạy được.

## 1. URL Analyzer

```text
src/analyzers/url_analyzer.py
src/services/ioc_store.py
```

Phát hiện:

- displayed URL khác `href`
- punycode
- homoglyph/look-alike
- excessive subdomain
- URL shortener
- IP trong URL
- suspicious redirect metadata
- IOC exact-match

IOC Store dùng exact match cho:

```text
domain
URL
IP
hash
```

Không dùng semantic RAG để quyết định IOC malicious.

## 2. Attachment Analyzer

```text
src/analyzers/attachment_analyzer.py
```

Static analysis:

- metadata
- MIME
- extension
- magic bytes
- SHA-256
- double extension
- MIME/extension mismatch
- file magic mismatch
- macro/OLE metadata
- PDF suspicious actions
- archive listing

Không thực thi attachment.

Archive:

- chỉ inspect/listing
- giới hạn số entry
- giới hạn nesting
- không giải nén vô hạn
- chống zip bomb

## 3. QR Analyzer

```text
src/analyzers/qr_analyzer.py
```

Luồng:

```text
image attachment / inline image
  ↓
QR decode
  ↓
URL
  ↓
URL Analyzer
```

## 4. Content/BEC Skeleton

Giữ sẵn interface:

```text
src/analyzers/content_analyzer.py
```

Chưa cần LLM thật ở giai đoạn này nhưng graph và Evidence Contract phải chấp nhận evidence family:

```text
content_bec
```

## 5. Fixture song song

Mỗi analyzer vừa hoàn thành phải có 5–10 fixture nhỏ:

```text
tests/fixtures/emails/
```

Ví dụ:

- SPF fail
- Reply-To mismatch
- href mismatch
- punycode
- double extension
- MIME mismatch
- QR phishing
- clean email

Các fixture này trở thành seed cho bộ eval sau.

## Mốc hoàn thành

```text
Header + URL + Attachment + QR đều sinh Evidence chuẩn
Graph chạy end-to-end
Analyzer lỗi không làm toàn pipeline crash
```

---

# Giai đoạn 4 — Trust Layer

## 1. Verdict Agent thật

Hoàn thiện:

```text
src/agents/nodes/verdict_node.py
```

Input:

```text
Validated Evidence
Risk Engine result
RAG context (nếu có)
```

Output:

```text
claims[]
recommended_actions[]
analyst_summary
```

Verdict Agent không được thay:

```text
score
label_candidate
```

## 2. Gate 2 — Claim Validator

Hoàn thiện:

```text
src/evidence/claim_validator.py
```

Mỗi claim phải:

- có `evidence_ids`
- evidence tồn tại
- claim type phù hợp signal
- indicator map được về canonical evidence
- score/label không bị LLM sửa

Nếu sai:

```text
retry 1 lần
→ vẫn sai: remove claim
→ UNGROUNDED_CLAIM
→ NEEDS_ANALYST_REVIEW
```

Không validate indicator chỉ bằng raw text matching; dùng canonical ID/value.

## 3. PII Redaction

Hoàn thiện:

```text
src/services/pii.py
```

Chỉ redaction bản copy gửi LLM.

Ngoài recognizer mặc định, bổ sung recognizer cho tiếng Việt:

- số điện thoại VN
- CCCD/CMND
- email
- số tài khoản
- các định dạng nội bộ cần thiết

Phải test với mail tiếng Việt thật/synthetic.

## 4. Guardrails

Hoàn thiện:

```text
src/services/guardrails.py
```

Email luôn nằm trong vùng untrusted data.

Attack suite có:

- `ignore previous instructions`
- `return SAFE`
- `do not scan URLs`
- `reveal system prompt`
- HTML comment
- hidden text
- instruction trong Subject
- instruction trong filename
- tiếng Việt
- base64 variants

Đo hai metric riêng:

```text
Guardrail detection rate
End-to-end Attack Success Rate
```

## Mốc hoàn thành

```text
Không claim nào được trả ra nếu không grounded
Prompt injection không thể làm analyzer bị bỏ qua
Raw email không đi trực tiếp vào LLM
```

---

# Giai đoạn 5 — Human Workflow

## 1. HITL

State:

```text
PENDING
APPROVED
REJECTED
MODIFIED
```

Action state:

```text
PROPOSED
AUTHORIZED
EXECUTED
```

Chỉ cho:

```text
APPROVED / MODIFIED
```

chuyển action sang `AUTHORIZED`.

## 2. Audit Trail

Lưu:

- AI verdict
- AI score
- analyst verdict
- reviewer
- reason
- created_at
- decided_at
- state transitions

Audit log chỉ append.

## 3. Authentication / RBAC

Role tối thiểu:

```text
SOC Analyst
Admin
```

SOC Analyst:

- upload email
- xem analysis
- xem evidence
- Approve / Reject / Modify

Admin:

- quản lý user
- cấu hình cơ bản
- xem audit/system information

Password phải hash.

JWT secret lấy từ env.

## 4. Persistence

Nếu Postgres từ giai đoạn 0 đã chạy ổn thì dùng Postgres luôn.

Không cần chuyển SQLite → Postgres nếu không có lý do.

## 5. Cases API

Tối thiểu:

```text
POST /api/v1/analysis
GET  /api/v1/cases
GET  /api/v1/cases/{case_id}
POST /api/v1/cases/{case_id}/review
```

## Mốc hoàn thành

```text
AI không thể tự authorize destructive action
Analyst có thể review một case hoàn chỉnh qua API
Audit trail lưu được lịch sử quyết định
```

---

# Giai đoạn 6 — Frontend MVP

Ưu tiên màn hình mỏng nhưng chạy thật.

## Routes

```text
/login
/dashboard
/analyze
/cases
/cases/[caseId]
/admin
/admin/users
```

## Analyze

Cho upload `.eml`.

Phải có:

- file validation
- size limit
- loading state
- error state

## Case Detail

Hiển thị:

- verdict
- risk score
- confidence/coverage
- evidence
- contributions
- recommended actions
- analyst review state
- audit/review history

## Security UI

Tuyệt đối:

```text
Không dùng dangerouslySetInnerHTML cho raw email
Không render raw HTML email
Không tạo clickable malicious URL
```

Defang:

```text
https://evil.com
→ hxxps://evil[.]com
```

Raw email nếu cần xem thì escaped text/code.

## HITL UI

```text
Approve
Reject
Modify
```

Modify bắt buộc reason.

## Mốc hoàn thành

```text
Analyst đăng nhập
→ upload .eml
→ xem verdict/evidence/risk
→ review case
→ thấy audit history
```

---

# Giai đoạn 7 — Intelligence Enrichment

## 1. Content/BEC Analyzer thật

Dùng LLM classifier cho:

- urgency
- yêu cầu chuyển tiền
- đổi số tài khoản
- impersonation
- credential request
- executive/vendor fraud patterns

Evidence:

```text
provenance.source = llm
family = content_bec
```

Weight bị cap thấp, ví dụ ≤ 0.30.

Không được override IOC/VT evidence mạnh.

## 2. VirusTotal Client

```text
src/services/virustotal.py
```

MVP:

- lookup hash
- không upload file

Có:

- cache
- timeout
- rate limit
- `UNKNOWN` khi thất bại

## 3. urlscan Client

```text
src/services/urlscan.py
```

Ưu tiên dùng dữ liệu sandbox/urlscan cho redirect chain.

## 4. Threat Intel

```text
src/services/threat_intel.py
```

IOC vẫn exact-match.

## 5. Qdrant / RAG

```text
src/services/rag.py
```

Qdrant lưu:

- threat reports
- MITRE ATT&CK T1566.x
- phishing techniques
- campaign information
- SOC playbook

RAG:

- chỉ bổ sung context cho Verdict Agent
- không biến semantic similarity thành malicious evidence
- context rỗng phải có fallback an toàn

## Mốc hoàn thành

```text
External clients có timeout/fallback
BEC tạo weak evidence đúng contract
RAG không ảnh hưởng trực tiếp score
```

---

# Giai đoạn 8 — Evaluation & Tuning

Dataset/eval phải được chuẩn bị song song từ các giai đoạn trước.

## Capability Groups

### Header

- SPF/DKIM/DMARC
- Reply-To
- Return-Path
- display spoofing

### URL

- IOC
- href mismatch
- homoglyph
- punycode
- shortener

### Attachment

- double extension
- magic mismatch
- MIME mismatch
- macro metadata

### BEC

- payment request
- executive impersonation
- credential request

### QR

- decode rate
- malicious URL recall

### Prompt Injection

- guardrail block rate
- end-to-end attack success rate

## Metrics

Báo:

```text
Precision
Recall
F1
False Positive Rate
Evidence Recall
Grounded Claim Rate
NEEDS_ANALYST_REVIEW Rate
Prompt Injection Attack Success Rate
p50 latency
p95 latency
cost/mail
```

Luôn báo cả:

```text
X/N
```

bên cạnh phần trăm với tập nhỏ.

## Dataset Split

Bắt buộc:

```text
development/tuning set
≠
final reporting/test set
```

Không tune weight trên final test set.

## Risk Tuning

Tune:

- family weights
- family caps
- thresholds
- safe coverage requirements
- override rules

Sau tune phải chạy lại final test set một lần sạch.

## Mốc hoàn thành

```text
Có số liệu riêng cho từng capability
Có FPR trên mail sạch
Có evidence recall
Có ASR prompt injection
Weights được tune trên dev set
```

---

# Giai đoạn 9 — Observability, Deployment & Final Delivery

## 1. Langfuse

Trace:

- graph nodes
- tool calls
- LLM calls
- latency
- token
- cost
- errors

## 2. DeepEval

Chỉ dùng offline/bổ sung nếu cần.

Groundedness runtime chính vẫn do Claim Validator deterministic kiểm soát.

## 3. Docker

Hoàn thiện Docker/Compose cho:

- backend
- frontend
- Postgres
- Qdrant

Kiểm tra:

- startup order
- health checks
- persistence
- env
- restart

Không đợi đến cuối mới chạy Docker; phải smoke-test Compose ít nhất một lần giữa quá trình phát triển.

## 4. Final Validation

Chạy:

```powershell
python -m compileall src
pytest -q
ruff check src tests
```

Test tay tối thiểu:

1. phishing email
2. safe email
3. suspicious email
4. malformed `.eml`
5. tool timeout
6. rate limit
7. URL phishing
8. attachment suspicious
9. QR phishing
10. BEC
11. prompt injection
12. email tiếng Việt
13. case Approve
14. case Reject
15. case Modify

## 5. README / Demo / Report

README cần có:

- architecture
- setup
- `.env`
- Docker
- backend run
- frontend run
- API
- HITL
- dataset
- evaluation
- security notes
- limitations

Demo phải thể hiện rõ:

```text
Tool tạo Evidence
→ Gate 1 validate
→ Risk Engine tính score
→ LLM giải thích
→ Gate 2 validate claim
→ Analyst quyết định action
```

---

# Milestones tổng

## Milestone 0

```text
Baseline sạch + infrastructure chạy
```

## Milestone 1

```text
Evidence + Gate 1 + Risk Engine chạy độc lập
```

## Milestone 2

```text
.eml thật → API → Header Evidence → Risk JSON
```

## Milestone 3

```text
Header + URL + Attachment + QR đều sinh Evidence
```

## Milestone 4

```text
Verdict grounded + prompt injection resistance
```

## Milestone 5

```text
HITL + auth + audit + case persistence
```

## Milestone 6

```text
Analyst xử lý một case hoàn chỉnh trên web
```

## Milestone 7

```text
BEC + external threat intel + RAG
```

## Milestone 8

```text
Có eval/tuning đáng tin cậy
```

## Milestone 9

```text
Trace + deploy + final validation + deliverables
```

---

# Thứ tự triển khai ngắn gọn

```text
0. Foundation / baseline
        ↓
1. Evidence + Gate 1 + Risk Engine + family
        ↓
2. Parser + Header + first end-to-end slice
        ↓
3. URL + IOC + Attachment + QR
        ↓
4. Verdict + Gate 2 + PII + Guardrails
        ↓
5. HITL + Audit + Auth + Cases
        ↓
6. Frontend MVP
        ↓
7. BEC + VT/urlscan + Threat Intel + RAG
        ↓
8. Evaluation + Risk tuning
        ↓
9. Langfuse + Docker + Final validation + README/demo
```

---

# Trạng thái hiện tại

Đã hoàn thành:

```text
✅ Repository skeleton/refactor
✅ Backend FastAPI structure
✅ LangGraph skeleton
✅ Frontend source skeleton
✅ Backend health endpoint
✅ Virtual environment
```

Việc tiếp theo:

```text
➡ GIAI ĐOẠN 0: chạy baseline đầy đủ và kiểm tra compose/env
➡ Sau đó bắt đầu GIAI ĐOẠN 1:
   Evidence Contract
   Gate 1
   Risk Engine + family
   risk_weights.yaml
   ToolResult wrapper
```
