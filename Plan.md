# PhishHunter (VSOC-08): Kế hoạch triển khai 2 ngày

> AI Agent phân tích email lừa đảo và báo cáo người dùng.
> Luồng chính: **Tool tạo Evidence → Evidence Validation → Risk Engine → Verdict Agent → HITL**

---

## 1. Mục tiêu và phạm vi

**Mục tiêu 2 ngày:** một MVP chạy end-to-end. Đầu vào là file `.eml`, đầu ra là báo cáo gồm nhãn, điểm rủi ro, bằng chứng có dẫn chiếu, khuyến nghị xử lý và bước analyst duyệt (HITL).

**Yêu cầu cơ bản (theo đề):**
- Web app deploy, đăng nhập, tối thiểu 2 vai trò (SOC Analyst, Admin).
- Nộp email nghi ngờ, agent phân tích và phân quyết kèm bằng chứng, HITL duyệt trước khi cách ly/báo cáo, xử lý lỗi email hỏng định dạng.

**Yêu cầu nâng cao (theo đề):**
- Multi-agent (Header + URL + Attachment Analyzer).
- Eval đo chính xác phân loại và false positive.
- Guardrails chống indirect prompt injection từ nội dung email.
- Trace, PII redaction, tối ưu chi phí/độ trễ và báo cáo.

**Ràng buộc cứng:**
- Không tự cách ly, chặn người gửi hay xóa email khi chưa có HITL duyệt.
- URL và file đính kèm chỉ xử lý trong sandbox an toàn, không mở trên máy thật.
- Kết luận phải dựa trên bằng chứng (grounded), không bịa.
- Bảo vệ PII trong email trước khi đưa vào LLM.

**Tech stack:** LLM, LangGraph, parser email (header/SPF/DKIM/DMARC), URL sandbox, Qdrant (RAG), NeMo Guardrails, Presidio, FastAPI, React/Next.js, Langfuse, DeepEval, Docker.

---

## 2. Nguyên tắc thiết kế

1. **Tool tạo evidence, LLM không tự tạo "sự thật".** Mọi tín hiệu là một `Evidence` có provenance.
2. **Analyzer luôn chạy bắt buộc và deterministic.** Không do LLM quyết định có gọi hay không (chặn kiểu "do not scan URLs").
3. **Risk Engine tính điểm bằng rule và weight**, LLM không tự nghĩ ra điểm.
4. **Verdict Agent chỉ giải thích**, mỗi claim phải trích `evidence_ids`.
5. **Không đủ bằng chứng thì không ép nhãn.** Chuyển sang `NEEDS_ANALYST_REVIEW`.
6. **Tool lỗi (timeout, hết quota) không bao giờ được coi là an toàn.**
7. **Nội dung email luôn là DATA, không phải lệnh.**
8. **Mọi hành động phá hủy (quarantine/block/delete) cần HITL approve.**

---

## 3. Kiến trúc

```
.eml ─► Parser (+ Presidio redaction) ─► Guardrail đầu vào (NeMo)
                                              │ (nội dung mail luôn là DATA)
                                              ▼
  ┌──────────────── LangGraph: chạy song song, luôn bắt buộc ───────────────┐
  │ Header/BEC     URL            Attachment        QR (image→decode)       │
  │  analyzer     analyzer         analyzer      └──► URL analyzer          │
  │      └── dùng chung: IOC Store (exact-match) + tra cứu domain/VT hash ──┘
  └───────────────────────────── list[Evidence] ───────────────────────────┘
                                              ▼
                        Gate 1: Evidence Validation (schema, provenance, dedupe)
                                              ▼
                        Risk Engine (rule + weight, YAML) ─► score, label_candidate,
                                              │             coverage, contributions
                                              ▼
              Verdict Agent (LLM; RAG: MITRE/technique/SOC playbook chỉ làm ngữ cảnh)
                      output: claims[ {text, evidence_ids} ] + recommended_actions
                                              ▼
                        Gate 2: Claim Validator ─► UNGROUNDED_CLAIM nếu sai
                                              ▼
              HITL: PENDING → APPROVED / REJECTED / MODIFIED (+ audit_log)
                                              ▼
              Action: PROPOSED → AUTHORIZED (chỉ sau approve) → EXECUTED (stub)
```

**Phân quyền:** Verdict Agent **không được sửa** `score` và `label_candidate`. Nó chỉ giải thích, hoặc đề nghị chuyển sang `NEEDS_ANALYST_REVIEW` kèm lý do.

---

## 4. Đặc tả cốt lõi

### 4.1 Evidence Contract

```python
class Evidence(BaseModel):
    evidence_id: str        # deterministic: hash(analyzer+signal_type+indicator) -> tự dedupe
    analyzer: Literal["header", "url", "attachment", "qr", "content", "ioc"]
    tool: str               # vd "dmarc_check", "vt_hash_lookup"
    signal_type: str        # enum: HREF_MISMATCH, PUNYCODE_DOMAIN, DOUBLE_EXTENSION, ...
    indicator: str          # đối tượng được kiểm: URL/domain/hash/header name
    value: str              # giá trị quan sát được (cắt ngắn, coi là untrusted)
    result: Literal["PASS", "FAIL", "UNKNOWN"]
    tool_status: Literal["OK", "TIMEOUT", "RATE_LIMITED", "ERROR"]
    severity: Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    confidence: float       # 0-1, độ chắc chắn của tool
    provenance: dict        # {source: dns|virustotal|urlscan|local_rule|llm, ref: ...}
    collected_at: datetime
```

**Quy tắc:**
- `result` là kết quả của check. `tool_status` là tình trạng của tool.
- Nếu `tool_status != OK` thì bắt buộc `result = UNKNOWN`.
- Tool **không tự tính điểm**. Tool chỉ gán severity và confidence, weight do Risk Engine quyết định.
- Evidence từ LLM (`provenance.source = "llm"`) có trần weight thấp.
- Phát hiện prompt injection cũng là evidence (`PROMPT_INJECTION_DETECTED`, HIGH).
- `PASS` không trừ điểm rủi ro (phishing hay vượt SPF/DKIM). PASS chỉ đóng góp vào coverage và giải thích.

### 4.2 Gate 1: Evidence Validation (trước Risk Engine)
- Kiểm tra schema, provenance bắt buộc, `collected_at` hợp lệ.
- Dedupe theo `evidence_id`.
- Evidence lỗi bị loại hoặc hạ thành `UNKNOWN`.

### 4.3 Risk Engine

- Hàm Python thuần, weight đặt trong file YAML.
- Công thức: `score = 100 × (1 − Π(1 − weight[signal] × confidence))` (noisy-OR, luôn nằm trong 0-100).
- Luật override: IOC exact-match độc hại hoặc VT nhiều engine phát hiện thì đặt sàn ~90.
- Đầu ra: `score`, `label_candidate`, `coverage`, `contributions` (mỗi evidence đóng góp bao nhiêu).

**Weight khởi đầu (chưa kiểm chứng, phải tune trên bộ eval):**

| Tín hiệu | Weight | Ghi chú |
|---|---|---|
| IOC exact-match độc hại | 0.95 | override |
| VT hash nhiều engine phát hiện | 0.90 | |
| Double extension thực thi được | 0.70 | |
| `href ≠ displayed`, punycode/homoglyph | 0.60 | |
| Magic mismatch, macro đáng ngờ | 0.60 | |
| Prompt injection phát hiện | 0.40 | |
| Reply-To lệch, DMARC fail | 0.25-0.30 | mail hợp lệ cũng hay fail |
| Excessive subdomain | 0.20 | |
| BEC intent (LLM) | ≤ 0.30 | trần thấp vì nguồn LLM |

**Ngưỡng ban đầu:** dưới 25 là SAFE ứng viên, 25-60 là SUSPICIOUS, từ 60 là PHISHING.

**Điều kiện SAFE:** chỉ cấp khi các check bắt buộc đã chạy xong thành công (coverage đủ).

### 4.4 Nhãn verdict

Chỉ có 4 nhãn: `SAFE`, `SUSPICIOUS`, `PHISHING`, `NEEDS_ANALYST_REVIEW`.

`NEEDS_ANALYST_REVIEW` đi kèm reason code:
- `INSUFFICIENT_EVIDENCE`: bằng chứng chưa đủ.
- `CONFLICTING_EVIDENCE`: tín hiệu mâu thuẫn.
- `TOOL_FAILURE`: tool lỗi/timeout/hết quota làm thiếu coverage.
- `UNGROUNDED_CLAIM_REMOVED`: Claim Validator đã gỡ claim không có căn cứ.

### 4.5 Verdict Agent
- Đầu vào: evidence đã validate, kết quả Risk Engine, ngữ cảnh RAG (MITRE ATT&CK T1566.x, kỹ thuật phishing, SOC playbook).
- Đầu ra bắt buộc có cấu trúc: `claims[{claim_type, text, evidence_ids}]`, `recommended_actions`, tóm tắt cho analyst.
- Bản tóm tắt cho người dùng cuối nên ngắn, không lộ chi tiết nhạy cảm.

### 4.6 Gate 2: Claim Validator (deterministic, không dùng LLM-judge)
1. Mọi claim phải có `evidence_ids` không rỗng và tồn tại trong tập evidence đã qua Gate 1.
2. `claim_type` phải khớp `signal_type` của evidence được trích.
3. Mọi domain/URL/IP/hash xuất hiện trong văn bản tóm tắt phải xuất hiện trong `value` của một evidence nào đó.
4. `score` và `label` trong output phải bằng kết quả Risk Engine.
5. Vi phạm: retry một lần kèm phản hồi lỗi. Vẫn sai thì gỡ claim, gắn `UNGROUNDED_CLAIM` và chuyển `NEEDS_ANALYST_REVIEW`.

### 4.7 HITL và audit trail
- Trạng thái case: `PENDING → APPROVED / REJECTED / MODIFIED`.
- Bảng `review_cases(case_id, ai_verdict, ai_score, status, analyst_verdict, reviewer, reason, created_at, decided_at)`.
- Bảng `audit_log` chỉ thêm, không sửa: mỗi thay đổi trạng thái một dòng. `MODIFIED` bắt buộc có `reason`.
- Trạng thái action: `PROPOSED → AUTHORIZED → EXECUTED`.
  - Chỉ chuyển sang `AUTHORIZED` khi case là `APPROVED` hoặc `MODIFIED`.
  - `REJECTED` thì không action nào được cấp quyền.
- Vai trò: SOC Analyst duyệt case, Admin quản trị người dùng và cấu hình. Tùy chọn: action phá hủy như delete cần Admin xác nhận.

---

## 5. Các analyzer

### 5.1 Header/BEC Analyzer (rule)
- SPF/DKIM/DMARC, `Reply-To ≠ From`, lệch domain `From` và `Return-Path`.
- Display-name spoofing (tên lãnh đạo + domain free-mail).
- Phân tích chuỗi `Received`.

### 5.2 URL Analyzer
- Trích URL từ body (text/HTML) và từ QR.
- Tín hiệu tĩnh: `displayed URL ≠ href`, punycode/homoglyph, look-alike domain (Levenshtein), excessive subdomain, URL shortener, IP trong URL.
- Tra IOC (exact-match), urlscan/sandbox, domain age/WHOIS.
- Redirect chain: bản an toàn, giới hạn 3 hop, chặn IP nội bộ (SSRF), có timeout, hoặc chỉ lấy từ kết quả urlscan.

### 5.3 Attachment Analyzer (chỉ static, không thực thi)
- Metadata, MIME, extension, magic bytes (`python-magic`), hash (SHA-256).
- Double extension, MIME khác extension, file magic mismatch.
- Macro/OLE (`oletools`, chỉ parse), PDF (`/JavaScript`, `/OpenAction`), liệt kê nội dung zip.
- VirusTotal: **chỉ tra theo hash, không upload file**. Có cache. Hết quota thì `RATE_LIMITED` và `UNKNOWN`.

### 5.4 QR Analyzer
- Quét ảnh inline và ảnh đính kèm, decode bằng `cv2.QRCodeDetector` (tránh phụ thuộc zbar trong Docker).
- URL decode được chuyển cho URL Analyzer (evidence ghi `analyzer = "qr"` kèm nguồn ảnh).
- QR nằm trong PDF cần render trang trước (ưu tiên thấp).

### 5.5 Content/BEC Intent
- Một LLM classifier nhỏ: khẩn cấp, yêu cầu chuyển tiền/đổi tài khoản, mạo danh lãnh đạo.
- Weight bị chặn trần thấp trong Risk Engine để không tự quyết định.

### 5.6 IOC Store và RAG (tách biệt)

| | IOC Store | Semantic RAG (Qdrant) |
|---|---|---|
| Nội dung | domain, URL, IP, hash | threat report, kỹ thuật phishing, campaign, MITRE ATT&CK, SOC playbook |
| Truy vấn | **exact-match** sau chuẩn hóa (lowercase, punycode, eTLD+1) | semantic search |
| Lưu trữ | SQLite/Postgres | Qdrant |
| Vai trò | tạo Evidence | chỉ làm **ngữ cảnh** cho Verdict Agent, không tạo evidence nghiêm trọng |

---

## 6. Guardrails và Prompt Injection

- NeMo Guardrails làm lớp đầu vào. Nội dung email luôn bọc trong khối dữ liệu, không phải chỉ dẫn.
- Lớp phòng thủ chính là **kiến trúc**: analyzer deterministic và Risk Engine không phụ thuộc LLM.
- Presidio che PII (tên, email, số điện thoại, số tài khoản) trước khi vào LLM.
- Phát hiện injection sinh evidence `PROMPT_INJECTION_DETECTED`.

### Attack suite (~40 mail, chia nhóm)
- Ghi đè lệnh trực tiếp ("ignore previous instructions").
- Ép nhãn ("return SAFE").
- Cấm công cụ ("do not scan URLs").
- Lộ system prompt ("reveal system prompt").
- Văn bản ẩn (HTML comment, chữ trắng trên nền trắng).
- Lệnh nằm trong Subject/tên người gửi/tên file đính kèm.
- Biến thể tiếng Việt và mã hóa base64.

**Báo cáo hai số riêng:**
1. Tỷ lệ guardrail NeMo phát hiện.
2. **Attack success rate đầu-cuối** (verdict bị lật, tool bị bỏ qua hoặc lộ prompt).

---

## 7. Dataset

### 7.1 Email

| Dataset | Nội dung | Ghi chú |
|---|---|---|
| Nazario Phishing Corpus | Email phishing thật | ~11.5K mẫu, chỉ có mail độc hại, cần ghép nguồn mail sạch |
| Nigerian Fraud | Mail lừa đảo advance-fee | ~4K mẫu |
| SpamAssassin | Spam/ham | ~6K mẫu, dùng làm mail sạch |
| Enron | Mail nội bộ doanh nghiệp | Kho lớn không gắn nhãn, dùng làm mail lành tính |
| CEAS-08 | Spam challenge 2008 | ~39K mẫu |
| Kaggle "Phishing Email Dataset" (Naser Abdullah Alam) | Bản gộp sẵn Enron, Ling, CEAS, Nazario, Nigerian, SpamAssassin | ~82.5K mail (~42.9K spam, ~39.6K hợp lệ). **Bắt đầu từ đây** |
| IWSPA-AP 2023 (synthetic và adversarial) | Mail phishing tổng hợp và đối kháng | GitHub: `ReDASers/IWSPA-2023-Adversarial-Synthetic-Dataset`. **Giữ riêng làm test set** |
| MeAJOR Corpus (arXiv 2507.17978) | Bản gộp đa nguồn mới hơn | Tham khảo thêm |

### 7.2 URL và threat intel (cho IOC Store)
- PhishTank, OpenPhish: feed URL phishing đang hoạt động.
- URLhaus (abuse.ch): URL phát tán malware.
- Tranco top-1M: domain uy tín, làm baseline và phát hiện look-alike.

### 7.3 Lưu ý
1. **Dữ liệu cũ:** Nazario, SpamAssassin và Enron phần lớn là mail đời đầu những năm 2000, chưa phản ánh phishing hiện đại (QR, AI-generated, BEC). Cần bổ sung dữ liệu synthetic.
2. **Mất header:** các bản CSV gộp thường chỉ có subject và body. Với Header Analyzer phải lấy **raw `.eml`** từ Nazario/SpamAssassin.
3. **Tách tập:** dữ liệu dùng để tune prompt/weight tách riêng khỏi tập báo cáo kết quả (IWSPA làm test).
4. **An toàn:** chỉ mở URL và file trong sandbox/VM cô lập, không click link trong dataset trên máy cá nhân.
5. **Synthetic attachment:** dùng file vô hại (đổi tên, đổi magic bytes), không dùng mã độc thật.
6. **Bổ sung tiếng Việt:** 20-30 mail (giả ngân hàng, nhà mạng, cơ quan thuế...) để demo sát bối cảnh VinSOC.

---

## 8. Kế hoạch 2 ngày

Ước tính khoảng 26-30 giờ công. Phù hợp 2-3 người chạy song song (Track A: Core, Track B: Analyzer, Track C: Data/Eval). Một người làm một mình sẽ không hết, nên mỗi mục có mức ưu tiên.

### Ngày 1: Nền tảng, evidence, analyzer

| Track | Việc | Giờ | Ưu tiên |
|---|---|---|---|
| **A: Core** | Evidence schema, Gate 1, Risk Engine và YAML weights | 3 | P0 |
| | LangGraph skeleton với analyzer giả, Verdict Agent có citation, Claim Validator | 3 | P0 |
| **B: Analyzer** | Parser, Presidio, Header/BEC header rules | 3 | P0 |
| | URL analyzer: href mismatch, punycode/homoglyph, subdomain, IOC lookup, urlscan | 3 | P0 |
| **C: Data/Eval** | Tải dataset, chuẩn hóa, lấy raw `.eml` cho Header | 1.5 | P0 |
| | IOC store: ingest PhishTank/OpenPhish/URLhaus/Tranco (normalize, punycode, eTLD+1) | 1.5 | P0 |
| | Dữ liệu synthetic (BEC, QR, attachment, tiếng Việt) | 2 | P0 |
| | Harness eval có tag capability | 1 | P0 |

**Mốc cuối ngày 1:** một `.eml` đi qua Tools → Gate 1 → Risk Engine → Verdict → Gate 2 và ra JSON có `contributions`.

### Ngày 2: Attachment, QR, HITL, guardrail, đánh giá

| Track | Việc | Giờ | Ưu tiên |
|---|---|---|---|
| **A: Core** | HITL state machine, audit log, action authorization | 2 | P1 |
| | Guardrail (NeMo) và chạy attack suite | 2.5 | P0 |
| | Web app, đăng nhập, 2 vai trò, màn Approve/Reject/Modify | 3 | P0 |
| **B: Analyzer** | Attachment static: magic, MIME/extension, double extension, oletools, PDF, zip, VT hash | 2 | P0 |
| | QR decode (ảnh inline/attachment) rồi chuyển URL analyzer | 1.5 | P0 |
| | Content/BEC intent, Qdrant với MITRE/technique/playbook | 2 | P1 |
| | Redirect chain (bản giới hạn hoặc đọc từ urlscan) | 1 | P2 |
| **C: Data/Eval** | Chạy eval theo capability, tune weight/ngưỡng | 2 | P0 |
| | Langfuse, DeepEval (offline groundedness), Docker deploy | 1.5 | P1 |
| | README, video demo, slide | 1.5 | P0 |

### Nếu thiếu thời gian: giảm độ sâu, không bỏ tính năng
1. Redirect chain (chỉ lấy từ urlscan).
2. DeepEval (chạy tập nhỏ).
3. Độ đa dạng RAG (chỉ nạp MITRE T1566.x).
4. Quy tắc Admin cho action phá hủy.

**Luôn giữ:** parser, Evidence/Risk Engine/Validator, verdict có bằng chứng, HITL, guardrail, eval.

---

## 9. Đánh giá (Evaluation) theo capability

Mỗi mail eval có tag `capabilities` và danh sách `expected_signals`, để đo cả verdict lẫn **evidence recall** (tool có sinh đúng tín hiệu không).

| Capability | Chỉ số | Nguồn dữ liệu | Số mẫu gợi ý |
|---|---|---|---|
| Header attacks | Recall/precision theo signal | Raw Nazario/SpamAssassin, mail sửa header | 40 |
| Malicious URL | Recall, FPR | Nazario, PhishTank/URLhaus, Tranco làm sạch | 60 |
| Attachment | Recall theo loại (double ext, magic mismatch, macro) | Synthetic vô hại | 25 |
| BEC | Recall, tỷ lệ NEEDS_ANALYST_REVIEW | LLM sinh rồi duyệt tay, mẫu từ IWSPA | 20 |
| QR phishing | Tỷ lệ decode, recall | Tự sinh bằng thư viện `qrcode` nhúng vào mail | 20 |
| Prompt injection | Attack success rate, block rate theo từng lớp | Attack suite | 40 |
| Groundedness | Tỷ lệ claim hợp lệ, tỷ lệ `UNGROUNDED_CLAIM` | Toàn bộ eval | tất cả |
| FPR | FPR trên mail sạch | Enron/SpamAssassin ham, mail tiếng Việt hợp lệ | 100 |
| Latency, cost | p50/p95, chi phí/mail | Langfuse | tất cả |

**Quy ước báo cáo:**
- Báo số thô dạng X/N bên cạnh phần trăm (nhóm 20-25 mẫu dễ gây hiểu lầm nếu chỉ có %).
- Ghi rõ nhóm nào dùng dữ liệu synthetic (thường dễ hơn thực tế).
- Báo thêm tỷ lệ mail rơi vào `NEEDS_ANALYST_REVIEW` (đừng giấu bằng cách ép nhãn).
- Weight và ngưỡng chỉ có ý nghĩa nếu tune trên một tập và báo cáo trên tập tách riêng.

---

## 10. Rủi ro và lưu ý

| Rủi ro | Giảm thiểu |
|---|---|
| Weight là giả thuyết ban đầu | Tune trên tập dev, báo cáo trên tập test tách riêng (IWSPA) |
| Dữ liệu synthetic dễ hơn thực tế | Ghi rõ trong báo cáo, bổ sung vài mẫu thật nếu có |
| Tín hiệu từ LLM (BEC) là nguồn yếu nhất | Trần weight thấp, không cho override |
| Quota VirusTotal bản free (khoảng 4 request/phút) | Cache, trả `RATE_LIMITED` và `UNKNOWN`, không coi là safe |
| Redirect chain gây SSRF/lộ IP | Giới hạn hop, chặn IP nội bộ, timeout, ưu tiên dữ liệu từ urlscan |
| Lộ nội dung mail ra dịch vụ ngoài | Chỉ tra hash, che PII, không upload file |
| Over-engineering | Pydantic model dùng chung, không làm provenance graph, không calibrate bằng ML, không dùng LLM-judge |

---

## 11. Deliverables

- [ ] Web app đã deploy (đăng nhập, 2 vai trò, upload, kết quả, HITL).
- [ ] Pipeline: Analyzer → Gate 1 → Risk Engine → Verdict → Gate 2 → HITL.
- [ ] IOC Store và Qdrant (tách biệt).
- [ ] Attack suite và báo cáo guardrail (2 số liệu).
- [ ] Bảng eval theo capability.
- [ ] Trace Langfuse, audit log HITL.
- [ ] README, video demo, slide.
