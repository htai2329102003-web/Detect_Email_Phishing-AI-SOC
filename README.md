# AI20K Agent Template

Template chính thức cho học viên VinUni AI20K Build Phase: cấu trúc dự án, code
mẫu và hướng dẫn kỹ thuật để xây dựng một AI Agent hoàn chỉnh — từ kiến trúc,
code, test cho đến deploy và nộp bài Demo Day.

Technical Guidebook: <https://phoenix.note.transformerlabs.ai/technical-book>

## Template có sẵn những gì

- **Cấu trúc thư mục tách lớp** — `agents/`, `api/`, `services/`, `models/` đã
  chia sẵn, không phải bàn lại từ đầu.
- **Code mẫu chạy được** — LangGraph agent (state, node, tool), FastAPI routes,
  Pydantic settings, schema.
- **Docker và CI** — Dockerfile multi-stage, `docker-compose.yml`, workflow
  GitHub Actions chạy `ruff` + `pytest` khi push lên `main`/`develop` và khi mở
  pull request vào `main`.
- **Technical Guidebook 10 chương** trong `docs/guide/`, đồng thời đọc được
  online.
- **Checklist 10 deliverables** của Demo Day.

## Yêu cầu

- Python 3.11 (phiên bản CI đang dùng)
- Git
- Docker — tuỳ chọn, chỉ cần nếu chạy `docker compose`

## Bắt đầu

### 1. Clone repo của đội

Khi đội được chốt, hệ thống tự sinh repo cho đội từ template này, nằm trong org
GitHub của khoá bạn đang học và đặt tên theo mã đội. Copy URL ở trang đội trên
Phoenix rồi clone về:

```bash
git clone https://github.com/<ORG-CỦA-KHOÁ>/<MÃ-ĐỘI>.git
cd <MÃ-ĐỘI>
```

Không cần `rm -rf .git`, `git init` hay `git remote add`: repo sinh từ template
đã bắt đầu bằng lịch sử riêng của đội và remote trỏ sẵn đúng chỗ. Chưa thấy repo
của đội thì báo BTC — repo tự tạo nằm ngoài org sẽ không được chấm.

### 2. Cài môi trường

```bash
python3.11 -m venv .venv
& "C:\Users\pc\AppData\Local\Programs\Python\Python311\python.exe" -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 3. Cấu hình biến môi trường

```bash
cp .env.example .env
```

Health và static graph chạy offline; để trống các external API key trong `.env`.
Từ GROUP 5, auth/analysis/cases cần PostgreSQL đã migrate và `JWT_SECRET` từ environment.
GROUP 7 đã có boundaries/mocks cho LLM, VirusTotal, urlscan và RAG; chưa gọi hoặc
test real API. Enrichment mặc định tắt, không cần API key cho static pipeline.

### 4. Chạy server

```bash
uvicorn src.main:app --reload --port 8000
```

Swagger UI ở <http://localhost:8000/docs>. Hoặc dùng `make run`, `make test`,
`make lint` — xem `Makefile`.

Trên Windows, có thể gọi trực tiếp Python của virtual environment:

```powershell
& .venv\Scripts\python.exe -m uvicorn src.main:app --host 127.0.0.1 --port 8000
Invoke-RestMethod http://127.0.0.1:8000/api/v1/health
```

Health trả HTTP 200 với `status: ok`, `service: PhishHunter` và môi trường hiện tại.
Đây là liveness của backend; endpoint chưa kiểm tra kết nối database hoặc Qdrant.
Các cờ `--host` / `--port` của Uvicorn quyết định địa chỉ server khi chạy lệnh này.

### 5. Infrastructure Docker (tuỳ chọn)

Điền `POSTGRES_PASSWORD` trong `.env` bằng mật khẩu local dùng ký tự URL-safe.
Sau khi Docker Desktop chạy Linux containers:

```bash
docker compose config --quiet
docker compose up -d postgres qdrant
# Hoặc build và chạy cả backend:
docker compose up -d --build
```

Compose có Postgres 16 và Qdrant, dùng named volumes để lưu dữ liệu.
Postgres/Qdrant chỉ publish trên localhost. Backend trong Compose nhận địa chỉ
`postgres:5432` và `http://qdrant:6333`; khi chạy trên host, Qdrant ở
`http://localhost:6333`. GROUP 5 đã có ORM/migration PostgreSQL cho users, cases,
action proposals và audit; Qdrant vẫn chưa có collection/ingestion/query thật.

Sau khi cấu hình `.env` với DB credentials và `JWT_SECRET` ngẫu nhiên ít nhất 32 byte,
chạy schema setup và bootstrap admin trên DB đã chọn:

```powershell
& .venv\Scripts\python.exe -m alembic upgrade head
& .venv\Scripts\python.exe -m scripts.create_admin --email admin@example.test
```

CLI hỏi password qua `getpass`; không có tài khoản/password mặc định. Host runtime
cần `DATABASE_URL=postgresql://USER:URL_ENCODED_PASSWORD@localhost:5432/DB` với giá trị
thực ở `.env`. Compose tự dùng địa chỉ service `postgres`. Hướng dẫn Compose, login
và giới hạn runtime: [báo cáo GROUP 5](docs/group5-hitl-database-auth.md).

Frontend GROUP 6 dùng Next.js App Router + TypeScript. Cần Node >= 20.9
(đã kiểm tra với Node 22.19). Sau khi backend, migration và user đã sẵn sàng:

```powershell
cd frontend
Copy-Item .env.example .env.local
npm install
npm run lint
npm run build
npm run dev
```

Mở <http://localhost:3000/login>, đăng nhập bằng user đã được bootstrap/tạo qua
Admin. Không có tài khoản mặc định. `NEXT_PUBLIC_API_URL` mặc định là
`http://localhost:8000/api/v1`; giá trị này được đóng vào browser bundle khi build.
Không đặt JWT secret hay API key trong biến `NEXT_PUBLIC_*`. Backend CORS phải
cho phép origin frontend (mặc định `http://localhost:3000`). Dùng `npm start`
sau build để chạy production server local.

Dashboard, upload, cases, HITL, action authorization và admin dùng API GROUP 5
thật. Hướng dẫn smoke, ảnh chụp và giới hạn xác minh:
[báo cáo GROUP 6](docs/group6-frontend-mvp.md).

### 6. Upload `.eml` (GROUP 2–5)

```powershell
curl.exe -H "Authorization: Bearer $env:PHISHHUNTER_ACCESS_TOKEN" -F "file=@tests/fixtures/emails/clean.eml" http://127.0.0.1:8000/api/v1/analysis
```

Endpoint nhận multipart field `file`, trả HTTP 200 với `score`, `label_candidate`,
`coverage`, `evidence`, `contributions`. File malformed trả 422, sai extension 415,
vượt 5 MiB trả 413. Mặc định auth header chưa được tin cậy nên yêu cầu analyst review.
Xem [API contract](docs/api-contract.md) để cấu hình receiver cho fixture và giới hạn
scope static local. Fixtures synthetic nhỏ trong `tests/fixtures/emails/`
không phải dataset chính thức. Header, URL, attachment và QR hiện chạy local;
IOC chưa cấu hình sẽ UNKNOWN và yêu cầu review. Không fetch URL hoặc upload attachment.

GROUP 7 bổ sung optional enrichment trước Gate 1 với transport/provider injectable.
VT chỉ hash lookup; urlscan chỉ lookup/result retrieval, không submit. IOC vẫn
canonical exact-match; RAG chỉ cung cấp knowledge context cho verdict; Content/BEC
chỉ nhận redacted copy và chịu cap hiện có. Không bật fake clients trong production.
`EXTERNAL_ENRICHMENT_ENABLED=false` giữ nguyên behavior mặc định; các scope enriched,
error mapping, config và giới hạn provision được ghi trong
[báo cáo GROUP 7](docs/group7-external-boundaries.md).

Smoke HTTP bằng fake clients, auth thật và DB test cô lập:

```powershell
& .venv\Scripts\python.exe -m scripts.smoke_group7 --test-db
```

Smoke này không xác minh PostgreSQL hoặc external API thật.

GROUP 4 nối Verdict deterministic → Gate 2: response thêm `claims` có `evidence_ids`,
`recommended_actions`, `analyst_summary` và `assessment_label`. Score/label_candidate
vẫn thuộc Risk Engine; trust failure chỉ nâng assessment sang review. Analyzer dùng raw
data; provider chỉ thấy bản sao redacted và evidence metadata. Email được giữ ở vai trò
untrusted DATA, không điều khiển analyzer hoặc risk. Chưa gọi LLM/NeMo thật; regex PII
offline có coverage giới hạn. Xem [báo cáo GROUP 4](docs/group4-trust-layer.md).

GROUP 5 yêu cầu login ở `POST /api/v1/auth/login` (JSON email/password). Analyst/Admin
có thể upload, list/get case và review; chỉ Admin quản lý users và xem system audit.
Analysis thành công tạo case `PENDING` cùng audit trong một transaction, không còn
trả thành công khi persistence lỗi. Review APPROVE/REJECT/MODIFY lưu riêng quyết định
analyst, không sửa AI score/result. Action proposal/authorization là state model;
không quarantine/block/delete thật. Postgres runtime hiện **NOT VERIFIED** do Docker
daemon không khả dụng; ORM, migration và HTTP workflow đã test trên DB SQLite cô lập
bằng dependency override, không có SQLite fallback production. Xem [API contract](docs/api-contract.md).

## Cấu trúc thư mục

```
src/
  agents/            LangGraph orchestration and nodes
  analyzers/         Deterministic phishing analysis
  api/routers/       FastAPI endpoints
  db/                Persistence boundaries and models
  evidence/          Evidence contract, validation, risk and claims
  parsers/           Email, HTML and attachment parsing
  schemas/           Pydantic API contracts
  services/          LLM and external integration boundaries
  utils/             Pure shared utilities
  config.py          Pydantic Settings
  main.py            FastAPI bootstrap
frontend/            Next.js App Router MVP for the SOC workspace
tests/               pytest suite
scripts/             Tiện ích dự án
docs/
  guide/             Technical Guidebook (nguồn của bản online)
  architecture_diagram.md
eval/                Kết quả evaluation
presentation/        Slide và video Demo Day
.github/workflows/   CI
Dockerfile           Multi-stage build
docker-compose.yml   Chạy backend bằng Docker
README_boilerplate.md  Khung README cho dự án của đội
```

## Technical Guidebook

| Chương | Nội dung | Thời gian |
|---|---|---|
| 1 | Lời mở đầu — mục tiêu, cách sử dụng | 15 phút |
| 2 | Khởi tạo dự án — clone, setup, git workflow | 4 giờ |
| 3 | Thiết kế kiến trúc — 3-tier, diagram, ADR | 6 giờ |
| 4 | LangGraph Agent — state, node, edge, tool, RAG | 8 giờ |
| 5 | FastAPI — routes, validation, error handling, streaming | 6 giờ |
| 6 | Giao diện — Next.js và Streamlit | 6 giờ |
| 7 | DevOps — Docker, CI/CD, deploy, logging | 6 giờ |
| 8 | Kiểm thử — unit test, integration test, RAGAS | 4 giờ |
| 9 | Demo Day — 10 deliverables, checklist | 2 giờ |
| 10 | Tài nguyên — khoá học, tài liệu, BMAD method | tham khảo |

Đọc online tại <https://phoenix.note.transformerlabs.ai/technical-book>: đăng
nhập bằng GitHub (đúng account đã được BTC mời vào org của khoá), chọn tab
**Technical Book** ở sidebar trái. Bản offline nằm trong `docs/guide/`, mở được
bằng bất kỳ markdown viewer nào.

## 9 deliverables cho Demo Day

| # | Deliverable | Vị trí | Template lo tới đâu |
|---|---|---|---|
| 1 | Source code | `src/` | Khung sẵn |
| 2 | README | copy `README_boilerplate.md` thành `README.md` | Khung sẵn |
| 3 | Architecture diagram | `docs/architecture_diagram.md` | Khung sẵn |
| 4 | Live URL | deploy lên Render/Vercel | CI/CD sẵn |
| 5 | Video demo | `presentation/` | Đội tự làm |
| 6 | Pitch deck | `presentation/` | Đội tự làm |
| 7 | Development journal | `JOURNAL.md` | Khung sẵn |
| 8 | Worklog | `WORKLOG.md` | Khung sẵn |
| 9 | Evaluation evidence | `eval/` | Đội tự làm |

## Tech stack

| Lớp | Công nghệ |
|---|---|
| Agent | LangGraph + LangChain 0.3 |
| Backend | FastAPI 0.115 + Uvicorn |
| LLM | OpenAI, mặc định `gpt-4o-mini` (đổi trong `src/config.py`) |
| Giao diện | Next.js hoặc Streamlit (đội tự chọn, hướng dẫn ở chương 6) |
| Lint / test | ruff + pytest 8 |
| DevOps | Docker + GitHub Actions |

## Đóng góp

Repo này là open source. Đọc [CONTRIBUTING.md](CONTRIBUTING.md) trước khi mở PR.

Nội dung trong `docs/guide/` là nguồn của Technical Book và được đồng bộ lên bản
online, nên mọi thay đổi ở đó cần review của
[@AI20K-Build-Phase/book-maintainers](https://github.com/orgs/AI20K-Build-Phase/teams/book-maintainers)
— xem [.github/CODEOWNERS](.github/CODEOWNERS).

Báo lỗ hổng bảo mật theo [SECURITY.md](SECURITY.md), đừng mở public issue.

## License

[MIT](LICENSE) — dùng tự do cho mục đích giáo dục.
