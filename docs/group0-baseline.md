# GROUP 0 — Baseline / Foundation

Ngày kiểm tra: 2026-10-09 (Asia/Saigon).

## Phạm vi và thay đổi

- `.env.example`: cấu hình PhishHunter, API key để trống, đủ các biến Settings,
  cấu hình Postgres local và URL frontend đúng prefix `/api/v1`.
- `docker-compose.yml`: thêm Postgres 16, Qdrant v1.12.5, named volumes,
  Postgres healthcheck, dependency startup và địa chỉ nội bộ cho backend.
  Mật khẩu Postgres phải được cấu hình; các cổng database/Qdrant chỉ bind localhost.
- `Dockerfile`: chuyển dependency từ `/root/.local` sang `/usr/local` để
  `appuser` có thể chạy Python và Uvicorn.
- `README.md`: hướng dẫn startup offline, health, infrastructure và giới hạn hiện tại.
- Tạo báo cáo này. Không xoá file, không commit/push.

Không thêm business logic, API, dependency, database model hoặc Qdrant client.
`src/main.py`, `src/config.py`, health endpoint và requirements hiện tại dùng được.
`config/risk_weights.yaml` vẫn là draft với `weights: {}`; cấu hình risk thuộc GROUP 1.
DB base/session và RAG vẫn là boundary skeleton; chưa có persistence/retrieval thật.

## Kết quả thực tế

Các lệnh Python chạy bằng `.venv/Scripts/python.exe` (Python 3.11.9).
Alias `python` trên PATH trỏ đến WindowsApps; nên gọi trực tiếp virtual environment.

| Kiểm tra | Kết quả |
| --- | --- |
| `python -m compileall src` | PASS |
| `python -m pytest -q` | PASS — 5 passed |
| `python -m ruff check src tests` | PASS |
| `python -m pip check` | PASS — No broken requirements found |
| Settings đọc `.env.example`, API key trống | PASS |
| Uvicorn startup và HTTP GET `/api/v1/health` | PASS — HTTP 200 |
| Compose full config với env tạm và mật khẩu chỉ để validation | PASS |
| Compose từ example với mật khẩu Postgres trống | Từ chối đúng như thiết kế |
| Docker image build / Postgres / Qdrant runtime | BLOCKED — Docker daemon chưa chạy |
| Frontend lint/build | Chưa áp dụng — chưa có `frontend/package.json` |

Smoke test khởi động Uvicorn thành process riêng trên cổng localhost tạm,
để trống OpenAI/VirusTotal/urlscan key, rồi gửi HTTP request thật. Response:

```json
{"status": "ok", "service": "PhishHunter", "env": "test"}
```

Process kiểm tra đã dừng. Không gọi LLM/external API.
Health chỉ xác nhận liveness của backend, không chứng minh database/Qdrant sẵn sàng.

Compose được kiểm tra bằng bản sao nguyên nội dung trong thư mục tạm, kèm `.env`
từ example và mật khẩu validation trong process environment. Không tạo `.env`
hoặc lưu mật khẩu trong workspace. Khi sử dụng thực tế, copy `.env.example` thành
`.env`, đặt `POSTGRES_PASSWORD` và làm theo README.

Docker CLI có sẵn nhưng không kết nối được pipe `dockerDesktopLinuxEngine`.
Do đó chưa xác nhận build image, pull image, database health hoặc Qdrant runtime.
Sau khi Docker Desktop chạy Linux containers, cần chạy `docker compose up -d --build`
và kiểm tra container/health để đóng phần kiểm chứng infrastructure còn lại.

## GROUP tiếp theo (chưa thực hiện)

GROUP 1: Evidence contract, ToolResult, Gate 1, deterministic Risk Engine,
family/coverage/override config và các tests hành vi yêu cầu. Chờ người dùng xác nhận.
