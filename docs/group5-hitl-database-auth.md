# GROUP 5 — HITL + Database + Auth + Cases

Ngày thực hiện: 2026-10-09 (Asia/Saigon). Chỉ GROUP 5; không bắt đầu GROUP 6.

## Database và persistence

SQLAlchemy 2.0 ORM cho users, analysis_cases, case_actions, audit_logs. Alembic revision
`0001_group5` là schema snapshot độc lập với ORM tương lai; UUID, timezone timestamps,
JSONB trên Postgres, role/state check constraints, foreign keys, unique user email và
unique case/action kind. Review cần reviewer/timestamp; MODIFIED cần reason và analyst
assessment. Không tự chạy create_all khi backend startup. Downgrade phá hủy dữ liệu
được vô hiệu hóa, không tạo reset/destructive executor trong group này.

Production chỉ nhận DATABASE_URL PostgreSQL từ env/.env (SecretStr). Default rỗng;
không dùng default SQLite cũ hoặc fallback memory. Thiếu DB/config lỗi/unavailable trả
503; không trả thành công giả. Health vẫn là liveness. Session theo request, rollback
phần chưa commit. SQL error handler không expose connection URL/parameters/error text.

Analysis chỉ persist sau graph hoàn tất Gate 2. Case + CASE_CREATED + ANALYSIS_COMPLETED
commit cùng transaction. Lưu case_id, original filename, submitter, toàn bộ public
analysis snapshot (risk/evidence/verdict/trust), risk_score, label_candidate,
assessment_label, analysis_scope, review status và timestamps. Không lưu raw .eml,
body hoặc attachment bytes. Evidence vẫn canonical, có thể chứa PII như GROUP 4;
không tuyên bố DB đã che mọi PII. Filename chỉ là bounded metadata, không dùng làm path.

CaseDetail giữ ai_assessment không đổi và analyst_assessment riêng. Review không sửa
risk_score, label_candidate, assessment_label hoặc evidence/claims history. ORM cũng
chặn thay AI snapshot/scalar fields bằng normal instance update. Graph và các trust
boundaries GROUP 1–4 giữ nguyên source; review/persistence nằm ngoài analysis graph.

## Auth / RBAC

Password dùng Argon2id salted hash; không có plaintext/default password. Login JSON
email/password; JWT access token HS256 với persistent secret >=32 bytes từ env,
default TTL 30 phút, exp/nbf/iat/issuer/audience/type/UUID subject validation. Không
log password/token, không expose password hash, không echo input secrets trong lỗi
validation. Missing user login cũng verify dummy random hash. Invalid credentials,
invalid/expired token hoặc inactive user trả 401. Role/active lấy từ DB mỗi request,
không tin role do client hoặc JWT khai báo. Thiếu secret fail closed 503.

SOC_ANALYST/Admin có upload, list/get case, review, propose/authorize action và đọc
case audit. Chỉ Admin tạo/list users, thay role/active và đọc system audit. Analyst
vào admin endpoint nhận 403. Chưa có public signup, refresh token hoặc auth frontend.
Đây là SOC queue dùng chung, chưa có tenant/owner isolation. Admin không tự disable/
demote chính mình qua API. Bootstrap local operator chỉ khi chưa có active Admin.

Tham khảo implementation libraries: [Argon2 password hashing](https://argon2-cffi.readthedocs.io/en/stable/howto.html),
[PyJWT validation](https://pyjwt.readthedocs.io/en/stable/usage.html),
[SQLAlchemy transactions](https://docs.sqlalchemy.org/en/20/orm/session_basics.html),
[Alembic migrations](https://alembic.sqlalchemy.org/en/latest/tutorial.html).

## HITL / action / audit

PENDING chỉ chuyển một lần sang APPROVED, REJECTED hoặc MODIFIED. Conditional UPDATE
với review_status=PENDING tránh overwrite một final decision khi hai request cạnh
tranh. Không có reopen. MODIFY bắt buộc reason không rỗng và analyst label/summary;
không có score. Reviewer lấy từ authenticated UUID, lưu reviewed_at/updated_at.
Client-supplied reviewer_id/ai_score/action_state bị schema reject.

Action do human propose riêng, không tự sinh destructive action từ verdict. PROPOSED
→ AUTHORIZED chỉ qua authenticated authorization request có reason. PENDING/REJECTED
bị deny; APPROVED có thể authorize; MODIFIED chỉ authorize kind nằm trong allowed_actions
do analyst chọn lúc review (mặc định empty). ActionKind là QUARANTINE/BLOCK_SENDER/
DELETE_EMAIL; chỉ lưu state, không có code thực thi. EXECUTED reserved, bị chặn ở
input/ORM và không có endpoint chuyển trạng thái. Postgres authorization dùng row lock.

Audit append-only application layer. Events: CASE_CREATED, ANALYSIS_COMPLETED,
REVIEW_APPROVED/REJECTED/MODIFIED/DENIED, ACTION_PROPOSED/AUTHORIZED/DENIED,
USER_CREATED/UPDATED. Mỗi event có audit_id, optional case_id, actor_id, old_state,
new_state, reason, UTC timestamp và metadata allowlist không có secret. State write
và audit commit cùng transaction. Denial audit commit trước HTTP 409 nên không mất
khi request bị từ chối. Không có API sửa/xóa audit, ORM và bulk Session update/delete
bị chặn. Đây không phải DB-level WORM/tamper-proof log chống DB superuser. Khi DB
unavailable không thể ghi audit vào chính DB đó; rollback và trả sanitized 503.

## Endpoints

Các path có prefix `/api/v1`:

- POST /auth/login; GET /auth/me; GET /auth/status (implementation status, public).
- POST /analysis: authenticated upload, HTTP 200 sau commit, status/review_status=PENDING.
- GET /cases; GET /cases/{case_id}; POST /cases/{case_id}/review.
- POST /cases/{case_id}/actions; POST /cases/{case_id}/actions/{action_id}/authorize.
- GET /cases/{case_id}/audit.
- POST/GET /admin/users; PATCH /admin/users/{user_id}; GET /admin/audit.

Case/action/user IDs là UUID. List endpoints có limit <=100/offset. Missing row 404,
invalid schema/ID 422, duplicate/final-state/action-denied 409. Unauthorized 401,
forbidden 403. [API contract](api-contract.md) có request/response fields và rule cụ thể.

## Setup Postgres khi runtime khả dụng

Điền .env riêng: POSTGRES_PASSWORD, JWT_SECRET ngẫu nhiên persistent >=32 bytes và
DATABASE_URL PostgreSQL cho host (URL-encode password). Không có secret được commit.
Compose tự override host thành service postgres. Với Docker:

```powershell
docker compose up -d postgres
docker compose run --rm --no-deps backend python -m alembic upgrade head
docker compose run --rm --no-deps backend python -m scripts.create_admin --email admin@example.test
docker compose up -d backend
```

Hoặc PostgreSQL host đã sẵn sàng:

```powershell
& .venv\Scripts\python.exe -m alembic upgrade head
& .venv\Scripts\python.exe -m scripts.create_admin --email admin@example.test
& .venv\Scripts\python.exe -m uvicorn src.main:app --host 127.0.0.1 --port 8000
```

CLI hỏi password/confirm qua getpass; dùng Admin login rồi POST /admin/users tạo Analyst.
Login response token dùng Authorization: Bearer cho subsequent requests; không ghi token
vào docs/logs. Compose vẫn giữ hạ tầng Qdrant từ GROUP 0, không có RAG integration mới.

## Kiểm chứng và runtime status

Postgres runtime: **NOT VERIFIED**. Docker CLI 29.8.0 có mặt nhưng daemon
`dockerDesktopLinuxEngine` không chạy/không có pipe. Không tìm thấy psql/postgres/initdb;
localhost 5432/5433 không reachable. Không thay production sang SQLite và không tạo
production persistence result giả. PostgreSQL connection/migration/row-lock behavior
trên runtime thật chưa kiểm chứng; cần chạy lại khi có DB/Docker runtime.

DB test adapter: SQLite cô lập, foreign keys ON, chỉ inject ở tests/dependency override.
Production factory từ chối SQLite. Tests chạy ORM/SQL transactions thật. Migration
upgrade chạy trên test DB rồi compare schema với ORM; Postgres DDL render offline có
UUID/JSONB/TIMESTAMP WITH TIME ZONE/check constraints. SQLite test không chứng minh
mọi Postgres concurrency/driver behavior. Không có runtime fallback flag trong app.

Python 3.11 của .venv:

- `python -m compileall src`: PASS.
- `python -m pytest -q`: PASS — 103 tests (79 GROUP 1–4 regression + 24 GROUP 5 cases).
- `python -m ruff check src tests`: PASS.
- Ruff cho migrations và hai script mới: PASS.
- `python -m pip check`: PASS.

Test auth hash/salt/login/invalid credentials/invalid-expired-missing-exp token/RBAC/
inactive user/fail-closed config. Test case create/read/list/404/UUID; review ba nhánh,
reason/assessment bắt buộc, protected fields, reviewer identity, final-state denial,
AI immutable history. Test action pending/rejected denial, approved authorization,
modified allowlist, repeat denial/no EXECUTED, audit old/new/append-only, transaction
rollback khi audit/persistence lỗi. Existing HTTP analyzer regressions được cấp bearer
và test DB thật; không bypass auth hoặc thay analyzer assertions.

HTTP smoke: **PASS trên TEST DB**, không phải Postgres production PASS. Uvicorn subprocess
thật trên loopback/random port, migration thật lên SQLite temporary file, credentials
ngẫu nhiên không print/save, auth thật qua HTTP, không override current-user dependency.
Server dừng, DB tạm được cleanup sau chạy. Có thể lặp lại:

```powershell
& .venv\Scripts\python.exe -m scripts.smoke_group5 --test-db
```

| Flow | Login | Analysis | GET case | Review | Authorize | Final action | Audit |
| --- | --- | --- | --- | --- | --- | --- | --- |
| APPROVE | 200 | 200 PENDING | 200 | 200 APPROVED | 200 | AUTHORIZED | 200 |
| REJECT | 200 | 200 PENDING | 200 | 200 REJECTED | 409 | PROPOSED | 200 |
| MODIFY + QUARANTINE allowed | 200 | 200 PENDING | 200 | 200 MODIFIED | 200 | AUTHORIZED | 200 |

Mỗi flow xác nhận PENDING authorize trả 409, re-review final trả 409 và snapshot AI
không đổi. Unauthorized list 401, Analyst admin access 403. URL mismatch và injection
upload cũng HTTP 200, score 60/NEEDS_ANALYST_REVIEW/Gate 2 PASS như GROUP 4. Clean
fixture receiver tin cậy mx.recipient.test cho score 0/SAFE. Không gọi external API/LLM.

Trích các trường từ case response thật trước/sau APPROVE:

```json
{
  "before": {
    "case_id": "8f549890-834b-4c43-80f8-b0edbe2d094c",
    "review_status": "PENDING",
    "risk_score": 0.0,
    "label_candidate": "SAFE",
    "reviewer_id": null,
    "reviewed_at": null
  },
  "after": {
    "case_id": "8f549890-834b-4c43-80f8-b0edbe2d094c",
    "review_status": "APPROVED",
    "risk_score": 0.0,
    "label_candidate": "SAFE",
    "reviewer_id": "20cf539e-0d24-477a-9f32-f94651cdddef",
    "reviewed_at": "2026-10-09T15:40:42.176656Z"
  }
}
```

Sau review APPROVE, review_status=APPROVED, reviewer_id là UUID authenticated Analyst,
reviewed_at có UTC timestamp; risk_score/label/ai_assessment không đổi. MODIFY giữ cùng
AI snapshot, analyst_assessment riêng có label SUSPICIOUS và summary của human.
[Before/after đầy đủ cùng audit](examples/group5-workflow-response.json) là HTTP response
thật trên test adapter, không chứa token/password hoặc attachment bytes.

## Files created

- `src/db/types.py`
- `src/db/models/case_action.py`
- `src/services/auth.py`
- `src/services/cases.py`
- `alembic.ini`
- `migrations/env.py`
- `migrations/script.py.mako`
- `migrations/versions/0001_group5.py`
- `scripts/create_admin.py`
- `scripts/smoke_group5.py`
- `tests/db_support.py`
- `tests/http_smoke_app.py`
- `tests/test_case_workflow.py`
- `tests/test_db_migration.py`
- `docs/examples/group5-workflow-response.json`
- `docs/group5-hitl-database-auth.md`

## Files modified

- `requirements.txt`
- `.env.example`
- `src/config.py`
- `src/db/base.py`
- `src/db/session.py`
- `src/db/models/user.py`
- `src/db/models/analysis_case.py`
- `src/db/models/audit_log.py`
- `src/db/models/__init__.py`
- `src/services/audit.py`
- `src/schemas/auth.py`
- `src/schemas/case.py`
- `src/api/deps.py`
- `src/api/routers/auth.py`
- `src/api/routers/admin.py`
- `src/api/routers/cases.py`
- `src/api/routers/analysis.py`
- `src/main.py`
- `tests/conftest.py`
- `README.md`
- `docs/api-contract.md`

Files deleted: không. Không commit/push. Danh sách riêng GROUP 5; workspace Git chưa
có tracked baseline nên git status untracked gồm cả code từ các group trước.

## Phần còn blocked / ngoài scope

Runtime PostgreSQL + production HTTP persistence smoke còn chờ Docker/DB runtime;
không có code bắt buộc local GROUP 5 nào còn placeholder. Chưa kiểm chứng Postgres
concurrent review/authorization trên runtime thật. CLI bootstrap đã có implementation,
chưa tạo production user vì chưa có DB; credentials phải do operator provision.

Không làm frontend, external API thật, LLM thật, Qdrant/RAG integration hoặc quarantine/
block/delete executor. Không bắt đầu GROUP 6.
