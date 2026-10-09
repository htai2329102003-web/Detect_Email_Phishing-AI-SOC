import json
import secrets
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

import jwt
import pytest
from pydantic import SecretStr
from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import SQLAlchemyError

from src.db.base import utcnow
from src.db.models import AnalysisCase, AuditLog
from src.db.session import get_session_factory
from src.services.auth import hash_password, issue_token, verify_password

EMAILS = Path(__file__).parent / "fixtures/emails"


async def upload(client):
    response = await client.post("/api/v1/analysis", files={"file": ("clean.eml", (EMAILS / "clean.eml").read_bytes())})
    assert response.status_code == 200, response.text
    return response.json()


async def detail(client, case_id):
    response = await client.get(f"/api/v1/cases/{case_id}")
    assert response.status_code == 200, response.text
    return response.json()


def test_argon2_password_hash_is_salted_and_verifiable():
    password = secrets.token_urlsafe(24)
    first, second = hash_password(password), hash_password(password)
    assert first.startswith("$argon2id$") and first != second and password not in first
    assert verify_password(password, first) and not verify_password("wrong", first)


@pytest.mark.asyncio
async def test_login_me_wrong_password_and_absent_auth(anonymous_client, database):
    client = anonymous_client
    assert (await client.get("/api/v1/cases")).status_code == 401
    assert (await client.post("/api/v1/analysis", files={"file": ("x.eml", b"x")})).status_code == 401
    response = await client.post(
        "/api/v1/auth/login", json={"email": database["analyst"].email, "password": database["password"]}
    )
    assert response.status_code == 200 and response.json()["token_type"] == "bearer"
    client.headers["Authorization"] = "Bearer " + response.json()["access_token"]
    me = await client.get("/api/v1/auth/me")
    assert me.status_code == 200 and me.json()["role"] == "SOC_ANALYST"
    assert "password_hash" not in me.text and database["password"] not in me.text
    for email in (database["analyst"].email, "missing@recipient.test"):
        bad = await client.post("/api/v1/auth/login", json={"email": email, "password": "wrong"})
        assert bad.status_code == 401 and bad.json()["detail"]["code"] == "INVALID_CREDENTIALS"


@pytest.mark.parametrize("bad_token", ["invalid", "expired", "missing_exp"])
@pytest.mark.asyncio
async def test_invalid_and_expired_tokens_are_rejected(anonymous_client, database, bad_token):
    token = issue_token(database["analyst"], database["settings"])
    if bad_token == "invalid":
        token = "not-a-token"
    else:
        key = database["settings"].jwt_secret.get_secret_value()
        payload = jwt.decode(token, key, algorithms=["HS256"], audience=database["settings"].jwt_audience)
        if bad_token == "expired":
            payload["exp"] = int((utcnow() - timedelta(minutes=1)).timestamp())
        else:
            del payload["exp"]
        token = jwt.encode(payload, key, algorithm="HS256")
    response = await anonymous_client.get("/api/v1/auth/me", headers={"Authorization": "Bearer " + token})
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_rbac_user_management_and_disabled_user_token(client, database):
    assert (await client.get("/api/v1/admin/users")).status_code == 403
    assert (
        await client.post("/api/v1/admin/users", json={"email": "new@recipient.test", "password": "x" * 20})
    ).status_code == 403
    client.headers["Authorization"] = "Bearer " + issue_token(database["admin"], database["settings"])
    password = secrets.token_urlsafe(24)
    created = await client.post("/api/v1/admin/users", json={"email": "new@recipient.test", "password": password})
    assert created.status_code == 201 and "password_hash" not in created.text and password not in created.text
    assert (await client.get("/api/v1/admin/audit")).status_code == 200
    analyst_id = str(database["analyst"].user_id)
    disabled = await client.patch(f"/api/v1/admin/users/{analyst_id}", json={"active": False})
    assert disabled.status_code == 200
    client.headers["Authorization"] = "Bearer " + issue_token(database["analyst"], database["settings"])
    assert (await client.get("/api/v1/cases")).status_code == 401


@pytest.mark.asyncio
async def test_configuration_fails_closed_without_secret_or_postgres(client, database, monkeypatch):
    monkeypatch.setattr(database["settings"], "jwt_secret", SecretStr(""))
    response = await client.post(
        "/api/v1/auth/login", json={"email": database["analyst"].email, "password": database["password"]}
    )
    assert response.status_code == 503 and response.json()["detail"]["code"] == "AUTH_NOT_CONFIGURED"
    get_session_factory.cache_clear()
    for url, code in (("", "DATABASE_NOT_CONFIGURED"), ("sqlite:///unwanted.db", "DATABASE_CONFIG_INVALID")):
        monkeypatch.setattr(database["settings"], "database_url", SecretStr(url))
        with pytest.raises(Exception) as exc:
            get_session_factory()
        assert exc.value.status_code == 503 and exc.value.detail["code"] == code
    assert not Path("unwanted.db").exists()


@pytest.mark.asyncio
async def test_analysis_creates_pending_case_and_initial_audit(client):
    result = await upload(client)
    assert result["status"] == result["review_status"] == "PENDING"
    case = await detail(client, result["case_id"])
    assert case["review_status"] == "PENDING" and case["reviewer_id"] is None and case["reviewed_at"] is None
    assert case["ai_assessment"]["score"] == case["risk_score"] == result["score"]
    assert case["ai_assessment"]["claims"] == result["claims"] and case["original_filename"] == "clean.eml"
    assert not {"raw_email", "parsed_email", "text_body", "html_body", "attachments"} & case["ai_assessment"].keys()
    assert (await client.get("/api/v1/cases")).json()[0]["case_id"] == result["case_id"]
    events = (await client.get(f"/api/v1/cases/{result['case_id']}/audit")).json()
    assert {row["event"] for row in events} == {"CASE_CREATED", "ANALYSIS_COMPLETED"}


@pytest.mark.parametrize("case_id,expected", [(str(uuid4()), 404), ("bad-id", 422)])
@pytest.mark.asyncio
async def test_missing_case_and_invalid_identifier(client, case_id, expected):
    assert (await client.get(f"/api/v1/cases/{case_id}")).status_code == expected


@pytest.mark.parametrize("decision,status", [("APPROVE", "APPROVED"), ("REJECT", "REJECTED"), ("MODIFY", "MODIFIED")])
@pytest.mark.asyncio
async def test_review_transitions_identity_immutable_ai_and_audit(client, database, decision, status):
    created = await upload(client)
    case_id = created["case_id"]
    original = (await detail(client, case_id))["ai_assessment"]
    body = {"decision": decision, "reason": "Analyst checked evidence"}
    if decision == "MODIFY":
        body["analyst_assessment"] = {"label": "SUSPICIOUS", "summary": "Manual interpretation"}
    response = await client.post(f"/api/v1/cases/{case_id}/review", json=body)
    assert response.status_code == 200, response.text
    reviewed = response.json()
    assert reviewed["review_status"] == status and reviewed["reviewer_id"] == str(database["analyst"].user_id)
    assert reviewed["reviewed_at"] and reviewed["updated_at"] >= reviewed["created_at"]
    assert reviewed["ai_assessment"] == original and reviewed["risk_score"] == created["score"]
    assert (reviewed["analyst_assessment"] is not None) == (decision == "MODIFY")
    events = (await client.get(f"/api/v1/cases/{case_id}/audit")).json()
    audit = next(row for row in events if row["event"] == f"REVIEW_{status}")
    assert (audit["old_state"], audit["new_state"]) == ("PENDING", status)
    assert audit["actor_id"] == str(database["analyst"].user_id) and audit["reason"] == body["reason"]
    assert (await client.post(f"/api/v1/cases/{case_id}/review", json=body)).status_code == 409
    assert (await detail(client, case_id))["review_status"] == status


@pytest.mark.asyncio
async def test_review_rejects_missing_reason_and_client_control_of_protected_fields(client):
    case_id = (await upload(client))["case_id"]
    url = f"/api/v1/cases/{case_id}/review"
    for body in (
        {"decision": "MODIFY", "analyst_assessment": {"label": "SAFE", "summary": "Manual"}},
        {"decision": "MODIFY", "reason": " ", "analyst_assessment": {"label": "SAFE", "summary": "Manual"}},
        {"decision": "MODIFY", "reason": "Manual"},
        {"decision": "APPROVE", "ai_score": 100},
        {"decision": "APPROVE", "reviewer_id": str(uuid4())},
        {"decision": "APPROVE", "action_state": "EXECUTED"},
        {
            "decision": "MODIFY",
            "reason": "Manual",
            "analyst_assessment": {"label": "SAFE", "summary": "Manual", "score": 0},
        },
    ):
        assert (await client.post(url, json=body)).status_code == 422
    assert (await detail(client, case_id))["review_status"] == "PENDING"


@pytest.mark.parametrize(
    "review,allow,expected",
    [
        (None, False, 409),
        ("REJECT", False, 409),
        ("APPROVE", False, 200),
        ("MODIFY", True, 200),
        ("MODIFY", False, 409),
    ],
)
@pytest.mark.asyncio
async def test_action_authorization_requires_human_review_and_modified_allowlist(client, review, allow, expected):
    case_id = (await upload(client))["case_id"]
    base = f"/api/v1/cases/{case_id}"
    action = await client.post(base + "/actions", json={"kind": "QUARANTINE"})
    assert action.status_code == 201 and action.json()["state"] == "PROPOSED"
    action_id = action.json()["action_id"]
    if review:
        body = {"decision": review, "reason": "Human review"}
        if review == "MODIFY":
            body.update(
                analyst_assessment={"label": "SUSPICIOUS", "summary": "Human interpretation"},
                allowed_actions=["QUARANTINE"] if allow else [],
            )
        assert (await client.post(base + "/review", json=body)).status_code == 200
    endpoint = base + f"/actions/{action_id}/authorize"
    response = await client.post(endpoint, json={"reason": "Human authorizes this action"})
    assert response.status_code == expected, response.text
    action_state = "AUTHORIZED" if expected == 200 else "PROPOSED"
    assert (await detail(client, case_id))["actions"][0]["state"] == action_state
    events = (await client.get(base + "/audit")).json()
    event = next(row for row in events if row["event"] == ("ACTION_AUTHORIZED" if expected == 200 else "ACTION_DENIED"))
    assert (event["old_state"], event["new_state"]) == ("PROPOSED", action_state)
    assert (await client.post(endpoint, json={"reason": "Bad", "state": "EXECUTED"})).status_code == 422
    if expected == 200:
        assert response.json()["authorized_by"] and response.json()["authorized_at"]
        assert (await client.post(endpoint, json={"reason": "Repeat"})).status_code == 409


@pytest.mark.asyncio
async def test_audit_is_append_only_at_application_layer(client, database):
    await upload(client)
    factory = database["factory"]
    for mode in ("update", "delete", "bulk_update", "bulk_delete"):
        with factory() as session:
            row = session.scalars(select(AuditLog)).first()
            with pytest.raises(ValueError, match="AUDIT_APPEND_ONLY"):
                if mode == "update":
                    row.reason = "tampered"
                elif mode == "delete":
                    session.delete(row)
                else:
                    statement = (
                        update(AuditLog).values(reason="tampered") if mode == "bulk_update" else delete(AuditLog)
                    )
                    session.execute(statement)
                session.commit()
            session.rollback()
    with factory() as session:
        assert session.scalar(select(func.count()).select_from(AuditLog)) == 2
        assert all(row.reason != "tampered" for row in session.scalars(select(AuditLog)))


@pytest.mark.asyncio
async def test_persistence_failure_never_returns_fake_success_or_partial_case(client, database, monkeypatch):
    def fail(*args, **kwargs):
        raise SQLAlchemyError("simulated failure; sensitive text must not reach HTTP")

    monkeypatch.setattr("src.services.cases.append_audit", fail)
    response = await client.post("/api/v1/analysis", files={"file": ("clean.eml", (EMAILS / "clean.eml").read_bytes())})
    assert response.status_code == 503 and response.json() == {"detail": {"code": "DATABASE_UNAVAILABLE"}}
    with database["factory"]() as session:
        assert session.scalar(select(func.count()).select_from(AnalysisCase)) == 0
        assert session.scalar(select(func.count()).select_from(AuditLog)) == 0


@pytest.mark.asyncio
async def test_validation_errors_do_not_echo_submitted_secrets(anonymous_client):
    password = secrets.token_urlsafe(256)
    response = await anonymous_client.post(
        "/api/v1/auth/login", json={"email": "user@recipient.test", "password": password}
    )
    assert response.status_code == 422 and password not in response.text
    assert "input" not in json.dumps(response.json())
