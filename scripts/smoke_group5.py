"""Real HTTP acceptance on an explicit isolated SQLite TEST adapter, not PostgreSQL verification.

Run: python -m scripts.smoke_group5 --test-db
Credentials are random, temporary and never printed or saved in the response artifact.
"""

import argparse
import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from scripts.smoke_support import SmokeDirectory, stop_server
from src.db.models import User
from src.db.types import Role
from src.services.auth import hash_password

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-db", action="store_true", required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "docs/examples/group5-workflow-response.json")
    args = parser.parse_args()
    with SmokeDirectory(prefix="phishhunter-group5-") as folder:
        db_path = Path(folder) / "workflow.db"
        engine = create_engine(f"sqlite:///{db_path}")
        config = Config(str(ROOT / "alembic.ini"))
        with engine.begin() as connection:
            config.attributes["connection"] = connection
            command.upgrade(config, "head")
        password = secrets.token_urlsafe(24)
        with Session(engine) as session:
            analyst = User(email="analyst@recipient.test", password_hash=hash_password(password), role=Role.SOC_ANALYST)
            admin = User(email="admin@recipient.test", password_hash=hash_password(password), role=Role.ADMIN)
            session.add_all([analyst, admin])
            session.commit()
        engine.dispose()
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        environment = os.environ.copy()
        environment.update(
            APP_ENV="test",
            PHISHHUNTER_SMOKE_DB=str(db_path),
            DATABASE_URL="",
            JWT_SECRET=secrets.token_urlsafe(48),
            HEADER_TRUSTED_AUTHSERV_IDS="mx.recipient.test",
            URL_PROTECTED_DOMAINS="paypal.test",
            OPENAI_API_KEY="",
            VIRUSTOTAL_API_KEY="",
            URLSCAN_API_KEY="",
            EXTERNAL_ENRICHMENT_ENABLED="false",
        )
        with tempfile.TemporaryFile(mode="w+b") as logs:
            server = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "uvicorn",
                    "tests.http_smoke_app:create_app",
                    "--factory",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(port),
                ],
                cwd=ROOT,
                env=environment,
                stdout=logs,
                stderr=logs,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
            try:
                with httpx.Client(base_url=f"http://127.0.0.1:{port}", trust_env=False, timeout=20) as client:
                    for _ in range(100):
                        if server.poll() is not None:
                            raise RuntimeError("Smoke server failed to start; credentials/logs withheld")
                        try:
                            if client.get("/api/v1/health").status_code == 200:
                                break
                        except httpx.ConnectError:
                            pass
                        time.sleep(0.1)
                    else:
                        raise RuntimeError("Server readiness timeout")
                    run_flows(client, password, output=args.output)
            finally:
                stop_server(server)
                print("Smoke server stopped; temporary test DB removed on exit")


def run_flows(client, password, *, output=ROOT / "docs/examples/group5-workflow-response.json"):
    assert client.get("/api/v1/cases").status_code == 401
    login = client.post("/api/v1/auth/login", json={"email": "analyst@recipient.test", "password": password})
    assert login.status_code == 200
    client.headers["Authorization"] = "Bearer " + login.json()["access_token"]
    assert client.get("/api/v1/auth/me").status_code == 200
    assert client.get("/api/v1/admin/users").status_code == 403
    snapshots = {}
    clean = (ROOT / "tests/fixtures/emails/clean.eml").read_bytes()
    for decision, status in (("APPROVE", "APPROVED"), ("REJECT", "REJECTED"), ("MODIFY", "MODIFIED")):
        filename = "href_mismatch.eml" if decision == "MODIFY" else "clean.eml"
        raw = (ROOT / "tests/fixtures/emails" / filename).read_bytes() if decision == "MODIFY" else clean
        analyzed = client.post("/api/v1/analysis", files={"file": (filename, raw, "message/rfc822")})
        assert analyzed.status_code == 200 and analyzed.json()["review_status"] == "PENDING"
        case_id = analyzed.json()["case_id"]
        base = f"/api/v1/cases/{case_id}"
        before = client.get(base)
        assert before.status_code == 200 and before.json()["review_status"] == "PENDING"
        proposal = client.post(base + "/actions", json={"kind": "QUARANTINE"})
        assert proposal.status_code == 201 and proposal.json()["state"] == "PROPOSED"
        auth_path = base + "/actions/" + proposal.json()["action_id"] + "/authorize"
        assert client.post(auth_path, json={"reason": "Premature request"}).status_code == 409
        body = {"decision": decision, "reason": "Synthetic HTTP smoke analyst review"}
        if decision == "MODIFY":
            body.update(
                analyst_assessment={"label": "SUSPICIOUS", "summary": "Manual smoke interpretation"},
                allowed_actions=["QUARANTINE"],
            )
        reviewed = client.post(base + "/review", json=body)
        assert reviewed.status_code == 200 and reviewed.json()["review_status"] == status
        after = client.get(base).json()
        assert after["ai_assessment"] == before.json()["ai_assessment"]
        if decision == "MODIFY":
            assert after["risk_score"] == 60 and after["label_candidate"] == "NEEDS_ANALYST_REVIEW"
            assert after["analyst_assessment"]["label"] == "SUSPICIOUS"
        assert after["reviewer_id"] == before.json()["submitted_by"] and after["reviewed_at"]
        authorization = client.post(auth_path, json={"reason": "Explicit human authorization"})
        assert authorization.status_code == (409 if decision == "REJECT" else 200)
        final = client.get(base).json()
        assert final["actions"][0]["state"] == ("PROPOSED" if decision == "REJECT" else "AUTHORIZED")
        audit = client.get(base + "/audit")
        assert audit.status_code == 200
        events = audit.json()
        review_event = next(row for row in events if row["event"] == f"REVIEW_{status}")
        assert (review_event["old_state"], review_event["new_state"]) == ("PENDING", status)
        assert any(row["event"] == ("ACTION_DENIED" if decision == "REJECT" else "ACTION_AUTHORIZED") for row in events)
        assert client.post(base + "/review", json=body).status_code == 409
        snapshots[decision] = {"before": before.json(), "after": final, "audit": events}
        print(
            json.dumps(
                {
                    "decision": decision,
                    "login_http": login.status_code,
                    "analysis_http": analyzed.status_code,
                    "case_http": before.status_code,
                    "review_http": reviewed.status_code,
                    "review_status": final["review_status"],
                    "authorization_http": authorization.status_code,
                    "action_state": final["actions"][0]["state"],
                    "audit_http": audit.status_code,
                }
            )
        )
    assert len(client.get("/api/v1/cases").json()) == 3
    for name, score in (("href_mismatch.eml", 60), ("prompt_injection.eml", 60)):
        response = client.post(
            "/api/v1/analysis", files={"file": (name, (ROOT / "tests/fixtures/emails" / name).read_bytes())}
        )
        assert response.status_code == 200 and response.json()["score"] == score
        assert (
            response.json()["label_candidate"] == "NEEDS_ANALYST_REVIEW"
            and response.json()["claim_validation_status"] == "PASS"
        )
    artifact = {"database": "isolated SQLite TEST adapter; PostgreSQL runtime NOT VERIFIED", "flows": snapshots}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(artifact, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print("HTTP smoke PASS on explicit TEST adapter; PostgreSQL runtime NOT VERIFIED")


if __name__ == "__main__":
    main()
