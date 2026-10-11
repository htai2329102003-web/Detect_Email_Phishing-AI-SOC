"""Real HTTP smoke with explicitly injected fakes and isolated SQLite TEST persistence.

Run: python -m scripts.smoke_group7 --test-db
No real provider keys, external requests or PostgreSQL runtime claims.
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
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-db", action="store_true", required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "docs/examples/group7-http-smoke.json")
    args = parser.parse_args()
    artifacts = []
    with SmokeDirectory(prefix="phishhunter-group7-") as folder:
        db_path = Path(folder) / "workflow.db"
        engine = create_engine(f"sqlite:///{db_path}")
        config = Config(str(ROOT / "alembic.ini"))
        with engine.begin() as connection:
            config.attributes["connection"] = connection
            command.upgrade(config, "head")
        password = secrets.token_urlsafe(24)
        with Session(engine) as session:
            session.add(
                User(email="analyst@recipient.test", password_hash=hash_password(password), role=Role.SOC_ANALYST)
            )
            session.commit()
        engine.dispose()
        environment = os.environ.copy()
        environment.update(
            APP_ENV="test",
            PHISHHUNTER_SMOKE_DB=str(db_path),
            DATABASE_URL="",
            JWT_SECRET=secrets.token_urlsafe(48),
            HEADER_TRUSTED_AUTHSERV_IDS="mx.recipient.test",
            OPENAI_API_KEY="",
            VIRUSTOTAL_API_KEY="",
            URLSCAN_API_KEY="",
            QDRANT_URL="",
            EXTERNAL_ENRICHMENT_ENABLED="false",
        )
        cases = {
            "success": ["clean.eml", "href_mismatch.eml", "suspicious_attachment.eml", "qr_url.eml"],
            "bec": ["clean.eml"],
            "timeout": ["href_mismatch.eml"],
            "unavailable": ["suspicious_attachment.eml"],
        }
        for scenario, filenames in cases.items():
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                port = listener.getsockname()[1]
            environment["PHISHHUNTER_EXTERNAL_SCENARIO"] = scenario
            with tempfile.TemporaryFile(mode="w+b") as logs:
                server = subprocess.Popen(
                    [
                        sys.executable,
                        "-m",
                        "uvicorn",
                        "tests.group7_smoke_app:create_app",
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
                    with httpx.Client(base_url=f"http://127.0.0.1:{port}", trust_env=False, timeout=30) as client:
                        for _ in range(150):
                            if server.poll() is not None:
                                raise RuntimeError("Smoke server stopped; sensitive logs withheld")
                            try:
                                if client.get("/api/v1/health").status_code == 200:
                                    break
                            except httpx.HTTPError:
                                pass
                            time.sleep(0.1)
                        else:
                            raise RuntimeError("Smoke server readiness timeout")
                        login = client.post(
                            "/api/v1/auth/login", json={"email": "analyst@recipient.test", "password": password}
                        )
                        assert login.status_code == 200
                        client.headers["Authorization"] = "Bearer " + login.json()["access_token"]
                        for filename in filenames:
                            response = client.post(
                                "/api/v1/analysis",
                                files={
                                    "file": (
                                        filename,
                                        (ROOT / "tests/fixtures/emails" / filename).read_bytes(),
                                        "message/rfc822",
                                    )
                                },
                            )
                            assert response.status_code == 200, (scenario, filename, response.status_code)
                            body = response.json()
                            partial = scenario in {"timeout", "unavailable"} or filename == "suspicious_attachment.eml"
                            assert body["analysis_scope"] == (
                                "static_enriched_partial" if partial else "static_enriched"
                            )
                            assert body["coverage"]["complete"] is not partial
                            assert body["claim_validation_status"] == "PASS"
                            if partial:
                                assert body["label_candidate"] == "NEEDS_ANALYST_REVIEW"
                                assert body["coverage"]["unknown"]
                            for evidence in body["evidence"]:
                                if evidence["tool_status"] != "OK":
                                    assert evidence["result"] == "UNKNOWN"
                                if evidence["analyzer"] in {"virustotal", "urlscan"}:
                                    assert evidence["provenance"]["source"] == "external"
                                if evidence["analyzer"] == "content_bec":
                                    assert (
                                        evidence["provenance"]["source"] == "llm"
                                        and evidence["family"] == "content_bec"
                                    )
                            expected = {
                                "clean.eml": 9 if scenario == "bec" else 0,
                                "href_mismatch.eml": 60,
                                "suspicious_attachment.eml": 50,
                                "qr_url.eml": 40,
                            }
                            assert body["score"] == expected[filename]
                            case = client.get("/api/v1/cases/" + body["case_id"])
                            assert case.status_code == 200 and case.json()["ai_assessment"]["score"] == body["score"]
                            artifacts.append(
                                {
                                    "scenario": scenario,
                                    "fixture": filename,
                                    "http_status": response.status_code,
                                    "case_http_status": case.status_code,
                                    "response": body,
                                }
                            )
                            print(
                                json.dumps(
                                    {
                                        "scenario": scenario,
                                        "fixture": filename,
                                        "http": response.status_code,
                                        "score": body["score"],
                                        "label": body["label_candidate"],
                                        "scope": body["analysis_scope"],
                                        "coverage_complete": body["coverage"]["complete"],
                                    }
                                )
                            )
                finally:
                    stop_server(server)
    target = args.output
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(
            {
                "database": "isolated SQLite TEST adapter; PostgreSQL runtime NOT VERIFIED",
                "external_real_apis": "NOT TESTED",
                "flows": artifacts,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print("HTTP smoke PASS: 7 cases; servers stopped, temporary DB removed; no real external API calls")


if __name__ == "__main__":
    main()
