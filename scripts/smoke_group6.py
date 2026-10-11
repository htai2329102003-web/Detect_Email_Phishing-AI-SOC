"""Start unchanged FastAPI + production Next.js and drive a real Chromium browser.

Explicit isolated SQLite test adapter from GROUP 5; not Postgres runtime verification.
Run after npm install/build: python -m scripts.smoke_group6 --test-db
"""

import argparse
import os
import re
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


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def wait_ready(url, process):
    with httpx.Client(trust_env=False, timeout=2) as client:
        for _ in range(150):
            if process.poll() is not None:
                raise RuntimeError("Smoke server stopped; secret-bearing logs withheld")
            try:
                if client.get(url).status_code == 200:
                    return
            except httpx.HTTPError:
                pass
            time.sleep(0.1)
    raise RuntimeError("Smoke server readiness timeout")


def main():
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-db", action="store_true", required=True)
    parser.add_argument("--artifacts", type=Path, default=ROOT / "docs/examples")
    args = parser.parse_args()
    args.artifacts.mkdir(parents=True, exist_ok=True)
    if not (ROOT / "frontend/.next/BUILD_ID").exists():
        parser.error("Run npm run build in frontend first")
    # Public API URL is compiled into the browser bundle; bind to that configured port.
    api_port = int(os.environ.get("SMOKE_API_PORT", "8000"))
    with socket.socket() as probe:
        try:
            probe.bind(("127.0.0.1", api_port))
        except OSError:
            parser.error("Smoke API port is in use; existing servers are never reused or terminated")
    front_port = free_port()
    password = secrets.token_urlsafe(24)
    processes = []
    with SmokeDirectory(prefix="phishhunter-group6-") as folder:
        db_path = Path(folder) / "workflow.db"
        engine = create_engine(f"sqlite:///{db_path}")
        config = Config(str(ROOT / "alembic.ini"))
        with engine.begin() as connection:
            config.attributes["connection"] = connection
            command.upgrade(config, "head")
        with Session(engine) as session:
            session.add_all(
                [
                    User(email=f"{name}@recipient.test", password_hash=hash_password(password), role=role)
                    for name, role in (("analyst", Role.SOC_ANALYST), ("admin", Role.ADMIN))
                ]
            )
            session.commit()
        engine.dispose()
        environment = os.environ.copy()
        environment.update(
            APP_ENV="test",
            PHISHHUNTER_SMOKE_DB=str(db_path),
            DATABASE_URL="",
            JWT_SECRET=secrets.token_urlsafe(48),
            SMOKE_USER_PASSWORD=password,
            SMOKE_FRONTEND_URL=f"http://localhost:{front_port}",
            CORS_ORIGINS=f"http://localhost:{front_port}",
            HEADER_TRUSTED_AUTHSERV_IDS="mx.recipient.test",
            URL_PROTECTED_DOMAINS="paypal.test",
            OPENAI_API_KEY="",
            VIRUSTOTAL_API_KEY="",
            URLSCAN_API_KEY="",
            NEXT_TELEMETRY_DISABLED="1",
            EXTERNAL_ENRICHMENT_ENABLED="false",
            SMOKE_ARTIFACTS_DIR=str(args.artifacts.resolve()),
        )
        flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        with tempfile.TemporaryFile(mode="w+b") as backend_logs, tempfile.TemporaryFile(mode="w+b") as front_logs:
            try:
                backend = subprocess.Popen(
                    [
                        sys.executable,
                        "-m",
                        "uvicorn",
                        "tests.http_smoke_app:create_app",
                        "--factory",
                        "--host",
                        "127.0.0.1",
                        "--port",
                        str(api_port),
                    ],
                    cwd=ROOT,
                    env=environment,
                    stdout=backend_logs,
                    stderr=backend_logs,
                    creationflags=flags,
                )
                processes.append(backend)
                wait_ready(f"http://127.0.0.1:{api_port}/api/v1/health", backend)
                frontend = subprocess.Popen(
                    [
                        "node",
                        "node_modules/next/dist/bin/next",
                        "start",
                        "--hostname",
                        "127.0.0.1",
                        "--port",
                        str(front_port),
                    ],
                    cwd=ROOT / "frontend",
                    env=environment,
                    stdout=front_logs,
                    stderr=front_logs,
                    creationflags=flags,
                )
                processes.append(frontend)
                wait_ready(f"http://127.0.0.1:{front_port}/login", frontend)
                print("Running Chromium against real Next.js + FastAPI on isolated TEST DB", flush=True)
                result = subprocess.run(
                    ["node", "node_modules/@playwright/test/cli.js", "test"],
                    cwd=ROOT / "frontend",
                    env=environment,
                    creationflags=flags,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                )
                output = result.stdout.replace(password, "[REDACTED_PASSWORD]")
                output = re.sub(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "[REDACTED_JWT]", output)
                print(output, flush=True)
                if result.returncode:
                    raise SystemExit(result.returncode)
                print("Browser smoke PASS on explicit TEST DB; Postgres runtime NOT VERIFIED")
            finally:
                for process in reversed(processes):
                    stop_server(process)
                print("Frontend/backend stopped; temporary DB removed on exit")


if __name__ == "__main__":
    main()
