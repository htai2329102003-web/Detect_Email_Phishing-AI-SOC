from functools import lru_cache

import httpx
from alembic.config import Config
from alembic.script import ScriptDirectory
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from sqlalchemy import text

from src.api.deps import Admin
from src.config import get_settings
from src.db.session import get_session_factory
from src.evidence.risk_engine import load_risk_policy
from src.services.auth import jwt_key
from src.services.ioc_index import SQLiteIOCClient
from src.services.observability import METRICS

router = APIRouter(tags=["health"])


@router.get("/health")
async def health_check() -> dict[str, str]:
    """Return a lightweight liveness response."""
    settings = get_settings()
    return {"status": "ok", "service": settings.app_name, "env": settings.app_env}


@lru_cache(maxsize=1)
def readiness_ioc_client(source, index):
    return SQLiteIOCClient(source, index)


def dependency_readiness():
    """Local required dependencies; never probe billable model/enrichment APIs."""
    settings = get_settings()
    checks = {}
    try:
        with get_session_factory()() as session:
            session.execute(text("SELECT 1"))
            current = set(session.execute(text("SELECT version_num FROM alembic_version")).scalars())
            heads = set(ScriptDirectory.from_config(Config("alembic.ini")).get_heads())
            checks["postgresql"] = "ready" if current == heads else "not_ready"
    except Exception:
        checks["postgresql"] = "not_ready"
    try:
        jwt_key(settings)
        load_risk_policy()
        checks["configuration"] = "ready"
    except Exception:
        checks["configuration"] = "not_ready"
    ioc = readiness_ioc_client(settings.ioc_data_path, settings.ioc_index_path)
    checks["ioc_snapshot"] = "ready" if ioc.lookup("domain", "example.org").status == "OK" else "not_ready"
    if settings.rag_enabled:
        try:
            with httpx.Client(timeout=2, trust_env=False) as client:
                response = client.get(settings.qdrant_url.rstrip("/") + "/readyz")
                checks["qdrant"] = "ready" if response.status_code == 200 else "not_ready"
        except Exception:
            checks["qdrant"] = "not_ready"
    return checks


@router.get("/readyz")
def readiness_check(checks: dict = Depends(dependency_readiness)):
    ready = all(value == "ready" for value in checks.values())
    return JSONResponse({"status": "ready" if ready else "not_ready", "checks": checks},
                        status_code=200 if ready else 503)


@router.get("/metrics")
def runtime_metrics(user: Admin):
    return METRICS.snapshot()

