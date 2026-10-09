from functools import lru_cache

from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.orm import sessionmaker

from src.config import get_settings


@lru_cache
def get_session_factory():
    url = get_settings().database_url.get_secret_value()
    if not url:
        raise HTTPException(503, detail={"code": "DATABASE_NOT_CONFIGURED"})
    try:
        parsed = make_url(url)
        if parsed.get_backend_name() != "postgresql":
            raise ValueError("Production persistence requires PostgreSQL")
        engine = create_engine(parsed, pool_pre_ping=True, hide_parameters=True, connect_args={"connect_timeout": 5})
    except (ValueError, ImportError):
        raise HTTPException(503, detail={"code": "DATABASE_CONFIG_INVALID"}) from None
    return sessionmaker(bind=engine, expire_on_commit=False)


def get_session():
    with get_session_factory()() as session:
        try:
            yield session
        finally:
            session.rollback()  # Uncommitted reads/errors are never implicitly committed.
