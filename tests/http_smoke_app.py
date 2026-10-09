"""Explicit test-only ASGI factory. Never selected by src.main or Compose."""

import os
from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from src.db.session import get_session
from src.main import app


def create_app():
    if os.environ.get("APP_ENV") != "test":
        raise RuntimeError("Smoke adapter requires APP_ENV=test")
    path = Path(os.environ["PHISHHUNTER_SMOKE_DB"]).resolve(strict=True)
    engine = create_engine(f"sqlite:///{path}", connect_args={"check_same_thread": False})

    @event.listens_for(engine, "connect")
    def foreign_keys(connection, record):
        connection.execute("PRAGMA foreign_keys=ON")

    factory = sessionmaker(engine, expire_on_commit=False)

    def session_dependency():
        with factory() as session:
            yield session

    app.dependency_overrides[get_session] = session_dependency
    return app
