"""SQLite is an explicit isolated test adapter, not an application runtime option."""

from sqlalchemy import create_engine, event
from sqlalchemy.pool import StaticPool

from src.db.base import Base
from src.db.models import AnalysisCase, AuditLog, CaseAction, User  # noqa: F401


def test_engine(path=None):
    url = f"sqlite:///{path}" if path else "sqlite://"
    options = {} if path else {"poolclass": StaticPool}
    engine = create_engine(url, connect_args={"check_same_thread": False}, **options)

    @event.listens_for(engine, "connect")
    def foreign_keys(connection, record):
        connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    return engine


test_engine.__test__ = False
