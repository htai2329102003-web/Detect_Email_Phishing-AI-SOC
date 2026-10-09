import io
from pathlib import Path

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect

from src.db.base import Base
from src.db.models import AnalysisCase, AuditLog, CaseAction, User  # noqa: F401

ROOT = Path(__file__).resolve().parents[1]


def test_initial_migration_applies_and_matches_orm_on_isolated_test_db(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'migration.db'}")
    config = Config(str(ROOT / "alembic.ini"))
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "head")
        assert set(inspect(connection).get_table_names()) == {
            "users",
            "analysis_cases",
            "case_actions",
            "audit_logs",
            "alembic_version",
        }
        assert not compare_metadata(MigrationContext.configure(connection), Base.metadata)
    engine.dispose()


def test_postgresql_migration_ddl_renders_without_runtime_credentials():
    output = io.StringIO()
    config = Config(str(ROOT / "alembic.ini"), output_buffer=output)
    command.upgrade(config, "head", sql=True)
    ddl = output.getvalue()
    assert "JSONB" in ddl and "UUID" in ddl and "TIMESTAMP WITH TIME ZONE" in ddl
    assert "CREATE TABLE audit_logs" in ddl and "ck_analysis_cases_modified_reason" in ddl
