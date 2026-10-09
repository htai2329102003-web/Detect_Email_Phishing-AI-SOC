from alembic import context

from src.db.base import Base
from src.db.models import AnalysisCase, AuditLog, CaseAction, User  # noqa: F401
from src.db.session import get_session_factory

config = context.config
target_metadata = Base.metadata


def migrate(connection):
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        render_as_batch=connection.dialect.name == "sqlite",
    )
    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():
    # PostgreSQL DDL can be reviewed without credentials or a running server.
    context.configure(
        dialect_name="postgresql",
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()
elif config.attributes.get("connection") is not None:
    # Explicit test/migration runner connection, never a production SQLite fallback.
    migrate(config.attributes["connection"])
else:
    with get_session_factory().kw["bind"].connect() as connection:
        migrate(connection)
