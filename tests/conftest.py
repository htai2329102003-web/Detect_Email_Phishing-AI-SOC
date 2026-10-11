import secrets
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from pydantic import SecretStr
from sqlalchemy.orm import sessionmaker

from src.config import get_settings
from src.db.models.user import User
from src.db.session import get_session
from src.db.types import Role
from src.main import app
from src.services.auth import hash_password, issue_token
from tests.db_support import test_engine


@pytest.fixture(autouse=True)
def forbid_real_provider_network(monkeypatch):
    """Production .env opt-ins must never turn a regression into real API usage."""
    import socket

    import httpx

    original = httpx.Client.send

    def offline_send(client, request, *args, **kwargs):
        if not isinstance(client._transport, httpx.MockTransport):
            raise AssertionError("Unit tests require an explicit mock HTTP transport")
        return original(client, request, *args, **kwargs)

    monkeypatch.setattr(httpx.Client, "send", offline_send)

    original_connect = socket.socket.connect
    original_create_connection = socket.create_connection

    def blocked_connect(sock, address):
        if isinstance(address, tuple) and address[0] in {"127.0.0.1", "::1", "localhost"}:
            return original_connect(sock, address)
        raise AssertionError("Unit tests cannot open network sockets")

    def blocked_create_connection(address, *args, **kwargs):
        if isinstance(address, tuple) and address[0] in {"127.0.0.1", "::1", "localhost"}:
            return original_create_connection(address, *args, **kwargs)
        raise AssertionError("Unit tests cannot open network sockets")

    monkeypatch.setattr(socket.socket, "connect", blocked_connect)
    monkeypatch.setattr(socket, "create_connection", blocked_create_connection)


@pytest.fixture
def database(monkeypatch):
    """Real ORM/SQL transactions against an isolated test DB; auth is not bypassed."""
    settings = get_settings()
    # API regressions use explicit offline dependencies, independent of local production data.
    from src.agents.graph import build_graph
    from src.api.routers import analysis

    monkeypatch.setattr(analysis, "agent", build_graph())
    monkeypatch.setattr(settings, "jwt_secret", SecretStr(secrets.token_urlsafe(48)))
    engine = test_engine()
    factory = sessionmaker(engine, expire_on_commit=False)
    password = secrets.token_urlsafe(24)
    with factory() as session:
        analyst = User(email="analyst@recipient.test", password_hash=hash_password(password), role=Role.SOC_ANALYST)
        admin = User(email="admin@recipient.test", password_hash=hash_password(password), role=Role.ADMIN)
        session.add_all([analyst, admin])
        session.commit()

    def override_session():
        with factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_session
    yield {"factory": factory, "analyst": analyst, "admin": admin, "password": password, "settings": settings}
    app.dependency_overrides.pop(get_session, None)
    engine.dispose()


@pytest_asyncio.fixture
async def client(database):
    """Existing analyzer/API regressions now exercise authenticated persistence."""
    transport = ASGITransport(app=app)
    token = issue_token(database["analyst"], database["settings"])
    async with AsyncClient(
        transport=transport, base_url="http://test", headers={"Authorization": f"Bearer {token}"}
    ) as ac:
        yield ac


@pytest_asyncio.fixture
async def anonymous_client(database):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac


@pytest.fixture
def mock_llm():
    """Mock LLM to avoid calling OpenAI during tests.

    Usage in test:
        def test_something(mock_llm):
            # LLM calls will return mock response instead of hitting OpenAI
            ...
    """
    mock = AsyncMock()
    mock.ainvoke.return_value = AsyncMock(content="Mocked LLM response")
    return mock
