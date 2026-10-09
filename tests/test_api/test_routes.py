import pytest


@pytest.mark.asyncio
async def test_health(client):
    response = await client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"


@pytest.mark.asyncio
async def test_analysis_empty_email(client):
    response = await client.post(
        "/api/v1/analysis",
        files={"file": ("empty.eml", b"", "message/rfc822")},
    )
    assert response.status_code == 422  # Validation error
    assert response.json()["detail"]["code"] == "EMPTY_EMAIL"


@pytest.mark.asyncio
async def test_auth_status(client):
    response = await client.get("/api/v1/auth/status")
    assert response.status_code == 200
