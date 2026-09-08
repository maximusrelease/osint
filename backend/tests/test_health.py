import pytest
from httpx import ASGITransport, AsyncClient
from backend.main import app


@pytest.mark.anyio
async def test_root_frontend_endpoint():
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")
    assert "Cyber Intelligence Search" in response.text
    assert "Enter an email address..." in response.text
    assert "segmented-selector" in response.text


@pytest.mark.anyio
async def test_health_check_endpoint():
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "version" in data
    assert "project" in data


@pytest.mark.anyio
async def test_search_email_endpoint():
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/api/v1/search",
            json={"type": "email", "query": "analyst@security.org"},
        )
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["type"] == "email"
    assert data["query"] == "analyst@security.org"
    assert len(data["records"]) > 0


@pytest.mark.anyio
async def test_search_validation_error():
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/api/v1/search",
            json={"type": "email", "query": "not-an-email"},
        )
    assert response.status_code == 422


@pytest.mark.anyio
async def test_legal_placeholder_endpoints():
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        for path in ["/terms", "/privacy", "/opt-out"]:
            res = await client.get(path)
            assert res.status_code == 200
            assert "text/html" in res.headers.get("content-type", "")
