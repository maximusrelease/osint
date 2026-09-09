import pytest
from httpx import ASGITransport, AsyncClient
from backend.main import app


@pytest.mark.anyio
async def test_search_username_endpoint():
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/api/v1/search",
            json={"type": "username", "query": "cyber_analyst"},
        )
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["type"] == "username"
    assert data["query"] == "cyber_analyst"
    assert len(data["records"]) > 0


@pytest.mark.anyio
async def test_search_phone_endpoint():
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/api/v1/search",
            json={"type": "phone", "query": "+1-555-0199"},
        )
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["type"] == "phone"
    assert data["query"] == "+1-555-0199"
    assert len(data["records"]) > 0


@pytest.mark.anyio
async def test_search_alias_endpoint():
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/api/search",
            json={"type": "email", "query": "test@example.com"},
        )
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True


@pytest.mark.anyio
async def test_search_invalid_phone_validation():
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/api/v1/search",
            json={"type": "phone", "query": "abc"},
        )
    assert response.status_code == 422


@pytest.mark.anyio
async def test_search_short_username_validation():
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/api/v1/search",
            json={"type": "username", "query": "a"},
        )
    assert response.status_code == 422


@pytest.mark.anyio
async def test_search_domain_endpoint():
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/api/v1/search",
            json={"type": "domain", "query": "google.com"},
        )
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["type"] == "domain"
    assert len(data["records"]) > 0


@pytest.mark.anyio
async def test_search_invalid_domain_validation():
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/api/v1/search",
            json={"type": "domain", "query": "not_a_domain"},
        )
    assert response.status_code == 422


@pytest.mark.anyio
async def test_search_empty_query_validation():
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/api/v1/search",
            json={"type": "email", "query": "   "},
        )
    assert response.status_code == 422

