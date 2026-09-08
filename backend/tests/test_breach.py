from unittest.mock import AsyncMock, patch
import pytest
from httpx import ASGITransport, AsyncClient, Response
from backend.config import get_settings
from backend.main import app
from backend.services.hibp import mask_email, sanitize_description


def test_mask_email():
    assert mask_email("user@example.com") == "u***r@example.com"
    assert mask_email("a@b.com") == "a***@b.com"
    assert mask_email("invalid") == "***"


def test_sanitize_description():
    raw = "In October 2020, &quot;Example&quot; suffered a breach. &lt;b&gt;Details&lt;/b&gt; here."
    clean = sanitize_description(raw)
    assert clean == 'In October 2020, "Example" suffered a breach. Details here.'
    assert sanitize_description(None) is None


@pytest.mark.anyio
async def test_breach_check_missing_or_invalid_email():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Invalid email format -> 400
        res = await client.post("/api/breach-check", json={"email": "not-an-email"})
        assert res.status_code == 400
        assert "Invalid email" in res.json()["detail"]

        # Blank email -> 400
        res = await client.post("/api/breach-check", json={"email": "   "})
        assert res.status_code == 400


@pytest.mark.anyio
async def test_breach_check_unconfigured_api_key():
    settings = get_settings()
    original_key = settings.HIBP_API_KEY
    settings.HIBP_API_KEY = ""
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            res = await client.post("/api/breach-check", json={"email": "test@example.com"})
            assert res.status_code == 503
            assert "HIBP API key is not configured" in res.json()["detail"]
    finally:
        settings.HIBP_API_KEY = original_key


@pytest.mark.anyio
async def test_breach_check_clean_404_response():
    settings = get_settings()
    settings.HIBP_API_KEY = "test_mock_api_key"

    mock_response = Response(
        status_code=404,
        headers={"Content-Type": "application/json"},
    )

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_response

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            res = await client.post("/api/breach-check", json={"email": "  CleanUser@Example.Com  "})
            assert res.status_code == 200
            data = res.json()
            assert data["success"] is True
            assert data["pwned"] is False
            assert data["count"] == 0
            assert data["email"] == "cleanuser@example.com"
            assert data["breaches"] == []
            assert "no pwnage found" in data["message"].lower()

            # Verify headers passed
            mock_get.assert_called_once()
            called_headers = mock_get.call_args[1]["headers"]
            assert called_headers["hibp-api-key"] == "test_mock_api_key"
            assert "OSINT" in called_headers["user-agent"]


@pytest.mark.anyio
async def test_breach_check_pwned_200_response():
    settings = get_settings()
    settings.HIBP_API_KEY = "test_mock_api_key"

    sample_breaches = [
        {
            "Name": "Adobe",
            "Title": "Adobe Inc.",
            "Domain": "adobe.com",
            "BreachDate": "2013-10-04",
            "AddedDate": "2013-12-04T00:00:00Z",
            "ModifiedDate": "2013-12-04T00:00:00Z",
            "PwnCount": 152445165,
            "Description": "In October 2013, 153 million Adobe accounts were breached.",
            "DataClasses": ["Email addresses", "Password hints", "Passwords", "Usernames"],
            "IsVerified": True,
            "IsFabricated": False,
            "IsSensitive": False,
            "IsRetired": False,
            "IsSpamList": False,
            "LogoPath": "https://haveibeenpwned.com/Content/Images/PwnedLogos/Adobe.png",
        }
    ]

    mock_response = Response(
        status_code=200,
        json=sample_breaches,
        headers={"Content-Type": "application/json"},
    )

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_response

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            res = await client.post("/api/breach-check", json={"email": "victim@example.com"})
            assert res.status_code == 200
            data = res.json()
            assert data["success"] is True
            assert data["pwned"] is True
            assert data["count"] == 1
            assert data["email"] == "victim@example.com"
            assert len(data["breaches"]) == 1
            b = data["breaches"][0]
            assert b["name"] == "Adobe"
            assert b["title"] == "Adobe Inc."
            assert b["pwn_count"] == 152445165
            assert "Passwords" in b["data_classes"]
            # Verify API key is NOT in the response
            assert "test_mock_api_key" not in res.text


@pytest.mark.anyio
async def test_breach_check_rate_limit_429():
    settings = get_settings()
    settings.HIBP_API_KEY = "test_mock_api_key"

    mock_response = Response(
        status_code=429,
        headers={"Retry-After": "3"},
    )

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_response

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            res = await client.post("/api/breach-check", json={"email": "victim@example.com"})
            assert res.status_code == 429
            assert "Rate limit exceeded" in res.json()["detail"]


@pytest.mark.anyio
async def test_breach_check_alias_endpoint():
    settings = get_settings()
    settings.HIBP_API_KEY = "test_mock_api_key"

    mock_response = Response(
        status_code=404,
        headers={"Content-Type": "application/json"},
    )

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_response

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            # Test versioned endpoint /api/v1/breach-check
            res = await client.post("/api/v1/breach-check", json={"email": "clean@example.com"})
            assert res.status_code == 200
            assert res.json()["pwned"] is False
