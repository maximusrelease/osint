from unittest.mock import AsyncMock, patch
import pytest
from backend.services.providers.holehe_provider import HoleheProvider, get_holehe_functions
from backend.services.providers.registry import IntelligenceAggregator, IntelligenceRegistry


@pytest.mark.anyio
async def test_holehe_provider_properties():
    provider = HoleheProvider()
    assert provider.provider_id == "holehe_osint"
    assert provider.display_name == "Holehe Email OSINT"
    assert provider.supported_types == {"email"}
    assert provider.is_enabled() is True


@pytest.mark.anyio
async def test_holehe_provider_non_email_or_invalid_query():
    provider = HoleheProvider()

    # Phone query type should be skipped cleanly
    res_phone = await provider.execute("+15550100", "phone")
    assert res_phone.success is True
    assert len(res_phone.records) == 0

    # Username query type should be skipped cleanly
    res_user = await provider.execute("target_user", "username")
    assert res_user.success is True
    assert len(res_phone.records) == 0

    # Invalid email without @ should be skipped cleanly
    res_invalid = await provider.execute("notanemail", "email")
    assert res_invalid.success is True
    assert len(res_invalid.records) == 0


@pytest.mark.anyio
async def test_holehe_provider_mock_detections():
    provider = HoleheProvider()

    async def mock_github_module(email, client, out):
        out.append({
            "name": "github",
            "domain": "github.com",
            "method": "register",
            "frequent_rate_limit": False,
            "rateLimit": False,
            "exists": True,
            "emailrecovery": "u***@gmail.com",
            "phoneNumber": None,
            "others": None,
        })

    async def mock_twitter_module(email, client, out):
        out.append({
            "name": "twitter",
            "domain": "twitter.com",
            "method": "password_recovery",
            "frequent_rate_limit": False,
            "rateLimit": False,
            "exists": True,
            "emailrecovery": None,
            "phoneNumber": "+1234567****",
            "others": None,
        })

    async def mock_unused_module(email, client, out):
        out.append({
            "name": "randomsite",
            "domain": "randomsite.com",
            "method": "register",
            "frequent_rate_limit": False,
            "rateLimit": False,
            "exists": False,
            "emailrecovery": None,
            "phoneNumber": None,
            "others": None,
        })

    with patch("backend.services.providers.holehe_provider.get_holehe_functions", return_value=[mock_github_module, mock_twitter_module, mock_unused_module]):
        res = await provider.execute("target@example.com", "email")

        assert res.success is True
        assert len(res.records) == 2  # only detected accounts

        github_rec = next(r for r in res.records if "Github" in r.title)
        assert github_rec.source == "Holehe Email OSINT"
        assert github_rec.details["Platform"] == "Github"
        assert github_rec.details["Domain"] == "github.com"
        assert github_rec.details["Recovery Email Hint"] == "u***@gmail.com"
        assert "GITHUB" in github_rec.tags
        assert "ACCOUNT_DISCOVERY" in github_rec.tags
        assert github_rec.risk_level == "Medium"
        assert github_rec.risk_score == 45

        twitter_rec = next(r for r in res.records if "Twitter" in r.title)
        assert twitter_rec.details["Recovery Phone Hint"] == "+1234567****"
        assert "TWITTER" in twitter_rec.tags


@pytest.mark.anyio
async def test_holehe_provider_error_resilience():
    provider = HoleheProvider()

    async def mock_faulty_module(email, client, out):
        raise RuntimeError("Simulated module network failure")

    async def mock_good_module(email, client, out):
        out.append({
            "name": "spotify",
            "domain": "spotify.com",
            "method": "register",
            "exists": True,
        })

    with patch("backend.services.providers.holehe_provider.get_holehe_functions", return_value=[mock_faulty_module, mock_good_module]):
        res = await provider.execute("target@example.com", "email")

        assert res.success is True
        assert len(res.records) == 1
        assert res.records[0].title == "Account Detected on Spotify"


@pytest.mark.anyio
async def test_holehe_aggregator_integration():
    registry = IntelligenceRegistry()
    holehe_provider = HoleheProvider()
    registry.register(holehe_provider)

    async def mock_detection(email, client, out):
        out.append({
            "name": "discord",
            "domain": "discord.com",
            "method": "register",
            "exists": True,
        })

    with patch("backend.services.providers.holehe_provider.get_holehe_functions", return_value=[mock_detection]):
        aggregator = IntelligenceAggregator(registry)
        search_res = await aggregator.execute_search("target@example.com", "email")

        assert search_res.success is True
        assert search_res.total_results == 1
        assert "Holehe Email OSINT" in search_res.providers_succeeded
        assert len(search_res.tool_telemetry) == 1
        assert search_res.tool_telemetry[0].provider_id == "holehe_osint"
        assert search_res.tool_telemetry[0].status == "succeeded"
        assert search_res.tool_telemetry[0].records_count == 1
