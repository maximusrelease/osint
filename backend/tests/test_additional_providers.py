import pytest
from backend.services.providers.disposable_email_provider import DisposableEmailProvider
from backend.services.providers.mail_dns_provider import MailDNSProvider
from backend.services.providers.phone_intelligence_provider import PhoneIntelligenceProvider


@pytest.mark.anyio
async def test_disposable_email_provider_burner():
    provider = DisposableEmailProvider()
    res = await provider.execute("attacker@mailinator.com", "email")

    assert res.success is True
    assert len(res.records) == 1
    rec = res.records[0]
    assert rec.risk_level == "High"
    assert rec.details["Disposable / Burner Status"] == "Yes (Flagged)"


@pytest.mark.anyio
async def test_disposable_email_provider_clean_consumer():
    provider = DisposableEmailProvider()
    res = await provider.execute("user@gmail.com", "email")

    assert res.success is True
    assert len(res.records) == 1
    rec = res.records[0]
    assert rec.risk_level == "Clean"
    assert "Free Consumer" in rec.details["Classification"]


@pytest.mark.anyio
async def test_phone_intelligence_provider_valid_number():
    provider = PhoneIntelligenceProvider()
    res = await provider.execute("+16502530000", "phone")  # Google Mountain View HQ number

    assert res.success is True
    assert len(res.records) == 1
    rec = res.records[0]
    assert "United States" in rec.details["Geographic Location"] or "US" in rec.details["Geographic Location"]
    assert rec.details["ITU Validation Status"] == "Valid Number"
    assert rec.details["E.164 Identifier"] == "+16502530000"


@pytest.mark.anyio
async def test_phone_intelligence_provider_international_format():
    provider = PhoneIntelligenceProvider()
    res = await provider.execute("+442071838750", "phone")  # UK number

    assert res.success is True
    assert len(res.records) == 1
    rec = res.records[0]
    assert "United Kingdom" in rec.details["Geographic Location"] or "GB" in rec.details["Geographic Location"]


@pytest.mark.anyio
async def test_mail_dns_provider():
    provider = MailDNSProvider()
    res = await provider.execute("test@google.com", "email")

    assert res.success is True
    assert len(res.records) == 1
    rec = res.records[0]
    assert rec.details["Domain"] == "google.com"
    assert "Primary Mail Host" in rec.details


@pytest.mark.anyio
async def test_omniscan_provider_email():
    from backend.services.providers.omniscan_provider import OmniScanProvider
    provider = OmniScanProvider()
    assert provider.provider_id == "omniscan_package"
    assert "email" in provider.supported_types
    assert "username" in provider.supported_types

    res = await provider.execute("test@gmail.com", "email")
    assert res.success is True
    assert res.provider_id == "omniscan_package"

