from typing import List, Set
import pytest
from backend.schemas.search import SearchRecord
from backend.services.providers.base import BaseIntelligenceProvider, ProviderResult
from backend.services.providers.registry import IntelligenceAggregator, IntelligenceRegistry


class MockHealthyProvider(BaseIntelligenceProvider):
    @property
    def provider_id(self) -> str:
        return "mock_healthy"

    @property
    def display_name(self) -> str:
        return "Mock Healthy Provider"

    @property
    def supported_types(self) -> Set[str]:
        return {"email", "username"}

    async def execute(self, query: str, query_type: str) -> ProviderResult:
        return ProviderResult(
            provider_id=self.provider_id,
            provider_name=self.display_name,
            success=True,
            records=[
                SearchRecord(
                    source=self.display_name,
                    record_type="MOCK_INTEL",
                    identifier=query,
                    title="Mock Intelligence Record",
                    details={"Status": "Active"},
                )
            ],
        )


class MockFailingProvider(BaseIntelligenceProvider):
    @property
    def provider_id(self) -> str:
        return "mock_failing"

    @property
    def display_name(self) -> str:
        return "Mock Failing Provider"

    @property
    def supported_types(self) -> Set[str]:
        return {"email"}

    async def execute(self, query: str, query_type: str) -> ProviderResult:
        raise RuntimeError("Simulated upstream network or API crash!")


class MockPhoneOnlyProvider(BaseIntelligenceProvider):
    @property
    def provider_id(self) -> str:
        return "mock_phone"

    @property
    def display_name(self) -> str:
        return "Mock Phone Provider"

    @property
    def supported_types(self) -> Set[str]:
        return {"phone"}

    async def execute(self, query: str, query_type: str) -> ProviderResult:
        return ProviderResult(
            provider_id=self.provider_id,
            provider_name=self.display_name,
            success=True,
            records=[
                SearchRecord(
                    source=self.display_name,
                    record_type="PHONE_INTEL",
                    identifier=query,
                    title="Phone Carrier Intel",
                )
            ],
        )


@pytest.mark.anyio
async def test_registry_registration_and_unregistration():
    custom_registry = IntelligenceRegistry()
    p1 = MockHealthyProvider()
    p2 = MockPhoneOnlyProvider()

    custom_registry.register(p1)
    custom_registry.register(p2)

    assert len(custom_registry.get_all_providers()) == 2
    assert len(custom_registry.get_providers_for_type("email")) == 1
    assert len(custom_registry.get_providers_for_type("phone")) == 1

    # Unregister provider
    removed = custom_registry.unregister("mock_healthy")
    assert removed == p1
    assert len(custom_registry.get_providers_for_type("email")) == 0
    assert len(custom_registry.get_providers_for_type("phone")) == 1


@pytest.mark.anyio
async def test_aggregator_fault_isolation():
    """
    CRITICAL TEST: If one provider fails or throws an exception,
    other providers must still execute and return their full results
    without interference.
    """
    custom_registry = IntelligenceRegistry()
    healthy = MockHealthyProvider()
    failing = MockFailingProvider()

    custom_registry.register(healthy)
    custom_registry.register(failing)

    agg = IntelligenceAggregator(custom_registry)
    response = await agg.execute_search(query="test@example.com", query_type="email")

    assert response.success is True
    assert response.total_results == 1
    assert len(response.records) == 1
    assert response.records[0].source == "Mock Healthy Provider"
    assert "Mock Healthy Provider" in response.providers_succeeded
    assert "Mock Failing Provider" in response.providers_failed


@pytest.mark.anyio
async def test_aggregator_query_type_filtering():
    custom_registry = IntelligenceRegistry()
    custom_registry.register(MockHealthyProvider())
    custom_registry.register(MockPhoneOnlyProvider())

    agg = IntelligenceAggregator(custom_registry)

    # Phone query should only trigger MockPhoneOnlyProvider
    res_phone = await agg.execute_search(query="+15550199", query_type="phone")
    assert res_phone.total_results == 1
    assert res_phone.records[0].source == "Mock Phone Provider"
    assert res_phone.providers_queried == ["Mock Phone Provider"]

    # Username query should only trigger MockHealthyProvider
    res_user = await agg.execute_search(query="target_user", query_type="username")
    assert res_user.total_results == 1
    assert res_user.records[0].source == "Mock Healthy Provider"
    assert res_user.providers_queried == ["Mock Healthy Provider"]
