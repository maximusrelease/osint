from abc import ABC, abstractmethod
from typing import List, Optional, Set
from pydantic import BaseModel, Field
from backend.schemas.search import SearchRecord


class ProviderResult(BaseModel):
    """Result returned by an individual intelligence provider."""
    provider_id: str
    provider_name: str
    success: bool = True
    records: List[SearchRecord] = Field(default_factory=list)
    error_message: Optional[str] = None
    execution_time_ms: float = 0.0


class BaseIntelligenceProvider(ABC):
    """
    Abstract Base Class for all Intelligence Providers (Plugins/Adapters).

    To add any new intelligence tool/API (e.g., Shodan, VirusTotal, DeHashed, PhoneInfoga):
    1. Create a class inheriting from BaseIntelligenceProvider.
    2. Implement `provider_id`, `display_name`, `supported_types`, and `execute()`.
    3. The provider will automatically integrate into the aggregator engine.
    """

    @property
    @abstractmethod
    def provider_id(self) -> str:
        """Unique machine-readable identifier (e.g. 'xposedornot', 'threat_feed')."""
        pass

    @property
    @abstractmethod
    def display_name(self) -> str:
        """Human-readable provider name (e.g. 'XposedOrNot Data Breach Intel')."""
        pass

    @property
    @abstractmethod
    def supported_types(self) -> Set[str]:
        """Set of supported query types (e.g. {'email', 'username', 'phone'})."""
        pass

    def is_enabled(self) -> bool:
        """Return True if this provider is enabled and ready to query."""
        return True

    @abstractmethod
    async def execute(self, query: str, query_type: str) -> ProviderResult:
        """
        Execute intelligence query against the provider source.
        Must return a ProviderResult containing standardized SearchRecord objects.
        """
        pass
