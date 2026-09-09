from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field

SearchType = Literal["username", "email", "phone", "domain", "ip"]


class SearchRequest(BaseModel):
    type: str = Field(..., description="Type of search identifier: username, email, phone, domain, etc.")
    query: str = Field(..., min_length=1, max_length=320, description="Search query string")


class SearchRecord(BaseModel):
    source: str = Field(..., description="Provider or tool that sourced this record (e.g. XposedOrNot, Threat Feed)")
    record_type: str = Field(..., description="Classification category (e.g. BREACH, OSINT_CORRELATION, LEAK)")
    identifier: str = Field(..., description="The queried identifier associated with this intelligence")
    title: Optional[str] = Field(None, description="Human-readable title or service name")
    description: Optional[str] = Field(None, description="Detailed context or narrative of the intelligence")
    details: Dict[str, Any] = Field(default_factory=dict, description="Key-value intelligence attributes")
    tags: List[str] = Field(default_factory=list, description="Categorized tags (e.g., Passwords, Emails, High Risk)")
    risk_level: Optional[str] = Field(None, description="Assessed risk level: Clean, Low, Medium, High, Critical")
    risk_score: Optional[int] = Field(None, description="Numerical risk score (e.g., 0-100)")
    logo_url: Optional[str] = Field(None, description="URL to the organization or service logo")
    timestamp: Optional[str] = Field(None, description="Date or timestamp of the record occurrence")


class ProviderTelemetry(BaseModel):
    provider_id: str = Field(..., description="Unique provider ID")
    display_name: str = Field(..., description="Display name of the tool")
    status: str = Field("succeeded", description="Tool execution status: succeeded, failed, or clean")
    execution_time_ms: float = Field(0.0, description="Latency of the tool in milliseconds")
    records_count: int = Field(0, description="Number of records returned by this tool")
    summary: Optional[str] = Field(None, description="Summary verdict of this tool's findings")


class SearchResponse(BaseModel):
    success: bool = True
    type: str = Field(..., description="Search query category")
    query: str = Field(..., description="Queried string")
    engine: str = Field("OmniScan Multi-Tool Engine", description="Active multi-tool intelligence engine")
    execution_time_ms: float = Field(0.0, description="Total multi-tool pipeline execution duration in milliseconds")
    total_results: int = Field(0, description="Total aggregated records returned")
    records: List[SearchRecord] = Field(default_factory=list, description="Aggregated intelligence records")
    providers_queried: List[str] = Field(default_factory=list, description="List of providers dispatched for this query")
    providers_succeeded: List[str] = Field(default_factory=list, description="List of providers that returned successfully")
    providers_failed: List[str] = Field(default_factory=list, description="List of providers that timed out or failed")
    tool_telemetry: List[ProviderTelemetry] = Field(default_factory=list, description="Per-tool telemetry from the OmniScan suite")
    message: Optional[str] = Field(None, description="Summary status message")

