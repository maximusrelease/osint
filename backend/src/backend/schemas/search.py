from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field


SearchType = Literal["username", "email", "phone"]


class SearchRequest(BaseModel):
    type: SearchType = Field(..., description="Type of search: username, email, or phone")
    query: str = Field(..., min_length=1, max_length=256, description="Search query string")


class SearchRecord(BaseModel):
    source: str
    record_type: str
    identifier: str
    details: Dict[str, Any] = Field(default_factory=dict)
    timestamp: Optional[str] = None


class SearchResponse(BaseModel):
    success: bool
    type: SearchType
    query: str
    total_results: int
    records: List[SearchRecord] = Field(default_factory=list)
    message: Optional[str] = None
