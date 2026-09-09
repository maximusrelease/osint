from typing import List, Optional
from pydantic import BaseModel, Field


class BreachCheckRequest(BaseModel):
    email: str = Field(..., min_length=1, max_length=320, description="Email address to check for data breaches")


class BreachDetail(BaseModel):
    breach: str = Field(..., description="Name of the breached service or organization")
    details: Optional[str] = Field(None, description="Detailed narrative description of the incident")
    domain: Optional[str] = Field(None, description="Domain name associated with the breached entity")
    industry: Optional[str] = Field(None, description="Industry category of the breached entity")
    logo: Optional[str] = Field(None, description="URL or asset path for the breach logo")
    password_risk: Optional[str] = Field(None, description="Severity or risk level of passwords exposed")
    references: Optional[str] = Field(None, description="Reference URLs or public advisories")
    searchable: Optional[str] = Field(None, description="Whether the breach is publicly searchable in XON")
    verified: Optional[str] = Field(None, description="Whether the breach is verified")
    xposed_data: List[str] = Field(default_factory=list, description="List of compromised data types")
    xposed_date: Optional[str] = Field(None, description="Year or date when breach occurred")
    xposed_records: Optional[int] = Field(None, description="Total number of records compromised")


class BreachCheckResponse(BaseModel):
    success: bool = True
    breached: bool = Field(..., description="True if breach records were detected, False if clean")
    count: int = Field(0, description="Total count of breach incidents found")
    email: str = Field(..., description="Normalized queried email address")
    risk_score: Optional[int] = Field(None, description="Calculated breach risk score (1-100)")
    risk_label: Optional[str] = Field(None, description="Categorical risk label (e.g., Low, Medium, High)")
    breaches: List[BreachDetail] = Field(default_factory=list, description="List of detailed breach records")
    message: str = Field(..., description="User-facing summary status message")
