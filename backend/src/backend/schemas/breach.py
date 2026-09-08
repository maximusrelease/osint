from typing import List, Optional
from pydantic import BaseModel, Field


class BreachCheckRequest(BaseModel):
    email: str = Field(..., min_length=1, max_length=320, description="Email address to check for breaches")


class BreachItem(BaseModel):
    name: str = Field(..., description="Unique machine-readable breach name")
    title: str = Field(..., description="Human-readable title of the breach")
    domain: Optional[str] = Field(None, description="Domain of the breached service")
    breach_date: Optional[str] = Field(None, description="Date the breach occurred (YYYY-MM-DD)")
    added_date: Optional[str] = Field(None, description="Date the breach was added to HIBP")
    modified_date: Optional[str] = Field(None, description="Date the breach record was last modified")
    pwn_count: Optional[int] = Field(None, description="Total number of accounts affected")
    description: Optional[str] = Field(None, description="Cleaned description of the breach incident")
    data_classes: List[str] = Field(default_factory=list, description="Types of data compromised (e.g., Passwords, Emails)")
    is_verified: bool = Field(True, description="Whether the breach is verified by HIBP")
    is_fabricated: bool = Field(False, description="Whether the breach was fabricated")
    is_sensitive: bool = Field(False, description="Whether the breach is flagged as sensitive")
    is_retired: bool = Field(False, description="Whether the breach has been retired")
    is_spam_list: bool = Field(False, description="Whether the breach is from a spam list")
    logo_path: Optional[str] = Field(None, description="URL or URI to breach logo")


class BreachCheckResponse(BaseModel):
    success: bool = True
    pwned: bool = Field(..., description="True if breach records were found, False if clean")
    count: int = Field(0, description="Total number of breaches found")
    email: str = Field(..., description="Normalized query email")
    breaches: List[BreachItem] = Field(default_factory=list, description="List of breach details")
    message: str = Field(..., description="Summary message for the user")
