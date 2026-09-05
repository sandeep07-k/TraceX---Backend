from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class CaseCreate(BaseModel):
    title: str = "Email Investigation"


class CaseResponse(BaseModel):
    case_id: str
    title: str
    status: str

    risk_score: int = 0
    risk_level: str = "UNKNOWN"

    created_at: datetime
    updated_at: datetime


class CaseDetail(CaseResponse):
    analysis: dict[str, Any] = Field(
        default_factory=dict
    )