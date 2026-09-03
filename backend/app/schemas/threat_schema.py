from typing import Any

from pydantic import BaseModel, Field


class ThreatCategory(BaseModel):
    detected: bool
    score: int
    indicators: list[str] = Field(
        default_factory=list
    )
    evidence: list[dict[str, Any]] = Field(
        default_factory=list
    )
    confidence: float


class URLAnalysis(BaseModel):
    count: int
    suspicious_count: int
    results: list[dict[str, Any]] = Field(
        default_factory=list
    )


class ThreatAnalysis(BaseModel):
    overall_score: int
    overall_level: str

    phishing: ThreatCategory
    bec: ThreatCategory
    impersonation: ThreatCategory

    urls: URLAnalysis