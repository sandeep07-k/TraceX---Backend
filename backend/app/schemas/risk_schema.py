from typing import Any

from pydantic import BaseModel, Field


class RiskEvidence(BaseModel):
    code: str
    category: str
    severity: str
    score_contribution: int
    message: str


class RiskComponents(BaseModel):
    header_forensics: int
    authentication: int
    phishing: int
    bec: int
    impersonation: int
    url_analysis: int
    ai_analysis: int


class RiskAssessment(BaseModel):
    score: int
    level: str

    components: RiskComponents

    evidence: list[RiskEvidence] = Field(
        default_factory=list
    )

    explanations: list[RiskEvidence] = Field(
        default_factory=list
    )

    evidence_count: int