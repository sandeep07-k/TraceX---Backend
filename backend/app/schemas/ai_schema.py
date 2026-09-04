from typing import Any

from pydantic import BaseModel, Field


class AIPrediction(BaseModel):
    label: str

    phishing_probability: float

    legitimate_probability: float

    confidence: float


class AILanguagePattern(BaseModel):
    category: str

    matches: list[str] = Field(
        default_factory=list
    )


class AIAnalysis(BaseModel):
    model: str

    prediction: AIPrediction

    language_patterns: list[
        AILanguagePattern
    ] = Field(
        default_factory=list
    )