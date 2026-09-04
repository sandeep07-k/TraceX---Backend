from typing import Any

from pydantic import BaseModel, Field


class IOC(BaseModel):
    type: str
    value: str
    source: str
    confidence: float

    algorithm: str | None = None


class IOCCollection(BaseModel):
    ips: list[IOC] = Field(
        default_factory=list
    )

    domains: list[IOC] = Field(
        default_factory=list
    )

    urls: list[IOC] = Field(
        default_factory=list
    )

    hashes: list[IOC] = Field(
        default_factory=list
    )

    all: list[IOC] = Field(
        default_factory=list
    )

    total: int


class IntelligenceResult(BaseModel):
    iocs: IOCCollection

    enrichment: dict[str, Any] = Field(
        default_factory=dict
    )