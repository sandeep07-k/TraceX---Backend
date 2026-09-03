from typing import Any

from pydantic import BaseModel, Field


class AuthenticationCheck(BaseModel):
    status: str

    verified: bool = False

    source: str | None = None

    confidence: float = 0.0

    evidence: list[dict[str, Any]] = Field(
        default_factory=list
    )


class DKIMAuthenticationCheck(
    AuthenticationCheck
):
    signatures: list[dict[str, Any]] = Field(
        default_factory=list
    )


class EmailAuthentication(BaseModel):
    spf: AuthenticationCheck

    dkim: DKIMAuthenticationCheck

    dmarc: AuthenticationCheck

    findings: list[dict[str, Any]] = Field(
        default_factory=list
    )