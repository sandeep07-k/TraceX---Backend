from typing import Any

from pydantic import BaseModel, Field

from app.schemas.authentication_schema import (
    EmailAuthentication,
)
from app.schemas.threat_schema import (
    ThreatAnalysis,
)
from app.schemas.risk_schema import (
    RiskAssessment,
)

class AttachmentInfo(BaseModel):
    filename: str
    content_type: str | None = None
    size: int | None = None


class EmailInfo(BaseModel):
    sender: str | None = None
    sender_email: str | None = None

    recipients: list[str] = Field(default_factory=list)
    cc: list[str] = Field(default_factory=list)
    bcc: list[str] = Field(default_factory=list)

    subject: str | None = None
    date: str | None = None

    reply_to: str | None = None
    reply_to_email: str | None = None

    return_path: str | None = None
    message_id: str | None = None

    received_headers: list[str] = Field(
        default_factory=list
    )

    text_body: str = ""
    html_body: str = ""

    urls: list[str] = Field(
        default_factory=list
    )

    attachments: list[AttachmentInfo] = Field(
        default_factory=list
    )

    authentication_results: list[str] = Field(
        default_factory=list
    )

    received_spf: list[str] = Field(
        default_factory=list
    )

    dkim_signatures: list[str] = Field(
        default_factory=list
    )


class Finding(BaseModel):
    type: str
    severity: str
    message: str
    evidence: dict[str, Any] = Field(
        default_factory=dict
    )


class HeaderEndpoint(BaseModel):
    email: str | None = None
    domain: str | None = None


class RelayHop(BaseModel):
    hop: int
    raw: str
    ips: list[str] = Field(
        default_factory=list
    )


class HeaderForensics(BaseModel):
    sender: HeaderEndpoint

    reply_to: HeaderEndpoint

    return_path: HeaderEndpoint

    message_id: str | None = None

    reply_to_mismatch: bool

    return_path_mismatch: bool

    reply_return_path_mismatch: bool

    received_header_count: int

    received_ips: list[str] = Field(
        default_factory=list
    )

    relay_chain: list[RelayHop] = Field(
        default_factory=list
    )

    findings: list[Finding] = Field(
        default_factory=list
    )

    finding_count: int


class EmailAnalysisResponse(BaseModel):
    success: bool
    filename: str
    email: EmailInfo
    header_forensics: HeaderForensics
    authentication: EmailAuthentication
    threat_analysis: ThreatAnalysis
    risk: RiskAssessment

