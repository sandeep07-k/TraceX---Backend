from typing import Any

from pydantic import BaseModel, Field


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

    received_headers: list[str] = Field(default_factory=list)

    text_body: str = ""
    html_body: str = ""

    urls: list[str] = Field(default_factory=list)

    attachments: list[AttachmentInfo] = Field(
        default_factory=list
    )


class EmailAnalysisResponse(BaseModel):
    success: bool
    filename: str
    email: EmailInfo