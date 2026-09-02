from email import policy
from email.message import Message
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from typing import Any

from app.services.email.url_extractor import extract_urls


def get_single_header(
    message: Message,
    header_name: str,
) -> str | None:
    """
    Safely extract a single email header.
    """

    value = message.get(header_name)

    if value is None:
        return None

    return str(value).strip()


def get_address_list(
    message: Message,
    header_name: str,
) -> list[str]:
    """
    Extract email addresses from headers such as To/CC/BCC.
    """

    values = message.get_all(header_name, [])

    if not values:
        return []

    addresses = getaddresses(
        [str(value) for value in values]
    )

    result = []

    for name, address in addresses:
        if address:
            if name:
                result.append(f"{name} <{address}>")
            else:
                result.append(address)

    return result


def extract_text_body(message: Message) -> str:
    """
    Extract text/plain body.
    """

    if message.is_multipart():

        for part in message.walk():
            if part.get_content_type() != "text/plain":
                continue

            disposition = str(
                part.get("Content-Disposition", "")
            ).lower()

            if "attachment" in disposition:
                continue

            try:
                return part.get_content()
            except Exception:
                payload = part.get_payload(decode=True)

                if payload:
                    charset = (
                        part.get_content_charset()
                        or "utf-8"
                    )

                    return payload.decode(
                        charset,
                        errors="replace",
                    )

        return ""

    if message.get_content_type() == "text/plain":

        try:
            return message.get_content()
        except Exception:
            payload = message.get_payload(decode=True)

            if payload:
                charset = (
                    message.get_content_charset()
                    or "utf-8"
                )

                return payload.decode(
                    charset,
                    errors="replace",
                )

    return ""


def extract_html_body(message: Message) -> str:
    """
    Extract text/html body.
    """

    if message.is_multipart():

        for part in message.walk():
            if part.get_content_type() != "text/html":
                continue

            disposition = str(
                part.get("Content-Disposition", "")
            ).lower()

            if "attachment" in disposition:
                continue

            try:
                return part.get_content()
            except Exception:
                payload = part.get_payload(decode=True)

                if payload:
                    charset = (
                        part.get_content_charset()
                        or "utf-8"
                    )

                    return payload.decode(
                        charset,
                        errors="replace",
                    )

        return ""

    if message.get_content_type() == "text/html":

        try:
            return message.get_content()
        except Exception:
            payload = message.get_payload(decode=True)

            if payload:
                charset = (
                    message.get_content_charset()
                    or "utf-8"
                )

                return payload.decode(
                    charset,
                    errors="replace",
                )

    return ""


def extract_received_headers(
    message: Message,
) -> list[str]:
    """
    Extract all Received headers.

    Order is intentionally preserved because these
    headers will later be used for relay-path analysis.
    """

    return [
        str(value).strip()
        for value in message.get_all("Received", [])
    ]


def extract_attachments(
    message: Message,
) -> list[dict[str, Any]]:
    """
    Extract basic attachment metadata.
    """

    attachments = []

    for part in message.walk():

        filename = part.get_filename()

        if not filename:
            continue

        payload = part.get_payload(decode=True)

        size = len(payload) if payload else 0

        attachments.append(
            {
                "filename": str(filename),
                "content_type": part.get_content_type(),
                "size": size,
            }
        )

    return attachments


def parse_eml(content: bytes) -> dict[str, Any]:
    """
    Parse raw .eml bytes into a structured dictionary.
    """

    if not content:
        raise ValueError(
            "The uploaded email file is empty."
        )

    try:
        message = BytesParser(
            policy=policy.default
        ).parsebytes(content)

    except Exception as exc:
        raise ValueError(
            f"Unable to parse .eml file: {exc}"
        ) from exc

    sender = get_single_header(
        message,
        "From",
    )

    reply_to = get_single_header(
        message,
        "Reply-To",
    )

    text_body = extract_text_body(message)

    html_body = extract_html_body(message)

    # Analyze both text and HTML content for URLs.
    combined_content = (
        f"{text_body}\n{html_body}"
    )

    return {
        "sender": sender,

        "sender_email": parseaddr(
            sender or ""
        )[1] or None,

        "recipients": get_address_list(
            message,
            "To",
        ),

        "cc": get_address_list(
            message,
            "Cc",
        ),

        "bcc": get_address_list(
            message,
            "Bcc",
        ),

        "subject": get_single_header(
            message,
            "Subject",
        ),

        "date": get_single_header(
            message,
            "Date",
        ),

        "reply_to": reply_to,

        "reply_to_email": parseaddr(
            reply_to or ""
        )[1] or None,

        "return_path": get_single_header(
            message,
            "Return-Path",
        ),

        "message_id": get_single_header(
            message,
            "Message-ID",
        ),

        "received_headers": extract_received_headers(
            message
        ),

        "text_body": text_body,

        "html_body": html_body,

        "urls": extract_urls(
            combined_content
        ),

        "attachments": extract_attachments(
            message
        ),
    }