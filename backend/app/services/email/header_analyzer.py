import re
from typing import Any
from email.utils import parseaddr


IPV4_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)

# Common form:
# from mail.example (203.0.113.10)
# from [203.0.113.10]
IP_WITH_PARENS_PATTERN = re.compile(
    r"\(([^\s()]+)\)"
)


def extract_email_address(value: str | None) -> str | None:
    """
    Extract only the email address from a header value.
    """
    if not value:
        return None

    address = parseaddr(value)[1]

    return address.lower().strip() or None


def extract_domain(email_address: str | None) -> str | None:
    """
    Extract domain from an email address.
    """
    if not email_address or "@" not in email_address:
        return None

    return email_address.rsplit("@", 1)[1].lower().strip()


def is_valid_ipv4(ip: str) -> bool:
    """
    Basic IPv4 validation.
    """
    parts = ip.split(".")

    if len(parts) != 4:
        return False

    try:
        return all(
            0 <= int(part) <= 255
            for part in parts
        )
    except ValueError:
        return False


def extract_ips_from_text(text: str) -> list[str]:
    """
    Extract valid IPv4 addresses from text.
    """
    if not text:
        return []

    candidates = IPV4_PATTERN.findall(text)

    return list(
        dict.fromkeys(
            ip for ip in candidates
            if is_valid_ipv4(ip)
        )
    )


def normalize_header_spaces(value: str | None) -> str:
    """
    Normalize whitespace inside a header.
    """
    if not value:
        return ""

    return " ".join(value.split())


def build_relay_chain(
    received_headers: list[str],
) -> list[dict[str, Any]]:
    """
    Convert Received headers into a structured relay chain.

    Note:
    Received headers are preserved in their original order.
    We do not assume every header is trustworthy.
    """
    chain: list[dict[str, Any]] = []

    for index, header in enumerate(received_headers, start=1):

        normalized = normalize_header_spaces(header)

        ips = extract_ips_from_text(normalized)

        chain.append(
            {
                "hop": index,
                "raw": header,
                "ips": ips,
            }
        )

    return chain


def compare_domains(
    first_domain: str | None,
    second_domain: str | None,
) -> bool:
    """
    Return True when both domains exist and differ.
    """
    if not first_domain or not second_domain:
        return False

    return first_domain != second_domain


def analyze_headers(email: dict[str, Any]) -> dict[str, Any]:
    """
    Perform basic forensic analysis of parsed email headers.

    This phase focuses on:
    - Sender / Reply-To mismatch
    - Sender / Return-Path mismatch
    - Received-header analysis
    - IP extraction
    - Basic header consistency findings
    """

    findings: list[dict[str, Any]] = []

    sender_email = email.get("sender_email")

    if not sender_email:
        sender_email = extract_email_address(
            email.get("sender")
        )

    reply_to_email = email.get("reply_to_email")

    if not reply_to_email:
        reply_to_email = extract_email_address(
            email.get("reply_to")
        )

    return_path = email.get("return_path")

    return_path_email = extract_email_address(
        return_path
    )

    sender_domain = extract_domain(
        sender_email
    )

    reply_to_domain = extract_domain(
        reply_to_email
    )

    return_path_domain = extract_domain(
        return_path_email
    )

    # -----------------------------------------
    # 1. Sender vs Reply-To
    # -----------------------------------------

    reply_to_mismatch = compare_domains(
        sender_domain,
        reply_to_domain,
    )

    if reply_to_mismatch:

        findings.append(
            {
                "type": "REPLY_TO_MISMATCH",
                "severity": "HIGH",
                "message": (
                    "Reply-To domain differs from "
                    "the sender domain."
                ),
                "evidence": {
                    "sender_domain": sender_domain,
                    "reply_to_domain": reply_to_domain,
                },
            }
        )

    # -----------------------------------------
    # 2. Sender vs Return-Path
    # -----------------------------------------

    return_path_mismatch = compare_domains(
        sender_domain,
        return_path_domain,
    )

    if return_path_mismatch:

        findings.append(
            {
                "type": "RETURN_PATH_MISMATCH",
                "severity": "MEDIUM",
                "message": (
                    "Return-Path domain differs "
                    "from the sender domain."
                ),
                "evidence": {
                    "sender_domain": sender_domain,
                    "return_path_domain": return_path_domain,
                },
            }
        )

    # -----------------------------------------
    # 3. Reply-To vs Return-Path
    # -----------------------------------------

    reply_return_mismatch = compare_domains(
        reply_to_domain,
        return_path_domain,
    )

    if reply_return_mismatch:

        findings.append(
            {
                "type": "REPLY_RETURN_PATH_MISMATCH",
                "severity": "MEDIUM",
                "message": (
                    "Reply-To and Return-Path "
                    "domains differ."
                ),
                "evidence": {
                    "reply_to_domain": reply_to_domain,
                    "return_path_domain": return_path_domain,
                },
            }
        )

    # -----------------------------------------
    # 4. Received header analysis
    # -----------------------------------------

    received_headers = email.get(
        "received_headers",
        [],
    )

    relay_chain = build_relay_chain(
        received_headers
    )

    all_received_ips: list[str] = []

    for hop in relay_chain:
        all_received_ips.extend(
            hop.get("ips", [])
        )

    all_received_ips = list(
        dict.fromkeys(all_received_ips)
    )

    # -----------------------------------------
    # 5. Missing Received headers
    # -----------------------------------------

    if not received_headers:

        findings.append(
            {
                "type": "NO_RECEIVED_HEADERS",
                "severity": "LOW",
                "message": (
                    "No Received headers were "
                    "available for relay analysis."
                ),
                "evidence": {},
            }
        )

    # -----------------------------------------
    # 6. Message-ID check
    # -----------------------------------------

    message_id = email.get("message_id")

    if not message_id:

        findings.append(
            {
                "type": "MISSING_MESSAGE_ID",
                "severity": "LOW",
                "message": (
                    "The email does not contain "
                    "a Message-ID header."
                ),
                "evidence": {},
            }
        )

    # -----------------------------------------
    # 7. Build result
    # -----------------------------------------

    return {
        "sender": {
            "email": sender_email,
            "domain": sender_domain,
        },

        "reply_to": {
            "email": reply_to_email,
            "domain": reply_to_domain,
        },

        "return_path": {
            "email": return_path_email,
            "domain": return_path_domain,
        },

        "message_id": message_id,

        "reply_to_mismatch": reply_to_mismatch,

        "return_path_mismatch": return_path_mismatch,

        "reply_return_path_mismatch": (
            reply_return_mismatch
        ),

        "received_header_count": len(
            received_headers
        ),

        "received_ips": all_received_ips,

        "relay_chain": relay_chain,

        "findings": findings,

        "finding_count": len(findings),
    }