import re
from typing import Any


URGENCY_PATTERNS = [
    "urgent",
    "immediately",
    "act now",
    "action required",
    "within 24 hours",
    "verify now",
    "verify immediately",
    "account suspended",
    "account will be suspended",
    "final warning",
]

CREDENTIAL_PATTERNS = [
    "password",
    "otp",
    "one time password",
    "login",
    "username",
    "verify your account",
    "confirm your identity",
    "security code",
]

FINANCIAL_PATTERNS = [
    "payment",
    "invoice",
    "bank account",
    "credit card",
    "debit card",
    "transaction",
    "refund",
    "wire transfer",
]


def count_matches(
    text: str,
    patterns: list[str],
) -> list[str]:
    matches = []

    normalized = text.lower()

    for pattern in patterns:
        if pattern.lower() in normalized:
            matches.append(pattern)

    return matches


def detect_phishing(
    email: dict[str, Any],
    header_forensics: dict[str, Any],
) -> dict[str, Any]:
    """
    Detect common phishing indicators.

    This is a baseline rule-based detector.
    ML/NLP will be added later.
    """

    subject = email.get("subject") or ""
    body = email.get("text_body") or ""

    text = f"{subject}\n{body}"

    indicators: list[str] = []
    evidence: list[dict[str, Any]] = []

    urgency_matches = count_matches(
        text,
        URGENCY_PATTERNS,
    )

    credential_matches = count_matches(
        text,
        CREDENTIAL_PATTERNS,
    )

    financial_matches = count_matches(
        text,
        FINANCIAL_PATTERNS,
    )

    # Urgency
    if urgency_matches:
        indicators.append("Urgency language")

        evidence.append(
            {
                "type": "URGENCY",
                "severity": "MEDIUM",
                "matches": urgency_matches,
            }
        )

    # Credentials
    if credential_matches:
        indicators.append("Credential-related language")

        evidence.append(
            {
                "type": "CREDENTIAL_REQUEST",
                "severity": "HIGH",
                "matches": credential_matches,
            }
        )

    # Financial
    if financial_matches:
        indicators.append("Financial-related language")

        evidence.append(
            {
                "type": "FINANCIAL_REQUEST",
                "severity": "HIGH",
                "matches": financial_matches,
            }
        )

    # URLs
    urls = email.get("urls", [])

    if urls:
        indicators.append("Contains external URL")

        evidence.append(
            {
                "type": "EXTERNAL_URL",
                "severity": "MEDIUM",
                "count": len(urls),
            }
        )

    # Header anomalies
    if header_forensics.get(
        "reply_to_mismatch",
        False,
    ):
        indicators.append(
            "Sender/Reply-To mismatch"
        )

        evidence.append(
            {
                "type": "REPLY_TO_MISMATCH",
                "severity": "HIGH",
            }
        )

    score = 0

    if urgency_matches:
        score += min(20, len(urgency_matches) * 5)

    if credential_matches:
        score += min(30, len(credential_matches) * 8)

    if financial_matches:
        score += min(20, len(financial_matches) * 5)

    if urls:
        score += 10

    if header_forensics.get(
        "reply_to_mismatch",
        False,
    ):
        score += 20

    score = min(score, 100)

    detected = score >= 40

    return {
        "detected": detected,
        "score": score,
        "indicators": indicators,
        "evidence": evidence,
        "confidence": round(
            min(score / 100 + 0.1, 0.95),
            2,
        ),
    }