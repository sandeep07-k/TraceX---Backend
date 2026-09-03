from typing import Any


EXECUTIVE_PATTERNS = [
    "ceo",
    "director",
    "manager",
    "executive",
    "president",
    "founder",
]

PAYMENT_PATTERNS = [
    "make a payment",
    "process payment",
    "urgent payment",
    "wire transfer",
    "bank transfer",
    "invoice",
    "payment details",
    "account details",
]

SECRECY_PATTERNS = [
    "confidential",
    "keep this confidential",
    "do not tell",
    "don't tell",
    "keep this between us",
]


def find_matches(
    text: str,
    patterns: list[str],
) -> list[str]:
    normalized = text.lower()

    return [
        pattern
        for pattern in patterns
        if pattern.lower() in normalized
    ]


def detect_bec(
    email: dict[str, Any],
    header_forensics: dict[str, Any],
) -> dict[str, Any]:

    sender = (
        email.get("sender_email")
        or ""
    )

    subject = (
        email.get("subject")
        or ""
    )

    body = (
        email.get("text_body")
        or ""
    )

    text = (
        f"{sender}\n"
        f"{subject}\n"
        f"{body}"
    )

    executive_matches = find_matches(
        text,
        EXECUTIVE_PATTERNS,
    )

    payment_matches = find_matches(
        text,
        PAYMENT_PATTERNS,
    )

    secrecy_matches = find_matches(
        text,
        SECRECY_PATTERNS,
    )

    indicators = []
    evidence = []

    score = 0

    if executive_matches:
        indicators.append(
            "Executive-related identity"
        )

        evidence.append(
            {
                "type": "EXECUTIVE_PATTERN",
                "matches": executive_matches,
            }
        )

        score += 20

    if payment_matches:
        indicators.append(
            "Payment/financial request"
        )

        evidence.append(
            {
                "type": "PAYMENT_PATTERN",
                "matches": payment_matches,
            }
        )

        score += min(
            30,
            len(payment_matches) * 8,
        )

    if secrecy_matches:
        indicators.append(
            "Secrecy/confidentiality language"
        )

        evidence.append(
            {
                "type": "SECRECY_PATTERN",
                "matches": secrecy_matches,
            }
        )

        score += 15

    if header_forensics.get(
        "reply_to_mismatch",
        False,
    ):
        indicators.append(
            "Reply-To mismatch"
        )

        evidence.append(
            {
                "type": "REPLY_TO_MISMATCH",
                "severity": "HIGH",
            }
        )

        score += 25

    score = min(score, 100)

    return {
        "detected": score >= 40,
        "score": score,
        "indicators": indicators,
        "evidence": evidence,
        "confidence": round(
            min(score / 100 + 0.1, 0.95),
            2,
        ),
    }