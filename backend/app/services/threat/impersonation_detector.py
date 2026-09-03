from typing import Any


def get_domain(
    email: str | None,
) -> str | None:

    if not email or "@" not in email:
        return None

    return (
        email.rsplit("@", 1)[1]
        .lower()
        .strip()
    )


def normalized_domain_similarity(
    first: str | None,
    second: str | None,
) -> bool:

    if not first or not second:
        return False

    first_clean = (
        first.lower()
        .replace("-", "")
        .replace("_", "")
    )

    second_clean = (
        second.lower()
        .replace("-", "")
        .replace("_", "")
    )

    return (
        first_clean != second_clean
        and (
            first_clean in second_clean
            or second_clean in first_clean
        )
    )


def detect_impersonation(
    email: dict[str, Any],
    header_forensics: dict[str, Any],
) -> dict[str, Any]:

    indicators = []
    evidence = []

    score = 0

    sender = email.get(
        "sender_email"
    )

    reply_to = email.get(
        "reply_to_email"
    )

    sender_domain = get_domain(
        sender
    )

    reply_domain = get_domain(
        reply_to
    )

    # Sender / Reply-To mismatch
    if header_forensics.get(
        "reply_to_mismatch",
        False,
    ):

        indicators.append(
            "Sender and Reply-To domains differ"
        )

        evidence.append(
            {
                "type": "DOMAIN_MISMATCH",
                "sender_domain": sender_domain,
                "reply_to_domain": reply_domain,
            }
        )

        score += 40

    # Approximate look-alike relationship
    if normalized_domain_similarity(
        sender_domain,
        reply_domain,
    ):

        indicators.append(
            "Potential look-alike domain"
        )

        evidence.append(
            {
                "type": "LOOKALIKE_DOMAIN",
                "sender_domain": sender_domain,
                "reply_to_domain": reply_domain,
            }
        )

        score += 30

    # Return-Path mismatch
    if header_forensics.get(
        "return_path_mismatch",
        False,
    ):

        indicators.append(
            "Return-Path domain differs"
        )

        evidence.append(
            {
                "type": "RETURN_PATH_MISMATCH",
            }
        )

        score += 20

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