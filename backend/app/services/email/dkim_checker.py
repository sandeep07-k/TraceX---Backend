import re
from typing import Any


DKIM_RESULT_PATTERN = re.compile(
    r"\bdkim=(pass|fail|neutral|temperror|permerror|none)\b",
    re.IGNORECASE,
)


def normalize_dkim_result(
    result: str | None,
) -> str:
    if not result:
        return "NOT_FOUND"

    value = result.lower().strip()

    allowed = {
        "pass",
        "fail",
        "neutral",
        "temperror",
        "permerror",
        "none",
    }

    if value in allowed:
        return value.upper()

    return "UNKNOWN"


def extract_dkim_signature_info(
    dkim_signatures: list[str],
) -> list[dict[str, Any]]:
    """
    Extract basic DKIM signature metadata.

    This does NOT cryptographically verify the signature yet.
    """

    signatures = []

    for header in dkim_signatures:

        domain_match = re.search(
            r"(?:^|;\s*)d=([^;]+)",
            header,
            re.IGNORECASE,
        )

        selector_match = re.search(
            r"(?:^|;\s*)s=([^;]+)",
            header,
            re.IGNORECASE,
        )

        signatures.append(
            {
                "domain": (
                    domain_match.group(1).strip()
                    if domain_match
                    else None
                ),
                "selector": (
                    selector_match.group(1).strip()
                    if selector_match
                    else None
                ),
                "header": header,
            }
        )

    return signatures


def check_dkim(
    authentication_results: list[str],
    dkim_signatures: list[str],
) -> dict[str, Any]:
    """
    Extract DKIM authentication evidence.
    """

    evidence = []

    for header in authentication_results:

        match = DKIM_RESULT_PATTERN.search(
            header
        )

        if match:

            evidence.append(
                {
                    "source": "Authentication-Results",
                    "header": header,
                    "result": normalize_dkim_result(
                        match.group(1)
                    ),
                }
            )

    signature_info = extract_dkim_signature_info(
        dkim_signatures
    )

    if not evidence:

        return {
            "status": (
                "SIGNATURE_PRESENT"
                if dkim_signatures
                else "NOT_FOUND"
            ),
            "verified": False,
            "source": (
                "DKIM-Signature"
                if dkim_signatures
                else None
            ),
            "evidence": signature_info,
            "confidence": (
                0.50
                if dkim_signatures
                else 0.0
            ),
        }

    preferred = evidence[0]

    return {
        "status": preferred["result"],
        "verified": False,
        "source": preferred["source"],
        "evidence": evidence,
        "signatures": signature_info,
        "confidence": 0.75,
    }
    