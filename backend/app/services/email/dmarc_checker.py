import re
from typing import Any


DMARC_RESULT_PATTERN = re.compile(
    r"\bdmarc=(pass|fail|neutral|temperror|permerror|none)\b",
    re.IGNORECASE,
)

POLICY_PATTERN = re.compile(
    r"\bp=([a-z]+)\b",
    re.IGNORECASE,
)

HEADER_FROM_PATTERN = re.compile(
    r"\bheader\.from=([^;\s]+)",
    re.IGNORECASE,
)


def normalize_dmarc_result(
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


def check_dmarc(
    authentication_results: list[str],
) -> dict[str, Any]:
    """
    Extract DMARC result and available alignment/policy evidence.

    This phase reads existing authentication evidence.
    """

    evidence = []

    for header in authentication_results:

        match = DMARC_RESULT_PATTERN.search(
            header
        )

        if not match:
            continue

        result = normalize_dmarc_result(
            match.group(1)
        )

        policy_match = POLICY_PATTERN.search(
            header
        )

        header_from_match = (
            HEADER_FROM_PATTERN.search(header)
        )

        evidence.append(
            {
                "source": "Authentication-Results",
                "header": header,
                "result": result,
                "policy": (
                    policy_match.group(1)
                    if policy_match
                    else None
                ),
                "header_from": (
                    header_from_match.group(1)
                    if header_from_match
                    else None
                ),
            }
        )

    if not evidence:

        return {
            "status": "NOT_FOUND",
            "verified": False,
            "source": None,
            "evidence": [],
            "confidence": 0.0,
        }

    preferred = evidence[0]

    return {
        "status": preferred["result"],
        "verified": False,
        "source": preferred["source"],
        "evidence": evidence,
        "confidence": 0.75,
    }