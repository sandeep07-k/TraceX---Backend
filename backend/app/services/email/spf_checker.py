import re
from typing import Any


SPF_RESULT_PATTERN = re.compile(
    r"\b(spf)=(pass|fail|softfail|neutral|temperror|permerror|none)\b",
    re.IGNORECASE,
)


def normalize_spf_result(
    result: str | None,
) -> str:
    if not result:
        return "NOT_FOUND"

    value = result.lower().strip()

    allowed = {
        "pass",
        "fail",
        "softfail",
        "neutral",
        "temperror",
        "permerror",
        "none",
    }

    if value in allowed:
        return value.upper()

    return "UNKNOWN"


def check_spf(
    authentication_results: list[str],
    received_spf: list[str],
) -> dict[str, Any]:
    """
    Extract and normalize SPF evidence from email headers.

    This function does NOT perform live DNS SPF validation yet.
    """

    sources: list[dict[str, Any]] = []

    # Authentication-Results
    for header in authentication_results:
        match = SPF_RESULT_PATTERN.search(header)

        if match:
            result = normalize_spf_result(
                match.group(2)
            )

            sources.append(
                {
                    "source": "Authentication-Results",
                    "header": header,
                    "result": result,
                }
            )

    # Received-SPF
    for header in received_spf:
        lower_header = header.lower()

        match = re.search(
            r"^\s*(pass|fail|softfail|neutral|"
            r"temperror|permerror|none)\b",
            lower_header,
        )

        if match:
            result = normalize_spf_result(
                match.group(1)
            )

            sources.append(
                {
                    "source": "Received-SPF",
                    "header": header,
                    "result": result,
                }
            )

    if not sources:
        return {
            "status": "NOT_FOUND",
            "verified": False,
            "source": None,
            "evidence": [],
            "confidence": 0.0,
        }

    # Prefer Authentication-Results when both exist.
    preferred = next(
        (
            item
            for item in sources
            if item["source"] == "Authentication-Results"
        ),
        sources[0],
    )

    return {
        "status": preferred["result"],
        "verified": False,
        "source": preferred["source"],
        "evidence": sources,
        "confidence": 0.75,
    }