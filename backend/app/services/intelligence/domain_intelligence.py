import re
from typing import Any


DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9-]{0,61}"
    r"[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}$"
)


def analyze_domain(
    domain: str,
) -> dict[str, Any]:

    normalized = domain.lower().strip()

    valid = bool(
        DOMAIN_PATTERN.match(
            normalized
        )
    )

    if not valid:
        return {
            "domain": domain,
            "valid": False,
            "risk": "UNKNOWN",
            "issues": [
                "Invalid domain format"
            ],
        }

    issues = []

    # Basic suspicious patterns.
    if "xn--" in normalized:
        issues.append(
            "Punycode domain detected"
        )

    if normalized.count("-") >= 3:
        issues.append(
            "Multiple hyphens detected"
        )

    digit_count = sum(
        char.isdigit()
        for char in normalized
    )

    if digit_count >= 3:
        issues.append(
            "Multiple numeric characters detected"
        )

    risk = (
        "MEDIUM"
        if issues
        else "UNKNOWN"
    )

    return {
        "domain": normalized,
        "valid": True,
        "risk": risk,
        "issues": issues,
    }


def analyze_domains(
    domains: list[str],
) -> list[dict[str, Any]]:

    return [
        analyze_domain(domain)
        for domain in domains
    ]