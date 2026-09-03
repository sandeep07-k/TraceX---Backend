from urllib.parse import urlparse
from typing import Any


SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
}


def analyze_url(
    url: str,
) -> dict[str, Any]:

    try:
        parsed = urlparse(url)

        domain = (
            parsed.hostname or ""
        ).lower()

        issues = []

        if parsed.scheme != "https":
            issues.append(
                "URL does not use HTTPS"
            )

        if domain in SHORTENERS:
            issues.append(
                "URL uses a shortening service"
            )

        if "@" in parsed.netloc:
            issues.append(
                "URL contains @ in network location"
            )

        return {
            "url": url,
            "domain": domain,
            "scheme": parsed.scheme,
            "issues": issues,
            "risk": (
                "HIGH"
                if len(issues) >= 2
                else "MEDIUM"
                if issues
                else "LOW"
            ),
        }

    except Exception:
        return {
            "url": url,
            "domain": None,
            "scheme": None,
            "issues": [
                "URL could not be parsed"
            ],
            "risk": "HIGH",
        }


def analyze_urls(
    urls: list[str],
) -> dict[str, Any]:

    results = [
        analyze_url(url)
        for url in urls
    ]

    suspicious = [
        result
        for result in results
        if result["risk"] in {
            "HIGH",
            "MEDIUM",
        }
    ]

    return {
        "count": len(results),
        "results": results,
        "suspicious_count": len(
            suspicious
        ),
    }