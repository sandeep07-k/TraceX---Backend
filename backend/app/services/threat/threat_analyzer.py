from typing import Any

from app.services.threat.bec_detector import (
    detect_bec,
)

from app.services.threat.impersonation_detector import (
    detect_impersonation,
)

from app.services.threat.phishing_detector import (
    detect_phishing,
)

from app.services.threat.url_analyzer import (
    analyze_urls,
)


def analyze_threats(
    email: dict[str, Any],
    header_forensics: dict[str, Any],
) -> dict[str, Any]:

    phishing = detect_phishing(
        email,
        header_forensics,
    )

    bec = detect_bec(
        email,
        header_forensics,
    )

    impersonation = (
        detect_impersonation(
            email,
            header_forensics,
        )
    )

    urls = analyze_urls(
        email.get(
            "urls",
            [],
        )
    )

    # Overall threat score.
    overall_score = max(
        phishing["score"],
        bec["score"],
        impersonation["score"],
    )

    if urls["suspicious_count"] > 0:
        overall_score = min(
            100,
            overall_score + 10,
        )

    if overall_score <= 30:
        level = "LOW"
    elif overall_score <= 60:
        level = "MEDIUM"
    elif overall_score <= 80:
        level = "HIGH"
    else:
        level = "CRITICAL"

    return {
        "overall_score": overall_score,
        "overall_level": level,

        "phishing": phishing,

        "bec": bec,

        "impersonation": impersonation,

        "urls": urls,
    }