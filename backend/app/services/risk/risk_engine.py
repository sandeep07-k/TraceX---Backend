from typing import Any

from app.services.risk.explainability import (
    build_explanations,
)
from app.services.risk.scoring_rules import (
    clamp_score,
    risk_level,
)


def add_evidence(
    evidence: list[dict[str, Any]],
    *,
    code: str,
    category: str,
    severity: str,
    score_contribution: int,
    message: str,
) -> None:
    """
    Add one explainable risk evidence item.
    """

    evidence.append(
        {
            "code": code,
            "category": category,
            "severity": severity,
            "score_contribution": score_contribution,
            "message": message,
        }
    )


def calculate_header_score(
    header_forensics: dict[str, Any],
    evidence: list[dict[str, Any]],
) -> int:

    score = 0

    if header_forensics.get(
        "reply_to_mismatch",
        False,
    ):
        score += 10

        add_evidence(
            evidence,
            code="HDR_REPLY_TO_MISMATCH",
            category="HEADER_FORENSICS",
            severity="HIGH",
            score_contribution=10,
            message=(
                "The Reply-To domain differs "
                "from the sender domain."
            ),
        )

    if header_forensics.get(
        "return_path_mismatch",
        False,
    ):
        score += 5

        add_evidence(
            evidence,
            code="HDR_RETURN_PATH_MISMATCH",
            category="HEADER_FORENSICS",
            severity="MEDIUM",
            score_contribution=5,
            message=(
                "The Return-Path domain differs "
                "from the sender domain."
            ),
        )

    if header_forensics.get(
        "reply_return_path_mismatch",
        False,
    ):
        score += 5

        add_evidence(
            evidence,
            code="HDR_REPLY_RETURN_MISMATCH",
            category="HEADER_FORENSICS",
            severity="MEDIUM",
            score_contribution=5,
            message=(
                "Reply-To and Return-Path "
                "domains differ."
            ),
        )

    return min(score, 20)


def calculate_authentication_score(
    authentication: dict[str, Any],
    evidence: list[dict[str, Any]],
) -> int:

    score = 0

    spf = authentication.get("spf", {})
    dkim = authentication.get("dkim", {})
    dmarc = authentication.get("dmarc", {})

    if spf.get("status") == "FAIL":
        score += 10

        add_evidence(
            evidence,
            code="AUTH_SPF_FAIL",
            category="AUTHENTICATION",
            severity="HIGH",
            score_contribution=10,
            message="SPF authentication failed.",
        )

    if dkim.get("status") == "FAIL":
        score += 7

        add_evidence(
            evidence,
            code="AUTH_DKIM_FAIL",
            category="AUTHENTICATION",
            severity="HIGH",
            score_contribution=7,
            message="DKIM authentication failed.",
        )

    if dmarc.get("status") == "FAIL":
        score += 8

        add_evidence(
            evidence,
            code="AUTH_DMARC_FAIL",
            category="AUTHENTICATION",
            severity="HIGH",
            score_contribution=8,
            message="DMARC authentication failed.",
        )

    return min(score, 25)


def calculate_phishing_score(
    phishing: dict[str, Any],
    evidence: list[dict[str, Any]],
) -> int:

    score = min(
        int(phishing.get("score", 0) * 0.25),
        25,
    )

    if phishing.get("detected"):
        add_evidence(
            evidence,
            code="THREAT_PHISHING",
            category="PHISHING",
            severity=(
                "CRITICAL"
                if score >= 20
                else "HIGH"
                if score >= 12
                else "MEDIUM"
            ),
            score_contribution=score,
            message=(
                "The email contains multiple "
                "phishing indicators."
            ),
        )

    return score


def calculate_bec_score(
    bec: dict[str, Any],
    evidence: list[dict[str, Any]],
) -> int:

    score = min(
        int(bec.get("score", 0) * 0.20),
        20,
    )

    if bec.get("detected"):
        add_evidence(
            evidence,
            code="THREAT_BEC",
            category="BUSINESS_EMAIL_COMPROMISE",
            severity=(
                "CRITICAL"
                if score >= 16
                else "HIGH"
                if score >= 10
                else "MEDIUM"
            ),
            score_contribution=score,
            message=(
                "The email shows Business Email "
                "Compromise indicators."
            ),
        )

    return score


def calculate_impersonation_score(
    impersonation: dict[str, Any],
    evidence: list[dict[str, Any]],
) -> int:

    score = min(
        int(
            impersonation.get("score", 0)
            * 0.20
        ),
        20,
    )

    if impersonation.get("detected"):
        add_evidence(
            evidence,
            code="THREAT_IMPERSONATION",
            category="IMPERSONATION",
            severity=(
                "CRITICAL"
                if score >= 16
                else "HIGH"
                if score >= 10
                else "MEDIUM"
            ),
            score_contribution=score,
            message=(
                "Potential sender impersonation "
                "indicators were detected."
            ),
        )

    return score


def calculate_url_score(
    url_analysis: dict[str, Any],
    evidence: list[dict[str, Any]],
) -> int:

    suspicious_count = int(
        url_analysis.get(
            "suspicious_count",
            0,
        )
    )

    if suspicious_count == 0:
        return 0

    score = min(
        suspicious_count * 7,
        15,
    )

    add_evidence(
        evidence,
        code="URL_SUSPICIOUS",
        category="URL_ANALYSIS",
        severity=(
            "HIGH"
            if score >= 10
            else "MEDIUM"
        ),
        score_contribution=score,
        message=(
            f"{suspicious_count} suspicious "
            f"URL(s) were identified."
        ),
    )

    return score

def calculate_ai_score(
    ai_analysis: dict[str, Any],
    evidence: list[dict[str, Any]],
) -> int:
    """
    Convert AI phishing probability into a
    controlled risk contribution.

    AI is supporting evidence only.
    It does not determine the final risk level alone.
    """

    prediction = ai_analysis.get(
        "prediction",
        {},
    )

    phishing_probability = float(
        prediction.get(
            "phishing_probability",
            0.0,
        )
    )

    # AI maximum contribution = 10 points
    score = round(
        phishing_probability * 10
    )

    if phishing_probability >= 0.70:

        add_evidence(
            evidence,
            code="AI_PHISHING_SIGNAL",
            category="AI_ANALYSIS",
            severity="HIGH",
            score_contribution=score,
            message=(
                "AI language analysis detected "
                "a strong phishing signal."
            ),
        )

    elif phishing_probability >= 0.40:

        add_evidence(
            evidence,
            code="AI_SUSPICIOUS_SIGNAL",
            category="AI_ANALYSIS",
            severity="MEDIUM",
            score_contribution=score,
            message=(
                "AI language analysis detected "
                "a suspicious email-language pattern."
            ),
        )

    return min(score, 10)


def calculate_risk(
    header_forensics: dict[str, Any],
    authentication: dict[str, Any],
    threat_analysis: dict[str, Any],
    ai_analysis: dict[str, Any],
) -> dict[str, Any]:
    """
    Combine all available security findings
    into one explainable risk assessment.
    """

    evidence: list[dict[str, Any]] = []

    header_score = calculate_header_score(
        header_forensics,
        evidence,
    )

    authentication_score = (
        calculate_authentication_score(
            authentication,
            evidence,
        )
    )

    phishing_score = calculate_phishing_score(
        threat_analysis.get(
            "phishing",
            {},
        ),
        evidence,
    )

    bec_score = calculate_bec_score(
        threat_analysis.get(
            "bec",
            {},
        ),
        evidence,
    )

    impersonation_score = (
        calculate_impersonation_score(
            threat_analysis.get(
                "impersonation",
                {},
            ),
            evidence,
        )
    )

    url_score = calculate_url_score(
        threat_analysis.get(
            "urls",
            {},
        ),
        evidence,
    )
    ai_score = calculate_ai_score(
        ai_analysis,
        evidence,
    )
    

    total_score = clamp_score(
        header_score
        + authentication_score
        + phishing_score
        + bec_score
        + impersonation_score
        + url_score
        + ai_score
    )

    level = risk_level(
        total_score
    )

    explanations = build_explanations(
        evidence
    )

    

    return {
        "score": total_score,
        "level": level,
        "components": {
            "header_forensics": header_score,
            "authentication": authentication_score,
            "phishing": phishing_score,
            "bec": bec_score,
            "impersonation": impersonation_score,
            "url_analysis": url_score,
            "ai_analysis": ai_score,
        },
        "evidence": evidence,
        "explanations": explanations,
        "evidence_count": len(evidence),
    }