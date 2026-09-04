from typing import Any


SEVERITY_WEIGHT = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def severity_from_weight(weight: int) -> str:
    if weight >= 4:
        return "CRITICAL"

    if weight >= 3:
        return "HIGH"

    if weight >= 2:
        return "MEDIUM"

    return "LOW"


def build_explanations(
    evidence: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Convert risk evidence into human-readable explanations.
    """

    explanations = []

    for item in evidence:
        explanations.append(
            {
                "code": item["code"],
                "category": item["category"],
                "severity": item["severity"],
                "score_contribution": item[
                    "score_contribution"
                ],
                "message": item["message"],
            }
        )

    # Highest severity / contribution first.
    explanations.sort(
        key=lambda item: (
            SEVERITY_WEIGHT.get(
                item["severity"],
                0,
            ),
            item["score_contribution"],
        ),
        reverse=True,
    )

    return explanations