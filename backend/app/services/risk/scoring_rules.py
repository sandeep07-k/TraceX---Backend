from typing import Final


# Maximum contribution for each major evidence group.
HEADER_SCORE: Final[int] = 20
AUTHENTICATION_SCORE: Final[int] = 25
PHISHING_SCORE: Final[int] = 25
BEC_SCORE: Final[int] = 20
IMPERSONATION_SCORE: Final[int] = 20
URL_SCORE: Final[int] = 15


def clamp_score(score: int) -> int:
    """
    Keep score between 0 and 100.
    """
    return max(0, min(score, 100))


def risk_level(score: int) -> str:
    """
    Convert numeric score into a risk level.
    """
    if score <= 30:
        return "LOW"

    if score <= 60:
        return "MEDIUM"

    if score <= 80:
        return "HIGH"

    return "CRITICAL"