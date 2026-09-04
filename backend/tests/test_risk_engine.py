from app.services.risk.risk_engine import (
    calculate_risk,
)


def test_high_risk_email():

    headers = {
        "reply_to_mismatch": True,
        "return_path_mismatch": True,
        "reply_return_path_mismatch": False,
    }

    authentication = {
        "spf": {
            "status": "FAIL",
        },
        "dkim": {
            "status": "NONE",
        },
        "dmarc": {
            "status": "FAIL",
        },
    }

    threat = {
        "phishing": {
            "detected": True,
            "score": 80,
        },
        "bec": {
            "detected": False,
            "score": 0,
        },
        "impersonation": {
            "detected": True,
            "score": 80,
        },
        "urls": {
            "suspicious_count": 1,
        },
    }

    result = calculate_risk(
        headers,
        authentication,
        threat,
    )

    assert result["score"] > 60
    assert result["level"] in {
        "HIGH",
        "CRITICAL",
    }

    assert result["evidence_count"] > 0