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
    ai_analysis = {
        "prediction": {
            "phishing_probability": 0.90,
            "legitimate_probability": 0.10,
            "confidence": 0.90,
        }
    }

    result = calculate_risk(
        headers,
        authentication,
        threat,
        ai_analysis,
    )

    assert result["score"] > 60
    assert result["level"] in {
        "HIGH",
        "CRITICAL",
    }
    assert result["components"]["ai_analysis"] == 9
    assert result["score"] > 0
    

    assert result["evidence_count"] > 0