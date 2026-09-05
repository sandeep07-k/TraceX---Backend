from pathlib import Path

from app.services.report.report_generator import (
    generate_report,
)


def test_generate_report(
    tmp_path,
):

    analysis = {
        "email": {
            "sender": "test@example.com",
            "sender_email": "test@example.com",
            "subject": "Test Email",
            "recipients": [
                "receiver@example.com"
            ],
            "date": "2026-09-05",
        },

        "risk": {
            "score": 85,
            "level": "CRITICAL",
            "explanations": [],
        },

        "authentication": {
            "spf": {
                "status": "FAIL",
                "source": "test",
            },
            "dkim": {
                "status": "NONE",
                "source": "test",
            },
            "dmarc": {
                "status": "FAIL",
                "source": "test",
            },
        },

        "header_forensics": {
            "reply_to_mismatch": True,
            "return_path_mismatch": True,
            "received_header_count": 1,
            "received_ips": [
                "198.51.100.20"
            ],
        },

        "threat_analysis": {
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
                "score": 70,
            },
        },

        "ai_analysis": {
            "model": "test-model",
            "prediction": {
                "label": "phishing",
                "phishing_probability": 0.9,
                "confidence": 0.9,
            },
        },

        "intelligence": {
            "iocs": {
                "all": [
                    {
                        "type": "IP",
                        "value": "198.51.100.20",
                        "source": "test",
                        "confidence": 0.8,
                    }
                ]
            }
        },

        "relay_trace": {
            "relay_chain": [],
        },

        "correlation": {
            "relationships": [],
        },
    }

    path = generate_report(
        case_id="TX-TEST-0001",
        analysis=analysis,
        filename="test.eml",
    )

    assert Path(path).exists()
    assert path.endswith(".pdf")