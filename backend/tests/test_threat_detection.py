from app.services.threat.threat_analyzer import (
    analyze_threats,
)


def test_phishing_detection():

    email = {
        "sender_email": (
            "support@paypa1-security.example"
        ),
        "reply_to_email": (
            "verify@random-mail.example"
        ),
        "subject": (
            "URGENT: Verify your account immediately"
        ),
        "text_body": (
            "Your account will be suspended. "
            "Please verify your password and "
            "payment details immediately."
        ),
        "urls": [
            "https://bit.ly/demo-tracex"
        ],
    }

    headers = {
        "reply_to_mismatch": True,
        "return_path_mismatch": True,
    }

    result = analyze_threats(
        email,
        headers,
    )

    assert result["phishing"]["detected"] is True
    assert result["phishing"]["score"] > 0


def test_bec_detection():

    email = {
        "sender_email": (
            "ceo@company-example.com"
        ),
        "reply_to_email": (
            "payment@random-mail.example"
        ),
        "subject": "Urgent Payment Request",
        "text_body": (
            "I need an urgent payment processed "
            "today. Please make a bank transfer."
        ),
        "urls": [],
    }

    headers = {
        "reply_to_mismatch": True,
        "return_path_mismatch": False,
    }

    result = analyze_threats(
        email,
        headers,
    )

    assert result["bec"]["detected"] is True