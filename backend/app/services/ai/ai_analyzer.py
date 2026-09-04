from typing import Any

from app.services.ai.phishing_model import (
    predict_phishing,
)


def analyze_email_with_ai(
    email: dict[str, Any],
) -> dict[str, Any]:

    subject = (
        email.get("subject")
        or ""
    )

    text_body = (
        email.get("text_body")
        or ""
    )

    combined_text = (
        f"{subject}\n{text_body}"
    ).strip()

    prediction = predict_phishing(
        combined_text
    )

    patterns = []

    normalized = combined_text.lower()

    pattern_checks = {
        "urgency": [
            "urgent",
            "immediately",
            "act now",
            "within 24 hours",
            "final warning",
        ],
        "credential_harvesting": [
            "password",
            "otp",
            "login",
            "credentials",
            "verify your account",
        ],
        "financial_request": [
            "payment",
            "bank account",
            "credit card",
            "wire transfer",
            "invoice",
        ],
    }

    for category, keywords in pattern_checks.items():

        matched = [
            keyword
            for keyword in keywords
            if keyword in normalized
        ]

        if matched:

            patterns.append(
                {
                    "category": category,
                    "matches": matched,
                }
            )

    return {
        "model": (
            "TF-IDF + Logistic Regression"
        ),
        "prediction": prediction,
        "language_patterns": patterns,
    }