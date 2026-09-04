from pathlib import Path

import joblib


BASE_DIR = Path(__file__).resolve().parents[3]

MODEL_PATH = (
    BASE_DIR
    / "ml"
    / "models"
    / "phishing_model.joblib"
)


_model = None


def load_model():

    global _model

    if _model is None:

        if not MODEL_PATH.exists():
            raise FileNotFoundError(
                f"ML model not found: {MODEL_PATH}"
            )

        _model = joblib.load(
            MODEL_PATH
        )

    return _model


def predict_phishing(
    text: str,
) -> dict:

    if not text.strip():

        return {
            "label": "unknown",
            "phishing_probability": 0.0,
            "legitimate_probability": 0.0,
            "confidence": 0.0,
        }

    model = load_model()

    probabilities = model.predict_proba(
        [text]
    )[0]

    classes = list(
        model.classes_
    )

    probability_map = {
        int(label): float(probability)
        for label, probability in zip(
            classes,
            probabilities,
        )
    }

    phishing_probability = (
        probability_map.get(1, 0.0)
    )

    legitimate_probability = (
        probability_map.get(0, 0.0)
    )

    label = (
        "phishing"
        if phishing_probability >= 0.5
        else "legitimate"
    )

    confidence = max(
        phishing_probability,
        legitimate_probability,
    )

    return {
        "label": label,
        "phishing_probability": round(
            phishing_probability,
            4,
        ),
        "legitimate_probability": round(
            legitimate_probability,
            4,
        ),
        "confidence": round(
            confidence,
            4,
        ),
    }