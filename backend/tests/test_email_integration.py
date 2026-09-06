from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)

SAMPLE_EMAILS = Path(__file__).parent / "sample_emails"


def upload_email(filename: str):
    file_path = SAMPLE_EMAILS / filename

    with open(file_path, "rb") as file:
        return client.post(
            "/api/email/upload",
            files={
                "file": (
                    filename,
                    file,
                    "message/rfc822",
                )
            },
        )


def test_legitimate_email_integration():
    response = upload_email("legitimate.eml")

    assert response.status_code == 200

    data = response.json()

    assert data["success"] is True
    assert data["filename"] == "legitimate.eml"

    assert data["threat_analysis"]["phishing"]["detected"] is False
    assert data["threat_analysis"]["bec"]["detected"] is False
    assert data["threat_analysis"]["impersonation"]["detected"] is False

    assert data["risk"]["level"] == "LOW"


def test_phishing_email_integration():
    response = upload_email("phishing.eml")

    assert response.status_code == 200

    data = response.json()

    assert data["success"] is True
    assert data["filename"] == "phishing.eml"

    assert data["threat_analysis"]["phishing"]["detected"] is True
    assert data["risk"]["level"] in ["HIGH", "CRITICAL"]

    assert data["forensic_graph"]["node_count"] > 0
    assert data["forensic_graph"]["edge_count"] > 0


def test_bec_email_integration():
    response = upload_email("bec.eml")

    assert response.status_code == 200

    data = response.json()

    assert data["success"] is True
    assert data["filename"] == "bec.eml"

    assert data["threat_analysis"]["bec"]["detected"] is True
    assert data["threat_analysis"]["impersonation"]["detected"] is True

    assert data["correlation"]["relationship_count"] > 0
    assert data["correlation"]["highest_severity"] == "HIGH"

    assert data["forensic_graph"]["node_count"] > 0
    assert data["forensic_graph"]["edge_count"] > 0