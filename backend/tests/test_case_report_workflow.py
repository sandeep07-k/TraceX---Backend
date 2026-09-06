from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)

SAMPLE_EMAILS = Path(__file__).parent / "sample_emails"


def test_email_to_case_to_report_workflow():
    file_path = SAMPLE_EMAILS / "phishing.eml"

    with open(file_path, "rb") as file:
        upload_response = client.post(
            "/api/email/upload",
            files={
                "file": (
                    "phishing.eml",
                    file,
                    "message/rfc822",
                )
            },
        )

    assert upload_response.status_code == 200

    upload_data = upload_response.json()

    assert upload_data["success"] is True
    assert "case_id" in upload_data

    case_id = upload_data["case_id"]

    # -------------------------------------------------
    # FETCH CASE
    # -------------------------------------------------

    case_response = client.get(
        f"/api/cases/{case_id}"
    )

    assert case_response.status_code == 200

    case_data = case_response.json()

    assert case_data["case_id"] == case_id
    assert "analysis" in case_data

    analysis = case_data["analysis"]

    assert analysis["source_filename"] == "phishing.eml"
    assert "risk" in analysis
    assert "threat_analysis" in analysis
    assert "ai_analysis" in analysis

    # -------------------------------------------------
    # GENERATE REPORT
    # -------------------------------------------------

    report_response = client.post(
        f"/api/reports/{case_id}"
    )

    assert report_response.status_code == 200

    report_data = report_response.json()

    assert report_data["success"] is True
    assert report_data["case_id"] == case_id
    assert report_data["filename"] == "phishing.eml"

    assert "report_path" in report_data
    assert report_data["report_path"]