from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_upload_rejects_non_eml_file():
    response = client.post(
        "/api/email/upload",
        files={
            "file": (
                "test.txt",
                b"this is not an eml file",
                "text/plain",
            )
        },
    )

    assert response.status_code == 400


def test_upload_rejects_empty_file():
    response = client.post(
        "/api/email/upload",
        files={
            "file": (
                "empty.eml",
                b"",
                "message/rfc822",
            )
        },
    )

    assert response.status_code == 400


def test_upload_accepts_eml_file():
    eml_content = b"""From: sender@example.com
To: receiver@example.com
Subject: Test Email

This is a harmless test email.
"""

    response = client.post(
        "/api/email/upload",
        files={
            "file": (
                "test.eml",
                eml_content,
                "message/rfc822",
            )
        },
    )

    # Endpoint should accept the file.
    # 200 means complete analysis succeeded.
    assert response.status_code == 200