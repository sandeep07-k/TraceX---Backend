from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_rate_limit():
    responses = []

    for _ in range(35):
        response = client.post(
            "/api/email/upload",
            files={
                "file": (
                    "test.txt",
                    b"not an eml file",
                    "text/plain",
                )
            },
        )

        responses.append(response.status_code)

    assert 429 in responses
    