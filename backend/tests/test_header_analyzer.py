from app.services.email.header_analyzer import (
    analyze_headers,
)


def test_reply_to_mismatch():

    email = {
        "sender_email": "support@example.com",
        "reply_to_email": "help@different.com",
        "return_path": "bounce@example.com",
        "message_id": "<test@example.com>",
        "received_headers": [],
    }

    result = analyze_headers(email)

    assert result["reply_to_mismatch"] is True

    assert any(
        finding["type"] == "REPLY_TO_MISMATCH"
        for finding in result["findings"]
    )


def test_return_path_mismatch():

    email = {
        "sender_email": "support@example.com",
        "reply_to_email": "support@example.com",
        "return_path": "bounce@different.com",
        "message_id": "<test@example.com>",
        "received_headers": [],
    }

    result = analyze_headers(email)

    assert result["return_path_mismatch"] is True


def test_received_ip_extraction():

    email = {
        "sender_email": "support@example.com",
        "reply_to_email": "support@example.com",
        "return_path": "bounce@example.com",
        "message_id": "<test@example.com>",
        "received_headers": [
            (
                "from mail.example "
                "(203.0.113.10) "
                "by mx.example"
            )
        ],
    }

    result = analyze_headers(email)

    assert "203.0.113.10" in result[
        "received_ips"
    ]


def test_no_mismatch():

    email = {
        "sender_email": "support@example.com",
        "reply_to_email": "support@example.com",
        "return_path": "bounce@example.com",
        "message_id": "<test@example.com>",
        "received_headers": [],
    }

    result = analyze_headers(email)

    assert result["reply_to_mismatch"] is False
    assert result["return_path_mismatch"] is False