from app.services.intelligence.ioc_extractor import (
    extract_iocs,
)


def test_ioc_extraction():

    email = {
        "sender_email": (
            "support@paypa1-security.example"
        ),
        "reply_to_email": (
            "verify@random-mail.example"
        ),
        "return_path": (
            "bounce@random-mail.example"
        ),
        "text_body": (
            "Visit https://bit.ly/demo-tracex "
            "from server 198.51.100.20"
        ),
        "html_body": "",
        "urls": [
            "https://bit.ly/demo-tracex"
        ],
        "received_headers": [
            (
                "from suspicious-host "
                "(198.51.100.20)"
            )
        ],
    }

    result = extract_iocs(
        email
    )

    ip_values = [
        item["value"]
        for item in result["ips"]
    ]

    url_values = [
        item["value"]
        for item in result["urls"]
    ]

    domain_values = [
        item["value"]
        for item in result["domains"]
    ]

    assert "198.51.100.20" in ip_values

    assert (
        "https://bit.ly/demo-tracex"
        in url_values
    )

    assert (
        "paypa1-security.example"
        in domain_values
    )


def test_empty_email():

    result = extract_iocs({})

    assert result["ips"] == []
    assert result["domains"] == []
    assert result["urls"] == []
    assert result["hashes"] == []
    assert result["total"] == 0