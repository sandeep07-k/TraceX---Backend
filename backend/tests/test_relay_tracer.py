from app.services.forensic.relay_tracer import (
    trace_relay_path,
)


def test_relay_path():

    headers = [
        (
            "from suspicious-mail.example "
            "(198.51.100.20) "
            "by relay.example with ESMTP; "
            "Tue, 01 Sep 2026 10:29:40 +0000"
        ),
        (
            "from mail-client.example "
            "(192.0.2.10) "
            "by suspicious-mail.example with ESMTP; "
            "Tue, 01 Sep 2026 10:29:20 +0000"
        ),
    ]

    result = trace_relay_path(
        headers
    )

    assert result["header_count"] == 2

    assert result["hop_count"] == 2

    assert (
        "198.51.100.20"
        in result["relay_ips"]
    )

    assert (
        "192.0.2.10"
        in result["relay_ips"]
    )


def test_empty_relay_trace():

    result = trace_relay_path([])

    assert result["header_count"] == 0

    assert result["hop_count"] == 0

    assert result["relay_ips"] == []

    assert result["trace_available"] is False