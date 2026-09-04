import re
from datetime import datetime
from email.utils import parsedate_to_datetime
from typing import Any


IPV4_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)

FROM_PATTERN = re.compile(
    r"\bfrom\s+([^\s;]+)",
    re.IGNORECASE,
)

BY_PATTERN = re.compile(
    r"\bby\s+([^\s;]+)",
    re.IGNORECASE,
)


def is_valid_ipv4(ip: str) -> bool:
    parts = ip.split(".")

    if len(parts) != 4:
        return False

    try:
        return all(
            0 <= int(part) <= 255
            for part in parts
        )
    except ValueError:
        return False


def extract_ips(text: str) -> list[str]:
    if not text:
        return []

    candidates = IPV4_PATTERN.findall(text)

    return list(
        dict.fromkeys(
            ip
            for ip in candidates
            if is_valid_ipv4(ip)
        )
    )


def extract_hostname(
    pattern: re.Pattern[str],
    text: str,
) -> str | None:

    match = pattern.search(text)

    if not match:
        return None

    return match.group(1).strip()


def extract_timestamp(
    header: str,
) -> str | None:
    """
    Extract the date portion from a Received header
    where possible.
    """

    if ";" not in header:
        return None

    date_part = header.split(
        ";",
        1,
    )[1].strip()

    try:
        parsed = parsedate_to_datetime(
            date_part
        )

        if parsed:
            return parsed.isoformat()

    except (TypeError, ValueError, OverflowError):
        pass

    return None


def parse_received_header(
    header: str,
    hop: int,
) -> dict[str, Any]:

    normalized = " ".join(
        header.split()
    )

    from_host = extract_hostname(
        FROM_PATTERN,
        normalized,
    )

    by_host = extract_hostname(
        BY_PATTERN,
        normalized,
    )

    ips = extract_ips(
        normalized
    )

    timestamp = extract_timestamp(
        header
    )

    return {
        "hop": hop,
        "raw": header,
        "from_host": from_host,
        "by_host": by_host,
        "ips": ips,
        "timestamp": timestamp,
    }


def build_relay_chain(
    received_headers: list[str],
) -> list[dict[str, Any]]:

    chain = []

    for index, header in enumerate(
        received_headers,
        start=1,
    ):

        chain.append(
            parse_received_header(
                header,
                index,
            )
        )

    return chain


def collect_relay_ips(
    relay_chain: list[dict[str, Any]],
) -> list[str]:

    ips = []

    for hop in relay_chain:

        for ip in hop.get(
            "ips",
            [],
        ):
            if ip not in ips:
                ips.append(ip)

    return ips


def trace_relay_path(
    received_headers: list[str],
) -> dict[str, Any]:

    relay_chain = build_relay_chain(
        received_headers
    )

    relay_ips = collect_relay_ips(
        relay_chain
    )

    return {
        "header_count": len(
            received_headers
        ),
        "hop_count": len(
            relay_chain
        ),
        "relay_chain": relay_chain,
        "relay_ips": relay_ips,
        "trace_available": bool(
            relay_chain
        ),
    }