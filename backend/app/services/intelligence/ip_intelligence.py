from ipaddress import ip_address
from typing import Any


PRIVATE_RANGES = {
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
}


def analyze_ip(
    ip: str,
) -> dict[str, Any]:

    try:
        parsed = ip_address(ip)
    except ValueError:
        return {
            "ip": ip,
            "valid": False,
            "risk": "UNKNOWN",
            "reason": "Invalid IP address",
        }

    if parsed.is_private:
        return {
            "ip": ip,
            "valid": True,
            "type": "PRIVATE",
            "risk": "LOW",
            "reason": (
                "Private/reserved address; "
                "not suitable as public origin evidence."
            ),
        }

    if parsed.is_loopback:
        return {
            "ip": ip,
            "valid": True,
            "type": "LOOPBACK",
            "risk": "LOW",
            "reason": "Loopback address.",
        }

    if parsed.is_reserved:
        return {
            "ip": ip,
            "valid": True,
            "type": "RESERVED",
            "risk": "UNKNOWN",
            "reason": "Reserved address range.",
        }

    return {
        "ip": ip,
        "valid": True,
        "type": "PUBLIC",
        "risk": "UNKNOWN",
        "reason": (
            "Public IP detected. "
            "External reputation lookup required."
        ),
    }


def analyze_ips(
    ips: list[str],
) -> list[dict[str, Any]]:

    return [
        analyze_ip(ip)
        for ip in ips
    ]