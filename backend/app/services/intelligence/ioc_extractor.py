import re
from typing import Any
from urllib.parse import urlparse


IPV4_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)

MD5_PATTERN = re.compile(
    r"\b[a-fA-F0-9]{32}\b"
)

SHA1_PATTERN = re.compile(
    r"\b[a-fA-F0-9]{40}\b"
)

SHA256_PATTERN = re.compile(
    r"\b[a-fA-F0-9]{64}\b"
)

DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}\b"
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


def extract_ips(
    text: str,
) -> list[str]:
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


def extract_urls(
    text: str,
) -> list[str]:
    if not text:
        return []

    pattern = re.compile(
        r"https?://[^\s<>'\"]+",
        re.IGNORECASE,
    )

    return list(
        dict.fromkeys(
            pattern.findall(text)
        )
    )


def extract_domains(
    text: str,
) -> list[str]:
    if not text:
        return []

    candidates = DOMAIN_PATTERN.findall(text)

    excluded = {
        "example.com",
        "example.org",
        "example.net",
    }

    return list(
        dict.fromkeys(
            domain.lower()
            for domain in candidates
            if domain.lower() not in excluded
        )
    )


def extract_hashes(
    text: str,
) -> list[dict[str, str]]:
    if not text:
        return []

    indicators = []

    for value in MD5_PATTERN.findall(text):
        indicators.append(
            {
                "algorithm": "MD5",
                "value": value.lower(),
            }
        )

    for value in SHA1_PATTERN.findall(text):
        indicators.append(
            {
                "algorithm": "SHA1",
                "value": value.lower(),
            }
        )

    for value in SHA256_PATTERN.findall(text):
        indicators.append(
            {
                "algorithm": "SHA256",
                "value": value.lower(),
            }
        )

    # Remove duplicates
    unique = []
    seen = set()

    for item in indicators:
        key = (
            item["algorithm"],
            item["value"],
        )

        if key not in seen:
            seen.add(key)
            unique.append(item)

    return unique


def extract_url_domains(
    urls: list[str],
) -> list[str]:
    domains = []

    for url in urls:

        try:
            hostname = urlparse(
                url
            ).hostname

            if hostname:
                domains.append(
                    hostname.lower()
                )

        except Exception:
            continue

    return list(
        dict.fromkeys(domains)
    )


def build_ioc(
    *,
    ioc_type: str,
    value: str,
    source: str,
    confidence: float,
) -> dict[str, Any]:
    return {
        "type": ioc_type,
        "value": value,
        "source": source,
        "confidence": confidence,
    }


def extract_iocs(
    email: dict[str, Any],
) -> dict[str, Any]:
    """
    Extract and normalize Indicators of Compromise
    from parsed email information.
    """

    text_body = (
        email.get("text_body")
        or ""
    )

    html_body = (
        email.get("html_body")
        or ""
    )

    sender = (
        email.get("sender_email")
        or ""
    )

    reply_to = (
        email.get("reply_to_email")
        or ""
    )

    return_path = (
        email.get("return_path")
        or ""
    )

    received_headers = email.get(
        "received_headers",
        [],
    )

    header_text = "\n".join(
        received_headers
    )

    combined_text = "\n".join(
        [
            text_body,
            html_body,
            sender,
            reply_to,
            return_path,
            header_text,
        ]
    )

    # -----------------------------
    # IPs
    # -----------------------------

    ips = extract_ips(
        combined_text
    )

    ip_iocs = [
        build_ioc(
            ioc_type="IP",
            value=ip,
            source="email_content_or_header",
            confidence=0.80,
        )
        for ip in ips
    ]

    # -----------------------------
    # URLs
    # -----------------------------

    urls = extract_urls(
        combined_text
    )

    # Prefer parser-extracted URLs too.
    urls.extend(
        email.get("urls", [])
    )

    urls = list(
        dict.fromkeys(urls)
    )

    url_iocs = []

    for url in urls:
        url_iocs.append(
            build_ioc(
                ioc_type="URL",
                value=url,
                source="email_body",
                confidence=0.90,
            )
        )

    # -----------------------------
    # Domains
    # -----------------------------

    domains = extract_domains(
        combined_text
    )

    domains.extend(
        extract_url_domains(urls)
    )

    # Sender/reply domains
    for address in [
        sender,
        reply_to,
        return_path,
    ]:
        if "@" in address:
            domains.append(
                address.rsplit(
                    "@",
                    1,
                )[1].lower()
            )

    domains = list(
        dict.fromkeys(
            domains
        )
    )

    domain_iocs = [
        build_ioc(
            ioc_type="DOMAIN",
            value=domain,
            source="email",
            confidence=0.85,
        )
        for domain in domains
    ]

    # -----------------------------
    # Hashes
    # -----------------------------

    hashes = extract_hashes(
        combined_text
    )

    hash_iocs = [
        build_ioc(
            ioc_type="HASH",
            value=item["value"],
            source="email_content",
            confidence=0.95,
        )
        | {
            "algorithm": item["algorithm"]
        }
        for item in hashes
    ]

    all_iocs = (
        ip_iocs
        + domain_iocs
        + url_iocs
        + hash_iocs
    )

    return {
        "ips": ip_iocs,
        "domains": domain_iocs,
        "urls": url_iocs,
        "hashes": hash_iocs,
        "all": all_iocs,
        "total": len(all_iocs),
    }