from typing import Any

from app.services.intelligence.domain_intelligence import (
    analyze_domains,
)

from app.services.intelligence.ip_intelligence import (
    analyze_ips,
)


def enrich_iocs(
    iocs: dict[str, Any],
) -> dict[str, Any]:
    """
    Perform local/basic IOC enrichment.

    External reputation providers will be plugged
    into this layer later.
    """

    ips = [
        item["value"]
        for item in iocs.get(
            "ips",
            [],
        )
    ]

    domains = [
        item["value"]
        for item in iocs.get(
            "domains",
            [],
        )
    ]

    ip_results = analyze_ips(
        ips
    )

    domain_results = analyze_domains(
        domains
    )

    suspicious_ips = [
        result
        for result in ip_results
        if result.get("risk")
        in {"HIGH", "MEDIUM"}
    ]

    suspicious_domains = [
        result
        for result in domain_results
        if result.get("risk")
        in {"HIGH", "MEDIUM"}
    ]

    return {
        "ips": ip_results,
        "domains": domain_results,
        "summary": {
            "ip_count": len(ip_results),
            "domain_count": len(domain_results),
            "suspicious_ip_count": len(
                suspicious_ips
            ),
            "suspicious_domain_count": len(
                suspicious_domains
            ),
        },
    }