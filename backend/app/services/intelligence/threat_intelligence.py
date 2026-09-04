from typing import Any

from app.services.intelligence.abuseipdb_client import (
    check_ip,
)

from app.services.intelligence.domain_intelligence import (
    analyze_domains,
)

from app.services.intelligence.ip_intelligence import (
    analyze_ips,
)

from app.services.intelligence.virustotal_client import (
    get_domain_report,
    get_ip_report,
    get_url_report,
)

from app.services.intelligence.intelligence_normalizer import (
    normalize_abuseipdb,
    normalize_virustotal,
)


def enrich_iocs(
    iocs: dict[str, Any],
) -> dict[str, Any]:

    ip_results = []
    domain_results = []
    url_results = []

    # ---------------------------------
    # Basic local IP analysis
    # ---------------------------------

    ips = [
        item["value"]
        for item in iocs.get(
            "ips",
            [],
        )
    ]

    basic_ip_results = analyze_ips(
        ips
    )

    # ---------------------------------
    # External IP intelligence
    # ---------------------------------

    for ip in ips:

        vt_raw = get_ip_report(
            ip
        )

        abuse_raw = check_ip(
            ip
        )

        ip_results.append(
            {
                "ip": ip,
                "local": next(
                    (
                        item
                        for item in basic_ip_results
                        if item.get("ip") == ip
                    ),
                    {},
                ),
                "virustotal": (
                    normalize_virustotal(
                        vt_raw
                    )
                ),
                "abuseipdb": (
                    normalize_abuseipdb(
                        abuse_raw
                    )
                ),
            }
        )

    # ---------------------------------
    # Domain intelligence
    # ---------------------------------

    domains = [
        item["value"]
        for item in iocs.get(
            "domains",
            [],
        )
    ]

    basic_domain_results = analyze_domains(
        domains
    )

    for domain in domains:

        vt_raw = get_domain_report(
            domain
        )

        domain_results.append(
            {
                "domain": domain,
                "local": next(
                    (
                        item
                        for item in basic_domain_results
                        if item.get(
                            "domain"
                        ) == domain
                    ),
                    {},
                ),
                "virustotal": (
                    normalize_virustotal(
                        vt_raw
                    )
                ),
            }
        )

    # ---------------------------------
    # URL intelligence
    # ---------------------------------

    urls = [
        item["value"]
        for item in iocs.get(
            "urls",
            [],
        )
    ]

    for url in urls:

        vt_raw = get_url_report(
            url
        )

        url_results.append(
            {
                "url": url,
                "virustotal": (
                    normalize_virustotal(
                        vt_raw
                    )
                ),
            }
        )

    return {
        "ips": ip_results,
        "domains": domain_results,
        "urls": url_results,
    }