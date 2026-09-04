from typing import Any


def normalize_virustotal(
    result: dict[str, Any],
) -> dict[str, Any]:

    if result.get("status") != "OK":

        return {
            "status": result.get(
                "status",
                "UNKNOWN",
            ),
            "source": "VirusTotal",
            "verdict": "UNKNOWN",
        }

    attributes = (
        result.get("data", {})
        .get("data", {})
        .get("attributes", {})
    )

    stats = attributes.get(
        "last_analysis_stats",
        {},
    )

    malicious = int(
        stats.get("malicious", 0)
    )

    suspicious = int(
        stats.get("suspicious", 0)
    )

    harmless = int(
        stats.get("harmless", 0)
    )

    undetected = int(
        stats.get("undetected", 0)
    )

    if malicious > 0:
        verdict = "MALICIOUS"

    elif suspicious > 0:
        verdict = "SUSPICIOUS"

    elif harmless > 0:
        verdict = "LOW_RISK"

    else:
        verdict = "UNKNOWN"

    return {
        "status": "OK",
        "source": "VirusTotal",
        "verdict": verdict,
        "analysis_stats": {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
        },
        "reputation": attributes.get(
            "reputation"
        ),
    }


def normalize_abuseipdb(
    result: dict[str, Any],
) -> dict[str, Any]:

    if result.get("status") != "OK":

        return {
            "status": result.get(
                "status",
                "UNKNOWN",
            ),
            "source": "AbuseIPDB",
            "verdict": "UNKNOWN",
        }

    data = result.get(
        "data",
        {},
    )

    abuse_score = data.get(
        "abuse_confidence_score"
    )

    if abuse_score is None:
        verdict = "UNKNOWN"

    elif abuse_score >= 80:
        verdict = "MALICIOUS"

    elif abuse_score >= 30:
        verdict = "SUSPICIOUS"

    else:
        verdict = "LOW_RISK"

    return {
        "status": "OK",
        "source": "AbuseIPDB",
        "verdict": verdict,
        "abuse_confidence_score": abuse_score,
        "total_reports": data.get(
            "total_reports"
        ),
        "country_code": data.get(
            "country_code"
        ),
        "isp": data.get(
            "isp"
        ),
        "usage_type": data.get(
            "usage_type"
        ),
    }