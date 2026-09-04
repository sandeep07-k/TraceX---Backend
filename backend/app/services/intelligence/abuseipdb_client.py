from typing import Any

import httpx

from app.config.settings import settings


BASE_URL = "https://api.abuseipdb.com/api/v2"


def check_ip(
    ip: str,
) -> dict[str, Any]:

    if not settings.abuseipdb_api_key:
        return {
            "status": "NOT_CONFIGURED",
            "source": "AbuseIPDB",
            "message": (
                "AbuseIPDB API key is not configured."
            ),
        }

    headers = {
        "Key": settings.abuseipdb_api_key,
        "Accept": "application/json",
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
    }

    try:
        with httpx.Client(
            timeout=15.0
        ) as client:

            response = client.get(
                f"{BASE_URL}/check",
                headers=headers,
                params=params,
            )

        if response.status_code == 401:
            return {
                "status": "UNAUTHORIZED",
                "source": "AbuseIPDB",
                "message": "Invalid AbuseIPDB API key.",
            }

        if response.status_code == 429:
            return {
                "status": "RATE_LIMITED",
                "source": "AbuseIPDB",
                "message": (
                    "AbuseIPDB rate limit reached."
                ),
            }

        response.raise_for_status()

        payload = response.json()

        data = payload.get(
            "data",
            {},
        )

        return {
            "status": "OK",
            "source": "AbuseIPDB",
            "data": {
                "ip_address": data.get(
                    "ipAddress"
                ),
                "is_public": data.get(
                    "isPublic"
                ),
                "is_whitelisted": data.get(
                    "isWhitelisted"
                ),
                "country_code": data.get(
                    "countryCode"
                ),
                "usage_type": data.get(
                    "usageType"
                ),
                "isp": data.get("isp"),
                "domain": data.get("domain"),
                "abuse_confidence_score": data.get(
                    "abuseConfidenceScore"
                ),
                "total_reports": data.get(
                    "totalReports"
                ),
                "last_reported_at": data.get(
                    "lastReportedAt"
                ),
            },
        }

    except httpx.TimeoutException:
        return {
            "status": "TIMEOUT",
            "source": "AbuseIPDB",
            "message": "AbuseIPDB request timed out.",
        }

    except httpx.HTTPError as exc:
        return {
            "status": "LOOKUP_FAILED",
            "source": "AbuseIPDB",
            "message": str(exc),
        }