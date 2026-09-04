from typing import Any
from urllib.parse import quote

import httpx

from app.config.settings import settings


BASE_URL = "https://www.virustotal.com/api/v3"


def _headers() -> dict[str, str]:
    return {
        "x-apikey": settings.virustotal_api_key,
        "Accept": "application/json",
    }


def _not_configured() -> dict[str, Any]:
    return {
        "status": "NOT_CONFIGURED",
        "source": "VirusTotal",
        "message": "VirusTotal API key is not configured.",
    }


def _request(
    endpoint: str,
) -> dict[str, Any]:

    if not settings.virustotal_api_key:
        return _not_configured()

    try:
        with httpx.Client(
            timeout=15.0
        ) as client:

            response = client.get(
                f"{BASE_URL}{endpoint}",
                headers=_headers(),
            )

        if response.status_code == 404:
            return {
                "status": "NOT_FOUND",
                "source": "VirusTotal",
                "message": "No VirusTotal object was found.",
            }

        if response.status_code == 401:
            return {
                "status": "UNAUTHORIZED",
                "source": "VirusTotal",
                "message": "VirusTotal API key is invalid.",
            }

        if response.status_code == 429:
            return {
                "status": "RATE_LIMITED",
                "source": "VirusTotal",
                "message": "VirusTotal API rate limit reached.",
            }

        response.raise_for_status()

        return {
            "status": "OK",
            "source": "VirusTotal",
            "data": response.json(),
        }

    except httpx.TimeoutException:
        return {
            "status": "TIMEOUT",
            "source": "VirusTotal",
            "message": "VirusTotal request timed out.",
        }

    except httpx.HTTPError as exc:
        return {
            "status": "LOOKUP_FAILED",
            "source": "VirusTotal",
            "message": str(exc),
        }


def get_ip_report(
    ip: str,
) -> dict[str, Any]:

    encoded_ip = quote(
        ip,
        safe="",
    )

    return _request(
        f"/ip_addresses/{encoded_ip}"
    )


def get_domain_report(
    domain: str,
) -> dict[str, Any]:

    encoded_domain = quote(
        domain,
        safe="",
    )

    return _request(
        f"/domains/{encoded_domain}"
    )


def get_url_report(
    url: str,
) -> dict[str, Any]:

    # VirusTotal supports URL IDs based on
    # unpadded URL-safe Base64.
    import base64

    encoded = (
        base64.urlsafe_b64encode(
            url.encode("utf-8")
        )
        .decode("utf-8")
        .rstrip("=")
    )

    return _request(
        f"/urls/{encoded}"
    )