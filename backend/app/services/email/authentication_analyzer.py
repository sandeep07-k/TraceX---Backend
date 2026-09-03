from typing import Any

from app.services.email.dkim_checker import (
    check_dkim,
)
from app.services.email.dmarc_checker import (
    check_dmarc,
)
from app.services.email.spf_checker import (
    check_spf,
)


def build_authentication_findings(
    spf: dict[str, Any],
    dkim: dict[str, Any],
    dmarc: dict[str, Any],
) -> list[dict[str, Any]]:

    findings = []

    if spf["status"] in {
        "FAIL",
        "SOFTFAIL",
        "PERMERROR",
        "TEMPERROR",
    }:
        findings.append(
            {
                "type": "SPF_ANOMALY",
                "severity": "HIGH"
                if spf["status"] == "FAIL"
                else "MEDIUM",
                "message": (
                    f"SPF result: {spf['status']}"
                ),
                "evidence": spf.get(
                    "evidence",
                    [],
                ),
            }
        )

    if dkim["status"] in {
        "FAIL",
        "PERMERROR",
        "TEMPERROR",
    }:
        findings.append(
            {
                "type": "DKIM_ANOMALY",
                "severity": "HIGH"
                if dkim["status"] == "FAIL"
                else "MEDIUM",
                "message": (
                    f"DKIM result: {dkim['status']}"
                ),
                "evidence": dkim.get(
                    "evidence",
                    [],
                ),
            }
        )

    if dmarc["status"] in {
        "FAIL",
        "PERMERROR",
        "TEMPERROR",
    }:
        findings.append(
            {
                "type": "DMARC_ANOMALY",
                "severity": "HIGH"
                if dmarc["status"] == "FAIL"
                else "MEDIUM",
                "message": (
                    f"DMARC result: {dmarc['status']}"
                ),
                "evidence": dmarc.get(
                    "evidence",
                    [],
                ),
            }
        )

    return findings


def analyze_authentication(
    email: dict[str, Any],
) -> dict[str, Any]:

    authentication_results = email.get(
        "authentication_results",
        [],
    )

    received_spf = email.get(
        "received_spf",
        [],
    )

    dkim_signatures = email.get(
        "dkim_signatures",
        [],
    )

    spf = check_spf(
        authentication_results,
        received_spf,
    )

    dkim = check_dkim(
        authentication_results,
        dkim_signatures,
    )

    dmarc = check_dmarc(
        authentication_results,
    )

    findings = build_authentication_findings(
        spf,
        dkim,
        dmarc,
    )

    return {
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "findings": findings,
    }