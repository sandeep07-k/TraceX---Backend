from typing import Any


def correlate_entities(
    intelligence: dict[str, Any],
    relay_trace: dict[str, Any],
    header_forensics: dict[str, Any],
) -> dict[str, Any]:
    """
    Correlate technical entities and identify
    useful investigation relationships.
    """

    relationships = []

    relay_ips = set(
        relay_trace.get(
            "relay_ips",
            [],
        )
    )

    intel_ips = {
        item.get("ip")
        for item in intelligence
        .get(
            "enrichment",
            {}
        )
        .get(
            "ips",
            []
        )
        if item.get("ip")
    }

    # -------------------------------------------
    # Relay IP + intelligence relationship
    # -------------------------------------------

    for ip in sorted(
        relay_ips.intersection(
            intel_ips
        )
    ):

        relationships.append(
            {
                "type": "RELAY_IP_INTELLIGENCE",
                "severity": "INFO",
                "message": (
                    "A relay IP was enriched "
                    "by threat-intelligence sources."
                ),
                "entities": [
                    {
                        "type": "IP",
                        "value": ip,
                    }
                ],
            }
        )

    # -------------------------------------------
    # Header anomalies
    # -------------------------------------------

    if header_forensics.get(
        "reply_to_mismatch",
        False,
    ):

        relationships.append(
            {
                "type": "SENDER_REPLY_RELATIONSHIP",
                "severity": "HIGH",
                "message": (
                    "Sender and Reply-To "
                    "domains differ."
                ),
                "entities": [
                    {
                        "type": "DOMAIN",
                        "value": (
                            header_forensics
                            .get("sender", {})
                            .get("domain")
                        ),
                    },
                    {
                        "type": "DOMAIN",
                        "value": (
                            header_forensics
                            .get("reply_to", {})
                            .get("domain")
                        ),
                    },
                ],
            }
        )

    if header_forensics.get(
        "return_path_mismatch",
        False,
    ):

        relationships.append(
            {
                "type": "SENDER_RETURN_PATH_RELATIONSHIP",
                "severity": "MEDIUM",
                "message": (
                    "Sender and Return-Path "
                    "domains differ."
                ),
            }
        )

    # -------------------------------------------
    # Summary
    # -------------------------------------------

    severity_order = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
        "INFO": 0,
    }

    highest_severity = "INFO"

    for relationship in relationships:

        current = relationship.get(
            "severity",
            "INFO",
        )

        if (
            severity_order[current]
            > severity_order[highest_severity]
        ):
            highest_severity = current

    return {
        "relationships": relationships,
        "relationship_count": len(
            relationships
        ),
        "highest_severity": highest_severity,
    }