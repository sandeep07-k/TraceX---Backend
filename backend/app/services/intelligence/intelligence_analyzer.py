from typing import Any

from app.services.intelligence.ioc_extractor import (
    extract_iocs,
)

from app.services.intelligence.threat_intelligence import (
    enrich_iocs,
)


def analyze_intelligence(
    email: dict[str, Any],
) -> dict[str, Any]:

    iocs = extract_iocs(
        email
    )

    enrichment = enrich_iocs(
        iocs
    )

    return {
        "iocs": iocs,
        "enrichment": enrichment,
    }