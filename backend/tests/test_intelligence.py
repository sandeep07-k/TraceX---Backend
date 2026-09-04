from app.services.intelligence.intelligence_normalizer import (
    normalize_abuseipdb,
    normalize_virustotal,
)


def test_virustotal_malicious():

    result = normalize_virustotal(
        {
            "status": "OK",
            "data": {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 5,
                            "suspicious": 1,
                            "harmless": 20,
                            "undetected": 10,
                        },
                        "reputation": -25,
                    }
                }
            },
        }
    )

    assert result["verdict"] == "MALICIOUS"


def test_abuseipdb_suspicious():

    result = normalize_abuseipdb(
        {
            "status": "OK",
            "data": {
                "abuse_confidence_score": 50,
                "total_reports": 8,
                "country_code": "IN",
                "isp": "Example ISP",
                "usage_type": "Data Center/Web Hosting/Transit",
            },
        }
    )

    assert result["verdict"] == "SUSPICIOUS"


def test_unknown_result():

    result = normalize_virustotal(
        {
            "status": "NOT_FOUND",
        }
    )

    assert result["verdict"] == "UNKNOWN"