from app.services.email.authentication_analyzer import (
    analyze_authentication,
)


def test_spf_dmarc_failure():

    email = {
        "authentication_results": [
            (
                "mx.example; "
                "spf=fail "
                "smtp.mailfrom=bad.example; "
                "dkim=none; "
                "dmarc=fail "
                "header.from=bad.example"
            )
        ],
        "received_spf": ["fail"],
        "dkim_signatures": [],
    }

    result = analyze_authentication(email)

    assert result["spf"]["status"] == "FAIL"
    assert result["dmarc"]["status"] == "FAIL"


def test_authentication_not_found():

    email = {
        "authentication_results": [],
        "received_spf": [],
        "dkim_signatures": [],
    }

    result = analyze_authentication(email)

    assert result["spf"]["status"] == "NOT_FOUND"
    assert result["dkim"]["status"] == "NOT_FOUND"
    assert result["dmarc"]["status"] == "NOT_FOUND"