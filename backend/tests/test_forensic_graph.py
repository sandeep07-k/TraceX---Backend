from app.services.forensic.graph_builder import (
    build_forensic_graph,
)


def test_forensic_graph():

    email = {
        "message_id": "<test@example.com>",
        "subject": "Urgent account verification",
        "sender_email": (
            "support@bad.example"
        ),
        "reply_to_email": (
            "verify@random.example"
        ),
        "urls": [
            "https://bit.ly/demo"
        ],
    }

    intelligence = {
        "enrichment": {
            "ips": [],
            "domains": [],
            "urls": [],
        }
    }

    relay_trace = {
        "relay_chain": [
            {
                "hop": 1,
                "from_host": "mail.bad.example",
                "by_host": "mx.example",
                "ips": [
                    "198.51.100.20"
                ],
            }
        ]
    }

    result = build_forensic_graph(
        email,
        intelligence,
        relay_trace,
    )

    node_types = {
        node["type"]
        for node in result["nodes"]
    }

    assert "EMAIL" in node_types
    assert "DOMAIN" in node_types
    assert "URL" in node_types
    assert "IP" in node_types

    assert result["node_count"] > 0
    assert result["edge_count"] > 0