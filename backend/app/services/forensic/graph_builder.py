from typing import Any


def make_node_id(
    node_type: str,
    value: str,
) -> str:
    """
    Generate a deterministic graph node ID.
    """

    normalized = value.strip().lower()

    safe_value = "".join(
        char
        if char.isalnum()
        else "_"
        for char in normalized
    )

    return f"{node_type.lower()}-{safe_value}"


def make_edge_id(
    source: str,
    target: str,
    relation: str,
) -> str:

    return (
        f"{source}"
        f"__{relation.lower()}"
        f"__{target}"
    )


def add_node(
    nodes: dict[str, dict[str, Any]],
    *,
    node_type: str,
    label: str,
    value: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> str:

    node_value = value or label

    node_id = make_node_id(
        node_type,
        node_value,
    )

    if node_id not in nodes:

        nodes[node_id] = {
            "id": node_id,
            "type": node_type,
            "label": label,
            "value": value,
            "metadata": metadata or {},
        }

    return node_id


def add_edge(
    edges: dict[str, dict[str, Any]],
    *,
    source: str,
    target: str,
    relation: str,
    metadata: dict[str, Any] | None = None,
) -> None:

    edge_id = make_edge_id(
        source,
        target,
        relation,
    )

    if edge_id not in edges:

        edges[edge_id] = {
            "id": edge_id,
            "source": source,
            "target": target,
            "relation": relation,
            "metadata": metadata or {},
        }


def build_forensic_graph(
    email: dict[str, Any],
    intelligence: dict[str, Any],
    relay_trace: dict[str, Any],
) -> dict[str, Any]:
    """
    Build a graph connecting email-related entities.
    """

    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[str, dict[str, Any]] = {}

    # ------------------------------------------------
    # Email node
    # ------------------------------------------------

    message_id = (
        email.get("message_id")
        or email.get("subject")
        or "unknown-email"
    )

    email_node = add_node(
        nodes,
        node_type="EMAIL",
        label="Email",
        value=message_id,
        metadata={
            "subject": email.get(
                "subject"
            ),
            "sender": email.get(
                "sender_email"
            ),
        },
    )

    # ------------------------------------------------
    # Sender domain
    # ------------------------------------------------

    sender_email = (
        email.get("sender_email")
        or ""
    )

    sender_domain = None

    if "@" in sender_email:
        sender_domain = (
            sender_email
            .rsplit("@", 1)[1]
            .lower()
        )

    if sender_domain:

        domain_node = add_node(
            nodes,
            node_type="DOMAIN",
            label=sender_domain,
            value=sender_domain,
            metadata={
                "source": "sender"
            },
        )

        add_edge(
            edges,
            source=email_node,
            target=domain_node,
            relation="SENT_FROM",
        )

    # ------------------------------------------------
    # Reply-To domain
    # ------------------------------------------------

    reply_to = (
        email.get("reply_to_email")
        or ""
    )

    if "@" in reply_to:

        reply_domain = (
            reply_to
            .rsplit("@", 1)[1]
            .lower()
        )

        reply_domain_node = add_node(
            nodes,
            node_type="DOMAIN",
            label=reply_domain,
            value=reply_domain,
            metadata={
                "source": "reply_to"
            },
        )

        add_edge(
            edges,
            source=email_node,
            target=reply_domain_node,
            relation="REPLY_TO",
        )

    # ------------------------------------------------
    # URLs
    # ------------------------------------------------

    urls = email.get(
        "urls",
        [],
    )

    for url in urls:

        url_node = add_node(
            nodes,
            node_type="URL",
            label=url,
            value=url,
            metadata={
                "source": "email_body"
            },
        )

        add_edge(
            edges,
            source=email_node,
            target=url_node,
            relation="CONTAINS_URL",
        )

    # ------------------------------------------------
    # Relay chain
    # ------------------------------------------------

    previous_host_node = None

    for hop in relay_trace.get(
        "relay_chain",
        [],
    ):

        from_host = hop.get(
            "from_host"
        )

        by_host = hop.get(
            "by_host"
        )

        current_node = None

        if from_host:

            current_node = add_node(
                nodes,
                node_type="MAIL_SERVER",
                label=from_host,
                value=from_host,
                metadata={
                    "hop": hop.get(
                        "hop"
                    )
                },
            )

        if by_host:

            by_node = add_node(
                nodes,
                node_type="MAIL_SERVER",
                label=by_host,
                value=by_host,
                metadata={
                    "hop": hop.get(
                        "hop"
                    )
                },
            )

            if current_node:

                add_edge(
                    edges,
                    source=current_node,
                    target=by_node,
                    relation="RELAY_TO",
                )

            current_node = by_node

        if previous_host_node and current_node:

            add_edge(
                edges,
                source=previous_host_node,
                target=current_node,
                relation="NEXT_HOP",
            )

        if current_node:
            previous_host_node = current_node

        # IP relationships
        for ip in hop.get(
            "ips",
            [],
        ):

            ip_node = add_node(
                nodes,
                node_type="IP",
                label=ip,
                value=ip,
                metadata={
                    "hop": hop.get(
                        "hop"
                    )
                },
            )

            if current_node:

                add_edge(
                    edges,
                    source=current_node,
                    target=ip_node,
                    relation="OBSERVED_IP",
                )

    # ------------------------------------------------
    # Intelligence relationships
    # ------------------------------------------------

    enrichment = intelligence.get(
        "enrichment",
        {}
    )

    for item in enrichment.get(
        "ips",
        [],
    ):

        ip = item.get("ip")

        if not ip:
            continue

        ip_node = add_node(
            nodes,
            node_type="IP",
            label=ip,
            value=ip,
        )

        for source_name in (
            "virustotal",
            "abuseipdb",
        ):

            result = item.get(
                source_name,
                {},
            )

            verdict = result.get(
                "verdict"
            )

            if verdict:

                intel_node = add_node(
                    nodes,
                    node_type="INTELLIGENCE",
                    label=(
                        f"{source_name.upper()}: "
                        f"{verdict}"
                    ),
                    value=(
                        f"{ip}:{source_name}"
                    ),
                    metadata=result,
                )

                add_edge(
                    edges,
                    source=ip_node,
                    target=intel_node,
                    relation="HAS_INTELLIGENCE",
                )

    return {
        "nodes": list(
            nodes.values()
        ),
        "edges": list(
            edges.values()
        ),
        "node_count": len(nodes),
        "edge_count": len(edges),
    }