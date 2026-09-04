from typing import Any

from pydantic import BaseModel, Field


class GraphNode(BaseModel):
    id: str
    type: str
    label: str
    value: str | None = None

    metadata: dict[str, Any] = Field(
        default_factory=dict
    )


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    relation: str

    metadata: dict[str, Any] = Field(
        default_factory=dict
    )


class ForensicGraph(BaseModel):
    nodes: list[GraphNode] = Field(
        default_factory=list
    )

    edges: list[GraphEdge] = Field(
        default_factory=list
    )

    node_count: int
    edge_count: int