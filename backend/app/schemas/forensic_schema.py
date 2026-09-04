from pydantic import BaseModel, Field


class RelayHop(BaseModel):
    hop: int
    raw: str

    from_host: str | None = None
    by_host: str | None = None

    ips: list[str] = Field(
        default_factory=list
    )

    timestamp: str | None = None


class RelayTrace(BaseModel):
    header_count: int
    hop_count: int

    relay_chain: list[RelayHop] = Field(
        default_factory=list
    )

    relay_ips: list[str] = Field(
        default_factory=list
    )

    trace_available: bool  
