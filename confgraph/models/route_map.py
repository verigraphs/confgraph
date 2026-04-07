"""Route-map configuration models."""

from pydantic import BaseModel, Field
from confgraph.models.base import BaseConfigObject


class RouteMapMatch(BaseModel):
    """Route-map match clause."""

    match_type: str = Field(
        ...,
        description="Match type (e.g., 'ip address', 'ip address prefix-list', 'as-path', 'community', 'metric', 'tag')",
    )
    values: list[str] = Field(
        default_factory=list,
        description="Match values (can reference prefix-list, ACL, community-list, AS-path list)",
    )


class RouteMapSet(BaseModel):
    """Route-map set clause."""

    set_type: str = Field(
        ...,
        description="Set type (e.g., 'local-preference', 'metric', 'metric-type', 'community', 'as-path', 'next-hop', 'origin', 'weight', 'tag')",
    )
    values: list[str] = Field(
        default_factory=list,
        description="Set values",
    )


class RouteMapSequence(BaseModel):
    """Route-map sequence (entry)."""

    sequence: int = Field(..., description="Sequence number")
    action: str = Field(
        ..., description="Action ('permit' or 'deny')"
    )
    match_clauses: list[RouteMapMatch] = Field(
        default_factory=list,
        description="Match clauses (AND operation within sequence)",
    )
    set_clauses: list[RouteMapSet] = Field(
        default_factory=list,
        description="Set clauses",
    )
    continue_sequence: int | None = Field(
        default=None,
        description="Continue to sequence number after processing this entry",
    )
    description: str | None = Field(
        default=None,
        description="Route-map sequence description",
    )


class RouteMapConfig(BaseConfigObject):
    """Route-map configuration.

    Route-maps are used for:
    - BGP route filtering and attribute manipulation
    - OSPF redistribution filtering
    - PBR (Policy-Based Routing)
    - VRF import/export policies
    """

    name: str = Field(..., description="Route-map name")
    sequences: list[RouteMapSequence] = Field(
        default_factory=list,
        description="Route-map sequences (entries)",
    )
