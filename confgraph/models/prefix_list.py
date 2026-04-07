"""Prefix-list configuration models."""

from ipaddress import IPv4Network, IPv6Network
from pydantic import BaseModel, Field
from confgraph.models.base import BaseConfigObject


class PrefixListEntry(BaseModel):
    """Prefix-list entry (sequence)."""

    sequence: int = Field(..., description="Sequence number")
    action: str = Field(..., description="Action ('permit' or 'deny')")
    prefix: IPv4Network | IPv6Network = Field(
        ..., description="IP prefix to match"
    )
    ge: int | None = Field(
        default=None,
        description="Minimum prefix length to match (greater than or equal)",
    )
    le: int | None = Field(
        default=None,
        description="Maximum prefix length to match (less than or equal)",
    )
    description: str | None = Field(
        default=None,
        description="Entry description (NX-OS/IOS-XE support)",
    )


class PrefixListConfig(BaseConfigObject):
    """Prefix-list configuration.

    Prefix-lists are used to:
    - Filter BGP routes
    - Filter routes in route-maps
    - Match prefixes in route redistribution
    """

    name: str = Field(..., description="Prefix-list name")
    afi: str = Field(
        default="ipv4",
        description="Address family ('ipv4' or 'ipv6')",
    )
    sequences: list[PrefixListEntry] = Field(
        default_factory=list,
        description="Prefix-list entries",
    )
    description: str | None = Field(
        default=None,
        description="Prefix-list description (NX-OS/IOS-XE support)",
    )
