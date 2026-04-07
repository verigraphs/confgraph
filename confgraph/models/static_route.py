"""Static route configuration models."""

from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from pydantic import BaseModel, Field
from confgraph.models.base import BaseConfigObject


class StaticRoute(BaseConfigObject):
    """Static route configuration.

    Represents a static route entry with destination, next-hop,
    and optional attributes like distance, tag, name, etc.
    """

    destination: IPv4Network | IPv6Network = Field(
        ...,
        description="Destination network prefix",
    )
    next_hop: IPv4Address | IPv6Address | str | None = Field(
        default=None,
        description="Next-hop IP address or interface name (e.g., 'Null0', 'GigabitEthernet0/0')",
    )
    next_hop_interface: str | None = Field(
        default=None,
        description="Outgoing interface for the route",
    )
    distance: int = Field(
        default=1,
        description="Administrative distance (default 1)",
    )
    tag: int | None = Field(
        default=None,
        description="Route tag for filtering/tracking",
    )
    name: str | None = Field(
        default=None,
        description="Route description/name",
    )
    permanent: bool = Field(
        default=False,
        description="Permanent route (stays even if interface goes down)",
    )
    track: int | None = Field(
        default=None,
        description="Object tracking number",
    )
    vrf: str | None = Field(
        default=None,
        description="VRF name (references VRFConfig)",
    )
