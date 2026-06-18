"""VPC (Virtual Port-Channel) / MLAG configuration models."""

from ipaddress import IPv4Address
from pydantic import Field
from confgraph.models.base import BaseConfigObject


class VPCConfig(BaseConfigObject):
    """VPC domain configuration (singleton per device).

    Covers NX-OS VPC (``vpc domain``) and conceptually Arista MLAG.
    Per-interface ``vpc <id>`` membership is on InterfaceConfig.vpc_id.
    """

    domain_id: int | str = Field(..., description="VPC/MLAG domain ID")
    role_priority: int | None = Field(
        default=None,
        description="VPC role priority (lower = primary)",
    )
    system_priority: int | None = Field(
        default=None,
        description="VPC system priority for LACP",
    )
    peer_keepalive_destination: IPv4Address | None = Field(
        default=None,
        description="Peer-keepalive destination IP",
    )
    peer_keepalive_source: IPv4Address | None = Field(
        default=None,
        description="Peer-keepalive source IP",
    )
    peer_keepalive_vrf: str | None = Field(
        default=None,
        description="VRF for peer-keepalive (e.g. 'management')",
    )
    peer_link: str | None = Field(
        default=None,
        description="Peer-link interface (typically a port-channel)",
    )
    delay_restore: int | None = Field(
        default=None,
        description="Delay restore timer (seconds)",
    )
    auto_recovery: bool = Field(
        default=False,
        description="Auto-recovery enabled after peer failure",
    )
