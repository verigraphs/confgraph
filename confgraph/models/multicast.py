"""Multicast configuration models (PIM, IGMP, MSDP)."""

from ipaddress import IPv4Address
from pydantic import BaseModel, Field
from confgraph.models.base import BaseConfigObject


class PIMRPAddress(BaseModel):
    """PIM rendezvous-point address entry."""

    rp_address: IPv4Address = Field(..., description="RP IP address")
    acl: str | None = Field(default=None, description="ACL defining groups served by this RP")
    override: bool = Field(default=False, description="Override auto-RP/BSR selection")
    bidir: bool = Field(default=False, description="Bidirectional PIM")


class MSDPPeer(BaseModel):
    """MSDP peer configuration."""

    peer_address: IPv4Address = Field(..., description="Peer IP address")
    connect_source: str | None = Field(default=None, description="Connect source interface")
    remote_as: int | None = Field(default=None, description="Remote AS number")
    description: str | None = Field(default=None, description="Peer description")
    mesh_group: str | None = Field(default=None, description="MSDP mesh group name")
    sa_filter_in: str | None = Field(default=None, description="SA inbound filter (ACL or route-map)")
    sa_filter_out: str | None = Field(default=None, description="SA outbound filter (ACL or route-map)")


class MulticastConfig(BaseConfigObject):
    """IP multicast configuration (singleton per device)."""

    multicast_routing_enabled: bool = Field(default=False, description="IP multicast routing enabled")
    multicast_routing_distributed: bool = Field(default=False, description="Distributed multicast routing")
    multicast_routing_vrfs: list[str] = Field(default_factory=list, description="VRFs with multicast routing enabled")
    pim_rp_addresses: list[PIMRPAddress] = Field(default_factory=list, description="Static PIM RP addresses")
    pim_ssm_range: str | None = Field(default=None, description="SSM range ACL name")
    pim_autorp: bool = Field(default=False, description="Auto-RP enabled")
    pim_bsr_candidate: str | None = Field(default=None, description="BSR candidate interface/priority")
    pim_rp_candidate: str | None = Field(default=None, description="RP candidate interface/group ACL")
    msdp_peers: list[MSDPPeer] = Field(default_factory=list, description="MSDP peers")
    msdp_originator_id: str | None = Field(default=None, description="MSDP originator-id interface")
    vrf: str | None = Field(default=None, description="VRF context (None = global)")

    class Config:
        use_enum_values = True
