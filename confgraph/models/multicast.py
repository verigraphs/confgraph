"""Multicast configuration models (PIM, IGMP, MSDP)."""

from ipaddress import IPv4Address
from pydantic import BaseModel, Field
from confgraph.models.base import BaseConfigObject


class PIMRPAddress(BaseModel):
    """PIM rendezvous-point address entry."""

    rp_address: IPv4Address = Field(..., description="RP IP address")
    acl: str | None = Field(default=None, description="ACL defining groups served by this RP")
    group_range: str | None = Field(
        default=None,
        description=(
            "Group prefix served by this RP, when the device names the groups by PREFIX "
            "rather than by ACL. EOS emits `rp address 1.1.1.1 239.0.0.0/8`. A prefix is "
            "not an ACL name, and writing one into `acl` is the wrong-field read CCR-0030 "
            "is about — a consumer resolving `acl` against ACLConfig would dangle."
        ),
    )
    override: bool = Field(default=False, description="Override auto-RP/BSR selection")
    bidir: bool = Field(default=False, description="Bidirectional PIM")


class PIMAnycastRP(BaseModel):
    """PIM anycast-RP peer entry.

    NX-OS emits `ip pim anycast-rp <anycast-rp-address> <peer-rp-address>`, one line per
    peer in the anycast-RP set. The anycast address is a shared RP address advertised by
    every member; the peer address identifies one member router. A consumer needs both to
    tell that two RPs are one logical (anycast) RP.
    """

    anycast_address: IPv4Address = Field(..., description="Shared anycast-RP address")
    peer_address: IPv4Address = Field(..., description="Peer RP address in the anycast-RP set")


class PIMSPTThreshold(BaseModel):
    """PIM shortest-path-tree switchover threshold policy.

    NX-OS emits `ip pim spt-threshold [infinity|<kbps>] [group-list <name>]`. `infinity`
    keeps traffic on the shared (RP) tree and never switches to the source tree; a numeric
    value is a kbps rate. An optional group-list/route-map scopes the policy to some groups.
    """

    threshold: str = Field(..., description="'infinity' (stay on shared tree) or a kbps value")
    group_list: str | None = Field(
        default=None, description="group-list/route-map name scoping the threshold, if any"
    )


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
    pim_anycast_rp: list[PIMAnycastRP] = Field(
        default_factory=list, description="PIM anycast-RP peer sets (RP redundancy)"
    )
    pim_spt_threshold: list[PIMSPTThreshold] = Field(
        default_factory=list, description="PIM SPT-switchover threshold policies"
    )
    pim_autorp: bool = Field(default=False, description="Auto-RP enabled")
    pim_bsr_candidate: str | None = Field(default=None, description="BSR candidate interface/priority")
    pim_rp_candidate: str | None = Field(default=None, description="RP candidate interface/group ACL")
    msdp_peers: list[MSDPPeer] = Field(default_factory=list, description="MSDP peers")
    msdp_originator_id: str | None = Field(default=None, description="MSDP originator-id interface")
    vrf: str | None = Field(default=None, description="VRF context (None = global)")

    class Config:
        use_enum_values = True
