"""VXLAN / EVPN configuration models."""

from pydantic import BaseModel, Field
from confgraph.models.base import BaseConfigObject


class VXLANVniMapping(BaseModel):
    """VNI-to-VLAN or VNI-to-VRF mapping entry."""

    vni: int = Field(..., description="VXLAN Network Identifier")
    vlan: int | None = Field(default=None, description="VLAN ID mapped to this VNI (L2 VNI)")
    vrf: str | None = Field(default=None, description="VRF mapped to this VNI (L3 VNI)")
    mcast_group: str | None = Field(default=None, description="Multicast group for BUM traffic replication")
    suppress_arp: bool = Field(default=False, description="ARP suppression enabled on this VNI")


class VXLANConfig(BaseConfigObject):
    """VXLAN tunnel endpoint (VTEP) configuration (singleton per device).

    Covers the VTEP interface configuration (``interface Vxlan1`` on EOS,
    ``interface nve1`` on NX-OS) and global VXLAN settings.
    """

    source_interface: str | None = Field(
        default=None,
        description="Source interface for VTEP (typically a Loopback)",
    )
    udp_port: int = Field(
        default=4789,
        description="VXLAN UDP port (default 4789 per RFC 7348)",
    )
    vni_mappings: list[VXLANVniMapping] = Field(
        default_factory=list,
        description="VNI-to-VLAN and VNI-to-VRF mappings",
    )
    flood_vtep_list: list[str] = Field(
        default_factory=list,
        description="Static flood list of remote VTEP IPs (head-end replication)",
    )
    learn_restrict: bool = Field(
        default=False,
        description="Restrict MAC learning to control-plane only (EVPN)",
    )
    host_reachability: str | None = Field(
        default=None,
        description="Control-plane protocol for host reachability (e.g. 'bgp')",
    )
