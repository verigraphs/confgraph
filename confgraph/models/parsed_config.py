"""Parsed configuration container model."""

from pydantic import BaseModel, Field
from confgraph.models.vrf import VRFConfig
from confgraph.models.interface import InterfaceConfig
from confgraph.models.bgp import BGPConfig
from confgraph.models.ospf import OSPFConfig
from confgraph.models.isis import ISISConfig
from confgraph.models.route_map import RouteMapConfig
from confgraph.models.prefix_list import PrefixListConfig
from confgraph.models.static_route import StaticRoute
from confgraph.models.acl import ACLConfig
from confgraph.models.community_list import CommunityListConfig, ASPathListConfig
from confgraph.models.base import OSType, UnrecognizedBlock
from confgraph.models.eigrp import EIGRPConfig
from confgraph.models.rip import RIPConfig
from confgraph.models.ntp import NTPConfig
from confgraph.models.snmp import SNMPConfig
from confgraph.models.logging_config import SyslogConfig
from confgraph.models.banner import BannerConfig
from confgraph.models.line import LineConfig
from confgraph.models.qos import ClassMapConfig, PolicyMapConfig
from confgraph.models.nat import NATConfig
from confgraph.models.crypto import CryptoConfig
from confgraph.models.bfd import BFDConfig
from confgraph.models.ipsla import IPSLAOperation
from confgraph.models.eem import EEMApplet
from confgraph.models.object_tracking import ObjectTrack
from confgraph.models.multicast import MulticastConfig
from confgraph.models.panos_zone import PANOSZoneConfig


class ParsedConfig(BaseModel):
    """Container for all parsed configuration objects.

    This is the top-level structure returned by parsers,
    containing all protocol/service configurations extracted
    from a device configuration file.
    """

    source_os: OSType = Field(
        ...,
        description="Source operating system type",
    )
    hostname: str | None = Field(
        default=None,
        description="Device hostname",
    )
    vrfs: list[VRFConfig] = Field(
        default_factory=list,
        description="VRF configurations",
    )
    interfaces: list[InterfaceConfig] = Field(
        default_factory=list,
        description="Interface configurations",
    )
    bgp_instances: list[BGPConfig] = Field(
        default_factory=list,
        description="BGP process configurations (global + per-VRF)",
    )
    ospf_instances: list[OSPFConfig] = Field(
        default_factory=list,
        description="OSPF process configurations (global + per-VRF)",
    )
    isis_instances: list[ISISConfig] = Field(
        default_factory=list,
        description="IS-IS process configurations",
    )
    route_maps: list[RouteMapConfig] = Field(
        default_factory=list,
        description="Route-map configurations",
    )
    prefix_lists: list[PrefixListConfig] = Field(
        default_factory=list,
        description="Prefix-list configurations",
    )
    static_routes: list[StaticRoute] = Field(
        default_factory=list,
        description="Static route configurations",
    )
    acls: list[ACLConfig] = Field(
        default_factory=list,
        description="Access control lists",
    )
    community_lists: list[CommunityListConfig] = Field(
        default_factory=list,
        description="BGP community lists",
    )
    as_path_lists: list[ASPathListConfig] = Field(
        default_factory=list,
        description="BGP AS-path access lists",
    )
    eigrp_instances: list[EIGRPConfig] = Field(
        default_factory=list,
        description="EIGRP process configurations",
    )
    rip_instances: list[RIPConfig] = Field(
        default_factory=list,
        description="RIP process configurations",
    )
    ntp: NTPConfig | None = Field(
        default=None,
        description="NTP configuration",
    )
    snmp: SNMPConfig | None = Field(
        default=None,
        description="SNMP configuration",
    )
    syslog: SyslogConfig | None = Field(
        default=None,
        description="Syslog/logging configuration",
    )
    banners: BannerConfig | None = Field(
        default=None,
        description="Device banner configuration",
    )
    lines: list[LineConfig] = Field(
        default_factory=list,
        description="Console, VTY, and aux line configurations",
    )
    class_maps: list[ClassMapConfig] = Field(
        default_factory=list,
        description="QoS class-map configurations",
    )
    policy_maps: list[PolicyMapConfig] = Field(
        default_factory=list,
        description="QoS policy-map configurations",
    )
    nat: NATConfig | None = Field(
        default=None,
        description="NAT configuration",
    )
    crypto: CryptoConfig | None = Field(
        default=None,
        description="Crypto/IPsec configuration",
    )
    bfd: BFDConfig | None = Field(
        default=None,
        description="BFD global configuration",
    )
    ip_sla_operations: list[IPSLAOperation] = Field(
        default_factory=list,
        description="IP SLA operation configurations",
    )
    eem_applets: list[EEMApplet] = Field(
        default_factory=list,
        description="EEM applet configurations",
    )
    object_tracks: list[ObjectTrack] = Field(
        default_factory=list,
        description="Object tracking configurations",
    )
    multicast: MulticastConfig | None = Field(
        default=None,
        description="IP multicast configuration",
    )
    zones: list[PANOSZoneConfig] = Field(
        default_factory=list,
        description="PAN-OS security zone configurations",
    )
    raw_config: str = Field(
        default="",
        description="Original raw configuration text",
    )
    unrecognized_blocks: list[UnrecognizedBlock] = Field(
        default_factory=list,
        description="Top-level config blocks not handled by any parser method",
    )

    class Config:
        """Pydantic model configuration."""
        use_enum_values = True

    def get_interface_by_name(self, name: str) -> InterfaceConfig | None:
        """Get interface by name."""
        for interface in self.interfaces:
            if interface.name == name:
                return interface
        return None

    def get_vrf_by_name(self, name: str) -> VRFConfig | None:
        """Get VRF by name."""
        for vrf in self.vrfs:
            if vrf.name == name:
                return vrf
        return None

    def get_route_map_by_name(self, name: str) -> RouteMapConfig | None:
        """Get route-map by name."""
        for route_map in self.route_maps:
            if route_map.name == name:
                return route_map
        return None

    def get_prefix_list_by_name(self, name: str) -> PrefixListConfig | None:
        """Get prefix-list by name."""
        for prefix_list in self.prefix_lists:
            if prefix_list.name == name:
                return prefix_list
        return None

    def get_bgp_by_asn(self, asn: int, vrf: str | None = None) -> BGPConfig | None:
        """Get BGP instance by ASN and VRF."""
        for bgp in self.bgp_instances:
            if bgp.asn == asn and bgp.vrf == vrf:
                return bgp
        return None

    def get_ospf_by_process_id(
        self, process_id: int | str, vrf: str | None = None
    ) -> OSPFConfig | None:
        """Get OSPF instance by process ID and VRF."""
        for ospf in self.ospf_instances:
            if ospf.process_id == process_id and ospf.vrf == vrf:
                return ospf
        return None
