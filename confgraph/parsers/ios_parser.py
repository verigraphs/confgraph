"""Cisco IOS/IOS-XE configuration parser."""

import re
from ipaddress import IPv4Address, IPv4Interface, IPv4Network, IPv6Address, IPv6Interface, IPv6Network

from confgraph.parsers.base import BaseParser
from confgraph.models.base import OSType
from confgraph.models.vrf import VRFConfig
from confgraph.models.interface import (
    InterfaceConfig,
    InterfaceType,
    HSRPGroup,
    VRRPGroup,
)
from confgraph.models.bgp import (
    BGPConfig,
    BGPNeighbor,
    BGPPeerGroup,
    BGPAddressFamily,
    BGPNeighborAF,
    BGPNetwork,
    BGPRedistribute,
    BGPAggregate,
    BGPBestpathOptions,
    BGPTimers,
)
from confgraph.models.ospf import (
    OSPFConfig,
    OSPFArea,
    OSPFAreaType,
    OSPFRange,
    OSPFRedistribute,
    OSPFMDKey,
)
from confgraph.models.route_map import (
    RouteMapConfig,
    RouteMapSequence,
    RouteMapMatch,
    RouteMapSet,
)
from confgraph.models.prefix_list import (
    PrefixListConfig,
    PrefixListEntry,
)
from confgraph.models.static_route import StaticRoute
from confgraph.models.acl import ACLConfig, ACLEntry
from confgraph.models.community_list import (
    CommunityListConfig,
    CommunityListEntry,
    ASPathListConfig,
    ASPathListEntry,
)
from confgraph.models.isis import ISISConfig, ISISRedistribute
from confgraph.models.eigrp import EIGRPConfig, EIGRPNetwork, EIGRPRedistribute, EIGRPMetric
from confgraph.models.rip import RIPConfig, RIPRedistribute, RIPTimers
from confgraph.models.ntp import NTPConfig, NTPServer, NTPAuthKey
from confgraph.models.snmp import SNMPConfig, SNMPCommunity, SNMPHost, SNMPView, SNMPGroup, SNMPUser
from confgraph.models.logging_config import SyslogConfig, LoggingHost
from confgraph.models.banner import BannerConfig
from confgraph.models.line import LineConfig, LineType
from confgraph.models.qos import (
    ClassMapConfig, ClassMapMatch,
    PolicyMapConfig, PolicyMapClass, PolicyMapPolice, PoliceAction, PolicyMapShape, PolicyMapSet,
)
from confgraph.models.nat import NATConfig, NATPool, NATStaticEntry, NATDynamicEntry, NATTimeouts
from confgraph.models.crypto import (
    CryptoConfig, IKEv1Policy, IKEv1Key, IKEv2Proposal, IKEv2Policy,
    IPSecTransformSet, CryptoMapEntry, CryptoMap, IPSecProfile,
)
from confgraph.models.bfd import BFDConfig, BFDTemplate, BFDInterval, BFDMap
from confgraph.models.ipsla import IPSLAOperation, IPSLASchedule, IPSLAReaction
from confgraph.models.eem import EEMApplet, EEMEvent, EEMAction
from confgraph.models.object_tracking import ObjectTrack, TrackListObject
from confgraph.models.multicast import MulticastConfig, PIMRPAddress, MSDPPeer


class IOSParser(BaseParser):
    """Parser for Cisco IOS and IOS-XE configurations.

    Supports both IOS and IOS-XE syntax (they are very similar).
    """

    def __init__(self, config_text: str, os_type: OSType = OSType.IOS):
        """Initialize IOS parser.

        Args:
            config_text: Raw configuration text
            os_type: OS type (IOS or IOS_XE)
        """
        super().__init__(config_text, os_type, syntax="ios")

    def parse_vrfs(self) -> list[VRFConfig]:
        """Parse VRF configurations from IOS/IOS-XE config.

        Supports both:
        - vrf definition NAME (IOS-XE)
        - ip vrf NAME (IOS)
        """
        vrfs = []
        parse = self._get_parse_obj()

        # IOS-XE style: vrf definition
        vrf_objs = parse.find_objects(r"^vrf\s+definition\s+(\S+)")
        for vrf_obj in vrf_objs:
            vrf_name = self._extract_match(vrf_obj.text, r"^vrf\s+definition\s+(\S+)")
            if not vrf_name:
                continue

            raw_lines, line_numbers = self._get_raw_lines_and_line_numbers(vrf_obj)

            # Extract RD
            rd = None
            rd_children = vrf_obj.re_search_children(r"^\s+rd\s+(\S+)")
            if rd_children:
                rd = self._extract_match(rd_children[0].text, r"^\s+rd\s+(\S+)")

            # Extract route-targets
            rt_import = []
            rt_export = []
            rt_both = []

            for child in vrf_obj.children:
                if "route-target export" in child.text:
                    rt_val = self._extract_match(child.text, r"route-target\s+export\s+(\S+)")
                    if rt_val:
                        rt_export.append(rt_val)
                elif "route-target import" in child.text:
                    rt_val = self._extract_match(child.text, r"route-target\s+import\s+(\S+)")
                    if rt_val:
                        rt_import.append(rt_val)
                elif re.search(r"route-target\s+both\s+", child.text):
                    rt_val = self._extract_match(child.text, r"route-target\s+both\s+(\S+)")
                    if rt_val:
                        rt_both.append(rt_val)

            # Extract route-maps (within address-family ipv4)
            route_map_import = None
            route_map_export = None
            for child in vrf_obj.children:
                if "route-map" in child.text and "import" in child.text:
                    route_map_import = self._extract_match(
                        child.text, r"route-map\s+(\S+)\s+import"
                    )
                elif "route-map" in child.text and "export" in child.text:
                    route_map_export = self._extract_match(
                        child.text, r"route-map\s+(\S+)\s+export"
                    )

            vrfs.append(
                VRFConfig(
                    object_id=f"vrf_{vrf_name}",
                    raw_lines=raw_lines,
                    source_os=self.os_type,
                    line_numbers=line_numbers,
                    name=vrf_name,
                    rd=rd,
                    route_target_import=rt_import,
                    route_target_export=rt_export,
                    route_target_both=rt_both,
                    route_map_import=route_map_import,
                    route_map_export=route_map_export,
                )
            )

        # TODO: Add support for "ip vrf NAME" (older IOS style)

        return vrfs

    def parse_interfaces(self) -> list[InterfaceConfig]:
        """Parse interface configurations."""
        interfaces = []
        parse = self._get_parse_obj()

        # Find all interface configurations
        intf_objs = parse.find_objects(r"^interface\s+")

        for intf_obj in intf_objs:
            intf_name = self._extract_match(intf_obj.text, r"^interface\s+(\S+)")
            if not intf_name:
                continue

            raw_lines, line_numbers = self._get_raw_lines_and_line_numbers(intf_obj)

            # Determine interface type
            intf_type = self._determine_interface_type(intf_name)

            # Basic attributes
            description = None
            desc_children = intf_obj.re_search_children(r"^\s+description\s+(.+)")
            if desc_children:
                description = self._extract_match(
                    desc_children[0].text, r"^\s+description\s+(.+)"
                )

            enabled = not self._is_shutdown(intf_obj)

            # VRF
            vrf = self._extract_interface_vrf(intf_obj)

            # IP addressing
            ip_address = None
            ip_children = intf_obj.re_search_children(
                r"^\s+ip\s+address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)"
            )
            if ip_children:
                match = re.search(
                    r"^\s+ip\s+address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)",
                    ip_children[0].text,
                )
                if match:
                    ip = match.group(1)
                    mask = match.group(2)
                    # Convert to prefix length
                    ip_address = IPv4Interface(f"{ip}/{mask}")

            # Secondary IPs
            secondary_ips = []
            secondary_children = intf_obj.re_search_children(
                r"^\s+ip\s+address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+secondary"
            )
            for sec_child in secondary_children:
                match = re.search(
                    r"^\s+ip\s+address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+secondary",
                    sec_child.text,
                )
                if match:
                    secondary_ips.append(IPv4Interface(f"{match.group(1)}/{match.group(2)}"))

            # IPv6 addresses
            ipv6_addresses = []
            ipv6_children = intf_obj.re_search_children(r"^\s+ipv6\s+address\s+(\S+)")
            for ipv6_child in ipv6_children:
                match = re.search(r"^\s+ipv6\s+address\s+(\S+)", ipv6_child.text)
                if match and "link-local" not in ipv6_child.text:
                    try:
                        ipv6_addresses.append(IPv6Interface(match.group(1)))
                    except ValueError:
                        pass

            # MTU
            mtu = None
            mtu_children = intf_obj.re_search_children(r"^\s+mtu\s+(\d+)")
            if mtu_children:
                mtu = int(self._extract_match(mtu_children[0].text, r"^\s+mtu\s+(\d+)"))

            # Speed
            speed = None
            speed_children = intf_obj.re_search_children(r"^\s+speed\s+(\S+)")
            if speed_children:
                speed = self._extract_match(speed_children[0].text, r"^\s+speed\s+(\S+)")

            # Duplex
            duplex = None
            duplex_children = intf_obj.re_search_children(r"^\s+duplex\s+(\S+)")
            if duplex_children:
                duplex = self._extract_match(duplex_children[0].text, r"^\s+duplex\s+(\S+)")

            # Bandwidth
            bandwidth = None
            bw_children = intf_obj.re_search_children(r"^\s+bandwidth\s+(\d+)")
            if bw_children:
                bandwidth = int(
                    self._extract_match(bw_children[0].text, r"^\s+bandwidth\s+(\d+)")
                )

            # Switchport attributes
            switchport_mode = None
            access_vlan = None
            trunk_allowed_vlans = []
            trunk_native_vlan = None

            sw_mode_children = intf_obj.re_search_children(r"^\s+switchport\s+mode\s+(\S+)")
            if sw_mode_children:
                switchport_mode = self._extract_match(
                    sw_mode_children[0].text, r"^\s+switchport\s+mode\s+(\S+)"
                )

            access_vlan_children = intf_obj.re_search_children(
                r"^\s+switchport\s+access\s+vlan\s+(\d+)"
            )
            if access_vlan_children:
                access_vlan = int(
                    self._extract_match(
                        access_vlan_children[0].text, r"^\s+switchport\s+access\s+vlan\s+(\d+)"
                    )
                )

            trunk_allowed_children = intf_obj.re_search_children(
                r"^\s+switchport\s+trunk\s+allowed\s+vlan\s+(.+)"
            )
            if trunk_allowed_children:
                vlan_str = self._extract_match(
                    trunk_allowed_children[0].text,
                    r"^\s+switchport\s+trunk\s+allowed\s+vlan\s+(.+)",
                )
                trunk_allowed_vlans = self._parse_vlan_list(vlan_str)

            trunk_native_children = intf_obj.re_search_children(
                r"^\s+switchport\s+trunk\s+native\s+vlan\s+(\d+)"
            )
            if trunk_native_children:
                trunk_native_vlan = int(
                    self._extract_match(
                        trunk_native_children[0].text,
                        r"^\s+switchport\s+trunk\s+native\s+vlan\s+(\d+)",
                    )
                )

            # Port-channel
            channel_group = None
            channel_group_mode = None
            ch_group_children = intf_obj.re_search_children(
                r"^\s+channel-group\s+(\d+)\s+mode\s+(\S+)"
            )
            if ch_group_children:
                match = re.search(
                    r"^\s+channel-group\s+(\d+)\s+mode\s+(\S+)",
                    ch_group_children[0].text,
                )
                if match:
                    channel_group = int(match.group(1))
                    channel_group_mode = match.group(2)

            # OSPF attributes
            ospf_process_id = None
            ospf_area = None
            ospf_cost = None
            ospf_priority = None
            ospf_hello_interval = None
            ospf_dead_interval = None
            ospf_network_type = None
            ospf_passive = False
            ospf_authentication = None
            ospf_authentication_key = None
            ospf_message_digest_keys = {}

            # ip ospf <process> area <area>
            ospf_area_children = intf_obj.re_search_children(
                r"^\s+ip\s+ospf\s+(\d+)\s+area\s+(\S+)"
            )
            if ospf_area_children:
                match = re.search(
                    r"^\s+ip\s+ospf\s+(\d+)\s+area\s+(\S+)",
                    ospf_area_children[0].text,
                )
                if match:
                    ospf_process_id = int(match.group(1))
                    ospf_area = match.group(2)

            # ip ospf cost
            ospf_cost_children = intf_obj.re_search_children(r"^\s+ip\s+ospf\s+cost\s+(\d+)")
            if ospf_cost_children:
                ospf_cost = int(
                    self._extract_match(ospf_cost_children[0].text, r"^\s+ip\s+ospf\s+cost\s+(\d+)")
                )

            # ip ospf priority
            ospf_priority_children = intf_obj.re_search_children(
                r"^\s+ip\s+ospf\s+priority\s+(\d+)"
            )
            if ospf_priority_children:
                ospf_priority = int(
                    self._extract_match(
                        ospf_priority_children[0].text, r"^\s+ip\s+ospf\s+priority\s+(\d+)"
                    )
                )

            # ip ospf hello-interval
            ospf_hello_children = intf_obj.re_search_children(
                r"^\s+ip\s+ospf\s+hello-interval\s+(\d+)"
            )
            if ospf_hello_children:
                ospf_hello_interval = int(
                    self._extract_match(
                        ospf_hello_children[0].text, r"^\s+ip\s+ospf\s+hello-interval\s+(\d+)"
                    )
                )

            # ip ospf dead-interval
            ospf_dead_children = intf_obj.re_search_children(
                r"^\s+ip\s+ospf\s+dead-interval\s+(\d+)"
            )
            if ospf_dead_children:
                ospf_dead_interval = int(
                    self._extract_match(
                        ospf_dead_children[0].text, r"^\s+ip\s+ospf\s+dead-interval\s+(\d+)"
                    )
                )

            # ip ospf network
            ospf_network_children = intf_obj.re_search_children(
                r"^\s+ip\s+ospf\s+network\s+(\S+)"
            )
            if ospf_network_children:
                ospf_network_type = self._extract_match(
                    ospf_network_children[0].text, r"^\s+ip\s+ospf\s+network\s+(.+)"
                )

            # ip ospf authentication
            ospf_auth_children = intf_obj.re_search_children(
                r"^\s+ip\s+ospf\s+authentication\s+(.+)"
            )
            if ospf_auth_children:
                ospf_authentication = self._extract_match(
                    ospf_auth_children[0].text, r"^\s+ip\s+ospf\s+authentication\s+(.+)"
                )

            # ip ospf message-digest-key
            ospf_md_key_children = intf_obj.re_search_children(
                r"^\s+ip\s+ospf\s+message-digest-key\s+(\d+)\s+md5\s+(\S+)"
            )
            for md_child in ospf_md_key_children:
                match = re.search(
                    r"^\s+ip\s+ospf\s+message-digest-key\s+(\d+)\s+md5\s+(\S+)",
                    md_child.text,
                )
                if match:
                    key_id = int(match.group(1))
                    key_str = match.group(2)
                    ospf_message_digest_keys[key_id] = key_str

            # Tunnel attributes
            tunnel_source = None
            tunnel_destination = None
            tunnel_mode = None

            if intf_type == InterfaceType.TUNNEL:
                tunnel_src_children = intf_obj.re_search_children(
                    r"^\s+tunnel\s+source\s+(\S+)"
                )
                if tunnel_src_children:
                    tunnel_source = self._extract_match(
                        tunnel_src_children[0].text, r"^\s+tunnel\s+source\s+(\S+)"
                    )

                tunnel_dst_children = intf_obj.re_search_children(
                    r"^\s+tunnel\s+destination\s+(\S+)"
                )
                if tunnel_dst_children:
                    dst_str = self._extract_match(
                        tunnel_dst_children[0].text, r"^\s+tunnel\s+destination\s+(\S+)"
                    )
                    try:
                        tunnel_destination = IPv4Address(dst_str)
                    except ValueError:
                        pass

                tunnel_mode_children = intf_obj.re_search_children(
                    r"^\s+tunnel\s+mode\s+(.+)"
                )
                if tunnel_mode_children:
                    tunnel_mode = self._extract_match(
                        tunnel_mode_children[0].text, r"^\s+tunnel\s+mode\s+(.+)"
                    )

            # HSRP groups
            hsrp_groups = self._parse_hsrp_groups(intf_obj)

            # VRRP groups
            vrrp_groups = self._parse_vrrp_groups(intf_obj)

            # Helper addresses
            helper_addresses = []
            helper_children = intf_obj.re_search_children(
                r"^\s+ip\s+helper-address\s+(\S+)"
            )
            for helper_child in helper_children:
                helper_ip_str = self._extract_match(
                    helper_child.text, r"^\s+ip\s+helper-address\s+(\S+)"
                )
                try:
                    helper_addresses.append(IPv4Address(helper_ip_str))
                except ValueError:
                    pass

            # PIM per-interface
            pim_mode = None
            pim_ch = intf_obj.re_search_children(r"^\s+ip\s+pim\s+")
            if pim_ch:
                pm = re.match(r"^\s+ip\s+pim\s+(sparse-mode|dense-mode|sparse-dense-mode)", pim_ch[0].text)
                if pm:
                    pim_mode = pm.group(1)
            pim_dr_priority = None
            pdr_ch = intf_obj.re_search_children(r"^\s+ip\s+pim\s+dr-priority\s+(\d+)")
            if pdr_ch:
                v = self._extract_match(pdr_ch[0].text, r"^\s+ip\s+pim\s+dr-priority\s+(\d+)")
                if v:
                    pim_dr_priority = int(v)
            pim_query_interval = None
            pqi_ch = intf_obj.re_search_children(r"^\s+ip\s+pim\s+query-interval\s+(\d+)")
            if pqi_ch:
                v = self._extract_match(pqi_ch[0].text, r"^\s+ip\s+pim\s+query-interval\s+(\d+)")
                if v:
                    pim_query_interval = int(v)
            pim_bfd = bool(intf_obj.re_search_children(r"^\s+ip\s+pim\s+bfd"))

            # IGMP per-interface
            igmp_version = None
            igv_ch = intf_obj.re_search_children(r"^\s+ip\s+igmp\s+version\s+(\d)")
            if igv_ch:
                v = self._extract_match(igv_ch[0].text, r"^\s+ip\s+igmp\s+version\s+(\d)")
                if v:
                    igmp_version = int(v)
            igmp_query_interval = None
            iqi_ch = intf_obj.re_search_children(r"^\s+ip\s+igmp\s+query-interval\s+(\d+)")
            if iqi_ch:
                v = self._extract_match(iqi_ch[0].text, r"^\s+ip\s+igmp\s+query-interval\s+(\d+)")
                if v:
                    igmp_query_interval = int(v)
            igmp_query_max_response_time = None
            iqmr_ch = intf_obj.re_search_children(r"^\s+ip\s+igmp\s+query-max-response-time\s+(\d+)")
            if iqmr_ch:
                v = self._extract_match(iqmr_ch[0].text, r"^\s+ip\s+igmp\s+query-max-response-time\s+(\d+)")
                if v:
                    igmp_query_max_response_time = int(v)
            # ip access-group applied to interface (inbound / outbound)
            acl_in = None
            acl_out = None
            for ag_ch in intf_obj.re_search_children(r"^\s+ip\s+access-group\s+\S+\s+(in|out)"):
                m = re.match(r"^\s+ip\s+access-group\s+(\S+)\s+(in|out)", ag_ch.text)
                if m:
                    if m.group(2) == "in":
                        acl_in = m.group(1)
                    else:
                        acl_out = m.group(1)

            igmp_access_group = None
            iag_ch = intf_obj.re_search_children(r"^\s+ip\s+igmp\s+access-group\s+(\S+)")
            if iag_ch:
                igmp_access_group = self._extract_match(iag_ch[0].text, r"^\s+ip\s+igmp\s+access-group\s+(\S+)")
            igmp_join_groups = []
            for jg_ch in intf_obj.re_search_children(r"^\s+ip\s+igmp\s+join-group\s+(\S+)"):
                v = self._extract_match(jg_ch.text, r"^\s+ip\s+igmp\s+join-group\s+(\S+)")
                if v:
                    igmp_join_groups.append(v)
            igmp_static_groups = []
            for sg_ch in intf_obj.re_search_children(r"^\s+ip\s+igmp\s+static-group\s+(\S+)"):
                v = self._extract_match(sg_ch.text, r"^\s+ip\s+igmp\s+static-group\s+(\S+)")
                if v:
                    igmp_static_groups.append(v)

            # QoS service-policy
            service_policy_input = None
            service_policy_output = None
            for sp_ch in intf_obj.re_search_children(r"^\s+service-policy\s+"):
                spm = re.match(r"^\s+service-policy\s+(input|output)\s+(\S+)", sp_ch.text)
                if spm:
                    if spm.group(1) == "input":
                        service_policy_input = spm.group(2)
                    else:
                        service_policy_output = spm.group(2)

            # NAT direction
            nat_direction = None
            nat_in_ch = intf_obj.re_search_children(r"^\s+ip\s+nat\s+inside")
            nat_out_ch = intf_obj.re_search_children(r"^\s+ip\s+nat\s+outside")
            if nat_in_ch:
                nat_direction = "inside"
            elif nat_out_ch:
                nat_direction = "outside"

            # Crypto map
            crypto_map_name = None
            cm_ch = intf_obj.re_search_children(r"^\s+crypto\s+map\s+(\S+)")
            if cm_ch:
                crypto_map_name = self._extract_match(cm_ch[0].text, r"^\s+crypto\s+map\s+(\S+)")

            interfaces.append(
                InterfaceConfig(
                    object_id=f"interface_{intf_name}",
                    raw_lines=raw_lines,
                    source_os=self.os_type,
                    line_numbers=line_numbers,
                    name=intf_name,
                    interface_type=intf_type,
                    description=description,
                    enabled=enabled,
                    vrf=vrf,
                    ip_address=ip_address,
                    ipv6_addresses=ipv6_addresses,
                    secondary_ips=secondary_ips,
                    mtu=mtu,
                    speed=speed,
                    duplex=duplex,
                    bandwidth=bandwidth,
                    switchport_mode=switchport_mode,
                    access_vlan=access_vlan,
                    trunk_allowed_vlans=trunk_allowed_vlans,
                    trunk_native_vlan=trunk_native_vlan,
                    channel_group=channel_group,
                    channel_group_mode=channel_group_mode,
                    hsrp_groups=hsrp_groups,
                    vrrp_groups=vrrp_groups,
                    ospf_process_id=ospf_process_id,
                    ospf_area=ospf_area,
                    ospf_cost=ospf_cost,
                    ospf_priority=ospf_priority,
                    ospf_hello_interval=ospf_hello_interval,
                    ospf_dead_interval=ospf_dead_interval,
                    ospf_network_type=ospf_network_type,
                    ospf_passive=ospf_passive,
                    ospf_authentication=ospf_authentication,
                    ospf_authentication_key=ospf_authentication_key,
                    ospf_message_digest_keys=ospf_message_digest_keys,
                    helper_addresses=helper_addresses,
                    tunnel_source=tunnel_source,
                    tunnel_destination=tunnel_destination,
                    tunnel_mode=tunnel_mode,
                    pim_mode=pim_mode,
                    pim_dr_priority=pim_dr_priority,
                    pim_query_interval=pim_query_interval,
                    pim_bfd=pim_bfd,
                    igmp_version=igmp_version,
                    igmp_query_interval=igmp_query_interval,
                    igmp_query_max_response_time=igmp_query_max_response_time,
                    acl_in=acl_in,
                    acl_out=acl_out,
                    igmp_access_group=igmp_access_group,
                    igmp_join_groups=igmp_join_groups,
                    igmp_static_groups=igmp_static_groups,
                    service_policy_input=service_policy_input,
                    service_policy_output=service_policy_output,
                    nat_direction=nat_direction,
                    crypto_map=crypto_map_name,
                )
            )

        return interfaces

    def parse_bgp(self) -> list[BGPConfig]:
        """Parse BGP configurations.

        Returns both global and VRF-specific BGP instances.
        """
        bgp_instances = []
        parse = self._get_parse_obj()

        # Find all BGP router configs
        bgp_objs = parse.find_objects(r"^router\s+bgp\s+(\d+)")

        for bgp_obj in bgp_objs:
            asn_str = self._extract_match(bgp_obj.text, r"^router\s+bgp\s+(\d+)")
            if not asn_str:
                continue

            asn = int(asn_str)
            raw_lines, line_numbers = self._get_raw_lines_and_line_numbers(bgp_obj)

            # Router ID
            router_id = None
            rid_children = bgp_obj.re_search_children(r"^\s+bgp\s+router-id\s+(\S+)")
            if rid_children:
                rid_str = self._extract_match(
                    rid_children[0].text, r"^\s+bgp\s+router-id\s+(\S+)"
                )
                try:
                    router_id = IPv4Address(rid_str)
                except ValueError:
                    pass

            # Log neighbor changes
            log_neighbor_changes = len(
                bgp_obj.re_search_children(r"^\s+bgp\s+log-neighbor-changes")
            ) > 0

            # Best-path options
            bestpath_options = self._parse_bgp_bestpath_options(bgp_obj)

            # Parse neighbors and peer-groups
            neighbors = self._parse_bgp_neighbors(bgp_obj)
            peer_groups = self._parse_bgp_peer_groups(bgp_obj)

            # Populate per-neighbor AF policies from address-family blocks
            self._apply_bgp_af_neighbor_policies(bgp_obj, neighbors)

            # Parse address-families
            address_families = self._parse_bgp_address_families(bgp_obj)

            # Parse global networks and redistribution (if any at global level)
            networks = self._parse_bgp_networks(bgp_obj, vrf=None)
            redistribute = self._parse_bgp_redistribute(bgp_obj, vrf=None)

            # Global BGP instance
            bgp_instances.append(
                BGPConfig(
                    object_id=f"bgp_{asn}",
                    raw_lines=raw_lines,
                    source_os=self.os_type,
                    line_numbers=line_numbers,
                    asn=asn,
                    router_id=router_id,
                    vrf=None,
                    log_neighbor_changes=log_neighbor_changes,
                    bestpath_options=bestpath_options,
                    neighbors=neighbors,
                    peer_groups=peer_groups,
                    address_families=address_families,
                    networks=networks,
                    redistribute=redistribute,
                )
            )

            # Parse VRF-specific BGP instances from address-family ipv4 vrf blocks
            vrf_instances = self._parse_bgp_vrf_instances(bgp_obj, asn)
            bgp_instances.extend(vrf_instances)

        return bgp_instances

    def parse_ospf(self) -> list[OSPFConfig]:
        """Parse OSPF configurations."""
        ospf_instances = []
        parse = self._get_parse_obj()

        # Find all OSPF router configs
        ospf_objs = parse.find_objects(r"^router\s+ospf\s+(\d+)")

        for ospf_obj in ospf_objs:
            process_id_str = self._extract_match(ospf_obj.text, r"^router\s+ospf\s+(\d+)")
            if not process_id_str:
                continue

            process_id = int(process_id_str)
            raw_lines, line_numbers = self._get_raw_lines_and_line_numbers(ospf_obj)

            # Router ID
            router_id = None
            rid_children = ospf_obj.re_search_children(r"^\s+router-id\s+(\S+)")
            if rid_children:
                rid_str = self._extract_match(rid_children[0].text, r"^\s+router-id\s+(\S+)")
                try:
                    router_id = IPv4Address(rid_str)
                except ValueError:
                    pass

            # Log adjacency changes
            log_adjacency_changes = len(
                ospf_obj.re_search_children(r"^\s+log-adjacency-changes")
            ) > 0

            log_adjacency_changes_detail = len(
                ospf_obj.re_search_children(r"^\s+log-adjacency-changes\s+detail")
            ) > 0

            # Auto-cost reference bandwidth
            auto_cost_ref_bw = None
            auto_cost_children = ospf_obj.re_search_children(
                r"^\s+auto-cost\s+reference-bandwidth\s+(\d+)"
            )
            if auto_cost_children:
                auto_cost_ref_bw = int(
                    self._extract_match(
                        auto_cost_children[0].text,
                        r"^\s+auto-cost\s+reference-bandwidth\s+(\d+)",
                    )
                )

            # Passive interface default
            passive_interface_default = len(
                ospf_obj.re_search_children(r"^\s+passive-interface\s+default")
            ) > 0

            # Passive interfaces
            passive_interfaces = []
            passive_intf_children = ospf_obj.re_search_children(
                r"^\s+passive-interface\s+(\S+)"
            )
            for passive_child in passive_intf_children:
                if "default" not in passive_child.text:
                    intf_name = self._extract_match(
                        passive_child.text, r"^\s+passive-interface\s+(\S+)"
                    )
                    if intf_name:
                        passive_interfaces.append(intf_name)

            # Non-passive interfaces (when default is set)
            non_passive_interfaces = []
            non_passive_children = ospf_obj.re_search_children(
                r"^\s+no\s+passive-interface\s+(\S+)"
            )
            for non_passive_child in non_passive_children:
                intf_name = self._extract_match(
                    non_passive_child.text, r"^\s+no\s+passive-interface\s+(\S+)"
                )
                if intf_name:
                    non_passive_interfaces.append(intf_name)

            # Parse areas
            areas = self._parse_ospf_areas(ospf_obj)

            # Parse redistribution
            redistribute = self._parse_ospf_redistribute(ospf_obj)

            # Default-information originate
            default_info_originate = False
            default_info_always = False
            default_info_metric: int | None = None
            default_info_metric_type: int | None = None
            default_info_route_map: str | None = None

            di_children = ospf_obj.re_search_children(
                r"^\s+default-information\s+originate"
            )
            if di_children:
                default_info_originate = True
                di_text = di_children[0].text
                default_info_always = "always" in di_text
                m = re.search(r"\bmetric\s+(\d+)", di_text)
                if m:
                    default_info_metric = int(m.group(1))
                m = re.search(r"\bmetric-type\s+(\d+)", di_text)
                if m:
                    default_info_metric_type = int(m.group(1))
                m = re.search(r"\broute-map\s+(\S+)", di_text)
                if m:
                    default_info_route_map = m.group(1)

            ospf_instances.append(
                OSPFConfig(
                    object_id=f"ospf_{process_id}",
                    raw_lines=raw_lines,
                    source_os=self.os_type,
                    line_numbers=line_numbers,
                    process_id=process_id,
                    vrf=None,
                    router_id=router_id,
                    log_adjacency_changes=log_adjacency_changes,
                    log_adjacency_changes_detail=log_adjacency_changes_detail,
                    auto_cost_reference_bandwidth=auto_cost_ref_bw,
                    passive_interface_default=passive_interface_default,
                    passive_interfaces=passive_interfaces,
                    non_passive_interfaces=non_passive_interfaces,
                    areas=areas,
                    redistribute=redistribute,
                    default_information_originate=default_info_originate,
                    default_information_originate_always=default_info_always,
                    default_information_originate_metric=default_info_metric,
                    default_information_originate_metric_type=default_info_metric_type,
                    default_information_originate_route_map=default_info_route_map,
                )
            )

        return ospf_instances

    def parse_route_maps(self) -> list[RouteMapConfig]:
        """Parse route-map configurations."""
        route_maps = []
        parse = self._get_parse_obj()

        # Find all route-map entries
        rm_objs = parse.find_objects(r"^route-map\s+(\S+)\s+(permit|deny)\s+(\d+)")

        # Group by route-map name
        rm_dict: dict[str, list] = {}
        for rm_obj in rm_objs:
            match = re.search(
                r"^route-map\s+(\S+)\s+(permit|deny)\s+(\d+)",
                rm_obj.text,
            )
            if not match:
                continue

            rm_name = match.group(1)
            action = match.group(2)
            sequence = int(match.group(3))

            if rm_name not in rm_dict:
                rm_dict[rm_name] = []

            # Parse match clauses
            match_clauses = []
            match_children = rm_obj.re_search_children(r"^\s+match\s+(.+)")
            for match_child in match_children:
                match_text = self._extract_match(match_child.text, r"^\s+match\s+(.+)")
                if match_text:
                    # Parse match type and values
                    parts = match_text.split(None, 1)
                    if len(parts) >= 1:
                        match_type_parts = []
                        values = []

                        # Handle complex match types like "ip address prefix-list"
                        if "ip address prefix-list" in match_text:
                            match_type_parts = ["ip", "address", "prefix-list"]
                            remaining = match_text.replace("ip address prefix-list", "").strip()
                            values = remaining.split() if remaining else []
                        elif "ip address" in match_text:
                            match_type_parts = ["ip", "address"]
                            remaining = match_text.replace("ip address", "").strip()
                            values = remaining.split() if remaining else []
                        else:
                            match_type_parts = [parts[0]]
                            values = parts[1].split() if len(parts) > 1 else []

                        match_clauses.append(
                            RouteMapMatch(
                                match_type=" ".join(match_type_parts),
                                values=values,
                            )
                        )

            # Parse set clauses
            set_clauses = []
            set_children = rm_obj.re_search_children(r"^\s+set\s+(.+)")
            for set_child in set_children:
                set_text = self._extract_match(set_child.text, r"^\s+set\s+(.+)")
                if set_text:
                    parts = set_text.split(None, 1)
                    if len(parts) >= 1:
                        set_type = parts[0]
                        values = parts[1].split() if len(parts) > 1 else []

                        # Handle special cases
                        if set_type in ["local-preference", "metric", "weight", "tag"]:
                            # These are single numeric values
                            pass
                        elif "as-path" in set_text:
                            set_type = "as-path"
                            remaining = set_text.replace("as-path", "").strip()
                            values = remaining.split() if remaining else []
                        elif "community" in set_text:
                            set_type = "community"
                            remaining = set_text.replace("community", "").strip()
                            values = remaining.split() if remaining else []

                        set_clauses.append(
                            RouteMapSet(
                                set_type=set_type,
                                values=values,
                            )
                        )

            # Check for continue statement
            continue_seq = None
            continue_children = rm_obj.re_search_children(r"^\s+continue\s+(\d+)")
            if continue_children:
                continue_seq = int(
                    self._extract_match(continue_children[0].text, r"^\s+continue\s+(\d+)")
                )

            # Description
            description = None
            desc_children = rm_obj.re_search_children(r"^\s+description\s+(.+)")
            if desc_children:
                description = self._extract_match(desc_children[0].text, r"^\s+description\s+(.+)")

            raw_lines, line_numbers = self._get_raw_lines_and_line_numbers(rm_obj)

            rm_dict[rm_name].append(
                {
                    "sequence": sequence,
                    "action": action,
                    "match_clauses": match_clauses,
                    "set_clauses": set_clauses,
                    "continue_sequence": continue_seq,
                    "description": description,
                    "raw_lines": raw_lines,
                    "line_numbers": line_numbers,
                }
            )

        # Create RouteMapConfig objects
        for rm_name, sequences_data in rm_dict.items():
            sequences = []
            all_raw_lines = []
            all_line_numbers = []

            for seq_data in sequences_data:
                sequences.append(
                    RouteMapSequence(
                        sequence=seq_data["sequence"],
                        action=seq_data["action"],
                        match_clauses=seq_data["match_clauses"],
                        set_clauses=seq_data["set_clauses"],
                        continue_sequence=seq_data["continue_sequence"],
                        description=seq_data["description"],
                    )
                )
                all_raw_lines.extend(seq_data["raw_lines"])
                all_line_numbers.extend(seq_data["line_numbers"])

            route_maps.append(
                RouteMapConfig(
                    object_id=f"route_map_{rm_name}",
                    raw_lines=all_raw_lines,
                    source_os=self.os_type,
                    line_numbers=all_line_numbers,
                    name=rm_name,
                    sequences=sequences,
                )
            )

        return route_maps

    def parse_prefix_lists(self) -> list[PrefixListConfig]:
        """Parse prefix-list configurations."""
        prefix_lists = []
        parse = self._get_parse_obj()

        # Find all prefix-list entries
        pl_objs = parse.find_objects(
            r"^ip\s+prefix-list\s+(\S+)\s+seq\s+(\d+)\s+(permit|deny)\s+(\S+)"
        )

        # Group by prefix-list name
        pl_dict: dict[str, list] = {}
        for pl_obj in pl_objs:
            match = re.search(
                r"^ip\s+prefix-list\s+(\S+)\s+seq\s+(\d+)\s+(permit|deny)\s+(\S+)",
                pl_obj.text,
            )
            if not match:
                continue

            pl_name = match.group(1)
            sequence = int(match.group(2))
            action = match.group(3)
            prefix_str = match.group(4)

            if pl_name not in pl_dict:
                pl_dict[pl_name] = []

            # Parse ge/le
            ge = None
            le = None
            ge_match = re.search(r"\sge\s+(\d+)", pl_obj.text)
            if ge_match:
                ge = int(ge_match.group(1))

            le_match = re.search(r"\sle\s+(\d+)", pl_obj.text)
            if le_match:
                le = int(le_match.group(1))

            # Parse description (if present)
            description = None
            desc_match = re.search(r"description\s+(.+)", pl_obj.text)
            if desc_match:
                description = desc_match.group(1)

            try:
                prefix = IPv4Network(prefix_str)
            except ValueError:
                continue

            raw_lines, line_numbers = self._get_raw_lines_and_line_numbers(pl_obj)

            pl_dict[pl_name].append(
                {
                    "sequence": sequence,
                    "action": action,
                    "prefix": prefix,
                    "ge": ge,
                    "le": le,
                    "description": description,
                    "raw_lines": raw_lines,
                    "line_numbers": line_numbers,
                }
            )

        # Create PrefixListConfig objects
        for pl_name, entries_data in pl_dict.items():
            entries = []
            all_raw_lines = []
            all_line_numbers = []

            for entry_data in entries_data:
                entries.append(
                    PrefixListEntry(
                        sequence=entry_data["sequence"],
                        action=entry_data["action"],
                        prefix=entry_data["prefix"],
                        ge=entry_data["ge"],
                        le=entry_data["le"],
                        description=entry_data["description"],
                    )
                )
                all_raw_lines.extend(entry_data["raw_lines"])
                all_line_numbers.extend(entry_data["line_numbers"])

            prefix_lists.append(
                PrefixListConfig(
                    object_id=f"prefix_list_{pl_name}",
                    raw_lines=all_raw_lines,
                    source_os=self.os_type,
                    line_numbers=all_line_numbers,
                    name=pl_name,
                    afi="ipv4",
                    sequences=entries,
                )
            )

        # TODO: Add support for IPv6 prefix-lists

        return prefix_lists

    # Helper methods

    def _extract_interface_vrf(self, intf_obj) -> str | None:
        """Extract VRF name from an interface object.

        IOS/IOS-XE format: ``vrf forwarding VRFNAME``
        Subclasses can override for OS-specific syntax.
        """
        vrf_children = intf_obj.re_search_children(r"^\s+vrf\s+forwarding\s+(\S+)")
        if vrf_children:
            return self._extract_match(
                vrf_children[0].text, r"^\s+vrf\s+forwarding\s+(\S+)"
            )
        return None

    def _determine_interface_type(self, intf_name: str) -> InterfaceType:
        """Determine interface type from interface name."""
        name_lower = intf_name.lower()
        if "loopback" in name_lower:
            return InterfaceType.LOOPBACK
        elif "port-channel" in name_lower or "po" == name_lower[:2]:
            return InterfaceType.PORTCHANNEL
        elif "vlan" in name_lower:
            return InterfaceType.SVI
        elif "tunnel" in name_lower:
            return InterfaceType.TUNNEL
        elif "management" in name_lower or "mgmt" in name_lower:
            return InterfaceType.MANAGEMENT
        elif "null" in name_lower:
            return InterfaceType.NULL
        else:
            return InterfaceType.PHYSICAL

    def _parse_vlan_list(self, vlan_str: str) -> list[int]:
        """Parse VLAN list string into list of VLAN IDs.

        Handles: "10,20,30-35" -> [10, 20, 30, 31, 32, 33, 34, 35]
        """
        vlans = []
        if not vlan_str:
            return vlans

        parts = vlan_str.split(",")
        for part in parts:
            part = part.strip()
            if "-" in part:
                # Range
                start, end = part.split("-")
                vlans.extend(range(int(start), int(end) + 1))
            else:
                vlans.append(int(part))

        return vlans

    def _parse_hsrp_groups(self, intf_obj) -> list[HSRPGroup]:
        """Parse HSRP groups from interface configuration."""
        hsrp_groups = []

        # Find all standby commands
        standby_children = intf_obj.re_search_children(r"^\s+standby\s+(\d+)")

        # Group by HSRP group number
        hsrp_dict: dict[int, dict] = {}

        for standby_child in standby_children:
            match = re.search(r"^\s+standby\s+(\d+)\s+(.+)", standby_child.text)
            if not match:
                continue

            group_num = int(match.group(1))
            command = match.group(2)

            if group_num not in hsrp_dict:
                hsrp_dict[group_num] = {
                    "group_number": group_num,
                    "priority": None,
                    "preempt": False,
                    "virtual_ip": None,
                    "timers_hello": None,
                    "timers_hold": None,
                    "authentication": None,
                    "track_objects": [],
                }

            if command.startswith("ip "):
                ip_str = command.replace("ip ", "").strip()
                try:
                    hsrp_dict[group_num]["virtual_ip"] = IPv4Address(ip_str)
                except ValueError:
                    pass
            elif command.startswith("priority "):
                priority_str = command.replace("priority ", "").strip()
                hsrp_dict[group_num]["priority"] = int(priority_str)
            elif command == "preempt":
                hsrp_dict[group_num]["preempt"] = True
            elif command.startswith("timers "):
                timers_match = re.search(r"timers\s+(\d+)\s+(\d+)", command)
                if timers_match:
                    hsrp_dict[group_num]["timers_hello"] = int(timers_match.group(1))
                    hsrp_dict[group_num]["timers_hold"] = int(timers_match.group(2))
            elif command.startswith("authentication "):
                auth_str = command.replace("authentication ", "").strip()
                hsrp_dict[group_num]["authentication"] = auth_str
            elif command.startswith("track "):
                track_str = command.replace("track ", "").strip()
                track_num = int(track_str.split()[0])
                hsrp_dict[group_num]["track_objects"].append(track_num)

        # Create HSRPGroup objects
        for group_data in hsrp_dict.values():
            hsrp_groups.append(HSRPGroup(**group_data))

        return hsrp_groups

    def _parse_vrrp_groups(self, intf_obj) -> list[VRRPGroup]:
        """Parse VRRP groups from interface configuration."""
        vrrp_groups = []

        # Find all vrrp commands
        vrrp_children = intf_obj.re_search_children(r"^\s+vrrp\s+(\d+)")

        # Group by VRRP group number
        vrrp_dict: dict[int, dict] = {}

        for vrrp_child in vrrp_children:
            match = re.search(r"^\s+vrrp\s+(\d+)\s+(.+)", vrrp_child.text)
            if not match:
                continue

            group_num = int(match.group(1))
            command = match.group(2)

            if group_num not in vrrp_dict:
                vrrp_dict[group_num] = {
                    "group_number": group_num,
                    "priority": None,
                    "preempt": False,
                    "virtual_ip": None,
                    "timers_advertise": None,
                    "authentication": None,
                    "track_objects": [],
                }

            if command.startswith("ip "):
                ip_str = command.replace("ip ", "").strip()
                try:
                    vrrp_dict[group_num]["virtual_ip"] = IPv4Address(ip_str)
                except ValueError:
                    pass
            elif command.startswith("priority "):
                priority_str = command.replace("priority ", "").strip()
                vrrp_dict[group_num]["priority"] = int(priority_str)
            elif command == "preempt":
                vrrp_dict[group_num]["preempt"] = True
            elif command.startswith("timers advertise "):
                timer_str = command.replace("timers advertise ", "").strip()
                vrrp_dict[group_num]["timers_advertise"] = int(timer_str)
            elif command.startswith("authentication "):
                auth_str = command.replace("authentication ", "").strip()
                vrrp_dict[group_num]["authentication"] = auth_str

        # Create VRRPGroup objects
        for group_data in vrrp_dict.values():
            vrrp_groups.append(VRRPGroup(**group_data))

        return vrrp_groups

    def _parse_bgp_bestpath_options(self, bgp_obj) -> BGPBestpathOptions:
        """Parse BGP best-path options."""
        return BGPBestpathOptions(
            as_path_ignore=len(
                bgp_obj.re_search_children(r"^\s+bgp\s+bestpath\s+as-path\s+ignore")
            ) > 0,
            as_path_multipath_relax=len(
                bgp_obj.re_search_children(r"^\s+bgp\s+bestpath\s+as-path\s+multipath-relax")
            ) > 0,
            compare_routerid=len(
                bgp_obj.re_search_children(r"^\s+bgp\s+bestpath\s+compare-routerid")
            ) > 0,
            med_confed=len(
                bgp_obj.re_search_children(r"^\s+bgp\s+bestpath\s+med\s+confed")
            ) > 0,
            med_missing_as_worst=len(
                bgp_obj.re_search_children(r"^\s+bgp\s+bestpath\s+med\s+missing-as-worst")
            ) > 0,
            always_compare_med=len(
                bgp_obj.re_search_children(r"^\s+bgp\s+bestpath\s+always-compare-med")
            ) > 0,
        )

    def _parse_bgp_neighbors(self, bgp_obj) -> list[BGPNeighbor]:
        """Parse BGP neighbors."""
        neighbors = []
        neighbor_children = bgp_obj.re_search_children(r"^\s+neighbor\s+(\S+)\s+")

        # First, find all peer-group names
        peer_group_names = set()
        for child in neighbor_children:
            match = re.search(r"^\s+neighbor\s+(\S+)\s+peer-group\s*$", child.text)
            if match:
                peer_group_names.add(match.group(1))

        # Group by neighbor IP
        neighbor_dict: dict[str, dict] = {}

        for neighbor_child in neighbor_children:
            match = re.search(r"^\s+neighbor\s+(\S+)\s+(.+)", neighbor_child.text)
            if not match:
                continue

            peer_ip_str = match.group(1)
            command = match.group(2)

            # Skip peer-group definition lines (neighbor GROUPNAME peer-group)
            # These are already captured in peer_group_names set
            if peer_ip_str in peer_group_names:
                continue

            if peer_ip_str not in neighbor_dict:
                neighbor_dict[peer_ip_str] = {
                    "peer_ip": peer_ip_str,
                    "remote_as": None,
                    "peer_group": None,
                    "description": None,
                    "update_source": None,
                    "ebgp_multihop": None,
                    "password": None,
                    "route_map_in": None,
                    "route_map_out": None,
                    "prefix_list_in": None,
                    "prefix_list_out": None,
                    "maximum_prefix": None,
                }

            # Parse commands
            if command.startswith("remote-as "):
                as_str = command.replace("remote-as ", "").strip()
                try:
                    neighbor_dict[peer_ip_str]["remote_as"] = int(as_str)
                except ValueError:
                    neighbor_dict[peer_ip_str]["remote_as"] = as_str
            elif command.startswith("peer-group "):
                pg_name = command.replace("peer-group ", "").strip()
                neighbor_dict[peer_ip_str]["peer_group"] = pg_name
            elif command.startswith("description "):
                neighbor_dict[peer_ip_str]["description"] = command.replace("description ", "").strip()
            elif command.startswith("update-source "):
                neighbor_dict[peer_ip_str]["update_source"] = command.replace("update-source ", "").strip()
            elif command.startswith("ebgp-multihop "):
                neighbor_dict[peer_ip_str]["ebgp_multihop"] = int(command.replace("ebgp-multihop ", "").strip())
            elif command.startswith("password "):
                neighbor_dict[peer_ip_str]["password"] = command.replace("password ", "").strip()
            elif command.startswith("route-map ") and " in" in command:
                rm_name = command.replace("route-map ", "").replace(" in", "").strip()
                neighbor_dict[peer_ip_str]["route_map_in"] = rm_name
            elif command.startswith("route-map ") and " out" in command:
                rm_name = command.replace("route-map ", "").replace(" out", "").strip()
                neighbor_dict[peer_ip_str]["route_map_out"] = rm_name
            elif command.startswith("prefix-list ") and " in" in command:
                pl_name = command.replace("prefix-list ", "").replace(" in", "").strip()
                neighbor_dict[peer_ip_str]["prefix_list_in"] = pl_name
            elif command.startswith("prefix-list ") and " out" in command:
                pl_name = command.replace("prefix-list ", "").replace(" out", "").strip()
                neighbor_dict[peer_ip_str]["prefix_list_out"] = pl_name
            elif command.startswith("maximum-prefix "):
                parts = command.replace("maximum-prefix ", "").split()
                if parts:
                    neighbor_dict[peer_ip_str]["maximum_prefix"] = int(parts[0])

        # Create BGPNeighbor objects
        for peer_ip_str, neighbor_data in neighbor_dict.items():
            try:
                peer_ip = IPv4Address(peer_ip_str)
            except ValueError:
                try:
                    peer_ip = IPv6Address(peer_ip_str)
                except ValueError:
                    continue

            # Skip if no remote-as and no peer-group (invalid neighbor)
            if neighbor_data["remote_as"] is None and neighbor_data["peer_group"] is None:
                continue

            # If no remote-as but has peer-group, it inherits from peer-group
            # We'll set a placeholder value
            remote_as = neighbor_data["remote_as"] if neighbor_data["remote_as"] is not None else "inherited"

            neighbors.append(
                BGPNeighbor(
                    peer_ip=peer_ip,
                    remote_as=remote_as,
                    peer_group=neighbor_data["peer_group"],
                    description=neighbor_data["description"],
                    update_source=neighbor_data["update_source"],
                    ebgp_multihop=neighbor_data["ebgp_multihop"],
                    password=neighbor_data["password"],
                    route_map_in=neighbor_data["route_map_in"],
                    route_map_out=neighbor_data["route_map_out"],
                    prefix_list_in=neighbor_data["prefix_list_in"],
                    prefix_list_out=neighbor_data["prefix_list_out"],
                    maximum_prefix=neighbor_data["maximum_prefix"],
                )
            )

        return neighbors

    def _parse_bgp_peer_groups(self, bgp_obj) -> list[BGPPeerGroup]:
        """Parse BGP peer-groups."""
        peer_groups = []
        pg_children = bgp_obj.re_search_children(r"^\s+neighbor\s+(\S+)\s+peer-group\s*$")

        for pg_child in pg_children:
            pg_name = self._extract_match(pg_child.text, r"^\s+neighbor\s+(\S+)\s+peer-group\s*$")
            if not pg_name:
                continue

            # Find all configurations for this peer-group
            pg_config_children = bgp_obj.re_search_children(rf"^\s+neighbor\s+{re.escape(pg_name)}\s+")

            pg_data = {
                "name": pg_name,
                "remote_as": None,
                "description": None,
                "update_source": None,
                "route_reflector_client": False,
                "send_community": False,
            }

            for pg_config_child in pg_config_children:
                match = re.search(rf"^\s+neighbor\s+{re.escape(pg_name)}\s+(.+)", pg_config_child.text)
                if not match:
                    continue

                command = match.group(1)

                if command.startswith("remote-as "):
                    as_str = command.replace("remote-as ", "").strip()
                    try:
                        pg_data["remote_as"] = int(as_str)
                    except ValueError:
                        pg_data["remote_as"] = as_str
                elif command.startswith("description "):
                    pg_data["description"] = command.replace("description ", "").strip()
                elif command.startswith("update-source "):
                    pg_data["update_source"] = command.replace("update-source ", "").strip()
                elif command == "route-reflector-client":
                    pg_data["route_reflector_client"] = True
                elif command.startswith("send-community"):
                    if "both" in command:
                        pg_data["send_community"] = "both"
                    elif "extended" in command:
                        pg_data["send_community"] = "extended"
                    else:
                        pg_data["send_community"] = True

            peer_groups.append(BGPPeerGroup(**pg_data))

        return peer_groups

    def _parse_ospf_areas(self, ospf_obj) -> list[OSPFArea]:
        """Parse OSPF area configurations."""
        areas = []
        area_children = ospf_obj.re_search_children(r"^\s+area\s+(\S+)")

        # Group by area ID
        area_dict: dict[str, dict] = {}

        for area_child in area_children:
            match = re.search(r"^\s+area\s+(\S+)\s+(.+)", area_child.text)
            if not match:
                continue

            area_id = match.group(1)
            command = match.group(2)

            if area_id not in area_dict:
                area_dict[area_id] = {
                    "area_id": area_id,
                    "area_type": OSPFAreaType.NORMAL,
                    "stub_no_summary": False,
                    "nssa_no_summary": False,
                    "authentication": None,
                    "ranges": [],
                }

            if "nssa" in command:
                if "no-summary" in command:
                    area_dict[area_id]["area_type"] = OSPFAreaType.TOTALLY_NSSA
                    area_dict[area_id]["nssa_no_summary"] = True
                else:
                    area_dict[area_id]["area_type"] = OSPFAreaType.NSSA
            elif "stub" in command:
                if "no-summary" in command:
                    area_dict[area_id]["area_type"] = OSPFAreaType.TOTALLY_STUB
                    area_dict[area_id]["stub_no_summary"] = True
                else:
                    area_dict[area_id]["area_type"] = OSPFAreaType.STUB
            elif "authentication" in command:
                if "message-digest" in command:
                    area_dict[area_id]["authentication"] = "message-digest"
                else:
                    area_dict[area_id]["authentication"] = "simple"
            elif "range" in command:
                range_match = re.search(r"range\s+(\S+)\s+(\S+)", command)
                if range_match:
                    try:
                        prefix = IPv4Network(f"{range_match.group(1)}/{range_match.group(2)}")
                        area_dict[area_id]["ranges"].append(
                            OSPFRange(prefix=prefix, advertise=True)
                        )
                    except ValueError:
                        pass

        # Create OSPFArea objects
        for area_data in area_dict.values():
            areas.append(OSPFArea(**area_data))

        return areas

    def _parse_ospf_redistribute(self, ospf_obj) -> list[OSPFRedistribute]:
        """Parse OSPF redistribution configurations."""
        redistribute = []
        redist_children = ospf_obj.re_search_children(r"^\s+redistribute\s+(\S+)")

        for redist_child in redist_children:
            match = re.search(r"^\s+redistribute\s+(\S+)(.+)?", redist_child.text)
            if not match:
                continue

            protocol = match.group(1)
            remaining = match.group(2).strip() if match.group(2) else ""

            process_id = None
            route_map = None
            metric = None
            metric_type = None
            subnets = "subnets" in remaining

            # Extract process ID for BGP/OSPF
            process_match = re.search(r"(\d+)", remaining)
            if process_match:
                process_id = int(process_match.group(1))

            # Extract route-map
            rm_match = re.search(r"route-map\s+(\S+)", remaining)
            if rm_match:
                route_map = rm_match.group(1)

            # Extract metric
            metric_match = re.search(r"metric\s+(\d+)", remaining)
            if metric_match:
                metric = int(metric_match.group(1))

            # Extract metric-type
            if "metric-type 1" in remaining or "metric-type type-1" in remaining:
                metric_type = 1
            elif "metric-type 2" in remaining or "metric-type type-2" in remaining:
                metric_type = 2

            redistribute.append(
                OSPFRedistribute(
                    protocol=protocol,
                    process_id=process_id,
                    route_map=route_map,
                    metric=metric,
                    metric_type=metric_type,
                    subnets=subnets,
                )
            )

        return redistribute

    def _parse_bgp_address_families(self, bgp_obj) -> list[BGPAddressFamily]:
        """Parse BGP address-families (global, non-VRF)."""
        address_families = []

        # Find address-family blocks (not VRF-specific)
        af_children = bgp_obj.re_search_children(r"^\s+address-family\s+(ipv4|ipv6)\s*$")

        for af_child in af_children:
            match = re.search(r"^\s+address-family\s+(ipv4|ipv6)\s*$", af_child.text)
            if not match:
                continue

            afi = match.group(1)
            safi = "unicast"  # Default SAFI

            # Parse networks within this AF
            networks = []
            network_children = af_child.re_search_children(r"^\s+network\s+")
            for net_child in network_children:
                net_match = re.search(
                    r"^\s+network\s+(\S+)(?:\s+mask\s+(\S+))?", net_child.text
                )
                if net_match:
                    prefix_str = net_match.group(1)
                    mask_str = net_match.group(2)

                    try:
                        if mask_str:
                            # IOS style: network 10.0.0.0 mask 255.255.0.0
                            prefix = IPv4Network(f"{prefix_str}/{mask_str}", strict=False)
                        else:
                            # Classless: network 192.168.1.0/24
                            prefix = IPv4Network(prefix_str, strict=False) if afi == "ipv4" else IPv6Network(prefix_str, strict=False)

                        networks.append(BGPNetwork(prefix=prefix))
                    except ValueError:
                        pass

            # Parse redistribution
            redistribute = []
            redist_children = af_child.re_search_children(r"^\s+redistribute\s+(\S+)")
            for redist_child in redist_children:
                match = re.search(r"^\s+redistribute\s+(\S+)(.+)?", redist_child.text)
                if match:
                    protocol = match.group(1)
                    remaining = match.group(2).strip() if match.group(2) else ""

                    process_id = None
                    route_map = None
                    metric = None

                    # Extract process ID
                    pid_match = re.search(r"(\d+)", remaining)
                    if pid_match:
                        process_id = int(pid_match.group(1))

                    # Extract route-map
                    rm_match = re.search(r"route-map\s+(\S+)", remaining)
                    if rm_match:
                        route_map = rm_match.group(1)

                    # Extract metric
                    metric_match = re.search(r"metric\s+(\d+)", remaining)
                    if metric_match:
                        metric = int(metric_match.group(1))

                    redistribute.append(
                        BGPRedistribute(
                            protocol=protocol,
                            process_id=process_id,
                            route_map=route_map,
                            metric=metric,
                        )
                    )

            # Parse aggregates
            aggregates = []
            agg_children = af_child.re_search_children(r"^\s+aggregate-address\s+(\S+)")
            for agg_child in agg_children:
                match = re.search(
                    r"^\s+aggregate-address\s+(\S+)(?:\s+(\S+))?(.+)?",
                    agg_child.text,
                )
                if match:
                    prefix_str = match.group(1)
                    mask_or_len = match.group(2)
                    remaining = match.group(3).strip() if match.group(3) else ""

                    try:
                        if mask_or_len and "." in mask_or_len:
                            # IOS style with mask
                            prefix = IPv4Network(f"{prefix_str}/{mask_or_len}", strict=False)
                        else:
                            prefix = IPv4Network(prefix_str, strict=False)

                        summary_only = "summary-only" in remaining
                        as_set = "as-set" in remaining

                        aggregates.append(
                            BGPAggregate(
                                prefix=prefix,
                                summary_only=summary_only,
                                as_set=as_set,
                            )
                        )
                    except ValueError:
                        pass

            address_families.append(
                BGPAddressFamily(
                    afi=afi,
                    safi=safi,
                    vrf=None,
                    networks=networks,
                    redistribute=redistribute,
                    aggregate_addresses=aggregates,
                )
            )

        return address_families

    def _apply_bgp_af_neighbor_policies(
        self,
        bgp_obj,
        neighbors: list,
    ) -> None:
        """Populate neighbor.address_families from per-neighbor policy in AF blocks.

        In EOS (and some IOS-XE configs), neighbor policy like route-map/prefix-list
        assignments live inside ``address-family`` blocks rather than at the global
        neighbor level.  This method parses those AF-block ``neighbor`` lines and
        appends a BGPNeighborAF entry to each matching neighbor.

        Modifies *neighbors* in-place.
        """
        # Build a lookup: peer_ip_str → BGPNeighbor
        nb_index = {str(nb.peer_ip): nb for nb in neighbors}

        # Find all non-VRF AF blocks inside this router bgp
        af_children = bgp_obj.re_search_children(r"^\s+address-family\s+(ipv4|ipv6)\s*$")

        for af_child in af_children:
            m = re.search(r"^\s+address-family\s+(ipv4|ipv6)\s*$", af_child.text)
            if not m:
                continue
            afi = m.group(1)
            safi = "unicast"

            # Collect per-neighbor settings from this AF block
            af_nb_data: dict[str, dict] = {}
            nb_lines = af_child.re_search_children(r"^\s+neighbor\s+(\S+)\s+")
            for child in nb_lines:
                nm = re.search(r"^\s+neighbor\s+(\S+)\s+(.+)", child.text)
                if not nm:
                    continue
                peer_str = nm.group(1)
                cmd = nm.group(2).strip()

                if peer_str not in af_nb_data:
                    af_nb_data[peer_str] = {
                        "activate": False,
                        "route_map_in": None,
                        "route_map_out": None,
                        "prefix_list_in": None,
                        "prefix_list_out": None,
                        "filter_list_in": None,
                        "filter_list_out": None,
                        "default_originate_route_map": None,
                    }

                if cmd == "activate":
                    af_nb_data[peer_str]["activate"] = True
                elif cmd.startswith("route-map ") and cmd.endswith(" in"):
                    af_nb_data[peer_str]["route_map_in"] = cmd[len("route-map "):-3].strip()
                elif cmd.startswith("route-map ") and cmd.endswith(" out"):
                    af_nb_data[peer_str]["route_map_out"] = cmd[len("route-map "):-4].strip()
                elif cmd.startswith("prefix-list ") and cmd.endswith(" in"):
                    af_nb_data[peer_str]["prefix_list_in"] = cmd[len("prefix-list "):-3].strip()
                elif cmd.startswith("prefix-list ") and cmd.endswith(" out"):
                    af_nb_data[peer_str]["prefix_list_out"] = cmd[len("prefix-list "):-4].strip()
                elif cmd.startswith("filter-list ") and cmd.endswith(" in"):
                    af_nb_data[peer_str]["filter_list_in"] = cmd[len("filter-list "):-3].strip()
                elif cmd.startswith("filter-list ") and cmd.endswith(" out"):
                    af_nb_data[peer_str]["filter_list_out"] = cmd[len("filter-list "):-4].strip()
                elif cmd.startswith("default-originate"):
                    rm_m = re.search(r"route-map\s+(\S+)", cmd)
                    if rm_m:
                        af_nb_data[peer_str]["default_originate_route_map"] = rm_m.group(1)

            # Attach BGPNeighborAF to matching neighbors
            for peer_str, data in af_nb_data.items():
                nb = nb_index.get(peer_str)
                if nb is None:
                    continue
                # Only attach if there is at least one policy field set
                if any(v for v in data.values() if v):
                    nb.address_families.append(
                        BGPNeighborAF(
                            afi=afi,
                            safi=safi,
                            activate=data["activate"],
                            route_map_in=data["route_map_in"],
                            route_map_out=data["route_map_out"],
                            prefix_list_in=data["prefix_list_in"],
                            prefix_list_out=data["prefix_list_out"],
                            filter_list_in=data["filter_list_in"],
                            filter_list_out=data["filter_list_out"],
                            default_originate_route_map=data["default_originate_route_map"],
                        )
                    )

    def _parse_bgp_networks(self, bgp_obj, vrf: str | None) -> list[BGPNetwork]:
        """Parse BGP network statements at global level (not in address-family)."""
        networks = []
        # Global network statements (outside address-family blocks)
        # These are rare in modern configs but supported
        return networks

    def _parse_bgp_redistribute(self, bgp_obj, vrf: str | None) -> list[BGPRedistribute]:
        """Parse BGP redistribute statements at global level."""
        redistribute = []
        # Global redistribute statements (outside address-family blocks)
        return redistribute

    def _parse_bgp_vrf_instances(self, bgp_obj, asn: int) -> list[BGPConfig]:
        """Parse VRF-specific BGP instances from address-family ipv4 vrf blocks."""
        vrf_instances = []

        # Find VRF address-family blocks
        vrf_af_children = bgp_obj.re_search_children(
            r"^\s+address-family\s+ipv4\s+vrf\s+(\S+)"
        )

        for vrf_af_child in vrf_af_children:
            match = re.search(
                r"^\s+address-family\s+ipv4\s+vrf\s+(\S+)",
                vrf_af_child.text,
            )
            if not match:
                continue

            vrf_name = match.group(1)
            raw_lines, line_numbers = self._get_raw_lines_and_line_numbers(vrf_af_child)

            # Parse VRF-specific neighbors
            vrf_neighbors = []
            neighbor_children = vrf_af_child.re_search_children(r"^\s+neighbor\s+(\S+)\s+")

            neighbor_dict: dict[str, dict] = {}
            for neighbor_child in neighbor_children:
                n_match = re.search(r"^\s+neighbor\s+(\S+)\s+(.+)", neighbor_child.text)
                if not n_match:
                    continue

                peer_ip_str = n_match.group(1)
                command = n_match.group(2)

                if peer_ip_str not in neighbor_dict:
                    neighbor_dict[peer_ip_str] = {
                        "peer_ip": peer_ip_str,
                        "remote_as": None,
                        "description": None,
                        "route_map_in": None,
                        "route_map_out": None,
                    }

                if command.startswith("remote-as "):
                    as_str = command.replace("remote-as ", "").strip()
                    try:
                        neighbor_dict[peer_ip_str]["remote_as"] = int(as_str)
                    except ValueError:
                        neighbor_dict[peer_ip_str]["remote_as"] = as_str
                elif command.startswith("description "):
                    neighbor_dict[peer_ip_str]["description"] = command.replace(
                        "description ", ""
                    ).strip()
                elif command.startswith("route-map ") and " in" in command:
                    rm_name = command.replace("route-map ", "").replace(" in", "").strip()
                    neighbor_dict[peer_ip_str]["route_map_in"] = rm_name
                elif command.startswith("route-map ") and " out" in command:
                    rm_name = command.replace("route-map ", "").replace(" out", "").strip()
                    neighbor_dict[peer_ip_str]["route_map_out"] = rm_name

            # Create VRF neighbor objects
            for peer_ip_str, neighbor_data in neighbor_dict.items():
                try:
                    peer_ip = IPv4Address(peer_ip_str)
                except ValueError:
                    try:
                        peer_ip = IPv6Address(peer_ip_str)
                    except ValueError:
                        continue

                if neighbor_data["remote_as"] is None:
                    continue

                vrf_neighbors.append(
                    BGPNeighbor(
                        peer_ip=peer_ip,
                        remote_as=neighbor_data["remote_as"],
                        description=neighbor_data["description"],
                        route_map_in=neighbor_data["route_map_in"],
                        route_map_out=neighbor_data["route_map_out"],
                    )
                )

            # Parse redistribution in VRF
            redistribute = []
            redist_children = vrf_af_child.re_search_children(r"^\s+redistribute\s+(\S+)")
            for redist_child in redist_children:
                match = re.search(r"^\s+redistribute\s+(\S+)(.+)?", redist_child.text)
                if match:
                    protocol = match.group(1)
                    remaining = match.group(2).strip() if match.group(2) else ""

                    process_id = None
                    route_map = None

                    # Extract process ID
                    pid_match = re.search(r"(\d+)", remaining)
                    if pid_match:
                        process_id = int(pid_match.group(1))

                    # Extract route-map
                    rm_match = re.search(r"route-map\s+(\S+)", remaining)
                    if rm_match:
                        route_map = rm_match.group(1)

                    redistribute.append(
                        BGPRedistribute(
                            protocol=protocol,
                            process_id=process_id,
                            route_map=route_map,
                        )
                    )

            # Create VRF BGP instance
            vrf_instances.append(
                BGPConfig(
                    object_id=f"bgp_{asn}_vrf_{vrf_name}",
                    raw_lines=raw_lines,
                    source_os=self.os_type,
                    line_numbers=line_numbers,
                    asn=asn,
                    router_id=None,  # VRF-specific router-id would be parsed here
                    vrf=vrf_name,
                    log_neighbor_changes=False,
                    bestpath_options=BGPBestpathOptions(),
                    neighbors=vrf_neighbors,
                    peer_groups=[],
                    address_families=[],
                    redistribute=redistribute,
                )
            )

        return vrf_instances

    def parse_static_routes(self) -> list[StaticRoute]:
        """Parse static route configurations."""
        static_routes = []
        parse = self._get_parse_obj()

        # Find all ip route statements
        route_objs = parse.find_objects(r"^ip\s+route\s+")

        for route_obj in route_objs:
            raw_lines, line_numbers = self._get_raw_lines_and_line_numbers(route_obj)

            # Parse: ip route [vrf NAME] destination mask next-hop [distance] [tag TAG] [name NAME] [permanent] [track TRACK]
            match = re.search(
                r"^ip\s+route\s+(?:vrf\s+(\S+)\s+)?(\S+)\s+(\S+)\s+(\S+)(.*)$",
                route_obj.text,
            )
            if not match:
                continue

            vrf = match.group(1)
            dest_str = match.group(2)
            mask_str = match.group(3)
            next_hop_str = match.group(4)
            remaining = match.group(5).strip() if match.group(5) else ""

            # Parse destination
            try:
                destination = IPv4Network(f"{dest_str}/{mask_str}", strict=False)
            except ValueError:
                continue

            # Parse next-hop (can be IP address or interface like "Null0")
            next_hop = None
            next_hop_interface = None
            try:
                next_hop = IPv4Address(next_hop_str)
            except ValueError:
                # It's an interface name
                next_hop_interface = next_hop_str

            # Parse optional parameters
            distance = 1  # Default administrative distance
            tag = None
            name = None
            permanent = False
            track = None

            # Extract distance (first number in remaining if not after a keyword)
            parts = remaining.split()
            if parts and parts[0].isdigit():
                distance = int(parts[0])
                remaining = " ".join(parts[1:])

            # Extract tag
            tag_match = re.search(r"tag\s+(\d+)", remaining)
            if tag_match:
                tag = int(tag_match.group(1))

            # Extract name
            name_match = re.search(r"name\s+(\S+)", remaining)
            if name_match:
                name = name_match.group(1)

            # Extract permanent
            if "permanent" in remaining:
                permanent = True

            # Extract track
            track_match = re.search(r"track\s+(\d+)", remaining)
            if track_match:
                track = int(track_match.group(1))

            static_routes.append(
                StaticRoute(
                    object_id=f"static_route_{destination}_{next_hop_str}",
                    raw_lines=raw_lines,
                    source_os=self.os_type,
                    line_numbers=line_numbers,
                    destination=destination,
                    next_hop=next_hop,
                    next_hop_interface=next_hop_interface,
                    distance=distance,
                    tag=tag,
                    name=name,
                    permanent=permanent,
                    track=track,
                    vrf=vrf,
                )
            )

        return static_routes

    def parse_acls(self) -> list[ACLConfig]:
        """Parse ACL configurations."""
        acls = []
        parse = self._get_parse_obj()

        # Find all ACL definitions (named ACLs)
        acl_objs = parse.find_objects(r"^ip\s+access-list\s+(standard|extended)\s+(\S+)")

        for acl_obj in acl_objs:
            match = re.search(
                r"^ip\s+access-list\s+(standard|extended)\s+(\S+)",
                acl_obj.text,
            )
            if not match:
                continue

            acl_type = match.group(1)
            acl_name = match.group(2)

            raw_lines, line_numbers = self._get_raw_lines_and_line_numbers(acl_obj)

            # Parse entries
            entries = []
            entry_children = acl_obj.children

            for entry_child in entry_children:
                entry_text = entry_child.text.strip()

                # Handle remark
                if entry_text.startswith("remark "):
                    remark = entry_text.replace("remark ", "").strip()
                    entries.append(
                        ACLEntry(
                            action="remark",
                            remark=remark,
                        )
                    )
                    continue

                # Parse standard ACL entry: [seq] (permit|deny) source [wildcard] [log]
                # Parse extended ACL entry: [seq] (permit|deny) protocol source [port] dest [port] [flags]
                parts = entry_text.split()
                if len(parts) < 2:
                    continue

                # Check if first part is sequence number
                sequence = None
                if parts[0].isdigit():
                    sequence = int(parts[0])
                    parts = parts[1:]

                if len(parts) < 2:
                    continue

                action = parts[0]  # permit or deny
                if action not in ["permit", "deny"]:
                    continue

                if acl_type == "standard":
                    # Standard ACL: permit/deny source [wildcard]
                    source = parts[1] if len(parts) > 1 else None
                    source_wildcard = None

                    if source == "host":
                        source = parts[2] if len(parts) > 2 else None
                        source_wildcard = None
                    elif source == "any":
                        source_wildcard = None
                    elif len(parts) > 2 and not parts[2] in ["log"]:
                        source_wildcard = parts[2]

                    flags = []
                    if "log" in entry_text:
                        flags.append("log")

                    entries.append(
                        ACLEntry(
                            sequence=sequence,
                            action=action,
                            source=source,
                            source_wildcard=source_wildcard,
                            flags=flags,
                        )
                    )

                elif acl_type == "extended":
                    # Extended ACL: permit/deny protocol source [port] dest [port] [flags]
                    protocol = parts[1] if len(parts) > 1 else None
                    remaining_parts = parts[2:]

                    # Parse source
                    source = None
                    source_wildcard = None
                    source_port = None
                    idx = 0

                    if idx < len(remaining_parts):
                        if remaining_parts[idx] == "host":
                            idx += 1
                            source = remaining_parts[idx] if idx < len(remaining_parts) else None
                            idx += 1
                        elif remaining_parts[idx] == "any":
                            source = "any"
                            idx += 1
                        else:
                            source = remaining_parts[idx]
                            idx += 1
                            if idx < len(remaining_parts) and not remaining_parts[idx] in ["eq", "range", "gt", "lt", "host", "any"]:
                                source_wildcard = remaining_parts[idx]
                                idx += 1

                    # Parse source port
                    if idx < len(remaining_parts) and remaining_parts[idx] in ["eq", "range", "gt", "lt"]:
                        port_op = remaining_parts[idx]
                        idx += 1
                        if port_op == "range" and idx + 1 < len(remaining_parts):
                            source_port = f"{port_op} {remaining_parts[idx]} {remaining_parts[idx + 1]}"
                            idx += 2
                        elif idx < len(remaining_parts):
                            source_port = f"{port_op} {remaining_parts[idx]}"
                            idx += 1

                    # Parse destination
                    destination = None
                    destination_wildcard = None
                    destination_port = None

                    if idx < len(remaining_parts):
                        if remaining_parts[idx] == "host":
                            idx += 1
                            destination = remaining_parts[idx] if idx < len(remaining_parts) else None
                            idx += 1
                        elif remaining_parts[idx] == "any":
                            destination = "any"
                            idx += 1
                        else:
                            destination = remaining_parts[idx]
                            idx += 1
                            if idx < len(remaining_parts) and not remaining_parts[idx] in ["eq", "range", "gt", "lt"]:
                                destination_wildcard = remaining_parts[idx]
                                idx += 1

                    # Parse destination port
                    if idx < len(remaining_parts) and remaining_parts[idx] in ["eq", "range", "gt", "lt"]:
                        port_op = remaining_parts[idx]
                        idx += 1
                        if port_op == "range" and idx + 1 < len(remaining_parts):
                            destination_port = f"{port_op} {remaining_parts[idx]} {remaining_parts[idx + 1]}"
                            idx += 2
                        elif idx < len(remaining_parts):
                            destination_port = f"{port_op} {remaining_parts[idx]}"
                            idx += 1

                    # Parse flags
                    flags = []
                    while idx < len(remaining_parts):
                        flags.append(remaining_parts[idx])
                        idx += 1

                    entries.append(
                        ACLEntry(
                            sequence=sequence,
                            action=action,
                            protocol=protocol,
                            source=source,
                            source_wildcard=source_wildcard,
                            source_port=source_port,
                            destination=destination,
                            destination_wildcard=destination_wildcard,
                            destination_port=destination_port,
                            flags=flags,
                        )
                    )

            acls.append(
                ACLConfig(
                    object_id=f"acl_{acl_name}",
                    raw_lines=raw_lines,
                    source_os=self.os_type,
                    line_numbers=line_numbers,
                    name=acl_name,
                    acl_type=acl_type,
                    entries=entries,
                )
            )

        # TODO: Add support for numbered ACLs (1-99, 100-199, etc.)

        return acls

    def parse_community_lists(self) -> list[CommunityListConfig]:
        """Parse BGP community-list configurations."""
        community_lists = []
        parse = self._get_parse_obj()

        # Find all community-list entries
        cl_objs = parse.find_objects(
            r"^ip\s+community-list\s+(standard|expanded)\s+(\S+)\s+(permit|deny)\s+"
        )

        # Group by community-list name
        cl_dict: dict[str, dict] = {}

        for cl_obj in cl_objs:
            match = re.search(
                r"^ip\s+community-list\s+(standard|expanded)\s+(\S+)\s+(permit|deny)\s+(.+)$",
                cl_obj.text,
            )
            if not match:
                continue

            list_type = match.group(1)
            cl_name = match.group(2)
            action = match.group(3)
            communities_str = match.group(4).strip()

            if cl_name not in cl_dict:
                cl_dict[cl_name] = {
                    "name": cl_name,
                    "list_type": list_type,
                    "entries": [],
                    "raw_lines": [],
                    "line_numbers": [],
                }

            raw_lines, line_numbers = self._get_raw_lines_and_line_numbers(cl_obj)
            cl_dict[cl_name]["raw_lines"].extend(raw_lines)
            cl_dict[cl_name]["line_numbers"].extend(line_numbers)

            # Parse communities (space-separated)
            communities = communities_str.split()

            cl_dict[cl_name]["entries"].append(
                CommunityListEntry(
                    action=action,
                    communities=communities,
                )
            )

        # Create CommunityListConfig objects
        for cl_data in cl_dict.values():
            community_lists.append(
                CommunityListConfig(
                    object_id=f"community_list_{cl_data['name']}",
                    raw_lines=cl_data["raw_lines"],
                    source_os=self.os_type,
                    line_numbers=cl_data["line_numbers"],
                    name=cl_data["name"],
                    list_type=cl_data["list_type"],
                    entries=cl_data["entries"],
                )
            )

        return community_lists

    def parse_as_path_lists(self) -> list[ASPathListConfig]:
        """Parse BGP AS-path access-list configurations."""
        as_path_lists = []
        parse = self._get_parse_obj()

        # Find all AS-path access-list entries
        aspath_objs = parse.find_objects(
            r"^ip\s+as-path\s+access-list\s+(\S+)\s+(permit|deny)\s+"
        )

        # Group by list name/number
        aspath_dict: dict[str, dict] = {}

        for aspath_obj in aspath_objs:
            match = re.search(
                r"^ip\s+as-path\s+access-list\s+(\S+)\s+(permit|deny)\s+(.+)$",
                aspath_obj.text,
            )
            if not match:
                continue

            list_name = match.group(1)
            action = match.group(2)
            regex = match.group(3).strip()

            if list_name not in aspath_dict:
                aspath_dict[list_name] = {
                    "name": list_name,
                    "entries": [],
                    "raw_lines": [],
                    "line_numbers": [],
                }

            raw_lines, line_numbers = self._get_raw_lines_and_line_numbers(aspath_obj)
            aspath_dict[list_name]["raw_lines"].extend(raw_lines)
            aspath_dict[list_name]["line_numbers"].extend(line_numbers)

            aspath_dict[list_name]["entries"].append(
                ASPathListEntry(
                    action=action,
                    regex=regex,
                )
            )

        # Create ASPathListConfig objects
        for aspath_data in aspath_dict.values():
            as_path_lists.append(
                ASPathListConfig(
                    object_id=f"as_path_list_{aspath_data['name']}",
                    raw_lines=aspath_data["raw_lines"],
                    source_os=self.os_type,
                    line_numbers=aspath_data["line_numbers"],
                    name=aspath_data["name"],
                    entries=aspath_data["entries"],
                )
            )

        return as_path_lists

    def parse_isis(self) -> list[ISISConfig]:
        """Parse IS-IS configurations."""
        isis_instances = []
        parse = self._get_parse_obj()

        # Find all IS-IS router configs
        isis_objs = parse.find_objects(r"^router\s+isis\s*(\S*)")

        for isis_obj in isis_objs:
            match = re.search(r"^router\s+isis\s*(\S*)$", isis_obj.text)
            if match:
                tag = match.group(1) if match.group(1) else None
            else:
                tag = None

            raw_lines, line_numbers = self._get_raw_lines_and_line_numbers(isis_obj)

            # NET addresses
            net = []
            net_children = isis_obj.re_search_children(r"^\s+net\s+(\S+)")
            for net_child in net_children:
                net_addr = self._extract_match(net_child.text, r"^\s+net\s+(\S+)")
                if net_addr:
                    net.append(net_addr)

            # IS type
            is_type = None
            is_type_children = isis_obj.re_search_children(r"^\s+is-type\s+(\S+)")
            if is_type_children:
                is_type = self._extract_match(is_type_children[0].text, r"^\s+is-type\s+(\S+)")

            # Metric style
            metric_style = None
            metric_children = isis_obj.re_search_children(r"^\s+metric-style\s+(\S+)")
            if metric_children:
                metric_style = self._extract_match(metric_children[0].text, r"^\s+metric-style\s+(\S+)")

            # Log adjacency changes
            log_adjacency_changes = len(isis_obj.re_search_children(r"^\s+log-adjacency-changes")) > 0

            # Passive interface default
            passive_interface_default = len(
                isis_obj.re_search_children(r"^\s+passive-interface\s+default")
            ) > 0

            # Passive interfaces
            passive_interfaces = []
            passive_intf_children = isis_obj.re_search_children(r"^\s+passive-interface\s+(\S+)")
            for passive_child in passive_intf_children:
                if "default" not in passive_child.text:
                    intf_name = self._extract_match(passive_child.text, r"^\s+passive-interface\s+(\S+)")
                    if intf_name:
                        passive_interfaces.append(intf_name)

            # Non-passive interfaces
            non_passive_interfaces = []
            non_passive_children = isis_obj.re_search_children(r"^\s+no\s+passive-interface\s+(\S+)")
            for non_passive_child in non_passive_children:
                intf_name = self._extract_match(non_passive_child.text, r"^\s+no\s+passive-interface\s+(\S+)")
                if intf_name:
                    non_passive_interfaces.append(intf_name)

            # Parse redistribution
            redistribute = []
            redist_children = isis_obj.re_search_children(r"^\s+redistribute\s+(\S+)")
            for redist_child in redist_children:
                match = re.search(r"^\s+redistribute\s+(\S+)(.+)?", redist_child.text)
                if match:
                    protocol = match.group(1)
                    remaining = match.group(2).strip() if match.group(2) else ""

                    process_id = None
                    route_map = None
                    metric = None
                    metric_type = None
                    level = None

                    # Extract process ID
                    pid_match = re.search(r"(\d+)", remaining)
                    if pid_match:
                        process_id = int(pid_match.group(1))

                    # Extract route-map
                    rm_match = re.search(r"route-map\s+(\S+)", remaining)
                    if rm_match:
                        route_map = rm_match.group(1)

                    # Extract metric
                    metric_match = re.search(r"metric\s+(\d+)", remaining)
                    if metric_match:
                        metric = int(metric_match.group(1))

                    # Extract metric-type
                    if "metric-type internal" in remaining:
                        metric_type = "internal"
                    elif "metric-type external" in remaining:
                        metric_type = "external"

                    # Extract level
                    if "level-1" in remaining:
                        level = "level-1"
                    elif "level-2" in remaining:
                        level = "level-2"
                    elif "level-1-2" in remaining:
                        level = "level-1-2"

                    redistribute.append(
                        ISISRedistribute(
                            protocol=protocol,
                            process_id=process_id,
                            route_map=route_map,
                            metric=metric,
                            metric_type=metric_type,
                            level=level,
                        )
                    )

            # Authentication
            authentication_mode = None
            authentication_key = None
            auth_children = isis_obj.re_search_children(r"^\s+authentication\s+mode\s+(\S+)")
            if auth_children:
                authentication_mode = self._extract_match(auth_children[0].text, r"^\s+authentication\s+mode\s+(\S+)")

            auth_key_children = isis_obj.re_search_children(r"^\s+authentication\s+key\s+(\S+)")
            if auth_key_children:
                authentication_key = self._extract_match(auth_key_children[0].text, r"^\s+authentication\s+key\s+(\S+)")

            # Timers
            max_lsp_lifetime = None
            lsp_lifetime_children = isis_obj.re_search_children(r"^\s+max-lsp-lifetime\s+(\d+)")
            if lsp_lifetime_children:
                max_lsp_lifetime = int(self._extract_match(lsp_lifetime_children[0].text, r"^\s+max-lsp-lifetime\s+(\d+)"))

            lsp_refresh_interval = None
            lsp_refresh_children = isis_obj.re_search_children(r"^\s+lsp-refresh-interval\s+(\d+)")
            if lsp_refresh_children:
                lsp_refresh_interval = int(self._extract_match(lsp_refresh_children[0].text, r"^\s+lsp-refresh-interval\s+(\d+)"))

            spf_interval = None
            spf_children = isis_obj.re_search_children(r"^\s+spf-interval\s+(\d+)")
            if spf_children:
                spf_interval = int(self._extract_match(spf_children[0].text, r"^\s+spf-interval\s+(\d+)"))

            isis_instances.append(
                ISISConfig(
                    object_id=f"isis_{tag if tag else 'default'}",
                    raw_lines=raw_lines,
                    source_os=self.os_type,
                    line_numbers=line_numbers,
                    tag=tag,
                    net=net,
                    is_type=is_type,
                    metric_style=metric_style,
                    log_adjacency_changes=log_adjacency_changes,
                    passive_interface_default=passive_interface_default,
                    passive_interfaces=passive_interfaces,
                    non_passive_interfaces=non_passive_interfaces,
                    redistribute=redistribute,
                    authentication_mode=authentication_mode,
                    authentication_key=authentication_key,
                    max_lsp_lifetime=max_lsp_lifetime,
                    lsp_refresh_interval=lsp_refresh_interval,
                    spf_interval=spf_interval,
                )
            )

        return isis_instances

    # -------------------------------------------------------------------------
    # EIGRP
    # -------------------------------------------------------------------------

    def parse_eigrp(self) -> list[EIGRPConfig]:
        """Parse EIGRP configurations."""
        parse = self._get_parse_obj()
        eigrp_instances = []

        for eigrp_obj in parse.find_objects(r"^router\s+eigrp\s+"):
            m = re.match(r"^router\s+eigrp\s+(\S+)", eigrp_obj.text)
            if not m:
                continue
            as_number_str = m.group(1)
            try:
                as_number = int(as_number_str)
            except ValueError:
                as_number = as_number_str

            raw_lines, line_numbers = self._get_raw_lines_and_line_numbers(eigrp_obj)

            # router-id
            router_id = None
            rid_ch = eigrp_obj.re_search_children(r"^\s+eigrp\s+router-id\s+(\S+)")
            if rid_ch:
                v = self._extract_match(rid_ch[0].text, r"^\s+eigrp\s+router-id\s+(\S+)")
                if v:
                    try:
                        from ipaddress import IPv4Address
                        router_id = IPv4Address(v)
                    except Exception:
                        pass

            # networks
            networks = []
            for nc in eigrp_obj.re_search_children(r"^\s+network\s+"):
                nm = re.match(r"^\s+network\s+(\S+)(?:\s+(\S+))?", nc.text)
                if nm:
                    try:
                        from ipaddress import IPv4Network, IPv4Address
                        net_addr = nm.group(1)
                        wildcard = nm.group(2)
                        if wildcard:
                            # convert wildcard to prefix for IPv4Network
                            wild_parts = wildcard.split(".")
                            mask_parts = [str(255 - int(p)) for p in wild_parts]
                            prefix = ".".join(mask_parts)
                            net = IPv4Network(f"{net_addr}/{prefix}", strict=False)
                        else:
                            net = IPv4Network(net_addr, strict=False)
                        from confgraph.models.eigrp import EIGRPNetwork
                        networks.append(EIGRPNetwork(network=net, wildcard=wildcard))
                    except Exception:
                        pass

            # passive-interface
            passive_default = bool(eigrp_obj.re_search_children(r"^\s+passive-interface\s+default"))
            passive_ifs = []
            non_passive_ifs = []
            for pic in eigrp_obj.re_search_children(r"^\s+(?:no\s+)?passive-interface\s+\S"):
                pim = re.match(r"^\s+(no\s+)?passive-interface\s+(\S+)", pic.text)
                if pim:
                    intf_name = pim.group(2)
                    if intf_name == "default":
                        continue
                    if pim.group(1):
                        non_passive_ifs.append(intf_name)
                    else:
                        passive_ifs.append(intf_name)

            # redistribute
            redistribute = []
            for rc in eigrp_obj.re_search_children(r"^\s+redistribute\s+"):
                rm = re.match(r"^\s+redistribute\s+(\S+)(?:\s+(\S+))?", rc.text)
                if rm:
                    proto = rm.group(1)
                    pid = rm.group(2)
                    route_map = self._extract_match(rc.text, r"\broute-map\s+(\S+)")
                    tag = None
                    tm = re.search(r"\btag\s+(\d+)", rc.text)
                    if tm:
                        tag = int(tm.group(1))
                    # metric bw delay reliability load mtu
                    metric = None
                    mm = re.search(r"\bmetric\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)", rc.text)
                    if mm:
                        from confgraph.models.eigrp import EIGRPMetric
                        metric = EIGRPMetric(
                            bandwidth=int(mm.group(1)), delay=int(mm.group(2)),
                            reliability=int(mm.group(3)), load=int(mm.group(4)), mtu=int(mm.group(5))
                        )
                    from confgraph.models.eigrp import EIGRPRedistribute
                    redistribute.append(EIGRPRedistribute(
                        protocol=proto, process_id=pid, metric=metric, route_map=route_map, tag=tag
                    ))

            # misc
            auto_summary = bool(eigrp_obj.re_search_children(r"^\s+auto-summary"))
            variance = None
            vc = eigrp_obj.re_search_children(r"^\s+variance\s+(\d+)")
            if vc:
                v = self._extract_match(vc[0].text, r"^\s+variance\s+(\d+)")
                if v:
                    variance = int(v)

            maximum_paths = None
            mpc = eigrp_obj.re_search_children(r"^\s+maximum-paths\s+(\d+)")
            if mpc:
                v = self._extract_match(mpc[0].text, r"^\s+maximum-paths\s+(\d+)")
                if v:
                    maximum_paths = int(v)

            distance_internal = distance_external = None
            dc = eigrp_obj.re_search_children(r"^\s+distance\s+eigrp\s+(\d+)\s+(\d+)")
            if dc:
                dm = re.match(r"^\s+distance\s+eigrp\s+(\d+)\s+(\d+)", dc[0].text)
                if dm:
                    distance_internal = int(dm.group(1))
                    distance_external = int(dm.group(2))

            default_metric = None
            dmc = eigrp_obj.re_search_children(r"^\s+default-metric\s+")
            if dmc:
                dmm = re.search(r"\bdefault-metric\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)", dmc[0].text)
                if dmm:
                    from confgraph.models.eigrp import EIGRPMetric
                    default_metric = EIGRPMetric(
                        bandwidth=int(dmm.group(1)), delay=int(dmm.group(2)),
                        reliability=int(dmm.group(3)), load=int(dmm.group(4)), mtu=int(dmm.group(5))
                    )

            log_neighbor = bool(eigrp_obj.re_search_children(r"^\s+eigrp\s+log-neighbor-changes"))
            stub = None
            sc = eigrp_obj.re_search_children(r"^\s+eigrp\s+stub")
            if sc:
                sm = re.match(r"^\s+eigrp\s+stub\s*(.*)", sc[0].text)
                if sm:
                    stub = sm.group(1).strip() or "stub"

            vrf = None
            vc2 = eigrp_obj.re_search_children(r"^\s+address-family\s+ipv4\s+vrf\s+(\S+)")
            if vc2:
                vrf = self._extract_match(vc2[0].text, r"\bvrf\s+(\S+)")

            eigrp_instances.append(EIGRPConfig(
                object_id=f"eigrp_{as_number}",
                raw_lines=raw_lines,
                source_os=self.os_type,
                line_numbers=line_numbers,
                as_number=as_number,
                router_id=router_id,
                networks=networks,
                passive_interface_default=passive_default,
                passive_interfaces=passive_ifs,
                non_passive_interfaces=non_passive_ifs,
                redistribute=redistribute,
                auto_summary=auto_summary,
                variance=variance,
                maximum_paths=maximum_paths,
                distance_internal=distance_internal,
                distance_external=distance_external,
                default_metric=default_metric,
                log_neighbor_changes=log_neighbor,
                vrf=vrf,
                stub=stub,
            ))

        return eigrp_instances

    # -------------------------------------------------------------------------
    # RIP
    # -------------------------------------------------------------------------

    def parse_rip(self) -> list[RIPConfig]:
        """Parse RIP configurations."""
        parse = self._get_parse_obj()
        rip_instances = []

        for rip_obj in parse.find_objects(r"^router\s+rip$"):
            raw_lines, line_numbers = self._get_raw_lines_and_line_numbers(rip_obj)

            version = 1
            vc = rip_obj.re_search_children(r"^\s+version\s+(\d)")
            if vc:
                v = self._extract_match(vc[0].text, r"^\s+version\s+(\d)")
                if v:
                    version = int(v)

            from ipaddress import IPv4Network
            networks = []
            for nc in rip_obj.re_search_children(r"^\s+network\s+"):
                nm = re.match(r"^\s+network\s+(\S+)", nc.text)
                if nm:
                    try:
                        networks.append(IPv4Network(nm.group(1), strict=False))
                    except Exception:
                        pass

            passive_default = bool(rip_obj.re_search_children(r"^\s+passive-interface\s+default"))
            passive_ifs = []
            non_passive_ifs = []
            for pic in rip_obj.re_search_children(r"^\s+(?:no\s+)?passive-interface\s+\S"):
                pim = re.match(r"^\s+(no\s+)?passive-interface\s+(\S+)", pic.text)
                if pim:
                    intf_name = pim.group(2)
                    if intf_name == "default":
                        continue
                    if pim.group(1):
                        non_passive_ifs.append(intf_name)
                    else:
                        passive_ifs.append(intf_name)

            redistribute = []
            for rc in rip_obj.re_search_children(r"^\s+redistribute\s+"):
                rm = re.match(r"^\s+redistribute\s+(\S+)(?:\s+(\S+))?", rc.text)
                if rm:
                    proto = rm.group(1)
                    pid = rm.group(2)
                    route_map = self._extract_match(rc.text, r"\broute-map\s+(\S+)")
                    metric = None
                    mm = re.search(r"\bmetric\s+(\d+)", rc.text)
                    if mm:
                        metric = int(mm.group(1))
                    from confgraph.models.rip import RIPRedistribute
                    redistribute.append(RIPRedistribute(
                        protocol=proto, process_id=pid, metric=metric, route_map=route_map
                    ))

            auto_summary = bool(rip_obj.re_search_children(r"^\s+auto-summary"))
            default_info = bool(rip_obj.re_search_children(r"^\s+default-information\s+originate"))

            timers = None
            tc = rip_obj.re_search_children(r"^\s+timers\s+basic\s+")
            if tc:
                tm = re.match(r"^\s+timers\s+basic\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)", tc[0].text)
                if tm:
                    from confgraph.models.rip import RIPTimers
                    timers = RIPTimers(
                        update=int(tm.group(1)), invalid=int(tm.group(2)),
                        holddown=int(tm.group(3)), flush=int(tm.group(4))
                    )

            maximum_paths = None
            mpc = rip_obj.re_search_children(r"^\s+maximum-paths\s+(\d+)")
            if mpc:
                v = self._extract_match(mpc[0].text, r"^\s+maximum-paths\s+(\d+)")
                if v:
                    maximum_paths = int(v)

            distance = None
            dc = rip_obj.re_search_children(r"^\s+distance\s+(\d+)")
            if dc:
                v = self._extract_match(dc[0].text, r"^\s+distance\s+(\d+)")
                if v:
                    distance = int(v)

            rip_instances.append(RIPConfig(
                object_id="rip",
                raw_lines=raw_lines,
                source_os=self.os_type,
                line_numbers=line_numbers,
                version=version,
                networks=networks,
                passive_interface_default=passive_default,
                passive_interfaces=passive_ifs,
                non_passive_interfaces=non_passive_ifs,
                redistribute=redistribute,
                auto_summary=auto_summary,
                timers=timers,
                default_information_originate=default_info,
                maximum_paths=maximum_paths,
                distance=distance,
            ))

        return rip_instances

    # -------------------------------------------------------------------------
    # NTP
    # -------------------------------------------------------------------------

    def parse_ntp(self) -> NTPConfig | None:
        """Parse NTP configuration."""
        parse = self._get_parse_obj()
        ntp_objs = parse.find_objects(r"^ntp\s+")
        if not ntp_objs:
            return None

        from ipaddress import IPv4Address, IPv6Address
        servers = []
        peers = []
        auth_keys = []
        trusted_keys = []
        source_interface = None
        authenticate = False
        master = False
        master_stratum = None
        update_calendar = False
        logging = False
        ag_query_only = ag_serve_only = ag_serve = ag_peer = None

        for obj in ntp_objs:
            t = obj.text.strip()
            if re.match(r"^ntp\s+server\s+", t):
                m = re.match(r"^ntp\s+server(?:\s+vrf\s+(\S+))?\s+(\S+)(.*)", t)
                if m:
                    vrf = m.group(1)
                    addr_str = m.group(2)
                    rest = m.group(3)
                    prefer = "prefer" in rest
                    key_m = re.search(r"\bkey\s+(\d+)", rest)
                    ver_m = re.search(r"\bversion\s+(\d+)", rest)
                    src_m = re.search(r"\bsource\s+(\S+)", rest)
                    try:
                        addr = IPv4Address(addr_str)
                    except Exception:
                        try:
                            addr = IPv6Address(addr_str)
                        except Exception:
                            addr = addr_str
                    servers.append(NTPServer(
                        address=addr, prefer=prefer,
                        key_id=int(key_m.group(1)) if key_m else None,
                        version=int(ver_m.group(1)) if ver_m else None,
                        vrf=vrf, source=src_m.group(1) if src_m else None,
                    ))
            elif re.match(r"^ntp\s+peer\s+", t):
                m = re.match(r"^ntp\s+peer(?:\s+vrf\s+(\S+))?\s+(\S+)(.*)", t)
                if m:
                    vrf = m.group(1)
                    addr_str = m.group(2)
                    rest = m.group(3)
                    prefer = "prefer" in rest
                    key_m = re.search(r"\bkey\s+(\d+)", rest)
                    try:
                        addr = IPv4Address(addr_str)
                    except Exception:
                        try:
                            addr = IPv6Address(addr_str)
                        except Exception:
                            addr = addr_str
                    peers.append(NTPServer(
                        address=addr, prefer=prefer,
                        key_id=int(key_m.group(1)) if key_m else None, vrf=vrf,
                    ))
            elif re.match(r"^ntp\s+authentication-key\s+", t):
                m = re.match(r"^ntp\s+authentication-key\s+(\d+)\s+(\S+)\s+(\S+)", t)
                if m:
                    auth_keys.append(NTPAuthKey(
                        key_id=int(m.group(1)), algorithm=m.group(2), key_string=m.group(3)
                    ))
            elif re.match(r"^ntp\s+trusted-key\s+", t):
                m = re.match(r"^ntp\s+trusted-key\s+(\d+)", t)
                if m:
                    trusted_keys.append(int(m.group(1)))
            elif re.match(r"^ntp\s+source\s+", t):
                source_interface = self._extract_match(t, r"^ntp\s+source\s+(\S+)")
            elif "ntp authenticate" in t:
                authenticate = True
            elif re.match(r"^ntp\s+master", t):
                master = True
                sm = re.match(r"^ntp\s+master\s+(\d+)", t)
                if sm:
                    master_stratum = int(sm.group(1))
            elif "ntp update-calendar" in t:
                update_calendar = True
            elif "ntp logging" in t:
                logging = True
            elif re.match(r"^ntp\s+access-group\s+", t):
                m = re.match(r"^ntp\s+access-group\s+(query-only|serve-only|serve|peer)\s+(\S+)", t)
                if m:
                    ag_type = m.group(1).replace("-", "_")
                    acl = m.group(2)
                    if ag_type == "query_only":
                        ag_query_only = acl
                    elif ag_type == "serve_only":
                        ag_serve_only = acl
                    elif ag_type == "serve":
                        ag_serve = acl
                    elif ag_type == "peer":
                        ag_peer = acl

        return NTPConfig(
            object_id="ntp",
            raw_lines=[o.text for o in ntp_objs],
            source_os=self.os_type,
            line_numbers=[o.linenum for o in ntp_objs],
            master=master, master_stratum=master_stratum,
            servers=servers, peers=peers,
            source_interface=source_interface,
            authenticate=authenticate,
            authentication_keys=auth_keys, trusted_keys=trusted_keys,
            access_group_query_only=ag_query_only,
            access_group_serve_only=ag_serve_only,
            access_group_serve=ag_serve,
            access_group_peer=ag_peer,
            update_calendar=update_calendar, logging=logging,
        )

    # -------------------------------------------------------------------------
    # SNMP
    # -------------------------------------------------------------------------

    def parse_snmp(self) -> SNMPConfig | None:
        """Parse SNMP configuration."""
        parse = self._get_parse_obj()
        snmp_objs = parse.find_objects(r"^snmp-server\s+")
        if not snmp_objs:
            return None

        from ipaddress import IPv4Address, IPv6Address
        communities = []
        hosts = []
        location = contact = chassis_id = source_interface = trap_source = None
        enable_traps = []
        views = []
        groups = []
        users = []
        if_index_persist = False

        for obj in snmp_objs:
            t = obj.text.strip()
            if re.match(r"^snmp-server\s+community\s+", t):
                m = re.match(r"^snmp-server\s+community\s+(\S+)\s+(ro|rw)(\s+.*)?$", t)
                if m:
                    acl = None
                    view = None
                    rest = (m.group(3) or "").strip()
                    vm = re.search(r"\bview\s+(\S+)", rest)
                    if vm:
                        view = vm.group(1)
                    # last token may be ACL
                    parts = rest.split()
                    if parts and not re.match(r"^(view|ipv6)$", parts[-1]):
                        acl = parts[-1]
                    communities.append(SNMPCommunity(
                        community_string=m.group(1), access=m.group(2),
                        acl=acl, view=view,
                    ))
            elif re.match(r"^snmp-server\s+host\s+", t):
                m = re.match(r"^snmp-server\s+host\s+(\S+)(?:\s+vrf\s+(\S+))?(?:\s+(traps|informs))?(?:\s+version\s+(1|2c|3\s+\S+))?\s+(\S+)", t)
                if m:
                    try:
                        addr = IPv4Address(m.group(1))
                    except Exception:
                        try:
                            addr = IPv6Address(m.group(1))
                        except Exception:
                            addr = m.group(1)
                    traps = m.group(3) != "informs" if m.group(3) else True
                    version = m.group(4).split()[0] if m.group(4) else "2c"
                    community = m.group(5) or ""
                    hosts.append(SNMPHost(
                        address=addr, version=version,
                        community_or_user=community, traps=traps,
                        vrf=m.group(2),
                    ))
            elif re.match(r"^snmp-server\s+location\s+", t):
                location = t[len("snmp-server location "):].strip()
            elif re.match(r"^snmp-server\s+contact\s+", t):
                contact = t[len("snmp-server contact "):].strip()
            elif re.match(r"^snmp-server\s+chassis-id\s+", t):
                chassis_id = self._extract_match(t, r"^snmp-server\s+chassis-id\s+(\S+)")
            elif re.match(r"^snmp-server\s+source-interface\s+", t):
                source_interface = self._extract_match(t, r"^snmp-server\s+source-interface\s+\S+\s+(\S+)")
            elif re.match(r"^snmp-server\s+trap-source\s+", t):
                trap_source = self._extract_match(t, r"^snmp-server\s+trap-source\s+(\S+)")
            elif re.match(r"^snmp-server\s+enable\s+traps", t):
                m = re.match(r"^snmp-server\s+enable\s+traps\s*(.*)", t)
                if m and m.group(1).strip():
                    enable_traps.extend(m.group(1).strip().split())
                elif "enable traps" in t:
                    enable_traps.append("all")
            elif re.match(r"^snmp-server\s+view\s+", t):
                m = re.match(r"^snmp-server\s+view\s+(\S+)\s+(\S+)\s+(included|excluded)", t)
                if m:
                    views.append(SNMPView(
                        name=m.group(1), oid_tree=m.group(2),
                        included=m.group(3) == "included"
                    ))
            elif re.match(r"^snmp-server\s+group\s+", t):
                m = re.match(r"^snmp-server\s+group\s+(\S+)\s+(v1|v2c|v3)\s*(.*)", t)
                if m:
                    rest = m.group(3)
                    sec_level = None
                    sl_m = re.match(r"(noauth|auth|priv)", rest)
                    if sl_m:
                        sec_level = sl_m.group(1)
                    read_v = self._extract_match(rest, r"\bread\s+(\S+)")
                    write_v = self._extract_match(rest, r"\bwrite\s+(\S+)")
                    notify_v = self._extract_match(rest, r"\bnotify\s+(\S+)")
                    acl = self._extract_match(rest, r"\baccess\s+(\S+)")
                    groups.append(SNMPGroup(
                        name=m.group(1), version=m.group(2), security_level=sec_level,
                        read_view=read_v, write_view=write_v, notify_view=notify_v, acl=acl,
                    ))
            elif re.match(r"^snmp-server\s+user\s+", t):
                m = re.match(r"^snmp-server\s+user\s+(\S+)\s+(\S+)\s+(v1|v2c|v3)(.*)", t)
                if m:
                    rest = m.group(4)
                    auth_alg = self._extract_match(rest, r"\bauth\s+(md5|sha)\s+")
                    auth_m = re.search(r"\bauth\s+(?:md5|sha)\s+(\S+)", rest)
                    auth_pw = auth_m.group(1) if auth_m else None
                    priv_alg = self._extract_match(rest, r"\bpriv\s+(des|3des|aes)")
                    priv_size_m = re.search(r"\bpriv\s+(?:des|aes)\s*(\d+)?", rest)
                    priv_size = int(priv_size_m.group(1)) if priv_size_m and priv_size_m.group(1) else None
                    priv_m = re.search(r"\bpriv\s+(?:des|aes)(?:\s+\d+)?\s+(\S+)", rest)
                    priv_pw = priv_m.group(1) if priv_m else None
                    users.append(SNMPUser(
                        username=m.group(1), group=m.group(2), version=m.group(3),
                        auth_algorithm=auth_alg, auth_password=auth_pw,
                        priv_algorithm=priv_alg, priv_key_size=priv_size, priv_password=priv_pw,
                    ))
            elif "ifindex-persist" in t.lower():
                if_index_persist = True

        return SNMPConfig(
            object_id="snmp",
            raw_lines=[o.text for o in snmp_objs],
            source_os=self.os_type,
            line_numbers=[o.linenum for o in snmp_objs],
            communities=communities, hosts=hosts,
            location=location, contact=contact, chassis_id=chassis_id,
            source_interface=source_interface, trap_source=trap_source,
            enable_traps=enable_traps, views=views, groups=groups, users=users,
            if_index_persist=if_index_persist,
        )

    # -------------------------------------------------------------------------
    # Syslog
    # -------------------------------------------------------------------------

    def parse_syslog(self) -> SyslogConfig | None:
        """Parse syslog/logging configuration."""
        parse = self._get_parse_obj()
        log_objs = parse.find_objects(r"^logging\s+")
        if not log_objs:
            return None

        from ipaddress import IPv4Address, IPv6Address
        hosts = []
        buffered_size = buffered_level = None
        console_level = monitor_level = trap_level = None
        facility = source_interface = origin_id = None
        timestamps_log = timestamps_debug = None
        enabled = True

        for obj in log_objs:
            t = obj.text.strip()
            if re.match(r"^logging\s+(host\s+)?\d+\.\d+\.\d+\.\d+", t) or re.match(r"^logging\s+host\s+", t):
                m = re.match(r"^logging\s+(?:host\s+)?(\S+)(.*)", t)
                if m:
                    addr_str = m.group(1)
                    rest = m.group(2)
                    transport = self._extract_match(rest, r"\btransport\s+(tcp|udp|tls)")
                    port = None
                    pm = re.search(r"\bport\s+(\d+)", rest)
                    if pm:
                        port = int(pm.group(1))
                    vrf = self._extract_match(rest, r"\bvrf\s+(\S+)")
                    try:
                        addr = IPv4Address(addr_str)
                    except Exception:
                        try:
                            addr = IPv6Address(addr_str)
                        except Exception:
                            addr = addr_str
                    hosts.append(LoggingHost(address=addr, transport=transport, port=port, vrf=vrf))
            elif re.match(r"^logging\s+buffered\s+", t):
                m = re.match(r"^logging\s+buffered\s+(\d+)(?:\s+(\S+))?", t)
                if m:
                    buffered_size = int(m.group(1))
                    buffered_level = m.group(2)
                else:
                    m2 = re.match(r"^logging\s+buffered\s+(\S+)", t)
                    if m2:
                        buffered_level = m2.group(1)
            elif re.match(r"^logging\s+console\s+", t):
                console_level = self._extract_match(t, r"^logging\s+console\s+(\S+)")
            elif re.match(r"^logging\s+monitor\s+", t):
                monitor_level = self._extract_match(t, r"^logging\s+monitor\s+(\S+)")
            elif re.match(r"^logging\s+trap\s+", t):
                trap_level = self._extract_match(t, r"^logging\s+trap\s+(\S+)")
            elif re.match(r"^logging\s+facility\s+", t):
                facility = self._extract_match(t, r"^logging\s+facility\s+(\S+)")
            elif re.match(r"^logging\s+source-interface\s+", t):
                source_interface = self._extract_match(t, r"^logging\s+source-interface\s+(\S+)")
            elif re.match(r"^logging\s+origin-id\s+", t):
                m = re.match(r"^logging\s+origin-id\s+(.*)", t)
                if m:
                    origin_id = m.group(1).strip()
            elif re.match(r"^logging\s+timestamps\s+log\s+", t):
                m = re.match(r"^logging\s+timestamps\s+log\s+(.*)", t)
                if m:
                    timestamps_log = m.group(1).strip()
            elif re.match(r"^logging\s+timestamps\s+debug\s+", t):
                m = re.match(r"^logging\s+timestamps\s+debug\s+(.*)", t)
                if m:
                    timestamps_debug = m.group(1).strip()
            elif "no logging" in t or "logging off" in t:
                enabled = False

        return SyslogConfig(
            object_id="syslog",
            raw_lines=[o.text for o in log_objs],
            source_os=self.os_type,
            line_numbers=[o.linenum for o in log_objs],
            enabled=enabled, hosts=hosts,
            buffered_size=buffered_size, buffered_level=buffered_level,
            console_level=console_level, monitor_level=monitor_level, trap_level=trap_level,
            facility=facility, source_interface=source_interface,
            origin_id=origin_id, timestamps_log=timestamps_log, timestamps_debug=timestamps_debug,
        )

    # -------------------------------------------------------------------------
    # Banners
    # -------------------------------------------------------------------------

    def parse_banners(self) -> BannerConfig | None:
        """Parse device banner configuration using raw regex (ciscoconfparse2 cannot handle multi-line banners)."""
        banner_types = {
            "motd": None,
            "login": None,
            "exec": None,
            "incoming": None,
        }
        found_any = False
        for banner_type in banner_types:
            # Match: banner <type> <delim><text><delim>
            pattern = rf"^banner\s+{banner_type}\s+(\S)(.*?)\1"
            m = re.search(pattern, self.config_text, re.MULTILINE | re.DOTALL)
            if m:
                banner_types[banner_type] = m.group(2).strip()
                found_any = True

        if not found_any:
            return None

        return BannerConfig(
            object_id="banners",
            raw_lines=[],
            source_os=self.os_type,
            line_numbers=[],
            motd=banner_types["motd"],
            login=banner_types["login"],
            exec_banner=banner_types["exec"],
            incoming=banner_types["incoming"],
        )

    # -------------------------------------------------------------------------
    # Lines
    # -------------------------------------------------------------------------

    def parse_lines(self) -> list[LineConfig]:
        """Parse line (console, VTY, aux, TTY) configurations."""
        parse = self._get_parse_obj()
        lines = []

        for line_obj in parse.find_objects(r"^line\s+(con|vty|aux|tty)\s+"):
            m = re.match(r"^line\s+(con(?:sole)?|vty|aux|tty)\s+(\d+)(?:\s+(\d+))?", line_obj.text)
            if not m:
                continue

            raw_type = m.group(1)
            first_line = int(m.group(2))
            last_line = int(m.group(3)) if m.group(3) else None

            if raw_type.startswith("con"):
                line_type = LineType.CONSOLE
            elif raw_type == "vty":
                line_type = LineType.VTY
            elif raw_type == "aux":
                line_type = LineType.AUX
            else:
                line_type = LineType.TTY

            raw_lines, line_numbers = self._get_raw_lines_and_line_numbers(line_obj)

            # exec-timeout
            exec_timeout_minutes = exec_timeout_seconds = None
            etc = line_obj.re_search_children(r"^\s+exec-timeout\s+")
            if etc:
                etm = re.match(r"^\s+exec-timeout\s+(\d+)(?:\s+(\d+))?", etc[0].text)
                if etm:
                    exec_timeout_minutes = int(etm.group(1))
                    exec_timeout_seconds = int(etm.group(2)) if etm.group(2) else 0

            logging_sync = bool(line_obj.re_search_children(r"^\s+logging\s+synchronous"))

            # transport input
            transport_input = []
            tic = line_obj.re_search_children(r"^\s+transport\s+input\s+")
            if tic:
                tim = re.match(r"^\s+transport\s+input\s+(.*)", tic[0].text)
                if tim:
                    transport_input = tim.group(1).strip().split()

            # transport output
            transport_output = []
            toc = line_obj.re_search_children(r"^\s+transport\s+output\s+")
            if toc:
                tom = re.match(r"^\s+transport\s+output\s+(.*)", toc[0].text)
                if tom:
                    transport_output = tom.group(1).strip().split()

            access_class_in = access_class_out = ipv6_in = None
            for acc in line_obj.re_search_children(r"^\s+access-class\s+"):
                acm = re.match(r"^\s+access-class\s+(\S+)\s+(in|out)", acc.text)
                if acm:
                    if acm.group(2) == "in":
                        access_class_in = acm.group(1)
                    else:
                        access_class_out = acm.group(1)
            for acc in line_obj.re_search_children(r"^\s+ipv6\s+access-class\s+"):
                acm = re.match(r"^\s+ipv6\s+access-class\s+(\S+)\s+in", acc.text)
                if acm:
                    ipv6_in = acm.group(1)

            privilege_level = None
            plc = line_obj.re_search_children(r"^\s+privilege\s+level\s+(\d+)")
            if plc:
                v = self._extract_match(plc[0].text, r"^\s+privilege\s+level\s+(\d+)")
                if v:
                    privilege_level = int(v)

            password = None
            pwc = line_obj.re_search_children(r"^\s+password\s+")
            if pwc:
                pm = re.match(r"^\s+password\s+(?:\d+\s+)?(\S+)", pwc[0].text)
                if pm:
                    password = pm.group(1)

            login = None
            lc = line_obj.re_search_children(r"^\s+login\s*")
            if lc:
                lm = re.match(r"^\s+login\s*(.*)", lc[0].text)
                if lm:
                    login = lm.group(1).strip() or "line"

            length = width = session_timeout = history_size = None
            lenc = line_obj.re_search_children(r"^\s+length\s+(\d+)")
            if lenc:
                v = self._extract_match(lenc[0].text, r"^\s+length\s+(\d+)")
                if v:
                    length = int(v)
            wc = line_obj.re_search_children(r"^\s+width\s+(\d+)")
            if wc:
                v = self._extract_match(wc[0].text, r"^\s+width\s+(\d+)")
                if v:
                    width = int(v)
            stc = line_obj.re_search_children(r"^\s+session-timeout\s+(\d+)")
            if stc:
                v = self._extract_match(stc[0].text, r"^\s+session-timeout\s+(\d+)")
                if v:
                    session_timeout = int(v)
            hsc = line_obj.re_search_children(r"^\s+history\s+size\s+(\d+)")
            if hsc:
                v = self._extract_match(hsc[0].text, r"^\s+history\s+size\s+(\d+)")
                if v:
                    history_size = int(v)

            no_exec = bool(line_obj.re_search_children(r"^\s+no\s+exec"))

            stopbits = speed = None
            sbc = line_obj.re_search_children(r"^\s+stopbits\s+(\d+)")
            if sbc:
                v = self._extract_match(sbc[0].text, r"^\s+stopbits\s+(\d+)")
                if v:
                    stopbits = int(v)
            spc = line_obj.re_search_children(r"^\s+speed\s+(\d+)")
            if spc:
                v = self._extract_match(spc[0].text, r"^\s+speed\s+(\d+)")
                if v:
                    speed = int(v)

            flowcontrol = None
            fcc = line_obj.re_search_children(r"^\s+flowcontrol\s+")
            if fcc:
                flowcontrol = self._extract_match(fcc[0].text, r"^\s+flowcontrol\s+(\S+)")

            lines.append(LineConfig(
                object_id=f"line_{raw_type}_{first_line}",
                raw_lines=raw_lines,
                source_os=self.os_type,
                line_numbers=line_numbers,
                line_type=line_type,
                first_line=first_line,
                last_line=last_line,
                exec_timeout_minutes=exec_timeout_minutes,
                exec_timeout_seconds=exec_timeout_seconds,
                logging_synchronous=logging_sync,
                transport_input=transport_input,
                transport_output=transport_output,
                access_class_in=access_class_in,
                access_class_out=access_class_out,
                ipv6_access_class_in=ipv6_in,
                privilege_level=privilege_level,
                password=password,
                login=login,
                length=length,
                width=width,
                session_timeout=session_timeout,
                history_size=history_size,
                no_exec=no_exec,
                stopbits=stopbits,
                speed=speed,
                flowcontrol=flowcontrol,
            ))

        return lines

    # -------------------------------------------------------------------------
    # QoS — class-map
    # -------------------------------------------------------------------------

    def parse_class_maps(self) -> list[ClassMapConfig]:
        """Parse QoS class-map configurations."""
        parse = self._get_parse_obj()
        class_maps = []

        for cm_obj in parse.find_objects(r"^class-map\s+"):
            m = re.match(r"^class-map\s+(?:(match-any|match-all)\s+)?(\S+)", cm_obj.text)
            if not m:
                continue
            match_type = m.group(1) or "match-all"
            name = m.group(2)
            raw_lines, line_numbers = self._get_raw_lines_and_line_numbers(cm_obj)

            matches = []
            for mc in cm_obj.re_search_children(r"^\s+match\s+"):
                mm = re.match(r"^\s+match\s+(not\s+)?([\w-]+)\s*(.*)", mc.text)
                if mm:
                    mtype = mm.group(2)
                    if mm.group(1):
                        mtype = f"not {mtype}"
                    vals = mm.group(3).strip().split() if mm.group(3) else []
                    matches.append(ClassMapMatch(match_type=mtype, values=vals))

            class_maps.append(ClassMapConfig(
                object_id=f"class_map_{name}",
                raw_lines=raw_lines,
                source_os=self.os_type,
                line_numbers=line_numbers,
                name=name,
                match_type=match_type,
                matches=matches,
            ))

        return class_maps

    # -------------------------------------------------------------------------
    # QoS — policy-map
    # -------------------------------------------------------------------------

    def parse_policy_maps(self) -> list[PolicyMapConfig]:
        """Parse QoS policy-map configurations."""
        parse = self._get_parse_obj()
        policy_maps = []

        for pm_obj in parse.find_objects(r"^policy-map\s+"):
            m = re.match(r"^policy-map\s+(\S+)", pm_obj.text)
            if not m:
                continue
            name = m.group(1)
            raw_lines, line_numbers = self._get_raw_lines_and_line_numbers(pm_obj)

            classes = []
            current_class_obj = None
            for child in pm_obj.children:
                cm = re.match(r"^\s+class\s+(\S+)", child.text)
                if cm:
                    current_class_obj = child
                    class_name = cm.group(1)
                    bandwidth = bandwidth_percent = priority = priority_percent = None
                    police = shape = None
                    queue_limit = None
                    random_detect = False
                    set_actions = []
                    service_policy = None

                    for cc in child.children:
                        ct = cc.text.strip()
                        if re.match(r"bandwidth\s+percent\s+", ct):
                            mm2 = re.match(r"bandwidth\s+percent\s+(\d+)", ct)
                            if mm2:
                                bandwidth_percent = int(mm2.group(1))
                        elif re.match(r"bandwidth\s+\d+", ct):
                            mm2 = re.match(r"bandwidth\s+(\d+)", ct)
                            if mm2:
                                bandwidth = int(mm2.group(1))
                        elif re.match(r"priority\s+percent\s+", ct):
                            mm2 = re.match(r"priority\s+percent\s+(\d+)", ct)
                            if mm2:
                                priority_percent = int(mm2.group(1))
                        elif re.match(r"priority\s+\d+", ct):
                            mm2 = re.match(r"priority\s+(\d+)", ct)
                            if mm2:
                                priority = int(mm2.group(1))
                        elif re.match(r"police\s+", ct):
                            rate = burst = excess_burst = None
                            rate_unit = None
                            pm2 = re.match(r"police\s+(\d+)(?:\s+(\d+))?(?:\s+(\d+))?", ct)
                            if pm2:
                                rate = int(pm2.group(1))
                                burst = int(pm2.group(2)) if pm2.group(2) else None
                                excess_burst = int(pm2.group(3)) if pm2.group(3) else None
                            conform_actions = exceed_actions = violate_actions = []
                            for pcc in cc.children:
                                pct = pcc.text.strip()
                                pam = re.match(r"(conform|exceed|violate)-action\s+(.*)", pct)
                                if pam:
                                    actions_list = [PoliceAction(action_type=pam.group(1), action=pam.group(2).strip())]
                                    if pam.group(1) == "conform":
                                        conform_actions = actions_list
                                    elif pam.group(1) == "exceed":
                                        exceed_actions = actions_list
                                    else:
                                        violate_actions = actions_list
                            police = PolicyMapPolice(
                                rate=rate, burst=burst, excess_burst=excess_burst,
                                rate_unit=rate_unit,
                                conform_actions=conform_actions,
                                exceed_actions=exceed_actions,
                                violate_actions=violate_actions,
                            )
                        elif re.match(r"shape\s+(average|peak)\s+\d+", ct):
                            sm2 = re.match(r"shape\s+(average|peak)\s+(\d+)", ct)
                            if sm2:
                                shape = PolicyMapShape(type=sm2.group(1), rate=int(sm2.group(2)))
                        elif re.match(r"queue-limit\s+\d+", ct):
                            qlm = re.match(r"queue-limit\s+(\d+)", ct)
                            if qlm:
                                queue_limit = int(qlm.group(1))
                        elif ct == "random-detect":
                            random_detect = True
                        elif re.match(r"set\s+", ct):
                            sm2 = re.match(r"set\s+([\w-]+)\s+(.*)", ct)
                            if sm2:
                                set_actions.append(PolicyMapSet(set_type=sm2.group(1), value=sm2.group(2).strip()))
                        elif re.match(r"service-policy\s+", ct):
                            service_policy = self._extract_match(ct, r"service-policy\s+(\S+)")

                    classes.append(PolicyMapClass(
                        class_name=class_name,
                        bandwidth=bandwidth, bandwidth_percent=bandwidth_percent,
                        priority=priority, priority_percent=priority_percent,
                        police=police, shape=shape,
                        queue_limit=queue_limit, random_detect=random_detect,
                        set_actions=set_actions, service_policy=service_policy,
                    ))

            policy_maps.append(PolicyMapConfig(
                object_id=f"policy_map_{name}",
                raw_lines=raw_lines,
                source_os=self.os_type,
                line_numbers=line_numbers,
                name=name,
                classes=classes,
            ))

        return policy_maps

    # -------------------------------------------------------------------------
    # NAT
    # -------------------------------------------------------------------------

    def parse_nat(self) -> NATConfig | None:
        """Parse NAT configuration."""
        parse = self._get_parse_obj()
        nat_objs = parse.find_objects(r"^ip\s+nat\s+")
        pool_objs = parse.find_objects(r"^ip\s+nat\s+pool\s+")
        timeout_objs = parse.find_objects(r"^ip\s+nat\s+translation\s+")

        if not nat_objs and not pool_objs and not timeout_objs:
            return None

        from ipaddress import IPv4Address
        pools = []
        static_entries = []
        dynamic_entries = []
        timeouts = NATTimeouts()
        translation_max_entries = None
        log_translations = False

        for obj in parse.find_objects(r"^ip\s+nat\s+"):
            t = obj.text.strip()
            if re.match(r"^ip\s+nat\s+pool\s+", t):
                m = re.match(r"^ip\s+nat\s+pool\s+(\S+)\s+(\S+)\s+(\S+)\s+(?:netmask\s+(\S+)|prefix-length\s+(\d+))", t)
                if m:
                    try:
                        pools.append(NATPool(
                            name=m.group(1),
                            start_address=IPv4Address(m.group(2)),
                            end_address=IPv4Address(m.group(3)),
                            netmask=m.group(4),
                            prefix_length=int(m.group(5)) if m.group(5) else None,
                        ))
                    except Exception:
                        pass
            elif re.match(r"^ip\s+nat\s+inside\s+source\s+static\s+", t):
                m = re.match(r"^ip\s+nat\s+inside\s+source\s+static\s+(?:(tcp|udp)\s+)?(\S+)(?:\s+(\d+))?\s+(\S+)(?:\s+(\d+))?", t)
                if m:
                    try:
                        static_entries.append(NATStaticEntry(
                            direction="inside",
                            protocol=m.group(1),
                            local_ip=IPv4Address(m.group(2)),
                            local_port=int(m.group(3)) if m.group(3) else None,
                            global_ip=IPv4Address(m.group(4)),
                            global_port=int(m.group(5)) if m.group(5) else None,
                            extendable="extendable" in t,
                        ))
                    except Exception:
                        pass
            elif re.match(r"^ip\s+nat\s+(?:inside|outside)\s+source\s+list\s+", t):
                m = re.match(r"^ip\s+nat\s+(inside|outside)\s+source\s+list\s+(\S+)\s+(?:pool\s+(\S+)|interface\s+(\S+))(.*)", t)
                if m:
                    dynamic_entries.append(NATDynamicEntry(
                        direction=m.group(1),
                        acl=m.group(2),
                        pool=m.group(3),
                        interface=m.group(4),
                        overload="overload" in t,
                    ))
            elif re.match(r"^ip\s+nat\s+translation\s+", t):
                m = re.match(r"^ip\s+nat\s+translation\s+(\S+)\s+(\d+)", t)
                if m:
                    timeout_type = m.group(1).replace("-", "_")
                    val = int(m.group(2))
                    if timeout_type == "timeout":
                        timeouts.default = val
                    elif timeout_type == "tcp_timeout":
                        timeouts.tcp = val
                    elif timeout_type == "udp_timeout":
                        timeouts.udp = val
                    elif timeout_type == "dns_timeout":
                        timeouts.dns = val
                    elif timeout_type == "finrst_timeout":
                        timeouts.finrst = val
                    elif timeout_type == "icmp_timeout":
                        timeouts.icmp = val
                    elif timeout_type == "syn_timeout":
                        timeouts.syn = val
                    elif timeout_type == "max_entries":
                        translation_max_entries = val
            elif "log-translations" in t:
                log_translations = True

        return NATConfig(
            object_id="nat",
            raw_lines=[o.text for o in parse.find_objects(r"^ip\s+nat\s+")],
            source_os=self.os_type,
            line_numbers=[o.linenum for o in parse.find_objects(r"^ip\s+nat\s+")],
            pools=pools,
            static_entries=static_entries,
            dynamic_entries=dynamic_entries,
            timeouts=timeouts,
            translation_max_entries=translation_max_entries,
            log_translations=log_translations,
        )

    # -------------------------------------------------------------------------
    # Crypto
    # -------------------------------------------------------------------------

    def parse_crypto(self) -> CryptoConfig | None:
        """Parse crypto/IPsec configuration."""
        parse = self._get_parse_obj()
        crypto_objs = parse.find_objects(r"^crypto\s+")
        if not crypto_objs:
            return None

        from ipaddress import IPv4Address
        isakmp_policies = []
        isakmp_keys = []
        ikev2_proposals = []
        ikev2_policies = []
        transform_sets = []
        crypto_maps: dict[str, list] = {}
        ipsec_profiles = []

        for obj in crypto_objs:
            t = obj.text.strip()
            if re.match(r"^crypto\s+isakmp\s+policy\s+(\d+)", t):
                priority = int(re.match(r"^crypto\s+isakmp\s+policy\s+(\d+)", t).group(1))
                enc = hash_alg = auth = group = lifetime = None
                for c in obj.children:
                    ct = c.text.strip()
                    if ct.startswith("encryption "):
                        enc = ct.split(None, 1)[1]
                    elif ct.startswith("hash "):
                        hash_alg = ct.split(None, 1)[1]
                    elif ct.startswith("authentication "):
                        auth = ct.split(None, 1)[1]
                    elif ct.startswith("group "):
                        group = int(ct.split()[1])
                    elif ct.startswith("lifetime "):
                        lifetime = int(ct.split()[1])
                isakmp_policies.append(IKEv1Policy(
                    priority=priority, encryption=enc, hash=hash_alg,
                    authentication=auth, group=group, lifetime=lifetime
                ))
            elif re.match(r"^crypto\s+isakmp\s+key\s+", t):
                m = re.match(r"^crypto\s+isakmp\s+key\s+(\S+)\s+address\s+(\S+)", t)
                if m:
                    try:
                        peer_addr = IPv4Address(m.group(2))
                        isakmp_keys.append(IKEv1Key(key_string=m.group(1), peer_address=peer_addr))
                    except Exception:
                        isakmp_keys.append(IKEv1Key(key_string=m.group(1), peer_wildcard=m.group(2)))
            elif re.match(r"^crypto\s+ikev2\s+proposal\s+", t):
                m = re.match(r"^crypto\s+ikev2\s+proposal\s+(\S+)", t)
                if m:
                    prop_name = m.group(1)
                    enc_list = []
                    int_list = []
                    grp_list = []
                    for c in obj.children:
                        ct = c.text.strip()
                        if ct.startswith("encryption "):
                            enc_list = ct.split(None, 1)[1].split()
                        elif ct.startswith("integrity "):
                            int_list = ct.split(None, 1)[1].split()
                        elif ct.startswith("group "):
                            grp_list = [int(g) for g in ct.split()[1:] if g.isdigit()]
                    ikev2_proposals.append(IKEv2Proposal(
                        name=prop_name, encryption=enc_list, integrity=int_list, group=grp_list
                    ))
            elif re.match(r"^crypto\s+ikev2\s+policy\s+", t):
                m = re.match(r"^crypto\s+ikev2\s+policy\s+(\S+)", t)
                if m:
                    pol_name = m.group(1)
                    proposals = []
                    for c in obj.children:
                        ct = c.text.strip()
                        if ct.startswith("proposal "):
                            proposals.extend(ct.split()[1:])
                    ikev2_policies.append(IKEv2Policy(name=pol_name, proposals=proposals))
            elif re.match(r"^crypto\s+ipsec\s+transform-set\s+", t):
                m = re.match(r"^crypto\s+ipsec\s+transform-set\s+(\S+)\s+(.*)", t)
                if m:
                    ts_name = m.group(1)
                    transforms = m.group(2).strip().split()
                    mode = "tunnel"
                    for c in obj.children:
                        if "mode transport" in c.text:
                            mode = "transport"
                    transform_sets.append(IPSecTransformSet(name=ts_name, transforms=transforms, mode=mode))
            elif re.match(r"^crypto\s+map\s+(\S+)\s+(\d+)\s+", t):
                m = re.match(r"^crypto\s+map\s+(\S+)\s+(\d+)\s+(\S+)", t)
                if m:
                    map_name = m.group(1)
                    seq = int(m.group(2))
                    map_type = m.group(3)
                    peer = None
                    ts_list = []
                    acl = None
                    pfs_group = None
                    sa_sec = sa_kb = None
                    for c in obj.children:
                        ct = c.text.strip()
                        if ct.startswith("set peer "):
                            try:
                                peer = IPv4Address(ct.split()[-1])
                            except Exception:
                                pass
                        elif ct.startswith("set transform-set "):
                            ts_list = ct.split()[2:]
                        elif ct.startswith("match address "):
                            acl = ct.split()[-1]
                        elif ct.startswith("set pfs group"):
                            pm2 = re.match(r"set\s+pfs\s+group(\d+)", ct)
                            if pm2:
                                pfs_group = int(pm2.group(1))
                        elif ct.startswith("set security-association lifetime seconds"):
                            sa_sec = int(ct.split()[-1])
                        elif ct.startswith("set security-association lifetime kilobytes"):
                            sa_kb = int(ct.split()[-1])
                    entry = CryptoMapEntry(
                        sequence=seq, map_type=map_type, peer=peer,
                        transform_sets=ts_list, acl=acl, pfs_group=pfs_group,
                        sa_lifetime_seconds=sa_sec, sa_lifetime_kilobytes=sa_kb,
                    )
                    if map_name not in crypto_maps:
                        crypto_maps[map_name] = []
                    crypto_maps[map_name].append(entry)
            elif re.match(r"^crypto\s+ipsec\s+profile\s+", t):
                m = re.match(r"^crypto\s+ipsec\s+profile\s+(\S+)", t)
                if m:
                    prof_name = m.group(1)
                    ts_list = []
                    pfs_group = None
                    sa_sec = None
                    for c in obj.children:
                        ct = c.text.strip()
                        if ct.startswith("set transform-set "):
                            ts_list = ct.split()[2:]
                        elif ct.startswith("set pfs group"):
                            pm2 = re.match(r"set\s+pfs\s+group(\d+)", ct)
                            if pm2:
                                pfs_group = int(pm2.group(1))
                        elif ct.startswith("set security-association lifetime seconds"):
                            sa_sec = int(ct.split()[-1])
                    ipsec_profiles.append(IPSecProfile(
                        name=prof_name, transform_sets=ts_list,
                        pfs_group=pfs_group, sa_lifetime_seconds=sa_sec,
                    ))

        crypto_map_list = [
            CryptoMap(name=name, entries=entries)
            for name, entries in crypto_maps.items()
        ]

        return CryptoConfig(
            object_id="crypto",
            raw_lines=[o.text for o in crypto_objs],
            source_os=self.os_type,
            line_numbers=[o.linenum for o in crypto_objs],
            isakmp_policies=isakmp_policies,
            isakmp_keys=isakmp_keys,
            ikev2_proposals=ikev2_proposals,
            ikev2_policies=ikev2_policies,
            transform_sets=transform_sets,
            crypto_maps=crypto_map_list,
            ipsec_profiles=ipsec_profiles,
        )

    # -------------------------------------------------------------------------
    # BFD
    # -------------------------------------------------------------------------

    def parse_bfd(self) -> BFDConfig | None:
        """Parse BFD global configuration."""
        parse = self._get_parse_obj()
        bfd_objs = parse.find_objects(r"^bfd(?:-template)?\s+")
        if not bfd_objs:
            return None

        templates = []
        maps = []
        slow_timers = None

        for obj in bfd_objs:
            t = obj.text.strip()
            if re.match(r"^bfd-template\s+", t):
                m = re.match(r"^bfd-template\s+(single-hop|multi-hop)\s+(\S+)", t)
                if m:
                    bfd_type = m.group(1)
                    tmpl_name = m.group(2)
                    interval = None
                    echo = True
                    auth = None
                    for c in obj.children:
                        ct = c.text.strip()
                        im = re.match(r"interval\s+min-tx\s+(\d+)\s+min-rx\s+(\d+)\s+multiplier\s+(\d+)", ct)
                        if im:
                            interval = BFDInterval(min_tx=int(im.group(1)), min_rx=int(im.group(2)), multiplier=int(im.group(3)))
                        elif "no echo" in ct:
                            echo = False
                        elif ct.startswith("authentication "):
                            auth = ct.split(None, 1)[1]
                    templates.append(BFDTemplate(name=tmpl_name, type=bfd_type, interval=interval, echo=echo, authentication=auth))
            elif re.match(r"^bfd\s+map\s+", t):
                m = re.match(r"^bfd\s+map\s+(ipv4|ipv6)\s+(\S+)\s+(\S+)\s+(\S+)", t)
                if m:
                    maps.append(BFDMap(afi=m.group(1), destination=m.group(2), source=m.group(3), template=m.group(4)))
            elif re.match(r"^bfd\s+slow-timers\s+", t):
                v = self._extract_match(t, r"^bfd\s+slow-timers\s+(\d+)")
                if v:
                    slow_timers = int(v)

        return BFDConfig(
            object_id="bfd",
            raw_lines=[o.text for o in bfd_objs],
            source_os=self.os_type,
            line_numbers=[o.linenum for o in bfd_objs],
            templates=templates,
            maps=maps,
            slow_timers=slow_timers,
        )

    # -------------------------------------------------------------------------
    # IP SLA
    # -------------------------------------------------------------------------

    def parse_ip_sla(self) -> list[IPSLAOperation]:
        """Parse IP SLA operations."""
        parse = self._get_parse_obj()
        operations: dict[int, dict] = {}

        for obj in parse.find_objects(r"^ip\s+sla\s+\d+$"):
            m = re.match(r"^ip\s+sla\s+(\d+)$", obj.text.strip())
            if not m:
                continue
            sla_id = int(m.group(1))
            raw_lines, line_numbers = self._get_raw_lines_and_line_numbers(obj)

            op_type = destination = source_interface = source_ip = None
            port = frequency = threshold_val = timeout = None
            vrf = tag = None

            for c in obj.children:
                ct = c.text.strip()
                for op in ("icmp-echo", "udp-jitter", "tcp-connect", "udp-echo", "http", "dns", "ftp", "dhcp"):
                    if ct.startswith(op + " "):
                        op_type = op
                        parts = ct.split()
                        destination = parts[1] if len(parts) > 1 else None
                        src_m = re.search(r"source-ipaddr\s+(\S+)", ct)
                        if src_m:
                            try:
                                from ipaddress import IPv4Address
                                source_ip = IPv4Address(src_m.group(1))
                            except Exception:
                                pass
                        break
                if ct.startswith("frequency "):
                    v = self._extract_match(ct, r"frequency\s+(\d+)")
                    if v:
                        frequency = int(v)
                elif ct.startswith("threshold "):
                    v = self._extract_match(ct, r"threshold\s+(\d+)")
                    if v:
                        threshold_val = int(v)
                elif ct.startswith("timeout "):
                    v = self._extract_match(ct, r"timeout\s+(\d+)")
                    if v:
                        timeout = int(v)
                elif ct.startswith("tag "):
                    tag = ct[4:].strip()
                elif ct.startswith("vrf "):
                    vrf = ct[4:].strip()

            operations[sla_id] = {
                "sla_id": sla_id,
                "operation_type": op_type or "unknown",
                "destination": destination or "",
                "source_interface": source_interface,
                "source_ip": source_ip,
                "port": port,
                "frequency": frequency,
                "threshold": threshold_val,
                "timeout": timeout,
                "vrf": vrf,
                "tag": tag,
                "raw_lines": raw_lines,
                "line_numbers": line_numbers,
                "schedule": None,
                "reactions": [],
            }

        # schedules
        for obj in parse.find_objects(r"^ip\s+sla\s+schedule\s+\d+"):
            m = re.match(r"^ip\s+sla\s+schedule\s+(\d+)(.*)", obj.text.strip())
            if not m:
                continue
            sla_id = int(m.group(1))
            rest = m.group(2)
            life = self._extract_match(rest, r"\blife\s+(\S+)") or "forever"
            start_time = self._extract_match(rest, r"\bstart-time\s+(\S+)") or "now"
            recurring = "recurring" in rest
            ageout_m = re.search(r"\bageout\s+(\d+)", rest)
            ageout = int(ageout_m.group(1)) if ageout_m else None
            schedule = IPSLASchedule(sla_id=sla_id, life=life, start_time=start_time, recurring=recurring, ageout=ageout)
            if sla_id in operations:
                operations[sla_id]["schedule"] = schedule
            else:
                operations[sla_id] = {
                    "sla_id": sla_id, "operation_type": "unknown", "destination": "",
                    "schedule": schedule, "reactions": [],
                    "raw_lines": [obj.text], "line_numbers": [obj.linenum],
                }

        # reactions
        for obj in parse.find_objects(r"^ip\s+sla\s+reaction-configuration\s+\d+"):
            m = re.match(r"^ip\s+sla\s+reaction-configuration\s+(\d+)\s+react\s+(\S+)(.*)", obj.text.strip())
            if not m:
                continue
            sla_id = int(m.group(1))
            react_elem = m.group(2)
            rest = m.group(3)
            threshold_type = self._extract_match(rest, r"\bthreshold-type\s+(\S+)") or "never"
            thresh_m = re.search(r"\bthreshold-value\s+(\d+)(?:\s+(\d+))?", rest)
            upper = int(thresh_m.group(1)) if thresh_m else None
            lower = int(thresh_m.group(2)) if thresh_m and thresh_m.group(2) else None
            action_type = self._extract_match(rest, r"\baction-type\s+(\S+)") or "none"
            reaction = IPSLAReaction(
                sla_id=sla_id, react_element=react_elem, threshold_type=threshold_type,
                threshold_value_upper=upper, threshold_value_lower=lower, action_type=action_type
            )
            if sla_id in operations:
                operations[sla_id]["reactions"].append(reaction)

        result = []
        for sla_id, data in operations.items():
            result.append(IPSLAOperation(
                object_id=f"ip_sla_{sla_id}",
                source_os=self.os_type,
                raw_lines=data.get("raw_lines", []),
                line_numbers=data.get("line_numbers", []),
                sla_id=sla_id,
                operation_type=data["operation_type"],
                destination=data["destination"],
                source_interface=data.get("source_interface"),
                source_ip=data.get("source_ip"),
                port=data.get("port"),
                frequency=data.get("frequency"),
                threshold=data.get("threshold"),
                timeout=data.get("timeout"),
                vrf=data.get("vrf"),
                tag=data.get("tag"),
                schedule=data.get("schedule"),
                reactions=data.get("reactions", []),
            ))

        return result

    # -------------------------------------------------------------------------
    # EEM
    # -------------------------------------------------------------------------

    def parse_eem(self) -> list[EEMApplet]:
        """Parse EEM applet configurations."""
        parse = self._get_parse_obj()
        applets = []

        for eem_obj in parse.find_objects(r"^event\s+manager\s+applet\s+"):
            m = re.match(r"^event\s+manager\s+applet\s+(\S+)", eem_obj.text.strip())
            if not m:
                continue
            name = m.group(1)
            raw_lines, line_numbers = self._get_raw_lines_and_line_numbers(eem_obj)

            event = None
            actions = []
            description = None
            max_run_time = None

            for c in eem_obj.children:
                ct = c.text.strip()
                if ct.startswith("event "):
                    parts = ct.split()
                    event_type = parts[1] if len(parts) > 1 else "unknown"
                    params = {}
                    # parse key-value pairs from rest of line
                    rest_parts = parts[2:]
                    i = 0
                    while i < len(rest_parts) - 1:
                        key = rest_parts[i].replace("-", "_")
                        val = rest_parts[i + 1]
                        params[key] = val
                        i += 2
                    event = EEMEvent(event_type=event_type, parameters=params, raw=ct)
                elif re.match(r"action\s+", ct):
                    am = re.match(r"action\s+(\S+)\s+(\S+)\s*(.*)", ct)
                    if am:
                        actions.append(EEMAction(
                            label=am.group(1),
                            action_type=am.group(2),
                            parameters=am.group(3).strip(),
                        ))
                elif ct.startswith("description "):
                    description = ct[12:].strip()
                elif ct.startswith("maximum-run-time "):
                    v = self._extract_match(ct, r"maximum-run-time\s+(\d+)")
                    if v:
                        max_run_time = int(v)

            applets.append(EEMApplet(
                object_id=f"eem_{name}",
                raw_lines=raw_lines,
                source_os=self.os_type,
                line_numbers=line_numbers,
                name=name,
                event=event,
                actions=actions,
                description=description,
                maximum_run_time=max_run_time,
            ))

        return applets

    # -------------------------------------------------------------------------
    # Object Tracking
    # -------------------------------------------------------------------------

    def parse_object_tracks(self) -> list[ObjectTrack]:
        """Parse object tracking configurations."""
        parse = self._get_parse_obj()
        tracks = []

        for track_obj in parse.find_objects(r"^track\s+\d+\s+"):
            m = re.match(r"^track\s+(\d+)\s+(\S+)(.*)", track_obj.text.strip())
            if not m:
                continue
            track_id = int(m.group(1))
            track_type = m.group(2)
            rest = m.group(3).strip()
            raw_lines, line_numbers = self._get_raw_lines_and_line_numbers(track_obj)

            tracked_interface = tracked_interface_param = None
            tracked_sla_id = tracked_sla_param = None
            tracked_route = tracked_route_vrf = None
            list_type = None
            list_objects = []
            delay_up = delay_down = None

            if track_type == "interface":
                parts = rest.split()
                if parts:
                    tracked_interface = parts[0]
                    tracked_interface_param = parts[1] if len(parts) > 1 else "line-protocol"
            elif track_type == "ip":
                # "ip sla N reachability" or "ip route X/Y reachability"
                sla_m = re.match(r"sla\s+(\d+)\s*(\S*)", rest)
                route_m = re.match(r"route\s+(\S+)(?:\s+vrf\s+(\S+))?", rest)
                if sla_m:
                    tracked_sla_id = int(sla_m.group(1))
                    tracked_sla_param = sla_m.group(2) or "reachability"
                elif route_m:
                    tracked_route = route_m.group(1)
                    tracked_route_vrf = route_m.group(2)
            elif track_type == "list":
                lt_m = re.match(r"(boolean-and|boolean-or|threshold)(.*)", rest)
                if lt_m:
                    list_type = lt_m.group(1)
                for c in track_obj.children:
                    ct = c.text.strip()
                    obj_m = re.match(r"object\s+(\d+)(\s+not)?", ct)
                    if obj_m:
                        list_objects.append(TrackListObject(
                            object_id=int(obj_m.group(1)),
                            negate=bool(obj_m.group(2)),
                        ))

            for c in track_obj.children:
                ct = c.text.strip()
                dm = re.match(r"delay\s+(?:up\s+(\d+))?(?:\s+down\s+(\d+))?", ct)
                if dm:
                    if dm.group(1):
                        delay_up = int(dm.group(1))
                    if dm.group(2):
                        delay_down = int(dm.group(2))

            tracks.append(ObjectTrack(
                object_id=f"track_{track_id}",
                raw_lines=raw_lines,
                source_os=self.os_type,
                line_numbers=line_numbers,
                track_id=track_id,
                track_type=track_type,
                tracked_interface=tracked_interface,
                tracked_interface_param=tracked_interface_param,
                tracked_sla_id=tracked_sla_id,
                tracked_sla_param=tracked_sla_param,
                tracked_route=tracked_route,
                tracked_route_vrf=tracked_route_vrf,
                list_type=list_type,
                list_objects=list_objects,
                delay_up=delay_up,
                delay_down=delay_down,
            ))

        return tracks

    # -------------------------------------------------------------------------
    # Multicast
    # -------------------------------------------------------------------------

    def parse_multicast(self) -> MulticastConfig | None:
        """Parse IP multicast configuration."""
        parse = self._get_parse_obj()

        routing_objs = parse.find_objects(r"^ip\s+multicast-routing")
        pim_rp_objs = parse.find_objects(r"^ip\s+pim\s+rp-address")
        msdp_objs = parse.find_objects(r"^ip\s+msdp\s+")
        pim_misc_objs = parse.find_objects(r"^ip\s+pim\s+")

        if not routing_objs and not pim_rp_objs and not msdp_objs and not pim_misc_objs:
            return None

        from ipaddress import IPv4Address
        multicast_routing_enabled = bool(routing_objs)
        multicast_routing_distributed = any("distributed" in o.text for o in routing_objs)
        multicast_routing_vrfs = []
        for o in routing_objs:
            vm = re.search(r"vrf\s+(\S+)", o.text)
            if vm:
                multicast_routing_vrfs.append(vm.group(1))

        pim_rp_addresses = []
        for obj in pim_rp_objs:
            m = re.match(r"^ip\s+pim\s+rp-address\s+(\S+)(.*)", obj.text.strip())
            if m:
                try:
                    rp_addr = IPv4Address(m.group(1))
                    rest = m.group(2)
                    acl = None
                    acl_m = re.search(r"\b(\S+)$", rest.strip())
                    if acl_m and not acl_m.group(1).startswith("override") and not acl_m.group(1).startswith("bidir"):
                        acl = acl_m.group(1)
                    pim_rp_addresses.append(PIMRPAddress(
                        rp_address=rp_addr,
                        acl=acl,
                        override="override" in rest,
                        bidir="bidir" in rest,
                    ))
                except Exception:
                    pass

        pim_ssm_range = None
        pim_autorp = False
        pim_bsr_candidate = None
        pim_rp_candidate = None

        for obj in pim_misc_objs:
            t = obj.text.strip()
            if "ssm range" in t:
                pim_ssm_range = self._extract_match(t, r"\bssm\s+range\s+(\S+)")
            elif "autorp" in t.lower():
                pim_autorp = True
            elif "bsr-candidate" in t:
                m = re.match(r"^ip\s+pim\s+bsr-candidate\s+(.*)", t)
                if m:
                    pim_bsr_candidate = m.group(1).strip()
            elif re.match(r"^ip\s+pim\s+rp-candidate\s+", t):
                m = re.match(r"^ip\s+pim\s+rp-candidate\s+(.*)", t)
                if m:
                    pim_rp_candidate = m.group(1).strip()

        msdp_peers = []
        msdp_originator_id = None
        for obj in msdp_objs:
            t = obj.text.strip()
            if re.match(r"^ip\s+msdp\s+peer\s+", t):
                m = re.match(r"^ip\s+msdp\s+peer\s+(\S+)(.*)", t)
                if m:
                    try:
                        peer_addr = IPv4Address(m.group(1))
                        rest = m.group(2)
                        connect_src = self._extract_match(rest, r"connect-source\s+(\S+)")
                        remote_as = None
                        asm = re.search(r"remote-as\s+(\d+)", rest)
                        if asm:
                            remote_as = int(asm.group(1))
                        msdp_peers.append(MSDPPeer(
                            peer_address=peer_addr, connect_source=connect_src, remote_as=remote_as
                        ))
                    except Exception:
                        pass
            elif "originator-id" in t:
                msdp_originator_id = self._extract_match(t, r"originator-id\s+(\S+)")

        all_objs = list(routing_objs) + list(pim_rp_objs) + list(msdp_objs) + list(pim_misc_objs)
        return MulticastConfig(
            object_id="multicast",
            raw_lines=[o.text for o in all_objs],
            source_os=self.os_type,
            line_numbers=[o.linenum for o in all_objs],
            multicast_routing_enabled=multicast_routing_enabled,
            multicast_routing_distributed=multicast_routing_distributed,
            multicast_routing_vrfs=multicast_routing_vrfs,
            pim_rp_addresses=pim_rp_addresses,
            pim_ssm_range=pim_ssm_range,
            pim_autorp=pim_autorp,
            pim_bsr_candidate=pim_bsr_candidate,
            pim_rp_candidate=pim_rp_candidate,
            msdp_peers=msdp_peers,
            msdp_originator_id=msdp_originator_id,
        )
