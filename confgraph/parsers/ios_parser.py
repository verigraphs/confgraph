"""Cisco IOS/IOS-XE configuration parser."""

import re
from ipaddress import IPv4Address, IPv4Interface, IPv4Network, IPv6Address, IPv6Interface, IPv6Network

from confgraph.parsers.base import BaseParser, apply_peer_group_command, _default_pg_data
from confgraph.utils.interface import normalize_interface_name
from confgraph.models.base import OSType
from confgraph.models.vrf import VRFConfig
from confgraph.models.interface import (
    InterfaceConfig,
    InterfaceType,
    HSRPGroup,
    VRRPGroup,
    GLBPGroup,
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
    OSPFVirtualLink,
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
from confgraph.models.isis import ISISConfig, ISISInterface, ISISRedistribute
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
from confgraph.models.aaa import AAAConfig, AAAAuthList, AAAAuthorList, AAAAcctList, TacacsServer, RadiusServer
from confgraph.models.dns import DNSConfig
from confgraph.models.dhcp import DHCPConfig, DHCPExcludedRange, DHCPPool
from confgraph.models.lldp import LLDPConfig
from confgraph.models.cdp import CDPConfig
from confgraph.models.stp import STPConfig, STPVlanConfig
from confgraph.models.vlan import VLANEntry
from confgraph.models.netflow import NetFlowConfig, NetFlowDestination


# Known DIRECT child lines per high-blast-radius block — _KNOWN_TOP_LEVEL_PATTERNS one
# level down (see BaseParser._KNOWN_CHILD_PATTERNS for the collector rules). A child
# line of a claimed block matching none of its known patterns is emitted as an
# UnrecognizedBlock ("<header> > <line>") so it is disclosed, not silently dropped.
#
# PRECISION OVER RECALL: every form a parse method consumes MUST be listed; forms we
# are unsure about are listed too ("unsure -> known"). The lists cover IOS/IOS-XE plus
# the NX-OS/EOS forms, since those parsers inherit this registry. "no ..." lines are
# skipped by the collector itself (tombstone surface) and never need listing.
_IOS_KNOWN_CHILD_PATTERNS: list[tuple[str, list[str]]] = [
    (r"^router\s+ospf\b", [
        r"^router-id\b",
        r"^log-adjacency-changes\b",
        r"^auto-cost\b",
        r"^passive-interface\b",
        r"^network\b",
        r"^area\b",
        r"^redistribute\b",
        r"^max-metric\b",
        r"^default-information\b",
        r"^default-metric\b",
        r"^distance\b",
        r"^max-lsa\b",
        r"^maximum-paths\b",        # unsure -> known (ECMP width, not modeled)
        r"^timers\b",
        r"^shutdown\b",
        r"^graceful-restart\b",
        r"^nsf\b",
        r"^bfd\b",
        r"^vrf\b",                  # NX-OS: per-VRF sub-block under router ospf
        r"^address-family\b",       # sub-block header; body not descended (v1)
        r"^exit-address-family\b",
    ]),
    (r"^router\s+bgp\b", [
        r"^bgp\b",                  # bgp router-id / cluster-id / bestpath / confed / ...
        r"^neighbor\b",
        r"^network\b",
        r"^redistribute\b",
        r"^address-family\b",       # sub-block header; body not descended (v1)
        r"^exit-address-family\b",
        r"^aggregate-address\b",
        r"^template\b",             # NX-OS: template peer <name>
        r"^inherit\b",              # NX-OS: inherit peer <name>
        r"^vrf\b",                  # NX-OS: vrf <name> sub-block
        r"^timers\b",
        r"^maximum-paths\b",
        r"^distance\b",
        r"^auto-summary\b",
        r"^synchronization\b",
        r"^default-information\b",  # unsure -> known
        r"^default-metric\b",       # unsure -> known
        r"^router-id\b",            # NX-OS bare form
        r"^cluster-id\b",           # NX-OS bare form
        r"^log-neighbor-changes\b", # NX-OS bare form
        r"^bestpath\b",             # NX-OS bare form
        r"^confederation\b",        # NX-OS bare form
        r"^graceful-restart\b",
        r"^event-history\b",        # NX-OS cosmetic
    ]),
    (r"^router\s+isis\b", [
        r"^net\b",
        r"^is-type\b",
        r"^metric-style\b",
        r"^metric\b",
        r"^log-adjacency-changes\b",
        r"^passive-interface\b",
        r"^passive\b",              # EOS form
        r"^redistribute\b",
        r"^address-family\b",       # sub-block header; body not descended (v1)
        r"^exit-address-family\b",
        r"^spf-interval\b",
        r"^lsp-gen-interval\b",
        r"^lsp-refresh-interval\b",
        r"^max-lsp-lifetime\b",
        r"^default-information\b",
        r"^summary-address\b",      # unsure -> known
        r"^maximum-paths\b",        # unsure -> known
        r"^distance\b",             # unsure -> known
        r"^authentication\b",       # unsure -> known
        r"^area-password\b",        # unsure -> known
        r"^domain-password\b",      # unsure -> known
        r"^set-overload-bit\b",     # unsure -> known
        r"^hostname\b",             # hostname dynamic
        r"^nsf\b",
        r"^bfd\b",
        r"^vrf\b",
    ]),
    (r"^router\s+eigrp\b", [
        r"^network\b",
        r"^passive-interface\b",
        r"^redistribute\b",
        r"^eigrp\b",                # eigrp router-id / stub / log-neighbor-changes
        r"^address-family\b",       # named mode; body not descended (v1)
        r"^af-interface\b",
        r"^topology\b",
        r"^exit-address-family\b",
        r"^exit-af-interface\b",
        r"^exit-af-topology\b",
        r"^metric\b",
        r"^variance\b",
        r"^maximum-paths\b",
        r"^distance\b",
        r"^default-metric\b",
        r"^auto-summary\b",
        r"^summary-address\b",      # unsure -> known
        r"^timers\b",               # unsure -> known
        r"^neighbor\b",             # unsure -> known (static neighbors)
        r"^nsf\b",
        r"^bfd\b",
        r"^shutdown\b",
    ]),
    (r"^interface\b", [
        # Broad by design: the interface surface is huge and OS-divergent, so v1
        # lists every family the IOS/NX-OS/EOS interface parsers consume plus the
        # common benign/cosmetic families. High-signal unparsed forms (e.g.
        # "service instance", "rate-limit") fall through and are disclosed.
        r"^arp\b",
        r"^authentication\b",
        r"^bandwidth\b",
        r"^bfd\b",
        r"^carrier-delay\b",
        r"^cdp\b",
        r"^channel-group\b",
        r"^clns\b",
        r"^crypto\b",
        r"^dampening\b",
        r"^delay\b",
        r"^description\b",
        r"^dot1x\b",
        r"^duplex\b",
        r"^encapsulation\b",
        r"^evpn\b",
        r"^fabric\b",               # NX-OS: fabric forwarding mode anycast-gateway
        r"^fex\b",
        r"^flowcontrol\b",
        r"^glbp\b",
        r"^hold-queue\b",
        r"^host-reachability\b",    # NX-OS NVE
        r"^hsrp\b",                 # NX-OS sub-block header; body not descended (v1)
        r"^ip\b",
        r"^ipv4\b",
        r"^ipv6\b",
        r"^isis\b",
        r"^keepalive\b",
        r"^lacp\b",
        r"^lldp\b",
        r"^load-interval\b",
        r"^logging\b",
        r"^mab\b",
        r"^mac\b",
        r"^mac-address\b",
        r"^mcast-group\b",          # NX-OS NVE (also under member vni)
        r"^mdix\b",
        r"^media-type\b",
        r"^medium\b",
        r"^member\b",               # NX-OS NVE: member vni ...
        r"^mlag\b",                 # EOS
        r"^mpls\b",
        r"^mtu\b",
        r"^negotiation\b",
        r"^ntp\b",
        r"^ospfv3\b",
        r"^pim\b",
        r"^port-channel\b",
        r"^power\b",
        r"^priority-flow-control\b",
        r"^ptp\b",
        r"^service-policy\b",
        r"^shutdown\b",
        r"^snmp\b",
        r"^source-interface\b",     # NX-OS NVE
        r"^spanning-tree\b",
        r"^speed\b",
        r"^standby\b",
        r"^storm-control\b",
        r"^suppress-arp\b",         # NX-OS NVE
        r"^switchport\b",
        r"^tunnel\b",
        r"^udld\b",
        r"^vpc\b",
        r"^vrf\b",
        r"^vrrp\b",
        r"^vtp\b",
        r"^vxlan\b",                # EOS: interface Vxlan1 children
        r"^xconnect\b",
        r"^zone-member\b",
    ]),
]


class IOSParser(BaseParser):
    """Parser for Cisco IOS and IOS-XE configurations.

    Supports both IOS and IOS-XE syntax (they are very similar).
    """

    _KNOWN_CHILD_PATTERNS: list[tuple[str, list[str]]] = _IOS_KNOWN_CHILD_PATTERNS

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

            # Capture the full VRF block, including lines nested under
            # ``address-family ipv4`` (route-targets, route-maps). The base
            # helper only walks direct children, so build raw_lines recursively
            # to avoid stopping at the ``address-family ipv4`` line.
            raw_lines = [vrf_obj.text]
            line_numbers = [vrf_obj.linenum]
            for child in vrf_obj.all_children:
                raw_lines.append(child.text)
                line_numbers.append(child.linenum)

            # Extract RD
            rd = None
            rd_children = vrf_obj.find_child_objects(r"^\s+rd\s+(\S+)")
            if rd_children:
                rd = self._extract_match(rd_children[0].text, r"^\s+rd\s+(\S+)")

            # Extract route-targets and route-maps. On IOS these live nested
            # under ``address-family ipv4`` / ``ipv6``, so walk all_children
            # (recursive) rather than only direct children.
            rt_import = []
            rt_export = []
            rt_both = []
            route_map_import = None
            route_map_export = None

            for child in vrf_obj.all_children:
                text = child.text.strip()
                if text.startswith("route-target export "):
                    rt_val = self._extract_match(text, r"route-target\s+export\s+(\S+)")
                    if rt_val and rt_val not in rt_export:
                        rt_export.append(rt_val)
                elif text.startswith("route-target import "):
                    rt_val = self._extract_match(text, r"route-target\s+import\s+(\S+)")
                    if rt_val and rt_val not in rt_import:
                        rt_import.append(rt_val)
                elif text.startswith("route-target both "):
                    rt_val = self._extract_match(text, r"route-target\s+both\s+(\S+)")
                    if rt_val and rt_val not in rt_both:
                        rt_both.append(rt_val)
                elif text.startswith("route-map") and "import" in text:
                    route_map_import = self._extract_match(
                        text, r"route-map\s+(\S+)\s+import"
                    )
                elif text.startswith("route-map") and "export" in text:
                    route_map_export = self._extract_match(
                        text, r"route-map\s+(\S+)\s+export"
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

    def _parse_iface_bfd(self, intf_obj) -> tuple[int | None, int | None, int | None, str | None]:
        """Return (bfd_interval, bfd_min_rx, bfd_multiplier, bfd_template) for an interface.

        IOS / EOS / NX-OS syntax::

            bfd interval 300 min_rx 300 multiplier 3
            bfd template MY-TEMPLATE

        Override this in platform-specific subclasses for different syntax.
        """
        bfd_interval = bfd_min_rx = bfd_multiplier = bfd_template = None
        bfd_ch = intf_obj.find_child_objects(r"^\s+bfd\s+interval\s+")
        if bfd_ch:
            m = re.match(
                r"^\s+bfd\s+interval\s+(\d+)\s+min_rx\s+(\d+)\s+multiplier\s+(\d+)",
                bfd_ch[-1].text,
            )
            if m:
                bfd_interval = int(m.group(1))
                bfd_min_rx = int(m.group(2))
                bfd_multiplier = int(m.group(3))
        tmpl_ch = intf_obj.find_child_objects(r"^\s+bfd\s+template\s+")
        if tmpl_ch:
            v = self._extract_match(tmpl_ch[-1].text, r"^\s+bfd\s+template\s+(\S+)")
            if v:
                bfd_template = v
        return bfd_interval, bfd_min_rx, bfd_multiplier, bfd_template

    def parse_interfaces(self) -> list[InterfaceConfig]:
        """Parse interface configurations."""
        interfaces = []
        parse = self._get_parse_obj()

        # Find all interface configurations
        intf_objs = parse.find_objects(r"^interface\s+")

        # Coalesce duplicate interface stanzas at the line level. IOS allows
        # the same interface to appear in multiple stanzas — the CLI merges
        # them into one running-config interface. By extending the first
        # object's children with subsequent stanzas' children, all
        # find_child_objects() calls naturally see the combined block.
        # Scalar extractions use [-1] (last match wins), mirroring IOS
        # merge semantics where later stanzas override earlier ones.
        # List extractions iterate all children, naturally unioning across
        # stanzas. This avoids the model-level merge ambiguity where
        # "field absent" vs "field explicitly set to default" are
        # indistinguishable.
        intf_objs = self._coalesce_interface_stanzas(intf_objs)

        for intf_obj in intf_objs:
            intf_name = self._extract_match(intf_obj.text, r"^interface\s+(\S+)")
            if not intf_name:
                continue

            raw_lines, line_numbers = self._get_raw_lines_and_line_numbers(intf_obj)

            # Determine interface type
            intf_type = self._determine_interface_type(intf_name)

            # Basic attributes
            iface_no_commands: list[str] = []
            description = None
            desc_children = intf_obj.find_child_objects(r"^\s+description\s+(.+)")
            if desc_children:
                description = self._extract_match(
                    desc_children[-1].text, r"^\s+description\s+(.+)"
                )
            elif intf_obj.find_child_objects(r"^\s+no\s+description"):
                iface_no_commands.append(f"field:interface:{intf_name}:description")

            enabled = not self._is_shutdown(intf_obj)

            # VRF
            vrf = self._extract_interface_vrf(intf_obj)

            # IP addressing
            ip_address = None
            ip_children = intf_obj.find_child_objects(
                r"^\s+ip\s+address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)"
            )
            # Filter out secondary IPs — primary is the last non-secondary match
            ip_children = [c for c in ip_children if "secondary" not in c.text.lower()]
            if ip_children:
                match = re.search(
                    r"^\s+ip\s+address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)",
                    ip_children[-1].text,
                )
                if match:
                    ip = match.group(1)
                    mask = match.group(2)
                    # Convert to prefix length
                    ip_address = IPv4Interface(f"{ip}/{mask}")

            # Secondary IPs
            secondary_ips = []
            secondary_children = intf_obj.find_child_objects(
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
            ipv6_children = intf_obj.find_child_objects(r"^\s+ipv6\s+address\s+(\S+)")
            for ipv6_child in ipv6_children:
                match = re.search(r"^\s+ipv6\s+address\s+(\S+)", ipv6_child.text)
                if match and "link-local" not in ipv6_child.text:
                    try:
                        ipv6_addresses.append(IPv6Interface(match.group(1)))
                    except ValueError:
                        pass

            # MTU (L2/system)
            mtu = None
            mtu_children = intf_obj.find_child_objects(r"^\s+mtu\s+(\d+)")
            if mtu_children:
                mtu = int(self._extract_match(mtu_children[-1].text, r"^\s+mtu\s+(\d+)"))

            # IP MTU (L3 override — OSPF uses this when present)
            ip_mtu = None
            ip_mtu_children = intf_obj.find_child_objects(r"^\s+ip\s+mtu\s+(\d+)")
            if ip_mtu_children:
                ip_mtu = int(self._extract_match(ip_mtu_children[-1].text, r"^\s+ip\s+mtu\s+(\d+)"))

            # Speed
            speed = None
            speed_children = intf_obj.find_child_objects(r"^\s+speed\s+(\S+)")
            if speed_children:
                speed = self._extract_match(speed_children[-1].text, r"^\s+speed\s+(\S+)")

            # Duplex
            duplex = None
            duplex_children = intf_obj.find_child_objects(r"^\s+duplex\s+(\S+)")
            if duplex_children:
                duplex = self._extract_match(duplex_children[-1].text, r"^\s+duplex\s+(\S+)")

            # Bandwidth
            bandwidth = None
            bw_children = intf_obj.find_child_objects(r"^\s+bandwidth\s+(\d+)")
            if bw_children:
                bandwidth = int(
                    self._extract_match(bw_children[-1].text, r"^\s+bandwidth\s+(\d+)")
                )

            # Delay (for EIGRP composite metric)
            delay = None
            delay_children = intf_obj.find_child_objects(r"^\s+delay\s+(\d+)")
            if delay_children:
                delay = int(
                    self._extract_match(delay_children[-1].text, r"^\s+delay\s+(\d+)")
                )

            # Switchport attributes
            switchport_mode = None
            access_vlan = None
            trunk_allowed_vlans = []
            trunk_native_vlan = None

            sw_mode_children = intf_obj.find_child_objects(r"^\s+switchport\s+mode\s+(\S+)")
            if sw_mode_children:
                switchport_mode = self._extract_match(
                    sw_mode_children[-1].text, r"^\s+switchport\s+mode\s+(\S+)"
                )

            access_vlan_children = intf_obj.find_child_objects(
                r"^\s+switchport\s+access\s+vlan\s+(\d+)"
            )
            if access_vlan_children:
                access_vlan = int(
                    self._extract_match(
                        access_vlan_children[-1].text, r"^\s+switchport\s+access\s+vlan\s+(\d+)"
                    )
                )

            trunk_allowed_children = intf_obj.find_child_objects(
                r"^\s+switchport\s+trunk\s+allowed\s+vlan\s+(.+)"
            )
            if trunk_allowed_children:
                # Process all lines as ordered set operations:
                #   'vlan <list>'     → set/replace (anchors the set)
                #   'add <list>'      → union
                #   'remove <list>'   → difference
                #   'except <list>'   → all-except (1-4094 minus list; absolute,
                #                       so it anchors the set too)
                #   'none'            → empty set (anchors the set)
                #   'all'             → all (1-4094) (anchors the set)
                #
                # add/remove are *stateful* — they operate on the device's
                # current allowed list.  In a full running config that state is
                # anchored by a preceding absolute form ('vlan <list>', 'none',
                # 'all', 'except <list>') and the lines fold into one set as
                # before.  In a proposal snippet there is no anchor: the base
                # state lives in the baseline config, which this parser never
                # sees.  Un-anchored delta lines
                # are therefore emitted as interface-scoped operations
                # (field:interface:<name>:trunk_allowed_vlans:<op>:<spec>) that
                # the merger applies against the baseline list, and
                # trunk_allowed_vlans stays [] (= "not mentioned").
                _ALL_VLANS = set(range(1, 4095))
                vlan_set: set[int] = set()
                anchored = False  # True once an absolute form fixes the base state
                trunk_vlan_ops: list[tuple[str, str]] = []
                for child in trunk_allowed_children:
                    vlan_str = self._extract_match(
                        child.text,
                        r"^\s+switchport\s+trunk\s+allowed\s+vlan\s+(.+)",
                    )
                    if not vlan_str:
                        continue
                    vlan_str = vlan_str.strip()
                    if vlan_str == "none":
                        anchored = True
                        trunk_vlan_ops.clear()
                        vlan_set = set()
                    elif vlan_str == "all":
                        anchored = True
                        trunk_vlan_ops.clear()
                        vlan_set = set(_ALL_VLANS)
                    elif vlan_str.startswith("except "):
                        # 'except' is absolute on the device (all VLANs minus
                        # the list, independent of prior state) — it anchors.
                        spec = vlan_str[7:].strip().replace(" ", "")
                        anchored = True
                        trunk_vlan_ops.clear()
                        vlan_set = _ALL_VLANS - set(self._parse_vlan_list(spec))
                    elif vlan_str.startswith(("add ", "remove ")):
                        op, _, spec = vlan_str.partition(" ")
                        spec = spec.strip().replace(" ", "")
                        if not spec:
                            continue
                        if anchored:
                            spec_set = set(self._parse_vlan_list(spec))
                            if op == "add":
                                vlan_set |= spec_set
                            else:  # remove
                                vlan_set -= spec_set
                        else:
                            trunk_vlan_ops.append((op, spec))
                    else:
                        anchored = True
                        trunk_vlan_ops.clear()
                        vlan_set = set(self._parse_vlan_list(vlan_str))
                if anchored:
                    trunk_allowed_vlans = sorted(vlan_set)
                for op, spec in trunk_vlan_ops:
                    iface_no_commands.append(
                        f"field:interface:{intf_name}:trunk_allowed_vlans:{op}:{spec}"
                    )

            trunk_native_children = intf_obj.find_child_objects(
                r"^\s+switchport\s+trunk\s+native\s+vlan\s+(\d+)"
            )
            if trunk_native_children:
                trunk_native_vlan = int(
                    self._extract_match(
                        trunk_native_children[-1].text,
                        r"^\s+switchport\s+trunk\s+native\s+vlan\s+(\d+)",
                    )
                )

            # Port-Security
            port_security_enabled = bool(
                intf_obj.find_child_objects(r"^\s+switchport\s+port-security\s*$")
            )
            port_security_max_mac = None
            psmax_ch = intf_obj.find_child_objects(
                r"^\s+switchport\s+port-security\s+maximum\s+(\d+)"
            )
            if psmax_ch:
                val = self._extract_match(
                    psmax_ch[-1].text, r"^\s+switchport\s+port-security\s+maximum\s+(\d+)"
                )
                if val:
                    port_security_max_mac = int(val)

            port_security_violation = None
            psv_ch = intf_obj.find_child_objects(
                r"^\s+switchport\s+port-security\s+violation\s+(\S+)"
            )
            if psv_ch:
                port_security_violation = self._extract_match(
                    psv_ch[-1].text,
                    r"^\s+switchport\s+port-security\s+violation\s+(\S+)",
                )

            port_security_sticky = bool(
                intf_obj.find_child_objects(
                    r"^\s+switchport\s+port-security\s+mac-address\s+sticky"
                )
            )

            # 802.1X
            dot1x_port_control = None
            # Modern IOS syntax: authentication port-control <mode>
            auth_pc_ch = intf_obj.find_child_objects(
                r"^\s+authentication\s+port-control\s+(\S+)"
            )
            if auth_pc_ch:
                dot1x_port_control = self._extract_match(
                    auth_pc_ch[-1].text, r"^\s+authentication\s+port-control\s+(\S+)"
                )
            else:
                # Legacy syntax: dot1x port-control <mode>
                d1x_pc_ch = intf_obj.find_child_objects(
                    r"^\s+dot1x\s+port-control\s+(\S+)"
                )
                if d1x_pc_ch:
                    dot1x_port_control = self._extract_match(
                        d1x_pc_ch[-1].text, r"^\s+dot1x\s+port-control\s+(\S+)"
                    )

            dot1x_host_mode = None
            hm_ch = intf_obj.find_child_objects(
                r"^\s+authentication\s+host-mode\s+(\S+)"
            )
            if hm_ch:
                dot1x_host_mode = self._extract_match(
                    hm_ch[-1].text, r"^\s+authentication\s+host-mode\s+(\S+)"
                )

            dot1x_mab = bool(intf_obj.find_child_objects(r"^\s+mab\s*$"))

            dot1x_guest_vlan = None
            gv_ch = intf_obj.find_child_objects(
                r"^\s+authentication\s+event\s+no-response\s+action\s+authorize\s+vlan\s+(\d+)"
            )
            if gv_ch:
                val = self._extract_match(
                    gv_ch[-1].text,
                    r"^\s+authentication\s+event\s+no-response\s+action\s+authorize\s+vlan\s+(\d+)",
                )
                if val:
                    dot1x_guest_vlan = int(val)

            dot1x_auth_fail_vlan = None
            afv_ch = intf_obj.find_child_objects(
                r"^\s+authentication\s+event\s+fail\s+action\s+authorize\s+vlan\s+(\d+)"
            )
            if afv_ch:
                val = self._extract_match(
                    afv_ch[-1].text,
                    r"^\s+authentication\s+event\s+fail\s+action\s+authorize\s+vlan\s+(\d+)",
                )
                if val:
                    dot1x_auth_fail_vlan = int(val)

            # STP per-interface
            stp_portfast: bool | None = None
            if intf_obj.find_child_objects(r"^\s+spanning-tree\s+portfast\b"):
                stp_portfast = True
            elif intf_obj.find_child_objects(r"^\s+no\s+spanning-tree\s+portfast\b"):
                stp_portfast = False

            stp_bpduguard: bool | None = None
            bg_ch = intf_obj.find_child_objects(r"^\s+spanning-tree\s+bpduguard\s+")
            if bg_ch:
                stp_bpduguard = "enable" in bg_ch[-1].text

            stp_bpdufilter: bool | None = None
            bf_ch = intf_obj.find_child_objects(r"^\s+spanning-tree\s+bpdufilter\s+")
            if bf_ch:
                stp_bpdufilter = "enable" in bf_ch[-1].text

            stp_cost: int | None = None
            cost_ch = intf_obj.find_child_objects(r"^\s+spanning-tree\s+cost\s+(\d+)")
            if cost_ch:
                val = self._extract_match(cost_ch[-1].text, r"spanning-tree\s+cost\s+(\d+)")
                if val:
                    stp_cost = int(val)

            stp_port_priority: int | None = None
            pp_ch = intf_obj.find_child_objects(r"^\s+spanning-tree\s+port-priority\s+(\d+)")
            if pp_ch:
                val = self._extract_match(pp_ch[-1].text, r"spanning-tree\s+port-priority\s+(\d+)")
                if val:
                    stp_port_priority = int(val)

            stp_root_guard = bool(
                intf_obj.find_child_objects(r"^\s+spanning-tree\s+guard\s+root")
            )

            # Port-channel
            channel_group = None
            channel_group_mode = None
            ch_group_children = intf_obj.find_child_objects(
                r"^\s+channel-group\s+(\d+)\s+mode\s+(\S+)"
            )
            if ch_group_children:
                match = re.search(
                    r"^\s+channel-group\s+(\d+)\s+mode\s+(\S+)",
                    ch_group_children[-1].text,
                )
                if match:
                    channel_group = int(match.group(1))
                    channel_group_mode = match.group(2)

            min_links = None
            ml_children = intf_obj.find_child_objects(
                r"^\s+port-channel\s+min-links\s+(\d+)"
            )
            if ml_children:
                ml_match = re.search(
                    r"port-channel\s+min-links\s+(\d+)", ml_children[-1].text
                )
                if ml_match:
                    min_links = int(ml_match.group(1))

            # LACP per-interface
            lacp_port_priority = None
            lacp_pp_children = intf_obj.find_child_objects(
                r"^\s+lacp\s+port-priority\s+(\d+)"
            )
            if lacp_pp_children:
                lacp_pp_match = re.search(
                    r"lacp\s+port-priority\s+(\d+)", lacp_pp_children[-1].text
                )
                if lacp_pp_match:
                    lacp_port_priority = int(lacp_pp_match.group(1))

            lacp_rate = None
            lacp_rate_children = intf_obj.find_child_objects(
                r"^\s+lacp\s+rate\s+(fast|normal)"
            )
            if lacp_rate_children:
                lacp_rate_match = re.search(
                    r"lacp\s+rate\s+(fast|normal)", lacp_rate_children[-1].text
                )
                if lacp_rate_match:
                    lacp_rate = lacp_rate_match.group(1)

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
            ospf_mtu_ignore = False

            # ip ospf <process> area <area>
            ospf_area_children = intf_obj.find_child_objects(
                r"^\s+ip\s+ospf\s+(\d+)\s+area\s+(\S+)"
            )
            if ospf_area_children:
                match = re.search(
                    r"^\s+ip\s+ospf\s+(\d+)\s+area\s+(\S+)",
                    ospf_area_children[-1].text,
                )
                if match:
                    ospf_process_id = int(match.group(1))
                    ospf_area = match.group(2)

            # ip ospf cost
            ospf_cost_children = intf_obj.find_child_objects(r"^\s+ip\s+ospf\s+cost\s+(\d+)")
            if ospf_cost_children:
                ospf_cost = int(
                    self._extract_match(ospf_cost_children[-1].text, r"^\s+ip\s+ospf\s+cost\s+(\d+)")
                )
            elif intf_obj.find_child_objects(r"^\s+no\s+ip\s+ospf\s+cost"):
                iface_no_commands.append(f"field:interface:{intf_name}:ospf_cost")

            # ip ospf priority
            ospf_priority_children = intf_obj.find_child_objects(
                r"^\s+ip\s+ospf\s+priority\s+(\d+)"
            )
            if ospf_priority_children:
                ospf_priority = int(
                    self._extract_match(
                        ospf_priority_children[-1].text, r"^\s+ip\s+ospf\s+priority\s+(\d+)"
                    )
                )

            # ip ospf hello-interval
            ospf_hello_children = intf_obj.find_child_objects(
                r"^\s+ip\s+ospf\s+hello-interval\s+(\d+)"
            )
            if ospf_hello_children:
                ospf_hello_interval = int(
                    self._extract_match(
                        ospf_hello_children[-1].text, r"^\s+ip\s+ospf\s+hello-interval\s+(\d+)"
                    )
                )

            # ip ospf dead-interval
            ospf_dead_children = intf_obj.find_child_objects(
                r"^\s+ip\s+ospf\s+dead-interval\s+(\d+)"
            )
            if ospf_dead_children:
                ospf_dead_interval = int(
                    self._extract_match(
                        ospf_dead_children[-1].text, r"^\s+ip\s+ospf\s+dead-interval\s+(\d+)"
                    )
                )

            # ip ospf network
            ospf_network_children = intf_obj.find_child_objects(
                r"^\s+ip\s+ospf\s+network\s+(\S+)"
            )
            if ospf_network_children:
                ospf_network_type = self._extract_match(
                    ospf_network_children[-1].text, r"^\s+ip\s+ospf\s+network\s+(.+)"
                )

            # ip ospf authentication (with or without mode argument)
            ospf_auth_children = intf_obj.find_child_objects(
                r"^\s+ip\s+ospf\s+authentication\b"
            )
            if ospf_auth_children:
                auth_mode = self._extract_match(
                    ospf_auth_children[-1].text, r"^\s+ip\s+ospf\s+authentication\s+(\S+)"
                )
                # Bare "ip ospf authentication" (no argument) → simple-password mode
                ospf_authentication = auth_mode if auth_mode else "simple"

            # ip ospf authentication-key (simple-password key)
            ospf_authkey_children = intf_obj.find_child_objects(
                r"^\s+ip\s+ospf\s+authentication-key\s+(\S+)"
            )
            if ospf_authkey_children:
                ospf_authentication_key = self._extract_match(
                    ospf_authkey_children[-1].text,
                    r"^\s+ip\s+ospf\s+authentication-key\s+(\S+)",
                )

            # ip ospf message-digest-key
            ospf_md_key_children = intf_obj.find_child_objects(
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

            # ip ospf mtu-ignore
            if intf_obj.find_child_objects(r"^\s+ip\s+ospf\s+mtu-ignore"):
                ospf_mtu_ignore = True

            # Tunnel attributes
            tunnel_source = None
            tunnel_destination = None
            tunnel_mode = None
            tunnel_protection_profile = None
            tunnel_key = None
            nhrp_network_id = None
            nhrp_authentication = None
            nhrp_nhs: list = []
            nhrp_map: list = []

            if intf_type == InterfaceType.TUNNEL:
                tunnel_src_children = intf_obj.find_child_objects(
                    r"^\s+tunnel\s+source\s+(\S+)"
                )
                if tunnel_src_children:
                    tunnel_source = self._extract_match(
                        tunnel_src_children[-1].text, r"^\s+tunnel\s+source\s+(\S+)"
                    )

                tunnel_dst_children = intf_obj.find_child_objects(
                    r"^\s+tunnel\s+destination\s+(\S+)"
                )
                if tunnel_dst_children:
                    dst_str = self._extract_match(
                        tunnel_dst_children[-1].text, r"^\s+tunnel\s+destination\s+(\S+)"
                    )
                    try:
                        tunnel_destination = IPv4Address(dst_str)
                    except ValueError:
                        pass

                tunnel_mode_children = intf_obj.find_child_objects(
                    r"^\s+tunnel\s+mode\s+(.+)"
                )
                if tunnel_mode_children:
                    tunnel_mode = self._extract_match(
                        tunnel_mode_children[-1].text, r"^\s+tunnel\s+mode\s+(.+)"
                    )

                # tunnel protection ipsec profile <name>
                tp_children = intf_obj.find_child_objects(
                    r"^\s+tunnel\s+protection\s+ipsec\s+profile\s+(\S+)"
                )
                if tp_children:
                    tunnel_protection_profile = self._extract_match(
                        tp_children[-1].text,
                        r"^\s+tunnel\s+protection\s+ipsec\s+profile\s+(\S+)",
                    )

                # tunnel key <num>
                tk_children = intf_obj.find_child_objects(r"^\s+tunnel\s+key\s+(\d+)")
                if tk_children:
                    key_str = self._extract_match(
                        tk_children[-1].text, r"^\s+tunnel\s+key\s+(\d+)"
                    )
                    if key_str:
                        tunnel_key = int(key_str)

                # ip nhrp network-id <id>
                nid_children = intf_obj.find_child_objects(
                    r"^\s+ip\s+nhrp\s+network-id\s+(\d+)"
                )
                if nid_children:
                    nid_str = self._extract_match(
                        nid_children[-1].text, r"^\s+ip\s+nhrp\s+network-id\s+(\d+)"
                    )
                    if nid_str:
                        nhrp_network_id = int(nid_str)

                # ip nhrp authentication <key>
                na_children = intf_obj.find_child_objects(
                    r"^\s+ip\s+nhrp\s+authentication\s+(\S+)"
                )
                if na_children:
                    nhrp_authentication = self._extract_match(
                        na_children[-1].text, r"^\s+ip\s+nhrp\s+authentication\s+(\S+)"
                    )

                # ip nhrp nhs <ip> (one per line, multiple allowed)
                nhs_children = intf_obj.find_child_objects(
                    r"^\s+ip\s+nhrp\s+nhs\s+(\d+\.\d+\.\d+\.\d+)"
                )
                for nhs_child in nhs_children:
                    ip_str = self._extract_match(
                        nhs_child.text, r"^\s+ip\s+nhrp\s+nhs\s+(\d+\.\d+\.\d+\.\d+)"
                    )
                    try:
                        nhrp_nhs.append(IPv4Address(ip_str))
                    except ValueError:
                        pass

                # ip nhrp map <proto-addr> <nbma-addr>
                nmap_children = intf_obj.find_child_objects(
                    r"^\s+ip\s+nhrp\s+map\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)"
                )
                for nmap_child in nmap_children:
                    m = re.search(
                        r"^\s+ip\s+nhrp\s+map\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)",
                        nmap_child.text,
                    )
                    if m:
                        nhrp_map.append(f"{m.group(1)} {m.group(2)}")

            # HSRP groups
            hsrp_groups = self._parse_hsrp_groups(intf_obj)

            # VRRP groups
            vrrp_groups = self._parse_vrrp_groups(intf_obj)

            # GLBP groups
            glbp_groups = self._parse_glbp_groups(intf_obj)

            # Helper addresses
            helper_addresses = []
            helper_children = intf_obj.find_child_objects(
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

            # MPLS per-interface
            mpls_ip = bool(intf_obj.find_child_objects(r"^\s+mpls\s+ip\b"))
            if intf_obj.find_child_objects(r"^\s+no\s+mpls\s+ip\b"):
                iface_no_commands.append(f"field:interface:{intf_name}:mpls_ip")

            # PIM per-interface
            pim_mode = None
            pim_ch = intf_obj.find_child_objects(r"^\s+ip\s+pim\s+")
            if pim_ch:
                pm = re.match(r"^\s+ip\s+pim\s+(sparse-mode|dense-mode|sparse-dense-mode)", pim_ch[-1].text)
                if pm:
                    pim_mode = pm.group(1)
            pim_dr_priority = None
            pdr_ch = intf_obj.find_child_objects(r"^\s+ip\s+pim\s+dr-priority\s+(\d+)")
            if pdr_ch:
                v = self._extract_match(pdr_ch[-1].text, r"^\s+ip\s+pim\s+dr-priority\s+(\d+)")
                if v:
                    pim_dr_priority = int(v)
            pim_query_interval = None
            pqi_ch = intf_obj.find_child_objects(r"^\s+ip\s+pim\s+query-interval\s+(\d+)")
            if pqi_ch:
                v = self._extract_match(pqi_ch[-1].text, r"^\s+ip\s+pim\s+query-interval\s+(\d+)")
                if v:
                    pim_query_interval = int(v)
            pim_bfd = bool(intf_obj.find_child_objects(r"^\s+ip\s+pim\s+bfd"))

            # EIGRP per-interface authentication
            eigrp_auth_mode = None
            eam_ch = intf_obj.find_child_objects(r"^\s+ip\s+authentication\s+mode\s+eigrp\s+")
            if eam_ch:
                eam = re.match(
                    r"^\s+ip\s+authentication\s+mode\s+eigrp\s+\d+\s+(\S+)",
                    eam_ch[-1].text,
                )
                if eam:
                    eigrp_auth_mode = eam.group(1)
            eigrp_auth_key_chain = None
            eakc_ch = intf_obj.find_child_objects(r"^\s+ip\s+authentication\s+key-chain\s+eigrp\s+")
            if eakc_ch:
                eakc = re.match(
                    r"^\s+ip\s+authentication\s+key-chain\s+eigrp\s+\d+\s+(\S+)",
                    eakc_ch[-1].text,
                )
                if eakc:
                    eigrp_auth_key_chain = eakc.group(1)

            # EIGRP per-interface timers
            eigrp_hello_interval = None
            ehi_ch = intf_obj.find_child_objects(r"^\s+ip\s+hello-interval\s+eigrp\s+")
            if ehi_ch:
                ehi = re.match(
                    r"^\s+ip\s+hello-interval\s+eigrp\s+\d+\s+(\d+)",
                    ehi_ch[-1].text,
                )
                if ehi:
                    eigrp_hello_interval = int(ehi.group(1))
            eigrp_hold_time = None
            eht_ch = intf_obj.find_child_objects(r"^\s+ip\s+hold-time\s+eigrp\s+")
            if eht_ch:
                eht = re.match(
                    r"^\s+ip\s+hold-time\s+eigrp\s+\d+\s+(\d+)",
                    eht_ch[-1].text,
                )
                if eht:
                    eigrp_hold_time = int(eht.group(1))

            # BFD per-interface (platform-specific hook)
            bfd_interval, bfd_min_rx, bfd_multiplier, bfd_template = self._parse_iface_bfd(intf_obj)
            if intf_obj.find_child_objects(r"^\s+no\s+bfd\s+interval"):
                iface_no_commands.append(f"field:interface:{intf_name}:bfd_interval")
                iface_no_commands.append(f"field:interface:{intf_name}:bfd_min_rx")
                iface_no_commands.append(f"field:interface:{intf_name}:bfd_multiplier")

            # IGMP per-interface
            igmp_version = None
            igv_ch = intf_obj.find_child_objects(r"^\s+ip\s+igmp\s+version\s+(\d)")
            if igv_ch:
                v = self._extract_match(igv_ch[-1].text, r"^\s+ip\s+igmp\s+version\s+(\d)")
                if v:
                    igmp_version = int(v)
            igmp_query_interval = None
            iqi_ch = intf_obj.find_child_objects(r"^\s+ip\s+igmp\s+query-interval\s+(\d+)")
            if iqi_ch:
                v = self._extract_match(iqi_ch[-1].text, r"^\s+ip\s+igmp\s+query-interval\s+(\d+)")
                if v:
                    igmp_query_interval = int(v)
            igmp_query_max_response_time = None
            iqmr_ch = intf_obj.find_child_objects(r"^\s+ip\s+igmp\s+query-max-response-time\s+(\d+)")
            if iqmr_ch:
                v = self._extract_match(iqmr_ch[-1].text, r"^\s+ip\s+igmp\s+query-max-response-time\s+(\d+)")
                if v:
                    igmp_query_max_response_time = int(v)
            # ip access-group applied to interface (inbound / outbound)
            acl_in = None
            acl_out = None
            for ag_ch in intf_obj.find_child_objects(r"^\s+ip\s+access-group\s+\S+\s+(in|out)"):
                m = re.match(r"^\s+ip\s+access-group\s+(\S+)\s+(in|out)", ag_ch.text)
                if m:
                    if m.group(2) == "in":
                        acl_in = m.group(1)
                    else:
                        acl_out = m.group(1)

            igmp_access_group = None
            iag_ch = intf_obj.find_child_objects(r"^\s+ip\s+igmp\s+access-group\s+(\S+)")
            if iag_ch:
                igmp_access_group = self._extract_match(iag_ch[-1].text, r"^\s+ip\s+igmp\s+access-group\s+(\S+)")
            igmp_join_groups = []
            for jg_ch in intf_obj.find_child_objects(r"^\s+ip\s+igmp\s+join-group\s+(\S+)"):
                v = self._extract_match(jg_ch.text, r"^\s+ip\s+igmp\s+join-group\s+(\S+)")
                if v:
                    igmp_join_groups.append(v)
            igmp_static_groups = []
            for sg_ch in intf_obj.find_child_objects(r"^\s+ip\s+igmp\s+static-group\s+(\S+)"):
                v = self._extract_match(sg_ch.text, r"^\s+ip\s+igmp\s+static-group\s+(\S+)")
                if v:
                    igmp_static_groups.append(v)

            # QoS service-policy
            service_policy_input = None
            service_policy_output = None
            for sp_ch in intf_obj.find_child_objects(r"^\s+service-policy\s+"):
                spm = re.match(r"^\s+service-policy\s+(input|output)\s+(\S+)", sp_ch.text)
                if spm:
                    if spm.group(1) == "input":
                        service_policy_input = spm.group(2)
                    else:
                        service_policy_output = spm.group(2)

            # NAT direction
            nat_direction = None
            nat_in_ch = intf_obj.find_child_objects(r"^\s+ip\s+nat\s+inside")
            nat_out_ch = intf_obj.find_child_objects(r"^\s+ip\s+nat\s+outside")
            if nat_in_ch:
                nat_direction = "inside"
            elif nat_out_ch:
                nat_direction = "outside"

            # uRPF — 'ip verify unicast source reachable-via rx|any'
            ip_verify_unicast = None
            urpf_ch = intf_obj.find_child_objects(
                r"^\s+ip\s+verify\s+unicast\s+source\s+reachable-via\s+(rx|any)"
            )
            if urpf_ch:
                m = re.search(
                    r"^\s+ip\s+verify\s+unicast\s+source\s+reachable-via\s+(rx|any)",
                    urpf_ch[-1].text,
                )
                if m:
                    ip_verify_unicast = m.group(1)

            # PBR — 'ip policy route-map <name>'
            ip_policy_route_map = None
            pbr_ch = intf_obj.find_child_objects(r"^\s+ip\s+policy\s+route-map\s+(\S+)")
            if pbr_ch:
                ip_policy_route_map = self._extract_match(
                    pbr_ch[-1].text, r"^\s+ip\s+policy\s+route-map\s+(\S+)"
                )

            # Crypto map
            crypto_map_name = None
            cm_ch = intf_obj.find_child_objects(r"^\s+crypto\s+map\s+(\S+)")
            if cm_ch:
                crypto_map_name = self._extract_match(cm_ch[-1].text, r"^\s+crypto\s+map\s+(\S+)")

            # IP unnumbered
            unnumbered_source = None
            unnum_ch = intf_obj.find_child_objects(r"^\s+ip\s+unnumbered\s+(\S+)")
            if unnum_ch:
                unnumbered_source = self._extract_match(
                    unnum_ch[-1].text, r"^\s+ip\s+unnumbered\s+(\S+)"
                )

            # Per-interface CDP
            cdp_enabled = True
            if intf_obj.find_child_objects(r"^\s+no\s+cdp\s+enable"):
                cdp_enabled = False

            # Per-interface LLDP
            lldp_transmit = True
            lldp_receive = True
            if intf_obj.find_child_objects(r"^\s+no\s+lldp\s+transmit"):
                lldp_transmit = False
            if intf_obj.find_child_objects(r"^\s+no\s+lldp\s+receive"):
                lldp_receive = False

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
                    ip_mtu=ip_mtu,
                    speed=speed,
                    duplex=duplex,
                    bandwidth=bandwidth,
                    delay=delay,
                    eigrp_authentication_mode=eigrp_auth_mode,
                    eigrp_authentication_key_chain=eigrp_auth_key_chain,
                    eigrp_hello_interval=eigrp_hello_interval,
                    eigrp_hold_time=eigrp_hold_time,
                    switchport_mode=switchport_mode,
                    access_vlan=access_vlan,
                    trunk_allowed_vlans=trunk_allowed_vlans,
                    trunk_native_vlan=trunk_native_vlan,
                    channel_group=channel_group,
                    channel_group_mode=channel_group_mode,
                    min_links=min_links,
                    lacp_port_priority=lacp_port_priority,
                    lacp_rate=lacp_rate,
                    port_security_enabled=port_security_enabled,
                    port_security_max_mac=port_security_max_mac,
                    port_security_violation=port_security_violation,
                    port_security_sticky=port_security_sticky,
                    dot1x_port_control=dot1x_port_control,
                    dot1x_host_mode=dot1x_host_mode,
                    dot1x_mab=dot1x_mab,
                    dot1x_guest_vlan=dot1x_guest_vlan,
                    dot1x_auth_fail_vlan=dot1x_auth_fail_vlan,
                    stp_portfast=stp_portfast,
                    stp_bpduguard=stp_bpduguard,
                    stp_bpdufilter=stp_bpdufilter,
                    stp_cost=stp_cost,
                    stp_port_priority=stp_port_priority,
                    stp_root_guard=stp_root_guard,
                    hsrp_groups=hsrp_groups,
                    vrrp_groups=vrrp_groups,
                    glbp_groups=glbp_groups,
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
                    ospf_mtu_ignore=ospf_mtu_ignore,
                    helper_addresses=helper_addresses,
                    tunnel_source=tunnel_source,
                    tunnel_destination=tunnel_destination,
                    tunnel_mode=tunnel_mode,
                    tunnel_protection_profile=tunnel_protection_profile,
                    tunnel_key=tunnel_key,
                    nhrp_network_id=nhrp_network_id,
                    nhrp_authentication=nhrp_authentication,
                    nhrp_nhs=nhrp_nhs,
                    nhrp_map=nhrp_map,
                    mpls_ip=mpls_ip,
                    pim_mode=pim_mode,
                    pim_dr_priority=pim_dr_priority,
                    pim_query_interval=pim_query_interval,
                    pim_bfd=pim_bfd,
                    bfd_interval=bfd_interval,
                    bfd_min_rx=bfd_min_rx,
                    bfd_multiplier=bfd_multiplier,
                    bfd_template=bfd_template,
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
                    ip_verify_unicast=ip_verify_unicast,
                    ip_policy_route_map=ip_policy_route_map,
                    crypto_map=crypto_map_name,
                    unnumbered_source=unnumbered_source,
                    cdp_enabled=cdp_enabled,
                    lldp_transmit=lldp_transmit,
                    lldp_receive=lldp_receive,
                    no_commands=iface_no_commands
                    + self._detect_interface_field_negations(intf_obj, intf_name),
                )
            )

        return interfaces

    def _coalesce_interface_stanzas(self, intf_objs: list) -> list:
        """Coalesce duplicate interface stanzas at the line level.

        Groups ciscoconfparse objects by interface name and extends the first
        object's children with subsequent stanzas' children.  The combined
        object is then parsed once — normal last-match semantics apply, so
        ``no shutdown`` after ``shutdown`` simply wins, and the model-level
        ambiguity (field absent vs explicitly-set-to-default) never arises.
        """
        from collections import OrderedDict

        seen: OrderedDict[str, object] = OrderedDict()
        for obj in intf_objs:
            name = self._extract_match(obj.text, r"^interface\s+(\S+)")
            if not name:
                continue
            if name not in seen:
                seen[name] = obj
            else:
                seen[name].children.extend(obj.children)
        return list(seen.values())

    def _detect_interface_field_negations(
        self, intf_obj, intf_name: str
    ) -> list[str]:
        """Detect interface-level ``no …`` commands that remove scalar fields.

        Returns tombstones in the ``field:interface:<name>:<attr>`` format
        consumed by ``_reset_fields_from_tombstones`` in the merger — no merger
        changes needed.  Called from ``parse_interfaces``; NX-OS inherits via
        ``super()``.  IOS-XR overrides with its own syntax variant.
        """
        tombstones: list[str] = []
        prefix = f"field:interface:{intf_name}"

        # no ip access-group … in / out
        for ch in intf_obj.find_child_objects(r"^\s+no\s+ip\s+access-group\s+"):
            m = re.match(r"^\s+no\s+ip\s+access-group\s+\S+\s+(in|out)", ch.text)
            if m:
                field = "acl_in" if m.group(1) == "in" else "acl_out"
                tombstones.append(f"{prefix}:{field}")

        # no service-policy input / output
        for ch in intf_obj.find_child_objects(r"^\s+no\s+service-policy\s+"):
            m = re.match(r"^\s+no\s+service-policy\s+(input|output)", ch.text)
            if m:
                field = (
                    "service_policy_input"
                    if m.group(1) == "input"
                    else "service_policy_output"
                )
                tombstones.append(f"{prefix}:{field}")

        # no ip nat inside / outside
        if intf_obj.find_child_objects(r"^\s+no\s+ip\s+nat\s+(inside|outside)"):
            tombstones.append(f"{prefix}:nat_direction")

        # no shutdown — restates the model default (enabled=True), so without a
        # tombstone the merger treats it as "not mentioned" and a baseline
        # `shutdown` silently survives the merge (Fable-5 review F1).  Last
        # match wins, mirroring _is_shutdown: emit only when the final
        # shutdown-form line in the (coalesced) block is the `no` form.
        last_shutdown_form: str | None = None
        for ch in intf_obj.children:
            if re.match(r"^\s+no\s+shutdown\s*$", ch.text):
                last_shutdown_form = "no"
            elif re.match(r"^\s+shutdown\s*$", ch.text):
                last_shutdown_form = "shutdown"
        if last_shutdown_form == "no":
            tombstones.append(f"{prefix}:enabled")

        # no switchport port-security (bare form) — positive detection is a
        # positive-only regex, so the `no` form parses to False == default and
        # is otherwise invisible to the merger (same F1 silent pattern).
        if intf_obj.find_child_objects(r"^\s+no\s+switchport\s+port-security\s*$"):
            tombstones.append(f"{prefix}:port_security_enabled")

        # no ip ospf mtu-ignore — same F1 silent pattern (default False).
        if intf_obj.find_child_objects(r"^\s+no\s+ip\s+ospf\s+mtu-ignore\s*$"):
            tombstones.append(f"{prefix}:ospf_mtu_ignore")

        return tombstones

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
            rid_children = bgp_obj.find_child_objects(r"^\s+bgp\s+router-id\s+(\S+)")
            if rid_children:
                rid_str = self._extract_match(
                    rid_children[0].text, r"^\s+bgp\s+router-id\s+(\S+)"
                )
                try:
                    router_id = IPv4Address(rid_str)
                except ValueError:
                    pass

            # Cluster ID (route reflector)
            cluster_id = None
            cid_children = bgp_obj.find_child_objects(r"^\s+bgp\s+cluster-id\s+(\S+)")
            if cid_children:
                cid_str = self._extract_match(
                    cid_children[0].text, r"^\s+bgp\s+cluster-id\s+(\S+)"
                )
                if cid_str:
                    try:
                        cluster_id = int(cid_str)
                    except ValueError:
                        try:
                            cluster_id = IPv4Address(cid_str)
                        except ValueError:
                            pass

            # RPKI cache server: 'bgp rpki server tcp <ip> port <port>'
            rpki_server = None
            rpki_children = bgp_obj.find_child_objects(
                r"^\s+bgp\s+rpki\s+server\s+tcp\s+(\S+)\s+port\s+(\d+)"
            )
            if rpki_children:
                m = re.search(
                    r"^\s+bgp\s+rpki\s+server\s+tcp\s+(\S+)\s+port\s+(\d+)",
                    rpki_children[0].text,
                )
                if m:
                    rpki_server = f"{m.group(1)}:{m.group(2)}"

            # Confederation identifier and peers
            confederation_id = None
            confed_id_children = bgp_obj.find_child_objects(
                r"^\s+bgp\s+confederation\s+identifier\s+(\d+)"
            )
            if confed_id_children:
                cid_val = self._extract_match(
                    confed_id_children[0].text,
                    r"^\s+bgp\s+confederation\s+identifier\s+(\d+)",
                )
                if cid_val:
                    try:
                        confederation_id = int(cid_val)
                    except ValueError:
                        pass

            confederation_peers: list[int] = []
            for cp_child in bgp_obj.find_child_objects(
                r"^\s+bgp\s+confederation\s+peers\s+"
            ):
                for tok in cp_child.text.split()[3:]:
                    try:
                        confederation_peers.append(int(tok))
                    except ValueError:
                        pass

            # Log neighbor changes
            log_neighbor_changes = len(
                bgp_obj.find_child_objects(r"^\s+bgp\s+log-neighbor-changes")
            ) > 0

            # Default local-preference (bgp default local-preference N)
            default_local_preference = 100
            dlp_children = bgp_obj.find_child_objects(
                r"^\s+bgp\s+default\s+local-preference\s+(\d+)"
            )
            if dlp_children:
                dlp_m = re.match(
                    r"^\s+bgp\s+default\s+local-preference\s+(\d+)",
                    dlp_children[0].text,
                )
                if dlp_m:
                    default_local_preference = int(dlp_m.group(1))

            # Best-path options
            bestpath_options = self._parse_bgp_bestpath_options(bgp_obj)

            # Parse neighbors and peer-groups
            neighbors = self._parse_bgp_neighbors(bgp_obj)
            peer_groups = self._parse_bgp_peer_groups(bgp_obj)

            # 'no neighbor X' tombstones (full removal + field-level resets)
            bgp_no_commands: list[str] = self._parse_bgp_neighbor_tombstones(bgp_obj)

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
                    cluster_id=cluster_id,
                    confederation_id=confederation_id,
                    confederation_peers=confederation_peers,
                    rpki_server=rpki_server,
                    vrf=None,
                    log_neighbor_changes=log_neighbor_changes,
                    bestpath_options=bestpath_options,
                    neighbors=neighbors,
                    peer_groups=peer_groups,
                    address_families=address_families,
                    networks=networks,
                    redistribute=redistribute,
                    no_commands=bgp_no_commands,
                    default_local_preference=default_local_preference,
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
            # Capture VRF from "router ospf <pid> vrf <name>" (IOS VRF-Lite style)
            ospf_vrf = self._extract_match(
                ospf_obj.text, r"^router\s+ospf\s+\d+\s+vrf\s+(\S+)"
            )  # None when no VRF qualifier
            raw_lines, line_numbers = self._get_raw_lines_and_line_numbers(ospf_obj)

            # Router ID
            router_id = None
            rid_children = ospf_obj.find_child_objects(r"^\s+router-id\s+(\S+)")
            if rid_children:
                rid_str = self._extract_match(rid_children[0].text, r"^\s+router-id\s+(\S+)")
                try:
                    router_id = IPv4Address(rid_str)
                except ValueError:
                    pass

            # Log adjacency changes
            log_adjacency_changes = len(
                ospf_obj.find_child_objects(r"^\s+log-adjacency-changes")
            ) > 0

            log_adjacency_changes_detail = len(
                ospf_obj.find_child_objects(r"^\s+log-adjacency-changes\s+detail")
            ) > 0

            # Auto-cost reference bandwidth
            auto_cost_ref_bw = None
            auto_cost_children = ospf_obj.find_child_objects(
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
                ospf_obj.find_child_objects(r"^\s+passive-interface\s+default")
            ) > 0

            # Passive interfaces
            passive_interfaces = []
            passive_intf_children = ospf_obj.find_child_objects(
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
            non_passive_children = ospf_obj.find_child_objects(
                r"^\s+no\s+passive-interface\s+(\S+)"
            )
            for non_passive_child in non_passive_children:
                intf_name = self._extract_match(
                    non_passive_child.text, r"^\s+no\s+passive-interface\s+(\S+)"
                )
                if intf_name:
                    non_passive_interfaces.append(intf_name)

            # Network statements: "network <addr> <wildcard> area <area-id>"
            # Wildcard is the inverse of the subnet mask — convert to IPv4Network.
            network_statements: list[tuple[IPv4Network, str]] = []
            net_children = ospf_obj.find_child_objects(
                r"^\s+network\s+\S+\s+\S+\s+area\s+\S+"
            )
            for nc in net_children:
                m = re.match(
                    r"^\s+network\s+(\S+)\s+(\S+)\s+area\s+(\S+)", nc.text
                )
                if m:
                    addr_str, wildcard_str, area_id = m.group(1), m.group(2), m.group(3)
                    try:
                        addr = IPv4Address(addr_str)
                        wildcard = IPv4Address(wildcard_str)
                        # Invert wildcard to get subnet mask, then build prefix
                        mask = IPv4Address(int(wildcard) ^ 0xFFFFFFFF)
                        net = IPv4Network(f"{addr}/{mask}", strict=False)
                        network_statements.append((net, area_id))
                    except ValueError:
                        pass

            # Parse areas
            areas = self._parse_ospf_areas(ospf_obj)

            # Parse redistribution
            redistribute = self._parse_ospf_redistribute(ospf_obj)

            # Default-information originate
            # Max-metric router-lsa
            max_metric_router_lsa = False
            max_metric_router_lsa_on_startup: int | None = None
            mm_children = ospf_obj.find_child_objects(r"^\s+max-metric\s+router-lsa")
            if mm_children:
                max_metric_router_lsa = True
                m = re.search(r"on-startup\s+(\d+)", mm_children[0].text)
                if m:
                    max_metric_router_lsa_on_startup = int(m.group(1))

            default_info_originate = False
            default_info_always = False
            default_info_metric: int | None = None
            default_info_metric_type: int | None = None
            default_info_route_map: str | None = None

            di_children = ospf_obj.find_child_objects(
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

            # OSPF distance: "distance ospf intra-area N inter-area N external N"
            distance: int | None = None
            distance_intra: int | None = None
            distance_inter: int | None = None
            distance_external: int | None = None
            dist_ospf_ch = ospf_obj.find_child_objects(r"^\s+distance\s+ospf")
            if dist_ospf_ch:
                dt = dist_ospf_ch[0].text
                m = re.search(r"intra-area\s+(\d+)", dt)
                if m:
                    distance_intra = int(m.group(1))
                m = re.search(r"inter-area\s+(\d+)", dt)
                if m:
                    distance_inter = int(m.group(1))
                m = re.search(r"external\s+(\d+)", dt)
                if m:
                    distance_external = int(m.group(1))
            # Simple "distance N"
            dist_simple_ch = ospf_obj.find_child_objects(r"^\s+distance\s+(\d+)\s*$")
            if dist_simple_ch:
                v = self._extract_match(dist_simple_ch[0].text, r"^\s+distance\s+(\d+)")
                if v:
                    distance = int(v)

            # Default metric
            default_metric: int | None = None
            dm_ch = ospf_obj.find_child_objects(r"^\s+default-metric\s+(\d+)")
            if dm_ch:
                v = self._extract_match(dm_ch[0].text, r"^\s+default-metric\s+(\d+)")
                if v:
                    default_metric = int(v)

            # Max-LSA
            max_lsa: int | None = None
            ml_ch = ospf_obj.find_child_objects(r"^\s+max-lsa\s+(\d+)")
            if ml_ch:
                v = self._extract_match(ml_ch[0].text, r"^\s+max-lsa\s+(\d+)")
                if v:
                    max_lsa = int(v)

            # Timers throttle SPF: "timers throttle spf <initial> <min> <max>"
            spf_initial: int | None = None
            spf_min: int | None = None
            spf_max: int | None = None
            spf_ch = ospf_obj.find_child_objects(r"^\s+timers\s+throttle\s+spf\s+")
            if spf_ch:
                m = re.search(r"timers\s+throttle\s+spf\s+(\d+)\s+(\d+)\s+(\d+)", spf_ch[0].text)
                if m:
                    spf_initial = int(m.group(1))
                    spf_min = int(m.group(2))
                    spf_max = int(m.group(3))

            # Timers throttle LSA: "timers throttle lsa all <msec>"
            lsa_all: int | None = None
            lsa_ch = ospf_obj.find_child_objects(r"^\s+timers\s+throttle\s+lsa\s+all\s+(\d+)")
            if lsa_ch:
                v = self._extract_match(lsa_ch[0].text, r"timers\s+throttle\s+lsa\s+all\s+(\d+)")
                if v:
                    lsa_all = int(v)

            # Shutdown
            ospf_shutdown = len(ospf_obj.find_child_objects(r"^\s+shutdown\s*$")) > 0

            # Graceful restart
            graceful_restart = len(ospf_obj.find_child_objects(r"^\s+graceful-restart\s*$")) > 0
            graceful_restart_helper = len(
                ospf_obj.find_child_objects(r"^\s+graceful-restart\s+helper")
            ) > 0
            # Also detect "nsf" (IOS synonym for graceful-restart)
            if not graceful_restart:
                graceful_restart = len(ospf_obj.find_child_objects(r"^\s+nsf\b")) > 0

            # BFD all-interfaces
            bfd_all = len(ospf_obj.find_child_objects(r"^\s+bfd\s+all-interfaces")) > 0

            ospf_instances.append(
                OSPFConfig(
                    object_id=f"ospf_{process_id}",
                    raw_lines=raw_lines,
                    source_os=self.os_type,
                    line_numbers=line_numbers,
                    process_id=process_id,
                    vrf=ospf_vrf,
                    router_id=router_id,
                    log_adjacency_changes=log_adjacency_changes,
                    log_adjacency_changes_detail=log_adjacency_changes_detail,
                    auto_cost_reference_bandwidth=auto_cost_ref_bw,
                    passive_interface_default=passive_interface_default,
                    passive_interfaces=passive_interfaces,
                    non_passive_interfaces=non_passive_interfaces,
                    network_statements=network_statements,
                    areas=areas,
                    redistribute=redistribute,
                    max_metric_router_lsa=max_metric_router_lsa,
                    max_metric_router_lsa_on_startup=max_metric_router_lsa_on_startup,
                    default_information_originate=default_info_originate,
                    default_information_originate_always=default_info_always,
                    default_information_originate_metric=default_info_metric,
                    default_information_originate_metric_type=default_info_metric_type,
                    default_information_originate_route_map=default_info_route_map,
                    distance=distance,
                    distance_intra_area=distance_intra,
                    distance_inter_area=distance_inter,
                    distance_external=distance_external,
                    default_metric=default_metric,
                    max_lsa=max_lsa,
                    timers_throttle_spf_initial=spf_initial,
                    timers_throttle_spf_min=spf_min,
                    timers_throttle_spf_max=spf_max,
                    timers_throttle_lsa_all=lsa_all,
                    shutdown=ospf_shutdown,
                    graceful_restart=graceful_restart,
                    graceful_restart_helper=graceful_restart_helper,
                    bfd_all_interfaces=bfd_all,
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
            match_children = rm_obj.find_child_objects(r"^\s+match\s+(.+)")
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
            set_children = rm_obj.find_child_objects(r"^\s+set\s+(.+)")
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
            continue_children = rm_obj.find_child_objects(r"^\s+continue\s+(\d+)")
            if continue_children:
                continue_seq = int(
                    self._extract_match(continue_children[0].text, r"^\s+continue\s+(\d+)")
                )

            # Description
            description = None
            desc_children = rm_obj.find_child_objects(r"^\s+description\s+(.+)")
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
        vrf_children = intf_obj.find_child_objects(r"^\s+vrf\s+forwarding\s+(\S+)")
        if vrf_children:
            return self._extract_match(
                vrf_children[-1].text, r"^\s+vrf\s+forwarding\s+(\S+)"
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

        # Capture interface-level "standby version <n>" (applies to all groups)
        hsrp_version: int | None = None
        version_children = intf_obj.find_child_objects(r"^\s+standby\s+version\s+(\d+)")
        if version_children:
            vm = re.search(r"standby\s+version\s+(\d+)", version_children[-1].text)
            if vm:
                hsrp_version = int(vm.group(1))

        # Find all standby commands with a group number
        standby_children = intf_obj.find_child_objects(r"^\s+standby\s+(\d+)")

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
            group_data["version"] = hsrp_version
            hsrp_groups.append(HSRPGroup(**group_data))

        return hsrp_groups

    def _parse_vrrp_groups(self, intf_obj) -> list[VRRPGroup]:
        """Parse VRRP groups from interface configuration."""
        vrrp_groups = []

        # Find all vrrp commands
        vrrp_children = intf_obj.find_child_objects(r"^\s+vrrp\s+(\d+)")

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

    def _parse_glbp_groups(self, intf_obj) -> list[GLBPGroup]:
        """Parse GLBP groups from interface configuration."""
        glbp_groups = []

        glbp_children = intf_obj.find_child_objects(r"^\s+glbp\s+(\d+)")

        glbp_dict: dict[int, dict] = {}

        for glbp_child in glbp_children:
            match = re.search(r"^\s+glbp\s+(\d+)\s+(.+)", glbp_child.text)
            if not match:
                continue

            group_num = int(match.group(1))
            command = match.group(2)

            if group_num not in glbp_dict:
                glbp_dict[group_num] = {
                    "group_number": group_num,
                    "priority": None,
                    "preempt": False,
                    "virtual_ip": None,
                    "weighting": None,
                    "authentication": None,
                    "track_objects": [],
                }

            if command.startswith("ip "):
                ip_str = command.replace("ip ", "").strip()
                try:
                    glbp_dict[group_num]["virtual_ip"] = IPv4Address(ip_str)
                except ValueError:
                    pass
            elif command.startswith("priority "):
                priority_str = command.replace("priority ", "").strip()
                glbp_dict[group_num]["priority"] = int(priority_str)
            elif command == "preempt":
                glbp_dict[group_num]["preempt"] = True
            elif command.startswith("weighting "):
                weight_str = command.replace("weighting ", "").strip().split()[0]
                glbp_dict[group_num]["weighting"] = int(weight_str)
            elif command.startswith("authentication "):
                auth_str = command.replace("authentication ", "").strip()
                glbp_dict[group_num]["authentication"] = auth_str

        for group_data in glbp_dict.values():
            glbp_groups.append(GLBPGroup(**group_data))

        return glbp_groups

    def _parse_bgp_bestpath_options(self, bgp_obj) -> BGPBestpathOptions:
        """Parse BGP best-path options."""
        return BGPBestpathOptions(
            as_path_ignore=len(
                bgp_obj.find_child_objects(r"^\s+bgp\s+bestpath\s+as-path\s+ignore")
            ) > 0,
            as_path_multipath_relax=len(
                bgp_obj.find_child_objects(r"^\s+bgp\s+bestpath\s+as-path\s+multipath-relax")
            ) > 0,
            compare_routerid=len(
                bgp_obj.find_child_objects(r"^\s+bgp\s+bestpath\s+compare-routerid")
            ) > 0,
            med_confed=len(
                bgp_obj.find_child_objects(r"^\s+bgp\s+bestpath\s+med\s+confed")
            ) > 0,
            med_missing_as_worst=len(
                bgp_obj.find_child_objects(r"^\s+bgp\s+bestpath\s+med\s+missing-as-worst")
            ) > 0,
            always_compare_med=len(
                bgp_obj.find_child_objects(r"^\s+bgp\s+bestpath\s+always-compare-med")
            ) > 0,
        )

    # ------------------------------------------------------------------
    # BGP neighbor tombstone parser (universal field-reset pattern)
    # ------------------------------------------------------------------

    # Maps the IOS command text that follows "no neighbor <peer> " to the
    # BGPNeighbor Pydantic field name that should be reset to its default.
    # Entries are checked in order; use the most specific pattern first.
    _BGP_NEIGHBOR_NO_FIELD_MAP: list[tuple[str, str]] = [
        # Boolean flags
        ("shutdown",                "shutdown"),
        ("next-hop-self",           "next_hop_self"),
        ("route-reflector-client",  "route_reflector_client"),
        ("fall-over bfd",           "fall_over_bfd"),
        ("disable-connected-check", "disable_connected_check"),
        ("local-as",                "local_as"),
        # Strings with optional trailing arguments
        ("description",             "description"),
        ("update-source",           "update_source"),
        ("ebgp-multihop",           "ebgp_multihop"),
        ("password",                "password"),
        ("timers",                  "timers"),
        # send-community accepts an optional type qualifier
        ("send-community",          "send_community"),
        # Directional route-map / prefix-list / filter-list
        ("route-map",               None),      # handled below — needs direction
        ("prefix-list",             None),
        ("filter-list",             None),
        ("maximum-prefix",          "maximum_prefix"),
        ("peer-group",              "peer_group"),
    ]

    def _parse_bgp_neighbor_tombstones(self, bgp_or_af_obj) -> list[str]:
        """Parse 'no neighbor X ...' lines under a BGP process or AF block.

        Returns a list of tombstone strings using two formats:

          ``neighbor:<peer>``
              Full neighbor removal ("no neighbor X" with no trailing attribute).

          ``field:neighbor:<peer>:<field_name>``
              Field-level reset (universal field-reset pattern, MERGE-7).
              The merger will reset the named field to its Pydantic default
              after applying the field-level merge from the proposal.

        This also fixes a pre-existing parser bug: previously any line matching
        "no neighbor X..." was treated as a full neighbor removal tombstone,
        which incorrectly removed the entire neighbor when only a single field
        was being cleared (e.g. "no neighbor 1.1.1.1 shutdown").
        """
        tombstones: list[str] = []

        for nc in bgp_or_af_obj.find_child_objects(r"^\s+no\s+neighbor\s+\S+"):
            m = re.search(r"^\s+no\s+neighbor\s+(\S+)(?:\s+(.+))?$", nc.text)
            if not m:
                continue

            peer = m.group(1)
            attr = (m.group(2) or "").strip()

            if not attr:
                # "no neighbor X" — full neighbor removal
                tombstones.append(f"neighbor:{peer}")
                continue

            # Directional policy objects: attribute starts with keyword + name + direction
            if attr.startswith("route-map "):
                field = "route_map_in" if attr.endswith(" in") else "route_map_out" if attr.endswith(" out") else None
                if field:
                    tombstones.append(f"field:neighbor:{peer}:{field}")
                continue
            if attr.startswith("prefix-list "):
                field = "prefix_list_in" if attr.endswith(" in") else "prefix_list_out" if attr.endswith(" out") else None
                if field:
                    tombstones.append(f"field:neighbor:{peer}:{field}")
                continue
            if attr.startswith("filter-list "):
                field = "filter_list_in" if attr.endswith(" in") else "filter_list_out" if attr.endswith(" out") else None
                if field:
                    tombstones.append(f"field:neighbor:{peer}:{field}")
                continue

            # Simple prefix-match table
            for prefix, field_name in self._BGP_NEIGHBOR_NO_FIELD_MAP:
                if prefix in ("route-map", "prefix-list", "filter-list"):
                    continue  # already handled above
                if attr == prefix or attr.startswith(prefix + " "):
                    tombstones.append(f"field:neighbor:{peer}:{field_name}")
                    break
            # Unrecognised attribute — skip silently (do not emit a full-removal tombstone)

        return tombstones

    def _parse_bgp_neighbors(self, bgp_obj) -> list[BGPNeighbor]:
        """Parse BGP neighbors."""
        neighbors = []
        neighbor_children = bgp_obj.find_child_objects(r"^\s+neighbor\s+(\S+)\s+")

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
                    "filter_list_in": None,
                    "filter_list_out": None,
                    "maximum_prefix": None,
                    "next_hop_self": False,
                    "route_reflector_client": False,
                    "send_community": None,
                    "fall_over_bfd": False,
                    "shutdown": False,
                    "disable_connected_check": False,
                    "timers": None,
                    "local_as": None,
                    "local_as_no_prepend": False,
                    "local_as_replace_as": False,
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
                try:
                    neighbor_dict[peer_ip_str]["ebgp_multihop"] = int(command.replace("ebgp-multihop ", "").strip())
                except ValueError:
                    pass
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
                    try:
                        neighbor_dict[peer_ip_str]["maximum_prefix"] = int(parts[0])
                    except ValueError:
                        pass
            elif command == "next-hop-self":
                neighbor_dict[peer_ip_str]["next_hop_self"] = True
            elif command == "route-reflector-client":
                neighbor_dict[peer_ip_str]["route_reflector_client"] = True
            elif command == "fall-over bfd":
                neighbor_dict[peer_ip_str]["fall_over_bfd"] = True
            elif command == "shutdown":
                neighbor_dict[peer_ip_str]["shutdown"] = True
            elif command == "disable-connected-check":
                neighbor_dict[peer_ip_str]["disable_connected_check"] = True
            elif command.startswith("timers "):
                tm = re.match(r"timers\s+(\d+)\s+(\d+)", command)
                if tm:
                    neighbor_dict[peer_ip_str]["timers"] = BGPTimers(
                        keepalive=int(tm.group(1)), holdtime=int(tm.group(2)),
                    )
            elif command.startswith("local-as "):
                la_parts = command.replace("local-as ", "").strip().split()
                if la_parts:
                    try:
                        neighbor_dict[peer_ip_str]["local_as"] = int(la_parts[0])
                    except ValueError:
                        pass
                    neighbor_dict[peer_ip_str]["local_as_no_prepend"] = "no-prepend" in la_parts
                    neighbor_dict[peer_ip_str]["local_as_replace_as"] = "replace-as" in la_parts
            elif command.startswith("send-community"):
                if "both" in command:
                    neighbor_dict[peer_ip_str]["send_community"] = "both"
                elif "extended" in command:
                    neighbor_dict[peer_ip_str]["send_community"] = "extended"
                else:
                    neighbor_dict[peer_ip_str]["send_community"] = True
            elif command.startswith("filter-list ") and " in" in command:
                m = re.search(r"filter-list\s+(\S+)\s+in", command)
                if m:
                    neighbor_dict[peer_ip_str]["filter_list_in"] = m.group(1)
            elif command.startswith("filter-list ") and " out" in command:
                m = re.search(r"filter-list\s+(\S+)\s+out", command)
                if m:
                    neighbor_dict[peer_ip_str]["filter_list_out"] = m.group(1)

        # Create BGPNeighbor objects
        for peer_ip_str, neighbor_data in neighbor_dict.items():
            try:
                peer_ip = IPv4Address(peer_ip_str)
            except ValueError:
                try:
                    peer_ip = IPv6Address(peer_ip_str)
                except ValueError:
                    continue

            # Skip if no remote-as and no peer-group (invalid neighbor).
            # Exception: allow shutdown-only stubs — a proposal may contain only
            # "neighbor X shutdown" to administratively shut an existing session
            # without restating remote-as. The merger will apply shutdown=True to
            # the matching base neighbor via _merge_neighbor_fields.
            if (
                neighbor_data["remote_as"] is None
                and neighbor_data["peer_group"] is None
                and not neighbor_data.get("shutdown", False)
            ):
                continue

            # If no remote-as but has peer-group (or shutdown stub), it inherits
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
                    filter_list_in=neighbor_data["filter_list_in"],
                    filter_list_out=neighbor_data["filter_list_out"],
                    maximum_prefix=neighbor_data["maximum_prefix"],
                    next_hop_self=neighbor_data.get("next_hop_self", False),
                    route_reflector_client=neighbor_data["route_reflector_client"],
                    send_community=neighbor_data["send_community"],
                    fall_over_bfd=neighbor_data.get("fall_over_bfd", False),
                    disable_connected_check=neighbor_data.get("disable_connected_check", False),
                    shutdown=neighbor_data.get("shutdown", False),
                    timers=neighbor_data["timers"],
                    local_as=neighbor_data["local_as"],
                    local_as_no_prepend=neighbor_data["local_as_no_prepend"],
                    local_as_replace_as=neighbor_data["local_as_replace_as"],
                )
            )

        return neighbors

    def _parse_bgp_peer_groups(self, bgp_obj) -> list[BGPPeerGroup]:
        """Parse BGP peer-groups."""
        peer_groups = []
        pg_children = bgp_obj.find_child_objects(r"^\s+neighbor\s+(\S+)\s+peer-group\s*$")

        for pg_child in pg_children:
            pg_name = self._extract_match(pg_child.text, r"^\s+neighbor\s+(\S+)\s+peer-group\s*$")
            if not pg_name:
                continue

            pg_data = _default_pg_data(pg_name)

            for pg_config_child in bgp_obj.find_child_objects(rf"^\s+neighbor\s+{re.escape(pg_name)}\s+"):
                match = re.search(rf"^\s+neighbor\s+{re.escape(pg_name)}\s+(.+)", pg_config_child.text)
                if match:
                    apply_peer_group_command(pg_data, match.group(1))

            peer_groups.append(BGPPeerGroup(**pg_data))

        return peer_groups

    def _parse_ospf_areas(self, ospf_obj) -> list[OSPFArea]:
        """Parse OSPF area configurations."""
        areas = []
        area_children = ospf_obj.find_child_objects(r"^\s+area\s+(\S+)")

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
                    "nssa_default_information_originate": False,
                    "nssa_default_information_originate_always": False,
                    "authentication": None,
                    "ranges": [],
                    "virtual_links": [],
                    "filter_list_in": None,
                    "filter_list_out": None,
                }

            if "nssa" in command:
                if "no-summary" in command:
                    area_dict[area_id]["area_type"] = OSPFAreaType.TOTALLY_NSSA
                    area_dict[area_id]["nssa_no_summary"] = True
                else:
                    area_dict[area_id]["area_type"] = OSPFAreaType.NSSA
                if "default-information-originate" in command:
                    area_dict[area_id]["nssa_default_information_originate"] = True
                    if "always" in command:
                        area_dict[area_id]["nssa_default_information_originate_always"] = True
            elif "stub" in command:
                if "no-summary" in command:
                    area_dict[area_id]["area_type"] = OSPFAreaType.TOTALLY_STUB
                    area_dict[area_id]["stub_no_summary"] = True
                else:
                    area_dict[area_id]["area_type"] = OSPFAreaType.STUB
            elif command.startswith("virtual-link "):
                vl_match = re.search(r"virtual-link\s+(\S+)", command)
                if vl_match:
                    try:
                        neighbor_rid = IPv4Address(vl_match.group(1))
                        hello = None
                        dead = None
                        auth = None
                        auth_key = None
                        h_m = re.search(r"hello-interval\s+(\d+)", command)
                        if h_m:
                            hello = int(h_m.group(1))
                        d_m = re.search(r"dead-interval\s+(\d+)", command)
                        if d_m:
                            dead = int(d_m.group(1))
                        if "authentication message-digest" in command:
                            auth = "message-digest"
                        elif "authentication" in command:
                            auth = "simple"
                        ak_m = re.search(r"authentication-key\s+(\S+)", command)
                        if ak_m:
                            auth_key = ak_m.group(1)
                        area_dict[area_id]["virtual_links"].append(
                            OSPFVirtualLink(
                                neighbor_router_id=neighbor_rid,
                                hello_interval=hello,
                                dead_interval=dead,
                                authentication=auth,
                                authentication_key=auth_key,
                            )
                        )
                    except ValueError:
                        pass
            elif "authentication" in command:
                if "message-digest" in command:
                    area_dict[area_id]["authentication"] = "message-digest"
                else:
                    area_dict[area_id]["authentication"] = "simple"
            elif "filter-list" in command:
                fl_match = re.search(r"filter-list\s+prefix\s+(\S+)\s+(in|out)", command)
                if fl_match:
                    pl_name, direction = fl_match.group(1), fl_match.group(2)
                    if direction == "in":
                        area_dict[area_id]["filter_list_in"] = pl_name
                    else:
                        area_dict[area_id]["filter_list_out"] = pl_name
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
        redist_children = ospf_obj.find_child_objects(r"^\s+redistribute\s+(\S+)")

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

            # Extract process ID — only for protocols that carry one,
            # and only as the leading positional token.
            if protocol in ("bgp", "ospf", "eigrp", "isis"):
                process_match = re.match(r"(\d+)", remaining)
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

    # ------------------------------------------------------------------
    # Shared BGP helpers — single source of truth for network/redistribute
    # ------------------------------------------------------------------

    def _parse_bgp_network_stmts(self, config_objs) -> list["BGPNetwork"]:
        """Parse ``network`` statements from a list of config-line objects.

        Handles all IOS forms::

            network 10.50.1.0 mask 255.255.255.0
            network 10.50.1.0 mask 255.255.255.0 route-map RM_NAME
            network 10.50.1.0 mask 255.255.255.0 backdoor
            network 192.168.1.0/24              (classless)
            network 2001:db8::/32               (IPv6)
        """
        from confgraph.models.bgp import BGPNetwork

        networks: list[BGPNetwork] = []
        for obj in config_objs:
            t = obj.text
            net_match = re.search(
                r"^\s+network\s+(\S+)(?:\s+mask\s+(\S+))?", t
            )
            if not net_match:
                continue

            prefix_str = net_match.group(1)
            mask_str = net_match.group(2)

            rm_match = re.search(r"\broute-map\s+(\S+)", t)
            backdoor = bool(re.search(r"\bbackdoor\b", t))

            try:
                if mask_str:
                    prefix = IPv4Network(f"{prefix_str}/{mask_str}", strict=False)
                elif ":" in prefix_str:
                    prefix = IPv6Network(prefix_str, strict=False)
                else:
                    prefix = IPv4Network(prefix_str, strict=False)

                networks.append(BGPNetwork(
                    prefix=prefix,
                    route_map=rm_match.group(1) if rm_match else None,
                    backdoor=backdoor,
                ))
            except ValueError:
                pass

        return networks

    def _parse_bgp_redistribute_stmts(self, config_objs) -> list["BGPRedistribute"]:
        """Parse ``redistribute`` statements from a list of config-line objects."""
        from confgraph.models.bgp import BGPRedistribute

        redistribute: list[BGPRedistribute] = []
        for obj in config_objs:
            match = re.search(r"^\s+redistribute\s+(\S+)(.+)?", obj.text)
            if not match:
                continue

            protocol = match.group(1)
            remaining = match.group(2).strip() if match.group(2) else ""

            process_id = None
            route_map = None
            metric = None

            pid_match = re.search(r"(\d+)", remaining)
            if pid_match:
                process_id = int(pid_match.group(1))

            rm_match = re.search(r"route-map\s+(\S+)", remaining)
            if rm_match:
                route_map = rm_match.group(1)

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

        return redistribute

    def _parse_bgp_address_families(self, bgp_obj) -> list[BGPAddressFamily]:
        """Parse BGP address-families (global, non-VRF)."""
        address_families = []

        # Find address-family blocks (not VRF-specific).
        # Matches both the shorthand 'address-family ipv4' and the explicit-SAFI
        # form 'address-family ipv4 unicast' / 'address-family ipv4 multicast'.
        # VRF-specific AF blocks ('address-family ipv4 vrf NAME') are excluded
        # because they use the 'vrf' keyword, which this pattern does not match.
        _AF_RE = r"^\s+address-family\s+(ipv4|ipv6)(?:\s+(unicast|multicast))?\s*$"
        af_children = bgp_obj.find_child_objects(_AF_RE)

        for af_child in af_children:
            match = re.search(_AF_RE, af_child.text)
            if not match:
                continue

            afi = match.group(1)
            safi = match.group(2) or "unicast"

            networks = self._parse_bgp_network_stmts(
                af_child.find_child_objects(r"^\s+network\s+")
            )
            redistribute = self._parse_bgp_redistribute_stmts(
                af_child.find_child_objects(r"^\s+redistribute\s+(\S+)")
            )

            # Parse aggregates
            aggregates = []
            agg_children = af_child.find_child_objects(r"^\s+aggregate-address\s+(\S+)")
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

                        route_map = None
                        attribute_map = None
                        advertise_map = None
                        suppress_map = None
                        rm = re.search(r"\broute-map\s+(\S+)", remaining)
                        if rm:
                            route_map = rm.group(1)
                        am = re.search(r"\battribute-map\s+(\S+)", remaining)
                        if am:
                            attribute_map = am.group(1)
                        adm = re.search(r"\badvertise-map\s+(\S+)", remaining)
                        if adm:
                            advertise_map = adm.group(1)
                        sm = re.search(r"\bsuppress-map\s+(\S+)", remaining)
                        if sm:
                            suppress_map = sm.group(1)

                        aggregates.append(
                            BGPAggregate(
                                prefix=prefix,
                                summary_only=summary_only,
                                as_set=as_set,
                                route_map=route_map,
                                attribute_map=attribute_map,
                                advertise_map=advertise_map,
                                suppress_map=suppress_map,
                            )
                        )
                    except ValueError:
                        pass

            # Parse maximum-paths (eBGP) and maximum-paths ibgp
            maximum_paths = None
            mp_children = af_child.find_child_objects(r"^\s+maximum-paths\s+(?!ibgp)(\d+)")
            if mp_children:
                v = self._extract_match(mp_children[0].text, r"^\s+maximum-paths\s+(\d+)")
                if v:
                    maximum_paths = int(v)

            maximum_paths_ibgp = None
            mp_ibgp_children = af_child.find_child_objects(r"^\s+maximum-paths\s+ibgp\s+(\d+)")
            if mp_ibgp_children:
                v = self._extract_match(mp_ibgp_children[0].text, r"^\s+maximum-paths\s+ibgp\s+(\d+)")
                if v:
                    maximum_paths_ibgp = int(v)

            # RPKI prefix validation mode.
            # 'bgp bestpath prefix-validate allow-invalid' → permissive (True).
            # 'no bgp bestpath prefix-validate allow-invalid' → strict (False).
            # Absent from this AF block → None (merger: do not override baseline).
            prefix_validate_allow_invalid: bool | None = None
            if af_child.find_child_objects(
                r"^\s+no\s+bgp\s+bestpath\s+prefix-validate\s+allow-invalid"
            ):
                prefix_validate_allow_invalid = False
            elif af_child.find_child_objects(
                r"^\s+bgp\s+bestpath\s+prefix-validate\s+allow-invalid"
            ):
                prefix_validate_allow_invalid = True

            address_families.append(
                BGPAddressFamily(
                    afi=afi,
                    safi=safi,
                    vrf=None,
                    networks=networks,
                    redistribute=redistribute,
                    aggregate_addresses=aggregates,
                    maximum_paths=maximum_paths,
                    maximum_paths_ibgp=maximum_paths_ibgp,
                    prefix_validate_allow_invalid=prefix_validate_allow_invalid,
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

        # Find all non-VRF AF blocks inside this router bgp.
        # Matches 'address-family ipv4', 'address-family ipv4 unicast',
        # and 'address-family ipv4 multicast'.  VRF AF blocks are excluded.
        _AF_RE = r"^\s+address-family\s+(ipv4|ipv6)(?:\s+(unicast|multicast))?\s*$"
        af_children = bgp_obj.find_child_objects(_AF_RE)

        for af_child in af_children:
            m = re.search(_AF_RE, af_child.text)
            if not m:
                continue
            afi = m.group(1)
            safi = m.group(2) or "unicast"

            # Collect per-neighbor settings from this AF block
            af_nb_data: dict[str, dict] = {}

            def _ensure_af_nb_entry(peer: str) -> None:
                if peer not in af_nb_data:
                    af_nb_data[peer] = {
                        # Default True — consistent with BGPNeighborAF model default.
                        # Only 'no neighbor X activate' overrides this to False.
                        "activate": True,
                        "next_hop_self": False,
                        "route_map_in": None,
                        "route_map_out": None,
                        "prefix_list_in": None,
                        "prefix_list_out": None,
                        "filter_list_in": None,
                        "filter_list_out": None,
                        "default_originate_route_map": None,
                        "maximum_prefix": None,
                        "maximum_prefix_warning_only": False,
                        "advertise_map": None,
                        "exist_map": None,
                    }

            # 'no neighbor X activate' — explicit AF deactivation
            nb_no_lines = af_child.find_child_objects(r"^\s+no\s+neighbor\s+(\S+)\s+activate")
            for child in nb_no_lines:
                no_m = re.search(r"^\s+no\s+neighbor\s+(\S+)\s+activate", child.text)
                if no_m:
                    peer_str = no_m.group(1)
                    _ensure_af_nb_entry(peer_str)
                    af_nb_data[peer_str]["activate"] = False

            nb_lines = af_child.find_child_objects(r"^\s+neighbor\s+(\S+)\s+")
            for child in nb_lines:
                nm = re.search(r"^\s+neighbor\s+(\S+)\s+(.+)", child.text)
                if not nm:
                    continue
                peer_str = nm.group(1)
                cmd = nm.group(2).strip()

                _ensure_af_nb_entry(peer_str)

                if cmd == "activate":
                    af_nb_data[peer_str]["activate"] = True
                elif cmd == "next-hop-self":
                    af_nb_data[peer_str]["next_hop_self"] = True
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
                elif cmd.startswith("maximum-prefix "):
                    parts = cmd.replace("maximum-prefix ", "").split()
                    if parts:
                        try:
                            af_nb_data[peer_str]["maximum_prefix"] = int(parts[0])
                        except ValueError:
                            pass
                        if "warning-only" in parts:
                            af_nb_data[peer_str]["maximum_prefix_warning_only"] = True
                elif cmd.startswith("advertise-map "):
                    # advertise-map ADVERTISE-MAP exist-map EXIST-MAP
                    am_m = re.match(r"advertise-map\s+(\S+)\s+exist-map\s+(\S+)", cmd)
                    if am_m:
                        af_nb_data[peer_str]["advertise_map"] = am_m.group(1)
                        af_nb_data[peer_str]["exist_map"] = am_m.group(2)

            # Attach BGPNeighborAF to matching neighbors.
            # If the neighbor appears in the AF block but NOT at the global level
            # (common in delta proposals that only add a route-map to an existing
            # neighbor), create a thin stub so the merger can merge the AF policy
            # into the base config's existing neighbor entry.
            for peer_str, data in af_nb_data.items():
                # Only attach if there is at least one non-default field.
                # activate=False (explicit deactivation) counts as meaningful
                # even though it is falsy.
                has_content = any(v for v in data.values() if v) or not data.get("activate", True)
                if not has_content:
                    continue
                af_entry = BGPNeighborAF(
                    afi=afi,
                    safi=safi,
                    activate=data["activate"],
                    next_hop_self=data.get("next_hop_self", False),
                    route_map_in=data["route_map_in"],
                    route_map_out=data["route_map_out"],
                    prefix_list_in=data["prefix_list_in"],
                    prefix_list_out=data["prefix_list_out"],
                    filter_list_in=data["filter_list_in"],
                    filter_list_out=data["filter_list_out"],
                    default_originate_route_map=data["default_originate_route_map"],
                    maximum_prefix=data["maximum_prefix"],
                    maximum_prefix_warning_only=data["maximum_prefix_warning_only"],
                    advertise_map=data.get("advertise_map"),
                    exist_map=data.get("exist_map"),
                )
                nb = nb_index.get(peer_str)
                if nb is not None:
                    # Propagate next_hop_self from AF block to the neighbor object
                    # so the simulator can read it from nbr_src.next_hop_self directly.
                    if data.get("next_hop_self"):
                        nb.next_hop_self = True
                    nb.address_families.append(af_entry)
                else:
                    # AF-only neighbor (no global declaration in this proposal).
                    # Create a thin stub with remote_as="inherited" so the merger
                    # can match it by peer IP to the baseline's existing neighbor
                    # and apply the AF policy without clobbering remote_as.
                    try:
                        from ipaddress import IPv4Address, IPv6Address
                        peer_ip = IPv4Address(peer_str)
                    except ValueError:
                        try:
                            peer_ip = IPv6Address(peer_str)
                        except ValueError:
                            continue
                    stub = BGPNeighbor(
                        peer_ip=peer_ip,
                        remote_as="inherited",
                        next_hop_self=data.get("next_hop_self", False),
                        address_families=[af_entry],
                    )
                    neighbors.append(stub)
                    nb_index[peer_str] = stub

    def _parse_bgp_networks(self, bgp_obj, vrf: str | None) -> list["BGPNetwork"]:
        """Parse BGP network statements at global level (not in address-family).

        Classic IOS configs place ``network`` directly under ``router bgp``
        without an explicit ``address-family`` block.  These are implicit
        IPv4 unicast.  Using ``bgp_obj.children`` (direct children only)
        ensures we never pick up networks nested inside AF blocks.
        """
        network_objs = [
            c for c in bgp_obj.children
            if re.match(r"^\s+network\s+", c.text)
        ]
        return self._parse_bgp_network_stmts(network_objs)

    def _parse_bgp_redistribute(self, bgp_obj, vrf: str | None) -> list["BGPRedistribute"]:
        """Parse BGP redistribute statements at global level (not in address-family)."""
        redist_objs = [
            c for c in bgp_obj.children
            if re.match(r"^\s+redistribute\s+", c.text)
        ]
        return self._parse_bgp_redistribute_stmts(redist_objs)

    def _parse_bgp_vrf_instances(self, bgp_obj, asn: int) -> list[BGPConfig]:
        """Parse VRF-specific BGP instances from address-family ipv4 vrf blocks."""
        vrf_instances = []

        # Find VRF address-family blocks
        vrf_af_children = bgp_obj.find_child_objects(
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
            neighbor_children = vrf_af_child.find_child_objects(r"^\s+neighbor\s+(\S+)\s+")

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

            # Parse VRF networks and redistribution via shared helpers
            vrf_networks = self._parse_bgp_network_stmts(
                vrf_af_child.find_child_objects(r"^\s+network\s+")
            )
            redistribute = self._parse_bgp_redistribute_stmts(
                vrf_af_child.find_child_objects(r"^\s+redistribute\s+(\S+)")
            )

            # 'no neighbor X ...' tombstones for VRF instance
            vrf_no_commands = self._parse_bgp_neighbor_tombstones(vrf_af_child)

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
                    networks=vrf_networks,
                    redistribute=redistribute,
                    no_commands=vrf_no_commands,
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
                # IOS allows "ip route DEST MASK <interface> <next-hop-ip>" —
                # when both are present, the next-hop IP is the first token in remaining.
                r_parts = remaining.split()
                if r_parts:
                    try:
                        next_hop = IPv4Address(r_parts[0])
                        remaining = " ".join(r_parts[1:])
                    except ValueError:
                        pass

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

    def _static_route_deletion_tombstone(
        self, vrf: str, tokens: list[str]
    ) -> str | None:
        """Build a ``static:<vrf>:<dest>[:<nh_spec>]`` tombstone from a route spec.

        ``tokens`` is the whitespace-split remainder of a ``no ip route`` line
        after the optional ``vrf <NAME>`` keyword form.  Two destination forms
        are accepted:

          - ``DEST MASK [NH ...]``  — IOS traditional (two tokens)
          - ``DEST/PLEN [NH ...]``  — NX-OS/EOS CIDR (single token)

        The optional next-hop spec mirrors ``parse_static_routes``: the first
        token after the destination is an NH IP or an interface name; an
        interface may be followed by an explicit NH IP.  A pure-numeric first
        token can never be an NH (it would be an AD, which is invalid without
        an NH) — treated as NH-less defensively.  Trailing AD / tag / name /
        permanent / track tokens are excluded from the tombstone (AD is not
        part of the route identity).  Returns ``None`` when the destination
        does not parse.
        """
        if not tokens:
            return None
        if "/" in tokens[0]:
            # CIDR form (NX-OS/EOS): destination is a single token.
            dest_str = tokens[0]
            remaining = tokens[1:]
        else:
            # Traditional form: destination is DEST MASK.
            if len(tokens) < 2:
                return None
            dest_str = f"{tokens[0]}/{tokens[1]}"
            remaining = tokens[2:]
        try:
            dest = IPv4Network(dest_str, strict=False)
        except ValueError:
            return None
        nh_tokens: list[str] = []
        if remaining and not remaining[0].isdigit():
            nh_tokens.append(remaining[0])
            try:
                IPv4Address(remaining[0])
            except ValueError:
                # Interface name — may be followed by an explicit NH IP.
                if len(remaining) > 1:
                    try:
                        IPv4Address(remaining[1])
                        nh_tokens.append(remaining[1])
                    except ValueError:
                        pass
        if nh_tokens:
            return f"static:{vrf}:{dest}:{' '.join(nh_tokens)}"
        return f"static:{vrf}:{dest}"

    def parse_deletion_commands(self) -> list[str]:
        # Handles:
        #   - ``no vlan <id>``                              → ``vlan:<id>``
        """Parse top-level 'no' deletion commands into tombstone strings.

        Handles:
          - ``no ip route [vrf NAME] DEST MASK``         → ``static:<vrf>:DEST/PLEN``
          - ``no ip route [vrf NAME] DEST MASK NH [AD]`` → ``static:<vrf>:DEST/PLEN:NH``
          - ``no ip route [vrf NAME] DEST/PLEN [NH [AD]]`` (NX-OS/EOS CIDR form)
                                                          → same tombstones
          - ``no router ospf <id>``                       → ``process:ospf:<id>``
          - ``no router bgp <asn>``                       → ``process:bgp:<asn>``
          - ``no router isis [<tag>]``                    → ``process:isis:<tag>``
          - ``no router eigrp <asn>``                     → ``process:eigrp:<asn>``
          - ``no ip access-list (standard|extended) <n>`` → ``acl:<name>``
          - ``no route-map <name> (permit|deny) <seq>``  → ``route-map:<name>:seq:<seq>``
          - ``no ip prefix-list <name> seq <num>``        → ``prefix-list:<name>:seq:<num>``
          - ``no <seq>`` inside ip access-list blocks    → ``acl-seq:<name>:<seq>``
        """
        tombstones: list[str] = []
        parse = self._get_parse_obj()

        # --- static route deletions ---
        # Tombstone format: "static:<vrf>:<dest/plen>[:<nh_spec>]" where vrf=""
        # for global.  The VRF is preserved so _apply_deletions() can do a
        # VRF-exact match and avoid deleting the same prefix from a different
        # routing table.
        #
        # IOS ground truth: the identity of a static route is
        # (prefix, next-hop-or-interface).  ``no ip route DEST MASK NH``
        # removes ONLY the route via that next-hop (ECMP/floating siblings
        # survive); the NH-less ``no ip route DEST MASK`` removes ALL routes
        # for the prefix.  When an NH is present it is carried in the
        # tombstone as <nh_spec> — the space-joined NH tokens exactly as the
        # positive ``ip route`` parser would read them ("10.0.99.2", "Null0",
        # or "GigabitEthernet0/0 10.1.1.1").  Trailing AD / tag / name /
        # permanent / track tokens are excluded: AD is not part of the
        # identity (re-entering the same dest+NH with a different AD replaces
        # the entry on IOS).
        #
        # Route-spec parsing lives in _static_route_deletion_tombstone so the
        # NX-OS parser can reuse it for deletions nested under ``vrf context``
        # blocks; it also accepts the NX-OS/EOS CIDR form (``DEST/PLEN`` as a
        # single token) alongside the IOS ``DEST MASK`` form.
        for obj in parse.find_objects(r"^no\s+ip\s+route\s+"):
            m = re.search(
                r"^no\s+ip\s+route\s+(?:vrf\s+(\S+)\s+)?(.+)$",
                obj.text,
            )
            if not m:
                continue
            tombstone = self._static_route_deletion_tombstone(
                m.group(1) or "", m.group(2).split()
            )
            if tombstone:
                tombstones.append(tombstone)
        # --- vlan database deletions ---
        for obj in parse.find_objects(r"^no\s+vlan\s+"):
            m = re.search(r"^no\s+vlan\s+([\d,\-]+)", obj.text)
            if m:
                vlan_str = m.group(1)
                for part in vlan_str.split(","):
                    part = part.strip()
                    if "-" in part:
                        try:
                            start, end = part.split("-", 1)
                            for vid in range(int(start), int(end) + 1):
                                tombstones.append(f"vlan:{vid}")
                        except ValueError:
                            pass
                    else:
                        tombstones.append(f"vlan:{part}")


        # --- process-level deletions ---
        for obj in parse.find_objects(r"^no\s+router\s+ospf\s+"):
            m = re.search(r"^no\s+router\s+ospf\s+(\S+)", obj.text)
            if m:
                tombstones.append(f"process:ospf:{m.group(1)}")

        for obj in parse.find_objects(r"^no\s+router\s+bgp\s+"):
            m = re.search(r"^no\s+router\s+bgp\s+(\S+)", obj.text)
            if m:
                tombstones.append(f"process:bgp:{m.group(1)}")

        for obj in parse.find_objects(r"^no\s+router\s+isis"):
            m = re.search(r"^no\s+router\s+isis(?:\s+(\S+))?", obj.text)
            tag = m.group(1) if (m and m.group(1)) else ""
            tombstones.append(f"process:isis:{tag}")

        for obj in parse.find_objects(r"^no\s+router\s+eigrp\s+"):
            m = re.search(r"^no\s+router\s+eigrp\s+(\S+)", obj.text)
            if m:
                tombstones.append(f"process:eigrp:{m.group(1)}")

        for obj in parse.find_objects(r"^no\s+ip\s+access-list\s+"):
            m = re.search(
                r"^no\s+ip\s+access-list\s+(?:standard|extended)\s+(\S+)", obj.text
            )
            if m:
                tombstones.append(f"acl:{m.group(1)}")

        # --- route-map sequence deletion ---
        for obj in parse.find_objects(r"^no\s+route-map\s+"):
            m = re.search(
                r"^no\s+route-map\s+(\S+)\s+(?:permit|deny)\s+(\d+)", obj.text
            )
            if m:
                tombstones.append(f"route-map:{m.group(1)}:seq:{m.group(2)}")

        # --- prefix-list sequence deletion ---
        for obj in parse.find_objects(r"^no\s+ip\s+prefix-list\s+"):
            m = re.search(
                r"^no\s+ip\s+prefix-list\s+(\S+)\s+seq\s+(\d+)", obj.text
            )
            if m:
                tombstones.append(f"prefix-list:{m.group(1)}:seq:{m.group(2)}")

        # --- singleton protocol removals (whole-section) ---
        if parse.find_objects(r"^no\s+ip\s+multicast-routing"):
            tombstones.append("singleton:multicast")
        if parse.find_objects(r"^no\s+aaa\s+new-model"):
            tombstones.append("singleton:aaa")

        # --- Multicast entry-level tombstones ---
        for obj in parse.find_objects(r"^no\s+ip\s+pim\s+rp-address\s+"):
            m = re.match(r"^no\s+ip\s+pim\s+rp-address\s+(\S+)", obj.text.strip())
            if m:
                tombstones.append(f"field:multicast:rp:{m.group(1)}")
        for obj in parse.find_objects(r"^no\s+ip\s+msdp\s+peer\s+"):
            m = re.match(r"^no\s+ip\s+msdp\s+peer\s+(\S+)", obj.text.strip())
            if m:
                tombstones.append(f"field:multicast:msdp:{m.group(1)}")

        # --- BFD entry-level tombstones ---
        for obj in parse.find_objects(r"^no\s+bfd-template\s+"):
            m = re.match(r"^no\s+bfd-template\s+(?:single-hop|multi-hop)\s+(\S+)", obj.text.strip())
            if m:
                tombstones.append(f"field:bfd:template:{m.group(1)}")
            # Untyped "no bfd-template <name>" or bare "no bfd ..." (slow-timers
            # etc.) are attribute removals, not service removal — no tombstone.
        # --- Syslog entry-level tombstones ---
        for obj in parse.find_objects(r"^no\s+logging\s+"):
            t = obj.text.strip()
            m = re.match(r"^no\s+logging\s+host\s+(\S+)", t)
            if m:
                tombstones.append(f"field:syslog:host:{m.group(1)}")

        # --- DNS entry-level tombstones ---
        for obj in parse.find_objects(r"^no\s+ip\s+name-server\s+"):
            m = re.match(r"^no\s+ip\s+name-server\s+(\S+)", obj.text.strip())
            if m:
                tombstones.append(f"field:dns:name_server:{m.group(1)}")
        for obj in parse.find_objects(r"^no\s+ip\s+domain.list\s+"):
            m = re.match(r"^no\s+ip\s+domain.list\s+(\S+)", obj.text.strip())
            if m:
                tombstones.append(f"field:dns:domain:{m.group(1)}")
        if parse.find_objects(r"^no\s+ip\s+domain.lookup\s*$"):
            tombstones.append("singleton:dns")

        # --- NetFlow entry-level tombstones ---
        for obj in parse.find_objects(r"^no\s+ip\s+flow-export\s+destination\s+"):
            m = re.match(r"^no\s+ip\s+flow-export\s+destination\s+(\S+)\s+(\d+)", obj.text.strip())
            if m:
                tombstones.append(f"field:netflow:destination:{m.group(1)}:{m.group(2)}")
        if parse.find_objects(r"^no\s+ip\s+flow-export\s*$"):
            tombstones.append("singleton:netflow")

        # --- DHCP entry-level tombstones ---
        for obj in parse.find_objects(r"^no\s+ip\s+dhcp\s+pool\s+"):
            m = re.match(r"^no\s+ip\s+dhcp\s+pool\s+(\S+)", obj.text.strip())
            if m:
                tombstones.append(f"field:dhcp:pool:{m.group(1)}")
        for obj in parse.find_objects(r"^no\s+ip\s+dhcp\s+excluded-address\s+"):
            m = re.match(r"^no\s+ip\s+dhcp\s+excluded-address\s+(\S+)", obj.text.strip())
            if m:
                tombstones.append(f"field:dhcp:excluded:{m.group(1)}")

        # --- NTP entry-level tombstones ---
        for obj in parse.find_objects(r"^no\s+ntp\s+"):
            t = obj.text.strip()
            m = re.match(r"^no\s+ntp\s+server\s+(\S+)", t)
            if m:
                tombstones.append(f"field:ntp:server:{m.group(1)}")
                continue
            m = re.match(r"^no\s+ntp\s+peer\s+(\S+)", t)
            if m:
                tombstones.append(f"field:ntp:peer:{m.group(1)}")
                continue
            m = re.match(r"^no\s+ntp\s+authentication-key\s+(\d+)", t)
            if m:
                tombstones.append(f"field:ntp:auth_key:{m.group(1)}")

        # --- SNMP entry-level tombstones ---
        # Bare "no snmp-server" (no sub-command) → whole-section removal
        if parse.find_objects(r"^no\s+snmp-server\s*$"):
            tombstones.append("singleton:snmp")
        for obj in parse.find_objects(r"^no\s+snmp-server\s+"):
            t = obj.text.strip()
            m = re.match(r"^no\s+snmp-server\s+community\s+(\S+)", t)
            if m:
                tombstones.append(f"field:snmp:community:{m.group(1)}")
                continue
            m = re.match(r"^no\s+snmp-server\s+host\s+(\S+)", t)
            if m:
                tombstones.append(f"field:snmp:host:{m.group(1)}")
                continue
            m = re.match(r"^no\s+snmp-server\s+view\s+(\S+)", t)
            if m:
                tombstones.append(f"field:snmp:view:{m.group(1)}")
                continue
            m = re.match(r"^no\s+snmp-server\s+group\s+(\S+)", t)
            if m:
                tombstones.append(f"field:snmp:group:{m.group(1)}")
                continue
            m = re.match(r"^no\s+snmp-server\s+user\s+(\S+)", t)
            if m:
                tombstones.append(f"field:snmp:user:{m.group(1)}")

        # --- AAA entry-level tombstones ---
        for obj in parse.find_objects(r"^no\s+aaa\s+authentication\s+"):
            m = re.match(r"^no\s+aaa\s+authentication\s+(\S+)\s+(\S+)", obj.text.strip())
            if m:
                tombstones.append(f"field:aaa:authentication:{m.group(1)}:{m.group(2)}")
        for obj in parse.find_objects(r"^no\s+aaa\s+authorization\s+"):
            m = re.match(r"^no\s+aaa\s+authorization\s+(\S+)\s+(\S+)", obj.text.strip())
            if m:
                tombstones.append(f"field:aaa:authorization:{m.group(1)}:{m.group(2)}")
        for obj in parse.find_objects(r"^no\s+aaa\s+accounting\s+"):
            m = re.match(r"^no\s+aaa\s+accounting\s+(\S+)\s+(\S+)", obj.text.strip())
            if m:
                tombstones.append(f"field:aaa:accounting:{m.group(1)}:{m.group(2)}")
        for obj in parse.find_objects(r"^no\s+tacacs\s+server\s+"):
            m = re.match(r"^no\s+tacacs\s+server\s+(\S+)", obj.text.strip())
            if m:
                tombstones.append(f"field:aaa:tacacs_named:{m.group(1)}")
        for obj in parse.find_objects(r"^no\s+tacacs-server\s+host\s+"):
            m = re.match(r"^no\s+tacacs-server\s+host\s+(\S+)", obj.text.strip())
            if m:
                tombstones.append(f"field:aaa:tacacs:{m.group(1)}")
        for obj in parse.find_objects(r"^no\s+radius\s+server\s+"):
            m = re.match(r"^no\s+radius\s+server\s+(\S+)", obj.text.strip())
            if m:
                tombstones.append(f"field:aaa:radius_named:{m.group(1)}")
        for obj in parse.find_objects(r"^no\s+radius-server\s+host\s+"):
            m = re.match(r"^no\s+radius-server\s+host\s+(\S+)", obj.text.strip())
            if m:
                tombstones.append(f"field:aaa:radius:{m.group(1)}")

        # --- LLDP entry-level tombstones ---
        for obj in parse.find_objects(r"^no\s+lldp\s+tlv-select\s+"):
            m = re.match(r"^no\s+lldp\s+tlv-select\s+(\S+)", obj.text.strip())
            if m:
                tombstones.append(f"field:lldp:tlv:{m.group(1)}")

        # --- Service entity removals: IP SLA / object track / EEM / banner ---
        # (CCR confgraph_service_entity_removal_tombstones.md.)  Path segments
        # use the ParsedConfig field names (the ``field:vrfs:…`` precedent) so
        # the engine classifier attributes each removal to its coverage area
        # (IPSLA / OBJECT_TRACKING / EEM / BANNER) via _TOP_FIELD_AREA.
        # NX-OS/EOS inherit these walks — the syntax is identical there.
        #
        # Device-true "delete + re-add" = replace: when the SAME entity is
        # positively re-asserted later in the script (``no ip sla 1`` followed
        # by ``ip sla 1 …`` — the canonical retarget shape), the keyed replace
        # merge already models the replacement, and a tombstone would clobber
        # the re-added entity (deletions apply after the additive pass).  Each
        # walk therefore suppresses the tombstone if a positive definition of
        # the same entity appears after the negation line.
        def _readded_later(neg_linenum: int, positive_pattern: str) -> bool:
            return any(
                o.linenum > neg_linenum
                for o in parse.find_objects(positive_pattern)
            )

        # ``no ip sla <id>`` only — sub-forms (``no ip sla schedule 10``,
        # ``no ip sla responder``) are attribute removals, not entity removal.
        for obj in parse.find_objects(r"^no\s+ip\s+sla\s+\d"):
            m = re.match(r"^no\s+ip\s+sla\s+(\d+)\s*$", obj.text.strip())
            if m and not _readded_later(
                obj.linenum, rf"^ip\s+sla\s+{m.group(1)}\s*$"
            ):
                tombstones.append(f"field:ip_sla_operations:{m.group(1)}")

        # ``no track <id>`` only — ``no track 1 ip sla …`` (attribute negation
        # inside a re-assert) is not a whole-entity removal.
        for obj in parse.find_objects(r"^no\s+track\s+\d"):
            m = re.match(r"^no\s+track\s+(\d+)\s*$", obj.text.strip())
            if m and not _readded_later(
                obj.linenum, rf"^track\s+{m.group(1)}\b"
            ):
                tombstones.append(f"field:object_tracks:{m.group(1)}")

        for obj in parse.find_objects(r"^no\s+event\s+manager\s+applet\s+"):
            m = re.match(r"^no\s+event\s+manager\s+applet\s+(\S+)", obj.text.strip())
            if m and not _readded_later(
                obj.linenum,
                rf"^event\s+manager\s+applet\s+{re.escape(m.group(1))}\s*$",
            ):
                tombstones.append(f"field:eem_applets:{m.group(1)}")

        # ``no banner <type>`` → scalar reset of the BannerConfig field.  The
        # tombstone carries the model FIELD name (exec → exec_banner) so the
        # merger's generic scalar-field-reset accessor applies it directly.
        _banner_field = {
            "motd": "motd",
            "login": "login",
            "exec": "exec_banner",
            "incoming": "incoming",
        }
        for obj in parse.find_objects(r"^no\s+banner\s+"):
            m = re.match(
                r"^no\s+banner\s+(motd|login|exec|incoming)\b", obj.text.strip()
            )
            if m and not _readded_later(
                obj.linenum, rf"^banner\s+{m.group(1)}\b"
            ):
                tombstones.append(f"field:banners:{_banner_field[m.group(1)]}")

        # --- whole-VRF deletions ---
        # ``no vrf definition GUEST`` → ``field:vrfs:GUEST``
        # (CCR confgraph_vrf_rt_removal_tombstones.md).  The ``field:vrfs:…``
        # shape (plural — the ParsedConfig field name) lets the engine
        # classifier attribute the removal to the VRF coverage area.  The
        # NX-OS override adds the equivalent ``no vrf context NAME`` walk.
        for obj in parse.find_objects(r"^no\s+vrf\s+definition\s+"):
            m = re.search(r"^no\s+vrf\s+definition\s+(\S+)", obj.text)
            if m:
                tombstones.append(f"field:vrfs:{m.group(1)}")

        # --- interface deletions ---
        # ``no interface Loopback0`` → ``interface:Loopback0``
        # Deleting a parent also implicitly removes its sub-interfaces
        # (e.g. ``no interface GigabitEthernet0/0`` removes ``GigabitEthernet0/0.10``).
        for obj in parse.find_objects(r"^no\s+interface\s+"):
            m = re.search(r"^no\s+interface\s+(\S+)", obj.text)
            if m:
                tombstones.append(f"interface:{normalize_interface_name(m.group(1))}")

        # --- ACE-level deletions: "no <seq>" inside ip access-list blocks ---
        for acl_obj in parse.find_objects(
            r"^ip\s+access-list\s+(?:standard|extended)\s+"
        ):
            m = re.search(
                r"^ip\s+access-list\s+(?:standard|extended)\s+(\S+)", acl_obj.text
            )
            if not m:
                continue
            acl_name = m.group(1)
            for child in acl_obj.children:
                child_text = child.text.strip()
                m2 = re.match(r"^no\s+(\d+)$", child_text)
                if m2:
                    tombstones.append(f"acl-seq:{acl_name}:{m2.group(1)}")

        # --- Registry-driven nested block deletions ---
        # Each NestedDeletionRule maps a (parent_block, nested_no_command) pair
        # to a ``field:<template>`` tombstone consumed by _apply_deletions() →
        # _del_field() in the merger.  Adding a new nested deletion requires
        # exactly one new entry in tombstones.NESTED_DELETION_RULES plus one
        # accessor in merger._FIELD_PATH_ACCESSORS — nothing else changes.
        from confgraph.tombstones import NESTED_DELETION_RULES
        for rule in NESTED_DELETION_RULES:
            for block_obj in parse.find_objects(rule.parent_pattern):
                pm = re.search(rule.parent_pattern, block_obj.text)
                if not pm:
                    continue
                parent_ctx = {
                    name: (pm.group(i + 1) or "")
                    for i, name in enumerate(rule.parent_groups)
                }
                for child in block_obj.all_children:
                    text = child.text.strip()
                    cm = re.match(rule.child_pattern, text)
                    if not cm:
                        continue
                    child_ctx = {
                        name: (cm.group(i + 1) or "")
                        for i, name in enumerate(rule.child_groups)
                    }
                    ctx = {**parent_ctx, **child_ctx}
                    tombstones.append("field:" + rule.template.format(**ctx))

        return tombstones

    def parse_acls(self) -> list[ACLConfig]:
        """Parse ACL configurations."""
        acls = []
        parse = self._get_parse_obj()

        # Find all ACL definitions (named ACLs)
        # IOS: "ip access-list standard|extended NAME"
        # NX-OS: "ip access-list NAME" (no keyword — treated as extended)
        acl_objs = parse.find_objects(r"^ip\s+access-list\s+\S+")

        for acl_obj in acl_objs:
            match = re.search(
                r"^ip\s+access-list\s+(?:(standard|extended)\s+)?(\S+)",
                acl_obj.text,
            )
            if not match:
                continue

            acl_type = match.group(1) or "extended"
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
            net_children = isis_obj.find_child_objects(r"^\s+net\s+(\S+)")
            for net_child in net_children:
                net_addr = self._extract_match(net_child.text, r"^\s+net\s+(\S+)")
                if net_addr:
                    net.append(net_addr)

            # IS type
            is_type = None
            is_type_children = isis_obj.find_child_objects(r"^\s+is-type\s+(\S+)")
            if is_type_children:
                is_type = self._extract_match(is_type_children[0].text, r"^\s+is-type\s+(\S+)")

            # Metric style
            metric_style = None
            metric_children = isis_obj.find_child_objects(r"^\s+metric-style\s+(\S+)")
            if metric_children:
                metric_style = self._extract_match(metric_children[0].text, r"^\s+metric-style\s+(\S+)")

            # Log adjacency changes
            log_adjacency_changes = len(isis_obj.find_child_objects(r"^\s+log-adjacency-changes")) > 0

            # Passive interface default
            passive_interface_default = len(
                isis_obj.find_child_objects(r"^\s+passive-interface\s+default")
            ) > 0

            # Passive interfaces
            passive_interfaces = []
            passive_intf_children = isis_obj.find_child_objects(r"^\s+passive-interface\s+(\S+)")
            for passive_child in passive_intf_children:
                if "default" not in passive_child.text:
                    intf_name = self._extract_match(passive_child.text, r"^\s+passive-interface\s+(\S+)")
                    if intf_name:
                        passive_interfaces.append(intf_name)

            # Non-passive interfaces
            non_passive_interfaces = []
            non_passive_children = isis_obj.find_child_objects(r"^\s+no\s+passive-interface\s+(\S+)")
            for non_passive_child in non_passive_children:
                intf_name = self._extract_match(non_passive_child.text, r"^\s+no\s+passive-interface\s+(\S+)")
                if intf_name:
                    non_passive_interfaces.append(intf_name)

            # Parse redistribution
            redistribute = []
            redist_children = isis_obj.find_child_objects(r"^\s+redistribute\s+(\S+)")
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

                    # Extract process ID — only for protocols that carry one,
                    # and only as the leading token (positional, not from keywords).
                    if protocol in ("ospf", "eigrp", "bgp"):
                        pid_match = re.match(r"(\d+)", remaining)
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

                    # Extract level — check level-1-2 before level-1/level-2
                    if "level-1-2" in remaining:
                        level = "level-1-2"
                    elif "level-1" in remaining:
                        level = "level-1"
                    elif "level-2" in remaining:
                        level = "level-2"

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

            # Default-information originate
            default_info_originate = False
            default_info_route_map: str | None = None
            di_children = isis_obj.find_child_objects(
                r"^\s+default-information\s+originate"
            )
            if di_children:
                default_info_originate = True
                m = re.search(r"\broute-map\s+(\S+)", di_children[0].text)
                if m:
                    default_info_route_map = m.group(1)

            # Authentication
            authentication_mode = None
            authentication_key = None
            auth_children = isis_obj.find_child_objects(r"^\s+authentication\s+mode\s+(\S+)")
            if auth_children:
                authentication_mode = self._extract_match(auth_children[0].text, r"^\s+authentication\s+mode\s+(\S+)")

            auth_key_children = isis_obj.find_child_objects(r"^\s+authentication\s+key\s+(\S+)")
            if auth_key_children:
                authentication_key = self._extract_match(auth_key_children[0].text, r"^\s+authentication\s+key\s+(\S+)")

            # Timers
            max_lsp_lifetime = None
            lsp_lifetime_children = isis_obj.find_child_objects(r"^\s+max-lsp-lifetime\s+(\d+)")
            if lsp_lifetime_children:
                max_lsp_lifetime = int(self._extract_match(lsp_lifetime_children[0].text, r"^\s+max-lsp-lifetime\s+(\d+)"))

            lsp_refresh_interval = None
            lsp_refresh_children = isis_obj.find_child_objects(r"^\s+lsp-refresh-interval\s+(\d+)")
            if lsp_refresh_children:
                lsp_refresh_interval = int(self._extract_match(lsp_refresh_children[0].text, r"^\s+lsp-refresh-interval\s+(\d+)"))

            spf_interval = None
            spf_children = isis_obj.find_child_objects(r"^\s+spf-interval\s+(\d+)")
            if spf_children:
                spf_interval = int(self._extract_match(spf_children[0].text, r"^\s+spf-interval\s+(\d+)"))

            # Per-interface IS-IS config — IOS stores this in the interface block.
            # Scan all interfaces for "ip router isis [TAG]" membership, then collect
            # isis metric / circuit-type / passive commands for this instance.
            isis_interfaces: list[ISISInterface] = []
            for intf_obj in parse.find_objects(r"^interface\s+"):
                # Check if this interface is in this IS-IS instance
                isis_ref_ch = intf_obj.find_child_objects(r"^\s+ip\s+router\s+isis\s*(\S*)")
                if not isis_ref_ch:
                    continue
                ref_tag = self._extract_match(
                    isis_ref_ch[0].text, r"^\s+ip\s+router\s+isis\s*(\S*)"
                ) or None
                # Match: tagless "ip router isis" matches the default (tag=None) instance;
                # named tag must match exactly.
                if ref_tag != tag:
                    continue

                intf_name = self._extract_match(intf_obj.text, r"^interface\s+(\S+)")
                if not intf_name:
                    continue

                # Global metric: isis metric N  (no level qualifier)
                isis_metric: int | None = None
                m_ch = intf_obj.find_child_objects(r"^\s+isis\s+metric\s+(\d+)\s*$")
                if m_ch:
                    v = self._extract_match(m_ch[0].text, r"^\s+isis\s+metric\s+(\d+)")
                    if v:
                        isis_metric = int(v)

                # Level-specific metrics
                isis_metric_l1: int | None = None
                m1_ch = intf_obj.find_child_objects(r"^\s+isis\s+metric\s+(\d+)\s+level-1")
                if m1_ch:
                    v = self._extract_match(m1_ch[0].text, r"^\s+isis\s+metric\s+(\d+)")
                    if v:
                        isis_metric_l1 = int(v)

                isis_metric_l2: int | None = None
                m2_ch = intf_obj.find_child_objects(r"^\s+isis\s+metric\s+(\d+)\s+level-2")
                if m2_ch:
                    v = self._extract_match(m2_ch[0].text, r"^\s+isis\s+metric\s+(\d+)")
                    if v:
                        isis_metric_l2 = int(v)

                # Circuit type
                circuit_type: str | None = None
                ct_ch = intf_obj.find_child_objects(r"^\s+isis\s+circuit-type\s+(\S+)")
                if ct_ch:
                    circuit_type = self._extract_match(
                        ct_ch[0].text, r"^\s+isis\s+circuit-type\s+(\S+)"
                    )

                # Passive
                isis_passive = bool(intf_obj.find_child_objects(r"^\s+isis\s+passive"))

                isis_interfaces.append(ISISInterface(
                    name=intf_name,
                    circuit_type=circuit_type,
                    metric=isis_metric,
                    level_1_metric=isis_metric_l1,
                    level_2_metric=isis_metric_l2,
                    passive=isis_passive,
                ))

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
                    default_information_originate=default_info_originate,
                    default_information_originate_route_map=default_info_route_map,
                    authentication_mode=authentication_mode,
                    authentication_key=authentication_key,
                    max_lsp_lifetime=max_lsp_lifetime,
                    lsp_refresh_interval=lsp_refresh_interval,
                    spf_interval=spf_interval,
                    interfaces=isis_interfaces,
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
                # Named-mode EIGRP: "router eigrp NAME" — the real AS is
                # under "address-family ipv4 unicast autonomous-system N"
                as_number = as_number_str
                af_ch = eigrp_obj.find_child_objects(
                    r"^\s+address-family\s+ipv4.*autonomous-system\s+(\d+)"
                )
                if af_ch:
                    as_val = self._extract_match(
                        af_ch[0].text,
                        r"autonomous-system\s+(\d+)",
                    )
                    if as_val:
                        as_number = int(as_val)

            raw_lines, line_numbers = self._get_raw_lines_and_line_numbers(eigrp_obj)

            # router-id
            router_id = None
            rid_ch = eigrp_obj.find_child_objects(r"^\s+eigrp\s+router-id\s+(\S+)")
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
            for nc in eigrp_obj.find_child_objects(r"^\s+network\s+"):
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
            passive_default = bool(eigrp_obj.find_child_objects(r"^\s+passive-interface\s+default"))
            passive_ifs = []
            non_passive_ifs = []
            for pic in eigrp_obj.find_child_objects(r"^\s+(?:no\s+)?passive-interface\s+\S"):
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
            for rc in eigrp_obj.find_child_objects(r"^\s+redistribute\s+"):
                rm = re.match(r"^\s+redistribute\s+(\S+)", rc.text)
                if not rm:
                    continue
                proto = rm.group(1)
                remaining = rc.text[rm.end():].strip()

                # Process ID — only for protocols that carry one,
                # and only as the leading positional token.
                pid: int | str | None = None
                if proto in ("bgp", "ospf", "eigrp"):
                    pid_match = re.match(r"(\d+)", remaining)
                    if pid_match:
                        pid = int(pid_match.group(1))

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
            auto_summary = bool(eigrp_obj.find_child_objects(r"^\s+auto-summary"))
            variance = None
            vc = eigrp_obj.find_child_objects(r"^\s+variance\s+(\d+)")
            if vc:
                v = self._extract_match(vc[0].text, r"^\s+variance\s+(\d+)")
                if v:
                    variance = int(v)

            maximum_paths = None
            mpc = eigrp_obj.find_child_objects(r"^\s+maximum-paths\s+(\d+)")
            if mpc:
                v = self._extract_match(mpc[0].text, r"^\s+maximum-paths\s+(\d+)")
                if v:
                    maximum_paths = int(v)

            distance_internal = distance_external = None
            dc = eigrp_obj.find_child_objects(r"^\s+distance\s+eigrp\s+(\d+)\s+(\d+)")
            if dc:
                dm = re.match(r"^\s+distance\s+eigrp\s+(\d+)\s+(\d+)", dc[0].text)
                if dm:
                    distance_internal = int(dm.group(1))
                    distance_external = int(dm.group(2))

            default_metric = None
            dmc = eigrp_obj.find_child_objects(r"^\s+default-metric\s+")
            if dmc:
                dmm = re.search(r"\bdefault-metric\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)", dmc[0].text)
                if dmm:
                    from confgraph.models.eigrp import EIGRPMetric
                    default_metric = EIGRPMetric(
                        bandwidth=int(dmm.group(1)), delay=int(dmm.group(2)),
                        reliability=int(dmm.group(3)), load=int(dmm.group(4)), mtu=int(dmm.group(5))
                    )

            # K-values: metric weights tos K1 K2 K3 K4 K5
            k_values = None
            kv_objs = eigrp_obj.find_child_objects(r"^\s+metric\s+weights\s+")
            if kv_objs:
                kvm = re.match(
                    r"^\s+metric\s+weights\s+\d+\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)",
                    kv_objs[0].text,
                )
                if kvm:
                    k_values = [int(kvm.group(i)) for i in range(1, 6)]

            log_neighbor = bool(eigrp_obj.find_child_objects(r"^\s+eigrp\s+log-neighbor-changes"))
            stub = None
            sc = eigrp_obj.find_child_objects(r"^\s+eigrp\s+stub")
            if sc:
                sm = re.match(r"^\s+eigrp\s+stub\s*(.*)", sc[0].text)
                if sm:
                    stub = sm.group(1).strip() or "stub"

            # summary-address
            summary_addresses = []
            for sac in eigrp_obj.find_child_objects(r"^\s+summary-address\s+"):
                sam = re.match(r"^\s+summary-address\s+(\S+)\s+(\S+)(?:\s+(\d+))?", sac.text)
                if sam:
                    try:
                        from ipaddress import IPv4Network
                        net_addr = sam.group(1)
                        mask = sam.group(2)
                        pfx = IPv4Network(f"{net_addr}/{mask}", strict=False)
                        ad = int(sam.group(3)) if sam.group(3) else None
                        from confgraph.models.eigrp import EIGRPSummaryAddress
                        summary_addresses.append(EIGRPSummaryAddress(prefix=pfx, admin_distance=ad))
                    except Exception:
                        pass

            vrf = None
            vc2 = eigrp_obj.find_child_objects(r"^\s+address-family\s+ipv4\s+vrf\s+(\S+)")
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
                k_values=k_values,
                vrf=vrf,
                stub=stub,
                summary_addresses=summary_addresses,
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
            vc = rip_obj.find_child_objects(r"^\s+version\s+(\d)")
            if vc:
                v = self._extract_match(vc[0].text, r"^\s+version\s+(\d)")
                if v:
                    version = int(v)

            from ipaddress import IPv4Network
            networks = []
            for nc in rip_obj.find_child_objects(r"^\s+network\s+"):
                nm = re.match(r"^\s+network\s+(\S+)", nc.text)
                if nm:
                    try:
                        networks.append(IPv4Network(nm.group(1), strict=False))
                    except Exception:
                        pass

            passive_default = bool(rip_obj.find_child_objects(r"^\s+passive-interface\s+default"))
            passive_ifs = []
            non_passive_ifs = []
            for pic in rip_obj.find_child_objects(r"^\s+(?:no\s+)?passive-interface\s+\S"):
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
            for rc in rip_obj.find_child_objects(r"^\s+redistribute\s+"):
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

            auto_summary = bool(rip_obj.find_child_objects(r"^\s+auto-summary"))
            default_info = bool(rip_obj.find_child_objects(r"^\s+default-information\s+originate"))

            timers = None
            tc = rip_obj.find_child_objects(r"^\s+timers\s+basic\s+")
            if tc:
                tm = re.match(r"^\s+timers\s+basic\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)", tc[0].text)
                if tm:
                    from confgraph.models.rip import RIPTimers
                    timers = RIPTimers(
                        update=int(tm.group(1)), invalid=int(tm.group(2)),
                        holddown=int(tm.group(3)), flush=int(tm.group(4))
                    )

            maximum_paths = None
            mpc = rip_obj.find_child_objects(r"^\s+maximum-paths\s+(\d+)")
            if mpc:
                v = self._extract_match(mpc[0].text, r"^\s+maximum-paths\s+(\d+)")
                if v:
                    maximum_paths = int(v)

            distance = None
            dc = rip_obj.find_child_objects(r"^\s+distance\s+(\d+)")
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
                # IOS/IOS-XR: snmp-server community STRING ro|rw [view V] [ACL]
                m = re.match(r"^snmp-server\s+community\s+(\S+)\s+(ro|rw)(\s+.*)?$", t, re.IGNORECASE)
                if m:
                    acl = None
                    view = None
                    rest = (m.group(3) or "").strip()
                    vm = re.search(r"\bview\s+(\S+)", rest)
                    if vm:
                        view = vm.group(1)
                        # Remove "view NAME" so view name isn't also treated as ACL
                        rest = re.sub(r"\bview\s+\S+", "", rest).strip()
                    # last token may be ACL
                    parts = rest.split()
                    if parts and not re.match(r"^(view|ipv6)$", parts[-1]):
                        acl = parts[-1]
                    communities.append(SNMPCommunity(
                        community_string=m.group(1), access=m.group(2).lower(),
                        acl=acl, view=view,
                    ))
                    continue
                # NX-OS: snmp-server community STRING group ROLE
                m = re.match(r"^snmp-server\s+community\s+(\S+)\s+group\s+(\S+)", t)
                if m:
                    # Map NX-OS roles to ro/rw: network-operator → ro, network-admin → rw
                    role = m.group(2)
                    access = "rw" if "admin" in role else "ro"
                    communities.append(SNMPCommunity(
                        community_string=m.group(1), access=access,
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
        no_log_objs = parse.find_objects(r"^no\s+logging\s+on\s*$")
        if not log_objs and not no_log_objs:
            return None

        from ipaddress import IPv4Address, IPv6Address
        hosts = []
        buffered_size = buffered_level = None
        console_level = monitor_level = trap_level = None
        facility = source_interface = origin_id = None
        timestamps_log = timestamps_debug = None
        enabled = not bool(no_log_objs)

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
            elif t == "logging off":
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
            etc = line_obj.find_child_objects(r"^\s+exec-timeout\s+")
            if etc:
                etm = re.match(r"^\s+exec-timeout\s+(\d+)(?:\s+(\d+))?", etc[0].text)
                if etm:
                    exec_timeout_minutes = int(etm.group(1))
                    exec_timeout_seconds = int(etm.group(2)) if etm.group(2) else 0

            logging_sync = bool(line_obj.find_child_objects(r"^\s+logging\s+synchronous"))

            # transport input
            transport_input = []
            tic = line_obj.find_child_objects(r"^\s+transport\s+input\s+")
            if tic:
                tim = re.match(r"^\s+transport\s+input\s+(.*)", tic[0].text)
                if tim:
                    transport_input = tim.group(1).strip().split()

            # transport output
            transport_output = []
            toc = line_obj.find_child_objects(r"^\s+transport\s+output\s+")
            if toc:
                tom = re.match(r"^\s+transport\s+output\s+(.*)", toc[0].text)
                if tom:
                    transport_output = tom.group(1).strip().split()

            access_class_in = access_class_out = ipv6_in = None
            for acc in line_obj.find_child_objects(r"^\s+access-class\s+"):
                acm = re.match(r"^\s+access-class\s+(\S+)\s+(in|out)", acc.text)
                if acm:
                    if acm.group(2) == "in":
                        access_class_in = acm.group(1)
                    else:
                        access_class_out = acm.group(1)
            for acc in line_obj.find_child_objects(r"^\s+ipv6\s+access-class\s+"):
                acm = re.match(r"^\s+ipv6\s+access-class\s+(\S+)\s+in", acc.text)
                if acm:
                    ipv6_in = acm.group(1)

            privilege_level = None
            plc = line_obj.find_child_objects(r"^\s+privilege\s+level\s+(\d+)")
            if plc:
                v = self._extract_match(plc[0].text, r"^\s+privilege\s+level\s+(\d+)")
                if v:
                    privilege_level = int(v)

            password = None
            pwc = line_obj.find_child_objects(r"^\s+password\s+")
            if pwc:
                pm = re.match(r"^\s+password\s+(?:\d+\s+)?(\S+)", pwc[0].text)
                if pm:
                    password = pm.group(1)

            login = None
            lc = line_obj.find_child_objects(r"^\s+login\s*")
            if lc:
                lm = re.match(r"^\s+login\s*(.*)", lc[0].text)
                if lm:
                    login = lm.group(1).strip() or "line"

            length = width = session_timeout = history_size = None
            lenc = line_obj.find_child_objects(r"^\s+length\s+(\d+)")
            if lenc:
                v = self._extract_match(lenc[0].text, r"^\s+length\s+(\d+)")
                if v:
                    length = int(v)
            wc = line_obj.find_child_objects(r"^\s+width\s+(\d+)")
            if wc:
                v = self._extract_match(wc[0].text, r"^\s+width\s+(\d+)")
                if v:
                    width = int(v)
            stc = line_obj.find_child_objects(r"^\s+session-timeout\s+(\d+)")
            if stc:
                v = self._extract_match(stc[0].text, r"^\s+session-timeout\s+(\d+)")
                if v:
                    session_timeout = int(v)
            hsc = line_obj.find_child_objects(r"^\s+history\s+size\s+(\d+)")
            if hsc:
                v = self._extract_match(hsc[0].text, r"^\s+history\s+size\s+(\d+)")
                if v:
                    history_size = int(v)

            no_exec = bool(line_obj.find_child_objects(r"^\s+no\s+exec"))

            stopbits = speed = None
            sbc = line_obj.find_child_objects(r"^\s+stopbits\s+(\d+)")
            if sbc:
                v = self._extract_match(sbc[0].text, r"^\s+stopbits\s+(\d+)")
                if v:
                    stopbits = int(v)
            spc = line_obj.find_child_objects(r"^\s+speed\s+(\d+)")
            if spc:
                v = self._extract_match(spc[0].text, r"^\s+speed\s+(\d+)")
                if v:
                    speed = int(v)

            flowcontrol = None
            fcc = line_obj.find_child_objects(r"^\s+flowcontrol\s+")
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
            for mc in cm_obj.find_child_objects(r"^\s+match\s+"):
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

    # -----------------------------------------------------------------------
    # MPLS / LDP
    # -----------------------------------------------------------------------

    def parse_mpls(self) -> "MPLSConfig | None":
        """Parse global MPLS and LDP configuration.

        Handles::

            mpls ldp router-id Loopback0 force
            mpls label range 100 199
            mpls ldp graceful-restart
            mpls ldp session protection
            mpls ldp password required for <acl>

        Per-interface ``mpls ip`` is parsed in parse_interfaces().
        """
        from confgraph.models.mpls import MPLSConfig

        parse = self._get_parse_obj()

        ldp_objs = parse.find_objects(r"^mpls\s+")
        if not ldp_objs:
            return None

        ldp_router_id = None
        ldp_router_id_force = False
        label_range_min = None
        label_range_max = None
        ldp_graceful_restart = False
        ldp_session_protection = False
        ldp_password = None

        for obj in ldp_objs:
            t = obj.text.strip()

            m = re.match(r"^mpls\s+ldp\s+router-id\s+(\S+)(\s+force)?", t)
            if m:
                ldp_router_id = m.group(1)
                ldp_router_id_force = m.group(2) is not None
                continue

            m = re.match(r"^mpls\s+label\s+range\s+(\d+)\s+(\d+)", t)
            if m:
                label_range_min = int(m.group(1))
                label_range_max = int(m.group(2))
                continue

            if re.match(r"^mpls\s+ldp\s+graceful-restart\b", t):
                ldp_graceful_restart = True
                continue

            if re.match(r"^mpls\s+ldp\s+session\s+protection\b", t):
                ldp_session_protection = True
                continue

            m = re.match(r"^mpls\s+ldp\s+password\s+", t)
            if m:
                ldp_password = t  # store raw line for config-only assessment
                continue

        # Determine if LDP is effectively enabled (any interface has mpls ip,
        # or ldp router-id is set).
        ldp_enabled = ldp_router_id is not None

        return MPLSConfig(
            object_id="mpls",
            raw_lines=[o.text for o in ldp_objs],
            source_os=self.os_type,
            line_numbers=[],
            ldp_router_id=ldp_router_id,
            ldp_router_id_force=ldp_router_id_force,
            label_range_min=label_range_min,
            label_range_max=label_range_max,
            ldp_enabled=ldp_enabled,
            ldp_graceful_restart=ldp_graceful_restart,
            ldp_session_protection=ldp_session_protection,
            ldp_password=ldp_password,
        )

    # -----------------------------------------------------------------------
    # AAA
    # -----------------------------------------------------------------------

    def parse_aaa(self) -> AAAConfig | None:
        """Parse AAA configuration.

        Handles::

            aaa new-model
            aaa authentication login default local tacacs+
            aaa authentication enable default enable
            aaa authorization exec default local
            aaa authorization commands 15 default local
            aaa accounting exec default start-stop group tacacs+
            tacacs server TACACS_SRV
             address ipv4 10.0.0.1
             key Secret
            tacacs-server host 10.0.0.2 key Secret
            radius server RAD_SRV
             address ipv4 10.0.0.3 auth-port 1812 acct-port 1813
             key Secret
        """
        parse = self._get_parse_obj()
        aaa_objs = parse.find_objects(r"^aaa\s+")
        tacacs_named = parse.find_objects(r"^tacacs\s+server\s+")
        tacacs_legacy = parse.find_objects(r"^tacacs-server\s+host\s+")
        radius_named = parse.find_objects(r"^radius\s+server\s+")
        radius_legacy = parse.find_objects(r"^radius-server\s+host\s+")
        group_objs = parse.find_objects(r"^aaa\s+group\s+server\s+")

        tacacs_src_objs = parse.find_objects(r"^ip\s+tacacs\s+source-interface\s+")
        radius_src_objs = parse.find_objects(r"^ip\s+radius\s+source-interface\s+")

        if (not aaa_objs and not tacacs_named and not tacacs_legacy
                and not radius_named and not radius_legacy
                and not tacacs_src_objs and not radius_src_objs):
            return None

        new_model = False
        auth_lists: list[AAAAuthList] = []
        author_lists: list[AAAAuthorList] = []
        acct_lists: list[AAAAcctList] = []
        tacacs_servers: list[TacacsServer] = []
        radius_servers: list[RadiusServer] = []
        raw_lines: list[str] = []
        line_numbers: list[int] = []

        for obj in aaa_objs:
            raw_lines.append(obj.text)
            line_numbers.append(obj.linenum)
            t = obj.text.strip()

            if t == "aaa new-model":
                new_model = True
            elif re.match(r"^aaa\s+authentication\s+", t):
                m = re.match(r"^aaa\s+authentication\s+(\S+)\s+(\S+)\s+(.*)", t)
                if m:
                    service, name, methods_str = m.group(1), m.group(2), m.group(3)
                    methods = methods_str.split()
                    auth_lists.append(AAAAuthList(name=name, service=service, methods=methods))
            elif re.match(r"^aaa\s+authorization\s+", t):
                m = re.match(r"^aaa\s+authorization\s+(\S+)(?:\s+(\d+))?\s+(\S+)\s+(.*)", t)
                if m:
                    service, priv, name, methods_str = m.group(1), m.group(2), m.group(3), m.group(4)
                    methods = methods_str.split()
                    author_lists.append(AAAAuthorList(
                        name=name, service=service,
                        privilege_level=int(priv) if priv else None,
                        methods=methods,
                    ))
            elif re.match(r"^aaa\s+accounting\s+", t):
                m = re.match(r"^aaa\s+accounting\s+(\S+)(?:\s+(\d+))?\s+(\S+)\s+(start-stop|stop-only|none)\s+(.*)", t)
                if m:
                    service, priv, name, trigger, methods_str = m.group(1), m.group(2), m.group(3), m.group(4), m.group(5)
                    methods = methods_str.split()
                    acct_lists.append(AAAAcctList(
                        name=name, service=service,
                        privilege_level=int(priv) if priv else None,
                        trigger=trigger, methods=methods,
                    ))

        # Named TACACS+ servers ("tacacs server NAME" block)
        for obj in tacacs_named:
            raw_lines.append(obj.text)
            line_numbers.append(obj.linenum)
            block_name = self._extract_match(obj.text.strip(), r"^tacacs\s+server\s+(\S+)")
            address = None
            port = None
            timeout_val = None
            key = None
            vrf = None
            for child in obj.children:
                raw_lines.append(child.text)
                line_numbers.append(child.linenum)
                ct = child.text.strip()
                am = re.match(r"address\s+ipv[46]\s+(\S+)(?:\s+port\s+(\d+))?", ct)
                if am:
                    address = am.group(1)
                    port = int(am.group(2)) if am.group(2) else None
                elif ct.startswith("key "):
                    key = ct.split(None, 1)[1]
                elif ct.startswith("timeout "):
                    v = self._extract_match(ct, r"timeout\s+(\d+)")
                    if v:
                        timeout_val = int(v)
                elif ct.startswith("vrf "):
                    vrf = ct.split(None, 1)[1]
            if address:
                tacacs_servers.append(TacacsServer(name=block_name, address=address, port=port, timeout=timeout_val, key=key, vrf=vrf))

        # Legacy single-line TACACS ("tacacs-server host ADDR")
        for obj in tacacs_legacy:
            raw_lines.append(obj.text)
            line_numbers.append(obj.linenum)
            t = obj.text.strip()
            m = re.match(r"tacacs-server\s+host\s+(\S+)(?:\s+port\s+(\d+))?(?:\s+timeout\s+(\d+))?(?:\s+key\s+(\S+))?", t)
            if m:
                tacacs_servers.append(TacacsServer(
                    name=m.group(1),
                    address=m.group(1),
                    port=int(m.group(2)) if m.group(2) else None,
                    timeout=int(m.group(3)) if m.group(3) else None,
                    key=m.group(4),
                ))

        # Named RADIUS servers ("radius server NAME" block)
        for obj in radius_named:
            raw_lines.append(obj.text)
            line_numbers.append(obj.linenum)
            block_name = self._extract_match(obj.text.strip(), r"^radius\s+server\s+(\S+)")
            address = None
            auth_port = acct_port = timeout_val = None
            key = vrf = None
            for child in obj.children:
                raw_lines.append(child.text)
                line_numbers.append(child.linenum)
                ct = child.text.strip()
                am = re.match(r"address\s+ipv[46]\s+(\S+)(?:\s+auth-port\s+(\d+))?(?:\s+acct-port\s+(\d+))?", ct)
                if am:
                    address = am.group(1)
                    auth_port = int(am.group(2)) if am.group(2) else None
                    acct_port = int(am.group(3)) if am.group(3) else None
                elif ct.startswith("key "):
                    key = ct.split(None, 1)[1]
                elif ct.startswith("timeout "):
                    v = self._extract_match(ct, r"timeout\s+(\d+)")
                    if v:
                        timeout_val = int(v)
            if address:
                radius_servers.append(RadiusServer(name=block_name, address=address, auth_port=auth_port, acct_port=acct_port, timeout=timeout_val, key=key))

        # Legacy single-line RADIUS ("radius-server host ADDR")
        for obj in radius_legacy:
            raw_lines.append(obj.text)
            line_numbers.append(obj.linenum)
            t = obj.text.strip()
            m = re.match(r"radius-server\s+host\s+(\S+)(?:\s+auth-port\s+(\d+))?(?:\s+acct-port\s+(\d+))?(?:\s+key\s+(\S+))?", t)
            if m:
                radius_servers.append(RadiusServer(
                    name=m.group(1),
                    address=m.group(1),
                    auth_port=int(m.group(2)) if m.group(2) else None,
                    acct_port=int(m.group(3)) if m.group(3) else None,
                    key=m.group(4),
                ))

        for obj in group_objs:
            raw_lines.append(obj.text)
            line_numbers.append(obj.linenum)

        # Source-interface bindings (global config lines)
        tacacs_src_iface: str | None = None
        for obj in tacacs_src_objs:
            raw_lines.append(obj.text)
            line_numbers.append(obj.linenum)
            m = re.match(r"ip\s+tacacs\s+source-interface\s+(\S+)", obj.text.strip())
            if m:
                tacacs_src_iface = m.group(1)

        radius_src_iface: str | None = None
        for obj in radius_src_objs:
            raw_lines.append(obj.text)
            line_numbers.append(obj.linenum)
            m = re.match(r"ip\s+radius\s+source-interface\s+(\S+)", obj.text.strip())
            if m:
                radius_src_iface = m.group(1)

        local_auth = any("local" in al.methods for al in auth_lists)

        return AAAConfig(
            object_id="aaa",
            raw_lines=raw_lines,
            source_os=self.os_type,
            line_numbers=line_numbers,
            new_model=new_model,
            authentication_lists=auth_lists,
            authorization_lists=author_lists,
            accounting_lists=acct_lists,
            tacacs_servers=tacacs_servers,
            radius_servers=radius_servers,
            tacacs_source_interface=tacacs_src_iface,
            radius_source_interface=radius_src_iface,
            local_auth_enabled=local_auth,
        )

    # -----------------------------------------------------------------------
    # DNS
    # -----------------------------------------------------------------------

    def parse_dns(self) -> DNSConfig | None:
        """Parse DNS / name-resolution configuration.

        Handles::

            ip domain name example.com          (IOS)
            ip domain-name example.com          (alternate form)
            ip domain list corp.example.com
            ip name-server 8.8.8.8 8.8.4.4
            no ip domain lookup
            domain name example.com             (IOS-XR, no "ip" prefix)
            domain name-server 8.8.8.8          (IOS-XR)
        """
        parse = self._get_parse_obj()
        # IOS: "ip domain …" / IOS-XR: "domain …" (no ip prefix)
        domain_objs = parse.find_objects(r"^(?:ip\s+)?domain")
        # IOS: "ip name-server" / IOS-XR: "domain name-server"
        ns_objs = parse.find_objects(r"^ip\s+name-server")
        xr_ns_objs = parse.find_objects(r"^domain\s+name-server")
        no_ns_objs = parse.find_objects(r"^no\s+(?:ip\s+)?name-server")
        lookup_disabled = bool(parse.find_objects(r"^no\s+(?:ip\s+)?domain.lookup"))

        if not domain_objs and not ns_objs and not xr_ns_objs and not no_ns_objs and not lookup_disabled:
            return None

        domain_name: str | None = None
        domain_list: list[str] = []
        name_servers: list[str] = []
        raw_lines: list[str] = []
        line_numbers: list[int] = []

        for obj in domain_objs:
            raw_lines.append(obj.text)
            line_numbers.append(obj.linenum)
            t = obj.text.strip()
            # "ip domain name DOMAIN" / "ip domain-name DOMAIN" / "domain name DOMAIN"
            m = re.match(r"^(?:ip\s+)?domain(?:-|\s+)name\s+(\S+)", t)
            if m and domain_name is None:
                domain_name = m.group(1)
                continue
            # "ip domain list DOMAIN" / "domain list DOMAIN"
            m = re.match(r"^(?:ip\s+)?domain\s+list\s+(\S+)", t)
            if m:
                domain_list.append(m.group(1))

        for obj in ns_objs:
            raw_lines.append(obj.text)
            line_numbers.append(obj.linenum)
            # "ip name-server [vrf NAME] A B C ..." — multiple IPs on one line
            t = obj.text.strip()
            parts = re.split(r"\s+", t)[2:]  # skip "ip name-server"
            # Strip optional "vrf <name>" prefix
            if len(parts) >= 2 and parts[0].lower() == "vrf":
                parts = parts[2:]
            name_servers.extend(parts)

        # IOS-XR: "domain name-server <ip>" — one IP per line
        for obj in xr_ns_objs:
            raw_lines.append(obj.text)
            line_numbers.append(obj.linenum)
            t = obj.text.strip()
            m = re.match(r"^domain\s+name-server\s+(\S+)", t)
            if m:
                name_servers.append(m.group(1))

        return DNSConfig(
            object_id="dns",
            raw_lines=raw_lines,
            source_os=self.os_type,
            line_numbers=line_numbers,
            lookup_enabled=not lookup_disabled,
            domain_name=domain_name,
            domain_list=domain_list,
            name_servers=name_servers,
        )

    # -----------------------------------------------------------------------
    # DHCP
    # -----------------------------------------------------------------------

    def parse_dhcp(self) -> DHCPConfig | None:
        """Parse DHCP server / relay / snooping configuration.

        Handles::

            ip dhcp excluded-address 192.168.1.1 192.168.1.10
            ip dhcp pool VLAN10
             network 192.168.1.0 255.255.255.0
             default-router 192.168.1.1
             dns-server 8.8.8.8 8.8.4.4
             domain-name example.com
             lease 1
            ip dhcp snooping
            ip dhcp snooping vlan 10,20
        """
        parse = self._get_parse_obj()
        dhcp_objs = parse.find_objects(r"^ip\s+dhcp\s+")
        if not dhcp_objs:
            return None

        excluded: list[DHCPExcludedRange] = []
        pools: list[DHCPPool] = []
        snooping_enabled = False
        snooping_vlans: list[str] = []
        relay_opt = True
        raw_lines: list[str] = []
        line_numbers: list[int] = []

        for obj in dhcp_objs:
            raw_lines.append(obj.text)
            line_numbers.append(obj.linenum)
            t = obj.text.strip()

            if re.match(r"^ip\s+dhcp\s+excluded-address\s+", t):
                m = re.match(r"^ip\s+dhcp\s+excluded-address\s+(\S+)(?:\s+(\S+))?", t)
                if m:
                    excluded.append(DHCPExcludedRange(low=m.group(1), high=m.group(2)))
            elif re.match(r"^ip\s+dhcp\s+pool\s+", t):
                pool_name = self._extract_match(t, r"^ip\s+dhcp\s+pool\s+(\S+)")
                network = default_routers = dns_srvs = domain = None
                default_routers = []
                dns_srvs = []
                lease_days = lease_hours = lease_mins = None
                lease_inf = False
                for child in obj.children:
                    raw_lines.append(child.text)
                    line_numbers.append(child.linenum)
                    ct = child.text.strip()
                    if ct.startswith("network "):
                        network = ct[len("network "):].strip()
                    elif ct.startswith("default-router "):
                        default_routers = ct.split()[1:]
                    elif ct.startswith("dns-server "):
                        dns_srvs = ct.split()[1:]
                    elif ct.startswith("domain-name "):
                        domain = ct.split(None, 1)[1]
                    elif ct.startswith("lease "):
                        parts = ct.split()
                        if len(parts) >= 2 and parts[1] == "infinite":
                            lease_inf = True
                        else:
                            if len(parts) >= 2:
                                lease_days = int(parts[1])
                            if len(parts) >= 3:
                                lease_hours = int(parts[2])
                            if len(parts) >= 4:
                                lease_mins = int(parts[3])
                if pool_name:
                    pools.append(DHCPPool(
                        name=pool_name, network=network,
                        default_router=default_routers, dns_servers=dns_srvs,
                        domain_name=domain,
                        lease_days=lease_days, lease_hours=lease_hours,
                        lease_minutes=lease_mins, lease_infinite=lease_inf,
                    ))
            elif re.match(r"^ip\s+dhcp\s+snooping\s+vlan\s+", t):
                vlan_str = self._extract_match(t, r"^ip\s+dhcp\s+snooping\s+vlan\s+(\S+)")
                if vlan_str:
                    snooping_vlans.append(vlan_str)
            elif re.match(r"^ip\s+dhcp\s+snooping\s*$", t):
                snooping_enabled = True
            elif "no ip dhcp relay information option" in t:
                relay_opt = False

        return DHCPConfig(
            object_id="dhcp",
            raw_lines=raw_lines,
            source_os=self.os_type,
            line_numbers=line_numbers,
            excluded_ranges=excluded,
            pools=pools,
            snooping_enabled=snooping_enabled,
            snooping_vlans=snooping_vlans,
            relay_information_option=relay_opt,
        )

    # -----------------------------------------------------------------------
    # LLDP
    # -----------------------------------------------------------------------

    def parse_lldp(self) -> LLDPConfig | None:
        """Parse LLDP global configuration.

        Handles::

            lldp run
            no lldp run
            lldp timer 30
            lldp holdtime 120
            lldp reinit 2
            lldp tlv-select system-description
        """
        parse = self._get_parse_obj()
        lldp_objs = parse.find_objects(r"^(?:no\s+)?lldp\b")
        if not lldp_objs:
            return None

        enabled = True
        timer = holdtime = reinit = None
        tlv_select: list[str] = []
        raw_lines: list[str] = []
        line_numbers: list[int] = []

        for obj in lldp_objs:
            raw_lines.append(obj.text)
            line_numbers.append(obj.linenum)
            t = obj.text.strip()
            if t in ("no lldp run", "no lldp"):
                enabled = False
            elif re.match(r"^lldp\s+timer\s+", t):
                v = self._extract_match(t, r"^lldp\s+timer\s+(\d+)")
                if v:
                    timer = int(v)
            elif re.match(r"^lldp\s+holdtime\s+", t):
                v = self._extract_match(t, r"^lldp\s+holdtime\s+(\d+)")
                if v:
                    holdtime = int(v)
            elif re.match(r"^lldp\s+reinit\s+", t):
                v = self._extract_match(t, r"^lldp\s+reinit\s+(\d+)")
                if v:
                    reinit = int(v)
            elif re.match(r"^lldp\s+tlv-select\s+", t):
                tlv = self._extract_match(t, r"^lldp\s+tlv-select\s+(\S+)")
                if tlv:
                    tlv_select.append(tlv)

        return LLDPConfig(
            object_id="lldp",
            raw_lines=raw_lines,
            source_os=self.os_type,
            line_numbers=line_numbers,
            enabled=enabled,
            timer=timer,
            holdtime=holdtime,
            reinit=reinit,
            tlv_select=tlv_select,
        )

    # -----------------------------------------------------------------------
    # CDP
    # -----------------------------------------------------------------------

    def parse_cdp(self) -> CDPConfig | None:
        """Parse CDP global configuration.

        Handles::

            cdp run
            no cdp run
            cdp timer 60
            cdp holdtime 180
            cdp advertise-v2
            no cdp advertise-v2
        """
        parse = self._get_parse_obj()
        cdp_objs = parse.find_objects(r"^(?:no\s+)?cdp\b")
        if not cdp_objs:
            return None

        enabled = True
        timer = holdtime = None
        advertise_v2 = True
        raw_lines: list[str] = []
        line_numbers: list[int] = []

        for obj in cdp_objs:
            raw_lines.append(obj.text)
            line_numbers.append(obj.linenum)
            t = obj.text.strip()
            if t in ("no cdp run", "no cdp"):
                enabled = False
            elif re.match(r"^cdp\s+timer\s+", t):
                v = self._extract_match(t, r"^cdp\s+timer\s+(\d+)")
                if v:
                    timer = int(v)
            elif re.match(r"^cdp\s+holdtime\s+", t):
                v = self._extract_match(t, r"^cdp\s+holdtime\s+(\d+)")
                if v:
                    holdtime = int(v)
            elif "no cdp advertise-v2" in t:
                advertise_v2 = False

        return CDPConfig(
            object_id="cdp",
            raw_lines=raw_lines,
            source_os=self.os_type,
            line_numbers=line_numbers,
            enabled=enabled,
            timer=timer,
            holdtime=holdtime,
            advertise_v2=advertise_v2,
        )

    # -----------------------------------------------------------------------
    # Spanning Tree
    # -----------------------------------------------------------------------

    def parse_spanning_tree(self) -> STPConfig | None:
        """Parse Spanning Tree Protocol global configuration.

        Handles::

            spanning-tree mode rapid-pvst
            spanning-tree vlan 1 priority 4096
            spanning-tree vlan 10,20 priority 8192
            spanning-tree portfast default
            spanning-tree portfast bpduguard default
            spanning-tree portfast bpdufilter default
            spanning-tree loopguard default
        """
        parse = self._get_parse_obj()
        stp_objs = parse.find_objects(r"^spanning-tree\s+")
        if not stp_objs:
            return None

        mode: str | None = None
        vlan_configs: list[STPVlanConfig] = []
        portfast_default = False
        bpduguard_default = False
        bpdufilter_default = False
        loopguard_default = False
        raw_lines: list[str] = []
        line_numbers: list[int] = []

        for obj in stp_objs:
            raw_lines.append(obj.text)
            line_numbers.append(obj.linenum)
            t = obj.text.strip()

            if re.match(r"^spanning-tree\s+mode\s+", t):
                mode = self._extract_match(t, r"^spanning-tree\s+mode\s+(\S+)")
            elif re.match(r"^spanning-tree\s+vlan\s+", t):
                m = re.match(r"^spanning-tree\s+vlan\s+(\S+)\s+(\S+)\s+(\S+)", t)
                if m:
                    vlan_id, param, value = m.group(1), m.group(2), m.group(3)
                    # Find existing vlan entry or create new one
                    existing = next((v for v in vlan_configs if v.vlan_id == vlan_id), None)
                    if existing is None:
                        existing = STPVlanConfig(vlan_id=vlan_id)
                        vlan_configs.append(existing)
                    if param == "priority":
                        existing.priority = int(value)
                    elif param == "hello-time":
                        existing.hello_time = int(value)
                    elif param == "forward-time":
                        existing.forward_time = int(value)
                    elif param == "max-age":
                        existing.max_age = int(value)
            elif "portfast bpduguard default" in t:
                bpduguard_default = True
            elif "portfast bpdufilter default" in t:
                bpdufilter_default = True
            elif "portfast default" in t:
                portfast_default = True
            elif "loopguard default" in t:
                loopguard_default = True

        return STPConfig(
            object_id="spanning_tree",
            raw_lines=raw_lines,
            source_os=self.os_type,
            line_numbers=line_numbers,
            mode=mode,
            vlan_configs=vlan_configs,
            portfast_default=portfast_default,
            bpduguard_default=bpduguard_default,
            bpdufilter_default=bpdufilter_default,
            loopguard_default=loopguard_default,
        )

    def parse_lacp_system_priority(self) -> int | None:
        """Parse global ``lacp system-priority <N>``."""
        parse = self._get_parse_obj()
        objs = parse.find_objects(r"^lacp\s+system-priority\s+\d+")
        if objs:
            m = re.search(r"lacp\s+system-priority\s+(\d+)", objs[0].text)
            if m:
                return int(m.group(1))
        return None

    def parse_vtp(self):
        """Parse VTP configuration.

        Handles::

            vtp domain EXAMPLE
            vtp mode transparent
            vtp version 2
        """
        from confgraph.models.vlan import VTPConfig

        parse = self._get_parse_obj()
        vtp_objs = parse.find_objects(r"^vtp\s+")
        if not vtp_objs:
            return None

        domain: str | None = None
        mode: str | None = None
        version: int | None = None
        raw_lines: list[str] = []
        line_numbers: list[int] = []

        for obj in vtp_objs:
            raw_lines.append(obj.text)
            line_numbers.append(obj.linenum)
            t = obj.text.strip()

            dm = re.match(r"^vtp\s+domain\s+(\S+)", t)
            if dm:
                domain = dm.group(1)
            mm = re.match(r"^vtp\s+mode\s+(\S+)", t)
            if mm:
                mode = mm.group(1).lower()
            vm = re.match(r"^vtp\s+version\s+(\d+)", t)
            if vm:
                version = int(vm.group(1))

        return VTPConfig(
            object_id="vtp",
            raw_lines=raw_lines,
            source_os=self.os_type,
            line_numbers=line_numbers,
            domain=domain,
            mode=mode,
            version=version,
        )

    def parse_vlans(self) -> list[VLANEntry]:
        """Parse VLAN database entries.

        Handles the IOS/IOS-XE block-level VLAN syntax::

            vlan 10
             name MGMT
            vlan 20
             name SERVERS
            vlan 30
             state suspend

        Each ``vlan N`` block is parsed into a VLANEntry.  The compact
        comma-separated form (``vlan 10,20,30``) is also supported — in that
        case all VLAN IDs in the range share the same state (no name).
        """
        parse = self._get_parse_obj()
        vlan_objs = parse.find_objects(r"^vlan\s+\d")
        entries: list[VLANEntry] = []

        for obj in vlan_objs:
            m = re.match(r"^vlan\s+([\d,\-]+)", obj.text.strip())
            if not m:
                continue
            vlan_str = m.group(1)

            # Expand comma-separated / range notation
            vlan_ids: list[int] = []
            for part in vlan_str.split(","):
                part = part.strip()
                if "-" in part:
                    try:
                        start, end = part.split("-", 1)
                        vlan_ids.extend(range(int(start), int(end) + 1))
                    except ValueError:
                        pass
                else:
                    try:
                        vlan_ids.append(int(part))
                    except ValueError:
                        pass

            # For single-VLAN blocks, read children for name / state / vn-segment
            if len(vlan_ids) == 1:
                vid = vlan_ids[0]
                name: str | None = None
                state = "active"
                vn_segment: int | None = None

                for child in obj.children:
                    child_text = child.text.strip()
                    nm = re.match(r"^name\s+(\S+)", child_text)
                    if nm:
                        name = nm.group(1)
                    sm = re.match(r"^state\s+(active|suspend)", child_text)
                    if sm:
                        state = sm.group(1)
                    vnseg = re.match(r"^vn-segment\s+(\d+)", child_text)
                    if vnseg:
                        vn_segment = int(vnseg.group(1))

                entries.append(VLANEntry(vlan_id=vid, name=name, state=state,
                                         vn_segment=vn_segment))
            else:
                # Compact form — no per-VLAN children
                for vid in vlan_ids:
                    entries.append(VLANEntry(vlan_id=vid))

        # Deduplicate by vlan_id (last definition wins, matching IOS semantics)
        seen: dict[int, VLANEntry] = {}
        for entry in entries:
            seen[entry.vlan_id] = entry
        return list(seen.values())

    def parse_netflow(self) -> NetFlowConfig | None:
        """Parse NetFlow export configuration.

        Handles::

            ip flow-export destination 10.0.0.100 9996
            ip flow-export source GigabitEthernet0/1
            ip flow-export version 9
        """
        parse = self._get_parse_obj()
        flow_objs = parse.find_objects(r"^ip\s+flow-export\s+")
        if not flow_objs:
            return None

        source_interface: str | None = None
        destinations: list[NetFlowDestination] = []
        version: int | None = None
        raw_lines: list[str] = []
        line_numbers: list[int] = []

        for obj in flow_objs:
            raw_lines.append(obj.text)
            line_numbers.append(obj.linenum)
            t = obj.text.strip()

            m_dst = re.match(r"^ip\s+flow-export\s+destination\s+(\S+)\s+(\d+)", t)
            if m_dst:
                try:
                    destinations.append(NetFlowDestination(
                        address=IPv4Address(m_dst.group(1)),
                        port=int(m_dst.group(2)),
                    ))
                except ValueError:
                    pass
                continue

            m_src = re.match(r"^ip\s+flow-export\s+source\s+(\S+)", t)
            if m_src:
                source_interface = m_src.group(1)
                continue

            m_ver = re.match(r"^ip\s+flow-export\s+version\s+(\d+)", t)
            if m_ver:
                try:
                    version = int(m_ver.group(1))
                except ValueError:
                    pass

        return NetFlowConfig(
            object_id="netflow",
            raw_lines=raw_lines,
            source_os=self.os_type,
            line_numbers=line_numbers,
            source_interface=source_interface,
            destinations=destinations,
            version=version,
        )
