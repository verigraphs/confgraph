"""Cisco IOS-XR configuration parser."""

import re
from ipaddress import IPv4Address, IPv4Interface, IPv4Network, IPv6Address, IPv6Interface

from confgraph.models.base import OSType
from confgraph.models.vrf import VRFConfig
from confgraph.models.bgp import (
    BGPConfig,
    BGPNeighbor,
    BGPNeighborAF,
    BGPPeerGroup,
    BGPRedistribute,
    BGPBestpathOptions,
)
from confgraph.models.acl import ACLConfig, ACLEntry
from confgraph.models.static_route import StaticRoute
from confgraph.models.multicast import MulticastConfig, PIMRPAddress
from confgraph.models.ospf import (
    OSPFConfig,
    OSPFArea,
    OSPFAreaType,
    OSPFRange,
    OSPFRedistribute,
)
from confgraph.models.route_map import RouteMapConfig, RouteMapSequence, RouteMapMatch, RouteMapSet
from confgraph.models.prefix_list import PrefixListConfig, PrefixListEntry
from confgraph.models.community_list import (
    CommunityListConfig,
    CommunityListEntry,
    ASPathListConfig,
    ASPathListEntry,
)
from confgraph.parsers.base import _BASE_KNOWN_PATTERNS
from confgraph.parsers.ios_parser import IOSParser


# IOS-XR patterns differ from IOS: different VRF, route-policy, prefix-set, etc.
_IOSXR_KNOWN_PATTERNS: list[str] = [
    p for p in _BASE_KNOWN_PATTERNS
    if p not in (
        r"^vrf definition",
        r"^route-map",
        r"^ip prefix-list",
        r"^ipv6 prefix-list",
        r"^ip as-path access-list",
        r"^ip community-list",
    )
] + [
    r"^vrf\s+\S+",           # "vrf CUSTOMER_A"
    r"^route-policy",         # IOS-XR route-policy
    r"^prefix-set",           # IOS-XR prefix-set
    r"^as-path-set",          # IOS-XR as-path-set
    r"^community-set",        # IOS-XR community-set
    r"^extcommunity-set",     # IOS-XR extcommunity-set
    r"^mpls",
    r"^l2vpn",
]


class IOSXRParser(IOSParser):
    """Parser for Cisco IOS-XR configurations.

    Inherits from IOSParser and overrides methods where IOS-XR syntax
    differs: VRF (vrf NAME with nested RT blocks), interfaces (ipv4 address),
    BGP (neighbor-group / use neighbor-group), OSPF (interfaces nested under
    area blocks), route-policy → RouteMapConfig, prefix-set → PrefixListConfig,
    as-path-set → ASPathListConfig, community-set → CommunityListConfig.
    """

    _KNOWN_TOP_LEVEL_PATTERNS: list[str] = _IOSXR_KNOWN_PATTERNS

    def __init__(self, config_text: str):
        super().__init__(config_text, os_type=OSType.IOS_XR)
        self.syntax = "iosxr"
        self.parse_obj = None  # Force re-creation with new syntax

    # -----------------------------------------------------------------------
    # VRFs — "vrf NAME" with nested import/export route-target blocks
    # -----------------------------------------------------------------------

    def parse_vrfs(self) -> list[VRFConfig]:
        """Parse VRF configurations from IOS-XR config.

        IOS-XR format::

            vrf CUSTOMER_A
             address-family ipv4 unicast
              import route-target
               65000:100
              !
              export route-target
               65000:100
              !
        """
        vrfs = []
        parse = self._get_parse_obj()

        # IOS-XR: top-level "vrf NAME" blocks (not "vrf definition" or "vrf context")
        vrf_objs = parse.find_objects(r"^vrf\s+(\S+)")
        for vrf_obj in vrf_objs:
            # Skip false positives like "vrf definition" (IOS-XE)
            if re.match(r"^vrf\s+(definition|context)\s+", vrf_obj.text):
                continue

            vrf_name = self._extract_match(vrf_obj.text, r"^vrf\s+(\S+)")
            if not vrf_name:
                continue

            raw_lines, line_numbers = self._get_raw_lines_and_line_numbers(vrf_obj)

            # Route-targets are under address-family → import/export route-target blocks
            rt_import: list[str] = []
            rt_export: list[str] = []
            rt_both: list[str] = []

            # Walk all_children to find import/export route-target stanzas
            in_import_rt = False
            in_export_rt = False
            for child in vrf_obj.all_children:
                text = child.text.strip()
                if text == "import route-target":
                    in_import_rt = True
                    in_export_rt = False
                    continue
                elif text == "export route-target":
                    in_export_rt = True
                    in_import_rt = False
                    continue
                elif text.startswith("!") or (text and not text[0].isdigit() and ":" not in text):
                    in_import_rt = False
                    in_export_rt = False

                if in_import_rt and re.match(r"\d+:\d+", text):
                    rt_import.append(text)
                elif in_export_rt and re.match(r"\d+:\d+", text):
                    rt_export.append(text)

            # Route-policy import/export
            route_map_import = None
            route_map_export = None
            for child in vrf_obj.all_children:
                text = child.text.strip()
                if text.startswith("import route-policy "):
                    route_map_import = self._extract_match(
                        text, r"import\s+route-policy\s+(\S+)"
                    )
                elif text.startswith("export route-policy "):
                    route_map_export = self._extract_match(
                        text, r"export\s+route-policy\s+(\S+)"
                    )

            vrfs.append(
                VRFConfig(
                    object_id=f"vrf_{vrf_name}",
                    raw_lines=raw_lines,
                    source_os=self.os_type,
                    line_numbers=line_numbers,
                    name=vrf_name,
                    rd=None,  # IOS-XR puts RD under BGP, not VRF definition
                    route_target_import=rt_import,
                    route_target_export=rt_export,
                    route_target_both=rt_both,
                    route_map_import=route_map_import,
                    route_map_export=route_map_export,
                )
            )

        return vrfs

    # -----------------------------------------------------------------------
    # Interface VRF — "vrf NAME" (no "forwarding" keyword)
    # -----------------------------------------------------------------------

    def _extract_interface_vrf(self, intf_obj) -> str | None:
        """Extract VRF from interface. IOS-XR uses ``vrf NAME`` (no keyword)."""
        vrf_ch = intf_obj.re_search_children(r"^\s+vrf\s+(\S+)")
        if vrf_ch:
            return self._extract_match(vrf_ch[0].text, r"^\s+vrf\s+(\S+)")
        return None

    # -----------------------------------------------------------------------
    # Interfaces — "ipv4 address X.X.X.X MASK"
    # -----------------------------------------------------------------------

    def parse_interfaces(self) -> list:
        """Parse interfaces. Override IP address extraction for IOS-XR notation."""
        interfaces = super().parse_interfaces()

        parse = self._get_parse_obj()
        intf_objs = parse.find_objects(r"^interface\s+")

        for intf_obj in intf_objs:
            intf_name = self._extract_match(intf_obj.text, r"^interface\s+(\S+)")
            if not intf_name:
                continue

            intf_cfg = next((i for i in interfaces if i.name == intf_name), None)
            if intf_cfg is None:
                continue

            # IOS-XR: ipv4 address X.X.X.X MASK
            ipv4_children = intf_obj.re_search_children(
                r"^\s+ipv4\s+address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)"
            )
            if ipv4_children:
                match = re.search(
                    r"^\s+ipv4\s+address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)",
                    ipv4_children[0].text,
                )
                if match:
                    try:
                        intf_cfg.ip_address = IPv4Interface(
                            f"{match.group(1)}/{match.group(2)}"
                        )
                    except ValueError:
                        pass

            # IOS-XR: ipv4 access-group <name> ingress|egress
            for ag_ch in intf_obj.re_search_children(
                r"^\s+ipv4\s+access-group\s+\S+\s+(ingress|egress)"
            ):
                m = re.match(r"^\s+ipv4\s+access-group\s+(\S+)\s+(ingress|egress)", ag_ch.text)
                if m:
                    if m.group(2) == "ingress":
                        intf_cfg.acl_in = m.group(1)
                    else:
                        intf_cfg.acl_out = m.group(1)

            # IOS-XR: ipv6 address
            ipv6_children = intf_obj.re_search_children(r"^\s+ipv6\s+address\s+(\S+)")
            ipv6_addresses = []
            for ipv6_child in ipv6_children:
                m = re.search(r"^\s+ipv6\s+address\s+(\S+)", ipv6_child.text)
                if m and "link-local" not in ipv6_child.text:
                    try:
                        ipv6_addresses.append(IPv6Interface(m.group(1)))
                    except ValueError:
                        pass
            if ipv6_addresses:
                intf_cfg.ipv6_addresses = ipv6_addresses

        return interfaces

    # -----------------------------------------------------------------------
    # BGP — "neighbor-group NAME" / "use neighbor-group NAME"
    # -----------------------------------------------------------------------

    def _parse_bgp_peer_groups(self, bgp_obj) -> list[BGPPeerGroup]:
        """Parse BGP peer-groups. IOS-XR uses ``neighbor-group NAME`` blocks."""
        peer_groups = []

        ng_children = bgp_obj.re_search_children(r"^\s+neighbor-group\s+(\S+)")
        for ng_child in ng_children:
            pg_name = self._extract_match(ng_child.text, r"^\s+neighbor-group\s+(\S+)")
            if not pg_name:
                continue

            pg_data: dict = {
                "name": pg_name,
                "remote_as": None,
                "description": None,
                "update_source": None,
                "route_reflector_client": False,
                "send_community": False,
            }

            for child in ng_child.all_children:
                text = child.text.strip()
                if text.startswith("remote-as "):
                    val = text.replace("remote-as ", "").strip()
                    try:
                        pg_data["remote_as"] = int(val)
                    except ValueError:
                        pg_data["remote_as"] = val
                elif text.startswith("description "):
                    pg_data["description"] = text.replace("description ", "").strip()
                elif text.startswith("update-source "):
                    pg_data["update_source"] = text.replace("update-source ", "").strip()
                elif text == "route-reflector-client":
                    pg_data["route_reflector_client"] = True
                elif text.startswith("send-community"):
                    if "both" in text:
                        pg_data["send_community"] = "both"
                    elif "extended" in text:
                        pg_data["send_community"] = "extended"
                    else:
                        pg_data["send_community"] = True

            peer_groups.append(BGPPeerGroup(**pg_data))

        return peer_groups

    def _parse_bgp_vrf_instances(self, bgp_obj, asn: int) -> list[BGPConfig]:
        """Parse VRF-specific BGP instances.

        IOS-XR uses ``vrf VRFNAME`` blocks directly under ``router bgp``.
        """
        vrf_instances = []
        vrf_children = bgp_obj.re_search_children(r"^\s+vrf\s+(\S+)")

        for vrf_child in vrf_children:
            vrf_name = self._extract_match(vrf_child.text, r"^\s+vrf\s+(\S+)")
            if not vrf_name:
                continue

            raw_lines, line_numbers = self._get_raw_lines_and_line_numbers(vrf_child)

            # RD is inside the VRF block
            rd = None
            rd_ch = vrf_child.re_search_children(r"^\s+rd\s+(\S+)")
            if rd_ch:
                rd = self._extract_match(rd_ch[0].text, r"^\s+rd\s+(\S+)")

            # VRF neighbors — IOS-XR uses block syntax per neighbor
            vrf_neighbors: list[BGPNeighbor] = []
            for nb_child in vrf_child.re_search_children(r"^\s+neighbor\s+(\S+)\s*$"):
                peer_str = self._extract_match(nb_child.text, r"^\s+neighbor\s+(\S+)\s*$")
                if not peer_str:
                    continue
                try:
                    peer_ip = IPv4Address(peer_str)
                except ValueError:
                    try:
                        peer_ip = IPv6Address(peer_str)
                    except ValueError:
                        continue

                nd: dict = {
                    "remote_as": None,
                    "description": None,
                    "update_source": None,
                    "route_map_in": None,
                    "route_map_out": None,
                }
                for child in nb_child.all_children:
                    text = child.text.strip()
                    if text.startswith("remote-as "):
                        val = text.split(None, 1)[1].strip()
                        try:
                            nd["remote_as"] = int(val)
                        except ValueError:
                            nd["remote_as"] = val
                    elif text.startswith("description "):
                        nd["description"] = text.split(None, 1)[1].strip()
                    elif text.startswith("update-source "):
                        nd["update_source"] = text.split(None, 1)[1].strip()
                    # AF-level route-policy (inside address-family block)
                    elif text.startswith("route-policy ") and text.endswith(" in"):
                        nd["route_map_in"] = text[len("route-policy "):-3].strip()
                    elif text.startswith("route-policy ") and text.endswith(" out"):
                        nd["route_map_out"] = text[len("route-policy "):-4].strip()

                if nd["remote_as"] is None:
                    continue
                vrf_neighbors.append(BGPNeighbor(
                    peer_ip=peer_ip,
                    remote_as=nd["remote_as"],
                    description=nd["description"],
                    update_source=nd["update_source"],
                    route_map_in=nd["route_map_in"],
                    route_map_out=nd["route_map_out"],
                ))

            # Redistribution
            redistribute: list[BGPRedistribute] = []
            for child in vrf_child.all_children:
                text = child.text.strip()
                rd_m = re.match(r"redistribute\s+(\S+)(.*)", text)
                if not rd_m:
                    continue
                protocol = rd_m.group(1)
                remaining = rd_m.group(2).strip()
                process_id = None
                route_map = None
                pid_m = re.search(r"(\d+)", remaining)
                if pid_m:
                    process_id = int(pid_m.group(1))
                rm_m = re.search(r"route-policy\s+(\S+)", remaining)
                if rm_m:
                    route_map = rm_m.group(1)
                redistribute.append(
                    BGPRedistribute(protocol=protocol, process_id=process_id, route_map=route_map)
                )

            vrf_instances.append(
                BGPConfig(
                    object_id=f"bgp_{asn}_vrf_{vrf_name}",
                    raw_lines=raw_lines,
                    source_os=self.os_type,
                    line_numbers=line_numbers,
                    asn=asn,
                    router_id=None,
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

    # -----------------------------------------------------------------------
    # OSPF — interfaces nested under area blocks
    # -----------------------------------------------------------------------

    def parse_ospf(self) -> list[OSPFConfig]:
        """Parse OSPF configurations for IOS-XR.

        IOS-XR nests interface membership under ``area N`` → ``interface NAME``
        blocks instead of per-interface ``ip ospf`` commands.
        """
        ospf_instances = []
        parse = self._get_parse_obj()

        ospf_objs = parse.find_objects(r"^router\s+ospf\s+(\d+)")
        for ospf_obj in ospf_objs:
            process_id_str = self._extract_match(ospf_obj.text, r"^router\s+ospf\s+(\d+)")
            if not process_id_str:
                continue

            process_id = int(process_id_str)
            raw_lines, line_numbers = self._get_raw_lines_and_line_numbers(ospf_obj)

            # Router ID
            router_id = None
            rid_ch = ospf_obj.re_search_children(r"^\s+router-id\s+(\S+)")
            if rid_ch:
                rid_str = self._extract_match(rid_ch[0].text, r"^\s+router-id\s+(\S+)")
                try:
                    router_id = IPv4Address(rid_str)
                except ValueError:
                    pass

            # Log adjacency changes
            log_adj = bool(ospf_obj.re_search_children(r"^\s+log\s+adjacency\s+changes"))
            log_adj_detail = bool(ospf_obj.re_search_children(r"^\s+log\s+adjacency\s+changes\s+detail"))

            # Auto-cost
            auto_cost_ref_bw = None
            ac_ch = ospf_obj.re_search_children(r"^\s+auto-cost\s+reference-bandwidth\s+(\d+)")
            if ac_ch:
                v = self._extract_match(ac_ch[0].text, r"^\s+auto-cost\s+reference-bandwidth\s+(\d+)")
                if v:
                    auto_cost_ref_bw = int(v)

            # Passive interface default (IOS-XR: per-interface "passive enable")
            passive_interface_default = False
            passive_interfaces: list[str] = []
            non_passive_interfaces: list[str] = []

            # Parse areas — IOS-XR has "area N" stanzas with nested interfaces
            areas, passive_interfaces = self._parse_ospf_areas_iosxr(ospf_obj)

            # Redistribution
            redistribute = self._parse_ospf_redistribute_iosxr(ospf_obj)

            # Default-information originate
            di_originate = False
            di_always = False
            di_metric: int | None = None
            di_metric_type: int | None = None
            di_route_map: str | None = None

            di_ch = ospf_obj.re_search_children(r"^\s+default-information\s+originate")
            if di_ch:
                di_originate = True
                di_text = di_ch[0].text
                di_always = "always" in di_text
                m = re.search(r"\bmetric\s+(\d+)", di_text)
                if m:
                    di_metric = int(m.group(1))
                m = re.search(r"\bmetric-type\s+(\d+)", di_text)
                if m:
                    di_metric_type = int(m.group(1))
                m = re.search(r"\broute-policy\s+(\S+)", di_text)
                if m:
                    di_route_map = m.group(1)

            ospf_instances.append(
                OSPFConfig(
                    object_id=f"ospf_{process_id}",
                    raw_lines=raw_lines,
                    source_os=self.os_type,
                    line_numbers=line_numbers,
                    process_id=process_id,
                    vrf=None,
                    router_id=router_id,
                    log_adjacency_changes=log_adj,
                    log_adjacency_changes_detail=log_adj_detail,
                    auto_cost_reference_bandwidth=auto_cost_ref_bw,
                    passive_interface_default=passive_interface_default,
                    passive_interfaces=passive_interfaces,
                    non_passive_interfaces=non_passive_interfaces,
                    areas=areas,
                    redistribute=redistribute,
                    default_information_originate=di_originate,
                    default_information_originate_always=di_always,
                    default_information_originate_metric=di_metric,
                    default_information_originate_metric_type=di_metric_type,
                    default_information_originate_route_map=di_route_map,
                )
            )

        return ospf_instances

    def _parse_ospf_areas_iosxr(self, ospf_obj) -> tuple[list[OSPFArea], list[str]]:
        """Parse OSPF areas with nested interface blocks (IOS-XR style).

        Returns a tuple of (areas, passive_interfaces).
        """
        areas: list[OSPFArea] = []
        area_dict: dict[str, dict] = {}
        passive_interfaces: list[str] = []

        area_children = ospf_obj.re_search_children(r"^\s+area\s+(\S+)")
        for area_child in area_children:
            area_id = self._extract_match(area_child.text, r"^\s+area\s+(\S+)")
            if not area_id:
                continue

            if area_id not in area_dict:
                area_dict[area_id] = {
                    "area_id": area_id,
                    "area_type": OSPFAreaType.NORMAL,
                    "stub_no_summary": False,
                    "nssa_no_summary": False,
                    "authentication": None,
                    "ranges": [],
                    "interfaces": [],
                }

            # Area type
            for prop_child in area_child.re_search_children(r"^\s+nssa"):
                text = prop_child.text.strip()
                if "no-summary" in text or "no-redistribution no-summary" in text:
                    area_dict[area_id]["area_type"] = OSPFAreaType.TOTALLY_NSSA
                    area_dict[area_id]["nssa_no_summary"] = True
                else:
                    area_dict[area_id]["area_type"] = OSPFAreaType.NSSA

            for prop_child in area_child.re_search_children(r"^\s+stub"):
                text = prop_child.text.strip()
                if "no-summary" in text:
                    area_dict[area_id]["area_type"] = OSPFAreaType.TOTALLY_STUB
                    area_dict[area_id]["stub_no_summary"] = True
                else:
                    area_dict[area_id]["area_type"] = OSPFAreaType.STUB

            # Authentication
            auth_ch = area_child.re_search_children(r"^\s+authentication\s+")
            if auth_ch:
                if "message-digest" in auth_ch[0].text:
                    area_dict[area_id]["authentication"] = "message-digest"
                else:
                    area_dict[area_id]["authentication"] = "simple"

            # Ranges (IOS-XR: range X.X.X.X/N)
            for range_child in area_child.re_search_children(r"^\s+range\s+(\S+)"):
                range_str = self._extract_match(range_child.text, r"^\s+range\s+(\S+)")
                if range_str:
                    try:
                        prefix = IPv4Network(range_str, strict=False)
                        area_dict[area_id]["ranges"].append(
                            OSPFRange(prefix=prefix, advertise=True)
                        )
                    except ValueError:
                        pass

            # Interfaces nested under area
            for intf_child in area_child.re_search_children(r"^\s+interface\s+(\S+)"):
                intf_name = self._extract_match(intf_child.text, r"^\s+interface\s+(\S+)")
                if intf_name and intf_name not in area_dict[area_id]["interfaces"]:
                    area_dict[area_id]["interfaces"].append(intf_name)
                # IOS-XR marks passive with "passive enable" inside the interface block
                if intf_name and intf_child.re_search_children(r"^\s+passive\s+enable"):
                    if intf_name not in passive_interfaces:
                        passive_interfaces.append(intf_name)

        for area_data in area_dict.values():
            areas.append(OSPFArea(**area_data))

        return areas, passive_interfaces

    def _parse_ospf_redistribute_iosxr(self, ospf_obj) -> list[OSPFRedistribute]:
        """Parse OSPF redistribution for IOS-XR (uses route-policy instead of route-map)."""
        redistribute: list[OSPFRedistribute] = []
        redist_ch = ospf_obj.re_search_children(r"^\s+redistribute\s+(\S+)")

        for redist_child in redist_ch:
            match = re.search(r"^\s+redistribute\s+(\S+)(.+)?", redist_child.text)
            if not match:
                continue

            protocol = match.group(1)
            remaining = match.group(2).strip() if match.group(2) else ""

            process_id = None
            route_map = None
            metric = None
            metric_type = None

            pid_m = re.search(r"\b(\d+)\b", remaining)
            if pid_m:
                process_id = int(pid_m.group(1))

            # IOS-XR uses route-policy
            rpm = re.search(r"route-policy\s+(\S+)", remaining)
            if rpm:
                route_map = rpm.group(1)

            mm = re.search(r"\bmetric\s+(\d+)", remaining)
            if mm:
                metric = int(mm.group(1))

            mtm = re.search(r"\bmetric-type\s+(\d+)", remaining)
            if mtm:
                metric_type = int(mtm.group(1))

            redistribute.append(
                OSPFRedistribute(
                    protocol=protocol,
                    process_id=process_id,
                    route_map=route_map,
                    metric=metric,
                    metric_type=metric_type,
                )
            )

        return redistribute

    # -----------------------------------------------------------------------
    # Route-maps — "route-policy NAME" ... "end-policy"
    # -----------------------------------------------------------------------

    def parse_route_maps(self) -> list[RouteMapConfig]:
        """Parse IOS-XR route-policy blocks and map them to RouteMapConfig.

        The full policy body is stored as raw set/match entries so that
        the dependency graph can reference policy names without needing
        to interpret the if/then/else language.
        """
        route_maps: list[RouteMapConfig] = []
        parse = self._get_parse_obj()

        rp_objs = parse.find_objects(r"^route-policy\s+(\S+)")
        for rp_obj in rp_objs:
            rp_name = self._extract_match(rp_obj.text, r"^route-policy\s+(\S+)")
            if not rp_name:
                continue

            raw_lines, line_numbers = self._get_raw_lines_and_line_numbers(rp_obj)

            # Extract match/set clauses as best-effort from the policy body
            match_clauses: list[RouteMapMatch] = []
            set_clauses: list[RouteMapSet] = []

            for child in rp_obj.all_children:
                text = child.text.strip()
                if text.startswith("if destination in "):
                    dest = self._extract_match(text, r"if destination in (\S+)")
                    if dest:
                        match_clauses.append(
                            RouteMapMatch(match_type="ip address prefix-list", values=[dest])
                        )
                elif text.startswith("set local-preference "):
                    val = self._extract_match(text, r"set local-preference (\S+)")
                    if val:
                        set_clauses.append(RouteMapSet(set_type="local-preference", values=[val]))
                elif text.startswith("set med ") or text.startswith("set metric "):
                    val = self._extract_match(text, r"set (?:med|metric) (\S+)")
                    if val:
                        set_clauses.append(RouteMapSet(set_type="metric", values=[val]))
                elif text.startswith("set community "):
                    val = self._extract_match(text, r"set community (\S+)")
                    if val:
                        set_clauses.append(RouteMapSet(set_type="community", values=[val]))
                elif text.startswith("prepend as-path "):
                    vals = text.replace("prepend as-path ", "").split()
                    set_clauses.append(RouteMapSet(set_type="as-path prepend", values=vals))
                elif text.startswith("set origin "):
                    val = self._extract_match(text, r"set origin (\S+)")
                    if val:
                        set_clauses.append(RouteMapSet(set_type="origin", values=[val]))

            sequence = RouteMapSequence(
                sequence=10,
                action="permit",
                match_clauses=match_clauses,
                set_clauses=set_clauses,
            )

            route_maps.append(
                RouteMapConfig(
                    object_id=f"route_map_{rp_name}",
                    raw_lines=raw_lines,
                    source_os=self.os_type,
                    line_numbers=line_numbers,
                    name=rp_name,
                    sequences=[sequence],
                )
            )

        return route_maps

    # -----------------------------------------------------------------------
    # Prefix-lists — "prefix-set NAME" ... "end-set"
    # -----------------------------------------------------------------------

    def parse_prefix_lists(self) -> list[PrefixListConfig]:
        """Parse IOS-XR prefix-set blocks and map to PrefixListConfig.

        IOS-XR format::

            prefix-set ISP1_PREFIX_OUT
              10.0.0.0/16 le 24,
              192.168.0.0/16 le 24
            end-set
        """
        prefix_lists: list[PrefixListConfig] = []
        parse = self._get_parse_obj()

        ps_objs = parse.find_objects(r"^prefix-set\s+(\S+)")
        for ps_obj in ps_objs:
            ps_name = self._extract_match(ps_obj.text, r"^prefix-set\s+(\S+)")
            if not ps_name:
                continue

            raw_lines, line_numbers = self._get_raw_lines_and_line_numbers(ps_obj)
            entries: list[PrefixListEntry] = []
            seq = 10

            for child in ps_obj.all_children:
                # Each line may be: "  10.0.0.0/16 le 24," (comma = not last)
                text = child.text.strip().rstrip(",")
                if not text or text == "end-set":
                    continue

                # Extract prefix and optional ge/le
                prefix_match = re.match(r"(\d+\.\d+\.\d+\.\d+/\d+)(.*)", text)
                if not prefix_match:
                    continue

                prefix_str = prefix_match.group(1)
                options = prefix_match.group(2).strip()

                ge = None
                le = None
                ge_m = re.search(r"\bge\s+(\d+)", options)
                if ge_m:
                    ge = int(ge_m.group(1))
                le_m = re.search(r"\ble\s+(\d+)", options)
                if le_m:
                    le = int(le_m.group(1))

                try:
                    prefix = IPv4Network(prefix_str, strict=False)
                except ValueError:
                    continue

                entries.append(
                    PrefixListEntry(
                        sequence=seq,
                        action="permit",
                        prefix=prefix,
                        ge=ge,
                        le=le,
                    )
                )
                seq += 10

            prefix_lists.append(
                PrefixListConfig(
                    object_id=f"prefix_list_{ps_name}",
                    raw_lines=raw_lines,
                    source_os=self.os_type,
                    line_numbers=line_numbers,
                    name=ps_name,
                    afi="ipv4",
                    sequences=entries,
                )
            )

        return prefix_lists

    # -----------------------------------------------------------------------
    # AS-path lists — "as-path-set NAME" ... "end-set"
    # -----------------------------------------------------------------------

    def parse_as_path_lists(self) -> list[ASPathListConfig]:
        """Parse IOS-XR as-path-set blocks and map to ASPathListConfig."""
        as_path_lists: list[ASPathListConfig] = []
        parse = self._get_parse_obj()

        aps_objs = parse.find_objects(r"^as-path-set\s+(\S+)")
        for aps_obj in aps_objs:
            aps_name = self._extract_match(aps_obj.text, r"^as-path-set\s+(\S+)")
            if not aps_name:
                continue

            raw_lines, line_numbers = self._get_raw_lines_and_line_numbers(aps_obj)
            entries: list[ASPathListEntry] = []

            for child in aps_obj.all_children:
                text = child.text.strip().rstrip(",")
                if not text or text in ("end-set",):
                    continue
                entries.append(ASPathListEntry(action="permit", regex=text))

            as_path_lists.append(
                ASPathListConfig(
                    object_id=f"as_path_list_{aps_name}",
                    raw_lines=raw_lines,
                    source_os=self.os_type,
                    line_numbers=line_numbers,
                    name=aps_name,
                    entries=entries,
                )
            )

        return as_path_lists

    # -----------------------------------------------------------------------
    # Community-lists — "community-set NAME" ... "end-set"
    # -----------------------------------------------------------------------

    def parse_community_lists(self) -> list[CommunityListConfig]:
        """Parse IOS-XR community-set blocks and map to CommunityListConfig."""
        community_lists: list[CommunityListConfig] = []
        parse = self._get_parse_obj()

        cs_objs = parse.find_objects(r"^community-set\s+(\S+)")
        for cs_obj in cs_objs:
            cs_name = self._extract_match(cs_obj.text, r"^community-set\s+(\S+)")
            if not cs_name:
                continue

            raw_lines, line_numbers = self._get_raw_lines_and_line_numbers(cs_obj)
            entries: list[CommunityListEntry] = []

            all_communities: list[str] = []
            for child in cs_obj.all_children:
                text = child.text.strip().rstrip(",")
                if not text or text in ("end-set",):
                    continue
                # Each line may be a community value like "65000:100"
                all_communities.append(text)

            if all_communities:
                entries.append(CommunityListEntry(action="permit", communities=all_communities))

            community_lists.append(
                CommunityListConfig(
                    object_id=f"community_list_{cs_name}",
                    raw_lines=raw_lines,
                    source_os=self.os_type,
                    line_numbers=line_numbers,
                    name=cs_name,
                    list_type="standard",
                    entries=entries,
                )
            )

        # Also parse extcommunity-set blocks (RT/SoO sets)
        ecs_objs = parse.find_objects(r"^extcommunity-set\s+\S+\s+(\S+)")
        for ecs_obj in ecs_objs:
            m = re.match(r"^extcommunity-set\s+\S+\s+(\S+)", ecs_obj.text)
            if not m:
                continue
            ecs_name = m.group(1)
            raw_lines, line_numbers = self._get_raw_lines_and_line_numbers(ecs_obj)
            all_communities = []
            for child in ecs_obj.all_children:
                text = child.text.strip().rstrip(",")
                if not text or text in ("end-set",):
                    continue
                all_communities.append(text)
            entries = []
            if all_communities:
                entries.append(CommunityListEntry(action="permit", communities=all_communities))
            community_lists.append(
                CommunityListConfig(
                    object_id=f"community_list_{ecs_name}",
                    raw_lines=raw_lines,
                    source_os=self.os_type,
                    line_numbers=line_numbers,
                    name=ecs_name,
                    list_type="extended",
                    entries=entries,
                )
            )

        return community_lists

    # -----------------------------------------------------------------------
    # ACLs — "ipv4 access-list NAME" / "ipv6 access-list NAME"
    # -----------------------------------------------------------------------

    def parse_acls(self) -> list[ACLConfig]:
        """Parse IOS-XR ACL configurations.

        IOS-XR uses ``ipv4 access-list NAME`` and ``ipv6 access-list NAME``
        instead of IOS ``ip access-list standard|extended NAME``.
        """
        acls = []
        parse = self._get_parse_obj()

        for keyword in ("ipv4", "ipv6"):
            acl_objs = parse.find_objects(rf"^{keyword}\s+access-list\s+(\S+)")
            for acl_obj in acl_objs:
                acl_name = self._extract_match(acl_obj.text, rf"^{keyword}\s+access-list\s+(\S+)")
                if not acl_name:
                    continue

                raw_lines, line_numbers = self._get_raw_lines_and_line_numbers(acl_obj)
                entries = []

                for entry_child in acl_obj.children:
                    entry_text = entry_child.text.strip()
                    parts = entry_text.split()
                    if not parts:
                        continue

                    sequence = None
                    if parts[0].isdigit():
                        sequence = int(parts[0])
                        parts = parts[1:]

                    if not parts:
                        continue
                    action = parts[0].lower()
                    if action not in ("permit", "deny", "remark"):
                        continue

                    if action == "remark":
                        entries.append(ACLEntry(
                            action="remark",
                            sequence=sequence,
                            remark=" ".join(parts[1:]),
                        ))
                    else:
                        entries.append(ACLEntry(
                            action=action,
                            sequence=sequence,
                            protocol=parts[1] if len(parts) > 1 else None,
                        ))

                acls.append(ACLConfig(
                    object_id=f"acl_{acl_name}",
                    raw_lines=raw_lines,
                    source_os=self.os_type,
                    line_numbers=line_numbers,
                    name=acl_name,
                    acl_type="extended",
                    entries=entries,
                ))

        return acls

    # -----------------------------------------------------------------------
    # Static routes — "router static" block
    # -----------------------------------------------------------------------

    def parse_static_routes(self) -> list[StaticRoute]:
        """Parse IOS-XR static routes from ``router static`` block.

        IOS-XR format::

            router static
             address-family ipv4 unicast
              0.0.0.0/0 192.168.1.1
              10.0.0.0/8 Null0 200
             !
             vrf MGMT
              address-family ipv4 unicast
               0.0.0.0/0 10.100.100.1
        """
        static_routes = []
        parse = self._get_parse_obj()

        static_objs = parse.find_objects(r"^router\s+static")
        for static_obj in static_objs:
            raw_lines, line_numbers = self._get_raw_lines_and_line_numbers(static_obj)

            def _extract_routes(af_obj, vrf: str | None) -> None:
                for route_child in af_obj.all_children:
                    text = route_child.text.strip()
                    m = re.match(r"^(\d+\.\d+\.\d+\.\d+/\d+)\s+(\S+)(.*)", text)
                    if not m:
                        continue
                    prefix_str, next_hop_str = m.group(1), m.group(2)
                    remaining = m.group(3).strip()
                    try:
                        destination = IPv4Network(prefix_str, strict=False)
                    except ValueError:
                        continue
                    next_hop = None
                    next_hop_interface = None
                    try:
                        next_hop = IPv4Address(next_hop_str)
                    except ValueError:
                        next_hop_interface = next_hop_str
                    distance = 1
                    parts = remaining.split()
                    if parts and parts[0].isdigit():
                        distance = int(parts[0])
                    static_routes.append(StaticRoute(
                        object_id=f"static_route_{destination}_{next_hop_str}",
                        raw_lines=raw_lines,
                        source_os=self.os_type,
                        line_numbers=line_numbers,
                        destination=destination,
                        next_hop=next_hop,
                        next_hop_interface=next_hop_interface,
                        distance=distance,
                        vrf=vrf,
                    ))

            # Global routes
            for af_child in static_obj.re_search_children(r"^\s+address-family\s+ipv4\s+unicast"):
                _extract_routes(af_child, vrf=None)

            # VRF routes
            for vrf_child in static_obj.re_search_children(r"^\s+vrf\s+(\S+)"):
                vrf_name = self._extract_match(vrf_child.text, r"^\s+vrf\s+(\S+)")
                if not vrf_name:
                    continue
                for af_child in vrf_child.re_search_children(r"^\s+address-family\s+ipv4\s+unicast"):
                    _extract_routes(af_child, vrf=vrf_name)

        return static_routes

    # -----------------------------------------------------------------------
    # BGP neighbors — block syntax "neighbor X\n  remote-as Y"
    # -----------------------------------------------------------------------

    def _parse_bgp_neighbors(self, bgp_obj) -> list[BGPNeighbor]:
        """Parse BGP neighbors from IOS-XR block-style syntax.

        IOS-XR uses a block per neighbor instead of flat ``neighbor X cmd`` lines::

            neighbor 203.0.113.1
             remote-as 65001
             description ISP1-PEER
             address-family ipv4 unicast
              route-policy ISP1-IN in
        """
        neighbors = []
        neighbor_blocks = bgp_obj.re_search_children(r"^\s+neighbor\s+(\S+)\s*$")

        for nb_child in neighbor_blocks:
            peer_str = self._extract_match(nb_child.text, r"^\s+neighbor\s+(\S+)\s*$")
            if not peer_str:
                continue

            try:
                peer_ip = IPv4Address(peer_str)
            except ValueError:
                try:
                    peer_ip = IPv6Address(peer_str)
                except ValueError:
                    continue

            nd: dict = {
                "remote_as": None,
                "peer_group": None,
                "description": None,
                "update_source": None,
                "ebgp_multihop": None,
                "password": None,
                "route_map_in": None,
                "route_map_out": None,
            }

            for child in nb_child.all_children:
                text = child.text.strip()
                if text.startswith("remote-as "):
                    val = text.split(None, 1)[1].strip()
                    try:
                        nd["remote_as"] = int(val)
                    except ValueError:
                        nd["remote_as"] = val
                elif text.startswith("description "):
                    nd["description"] = text.split(None, 1)[1].strip()
                elif text.startswith("update-source "):
                    nd["update_source"] = text.split(None, 1)[1].strip()
                elif text.startswith("ebgp-multihop "):
                    parts = text.split()
                    if len(parts) > 1 and parts[1].isdigit():
                        nd["ebgp_multihop"] = int(parts[1])
                elif text.startswith("use neighbor-group "):
                    nd["peer_group"] = text.split(None, 2)[2].strip()

            if nd["remote_as"] is None and nd["peer_group"] is None:
                continue

            remote_as = nd["remote_as"] if nd["remote_as"] is not None else "inherited"
            neighbors.append(BGPNeighbor(
                peer_ip=peer_ip,
                remote_as=remote_as,
                peer_group=nd["peer_group"],
                description=nd["description"],
                update_source=nd["update_source"],
                ebgp_multihop=nd["ebgp_multihop"],
                password=nd["password"],
                route_map_in=nd["route_map_in"],
                route_map_out=nd["route_map_out"],
            ))

        return neighbors

    # -----------------------------------------------------------------------
    # BGP AF neighbor policies — "route-policy NAME in|out"
    # -----------------------------------------------------------------------

    def _apply_bgp_af_neighbor_policies(self, bgp_obj, neighbors: list) -> None:
        """Populate neighbor AF policies from IOS-XR nested neighbor blocks.

        IOS-XR nests AF policy under each neighbor block::

            neighbor 192.0.2.1
             address-family ipv4 unicast
              route-policy ISP-IN in
              route-policy ISP-OUT out
        """
        nb_index = {str(nb.peer_ip): nb for nb in neighbors}

        neighbor_blocks = bgp_obj.re_search_children(r"^\s+neighbor\s+(\S+)\s*$")
        for nb_child in neighbor_blocks:
            peer_str = self._extract_match(nb_child.text, r"^\s+neighbor\s+(\S+)\s*$")
            if not peer_str or peer_str not in nb_index:
                continue

            nb = nb_index[peer_str]
            af_children = nb_child.re_search_children(
                r"^\s+address-family\s+(ipv4|ipv6)\s+unicast"
            )
            for af_child in af_children:
                m = re.search(r"^\s+address-family\s+(ipv4|ipv6)\s+unicast", af_child.text)
                if not m:
                    continue
                afi, safi = m.group(1), "unicast"
                af_data: dict = {
                    "activate": True,
                    "route_map_in": None,
                    "route_map_out": None,
                    "prefix_list_in": None,
                    "prefix_list_out": None,
                    "filter_list_in": None,
                    "filter_list_out": None,
                    "default_originate_route_map": None,
                }
                for policy_child in af_child.all_children:
                    cmd = policy_child.text.strip()
                    if cmd.startswith("route-policy ") and cmd.endswith(" in"):
                        af_data["route_map_in"] = cmd[len("route-policy "):-3].strip()
                    elif cmd.startswith("route-policy ") and cmd.endswith(" out"):
                        af_data["route_map_out"] = cmd[len("route-policy "):-4].strip()
                    elif cmd.startswith("prefix-set ") and cmd.endswith(" in"):
                        af_data["prefix_list_in"] = cmd[len("prefix-set "):-3].strip()
                    elif cmd.startswith("prefix-set ") and cmd.endswith(" out"):
                        af_data["prefix_list_out"] = cmd[len("prefix-set "):-4].strip()

                if any(v for v in af_data.values() if v and v is not True):
                    nb.address_families.append(BGPNeighborAF(afi=afi, safi=safi, **af_data))

    # -----------------------------------------------------------------------
    # Multicast — "router pim" block
    # -----------------------------------------------------------------------

    def parse_multicast(self) -> MulticastConfig | None:
        """Parse IOS-XR multicast configuration from ``router pim`` block.

        IOS-XR format::

            router pim
             address-family ipv4
              rp-address 10.0.0.1
              ssm range RFC1918
        """
        parse = self._get_parse_obj()
        pim_objs = parse.find_objects(r"^router\s+pim")
        multicast_routing_objs = parse.find_objects(r"^multicast-routing")

        if not pim_objs and not multicast_routing_objs:
            return None

        raw_lines: list[str] = []
        line_numbers: list[int] = []
        for obj in pim_objs + multicast_routing_objs:
            rl, ln = self._get_raw_lines_and_line_numbers(obj)
            raw_lines.extend(rl)
            line_numbers.extend(ln)

        multicast_routing_enabled = bool(multicast_routing_objs)
        pim_rp_addresses: list[PIMRPAddress] = []
        pim_ssm_range: str | None = None
        pim_autorp = False

        for pim_obj in pim_objs:
            for af_child in pim_obj.re_search_children(r"^\s+address-family\s+ipv4"):
                for child in af_child.all_children:
                    text = child.text.strip()
                    rp_m = re.match(r"^rp-address\s+(\S+)(.*)", text)
                    if rp_m:
                        try:
                            rp_addr = IPv4Address(rp_m.group(1))
                            rest = rp_m.group(2).strip()
                            acl = rest if rest and not rest.startswith("bidir") and not rest.startswith("override") else None
                            pim_rp_addresses.append(PIMRPAddress(
                                rp_address=rp_addr,
                                acl=acl,
                                override="override" in rest,
                                bidir="bidir" in rest,
                            ))
                        except ValueError:
                            pass
                    elif text.startswith("ssm range "):
                        pim_ssm_range = text.split(None, 2)[2] if len(text.split()) > 2 else None
                    elif "auto-rp" in text.lower():
                        pim_autorp = True

        return MulticastConfig(
            object_id="multicast",
            raw_lines=raw_lines,
            source_os=self.os_type,
            line_numbers=line_numbers,
            multicast_routing_enabled=multicast_routing_enabled,
            pim_rp_addresses=pim_rp_addresses,
            pim_ssm_range=pim_ssm_range,
            pim_autorp=pim_autorp,
        )
