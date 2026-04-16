"""Cisco NX-OS configuration parser."""

import re
from ipaddress import IPv4Address, IPv4Interface, IPv4Network, IPv6Interface

from confgraph.models.base import OSType
from confgraph.models.vrf import VRFConfig
from confgraph.models.bgp import (
    BGPConfig,
    BGPNeighbor,
    BGPPeerGroup,
    BGPRedistribute,
    BGPBestpathOptions,
)
from confgraph.models.ospf import OSPFConfig
from confgraph.models.static_route import StaticRoute
from confgraph.parsers.base import _BASE_KNOWN_PATTERNS
from confgraph.parsers.ios_parser import IOSParser


# NX-OS top-level patterns differ from IOS: "vrf context" instead of "vrf definition"
_NXOS_KNOWN_PATTERNS: list[str] = [
    p for p in _BASE_KNOWN_PATTERNS if p != r"^vrf definition"
] + [
    r"^vrf\s+context",
    r"^template\s+peer",
    r"^feature",
    r"^hardware",
    r"^vpc\s+domain",
    r"^fabric",
    r"^system",
    r"^boot",
    r"^spanning-tree",
    r"^port-profile",
]


class NXOSParser(IOSParser):
    """Parser for Cisco NX-OS configurations.

    Inherits from IOSParser and overrides methods where NX-OS syntax
    differs: VRF (vrf context), interface VRF (vrf member), CIDR
    addresses, BGP templates (template peer / inherit peer), and
    OSPF interface membership (ip router ospf PROC area AREA).
    """

    _KNOWN_TOP_LEVEL_PATTERNS: list[str] = _NXOS_KNOWN_PATTERNS

    def __init__(self, config_text: str):
        super().__init__(config_text, os_type=OSType.NXOS)
        # Re-initialize with nxos syntax for CiscoConfParse
        self.syntax = "nxos"
        self.parse_obj = None  # Force re-creation with new syntax

    # -----------------------------------------------------------------------
    # VRFs — "vrf context NAME"
    # -----------------------------------------------------------------------

    def parse_vrfs(self) -> list[VRFConfig]:
        """Parse VRF configurations from NX-OS config.

        NX-OS format: ``vrf context NAME``
        """
        vrfs = []
        parse = self._get_parse_obj()

        vrf_objs = parse.find_objects(r"^vrf\s+context\s+(\S+)")

        # Deduplicate: NX-OS may split the same VRF context into multiple blocks
        # (e.g., one with `rd` and one with `address-family`). Merge by name.
        vrf_map: dict[str, dict] = {}

        for vrf_obj in vrf_objs:
            vrf_name = self._extract_match(vrf_obj.text, r"^vrf\s+context\s+(\S+)")
            if not vrf_name:
                continue

            raw_lines, line_numbers = self._get_raw_lines_and_line_numbers(vrf_obj)

            if vrf_name not in vrf_map:
                vrf_map[vrf_name] = {
                    "raw_lines": raw_lines,
                    "line_numbers": line_numbers,
                    "rd": None,
                    "rt_import": [],
                    "rt_export": [],
                    "rt_both": [],
                    "route_map_import": None,
                    "route_map_export": None,
                }
            else:
                vrf_map[vrf_name]["raw_lines"].extend(raw_lines)
                vrf_map[vrf_name]["line_numbers"].extend(line_numbers)

            entry = vrf_map[vrf_name]

            # RD
            rd_ch = vrf_obj.re_search_children(r"^\s+rd\s+(\S+)")
            if rd_ch and entry["rd"] is None:
                entry["rd"] = self._extract_match(rd_ch[0].text, r"^\s+rd\s+(\S+)")

            for child in vrf_obj.all_children:
                text = child.text.strip()
                if text.startswith("route-target import "):
                    val = self._extract_match(text, r"route-target\s+import\s+(\S+)")
                    if val and val not in entry["rt_import"]:
                        entry["rt_import"].append(val)
                elif text.startswith("route-target export "):
                    val = self._extract_match(text, r"route-target\s+export\s+(\S+)")
                    if val and val not in entry["rt_export"]:
                        entry["rt_export"].append(val)
                elif text.startswith("route-target both "):
                    val = self._extract_match(text, r"route-target\s+both\s+(\S+)")
                    if val and val not in entry["rt_both"]:
                        entry["rt_both"].append(val)
                elif text.startswith("route-map") and "import" in text:
                    entry["route_map_import"] = self._extract_match(text, r"route-map\s+(\S+)\s+import")
                elif text.startswith("route-map") and "export" in text:
                    entry["route_map_export"] = self._extract_match(text, r"route-map\s+(\S+)\s+export")

        for vrf_name, entry in vrf_map.items():
            vrfs.append(
                VRFConfig(
                    object_id=f"vrf_{vrf_name}",
                    raw_lines=entry["raw_lines"],
                    source_os=self.os_type,
                    line_numbers=entry["line_numbers"],
                    name=vrf_name,
                    rd=entry["rd"],
                    route_target_import=entry["rt_import"],
                    route_target_export=entry["rt_export"],
                    route_target_both=entry["rt_both"],
                    route_map_import=entry["route_map_import"],
                    route_map_export=entry["route_map_export"],
                )
            )

        return vrfs

    # -----------------------------------------------------------------------
    # Interface VRF — "vrf member NAME"
    # -----------------------------------------------------------------------

    def _extract_interface_vrf(self, intf_obj) -> str | None:
        """Extract VRF from interface.

        NX-OS uses ``vrf member NAME`` (NX-OS native) or bare ``vrf NAME``
        (seen in some NX-OS configs and older-style templates).
        """
        vrf_ch = intf_obj.re_search_children(r"^\s+vrf\s+member\s+(\S+)")
        if vrf_ch:
            return self._extract_match(vrf_ch[0].text, r"^\s+vrf\s+member\s+(\S+)")
        # Fallback: bare "vrf NAME" (without member keyword)
        vrf_bare = intf_obj.re_search_children(r"^\s+vrf\s+(?!member\s)(\S+)")
        if vrf_bare:
            return self._extract_match(vrf_bare[0].text, r"^\s+vrf\s+(?!member\s)(\S+)")
        return None

    # -----------------------------------------------------------------------
    # Interfaces — CIDR notation (ip address X.X.X.X/24)
    # -----------------------------------------------------------------------

    def parse_interfaces(self) -> list:
        """Parse interfaces. Overrides IP address extraction for CIDR notation."""
        # Let IOSParser do the heavy lifting, then patch up addresses
        interfaces = super().parse_interfaces()

        parse = self._get_parse_obj()
        intf_objs = parse.find_objects(r"^interface\s+")

        for intf_obj in intf_objs:
            intf_name = self._extract_match(intf_obj.text, r"^interface\s+(\S+)")
            if not intf_name:
                continue

            # Find the matching InterfaceConfig already built
            intf_cfg = next((i for i in interfaces if i.name == intf_name), None)
            if intf_cfg is None:
                continue

            # NX-OS: ip address X.X.X.X/24
            cidr_children = intf_obj.re_search_children(
                r"^\s+ip\s+address\s+(\d+\.\d+\.\d+\.\d+/\d+)"
            )
            if cidr_children:
                match = re.search(
                    r"^\s+ip\s+address\s+(\d+\.\d+\.\d+\.\d+/\d+)",
                    cidr_children[0].text,
                )
                if match:
                    try:
                        intf_cfg.ip_address = IPv4Interface(match.group(1))
                    except ValueError:
                        pass

            # NX-OS OSPF: "ip router ospf PROC area AREA" (slightly different
            # from IOS "ip ospf PROC area AREA")
            ospf_router_children = intf_obj.re_search_children(
                r"^\s+ip\s+router\s+ospf\s+(\d+)\s+area\s+(\S+)"
            )
            if ospf_router_children:
                m = re.search(
                    r"^\s+ip\s+router\s+ospf\s+(\d+)\s+area\s+(\S+)",
                    ospf_router_children[0].text,
                )
                if m:
                    intf_cfg.ospf_process_id = int(m.group(1))
                    intf_cfg.ospf_area = m.group(2)

        return interfaces

    # -----------------------------------------------------------------------
    # BGP — "template peer NAME" / "inherit peer NAME"
    # -----------------------------------------------------------------------

    def _parse_bgp_peer_groups(self, bgp_obj) -> list[BGPPeerGroup]:
        """Parse BGP peer-groups.

        Handles both NX-OS native ``template peer NAME`` blocks and
        IOS-style ``neighbor NAME peer-group`` declarations that some
        NX-OS configs also use.
        """
        peer_groups = []
        seen: set[str] = set()

        def _build_pg(pg_name: str, children_iter) -> BGPPeerGroup:
            pg_data: dict = {
                "name": pg_name,
                "remote_as": None,
                "description": None,
                "update_source": None,
                "route_reflector_client": False,
                "send_community": False,
                "route_map_in": None,
                "route_map_out": None,
                "prefix_list_in": None,
                "prefix_list_out": None,
            }
            for child in children_iter:
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
                elif text.startswith("route-map ") and " in" in text:
                    m = re.search(r"route-map\s+(\S+)\s+in", text)
                    if m:
                        pg_data["route_map_in"] = m.group(1)
                elif text.startswith("route-map ") and " out" in text:
                    m = re.search(r"route-map\s+(\S+)\s+out", text)
                    if m:
                        pg_data["route_map_out"] = m.group(1)
                elif text.startswith("prefix-list ") and " in" in text:
                    m = re.search(r"prefix-list\s+(\S+)\s+in", text)
                    if m:
                        pg_data["prefix_list_in"] = m.group(1)
                elif text.startswith("prefix-list ") and " out" in text:
                    m = re.search(r"prefix-list\s+(\S+)\s+out", text)
                    if m:
                        pg_data["prefix_list_out"] = m.group(1)
            return BGPPeerGroup(**pg_data)

        # NX-OS native: template peer NAME blocks
        for tmpl_child in bgp_obj.re_search_children(r"^\s+template\s+peer\s+(\S+)"):
            pg_name = self._extract_match(tmpl_child.text, r"^\s+template\s+peer\s+(\S+)")
            if not pg_name or pg_name in seen:
                continue
            seen.add(pg_name)
            peer_groups.append(_build_pg(pg_name, tmpl_child.all_children))

        # IOS-style: neighbor NAME peer-group (declaration line)
        for pg_decl in bgp_obj.re_search_children(r"^\s+neighbor\s+(\S+)\s+peer-group\s*$"):
            pg_name = self._extract_match(pg_decl.text, r"^\s+neighbor\s+(\S+)\s+peer-group\s*$")
            if not pg_name or pg_name in seen:
                continue
            seen.add(pg_name)
            # Gather all config lines for this peer-group name
            pg_config = bgp_obj.re_search_children(
                rf"^\s+neighbor\s+{re.escape(pg_name)}\s+(.+)"
            )

            class _FakeChild:
                def __init__(self, t):
                    self.text = t

            fake_children = []
            for cfg_child in pg_config:
                m = re.search(rf"^\s+neighbor\s+{re.escape(pg_name)}\s+(.+)", cfg_child.text)
                if m:
                    fake_children.append(_FakeChild("  " + m.group(1)))

            peer_groups.append(_build_pg(pg_name, fake_children))

        return peer_groups

    def _parse_bgp_vrf_instances(self, bgp_obj, asn: int) -> list[BGPConfig]:
        """Parse VRF-specific BGP instances.

        NX-OS uses ``vrf VRFNAME`` blocks directly under ``router bgp``.
        """
        from ipaddress import IPv4Address, IPv6Address

        vrf_instances = []
        vrf_children = bgp_obj.re_search_children(r"^\s+vrf\s+(\S+)")

        for vrf_child in vrf_children:
            vrf_name = self._extract_match(vrf_child.text, r"^\s+vrf\s+(\S+)")
            if not vrf_name:
                continue

            raw_lines, line_numbers = self._get_raw_lines_and_line_numbers(vrf_child)

            # VRF neighbors
            vrf_neighbors = []
            neighbor_dict: dict[str, dict] = {}

            for child in vrf_child.all_children:
                text = child.text.strip()
                n_match = re.match(r"neighbor\s+(\S+)\s+(.+)", text)
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
                    val = command.replace("remote-as ", "").strip()
                    try:
                        neighbor_dict[peer_ip_str]["remote_as"] = int(val)
                    except ValueError:
                        neighbor_dict[peer_ip_str]["remote_as"] = val
                elif command.startswith("description "):
                    neighbor_dict[peer_ip_str]["description"] = command.replace("description ", "").strip()
                elif command.startswith("route-map ") and " in" in command:
                    neighbor_dict[peer_ip_str]["route_map_in"] = (
                        command.replace("route-map ", "").replace(" in", "").strip()
                    )
                elif command.startswith("route-map ") and " out" in command:
                    neighbor_dict[peer_ip_str]["route_map_out"] = (
                        command.replace("route-map ", "").replace(" out", "").strip()
                    )

            for peer_ip_str, nd in neighbor_dict.items():
                try:
                    peer_ip = IPv4Address(peer_ip_str)
                except ValueError:
                    try:
                        peer_ip = IPv6Address(peer_ip_str)
                    except ValueError:
                        continue

                if nd["remote_as"] is None:
                    continue

                vrf_neighbors.append(
                    BGPNeighbor(
                        peer_ip=peer_ip,
                        remote_as=nd["remote_as"],
                        description=nd["description"],
                        route_map_in=nd["route_map_in"],
                        route_map_out=nd["route_map_out"],
                    )
                )

            # Redistribution inside vrf block
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
                rm_m = re.search(r"route-map\s+(\S+)", remaining)
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
    # BGP — peer-group attribute inheritance
    # -----------------------------------------------------------------------

    def parse_bgp(self) -> list[BGPConfig]:
        """Parse BGP, then inherit route-maps/prefix-lists from peer-groups to neighbors."""
        instances = super().parse_bgp()
        for inst in instances:
            pg_map = {pg.name: pg for pg in inst.peer_groups}
            for neighbor in inst.neighbors:
                if not neighbor.peer_group or neighbor.peer_group not in pg_map:
                    continue
                pg = pg_map[neighbor.peer_group]
                if neighbor.route_map_in is None and pg.route_map_in:
                    neighbor.route_map_in = pg.route_map_in
                if neighbor.route_map_out is None and pg.route_map_out:
                    neighbor.route_map_out = pg.route_map_out
                if neighbor.prefix_list_in is None and pg.prefix_list_in:
                    neighbor.prefix_list_in = pg.prefix_list_in
                if neighbor.prefix_list_out is None and pg.prefix_list_out:
                    neighbor.prefix_list_out = pg.prefix_list_out
                if neighbor.remote_as in (None, "inherited") and pg.remote_as is not None:
                    neighbor.remote_as = pg.remote_as
                if neighbor.update_source is None and pg.update_source:
                    neighbor.update_source = pg.update_source
        return instances

    # -----------------------------------------------------------------------
    # OSPF — "router ospf N vrf NAME"
    # -----------------------------------------------------------------------

    def parse_ospf(self) -> list[OSPFConfig]:
        """Parse OSPF. Inherits IOS logic but extracts VRF from ``router ospf N vrf NAME``."""
        instances = super().parse_ospf()
        parse = self._get_parse_obj()

        # Re-scan to pick up VRF from the process header line
        ospf_objs = parse.find_objects(r"^router\s+ospf\s+(\d+)")
        for ospf_obj in ospf_objs:
            m = re.search(r"^router\s+ospf\s+(\d+)\s+vrf\s+(\S+)", ospf_obj.text)
            if not m:
                continue
            process_id = int(m.group(1))
            vrf_name = m.group(2)
            for inst in instances:
                if inst.process_id == process_id and inst.vrf is None:
                    inst.vrf = vrf_name
                    break

        return instances

    # -----------------------------------------------------------------------
    # Static routes — inside "vrf context NAME" blocks
    # -----------------------------------------------------------------------

    def parse_static_routes(self) -> list[StaticRoute]:
        """Parse static routes from both global scope and ``vrf context NAME`` blocks."""
        # Global ip route statements (handled by IOS parser)
        routes = super().parse_static_routes()

        parse = self._get_parse_obj()
        vrf_objs = parse.find_objects(r"^vrf\s+context\s+(\S+)")

        for vrf_obj in vrf_objs:
            vrf_name = self._extract_match(vrf_obj.text, r"^vrf\s+context\s+(\S+)")
            if not vrf_name:
                continue

            for child in vrf_obj.all_children:
                text = child.text.strip()
                # NX-OS: ip route DEST/PREFIX NEXTHOP  (CIDR)
                #        ip route DEST MASK NEXTHOP     (traditional)
                m_cidr = re.match(
                    r"ip\s+route\s+(\d+\.\d+\.\d+\.\d+/\d+)\s+(\S+)(.*)", text
                )
                m_trad = re.match(
                    r"ip\s+route\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)(.*)",
                    text,
                )

                destination = None
                next_hop = None
                next_hop_interface = None
                remaining = ""

                if m_cidr:
                    try:
                        destination = IPv4Network(m_cidr.group(1), strict=False)
                    except ValueError:
                        continue
                    next_hop_str = m_cidr.group(2)
                    remaining = m_cidr.group(3).strip()
                    try:
                        next_hop = IPv4Address(next_hop_str)
                    except ValueError:
                        next_hop_interface = next_hop_str
                elif m_trad:
                    try:
                        destination = IPv4Network(
                            f"{m_trad.group(1)}/{m_trad.group(2)}", strict=False
                        )
                    except ValueError:
                        continue
                    next_hop_str = m_trad.group(3)
                    remaining = m_trad.group(4).strip()
                    try:
                        next_hop = IPv4Address(next_hop_str)
                    except ValueError:
                        next_hop_interface = next_hop_str
                else:
                    continue

                raw_lines, line_numbers = self._get_raw_lines_and_line_numbers(child)
                obj_id = f"static_route_{destination}_{next_hop or next_hop_interface}_vrf_{vrf_name}"

                distance = 1
                parts = remaining.split()
                if parts and parts[0].isdigit():
                    distance = int(parts[0])

                routes.append(
                    StaticRoute(
                        object_id=obj_id,
                        raw_lines=raw_lines,
                        source_os=self.os_type,
                        line_numbers=line_numbers,
                        destination=destination,
                        next_hop=next_hop,
                        next_hop_interface=next_hop_interface,
                        distance=distance,
                        vrf=vrf_name,
                    )
                )

        return routes
