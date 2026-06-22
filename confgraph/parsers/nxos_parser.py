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
from confgraph.parsers.base import _BASE_KNOWN_PATTERNS, apply_peer_group_command, _default_pg_data
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
    r"^mpls",
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
            rd_ch = vrf_obj.find_child_objects(r"^\s+rd\s+(\S+)")
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
        vrf_ch = intf_obj.find_child_objects(r"^\s+vrf\s+member\s+(\S+)")
        if vrf_ch:
            return self._extract_match(vrf_ch[0].text, r"^\s+vrf\s+member\s+(\S+)")
        # Fallback: bare "vrf NAME" (without member keyword)
        vrf_bare = intf_obj.find_child_objects(r"^\s+vrf\s+(?!member\s)(\S+)")
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
            cidr_children = intf_obj.find_child_objects(
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

            # VPC per-interface: "vpc <id>" or "vpc peer-link"
            vpc_ch = intf_obj.find_child_objects(r"^\s+vpc\s+(\d+)\s*$")
            if vpc_ch:
                vpc_m = re.match(r"^\s+vpc\s+(\d+)", vpc_ch[0].text)
                if vpc_m:
                    intf_cfg.vpc_id = int(vpc_m.group(1))

            # NX-OS OSPF: "ip router ospf PROC area AREA" (slightly different
            # from IOS "ip ospf PROC area AREA")
            ospf_router_children = intf_obj.find_child_objects(
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
            pg_data = _default_pg_data(pg_name)
            for child in children_iter:
                apply_peer_group_command(pg_data, child.text.strip())
            return BGPPeerGroup(**pg_data)

        # NX-OS native: template peer NAME blocks
        for tmpl_child in bgp_obj.find_child_objects(r"^\s+template\s+peer\s+(\S+)"):
            pg_name = self._extract_match(tmpl_child.text, r"^\s+template\s+peer\s+(\S+)")
            if not pg_name or pg_name in seen:
                continue
            seen.add(pg_name)
            peer_groups.append(_build_pg(pg_name, tmpl_child.all_children))

        # IOS-style: neighbor NAME peer-group (declaration line)
        for pg_decl in bgp_obj.find_child_objects(r"^\s+neighbor\s+(\S+)\s+peer-group\s*$"):
            pg_name = self._extract_match(pg_decl.text, r"^\s+neighbor\s+(\S+)\s+peer-group\s*$")
            if not pg_name or pg_name in seen:
                continue
            seen.add(pg_name)
            # Gather all config lines for this peer-group name
            pg_config = bgp_obj.find_child_objects(
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
        vrf_children = bgp_obj.find_child_objects(r"^\s+vrf\s+(\S+)")

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
    # BGP — NX-OS nested neighbor blocks + inherit peer
    # -----------------------------------------------------------------------

    def _parse_bgp_neighbors(self, bgp_obj) -> list["BGPNeighbor"]:
        """Parse BGP neighbors, adding NX-OS nested-block / ``inherit peer`` support.

        NX-OS uses two neighbor forms:

        1. **Inline** (IOS-compatible)::

               neighbor 10.0.0.2 remote-as 65001

        2. **Nested block** (NX-OS native)::

               neighbor 10.0.0.2
                 inherit peer LEAF
                 description spine-link

        ``super()`` handles form 1.  This override additionally scans for
        bare ``neighbor <ip>`` lines (no trailing command) and parses their
        child attributes, including ``inherit peer NAME`` → ``peer_group``.
        """
        from confgraph.models.bgp import BGPNeighbor, BGPTimers

        # --- Form 1: inline neighbors via IOS parser ---
        neighbors = super()._parse_bgp_neighbors(bgp_obj)
        seen_ips = {str(n.peer_ip) for n in neighbors}

        # --- Form 2: nested neighbor blocks ---
        # Match bare "neighbor <ip>" lines (no command after the IP).
        for nb_obj in bgp_obj.find_child_objects(r"^\s+neighbor\s+\S+\s*$"):
            m = re.match(r"^\s+neighbor\s+(\S+)\s*$", nb_obj.text)
            if not m:
                continue
            peer_ip_str = m.group(1)

            # Skip if already captured by the inline pass
            if peer_ip_str in seen_ips:
                continue

            # Validate as IP address
            try:
                peer_ip = IPv4Address(peer_ip_str)
            except ValueError:
                from ipaddress import IPv6Address
                try:
                    peer_ip = IPv6Address(peer_ip_str)
                except ValueError:
                    continue

            # Parse child attributes
            nd: dict = {
                "remote_as": None, "peer_group": None, "description": None,
                "update_source": None, "ebgp_multihop": None, "password": None,
                "route_map_in": None, "route_map_out": None,
                "prefix_list_in": None, "prefix_list_out": None,
                "filter_list_in": None, "filter_list_out": None,
                "maximum_prefix": None, "next_hop_self": False,
                "route_reflector_client": False, "send_community": None,
                "fall_over_bfd": False, "shutdown": False,
                "disable_connected_check": False, "timers": None,
                "local_as": None, "local_as_no_prepend": False,
                "local_as_replace_as": False,
            }

            for child in nb_obj.all_children:
                cmd = child.text.strip()

                # inherit peer NAME → peer_group
                im = re.match(r"inherit\s+peer\s+(\S+)", cmd)
                if im:
                    nd["peer_group"] = im.group(1)
                    continue
                if cmd.startswith("remote-as "):
                    val = cmd.replace("remote-as ", "").strip()
                    try:
                        nd["remote_as"] = int(val)
                    except ValueError:
                        nd["remote_as"] = val
                elif cmd.startswith("description "):
                    nd["description"] = cmd.replace("description ", "").strip()
                elif cmd.startswith("update-source "):
                    nd["update_source"] = cmd.replace("update-source ", "").strip()
                elif cmd.startswith("ebgp-multihop "):
                    nd["ebgp_multihop"] = int(cmd.replace("ebgp-multihop ", "").strip())
                elif cmd.startswith("password "):
                    nd["password"] = cmd.replace("password ", "").strip()
                elif cmd.startswith("route-map ") and " in" in cmd:
                    nd["route_map_in"] = cmd.replace("route-map ", "").replace(" in", "").strip()
                elif cmd.startswith("route-map ") and " out" in cmd:
                    nd["route_map_out"] = cmd.replace("route-map ", "").replace(" out", "").strip()
                elif cmd.startswith("prefix-list ") and " in" in cmd:
                    nd["prefix_list_in"] = cmd.replace("prefix-list ", "").replace(" in", "").strip()
                elif cmd.startswith("prefix-list ") and " out" in cmd:
                    nd["prefix_list_out"] = cmd.replace("prefix-list ", "").replace(" out", "").strip()
                elif cmd.startswith("maximum-prefix "):
                    parts = cmd.replace("maximum-prefix ", "").split()
                    if parts:
                        nd["maximum_prefix"] = int(parts[0])
                elif cmd == "next-hop-self":
                    nd["next_hop_self"] = True
                elif cmd == "route-reflector-client":
                    nd["route_reflector_client"] = True
                elif cmd == "fall-over bfd":
                    nd["fall_over_bfd"] = True
                elif cmd == "shutdown":
                    nd["shutdown"] = True
                elif cmd == "disable-connected-check":
                    nd["disable_connected_check"] = True
                elif cmd.startswith("timers "):
                    tm = re.match(r"timers\s+(\d+)\s+(\d+)", cmd)
                    if tm:
                        nd["timers"] = BGPTimers(keepalive=int(tm.group(1)), holdtime=int(tm.group(2)))
                elif cmd.startswith("local-as "):
                    la_parts = cmd.replace("local-as ", "").strip().split()
                    if la_parts:
                        try:
                            nd["local_as"] = int(la_parts[0])
                        except ValueError:
                            pass
                        nd["local_as_no_prepend"] = "no-prepend" in la_parts
                        nd["local_as_replace_as"] = "replace-as" in la_parts
                elif cmd.startswith("send-community"):
                    if "both" in cmd:
                        nd["send_community"] = "both"
                    elif "extended" in cmd:
                        nd["send_community"] = "extended"
                    else:
                        nd["send_community"] = True

            # Skip if no remote-as, no peer-group, and not a shutdown stub
            if nd["remote_as"] is None and nd["peer_group"] is None and not nd["shutdown"]:
                continue

            remote_as = nd["remote_as"] if nd["remote_as"] is not None else "inherited"

            seen_ips.add(peer_ip_str)
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
                prefix_list_in=nd["prefix_list_in"],
                prefix_list_out=nd["prefix_list_out"],
                filter_list_in=nd["filter_list_in"],
                filter_list_out=nd["filter_list_out"],
                maximum_prefix=nd["maximum_prefix"],
                next_hop_self=nd["next_hop_self"],
                route_reflector_client=nd["route_reflector_client"],
                send_community=nd["send_community"],
                fall_over_bfd=nd["fall_over_bfd"],
                disable_connected_check=nd["disable_connected_check"],
                shutdown=nd["shutdown"],
                timers=nd["timers"],
                local_as=nd["local_as"],
                local_as_no_prepend=nd["local_as_no_prepend"],
                local_as_replace_as=nd["local_as_replace_as"],
            ))

        return neighbors

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

    # -----------------------------------------------------------------------
    # NTP — NX-OS uses "use-vrf VRF" after the IP and "source-interface"
    # -----------------------------------------------------------------------

    def parse_ntp(self):
        """Parse NTP from NX-OS config.

        NX-OS differs from IOS in two ways:

        - VRF is ``use-vrf VRF`` *after* the server IP, not ``vrf VRF`` before it.
        - Source interface is ``ntp source-interface INTF`` (hyphenated).

        Example::

            ntp server 10.0.0.1 prefer use-vrf management
            ntp server 10.0.0.2 use-vrf default
            ntp source-interface mgmt0
            ntp authenticate
            ntp authentication-key 1 md5 password 3 <hash>
            ntp trusted-key 1
        """
        from ipaddress import IPv4Address, IPv6Address
        from confgraph.models.ntp import NTPConfig, NTPServer, NTPAuthKey

        parse = self._get_parse_obj()
        ntp_objs = parse.find_objects(r"^ntp\s+")
        if not ntp_objs:
            return None

        servers = []
        peers = []
        auth_keys = []
        trusted_keys = []
        source_interface = None
        authenticate = False
        master = False
        master_stratum = None
        raw_lines = []
        line_numbers = []

        for obj in ntp_objs:
            raw_lines.append(obj.text)
            line_numbers.append(obj.linenum)
            t = obj.text.strip()

            if re.match(r"^ntp\s+server\s+", t):
                m = re.match(r"^ntp\s+server\s+(\S+)(.*)", t)
                if m:
                    addr_str, rest = m.group(1), m.group(2)
                    prefer = "prefer" in rest
                    vrf_m = re.search(r"\buse-vrf\s+(\S+)", rest)
                    vrf = vrf_m.group(1) if vrf_m else None
                    key_m = re.search(r"\bkey\s+(\d+)", rest)
                    ver_m = re.search(r"\bversion\s+(\d+)", rest)
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
                        vrf=vrf,
                    ))
            elif re.match(r"^ntp\s+peer\s+", t):
                m = re.match(r"^ntp\s+peer\s+(\S+)(.*)", t)
                if m:
                    addr_str, rest = m.group(1), m.group(2)
                    prefer = "prefer" in rest
                    vrf_m = re.search(r"\buse-vrf\s+(\S+)", rest)
                    vrf = vrf_m.group(1) if vrf_m else None
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
                        key_id=int(key_m.group(1)) if key_m else None,
                        vrf=vrf,
                    ))
            elif re.match(r"^ntp\s+authentication-key\s+", t):
                # NX-OS: "ntp authentication-key 1 md5 password 3 <hash>"
                #     or "ntp authentication-key 1 md5 <plaintext>"
                m = re.match(
                    r"^ntp\s+authentication-key\s+(\d+)\s+(\S+)\s+(?:password\s+\S+\s+)?(\S+)", t
                )
                if m:
                    auth_keys.append(NTPAuthKey(
                        key_id=int(m.group(1)),
                        algorithm=m.group(2),
                        key_string=m.group(3),
                    ))
            elif re.match(r"^ntp\s+trusted-key\s+", t):
                m = re.match(r"^ntp\s+trusted-key\s+(\d+)", t)
                if m:
                    trusted_keys.append(int(m.group(1)))
            elif re.match(r"^ntp\s+source-interface\s+", t):
                source_interface = self._extract_match(t, r"^ntp\s+source-interface\s+(\S+)")
            elif re.match(r"^ntp\s+source\s+", t):
                source_interface = self._extract_match(t, r"^ntp\s+source\s+(\S+)")
            elif re.match(r"^ntp\s+authenticate\b", t):
                authenticate = True
            elif re.match(r"^ntp\s+master", t):
                master = True
                sm = re.match(r"^ntp\s+master\s+(\d+)", t)
                if sm:
                    master_stratum = int(sm.group(1))

        return NTPConfig(
            object_id="ntp",
            raw_lines=raw_lines,
            source_os=self.os_type,
            line_numbers=line_numbers,
            master=master,
            master_stratum=master_stratum,
            servers=servers,
            peers=peers,
            source_interface=source_interface,
            authenticate=authenticate,
            authentication_keys=auth_keys,
            trusted_keys=trusted_keys,
            update_calendar=False,
            logging=False,
        )

    # -----------------------------------------------------------------------
    # Syslog — NX-OS uses "logging server" (not "logging host")
    # -----------------------------------------------------------------------

    def parse_syslog(self):
        """Parse syslog from NX-OS config.

        NX-OS uses ``logging server`` (not ``logging host`` or bare IP)::

            logging server 10.0.0.1 5 use-vrf management
            logging server 10.0.0.2 use-vrf default port 1514
            logging source-interface mgmt0
            logging console 6
            logging level bgp 5
        """
        from ipaddress import IPv4Address, IPv6Address
        from confgraph.models.logging_config import SyslogConfig, LoggingHost

        parse = self._get_parse_obj()
        log_objs = parse.find_objects(r"^logging\s+")

        # Check for "no logging on" separately (regex above won't match it)
        no_log_objs = parse.find_objects(r"^no\s+logging\s+on\s*$")

        if not log_objs and not no_log_objs:
            return None

        hosts = []
        buffered_size = buffered_level = None
        console_level = monitor_level = None
        source_interface = None
        enabled = not bool(no_log_objs)
        raw_lines = []
        line_numbers = []

        for obj in no_log_objs:
            raw_lines.append(obj.text)
            line_numbers.append(obj.linenum)

        for obj in log_objs:
            raw_lines.append(obj.text)
            line_numbers.append(obj.linenum)
            t = obj.text.strip()

            if re.match(r"^logging\s+server\s+", t):
                # NX-OS: logging server ADDR [SEVERITY] [use-vrf VRF] [port PORT]
                m = re.match(r"^logging\s+server\s+(\S+)(.*)", t)
                if m:
                    addr_str, rest = m.group(1), m.group(2)
                    vrf_m = re.search(r"\buse-vrf\s+(\S+)", rest)
                    vrf = vrf_m.group(1) if vrf_m else None
                    port_m = re.search(r"\bport\s+(\d+)", rest)
                    port = int(port_m.group(1)) if port_m else None
                    # Optional severity integer immediately after the address
                    level_m = re.match(r"^\s+(\d+)\b", rest)
                    level = str(level_m.group(1)) if level_m else None
                    try:
                        addr = IPv4Address(addr_str)
                    except Exception:
                        try:
                            addr = IPv6Address(addr_str)
                        except Exception:
                            addr = addr_str
                    hosts.append(LoggingHost(address=addr, port=port, vrf=vrf, level=level))
            elif re.match(r"^logging\s+source-interface\s+", t):
                source_interface = self._extract_match(t, r"^logging\s+source-interface\s+(\S+)")
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
            elif t == "logging off":
                enabled = False

        return SyslogConfig(
            object_id="syslog",
            raw_lines=raw_lines,
            source_os=self.os_type,
            line_numbers=line_numbers,
            enabled=enabled,
            hosts=hosts,
            buffered_size=buffered_size,
            buffered_level=buffered_level,
            console_level=console_level,
            monitor_level=monitor_level,
            source_interface=source_interface,
        )

    # -------------------------------------------------------------------
    # VXLAN
    # -------------------------------------------------------------------

    def parse_vxlan(self) -> "VXLANConfig | None":
        """Parse VXLAN configuration from all ``interface nve`` interfaces.

        Handles::

            vlan 10
              vn-segment 10010
            vlan 20
              vn-segment 10020

            interface nve1
              no shutdown
              host-reachability protocol bgp
              source-interface loopback1
              member vni 10010
                suppress-arp
                mcast-group 239.1.1.1
              member vni 50001 associate-vrf
        """
        from confgraph.models.vxlan import VXLANConfig, VXLANVniMapping

        parse = self._get_parse_obj()
        nve_objs = parse.find_objects(r"^interface\s+nve\d+")
        if not nve_objs:
            return None

        # Build VNI→VLAN map from "vlan X / vn-segment Y" blocks
        vni_to_vlan: dict[int, int] = {}
        vlan_objs = parse.find_objects(r"^vlan\s+\d+\s*$")
        for vlan_obj in vlan_objs:
            vlan_m = re.match(r"^vlan\s+(\d+)", vlan_obj.text)
            if not vlan_m:
                continue
            vlan_id = int(vlan_m.group(1))
            for child in vlan_obj.children:
                vnseg_m = re.match(r"\s+vn-segment\s+(\d+)", child.text)
                if vnseg_m:
                    vni_to_vlan[int(vnseg_m.group(1))] = vlan_id

        source_interface = None
        vni_mappings: list[VXLANVniMapping] = []
        raw_lines: list[str] = []
        line_numbers: list[int] = []

        for nve_intf in nve_objs:
            raw_lines.append(nve_intf.text)
            line_numbers.append(nve_intf.linenum)

            for child in nve_intf.children:
                raw_lines.append(child.text)
                line_numbers.append(child.linenum)
                t = child.text.strip()

                m = re.match(r"source-interface\s+(\S+)", t, re.IGNORECASE)
                if m:
                    source_interface = m.group(1)
                    continue

                m = re.match(r"member\s+vni\s+(\d+)(?:\s+associate-vrf)?", t)
                if m:
                    vni = int(m.group(1))
                    is_l3 = "associate-vrf" in t
                    # Parse sub-attributes from VNI member children
                    mcast_group = None
                    suppress_arp = False
                    for sub in child.children:
                        raw_lines.append(sub.text)
                        line_numbers.append(sub.linenum)
                        st = sub.text.strip()
                        mg = re.match(r"mcast-group\s+(\S+)", st)
                        if mg:
                            mcast_group = mg.group(1)
                        elif st == "suppress-arp":
                            suppress_arp = True
                    vni_mappings.append(VXLANVniMapping(
                        vni=vni,
                        vlan=vni_to_vlan.get(vni),
                        vrf="(L3)" if is_l3 else None,
                        mcast_group=mcast_group,
                        suppress_arp=suppress_arp,
                    ))
                    continue

        return VXLANConfig(
            object_id="vxlan",
            raw_lines=raw_lines,
            source_os=self.os_type,
            line_numbers=line_numbers,
            source_interface=source_interface,
            vni_mappings=vni_mappings,
        )

    # -------------------------------------------------------------------
    # VPC
    # -------------------------------------------------------------------

    def parse_vpc(self) -> "VPCConfig | None":
        """Parse VPC domain configuration.

        Handles::

            vpc domain 100
              role priority 1000
              system-priority 2000
              peer-keepalive destination 10.0.0.2 source 10.0.0.1 vrf management
              peer-gateway
              delay restore 150
              auto-recovery
        """
        from confgraph.models.vpc import VPCConfig

        parse = self._get_parse_obj()
        vpc_objs = parse.find_objects(r"^vpc\s+domain\s+\d+")
        if not vpc_objs:
            return None

        vpc_obj = vpc_objs[0]
        m = re.match(r"^vpc\s+domain\s+(\d+)", vpc_obj.text)
        domain_id = int(m.group(1))

        role_priority = None
        system_priority = None
        peer_ka_dst = None
        peer_ka_src = None
        peer_ka_vrf = None
        peer_link = None
        delay_restore = None
        auto_recovery = False

        for child in vpc_obj.children:
            t = child.text.strip()

            m = re.match(r"role\s+priority\s+(\d+)", t)
            if m:
                role_priority = int(m.group(1))
                continue

            m = re.match(r"system-priority\s+(\d+)", t)
            if m:
                system_priority = int(m.group(1))
                continue

            m = re.match(r"peer-keepalive\s+destination\s+(\S+)", t)
            if m:
                try:
                    peer_ka_dst = IPv4Address(m.group(1))
                except ValueError:
                    continue
                src_m = re.search(r"source\s+(\S+)", t)
                if src_m:
                    try:
                        peer_ka_src = IPv4Address(src_m.group(1))
                    except ValueError:
                        pass
                vrf_m = re.search(r"vrf\s+(\S+)", t)
                if vrf_m:
                    peer_ka_vrf = vrf_m.group(1)
                continue

            m = re.match(r"delay\s+restore\s+(\d+)", t)
            if m:
                delay_restore = int(m.group(1))
                continue

            if re.match(r"auto-recovery\b", t):
                auto_recovery = True
                continue

        # Find peer-link from interfaces (interface port-channel X → vpc peer-link)
        for intf_obj in parse.find_objects(r"^interface\s+"):
            for ch in intf_obj.children:
                if re.match(r"\s+vpc\s+peer-link\b", ch.text):
                    intf_name = re.match(r"^interface\s+(\S+)", intf_obj.text)
                    if intf_name:
                        peer_link = intf_name.group(1)
                    break

        return VPCConfig(
            object_id="vpc",
            raw_lines=[vpc_obj.text] + [c.text for c in vpc_obj.children],
            source_os=self.os_type,
            line_numbers=[vpc_obj.linenum] + [c.linenum for c in vpc_obj.children],
            domain_id=domain_id,
            role_priority=role_priority,
            system_priority=system_priority,
            peer_keepalive_destination=peer_ka_dst,
            peer_keepalive_source=peer_ka_src,
            peer_keepalive_vrf=peer_ka_vrf,
            peer_link=peer_link,
            delay_restore=delay_restore,
            auto_recovery=auto_recovery,
        )

    # -----------------------------------------------------------------------
    # MPLS / LDP — "mpls ldp configuration" block (NX-OS style)
    # -----------------------------------------------------------------------

    # -------------------------------------------------------------------
    # Deletion commands (tombstones)
    # -------------------------------------------------------------------

    def parse_deletion_commands(self) -> list[str]:
        """Parse NX-OS deletion commands into tombstone strings.

        Inherits all IOS top-level tombstones (``no router ospf``,
        ``no ip pim rp-address``, ``no vlan``, etc.) and adds NX-OS-specific
        nested block deletions:

          - ``no member vni <id>`` inside ``interface nve``  → ``field:vxlan:vni:<id>``
          - ``no peer-keepalive`` inside ``vpc domain``      → ``field:vpc:peer_keepalive_*``
        """
        tombstones = super().parse_deletion_commands()
        parse = self._get_parse_obj()

        # --- VXLAN VNI removal (nested under interface nve) ---
        for nve_obj in parse.find_objects(r"^interface\s+nve\d+"):
            for child in nve_obj.children:
                t = child.text.strip()
                m = re.match(r"no\s+member\s+vni\s+(\d+)", t)
                if m:
                    tombstones.append(f"field:vxlan:vni:{m.group(1)}")

        # --- vPC peer-keepalive removal (nested under vpc domain) ---
        for vpc_obj in parse.find_objects(r"^vpc\s+domain\s+\d+"):
            for child in vpc_obj.children:
                t = child.text.strip()
                if re.match(r"no\s+peer-keepalive\b", t):
                    tombstones.append("field:vpc:peer_keepalive_destination")
                    tombstones.append("field:vpc:peer_keepalive_source")
                    tombstones.append("field:vpc:peer_keepalive_vrf")

        return tombstones

    def parse_mpls(self) -> "MPLSConfig | None":
        """Parse MPLS/LDP from NX-OS hierarchical ``mpls ldp configuration`` block.

        NX-OS nests LDP sub-commands under ``mpls ldp configuration``::

            feature mpls ldp
            mpls ldp configuration
              router-id Loopback0
              graceful-restart
        """
        from confgraph.models.mpls import MPLSConfig

        parse = self._get_parse_obj()

        ldp_objs = parse.find_objects(r"^mpls\s+ldp\s+configuration\s*$")
        if not ldp_objs:
            return None

        ldp_obj = ldp_objs[0]

        ldp_router_id = None
        ldp_router_id_force = False
        ldp_graceful_restart = False
        ldp_session_protection = False
        ldp_password = None

        for child in ldp_obj.children:
            t = child.text.strip()

            m = re.match(r"router-id\s+(\S+)(\s+force)?", t)
            if m:
                ldp_router_id = m.group(1)
                ldp_router_id_force = m.group(2) is not None
                continue

            if re.match(r"graceful-restart\b", t):
                ldp_graceful_restart = True
                continue

            if re.match(r"session\s+protection\b", t):
                ldp_session_protection = True
                continue

            m = re.match(r"password\s+", t)
            if m:
                ldp_password = t
                continue

        ldp_enabled = ldp_router_id is not None

        raw = [ldp_obj.text] + [c.text for c in ldp_obj.children]
        return MPLSConfig(
            object_id="mpls",
            raw_lines=raw,
            source_os=self.os_type,
            line_numbers=[ldp_obj.linenum] + [c.linenum for c in ldp_obj.children],
            ldp_router_id=ldp_router_id,
            ldp_router_id_force=ldp_router_id_force,
            ldp_enabled=ldp_enabled,
            ldp_graceful_restart=ldp_graceful_restart,
            ldp_session_protection=ldp_session_protection,
            ldp_password=ldp_password,
        )

    # -------------------------------------------------------------------
    # LLDP — NX-OS uses "feature lldp" (N7)
    # -------------------------------------------------------------------

    def parse_lldp(self):
        """Parse LLDP, treating ``feature lldp`` as the NX-OS enable signal.

        NX-OS defaults LLDP to **disabled**; ``feature lldp`` enables it.
        The inherited IOS parser looks for ``lldp run`` which NX-OS does not
        use.  This override checks ``feature lldp`` first, then delegates to
        the parent for timer/holdtime/tlv-select parsing.
        """
        from confgraph.models.lldp import LLDPConfig

        parse = self._get_parse_obj()

        feature_objs = parse.find_objects(r"^(?:no\s+)?feature\s+lldp\b")
        lldp_objs = parse.find_objects(r"^(?:no\s+)?lldp\b")

        if not feature_objs and not lldp_objs:
            return None

        # NX-OS default: LLDP disabled unless "feature lldp" is present
        enabled = False
        for obj in feature_objs:
            t = obj.text.strip()
            if t == "feature lldp":
                enabled = True
            elif t == "no feature lldp":
                enabled = False

        timer = holdtime = reinit = None
        tlv_select: list[str] = []
        raw_lines: list[str] = []
        line_numbers: list[int] = []

        for obj in feature_objs:
            raw_lines.append(obj.text)
            line_numbers.append(obj.linenum)

        for obj in lldp_objs:
            raw_lines.append(obj.text)
            line_numbers.append(obj.linenum)
            t = obj.text.strip()
            if re.match(r"^lldp\s+timer\s+", t):
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

    # -------------------------------------------------------------------
    # CDP — NX-OS uses "feature cdp" (N7)
    # -------------------------------------------------------------------

    def parse_cdp(self):
        """Parse CDP, treating ``feature cdp`` as the NX-OS enable signal.

        NX-OS defaults CDP to **disabled**; ``feature cdp`` enables it.
        """
        from confgraph.models.cdp import CDPConfig

        parse = self._get_parse_obj()

        feature_objs = parse.find_objects(r"^(?:no\s+)?feature\s+cdp\b")
        cdp_objs = parse.find_objects(r"^(?:no\s+)?cdp\b")

        if not feature_objs and not cdp_objs:
            return None

        # NX-OS default: CDP disabled unless "feature cdp" is present
        enabled = False
        for obj in feature_objs:
            t = obj.text.strip()
            if t == "feature cdp":
                enabled = True
            elif t == "no feature cdp":
                enabled = False

        timer = holdtime = None
        advertise_v2 = True
        raw_lines: list[str] = []
        line_numbers: list[int] = []

        for obj in feature_objs:
            raw_lines.append(obj.text)
            line_numbers.append(obj.linenum)

        for obj in cdp_objs:
            raw_lines.append(obj.text)
            line_numbers.append(obj.linenum)
            t = obj.text.strip()
            if re.match(r"^cdp\s+timer\s+", t):
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

    # -------------------------------------------------------------------
    # DNS — scan vrf context blocks (N6)
    # -------------------------------------------------------------------

    def parse_dns(self):
        """Parse DNS config, including entries inside ``vrf context`` blocks.

        NX-OS places per-VRF DNS entries as children of ``vrf context NAME``
        stanzas.  The inherited IOS ``parse_dns`` only scans global lines.
        """
        from confgraph.models.dns import DNSConfig

        dns = super().parse_dns()

        parse = self._get_parse_obj()
        vrf_objs = parse.find_objects(r"^vrf\s+context\s+(\S+)")

        extra_servers: list[str] = []
        extra_domain_name: str | None = None
        extra_domain_list: list[str] = []
        extra_lookup_disabled = False
        extra_raw: list[str] = []
        extra_line_numbers: list[int] = []

        for vrf_obj in vrf_objs:
            for child in vrf_obj.children:
                t = child.text.strip()

                m = re.match(r"ip\s+name-server\s+(.*)", t)
                if m:
                    extra_raw.append(child.text)
                    extra_line_numbers.append(child.linenum)
                    parts = m.group(1).split()
                    # Strip optional "vrf <name>" prefix
                    if len(parts) >= 2 and parts[0].lower() == "vrf":
                        parts = parts[2:]
                    extra_servers.extend(parts)
                    continue

                m = re.match(r"ip\s+domain(?:-|\s+)name\s+(\S+)", t)
                if m:
                    extra_raw.append(child.text)
                    extra_line_numbers.append(child.linenum)
                    if extra_domain_name is None:
                        extra_domain_name = m.group(1)
                    continue

                m = re.match(r"ip\s+domain(?:-|\s+)list\s+(\S+)", t)
                if m:
                    extra_raw.append(child.text)
                    extra_line_numbers.append(child.linenum)
                    extra_domain_list.append(m.group(1))
                    continue

                if re.match(r"no\s+ip\s+domain.lookup", t):
                    extra_raw.append(child.text)
                    extra_line_numbers.append(child.linenum)
                    extra_lookup_disabled = True

        if not extra_raw:
            return dns

        if dns is None:
            dns = DNSConfig(
                object_id="dns",
                raw_lines=extra_raw,
                source_os=self.os_type,
                line_numbers=extra_line_numbers,
                lookup_enabled=not extra_lookup_disabled,
                domain_name=extra_domain_name,
                domain_list=extra_domain_list,
                name_servers=extra_servers,
            )
        else:
            dns.raw_lines.extend(extra_raw)
            dns.line_numbers.extend(extra_line_numbers)
            dns.name_servers.extend(extra_servers)
            if extra_domain_name and dns.domain_name is None:
                dns.domain_name = extra_domain_name
            dns.domain_list.extend(extra_domain_list)
            if extra_lookup_disabled:
                dns.lookup_enabled = False

        return dns

    # -------------------------------------------------------------------
    # AAA — parse group server members (N2)
    # -------------------------------------------------------------------

    def parse_aaa(self):
        """Parse AAA, linking ``aaa group server`` members to server definitions.

        NX-OS uses ``aaa group server tacacs+ NAME`` / ``aaa group server
        radius NAME`` blocks with child ``server <ip>`` lines.  The inherited
        IOS parser finds these blocks but does not parse their children.

        This override calls ``super().parse_aaa()`` then scans the group
        blocks.  For each ``server <ip>`` child, if a matching server does
        not already exist in the parsed server list, it is added with the
        address as its name (stable identity for merge keys — fixes M8
        collision on ``name=None``).
        """
        from confgraph.models.aaa import AAAConfig, TacacsServer, RadiusServer

        aaa = super().parse_aaa()
        if aaa is None:
            return None

        parse = self._get_parse_obj()
        group_objs = parse.find_objects(r"^aaa\s+group\s+server\s+")

        for obj in group_objs:
            t = obj.text.strip()
            m = re.match(r"aaa\s+group\s+server\s+(tacacs\+|radius)\s+(\S+)", t)
            if not m:
                continue

            server_type = m.group(1)  # "tacacs+" or "radius"

            for child in obj.children:
                ct = child.text.strip()
                sm = re.match(r"server\s+(\S+)", ct)
                if not sm:
                    continue
                server_ref = sm.group(1)

                if server_type == "tacacs+":
                    # Add if not already present by address
                    exists = any(s.address == server_ref for s in aaa.tacacs_servers)
                    if not exists:
                        aaa.tacacs_servers.append(TacacsServer(
                            name=server_ref,
                            address=server_ref,
                        ))
                    aaa.raw_lines.append(child.text)
                    aaa.line_numbers.append(child.linenum)
                else:
                    exists = any(s.address == server_ref for s in aaa.radius_servers)
                    if not exists:
                        aaa.radius_servers.append(RadiusServer(
                            name=server_ref,
                            address=server_ref,
                        ))
                    aaa.raw_lines.append(child.text)
                    aaa.line_numbers.append(child.linenum)

        return aaa
