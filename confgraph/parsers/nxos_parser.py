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
        if not log_objs:
            return None

        hosts = []
        buffered_size = buffered_level = None
        console_level = monitor_level = None
        source_interface = None
        enabled = True
        raw_lines = []
        line_numbers = []

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
            elif "no logging" in t or "logging off" in t:
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
