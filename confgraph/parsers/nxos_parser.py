"""Cisco NX-OS configuration parser."""

import re
from ipaddress import IPv4Interface, IPv6Interface

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
        for vrf_obj in vrf_objs:
            vrf_name = self._extract_match(vrf_obj.text, r"^vrf\s+context\s+(\S+)")
            if not vrf_name:
                continue

            raw_lines, line_numbers = self._get_raw_lines_and_line_numbers(vrf_obj)

            # RD
            rd = None
            rd_ch = vrf_obj.re_search_children(r"^\s+rd\s+(\S+)")
            if rd_ch:
                rd = self._extract_match(rd_ch[0].text, r"^\s+rd\s+(\S+)")

            # Route-targets — NX-OS style under address-family ipv4 unicast block
            rt_import: list[str] = []
            rt_export: list[str] = []
            rt_both: list[str] = []

            for child in vrf_obj.all_children:
                text = child.text.strip()
                if text.startswith("route-target import "):
                    val = self._extract_match(text, r"route-target\s+import\s+(\S+)")
                    if val:
                        rt_import.append(val)
                elif text.startswith("route-target export "):
                    val = self._extract_match(text, r"route-target\s+export\s+(\S+)")
                    if val:
                        rt_export.append(val)
                elif text.startswith("route-target both "):
                    val = self._extract_match(text, r"route-target\s+both\s+(\S+)")
                    if val:
                        rt_both.append(val)

            # Route-map import/export (under address-family)
            route_map_import = None
            route_map_export = None
            for child in vrf_obj.all_children:
                text = child.text.strip()
                if text.startswith("route-map") and "import" in text:
                    route_map_import = self._extract_match(text, r"route-map\s+(\S+)\s+import")
                elif text.startswith("route-map") and "export" in text:
                    route_map_export = self._extract_match(text, r"route-map\s+(\S+)\s+export")

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

        return vrfs

    # -----------------------------------------------------------------------
    # Interface VRF — "vrf member NAME"
    # -----------------------------------------------------------------------

    def _extract_interface_vrf(self, intf_obj) -> str | None:
        """Extract VRF from interface. NX-OS uses ``vrf member NAME``."""
        vrf_ch = intf_obj.re_search_children(r"^\s+vrf\s+member\s+(\S+)")
        if vrf_ch:
            return self._extract_match(vrf_ch[0].text, r"^\s+vrf\s+member\s+(\S+)")
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
        """Parse BGP peer-groups. NX-OS uses ``template peer NAME`` blocks."""
        peer_groups = []

        # NX-OS: template peer NAME (top-level under router bgp)
        template_children = bgp_obj.re_search_children(r"^\s+template\s+peer\s+(\S+)")
        for tmpl_child in template_children:
            pg_name = self._extract_match(tmpl_child.text, r"^\s+template\s+peer\s+(\S+)")
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

            for child in tmpl_child.all_children:
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
