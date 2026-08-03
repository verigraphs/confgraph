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
from confgraph.models.qos import ControlPlaneConfig
from confgraph.models.interface import InterfaceFlowMonitor, StormControlLevel, VRRPGroup
from confgraph.models.netflow import (
    NetFlowConfig,
    NetFlowExporter,
    NetFlowMonitor,
    NetFlowRecord,
)
from confgraph.models.static_route import StaticRoute
from confgraph.parsers.base import _BASE_KNOWN_PATTERNS, apply_peer_group_command, _default_pg_data, parse_remote_as_token
from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.iosxr_parser import _AFTransparentBlock


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
    r"^control-plane",
    # CCR-0094: Flexible NetFlow top-level blocks (claimed by parse_netflow).
    r"^flow\s+(record|exporter|monitor)\b",
    # CCR-0155: the top-level ``evpn`` block is PARSED (parse_evpn → L2VNIs),
    # so it must be claimed — recording it as unrecognized too made a report
    # say "evpn analyzed" and "unrecognized config present" about the same
    # lines, and pushed its raw text into digest family F6 alongside F9.
    r"^evpn\s*$",
]


class NXOSParser(IOSParser):
    """Parser for Cisco NX-OS configurations.

    Inherits from IOSParser and overrides methods where NX-OS syntax
    differs: VRF (vrf context), interface VRF (vrf member), CIDR
    addresses, BGP templates (template peer / inherit peer), and
    OSPF interface membership (ip router ospf PROC area AREA).
    """

    _KNOWN_TOP_LEVEL_PATTERNS: list[str] = _NXOS_KNOWN_PATTERNS

    # CCR-0155: claiming ``evpn`` at top level must not silence UNPARSED
    # lines inside it — register its known direct children so anything else
    # still discloses ("evpn > <line>").  parse_evpn consumes only
    # ``vni <n> l2`` sub-blocks here (rd/route-target are grandchildren,
    # which the collector does not descend into).
    _KNOWN_CHILD_PATTERNS: list[tuple[str, list[str]]] = (
        IOSParser._KNOWN_CHILD_PATTERNS + [
            (r"^evpn\s*$", [r"^vni\s+\d+\s+l2\b"]),
        ]
    )

    # CCR-0038 Theme 1 — the NX-OS dialect of the shared VRF body vocabulary.
    # The CLI token that applies a route-map to VRF import/export is the bare
    # word `map`, NOT `route-map`:
    #
    #     vrf context CUSTOMER_A
    #       address-family ipv4 unicast
    #         import map RM_VRF_IN
    #         export map RM_VRF_OUT
    #
    # (`import map <rmap-name> [evpn]` / `export map <rmap-name>`, command mode
    # /exec/configure/vrf-af-ipv4. The string "import route-map" appears nowhere
    # in the NX-OS command reference — a fixture carrying it was testing a line
    # no Nexus emits.) `description` needs no entry: it is spelled the same as on
    # IOS and comes free from the parent set — which is the whole point of
    # extending rather than re-implementing.
    _VRF_SCALAR_PATTERNS = {
        **IOSParser._VRF_SCALAR_PATTERNS,
        "route_map_import": IOSParser._VRF_SCALAR_PATTERNS["route_map_import"].extended(
            r"^import\s+map\s+(?P<val>\S+)",
        ),
        "route_map_export": IOSParser._VRF_SCALAR_PATTERNS["route_map_export"].extended(
            r"^export\s+map\s+(?P<val>\S+)",
        ),
    }

    # CCR-0038 Theme 4 — the NX-OS line dialect. NX-OS lines carry NO NUMBER and
    # no range: the grammar is the bare `line vty` and the bare `line console`
    # (command mode /exec/configure). `line vty 0 4` is the IOS spelling and has
    # no NX-OS counterpart, so the inherited IOS header — which requires a digit
    # — matched nothing and `p.lines` came back empty on every Nexus.
    #
    # The BODY (exec-timeout, session-limit, access-class, transport input …) is
    # the shared walk in IOSParser.parse_lines; only the header differs, so only
    # the header is declared here. Note NX-OS `exec-timeout` takes MINUTES only,
    # which the shared body regex already handles (the seconds group is optional).
    _LINE_HEADER_PATTERNS = IOSParser._LINE_HEADER_PATTERNS.extended(
        r"^line\s+(?P<type>vty|console)\s*$",
    )

    def __init__(self, config_text: str):
        super().__init__(config_text, os_type=OSType.NXOS)
        # Re-initialize with nxos syntax for CiscoConfParse
        self.syntax = "nxos"
        self.parse_obj = None  # Force re-creation with new syntax

    def _nested_block(self, obj):
        """AF-transparent view for NX-OS routing blocks (CCR-0067).

        NX-OS nests a routing instance's own attributes one level deeper, inside
        ``address-family ipv4 unicast`` — exactly as IOS-XR does — so the shared
        ``parse_isis`` direct-child extractors (``redistribute``,
        ``default-information originate``, …) stop at the AF door and read nothing.
        Reuse IOS-XR's ``_AFTransparentBlock`` (the SAME splice, single source):
        it hoists ONLY the ``ipv4 unicast`` AF's contents alongside the direct
        children. That reads the instance-level IPv4 values on a dual-stack device
        deterministically and withholds the IPv6 AF (whose values have no home
        until IS-IS gains an address-family dimension — CCR-0049's guard, not this
        seam's to fake). On a flat (no-AF) NX-OS instance the view is the identity.
        """
        return _AFTransparentBlock(obj)

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
                    "name_servers": [],
                    "domain_name": None,
                    "domain_list": [],
                    "scalars": {},
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
                elif text.startswith("ip name-server "):
                    # VRF-scoped resolver(s) — attribute to THIS VRF, not global
                    # DNS (CCR-0093). Multiple IPs may share one line; an optional
                    # "vrf <name>" prefix is stripped as in the global scan.
                    parts = text.split()[2:]
                    if len(parts) >= 2 and parts[0].lower() == "vrf":
                        parts = parts[2:]
                    for server in parts:
                        if server not in entry["name_servers"]:
                            entry["name_servers"].append(server)
                elif re.match(r"ip\s+domain(?:-|\s+)name\s+\S+", text):
                    # VRF-scoped domain name (CCR-0093). First occurrence wins,
                    # mirroring the global DNSConfig.domain_name semantics.
                    dm = re.match(r"ip\s+domain(?:-|\s+)name\s+(\S+)", text)
                    if dm and entry["domain_name"] is None:
                        entry["domain_name"] = dm.group(1)
                elif re.match(r"ip\s+domain(?:-|\s+)list\s+\S+", text):
                    # VRF-scoped search domain(s) (CCR-0093).
                    lm = re.match(r"ip\s+domain(?:-|\s+)list\s+(\S+)", text)
                    if lm and lm.group(1) not in entry["domain_list"]:
                        entry["domain_list"].append(lm.group(1))
                else:
                    # description (direct child of `vrf context`) and
                    # import/export map (under address-family) — the shared VRF
                    # body vocabulary, NX-OS dialect (CCR-0038 Theme 1).
                    self._apply_vrf_body_line(entry["scalars"], text)

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
                    name_servers=entry["name_servers"],
                    domain_name=entry["domain_name"],
                    domain_list=entry["domain_list"],
                    **entry["scalars"],
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
    # FHRP block spellings — NX-OS uses "hsrp N" / "vrrp N" sub-blocks whose
    # attribute lines (ip / address / priority / preempt) are the group's
    # commands. We EXTEND the parent collectors (handbook §7.3): the flat IOS
    # "standby N <cmd>" pairs from super() plus the block-form pairs here feed
    # the one shared HSRP/VRRP applier — the command vocabulary is not
    # re-implemented.
    # -----------------------------------------------------------------------

    def _collect_hsrp_commands(self, intf_obj) -> tuple[list[tuple[int, str]], int | None]:
        pairs, version = super()._collect_hsrp_commands(intf_obj)
        # Interface-level "hsrp version N" (applies to all block-form groups)
        for vch in intf_obj.find_child_objects(r"^\s+hsrp\s+version\s+(\d+)\s*$"):
            vm = re.search(r"hsrp\s+version\s+(\d+)", vch.text)
            if vm:
                version = int(vm.group(1))
        # "hsrp N" blocks: each child line is a group command (normalized to
        # the IOS "standby N <cmd>" vocabulary; "address" -> "ip").
        for blk in intf_obj.find_child_objects(r"^\s+hsrp\s+(\d+)\s*$"):
            gm = re.match(r"^\s+hsrp\s+(\d+)\s*$", blk.text)
            if not gm:
                continue
            group_num = int(gm.group(1))
            for cmd_child in blk.children:
                cmd = cmd_child.text.strip()
                if cmd.startswith("address "):
                    cmd = "ip " + cmd[len("address "):]
                pairs.append((group_num, cmd))
        return pairs, version

    def _collect_vrrp_commands(self, intf_obj) -> list[tuple[int, str]]:
        pairs = super()._collect_vrrp_commands(intf_obj)
        for blk in intf_obj.find_child_objects(r"^\s+vrrp\s+(\d+)\s*$"):
            gm = re.match(r"^\s+vrrp\s+(\d+)\s*$", blk.text)
            if not gm:
                continue
            group_num = int(gm.group(1))
            for cmd_child in blk.children:
                cmd = cmd_child.text.strip()
                if cmd.startswith("address "):
                    cmd = "ip " + cmd[len("address "):]
                elif cmd.startswith("advertisement-interval "):
                    # NX-OS block spelling of the advertise timer; the shared
                    # applier only knows the IOS "timers advertise N" vocab.
                    cmd = "timers advertise " + cmd[len("advertisement-interval "):]
                pairs.append((group_num, cmd))
        return pairs

    def _parse_vrrp_groups(self, intf_obj) -> list:
        """VRRPv2 groups (shared applier) plus NX-OS VRRPv3 address-family groups.

        VRRPv3 (``vrrpv3 <grp> address-family {ipv4|ipv6}``) is a distinct
        command family with an address-family dimension and (per device emit)
        priority reordered before address; it is parsed key-by-key here and
        merged into the same ``vrrp_groups`` list. VRRPv2 and VRRPv3 are
        mutually exclusive on the interface, so the two never collide.
        """
        groups = super()._parse_vrrp_groups(intf_obj)
        groups.extend(self._parse_vrrpv3_groups(intf_obj))
        return groups

    def _parse_vrrpv3_groups(self, intf_obj) -> list:
        """Parse ``vrrpv3 <grp> address-family {ipv4|ipv6}`` blocks.

        Device-verified emitted form (n9kv 10.5(5), CCR-0088)::

            vrrpv3 31 address-family ipv4
              priority 120
              address 10.131.131.254 primary

        Parsed by key, not position (the device emits priority before address).
        """
        v3_groups: list = []
        header_re = r"^\s+vrrpv3\s+(\d+)\s+address-family\s+(\S+)"
        for blk in intf_obj.find_child_objects(header_re):
            hm = re.match(header_re, blk.text)
            if not hm:
                continue
            group_num = int(hm.group(1))
            afi = hm.group(2).strip()
            data: dict = {
                "group_number": group_num,
                "version": 3,
                "afi": afi,
                "priority": None,
                "preempt": False,
                "virtual_ip": None,
                "timers_advertise": None,
                "authentication": None,
                "track_objects": [],
                "addresses": [],
            }
            for cmd_child in blk.children:
                cmd = cmd_child.text.strip()
                if cmd.startswith("address "):
                    addr = cmd[len("address "):].strip()
                    data["addresses"].append(addr)
                    # Mirror the IPv4 primary into virtual_ip for VRRPv2 parity.
                    if afi == "ipv4":
                        first_tok = addr.split()[0] if addr.split() else ""
                        is_primary = ("secondary" not in addr) and (
                            data["virtual_ip"] is None
                        )
                        if is_primary:
                            try:
                                data["virtual_ip"] = IPv4Address(first_tok)
                            except ValueError:
                                pass
                elif cmd.startswith("priority "):
                    try:
                        data["priority"] = int(cmd[len("priority "):].strip())
                    except ValueError:
                        pass
                elif cmd == "preempt" or cmd.startswith("preempt "):
                    data["preempt"] = True
                # NOTE: the VRRPv3 advertise timer is intentionally NOT parsed
                # here. NX-OS emits it as `timers advertise <ms>` (milliseconds,
                # not the VRRPv2 `advertisement-interval <sec>` keyword) and that
                # emitted form is doc-only, not capture-verified — see follow-up.
            v3_groups.append(VRRPGroup(**data))
        return v3_groups

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

            # NX-OS: ip address X.X.X.X/24 [secondary]
            cidr_children = intf_obj.find_child_objects(
                r"^\s+ip\s+address\s+(\d+\.\d+\.\d+\.\d+/\d+)"
            )
            cidr_primary = [c for c in cidr_children if "secondary" not in c.text.lower()]
            if cidr_primary:
                match = re.search(
                    r"^\s+ip\s+address\s+(\d+\.\d+\.\d+\.\d+/\d+)",
                    cidr_primary[0].text,
                )
                if match:
                    try:
                        intf_cfg.ip_address = IPv4Interface(match.group(1))
                    except ValueError:
                        pass
            for sec in (c for c in cidr_children if "secondary" in c.text.lower()):
                sm = re.search(r"^\s+ip\s+address\s+(\d+\.\d+\.\d+\.\d+/\d+)", sec.text)
                if sm:
                    try:
                        ip = IPv4Interface(sm.group(1))
                        if ip not in intf_cfg.secondary_ips:
                            intf_cfg.secondary_ips.append(ip)
                    except ValueError:
                        pass

            # NX-OS STP portfast spelling: "spanning-tree port type edge"
            # (and "... edge trunk") is Cisco's NX-OS rename of IOS
            # "spanning-tree portfast"; "... normal" is the explicit non-edge
            # designation. IOSParser.parse_interfaces (the super() call above)
            # only knows the IOS "spanning-tree portfast" spelling, so map the
            # NX-OS spelling onto the same InterfaceConfig.stp_portfast field.
            if intf_obj.find_child_objects(r"^\s+spanning-tree\s+port\s+type\s+edge\b"):
                intf_cfg.stp_portfast = True
            elif intf_obj.find_child_objects(r"^\s+spanning-tree\s+port\s+type\s+normal\b"):
                intf_cfg.stp_portfast = False

            # VPC per-interface: "vpc <id>" or "vpc peer-link"
            vpc_ch = intf_obj.find_child_objects(r"^\s+vpc\s+(\d+)\s*$")
            if vpc_ch:
                vpc_m = re.match(r"^\s+vpc\s+(\d+)", vpc_ch[0].text)
                if vpc_m:
                    intf_cfg.vpc_id = int(vpc_m.group(1))

            # NX-OS DHCP relay targets: "ip dhcp relay address <ip>" is the
            # per-interface, repeatable helper-address analogue (IOS emits it
            # as "ip helper-address"). The IOSParser super() call does not know
            # the NX-OS spelling, so collect each target here in config order.
            # CCR-0129: both spellings land in the SAME field — one operational
            # fact, one field — so every helper_addresses consumer (the DHCP
            # relay assessor, the relay-loop check, the merge union, the
            # Change-IR member ops) covers NX-OS with no per-OS special case.
            for relay_ch in intf_obj.find_child_objects(
                r"^\s+ip\s+dhcp\s+relay\s+address\s+"
            ):
                rm = re.match(
                    r"^\s+ip\s+dhcp\s+relay\s+address\s+(\d+\.\d+\.\d+\.\d+)",
                    relay_ch.text,
                )
                if rm:
                    try:
                        addr = IPv4Address(rm.group(1))
                    except ValueError:
                        continue
                    if addr not in intf_cfg.helper_addresses:
                        intf_cfg.helper_addresses.append(addr)

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

            # NX-OS storm-control: "storm-control {broadcast|multicast|unicast}
            # level <threshold>". The threshold is a bandwidth percentage by
            # default (emitted "level 5.00"), or an absolute rate when a unit
            # keyword precedes the value ("level pps <n>" / "level bps <n>").
            # IOSParser's super() call marks the line known-but-unparsed (the
            # interface known-child allowlist); collect it into the model here.
            for sc_ch in intf_obj.find_child_objects(r"^\s+storm-control\s+"):
                sc_m = re.match(
                    r"^\s+storm-control\s+(broadcast|multicast|unicast)\s+level\s+"
                    r"(?:(pps|bps)\s+)?(\S+)",
                    sc_ch.text,
                )
                if not sc_m:
                    continue
                traffic_type, unit_kw, raw_level = sc_m.groups()
                try:
                    level_val = float(raw_level)
                except ValueError:
                    continue
                unit = unit_kw if unit_kw else "percent"
                if any(s.traffic_type == traffic_type for s in intf_cfg.storm_control):
                    continue
                intf_cfg.storm_control.append(
                    StormControlLevel(
                        traffic_type=traffic_type, level=level_val, unit=unit
                    )
                )

            # NX-OS NetFlow application: "ip flow monitor <name> {input|output}"
            # binds a flow monitor to the interface in one direction. One line
            # per direction; the "^ip" known-child pattern marks it
            # known-but-unparsed in the super() call, so collect it here. Only
            # the IPv4 "input" direction is corpus-verified
            # (syntax-corpus/nxos/netflow.yaml); "output" is parsed leniently.
            for fm_ch in intf_obj.find_child_objects(
                r"^\s+ip\s+flow\s+monitor\s+"
            ):
                fm_m = re.match(
                    r"^\s+ip\s+flow\s+monitor\s+(\S+)\s+(input|output)\b",
                    fm_ch.text,
                )
                if not fm_m:
                    continue
                mon_name, direction = fm_m.groups()
                if any(fm.direction == direction for fm in intf_cfg.flow_monitors):
                    continue
                intf_cfg.flow_monitors.append(
                    InterfaceFlowMonitor(monitor=mon_name, direction=direction)
                )

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
        """Parse VRF-specific BGP instances (``router bgp`` → ``vrf NAME`` block).

        Delegates to the shared block-form traversal ``_parse_bgp_vrf_blocks``
        (CCR-0032), which descends into each ``vrf NAME`` sub-block and reuses
        the NX-OS neighbor parser (``_parse_bgp_neighbors``) so nested-block VRF
        neighbors — previously dropped by a hand-rolled inline-only loop — are
        captured with their address-family route-maps.
        """
        return self._parse_bgp_vrf_blocks(bgp_obj, asn)

    # -----------------------------------------------------------------------
    # BGP — NX-OS nested neighbor blocks + inherit peer
    # -----------------------------------------------------------------------

    @staticmethod
    def _parse_nxos_neighbor_children(ccp_node) -> dict:
        """Extract neighbor attributes from a CiscoConfParse node's children.

        Pure extractor — takes a CCP node (inline or bare ``neighbor`` line),
        walks its **direct** ``.children`` for session-level attributes, then
        descends each ``address-family <afi> <safi>`` sub-block into a
        ``BGPNeighborAF`` (CCR-0077).  NX-OS nests ALL per-neighbor policy
        (prefix-list / route-map / send-community / next-hop-self /
        default-originate / maximum-prefix) under the address-family, so a
        recursive ``.all_children`` walk previously flattened it onto the
        session scalars and left ``address_families == []`` — and on a
        dual-stack neighbor the ipv6 values clobbered the ipv4 ones.  Now the
        per-AF policy lives in ``nd["address_families"]``; the session scalars
        are kept populated from the ipv4-unicast AF only, for back-compat, so
        they never carry a colliding value.  Callers merge the dict into their
        model neighbor.
        """
        from confgraph.models.bgp import BGPTimers

        nd: dict = {
            "remote_as": None, "remote_as_source": None,
            "peer_group": None, "description": None,
            "update_source": None, "ebgp_multihop": None, "password": None,
            "password_encryption_type": None,
            "route_map_in": None, "route_map_out": None,
            "prefix_list_in": None, "prefix_list_out": None,
            "filter_list_in": None, "filter_list_out": None,
            "maximum_prefix": None, "next_hop_self": False,
            "route_reflector_client": False, "send_community": None,
            "fall_over_bfd": False, "shutdown": False,
            "disable_connected_check": False, "timers": None,
            "local_as": None, "local_as_no_prepend": False,
            "local_as_replace_as": False,
            "default_originate": False, "default_originate_route_map": None,
            "address_families": [],
        }

        # Direct children only — NOT .all_children.  Address-family policy lines
        # are grandchildren and are handled by the AF descent below; walking
        # them here would flatten them (the CCR-0077 bug).  Session-genuine
        # policy (a flattened form) still parses because these branches remain.
        for child in ccp_node.children:
            cmd = child.text.strip()

            # inherit peer NAME → peer_group
            im = re.match(r"inherit\s+peer\s+(\S+)", cmd)
            if im:
                nd["peer_group"] = im.group(1)
                continue
            if cmd.startswith("remote-as "):
                val = cmd.replace("remote-as ", "").strip()
                nd["remote_as"], nd["remote_as_source"] = (
                    parse_remote_as_token(val)
                )
            elif cmd.startswith("description "):
                nd["description"] = cmd.replace("description ", "").strip()
            elif cmd.startswith("update-source "):
                nd["update_source"] = cmd.replace("update-source ", "").strip()
            elif cmd.startswith("ebgp-multihop "):
                nd["ebgp_multihop"] = int(cmd.replace("ebgp-multihop ", "").strip())
            elif cmd.startswith("password "):
                # Shared extractor inherited from IOSParser (CCR-0030 bug 4);
                # this walk is a staticmethod, so reference it via the class.
                key, enc = NXOSParser._split_bgp_password(cmd[len("password "):])
                nd["password"] = key
                nd["password_encryption_type"] = enc
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

        # --- Per-neighbor address-family descent (CCR-0077) ---
        # Each `address-family <afi> <safi>` sub-block becomes one BGPNeighborAF.
        # Match ANY afi/safi pair — not just ipv4|ipv6 unicast|multicast — so
        # that `l2vpn evpn`, `vpnv4 unicast`, `ipv4 labeled-unicast`, etc. are
        # descended into address_families (with their true afi/safi) rather than
        # dropped: previously the recursive `.all_children` walk flattened them
        # lossily onto the session, and a regex restricted to the unicast set
        # would turn that lossy-but-PRESENT policy into an absent one.
        for child in ccp_node.children:
            afm = re.match(
                r"address-family\s+(\S+)\s+(\S+?)\s*$",
                child.text.strip(),
            )
            if not afm:
                continue
            nd["address_families"].append(
                NXOSParser._parse_nxos_neighbor_af_block(
                    child, afm.group(1), afm.group(2)
                )
            )

        # Back-compat: keep the flattened session scalars populated, but from
        # the ipv4-unicast AF ONLY (falling back to the first AF), and only
        # where a direct-child line has not already set them.  This is what
        # stops a dual-stack neighbor's ipv6 policy from clobbering the ipv4
        # scalar — `address_families` is the source of truth.
        bc_af = next(
            (a for a in nd["address_families"]
             if a.afi == "ipv4" and a.safi == "unicast"),
            None,
        )
        if bc_af is None and nd["address_families"]:
            bc_af = nd["address_families"][0]
        if bc_af is not None:
            for key in (
                "route_map_in", "route_map_out", "prefix_list_in",
                "prefix_list_out", "maximum_prefix",
                "default_originate_route_map",
            ):
                if nd[key] is None and getattr(bc_af, key) is not None:
                    nd[key] = getattr(bc_af, key)
            if nd["send_community"] is None and bc_af.send_community is not None:
                nd["send_community"] = bc_af.send_community
            if not nd["next_hop_self"] and bc_af.next_hop_self:
                nd["next_hop_self"] = True
            if not nd["route_reflector_client"] and bc_af.route_reflector_client:
                nd["route_reflector_client"] = True
            if not nd["default_originate"] and bc_af.default_originate:
                nd["default_originate"] = True

        return nd

    @staticmethod
    def _parse_nxos_neighbor_af_block(af_child, afi: str, safi: str):
        """Build one ``BGPNeighborAF`` from a neighbor ``address-family`` block.

        NX-OS emits all per-neighbor policy nested under
        ``neighbor <ip> / address-family <afi> <safi>``.  Mirrors the IOS-XR
        descent (``_parse_iosxr_neighbor_af_block``, CCR-0046) but with NX-OS
        token syntax (`route-map <RM> in|out`, `prefix-list <PL> in|out`,
        `next-hop-self`, `send-community`, `maximum-prefix <n> [<thr>]`,
        `default-originate [route-map <RM>]`).  Reads the AF block's direct
        ``.children`` only.
        """
        from confgraph.models.bgp import BGPNeighborAF

        af: dict = {
            "route_map_in": None, "route_map_out": None,
            "prefix_list_in": None, "prefix_list_out": None,
            "next_hop_self": False, "route_reflector_client": False,
            "send_community": None, "maximum_prefix": None,
            "maximum_prefix_threshold": None,
            "default_originate": False, "default_originate_route_map": None,
        }

        for pc in af_child.children:
            cmd = pc.text.strip()
            if cmd.startswith("route-map ") and cmd.endswith(" in"):
                af["route_map_in"] = cmd[len("route-map "):-len(" in")].strip()
            elif cmd.startswith("route-map ") and cmd.endswith(" out"):
                af["route_map_out"] = cmd[len("route-map "):-len(" out")].strip()
            elif cmd.startswith("prefix-list ") and cmd.endswith(" in"):
                af["prefix_list_in"] = cmd[len("prefix-list "):-len(" in")].strip()
            elif cmd.startswith("prefix-list ") and cmd.endswith(" out"):
                af["prefix_list_out"] = cmd[len("prefix-list "):-len(" out")].strip()
            elif cmd == "next-hop-self":
                af["next_hop_self"] = True
            elif cmd == "route-reflector-client":
                af["route_reflector_client"] = True
            elif cmd.startswith("send-community"):
                if "both" in cmd:
                    af["send_community"] = "both"
                elif "extended" in cmd:
                    af["send_community"] = "extended"
                else:
                    af["send_community"] = True
            elif cmd.startswith("maximum-prefix "):
                mp = cmd.split()
                if len(mp) >= 2 and mp[1].isdigit():
                    af["maximum_prefix"] = int(mp[1])
                    if len(mp) >= 3 and mp[2].isdigit():
                        af["maximum_prefix_threshold"] = int(mp[2])
            elif cmd.startswith("default-originate route-map "):
                af["default_originate"] = True
                af["default_originate_route_map"] = cmd.split(None, 2)[2].strip()
            elif cmd == "default-originate":
                af["default_originate"] = True

        # CCR-0165: NX-OS has no ``activate`` line — the AF block's presence
        # activates the family. Assert it explicitly (model default is now
        # None = unstated).
        af.setdefault("activate", True)
        return BGPNeighborAF(afi=afi, safi=safi, **af)

    def _emit_bgp_neighbor_submode_negations(
        self, bgp_or_af_obj, asn, vrf, pg_names
    ) -> None:
        """NX-OS indented neighbor sub-mode ``no <attr>`` negations (CCR-0112).

        NX-OS prints per-neighbor negations INSIDE the ``neighbor <ip>`` block —
        ``no description`` at session level, ``no next-hop-self`` under
        ``address-family ipv4 unicast`` (corpus: verified-capture n9kv 10.3.8,
        next-hop-self is an address-family child). Both spellings are mapped to
        the SAME session-level ``field:neighbor:<peer>:<attr>`` reset op the flat
        ``no neighbor X <attr>`` line would emit (parity), through the shared
        ``_emit_bgp_neighbor_no_op`` path — mirroring how the POSITIVE AF policy
        is flattened onto the session neighbor (CCR-0077). Direct-child neighbor
        blocks only (``find_child_objects``), so global-scope neighbors are never
        swept into a VRF instance and vice-versa.
        """
        for nb_obj in bgp_or_af_obj.find_child_objects(r"^\s+neighbor\s+\S+"):
            m = re.match(r"^\s+neighbor\s+(\S+)", nb_obj.text)
            if not m:
                continue
            peer = m.group(1)
            # Only real IP neighbors; skip peer-group / template names.
            try:
                IPv4Address(peer)
            except ValueError:
                from ipaddress import IPv6Address
                try:
                    IPv6Address(peer)
                except ValueError:
                    continue

            def _walk_no_lines(node):
                for child in node.children:
                    nm = re.match(r"^\s+no\s+(\S.*)$", child.text)
                    if nm:
                        self._emit_bgp_neighbor_no_op(
                            peer, nm.group(1).strip(), child, asn, vrf, pg_names
                        )

            # Session-level negations (direct children of the neighbor block)…
            _walk_no_lines(nb_obj)
            # …and address-family sub-block negations (where NX-OS nests
            # next-hop-self / send-community / route-map / prefix-list).
            for child in nb_obj.children:
                if re.match(r"^\s+address-family\s+", child.text):
                    _walk_no_lines(child)

        # Peer-group / template-peer address-family DEACTIVATION (CCR-0148):
        # ``no address-family <afi> [<safi>]`` under a ``template peer NAME``
        # block removes the whole keyed (afi, safi) AF entry from the
        # peer-group.  Direct children of the template block only
        # (``find_child_objects``), scope="peer_group" so the entrp replay keys
        # into ``BGPPeerGroup.address_families`` rather than a neighbor's.
        for tmpl_obj in bgp_or_af_obj.find_child_objects(
            r"^\s+template\s+peer\s+\S+\s*$"
        ):
            tm = re.match(r"^\s+template\s+peer\s+(\S+)\s*$", tmpl_obj.text)
            if not tm:
                continue
            pg_name = tm.group(1)
            for child in tmpl_obj.children:
                am = re.match(
                    r"^\s+no\s+address-family\s+(\S+)(?:\s+(\S+))?\s*$", child.text
                )
                if am:
                    self._emit_bgp_neighbor_af_removal(
                        pg_name, "peer_group", am.group(1), am.group(2) or "",
                        child, asn, vrf,
                    )

    def _parse_bgp_neighbors(self, bgp_obj) -> list["BGPNeighbor"]:
        """Parse BGP neighbors, adding NX-OS nested-block / ``inherit peer`` support.

        NX-OS uses two neighbor forms:

        1. **Inline** (IOS-compatible)::

               neighbor 10.0.0.2 remote-as 65001
                 description spine-link
                 password 3 abc123

        2. **Nested block** (NX-OS native)::

               neighbor 10.0.0.2
                 inherit peer LEAF
                 description spine-link

        ``super()`` handles form 1 but only captures the inline command
        (``remote-as``).  This override:

        - **Form 1b**: re-scans inline neighbors that have indented children
          and merges child attributes (description, password, route-map, etc.)
          into the existing neighbor objects — no new objects, no duplicates.
        - **Form 2**: scans bare ``neighbor <ip>`` lines and builds new
          neighbor objects from their child blocks.
        """
        from confgraph.models.bgp import BGPNeighbor, BGPTimers

        # --- Form 1: inline neighbors via IOS parser ---
        neighbors = super()._parse_bgp_neighbors(bgp_obj)
        seen_ips = {str(n.peer_ip) for n in neighbors}

        # --- Form 1b: backfill children for inline neighbors ---
        # super() captured remote-as from the inline line but missed indented
        # child attributes.  Re-scan inline neighbor lines and merge children.
        neighbor_by_ip = {str(n.peer_ip): n for n in neighbors}
        for nb_obj in bgp_obj.find_child_objects(r"^\s+neighbor\s+\S+\s+remote-as\s+"):
            m = re.match(r"^\s+neighbor\s+(\S+)\s+remote-as\s+", nb_obj.text)
            if not m:
                continue
            peer_ip_str = m.group(1)
            existing = neighbor_by_ip.get(peer_ip_str)
            if existing is None or not nb_obj.all_children:
                continue
            nd = self._parse_nxos_neighbor_children(nb_obj)
            # Merge non-default values into the existing neighbor
            for key, val in nd.items():
                if key == "remote_as":
                    continue  # already set by super()
                default = False if isinstance(val, bool) else None
                if val != default:
                    setattr(existing, key, val)

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

            nd = self._parse_nxos_neighbor_children(nb_obj)

            # CCR-0159: keep any block that carries PARSED CONTENT even
            # without remote-as/peer-group — proposal snippets legitimately
            # omit remote-as when attaching policy to an EXISTING neighbor
            # (on a real device the snippet applies to it; device-verified
            # reality check in the CCR).  remote_as=None with
            # source="inherited" below is the established non-clobbering
            # stub (CCR-0170): the merge skips it
            # (merger.py field-level exception) and topology treats it as
            # unresolved.  Only a truly EMPTY bare ``neighbor <ip>`` stub is
            # still dropped (unchanged pre-CCR behavior).
            has_content = bool(nd["address_families"]) or any(
                v for k, v in nd.items() if k != "address_families"
            )
            if (nd["remote_as"] is None and nd["remote_as_source"] is None
                    and nd["peer_group"] is None
                    and not nd["shutdown"] and not has_content):
                continue

            # No remote-as stated -> None with source="inherited"
            # (CCR-0170 — the string sentinel retired).
            remote_as = nd["remote_as"]
            remote_as_source = (
                nd["remote_as_source"]
                if remote_as is not None or nd["remote_as_source"]
                else "inherited"
            )

            seen_ips.add(peer_ip_str)
            neighbors.append(BGPNeighbor(
                peer_ip=peer_ip,
                remote_as=remote_as,
                remote_as_source=remote_as_source,
                peer_group=nd["peer_group"],
                description=nd["description"],
                update_source=nd["update_source"],
                ebgp_multihop=nd["ebgp_multihop"],
                password=nd["password"],
                password_encryption_type=nd["password_encryption_type"],
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
                default_originate=nd["default_originate"],
                default_originate_route_map=nd["default_originate_route_map"],
                address_families=nd["address_families"],
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
                # CCR-0170: inheritance fills the VALUE only; the
                # parse-time provenance (source="inherited") stays.
                if neighbor.remote_as is None and pg.remote_as is not None:
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

        # NX-OS native OSPF-VRF: nested ``router ospf N`` → ``vrf NAME`` blocks
        # (CCR-0032). Same VRF-block traversal as BGP-VRF (_iter_router_vrf_blocks).
        instances.extend(self._parse_ospf_vrf_instances(parse))

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
        host_reachability = None
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

                m = re.match(r"host-reachability\s+protocol\s+(\S+)", t)
                if m:
                    host_reachability = m.group(1)
                    continue

                m = re.match(r"member\s+vni\s+(\d+)(?:\s+associate-vrf)?", t)
                if m:
                    vni = int(m.group(1))
                    is_l3 = "associate-vrf" in t
                    # Parse sub-attributes from VNI member children
                    mcast_group = None
                    suppress_arp = False
                    ingress_replication = None
                    ingress_replication_peers: list[str] = []
                    for sub in child.children:
                        raw_lines.append(sub.text)
                        line_numbers.append(sub.linenum)
                        st = sub.text.strip()
                        mg = re.match(r"mcast-group\s+(\S+)", st)
                        if mg:
                            mcast_group = mg.group(1)
                            continue
                        if st == "suppress-arp":
                            suppress_arp = True
                            continue
                        ir = re.match(r"ingress-replication\s+protocol\s+(\S+)", st)
                        if ir:
                            ingress_replication = ir.group(1)
                            continue
                        # Static head-end replication: each remote VTEP is a
                        # sibling 'peer-ip <ip>' line under 'member vni' (same
                        # config-if-vni submode as the protocol line).
                        # doc-only (NX-OS VXLAN Config Guide 10.5(x)); parsed
                        # defensively, no verified fixture ships for it.
                        pip = re.match(r"peer-ip\s+(\S+)", st)
                        if pip:
                            ingress_replication_peers.append(pip.group(1))
                            continue
                    vni_mappings.append(VXLANVniMapping(
                        vni=vni,
                        vlan=vni_to_vlan.get(vni),
                        # vlan is a vn-segment JOIN, not a declaration on this
                        # line — binding_declared stays False (CCR-0166).
                        # associate_vrf replaces the retired "(L3)" vrf
                        # sentinel; vrf stays None.
                        associate_vrf=is_l3,
                        mcast_group=mcast_group,
                        suppress_arp=suppress_arp,
                        ingress_replication=ingress_replication,
                        ingress_replication_peers=ingress_replication_peers,
                    ))
                    continue

        return VXLANConfig(
            object_id="vxlan",
            raw_lines=raw_lines,
            source_os=self.os_type,
            line_numbers=line_numbers,
            source_interface=source_interface,
            vni_mappings=vni_mappings,
            host_reachability=host_reachability,
        )

    # -------------------------------------------------------------------
    # EVPN control-plane
    # -------------------------------------------------------------------

    def parse_evpn(self) -> "EVPNConfig | None":
        """Parse the NX-OS MP-BGP EVPN control-plane (L2VNI + L3VNI).

        Two control-plane surfaces feed the model:

        1. The top-level ``evpn`` block — **L2VNI (MAC-VRF) only**::

               evpn
                 vni 90901 l2          # L2VNI (MAC-VRF)
                   rd auto
                   route-target import auto
                   route-target export auto

           The top-level ``evpn`` block carries only L2VNIs; there is NO
           ``vni <n> l3`` form here (vendor doc + validator re-fetch). L2VNIs go
           to :attr:`EVPNConfig.l2vnis`; this path is byte-identical to CCR-0087.

        2. The **canonical L3VNI control-plane** under ``vrf context`` (CCR-0118),
           where the L3VNI's tenant-VRF RD / route-targets actually live::

               vrf context TENANT
                 vni 50001                                   # L3VNI ↔ VRF join
                 rd 65001:50001
                 address-family ipv4 unicast
                   route-target both 65001:50001 evpn        # trailing `evpn`
                 address-family ipv6 unicast
                   route-target both 65001:50001 evpn

           The ``vni <n>`` declaration (traditional; the new SVI-less mode spells
           it ``vni <n> L3``) ties the L3VNI to its tenant VRF. The trailing
           ``evpn`` keyword marks the L3VNI/EVPN route-targets — captured
           DISTINCTLY here and joined by VNI; plain ``route-target`` lines (no
           ``evpn`` suffix) are the L3VPN RTs and are left entirely to
           :meth:`parse_vrfs` (untouched — no hijack).

        The NVE binding ``member vni <n> associate-vrf`` (parsed by
        :meth:`parse_vxlan`, which sets the mapping's typed ``associate_vrf``
        flag — CCR-0166, formerly the ``"(L3)"`` vrf sentinel) is reused as the
        ``associate_vrf`` signal — that VNI is fabric-associated as an L3VNI.

        JOIN: one :class:`EVPNL3VNI` per VNI number. ``rd``, route-targets and
        ``vrf`` come from the ``vrf context`` source (``both`` → both lists,
        ``auto`` kept literal); ``associate_vrf`` from the NVE signal. The L3VNI
        never draws rd/route-targets from the ``evpn`` block (no such form).

        Device-emitted behaviour honoured (n9kv 10.5(5), CCR-0087):
        - ``route-target both <rt>`` populates BOTH lists; ``auto`` is kept as the
          literal token.

        DOC-GROUNDED CAVEAT (CCR-0118): the L2VNI form is device-verified; the
        L3VNI's ``vrf context`` emitted ``rd`` / ``route-target ... evpn`` block is
        NOT captured on the 9000v — grounded in the Cisco Nexus 9000 VXLAN Config
        Guide 10.5(x) (promotable later). Fields are optional so partial
        declarations still parse.
        """
        from confgraph.models.evpn import EVPNConfig, EVPNL2VNI, EVPNL3VNI

        parse = self._get_parse_obj()
        evpn_objs = parse.find_objects(r"^evpn\s*$")

        l2vnis: list[EVPNL2VNI] = []
        raw_lines: list[str] = []
        line_numbers: list[int] = []
        # L3VNI accumulator keyed by VNI number — merged across the three sources.
        l3_by_vni: dict[int, dict] = {}

        def _l3_entry(vni: int) -> dict:
            return l3_by_vni.setdefault(
                vni,
                {"rd": None, "rt_import": [], "rt_export": [], "vrf": None,
                 "associate_vrf": False},
            )

        def _add_rt(bucket: list[str], value: str) -> None:
            if value not in bucket:
                bucket.append(value)

        # --- Source 1: the top-level `evpn` block (L2VNI ONLY) -----------------
        # The top-level `evpn` block carries only L2VNIs (`vni <n> l2`). The
        # vendor doc (and the validator's re-fetch) confirm there is NO
        # `vni <n> l3` form here — the L3VNI control-plane lives under
        # `vrf context` (Source 2). An `l3` keyword under `evpn` is therefore not
        # a device-emitted form and is deliberately ignored. This path is
        # byte-identical to CCR-0087.
        for evpn_obj in evpn_objs:
            raw_lines.append(evpn_obj.text)
            line_numbers.append(evpn_obj.linenum)
            for vni_child in evpn_obj.children:
                raw_lines.append(vni_child.text)
                line_numbers.append(vni_child.linenum)
                # ``vni <n> l2`` binds an L2VNI (MAC-VRF); ``l3`` would be an
                # L3VNI, but that form does not exist under `evpn` (see above).
                m = re.match(r"vni\s+(\d+)\s+l2\b", vni_child.text.strip())
                if not m:
                    continue
                vni = int(m.group(1))
                rd = None
                rt_import: list[str] = []
                rt_export: list[str] = []
                for sub in vni_child.children:
                    raw_lines.append(sub.text)
                    line_numbers.append(sub.linenum)
                    st = sub.text.strip()
                    rd_m = re.match(r"rd\s+(\S+)", st)
                    if rd_m:
                        rd = rd_m.group(1)
                        continue
                    rt_m = re.match(r"route-target\s+(import|export|both)\s+(\S+)", st)
                    if rt_m:
                        direction, value = rt_m.group(1), rt_m.group(2)
                        if direction in ("import", "both"):
                            rt_import.append(value)
                        if direction in ("export", "both"):
                            rt_export.append(value)
                l2vnis.append(EVPNL2VNI(
                    vni=vni,
                    rd=rd,
                    route_target_import=rt_import,
                    route_target_export=rt_export,
                ))

        # --- Source 2: the canonical `vrf context` L3VNI control-plane ----------
        # An L3VNI is declared with `vni <n>` directly under `vrf context NAME`;
        # its RD and the `evpn`-suffixed route-targets (under `address-family`)
        # are the tenant-VRF EVPN control-plane. Plain (non-`evpn`) RTs are left
        # to parse_vrfs — matched distinctly here by the trailing `evpn` token.
        for vrf_obj in parse.find_objects(r"^vrf\s+context\s+(\S+)"):
            vrf_name = self._extract_match(vrf_obj.text, r"^vrf\s+context\s+(\S+)")
            if not vrf_name:
                continue
            vni_children = vrf_obj.find_child_objects(r"^\s+vni\s+(\d+)\b")
            if not vni_children:
                continue  # no L3VNI declared in this VRF context
            for vni_ch in vni_children:
                vm = re.match(r"vni\s+(\d+)\b", vni_ch.text.strip())
                if not vm:
                    continue
                vni = int(vm.group(1))
                entry = _l3_entry(vni)
                entry["vrf"] = vrf_name
                raw_lines.append(vni_ch.text)
                line_numbers.append(vni_ch.linenum)
                # RD directly under `vrf context` (shared L3VPN/L3VNI RD).
                rd_ch = vrf_obj.find_child_objects(r"^\s+rd\s+(\S+)")
                if rd_ch and entry["rd"] is None:
                    entry["rd"] = self._extract_match(rd_ch[0].text, r"^\s+rd\s+(\S+)")
                # `evpn`-suffixed route-targets under any address-family child.
                for child in vrf_obj.all_children:
                    ct = child.text.strip()
                    rt_m = re.match(
                        r"route-target\s+(both|import|export)\s+(\S+)\s+evpn\b", ct
                    )
                    if not rt_m:
                        continue
                    direction, value = rt_m.group(1), rt_m.group(2)
                    if direction in ("import", "both"):
                        _add_rt(entry["rt_import"], value)
                    if direction in ("export", "both"):
                        _add_rt(entry["rt_export"], value)
                    raw_lines.append(child.text)
                    line_numbers.append(child.linenum)

        # --- Source 3: NVE `member vni <n> associate-vrf` (reuse parse_vxlan) ---
        # parse_vxlan already flags an L3VNI membership via the typed
        # `associate_vrf` field (CCR-0166; formerly the "(L3)" vrf sentinel);
        # reuse that signal rather than re-parsing the NVE line. Enriches known
        # L3VNIs only (an associate-vrf line alone does not synthesise a
        # control-plane).
        vxlan = self.parse_vxlan()
        if vxlan is not None:
            for mapping in vxlan.vni_mappings:
                if mapping.associate_vrf and mapping.vni in l3_by_vni:
                    l3_by_vni[mapping.vni]["associate_vrf"] = True

        if not evpn_objs and not l3_by_vni:
            return None

        l3vnis: list[EVPNL3VNI] = [
            EVPNL3VNI(
                vni=vni,
                rd=data["rd"],
                route_target_import=data["rt_import"],
                route_target_export=data["rt_export"],
                vrf=data["vrf"],
                associate_vrf=data["associate_vrf"],
            )
            for vni, data in l3_by_vni.items()
        ]

        return EVPNConfig(
            object_id="evpn",
            raw_lines=raw_lines,
            source_os=self.os_type,
            line_numbers=line_numbers,
            l2vnis=l2vnis,
            l3vnis=l3vnis,
        )

    # -------------------------------------------------------------------
    # NetFlow — flow record / flow exporter / flow monitor
    # -------------------------------------------------------------------

    def parse_netflow(self) -> "NetFlowConfig | None":
        """Parse Flexible NetFlow flow record / exporter / monitor blocks.

        NX-OS models NetFlow as three named top-level block types (unlike the
        IOS ``ip flow-export`` singleton the base :meth:`parse_netflow`
        handles)::

            flow record <name>
              match ipv4 source address
              collect counter bytes
            flow exporter <name>
              destination <ip> [use-vrf <vrf>]
              source <interface>
              version 9
            flow monitor <name>
              record <record>
              exporter <exporter>

        Returns ``None`` when the device carries none of the three blocks, so
        the ``netflow`` field stays absent on configs without Flexible
        NetFlow. Syntax is doc-verified from
        ``syntax-corpus/nxos/netflow.yaml`` (the emitted running-config form
        is not yet hardware-captured — the n9kv 10.5(5) probe rejected
        ``feature netflow``).
        """
        parse = self._get_parse_obj()

        records: list[NetFlowRecord] = []
        for obj in parse.find_objects(r"^flow\s+record\s+"):
            name = self._extract_match(obj.text, r"^flow\s+record\s+(\S+)")
            if not name:
                continue
            match_fields: list[str] = []
            collect_fields: list[str] = []
            for child in obj.children:
                text = child.text.strip()
                mm = re.match(r"^match\s+(.+)$", text)
                if mm:
                    match_fields.append(mm.group(1).strip())
                    continue
                cm = re.match(r"^collect\s+(.+)$", text)
                if cm:
                    collect_fields.append(cm.group(1).strip())
            records.append(
                NetFlowRecord(
                    name=name,
                    match_fields=match_fields,
                    collect_fields=collect_fields,
                )
            )

        exporters: list[NetFlowExporter] = []
        for obj in parse.find_objects(r"^flow\s+exporter\s+"):
            name = self._extract_match(obj.text, r"^flow\s+exporter\s+(\S+)")
            if not name:
                continue
            destination = None
            use_vrf = None
            source = None
            version = None
            for child in obj.children:
                text = child.text.strip()
                dm = re.match(
                    r"^destination\s+(\S+)(?:\s+use-vrf\s+(\S+))?", text
                )
                if dm:
                    destination = dm.group(1)
                    if dm.group(2):
                        use_vrf = dm.group(2)
                    continue
                sm = re.match(r"^source\s+(\S+)", text)
                if sm:
                    source = sm.group(1)
                    continue
                vm = re.match(r"^version\s+(\d+)", text)
                if vm:
                    try:
                        version = int(vm.group(1))
                    except ValueError:
                        pass
            exporters.append(
                NetFlowExporter(
                    name=name,
                    destination=destination,
                    use_vrf=use_vrf,
                    source=source,
                    version=version,
                )
            )

        monitors: list[NetFlowMonitor] = []
        for obj in parse.find_objects(r"^flow\s+monitor\s+"):
            name = self._extract_match(obj.text, r"^flow\s+monitor\s+(\S+)")
            if not name:
                continue
            record = None
            exporter = None
            for child in obj.children:
                text = child.text.strip()
                rm = re.match(r"^record\s+(\S+)", text)
                if rm:
                    record = rm.group(1)
                    continue
                em = re.match(r"^exporter\s+(\S+)", text)
                if em:
                    exporter = em.group(1)
            monitors.append(
                NetFlowMonitor(name=name, record=record, exporter=exporter)
            )

        if not records and not exporters and not monitors:
            return None

        return NetFlowConfig(
            object_id="netflow",
            source_os=self.os_type,
            flow_records=records,
            flow_exporters=exporters,
            flow_monitors=monitors,
        )

    # -------------------------------------------------------------------
    # VPC
    # -------------------------------------------------------------------

    def parse_control_plane(self) -> "ControlPlaneConfig | None":
        """Parse the ``control-plane`` (CoPP) service-policy binding.

        Handles the bare CoPP header::

            control-plane
              service-policy input PM_COPP

        Only the attaching ``service-policy input <PM>`` is modeled — the
        policed traffic itself lives in the referenced ``policy-map type
        control-plane`` (see parse_policy_maps). VDC scope is a separate
        top-level ``vdc <name> id <n>`` block, not part of this header, and
        is out of scope here.
        """
        parse = self._get_parse_obj()
        cp_objs = parse.find_objects(r"^control-plane\s*$")
        if not cp_objs:
            return None

        cp_obj = cp_objs[0]
        service_policy_input = None
        for child in cp_obj.children:
            cm = re.match(r"^\s*service-policy\s+input\s+(\S+)", child.text)
            if cm:
                service_policy_input = cm.group(1)

        if service_policy_input is None:
            return None

        return ControlPlaneConfig(
            service_policy_input=service_policy_input,
        )

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
        peer_gateway = False

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

            # peer-gateway is default-off; the device emits the bare line when
            # enabled and `no peer-gateway` (or absence) when disabled.
            if re.match(r"peer-gateway\b", t):
                peer_gateway = True
                continue
            if re.match(r"no\s+peer-gateway\b", t):
                peer_gateway = False
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
            peer_gateway=peer_gateway,
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
          - ``no host-reachability protocol`` inside ``interface nve`` → ``field:vxlan:host_reachability``
          - ``no peer-keepalive`` inside ``vpc domain``      → ``field:vpc:peer_keepalive_*``
          - ``no ip route ...`` inside ``vrf context NAME``  → ``static:NAME:<dest>[:<nh_spec>]``
          - ``no vrf context NAME`` (top-level)              → ``field:vrfs:NAME``

        The inherited static-route handling accepts both the traditional
        ``DEST MASK`` and the NX-OS-native CIDR ``DEST/PLEN`` forms (see
        ``IOSParser._static_route_deletion_tombstone``); the ``vrf context``
        walk below mirrors the structure of ``parse_static_routes``, which is
        where NX-OS VRF statics live (there is no ``ip route vrf NAME ...``
        keyword form on NX-OS).
        """
        tombstones = super().parse_deletion_commands()
        parse = self._get_parse_obj()

        # --- whole-VRF deletions ---
        # ``no vrf context GUEST`` → ``field:vrfs:GUEST``
        # (NX-OS equivalent of the IOS ``no vrf definition`` walk in the base
        # parser; CCR confgraph_vrf_rt_removal_tombstones.md).  The nested
        # ``no route-target`` / ``no rd`` removals inside ``vrf context``
        # blocks are handled by the inherited NESTED_DELETION_RULES traversal —
        # the registry's parent pattern matches both VRF block spellings.
        for obj in parse.find_objects(r"^no\s+vrf\s+context\s+"):
            m = re.match(r"^no\s+vrf\s+context\s+(\S+)", obj.text.strip())
            if m:
                # Change-IR family 7a (CCR Appendix R): queue the native
                # line-numbered OBJECT_DELETE via the shared IOS helper and
                # regenerate the tombstone FROM it (single source, byte-exact).
                # super().parse_deletion_commands() already initialised
                # _pending_native_vrf_ops.
                self._queue_native_vrf_delete(
                        f"field:vrfs:{m.group(1)}", obj
                    )

        # --- VRF static route deletions (nested under vrf context NAME) ---
        for vrf_obj in parse.find_objects(r"^vrf\s+context\s+(\S+)"):
            vrf_name = self._extract_match(vrf_obj.text, r"^vrf\s+context\s+(\S+)")
            if not vrf_name:
                continue
            for child in vrf_obj.all_children:
                m = re.match(r"no\s+ip\s+route\s+(.+)$", child.text.strip())
                if not m:
                    continue
                tombstone = self._static_route_deletion_tombstone(
                    vrf_name, m.group(1).split()
                )
                if tombstone:
                    # Change-IR family 4 (CCR Appendix G): queue the native
                    # LIST_REMOVE op and regenerate the tombstone from it
                    # (single source).  super().parse_deletion_commands()
                    # already initialised _pending_native_static_ops.
                    self._queue_native_static_delete(tombstone, child)

        # --- VXLAN nested deletions (under interface nve) ---
        # Change-IR family 8b (CCR Appendix U): tombstones regenerated FROM the
        # native removal ops via the shared IOS queue helper (byte-exact, same
        # walk positions).  super().parse_deletion_commands() already
        # initialised _pending_native_singleton_ops.
        for nve_obj in parse.find_objects(r"^interface\s+nve\d+"):
            for child in nve_obj.children:
                t = child.text.strip()
                m = re.match(r"no\s+member\s+vni\s+(\d+)", t)
                if m:
                    self._queue_native_singleton_removal(
                            f"field:vxlan:vni:{m.group(1)}", child
                        )
                if re.match(r"no\s+host-reachability\s+protocol\b", t):
                    self._queue_native_singleton_removal(
                            "field:vxlan:host_reachability", child
                        )

        # --- vPC peer-keepalive removal (nested under vpc domain) ---
        # ONE ``no peer-keepalive`` line fans out to THREE scalar-reset
        # tombstones — three native UNSETs queued at the same line, twins
        # regenerated in the same order (family 8b).
        for vpc_obj in parse.find_objects(r"^vpc\s+domain\s+\d+"):
            for child in vpc_obj.children:
                t = child.text.strip()
                if re.match(r"no\s+peer-keepalive\b", t):
                    for _vpc_ts in (
                        "field:vpc:peer_keepalive_destination",
                        "field:vpc:peer_keepalive_source",
                        "field:vpc:peer_keepalive_vrf",
                    ):
                        self._queue_native_singleton_removal(
                                _vpc_ts, child
                            )

        # --- EVPN control-plane removals (CCR-0145) --------------------------
        # Context-aware ``no`` forms under the ``evpn`` block (L2VNI) and under
        # ``vrf context`` (L3VNI).  The device renders every removal by OMISSION
        # (never a ``no`` line — capture 2026-07-30 n9kv 10.5(5)); these
        # tombstones therefore serve PROPOSAL text only.  Three-level nesting
        # (``evpn / vni N l2 / no route-target …``) and the L3VNI's VNI-on-a-
        # sibling-line shape are why this is a bespoke walk, not a flat
        # NESTED_DELETION_RULES entry.  All ops fall through both change-IR modes
        # to the engine's ``field:evpn:…`` deletion handlers (CCR-0145 entrp
        # half); the change-IR verbs are the ``_TOP_TOMBSTONE_VERBS`` rows.
        self._parse_evpn_deletions(parse)

        return tombstones

    # NX-OS RT line under an ``evpn / vni N l2`` block or a ``vrf context``
    # address-family: ``[no] route-target import|export|both <rt> [evpn]``.
    # The trailing ``evpn`` token is matched CASE-INSENSITIVELY (CCR-0145 F3, WI-E2):
    # the NX-OS CLI accepts ``EVPN``, and a case-only mismatch used to fail this
    # anchored match outright — dropping the removal ENTIRELY, including the vrfs
    # half (the inherited plain vrfs patterns end ``(\\S+)\\s*$``, so an
    # ``... X EVPN`` line does not reach them either).  Callers must ``lower()``
    # group(3) before comparing.  The POSITIVE parse (``parse_evpn``, the
    # ``route-target ... evpn`` capture) stays case-sensitive — widening it would
    # move parse output, which this WI may not do; residual disclosed.
    _EVPN_RT_REMOVAL = re.compile(
        r"^no\s+route-target\s+(import|export|both)\s+(\S+)(?:\s+((?i:evpn)))?\s*$"
    )

    # ``no rd [<value>]`` under an ``evpn / vni N l2`` block or a ``vrf context``.
    # The optional value is CONSTRAINED to the RD grammar — ``auto`` or a
    # colon-bearing ``ASN2:NN`` / ``ASN4:NN`` / ``IPV4:NN`` (CCR-0145 V-2): the
    # former ``(?:\s+\S+)?`` accepted ANY single trailing token, so ``no rd
    # bogus`` cleared a real RD.  That was inert before the WI-E2 replay landed
    # and state-changing after it — the §6.2 grammar-token-in-value-position
    # class.  A wrong-but-well-formed value (``no rd 65432:999`` against a
    # different configured RD) still fires: value-blind negation is a separate,
    # pre-existing, disclosed class, not this fix's business.
    _RD_REMOVAL = re.compile(r"^no\s+rd(?:\s+(?:auto|\S+:\S+))?\s*$")

    def _parse_evpn_deletions(self, parse) -> None:
        """Queue native ops for EVPN L2VNI/L3VNI ``no`` removals (CCR-0145).

        Emission map (VNI = ``N``, RT value = ``X``, direction = ``D``):

        * ``evpn / vni N l2 / no route-target D X``
          -> ``field:evpn:l2vnis:N:route_target_D:X`` (LIST_REMOVE; ``both``
          clears both lists in the engine accessor).
        * ``evpn / vni N l2 / no rd``        -> ``field:evpn:l2vnis:N:rd`` (UNSET).
        * ``evpn / no vni N l2|l3``          -> ``field:evpn:l2vnis|l3vnis:N``
          (OBJECT_DELETE).  ``l3`` under ``evpn`` is not a device-emitted
          positive form (L3VNIs live under ``vrf context``); the tombstone is
          accepted permissively so a proposal that spells it still reaches a
          removal — disclosed.

        L3VNI (under ``vrf context NAME``; VNI from the sibling positive
        ``vni N`` line) is the N1 copy-coherence surface — one device line
        populates BOTH ``VRFConfig.route_target_*`` (parse_vrfs ignores the
        trailing ``evpn`` token) and the authoritative ``EVPNL3VNI.route_target_*``
        (parse_evpn keys off ``vni``).  The ``evpn``-suffixed removal is a
        DUAL-TOMBSTONE clearing both copies:

        * ``vrf context NAME / … / no route-target D X evpn``
          -> ``field:evpn:l3vnis:N:route_target_D:X`` (evpn copy) AND
          ``field:vrfs:NAME:route_target_D:X`` (vrfs copy — always, matching
          what parse_vrfs captured).
        * ``vrf context NAME / no rd``  -> ``field:evpn:l3vnis:N:rd`` (evpn copy
          only; the ``field:vrfs:NAME:rd`` twin is already emitted by the
          inherited vrfs NESTED_DELETION_RULES walk).

        BY-VRF FALLBACK (CCR-0145 V-1).  The VNI above comes from a sibling
        POSITIVE ``vni N`` line, but product proposals are PARTIAL SNIPPETS —
        the common real shape is a ``vrf context`` block containing ONLY the
        ``no`` line, with no ``vni N`` to read.  Keying on a VNI the snippet
        never mentions would emit the vrfs half alone and leave the two parsed
        copies incoherent — precisely the N1 harm this CCR exists to close.  So
        when no VNI is in scope the evpn half is emitted VRF-NAME-keyed instead:

        * ``field:evpn:l3vnis_by_vrf:NAME:route_target_D:X``
        * ``field:evpn:l3vnis_by_vrf:NAME:rd``

        The engine resolves those against the BASELINE's L3VNIs by ``.vrf``
        match (it has the full config; the proposal does not).  Both keyings
        emit the SAME dual-tombstone pair, so copy coherence no longer depends
        on how much context the author happened to restate.

        The whole-VNI delete keeps requiring an explicit number: ``no vni N``
        names its own key, so there is nothing to fall back from.
        * ``vrf context NAME / no vni N`` -> ``field:evpn:l3vnis:N``
          (OBJECT_DELETE; evpn copy only — ``VRFConfig`` has no vni field).

        The PLAIN (non-``evpn``) ``no route-target D X`` under ``vrf context`` is
        NOT touched here (it is L3VPN, handled by the inherited vrfs walk); the
        ``_EVPN_RT_REMOVAL`` capture requires the trailing ``evpn`` token in the
        vrf-context branch, and the inherited plain patterns end ``(\\S+)\\s*$``
        so they never fire on an ``evpn``-suffixed line — the two never overlap.
        """
        # --- L2VNI: the top-level `evpn` block -----------------------------
        for evpn_obj in parse.find_objects(r"^evpn\s*$"):
            for vni_child in evpn_obj.children:
                ct = vni_child.text.strip()
                # Whole-VNI removal: `no vni N l2|l3` (direct evpn child).
                # END-ANCHORED (CCR-0145 F2, WI-E2): a bare ``\b`` let trailing
                # garbage (`no vni 5 l2 bogus`) fire a real OBJECT_DELETE.  The
                # device form takes no further tokens, so anything after the
                # l2|l3 keyword means the line is not this command.
                dm = re.match(r"^no\s+vni\s+(\d+)\s+(l2|l3)\s*$", ct)
                if dm:
                    coll = "l2vnis" if dm.group(2) == "l2" else "l3vnis"
                    self._queue_native_keyed_removal(
                        f"field:evpn:{coll}:{dm.group(1)}", vni_child
                    )
                    continue
                # Per-entry removals nested under `vni N l2`.
                vm = re.match(r"^vni\s+(\d+)\s+l2\b", ct)
                if not vm:
                    continue
                vni = vm.group(1)
                for sub in vni_child.children:
                    st = sub.text.strip()
                    rtm = self._EVPN_RT_REMOVAL.match(st)
                    if rtm and rtm.group(3) is None:  # no `evpn` suffix under evpn block
                        self._queue_native_keyed_removal(
                            f"field:evpn:l2vnis:{vni}:route_target_{rtm.group(1)}:{rtm.group(2)}",
                            sub,
                        )
                        continue
                    if self._RD_REMOVAL.match(st):
                        self._queue_native_keyed_removal(
                            f"field:evpn:l2vnis:{vni}:rd", sub
                        )

        # --- L3VNI: the `vrf context` control-plane ------------------------
        for vrf_obj in parse.find_objects(r"^vrf\s+context\s+(\S+)"):
            vrf_name = self._extract_match(vrf_obj.text, r"^vrf\s+context\s+(\S+)")
            if not vrf_name:
                continue
            # The L3VNI VNI is the sibling POSITIVE `vni N` line (not `no vni`).
            l3_vni = None
            for child in vrf_obj.all_children:
                vpm = re.match(r"^vni\s+(\d+)\b", child.text.strip())
                if vpm:
                    l3_vni = vpm.group(1)
                    break
            for child in vrf_obj.all_children:
                ct = child.text.strip()
                # Whole-L3VNI removal: `no vni N` (traditional) or `no vni N L3`
                # (SVI-less mode) under vrf context — evpn copy only.
                nvm = re.match(r"^no\s+vni\s+(\d+)(?:\s+[lL]3)?\s*$", ct)
                if nvm:
                    self._queue_native_keyed_removal(
                        f"field:evpn:l3vnis:{nvm.group(1)}", child
                    )
                    continue
                # rd reset: the vrfs twin is emitted by the inherited walk; add
                # the authoritative evpn copy.  VNI-keyed when the proposal
                # declares one, else VRF-NAME-keyed (see the by-vrf note below).
                if self._RD_REMOVAL.match(ct):
                    self._queue_native_keyed_removal(
                        f"field:evpn:l3vnis:{l3_vni}:rd" if l3_vni is not None
                        else f"field:evpn:l3vnis_by_vrf:{vrf_name}:rd",
                        child,
                    )
                    continue
                # evpn-suffixed RT removal: DUAL-TOMBSTONE (both parsed copies).
                rtm = self._EVPN_RT_REMOVAL.match(ct)
                if rtm and (rtm.group(3) or "").lower() == "evpn":
                    direction, value = rtm.group(1), rtm.group(2)
                    # vrfs copy — parse_vrfs stored X under route_target_<D>,
                    # ignoring the trailing `evpn`; clear it (native vrf channel).
                    self._queue_native_vrf_removal(
                        f"field:vrfs:{vrf_name}:route_target_{direction}:{value}",
                        child,
                    )
                    # Authoritative EVPN copy.
                    self._queue_native_keyed_removal(
                        f"field:evpn:l3vnis:{l3_vni}:route_target_{direction}:{value}"
                        if l3_vni is not None
                        else f"field:evpn:l3vnis_by_vrf:{vrf_name}"
                             f":route_target_{direction}:{value}",
                        child,
                    )

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

    # DNS — VRF-scoped DNS (`ip name-server` / `ip domain-name` /
    # `ip domain-list` under `vrf context NAME`) is attributed to the VRF in
    # ``parse_vrfs`` (VRFConfig.name_servers / domain_name / domain_list),
    # NOT flattened into the global DNSConfig (CCR-0093). The inherited IOS
    # ``parse_dns`` reads only top-level lines, which is exactly the global
    # resolver set — so no NX-OS override is needed here.

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
