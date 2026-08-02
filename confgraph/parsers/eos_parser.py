"""Arista EOS configuration parser."""

import re
from ipaddress import IPv4Address, IPv4Interface, IPv4Network, IPv6Address, IPv6Interface, IPv6Network

from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.base import (
    PatternSet,
    _BASE_KNOWN_PATTERNS,
    _BASE_BEST_GUESS_KEYWORDS,
    apply_peer_group_command,
    _default_pg_data,
)
from confgraph.models.base import OSType, UnrecognizedBlock
from confgraph.models.line import LineType
from confgraph.models.ospf import OSPFConfig
from confgraph.models.bgp import BGPConfig, BGPNeighborAF
from confgraph.models.prefix_list import PrefixListConfig, PrefixListEntry
from confgraph.models.static_route import StaticRoute
from confgraph.models.acl import ACLConfig, ACLEntry
from confgraph.models.community_list import (
    CommunityListConfig,
    CommunityListEntry,
    ASPathListConfig,
    ASPathListEntry,
)


class EOSParser(IOSParser):
    """Parser for Arista EOS configurations.

    Arista EOS uses similar syntax to IOS but with some differences:
    - IP addresses use CIDR notation (e.g., 10.1.1.1/30) instead of mask
    - VRF syntax: "vrf instance NAME" instead of "vrf definition NAME"
    - Route-map syntax and ACL syntax are similar but with some enhancements
    - IS-IS configuration is more aligned with modern routing practices

    This parser inherits from IOSParser and overrides methods where
    EOS syntax differs from IOS.
    """

    # Replace IOS "vrf definition" with EOS "vrf instance".
    # Add EOS-specific top-level keywords that are handled by parse_* methods.
    # EOS states the EVPN L2VNI (MAC-VRF) as a ``vlan <id>`` sub-block DIRECTLY
    # under ``router bgp`` (device capture, cEOS 4.36.1F — see parse_evpn). That
    # is the ONE EOS-only child form the shared IOS ``router bgp`` child registry
    # (``_IOS_KNOWN_CHILD_PATTERNS``) does not list, so without this it lands in
    # ``unrecognized_blocks``. The pattern is anchored to EXACTLY the bare numeric
    # MAC-VRF header (``^vlan\s+\d+\s*$``) that ``parse_evpn`` consumes — a broad
    # ``^vlan\b`` would suppress unrecognized-flagging for ``vlan``-prefixed forms
    # we do NOT parse (``vlan-aware-bundle NAME``, malformed ``vlan`` lines),
    # turning a visible gap into an invisible one (the bleed the CCR warns of). The
    # sibling EVPN sub-blocks (``vrf NAME``, ``address-family evpn``) already match
    # the inherited ``^vrf`` / ``^address-family`` patterns. Extend only the
    # ``router bgp`` group; every other block group is inherited unchanged (CCR-0157).
    _KNOWN_CHILD_PATTERNS: list[tuple[str, list[str]]] = [
        (blk, pats + [r"^vlan\s+\d+\s*$"]) if blk.startswith(r"^router\s+bgp") else (blk, pats)
        for blk, pats in IOSParser._KNOWN_CHILD_PATTERNS
    ]

    _KNOWN_TOP_LEVEL_PATTERNS: list[str] = [
        p for p in _BASE_KNOWN_PATTERNS if p != r"^vrf definition"
    ] + [
        r"^vrf instance",          # EOS VRF syntax (EOS >= 4.23)
        r"^vrf definition",        # EOS VRF syntax (EOS < 4.23) — parse_vrfs handles both
        r"^management api",        # EOS: management api http-commands etc.
        r"^management ssh",        # EOS: management ssh
        r"^management telnet",     # EOS: management telnet
        r"^daemon",                # EOS: daemon TerminAttr etc.
        r"^event-handler",         # EOS: event-handler
        r"^policy-map",            # EOS: QoS policy-maps
        r"^class-map",             # EOS: QoS class-maps
        # EOS global routing/L2 control lines (not config objects, just mode enables)
        r"^ip routing",
        r"^no\s+ip routing",
        r"^ipv6\s+unicast-routing",
        r"^spanning-tree",
        r"^no\s+aaa",
        r"^aaa",
        r"^transceiver",
        r"^mpls",
        r"^mlag configuration",
    ]

    # Extend base best_guess keywords with EOS-specific ones
    _BEST_GUESS_KEYWORDS: list[tuple[str, str]] = _BASE_BEST_GUESS_KEYWORDS + [
        ("management api",  "management_api"),
        ("management ssh",  "management_ssh"),
        ("daemon",          "daemon"),
        ("event-handler",   "event_handler"),
        ("policy-map",      "qos"),
        ("class-map",       "qos"),
        ("hardware",        "hardware"),
        ("platform",        "platform"),
    ]

    # CCR-0031 EOS dialect extensions (§7.3 — extend the parent set, don't
    # re-implement). Interface VRF: IOS "vrf forwarding" (in-scope old EOS
    # spelling) is already in the parent set; EOS adds bare "vrf NAME".
    _IFACE_VRF_PATTERNS = IOSParser._IFACE_VRF_PATTERNS.extended(
        r"^\s+vrf\s+(?!forwarding\b)(?P<vrf>\S+)\s*$",
    )

    # Global VRF header: EOS-native "vrf instance" plus legacy "vrf definition".
    _VRF_HEADER_PATTERNS = PatternSet(
        r"^vrf\s+instance\s+(?P<name>\S+)",
        r"^vrf\s+definition\s+(?P<name>\S+)",
    )

    # OSPF process-wide BFD. BOTH spellings are Arista's, by version: EOS emits
    # "bfd all-interfaces" before 4.23 and "bfd default" from 4.23 on
    # (syntax-corpus/eos/ospf.yaml: bfd-default, versions.introduced 4.23).
    # Extending the parent set — rather than overriding the OSPF walk — is what
    # makes an EOS parser accept both without IOS accepting "bfd default".
    _OSPF_BFD_ALL_PATTERNS = IOSParser._OSPF_BFD_ALL_PATTERNS.extended(
        r"^\s+bfd\s+default\s*$",
    )

    # BGP best-path tie-break. EOS spells the router-id tie-break
    # ``bgp bestpath tie-break router-id`` where IOS spells it
    # ``bgp bestpath compare-routerid`` — same concept (model field
    # ``bestpath_options.compare_routerid``), different command word, and EOS
    # REJECTS the IOS spelling (verified cEOS 4.36.1F, CCR-0061). Extend only
    # that field's spelling tuple; the shared bestpath walk in IOSParser handles
    # positive and negated forms. The spelling stays EOS-scoped — IOS / NX-OS /
    # IOS-XR never see it — and the next vendor spelling is one more tuple entry.
    _BGP_BESTPATH_SPELLINGS = {
        **IOSParser._BGP_BESTPATH_SPELLINGS,
        "compare_routerid": IOSParser._BGP_BESTPATH_SPELLINGS["compare_routerid"]
        + (r"tie-break\s+router-id",),
    }

    # Interface BFD timers. Again BOTH spellings are Arista's and the difference
    # is EOS version, not vendor: EOS-4.13 emits "min_rx" (underscore, the same
    # as IOS/NX-OS) while modern EOS renders "min-rx" (hyphen)
    # (syntax-corpus/eos/bfd.yaml: bfd-interval-min-rx-multiplier). The parent
    # pattern carries the underscore, so EOS reads both.
    _IFACE_BFD_PATTERNS = IOSParser._IFACE_BFD_PATTERNS.extended(
        r"^\s+bfd\s+interval\s+(?P<interval>\d+)\s+min-rx\s+(?P<min_rx>\d+)"
        r"\s+multiplier\s+(?P<multiplier>\d+)",
    )

    # Interface PIM mode. EOS spells it "pim ipv4 sparse-mode" — the address family
    # is a keyword IN the command, where IOS puts "ip" (device capture, cEOS 4.36.1F).
    #
    # sparse-mode ONLY. On the device, `pim ipv4 bidirectional` and
    # `pim ipv4 border-router` are additional flags that COEXIST with
    # `pim ipv4 sparse-mode` on the same interface (all three emitted together), so a
    # lenient `pim ipv4 (?P<mode>\S+)` would report a PIM mode of "border-router"; and
    # `pim ipv4 dense-mode` is rejected outright — EOS has no dense mode.
    _IFACE_PIM_MODE_PATTERNS = IOSParser._IFACE_PIM_MODE_PATTERNS.extended(
        r"^\s+pim\s+ipv4\s+(?P<mode>sparse-mode)\b",
    )

    # Syslog server. EOS names the VRF BEFORE the host — "logging vrf MGMT host
    # 10.0.0.21" — where IOS-XE trails it after the address. Both dialects expose the
    # same `addr` / `vrf` groups, so the shared parse_syslog walk reads either. This
    # entry must come BEFORE nothing and AFTER everything: the inherited patterns
    # cannot match a line whose first token after `logging` is `vrf`, so appending is
    # safe (device capture, cEOS 4.36.1F).
    _SYSLOG_HOST_PATTERNS = IOSParser._SYSLOG_HOST_PATTERNS.extended(
        r"^logging\s+vrf\s+(?P<vrf>\S+)\s+host\s+(?P<addr>\S+)(?P<rest>.*)$",
    )

    # DNS domain. EOS emits "dns domain example.com"; it has no "ip domain-name"
    # (the device rejects it). The name-server line IS the IOS spelling — EOS just
    # always qualifies it with a VRF ("ip name-server vrf default 8.8.8.8"), which
    # the inherited walk already strips.
    _DNS_DOMAIN_PATTERNS = IOSParser._DNS_DOMAIN_PATTERNS.extended(
        r"^dns\s+domain\s+(?P<domain>\S+)",
    )

    # Interface → IS-IS membership. EOS: "isis enable CORE" (IOS: "ip router isis").
    _ISIS_IFACE_ENABLE_PATTERNS = IOSParser._ISIS_IFACE_ENABLE_PATTERNS.extended(
        r"^\s+isis\s+enable\s+(?P<tag>\S+)",
    )

    # Line / session config. EOS has no numbered `line vty` block — the same
    # concept (idle admin-session lifetime, and over which transport) is spelled
    # as top-level `management ssh|console|telnet` blocks with an `idle-timeout
    # <minutes>` child (verified cEOS 4.36.1F, CCR-0062). These four table
    # extensions are the ENTIRE EOS dialect; the shared parse_lines walk in
    # IOSParser is untouched (CCR-0038 built it; CCR-0044/0059 deleted EOS forks).
    #
    #   1. Header: match ONLY ssh|console|telnet, anchored `\s*$` so the sibling
    #      `management api http-commands|gnmi|netconf` blocks are NOT swallowed.
    #   2. console → CONSOLE inherited; ssh/telnet → the remote-session type (VTY).
    #   3. idle-timeout is the exec-timeout child by another name (minutes only,
    #      no seconds field).
    #   4. ssh/telnet name the transport as the block, so the header keyword is
    #      the transport_input value — EOS emits no `transport input` child here.
    _LINE_HEADER_PATTERNS = IOSParser._LINE_HEADER_PATTERNS.extended(
        r"^management\s+(?P<type>ssh|console|telnet)\s*$",
    )
    _LINE_TYPES = {
        **IOSParser._LINE_TYPES,
        "ssh": LineType.VTY,
        "telnet": LineType.VTY,
    }
    _LINE_EXEC_TIMEOUT_PATTERNS = IOSParser._LINE_EXEC_TIMEOUT_PATTERNS.extended(
        r"^\s+idle-timeout\s+(?P<minutes>\d+)",
    )
    _LINE_TRANSPORT_KEYWORDS = {"ssh", "telnet"}

    # Banners. EOS emits a BARE "banner motd" header — no delimiter character —
    # then the body, then a line containing the literal "EOF"
    # (syntax-corpus/eos/system.yaml: banner-motd). The body may contain "!",
    # so only the EOF line ends it. The inherited IOS delimiter form stays first
    # in the set: EOS accepts it, and the two are disjoint (IOS requires the
    # delimiter on the header line, EOS requires the header line to end there).
    _BANNER_PATTERNS: tuple[str, ...] = IOSParser._BANNER_PATTERNS + (
        r"^banner[ \t]+{type}[ \t]*\n(?P<text>.*?)\n[ \t]*EOF[ \t]*$",
    )

    # BGP neighbor/peer-group verb aliases. These two dict entries are the
    # *entire* EOS dialect of the Cisco-family neighbor walk (CCR-0044):
    #
    #   "maximum-routes"  — EOS-native spelling of IOS "maximum-prefix"
    #   "peer group"      — EOS emits two words where IOS emits "peer-group"
    #
    # Everything else (route-map / prefix-list / timers / local-as / password /
    # send-community / …) is spelled identically to IOS, so EOS runs the shared
    # walk in IOSParser._parse_bgp_neighbors and inherits every command that
    # walk learns. EOS used to fork the walk to translate "peer group"; the fork
    # then never learned the policy commands, and BGP neighbor policy silently
    # never reached the model.
    _BGP_CMD_ALIASES = {
        "maximum-routes": "maximum-prefix",
        "peer group": "peer-group",
    }

    def __init__(self, config_text: str):
        """Initialize EOS parser.

        Args:
            config_text: Raw configuration text
        """
        # Call the parent IOSParser __init__ but set OS type to EOS
        super().__init__(config_text, OSType.EOS)

    # EOS interface VRF binding is handled by the inherited pattern-set walk
    # in IOSParser._extract_interface_vrf; EOS contributes its dialects via
    # _IFACE_VRF_PATTERNS above (§7.3), so no method override is needed.

    def parse_interfaces(self) -> list:
        """Parse interfaces — patches CIDR IPv4 and EOS OSPF area.

        EOS uses ``ip address 10.0.0.1/30`` (CIDR) instead of IOS dotted-mask,
        and ``ip ospf area 0.0.0.0`` (no process ID) for interface OSPF binding.
        """
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

            # EOS CIDR primary: "ip address X.X.X.X/Y"
            cidr_children = intf_obj.find_child_objects(
                r"^\s+ip\s+address\s+(\d+\.\d+\.\d+\.\d+/\d+)"
            )
            # Filter out secondary
            cidr_primary = [
                c for c in cidr_children if "secondary" not in c.text.lower()
            ]
            if cidr_primary:
                m = re.search(
                    r"^\s+ip\s+address\s+(\d+\.\d+\.\d+\.\d+/\d+)",
                    cidr_primary[0].text,
                )
                if m:
                    try:
                        intf_cfg.ip_address = IPv4Interface(m.group(1))
                    except ValueError:
                        pass

            # EOS CIDR secondary: "ip address X.X.X.X/Y secondary"
            cidr_sec = [
                c for c in cidr_children if "secondary" in c.text.lower()
            ]
            for sec in cidr_sec:
                sm = re.search(
                    r"^\s+ip\s+address\s+(\d+\.\d+\.\d+\.\d+/\d+)",
                    sec.text,
                )
                if sm:
                    try:
                        intf_cfg.secondary_ips.append(IPv4Interface(sm.group(1)))
                    except ValueError:
                        pass

            # EOS OSPF area: "ip ospf area <area>" (no process ID)
            ospf_area_children = intf_obj.find_child_objects(
                r"^\s+ip\s+ospf\s+area\s+(\S+)"
            )
            if ospf_area_children and intf_cfg.ospf_area is None:
                am = re.search(
                    r"^\s+ip\s+ospf\s+area\s+(\S+)",
                    ospf_area_children[0].text,
                )
                if am:
                    intf_cfg.ospf_area = am.group(1)

            # VARP: "ip virtual-router address <ip>". A device emits ONE LINE
            # PER ADDRESS, so accumulate rather than overwrite
            # (syntax-corpus/eos/interfaces.yaml: ip-virtual-router-address).
            # This is EOS's anycast-gateway concept — not HSRP, not VRRP, and
            # not the PAN-OS `virtual_router` field (a routing-instance name).
            for varp_child in intf_obj.find_child_objects(
                r"^\s+ip\s+virtual-router\s+address\s+"
            ):
                vm = re.search(
                    r"^\s+ip\s+virtual-router\s+address\s+(\S+)", varp_child.text
                )
                if not vm:
                    continue
                try:
                    addr = IPv4Address(vm.group(1))
                except ValueError:
                    continue
                if addr not in intf_cfg.varp_addresses:
                    intf_cfg.varp_addresses.append(addr)

        # CCR-0164: EOS's `ip ospf area <id>` carries no process id by design,
        # so the interface's ``ospf_process_id`` stays None and the engine's
        # OSPF enrollment gate (which requires a process id) never enrolls the
        # interface even though ``ospf_area`` is set. When the config has
        # EXACTLY ONE ``router ospf <id>`` instance, bind that single process id
        # onto the participating (``ospf_area`` set) interfaces that have no
        # process id. GUARD: with zero or multiple instances there is no way to
        # know which process an area-only interface belongs to, so leave it None
        # — multi-instance disambiguation is the (frozen) entrp half of the CCR.
        ospf_pids: list[int | str] = []
        for proc_obj in parse.find_objects(r"^router\s+ospf\s+\d+\b"):
            pm = re.match(r"^router\s+ospf\s+(\S+)", proc_obj.text)
            if pm:
                pid_str = pm.group(1)
                ospf_pids.append(int(pid_str) if pid_str.isdigit() else pid_str)
        if len(ospf_pids) == 1:
            single_pid = ospf_pids[0]
            for intf_cfg in interfaces:
                if intf_cfg.ospf_area is not None and intf_cfg.ospf_process_id is None:
                    intf_cfg.ospf_process_id = single_pid

        return interfaces

    def parse_ospf(self) -> list[OSPFConfig]:
        """Parse OSPF, adding EOS's prefix-form ``network`` statements.

        EOS emits ``network <prefix> area <id>`` under ``router ospf`` in CIDR
        slash notation — two tokens (prefix, area-id) around ``area`` — whereas
        the inherited IOS walk matches only the classic three-token
        ``network <addr> <wildcard> area <id>`` form
        (syntax-corpus/eos/ospf.yaml: network-area, verified-capture cEOS
        4.36.1F). The IOS regex never matches the EOS spelling, so the statement
        was silently DROPPED — and it did not even surface in
        ``unrecognized_blocks`` because ``network`` is a claimed child of
        ``router ospf`` (_IOS_KNOWN_CHILD_PATTERNS). Parse the prefix form into
        the SAME ``OSPFConfig.network_statements`` shape the IOS wildcard form
        fills — a ``(IPv4Network, area-id)`` tuple — so the engine's network
        overlap enrollment (igp.py) and any goldens stay consistent. The
        inherited three-token walk is left intact for mixed configs.
        """
        ospf_instances = super().parse_ospf()

        parse = self._get_parse_obj()
        by_pid: dict[int | str, OSPFConfig] = {
            inst.process_id: inst for inst in ospf_instances
        }

        for ospf_obj in parse.find_objects(self._OSPF_PROC_PATTERNS.union):
            hdr = self._OSPF_PROC_PATTERNS.match(ospf_obj.text)
            pid_str = hdr.group("pid") if hdr else None
            if not pid_str:
                continue
            pid: int | str = int(pid_str) if pid_str.isdigit() else pid_str
            inst = by_pid.get(pid)
            if inst is None:
                continue
            existing = set(inst.network_statements)
            # Prefix form only: exactly ``network <prefix> area <id>`` (the
            # trailing ``$`` keeps this disjoint from the inherited three-token
            # wildcard form, which has an extra token before ``area``).
            for nc in ospf_obj.find_child_objects(
                r"^\s+network\s+\S+\s+area\s+\S+\s*$"
            ):
                m = re.match(r"^\s+network\s+(\S+)\s+area\s+(\S+)\s*$", nc.text)
                if not m:
                    continue
                prefix_str, area_id = m.group(1), m.group(2)
                try:
                    net = IPv4Network(prefix_str, strict=False)
                except ValueError:
                    # A device-emitted CIDR prefix always parses; this guards
                    # malformed input only. Leave it unrepresented rather than
                    # fabricate a statement — it is not silently claimed here.
                    continue
                stmt = (net, area_id)
                if stmt not in existing:
                    inst.network_statements.append(stmt)
                    existing.add(stmt)

        return ospf_instances

    # VRFs — no override. The header spelling ("vrf instance") is data
    # (_VRF_HEADER_PATTERNS above) and the body vocabulary — description, rd,
    # route-target, route-map import/export — is the shared one in
    # IOSParser.parse_vrfs (_apply_vrf_body_line + _apply_route_target_line).
    #
    # This method used to be a fork that re-implemented rd and route-target
    # extraction from the `vrf instance` block. On a REAL Arista switch that block
    # contains neither: `rd` and `route-target import|export` are printed inside
    # `router bgp <asn> > vrf NAME`, and are read from there by the shared
    # _parse_bgp_vrf_blocks and attributed back onto the VRFConfig by the shared
    # BaseParser._backfill_vrf_rd_rt ([[CCR-0059]], device capture cEOS 4.36.1F).
    # The fork was reading a block the device never writes into — and scoring 100%
    # against a hand-written fixture that humored it.

    def parse_prefix_lists(self) -> list[PrefixListConfig]:
        """Parse prefix-list configurations for EOS.

        EOS prefix-lists don't require explicit "seq" keyword and support CIDR notation.
        """
        prefix_lists = []
        parse = self._get_parse_obj()

        # Find all prefix-list entries
        # EOS format: ip prefix-list NAME
        #   seq 10 permit 10.0.0.0/16 le 24
        pl_objs = parse.find_objects(r"^ip\s+prefix-list\s+")

        # Group entries by prefix-list name
        pl_dict: dict[str, dict] = {}

        for pl_obj in pl_objs:
            # Single-line form ("ip prefix-list NAME seq N permit X", also the
            # no-seq shorthand) — one entry per line. Reuses the inherited IOS
            # prefix-list line pattern set (§7.3).
            line_match = self._PREFIX_LIST_LINE_PATTERNS.match(pl_obj.text)
            if line_match:
                g = line_match.groupdict()
                pl_name = g["name"]
                if pl_name not in pl_dict:
                    raw_lines, line_numbers = self._get_raw_lines_and_line_numbers(pl_obj)
                    pl_dict[pl_name] = {
                        "name": pl_name,
                        "sequences": [],
                        "raw_lines": raw_lines,
                        "line_numbers": line_numbers,
                    }
                seq = int(g["seq"]) if g.get("seq") else (len(pl_dict[pl_name]["sequences"]) + 1) * 5
                rest = pl_obj.text[line_match.end():]
                ge = int(m.group(1)) if (m := re.search(r"\sge\s+(\d+)", rest)) else None
                le = int(m.group(1)) if (m := re.search(r"\sle\s+(\d+)", rest)) else None
                try:
                    prefix = IPv4Network(g["prefix"])
                except ValueError:
                    continue
                pl_dict[pl_name]["sequences"].append(
                    PrefixListEntry(sequence=seq, action=g["action"], prefix=prefix, ge=ge, le=le)
                )
                continue

            # Match parent: ip prefix-list NAME  (block/show-run form)
            parent_match = re.search(r"^ip\s+prefix-list\s+(\S+)$", pl_obj.text)
            if not parent_match:
                continue

            pl_name = parent_match.group(1)

            if pl_name not in pl_dict:
                raw_lines, line_numbers = self._get_raw_lines_and_line_numbers(pl_obj)
                pl_dict[pl_name] = {
                    "name": pl_name,
                    "sequences": [],
                    "raw_lines": raw_lines,
                    "line_numbers": line_numbers,
                }

            # Parse entries (children)
            for entry_child in pl_obj.children:
                entry_text = entry_child.text.strip()

                # EOS format: seq 10 permit 10.0.0.0/16 le 24
                entry_match = re.search(
                    r"^\s*seq\s+(\d+)\s+(permit|deny)\s+(\S+)(.*)$",
                    entry_text,
                )
                if not entry_match:
                    continue

                sequence = int(entry_match.group(1))
                action = entry_match.group(2)
                prefix_str = entry_match.group(3)
                remaining = entry_match.group(4).strip() if entry_match.group(4) else ""

                # Parse ge/le
                ge = None
                le = None
                ge_match = re.search(r"\sge\s+(\d+)", remaining)
                if ge_match:
                    ge = int(ge_match.group(1))

                le_match = re.search(r"\sle\s+(\d+)", remaining)
                if le_match:
                    le = int(le_match.group(1))

                try:
                    prefix = IPv4Network(prefix_str)
                except ValueError:
                    continue

                pl_dict[pl_name]["sequences"].append(
                    PrefixListEntry(
                        sequence=sequence,
                        action=action,
                        prefix=prefix,
                        ge=ge,
                        le=le,
                    )
                )

        # Create PrefixListConfig objects
        for pl_data in pl_dict.values():
            if pl_data["sequences"]:  # Only create if has sequences
                prefix_lists.append(
                    PrefixListConfig(
                        object_id=f"prefix_list_{pl_data['name']}",
                        raw_lines=pl_data["raw_lines"],
                        source_os=self.os_type,
                        line_numbers=pl_data["line_numbers"],
                        name=pl_data["name"],
                        sequences=pl_data["sequences"],
                    )
                )

        return prefix_lists

    def parse_static_routes(self) -> list[StaticRoute]:
        """Parse static route configurations for EOS.

        EOS static route syntax:
        ip route [vrf <vrf-name>] <destination>/<prefix-length> [<egress-vrf> <vrf-name>] <next-hop> [<distance>] [tag <tag>] [name <name>]
        """
        static_routes = []
        parse = self._get_parse_obj()

        # Find all ip route statements
        route_objs = parse.find_objects(r"^ip\s+route\s+")

        for route_obj in route_objs:
            raw_lines, line_numbers = self._get_raw_lines_and_line_numbers(route_obj)

            # Parse: ip route [vrf NAME] destination/prefix [egress-vrf VRF] next-hop [distance] [tag TAG] [name NAME]
            # EOS uses CIDR notation
            match = re.search(
                r"^ip\s+route\s+(?:vrf\s+(\S+)\s+)?(\S+)(?:\s+egress-vrf\s+(\S+))?\s+(\S+)(.*)$",
                route_obj.text,
            )
            if not match:
                continue

            vrf = match.group(1)
            dest_str = match.group(2)  # Should be in CIDR format like 10.0.0.0/8
            egress_vrf = match.group(3)  # EOS supports egress VRF for inter-VRF routing
            next_hop_str = match.group(4)
            remaining = match.group(5).strip() if match.group(5) else ""

            # Parse destination (CIDR format)
            try:
                destination = IPv4Network(dest_str, strict=False)
            except ValueError:
                continue

            # Parse next-hop (can be IP address or interface)
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

            # Extract track (EOS supports object tracking)
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
        """Parse ACL configurations for EOS.

        EOS ACL syntax:
        ip access-list [standard] <name>
           [seq] <action> <protocol> <source> [<source-port>] <destination> [<dest-port>] [flags]

        EOS supports both standard and extended ACLs with sequence numbers.
        The "standard" keyword is optional.
        """
        acls = []
        parse = self._get_parse_obj()

        # Find all ACL definitions (EOS uses "ip access-list [standard] NAME")
        acl_objs = parse.find_objects(r"^ip\s+access-list\s+")

        for acl_obj in acl_objs:
            # Match both "ip access-list NAME" and "ip access-list standard NAME"
            match = re.search(r"^ip\s+access-list\s+(?:(standard)\s+)?(\S+)", acl_obj.text)
            if not match:
                continue

            explicit_type = match.group(1)  # Will be "standard" if present, None otherwise
            acl_name = match.group(2)

            raw_lines, line_numbers = self._get_raw_lines_and_line_numbers(acl_obj)

            # Determine ACL type
            # If "standard" keyword was explicit, use it; otherwise examine entries
            if explicit_type == "standard":
                acl_type = "standard"
            else:
                acl_type = "extended"  # Default to extended

            entries = []
            entry_children = acl_obj.children

            # First pass: determine type if not explicit
            if explicit_type is None:
                for entry_child in entry_children:
                    entry_text = entry_child.text.strip()
                    if entry_text.startswith("remark") or entry_text.startswith("statistics"):
                        continue
                    # If we see only source (no dest), it's standard
                    parts = entry_text.split()
                    if len(parts) >= 3:
                        # Standard: seq permit/deny source
                        # Extended: seq permit/deny protocol source dest
                        idx = 0
                        if parts[0].isdigit():
                            idx = 1
                        if idx + 2 < len(parts):
                            action = parts[idx]
                            next_word = parts[idx + 1]
                            # If next word is not a protocol (tcp/udp/ip/icmp), might be standard
                            if next_word not in ["tcp", "udp", "ip", "icmp", "icmpv6", "ahp", "esp", "gre", "pim", "vrrp"]:
                                if "host" in entry_text or "any" in entry_text or "/" in entry_text:
                                    acl_type = "standard"

            # Second pass: parse entries
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

                # Skip statistics-per-entry
                if entry_text.startswith("statistics") or entry_text.startswith("counters"):
                    continue

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
                    # Standard ACL: permit/deny source [log]
                    source = parts[1] if len(parts) > 1 else None
                    source_wildcard = None

                    if source and "/" in source:
                        # CIDR notation
                        pass
                    elif source == "host":
                        source = parts[2] if len(parts) > 2 else None
                    elif source == "any":
                        pass
                    elif len(parts) > 2 and parts[2] not in ["log"]:
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

                else:
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
                            # Check for wildcard (EOS also supports CIDR)
                            if idx < len(remaining_parts) and "/" not in source:
                                if remaining_parts[idx] not in ["eq", "range", "gt", "lt", "neq", "host", "any"]:
                                    source_wildcard = remaining_parts[idx]
                                    idx += 1

                    # Parse source port
                    if idx < len(remaining_parts) and remaining_parts[idx] in ["eq", "range", "gt", "lt", "neq"]:
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
                            if idx < len(remaining_parts) and "/" not in destination:
                                if remaining_parts[idx] not in ["eq", "range", "gt", "lt", "neq"]:
                                    destination_wildcard = remaining_parts[idx]
                                    idx += 1

                    # Parse destination port
                    if idx < len(remaining_parts) and remaining_parts[idx] in ["eq", "range", "gt", "lt", "neq"]:
                        port_op = remaining_parts[idx]
                        idx += 1
                        if port_op == "range" and idx + 1 < len(remaining_parts):
                            destination_port = f"{port_op} {remaining_parts[idx]} {remaining_parts[idx + 1]}"
                            idx += 2
                        elif idx < len(remaining_parts):
                            destination_port = f"{port_op} {remaining_parts[idx]}"
                            idx += 1

                    # Parse flags (EOS supports many TCP flags and other options)
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

            if entries:  # Only add ACL if it has entries
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

        return acls

    def parse_community_lists(self) -> list[CommunityListConfig]:
        """Parse BGP community-list configurations for EOS.

        EOS community-list syntax:
        ip community-list <name> permit|deny <communities>
        ip community-list regexp <name> permit|deny <regex>
        """
        community_lists = []
        parse = self._get_parse_obj()

        # Find all community-list entries (EOS doesn't use standard/expanded keywords in config)
        cl_objs = parse.find_objects(r"^ip\s+community-list\s+")

        # Group by community-list name
        cl_dict: dict[str, dict] = {}

        for cl_obj in cl_objs:
            # EOS syntax: ip community-list [regexp|expanded] NAME permit|deny COMMUNITIES
            match = re.search(
                r"^ip\s+community-list\s+(?:(regexp|expanded)\s+)?(\S+)\s+(permit|deny)\s+(.+)$",
                cl_obj.text,
            )
            if not match:
                continue

            kw = match.group(1)
            cl_name = match.group(2)
            action = match.group(3)
            communities_str = match.group(4).strip()

            # Determine list type ("regexp" is EOS-native, "expanded" IOS-style;
            # both denote regex-matched communities)
            list_type = "expanded" if kw in ("regexp", "expanded") else "standard"

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
        """Parse BGP AS-path access-list configurations for EOS.

        EOS AS-path list syntax:
        ip as-path access-list <name> permit|deny <regex>
        """
        as_path_lists = []
        parse = self._get_parse_obj()

        # Find all AS-path access-list entries
        aspath_objs = parse.find_objects(r"^ip\s+as-path\s+access-list\s+")

        # Group by list name
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

    # -------------------------------------------------------------------
    # BGP — EOS "peer group" (two words) is a verb alias, not a fork.
    # See _BGP_CMD_ALIASES above: _parse_bgp_neighbors and
    # _parse_bgp_peer_groups are inherited from IOSParser unchanged.
    # -------------------------------------------------------------------

    def _parse_bgp_vrf_instances(self, bgp_obj, asn: int) -> list[BGPConfig]:
        """Parse VRF-specific BGP instances (``router bgp`` → ``vrf NAME`` block).

        EOS uses the same block form as NX-OS and IOS-XR, not the IOS-XE
        ``address-family ipv4 vrf NAME`` form the inherited IOS parser expects —
        which is why the whole VRF instance was previously dropped. Delegates to
        the shared block-form traversal ``_parse_bgp_vrf_blocks`` (CCR-0032),
        reusing the EOS neighbor parser for the VRF neighbors.

        EOS EVPN L3VNI exception (CCR-0157): a ``router bgp <asn> > vrf NAME``
        block that carries ONLY the EVPN control-plane (an ``rd`` and
        ``route-target ... evpn`` lines, nothing else) is the L3VNI declaration —
        it is consumed by :meth:`parse_evpn`, not an L3VPN BGP routing instance.
        Emitting a ``BGPConfig`` for it mis-split BGP into a phantom second
        instance. Such EVPN-only blocks are dropped here; a real tenant VRF that
        also carries neighbors / networks / redistribute / an ``address-family``
        (symmetric-IRB) still yields its instance AND its L3VNI.
        """
        evpn_only = {
            name
            for name, vrf_obj in self._iter_router_vrf_blocks(bgp_obj)
            if self._eos_vrf_block_is_evpn_only(vrf_obj)
        }
        return [
            inst
            for inst in self._parse_bgp_vrf_blocks(bgp_obj, asn)
            if inst.vrf not in evpn_only
        ]

    # ---- EOS EVPN control-plane (under `router bgp`) — CCR-0157 -------------
    #
    # afi-token DECISION (locked, CCR-0157): EOS spells the overlay AF as the
    # single token ``address-family evpn``, where NX-OS/IOS emit ``l2vpn evpn``.
    # The activation is NORMALIZED to ``BGPNeighborAF(afi="l2vpn", safi="evpn")``
    # so the vendor-neutral model and the engine's per-neighbor EVPN-AF facts
    # match what NX-OS produces — one EVPN-AF shape across vendors.

    @staticmethod
    def _eos_vrf_evpn_route_targets(vrf_obj):
        """Return ``(rd, rt_import, rt_export, has_evpn_rt)`` for a bgp vrf block.

        EOS L3VNI route-targets carry the ``evpn`` keyword BETWEEN the direction
        and the value — ``route-target import evpn <rt>`` — unlike NX-OS, which
        trails it (``route-target both <rt> evpn``). Only the ``evpn``-suffixed
        lines are EVPN control-plane; plain ``route-target import <rt>`` lines are
        L3VPN and are left to the shared VRF path.
        """
        rd = None
        rt_import: list[str] = []
        rt_export: list[str] = []
        has_evpn_rt = False
        for child in vrf_obj.all_children:
            st = child.text.strip()
            rd_m = re.match(r"rd\s+(\S+)", st)
            if rd_m and rd is None:
                rd = rd_m.group(1)
                continue
            rt_m = re.match(
                r"route-target\s+(both|import|export)\s+evpn\s+(\S+)", st
            )
            if rt_m:
                has_evpn_rt = True
                direction, value = rt_m.group(1), rt_m.group(2)
                if direction in ("import", "both") and value not in rt_import:
                    rt_import.append(value)
                if direction in ("export", "both") and value not in rt_export:
                    rt_export.append(value)
        return rd, rt_import, rt_export, has_evpn_rt

    def _eos_vrf_block_is_evpn_only(self, vrf_obj) -> bool:
        """True when a ``router bgp > vrf NAME`` block is JUST an EVPN L3VNI.

        EVPN-only means every direct child is an ``rd`` or an
        ``route-target ... evpn`` line (comments ignored). Any other content
        (neighbor / network / redistribute / address-family / a plain non-evpn
        route-target / router-id …) means it is a real L3VPN BGP instance and is
        kept. Used to suppress the phantom second BGP instance (CCR-0157).
        """
        has_evpn_rt = False
        for child in vrf_obj.children:
            st = child.text.strip()
            if not st or st.startswith("!"):
                continue
            if re.match(r"rd\s+\S+\s*$", st):
                continue
            if re.match(r"route-target\s+(both|import|export)\s+evpn\s+\S+\s*$", st):
                has_evpn_rt = True
                continue
            return False
        return has_evpn_rt

    def _eos_evpn_af_neighbor_policies(self, bgp_obj):
        """Read every peer-policy line inside EOS ``address-family evpn``.

        EOS states the overlay AF as the single-token ``address-family evpn``
        block under ``router bgp``, and emits both the activation
        (``neighbor <x> activate``) and the per-hop policy attachments
        (``neighbor <x> route-map <rm> in|out``, and the rest of the peer-policy
        vocabulary) inside it. ``<x>`` is the EVPN peer group or a direct neighbor
        IP. The shared ipv4/ipv6 AF walker (``_apply_bgp_af_neighbor_policies``)
        matches only ``address-family ipv4|ipv6`` and keys on neighbor IPs, so
        neither the ``evpn`` token nor a peer-group target is reached by it —
        hence this EOS-scoped collector.

        Returns ``(policies, activated, unrecognized)``:

        * ``policies`` — ``{target: pg_data}``; ``pg_data`` is the SHARED
          peer-command dict, filled by ``apply_peer_group_command``, so
          route-map / prefix-list / filter-list in|out and every other base AF
          policy key is read HERE in one place, never re-spelled (CCR-0044 guard).
        * ``activated`` — targets that carried an explicit ``activate`` line.
        * ``unrecognized`` — raw child lines the shared vocabulary did not claim,
          so the block never drops content silently — the double-miss CCR-0162
          closes (dropped AND not surfaced).
        """
        policies: dict[str, dict] = {}
        activated: set[str] = set()
        unrecognized: list[str] = []

        def _target_data(target: str) -> dict:
            if target not in policies:
                data = _default_pg_data(target)
                data.pop("name", None)
                policies[target] = data
            return policies[target]

        for af in bgp_obj.find_child_objects(r"^\s+address-family\s+evpn\s*$"):
            for child in af.children:  # direct children of the evpn AF block
                text = child.text.strip()
                if not text or text.startswith("!"):
                    continue
                # `no ...` / `default ...` withdrawals belong to the tombstone path,
                # never to the unrecognized channel — mirror the base child-line
                # walk (``default`` is the CCR-0161 alias of ``no`` for EVPN
                # removals; the deletion walk emits its AF-removal tombstone).
                if text in ("no", "default") or text.startswith(("no ", "default ")):
                    continue
                m = re.match(r"^neighbor\s+(\S+)\s+(.+?)\s*$", text)
                if m:
                    target, cmd = m.group(1), m.group(2)
                    if cmd == "activate":
                        activated.add(target)
                        _target_data(target)  # ensure an entry even if policy-free
                        continue
                    if apply_peer_group_command(_target_data(target), cmd):
                        continue
                # a non-neighbor line, or a neighbor command the shared vocabulary
                # does not know → disclose it, do not drop it.
                unrecognized.append(child.text)

        return policies, activated, unrecognized

    def parse_bgp(self) -> list[BGPConfig]:
        """Shared BGP parse, plus EOS ``address-family evpn`` overlay policy.

        A THIN wrapper — every field is parsed by the inherited
        ``IOSParser.parse_bgp`` (the neighbor / peer-group walks stay shared, so
        the CCR-0044 anti-fork guard holds). It then attaches the one thing the
        shared walk cannot express: EOS's single-token ``address-family evpn``
        block, applied to the activated/policy-bearing PEER GROUP (the usual EVPN
        target) or a direct IP neighbor, as ``BGPNeighborAF(afi="l2vpn",
        safi="evpn")`` (afi-token decision above) carrying the block's route-map
        (and other peer-policy) attachments. The shared ipv4/ipv6 AF walk
        (``_apply_bgp_af_neighbor_policies``) reaches neither the ``evpn`` token
        nor peer-group targets, so this fills that gap by REUSING the shared
        peer-command vocabulary, not re-implementing it (CCR-0157 / CCR-0162).
        """
        bgp_instances = super().parse_bgp()
        parse = self._get_parse_obj()

        for bgp_obj in parse.find_objects(r"^router\s+bgp\s+(\d+)"):
            asn_str = self._extract_match(bgp_obj.text, r"^router\s+bgp\s+(\d+)")
            if not asn_str:
                continue
            policies, activated, _unrecognized = self._eos_evpn_af_neighbor_policies(bgp_obj)
            targets = set(policies) | activated
            if not targets:
                continue
            asn = int(asn_str)
            # `address-family evpn` sits at the global process level; apply to the
            # matching global instance (vrf is None).
            for inst in bgp_instances:
                if inst.asn != asn or inst.vrf is not None:
                    continue
                for pg in inst.peer_groups:
                    if pg.name in targets:
                        self._eos_attach_evpn_af(
                            pg, policies.get(pg.name), pg.name in activated
                        )
                for nb in inst.neighbors:
                    key = str(nb.peer_ip)
                    if key in targets:
                        self._eos_attach_evpn_af(
                            nb, policies.get(key), key in activated
                        )
        return bgp_instances

    def _eos_attach_evpn_af(self, target, pg_data, activated: bool) -> None:
        """Attach (or enrich) the ``l2vpn/evpn`` AF entry on a peer-group/neighbor.

        ``activated`` records whether an explicit ``neighbor <x> activate`` line
        appeared: the AF entry's ``activate`` reflects exactly that (EOS emits
        ``activate`` when the overlay AF is on), so a policy-only appearance does
        not invent activation state the config never showed (CCR-0162 item 2).

        Only policy fields the config actually set are copied — a bare
        activation still yields the CCR-0157 shape (route_map_* = None). The
        vocabulary writes peer-level keys (remote_as, timers, …) with no AF
        meaning; the ``BGPNeighborAF.model_fields`` filter drops them, so the
        shared vocabulary can grow without touching this call site.
        """
        defaults = _default_pg_data("")
        fields = {}
        if pg_data:
            fields = {
                k: v
                for k, v in pg_data.items()
                if k in BGPNeighborAF.model_fields
                and k not in ("afi", "safi")
                and v != defaults.get(k)
            }

        existing = next(
            (af for af in target.address_families
             if af.afi == "l2vpn" and af.safi == "evpn"),
            None,
        )
        if existing is None:
            target.address_families.append(
                # CCR-0165: a policy-only line leaves activation UNSTATED (None) so a
                # partial-snippet restate cannot merge as a deactivation; an
                # explicit ``activate`` line asserts True.
                BGPNeighborAF(afi="l2vpn", safi="evpn",
                              activate=True if activated else None, **fields)
            )
        else:
            for k, v in fields.items():
                setattr(existing, k, v)
            if activated:
                existing.activate = True

    def _collect_unrecognized_child_lines(self, obj, header: str):
        """Extend the base direct-child walk into ``address-family evpn``.

        The framework's registry walk inspects only DIRECT children of a claimed
        top-level block, so lines nested inside the ``router bgp`` →
        ``address-family evpn`` sub-block are never reached by it — the exact
        silent-drop channel CCR-0162 closes. For a ``router bgp`` block, descend
        one level and disclose anything the EVPN AF policy walk did not consume,
        reusing the SAME collector ``parse_bgp`` uses so "what is recognized" is
        defined in exactly one place.
        """
        flagged = super()._collect_unrecognized_child_lines(obj, header)
        if re.match(r"^router\s+bgp\b", header):
            _policies, _activated, unrecognized = self._eos_evpn_af_neighbor_policies(obj)
            for raw in unrecognized:
                line = raw.strip()
                flagged.append(UnrecognizedBlock(
                    block_header=f"{header} > {line}",
                    raw_lines=[raw],
                    best_guess=next(
                        (label for kw, label in self._BEST_GUESS_KEYWORDS
                         if kw in line.lower()),
                        None,
                    ),
                ))
        return flagged

    # EOS's process-level ``maximum-paths`` is a process-wide multipath limit — it
    # applies to every address-family, not only the implicit IPv4-unicast one (which
    # is where a process-level ``aggregate-address`` belongs).
    _BGP_PROCESS_LEVEL_AF_FANOUT = ("maximum_paths", "maximum_paths_ibgp")

    def _parse_bgp_process_level_af_settings(self, bgp_obj) -> dict:
        """AF-scoped BGP settings EOS prints at the ``router bgp`` process level.

        EOS emits BOTH ``maximum-paths 8 ecmp 8`` AND ``aggregate-address …``
        outside any ``address-family`` block, as direct children of ``router bgp``
        (device capture, cEOS 4.36.1F). They belong to the IPv4-unicast family; the
        shared ``_merge_bgp_process_level_af_settings`` puts them there.

        This used to be a whole-method override of ``_parse_bgp_address_families``
        that grafted on max-paths. Being a fork, it never learned the OTHER setting
        EOS emits in the same position, so a real Arista switch parsed **zero** BGP
        aggregates ([[CCR-0059]]). Placement is now DATA — this dict — and the walk
        that consumes it is shared.
        """
        settings = super()._parse_bgp_process_level_af_settings(bgp_obj)

        # EOS: maximum-paths N [ecmp N]  (global, eBGP)
        mp_ch = bgp_obj.find_child_objects(r"^\s+maximum-paths\s+(?!ibgp)(\d+)")
        if mp_ch:
            v = self._extract_match(mp_ch[0].text, r"^\s+maximum-paths\s+(\d+)")
            if v:
                settings["maximum_paths"] = int(v)

        # EOS: maximum-paths ibgp N  (global)
        mp_ibgp_ch = bgp_obj.find_child_objects(r"^\s+maximum-paths\s+ibgp\s+(\d+)")
        if mp_ibgp_ch:
            v = self._extract_match(mp_ibgp_ch[0].text, r"^\s+maximum-paths\s+ibgp\s+(\d+)")
            if v:
                settings["maximum_paths_ibgp"] = int(v)

        return settings

    # IS-IS — no override. The instance body (net / is-type / redistribute /
    # log-adjacency-changes / timers) is spelled identically to IOS, and EOS's two
    # real dialects are DATA:
    #
    #   * interface membership — "isis enable CORE", vs IOS "ip router isis CORE"
    #     (_ISIS_IFACE_ENABLE_PATTERNS above);
    #   * WHERE passive lives — EOS has no `passive-interface` under `router isis`
    #     (the device REJECTS it); an interface declares itself with `isis passive`,
    #     which the shared interface walk in IOSParser.parse_isis already reads into
    #     ISISInterface.passive and back-fills into ISISConfig.passive_interfaces.
    #
    # This method used to be a fork, and being a fork it looked for passive
    # interfaces only at the process level — the one place EOS cannot put them — so
    # `passive_interfaces` came back empty from a switch that had passive interfaces
    # ([[CCR-0059]], device capture cEOS 4.36.1F). Dropping the fork also inherits
    # `default-information originate`, the ISIS interface list and the `no net`
    # withdrawal ops, none of which the fork had ever learned.

    # -----------------------------------------------------------------------
    # BFD — "bfd slow-timer N" (singular, unlike IOS "bfd slow-timers")
    # -----------------------------------------------------------------------

    def parse_bfd(self):
        """Parse EOS global BFD.

        Two renderings, both accepted, because both are Arista's — the
        difference is EOS version, not vendor (syntax-corpus/eos/bfd.yaml:
        router-bfd). Modern EOS nests global BFD under a ``router bfd`` block;
        EOS-4.13 emits the knobs flat at global level with no block at all.

        **Block form** — ``router bfd``, whose children do NOT repeat the word
        ``bfd`` (syntax-corpus/eos/bfd.yaml: router-bfd, slow-timer)::

            router bfd
               interval 900 min-rx 900 multiplier 50 default
               slow-timer 5000

        **Flat form** — the singular ``bfd slow-timer <ms>`` global line::

            bfd slow-timer 2000

        Reading only the flat form is why this method never fired on a modern
        EOS config; reading only the block form would drop a 4.13 one. A parser
        that must ingest whatever a fleet actually runs reads both.

        IOS-style ``bfd-template`` does not exist in EOS; per-interface timers
        (``bfd interval N min-rx N multiplier N``) are read by the inherited
        interface walk.
        """
        from confgraph.models.bfd import BFDConfig

        parse = self._get_parse_obj()
        slow_timers: int | None = None
        raw_lines: list[str] = []
        line_numbers: list[int] = []

        # Block form: "router bfd" + indented children
        for bfd_obj in parse.find_objects(r"^router\s+bfd\s*$"):
            raw_lines.append(bfd_obj.text)
            line_numbers.append(bfd_obj.linenum)
            for child in bfd_obj.children:
                raw_lines.append(child.text)
                line_numbers.append(child.linenum)
                v = self._extract_match(child.text, r"^\s+slow-timer\s+(\d+)")
                if v:
                    slow_timers = int(v)

        # Flat form: "bfd slow-timer <ms>" (singular — never IOS's plural
        # "slow-timers", which EOS does not accept)
        for obj in parse.find_objects(r"^bfd\s+slow-timer\s+\d+"):
            raw_lines.append(obj.text)
            line_numbers.append(obj.linenum)
            v = self._extract_match(obj.text, r"^bfd\s+slow-timer\s+(\d+)")
            if v:
                slow_timers = int(v)

        if not raw_lines:
            return None

        return BFDConfig(
            object_id="bfd",
            raw_lines=raw_lines,
            source_os=self.os_type,
            line_numbers=line_numbers,
            slow_timers=slow_timers,
        )

    # -------------------------------------------------------------------
    # DNS — override to scan vrf instance blocks (E6)
    # -------------------------------------------------------------------

    def parse_dns(self):
        """Parse DNS config, including entries inside ``vrf instance`` blocks.

        EOS places per-VRF DNS entries as children of ``vrf instance NAME``
        stanzas.  The inherited IOS ``parse_dns`` only scans global lines, so
        this override merges those with any VRF-scoped entries.
        """
        from confgraph.models.dns import DNSConfig

        dns = super().parse_dns()

        parse = self._get_parse_obj()
        vrf_objs = parse.find_objects(r"^vrf\s+instance\s+(\S+)")

        extra_servers: list[str] = []
        extra_domain_name: str | None = None
        extra_domain_list: list[str] = []
        extra_lookup_disabled = False
        extra_raw: list[str] = []
        extra_line_numbers: list[int] = []

        for vrf_obj in vrf_objs:
            for child in vrf_obj.children:
                t = child.text.strip()

                # ip name-server [vrf NAME] A B C ...
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

                # ip domain name DOMAIN / ip domain-name DOMAIN
                m = re.match(r"ip\s+domain(?:-|\s+)name\s+(\S+)", t)
                if m:
                    extra_raw.append(child.text)
                    extra_line_numbers.append(child.linenum)
                    if extra_domain_name is None:
                        extra_domain_name = m.group(1)
                    continue

                # ip domain list DOMAIN
                m = re.match(r"ip\s+domain\s+list\s+(\S+)", t)
                if m:
                    extra_raw.append(child.text)
                    extra_line_numbers.append(child.linenum)
                    extra_domain_list.append(m.group(1))
                    continue

                # no ip domain lookup
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
    # Multicast / PIM — EOS states them as BLOCKS, not as global lines
    # -------------------------------------------------------------------

    #: EOS ``rp address`` line. Verified against the device, which accepts and emits
    #: every one of these forms (cEOS 4.36.1F, 2026-07-14)::
    #:
    #:     rp address 1.1.1.1 239.0.0.0/8
    #:     rp address 2.2.2.2 access-list ACL_MGMT
    #:     rp address 3.3.3.3 priority 10
    #:     rp address 4.4.4.4 override
    #:     rp address 5.5.5.5 239.1.0.0/16 priority 20
    #:
    #: The groups an RP serves are named by PREFIX or by ACL, and the two are
    #: different fields — writing a prefix into ``acl`` would be the CCR-0030
    #: wrong-field read (a consumer resolving it against ACLConfig would dangle).
    _PIM_RP_PATTERN = re.compile(
        r"^rp\s+address\s+(?P<rp>\d+\.\d+\.\d+\.\d+)"
        r"(?:\s+(?P<group>\d+\.\d+\.\d+\.\d+/\d+))?"
        r"(?:\s+access-list\s+(?P<acl>\S+))?"
        r"(?P<rest>.*)$"
    )

    def parse_multicast(self):
        """Parse EOS multicast: ``router multicast`` and ``router pim sparse-mode``.

        EOS does not have IOS's flat ``ip multicast-routing`` / ``ip pim rp-address``
        global lines — it rejects them. It states both as blocks, with the address
        family as an intermediate level (device capture, cEOS 4.36.1F)::

            router multicast
               ipv4
                  routing
            !
            router pim sparse-mode
               ipv4
                  rp address 1.1.1.1 239.0.0.0/8

        The inherited IOS walk finds none of that and returned ``None``: on a real
        Arista switch confgraph reported NO multicast configuration at all, while the
        coverage fixture — which had been hand-written in IOS syntax the device
        rejects — scored it green ([[CCR-0059]]).

        Any flat lines the inherited walk *does* find are kept and merged, so a
        hybrid config loses nothing.
        """
        from confgraph.models.multicast import MulticastConfig, PIMRPAddress

        multicast = super().parse_multicast()

        parse = self._get_parse_obj()
        raw_lines: list[str] = []
        line_numbers: list[int] = []
        routing_enabled = False
        rp_addresses: list[PIMRPAddress] = []

        # "router multicast" → "ipv4" → "routing"
        for mc_obj in parse.find_objects(r"^router\s+multicast\s*$"):
            raw_lines.append(mc_obj.text)
            line_numbers.append(mc_obj.linenum)
            for child in mc_obj.all_children:
                raw_lines.append(child.text)
                line_numbers.append(child.linenum)
                if re.match(r"^\s+routing\s*$", child.text):
                    routing_enabled = True

        # "router pim sparse-mode" → "ipv4" → "rp address …"
        for pim_obj in parse.find_objects(r"^router\s+pim\s+sparse-mode\s*$"):
            raw_lines.append(pim_obj.text)
            line_numbers.append(pim_obj.linenum)
            for child in pim_obj.all_children:
                raw_lines.append(child.text)
                line_numbers.append(child.linenum)
                m = self._PIM_RP_PATTERN.match(child.text.strip())
                if not m:
                    continue
                try:
                    rp_addr = IPv4Address(m.group("rp"))
                except ValueError:
                    continue
                rest = m.group("rest") or ""
                rp_addresses.append(PIMRPAddress(
                    rp_address=rp_addr,
                    group_range=m.group("group"),
                    acl=m.group("acl"),
                    override="override" in rest,
                    bidir=False,   # EOS states bidirectional per-interface, not per-RP
                ))

        if not raw_lines:
            return multicast

        if multicast is None:
            return MulticastConfig(
                object_id="multicast",
                raw_lines=raw_lines,
                source_os=self.os_type,
                line_numbers=line_numbers,
                multicast_routing_enabled=routing_enabled,
                pim_rp_addresses=rp_addresses,
            )

        multicast.raw_lines.extend(raw_lines)
        multicast.line_numbers.extend(line_numbers)
        multicast.multicast_routing_enabled = (
            multicast.multicast_routing_enabled or routing_enabled
        )
        multicast.pim_rp_addresses.extend(rp_addresses)
        return multicast

    # -------------------------------------------------------------------
    # VXLAN
    # -------------------------------------------------------------------

    def parse_vxlan(self) -> "VXLANConfig | None":
        """Parse VXLAN configuration from ``interface Vxlan1``.

        Handles::

            interface Vxlan1
               vxlan source-interface Loopback1
               vxlan udp-port 4789
               vxlan vlan 10 vni 10010
               vxlan vlan 20 vni 10020
               vxlan vrf TENANT-A vni 50001
               vxlan learn-restrict any
               vxlan flood vtep 10.0.0.2 10.0.0.3
        """
        from confgraph.models.vxlan import VXLANConfig, VXLANVniMapping

        parse = self._get_parse_obj()
        vxlan_objs = parse.find_objects(r"^interface\s+Vxlan1\b")
        if not vxlan_objs:
            return None

        vxlan_intf = vxlan_objs[0]
        source_interface = None
        udp_port = 4789
        vni_mappings: list[VXLANVniMapping] = []
        flood_vteps: list[str] = []
        learn_restrict = False

        for child in vxlan_intf.children:
            t = child.text.strip()

            m = re.match(r"vxlan\s+source-interface\s+(\S+)", t)
            if m:
                source_interface = m.group(1)
                continue

            m = re.match(r"vxlan\s+udp-port\s+(\d+)", t)
            if m:
                udp_port = int(m.group(1))
                continue

            # "vxlan vlan N vni M" and EOS >= 4.27 "vxlan vlan add N vni M"
            m = re.match(r"vxlan\s+vlan\s+(?:add\s+)?(\d+)\s+vni\s+(\d+)", t)
            if m:
                vni_mappings.append(VXLANVniMapping(
                    vni=int(m.group(2)), vlan=int(m.group(1)),
                ))
                continue

            m = re.match(r"vxlan\s+vrf\s+(\S+)\s+vni\s+(\d+)", t)
            if m:
                vni_mappings.append(VXLANVniMapping(
                    vni=int(m.group(2)), vrf=m.group(1),
                ))
                continue

            if re.match(r"vxlan\s+learn-restrict\s+", t):
                learn_restrict = True
                continue

            m = re.match(r"vxlan\s+flood\s+vtep\s+(.*)", t)
            if m:
                flood_vteps.extend(m.group(1).split())
                continue

        return VXLANConfig(
            object_id="vxlan",
            raw_lines=[vxlan_intf.text] + [c.text for c in vxlan_intf.children],
            source_os=self.os_type,
            line_numbers=[vxlan_intf.linenum] + [c.linenum for c in vxlan_intf.children],
            source_interface=source_interface,
            udp_port=udp_port,
            vni_mappings=vni_mappings,
            flood_vtep_list=flood_vteps,
            learn_restrict=learn_restrict,
        )

    # -------------------------------------------------------------------
    # EVPN control-plane — EOS states it UNDER `router bgp` (CCR-0157)
    # -------------------------------------------------------------------

    def parse_evpn(self) -> "EVPNConfig | None":
        """Parse the Arista EOS MP-BGP EVPN control-plane (L2VNI + L3VNI).

        EOS is structurally UNLIKE NX-OS: there is no top-level ``evpn`` block.
        Both VNI families are declared as sub-blocks under ``router bgp``, and the
        VNI number itself lives on ``interface Vxlan1`` — so each family is JOINED
        to a VXLAN mapping (device capture, cEOS 4.36.1F)::

            router bgp 65101
               vlan 10                         # L2VNI (MAC-VRF), keyed by VLAN id
                  rd 1.1.1.1:10010
                  route-target both 10010:10010    # NO `evpn` keyword
               vrf ZZ-TENANT                   # L3VNI, keyed by tenant VRF name
                  rd 1.1.1.1:50001
                  route-target import evpn 50001:50001   # `evpn` BEFORE the value
                  route-target export evpn 50001:50001
            interface Vxlan1
               vxlan vlan 10 vni 10010         # VLAN 10  -> L2VNI 10010
               vxlan vrf ZZ-TENANT vni 50001   # ZZ-TENANT -> L3VNI 50001

        L2VNI join: the ``vlan <id>`` sub-block's VNI comes from the matching
        ``vxlan vlan <id> vni <n>`` mapping (``parse_vxlan``). ``EVPNL2VNI.vni`` is
        a required int, so a ``vlan`` sub-block with no VXLAN mapping is SKIPPED
        rather than fabricated. ``route-target both`` populates BOTH lists.

        L3VNI join / discriminator: a ``vrf NAME`` sub-block is an EVPN L3VNI when
        it carries at least one ``route-target ... evpn`` line — that ``evpn``
        keyword is the marker that the VRF participates in the EVPN control-plane,
        exactly as NX-OS's trailing ``evpn`` token distinguishes EVPN RTs from
        plain L3VPN RTs. A plain L3VPN VRF (``route-target import <rt>`` with no
        ``evpn`` keyword) is NOT an L3VNI, even if it happens to have a VXLAN VRF
        binding. The VNI comes from the ``vxlan vrf NAME vni <n>`` mapping, and
        that binding IS the EOS L3VNI↔fabric association (EOS has no NX-OS-style
        ``member vni ... associate-vrf`` line), so it also sets ``associate_vrf``.

        afi-token: the overlay activation (``address-family evpn`` +
        ``neighbor X activate``) is parsed onto the BGP peer group / neighbor as
        ``BGPNeighborAF(afi="l2vpn", safi="evpn")`` — see the decision recorded on
        the BGP section above; it is not represented in :class:`EVPNConfig`.

        Returns ``None`` when there is no EVPN config at all, so a non-EVPN EOS
        config keeps ``evpn`` absent.
        """
        from confgraph.models.evpn import EVPNConfig, EVPNL2VNI, EVPNL3VNI

        parse = self._get_parse_obj()
        bgp_objs = parse.find_objects(r"^router\s+bgp\s+\d+")
        if not bgp_objs:
            return None

        # VNI joins from interface Vxlan1 (parse_vxlan records the real vrf name).
        vlan_to_vni: dict[int, int] = {}
        vrf_to_vni: dict[str, int] = {}
        vxlan = self.parse_vxlan()
        if vxlan is not None:
            for mapping in vxlan.vni_mappings:
                if mapping.vlan is not None:
                    vlan_to_vni.setdefault(mapping.vlan, mapping.vni)
                elif mapping.vrf is not None:
                    vrf_to_vni.setdefault(mapping.vrf, mapping.vni)

        l2vnis: list[EVPNL2VNI] = []
        l3vnis: list[EVPNL3VNI] = []
        raw_lines: list[str] = []
        line_numbers: list[int] = []
        has_af_evpn = False

        for bgp_obj in bgp_objs:
            # --- L2VNI: `vlan <id>` sub-blocks (MAC-VRF) ---------------------
            for vlan_obj in bgp_obj.find_child_objects(r"^\s+vlan\s+\d+\s*$"):
                vid = self._extract_match(vlan_obj.text, r"^\s+vlan\s+(\d+)")
                if vid is None:
                    continue
                vni = vlan_to_vni.get(int(vid))
                if vni is None:
                    continue  # no VXLAN mapping — cannot fabricate a required VNI
                rd = None
                rt_import: list[str] = []
                rt_export: list[str] = []
                raw_lines.append(vlan_obj.text)
                line_numbers.append(vlan_obj.linenum)
                for sub in vlan_obj.children:
                    st = sub.text.strip()
                    rd_m = re.match(r"rd\s+(\S+)", st)
                    if rd_m and rd is None:
                        rd = rd_m.group(1)
                        raw_lines.append(sub.text)
                        line_numbers.append(sub.linenum)
                        continue
                    rt_m = re.match(r"route-target\s+(both|import|export)\s+(\S+)", st)
                    if rt_m:
                        direction, value = rt_m.group(1), rt_m.group(2)
                        if direction in ("import", "both") and value not in rt_import:
                            rt_import.append(value)
                        if direction in ("export", "both") and value not in rt_export:
                            rt_export.append(value)
                        raw_lines.append(sub.text)
                        line_numbers.append(sub.linenum)
                l2vnis.append(EVPNL2VNI(
                    vni=vni,
                    rd=rd,
                    route_target_import=rt_import,
                    route_target_export=rt_export,
                ))

            # --- L3VNI: `vrf <name>` sub-blocks carrying `... evpn` RTs -------
            for vrf_name, vrf_obj in self._iter_router_vrf_blocks(bgp_obj):
                rd, rt_import, rt_export, has_evpn_rt = \
                    self._eos_vrf_evpn_route_targets(vrf_obj)
                if not has_evpn_rt:
                    continue  # plain L3VPN VRF, not an EVPN L3VNI
                vni = vrf_to_vni.get(vrf_name)
                if vni is None:
                    continue  # no VXLAN mapping — cannot fabricate a required VNI
                raw_lines.append(vrf_obj.text)
                line_numbers.append(vrf_obj.linenum)
                l3vnis.append(EVPNL3VNI(
                    vni=vni,
                    rd=rd,
                    route_target_import=rt_import,
                    route_target_export=rt_export,
                    vrf=vrf_name,
                    associate_vrf=True,
                ))

            # --- Overlay activation presence (`address-family evpn`) ---------
            if bgp_obj.find_child_objects(r"^\s+address-family\s+evpn\s*$"):
                has_af_evpn = True

        if not l2vnis and not l3vnis and not has_af_evpn:
            return None

        return EVPNConfig(
            object_id="evpn",
            raw_lines=raw_lines,
            source_os=self.os_type,
            line_numbers=line_numbers,
            l2vnis=l2vnis,
            l3vnis=l3vnis,
        )

    # -------------------------------------------------------------------
    # MPLS / LDP — hierarchical "mpls ldp" block (EOS style)
    # -------------------------------------------------------------------

    def parse_mpls(self) -> "MPLSConfig | None":
        """Parse MPLS/LDP from EOS hierarchical ``mpls ldp`` block.

        EOS nests LDP sub-commands under ``mpls ldp``::

            mpls ldp
               router-id interface Loopback0
               no shutdown
               transport-address interface Loopback0

        Note: EOS uses ``router-id interface <name>`` (with the "interface"
        keyword) unlike IOS-XR which uses a raw IP.
        """
        from confgraph.models.mpls import MPLSConfig

        parse = self._get_parse_obj()

        ldp_objs = parse.find_objects(r"^mpls\s+ldp\s*$")
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

            # EOS: "router-id interface Loopback0"
            m = re.match(r"router-id\s+interface\s+(\S+)", t)
            if m:
                ldp_router_id = m.group(1)
                continue

            # EOS also supports "router-id <IP>" without "interface"
            m = re.match(r"router-id\s+(\S+)", t)
            if m:
                ldp_router_id = m.group(1)
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
    # Deletion commands (tombstones)
    # -------------------------------------------------------------------

    def parse_deletion_commands(self) -> list[str]:
        """Parse EOS deletion commands into tombstone strings.

        Inherits all IOS top-level tombstones (``no router ospf``,
        ``no ip pim rp-address``, ``no vlan``, etc.) and adds EOS-specific
        nested block deletions:

          - ``no vxlan vlan <id> vni <id>`` inside ``interface Vxlan1``
            → ``field:vxlan:vni:<vni_id>``
          - ``no vxlan vrf <name> vni <id>`` inside ``interface Vxlan1``
            → ``field:vxlan:vni:<vni_id>``
          - ``no peer-address`` inside ``mlag configuration``
            → ``field:vpc:peer_keepalive_destination``
        """
        tombstones = super().parse_deletion_commands()
        parse = self._get_parse_obj()

        # --- VXLAN VNI removal (nested under interface Vxlan1) ---
        # Change-IR family 8b (CCR Appendix U): tombstones regenerated FROM the
        # native removal ops via the shared IOS queue helper (byte-exact, same
        # walk positions).  super().parse_deletion_commands() already
        # initialised _pending_native_singleton_ops.
        for vxlan_obj in parse.find_objects(r"^interface\s+Vxlan1\b"):
            for child in vxlan_obj.children:
                t = child.text.strip()
                # "no vxlan vlan <vlan_id> vni <vni_id>"
                m = re.match(r"no\s+vxlan\s+vlan\s+\d+\s+vni\s+(\d+)", t)
                if m:
                    self._queue_native_singleton_removal(
                            f"field:vxlan:vni:{m.group(1)}", child
                        )
                    continue
                # "no vxlan vrf <name> vni <vni_id>"
                m = re.match(r"no\s+vxlan\s+vrf\s+\S+\s+vni\s+(\d+)", t)
                if m:
                    self._queue_native_singleton_removal(
                            f"field:vxlan:vni:{m.group(1)}", child
                        )

        # --- MLAG peer-address removal (nested under mlag configuration) ---
        for mlag_obj in parse.find_objects(r"^mlag\s+configuration"):
            for child in mlag_obj.children:
                t = child.text.strip()
                if re.match(r"no\s+peer-address\b", t):
                    self._queue_native_singleton_removal(
                            "field:vpc:peer_keepalive_destination", child
                        )

        # --- EVPN control-plane removals under `router bgp` (CCR-0161) ---
        # L2VNI (``vlan <id>``), L3VNI (``vrf <name>``) and overlay-AF
        # deactivations.  Every EOS EVPN removal but ``no neighbor <x> activate``
        # renders by OMISSION (capture 2026-08-01 cEOS 4.36.1F), so these
        # tombstones serve PROPOSAL text; the emitted ``no neighbor activate`` line
        # is handled here too via the shared CCR-0148 AF-removal channel.
        self._parse_eos_evpn_deletions(parse)

        return tombstones

    # EOS EVPN removal-form patterns (CCR-0161) — device-verified on cEOS 4.36.1F
    # (capture 2026-08-01-ceos-4.36.1F-evpn-deletion-forms.txt).  Every pattern is
    # END-ANCHORED (``\s*$``) so trailing garbage (``no vlan 10 bogus``,
    # ``default rd bananas``) fires NO tombstone — the CCR-0145 F2/V-2 hardening
    # replayed.
    #
    # ``default`` is an ALIAS of ``no`` (leading ``(?:no|default)\s+``).  The device
    # confirms every value-bearing removal here accepts BOTH spellings with the
    # SAME effect (``default route-target both <rt>`` == ``no route-target both
    # <rt>``, removal by omission — capture 2026-08-01), so both must emit the
    # IDENTICAL tombstone.  Only these value-bearing forms are aliased: a
    # VALUELESS ``default route-target`` is an all-reset (different semantic), out
    # of scope and deliberately not matched.

    # L2VNI RT under ``router bgp / vlan <id>``: NO trailing ``evpn`` keyword and
    # ``route-target both`` is kept unexpanded (device-confirmed).
    _EOS_L2VNI_RT_REMOVAL = re.compile(
        r"^(?:no|default)\s+route-target\s+(both|import|export)\s+(\S+)\s*$"
    )
    # L3VNI RT under ``router bgp / vrf <name>``: the ``evpn`` keyword sits BETWEEN
    # the direction and the value (unlike NX-OS's trailing ``evpn``).  A plain
    # ``no route-target import <rt>`` (no ``evpn``) is L3VPN — it does not match here
    # and is left to the inherited path, never claimed as an EVPN removal.
    _EOS_L3VNI_RT_REMOVAL = re.compile(
        r"^(?:no|default)\s+route-target\s+(both|import|export)\s+evpn\s+(\S+)\s*$"
    )
    # ``no|default rd [<value>]`` — the optional value is CONSTRAINED to the RD
    # grammar (``auto`` or a colon-bearing ASN2:NN / ASN4:NN / IPV4:NN), so
    # ``default rd bananas`` does not clear a real RD (CCR-0145 V-2,
    # grammar-token-in-value-position).
    _EOS_RD_REMOVAL = re.compile(
        r"^(?:no|default)\s+rd(?:\s+(?:auto|\S+:\S+))?\s*$"
    )
    # Whole-object deletes as DIRECT children of ``router bgp`` (end-anchored).
    _EOS_VLAN_REMOVAL = re.compile(r"^(?:no|default)\s+vlan\s+(\d+)\s*$")
    _EOS_VRF_REMOVAL = re.compile(r"^(?:no|default)\s+vrf\s+(\S+)\s*$")
    # Overlay deactivation under ``address-family evpn`` — the ONE removal EOS
    # emits as a literal ``no`` line rather than by omission (``default`` accepted
    # equivalently, device-confirmed).
    _EOS_NEIGHBOR_DEACTIVATE = re.compile(
        r"^(?:no|default)\s+neighbor\s+(\S+)\s+activate\s*$"
    )
    # EVPN evidence in a ``router bgp / vrf <name>`` block: any ``route-target …
    # evpn …`` line (positive, ``no``, OR ``default``).  Discriminates an EVPN
    # L3VNI block from a plain-L3VPN BGP VRF instance for the ``no|default rd``
    # case, which carries no ``evpn`` marker of its own.  Mirrors
    # ``_eos_vrf_block_is_evpn_only`` / ``_eos_vrf_evpn_route_targets`` (CCR-0157
    # discriminator).
    _EOS_VRF_EVPN_EVIDENCE = re.compile(
        r"^(?:(?:no|default)\s+)?route-target\s+(?:both|import|export)\s+evpn\s+\S+\s*$"
    )

    @staticmethod
    def _eos_af_removal_scope(name: str) -> str:
        """``"neighbor"`` when *name* parses as an IP, else ``"peer_group"``.

        EOS ``address-family evpn`` activates either a peer group (the usual EVPN
        target) or a direct IP neighbor; the removal must key into the matching
        collection.  A removal snippet may not restate the peer-group definition,
        so the IP-vs-name shape of ``<x>`` itself is the discriminator (the same
        signal ``parse_bgp``'s positive path ultimately keys on).
        """
        from ipaddress import ip_address

        try:
            ip_address(name)
            return "neighbor"
        except ValueError:
            return "peer_group"

    def _parse_eos_evpn_deletions(self, parse) -> None:
        """Queue native ops for EOS EVPN L2VNI/L3VNI/overlay ``no`` removals.

        Emission map (VNI = ``N``, VLAN = ``V``, tenant VRF = ``NAME``, RT = ``X``,
        direction = ``D``), all under ``router bgp <asn>``:

        L2VNI (``vlan <id>`` sub-block, keyed by VLAN; VNI joined from
        ``interface Vxlan1`` ``vxlan vlan <id> vni <n>``):

        * ``vlan V / no route-target D X`` (no ``evpn`` kw)
          -> ``field:evpn:l2vnis:N:route_target_D:X`` when the VLAN resolves to a
          VNI, else ``field:evpn:l2vnis_by_vlan:V:route_target_D:X`` (LIST_REMOVE;
          ``both`` clears both lists in the engine accessor).
        * ``vlan V / no rd``  -> ``…:rd`` (UNSET) with the same VNI/VLAN keying.
        * ``no vlan V`` (direct child) -> ``field:evpn:l2vnis:N`` /
          ``field:evpn:l2vnis_by_vlan:V`` (OBJECT_DELETE).

        L3VNI (``vrf <name>`` sub-block, keyed by tenant VRF — the VNI lives on
        ``interface Vxlan1`` and is not restated on the removal, so these are
        VRF-NAME-keyed and the engine resolves them against the baseline's L3VNIs
        by ``.vrf``, exactly like the NX-OS ``l3vnis_by_vrf`` fallback):

        * ``vrf NAME / no route-target D evpn X`` -> ``field:evpn:l3vnis_by_vrf:
          NAME:route_target_D:X`` (LIST_REMOVE).  The ``evpn`` keyword IS the
          discriminator; a plain ``no route-target D X`` is L3VPN and is not
          matched here.
        * ``vrf NAME / no rd``, but ONLY when the block carries EVPN evidence (a
          ``route-target … evpn`` line, positive or negated) -> ``field:evpn:
          l3vnis_by_vrf:NAME:rd`` (UNSET).  A plain-L3VPN VRF's ``no rd`` has no
          ``evpn`` marker and is left to the inherited path.
        * ``no vrf NAME`` (direct child) -> ``field:evpn:l3vnis_by_vrf:NAME``
          (OBJECT_DELETE), emitted unconditionally — the delete line carries no
          block to inspect, and the engine's by-vrf resolution is itself the
          discriminator (a non-L3VNI VRF finds no L3VNI and the delete no-ops).

        Overlay (``address-family evpn`` sub-block):

        * ``no neighbor <x> activate`` -> the CCR-0148 per-neighbor/peer-group AF
          removal op for ``(l2vpn, evpn)`` (``_emit_bgp_neighbor_af_removal``),
          scope decided by the IP-vs-name shape of ``<x>``.

        All ``field:evpn:…`` tombstones fall through change-IR to the engine's
        deletion handlers; the ``l2vnis_by_vlan`` shapes and the
        ``l3vnis_by_vrf`` whole-delete are the CCR-0161 additions to
        ``_TOP_TOMBSTONE_VERBS``.  Native BGP ops are initialised by ``parse_bgp``
        (runs earlier); guard defensively in case of an early-return parse.
        """
        if not hasattr(self, "_pending_native_bgp_ops"):
            self._pending_native_bgp_ops = []

        # VLAN->VNI joins from interface Vxlan1 — may be ABSENT in a partial
        # snippet, in which case the removal falls back to VLAN-id keying.
        vlan_to_vni: dict[int, int] = {}
        vxlan = self.parse_vxlan()
        if vxlan is not None:
            for mapping in vxlan.vni_mappings:
                if mapping.vlan is not None:
                    vlan_to_vni.setdefault(mapping.vlan, mapping.vni)

        for bgp_obj in parse.find_objects(r"^router\s+bgp\s+(\d+)"):
            asn_str = self._extract_match(bgp_obj.text, r"^router\s+bgp\s+(\d+)")
            if not asn_str:
                continue
            asn = int(asn_str)

            # --- whole-object deletes (direct children of `router bgp`) ---
            for child in bgp_obj.children:
                ct = child.text.strip()
                m = self._EOS_VLAN_REMOVAL.match(ct)
                if m:
                    vlan = m.group(1)
                    vni = vlan_to_vni.get(int(vlan))
                    self._queue_native_keyed_removal(
                        f"field:evpn:l2vnis:{vni}" if vni is not None
                        else f"field:evpn:l2vnis_by_vlan:{vlan}",
                        child,
                    )
                    continue
                m = self._EOS_VRF_REMOVAL.match(ct)
                if m:
                    self._queue_native_keyed_removal(
                        f"field:evpn:l3vnis_by_vrf:{m.group(1)}", child
                    )

            # --- L2VNI RT/rd removals nested under `vlan <id>` sub-blocks ---
            for vlan_obj in bgp_obj.find_child_objects(r"^\s+vlan\s+\d+\s*$"):
                vid = self._extract_match(vlan_obj.text, r"^\s+vlan\s+(\d+)")
                if vid is None:
                    continue
                vni = vlan_to_vni.get(int(vid))
                key = (
                    f"field:evpn:l2vnis:{vni}" if vni is not None
                    else f"field:evpn:l2vnis_by_vlan:{vid}"
                )
                for sub in vlan_obj.children:
                    st = sub.text.strip()
                    rtm = self._EOS_L2VNI_RT_REMOVAL.match(st)
                    if rtm:
                        self._queue_native_keyed_removal(
                            f"{key}:route_target_{rtm.group(1)}:{rtm.group(2)}",
                            sub,
                        )
                        continue
                    if self._EOS_RD_REMOVAL.match(st):
                        self._queue_native_keyed_removal(f"{key}:rd", sub)

            # --- L3VNI RT/rd removals nested under `vrf <name>` sub-blocks ---
            for vrf_name, vrf_obj in self._iter_router_vrf_blocks(bgp_obj):
                block_is_evpn = any(
                    self._EOS_VRF_EVPN_EVIDENCE.match(c.text.strip())
                    for c in vrf_obj.children
                )
                for sub in vrf_obj.children:
                    st = sub.text.strip()
                    rtm = self._EOS_L3VNI_RT_REMOVAL.match(st)
                    if rtm:
                        self._queue_native_keyed_removal(
                            f"field:evpn:l3vnis_by_vrf:{vrf_name}"
                            f":route_target_{rtm.group(1)}:{rtm.group(2)}",
                            sub,
                        )
                        continue
                    if block_is_evpn and self._EOS_RD_REMOVAL.match(st):
                        self._queue_native_keyed_removal(
                            f"field:evpn:l3vnis_by_vrf:{vrf_name}:rd", sub
                        )

            # --- overlay deactivation under `address-family evpn` ---
            for af in bgp_obj.find_child_objects(r"^\s+address-family\s+evpn\s*$"):
                for sub in af.children:
                    m = self._EOS_NEIGHBOR_DEACTIVATE.match(sub.text.strip())
                    if m:
                        name = m.group(1)
                        self._emit_bgp_neighbor_af_removal(
                            name,
                            self._eos_af_removal_scope(name),
                            "l2vpn",
                            "evpn",
                            sub,
                            asn,
                            None,
                        )

    # -------------------------------------------------------------------
    # MLAG → VPCConfig
    # -------------------------------------------------------------------

    def parse_vpc(self) -> "VPCConfig | None":
        """Parse EOS MLAG configuration into VPCConfig.

        Handles::

            mlag configuration
               domain-id MLAG_DOMAIN
               local-interface Vlan4094
               peer-address 10.0.0.2
               peer-link Port-Channel1
               reload-delay mlag 300
        """
        from ipaddress import IPv4Address
        from confgraph.models.vpc import VPCConfig

        parse = self._get_parse_obj()
        mlag_objs = parse.find_objects(r"^mlag\s+configuration")
        if not mlag_objs:
            return None

        mlag_obj = mlag_objs[0]

        domain_id: str | None = None
        peer_link: str | None = None
        peer_address: IPv4Address | None = None
        reload_delay: int | None = None

        for child in mlag_obj.children:
            t = child.text.strip()

            m = re.match(r"domain-id\s+(\S+)", t)
            if m:
                domain_id = m.group(1)
                continue

            m = re.match(r"peer-link\s+(\S+)", t)
            if m:
                peer_link = m.group(1)
                continue

            m = re.match(r"peer-address\s+(\S+)", t)
            if m:
                try:
                    peer_address = IPv4Address(m.group(1))
                except ValueError:
                    pass
                continue

            m = re.match(r"reload-delay\s+mlag\s+(\d+)", t)
            if m:
                reload_delay = int(m.group(1))
                continue

        if domain_id is None:
            return None

        return VPCConfig(
            object_id="vpc",
            raw_lines=[mlag_obj.text] + [c.text for c in mlag_obj.children],
            source_os=self.os_type,
            line_numbers=[mlag_obj.linenum] + [c.linenum for c in mlag_obj.children],
            domain_id=domain_id,
            peer_link=peer_link,
            peer_keepalive_destination=peer_address,
            peer_keepalive_source=None,
            peer_keepalive_vrf=None,
            delay_restore=reload_delay,
        )
