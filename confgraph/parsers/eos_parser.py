"""Arista EOS configuration parser."""

import re
from ipaddress import IPv4Address, IPv4Interface, IPv4Network, IPv6Address, IPv6Interface, IPv6Network

from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.base import PatternSet, _BASE_KNOWN_PATTERNS, _BASE_BEST_GUESS_KEYWORDS
from confgraph.models.base import OSType
from confgraph.models.line import LineType
from confgraph.models.bgp import BGPConfig
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

        return interfaces

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
        """
        return self._parse_bgp_vrf_blocks(bgp_obj, asn)

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
                    tombstones.extend(
                        self._queue_native_singleton_removal(
                            f"field:vxlan:vni:{m.group(1)}", child
                        ).no_commands
                    )
                    continue
                # "no vxlan vrf <name> vni <vni_id>"
                m = re.match(r"no\s+vxlan\s+vrf\s+\S+\s+vni\s+(\d+)", t)
                if m:
                    tombstones.extend(
                        self._queue_native_singleton_removal(
                            f"field:vxlan:vni:{m.group(1)}", child
                        ).no_commands
                    )

        # --- MLAG peer-address removal (nested under mlag configuration) ---
        for mlag_obj in parse.find_objects(r"^mlag\s+configuration"):
            for child in mlag_obj.children:
                t = child.text.strip()
                if re.match(r"no\s+peer-address\b", t):
                    tombstones.extend(
                        self._queue_native_singleton_removal(
                            "field:vpc:peer_keepalive_destination", child
                        ).no_commands
                    )

        return tombstones

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
