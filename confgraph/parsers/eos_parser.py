"""Arista EOS configuration parser."""

import re
from ipaddress import IPv4Address, IPv4Interface, IPv4Network, IPv6Address, IPv6Interface, IPv6Network

from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.base import _BASE_KNOWN_PATTERNS, _BASE_BEST_GUESS_KEYWORDS, _default_pg_data, apply_peer_group_command
from confgraph.models.base import OSType
from confgraph.models.bgp import BGPAddressFamily, BGPConfig, BGPNeighbor, BGPPeerGroup
from confgraph.models.vrf import VRFConfig
from confgraph.models.prefix_list import PrefixListConfig, PrefixListEntry
from confgraph.models.static_route import StaticRoute
from confgraph.models.acl import ACLConfig, ACLEntry
from confgraph.models.community_list import (
    CommunityListConfig,
    CommunityListEntry,
    ASPathListConfig,
    ASPathListEntry,
)
from confgraph.models.isis import ISISConfig, ISISRedistribute


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
        r"^vrf instance",          # EOS VRF syntax
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

    def __init__(self, config_text: str):
        """Initialize EOS parser.

        Args:
            config_text: Raw configuration text
        """
        # Call the parent IOSParser __init__ but set OS type to EOS
        super().__init__(config_text, OSType.EOS)

    def _extract_interface_vrf(self, intf_obj) -> str | None:
        """Extract VRF name from an EOS interface object.

        EOS format: ``vrf VRFNAME`` (no "forwarding" keyword).
        Uses end-of-line anchor to avoid matching other ``vrf``-prefixed
        sub-commands (e.g. hypothetical ``vrf-filter`` or similar).
        """
        vrf_children = intf_obj.find_child_objects(r"^\s+vrf\s+(\S+)\s*$")
        if vrf_children:
            return self._extract_match(
                vrf_children[0].text, r"^\s+vrf\s+(\S+)\s*$"
            )
        return None

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

        return interfaces

    def parse_vrfs(self) -> list[VRFConfig]:
        """Parse VRF configurations for EOS.

        EOS uses "vrf instance NAME" instead of "vrf definition NAME".
        """
        vrfs = []
        parse = self._get_parse_obj()

        # EOS style: vrf instance
        vrf_objs = parse.find_objects(r"^vrf\s+instance\s+(\S+)")
        for vrf_obj in vrf_objs:
            vrf_name = self._extract_match(vrf_obj.text, r"^vrf\s+instance\s+(\S+)")
            if not vrf_name:
                continue

            raw_lines, line_numbers = self._get_raw_lines_and_line_numbers(vrf_obj)

            # Extract RD
            rd = None
            rd_children = vrf_obj.find_child_objects(r"^\s+rd\s+(\S+)")
            if rd_children:
                rd = self._extract_match(rd_children[0].text, r"^\s+rd\s+(\S+)")

            # Extract route-targets (EOS uses EVPN route-targets)
            rt_import = []
            rt_export = []
            rt_both = []

            for child in vrf_obj.children:
                # EOS: route-target import evpn 65000:100
                if "route-target" in child.text and "import" in child.text:
                    rt_val = self._extract_match(child.text, r"route-target\s+import\s+(?:evpn\s+)?(\S+)")
                    if rt_val:
                        rt_import.append(rt_val)
                elif "route-target" in child.text and "export" in child.text:
                    rt_val = self._extract_match(child.text, r"route-target\s+export\s+(?:evpn\s+)?(\S+)")
                    if rt_val:
                        rt_export.append(rt_val)
                elif re.search(r"route-target\s+both\s+", child.text):
                    rt_val = self._extract_match(child.text, r"route-target\s+both\s+(?:evpn\s+)?(\S+)")
                    if rt_val:
                        rt_both.append(rt_val)

            # Extract route-maps
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

        return vrfs

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
            # Match parent: ip prefix-list NAME
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
            # EOS syntax: ip community-list [regexp] NAME permit|deny COMMUNITIES
            match = re.search(
                r"^ip\s+community-list\s+(?:(regexp)\s+)?(\S+)\s+(permit|deny)\s+(.+)$",
                cl_obj.text,
            )
            if not match:
                continue

            is_regexp = match.group(1) == "regexp"
            cl_name = match.group(2)
            action = match.group(3)
            communities_str = match.group(4).strip()

            # Determine list type
            list_type = "expanded" if is_regexp else "standard"

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
    # BGP — EOS "peer group" (two words) support
    # -------------------------------------------------------------------

    def _parse_bgp_peer_groups(self, bgp_obj) -> list[BGPPeerGroup]:
        """Parse BGP peer-groups for EOS.

        EOS uses ``neighbor NAME peer group`` (two words) instead of IOS
        ``neighbor NAME peer-group`` (hyphen).
        """
        # IOS hyphenated form
        peer_groups = super()._parse_bgp_peer_groups(bgp_obj)
        seen = {pg.name for pg in peer_groups}

        # EOS two-word form: "neighbor NAME peer group"
        pg_children = bgp_obj.find_child_objects(
            r"^\s+neighbor\s+(\S+)\s+peer\s+group\s*$"
        )
        for pg_child in pg_children:
            pg_name = self._extract_match(
                pg_child.text, r"^\s+neighbor\s+(\S+)\s+peer\s+group\s*$"
            )
            if not pg_name or pg_name in seen:
                continue
            seen.add(pg_name)

            pg_data = _default_pg_data(pg_name)
            for config_child in bgp_obj.find_child_objects(
                rf"^\s+neighbor\s+{re.escape(pg_name)}\s+"
            ):
                m = re.search(
                    rf"^\s+neighbor\s+{re.escape(pg_name)}\s+(.+)",
                    config_child.text,
                )
                if m:
                    cmd = m.group(1)
                    # Skip the "peer group" definition line itself
                    if cmd.strip() == "peer group":
                        continue
                    apply_peer_group_command(pg_data, cmd)

            peer_groups.append(BGPPeerGroup(**pg_data))

        return peer_groups

    def _parse_bgp_neighbors(self, bgp_obj) -> list[BGPNeighbor]:
        """Parse BGP neighbors for EOS.

        Handles the two-word ``peer group NAME`` form in addition to IOS
        ``peer-group NAME`` (hyphen).
        """
        # Let IOS handle what it can (hyphenated peer-group, inline remote-as)
        neighbors = super()._parse_bgp_neighbors(bgp_obj)
        existing_ips = {str(n.peer_ip) for n in neighbors}

        # Build the set of EOS peer-group names (two-word form)
        eos_pg_names = set()
        for child in bgp_obj.find_child_objects(r"^\s+neighbor\s+(\S+)\s+peer\s+group\s*$"):
            m = re.search(r"^\s+neighbor\s+(\S+)\s+peer\s+group\s*$", child.text)
            if m:
                eos_pg_names.add(m.group(1))

        # Find neighbors that use "peer group NAME" (two words)
        neighbor_children = bgp_obj.find_child_objects(r"^\s+neighbor\s+(\S+)\s+")
        neighbor_dict: dict[str, dict] = {}

        for child in neighbor_children:
            m = re.search(r"^\s+neighbor\s+(\S+)\s+(.+)", child.text)
            if not m:
                continue

            peer_ip_str = m.group(1)
            command = m.group(2)

            # Skip peer-group definition lines
            if peer_ip_str in eos_pg_names:
                continue

            # Skip neighbors already captured by super()
            if peer_ip_str in existing_ips:
                # But still check if this line has "peer group" to patch
                if command.startswith("peer group "):
                    pg_name = command.replace("peer group ", "").strip()
                    for n in neighbors:
                        if str(n.peer_ip) == peer_ip_str and n.peer_group is None:
                            n.peer_group = pg_name
                continue

            # New neighbor not captured by super()
            if peer_ip_str not in neighbor_dict:
                neighbor_dict[peer_ip_str] = {
                    "peer_ip": peer_ip_str,
                    "remote_as": None,
                    "peer_group": None,
                    "description": None,
                    "update_source": None,
                    "ebgp_multihop": None,
                    "password": None,
                    "password_encryption_type": None,
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

            if command.startswith("peer group "):
                neighbor_dict[peer_ip_str]["peer_group"] = command.replace("peer group ", "").strip()
            elif command.startswith("remote-as "):
                as_str = command.replace("remote-as ", "").strip()
                try:
                    neighbor_dict[peer_ip_str]["remote_as"] = int(as_str)
                except ValueError:
                    neighbor_dict[peer_ip_str]["remote_as"] = as_str
            elif command.startswith("description "):
                neighbor_dict[peer_ip_str]["description"] = command.replace("description ", "").strip()
            elif command.startswith("update-source "):
                neighbor_dict[peer_ip_str]["update_source"] = command.replace("update-source ", "").strip()
            elif command.startswith("password "):
                # EOS previously had no password branch here, dropping the key
                # entirely for peer-group-form neighbors. Use the shared
                # extractor inherited from IOSParser (CCR-0030 bug 4).
                key, enc = self._split_bgp_password(command[len("password "):])
                neighbor_dict[peer_ip_str]["password"] = key
                neighbor_dict[peer_ip_str]["password_encryption_type"] = enc
            elif command == "shutdown":
                neighbor_dict[peer_ip_str]["shutdown"] = True

        # Create BGPNeighbor objects for EOS-specific neighbors
        from ipaddress import IPv6Address
        for peer_ip_str, ndata in neighbor_dict.items():
            try:
                peer_ip = IPv4Address(peer_ip_str)
            except ValueError:
                try:
                    peer_ip = IPv6Address(peer_ip_str)
                except ValueError:
                    continue

            # Same guard as IOS: skip if no remote-as and no peer-group
            if (
                ndata["remote_as"] is None
                and ndata["peer_group"] is None
                and not ndata.get("shutdown", False)
            ):
                continue

            remote_as = ndata["remote_as"] if ndata["remote_as"] is not None else "inherited"

            neighbors.append(
                BGPNeighbor(
                    peer_ip=peer_ip,
                    remote_as=remote_as,
                    peer_group=ndata["peer_group"],
                    description=ndata["description"],
                    update_source=ndata["update_source"],
                    ebgp_multihop=ndata["ebgp_multihop"],
                    password=ndata["password"],
                    password_encryption_type=ndata["password_encryption_type"],
                    route_map_in=ndata["route_map_in"],
                    route_map_out=ndata["route_map_out"],
                    prefix_list_in=ndata["prefix_list_in"],
                    prefix_list_out=ndata["prefix_list_out"],
                    filter_list_in=ndata["filter_list_in"],
                    filter_list_out=ndata["filter_list_out"],
                    maximum_prefix=ndata["maximum_prefix"],
                    next_hop_self=ndata["next_hop_self"],
                    route_reflector_client=ndata["route_reflector_client"],
                    send_community=ndata["send_community"],
                    fall_over_bfd=ndata["fall_over_bfd"],
                    shutdown=ndata["shutdown"],
                    disable_connected_check=ndata["disable_connected_check"],
                    timers=ndata["timers"],
                    local_as=ndata["local_as"],
                    local_as_no_prepend=ndata["local_as_no_prepend"],
                    local_as_replace_as=ndata["local_as_replace_as"],
                )
            )

        return neighbors

    def _parse_bgp_vrf_instances(self, bgp_obj, asn: int) -> list[BGPConfig]:
        """Parse VRF-specific BGP instances (``router bgp`` → ``vrf NAME`` block).

        EOS uses the same block form as NX-OS and IOS-XR, not the IOS-XE
        ``address-family ipv4 vrf NAME`` form the inherited IOS parser expects —
        which is why the whole VRF instance was previously dropped. Delegates to
        the shared block-form traversal ``_parse_bgp_vrf_blocks`` (CCR-0032),
        reusing the EOS neighbor parser for the VRF neighbors.
        """
        return self._parse_bgp_vrf_blocks(bgp_obj, asn)

    def _parse_bgp_address_families(self, bgp_obj) -> list[BGPAddressFamily]:
        """Parse BGP address-families for EOS.

        EOS places ``maximum-paths`` at the global ``router bgp`` level rather
        than inside individual ``address-family`` blocks.  The parent method
        handles AF-level networks/redistribute/aggregate; this override reads
        global max-paths and stamps them onto every AF that doesn't have its
        own value.  When no AFs are configured but global max-paths are set,
        a synthetic ipv4 unicast AF is created to carry them.
        """
        address_families = super()._parse_bgp_address_families(bgp_obj)

        # EOS: maximum-paths N  (global, eBGP)
        global_mp: int | None = None
        mp_ch = bgp_obj.find_child_objects(r"^\s+maximum-paths\s+(?!ibgp)(\d+)")
        if mp_ch:
            v = self._extract_match(mp_ch[0].text, r"^\s+maximum-paths\s+(\d+)")
            if v:
                global_mp = int(v)

        # EOS: maximum-paths ibgp N  (global)
        global_mp_ibgp: int | None = None
        mp_ibgp_ch = bgp_obj.find_child_objects(r"^\s+maximum-paths\s+ibgp\s+(\d+)")
        if mp_ibgp_ch:
            v = self._extract_match(mp_ibgp_ch[0].text, r"^\s+maximum-paths\s+ibgp\s+(\d+)")
            if v:
                global_mp_ibgp = int(v)

        if global_mp is None and global_mp_ibgp is None:
            return address_families

        if address_families:
            for af in address_families:
                if af.maximum_paths is None and global_mp is not None:
                    af.maximum_paths = global_mp
                if af.maximum_paths_ibgp is None and global_mp_ibgp is not None:
                    af.maximum_paths_ibgp = global_mp_ibgp
        else:
            # No AF blocks configured — synthesize ipv4 unicast to carry max-paths
            address_families.append(BGPAddressFamily(
                afi="ipv4",
                safi="unicast",
                vrf=None,
                maximum_paths=global_mp,
                maximum_paths_ibgp=global_mp_ibgp,
            ))

        return address_families

    def parse_isis(self) -> list[ISISConfig]:
        """Parse IS-IS configurations for EOS.

        EOS IS-IS syntax:
        router isis <instance-name>
           net <NET>
           is-type level-1|level-2|level-1-2
           address-family ipv4 unicast
        """
        isis_instances = []
        parse = self._get_parse_obj()

        # Find all IS-IS router configs
        isis_objs = parse.find_objects(r"^router\s+isis\s+")

        for isis_obj in isis_objs:
            match = re.search(r"^router\s+isis\s+(\S+)$", isis_obj.text)
            if not match:
                continue

            tag = match.group(1)

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

            # Metric style (EOS default is wide)
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

            # Parse redistribution (EOS uses address-family context)
            redistribute = []
            # Look for redistribute statements (can be at top level or in address-family)
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
                    # and only as the leading positional token.
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

                    # Extract metric-type (EOS uses internal/external)
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

            # Authentication (EOS supports various auth modes)
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

            isis_instances.append(
                ISISConfig(
                    object_id=f"isis_{tag}",
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

    # -----------------------------------------------------------------------
    # BFD — "bfd slow-timer N" (singular, unlike IOS "bfd slow-timers")
    # -----------------------------------------------------------------------

    def parse_bfd(self):
        """Parse BFD global configuration from EOS.

        EOS uses ``bfd slow-timer N`` (singular — no trailing ``s``) as the
        only global BFD knob.  BFD timers are otherwise per-interface.
        IOS-style ``bfd-template`` does not exist in EOS::

            bfd slow-timer 2000
        """
        from confgraph.models.bfd import BFDConfig

        parse = self._get_parse_obj()
        slow_timers = None
        raw_lines = []
        line_numbers = []

        # EOS uses "bfd slow-timer N" (singular), not "bfd slow-timers N"
        for obj in parse.find_objects(r"^bfd\s+slow-timer\b"):
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

            m = re.match(r"vxlan\s+vlan\s+(\d+)\s+vni\s+(\d+)", t)
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
