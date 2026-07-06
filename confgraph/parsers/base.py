"""Base parser class for network device configurations."""

import re
from abc import ABC, abstractmethod
from typing import Any
from ciscoconfparse2 import CiscoConfParse


class ParseError(Exception):
    """Raised when a config block cannot be parsed.

    Attributes:
        protocol: The protocol/section that failed (e.g. "bgp")
        line_number: 1-based line number in the config file (0 if unknown)
        line_text: The config line that triggered the failure
        original: The underlying exception
    """

    def __init__(
        self,
        protocol: str,
        line_number: int,
        line_text: str,
        original: Exception,
    ) -> None:
        self.protocol = protocol
        self.line_number = line_number
        self.line_text = line_text
        self.original = original
        super().__init__(
            f"Failed to parse '{protocol}' at line {line_number}: {line_text!r}\n"
            f"  Cause: {type(original).__name__}: {original}"
        )

from confgraph.models.base import OSType, UnrecognizedBlock
from confgraph.models.parsed_config import ParsedConfig
from confgraph.models.vrf import VRFConfig
from confgraph.models.interface import InterfaceConfig
from confgraph.models.bgp import BGPConfig
from confgraph.models.ospf import OSPFConfig
from confgraph.models.route_map import RouteMapConfig
from confgraph.models.prefix_list import PrefixListConfig
from confgraph.models.static_route import StaticRoute
from confgraph.models.acl import ACLConfig
from confgraph.models.community_list import CommunityListConfig, ASPathListConfig
from confgraph.models.isis import ISISConfig
from confgraph.models.eigrp import EIGRPConfig
from confgraph.models.rip import RIPConfig
from confgraph.models.ntp import NTPConfig
from confgraph.models.snmp import SNMPConfig
from confgraph.models.logging_config import SyslogConfig
from confgraph.models.banner import BannerConfig
from confgraph.models.line import LineConfig
from confgraph.models.qos import ClassMapConfig, PolicyMapConfig
from confgraph.models.nat import NATConfig
from confgraph.models.crypto import CryptoConfig
from confgraph.models.bfd import BFDConfig
from confgraph.models.ipsla import IPSLAOperation
from confgraph.models.eem import EEMApplet
from confgraph.models.object_tracking import ObjectTrack
from confgraph.models.multicast import MulticastConfig
from confgraph.models.panos_zone import PANOSZoneConfig
from confgraph.models.aaa import AAAConfig
from confgraph.models.dns import DNSConfig
from confgraph.models.dhcp import DHCPConfig
from confgraph.models.lldp import LLDPConfig
from confgraph.models.cdp import CDPConfig
from confgraph.models.stp import STPConfig
from confgraph.models.vlan import VLANEntry
from confgraph.models.netflow import NetFlowConfig


# Top-level config line patterns that are "claimed" by a parse_* method.
# Anything NOT matching these becomes an UnrecognizedBlock.
# Subclasses can override _KNOWN_TOP_LEVEL_PATTERNS to add/remove patterns.
_BASE_KNOWN_PATTERNS: list[str] = [
    r"^router bgp",
    r"^router ospf",
    r"^router isis",
    r"^router eigrp",
    r"^router rip",
    r"^vrf definition",
    r"^interface",
    r"^route-map",
    r"^ip prefix-list",
    r"^ipv6 prefix-list",
    r"^ip access-list",
    r"^access-list",
    r"^ip route",
    r"^ipv6 route",
    r"^ip community-list",
    r"^ip as-path access-list",
    # Management
    r"^ntp",
    r"^snmp-server",
    r"^logging",
    r"^banner",
    r"^line\s+(con|vty|aux|tty)",
    # QoS
    r"^class-map",
    r"^policy-map",
    # Security
    r"^ip nat",
    r"^crypto",
    # BFD
    r"^bfd",
    r"^bfd-template",
    # IP SLA
    r"^ip sla\s+\d",
    # EEM
    r"^event\s+manager\s+applet",
    # Object tracking
    r"^track\s+\d",
    # Multicast
    r"^ip multicast-routing",
    r"^ip pim",
    r"^ip msdp",
    r"^ip igmp\s+snooping",
    # AAA
    r"^aaa",
    r"^tacacs-server",
    r"^tacacs\s+server",
    r"^radius-server",
    r"^radius\s+server",
    r"^aaa\s+group\s+server",
    r"^ip\s+tacacs\s+source-interface",
    r"^ip\s+radius\s+source-interface",
    # DNS
    r"^ip\s+domain",
    r"^ip\s+name-server",
    r"^ip\s+domain-name",
    r"^ip\s+domain-lookup",
    # DHCP
    r"^ip\s+dhcp",
    # LLDP
    r"^lldp",
    # CDP
    r"^cdp",
    # Spanning Tree
    r"^spanning-tree",
    # VLAN database
    r"^vlan\s+\d",
    # Metadata / global service lines — not config objects
    r"^hostname",
    r"^version",
    r"^service",
    r"^no\s+service",
    r"^end\s*$",
    r"^!",
]

# Ordered list of (substring, label) for best_guess inference.
# Matched against the full header line — first match wins.
_BASE_BEST_GUESS_KEYWORDS: list[tuple[str, str]] = [
    ("ntp",            "ntp"),
    ("aaa",            "aaa"),
    ("snmp",           "snmp"),
    ("logging",        "logging"),
    ("banner",         "banner"),
    ("crypto",         "crypto"),
    ("mpls",           "mpls"),
    ("bfd",            "bfd"),
    ("ip sla",         "ip_sla"),
    ("ip name-server", "dns"),
    ("ip domain",      "dns"),
    ("ip vrf",         "vrf"),
    ("ip dhcp",        "dhcp"),
    ("spanning-tree",  "spanning_tree"),
    ("lldp",           "lldp"),
    ("cdp",            "cdp"),
    ("line con",       "console"),
    ("line vty",       "vty"),
    ("boot",           "boot"),
    ("service",        "service"),
    ("errdisable",     "errdisable"),
    ("clock",          "clock"),
    ("monitor",        "monitor"),
]


class BaseParser(ABC):
    """Abstract base class for configuration parsers.

    Each OS-specific parser inherits from this and implements
    the protocol-specific parsing methods.
    """

    # Subclasses override these to add/remove OS-specific patterns
    _KNOWN_TOP_LEVEL_PATTERNS: list[str] = _BASE_KNOWN_PATTERNS
    _BEST_GUESS_KEYWORDS: list[tuple[str, str]] = _BASE_BEST_GUESS_KEYWORDS

    # Child-line registry — _KNOWN_TOP_LEVEL_PATTERNS one level down.
    #
    # Each entry is (block-header pattern, [known child-line patterns]). For every
    # claimed top-level block whose header matches a block pattern, any DIRECT child
    # line that matches none of the known child patterns is emitted as an
    # UnrecognizedBlock ("<block header> > <child line>") so unparsed lines inside
    # recognized blocks are disclosed instead of silently dropped (Fable-5 F3).
    #
    # Rules the collector applies on top of the registry:
    #   - direct children only — sub-block bodies (address-family, NX-OS "hsrp N")
    #     are not descended into (v1 recall limitation);
    #   - "no ..." lines are never flagged — negations are the tombstone surface,
    #     with their own known-negation registries;
    #   - PRECISION OVER RECALL: a line a parse method consumes must never be
    #     flagged. When unsure whether a form is consumed, list it as known.
    #
    # Default empty = mechanism off. Cisco-style parsers register their blocks;
    # JunOS/PAN-OS override _collect_unrecognized_blocks wholesale and ignore this.
    _KNOWN_CHILD_PATTERNS: list[tuple[str, list[str]]] = []

    def __init__(self, config_text: str, os_type: OSType, syntax: str = "ios"):
        """Initialize parser with configuration text.

        Args:
            config_text: Raw configuration file content
            os_type: Operating system type
            syntax: CiscoConfParse syntax type (ios, nxos, iosxr, asa, junos)
        """
        self.config_text = config_text
        self.config_lines = config_text.splitlines()
        self.os_type = os_type
        self.syntax = syntax
        self.parse_obj: CiscoConfParse | None = None
        self._hostname: str | None = None

    def _get_parse_obj(self) -> CiscoConfParse:
        """Get or create CiscoConfParse object.

        Lazy-loads the parse object on first access.
        """
        if self.parse_obj is None:
            self.parse_obj = CiscoConfParse(self.config_lines, syntax=self.syntax)
        return self.parse_obj

    def _extract_hostname(self) -> str | None:
        """Extract hostname from configuration.

        Returns:
            Hostname or None if not found
        """
        if self._hostname is not None:
            return self._hostname

        parse = self._get_parse_obj()
        hostname_objs = parse.find_objects(r"^hostname\s+(\S+)")
        if hostname_objs:
            # Extract hostname from first match
            import re
            match = re.search(r"^hostname\s+(\S+)", hostname_objs[0].text)
            if match:
                self._hostname = match.group(1)
        return self._hostname

    @abstractmethod
    def parse_vrfs(self) -> list[VRFConfig]:
        """Parse VRF configurations.

        Returns:
            List of VRFConfig objects
        """
        pass

    @abstractmethod
    def parse_interfaces(self) -> list[InterfaceConfig]:
        """Parse interface configurations.

        Returns:
            List of InterfaceConfig objects
        """
        pass

    @abstractmethod
    def parse_bgp(self) -> list[BGPConfig]:
        """Parse BGP configurations.

        Returns:
            List of BGPConfig objects (global + per-VRF)
        """
        pass

    @abstractmethod
    def parse_ospf(self) -> list[OSPFConfig]:
        """Parse OSPF configurations.

        Returns:
            List of OSPFConfig objects (global + per-VRF)
        """
        pass

    @abstractmethod
    def parse_route_maps(self) -> list[RouteMapConfig]:
        """Parse route-map configurations.

        Returns:
            List of RouteMapConfig objects
        """
        pass

    @abstractmethod
    def parse_prefix_lists(self) -> list[PrefixListConfig]:
        """Parse prefix-list configurations.

        Returns:
            List of PrefixListConfig objects
        """
        pass

    def parse_static_routes(self) -> list[StaticRoute]:
        """Parse static route configurations.

        Returns:
            List of StaticRoute objects

        Note: This is optional - returns empty list by default.
        """
        return []

    def parse_acls(self) -> list[ACLConfig]:
        """Parse ACL configurations.

        Returns:
            List of ACLConfig objects

        Note: This is optional - returns empty list by default.
        """
        return []

    def parse_community_lists(self) -> list[CommunityListConfig]:
        """Parse BGP community-list configurations.

        Returns:
            List of CommunityListConfig objects

        Note: This is optional - returns empty list by default.
        """
        return []

    def parse_as_path_lists(self) -> list[ASPathListConfig]:
        """Parse BGP AS-path access-list configurations.

        Returns:
            List of ASPathListConfig objects

        Note: This is optional - returns empty list by default.
        """
        return []

    def parse_isis(self) -> list[ISISConfig]:
        """Parse IS-IS configurations."""
        return []

    def parse_eigrp(self) -> list[EIGRPConfig]:
        """Parse EIGRP configurations."""
        return []

    def parse_rip(self) -> list[RIPConfig]:
        """Parse RIP configurations."""
        return []

    def parse_ntp(self) -> NTPConfig | None:
        """Parse NTP configuration."""
        return None

    def parse_snmp(self) -> SNMPConfig | None:
        """Parse SNMP configuration."""
        return None

    def parse_syslog(self) -> SyslogConfig | None:
        """Parse syslog/logging configuration."""
        return None

    def parse_banners(self) -> BannerConfig | None:
        """Parse device banners."""
        return None

    def parse_lines(self) -> list[LineConfig]:
        """Parse line configurations (console, VTY, aux, TTY)."""
        return []

    def parse_class_maps(self) -> list[ClassMapConfig]:
        """Parse QoS class-map configurations."""
        return []

    def parse_policy_maps(self) -> list[PolicyMapConfig]:
        """Parse QoS policy-map configurations."""
        return []

    def parse_nat(self) -> NATConfig | None:
        """Parse NAT configuration."""
        return None

    def parse_crypto(self) -> CryptoConfig | None:
        """Parse crypto/IPsec configuration."""
        return None

    def parse_bfd(self) -> BFDConfig | None:
        """Parse BFD global configuration."""
        return None

    def parse_ip_sla(self) -> list[IPSLAOperation]:
        """Parse IP SLA operations."""
        return []

    def parse_eem(self) -> list[EEMApplet]:
        """Parse EEM applets."""
        return []

    def parse_object_tracks(self) -> list[ObjectTrack]:
        """Parse object tracking configurations."""
        return []

    def parse_multicast(self) -> MulticastConfig | None:
        """Parse IP multicast configuration."""
        return None

    def parse_mpls(self) -> "MPLSConfig | None":
        """Parse MPLS/LDP configuration."""
        return None

    def parse_vxlan(self) -> "VXLANConfig | None":
        """Parse VXLAN/VTEP configuration."""
        return None

    def parse_vpc(self) -> "VPCConfig | None":
        """Parse VPC/MLAG configuration."""
        return None

    def parse_zones(self) -> list[PANOSZoneConfig]:
        """Parse PAN-OS security zone configurations."""
        return []

    def parse_aaa(self) -> AAAConfig | None:
        """Parse AAA configuration."""
        return None

    def parse_dns(self) -> DNSConfig | None:
        """Parse DNS / name-resolution configuration."""
        return None

    def parse_dhcp(self) -> DHCPConfig | None:
        """Parse DHCP server / relay / snooping configuration."""
        return None

    def parse_lldp(self) -> LLDPConfig | None:
        """Parse LLDP global configuration."""
        return None

    def parse_cdp(self) -> CDPConfig | None:
        """Parse CDP global configuration."""
        return None

    def parse_spanning_tree(self) -> STPConfig | None:
        """Parse Spanning Tree Protocol global configuration."""
        return None

    def parse_lacp_system_priority(self) -> int | None:
        """Parse global LACP system-priority."""
        return None

    def parse_vtp(self):
        """Parse VTP configuration."""
        return None

    def parse_netflow(self) -> NetFlowConfig | None:
        """Parse NetFlow export configuration."""
        return None

    def parse_vlans(self) -> list[VLANEntry]:
        """Parse VLAN database entries."""
        return []

    def _collect_unrecognized_blocks(self) -> list[UnrecognizedBlock]:
        """Collect config the parse_* methods did not claim.

        Two walks:
          1. top-level (non-indented, non-comment) lines that match no pattern in
             _KNOWN_TOP_LEVEL_PATTERNS — the whole block is unrecognized;
          2. direct child lines of CLAIMED blocks registered in
             _KNOWN_CHILD_PATTERNS that match no known child pattern — the line is
             unrecognized even though the block is parsed (see the registry
             docstring on the class).
        """
        parse = self._get_parse_obj()
        blocks: list[UnrecognizedBlock] = []

        for obj in parse.find_objects(r"^[^ \t!]"):
            header = obj.text.strip()
            if not header or header == "end":
                continue

            claimed = any(
                re.match(pattern, header)
                for pattern in self._KNOWN_TOP_LEVEL_PATTERNS
            )
            if claimed:
                blocks.extend(self._collect_unrecognized_child_lines(obj, header))
                continue

            raw_lines = [obj.text] + [child.text for child in obj.all_children]

            best_guess = next(
                (label for kw, label in self._BEST_GUESS_KEYWORDS
                 if kw in header.lower()),
                None,
            )

            blocks.append(UnrecognizedBlock(
                block_header=header,
                raw_lines=raw_lines,
                best_guess=best_guess,
            ))

        return blocks

    def _collect_unrecognized_child_lines(
        self, obj, header: str
    ) -> list[UnrecognizedBlock]:
        """Flag direct child lines of a claimed block that no parse method consumes.

        ``obj`` is the CiscoConfParse object for a claimed top-level block; returns
        one UnrecognizedBlock per direct child line not matching any known child
        pattern for its block type in ``_KNOWN_CHILD_PATTERNS``. Blocks with no
        registry entry are skipped entirely (no flagging).
        """
        child_patterns = next(
            (
                patterns
                for block_pattern, patterns in self._KNOWN_CHILD_PATTERNS
                if re.match(block_pattern, header)
            ),
            None,
        )
        if child_patterns is None:
            return []

        flagged: list[UnrecognizedBlock] = []
        for child in obj.children:  # direct children only — see registry docstring
            text = child.text.strip()
            if not text or text.startswith("!"):
                continue
            if text == "no" or text.startswith("no "):
                continue  # negations belong to the tombstone registries, never here
            if any(re.match(pattern, text) for pattern in child_patterns):
                continue
            flagged.append(UnrecognizedBlock(
                block_header=f"{header} > {text}",
                raw_lines=[child.text],
                best_guess=next(
                    (label for kw, label in self._BEST_GUESS_KEYWORDS
                     if kw in text.lower()),
                    None,
                ),
            ))
        return flagged

    # Ordered list of (ParsedConfig field, parse method name) for the main parse loop.
    _PARSE_STEPS: list[tuple[str, str]] = [
        ("vrfs",               "parse_vrfs"),
        ("interfaces",         "parse_interfaces"),
        ("bgp_instances",      "parse_bgp"),
        ("ospf_instances",     "parse_ospf"),
        ("isis_instances",     "parse_isis"),
        ("eigrp_instances",    "parse_eigrp"),
        ("rip_instances",      "parse_rip"),
        ("route_maps",         "parse_route_maps"),
        ("prefix_lists",       "parse_prefix_lists"),
        ("static_routes",      "parse_static_routes"),
        ("acls",               "parse_acls"),
        ("community_lists",    "parse_community_lists"),
        ("as_path_lists",      "parse_as_path_lists"),
        ("ntp",                "parse_ntp"),
        ("snmp",               "parse_snmp"),
        ("syslog",             "parse_syslog"),
        ("banners",            "parse_banners"),
        ("lines",              "parse_lines"),
        ("class_maps",         "parse_class_maps"),
        ("policy_maps",        "parse_policy_maps"),
        ("nat",                "parse_nat"),
        ("crypto",             "parse_crypto"),
        ("bfd",                "parse_bfd"),
        ("ip_sla_operations",  "parse_ip_sla"),
        ("eem_applets",        "parse_eem"),
        ("object_tracks",      "parse_object_tracks"),
        ("multicast",          "parse_multicast"),
        ("mpls",               "parse_mpls"),
        ("vxlan",              "parse_vxlan"),
        ("vpc",                "parse_vpc"),
        ("zones",              "parse_zones"),
        ("aaa",                "parse_aaa"),
        ("dns",                "parse_dns"),
        ("dhcp",               "parse_dhcp"),
        ("lldp",               "parse_lldp"),
        ("cdp",                "parse_cdp"),
        ("spanning_tree",      "parse_spanning_tree"),
        ("lacp_system_priority", "parse_lacp_system_priority"),
        ("vtp",                "parse_vtp"),
        ("vlans",              "parse_vlans"),
        ("netflow",            "parse_netflow"),
        ("no_commands",        "parse_deletion_commands"),
    ]

    def parse_deletion_commands(self) -> list[str]:
        """Parse top-level 'no' deletion commands into tombstone strings.

        Returns strings like 'static:10.0.0.0/8'.  Overridden by platform
        parsers that support incremental/partial proposals (IOS, NX-OS, …).
        """
        return []

    def _find_error_context(self, exc: Exception) -> tuple[int, str]:
        """Extract the best-guess config line number and text from a parse exception.

        Walks the live traceback frames looking for a local variable that is a
        CiscoConfParse object with a ``linenum`` attribute (i.e. a config
        object being iterated at the point of failure).  Returns ``(0, "")``
        if no config-line context can be determined — an honest "unknown" is
        better than a misleading Python-source-line number.
        """
        # Walk outermost→innermost, keep the *last* match (innermost frame
        # is closest to the actual failure — e.g. the neighbor line, not the
        # router bgp section header).
        best = (0, "")
        tb = exc.__traceback__
        while tb is not None:
            frame_locals = tb.tb_frame.f_locals
            for val in frame_locals.values():
                if hasattr(val, "linenum") and hasattr(val, "text"):
                    linenum = val.linenum
                    text = val.text if isinstance(val.text, str) else ""
                    best = (linenum, text)
            tb = tb.tb_next
        return best

    def parse(self) -> ParsedConfig:
        """Parse entire configuration and return ParsedConfig object.

        **Design decision — strict / fail-fast (intentional):**

        If any protocol parser raises an exception the entire parse is
        aborted and a ``ParseError`` is raised.  No partial ``ParsedConfig``
        is returned.  This guarantees that a returned ``ParsedConfig`` is
        trustworthy and complete — consumers never silently operate on
        half-parsed data.

        Resilience against malformed input is pushed down to per-field
        guards (``try/except`` around ``int()``, ``IPv4Address()``, etc.)
        inside individual parse methods, so a junk token skips that line
        rather than blanking the device.  The platform layer is responsible
        for making a parse failure first-class and visible (degraded
        coverage, not a silent drop).

        Returns:
            ParsedConfig object containing all parsed configurations

        Raises:
            ParseError: If any protocol section cannot be parsed.
        """
        hostname = self._extract_hostname()
        results: dict[str, Any] = {}

        for field, method_name in self._PARSE_STEPS:
            try:
                results[field] = getattr(self, method_name)()
            except ParseError:
                raise  # already enriched by a nested parser
            except Exception as exc:
                line_number, line_text = self._find_error_context(exc)
                raise ParseError(field, line_number, line_text, exc) from exc

        pc = ParsedConfig(
            source_os=self.os_type,
            hostname=hostname,
            raw_config=self.config_text,
            unrecognized_blocks=self._collect_unrecognized_blocks(),
            **results,
        )

        # M3: back-fill InterfaceConfig.ospf_passive from OSPF passive lists.
        # Only set ospf_passive on interfaces that are known OSPF participants
        # (explicitly named in passive_interfaces or non_passive_interfaces,
        # or whose ospf_process_id matches). Never infer passive for L2 ports
        # or interfaces not in any OSPF process — correctness over coverage.
        if pc.ospf_instances and pc.interfaces:
            intf_by_name = {i.name: i for i in pc.interfaces}
            for ospf in pc.ospf_instances:
                for name in ospf.passive_interfaces:
                    intf = intf_by_name.get(name)
                    if intf:
                        intf.ospf_passive = True
                for name in ospf.non_passive_interfaces:
                    intf = intf_by_name.get(name)
                    if intf:
                        intf.ospf_passive = False
                # For default-passive, only mark interfaces that belong to
                # this process (ospf_process_id matches or listed in an area)
                if ospf.passive_interface_default:
                    area_intfs: set[str] = set()
                    for area in ospf.areas:
                        area_intfs.update(area.interfaces)
                    non_passive_set = set(ospf.non_passive_interfaces)
                    for intf in pc.interfaces:
                        if intf.name in non_passive_set:
                            continue  # already handled above
                        if intf.name in area_intfs or intf.ospf_process_id == ospf.process_id:
                            intf.ospf_passive = True

        # Change-IR Phase 3: native op emission for migrated command
        # families (CCR change_ir_proposal_operations.md, Appendix D).
        # Runs LAST so op values reflect the final parsed state (all
        # subclass post-patches and the M3 backfill above included).
        # Default is a no-op; the IOS-family line-based parsers override.
        self._attach_native_change_ops(pc)

        return pc

    def _attach_native_change_ops(self, pc: ParsedConfig) -> None:
        """Hook: populate ``pc.native_change_ops`` for migrated families.

        Base implementation intentionally does nothing (JunOS/PAN-OS keep
        full legacy derivation until Phase 5).  The IOS parser family
        overrides this with family-1 interface scalar/boolean emission.
        """
        return None

    # Helper methods for common parsing tasks

    def _get_raw_lines_and_line_numbers(self, obj: Any) -> tuple[list[str], list[int]]:
        """Extract raw config lines and line numbers from a config object.

        Args:
            obj: CiscoConfParse config object

        Returns:
            Tuple of (raw_lines, line_numbers)
        """
        raw_lines = [obj.text]
        line_numbers = [obj.linenum]

        # Add all children
        for child in obj.children:
            raw_lines.append(child.text)
            line_numbers.append(child.linenum)

        return raw_lines, line_numbers

    def _extract_match(self, text: str, pattern: str, group: int = 1) -> str | None:
        """Extract regex match from text.

        Args:
            text: Text to search
            pattern: Regex pattern
            group: Group number to extract (default 1)

        Returns:
            Matched string or None
        """
        import re
        match = re.search(pattern, text)
        return match.group(group) if match else None

    def _is_shutdown(self, obj: Any) -> bool:
        """Check if interface/protocol is shutdown.

        Uses last-match-wins so that coalesced duplicate stanzas resolve
        correctly (e.g. ``shutdown`` in stanza 1, ``no shutdown`` in stanza 2
        → not shutdown).

        Args:
            obj: CiscoConfParse config object

        Returns:
            True if shutdown, False otherwise
        """
        result = False
        for child in obj.children:
            if re.match(r"^\s+no\s+shutdown", child.text):
                result = False
            elif re.match(r"^\s+shutdown", child.text):
                result = True
        return result


# ---------------------------------------------------------------------------
# Shared BGP peer-group attribute parser
# ---------------------------------------------------------------------------

def apply_peer_group_command(pg_data: dict, command: str) -> None:
    """Apply a single BGP peer-group attribute line to *pg_data* in-place.

    *command* is the attribute text after the peer-group name — e.g.
    ``"route-map RM-IN in"`` or ``"next-hop-self"``.  All three OS parsers
    (IOS, IOS-XR, NX-OS) extract this text in the same form and call this
    function; adding a new peer-group attribute requires exactly one change
    here rather than one change per parser.

    *pg_data* must already have all BGPPeerGroup fields initialised to their
    defaults (None / False) before the first call.
    """
    import re as _re

    if command.startswith("remote-as "):
        val = command.replace("remote-as ", "").strip()
        try:
            pg_data["remote_as"] = int(val)
        except ValueError:
            pg_data["remote_as"] = val

    elif command.startswith("description "):
        pg_data["description"] = command.replace("description ", "").strip()

    elif command.startswith("update-source "):
        pg_data["update_source"] = command.replace("update-source ", "").strip()

    elif command == "next-hop-self":
        pg_data["next_hop_self"] = True

    elif command == "route-reflector-client":
        pg_data["route_reflector_client"] = True

    elif command.startswith("send-community"):
        if "both" in command:
            pg_data["send_community"] = "both"
        elif "extended" in command:
            pg_data["send_community"] = "extended"
        else:
            pg_data["send_community"] = True

    elif command.startswith("route-map ") and " in" in command:
        m = _re.search(r"route-map\s+(\S+)\s+in", command)
        if m:
            pg_data["route_map_in"] = m.group(1)

    elif command.startswith("route-map ") and " out" in command:
        m = _re.search(r"route-map\s+(\S+)\s+out", command)
        if m:
            pg_data["route_map_out"] = m.group(1)

    elif command.startswith("prefix-list ") and " in" in command:
        m = _re.search(r"prefix-list\s+(\S+)\s+in", command)
        if m:
            pg_data["prefix_list_in"] = m.group(1)

    elif command.startswith("prefix-list ") and " out" in command:
        m = _re.search(r"prefix-list\s+(\S+)\s+out", command)
        if m:
            pg_data["prefix_list_out"] = m.group(1)

    elif command.startswith("filter-list ") and " in" in command:
        m = _re.search(r"filter-list\s+(\S+)\s+in", command)
        if m:
            pg_data["filter_list_in"] = m.group(1)

    elif command.startswith("filter-list ") and " out" in command:
        m = _re.search(r"filter-list\s+(\S+)\s+out", command)
        if m:
            pg_data["filter_list_out"] = m.group(1)

    elif command.startswith("ebgp-multihop "):
        parts = command.replace("ebgp-multihop ", "").strip().split()
        if parts:
            try:
                pg_data["ebgp_multihop"] = int(parts[0])
            except ValueError:
                pass

    elif command.startswith("password "):
        pg_data["password"] = command.replace("password ", "").strip()

    elif command == "fall-over bfd":
        pg_data["fall_over_bfd"] = True

    elif command == "disable-connected-check":
        pg_data["disable_connected_check"] = True

    elif command.startswith("maximum-prefix "):
        parts = command.replace("maximum-prefix ", "").strip().split()
        if parts:
            try:
                pg_data["maximum_prefix"] = int(parts[0])
            except ValueError:
                pass

    elif command.startswith("timers "):
        import re as _re2
        tm = _re2.match(r"timers\s+(\d+)\s+(\d+)", command)
        if tm:
            from confgraph.models.bgp import BGPTimers
            pg_data["timers"] = BGPTimers(
                keepalive=int(tm.group(1)), holdtime=int(tm.group(2)),
            )

    elif command.startswith("local-as "):
        la_parts = command.replace("local-as ", "").strip().split()
        if la_parts:
            try:
                pg_data["local_as"] = int(la_parts[0])
            except ValueError:
                pass
            pg_data["local_as_no_prepend"] = "no-prepend" in la_parts
            pg_data["local_as_replace_as"] = "replace-as" in la_parts


def _default_pg_data(name: str) -> dict:
    """Return a pg_data dict with all BGPPeerGroup fields at their defaults.

    Every parser must start from this dict before calling
    ``apply_peer_group_command`` so that BGPPeerGroup(**pg_data) always
    receives the full field set.
    """
    return {
        "name": name,
        "remote_as": None,
        "description": None,
        "update_source": None,
        "next_hop_self": False,
        "route_reflector_client": False,
        "send_community": False,
        "route_map_in": None,
        "route_map_out": None,
        "prefix_list_in": None,
        "prefix_list_out": None,
        "filter_list_in": None,
        "filter_list_out": None,
        "ebgp_multihop": None,
        "password": None,
        "fall_over_bfd": False,
        "disable_connected_check": False,
        "maximum_prefix": None,
        "timers": None,
        "local_as": None,
        "local_as_no_prepend": False,
        "local_as_replace_as": False,
    }
