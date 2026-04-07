"""Base parser class for network device configurations."""

import re
import traceback
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

    def _collect_unrecognized_blocks(self) -> list[UnrecognizedBlock]:
        """Collect top-level config blocks not claimed by any parse_* method.

        Walks all top-level (non-indented, non-comment) lines and returns
        those that don't match any pattern in _KNOWN_TOP_LEVEL_PATTERNS.
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
    ]

    def _find_error_context(self, exc: Exception) -> tuple[int, str]:
        """Extract the best-guess line number and text from a parse exception.

        Walks the traceback frames looking for a local variable that is a
        CiscoConfParse object with a ``linenum`` attribute (i.e. a config
        object being iterated at the point of failure).  Falls back to
        line 0 / empty string if nothing useful is found.
        """
        tb = traceback.extract_tb(exc.__traceback__)
        # Walk frames in reverse (innermost first) looking for a linenum hint
        for frame_summary in reversed(tb):
            # CiscoConfParse objects carry .linenum; check the frame's locals
            # via the live traceback object
            pass

        # Simpler fallback: search traceback string for a line number hint
        tb_str = "".join(traceback.format_tb(exc.__traceback__))
        match = re.search(r"line (\d+)", tb_str)
        if match:
            lineno = int(match.group(1))
            # Map Python source line → config line if in range
            if 1 <= lineno <= len(self.config_lines):
                return lineno, self.config_lines[lineno - 1]
        return 0, ""

    def parse(self) -> ParsedConfig:
        """Parse entire configuration and return ParsedConfig object.

        Fails fast: if any protocol parser raises an exception the entire
        parse is aborted and a ``ParseError`` is raised with the line
        number and config text that caused the failure.  No partial
        ``ParsedConfig`` is returned.

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

        return ParsedConfig(
            source_os=self.os_type,
            hostname=hostname,
            raw_config=self.config_text,
            unrecognized_blocks=self._collect_unrecognized_blocks(),
            **results,
        )

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

        Args:
            obj: CiscoConfParse config object

        Returns:
            True if shutdown, False otherwise
        """
        shutdown_children = obj.re_search_children(r"^\s+shutdown")
        return len(shutdown_children) > 0
