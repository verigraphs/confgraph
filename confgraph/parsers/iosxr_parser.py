"""Cisco IOS-XR configuration parser."""

import re
from ipaddress import IPv4Address, IPv4Interface, IPv4Network, IPv6Address, IPv6Interface

from confgraph.models.base import OSType
from confgraph.models.vrf import VRFConfig
from confgraph.models.bgp import (
    BGPAddressFamily,
    BGPConfig,
    BGPNeighbor,
    BGPNeighborAF,
    BGPPeerGroup,
    BGPRedistribute,
    BGPBestpathOptions,
)
from confgraph.models.acl import ACLConfig, ACLEntry
from confgraph.models.static_route import StaticRoute
from confgraph.models.multicast import MulticastConfig, PIMRPAddress
from confgraph.models.line import LineType
from confgraph.models.ospf import (
    OSPFConfig,
    OSPFArea,
    OSPFAreaType,
    OSPFInterfaceConfig,
    OSPFRange,
    OSPFRedistribute,
)
from confgraph.models.route_map import RouteMapConfig, RouteMapSequence, RouteMapMatch, RouteMapSet
from confgraph.models.prefix_list import PrefixListConfig, PrefixListEntry
from confgraph.models.community_list import (
    CommunityListConfig,
    CommunityListEntry,
    ASPathListConfig,
    ASPathListEntry,
)
from confgraph.models.isis import ISISConfig, ISISInterface, ISISRedistribute
from confgraph.parsers.base import _BASE_KNOWN_PATTERNS, apply_peer_group_command, _default_pg_data
from confgraph.parsers.ios_parser import IOSParser


# IOS-XR patterns differ from IOS: different VRF, route-policy, prefix-set, etc.
_IOSXR_KNOWN_PATTERNS: list[str] = [
    p for p in _BASE_KNOWN_PATTERNS
    if p not in (
        r"^vrf definition",
        r"^route-map",
        r"^ip prefix-list",
        r"^ipv6 prefix-list",
        r"^ip as-path access-list",
        r"^ip community-list",
    )
] + [
    r"^vrf\s+\S+",           # "vrf CUSTOMER_A"
    # XR lines are unnumbered templates, not IOS's "line vty 0 4" — the base
    # pattern only claims (con|vty|aux|tty), so these blocks were disclosed as
    # unrecognized. parse_lines consumes them now (CCR-0038 Theme 4).
    r"^line\s+(default|console|template)",
    r"^route-policy",         # IOS-XR route-policy
    r"^prefix-set",           # IOS-XR prefix-set
    r"^as-path-set",          # IOS-XR as-path-set
    r"^community-set",        # IOS-XR community-set
    r"^extcommunity-set",     # IOS-XR extcommunity-set
    r"^mpls",
    r"^l2vpn",
]


# CCR-0046. Any IOS-XR address-family sub-block header: `address-family ipv4
# unicast`, `address-family ipv6 unicast`, `address-family ipv4 multicast`…
_AF_HEADER_RE = re.compile(r"^\s*address-family\s+\S+")

# …and the ONE address family whose contents may be attributed to the enclosing
# object.  See _AFTransparentBlock: the model's IS-IS fields (`metric_style`,
# `ISISInterface.metric`) have no address-family dimension, so they mean IPv4
# unicast and nothing else.  A value from any other AF has no home and must not
# be attributed to them.
_AF_SPLICE_RE = re.compile(r"^\s*address-family\s+ipv4\s+unicast\b")


class _AFTransparentBlock:
    """A read-through view of an IOS-XR block that reads *through* its
    ``address-family ipv4 unicast`` sub-block — and only that one.

    IOS-XR nests one level deeper than the rest of the Cisco family.  An
    attribute *of the enclosing object* is emitted INSIDE an
    ``address-family <afi> <safi>`` sub-block rather than as a direct child of
    the block that owns it::

        router isis CORE
         address-family ipv4 unicast
          metric-style wide                   <- an attribute of the INSTANCE
          redistribute bgp 65000 route-policy RP-BGP-IN
         interface GigabitEthernet0/0/0/0
          address-family ipv4 unicast
           metric 10                          <- an attribute of the INTERFACE

    Every extractor in the IOS family reads *direct* children —
    ``find_child_objects`` defaults to ``recurse=False`` — so on IOS-XR they all
    stop at the door of the AF block and see nothing inside it.  That single
    mechanism is why ``metric_style``, ``redistribute`` and the per-interface
    ``metric`` were all ``None``/empty on every IOS-XR device ([[CCR-0046]]).

    **Only IPv4 unicast is spliced, and that is the whole point.**  ``ISISConfig``
    and ``ISISInterface`` have no address-family dimension: their ``metric_style``
    and ``metric`` are single-valued, and every consumer reads them as the
    device's IPv4 values.  A dual-stack IS-IS instance carries *two* answers::

        router isis BACKBONE
         address-family ipv6 unicast
          metric-style narrow                 <- IPv6's answer
         address-family ipv4 unicast
          metric-style wide                   <- IPv4's answer

    Splicing both would merge them into one field and let **whichever the vendor
    happened to write first** win — handing a consumer IPv6's answer to an IPv4
    question, silently, and with no way to tell.  Being wrong beats being absent
    only in the sense that it is worse.  So:

    * dual-stack  → the IPv4 values, deterministically, whatever the block order;
    * IPv4-only   → the IPv4 values;
    * IPv6-only   → **nothing**.  The model cannot represent it, so it says so by
      leaving the field ``None`` rather than presenting IPv6 numbers as IPv4 ones.
      A loud absence is the honest answer when there is no home for the value.

    This is the same rule that keeps the view off BGP neighbor blocks (below), and
    the AF dimension the model is missing is its own CCR, not a thing to fake here.

    The view is strictly ADDITIVE: every direct child is still returned, and the
    IPv4-unicast AF's contents are hoisted alongside them.  Non-IPv4 AF *headers*
    are still visible (they are containers, which no extractor reads as an
    attribute); only their contents are withheld.  ``text``, ``linenum``,
    ``children`` and ``all_children`` are forwarded to the wrapped object
    untouched, so raw-line capture, line numbers and change-IR provenance are
    bit-for-bit unchanged.  ``recurse=True`` is forwarded as well.

    Deliberately NOT applied to BGP neighbor blocks: there the AF sub-block is a
    real object (``BGPNeighborAF``), and flattening an AF-scoped policy up onto
    the neighbor would assert it for every address family.  That value's home is
    [[CCR-0045]]'s question, not this view's to answer.
    """

    __slots__ = ("_obj",)

    def __init__(self, obj) -> None:
        self._obj = obj

    @staticmethod
    def _effective_children(obj) -> list:
        """Direct children, plus the contents of the ``ipv4 unicast`` AF sub-block.

        Additive by construction: every direct child is kept, and only the
        IPv4-unicast AF is descended into (recursively).  An ``ipv6 unicast`` /
        ``ipv4 multicast`` / ``vpnv4`` block therefore contributes its header and
        nothing else — its contents have no home in a model whose IS-IS fields
        carry no address-family dimension, and attributing them to those fields
        would be a confident wrong answer where ``None`` is the honest one.
        """
        out: list = []
        for child in obj.children:
            out.append(child)
            if _AF_SPLICE_RE.match(child.text):
                out.extend(_AFTransparentBlock._effective_children(child))
        return out

    def find_child_objects(self, regex, recurse: bool = False, reverse: bool = False) -> list:
        if recurse:
            return self._obj.find_child_objects(regex, recurse=True, reverse=reverse)
        matches = [c for c in self._effective_children(self._obj) if c.re_search(regex)]
        if reverse:
            matches.reverse()
        return matches

    def __getattr__(self, name):
        return getattr(self._obj, name)


class IOSXRParser(IOSParser):
    """Parser for Cisco IOS-XR configurations.

    Inherits from IOSParser and overrides methods where IOS-XR syntax
    differs: VRF (vrf NAME with nested RT blocks), interfaces (ipv4 address),
    BGP (neighbor-group / use neighbor-group), OSPF (interfaces nested under
    area blocks), route-policy → RouteMapConfig, prefix-set → PrefixListConfig,
    as-path-set → ASPathListConfig, community-set → CommunityListConfig.
    """

    _KNOWN_TOP_LEVEL_PATTERNS: list[str] = _IOSXR_KNOWN_PATTERNS

    # Child-line disclosure disabled for IOS-XR (v1): XR block bodies are deeply
    # nested and shaped differently from IOS (interfaces under OSPF areas,
    # neighbor-groups, "address-family ipv4 unicast" bodies), so the inherited IOS
    # known-child lists would false-flag consumed lines. Needs an XR-specific
    # registry — see CCR confgraph_unrecognized_child_lines_in_claimed_blocks.md.
    _KNOWN_CHILD_PATTERNS: list[tuple[str, list[str]]] = []

    # CCR-0038 Theme 1 — the IOS-XR dialect of the shared VRF body vocabulary.
    # XR names a *route-policy*, not a route-map, and puts the verb first:
    # `import route-policy RP-VRF-IN` / `export route-policy RP-VRF-OUT`.
    # `description` is spelled as everywhere else and comes free from the parent.
    _VRF_SCALAR_PATTERNS = {
        **IOSParser._VRF_SCALAR_PATTERNS,
        "route_map_import": IOSParser._VRF_SCALAR_PATTERNS["route_map_import"].extended(
            r"^import\s+route-policy\s+(?P<val>\S+)",
        ),
        "route_map_export": IOSParser._VRF_SCALAR_PATTERNS["route_map_export"].extended(
            r"^export\s+route-policy\s+(?P<val>\S+)",
        ),
    }

    # CCR-0038 Theme 4 — the IOS-XR line dialect. XR has no numbered vty lines at
    # all: it configures `line default` (the template every unmatched line
    # inherits), `line console`, and named `line template <name>` blocks. The
    # inherited IOS header requires (con|vty|aux|tty) followed by a DIGIT, so it
    # matched none of them and `p.lines` was empty on every XR device.
    #
    # `vty-pool default 0 4 line-template test` is deliberately NOT matched here:
    # it is a single top-level line that BINDS a template to a vty range, not a
    # line block, and parsing it as one would invent a block that does not exist.
    #
    # Only the header is declared; the body (exec-timeout, transport input,
    # access-class …) is the shared walk in IOSParser.parse_lines. Note XR emits
    # `exec-timeout <minutes> <seconds>` with BOTH operands always present, which
    # the shared body regex already reads.
    _LINE_HEADER_PATTERNS = IOSParser._LINE_HEADER_PATTERNS.extended(
        r"^line\s+(?P<type>template)\s+(?P<name>\S+)",
        r"^line\s+(?P<type>default|console)\s*$",
    )

    _LINE_TYPES = {
        **IOSParser._LINE_TYPES,
        "default": LineType.DEFAULT,
        "template": LineType.TEMPLATE,
    }

    def __init__(self, config_text: str):
        super().__init__(config_text, os_type=OSType.IOS_XR)
        self.syntax = "iosxr"
        self.parse_obj = None  # Force re-creation with new syntax

    # -----------------------------------------------------------------------
    # Nested-block descent (CCR-0046)
    # -----------------------------------------------------------------------

    def _nested_block(self, obj):
        """IOS-XR reads an object's attributes *through* its ``address-family``
        sub-blocks — see ``_AFTransparentBlock``.  This is the one override that
        turns the whole IOS-family extractor set into an AF-aware one.
        """
        return _AFTransparentBlock(obj)

    # -----------------------------------------------------------------------
    # VRFs — "vrf NAME" with nested import/export route-target blocks
    # -----------------------------------------------------------------------

    def parse_vrfs(self) -> list[VRFConfig]:
        """Parse VRF configurations from IOS-XR config.

        IOS-XR format::

            vrf CUSTOMER_A
             address-family ipv4 unicast
              import route-target
               65000:100
              !
              export route-target
               65000:100
              !
        """
        vrfs = []
        parse = self._get_parse_obj()

        # IOS-XR: top-level "vrf NAME" blocks (not "vrf definition" or "vrf context")
        vrf_objs = parse.find_objects(r"^vrf\s+(\S+)")
        for vrf_obj in vrf_objs:
            # Skip false positives like "vrf definition" (IOS-XE)
            if re.match(r"^vrf\s+(definition|context)\s+", vrf_obj.text):
                continue

            vrf_name = self._extract_match(vrf_obj.text, r"^vrf\s+(\S+)")
            if not vrf_name:
                continue

            raw_lines, line_numbers = self._get_raw_lines_and_line_numbers(vrf_obj)

            # Route-targets are under address-family → import/export route-target blocks
            rt_import: list[str] = []
            rt_export: list[str] = []
            rt_both: list[str] = []

            # Walk all_children to find import/export route-target stanzas
            in_import_rt = False
            in_export_rt = False
            for child in vrf_obj.all_children:
                text = child.text.strip()
                if text == "import route-target":
                    in_import_rt = True
                    in_export_rt = False
                    continue
                elif text == "export route-target":
                    in_export_rt = True
                    in_import_rt = False
                    continue
                elif text.startswith("!") or (text and not text[0].isdigit() and ":" not in text):
                    in_import_rt = False
                    in_export_rt = False

                if in_import_rt and re.match(r"\d+:\d+", text):
                    rt_import.append(text)
                elif in_export_rt and re.match(r"\d+:\d+", text):
                    rt_export.append(text)

            # description + import/export route-policy — the shared VRF body
            # vocabulary, IOS-XR dialect (CCR-0038 Theme 1).
            scalars: dict = {}
            for child in vrf_obj.all_children:
                self._apply_vrf_body_line(scalars, child.text.strip())

            vrfs.append(
                VRFConfig(
                    object_id=f"vrf_{vrf_name}",
                    raw_lines=raw_lines,
                    source_os=self.os_type,
                    line_numbers=line_numbers,
                    name=vrf_name,
                    rd=None,  # IOS-XR puts RD under BGP, not VRF definition
                    route_target_import=rt_import,
                    route_target_export=rt_export,
                    route_target_both=rt_both,
                    **scalars,
                )
            )

        return vrfs

    # -----------------------------------------------------------------------
    # Interface VRF — "vrf NAME" (no "forwarding" keyword)
    # -----------------------------------------------------------------------

    def _extract_interface_vrf(self, intf_obj) -> str | None:
        """Extract VRF from interface. IOS-XR uses ``vrf NAME`` (no keyword)."""
        vrf_ch = intf_obj.find_child_objects(r"^\s+vrf\s+(\S+)")
        if vrf_ch:
            return self._extract_match(vrf_ch[0].text, r"^\s+vrf\s+(\S+)")
        return None

    # -----------------------------------------------------------------------
    # Interfaces — "ipv4 address X.X.X.X MASK"
    # -----------------------------------------------------------------------

    def parse_interfaces(self) -> list:
        """Parse interfaces. Override IP address extraction for IOS-XR notation."""
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

            # IOS-XR: ipv4 address X.X.X.X MASK [secondary]
            ipv4_children = intf_obj.find_child_objects(
                r"^\s+ipv4\s+address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)"
            )
            ipv4_primary = [c for c in ipv4_children if "secondary" not in c.text.lower()]
            if ipv4_primary:
                match = re.search(
                    r"^\s+ipv4\s+address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)",
                    ipv4_primary[0].text,
                )
                if match:
                    try:
                        intf_cfg.ip_address = IPv4Interface(
                            f"{match.group(1)}/{match.group(2)}"
                        )
                    except ValueError:
                        pass
            for sec in (c for c in ipv4_children if "secondary" in c.text.lower()):
                sm = re.search(
                    r"^\s+ipv4\s+address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)",
                    sec.text,
                )
                if sm:
                    try:
                        ip = IPv4Interface(f"{sm.group(1)}/{sm.group(2)}")
                        if ip not in intf_cfg.secondary_ips:
                            intf_cfg.secondary_ips.append(ip)
                    except ValueError:
                        pass

            # IOS-XR: ipv4 access-group <name> ingress|egress
            for ag_ch in intf_obj.find_child_objects(
                r"^\s+ipv4\s+access-group\s+\S+\s+(ingress|egress)"
            ):
                m = re.match(r"^\s+ipv4\s+access-group\s+(\S+)\s+(ingress|egress)", ag_ch.text)
                if m:
                    if m.group(2) == "ingress":
                        intf_cfg.acl_in = m.group(1)
                    else:
                        intf_cfg.acl_out = m.group(1)

            # IOS-XR: ipv6 address
            ipv6_children = intf_obj.find_child_objects(r"^\s+ipv6\s+address\s+(\S+)")
            ipv6_addresses = []
            for ipv6_child in ipv6_children:
                m = re.search(r"^\s+ipv6\s+address\s+(\S+)", ipv6_child.text)
                if m and "link-local" not in ipv6_child.text:
                    try:
                        ipv6_addresses.append(IPv6Interface(m.group(1)))
                    except ValueError:
                        pass
            if ipv6_addresses:
                intf_cfg.ipv6_addresses = ipv6_addresses

        return interfaces

    def _detect_interface_field_negation_ops(
        self, intf_obj, intf_name: str
    ) -> list:
        """IOS-XR variant — ``no ipv4 access-group … ingress|egress``.

        Only acl_in / acl_out are positively parsed on XR; service_policy and
        nat_direction use different syntax and are not modeled, so no negation
        detection is needed for them.  Returns native UNSET ChangeOps (the
        caller generates the legacy tombstones from them via encode_legacy —
        Phase 3 family 1, CCR Appendix D).
        """
        from confgraph.change_ir import ChangeOp, Verb

        ops: list = []

        for ch in intf_obj.find_child_objects(
            r"^\s+no\s+ipv4\s+access-group\s+"
        ):
            m = re.match(
                r"^\s+no\s+ipv4\s+access-group\s+\S+\s+(ingress|egress)",
                ch.text,
            )
            if m:
                field = "acl_in" if m.group(1) == "ingress" else "acl_out"
                ops.append(
                    ChangeOp(
                        verb=Verb.UNSET,
                        path=("field", "interface", intf_name, field),
                        value=None,
                        source_line=ch.text.strip(),
                        line_no=ch.linenum,
                        origin="native",
                    )
                )

        return ops

    # -----------------------------------------------------------------------
    # BGP — shared neighbor block parsers (single source of truth)
    # -----------------------------------------------------------------------

    def _parse_iosxr_neighbor_block(self, nb_child) -> dict:
        """Parse all attributes from a single IOS-XR ``neighbor X { ... }`` block.

        This is the single source of truth for neighbor attribute parsing in
        IOS-XR.  Both the global neighbor path (``_parse_bgp_neighbors``) and
        the VRF neighbor path (``_parse_bgp_vrf_instances``) delegate here so
        that adding a new field requires exactly one code change.

        IOS-XR block structure::

            neighbor 10.1.1.1
             remote-as 65001
             description ISP1
             update-source Loopback0
             ebgp-multihop 2
             password encrypted <hash>
             fall-over bfd
             local-as 65099 no-prepend replace-as
             address-family ipv4 unicast
              route-policy ISP-IN in
              route-policy ISP-OUT out
              prefix-set ALLOWED-IN in
              next-hop-self
              send-community-ebgp
              route-reflector-client

        Returns a flat dict keyed by BGPNeighbor field names.  The caller is
        responsible for checking ``remote_as``/``peer_group`` presence and
        constructing the ``BGPNeighbor`` object.
        """
        nd: dict = {
            "remote_as": None,
            "peer_group": None,
            "description": None,
            "update_source": None,
            "ebgp_multihop": None,
            "password": None,
            "shutdown": False,
            "fall_over_bfd": False,
            "local_as": None,
            "local_as_no_prepend": False,
            "local_as_replace_as": False,
            "next_hop_self": False,
            "send_community": False,
            "route_reflector_client": False,
            "route_map_in": None,
            "route_map_out": None,
            "prefix_list_in": None,
            "prefix_list_out": None,
            "timers": None,
        }

        # Use .children (direct children only) — not .all_children — so
        # AF-level attributes (route-policy, next-hop-self, etc. inside
        # address-family sub-blocks) don't flatten onto the neighbor.
        # Per-AF policies are handled separately by _apply_bgp_af_neighbor_policies.
        for child in nb_child.children:
            text = child.text.strip()

            if text.startswith("remote-as "):
                val = text.split(None, 1)[1].strip()
                try:
                    nd["remote_as"] = int(val)
                except ValueError:
                    nd["remote_as"] = val
            elif text.startswith("description "):
                nd["description"] = text.split(None, 1)[1].strip()
            elif text.startswith("update-source "):
                nd["update_source"] = text.split(None, 1)[1].strip()
            elif text.startswith("ebgp-multihop "):
                parts = text.split()
                if len(parts) > 1 and parts[1].isdigit():
                    nd["ebgp_multihop"] = int(parts[1])
            elif text.startswith("use neighbor-group "):
                nd["peer_group"] = text.split(None, 2)[2].strip()
            elif text.startswith("password "):
                parts = text.split(None, 2)
                if len(parts) == 3:
                    nd["password"] = parts[2]
                elif len(parts) == 2:
                    nd["password"] = parts[1]
            elif text == "shutdown":
                nd["shutdown"] = True
            elif text == "fall-over bfd":
                nd["fall_over_bfd"] = True
            elif text.startswith("local-as "):
                parts = text.split()
                if len(parts) >= 2 and parts[1].isdigit():
                    nd["local_as"] = int(parts[1])
                    nd["local_as_no_prepend"] = "no-prepend" in parts
                    nd["local_as_replace_as"] = "replace-as" in parts
            elif text.startswith("timers "):
                tm = re.match(r"timers\s+(\d+)\s+(\d+)", text)
                if tm:
                    from confgraph.models.bgp import BGPTimers
                    nd["timers"] = BGPTimers(
                        keepalive=int(tm.group(1)), holdtime=int(tm.group(2)),
                    )
            # Neighbor-level route-policy / next-hop-self / etc. (direct child,
            # not nested under an address-family block)
            elif text.startswith("route-policy ") and text.endswith(" in"):
                nd["route_map_in"] = text[len("route-policy "):-3].strip()
            elif text.startswith("route-policy ") and text.endswith(" out"):
                nd["route_map_out"] = text[len("route-policy "):-4].strip()
            elif text.startswith("prefix-set ") and text.endswith(" in"):
                nd["prefix_list_in"] = text[len("prefix-set "):-3].strip()
            elif text.startswith("prefix-set ") and text.endswith(" out"):
                nd["prefix_list_out"] = text[len("prefix-set "):-4].strip()
            elif text == "next-hop-self":
                nd["next_hop_self"] = True
            elif text == "route-reflector-client":
                nd["route_reflector_client"] = True
            elif text.startswith("send-community"):
                if "both" in text:
                    nd["send_community"] = "both"
                elif "extended" in text:
                    nd["send_community"] = "extended"
                else:
                    nd["send_community"] = True

        return nd

    def _parse_iosxr_neighbor_af_block(self, af_child) -> dict:
        """Parse a single ``address-family ipv4|ipv6 unicast`` block under a neighbor.

        Used by ``_apply_bgp_af_neighbor_policies`` to build ``BGPNeighborAF``
        objects.  Returns an af_data dict keyed by ``BGPNeighborAF`` field names.
        """
        af_data: dict = {
            "activate": True,
            "route_map_in": None,
            "route_map_out": None,
            "prefix_list_in": None,
            "prefix_list_out": None,
            "filter_list_in": None,
            "filter_list_out": None,
            "next_hop_self": False,
            "send_community": False,
            "route_reflector_client": False,
            "default_originate": False,
            "default_originate_route_map": None,
            "maximum_prefix": None,
            "maximum_prefix_threshold": None,
            "maximum_prefix_warning_only": False,
        }

        for policy_child in af_child.all_children:
            cmd = policy_child.text.strip()
            if cmd.startswith("maximum-prefix "):
                # CCR-0046 row 4. `maximum-prefix <limit> [<threshold-pct>]
                # [warning-only | restart <n> | discard-extra-paths]`.  IOS-XR
                # scopes the prefix limit PER ADDRESS-FAMILY — it is emitted inside
                # `neighbor X / address-family ipv4 unicast` and a neighbor can
                # carry a different limit per AF — so it lands on the BGPNeighborAF,
                # which is where the model already has a home for it.  It is
                # deliberately NOT copied up onto BGPNeighbor.maximum_prefix:
                # promoting an AF-scoped value to the neighbor would assert one
                # AF's limit for all of them.  That promotion is [[CCR-0045]]'s
                # question, not this one's.
                mp = re.match(r"maximum-prefix\s+(\d+)(?:\s+(\d+))?", cmd)
                if mp:
                    af_data["maximum_prefix"] = int(mp.group(1))
                    if mp.group(2):
                        af_data["maximum_prefix_threshold"] = int(mp.group(2))
                    af_data["maximum_prefix_warning_only"] = "warning-only" in cmd
            elif cmd.startswith("route-policy ") and cmd.endswith(" in"):
                af_data["route_map_in"] = cmd[len("route-policy "):-3].strip()
            elif cmd.startswith("route-policy ") and cmd.endswith(" out"):
                af_data["route_map_out"] = cmd[len("route-policy "):-4].strip()
            elif cmd.startswith("prefix-set ") and cmd.endswith(" in"):
                af_data["prefix_list_in"] = cmd[len("prefix-set "):-3].strip()
            elif cmd.startswith("prefix-set ") and cmd.endswith(" out"):
                af_data["prefix_list_out"] = cmd[len("prefix-set "):-4].strip()
            elif cmd == "next-hop-self":
                af_data["next_hop_self"] = True
            elif cmd == "route-reflector-client":
                af_data["route_reflector_client"] = True
            elif cmd.startswith("send-community"):
                if "both" in cmd:
                    af_data["send_community"] = "both"
                elif "extended" in cmd:
                    af_data["send_community"] = "extended"
                else:
                    af_data["send_community"] = True
            elif cmd.startswith("default-originate"):
                # IOS-XR emits `default-originate` (unconditional) or
                # `default-originate route-policy <name>` (conditional) as a bare
                # child of the neighbor's address-family sub-block. The boolean is
                # set in BOTH cases; the route-policy is recorded only for the
                # conditional form (stored in default_originate_route_map, the
                # dialect-neutral field the model exposes).
                af_data["default_originate"] = True
                rp_m = re.match(r"default-originate\s+route-policy\s+(\S+)", cmd)
                if rp_m:
                    af_data["default_originate_route_map"] = rp_m.group(1)

        return af_data

    # -----------------------------------------------------------------------
    # BGP — "neighbor-group NAME" / "use neighbor-group NAME"
    # -----------------------------------------------------------------------

    def _parse_bgp_peer_groups(self, bgp_obj) -> list[BGPPeerGroup]:
        """Parse BGP peer-groups. IOS-XR uses ``neighbor-group NAME`` blocks."""
        peer_groups = []

        ng_children = bgp_obj.find_child_objects(r"^\s+neighbor-group\s+(\S+)")
        for ng_child in ng_children:
            pg_name = self._extract_match(ng_child.text, r"^\s+neighbor-group\s+(\S+)")
            if not pg_name:
                continue

            pg_data = _default_pg_data(pg_name)

            for child in ng_child.all_children:
                apply_peer_group_command(pg_data, child.text.strip())

            peer_groups.append(BGPPeerGroup(**pg_data))

        return peer_groups

    def _parse_bgp_vrf_instances(self, bgp_obj, asn: int) -> list[BGPConfig]:
        """Parse VRF-specific BGP instances (``router bgp`` → ``vrf NAME`` block).

        Delegates to the shared block-form traversal ``_parse_bgp_vrf_blocks``
        (CCR-0032). That helper descends via ``_iter_router_vrf_blocks``, reads the
        RD and any route-targets onto ``BGPConfig`` (from where the shared
        ``BaseParser._backfill_vrf_rd_rt`` walk attributes them to the VRFConfig —
        [[CCR-0059]]), and delegates neighbors to this class's
        ``_parse_bgp_neighbors`` — the same block-form neighbor parser used for
        the global instance, so the two paths can no longer diverge.
        """
        return self._parse_bgp_vrf_blocks(bgp_obj, asn)

    # -----------------------------------------------------------------------
    # BGP address-families — "address-family ipv4 unicast" + "maximum-paths ebgp N"
    # -----------------------------------------------------------------------

    def _parse_bgp_address_families(self, bgp_obj) -> list[BGPAddressFamily]:
        """Parse BGP address-families for IOS-XR.

        IOS-XR differences from IOS:
        - AF header: ``address-family ipv4 unicast`` (requires ``unicast`` keyword)
        - max-paths eBGP: ``maximum-paths ebgp N`` (not plain ``maximum-paths N``)
        - max-paths iBGP: ``maximum-paths ibgp N`` (same as IOS)
        """
        address_families: list[BGPAddressFamily] = []

        af_children = bgp_obj.find_child_objects(
            r"^\s+address-family\s+(ipv4|ipv6)\s+unicast"
        )
        for af_child in af_children:
            m = re.search(r"^\s+address-family\s+(ipv4|ipv6)\s+unicast", af_child.text)
            if not m:
                continue

            afi = m.group(1)

            # IOS-XR: maximum-paths ebgp N
            maximum_paths: int | None = None
            mp_ch = af_child.find_child_objects(r"^\s+maximum-paths\s+ebgp\s+(\d+)")
            if mp_ch:
                v = self._extract_match(mp_ch[0].text, r"^\s+maximum-paths\s+ebgp\s+(\d+)")
                if v:
                    maximum_paths = int(v)

            # IOS-XR: maximum-paths ibgp N
            maximum_paths_ibgp: int | None = None
            mp_ibgp_ch = af_child.find_child_objects(r"^\s+maximum-paths\s+ibgp\s+(\d+)")
            if mp_ibgp_ch:
                v = self._extract_match(mp_ibgp_ch[0].text, r"^\s+maximum-paths\s+ibgp\s+(\d+)")
                if v:
                    maximum_paths_ibgp = int(v)

            # CCR-0032: descend into the AF block for the prefixes the router
            # originates/redistributes/aggregates. Reuses the shared IOS
            # statement helpers (extended to accept route-policy as well as
            # route-map), so adding an AF child is one shared change, not a
            # new per-OS walk. IOS-XR spells these with route-policy.
            networks = self._parse_bgp_network_stmts(
                af_child.find_child_objects(r"^\s+network\s+")
            )
            redistribute = self._parse_bgp_redistribute_stmts(
                af_child.find_child_objects(r"^\s+redistribute\s+(\S+)")
            )
            aggregates = self._parse_bgp_aggregate_stmts(
                af_child.find_child_objects(r"^\s+aggregate-address\s+(\S+)")
            )

            address_families.append(BGPAddressFamily(
                afi=afi,
                safi="unicast",
                vrf=None,
                networks=networks,
                redistribute=redistribute,
                aggregate_addresses=aggregates,
                maximum_paths=maximum_paths,
                maximum_paths_ibgp=maximum_paths_ibgp,
            ))

        return address_families

    # -----------------------------------------------------------------------
    # OSPF — interfaces nested under area blocks
    # -----------------------------------------------------------------------

    def parse_ospf(self) -> list[OSPFConfig]:
        """Parse OSPF configurations for IOS-XR.

        IOS-XR nests interface membership under ``area N`` → ``interface NAME``
        blocks instead of per-interface ``ip ospf`` commands.
        """
        ospf_instances = []
        parse = self._get_parse_obj()

        # Process header pattern set: numeric id and string tag ("router ospf
        # CORE"). ``process_id`` is ``int | str`` so a tag is kept verbatim.
        ospf_objs = parse.find_objects(self._OSPF_PROC_PATTERNS.union)
        for ospf_obj in ospf_objs:
            hdr = self._OSPF_PROC_PATTERNS.match(ospf_obj.text)
            process_id_str = hdr.group("pid") if hdr else None
            if not process_id_str:
                continue

            process_id: int | str = int(process_id_str) if process_id_str.isdigit() else process_id_str
            raw_lines, line_numbers = self._get_raw_lines_and_line_numbers(ospf_obj)

            # Router ID
            router_id = None
            rid_ch = ospf_obj.find_child_objects(r"^\s+router-id\s+(\S+)")
            if rid_ch:
                rid_str = self._extract_match(rid_ch[0].text, r"^\s+router-id\s+(\S+)")
                try:
                    router_id = IPv4Address(rid_str)
                except ValueError:
                    pass

            # Log adjacency changes
            log_adj = bool(ospf_obj.find_child_objects(r"^\s+log\s+adjacency\s+changes"))
            log_adj_detail = bool(ospf_obj.find_child_objects(r"^\s+log\s+adjacency\s+changes\s+detail"))

            # Auto-cost
            auto_cost_ref_bw = None
            ac_ch = ospf_obj.find_child_objects(r"^\s+auto-cost\s+reference-bandwidth\s+(\d+)")
            if ac_ch:
                v = self._extract_match(ac_ch[0].text, r"^\s+auto-cost\s+reference-bandwidth\s+(\d+)")
                if v:
                    auto_cost_ref_bw = int(v)

            # Passive interface default (IOS-XR: per-interface "passive enable")
            passive_interface_default = False
            passive_interfaces: list[str] = []
            non_passive_interfaces: list[str] = []

            # Parse areas — IOS-XR has "area N" stanzas with nested interfaces
            areas, passive_interfaces = self._parse_ospf_areas_iosxr(ospf_obj, process_id)

            # Redistribution
            redistribute = self._parse_ospf_redistribute_iosxr(ospf_obj)

            # Max-metric router-lsa
            max_metric_router_lsa = False
            max_metric_router_lsa_on_startup: int | None = None
            mm_ch = ospf_obj.find_child_objects(r"^\s+max-metric\s+router-lsa")
            if mm_ch:
                max_metric_router_lsa = True
                m = re.search(r"on-startup\s+(\d+)", mm_ch[0].text)
                if m:
                    max_metric_router_lsa_on_startup = int(m.group(1))

            # Default-information originate
            di_originate = False
            di_always = False
            di_metric: int | None = None
            di_metric_type: int | None = None
            di_route_map: str | None = None

            di_ch = ospf_obj.find_child_objects(r"^\s+default-information\s+originate")
            if di_ch:
                di_originate = True
                di_text = di_ch[0].text
                di_always = "always" in di_text
                m = re.search(r"\bmetric\s+(\d+)", di_text)
                if m:
                    di_metric = int(m.group(1))
                m = re.search(r"\bmetric-type\s+(\d+)", di_text)
                if m:
                    di_metric_type = int(m.group(1))
                m = re.search(r"\broute-policy\s+(\S+)", di_text)
                if m:
                    di_route_map = m.group(1)

            # ---- OSPF-advanced fields ----

            # Distance
            distance: int | None = None
            distance_intra: int | None = None
            distance_inter: int | None = None
            distance_external: int | None = None
            dist_ospf_ch = ospf_obj.find_child_objects(r"^\s+distance\s+ospf")
            for dc in dist_ospf_ch:
                m = re.search(r"intra-area\s+(\d+)", dc.text)
                if m:
                    distance_intra = int(m.group(1))
                m = re.search(r"inter-area\s+(\d+)", dc.text)
                if m:
                    distance_inter = int(m.group(1))
                m = re.search(r"external\s+(\d+)", dc.text)
                if m:
                    distance_external = int(m.group(1))
            dist_simple_ch = ospf_obj.find_child_objects(r"^\s+distance\s+(\d+)\s*$")
            if dist_simple_ch:
                v = self._extract_match(dist_simple_ch[0].text, r"^\s+distance\s+(\d+)")
                if v:
                    distance = int(v)

            # Default metric
            default_metric: int | None = None
            dm_ch = ospf_obj.find_child_objects(r"^\s+default-metric\s+(\d+)")
            if dm_ch:
                v = self._extract_match(dm_ch[0].text, r"^\s+default-metric\s+(\d+)")
                if v:
                    default_metric = int(v)

            # Max LSA
            max_lsa: int | None = None
            ml_ch = ospf_obj.find_child_objects(r"^\s+max-lsa\s+(\d+)")
            if ml_ch:
                v = self._extract_match(ml_ch[0].text, r"^\s+max-lsa\s+(\d+)")
                if v:
                    max_lsa = int(v)

            # Timers throttle spf
            spf_initial: int | None = None
            spf_min: int | None = None
            spf_max: int | None = None
            spf_ch = ospf_obj.find_child_objects(r"^\s+timers\s+throttle\s+spf\s+(\d+)\s+(\d+)\s+(\d+)")
            if spf_ch:
                m = re.match(r"^\s+timers\s+throttle\s+spf\s+(\d+)\s+(\d+)\s+(\d+)", spf_ch[0].text)
                if m:
                    spf_initial = int(m.group(1))
                    spf_min = int(m.group(2))
                    spf_max = int(m.group(3))

            # Timers throttle lsa all
            lsa_all: int | None = None
            lsa_ch = ospf_obj.find_child_objects(r"^\s+timers\s+throttle\s+lsa\s+all\s+(\d+)")
            if lsa_ch:
                v = self._extract_match(lsa_ch[0].text, r"^\s+timers\s+throttle\s+lsa\s+all\s+(\d+)")
                if v:
                    lsa_all = int(v)

            # Shutdown
            ospf_shutdown = len(ospf_obj.find_child_objects(r"^\s+shutdown\s*$")) > 0

            # Graceful restart (IOS-XR uses "graceful-restart" directly)
            graceful_restart = len(ospf_obj.find_child_objects(r"^\s+graceful-restart\s*$")) > 0
            graceful_restart_helper = len(
                ospf_obj.find_child_objects(r"^\s+graceful-restart\s+helper")
            ) > 0
            if not graceful_restart:
                graceful_restart = len(ospf_obj.find_child_objects(r"^\s+nsf\b")) > 0

            # BFD all-interfaces
            bfd_all = len(ospf_obj.find_child_objects(r"^\s+bfd\s+(?:fast-detect|all-interfaces)")) > 0

            ospf_instances.append(
                OSPFConfig(
                    object_id=f"ospf_{process_id}",
                    raw_lines=raw_lines,
                    source_os=self.os_type,
                    line_numbers=line_numbers,
                    process_id=process_id,
                    vrf=None,
                    router_id=router_id,
                    log_adjacency_changes=log_adj,
                    log_adjacency_changes_detail=log_adj_detail,
                    auto_cost_reference_bandwidth=auto_cost_ref_bw,
                    passive_interface_default=passive_interface_default,
                    passive_interfaces=passive_interfaces,
                    non_passive_interfaces=non_passive_interfaces,
                    areas=areas,
                    redistribute=redistribute,
                    max_metric_router_lsa=max_metric_router_lsa,
                    max_metric_router_lsa_on_startup=max_metric_router_lsa_on_startup,
                    default_information_originate=di_originate,
                    default_information_originate_always=di_always,
                    default_information_originate_metric=di_metric,
                    default_information_originate_metric_type=di_metric_type,
                    default_information_originate_route_map=di_route_map,
                    distance=distance,
                    distance_intra_area=distance_intra,
                    distance_inter_area=distance_inter,
                    distance_external=distance_external,
                    default_metric=default_metric,
                    max_lsa=max_lsa,
                    timers_throttle_spf_initial=spf_initial,
                    timers_throttle_spf_min=spf_min,
                    timers_throttle_spf_max=spf_max,
                    timers_throttle_lsa_all=lsa_all,
                    shutdown=ospf_shutdown,
                    graceful_restart=graceful_restart,
                    graceful_restart_helper=graceful_restart_helper,
                    bfd_all_interfaces=bfd_all,
                )
            )

        # CCR-0032: OSPF-VRF via the same VRF-block traversal as BGP-VRF.
        ospf_instances.extend(self._parse_ospf_vrf_instances(parse))

        return ospf_instances

    def _build_ospf_vrf_instance(self, process_id, vrf_name, vrf_obj) -> OSPFConfig:
        """Build one OSPFConfig for an IOS-XR ``vrf NAME`` OSPF sub-block.

        Overrides the IOS flat-area default to use IOS-XR's nested
        ``area > interface`` area parser (CCR-0032).
        """
        raw_lines, line_numbers = self._get_raw_lines_and_line_numbers(vrf_obj)

        router_id = None
        rid_ch = vrf_obj.find_child_objects(r"^\s+router-id\s+(\S+)")
        if rid_ch:
            rid_str = self._extract_match(rid_ch[0].text, r"^\s+router-id\s+(\S+)")
            try:
                router_id = IPv4Address(rid_str)
            except ValueError:
                pass

        areas, passive_interfaces = self._parse_ospf_areas_iosxr(vrf_obj, process_id)
        redistribute = self._parse_ospf_redistribute_iosxr(vrf_obj)

        return OSPFConfig(
            object_id=f"ospf_{process_id}_vrf_{vrf_name}",
            raw_lines=raw_lines,
            source_os=self.os_type,
            line_numbers=line_numbers,
            process_id=process_id,
            vrf=vrf_name,
            router_id=router_id,
            areas=areas,
            passive_interfaces=passive_interfaces,
            redistribute=redistribute,
        )

    def _parse_ospf_areas_iosxr(
        self, ospf_obj, process_id: int | str | None = None
    ) -> tuple[list[OSPFArea], list[str]]:
        """Parse OSPF areas with nested interface blocks (IOS-XR style).

        Returns a tuple of (areas, passive_interfaces).
        """
        areas: list[OSPFArea] = []
        area_dict: dict[str, dict] = {}
        passive_interfaces: list[str] = []

        area_children = ospf_obj.find_child_objects(r"^\s+area\s+(\S+)")
        for area_child in area_children:
            area_id = self._extract_match(area_child.text, r"^\s+area\s+(\S+)")
            if not area_id:
                continue

            if area_id not in area_dict:
                area_dict[area_id] = {
                    "area_id": area_id,
                    "area_type": OSPFAreaType.NORMAL,
                    "stub_no_summary": False,
                    "nssa_no_summary": False,
                    "nssa_default_information_originate": False,
                    "nssa_default_information_originate_always": False,
                    "default_cost": None,
                    "authentication": None,
                    "ranges": [],
                    "virtual_links": [],
                    "interfaces": [],
                    "interface_settings": {},
                    "filter_list_in": None,
                    "filter_list_out": None,
                }

            # CCR-0046 row 5. IOS-XR spells the area body as a nested block —
            # `area 1` / `default-cost 10` — where IOS/NX-OS/EOS emit the one-liner
            # `area 1 default-cost 10`. CCR-0044 added the field and the extraction
            # for the one-liner and reached three of four OSes; the body vocabulary
            # is the same table (IOSParser._OSPF_AREA_SCALAR_PATTERNS), it just has
            # to be fed the block's child lines instead of the command tail.
            # Direct children only: an `area N > interface X` sub-block has its own
            # body (`cost 100`), which belongs to the interface, not the area.
            for body_child in area_child.children:
                self._apply_ospf_area_scalar(area_dict[area_id], body_child.text.strip())

            # Area type
            for prop_child in area_child.find_child_objects(r"^\s+nssa"):
                text = prop_child.text.strip()
                if "no-summary" in text or "no-redistribution no-summary" in text:
                    area_dict[area_id]["area_type"] = OSPFAreaType.TOTALLY_NSSA
                    area_dict[area_id]["nssa_no_summary"] = True
                else:
                    area_dict[area_id]["area_type"] = OSPFAreaType.NSSA
                if "default-information-originate" in text:
                    area_dict[area_id]["nssa_default_information_originate"] = True
                    if "always" in text:
                        area_dict[area_id]["nssa_default_information_originate_always"] = True

            for prop_child in area_child.find_child_objects(r"^\s+stub"):
                text = prop_child.text.strip()
                if "no-summary" in text:
                    area_dict[area_id]["area_type"] = OSPFAreaType.TOTALLY_STUB
                    area_dict[area_id]["stub_no_summary"] = True
                else:
                    area_dict[area_id]["area_type"] = OSPFAreaType.STUB

            # Authentication
            auth_ch = area_child.find_child_objects(r"^\s+authentication\s+")
            if auth_ch:
                if "message-digest" in auth_ch[0].text:
                    area_dict[area_id]["authentication"] = "message-digest"
                else:
                    area_dict[area_id]["authentication"] = "simple"

            # Ranges (IOS-XR: range X.X.X.X/N)
            for range_child in area_child.find_child_objects(r"^\s+range\s+(\S+)"):
                range_str = self._extract_match(range_child.text, r"^\s+range\s+(\S+)")
                if range_str:
                    try:
                        prefix = IPv4Network(range_str, strict=False)
                        area_dict[area_id]["ranges"].append(
                            OSPFRange(prefix=prefix, advertise=True)
                        )
                    except ValueError:
                        pass

            # Type-3 LSA filter-list (IOS-XR: 'filter-list prefix NAME in|out')
            for fl_child in area_child.find_child_objects(r"^\s+filter-list\s+prefix\s+"):
                fl_match = re.search(
                    r"filter-list\s+prefix\s+(\S+)\s+(in|out)", fl_child.text
                )
                if fl_match:
                    pl_name, direction = fl_match.group(1), fl_match.group(2)
                    if direction == "in":
                        area_dict[area_id]["filter_list_in"] = pl_name
                    else:
                        area_dict[area_id]["filter_list_out"] = pl_name

            # Virtual-links (IOS-XR: virtual-link <neighbor-rid>)
            for vl_child in area_child.find_child_objects(r"^\s+virtual-link\s+(\S+)"):
                vl_rid_str = self._extract_match(vl_child.text, r"^\s+virtual-link\s+(\S+)")
                if vl_rid_str:
                    try:
                        from confgraph.models.ospf import OSPFVirtualLink
                        neighbor_rid = IPv4Address(vl_rid_str)
                        area_dict[area_id]["virtual_links"].append(
                            OSPFVirtualLink(neighbor_router_id=neighbor_rid)
                        )
                    except ValueError:
                        pass

            # Interfaces nested under area
            for intf_child in area_child.find_child_objects(r"^\s+interface\s+(\S+)"):
                intf_name = self._extract_match(intf_child.text, r"^\s+interface\s+(\S+)")
                if not intf_name:
                    continue
                if intf_name not in area_dict[area_id]["interfaces"]:
                    area_dict[area_id]["interfaces"].append(intf_name)
                # IOS-XR marks passive with "passive enable" inside the interface block
                if intf_child.find_child_objects(r"^\s+passive\s+enable"):
                    if intf_name not in passive_interfaces:
                        passive_interfaces.append(intf_name)
                area_dict[area_id]["interface_settings"][intf_name] = (
                    self._parse_ospf_area_interface(
                        intf_child, intf_name, area_id, process_id
                    )
                )

        for area_data in area_dict.values():
            areas.append(OSPFArea(**area_data))

        return areas, passive_interfaces

    # IOS-XR OSPF `area > interface` body → OSPFInterfaceConfig field. One row per
    # setting; the regex's `val` group is the value, or the row is a bare flag
    # (no group) whose presence means True.
    #
    # This is the extraction half of CCR-0038 Theme 2. The ATTRIBUTION half — the
    # part that used to be missing entirely on IOS-XR, and duplicated per-OS on
    # JunOS and PAN-OS — is BaseParser._backfill_ospf_interface_settings, shared
    # by every parser. XR spells the cost `cost` (not `metric`, which is JunOS)
    # and the network type `network point-to-point`.
    _OSPF_AREA_IFACE_PATTERNS: tuple[tuple[str, str], ...] = (
        ("cost",           r"^\s+cost\s+(?P<val>\d+)\s*$"),
        ("priority",       r"^\s+priority\s+(?P<val>\d+)\s*$"),
        ("hello_interval", r"^\s+hello-interval\s+(?P<val>\d+)\s*$"),
        ("dead_interval",  r"^\s+dead-interval\s+(?P<val>\d+)\s*$"),
        ("network_type",   r"^\s+network\s+(?P<val>point-to-point|broadcast|"
                           r"non-broadcast|point-to-multipoint)\s*$"),
        ("authentication", r"^\s+authentication\s+(?P<val>message-digest|null)\s*$"),
        ("bfd_interval",   r"^\s+bfd\s+minimum-interval\s+(?P<val>\d+)\s*$"),
        ("bfd_multiplier", r"^\s+bfd\s+multiplier\s+(?P<val>\d+)\s*$"),
        # Bare flags — presence is the value.
        ("bfd",            r"^\s+bfd\s+fast-detect\s*$"),
        ("mtu_ignore",     r"^\s+mtu-ignore\s+enable\s*$"),
        ("passive",        r"^\s+passive\s+enable\s*$"),
    )

    _OSPF_INT_FIELDS = frozenset({
        "cost", "priority", "hello_interval", "dead_interval",
        "bfd_interval", "bfd_multiplier",
    })

    def _parse_ospf_area_interface(
        self, intf_child, intf_name: str, area_id: str,
        process_id: int | str | None = None,
    ) -> OSPFInterfaceConfig:
        """One ``area N > interface NAME`` block → OSPFInterfaceConfig.

        IOS-XR writes an interface's OSPF settings inside the routing process, so
        ``parse_interfaces`` never sees them and ``InterfaceConfig.ospf_cost`` came
        back None on every XR device — indistinguishable, to a consumer, from "no
        cost configured" ([[CCR-0038]] Theme 2).
        """
        settings = OSPFInterfaceConfig(
            name=intf_name, area_id=area_id, process_id=process_id
        )
        for child in intf_child.children:
            text = child.text
            for field, pattern in self._OSPF_AREA_IFACE_PATTERNS:
                m = re.match(pattern, text)
                if not m:
                    continue
                if "val" in m.groupdict():
                    raw = m.group("val")
                    value: object = int(raw) if field in self._OSPF_INT_FIELDS else raw
                else:
                    value = True  # bare flag
                setattr(settings, field, value)
                break
        return settings

    def _parse_ospf_redistribute_iosxr(self, ospf_obj) -> list[OSPFRedistribute]:
        """Parse OSPF redistribution for IOS-XR (uses route-policy instead of route-map)."""
        redistribute: list[OSPFRedistribute] = []
        redist_ch = ospf_obj.find_child_objects(r"^\s+redistribute\s+(\S+)")

        for redist_child in redist_ch:
            match = re.search(r"^\s+redistribute\s+(\S+)(.+)?", redist_child.text)
            if not match:
                continue

            protocol = match.group(1)
            remaining = match.group(2).strip() if match.group(2) else ""

            process_id = None
            route_map = None
            metric = None
            metric_type = None

            # Process ID — only for protocols that carry one,
            # and only as the leading positional token.
            if protocol in ("bgp", "ospf", "eigrp", "isis"):
                pid_m = re.match(r"(\d+)", remaining)
                if pid_m:
                    process_id = int(pid_m.group(1))

            # IOS-XR uses route-policy
            rpm = re.search(r"route-policy\s+(\S+)", remaining)
            if rpm:
                route_map = rpm.group(1)

            mm = re.search(r"\bmetric\s+(\d+)", remaining)
            if mm:
                metric = int(mm.group(1))

            mtm = re.search(r"\bmetric-type\s+(\d+)", remaining)
            if mtm:
                metric_type = int(mtm.group(1))

            redistribute.append(
                OSPFRedistribute(
                    protocol=protocol,
                    process_id=process_id,
                    route_map=route_map,
                    metric=metric,
                    metric_type=metric_type,
                )
            )

        return redistribute

    # -----------------------------------------------------------------------
    # Route-maps — "route-policy NAME" ... "end-policy"
    # -----------------------------------------------------------------------

    def parse_route_maps(self) -> list[RouteMapConfig]:
        """Parse IOS-XR route-policy blocks and map them to RouteMapConfig.

        The full policy body is stored as raw set/match entries so that
        the dependency graph can reference policy names without needing
        to interpret the if/then/else language.
        """
        route_maps: list[RouteMapConfig] = []
        parse = self._get_parse_obj()

        rp_objs = parse.find_objects(r"^route-policy\s+(\S+)")
        for rp_obj in rp_objs:
            rp_name = self._extract_match(rp_obj.text, r"^route-policy\s+(\S+)")
            if not rp_name:
                continue

            raw_lines, line_numbers = self._get_raw_lines_and_line_numbers(rp_obj)

            # Extract match/set clauses as best-effort from the policy body.
            # Handles IOS-XR if/then/else by emitting two RouteMapSequences:
            #   seq 10: match + if-branch sets
            #   seq 20: no match (catch-all) + else-branch sets
            match_clauses: list[RouteMapMatch] = []
            if_set_clauses: list[RouteMapSet] = []
            else_set_clauses: list[RouteMapSet] = []
            in_else = False

            def _parse_set(text: str, target: list[RouteMapSet]) -> None:
                if text.startswith("set local-preference "):
                    val = self._extract_match(text, r"set local-preference (\S+)")
                    if val:
                        target.append(RouteMapSet(set_type="local-preference", values=[val]))
                elif text.startswith("set med ") or text.startswith("set metric "):
                    val = self._extract_match(text, r"set (?:med|metric) (\S+)")
                    if val:
                        target.append(RouteMapSet(set_type="metric", values=[val]))
                elif text.startswith("set community "):
                    val = self._extract_match(text, r"set community (\S+)")
                    if val:
                        target.append(RouteMapSet(set_type="community", values=[val]))
                elif text.startswith("prepend as-path "):
                    vals = text.replace("prepend as-path ", "").split()
                    target.append(RouteMapSet(set_type="as-path prepend", values=vals))
                elif text.startswith("set origin "):
                    val = self._extract_match(text, r"set origin (\S+)")
                    if val:
                        target.append(RouteMapSet(set_type="origin", values=[val]))

            for child in rp_obj.all_children:
                text = child.text.strip()
                if text == "else":
                    in_else = True
                elif text in ("endif", "end-policy"):
                    in_else = False
                elif text.startswith("if destination in "):
                    dest = self._extract_match(text, r"if destination in (\S+)")
                    if dest:
                        match_clauses.append(
                            RouteMapMatch(match_type="ip address prefix-list", values=[dest])
                        )
                elif text.startswith("if community matches-any "):
                    comm_set = self._extract_match(text, r"if community matches-any (\S+)")
                    if comm_set:
                        match_clauses.append(
                            RouteMapMatch(match_type="community", values=[comm_set])
                        )
                elif text.startswith("set ") or text.startswith("prepend as-path "):
                    target = else_set_clauses if in_else else if_set_clauses
                    _parse_set(text, target)

            sequences: list[RouteMapSequence] = []
            if match_clauses:
                # Sequence 10: the if-branch (match + its set clauses)
                sequences.append(RouteMapSequence(
                    sequence=10,
                    action="permit",
                    match_clauses=match_clauses,
                    set_clauses=if_set_clauses,
                ))
                # Sequence 20: the else-branch (catch-all, no match clause)
                if else_set_clauses:
                    sequences.append(RouteMapSequence(
                        sequence=20,
                        action="permit",
                        match_clauses=[],
                        set_clauses=else_set_clauses,
                    ))
            else:
                # No if/then — simple policy with no match clause
                sequences.append(RouteMapSequence(
                    sequence=10,
                    action="permit",
                    match_clauses=[],
                    set_clauses=if_set_clauses,
                ))

            route_maps.append(
                RouteMapConfig(
                    object_id=f"route_map_{rp_name}",
                    raw_lines=raw_lines,
                    source_os=self.os_type,
                    line_numbers=line_numbers,
                    name=rp_name,
                    sequences=sequences,
                )
            )

        return route_maps

    # -----------------------------------------------------------------------
    # Prefix-lists — "prefix-set NAME" ... "end-set"
    # -----------------------------------------------------------------------

    def parse_prefix_lists(self) -> list[PrefixListConfig]:
        """Parse IOS-XR prefix-set blocks and map to PrefixListConfig.

        IOS-XR format::

            prefix-set ISP1_PREFIX_OUT
              10.0.0.0/16 le 24,
              192.168.0.0/16 le 24
            end-set
        """
        prefix_lists: list[PrefixListConfig] = []
        parse = self._get_parse_obj()

        ps_objs = parse.find_objects(r"^prefix-set\s+(\S+)")
        for ps_obj in ps_objs:
            ps_name = self._extract_match(ps_obj.text, r"^prefix-set\s+(\S+)")
            if not ps_name:
                continue

            raw_lines, line_numbers = self._get_raw_lines_and_line_numbers(ps_obj)
            entries: list[PrefixListEntry] = []
            seq = 10

            for child in ps_obj.all_children:
                # Each line may be: "  10.0.0.0/16 le 24," (comma = not last)
                text = child.text.strip().rstrip(",")
                if not text or text == "end-set":
                    continue

                # Extract prefix and optional ge/le
                prefix_match = re.match(r"(\d+\.\d+\.\d+\.\d+/\d+)(.*)", text)
                if not prefix_match:
                    continue

                prefix_str = prefix_match.group(1)
                options = prefix_match.group(2).strip()

                ge = None
                le = None
                ge_m = re.search(r"\bge\s+(\d+)", options)
                if ge_m:
                    ge = int(ge_m.group(1))
                le_m = re.search(r"\ble\s+(\d+)", options)
                if le_m:
                    le = int(le_m.group(1))

                try:
                    prefix = IPv4Network(prefix_str, strict=False)
                except ValueError:
                    continue

                entries.append(
                    PrefixListEntry(
                        sequence=seq,
                        action="permit",
                        prefix=prefix,
                        ge=ge,
                        le=le,
                    )
                )
                seq += 10

            prefix_lists.append(
                PrefixListConfig(
                    object_id=f"prefix_list_{ps_name}",
                    raw_lines=raw_lines,
                    source_os=self.os_type,
                    line_numbers=line_numbers,
                    name=ps_name,
                    afi="ipv4",
                    sequences=entries,
                )
            )

        return prefix_lists

    # -----------------------------------------------------------------------
    # AS-path lists — "as-path-set NAME" ... "end-set"
    # -----------------------------------------------------------------------

    def parse_as_path_lists(self) -> list[ASPathListConfig]:
        """Parse IOS-XR as-path-set blocks and map to ASPathListConfig."""
        as_path_lists: list[ASPathListConfig] = []
        parse = self._get_parse_obj()

        aps_objs = parse.find_objects(r"^as-path-set\s+(\S+)")
        for aps_obj in aps_objs:
            aps_name = self._extract_match(aps_obj.text, r"^as-path-set\s+(\S+)")
            if not aps_name:
                continue

            raw_lines, line_numbers = self._get_raw_lines_and_line_numbers(aps_obj)
            entries: list[ASPathListEntry] = []

            for child in aps_obj.all_children:
                text = child.text.strip().rstrip(",")
                if not text or text in ("end-set",):
                    continue
                entries.append(ASPathListEntry(action="permit", regex=text))

            as_path_lists.append(
                ASPathListConfig(
                    object_id=f"as_path_list_{aps_name}",
                    raw_lines=raw_lines,
                    source_os=self.os_type,
                    line_numbers=line_numbers,
                    name=aps_name,
                    entries=entries,
                )
            )

        return as_path_lists

    # -----------------------------------------------------------------------
    # Community-lists — "community-set NAME" ... "end-set"
    # -----------------------------------------------------------------------

    def _parse_iosxr_set_members(self, set_obj) -> list[str]:
        """Members of an IOS-XR ``community-set``/``extcommunity-set`` block, in order.

        The RPL member separator is the **comma**, and a newline after a comma is
        *optional* — the config guide states that one or more new lines **can**
        follow a comma separator in a named AS-path set, community set, extended
        community set or prefix set.  A member line may therefore carry one member
        or several, and the emitted layout (indent width, members per line) is not
        established by any readable source.  Splitting each body line on commas is
        correct under **either** layout and assumes nothing (CCR-0046 row 8).

        ``end-set`` is the block terminator, not a member.

        Deliberately not shared with ``prefix-set``/``as-path-set``: those already
        emit one entry per member, and an as-path member is a regex that may itself
        contain a comma, which this split would corrupt.
        """
        members: list[str] = []
        for child in set_obj.all_children:
            text = child.text.strip()
            if not text or text == "end-set":
                continue
            for member in text.split(","):
                member = member.strip()
                if member and member != "end-set":
                    members.append(member)
        return members

    def parse_community_lists(self) -> list[CommunityListConfig]:
        """Parse IOS-XR community-set blocks and map to CommunityListConfig.

        CCR-0046 row 8 — **one entry per member**, not one entry holding every
        member.  In this model a ``CommunityListEntry`` is one *clause*: the IOS
        parser builds it from a single ``ip community-list standard X permit A B``
        line, where a route must carry **A and B** to match.  ``communities`` on one
        entry is therefore a conjunction.

        An IOS-XR ``community-set`` asserts no such thing.  Its members are a plain
        list of specifications; the quantifier lives at the *use* site — under
        ``community matches-any`` a route carrying any ONE member matches, under
        ``matches-every`` all of them must.  Collapsing the members into a single
        entry states a conjunction the device never wrote, and makes
        ``len(entries)`` mean "1" on IOS-XR where it means "number of alternatives"
        on IOS/NX-OS/EOS — the same set, two different answers, depending on who
        wrote the config.  One entry per member keeps the members, their count and
        their independence.
        """
        community_lists: list[CommunityListConfig] = []
        parse = self._get_parse_obj()

        cs_objs = parse.find_objects(r"^community-set\s+(\S+)")
        for cs_obj in cs_objs:
            cs_name = self._extract_match(cs_obj.text, r"^community-set\s+(\S+)")
            if not cs_name:
                continue

            raw_lines, line_numbers = self._get_raw_lines_and_line_numbers(cs_obj)
            entries: list[CommunityListEntry] = [
                CommunityListEntry(action="permit", communities=[member])
                for member in self._parse_iosxr_set_members(cs_obj)
            ]

            community_lists.append(
                CommunityListConfig(
                    object_id=f"community_list_{cs_name}",
                    raw_lines=raw_lines,
                    source_os=self.os_type,
                    line_numbers=line_numbers,
                    name=cs_name,
                    list_type="standard",
                    entries=entries,
                )
            )

        # Also parse extcommunity-set blocks (RT/SoO sets)
        ecs_objs = parse.find_objects(r"^extcommunity-set\s+\S+\s+(\S+)")
        for ecs_obj in ecs_objs:
            m = re.match(r"^extcommunity-set\s+\S+\s+(\S+)", ecs_obj.text)
            if not m:
                continue
            ecs_name = m.group(1)
            raw_lines, line_numbers = self._get_raw_lines_and_line_numbers(ecs_obj)
            # Same block shape, same member walk, same one-entry-per-member rule as
            # community-set above — an extcommunity-set is a list of members too.
            entries = [
                CommunityListEntry(action="permit", communities=[member])
                for member in self._parse_iosxr_set_members(ecs_obj)
            ]
            community_lists.append(
                CommunityListConfig(
                    object_id=f"community_list_{ecs_name}",
                    raw_lines=raw_lines,
                    source_os=self.os_type,
                    line_numbers=line_numbers,
                    name=ecs_name,
                    list_type="extended",
                    entries=entries,
                )
            )

        return community_lists

    # -----------------------------------------------------------------------
    # ACLs — "ipv4 access-list NAME" / "ipv6 access-list NAME"
    # -----------------------------------------------------------------------

    def parse_acls(self) -> list[ACLConfig]:
        """Parse IOS-XR ACL configurations.

        IOS-XR uses ``ipv4 access-list NAME`` and ``ipv6 access-list NAME``
        instead of IOS ``ip access-list standard|extended NAME``.
        """
        acls = []
        parse = self._get_parse_obj()

        for keyword in ("ipv4", "ipv6"):
            acl_objs = parse.find_objects(rf"^{keyword}\s+access-list\s+(\S+)")
            for acl_obj in acl_objs:
                acl_name = self._extract_match(acl_obj.text, rf"^{keyword}\s+access-list\s+(\S+)")
                if not acl_name:
                    continue

                raw_lines, line_numbers = self._get_raw_lines_and_line_numbers(acl_obj)
                entries = []

                for entry_child in acl_obj.children:
                    entry_text = entry_child.text.strip()
                    parts = entry_text.split()
                    if not parts:
                        continue

                    sequence = None
                    if parts[0].isdigit():
                        sequence = int(parts[0])
                        parts = parts[1:]

                    if not parts:
                        continue
                    action = parts[0].lower()
                    if action not in ("permit", "deny", "remark"):
                        continue

                    if action == "remark":
                        entries.append(ACLEntry(
                            action="remark",
                            sequence=sequence,
                            remark=" ".join(parts[1:]),
                        ))
                    else:
                        entries.append(ACLEntry(
                            action=action,
                            sequence=sequence,
                            protocol=parts[1] if len(parts) > 1 else None,
                        ))

                acls.append(ACLConfig(
                    object_id=f"acl_{acl_name}",
                    raw_lines=raw_lines,
                    source_os=self.os_type,
                    line_numbers=line_numbers,
                    name=acl_name,
                    acl_type="extended",
                    entries=entries,
                ))

        return acls

    # -----------------------------------------------------------------------
    # Static routes — "router static" block
    # -----------------------------------------------------------------------

    # The keyword modifiers an IOS-XR static route can carry after its positional
    # next-hop(s) and distance. THE table for "the (N+1)th static-route modifier".
    # Every one of them must be listed even when it has no home in the model, because
    # the walk uses this set to know where the positional part ENDS and where a
    # free-text `description` STOPS.
    _STATIC_ROUTE_KEYWORDS: frozenset[str] = frozenset({
        "tag", "permanent", "vrflabel", "tunnel-id", "description", "track", "metric",
    })

    def _parse_iosxr_static_route_line(self, text: str) -> dict | None:
        """One emitted IOS-XR static-route line → ``StaticRoute`` field values.

        The emitted grammar (CCR-0046 rows 6-7) is::

            <prefix> [vrf <vrf>] [<interface>] [<ip>] [<distance>] [tag <n>]
                     [permanent] [vrflabel <n>] [tunnel-id <n>]
                     [description <text>] [track <name>] [metric <n>]

        Positionals first, then keyword modifiers.  Three things a naive walk gets
        wrong, and this one does not:

        * A **fully specified** route carries BOTH an output interface and a
          next-hop IP, and the device emits the interface FIRST
          (``10.0.0.0/8 GigabitEthernet0/0/0/0 172.16.1.2 200``).  Reading only the
          first token after the prefix drops the next hop and then mistakes the IP
          for the distance.
        * The administrative **distance is a bare positional integer** — while
          ``metric`` and ``tag`` carry their keywords.  A walk that treats every
          trailing integer alike misreads both directions.
        * ``description`` is free text, so it runs to the next KEYWORD, not to the
          next token.

        Returns None when the line is not a route (a ``!``, a nested block header,
        a ``no …`` withdrawal).
        """
        m = re.match(r"^(\d+\.\d+\.\d+\.\d+/\d+)\s+(.*)$", text)
        if not m:
            return None
        try:
            destination = IPv4Network(m.group(1), strict=False)
        except ValueError:
            return None

        tokens = m.group(2).split()
        data: dict = {
            "destination": destination,
            "next_hop": None,
            "next_hop_interface": None,
            "distance": 1,
            "tag": None,
            "name": None,      # the model spells a route's description `name`
            "metric": None,
            "permanent": False,
        }

        i = 0
        # A leading `vrf <name>` here is the next hop's DESTINATION vrf (route
        # leaking), not the vrf the route lives in — that one comes from the
        # enclosing block. Not modelled; step over both tokens so it cannot be
        # mistaken for an interface name.
        if len(tokens) > 1 and tokens[0] == "vrf":
            i = 2

        # Positional: interface, next-hop IP, administrative distance — in any
        # combination, in emitted order.
        while i < len(tokens) and tokens[i] not in self._STATIC_ROUTE_KEYWORDS:
            token = tokens[i]
            if token.isdigit():
                data["distance"] = int(token)
            else:
                try:
                    data["next_hop"] = IPv4Address(token)
                except ValueError:
                    if data["next_hop_interface"] is None:
                        data["next_hop_interface"] = token
            i += 1

        # Keyword modifiers.
        while i < len(tokens):
            keyword = tokens[i]
            i += 1
            if keyword == "permanent":
                data["permanent"] = True
            elif keyword == "description":
                words: list[str] = []
                while i < len(tokens) and tokens[i] not in self._STATIC_ROUTE_KEYWORDS:
                    words.append(tokens[i])
                    i += 1
                if words:
                    data["name"] = " ".join(words)
            elif keyword in ("tag", "metric"):
                if i < len(tokens) and tokens[i].isdigit():
                    data[keyword] = int(tokens[i])
                    i += 1
            else:
                # `track <name>` / `vrflabel <n>` / `tunnel-id <n>`: consume the
                # operand so it cannot be read as another modifier. IOS-XR's track
                # operand is an object NAME (a string); StaticRoute.track is an int
                # (the IOS object number), so it has no honest home here and is
                # deliberately not stored rather than coerced.
                if i < len(tokens) and tokens[i] not in self._STATIC_ROUTE_KEYWORDS:
                    i += 1

        return data

    def parse_static_routes(self) -> list[StaticRoute]:
        """Parse IOS-XR static routes from ``router static`` block.

        IOS-XR format::

            router static
             address-family ipv4 unicast
              0.0.0.0/0 192.168.1.1
              10.0.0.0/8 Null0 200
              192.168.0.0/16 Null0 tag 666
              10.200.0.0/16 172.16.1.2 200 description BACKUP-ROUTE
             !
             vrf MGMT
              address-family ipv4 unicast
               0.0.0.0/0 10.100.100.1

        The line grammar — including the trailing modifiers that carry ``tag`` and
        ``description`` — is ``_parse_iosxr_static_route_line``.
        """
        static_routes = []
        parse = self._get_parse_obj()

        static_objs = parse.find_objects(r"^router\s+static")
        for static_obj in static_objs:
            raw_lines, line_numbers = self._get_raw_lines_and_line_numbers(static_obj)

            def _extract_routes(af_obj, vrf: str | None) -> None:
                for route_child in af_obj.all_children:
                    data = self._parse_iosxr_static_route_line(route_child.text.strip())
                    if data is None:
                        continue
                    # Object identity keeps the emitted next hop: the interface when
                    # the route names one (it is emitted first), else the IP.
                    next_hop_str = data["next_hop_interface"] or data["next_hop"]
                    static_routes.append(StaticRoute(
                        object_id=f"static_route_{data['destination']}_{next_hop_str}",
                        raw_lines=raw_lines,
                        source_os=self.os_type,
                        line_numbers=line_numbers,
                        vrf=vrf,
                        **data,
                    ))

            # Global routes
            for af_child in static_obj.find_child_objects(r"^\s+address-family\s+ipv4\s+unicast"):
                _extract_routes(af_child, vrf=None)

            # VRF routes
            for vrf_child in static_obj.find_child_objects(r"^\s+vrf\s+(\S+)"):
                vrf_name = self._extract_match(vrf_child.text, r"^\s+vrf\s+(\S+)")
                if not vrf_name:
                    continue
                for af_child in vrf_child.find_child_objects(r"^\s+address-family\s+ipv4\s+unicast"):
                    _extract_routes(af_child, vrf=vrf_name)

        return static_routes

    # -----------------------------------------------------------------------
    # BGP neighbors — block syntax "neighbor X\n  remote-as Y"
    # -----------------------------------------------------------------------

    def _parse_bgp_neighbors(self, bgp_obj) -> list[BGPNeighbor]:
        """Parse BGP neighbors from IOS-XR block-style syntax.

        IOS-XR uses a block per neighbor instead of flat ``neighbor X cmd`` lines::

            neighbor 203.0.113.1
             remote-as 65001
             description ISP1-PEER
             address-family ipv4 unicast
              route-policy ISP1-IN in

        Delegates all attribute parsing to ``_parse_iosxr_neighbor_block`` so
        that this path and the VRF path stay in sync automatically.
        """
        neighbors = []
        neighbor_blocks = bgp_obj.find_child_objects(r"^\s+neighbor\s+(\S+)\s*$")

        for nb_child in neighbor_blocks:
            peer_str = self._extract_match(nb_child.text, r"^\s+neighbor\s+(\S+)\s*$")
            if not peer_str:
                continue

            try:
                peer_ip = IPv4Address(peer_str)
            except ValueError:
                try:
                    peer_ip = IPv6Address(peer_str)
                except ValueError:
                    continue

            nd = self._parse_iosxr_neighbor_block(nb_child)

            has_policy = (
                nd["route_map_in"] or nd["route_map_out"] or nd["next_hop_self"]
                or nd["prefix_list_in"] or nd["prefix_list_out"]
            )
            if nd["remote_as"] is None and nd["peer_group"] is None:
                if not has_policy:
                    continue
                nd["remote_as"] = "inherited"

            neighbors.append(BGPNeighbor(
                peer_ip=peer_ip,
                remote_as=nd["remote_as"] if nd["remote_as"] is not None else "inherited",
                peer_group=nd["peer_group"],
                description=nd["description"],
                update_source=nd["update_source"],
                ebgp_multihop=nd["ebgp_multihop"],
                password=nd["password"],
                shutdown=nd["shutdown"],
                fall_over_bfd=nd["fall_over_bfd"],
                local_as=nd["local_as"],
                local_as_no_prepend=nd["local_as_no_prepend"],
                local_as_replace_as=nd["local_as_replace_as"],
                next_hop_self=nd["next_hop_self"],
                send_community=nd["send_community"],
                route_reflector_client=nd["route_reflector_client"],
                route_map_in=nd["route_map_in"],
                route_map_out=nd["route_map_out"],
                prefix_list_in=nd["prefix_list_in"],
                prefix_list_out=nd["prefix_list_out"],
                timers=nd["timers"],
            ))

        return neighbors

    # -----------------------------------------------------------------------
    # BGP AF neighbor policies — "route-policy NAME in|out"
    # -----------------------------------------------------------------------

    def _apply_bgp_af_neighbor_policies(self, bgp_obj, neighbors: list) -> None:
        """Populate neighbor AF policies from IOS-XR nested neighbor blocks.

        IOS-XR nests AF policy under each neighbor block::

            neighbor 192.0.2.1
             address-family ipv4 unicast
              route-policy ISP-IN in
              route-policy ISP-OUT out

        Delegates AF-block parsing to ``_parse_iosxr_neighbor_af_block`` so
        that this method only handles iteration and object construction.
        """
        nb_index = {str(nb.peer_ip): nb for nb in neighbors}

        neighbor_blocks = bgp_obj.find_child_objects(r"^\s+neighbor\s+(\S+)\s*$")
        for nb_child in neighbor_blocks:
            peer_str = self._extract_match(nb_child.text, r"^\s+neighbor\s+(\S+)\s*$")
            if not peer_str or peer_str not in nb_index:
                continue

            nb = nb_index[peer_str]
            af_children = nb_child.find_child_objects(
                r"^\s+address-family\s+(ipv4|ipv6)\s+unicast"
            )
            for af_child in af_children:
                m = re.search(r"^\s+address-family\s+(ipv4|ipv6)\s+unicast", af_child.text)
                if not m:
                    continue
                afi, safi = m.group(1), "unicast"
                af_data = self._parse_iosxr_neighbor_af_block(af_child)
                # `v is not True` keeps a bare-activate AF block from attaching,
                # but it also discards blocks whose only modelled content is a
                # boolean flag. `default-originate` (unconditional) is exactly such
                # a block — witnessed on-device as a lone child of the neighbor AF
                # sub-block — so OR it in explicitly rather than letting the
                # generic filter drop the value we just set. (The same latent drop
                # affects next-hop-self / route-reflector-client-only AF blocks;
                # that broader filter fix is out of scope for CCR-0078.)
                if (
                    any(v for v in af_data.values() if v and v is not True)
                    or af_data.get("default_originate")
                ):
                    nb.address_families.append(BGPNeighborAF(afi=afi, safi=safi, **af_data))

    # -----------------------------------------------------------------------
    # Multicast — "router pim" block
    # -----------------------------------------------------------------------

    def parse_multicast(self) -> MulticastConfig | None:
        """Parse IOS-XR multicast configuration from ``router pim`` block.

        IOS-XR format::

            router pim
             address-family ipv4
              rp-address 10.0.0.1
              ssm range RFC1918
        """
        parse = self._get_parse_obj()
        pim_objs = parse.find_objects(r"^router\s+pim")
        multicast_routing_objs = parse.find_objects(r"^multicast-routing")

        if not pim_objs and not multicast_routing_objs:
            return None

        raw_lines: list[str] = []
        line_numbers: list[int] = []
        for obj in pim_objs + multicast_routing_objs:
            rl, ln = self._get_raw_lines_and_line_numbers(obj)
            raw_lines.extend(rl)
            line_numbers.extend(ln)

        multicast_routing_enabled = bool(multicast_routing_objs)
        pim_rp_addresses: list[PIMRPAddress] = []
        pim_ssm_range: str | None = None
        pim_autorp = False

        for pim_obj in pim_objs:
            for af_child in pim_obj.find_child_objects(r"^\s+address-family\s+ipv4"):
                for child in af_child.all_children:
                    text = child.text.strip()
                    rp_m = re.match(r"^rp-address\s+(\S+)(.*)", text)
                    if rp_m:
                        try:
                            rp_addr = IPv4Address(rp_m.group(1))
                            rest = rp_m.group(2).strip()
                            acl = rest if rest and not rest.startswith("bidir") and not rest.startswith("override") else None
                            pim_rp_addresses.append(PIMRPAddress(
                                rp_address=rp_addr,
                                acl=acl,
                                override="override" in rest,
                                bidir="bidir" in rest,
                            ))
                        except ValueError:
                            pass
                    elif text.startswith("ssm range "):
                        pim_ssm_range = text.split(None, 2)[2] if len(text.split()) > 2 else None
                    elif "auto-rp" in text.lower():
                        pim_autorp = True

        return MulticastConfig(
            object_id="multicast",
            raw_lines=raw_lines,
            source_os=self.os_type,
            line_numbers=line_numbers,
            multicast_routing_enabled=multicast_routing_enabled,
            pim_rp_addresses=pim_rp_addresses,
            pim_ssm_range=pim_ssm_range,
            pim_autorp=pim_autorp,
        )

    # -----------------------------------------------------------------------
    # IS-IS — interface stanzas nested under "router isis NAME"
    # -----------------------------------------------------------------------

    def parse_isis(self) -> list[ISISConfig]:
        """Parse IS-IS configurations for IOS-XR.

        IOS-XR nests per-interface IS-IS config under the ``router isis`` block::

            router isis CORE
             is-type level-2-only
             net 49.0001.0000.0000.0001.00
             interface GigabitEthernet0/0/0/1
              metric 20
              circuit-type level-2-only
             !
             interface Loopback0
              passive
        """
        # Use parent to get the process-level config (net, is-type, passive, etc.)
        isis_instances = super().parse_isis()
        parse = self._get_parse_obj()

        for isis_cfg in isis_instances:
            tag = isis_cfg.tag
            pattern = rf"^router\s+isis\s+{re.escape(tag)}" if tag else r"^router\s+isis\s*$"
            isis_objs = parse.find_objects(pattern)
            if not isis_objs:
                continue
            isis_obj = isis_objs[0]

            isis_interfaces: list[ISISInterface] = []

            for intf_child in isis_obj.find_child_objects(r"^\s+interface\s+(\S+)"):
                intf_name = self._extract_match(intf_child.text, r"^\s+interface\s+(\S+)")
                if not intf_name:
                    continue

                # CCR-0046: an IS-IS interface's metric is emitted inside the
                # interface's own `address-family ipv4 unicast` sub-block, so the
                # direct-child lookups below read the container and found nothing.
                # The AF-transparent view makes them read through it.  `passive`
                # and `point-to-point` sit directly under the interface and are
                # still seen — the view adds the AF's children, it removes nothing.
                intf_child = self._nested_block(intf_child)

                # Global metric: metric N  (no level qualifier)
                isis_metric: int | None = None
                m_ch = intf_child.find_child_objects(r"^\s+metric\s+(\d+)\s*$")
                if m_ch:
                    v = self._extract_match(m_ch[0].text, r"^\s+metric\s+(\d+)")
                    if v:
                        isis_metric = int(v)

                # Level-specific metrics
                isis_metric_l1: int | None = None
                m1_ch = intf_child.find_child_objects(r"^\s+metric\s+(\d+)\s+level-1")
                if m1_ch:
                    v = self._extract_match(m1_ch[0].text, r"^\s+metric\s+(\d+)")
                    if v:
                        isis_metric_l1 = int(v)

                isis_metric_l2: int | None = None
                m2_ch = intf_child.find_child_objects(r"^\s+metric\s+(\d+)\s+level-2")
                if m2_ch:
                    v = self._extract_match(m2_ch[0].text, r"^\s+metric\s+(\d+)")
                    if v:
                        isis_metric_l2 = int(v)

                # Circuit type
                circuit_type: str | None = None
                ct_ch = intf_child.find_child_objects(r"^\s+circuit-type\s+(\S+)")
                if ct_ch:
                    circuit_type = self._extract_match(ct_ch[0].text, r"^\s+circuit-type\s+(\S+)")

                # Passive — IOS-XR uses "passive" keyword directly
                isis_passive = bool(intf_child.find_child_objects(r"^\s+passive"))

                isis_interfaces.append(ISISInterface(
                    name=intf_name,
                    circuit_type=circuit_type,
                    metric=isis_metric,
                    level_1_metric=isis_metric_l1,
                    level_2_metric=isis_metric_l2,
                    passive=isis_passive,
                ))

            isis_cfg.interfaces = isis_interfaces

        return isis_instances

    # -----------------------------------------------------------------------
    # MPLS / LDP — hierarchical "mpls ldp" block (IOS-XR style)
    # -----------------------------------------------------------------------

    def parse_mpls(self) -> "MPLSConfig | None":
        """Parse MPLS/LDP from IOS-XR hierarchical ``mpls ldp`` block.

        IOS-XR nests LDP sub-commands under a ``mpls ldp`` block::

            mpls ldp
             router-id 10.0.0.1
             graceful-restart
             session protection
             address-family ipv4
             !
             interface GigabitEthernet0/0/0/0
             !

        Note: label range and per-interface ``mpls ip`` are not extracted
        from the hierarchical block — IOS-XR lists interfaces as children
        of ``mpls ldp`` rather than annotating ``interface`` blocks.
        Per-interface ``mpls ip`` on IOS-XR is therefore not available
        for ``_assess_mpls`` interface-state checks.  This is intentional:
        interface MPLS enablement on XR is implied by presence under the
        ``mpls ldp`` block and does not use a separate ``mpls ip`` knob.
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

            # IOS-XR: "router-id 10.0.0.1 [force]"
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
            line_numbers=[],
            ldp_router_id=ldp_router_id,
            ldp_router_id_force=ldp_router_id_force,
            ldp_enabled=ldp_enabled,
            ldp_graceful_restart=ldp_graceful_restart,
            ldp_session_protection=ldp_session_protection,
            ldp_password=ldp_password,
        )

    # -----------------------------------------------------------------------
    # NTP — hierarchical "ntp" block (IOS-XR style)
    # -----------------------------------------------------------------------

    def parse_ntp(self):
        """Parse NTP from IOS-XR hierarchical ``ntp`` block.

        IOS-XR nests NTP sub-commands under a top-level ``ntp`` block::

            ntp
             server 10.0.0.1 prefer
             server vrf MGMT 10.0.0.2
             source Loopback0
             authenticate
             authentication-key 1 md5 CiscoKey
             trusted-key 1
             update-calendar

        Falls back to IOS flat-style (``ntp server …``) for configs that
        use that syntax instead.
        """
        from ipaddress import IPv4Address, IPv6Address
        from confgraph.models.ntp import NTPConfig, NTPServer, NTPAuthKey

        parse = self._get_parse_obj()
        ntp_blocks = parse.find_objects(r"^ntp\s*$")
        if not ntp_blocks:
            return super().parse_ntp()

        servers = []
        peers = []
        auth_keys = []
        trusted_keys = []
        source_interface = None
        authenticate = False
        master = False
        master_stratum = None
        update_calendar = False
        ag_query_only = ag_serve_only = ag_serve = ag_peer = None
        raw_lines = []
        line_numbers = []

        for block in ntp_blocks:
            raw_lines.append(block.text)
            line_numbers.append(block.linenum)
            for child in block.children:
                raw_lines.append(child.text)
                line_numbers.append(child.linenum)
                ct = child.text.strip()

                if re.match(r"^server\s+", ct):
                    m = re.match(r"^server(?:\s+vrf\s+(\S+))?\s+(\S+)(.*)", ct)
                    if m:
                        vrf, addr_str, rest = m.group(1), m.group(2), m.group(3)
                        prefer = "prefer" in rest
                        key_m = re.search(r"\bkey\s+(\d+)", rest)
                        ver_m = re.search(r"\bversion\s+(\d+)", rest)
                        src_m = re.search(r"\bsource\s+(\S+)", rest)
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
                            source=src_m.group(1) if src_m else None,
                        ))
                elif re.match(r"^peer\s+", ct):
                    m = re.match(r"^peer(?:\s+vrf\s+(\S+))?\s+(\S+)(.*)", ct)
                    if m:
                        vrf, addr_str, rest = m.group(1), m.group(2), m.group(3)
                        prefer = "prefer" in rest
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
                elif re.match(r"^authentication-key\s+", ct):
                    m = re.match(r"^authentication-key\s+(\d+)\s+(\S+)\s+(\S+)", ct)
                    if m:
                        auth_keys.append(NTPAuthKey(
                            key_id=int(m.group(1)),
                            algorithm=m.group(2),
                            key_string=m.group(3),
                        ))
                elif re.match(r"^trusted-key\s+", ct):
                    m = re.match(r"^trusted-key\s+(\d+)", ct)
                    if m:
                        trusted_keys.append(int(m.group(1)))
                elif re.match(r"^source\s+", ct):
                    source_interface = ct.split(None, 1)[1].strip()
                elif ct == "authenticate":
                    authenticate = True
                elif re.match(r"^master", ct):
                    master = True
                    sm = re.match(r"^master\s+(\d+)", ct)
                    if sm:
                        master_stratum = int(sm.group(1))
                elif ct == "update-calendar":
                    update_calendar = True
                elif re.match(r"^access-group\s+", ct):
                    m = re.match(
                        r"^access-group\s+(query-only|serve-only|serve|peer)\s+(\S+)", ct
                    )
                    if m:
                        ag_type = m.group(1).replace("-", "_")
                        acl = m.group(2)
                        if ag_type == "query_only":
                            ag_query_only = acl
                        elif ag_type == "serve_only":
                            ag_serve_only = acl
                        elif ag_type == "serve":
                            ag_serve = acl
                        elif ag_type == "peer":
                            ag_peer = acl

        if not raw_lines:
            return None

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
            access_group_query_only=ag_query_only,
            access_group_serve_only=ag_serve_only,
            access_group_serve=ag_serve,
            access_group_peer=ag_peer,
            update_calendar=update_calendar,
            logging=False,
        )

    # -----------------------------------------------------------------------
    # BFD — no bfd-template in IOS-XR; capture slow-timers only
    # -----------------------------------------------------------------------

    def parse_bfd(self):
        """Parse BFD global configuration from IOS-XR.

        IOS-XR does not support ``bfd-template``.  BFD timers are per-interface
        or per-neighbor.  The only global knob modelled here is ``slow-timers``,
        which can appear either inside a hierarchical ``bfd`` block or as a flat
        command::

            bfd
             slow-timers 2000
             echo disable
             multipath include location 0/0/CPU0

        or (older XR style)::

            bfd slow-timers 2000
        """
        from confgraph.models.bfd import BFDConfig

        parse = self._get_parse_obj()
        slow_timers = None
        raw_lines = []
        line_numbers = []

        # Hierarchical "bfd" block
        for block in parse.find_objects(r"^bfd\s*$"):
            raw_lines.append(block.text)
            line_numbers.append(block.linenum)
            for child in block.children:
                raw_lines.append(child.text)
                line_numbers.append(child.linenum)
                ct = child.text.strip()
                m = re.match(r"^slow-timers\s+(\d+)", ct)
                if m:
                    slow_timers = int(m.group(1))

        # Flat "bfd slow-timers N"
        for obj in parse.find_objects(r"^bfd\s+slow-timers\s+"):
            raw_lines.append(obj.text)
            line_numbers.append(obj.linenum)
            v = self._extract_match(obj.text, r"^bfd\s+slow-timers\s+(\d+)")
            if v and slow_timers is None:
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

    def _parse_iface_bfd(self, intf_obj) -> tuple:
        """Parse per-interface BFD for IOS-XR.

        IOS-XR uses separate sub-commands rather than a single line::

            interface GigabitEthernet0/0/0/0
             bfd fast-detect
             bfd minimum-interval 300
             bfd multiplier 3

        ``bfd minimum-interval`` sets the same timer for both tx and rx.
        """
        bfd_interval = bfd_min_rx = bfd_multiplier = bfd_template = None

        mi_ch = intf_obj.find_child_objects(r"^\s+bfd\s+minimum-interval\s+")
        if mi_ch:
            m = re.match(r"^\s+bfd\s+minimum-interval\s+(\d+)", mi_ch[0].text)
            if m:
                val = int(m.group(1))
                bfd_interval = val
                bfd_min_rx = val  # XR uses a single interval for both tx and rx

        mul_ch = intf_obj.find_child_objects(r"^\s+bfd\s+multiplier\s+")
        if mul_ch:
            m = re.match(r"^\s+bfd\s+multiplier\s+(\d+)", mul_ch[0].text)
            if m:
                bfd_multiplier = int(m.group(1))

        # XR does not support "bfd template" per-interface; bfd_template stays None
        return bfd_interval, bfd_min_rx, bfd_multiplier, bfd_template

    # -------------------------------------------------------------------
    # DHCP — IOS-XR hierarchical "dhcp ipv4" (X2)
    # -------------------------------------------------------------------

    def parse_dhcp(self):
        """Parse IOS-XR DHCP relay/profile configuration.

        IOS-XR uses hierarchical ``dhcp ipv4`` blocks instead of IOS
        ``ip dhcp pool`` / ``ip dhcp snooping``::

            dhcp ipv4
             profile RELAY relay
              helper-address vrf default 10.1.1.1 giaddr 0.0.0.0
             !
             interface GigabitEthernet0/0/0/1
              relay profile RELAY
        """
        from confgraph.models.dhcp import DHCPConfig, DHCPPool

        parse = self._get_parse_obj()
        dhcp_objs = parse.find_objects(r"^dhcp\s+ipv4")
        if not dhcp_objs:
            return None

        raw_lines: list[str] = []
        line_numbers: list[int] = []
        pools: list[DHCPPool] = []

        for dhcp_obj in dhcp_objs:
            raw_lines.append(dhcp_obj.text)
            line_numbers.append(dhcp_obj.linenum)
            for child in dhcp_obj.children:
                raw_lines.append(child.text)
                line_numbers.append(child.linenum)

            # Parse profiles as pool-like entries
            for prof_child in dhcp_obj.find_child_objects(r"^\s+profile\s+(\S+)"):
                text = prof_child.text.strip()
                m = re.match(r"profile\s+(\S+)(?:\s+(\S+))?", text)
                if not m:
                    continue
                prof_name = m.group(1)

                # Extract helper addresses from profile children
                helpers: list[str] = []
                for pc in prof_child.all_children:
                    pt = pc.text.strip()
                    hm = re.match(r"helper-address\s+(?:vrf\s+\S+\s+)?(\S+)", pt)
                    if hm:
                        helpers.append(hm.group(1))

                pools.append(DHCPPool(
                    name=prof_name,
                    dns_servers=helpers,
                ))

        return DHCPConfig(
            object_id="dhcp",
            raw_lines=raw_lines,
            source_os=self.os_type,
            line_numbers=line_numbers,
            pools=pools,
        )

    # -------------------------------------------------------------------
    # Deletion tombstones — IOS-XR forms (X1)
    # -------------------------------------------------------------------

    def parse_deletion_commands(self) -> list[str]:
        """Parse IOS-XR deletion commands into tombstone strings.

        IOS-XR uses different syntax from IOS for deletions:

          - ``no router ospf <id>``                             → ``process:ospf:<id>``
          - ``no router bgp <asn>``                             → ``process:bgp:<asn>``
          - ``no router isis <tag>``                             → ``process:isis:<tag>``
          - ``no router static`` (removes all static routes)     → ``singleton:static_routes``
          - Nested ``no`` inside ``router static`` block for
            per-route deletion (``no address-family ...``)

        IOS-XR also uses hierarchical ``no`` inside config blocks.
        Top-level ``no`` lines are handled here; nested block deletions
        inside ``router ospf/bgp/static`` are parsed from block children.
        """
        tombstones: list[str] = []
        parse = self._get_parse_obj()

        # --- process-level deletions (top-level "no router ...") ---
        for obj in parse.find_objects(r"^no\s+router\s+ospf\s+"):
            m = re.search(r"^no\s+router\s+ospf\s+(\S+)", obj.text)
            if m:
                tombstones.append(f"process:ospf:{m.group(1)}")

        for obj in parse.find_objects(r"^no\s+router\s+bgp\s+"):
            m = re.search(r"^no\s+router\s+bgp\s+(\S+)", obj.text)
            if m:
                tombstones.append(f"process:bgp:{m.group(1)}")

        for obj in parse.find_objects(r"^no\s+router\s+isis"):
            m = re.search(r"^no\s+router\s+isis(?:\s+(\S+))?", obj.text)
            tag = m.group(1) if (m and m.group(1)) else ""
            tombstones.append(f"process:isis:{tag}")

        # --- whole static removal ---
        if parse.find_objects(r"^no\s+router\s+static\s*$"):
            tombstones.append("singleton:static_routes")

        # --- per-route deletions inside "router static" ---
        # IOS-XR: "router static" block with nested "no" inside
        # address-family sub-blocks
        for static_obj in parse.find_objects(r"^router\s+static"):
            for af_child in static_obj.find_child_objects(r"^\s+address-family"):
                for route_child in af_child.all_children:
                    text = route_child.text.strip()
                    m = re.match(r"no\s+(\d+\.\d+\.\d+\.\d+/\d+)\s+(\S+)", text)
                    if m:
                        try:
                            dest = IPv4Network(m.group(1), strict=False)
                            tombstones.append(f"static::{dest}")
                        except ValueError:
                            pass
            # VRF routes
            for vrf_child in static_obj.find_child_objects(r"^\s+vrf\s+(\S+)"):
                vrf_name = self._extract_match(vrf_child.text, r"^\s+vrf\s+(\S+)")
                if not vrf_name:
                    continue
                for af_child in vrf_child.find_child_objects(r"^\s+address-family"):
                    for route_child in af_child.all_children:
                        text = route_child.text.strip()
                        m = re.match(r"no\s+(\d+\.\d+\.\d+\.\d+/\d+)\s+(\S+)", text)
                        if m:
                            try:
                                dest = IPv4Network(m.group(1), strict=False)
                                tombstones.append(f"static:{vrf_name}:{dest}")
                            except ValueError:
                                pass

        # --- VRF deletion ---
        for obj in parse.find_objects(r"^no\s+vrf\s+(\S+)"):
            m = re.search(r"^no\s+vrf\s+(\S+)", obj.text)
            if m and m.group(1) not in ("definition", "context"):
                tombstones.append(f"vrf:{m.group(1)}")

        # --- ACL deletion (IOS-XR: "no ipv4 access-list NAME") ---
        for obj in parse.find_objects(r"^no\s+ipv4\s+access-list\s+"):
            m = re.search(r"^no\s+ipv4\s+access-list\s+(\S+)", obj.text)
            if m:
                tombstones.append(f"acl:{m.group(1)}")

        # --- route-policy deletion ---
        for obj in parse.find_objects(r"^no\s+route-policy\s+"):
            m = re.search(r"^no\s+route-policy\s+(\S+)", obj.text)
            if m:
                tombstones.append(f"route-map:{m.group(1)}")

        # --- prefix-set deletion ---
        for obj in parse.find_objects(r"^no\s+prefix-set\s+"):
            m = re.search(r"^no\s+prefix-set\s+(\S+)", obj.text)
            if m:
                tombstones.append(f"prefix-list:{m.group(1)}")

        # --- singleton service removals ---
        if parse.find_objects(r"^no\s+router\s+pim"):
            tombstones.append("singleton:multicast")
        if parse.find_objects(r"^no\s+ntp\b"):
            tombstones.append("singleton:ntp")

        # --- DNS tombstones (IOS-XR: "no domain ...") ---
        for obj in parse.find_objects(r"^no\s+domain\s+name-server\s+"):
            m = re.match(r"^no\s+domain\s+name-server\s+(\S+)", obj.text.strip())
            if m:
                tombstones.append(f"field:dns:name_server:{m.group(1)}")
        for obj in parse.find_objects(r"^no\s+domain\s+list\s+"):
            m = re.match(r"^no\s+domain\s+list\s+(\S+)", obj.text.strip())
            if m:
                tombstones.append(f"field:dns:domain:{m.group(1)}")
        if parse.find_objects(r"^no\s+domain\s+lookup\s*$"):
            tombstones.append("singleton:dns")

        return tombstones

    # -------------------------------------------------------------------
    # X4 (back-fill ospf_area / ospf_process_id from OSPFArea.interfaces) is GONE:
    # it was the IOS-XR copy of a back-fill that JunOS and PAN-OS each had their own
    # copy of, and it carried only membership — never the cost, network type or BFD
    # sitting one level deeper, inside the interface block. All four now run through
    # the model (OSPFArea.interface_settings) and the one shared walk,
    # BaseParser._backfill_ospf_interface_settings ([[CCR-0038]] Theme 2).
    #
    # X6 (populate VRF RD from the BGP VRF block — IOS-XR puts RD under "router bgp /
    # vrf NAME / rd X:Y", not under "vrf NAME") is GONE for the same reason: it was
    # the IOS-XR copy of a back-fill EOS needed too, and it carried only the RD, never
    # the route-targets sitting in the same block. Both now run through the model
    # (BGPConfig.rd / .route_target_*) and the one shared walk,
    # BaseParser._backfill_vrf_rd_rt ([[CCR-0059]]).  Hence: no parse() override.
    # -------------------------------------------------------------------
