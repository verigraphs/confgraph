"""Juniper JunOS configuration parser.

Parses JunOS brace-style (hierarchical) configuration files.  Uses a
custom recursive tokenizer (``junos_hierarchy``) rather than
CiscoConfParse, which is designed for IOS-style indentation.

Naming follows the existing parser convention:
  ios_parser.py   → IOSParser
  eos_parser.py   → EOSParser
  nxos_parser.py  → NXOSParser
  iosxr_parser.py → IOSXRParser
  junos_parser.py → JunOSParser
"""

from __future__ import annotations

import re
from ipaddress import IPv4Interface, IPv6Interface
from typing import Any

from confgraph.models.base import OSType, UnrecognizedBlock
from confgraph.models.interface import InterfaceConfig, InterfaceType
from confgraph.models.vrf import VRFConfig
from confgraph.models.bgp import BGPConfig
from confgraph.models.ospf import OSPFConfig
from confgraph.models.route_map import RouteMapConfig, RouteMapSequence, RouteMapMatch, RouteMapSet
from confgraph.models.prefix_list import PrefixListConfig, PrefixListEntry
from confgraph.models.static_route import StaticRoute
from confgraph.models.acl import ACLConfig
from confgraph.models.community_list import (
    CommunityListConfig, CommunityListEntry,
    ASPathListConfig, ASPathListEntry,
)
from confgraph.models.isis import ISISConfig
from confgraph.models.ntp import NTPConfig, NTPServer
from confgraph.models.snmp import SNMPConfig, SNMPCommunity
from confgraph.models.logging_config import SyslogConfig, LoggingHost
from confgraph.models.multicast import MulticastConfig
from confgraph.models.bgp import (
    BGPConfig, BGPNeighbor, BGPPeerGroup, BGPNeighborAF, BGPAddressFamily,
)
from confgraph.models.ospf import OSPFConfig, OSPFArea
from confgraph.models.acl import ACLConfig, ACLEntry
from confgraph.models.static_route import StaticRoute

from confgraph.parsers.base import BaseParser
from confgraph.parsers.junos_hierarchy import parse_junos_config


class JunOSParser(BaseParser):
    """Parser for Juniper JunOS (brace-style hierarchical) configurations."""

    def __init__(self, config_text: str) -> None:
        # Pass syntax="junos" so BaseParser records it; _get_parse_obj() is
        # never called because we override _extract_hostname() and
        # _collect_unrecognized_blocks() to use our own hierarchy instead.
        super().__init__(config_text, OSType.JUNOS, syntax="junos")
        self._hier: dict[str, Any] | None = None
        # Populated by parse_vrfs(); consumed by parse_interfaces()
        self._vrf_of_intf: dict[str, str] = {}

    # ------------------------------------------------------------------
    # Hierarchy access
    # ------------------------------------------------------------------

    def _get_hierarchy(self) -> dict[str, Any]:
        """Return the parsed JunOS hierarchy (lazy, cached)."""
        if self._hier is None:
            self._hier = parse_junos_config(self.config_text)
        return self._hier

    # ------------------------------------------------------------------
    # BaseParser overrides to avoid CiscoConfParse
    # ------------------------------------------------------------------

    def _extract_hostname(self) -> str | None:
        """Extract hostname from ``system { host-name X; }``."""
        system = self._get_hierarchy().get("system", {})
        if isinstance(system, dict):
            hn = system.get("host-name")
            if isinstance(hn, str):
                return hn.strip('"')
        return None

    def _collect_unrecognized_blocks(self) -> list[UnrecognizedBlock]:
        """JunOS uses a different structure; skip CiscoConfParse-based scan."""
        return []

    # ------------------------------------------------------------------
    # Interface parsing (Stage 3)
    # ------------------------------------------------------------------

    def parse_interfaces(self) -> list[InterfaceConfig]:
        """Parse ``interfaces { … }`` block.

        JunOS interface structure::

            interfaces {
                ge-0/0/0 {
                    description "text";
                    unit 0 {
                        family inet {
                            address 10.0.0.1/30;
                            filter { input ACL; output ACL; }
                        }
                        family inet6 { address 2001:db8::1/64; }
                    }
                }
            }

        Each ``intf.unit`` combination becomes one ``InterfaceConfig`` named
        ``ge-0/0/0.0``.  Interfaces with no units are also emitted as-is.
        """
        hier = self._get_hierarchy()
        intf_block = hier.get("interfaces", {})
        if not isinstance(intf_block, dict):
            return []

        result: list[InterfaceConfig] = []

        for intf_name, intf_data in intf_block.items():
            if not isinstance(intf_data, dict):
                continue

            intf_desc = _str_val(intf_data.get("description"))
            units = intf_data.get("unit", {})

            if not isinstance(units, dict) or not units:
                # Interface with no units — emit once with no addressing
                result.append(self._make_interface(
                    intf_name, intf_name, intf_desc, {}, {},
                    vrf=self._vrf_of_intf.get(intf_name),
                ))
                continue

            for unit_id, unit_data in units.items():
                if not isinstance(unit_data, dict):
                    continue

                full_name = f"{intf_name}.{unit_id}"
                unit_desc = _str_val(unit_data.get("description")) or intf_desc

                inet_block = unit_data.get("family", {})
                inet4: dict[str, Any] = {}
                inet6: dict[str, Any] = {}
                if isinstance(inet_block, dict):
                    inet4 = inet_block.get("inet", {}) or {}
                    inet6 = inet_block.get("inet6", {}) or {}
                    if not isinstance(inet4, dict):
                        inet4 = {}
                    if not isinstance(inet6, dict):
                        inet6 = {}

                result.append(self._make_interface(
                    full_name, intf_name, unit_desc, inet4, inet6,
                    vrf=self._vrf_of_intf.get(full_name),
                ))

        return result

    def _make_interface(
        self,
        full_name: str,
        base_name: str,
        description: str | None,
        inet4: dict[str, Any],
        inet6: dict[str, Any],
        vrf: str | None = None,
    ) -> InterfaceConfig:
        """Construct one InterfaceConfig from parsed unit data."""
        intf_type = _junos_interface_type(base_name)

        # IPv4 primary address
        ip_address: IPv4Interface | None = None
        secondary_ips: list[IPv4Interface] = []
        addr_val = inet4.get("address")
        if addr_val:
            if isinstance(addr_val, list):
                addrs = addr_val
            else:
                addrs = [addr_val]
            for idx, a in enumerate(addrs):
                a = _str_val(a) or ""
                # Strip any trailing keyword like "primary"
                a = a.split()[0]
                try:
                    iface = IPv4Interface(a)
                    if idx == 0:
                        ip_address = iface
                    else:
                        secondary_ips.append(iface)
                except ValueError:
                    pass

        # IPv6 addresses
        ipv6_addresses: list[IPv6Interface] = []
        addr6_val = inet6.get("address")
        if addr6_val:
            if isinstance(addr6_val, list):
                addrs6 = addr6_val
            else:
                addrs6 = [addr6_val]
            for a6 in addrs6:
                a6 = (_str_val(a6) or "").split()[0]
                try:
                    ipv6_addresses.append(IPv6Interface(a6))
                except ValueError:
                    pass

        # ACL filters from ``family inet { filter { input X; output X; } }``
        acl_in: str | None = None
        acl_out: str | None = None
        filter_block = inet4.get("filter", {})
        if isinstance(filter_block, dict):
            acl_in = _str_val(filter_block.get("input"))
            acl_out = _str_val(filter_block.get("output"))

        return InterfaceConfig(
            object_id=f"interface_{full_name}",
            raw_lines=[],
            source_os=self.os_type,
            line_numbers=[],
            name=full_name,
            interface_type=intf_type,
            description=description,
            enabled=True,
            vrf=vrf,
            ip_address=ip_address,
            ipv6_addresses=ipv6_addresses,
            secondary_ips=secondary_ips,
            acl_in=acl_in,
            acl_out=acl_out,
        )

    # ------------------------------------------------------------------
    # VRF parsing (Stage 4) — routing-instances
    # ------------------------------------------------------------------

    def parse_vrfs(self) -> list[VRFConfig]:
        """Parse ``routing-instances { … }`` into VRFConfig objects.

        Also populates ``self._vrf_of_intf`` so that ``parse_interfaces()``
        (called immediately after) can set ``InterfaceConfig.vrf``.

        JunOS routing-instance structure::

            routing-instances {
                CUST-A {
                    instance-type vrf;
                    interface ge-0/0/2.0;
                    route-distinguisher 65000:100;
                    vrf-target target:65000:100;
                }
            }
        """
        hier = self._get_hierarchy()
        ri_block = hier.get("routing-instances", {})
        if not isinstance(ri_block, dict):
            return []

        vrfs: list[VRFConfig] = []
        # Maps unit-interface name → vrf name for cross-referencing
        self._vrf_of_intf: dict[str, str] = {}

        for vrf_name, vrf_data in ri_block.items():
            if not isinstance(vrf_data, dict):
                continue

            # Skip non-VRF instance types (e.g. virtual-router, l2vpn)
            instance_type = _str_val(vrf_data.get("instance-type", "vrf"))
            if instance_type not in ("vrf", "vrf-target", None):
                pass  # include all — VRF-like enough for dependency tracking

            rd = _str_val(vrf_data.get("route-distinguisher"))

            rt_both: list[str] = []
            rt_import: list[str] = []
            rt_export: list[str] = []

            # vrf-target target:X  → both import and export
            vt = vrf_data.get("vrf-target")
            if vt:
                for v in (vt if isinstance(vt, list) else [vt]):
                    v = _str_val(v) or ""
                    v = v.replace("target:", "")
                    if v:
                        rt_both.append(v)

            # vrf-import / vrf-export (less common, explicit)
            vi = vrf_data.get("vrf-import")
            if vi:
                for v in (vi if isinstance(vi, list) else [vi]):
                    v = (_str_val(v) or "").replace("target:", "")
                    if v:
                        rt_import.append(v)

            ve = vrf_data.get("vrf-export")
            if ve:
                for v in (ve if isinstance(ve, list) else [ve]):
                    v = (_str_val(v) or "").replace("target:", "")
                    if v:
                        rt_export.append(v)

            # Member interfaces
            intf_members: list[str] = []
            intf_val = vrf_data.get("interface")
            if intf_val:
                for iv in (intf_val if isinstance(intf_val, list) else [intf_val]):
                    iv = _str_val(iv) or ""
                    if iv:
                        intf_members.append(iv)
                        self._vrf_of_intf[iv] = vrf_name

            vrfs.append(VRFConfig(
                object_id=f"vrf_{vrf_name}",
                raw_lines=[],
                source_os=self.os_type,
                line_numbers=[],
                name=vrf_name,
                rd=rd,
                route_target_import=rt_import,
                route_target_export=rt_export,
                route_target_both=rt_both,
                interfaces=intf_members,
            ))

        return vrfs

    # ------------------------------------------------------------------
    # Prefix-list parsing (Stage 5) — policy-options prefix-list
    # ------------------------------------------------------------------

    def parse_prefix_lists(self) -> list[PrefixListConfig]:
        """Parse ``policy-options { prefix-list NAME { … } }`` blocks.

        JunOS structure::

            prefix-list RFC1918 {
                10.0.0.0/8;
                172.16.0.0/12 upto /24;   # ge/le equivalent
            }

        Entries are comma-separated or newline-separated with optional
        ``upto``, ``orlonger``, ``exact`` qualifiers.
        """
        hier = self._get_hierarchy()
        po = hier.get("policy-options", {})
        if not isinstance(po, dict):
            return []

        pl_block = po.get("prefix-list", {})
        if not isinstance(pl_block, dict):
            return []

        result: list[PrefixListConfig] = []
        for pl_name, pl_data in pl_block.items():
            if not isinstance(pl_data, dict):
                continue

            entries: list[PrefixListEntry] = []
            seq = 10
            for key, val in pl_data.items():
                # Each key in a prefix-list block is a prefix
                if key in ("description",):
                    continue
                prefixes = val if isinstance(val, list) else [val]
                if not isinstance(prefixes, list):
                    prefixes = [prefixes]
                # key itself is the prefix when value is empty dict or str
                # In JunOS: "10.0.0.0/8;" → tokenizer gives key="10.0.0.0/8", val=""
                prefix_str = key.split()[0]
                ge_val: int | None = None
                le_val: int | None = None
                # Check for qualifiers in the key tokens
                tokens = key.split()
                for i, t in enumerate(tokens):
                    if t == "upto" and i + 1 < len(tokens):
                        try:
                            le_val = int(tokens[i + 1].lstrip("/"))
                        except ValueError:
                            pass
                    elif t == "orlonger":
                        # orlonger = ge N+1 le 32 — approximate as le 32
                        le_val = 32
                try:
                    from ipaddress import ip_network
                    network = ip_network(prefix_str, strict=False)
                    entries.append(PrefixListEntry(
                        sequence=seq,
                        action="permit",
                        prefix=network,
                        ge=ge_val,
                        le=le_val,
                    ))
                    seq += 10
                except ValueError:
                    pass

            result.append(PrefixListConfig(
                object_id=f"prefix_list_{pl_name}",
                raw_lines=[],
                source_os=self.os_type,
                line_numbers=[],
                name=pl_name,
                afi="ipv4",
                sequences=entries,
            ))

        return result

    def parse_community_lists(self) -> list[CommunityListConfig]:
        """Parse community definitions from ``policy-options``.

        JunOS community definitions appear as flat statements::

            community NO-EXPORT members no-export;
            community LOCAL-PREF-100 members 65000:100;

        which the hierarchy tokenizer stores as a list of strings:
        ``["NO-EXPORT members no-export", "LOCAL-PREF-100 members 65000:100"]``.

        Also handles the block form::

            community NAME { members VALUE; }
        """
        hier = self._get_hierarchy()
        po = hier.get("policy-options", {})
        if not isinstance(po, dict):
            return []

        comm_val = po.get("community")
        if comm_val is None:
            return []

        result: list[CommunityListConfig] = []

        if isinstance(comm_val, dict):
            # Block form: {name: {members: value}}
            for comm_name, comm_data in comm_val.items():
                if not isinstance(comm_data, dict):
                    continue
                members = _str_val(comm_data.get("members", "")) or ""
                communities = [m for m in members.split() if m]
                result.append(self._make_community(comm_name, communities))
        else:
            # Flat statement form: list of "NAME members VALUE" strings
            items = comm_val if isinstance(comm_val, list) else [comm_val]
            for item in items:
                item = _str_val(item) or ""
                # Format: "NAME members VALUE1 VALUE2 ..."
                if " members " in item:
                    name_part, _, members_part = item.partition(" members ")
                    comm_name = name_part.strip()
                    communities = [m for m in members_part.split() if m]
                    result.append(self._make_community(comm_name, communities))

        return result

    def _make_community(self, name: str, communities: list[str]) -> CommunityListConfig:
        return CommunityListConfig(
            object_id=f"community_list_{name}",
            raw_lines=[],
            source_os=self.os_type,
            line_numbers=[],
            name=name,
            list_type="standard",
            entries=[CommunityListEntry(action="permit", communities=communities)],
        )

    def parse_as_path_lists(self) -> list[ASPathListConfig]:
        """Parse AS-path definitions from ``policy-options``.

        JunOS AS-path definitions appear as flat statements::

            as-path CUSTOMER-AS "^65001$";

        which the hierarchy tokenizer stores as a list of strings:
        ``['CUSTOMER-AS "^65001$"', 'UPSTREAM-AS "^64512_"']``.
        """
        hier = self._get_hierarchy()
        po = hier.get("policy-options", {})
        if not isinstance(po, dict):
            return []

        asp_val = po.get("as-path")
        if asp_val is None:
            return []

        result: list[ASPathListConfig] = []

        if isinstance(asp_val, dict):
            # Block form: {name: regex_str}
            for asp_name, asp_data in asp_val.items():
                regex = _str_val(asp_data).strip('"') if not isinstance(asp_data, dict) else ""
                result.append(self._make_as_path(asp_name, regex))
        else:
            # Flat statement form: list of "NAME regex" strings
            items = asp_val if isinstance(asp_val, list) else [asp_val]
            for item in items:
                item = _str_val(item) or ""
                parts = item.split(None, 1)
                if len(parts) >= 1:
                    asp_name = parts[0]
                    regex = parts[1].strip('"') if len(parts) > 1 else ""
                    result.append(self._make_as_path(asp_name, regex))

        return result

    def _make_as_path(self, name: str, regex: str) -> ASPathListConfig:
        return ASPathListConfig(
            object_id=f"as_path_list_{name}",
            raw_lines=[],
            source_os=self.os_type,
            line_numbers=[],
            name=name,
            entries=[ASPathListEntry(action="permit", regex=regex)],
        )

    # ------------------------------------------------------------------
    # Route-map parsing (Stage 6) — policy-options policy-statement
    # ------------------------------------------------------------------

    def parse_route_maps(self) -> list[RouteMapConfig]:
        """Parse ``policy-options { policy-statement NAME { term T { … } } }`` blocks.

        JunOS structure::

            policy-statement ISP-IMPORT {
                term REJECT-DEFAULT {
                    from { prefix-list DEFAULT-ROUTE; }
                    then reject;
                }
                term ACCEPT-REST { then accept; }
            }

        Each policy-statement maps to a RouteMapConfig; each term becomes
        a RouteMapSequence.  Terms are numbered 10, 20, … in order of
        appearance (JunOS preserves insertion order).
        """
        hier = self._get_hierarchy()
        po = hier.get("policy-options", {})
        if not isinstance(po, dict):
            return []

        ps_block = po.get("policy-statement", {})
        if not isinstance(ps_block, dict):
            return []

        result: list[RouteMapConfig] = []

        for ps_name, ps_data in ps_block.items():
            if not isinstance(ps_data, dict):
                continue

            sequences: list[RouteMapSequence] = []
            terms = ps_data.get("term", {})
            if not isinstance(terms, dict):
                terms = {}

            seq = 10
            for term_name, term_data in terms.items():
                if not isinstance(term_data, dict):
                    seq += 10
                    continue

                match_clauses: list[RouteMapMatch] = []
                set_clauses: list[RouteMapSet] = []

                from_block = term_data.get("from", {})
                if isinstance(from_block, dict):
                    # prefix-list reference
                    pl_ref = from_block.get("prefix-list")
                    if pl_ref:
                        pl_names = pl_ref if isinstance(pl_ref, list) else [pl_ref]
                        match_clauses.append(RouteMapMatch(
                            match_type="ip address prefix-list",
                            values=[_str_val(p) or "" for p in pl_names],
                        ))
                    # community reference
                    comm_ref = from_block.get("community")
                    if comm_ref:
                        comms = comm_ref if isinstance(comm_ref, list) else [comm_ref]
                        match_clauses.append(RouteMapMatch(
                            match_type="community",
                            values=[_str_val(c) or "" for c in comms],
                        ))
                    # as-path reference
                    asp_ref = from_block.get("as-path")
                    if asp_ref:
                        asps = asp_ref if isinstance(asp_ref, list) else [asp_ref]
                        match_clauses.append(RouteMapMatch(
                            match_type="as-path",
                            values=[_str_val(a) or "" for a in asps],
                        ))

                then_block = term_data.get("then", {})
                # then can be a dict or a scalar (e.g. "then accept;")
                if isinstance(then_block, str):
                    action_str = then_block.strip()
                    action = "permit" if action_str in ("accept",) else "deny"
                elif isinstance(then_block, dict):
                    action = "deny" if "reject" in then_block else "permit"
                    comm_set = then_block.get("community")
                    if comm_set:
                        comm_add = comm_set if isinstance(comm_set, dict) else {}
                        add_val = comm_add.get("add") or comm_add.get("set")
                        if add_val:
                            set_clauses.append(RouteMapSet(
                                set_type="community",
                                values=[_str_val(add_val) or ""],
                            ))
                    lp = then_block.get("local-preference")
                    if lp:
                        set_clauses.append(RouteMapSet(
                            set_type="local-preference",
                            values=[_str_val(lp) or ""],
                        ))
                else:
                    action = "permit"

                sequences.append(RouteMapSequence(
                    sequence=seq,
                    action=action,
                    match_clauses=match_clauses,
                    set_clauses=set_clauses,
                ))
                seq += 10

            result.append(RouteMapConfig(
                object_id=f"route_map_{ps_name}",
                raw_lines=[],
                source_os=self.os_type,
                line_numbers=[],
                name=ps_name,
                sequences=sequences,
            ))

        return result

    # ------------------------------------------------------------------
    # BGP parsing (Stage 7) — protocols bgp + routing-instances VRF BGP
    # ------------------------------------------------------------------

    def parse_bgp(self) -> list[BGPConfig]:
        """Parse BGP from ``protocols bgp`` and each ``routing-instances`` VRF.

        JunOS BGP is group-centric::

            protocols {
                bgp {
                    group GROUP-NAME {
                        type internal|external;
                        peer-as REMOTE_ASN;
                        local-address IP;
                        neighbor IP {
                            description "text";
                            import POLICY;
                            export POLICY;
                        }
                    }
                }
            }

        Groups map to BGPPeerGroup; each ``neighbor`` within a group
        maps to a BGPNeighbor that references the group.
        """
        hier = self._get_hierarchy()
        ro = hier.get("routing-options", {}) if isinstance(hier.get("routing-options"), dict) else {}
        global_asn_str = _str_val(ro.get("autonomous-system")) or "0"
        try:
            global_asn = int(global_asn_str)
        except ValueError:
            global_asn = 0

        router_id_str = _str_val(ro.get("router-id"))

        result: list[BGPConfig] = []

        # Global BGP
        proto_bgp = hier.get("protocols", {})
        proto_bgp = proto_bgp.get("bgp", {}) if isinstance(proto_bgp, dict) else {}
        if isinstance(proto_bgp, dict) and proto_bgp:
            bgp_cfg = self._parse_bgp_block(proto_bgp, global_asn, router_id_str, vrf=None)
            if bgp_cfg:
                result.append(bgp_cfg)

        # Per-VRF BGP from routing-instances
        ri_block = hier.get("routing-instances", {})
        if isinstance(ri_block, dict):
            for vrf_name, vrf_data in ri_block.items():
                if not isinstance(vrf_data, dict):
                    continue
                vrf_proto = vrf_data.get("protocols", {})
                if not isinstance(vrf_proto, dict):
                    continue
                vrf_bgp = vrf_proto.get("bgp", {})
                if not isinstance(vrf_bgp, dict) or not vrf_bgp:
                    continue
                bgp_cfg = self._parse_bgp_block(vrf_bgp, global_asn, None, vrf=vrf_name)
                if bgp_cfg:
                    result.append(bgp_cfg)

        return result

    def _parse_bgp_block(
        self,
        bgp_data: dict[str, Any],
        asn: int,
        router_id_str: str | None,
        vrf: str | None,
    ) -> BGPConfig | None:
        """Build a BGPConfig from a parsed ``bgp { group … }`` dict."""
        from ipaddress import IPv4Address
        peer_groups: list[BGPPeerGroup] = []
        neighbors: list[BGPNeighbor] = []

        groups = bgp_data.get("group", {})
        if not isinstance(groups, dict):
            groups = {}

        for grp_name, grp_data in groups.items():
            if not isinstance(grp_data, dict):
                continue

            grp_type = _str_val(grp_data.get("type", ""))
            peer_as_str = _str_val(grp_data.get("peer-as"))
            try:
                remote_as: int | str = int(peer_as_str) if peer_as_str else ("internal" if grp_type == "internal" else 0)
            except ValueError:
                remote_as = peer_as_str or 0

            # local-address is an IP in JunOS, not an interface name — omit as update_source
            pg = BGPPeerGroup(
                name=grp_name,
                remote_as=remote_as if remote_as != 0 else None,
                route_map_in=_str_val(grp_data.get("import")),
                route_map_out=_str_val(grp_data.get("export")),
            )
            peer_groups.append(pg)

            # Parse neighbors within this group
            nbr_block = grp_data.get("neighbor", {})
            if not isinstance(nbr_block, dict):
                continue

            for nbr_ip_str, nbr_data in nbr_block.items():
                if not isinstance(nbr_data, dict):
                    nbr_data = {}
                try:
                    peer_ip = IPv4Address(nbr_ip_str)
                except ValueError:
                    continue

                nbr_remote_as = remote_as
                nbr_remote_as_str = _str_val(nbr_data.get("peer-as"))
                if nbr_remote_as_str:
                    try:
                        nbr_remote_as = int(nbr_remote_as_str)
                    except ValueError:
                        pass

                rm_in = _str_val(nbr_data.get("import")) or _str_val(grp_data.get("import"))
                rm_out = _str_val(nbr_data.get("export")) or _str_val(grp_data.get("export"))

                af = BGPNeighborAF(
                    afi="ipv4",
                    safi="unicast",
                    route_map_in=rm_in,
                    route_map_out=rm_out,
                )

                neighbors.append(BGPNeighbor(
                    peer_ip=peer_ip,
                    remote_as=nbr_remote_as if nbr_remote_as != 0 else "internal",
                    peer_group=grp_name,
                    description=_str_val(nbr_data.get("description")),
                    route_map_in=rm_in,
                    route_map_out=rm_out,
                    address_families=[af],
                ))

        if not neighbors and not peer_groups:
            return None

        rid = None
        if router_id_str:
            try:
                from ipaddress import IPv4Address
                rid = IPv4Address(router_id_str)
            except ValueError:
                pass

        return BGPConfig(
            object_id=f"bgp_{asn}" + (f"_vrf_{vrf}" if vrf else ""),
            raw_lines=[],
            source_os=self.os_type,
            line_numbers=[],
            asn=asn,
            router_id=rid,
            vrf=vrf,
            neighbors=neighbors,
            peer_groups=peer_groups,
        )

    # ------------------------------------------------------------------
    # Static routes (Stage 8) — routing-options static
    # ------------------------------------------------------------------

    def parse_static_routes(self) -> list[StaticRoute]:
        """Parse ``routing-options { static { route PREFIX next-hop NH; } }``."""
        hier = self._get_hierarchy()
        result: list[StaticRoute] = []
        self._parse_static_block(hier.get("routing-options", {}), vrf=None, result=result)

        ri_block = hier.get("routing-instances", {})
        if isinstance(ri_block, dict):
            for vrf_name, vrf_data in ri_block.items():
                if isinstance(vrf_data, dict):
                    self._parse_static_block(
                        vrf_data.get("routing-options", {}),
                        vrf=vrf_name,
                        result=result,
                    )
        return result

    def _parse_static_block(
        self,
        ro: Any,
        vrf: str | None,
        result: list[StaticRoute],
    ) -> None:
        """Parse a ``static { route … }`` sub-block into *result*."""
        if not isinstance(ro, dict):
            return
        static = ro.get("static", {})
        if not isinstance(static, dict):
            return

        routes = static.get("route", [])
        if isinstance(routes, str):
            routes = [routes]
        elif not isinstance(routes, list):
            routes = []

        from ipaddress import ip_network, ip_address
        for route_str in routes:
            route_str = (_str_val(route_str) or "").strip()
            if not route_str:
                continue
            parts = route_str.split()
            if not parts:
                continue
            prefix_str = parts[0]
            next_hop_str = parts[2] if len(parts) >= 3 and parts[1] == "next-hop" else None
            if next_hop_str is None and len(parts) >= 2:
                next_hop_str = parts[1]
            try:
                destination = ip_network(prefix_str, strict=False)
            except ValueError:
                continue

            next_hop = None
            if next_hop_str and next_hop_str not in ("discard", "reject", "blackhole"):
                try:
                    next_hop = ip_address(next_hop_str)
                except ValueError:
                    next_hop = next_hop_str  # interface name

            result.append(StaticRoute(
                object_id=f"static_{prefix_str}" + (f"_vrf_{vrf}" if vrf else ""),
                raw_lines=[],
                source_os=self.os_type,
                line_numbers=[],
                destination=destination,
                next_hop=next_hop,
                vrf=vrf,
            ))

    # ------------------------------------------------------------------
    # OSPF parsing (Stage 9)
    # ------------------------------------------------------------------

    def parse_ospf(self) -> list[OSPFConfig]:
        """Parse ``protocols { ospf { area AREA { interface INTF } } }``."""
        hier = self._get_hierarchy()
        proto = hier.get("protocols", {})
        if not isinstance(proto, dict):
            return []

        ospf_data = proto.get("ospf", {})
        if not isinstance(ospf_data, dict) or not ospf_data:
            return []

        areas: list[OSPFArea] = []
        area_block = ospf_data.get("area", {})
        if isinstance(area_block, dict):
            for area_id, area_data in area_block.items():
                if not isinstance(area_data, dict):
                    continue
                intf_block = area_data.get("interface", {})
                intf_names: list[str] = []
                if isinstance(intf_block, dict):
                    intf_names = list(intf_block.keys())
                areas.append(OSPFArea(
                    area_id=str(area_id),
                    interfaces=intf_names,
                ))

        return [OSPFConfig(
            object_id="ospf_1",
            raw_lines=[],
            source_os=self.os_type,
            line_numbers=[],
            process_id=1,
            areas=areas,
        )]

    # ------------------------------------------------------------------
    # Firewall filter → ACL (Stage 10)
    # ------------------------------------------------------------------

    def parse_acls(self) -> list[ACLConfig]:
        """Parse ``firewall { filter FILTER-NAME { term T { … } } }`` blocks."""
        hier = self._get_hierarchy()
        fw = hier.get("firewall", {})
        if not isinstance(fw, dict):
            return []

        filter_block = fw.get("filter", {})
        if not isinstance(filter_block, dict):
            return []

        result: list[ACLConfig] = []
        for filter_name, filter_data in filter_block.items():
            if not isinstance(filter_data, dict):
                continue
            entries: list[ACLEntry] = []
            terms = filter_data.get("term", {})
            if isinstance(terms, dict):
                seq = 10
                for term_name, term_data in terms.items():
                    if not isinstance(term_data, dict):
                        seq += 10
                        continue
                    then_block = term_data.get("then", {})
                    action = "deny"
                    if isinstance(then_block, dict):
                        action = "deny" if "discard" in then_block or "reject" in then_block else "permit"
                    elif isinstance(then_block, str):
                        action = "permit" if then_block in ("accept",) else "deny"
                    entries.append(ACLEntry(
                        sequence=seq,
                        action=action,
                        remark=term_name,
                    ))
                    seq += 10

            result.append(ACLConfig(
                object_id=f"acl_{filter_name}",
                raw_lines=[],
                source_os=self.os_type,
                line_numbers=[],
                name=filter_name,
                acl_type="extended",
                entries=entries,
            ))

        return result

    # ------------------------------------------------------------------
    # Management — NTP, SNMP, Syslog (Stage 11)
    # ------------------------------------------------------------------

    def parse_ntp(self) -> NTPConfig | None:
        """Parse ``system { ntp { server IP; } }``."""
        hier = self._get_hierarchy()
        system = hier.get("system", {})
        if not isinstance(system, dict):
            return None
        ntp_data = system.get("ntp", {})
        if not isinstance(ntp_data, dict):
            return None

        servers: list[NTPServer] = []
        srv_val = ntp_data.get("server")
        if srv_val:
            for sv in (srv_val if isinstance(srv_val, list) else [srv_val]):
                addr = _str_val(sv) or ""
                if addr:
                    servers.append(NTPServer(address=addr))

        if not servers:
            return None
        return NTPConfig(
            object_id="ntp",
            raw_lines=[],
            source_os=self.os_type,
            line_numbers=[],
            servers=servers,
        )

    def parse_snmp(self) -> SNMPConfig | None:
        """Parse ``system { snmp { community NAME { authorization ro|rw; } } }``."""
        hier = self._get_hierarchy()
        system = hier.get("system", {})
        if not isinstance(system, dict):
            return None
        snmp_data = system.get("snmp", {})
        if not isinstance(snmp_data, dict):
            return None

        communities: list[SNMPCommunity] = []
        comm_block = snmp_data.get("community", {})
        if isinstance(comm_block, dict):
            for comm_name, comm_data in comm_block.items():
                if not isinstance(comm_data, dict):
                    continue
                auth = _str_val(comm_data.get("authorization", "read-only")) or "read-only"
                access = "ro" if "read-only" in auth else "rw"
                communities.append(SNMPCommunity(
                    community_string=comm_name,
                    access=access,
                ))

        location = _str_val(snmp_data.get("location"))
        contact = _str_val(snmp_data.get("contact"))

        if not communities and not location and not contact:
            return None
        return SNMPConfig(
            object_id="snmp",
            raw_lines=[],
            source_os=self.os_type,
            line_numbers=[],
            communities=communities,
            location=location,
            contact=contact,
        )

    def parse_syslog(self) -> SyslogConfig | None:
        """Parse ``system { syslog { host IP { … } } }``."""
        hier = self._get_hierarchy()
        system = hier.get("system", {})
        if not isinstance(system, dict):
            return None
        syslog_data = system.get("syslog", {})
        if not isinstance(syslog_data, dict):
            return None

        hosts: list[LoggingHost] = []
        host_block = syslog_data.get("host", {})
        if isinstance(host_block, dict):
            for host_addr, host_data in host_block.items():
                hosts.append(LoggingHost(address=host_addr))

        if not hosts:
            return None
        return SyslogConfig(
            object_id="syslog",
            raw_lines=[],
            source_os=self.os_type,
            line_numbers=[],
            hosts=hosts,
        )


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _str_val(v: Any) -> str | None:
    """Return *v* as a plain string, stripping quotes, or None."""
    if v is None:
        return None
    if isinstance(v, list):
        v = v[0] if v else None
    if v is None:
        return None
    return str(v).strip('"')


def _junos_interface_type(name: str) -> InterfaceType:
    """Classify a JunOS interface name into an InterfaceType."""
    n = name.lower()
    if n.startswith("lo"):
        return InterfaceType.LOOPBACK
    if n.startswith(("fxp", "em", "me", "re")):
        return InterfaceType.MANAGEMENT
    if n.startswith("ae"):
        return InterfaceType.PORTCHANNEL
    if n.startswith(("irb", "vlan")):
        return InterfaceType.SVI
    if n.startswith(("gr-", "ip-", "st0", "lt-", "mt-")):
        return InterfaceType.TUNNEL
    return InterfaceType.PHYSICAL
