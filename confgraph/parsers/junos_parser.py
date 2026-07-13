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
    BGPTimers,
)
from confgraph.models.ospf import (
    OSPFConfig, OSPFArea, OSPFAreaType, OSPFInterfaceConfig, OSPFRedistribute,
)
from confgraph.models.acl import ACLConfig, ACLEntry
from confgraph.models.static_route import StaticRoute

from confgraph.parsers.base import BaseParser
from confgraph.parsers.junos_hierarchy import parse_junos_config, _is_set_style


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
        self._is_set_style: bool = _is_set_style(config_text)
        self._config_lines: list[str] = config_text.splitlines()
        # 1b: populated by _parse_bgp_block(); maps peer_ip → local-address IP str
        self._bgp_local_addresses: dict[str, str] = {}

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
            return _str_val(system.get("host-name"))
        return None

    def _collect_unrecognized_blocks(self) -> list[UnrecognizedBlock]:
        """JunOS uses a different structure; skip CiscoConfParse-based scan."""
        return []

    def parse(self) -> "ParsedConfig":
        """Override to back-fill BGP update_source.

        OSPF per-interface attributes used to be back-filled here from a private
        ``_ospf_intf_attrs`` dict. They now ride in the model
        (``OSPFArea.interface_settings``) and are attributed by
        ``BaseParser._backfill_ospf_interface_settings``, which every OS shares
        ([[CCR-0038]] Theme 2).
        """
        from confgraph.models.parsed_config import ParsedConfig
        pc = super().parse()

        # 1b: reverse-resolve BGP local-address IP → interface name.  JunOS names
        # an update source by ADDRESS; ``update_source`` names an INTERFACE, so
        # an unresolvable address is left unset rather than written into a field
        # that means something else (CCR-0030: a wrong value beats no value only
        # for the checker, never for the consumer).
        if pc.bgp_instances:
            ip_to_intf = self._build_ip_to_intf_map(pc.interfaces)
            for bgp_inst in pc.bgp_instances:
                for nbr in bgp_inst.neighbors:
                    local_addr = self._bgp_local_addresses.get(str(nbr.peer_ip))
                    if local_addr and not nbr.update_source:
                        resolved = ip_to_intf.get(local_addr)
                        if resolved:
                            nbr.update_source = resolved
                for pg in bgp_inst.peer_groups:
                    pg.update_source = self._resolve_local_address(
                        pg.update_source, ip_to_intf
                    )

        return pc

    @staticmethod
    def _resolve_local_address(
        value: str | None, ip_to_intf: dict[str, str]
    ) -> str | None:
        """Map a BGP ``local-address`` to the interface that owns it."""
        if not value:
            return None
        from ipaddress import ip_address
        try:
            canon = str(ip_address(value))
        except ValueError:
            return value  # already an interface name
        return ip_to_intf.get(canon)

    @staticmethod
    def _build_ip_to_intf_map(interfaces: list[InterfaceConfig]) -> dict[str, str]:
        """Build IP address → interface name mapping for local-address resolution.

        Keys are canonical (compressed, lowercase) IP strings so that
        non-canonical IPv6 forms (e.g. ``2001:DB8::1``) still match.
        """
        result: dict[str, str] = {}
        for intf in interfaces:
            if intf.ip_address:
                result[str(intf.ip_address.ip)] = intf.name
            for sec in intf.secondary_ips:
                result[str(sec.ip)] = intf.name
            for v6 in intf.ipv6_addresses:
                result[str(v6.ip)] = intf.name
        return result

    def _raw_lines_for(self, *path_tokens: str) -> list[str]:
        """Return raw config lines relevant to a given object path.

        For set-style: returns all ``set <path_tokens...>`` lines whose prefix
        matches the full token sequence.

        For brace-style: returns all lines inside the named block identified by
        the last token in path_tokens (heuristic: finds the first ``NAME {``
        occurrence and collects until its matching ``}``).
        """
        if self._is_set_style:
            prefix = "set " + " ".join(path_tokens)
            return [
                line for line in self._config_lines
                if line.strip().startswith(prefix)
            ]
        else:
            # Brace-style: find the block whose header contains the last path token
            target = path_tokens[-1] if path_tokens else ""
            result: list[str] = []
            depth = 0
            inside = False
            for line in self._config_lines:
                stripped = line.strip()
                if not inside:
                    # Detect block header: last token followed by optional name + '{'
                    if target in stripped and stripped.endswith("{"):
                        inside = True
                        depth = 1
                        result.append(line)
                        continue
                else:
                    result.append(line)
                    depth += stripped.count("{") - stripped.count("}")
                    if depth <= 0:
                        inside = False
                        break
            return result

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

            # J13: interface-level disable
            intf_disabled = "disable" in intf_data

            # J16: MTU at the interface level
            intf_mtu = _int_val(intf_data.get("mtu"))

            if not isinstance(units, dict) or not units:
                # Interface with no units — emit once with no addressing
                result.append(self._make_interface(
                    intf_name, intf_name, intf_desc, {}, {},
                    vrf=self._vrf_of_intf.get(intf_name),
                    enabled=not intf_disabled,
                    mtu=intf_mtu,
                ))
                continue

            for unit_id, unit_data in units.items():
                if not isinstance(unit_data, dict):
                    continue

                full_name = f"{intf_name}.{unit_id}"
                unit_desc = _str_val(unit_data.get("description")) or intf_desc

                # J13: unit-level disable overrides interface-level
                unit_disabled = "disable" in unit_data
                enabled = not intf_disabled and not unit_disabled

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
                    enabled=enabled,
                    mtu=intf_mtu,
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
        enabled: bool = True,
        mtu: int | None = None,
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

        # IP unnumbered: "family inet { unnumbered-address lo0.0; }"
        unnumbered_source: str | None = None
        unnum_val = _str_val(inet4.get("unnumbered-address"))
        if unnum_val:
            unnumbered_source = unnum_val.split()[0]  # strip any trailing keywords

        return InterfaceConfig(
            object_id=f"interface_{full_name}",
            raw_lines=self._raw_lines_for("interfaces", base_name),
            source_os=self.os_type,
            line_numbers=[],
            name=full_name,
            interface_type=intf_type,
            description=description,
            enabled=enabled,
            vrf=vrf,
            mtu=mtu,
            ip_address=ip_address,
            ipv6_addresses=ipv6_addresses,
            secondary_ips=secondary_ips,
            acl_in=acl_in,
            acl_out=acl_out,
            unnumbered_source=unnumbered_source,
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

            # vrf-target — brace-style: scalar / list of "target:X"
            #              set-style: dict with "import" / "export" sub-keys
            vt = vrf_data.get("vrf-target")
            if isinstance(vt, dict) and ("import" in vt or "export" in vt):
                # set-style: vrf-target import target:X / export target:Y
                vt_import = _str_val(vt.get("import")) or ""
                vt_export = _str_val(vt.get("export")) or ""
                if vt_import:
                    rt_import.append(vt_import.replace("target:", ""))
                if vt_export:
                    rt_export.append(vt_export.replace("target:", ""))
            elif vt:
                for v in (vt if isinstance(vt, list) else [vt]):
                    v = _str_val(v) or ""
                    v = v.replace("target:", "")
                    if v:
                        rt_both.append(v)

            # vrf-import / vrf-export name *policy-statements*, not route-targets.
            # They belong in the policy-reference fields (route_map_import /
            # route_map_export), never in route_target_* (CCR-0030 bug 1).
            policy_import: str | None = None
            policy_export: str | None = None
            vi = vrf_data.get("vrf-import")
            if vi:
                policy_import = _str_val(vi) or None
            ve = vrf_data.get("vrf-export")
            if ve:
                policy_export = _str_val(ve) or None

            # Member interfaces
            # Brace-style: interface = "ge-0/0/0.0" (scalar) or list
            # Set-style:   interface = {"ge-0/0/0.0": {}} (dict with intf names as keys)
            intf_members: list[str] = []
            intf_val = vrf_data.get("interface")
            if isinstance(intf_val, dict):
                for iv in intf_val.keys():
                    iv = iv.strip('"')
                    if iv:
                        intf_members.append(iv)
                        self._vrf_of_intf[iv] = vrf_name
            elif intf_val:
                for iv in (intf_val if isinstance(intf_val, list) else [intf_val]):
                    iv = _str_val(iv) or ""
                    if iv:
                        intf_members.append(iv)
                        self._vrf_of_intf[iv] = vrf_name

            vrfs.append(VRFConfig(
                object_id=f"vrf_{vrf_name}",
                raw_lines=self._raw_lines_for("routing-instances", vrf_name),
                source_os=self.os_type,
                line_numbers=[],
                name=vrf_name,
                rd=rd,
                route_target_import=rt_import,
                route_target_export=rt_export,
                route_target_both=rt_both,
                route_map_import=policy_import,
                route_map_export=policy_export,
                # `description text;` is a leaf inside the instance body. Quoting
                # is CONDITIONAL on the vendor's own rule ("if the text includes
                # one or more spaces, enclose it in quotation marks"), so both
                # renderings must parse — _str_val strips the quotes.
                description=_str_val(vrf_data.get("description")) or None,
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
            for prefix_str, qualifiers in pl_data.items():
                # Each key in a prefix-list block is a prefix; any ``upto`` /
                # ``orlonger`` qualifier is an inline option of that statement.
                if prefix_str in ("description", "apply-groups", "apply-groups-except"):
                    continue
                tokens = _stmt_tokens(qualifiers)
                le_val: int | None = None
                upto = _token_arg(tokens, "upto")
                if upto:
                    le_val = _int_or_none(upto.lstrip("/"))
                elif "orlonger" in tokens:
                    # orlonger = ge N+1 le 32 — approximate as le 32
                    le_val = 32
                try:
                    from ipaddress import ip_network
                    network = ip_network(str(prefix_str), strict=False)
                except ValueError:
                    continue
                entries.append(PrefixListEntry(
                    sequence=seq,
                    action="permit",
                    prefix=network,
                    ge=None,
                    le=le_val,
                ))
                seq += 10

            result.append(PrefixListConfig(
                object_id=f"prefix_list_{pl_name}",
                raw_lines=self._raw_lines_for("policy-options", "prefix-list", pl_name),
                source_os=self.os_type,
                line_numbers=[],
                name=pl_name,
                afi="ipv4",
                sequences=entries,
            ))

        return result

    def parse_community_lists(self) -> list[CommunityListConfig]:
        """Parse community definitions from ``policy-options``.

        The flat form and the block form are one statement in the canonical
        tree, so there is one code path::

            community CL members [ 65000:100 65000:200 ];   # emitted
            community CL { members 65000:100; }             # equivalent
            set policy-options community CL members 65000:100

        all give ``{community: {CL: {members: {65000:100: {}, …}}}}``.
        """
        hier = self._get_hierarchy()
        po = hier.get("policy-options", {})
        if not isinstance(po, dict):
            return []

        comm_block = po.get("community")
        if not isinstance(comm_block, dict):
            return []

        result: list[CommunityListConfig] = []
        for comm_name, comm_data in comm_block.items():
            comm_name = str(comm_name).strip('"')
            if not comm_name or not isinstance(comm_data, dict):
                continue
            members = _str_vals(comm_data.get("members"))
            result.append(self._make_community(comm_name, members))

        return result

    def _make_community(self, name: str, communities: list[str]) -> CommunityListConfig:
        return CommunityListConfig(
            object_id=f"community_list_{name}",
            raw_lines=self._raw_lines_for("policy-options", "community", name),
            source_os=self.os_type,
            line_numbers=[],
            name=name,
            list_type="standard",
            entries=[CommunityListEntry(action="permit", communities=communities)],
        )

    def parse_as_path_lists(self) -> list[ASPathListConfig]:
        """Parse AS-path definitions from ``policy-options``.

        ``as-path AS-OWN "^65000$";`` is a named statement whose value is the
        regex: ``{as-path: {AS-OWN: {^65000$: {}}}}``.
        """
        hier = self._get_hierarchy()
        po = hier.get("policy-options", {})
        if not isinstance(po, dict):
            return []

        asp_block = po.get("as-path")
        if not isinstance(asp_block, dict):
            return []

        result: list[ASPathListConfig] = []
        for asp_name, asp_data in asp_block.items():
            asp_name = str(asp_name).strip('"')
            if not asp_name:
                continue
            result.append(self._make_as_path(asp_name, _str_val(asp_data) or ""))

        return result

    def _make_as_path(self, name: str, regex: str) -> ASPathListConfig:
        return ASPathListConfig(
            object_id=f"as_path_list_{name}",
            raw_lines=self._raw_lines_for("policy-options", "as-path", name),
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
                    # prefix-list reference — search recursively (set-style nests
                    # it under family.inet.prefix-list)
                    pl_ref = _find_in_block(from_block, "prefix-list")
                    if pl_ref is not None:
                        pl_names = pl_ref if isinstance(pl_ref, list) else [pl_ref]
                        match_clauses.append(RouteMapMatch(
                            match_type="ip address prefix-list",
                            values=[_str_val(p) or "" for p in pl_names],
                        ))
                    # community reference
                    comm_ref = _find_in_block(from_block, "community")
                    if comm_ref is not None:
                        comms = comm_ref if isinstance(comm_ref, list) else [comm_ref]
                        match_clauses.append(RouteMapMatch(
                            match_type="community",
                            values=[_str_val(c) or "" for c in comms],
                        ))
                    # as-path reference
                    asp_ref = _find_in_block(from_block, "as-path")
                    if asp_ref is not None:
                        asps = asp_ref if isinstance(asp_ref, list) else [asp_ref]
                        match_clauses.append(RouteMapMatch(
                            match_type="as-path",
                            values=[_str_val(a) or "" for a in asps],
                        ))

                # ``then accept;`` (leaf) and ``then { … }`` (block) are the same
                # node in the canonical tree — both are dicts.
                then_block = term_data.get("then", {})
                if not isinstance(then_block, dict):
                    then_block = {}
                action = "deny" if "reject" in then_block else "permit"
                set_clauses.extend(self._policy_set_clauses(then_block))

                sequences.append(RouteMapSequence(
                    sequence=seq,
                    action=action,
                    match_clauses=match_clauses,
                    set_clauses=set_clauses,
                ))
                seq += 10

            result.append(RouteMapConfig(
                object_id=f"route_map_{ps_name}",
                raw_lines=self._raw_lines_for("policy-options", "policy-statement", ps_name),
                source_os=self.os_type,
                line_numbers=[],
                name=ps_name,
                sequences=sequences,
            ))

        return result

    #: JunOS ``then`` actions that carry a single value → RouteMapSet.set_type.
    #: Adding another scalar action is one row here, not a new branch.  Only
    #: statements attested by the syntax corpus are listed — an unverified row
    #: would be an invented statement name that nothing tests.
    _POLICY_SET_ACTIONS: tuple[tuple[str, str], ...] = (
        ("local-preference", "local-preference"),
        ("metric", "metric"),
    )

    #: JunOS community operations (``then community add|set|delete NAME;``).
    #: The operation is part of the set_type, as IOS-XR does for
    #: ``as-path prepend`` — consumers substring-match on "community".
    _POLICY_COMMUNITY_OPS: tuple[str, ...] = ("add", "set", "delete")

    def _policy_set_clauses(self, then_block: dict[str, Any]) -> list[RouteMapSet]:
        """Build the set-clauses of one policy term from its ``then`` block."""
        clauses: list[RouteMapSet] = []

        for keyword, set_type in self._POLICY_SET_ACTIONS:
            val = _str_val(then_block.get(keyword))
            if val:
                clauses.append(RouteMapSet(set_type=set_type, values=[val]))

        # ``community add CL;`` — the community actions the policy→community
        # dependency edge depends on.  Renderings converge on
        # ``{community: {add: {CL: {}}}}``.
        comm = then_block.get("community")
        if isinstance(comm, dict):
            for op in self._POLICY_COMMUNITY_OPS:
                names = _str_vals(comm.get(op))
                if names:
                    clauses.append(RouteMapSet(
                        set_type=f"community {op}",
                        values=names,
                    ))

        return clauses

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

    # JunOS BGP session attributes are legal at THREE levels — ``bgp``,
    # ``group`` and ``neighbor`` — and a peer inherits whatever it does not
    # override.  Every one of them is read by the same table-driven extractor,
    # so supporting the next attribute is one row here (handbook §7: a fix that
    # needs a change in two places within a layer is still a patch).
    #
    # (statement, model field, reader, inheritable)
    _BGP_ATTRS: tuple[tuple[str, str, str, bool], ...] = (
        ("local-address", "update_source", "str", True),
        ("authentication-key", "password", "str", True),
        ("hold-time", "timers", "timers", True),
        ("multihop", "ebgp_multihop", "multihop", True),
        ("family", "maximum_prefix", "prefix_limit", True),
        ("import", "route_map_in", "str", True),
        ("export", "route_map_out", "str", True),
        # A description describes the object it is written on; it is not a
        # session attribute a peer inherits from its group.
        ("description", "description", "str", False),
    )

    @classmethod
    def _bgp_attrs(cls, node: dict[str, Any], *, inherited: bool = False) -> dict[str, Any]:
        """Read every BGP session attribute present on one hierarchy node.

        Returns only the attributes the node actually configures, so that
        :meth:`_bgp_inherit` can layer neighbor over group over instance without
        a per-field ``or`` chain.  With *inherited* set, only the attributes a
        child level inherits are returned.
        """
        out: dict[str, Any] = {}
        for stmt, field, kind, inheritable in cls._BGP_ATTRS:
            if inherited and not inheritable:
                continue
            raw = node.get(stmt)
            if raw is None:
                continue
            value: Any = None
            if kind == "str":
                value = _str_val(raw)
            elif kind == "timers":
                # JunOS configures the hold time only; the keepalive interval is
                # one third of it and is not separately configurable.
                hold = _int_val(raw)
                if hold is not None:
                    value = BGPTimers(keepalive=max(hold // 3, 1), holdtime=hold)
            elif kind == "multihop":
                # Two vendor pages disagree on the emitted shape — the statement
                # page gives a container (``multihop { ttl 2; }``), the group
                # page a leaf (``multihop 2;``) — and ``set`` form gives
                # ``multihop ttl 2``.  Flattening the statement to its option
                # tokens reads all three, so the disagreement costs no branch.
                # A bare ``multihop;`` means multihop with the default TTL (64).
                tokens = _stmt_tokens(raw)
                ttl = _token_arg(tokens, "ttl")
                if ttl is None:
                    ttl = next((t for t in tokens if t.isdigit()), None)
                value = _int_or_none(ttl) or 64
            elif kind == "prefix_limit":
                value = cls._prefix_limit_maximum(raw)
            if value is not None:
                out[field] = value
        return out

    @staticmethod
    def _prefix_limit_maximum(family: Any) -> int | None:
        """Read ``family <af> { <safi> { prefix-limit { maximum N; } } }``.

        This WALKS THE PATH; it must not search for a ``maximum`` key wherever it
        appears under ``family``.  ``accepted-prefix-limit`` is a separate,
        identically-shaped statement at the same level with a different meaning —
        ``prefix-limit`` tears the session down, ``accepted-prefix-limit`` merely
        stops accepting further routes — and a key-hunt reports a peer that sets
        only the soft limit as having a hard limit it does not have.  So do the
        sibling containers ``drop-excess`` / ``hide-excess`` / ``teardown``.
        """
        if not isinstance(family, dict):
            return None
        for afi_data in family.values():          # inet | inet6 | inet-vpn | …
            if not isinstance(afi_data, dict):
                continue
            for safi_data in afi_data.values():   # unicast | multicast | …
                if not isinstance(safi_data, dict):
                    continue
                limit = safi_data.get("prefix-limit")
                if isinstance(limit, dict):
                    maximum = _int_val(limit.get("maximum"))
                    if maximum is not None:
                        return maximum
        return None

    @staticmethod
    def _bgp_inherit(*levels: dict[str, Any]) -> dict[str, Any]:
        """Flatten instance → group → neighbor attributes; the last one wins.

        This is the *inherited peer configuration* concept the JunOS group,
        the PAN-OS peer-group and the IOS peer-group all need: a peer reports
        the attributes of its group unless it overrides them.
        """
        merged: dict[str, Any] = {}
        for level in levels:
            merged.update(level)
        return merged

    def _parse_bgp_block(
        self,
        bgp_data: dict[str, Any],
        asn: int,
        router_id_str: str | None,
        vrf: str | None,
    ) -> BGPConfig | None:
        """Build a BGPConfig from a parsed ``bgp { group … }`` dict."""
        from ipaddress import IPv4Address, ip_address
        peer_groups: list[BGPPeerGroup] = []
        neighbors: list[BGPNeighbor] = []

        groups = bgp_data.get("group", {})
        if not isinstance(groups, dict):
            groups = {}

        # Attributes configured directly under ``protocols bgp`` apply to every
        # group and peer beneath it.
        inst_attrs = self._bgp_attrs(bgp_data, inherited=True)

        for grp_name, grp_data in groups.items():
            if not isinstance(grp_data, dict):
                continue

            grp_type = _str_val(grp_data.get("type", ""))
            peer_as_str = _str_val(grp_data.get("peer-as"))
            try:
                remote_as: int | str = int(peer_as_str) if peer_as_str else ("internal" if grp_type == "internal" else 0)
            except ValueError:
                remote_as = peer_as_str or 0

            # What the group itself reports, and what its members inherit — the
            # latter drops the attributes that describe only the group.
            grp_attrs = self._bgp_inherit(inst_attrs, self._bgp_attrs(grp_data))
            grp_inherited = self._bgp_inherit(
                inst_attrs, self._bgp_attrs(grp_data, inherited=True)
            )

            pg = BGPPeerGroup(
                name=grp_name,
                remote_as=remote_as if remote_as != 0 else None,
                **grp_attrs,
            )
            peer_groups.append(pg)

            # Parse neighbors within this group
            nbr_block = _as_named_block(grp_data.get("neighbor", {}))

            for nbr_ip_str, nbr_data in nbr_block.items():
                if not isinstance(nbr_data, dict):
                    nbr_data = {}
                # J14: support both IPv4 and IPv6 neighbors
                try:
                    peer_ip = ip_address(nbr_ip_str)
                except ValueError:
                    continue

                nbr_remote_as = remote_as
                nbr_remote_as_str = _str_val(nbr_data.get("peer-as"))
                if nbr_remote_as_str:
                    try:
                        nbr_remote_as = int(nbr_remote_as_str)
                    except ValueError:
                        pass

                # The peer's effective configuration: inherited group attributes
                # unless the peer overrides them.
                attrs = self._bgp_inherit(grp_inherited, self._bgp_attrs(nbr_data))
                rm_in = attrs.get("route_map_in")
                rm_out = attrs.get("route_map_out")

                # J9: resolve "internal" to the device's own ASN
                effective_remote_as: int | str
                if nbr_remote_as == 0 or nbr_remote_as == "internal":
                    effective_remote_as = asn  # device's own ASN for iBGP
                else:
                    effective_remote_as = nbr_remote_as

                # 1b: local-address is an IP; parse() reverse-resolves it to the
                # interface that owns it, so update_source names an interface.
                local_addr = attrs.pop("update_source", None)
                if local_addr:
                    # Canonicalize both peer IP key and local-address value
                    # so IPv6 forms like 2001:DB8::1 match the map built
                    # from parsed interface addresses.
                    canon_peer = str(peer_ip)  # already canonical from ip_address()
                    try:
                        canon_local = str(ip_address(local_addr))
                    except ValueError:
                        canon_local = local_addr
                    self._bgp_local_addresses[canon_peer] = canon_local

                afi = "ipv6" if peer_ip.version == 6 else "ipv4"
                af = BGPNeighborAF(
                    afi=afi,
                    safi="unicast",
                    route_map_in=rm_in,
                    route_map_out=rm_out,
                )

                neighbors.append(BGPNeighbor(
                    peer_ip=peer_ip,
                    remote_as=effective_remote_as,
                    peer_group=grp_name,
                    address_families=[af],
                    **attrs,
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

        # JunOS ECMP: "multipath;" at global BGP or group level
        # No explicit path count — JunOS default is 16; use 64 as a
        # high-water mark indicating "multipath enabled".
        multipath_enabled = (
            "multipath" in bgp_data
            or any(
                "multipath" in grp_data
                for grp_data in groups.values()
                if isinstance(grp_data, dict)
            )
        )
        address_families: list[BGPAddressFamily] = []
        if multipath_enabled:
            address_families.append(BGPAddressFamily(
                afi="ipv4",
                safi="unicast",
                vrf=None,
                maximum_paths=64,
            ))

        if vrf:
            _bgp_raw = self._raw_lines_for("routing-instances", vrf, "protocols", "bgp")
        else:
            _bgp_raw = self._raw_lines_for("protocols", "bgp")

        gr_enabled, gr_restart_time = self._graceful_restart(bgp_data, vrf)

        return BGPConfig(
            object_id=f"bgp_{asn}" + (f"_vrf_{vrf}" if vrf else ""),
            raw_lines=_bgp_raw,
            source_os=self.os_type,
            line_numbers=[],
            asn=asn,
            router_id=rid,
            vrf=vrf,
            neighbors=neighbors,
            peer_groups=peer_groups,
            address_families=address_families,
            graceful_restart=gr_enabled,
            graceful_restart_restart_time=gr_restart_time,
        )

    def _graceful_restart(
        self, bgp_data: dict[str, Any], vrf: str | None
    ) -> tuple[bool, int | None]:
        """Is graceful restart ON for this BGP instance, and with what restart-time?

        JunOS splits this across two hierarchies, and getting it wrong in either
        direction reports the opposite of the truth:

        * ``routing-options { graceful-restart; }`` is the GLOBAL ENABLE. Graceful
          restart is **disabled by default**, and per the vendor "you cannot enable
          graceful restart for specific protocols unless graceful restart is also
          enabled globally".
        * ``protocols { bgp { graceful-restart { … } } }`` can only MODIFY or
          DISABLE it — ``graceful-restart { disable; }`` opts BGP out; ``restart-time``
          tunes it. **A ``graceful-restart`` stanza under ``protocols bgp`` does not
          turn graceful restart on.**

        So a config carrying only the BGP stanza describes a device with GR OFF,
        and reporting True for it would be a fabricated value. For a routing
        instance the enable may also come from that instance's own
        ``routing-options``.
        """
        hier = self._get_hierarchy()

        ro: Any = hier.get("routing-options", {})
        if vrf:
            ri = hier.get("routing-instances", {})
            inst = ri.get(vrf, {}) if isinstance(ri, dict) else {}
            inst_ro = inst.get("routing-options", {}) if isinstance(inst, dict) else {}
            # An instance-local enable, else the global one.
            if isinstance(inst_ro, dict) and "graceful-restart" in inst_ro:
                ro = inst_ro

        if not isinstance(ro, dict) or "graceful-restart" not in ro:
            return False, None
        global_gr = ro.get("graceful-restart")
        if isinstance(global_gr, dict) and "disable" in global_gr:
            return False, None

        gr = bgp_data.get("graceful-restart")
        if isinstance(gr, dict) and "disable" in gr:
            return False, None

        restart_time = (
            _int_or_none(_str_val(gr.get("restart-time")))
            if isinstance(gr, dict) else None
        )
        return True, restart_time

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

        # ``static.route`` takes three shapes depending on which route forms are
        # present (CCR-0032 — data corruption):
        #   - str  : a single flat ``route PREFIX next-hop NH;``
        #   - list : several flat routes
        #   - dict : any route used the block form ``route PREFIX { … }`` — the
        #            tokenizer then keys EVERY route (block-form AND flat sibling)
        #            under ``route`` as a dict.  The old code handled only
        #            str/list, so one block-form route erased the whole block.
        # Normalize all three into ``(prefix_str, inline_tokens, block_attrs)``.
        routes = static.get("route", None)
        entries: list[tuple[str, list[str], dict]] = []
        if isinstance(routes, str):
            toks = (routes or "").split()
            if toks:
                entries.append((toks[0], toks[1:], {}))
        elif isinstance(routes, list):
            for item in routes:
                toks = (_str_val(item) or "").split()
                if toks:
                    entries.append((toks[0], toks[1:], {}))
        elif isinstance(routes, dict):
            for key, val in routes.items():
                toks = str(key).split()
                if not toks:
                    continue
                block = val if isinstance(val, dict) else {}
                entries.append((toks[0], toks[1:], block))

        from ipaddress import ip_network, ip_address
        for prefix_str, inline, block in entries:
            try:
                destination = ip_network(prefix_str, strict=False)
            except ValueError:
                continue

            # Next-hop from the block body or the inline remainder.
            next_hop_str = None
            if "next-hop" in block:
                next_hop_str = _str_val(block.get("next-hop"))
            elif len(inline) >= 2 and inline[0] == "next-hop":
                next_hop_str = inline[1]
            elif inline:
                next_hop_str = inline[0]

            next_hop = None
            if next_hop_str and next_hop_str not in ("discard", "reject", "blackhole"):
                try:
                    next_hop = ip_address(next_hop_str)
                except ValueError:
                    next_hop = next_hop_str  # interface name

            # ``preference`` → administrative distance; ``tag`` → route tag.
            distance = 1
            pref_val = _str_val(block.get("preference")) if "preference" in block else None
            if pref_val is not None:
                try:
                    distance = int(pref_val)
                except (TypeError, ValueError):
                    pass
            tag = None
            tag_val = _str_val(block.get("tag")) if "tag" in block else None
            if tag_val is not None:
                try:
                    tag = int(tag_val)
                except (TypeError, ValueError):
                    pass

            result.append(StaticRoute(
                object_id=f"static_{prefix_str}" + (f"_vrf_{vrf}" if vrf else ""),
                raw_lines=self._raw_lines_for("routing-options", "static") if not vrf else self._raw_lines_for("routing-instances", vrf, "routing-options", "static"),
                source_os=self.os_type,
                line_numbers=[],
                destination=destination,
                next_hop=next_hop,
                distance=distance,
                tag=tag,
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
        passive_interfaces: list[str] = []
        area_block = ospf_data.get("area", {})
        if isinstance(area_block, dict):
            for area_id, area_data in area_block.items():
                if not isinstance(area_data, dict):
                    continue
                intf_block = _as_named_block(area_data.get("interface", {}))
                intf_names = list(intf_block.keys())

                # J7: area type (stub / nssa).
                # ``stub`` is a LEAF STATEMENT WITH INLINE OPTIONS —
                # ``stub default-metric 10 no-summaries;`` — so its options are
                # read from the flattened token list, which is identical for the
                # brace chain and the set-form branches.
                area_type = OSPFAreaType.NORMAL
                stub_no_summary = False
                nssa_no_summary = False
                nssa_dio = False
                default_cost: int | None = None
                if "stub" in area_data:
                    stub_tokens = _stmt_tokens(area_data["stub"])
                    default_cost = _int_or_none(
                        _token_arg(stub_tokens, "default-metric")
                    )
                    if "no-summaries" in stub_tokens:
                        area_type = OSPFAreaType.TOTALLY_STUB
                        stub_no_summary = True
                    else:
                        area_type = OSPFAreaType.STUB
                elif "nssa" in area_data:
                    nssa_data = area_data["nssa"]
                    nssa_tokens = _stmt_tokens(nssa_data)
                    default_cost = _int_or_none(
                        _token_arg(nssa_tokens, "default-metric")
                    )
                    if "no-summaries" in nssa_tokens:
                        area_type = OSPFAreaType.TOTALLY_NSSA
                        nssa_no_summary = True
                    else:
                        area_type = OSPFAreaType.NSSA
                    if "default-lsa" in nssa_tokens:
                        nssa_dio = True

                # J7 / CCR-0038 Theme 2: JunOS writes the per-interface OSPF
                # settings INSIDE the area, where parse_interfaces cannot see
                # them. They are carried out in the MODEL —
                # OSPFArea.interface_settings — and attributed onto the
                # InterfaceConfig of that name by the ONE shared walk,
                # BaseParser._backfill_ospf_interface_settings. This used to be a
                # private dict applied in a JunOS-only parse() override; PAN-OS
                # had a second copy of the same idea and IOS-XR had none.
                iface_settings: dict[str, OSPFInterfaceConfig] = {}
                for intf_name, intf_ospf in intf_block.items():
                    if not isinstance(intf_ospf, dict) or not intf_ospf:
                        continue
                    settings = OSPFInterfaceConfig(
                        name=intf_name,
                        area_id=str(area_id),
                        # NOTE `metric` IS THE OSPF COST — JunOS has no `cost`
                        # keyword (syntax-corpus junos/ospf.yaml: interface).
                        cost=_int_val(intf_ospf.get("metric")),
                        hello_interval=_int_val(intf_ospf.get("hello-interval")),
                        dead_interval=_int_val(intf_ospf.get("dead-interval")),
                        network_type=_str_val(intf_ospf.get("interface-type")),
                        priority=_int_val(intf_ospf.get("priority")),
                        passive="passive" in intf_ospf,
                    )
                    if "passive" in intf_ospf:
                        passive_interfaces.append(intf_name)

                    # bfd-liveness-detection { minimum-interval 300; } — a BLOCK,
                    # not a flag. Its timers are the interface's BFD timers.
                    bfd_data = intf_ospf.get("bfd-liveness-detection")
                    if isinstance(bfd_data, dict):
                        settings.bfd = True
                        settings.bfd_interval = _int_val(
                            bfd_data.get("minimum-interval")
                        )
                        settings.bfd_min_rx = _int_val(
                            bfd_data.get("minimum-receive-interval")
                        )
                        settings.bfd_multiplier = _int_val(bfd_data.get("multiplier"))

                    if "authentication" in intf_ospf:
                        auth_data = intf_ospf["authentication"]
                        if isinstance(auth_data, dict) and "md5" in auth_data:
                            settings.authentication = "message-digest"
                        elif isinstance(auth_data, dict) and "simple-password" in auth_data:
                            settings.authentication = "simple"
                            settings.authentication_key = _str_val(
                                auth_data.get("simple-password")
                            )
                        else:
                            settings.authentication = "simple"

                    iface_settings[intf_name] = settings

                areas.append(OSPFArea(
                    area_id=str(area_id),
                    interfaces=intf_names,
                    interface_settings=iface_settings,
                    area_type=area_type,
                    stub_no_summary=stub_no_summary,
                    nssa_no_summary=nssa_no_summary,
                    nssa_default_information_originate=nssa_dio,
                    default_cost=default_cost,
                ))

        # ---- OSPF-advanced fields ----

        # Reference bandwidth: "reference-bandwidth 10g" or numeric
        auto_cost_ref_bw: int | None = None
        ref_bw = _str_val(ospf_data.get("reference-bandwidth"))
        if ref_bw:
            # JunOS uses suffixes: 1k=1000, 1m=1000000, 1g=1000000000
            m = re.match(r"(\d+)([kmg])?", ref_bw, re.IGNORECASE)
            if m:
                val = int(m.group(1))
                suffix = (m.group(2) or "").lower()
                if suffix == "k":
                    val *= 1000
                elif suffix == "m":
                    val *= 1000000
                elif suffix == "g":
                    val *= 1000000000
                auto_cost_ref_bw = val

        # Graceful restart
        graceful_restart = "graceful-restart" in ospf_data
        graceful_restart_helper = False
        gr_data = ospf_data.get("graceful-restart", {})
        if isinstance(gr_data, dict):
            graceful_restart_helper = "helper-disable" not in gr_data
        elif isinstance(gr_data, str) and gr_data == "helper-disable":
            graceful_restart_helper = False

        # BFD (JunOS: "bfd-liveness-detection" under ospf or per-interface)
        bfd_all = "bfd-liveness-detection" in ospf_data

        # Overload (equivalent to max-metric router-lsa)
        max_metric_router_lsa = "overload" in ospf_data

        # Router ID
        router_id = None
        rid_str = _str_val(ospf_data.get("router-id"))
        if rid_str:
            from ipaddress import IPv4Address
            try:
                router_id = IPv4Address(rid_str)
            except ValueError:
                pass

        # ``export [ POLICY … ];`` is how redistribution INTO OSPF is expressed
        # on JunOS — there is no ``redistribute`` keyword.  Everything a device
        # injects into OSPF from static/BGP/direct arrives through an export
        # policy, so a model that ignores ``export`` cannot see redistribution
        # at all, and the OSPF→policy dependency edge is lost.  The source
        # protocol is not named here (it lives in the policy's own ``from
        # protocol`` terms), so it is recorded as "policy".
        redistribute = [
            OSPFRedistribute(protocol="policy", route_map=policy)
            for policy in _str_vals(ospf_data.get("export"))
        ]

        return [OSPFConfig(
            object_id="ospf_1",
            raw_lines=self._raw_lines_for("protocols", "ospf"),
            source_os=self.os_type,
            line_numbers=[],
            process_id=1,
            router_id=router_id,
            areas=areas,
            passive_interfaces=passive_interfaces,
            auto_cost_reference_bandwidth=auto_cost_ref_bw,
            graceful_restart=graceful_restart,
            graceful_restart_helper=graceful_restart_helper,
            bfd_all_interfaces=bfd_all,
            max_metric_router_lsa=max_metric_router_lsa,
            redistribute=redistribute,
        )]

    # ------------------------------------------------------------------
    # Firewall filter → ACL (Stage 10)
    # ------------------------------------------------------------------

    def _iter_filters(self, fw: dict[str, Any]):
        """Yield ``(filter_name, filter_data, afi)`` for every firewall filter.

        ``[edit firewall]`` and ``[edit firewall family inet]`` are EQUIVALENT
        hierarchy levels: the ``family`` statement is required only for a family
        other than IPv4, and a device emits back whichever form was configured —
        it does not rewrite the family-less one.  (Juniper's own YANG model
        carries both paths as siblings sharing one body grouping.)  So this is
        not two parsers for two syntaxes; it is one walk over the two datastore
        paths the filter body can hang from.
        """
        # Family-less filters: [edit firewall filter <name>] — IPv4.
        direct = fw.get("filter")
        if isinstance(direct, dict):
            for name, data in direct.items():
                if isinstance(data, dict):
                    yield str(name), data, "ipv4"

        # [edit firewall family <family-name> filter <name>]
        families = fw.get("family")
        if isinstance(families, dict):
            for fam_name, fam_data in families.items():
                if not isinstance(fam_data, dict):
                    continue
                filters = fam_data.get("filter")
                if not isinstance(filters, dict):
                    continue
                afi = "ipv6" if str(fam_name) == "inet6" else "ipv4"
                for name, data in filters.items():
                    if isinstance(data, dict):
                        yield str(name), data, afi

    def parse_acls(self) -> list[ACLConfig]:
        """Parse ``firewall { [family F {] filter NAME { term T { … } } [}] }``."""
        hier = self._get_hierarchy()
        fw = hier.get("firewall", {})
        if not isinstance(fw, dict):
            return []

        result: list[ACLConfig] = []
        for filter_name, filter_data, afi in self._iter_filters(fw):
            entries: list[ACLEntry] = []
            terms = filter_data.get("term", {})
            if isinstance(terms, dict):
                seq = 10
                for term_name, term_data in terms.items():
                    if not isinstance(term_data, dict):
                        seq += 10
                        continue
                    entries.extend(self._make_acl_entries(seq, str(term_name), term_data))
                    seq += 10

            result.append(ACLConfig(
                object_id=f"acl_{filter_name}",
                raw_lines=self._raw_lines_for("firewall", "filter", filter_name),
                source_os=self.os_type,
                line_numbers=[],
                name=filter_name,
                acl_type="extended",
                entries=entries,
            ))

        return result

    @classmethod
    def _make_acl_entries(
        cls, seq: int, term_name: str, term_data: dict[str, Any]
    ) -> list[ACLEntry]:
        """Build the ACLEntry(s) for one firewall-filter ``term``.

        ``then`` collapses to a leaf for a single action (``then accept;``) and is
        a block for several (``then { log; syslog; discard; }``) — one node in the
        canonical tree either way.

        An address match is the mirror image: ``source-address`` is emitted as a
        CONTAINER holding **one prefix per line**, and stays a container even for
        a single prefix, while the ``set`` rendering flattens the same statement
        to a trailing token.  A term may therefore match SEVERAL source and
        several destination prefixes, and it matches the cross product of them —
        but ``ACLEntry.source``/``.destination`` are single strings (a Cisco ACE
        has exactly one of each).  Rather than keep the first prefix and silently
        drop the rest — a confidently wrong answer to "does this filter permit
        X?" — one ACLEntry is emitted per (source, destination) pair, all sharing
        the term's name, action and sequence.  Reachability semantics survive;
        the term is still recoverable by grouping on ``sequence``/``remark``.
        """
        then_tokens = _stmt_tokens(term_data.get("then", {}))
        action = "deny" if ("discard" in then_tokens or "reject" in then_tokens) else "permit"

        from_block = term_data.get("from", {})
        if not isinstance(from_block, dict):
            from_block = {}

        sources = cls._address_match(from_block, "source")
        destinations = cls._address_match(from_block, "destination")

        return [
            ACLEntry(
                sequence=seq,
                action=action,
                remark=term_name,
                protocol=_str_val(from_block.get("protocol")),
                source=source,
                destination=destination,
                source_port=_str_val(from_block.get("source-port")),
                destination_port=_str_val(from_block.get("destination-port")),
            )
            for source in sources
            for destination in destinations
        ]

    @staticmethod
    def _address_match(from_block: dict[str, Any], side: str) -> list[str | None]:
        """Every prefix (or prefix-list) matched on one side of a term.

        Returns ``[None]`` when the term does not match on this side, so that the
        caller's cross product still yields one entry.

        A prefix carrying the per-prefix ``except`` modifier
        (``source-address { 0.0.0.0/0; 10.0.0.0/8 except; }``) is an EXCLUSION,
        and ``ACLEntry`` has no way to express one: emitting it as a match would
        invert its meaning.  It is therefore not emitted — the entry over-matches
        rather than mis-matching — and the loss is recorded as a model limitation
        in CCR-0036 rather than papered over.
        """
        addresses = from_block.get(f"{side}-address")
        prefixes: list[str | None] = []
        if isinstance(addresses, dict):
            for prefix, options in addresses.items():
                prefix = str(prefix).strip('"')
                if prefix and "except" not in _stmt_tokens(options):
                    prefixes.append(prefix)
        if not prefixes:
            prefixes = list(_str_vals(from_block.get(f"{side}-prefix-list")))
        return prefixes or [None]

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

        # ``server`` is a named block keyed by address; each address carries its
        # own option tokens (``prefer``, ``key <id>``, ``version <n>``).  The
        # address is the key, never part of the option string (CCR-0030 bug 2).
        servers: list[NTPServer] = []
        srv_block = ntp_data.get("server")
        if isinstance(srv_block, dict):
            for addr, opts in srv_block.items():
                addr = str(addr).strip('"')
                if not addr:
                    continue
                tokens = _stmt_tokens(opts)
                servers.append(NTPServer(
                    address=addr,
                    prefer="prefer" in tokens,
                    key_id=_int_or_none(_token_arg(tokens, "key")),
                    version=_int_or_none(_token_arg(tokens, "version")),
                ))

        if not servers:
            return None
        return NTPConfig(
            object_id="ntp",
            raw_lines=self._raw_lines_for("system", "ntp"),
            source_os=self.os_type,
            line_numbers=[],
            servers=servers,
            # JunOS names the NTP source by ADDRESS ("A valid IP address
            # configured on one of the device's interfaces") — there is no
            # `ntp source-interface` on JunOS. It therefore goes in
            # source_address, never in source_interface: an address in a field
            # named for an interface is the wrong-value defect [[CCR-0030]] is
            # about.
            source_address=_str_val(ntp_data.get("source-address")),
        )

    def parse_snmp(self) -> SNMPConfig | None:
        """Parse the top-level ``snmp { … }`` stanza.

        ``snmp`` is a TOP-LEVEL stanza on JunOS — a sibling of ``protocols`` and
        ``firewall``, not a child of ``system`` (hierarchy level ``[edit snmp]``,
        `community (SNMP)` CLI reference).  Reading it from under ``system`` is
        reading a path no device emits.
        """
        hier = self._get_hierarchy()
        snmp_data = hier.get("snmp", {})
        if not isinstance(snmp_data, dict) or not snmp_data:
            return None

        communities: list[SNMPCommunity] = []
        comm_block = snmp_data.get("community", {})
        if isinstance(comm_block, dict):
            for comm_name, comm_data in comm_block.items():
                comm_name = str(comm_name).strip('"')
                if not comm_name:
                    continue
                # ``authorization`` is a nested statement, not a trailing token.
                auth = _str_val(comm_data.get("authorization")) or "read-only"
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
            raw_lines=self._raw_lines_for("snmp"),
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
            raw_lines=self._raw_lines_for("system", "syslog"),
            source_os=self.os_type,
            line_numbers=[],
            hosts=hosts,
            # A SIBLING of the `host` stanzas, not a child of one: the address
            # "is recorded as the message source in messages sent to the remote
            # machines specified in ALL host statements". An ADDRESS again, so
            # source_address (see NTPConfig.source_address).
            source_address=_str_val(syslog_data.get("source-address")),
        )


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _find_in_block(d: dict[str, Any], key: str) -> Any:
    """Return the value for *key* from *d* or any nested dict child.

    Needed for set-style configs where ``from family inet prefix-list PL_X``
    nests ``prefix-list`` under ``family.inet`` rather than directly under
    ``from``.  Direct lookup wins; nested lookup is a fallback.
    """
    if not isinstance(d, dict):
        return None
    if key in d:
        return d[key]
    for v in d.values():
        if isinstance(v, dict):
            found = _find_in_block(v, key)
            if found is not None:
                return found
    return None


def _int_or_none(s: str | None) -> int | None:
    """Return *s* as an int, or None if absent / not numeric."""
    if s is None:
        return None
    try:
        return int(s)
    except ValueError:
        return None


def _str_val(v: Any) -> str | None:
    """Return the value of a canonical-tree statement node as a string, or None.

    In the canonical tree a statement's value is its first child key
    (``peer-as 65006;`` and ``set … peer-as 65006`` both give ``{'65006': {}}``).
    Taking the *first* key is also what makes configuration-group precedence
    work: an explicit local value is inserted before any inherited one
    (see :mod:`confgraph.parsers.junos_groups`).

    ``str``/``list`` inputs are still accepted so that callers may pass a value
    that has already been reduced to a scalar.
    """
    if v is None:
        return None
    if isinstance(v, list):
        v = v[0] if v else None
    if v is None:
        return None
    if isinstance(v, dict):
        keys = [k for k in v if k != ""]
        if not keys:
            return None
        return str(keys[0]).strip('"') or None
    return str(v).strip('"')


def _str_vals(v: Any) -> list[str]:
    """Return *all* values of a canonical statement node, in configured order.

    ``members [ 65000:100 65000:200 ];`` and the two equivalent ``set`` lines
    both yield ``['65000:100', '65000:200']``.
    """
    if v is None:
        return []
    if isinstance(v, dict):
        return [str(k).strip('"') for k in v if str(k).strip('"')]
    if isinstance(v, list):
        return [s for s in (_str_val(item) for item in v) if s]
    s = _str_val(v)
    return [s] if s else []


def _stmt_tokens(v: Any) -> list[str]:
    """Flatten a statement node into its inline option tokens (DFS pre-order).

    This is the single reader for *leaf statements that carry inline options*,
    and it is what lets one code path handle every rendering of them:

    ==========================================  ==========================
    Config                                      ``_stmt_tokens`` result
    ==========================================  ==========================
    ``stub default-metric 10 no-summaries;``    ``[default-metric, 10, no-summaries]``
    ``set … stub default-metric 10``
        + ``set … stub no-summaries``           ``[default-metric, 10, no-summaries]``
    ``multihop { ttl 2; }``                     ``[ttl, 2]``
    ``multihop 2;``                             ``[2]``
    ``set … multihop ttl 2``                    ``[ttl, 2]``
    ==========================================  ==========================

    The brace form nests inline options in a *chain* and the ``set`` form splits
    them across sibling branches, so neither the chain nor the branch shape can
    be assumed — but the flattened token sequence is the same for both, and it is
    the sequence the operator wrote.
    """
    out: list[str] = []
    if not isinstance(v, dict):
        s = _str_val(v)
        return [s] if s else []
    for key, child in v.items():
        key = str(key).strip('"')
        if key:
            out.append(key)
        out.extend(_stmt_tokens(child))
    return out


def _token_arg(tokens: list[str], keyword: str) -> str | None:
    """Return the token following *keyword* in a flattened statement, or None."""
    for i, tok in enumerate(tokens):
        if tok == keyword and i + 1 < len(tokens):
            return tokens[i + 1]
    return None


def _int_val(v: Any) -> int | None:
    """Return *v* as an int, or None if not convertible."""
    s = _str_val(v)
    if s is None:
        return None
    try:
        return int(s)
    except ValueError:
        return None


def _as_named_block(v: Any) -> dict:
    """Normalise a hierarchy value to a dict keyed by name.

    Handles three shapes:
    - ``dict``  — already a named-block (return as-is)
    - ``str``   — single bare leaf (``'ge-0/0/0.0'`` → ``{'ge-0/0/0.0': {}}``)
    - ``list``  — multiple bare leaves → ``{name: {} for name in list}``
    - anything else → empty dict
    """
    if isinstance(v, dict):
        return v
    if isinstance(v, str):
        return {v: {}}
    if isinstance(v, list):
        return {str(item): {} for item in v}
    return {}


def _junos_interface_type(name: str) -> InterfaceType:
    """Classify a JunOS interface name into an InterfaceType.

    Delegates to the shared ``infer_interface_type`` util (single source of
    truth — also used by the Change-IR apply path, CCR
    change_ir_proposal_operations.md).
    """
    from confgraph.utils.interface import infer_interface_type

    return infer_interface_type(name, source_os="junos")
