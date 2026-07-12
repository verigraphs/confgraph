"""Palo Alto PAN-OS XML configuration parser.

Parses PAN-OS running-config XML files.  Uses xml.etree.ElementTree via the
panos_xml helper module rather than CiscoConfParse (which is IOS-style only).

Coverage:
  1. Virtual routers  → VRFConfig
  2. Interfaces + zone assignment → InterfaceConfig
  3. BGP (per virtual-router) → BGPConfig
  4. OSPF (per virtual-router) → OSPFConfig
  5. Static routes → StaticRoute
  6. Security policies → ACLConfig  (zone-based rules mapped to ACL model)
  7. NAT policies → NATConfig
  8. IPsec / IKE → CryptoConfig
  9. Security zones → PANOSZoneConfig

Two document layouts are read (CCR-0034):

  * **local firewall** — ``devices/entry/{deviceconfig,network,vsys/entry}``
  * **Panorama** — security/NAT policy under
    ``devices/entry/device-group/entry/{pre,post}-rulebase`` (plus
    ``/config/shared`` and the ``/config/readonly`` device-group hierarchy), and
    network/vsys config under ``devices/entry/template/entry/config/devices/entry``.

Which layout a document is in is decided **once**, by
``panos_xml.detect_layout``; the methods below only ever see its neutral scopes
(device / vsys / policy).  A document in neither layout raises ``ParseError`` —
an empty model would be indistinguishable from a firewall with no config, which
is exactly the harm CCR-0034 exists to end.
"""

from __future__ import annotations

from ipaddress import IPv4Interface, IPv4Network, IPv4Address, IPv6Interface
from xml.etree.ElementTree import Element

from confgraph.models.base import OSType, UnrecognizedBlock
from confgraph.models.interface import InterfaceConfig, InterfaceType
from confgraph.models.vrf import VRFConfig
from confgraph.models.bgp import (
    BGPConfig, BGPNeighbor, BGPPeerGroup, BGPRedistribute, BGPTimers,
)
from confgraph.models.ospf import (
    OSPFConfig, OSPFArea, OSPFAreaType, OSPFRedistribute,
)
from confgraph.models.route_map import (
    RouteMapConfig, RouteMapMatch, RouteMapSequence, RouteMapSet,
)
from confgraph.models.static_route import StaticRoute
from confgraph.models.acl import ACLConfig, ACLEntry
from confgraph.models.nat import NATConfig, NATDynamicEntry, NATStaticEntry
from confgraph.models.crypto import (
    CryptoConfig, IKEv1Policy, IKEv2Proposal, IKEv2Policy,
    IPSecTransformSet, CryptoMapEntry, CryptoMap,
)
from confgraph.models.panos_zone import PANOSZoneConfig

from confgraph.parsers.base import BaseParser, ParseError
from confgraph.parsers.panos_xml import (
    parse_panos_xml, detect_layout, UnrecognizedPANOSLayout,
    DeviceScope, PANOSLayout, PolicyScope, VsysScope,
    entries, text_val, members, raw_xml,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_net(prefix: str | None) -> IPv4Network | None:
    if not prefix:
        return None
    try:
        return IPv4Network(prefix, strict=False)
    except ValueError:
        return None


def _safe_addr(addr: str | None) -> IPv4Address | None:
    if not addr:
        return None
    try:
        return IPv4Address(addr)
    except ValueError:
        return None


def _safe_iface(addr: str | None) -> IPv4Interface | None:
    if not addr:
        return None
    try:
        return IPv4Interface(addr)
    except ValueError:
        return None


def _safe_int(val: str | None) -> int | None:
    if val is None:
        return None
    try:
        return int(val.strip())
    except ValueError:
        return None


def _choice(parent: Element | None, path: str) -> str | None:
    """Return the NAME of the child element at ``path`` — PAN-OS's enum encoding.

    PAN-OS encodes enumerations as ELEMENT NAMES, not text values.  An OSPF area
    type is ``<type><stub/></type>`` and never ``<type>stub</type>``; a BGP
    policy action is ``<action><deny/></action>``; a peer-group type is
    ``<type><ebgp>…</ebgp></type>``; a redist-profile action is
    ``<action><redist/></action>``.  Reading the *text* of those elements yields
    the empty string on every real device — that single mistake is CCR-0035 gaps
    #5 and #1.  This helper is the one place that reads the pattern, so the next
    enum costs a call, not a new branch.
    """
    el = parent.find(path) if parent is not None else None
    if el is None:
        return None
    for child in el:
        return child.tag
    return None


def _nat_source_acl_name(rule_name: str) -> str:
    """The ACL that holds the address set a source-NAT rule translates.

    ``parse_acls`` materializes it and ``parse_nat`` points ``NATDynamicEntry.acl``
    at it — one name, one definition, so the nat→acl edge always resolves.
    """
    return f"nat-source-{rule_name}"


def _classify_iface(name: str) -> InterfaceType:
    n = name.lower()
    if "loopback" in n or n.startswith("lo."):
        return InterfaceType.LOOPBACK
    if "tunnel" in n:
        return InterfaceType.TUNNEL
    if n.startswith("ae") or "bond" in n:
        return InterfaceType.PORTCHANNEL
    if "vlan" in n or n.startswith("vl"):
        return InterfaceType.VLAN
    if "mgmt" in n or "management" in n:
        return InterfaceType.MANAGEMENT
    return InterfaceType.PHYSICAL


class PANOSParser(BaseParser):
    """Parser for Palo Alto PAN-OS XML running configurations."""

    def __init__(self, config_text: str) -> None:
        # syntax="ios" is never used — we override all CiscoConfParse paths
        super().__init__(config_text, OSType.PANOS, syntax="ios")
        self._root: Element | None = None
        self._layout_view: PANOSLayout | None = None
        # zone_name → interface_name  (populated lazily)
        self._zone_of_iface: dict[str, str] = {}

    # ------------------------------------------------------------------
    # XML root + document layout (lazy, resolved exactly once)
    # ------------------------------------------------------------------

    def _get_root(self) -> Element:
        if self._root is None:
            self._root = parse_panos_xml(self.config_text)
        return self._root

    def _layout(self) -> PANOSLayout:
        """The document's layout — the only place that knows local vs Panorama.

        Every parse method below consumes the neutral scopes this returns, so a
        new layout costs one branch in ``detect_layout`` and nothing here.

        Raises:
            ParseError: the document is in no layout we can read.  An
                unreadable layout must be loud: returning an empty model made
                "no rules configured" indistinguishable from "rules we never
                looked for" (CCR-0034).
        """
        if self._layout_view is None:
            try:
                self._layout_view = detect_layout(self._get_root())
            except UnrecognizedPANOSLayout as exc:
                raise ParseError("layout", 0, "", exc) from exc
        return self._layout_view

    def _device_scopes(self) -> tuple[DeviceScope, ...]:
        """Elements owning ``deviceconfig``/``network`` (device or template)."""
        return self._layout().devices

    def _vsys_scopes(self) -> tuple[VsysScope, ...]:
        """vsys entries owning ``zone`` (local, or inside a template)."""
        return self._layout().vsys

    def _policy_scopes(self) -> tuple[PolicyScope, ...]:
        """Rulebase chains in evaluation order (vsys, or device-group)."""
        return self._layout().policies

    # ------------------------------------------------------------------
    # BaseParser overrides (avoid CiscoConfParse)
    # ------------------------------------------------------------------

    def _extract_hostname(self) -> str | None:
        for scope in self._device_scopes():
            hostname = text_val(scope.element, "deviceconfig/system/hostname")
            if hostname:
                return hostname
        return None

    def _collect_unrecognized_blocks(self) -> list[UnrecognizedBlock]:
        # PAN-OS XML has a flat, well-known structure — nothing to collect here
        return []

    # ------------------------------------------------------------------
    # 1. VRFs  (Virtual Routers)
    # ------------------------------------------------------------------

    def _virtual_routers(self) -> list[Element]:
        """Every ``network/virtual-router`` entry, across all device scopes."""
        vrs: list[Element] = []
        for scope in self._device_scopes():
            vrs.extend(entries(scope.element, "network/virtual-router"))
        return vrs

    def parse_vrfs(self) -> list[VRFConfig]:
        vrfs: list[VRFConfig] = []
        for vr in self._virtual_routers():
            name = vr.get("name", "")
            if not name:
                continue
            vrfs.append(VRFConfig(
                object_id=f"vr_{name}",
                source_os=self.os_type,
                name=name,
                raw_lines=[raw_xml(vr)],
            ))
        return vrfs

    # ------------------------------------------------------------------
    # 2. Interfaces
    # ------------------------------------------------------------------

    def parse_interfaces(self) -> list[InterfaceConfig]:
        # Build zone_of_iface map
        zone_of_iface: dict[str, str] = {}
        for vsys in self._vsys_scopes():
            for zone_el in entries(vsys.element, "zone"):
                zone_name = zone_el.get("name", "")
                net_el = zone_el.find("network")
                if net_el is not None:
                    for ztype in ("layer3", "layer2", "tap", "virtual-wire", "tunnel"):
                        for m in members(net_el, ztype):
                            zone_of_iface[m] = zone_name
        self._zone_of_iface = zone_of_iface

        # Build vr_of_iface map
        vr_of_iface: dict[str, str] = {}
        for vr in self._virtual_routers():
            vr_name = vr.get("name", "")
            for m in members(vr, "interface"):
                vr_of_iface[m] = vr_name

        # OSPF per-interface settings live inside the AREA, not on the interface.
        ospf_of_iface = self._ospf_interface_attrs()

        ifaces: list[InterfaceConfig] = []

        def _build(el: Element, name: str) -> InterfaceConfig:
            # IP address — PAN-OS stores as <ip><entry name="10.0.0.1/30"/>
            ip_addr = None
            first_ip_entry = el.find("layer3/ip/entry")
            if first_ip_entry is None:
                first_ip_entry = el.find("ip/entry")
            if first_ip_entry is not None:
                ip_addr = _safe_iface(first_ip_entry.get("name", ""))

            ipv6_addrs: list[IPv6Interface] = []
            for ip6_el in (el.findall(".//ipv6/addresses/entry") or []):
                try:
                    ipv6_addrs.append(IPv6Interface(ip6_el.get("name", "")))
                except ValueError:
                    pass

            desc = text_val(el, "comment")
            enabled = text_val(el, "link-state") != "down"
            mtu_str = text_val(el, "layer3/mtu") or text_val(el, "mtu")
            mtu = None
            if mtu_str and mtu_str.isdigit():
                mtu = int(mtu_str)

            ospf = ospf_of_iface.get(name, {})

            return InterfaceConfig(
                object_id=f"iface_{name}",
                source_os=self.os_type,
                name=name,
                interface_type=_classify_iface(name),
                description=desc,
                enabled=enabled,
                ip_address=ip_addr,
                ipv6_addresses=ipv6_addrs,
                mtu=mtu,
                zone=zone_of_iface.get(name),
                virtual_router=vr_of_iface.get(name),
                ospf_area=ospf.get("area"),
                ospf_cost=ospf.get("cost"),
                ospf_passive=bool(ospf.get("passive", False)),
                raw_lines=[raw_xml(el)],
            )

        for scope in self._device_scopes():
            net = scope.element.find("network")
            if net is None:
                continue

            # Ethernet interfaces (physical + sub-interfaces)
            for eth in entries(net, "interface/ethernet"):
                eth_name = eth.get("name", "")
                if not eth_name:
                    continue
                sub_entries = entries(eth, "layer3/units")
                if sub_entries:
                    for sub in sub_entries:
                        sub_name = sub.get("name", eth_name)
                        ifaces.append(_build(sub, sub_name))
                else:
                    ifaces.append(_build(eth, eth_name))

            # Loopback interfaces
            for lo in entries(net, "interface/loopback/units"):
                lo_name = lo.get("name", "")
                if lo_name:
                    ifaces.append(_build(lo, lo_name))

            # Tunnel interfaces
            for tun in entries(net, "interface/tunnel/units"):
                tun_name = tun.get("name", "")
                if tun_name:
                    ifaces.append(_build(tun, tun_name))

            # Aggregate-ethernet (AE/LACP bond)
            for ae in entries(net, "interface/aggregate-ethernet"):
                ae_name = ae.get("name", "")
                if not ae_name:
                    continue
                sub_entries = entries(ae, "layer3/units")
                if sub_entries:
                    for sub in sub_entries:
                        sub_name = sub.get("name", ae_name)
                        ifaces.append(_build(sub, sub_name))
                else:
                    ifaces.append(_build(ae, ae_name))

        return ifaces

    # ------------------------------------------------------------------
    # 3. BGP
    # ------------------------------------------------------------------

    def _redist_profiles(self, vr: Element) -> dict[str, list[str]]:
        """redist-profile name → the source protocols in its ``filter/type`` members.

        PAN-OS does not name the redistributed protocol on the redistribution
        *rule*.  BGP's ``redist-rules`` and OSPF's ``export-rules`` entries are
        keyed by the NAME of a ``redist-profile`` that sits beside ``<bgp>`` and
        ``<ospf>`` under ``<protocol>``; the protocols live in that profile's
        ``<filter><type><member>`` list.  ``address-family-identifier`` on the
        rule is ``ipv4|ipv6`` — an address family, not a protocol; reading it as
        the protocol is a category error (CCR-0035 #4).

        One resolver, both protocols: BGP and OSPF redistribution differ only in
        the container name (``redist-rules`` vs ``export-rules``).
        """
        profiles: dict[str, list[str]] = {}
        for container in ("protocol/redist-profile", "protocol/redist-profile-ipv6"):
            for prof in entries(vr, container):
                name = prof.get("name", "")
                if not name:
                    continue
                types = members(prof, "filter/type")
                if types:
                    profiles.setdefault(name, []).extend(types)
        return profiles

    def _bgp_auth_secrets(self, bgp_el: Element) -> dict[str, str]:
        """auth-profile name → secret.

        PAN-OS puts no password on the peer: the peer's
        ``connection-options/authentication`` holds the NAME of a profile under
        ``bgp/auth-profile``, and the secret lives there.  Authentication is a
        two-part relation, not a leaf (CCR-0035 #3).
        """
        secrets: dict[str, str] = {}
        for prof in entries(bgp_el, "auth-profile"):
            name = prof.get("name", "")
            secret = text_val(prof, "secret")
            if name and secret:
                secrets[name] = secret
        return secrets

    def _bgp_policy_bindings(self, bgp_el: Element) -> dict[str, dict[str, str]]:
        """peer-group name → {"import": rule, "export": rule}.

        A BGP policy rule binds to peer-groups through its ``<used-by>`` member
        list — that, not a per-peer statement, is PAN-OS's policy→peer edge.  A
        disabled rule (``<enable>no</enable>``) is not bound; it still exists as
        a policy node (``parse_route_maps``).  Where a group has several enabled
        rules in one direction, the first in document order is the one the
        normalized model can name — the rest remain visible as policy nodes.
        """
        bindings: dict[str, dict[str, str]] = {}
        for direction in ("import", "export"):
            for rule in entries(bgp_el, f"policy/{direction}/rules"):
                if text_val(rule, "enable") == "no":
                    continue
                rule_name = rule.get("name", "")
                if not rule_name:
                    continue
                for pg_name in members(rule, "used-by"):
                    bindings.setdefault(pg_name, {}).setdefault(direction, rule_name)
        return bindings

    def parse_bgp(self) -> list[BGPConfig]:
        bgp_list: list[BGPConfig] = []

        for vr in self._virtual_routers():
            vr_name = vr.get("name", "")
            bgp_el = vr.find("protocol/bgp")
            if bgp_el is None:
                continue
            if text_val(bgp_el, "enable") != "yes":
                continue

            local_as_str = text_val(bgp_el, "local-as")
            if not local_as_str:
                continue
            try:
                local_as = int(local_as_str)
            except ValueError:
                continue

            router_id = _safe_addr(text_val(bgp_el, "router-id"))
            auth_secrets = self._bgp_auth_secrets(bgp_el)
            bindings = self._bgp_policy_bindings(bgp_el)

            neighbors: list[BGPNeighbor] = []
            peer_groups: list[BGPPeerGroup] = []

            # Peers are ALWAYS nested in a peer-group — PAN-OS has no ungrouped peer.
            for pg in entries(bgp_el, "peer-group"):
                pg_name = pg.get("name", "")
                if not pg_name:
                    continue
                pg_type = _choice(pg, "type")           # ebgp | ibgp | *-confed
                export_nexthop = (
                    text_val(pg, f"type/{pg_type}/export-nexthop") if pg_type else None
                )
                bound = bindings.get(pg_name, {})
                route_map_in = bound.get("import")
                route_map_out = bound.get("export")

                peer_groups.append(BGPPeerGroup(
                    name=pg_name,
                    next_hop_self=(export_nexthop == "use-self"),
                    route_map_in=route_map_in,
                    route_map_out=route_map_out,
                ))

                for peer in entries(pg, "peer"):
                    peer_ip_str = text_val(peer, "peer-address/ip")
                    # <peer-as> is a DIRECT child of the peer entry. It is not
                    # spelled remote-as and it is not under connection-options —
                    # no device emits either of those (CCR-0035 #8).
                    remote_as_str = text_val(peer, "peer-as")
                    if not peer_ip_str or not remote_as_str:
                        continue
                    # The GUI accepts an IP or IP/mask for the peer address.
                    peer_ip = _safe_addr(peer_ip_str.split("/")[0])
                    if peer_ip is None:
                        continue
                    try:
                        remote_as = int(remote_as_str)
                    except ValueError:
                        remote_as = remote_as_str  # type: ignore[assignment]

                    opts = peer.find("connection-options")
                    keepalive = _safe_int(text_val(opts, "keep-alive-interval"))
                    holdtime = _safe_int(text_val(opts, "hold-time"))
                    timers = (
                        BGPTimers(keepalive=keepalive, holdtime=holdtime)
                        if keepalive is not None and holdtime is not None
                        else None
                    )
                    # <multihop> is a TTL (0-255), not a boolean: 0 means "the
                    # protocol default" (1 for eBGP, 255 for iBGP), not "off".
                    multihop = _safe_int(text_val(opts, "multihop"))
                    auth_name = text_val(opts, "authentication")

                    neighbors.append(BGPNeighbor(
                        peer_ip=peer_ip,
                        remote_as=remote_as,
                        peer_group=pg_name,
                        description=peer.get("name", ""),
                        shutdown=(text_val(peer, "enable") == "no"),
                        update_source=text_val(peer, "local-address/interface"),
                        timers=timers,
                        ebgp_multihop=multihop,
                        password=auth_secrets.get(auth_name) if auth_name else None,
                        maximum_prefix=_safe_int(text_val(peer, "max-prefixes")),
                        next_hop_self=(export_nexthop == "use-self"),
                        route_map_in=route_map_in,
                        route_map_out=route_map_out,
                    ))

            redistribute: list[BGPRedistribute] = []
            profiles = self._redist_profiles(vr)
            for redist in entries(bgp_el, "redist-rules"):
                if text_val(redist, "enable") == "no":
                    continue
                metric = _safe_int(text_val(redist, "metric"))
                for proto in profiles.get(redist.get("name", ""), []):
                    redistribute.append(BGPRedistribute(protocol=proto, metric=metric))

            bgp_list.append(BGPConfig(
                object_id=f"bgp_{local_as}_{vr_name}",
                source_os=self.os_type,
                asn=local_as,
                router_id=router_id,
                vrf=vr_name if vr_name != "default" else None,
                neighbors=neighbors,
                peer_groups=peer_groups,
                redistribute=redistribute,
                raw_lines=[raw_xml(bgp_el)],
            ))

        return bgp_list

    # ------------------------------------------------------------------
    # 3b. BGP import/export policy → RouteMapConfig (the policy nodes)
    # ------------------------------------------------------------------

    #: PAN-OS policy match elements → the normalized ``match_type``.  None of
    #: these names may collide with the Cisco vocabulary the dependency resolver
    #: treats as a REFERENCE ("as-path", "community", "prefix-list", "ip
    #: address"), because PAN-OS matches are INLINE values, not named objects —
    #: emitting them as references would manufacture dangling refs.  The
    #: ``-regex`` suffix is the resolver's signal for "inline pattern".
    _POLICY_TEXT_MATCHES = (
        ("as-path/regex", "as-path-regex"),
        ("community/regex", "community-regex"),
        ("extended-community/regex", "extended-community-regex"),
        ("med", "med"),
        ("route-table", "route-table"),
    )

    #: action/allow/update child → the normalized ``set_type``.
    _POLICY_TEXT_SETS = (
        ("local-preference", "local-preference"),
        ("med", "metric"),
        ("weight", "weight"),
        ("nexthop", "next-hop"),
        ("origin", "origin"),
        ("as-path-limit", "as-path-limit"),
    )

    def _policy_rule_to_route_map(self, rule: Element, direction: str) -> RouteMapConfig:
        """One PAN-OS BGP policy rule → one policy node, in the shared model.

        A graph consumer must not be able to tell which vendor produced a policy
        node, so a PAN-OS import/export rule becomes a ``RouteMapConfig`` with a
        single sequence, exactly as a Cisco ``route-map NAME permit 10`` does.
        """
        name = rule.get("name", "")
        # <action> is element-name-as-value: <allow>…</allow> or <deny/>.
        action_el = _choice(rule, "action")
        action = "deny" if action_el == "deny" else "permit"

        match_el = rule.find("match")
        matches: list[RouteMapMatch] = []
        if match_el is not None:
            prefixes = [
                e.get("name", "") for e in entries(match_el, "address-prefix")
                if e.get("name")
            ]
            if prefixes:
                matches.append(RouteMapMatch(
                    match_type="address-prefix", values=prefixes,
                ))
            from_peer = members(match_el, "from-peer")
            if from_peer:
                matches.append(RouteMapMatch(match_type="from-peer", values=from_peer))
            for path, match_type in self._POLICY_TEXT_MATCHES:
                val = text_val(match_el, path)
                if val:
                    matches.append(RouteMapMatch(match_type=match_type, values=[val]))

        sets: list[RouteMapSet] = []
        update_el = rule.find("action/allow/update")
        if update_el is not None:
            for path, set_type in self._POLICY_TEXT_SETS:
                val = text_val(update_el, path)
                if val:
                    sets.append(RouteMapSet(set_type=set_type, values=[val]))
            # as-path / community updates are element-name-as-value again:
            # <as-path><prepend>2</prepend></as-path>, <community><none/></community>.
            for path, set_type in (("as-path", "as-path"), ("community", "community")):
                op = _choice(update_el, path)
                if not op:
                    continue
                arg = text_val(update_el, f"{path}/{op}")
                sets.append(RouteMapSet(
                    set_type=set_type,
                    values=[op] + ([arg] if arg else []),
                ))

        return RouteMapConfig(
            object_id=f"policy_{direction}_{name}",
            source_os=self.os_type,
            name=name,
            sequences=[RouteMapSequence(
                sequence=10,
                action=action,
                match_clauses=matches,
                set_clauses=sets,
                description=f"panos bgp {direction} rule",
            )],
            raw_lines=[raw_xml(rule)],
        )

    def parse_route_maps(self) -> list[RouteMapConfig]:
        route_maps: list[RouteMapConfig] = []
        for vr in self._virtual_routers():
            bgp_el = vr.find("protocol/bgp")
            if bgp_el is None:
                continue
            for direction in ("import", "export"):
                for rule in entries(bgp_el, f"policy/{direction}/rules"):
                    if rule.get("name"):
                        route_maps.append(
                            self._policy_rule_to_route_map(rule, direction)
                        )
        return route_maps

    # ------------------------------------------------------------------
    # 4. OSPF
    # ------------------------------------------------------------------

    #: PAN-OS area <type> child element → normalized area type.
    _AREA_TYPES = {
        "normal": OSPFAreaType.NORMAL,
        "stub": OSPFAreaType.STUB,
        "nssa": OSPFAreaType.NSSA,
    }

    def _ospf_interface_attrs(self) -> dict[str, dict[str, object]]:
        """interface name → its OSPF attributes, read from inside the AREA.

        PAN-OS has no `ip ospf cost` on the interface object: an interface joins
        OSPF by being an ``<entry>`` INSIDE an area, and its cost is the
        ``<metric>`` on that entry (CCR-0035 #6).  parse_interfaces cannot find
        it by looking at ``network/interface`` — it has to come here.
        """
        attrs: dict[str, dict[str, object]] = {}
        for vr in self._virtual_routers():
            ospf_el = vr.find("protocol/ospf")
            if ospf_el is None:
                continue
            for area_el in entries(ospf_el, "area"):
                area_id = area_el.get("name", "")
                for iface_el in entries(area_el, "interface"):
                    name = iface_el.get("name", "")
                    if not name:
                        continue
                    attrs[name] = {
                        "area": area_id,
                        "cost": _safe_int(text_val(iface_el, "metric")),
                        "passive": text_val(iface_el, "passive") == "yes",
                    }
        return attrs

    def parse_ospf(self) -> list[OSPFConfig]:
        ospf_list: list[OSPFConfig] = []

        for vr in self._virtual_routers():
            vr_name = vr.get("name", "")
            ospf_el = vr.find("protocol/ospf")
            if ospf_el is None:
                continue
            if text_val(ospf_el, "enable") != "yes":
                continue

            router_id = _safe_addr(text_val(ospf_el, "router-id"))

            areas: list[OSPFArea] = []
            for area_el in entries(ospf_el, "area"):
                area_id = area_el.get("name", "0")
                area_ifaces: list[str] = []
                for iface_el in entries(area_el, "interface"):
                    iface_name = iface_el.get("name", "")
                    if iface_name:
                        area_ifaces.append(iface_name)

                # The area type is an ELEMENT NAME: <type><stub>…</stub></type>.
                # PAN-OS has no `no-summary` keyword — a stub/NSSA area whose
                # <accept-summary> is "no" IS the totally-stubby case, per the
                # vendor's own area doc (CCR-0035 #5).
                kind = _choice(area_el, "type")
                no_summary = (
                    text_val(area_el, f"type/{kind}/accept-summary") == "no"
                    if kind else False
                )
                area_type = self._AREA_TYPES.get(kind or "", OSPFAreaType.NORMAL)
                if no_summary and area_type is OSPFAreaType.STUB:
                    area_type = OSPFAreaType.TOTALLY_STUB
                elif no_summary and area_type is OSPFAreaType.NSSA:
                    area_type = OSPFAreaType.TOTALLY_NSSA

                # <default-route><advertise><metric>N — the cost of the default
                # route this ABR injects into the stub/NSSA area.
                default_cost = _safe_int(
                    text_val(area_el, f"type/{kind}/default-route/advertise/metric")
                ) if kind else None

                areas.append(OSPFArea(
                    area_id=area_id,
                    area_type=area_type,
                    stub_no_summary=(no_summary and kind == "stub"),
                    nssa_no_summary=(no_summary and kind == "nssa"),
                    default_cost=default_cost,
                    interfaces=area_ifaces,
                ))

            redistrib: list[OSPFRedistribute] = []
            profiles = self._redist_profiles(vr)
            for redist in entries(ospf_el, "export-rules"):
                # ext-1 / ext-2 → the E1/E2 metric type; the SOURCE protocol is
                # in the referenced redist-profile, exactly as for BGP.
                path_type = text_val(redist, "new-path-type")
                metric_type = 1 if path_type == "ext-1" else (2 if path_type == "ext-2" else None)
                for proto in profiles.get(redist.get("name", ""), []):
                    redistrib.append(OSPFRedistribute(
                        protocol=proto,
                        metric=_safe_int(text_val(redist, "metric")),
                        metric_type=metric_type,
                        tag=_safe_int(text_val(redist, "new-tag")),
                    ))

            ospf_list.append(OSPFConfig(
                object_id=f"ospf_1_{vr_name}",
                source_os=self.os_type,
                process_id=1,
                router_id=router_id,
                vrf=vr_name if vr_name != "default" else None,
                areas=areas,
                redistribute=redistrib,
                raw_lines=[raw_xml(ospf_el)],
            ))

        return ospf_list

    # ------------------------------------------------------------------
    # 5. Static routes
    # ------------------------------------------------------------------

    def parse_static_routes(self) -> list[StaticRoute]:
        routes: list[StaticRoute] = []

        for vr in self._virtual_routers():
            vr_name = vr.get("name", "")
            for route_el in entries(vr, "routing-table/ip/static-route"):
                dest_str = text_val(route_el, "destination")
                dest = _safe_net(dest_str)
                if dest is None:
                    continue

                nexthop_ip_str = text_val(route_el, "nexthop/ip-address")
                nexthop_iface = text_val(route_el, "interface")
                # PAN-OS carries administrative distance in <admin-dist> and the
                # route metric in <metric>; the two are distinct (CCR-0030 bug 3).
                admin_dist_str = text_val(route_el, "admin-dist")
                metric_str = text_val(route_el, "metric")
                try:
                    # PAN-OS default static-route administrative distance is 10.
                    distance = int(admin_dist_str) if admin_dist_str else 10
                except ValueError:
                    distance = 10
                metric = None
                if metric_str:
                    try:
                        metric = int(metric_str)
                    except ValueError:
                        metric = None

                nexthop: IPv4Address | str | None = None
                if nexthop_ip_str:
                    nexthop = _safe_addr(nexthop_ip_str)
                elif nexthop_iface:
                    nexthop = nexthop_iface

                routes.append(StaticRoute(
                    object_id=f"route_{dest}_{vr_name}",
                    source_os=self.os_type,
                    destination=dest,
                    next_hop=nexthop,
                    next_hop_interface=nexthop_iface,
                    distance=distance,
                    metric=metric,
                    vrf=vr_name if vr_name != "default" else None,
                    raw_lines=[raw_xml(route_el)],
                ))

        return routes

    # ------------------------------------------------------------------
    # 6. Security policies → ACLConfig
    # ------------------------------------------------------------------

    def _nat_rules(self) -> list[tuple[PolicyScope, Element]]:
        """Every NAT rule, with the policy scope it came from, in evaluation order."""
        rules: list[tuple[PolicyScope, Element]] = []
        for scope in self._policy_scopes():
            for rulebase in scope.rulebases:
                nat_el = rulebase.find("nat")
                if nat_el is None:
                    continue
                for rule in entries(nat_el, "rules"):
                    if rule.get("name"):
                        rules.append((scope, rule))
        return rules

    @staticmethod
    def _rule_match_remark(rule: Element) -> str:
        """The rule's match set (zones + addresses + service), as an ACL remark."""
        return (
            f"from:{','.join(members(rule, 'from'))} "
            f"to:{','.join(members(rule, 'to'))} "
            f"src:{','.join(members(rule, 'source'))} "
            f"dst:{','.join(members(rule, 'destination'))} "
            f"svc:{text_val(rule, 'service') or ''}"
        )

    def parse_acls(self) -> list[ACLConfig]:
        """One ACLConfig per policy scope (vsys locally, device-group under Panorama).

        A scope's rulebases arrive already ordered by the layout — locally the
        single vsys rulebase, under Panorama the resolved
        shared-pre → DG-pre → DG-post → shared-post chain — so ascending ACL
        sequence numbers carry the firewall's evaluation order.

        A source-NAT rule additionally gets an ACL of its own, holding the
        address set that rule translates.  ``NATDynamicEntry.acl`` must name the
        set of addresses being translated; a Cisco device names an ACL there, and
        PAN-OS carries the same information INLINE on the NAT rule.  Materializing
        it — with the same rulebase→ACLConfig mapping this parser already applies
        to security rules — is what lets source NAT enter the model at all
        (CCR-0035 #7) without the dangling ``nat → acl`` reference that made the
        previous author skip it.
        """
        acls: list[ACLConfig] = []
        for scope in self._policy_scopes():
            ace_entries: list[ACLEntry] = []
            raw_lines: list[str] = []
            seq = 10

            for rulebase in scope.rulebases:
                security_el = rulebase.find("security")
                if security_el is None:
                    continue
                raw_lines.append(raw_xml(security_el))

                for rule in entries(security_el, "rules"):
                    rule_name = rule.get("name", "")
                    action_str = text_val(rule, "action") or "allow"
                    action = "permit" if action_str == "allow" else "deny"

                    from_zones = members(rule, "from")
                    to_zones = members(rule, "to")
                    src_addrs = members(rule, "source")
                    dst_addrs = members(rule, "destination")
                    apps = members(rule, "application")

                    remark = (
                        f"rule:{rule_name} "
                        f"from:{','.join(from_zones)} to:{','.join(to_zones)} "
                        f"src:{','.join(src_addrs)} dst:{','.join(dst_addrs)} "
                        f"app:{','.join(apps)}"
                    )

                    ace_entries.append(ACLEntry(
                        sequence=seq,
                        action=action,
                        remark=remark,
                    ))
                    seq += 10

            if ace_entries:
                acls.append(ACLConfig(
                    object_id=f"acl_security_{scope.name}",
                    source_os=self.os_type,
                    name=f"security-policy-{scope.name}",
                    acl_type="extended",
                    entries=ace_entries,
                    raw_lines=raw_lines,
                ))

        # The address set each source-NAT rule translates (see docstring).
        for scope, rule in self._nat_rules():
            if rule.find("source-translation") is None:
                continue
            rule_name = rule.get("name", "")
            acls.append(ACLConfig(
                object_id=f"acl_nat_{scope.name}_{rule_name}",
                source_os=self.os_type,
                name=_nat_source_acl_name(rule_name),
                acl_type="extended",
                entries=[ACLEntry(
                    sequence=10,
                    action="permit",
                    remark=f"nat-rule:{rule_name} {self._rule_match_remark(rule)}",
                )],
                raw_lines=[raw_xml(rule)],
            ))

        return acls

    # ------------------------------------------------------------------
    # 7. NAT policies → NATConfig
    # ------------------------------------------------------------------

    def parse_nat(self) -> NATConfig | None:
        """Destination NAT → static entries; source / PAT NAT → dynamic entries.

        ``<source-translation>`` has three mutually exclusive branches, chosen by
        element name: ``dynamic-ip-and-port`` (PAT), ``dynamic-ip`` (1:1 dynamic,
        no ports) and ``static-ip``.  ``<translated-address>`` is a **member
        list** under the two dynamic branches and a **text node** under
        ``static-ip`` — one element name, two shapes.
        """
        static_entries: list[NATStaticEntry] = []
        dynamic_entries: list[NATDynamicEntry] = []

        for _scope, rule in self._nat_rules():
            rule_name = rule.get("name", "")
            dst_trans = rule.find("destination-translation")

            if dst_trans is not None:
                translated_ip = text_val(dst_trans, "translated-address")
                translated_port_str = text_val(dst_trans, "translated-port")
                dst_addrs = members(rule, "destination")
                dst_ip_str = dst_addrs[0] if dst_addrs else None

                if translated_ip and dst_ip_str:
                    local_ip = _safe_addr(dst_ip_str)
                    global_ip = _safe_addr(translated_ip)
                    if local_ip and global_ip:
                        translated_port = None
                        if translated_port_str and translated_port_str.isdigit():
                            translated_port = int(translated_port_str)
                        static_entries.append(NATStaticEntry(
                            local_ip=local_ip,
                            global_ip=global_ip,
                            local_port=translated_port,
                            direction="outside",
                        ))

            kind = _choice(rule, "source-translation")
            if kind is None:
                continue
            src = rule.find(f"source-translation/{kind}")
            acl_name = _nat_source_acl_name(rule_name)

            if kind == "static-ip":
                # Source static NAT: <translated-address> is a TEXT node here.
                translated = _safe_addr(text_val(src, "translated-address"))
                src_addrs = members(rule, "source")
                local_ip = _safe_addr(src_addrs[0]) if src_addrs else None
                if translated and local_ip:
                    static_entries.append(NATStaticEntry(
                        local_ip=local_ip,
                        global_ip=translated,
                        direction="inside",
                    ))
                continue

            # dynamic-ip-and-port (PAT) | dynamic-ip (no port overload)
            iface = text_val(src, "interface-address/interface")
            pool_members = members(src, "translated-address")
            dynamic_entries.append(NATDynamicEntry(
                direction="inside",
                acl=acl_name,
                pool=pool_members[0] if pool_members else None,
                interface=iface,
                overload=(kind == "dynamic-ip-and-port"),
            ))

        if not static_entries and not dynamic_entries:
            return None

        return NATConfig(
            object_id="nat",
            source_os=self.os_type,
            static_entries=static_entries,
            dynamic_entries=dynamic_entries,
        )

    # ------------------------------------------------------------------
    # 8. IPsec / IKE → CryptoConfig
    # ------------------------------------------------------------------

    def parse_crypto(self) -> CryptoConfig | None:
        ikev1_policies: list[IKEv1Policy] = []
        ikev2_proposals: list[IKEv2Proposal] = []
        ikev2_policies: list[IKEv2Policy] = []
        transform_sets: list[IPSecTransformSet] = []
        crypto_map_entries: list[CryptoMapEntry] = []

        priority = 10
        seq = 10
        for scope in self._device_scopes():
            net = scope.element.find("network")
            if net is None:
                continue

            # IKE crypto profiles → IKEv1 policies
            for profile in entries(net, "ike/crypto-profiles/ike-crypto-profiles"):
                enc_list = members(profile, "encryption")
                hash_list = members(profile, "hash")
                dh_group_list = members(profile, "dh-group")
                lifetime_str = text_val(profile, "lifetime/hours")
                lifetime = None
                if lifetime_str and lifetime_str.isdigit():
                    lifetime = int(lifetime_str) * 3600

                ikev1_policies.append(IKEv1Policy(
                    priority=priority,
                    encryption=enc_list[0] if enc_list else None,
                    hash=hash_list[0] if hash_list else None,
                    group=(
                        int(dh_group_list[0].replace("group", ""))
                        if dh_group_list and dh_group_list[0].replace("group", "").isdigit()
                        else None
                    ),
                    lifetime=lifetime,
                ))
                priority += 10

            # IPsec crypto profiles → transform sets
            for profile in entries(net, "ike/crypto-profiles/ipsec-crypto-profiles"):
                profile_name = profile.get("name", "")
                transforms = (
                    members(profile, "esp/encryption")
                    + members(profile, "esp/authentication")
                )
                transform_sets.append(IPSecTransformSet(
                    name=profile_name,
                    transforms=transforms,
                    mode="tunnel",
                ))

            # IKE gateways → crypto map entries
            for gw in entries(net, "ike/gateway"):
                peer_ip = _safe_addr(text_val(gw, "peer-address/ip"))
                crypto_profile = text_val(gw, "ike-crypto-profile")
                crypto_map_entries.append(CryptoMapEntry(
                    sequence=seq,
                    peer=peer_ip,
                    transform_sets=[crypto_profile] if crypto_profile else [],
                ))
                seq += 10

        if not ikev1_policies and not transform_sets and not crypto_map_entries:
            return None

        crypto_maps: list[CryptoMap] = []
        if crypto_map_entries:
            crypto_maps.append(CryptoMap(
                name="PANOS-IPSEC",
                entries=crypto_map_entries,
            ))

        return CryptoConfig(
            object_id="crypto",
            source_os=self.os_type,
            isakmp_policies=ikev1_policies,
            ikev2_proposals=ikev2_proposals,
            ikev2_policies=ikev2_policies,
            transform_sets=transform_sets,
            crypto_maps=crypto_maps,
        )

    # ------------------------------------------------------------------
    # 9. Security zones → PANOSZoneConfig
    # ------------------------------------------------------------------

    def parse_zones(self) -> list[PANOSZoneConfig]:
        zones: list[PANOSZoneConfig] = []
        for vsys in self._vsys_scopes():
            vs_name = vsys.name
            for zone_el in entries(vsys.element, "zone"):
                zone_name = zone_el.get("name", "")
                if not zone_name:
                    continue

                zone_type = "layer3"
                iface_names: list[str] = []
                net_el = zone_el.find("network")
                if net_el is not None:
                    for ztype in ("layer3", "layer2", "tap", "virtual-wire", "tunnel"):
                        mems = members(net_el, ztype)
                        if mems:
                            zone_type = ztype
                            iface_names = mems
                            break

                zones.append(PANOSZoneConfig(
                    object_id=f"zone_{zone_name}_{vs_name}",
                    source_os=self.os_type,
                    name=zone_name,
                    vsys=vs_name,
                    zone_type=zone_type,
                    interfaces=iface_names,
                    zone_protection_profile=text_val(zone_el, "network/zone-protection-profile"),
                    log_setting=text_val(zone_el, "log-setting"),
                    raw_lines=[raw_xml(zone_el)],
                ))

        return zones

    # ------------------------------------------------------------------
    # Stubs for unused abstract methods
    # ------------------------------------------------------------------

    def parse_prefix_lists(self):
        # PAN-OS has no named prefix-list object: BGP policy rules carry their
        # prefixes inline (match/address-prefix), which parse_route_maps keeps
        # on the policy node itself.
        return []
