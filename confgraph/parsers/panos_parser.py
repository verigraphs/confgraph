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
"""

from __future__ import annotations

from ipaddress import IPv4Interface, IPv4Network, IPv4Address, IPv6Interface
from xml.etree.ElementTree import Element

from confgraph.models.base import OSType, UnrecognizedBlock
from confgraph.models.interface import InterfaceConfig, InterfaceType
from confgraph.models.vrf import VRFConfig
from confgraph.models.bgp import (
    BGPConfig, BGPNeighbor, BGPRedistribute,
)
from confgraph.models.ospf import OSPFConfig, OSPFArea, OSPFRedistribute
from confgraph.models.static_route import StaticRoute
from confgraph.models.acl import ACLConfig, ACLEntry
from confgraph.models.nat import NATConfig, NATStaticEntry
from confgraph.models.crypto import (
    CryptoConfig, IKEv1Policy, IKEv2Proposal, IKEv2Policy,
    IPSecTransformSet, CryptoMapEntry, CryptoMap,
)
from confgraph.models.panos_zone import PANOSZoneConfig

from confgraph.parsers.base import BaseParser
from confgraph.parsers.panos_xml import (
    parse_panos_xml, find_device, find_vsys, find_all_vsys,
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
        self._device_el: Element | None = None
        # zone_name → interface_name  (populated lazily)
        self._zone_of_iface: dict[str, str] = {}

    # ------------------------------------------------------------------
    # XML root access (lazy)
    # ------------------------------------------------------------------

    def _get_root(self) -> Element:
        if self._root is None:
            self._root = parse_panos_xml(self.config_text)
        return self._root

    def _get_device(self) -> Element | None:
        if self._device_el is None:
            self._device_el = find_device(self._get_root())
        return self._device_el

    def _all_vsys(self) -> list[Element]:
        dev = self._get_device()
        if dev is None:
            return []
        return find_all_vsys(dev)

    # ------------------------------------------------------------------
    # BaseParser overrides (avoid CiscoConfParse)
    # ------------------------------------------------------------------

    def _extract_hostname(self) -> str | None:
        dev = self._get_device()
        if dev is None:
            return None
        return text_val(dev, "deviceconfig/system/hostname")

    def _collect_unrecognized_blocks(self) -> list[UnrecognizedBlock]:
        # PAN-OS XML has a flat, well-known structure — nothing to collect here
        return []

    # ------------------------------------------------------------------
    # 1. VRFs  (Virtual Routers)
    # ------------------------------------------------------------------

    def parse_vrfs(self) -> list[VRFConfig]:
        dev = self._get_device()
        if dev is None:
            return []
        vrfs: list[VRFConfig] = []
        for vr in entries(dev, "network/virtual-router"):
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
        dev = self._get_device()
        if dev is None:
            return []

        # Build zone_of_iface map
        zone_of_iface: dict[str, str] = {}
        for vs in self._all_vsys():
            for zone_el in entries(vs, "zone"):
                zone_name = zone_el.get("name", "")
                net_el = zone_el.find("network")
                if net_el is not None:
                    for ztype in ("layer3", "layer2", "tap", "virtual-wire", "tunnel"):
                        for m in members(net_el, ztype):
                            zone_of_iface[m] = zone_name
        self._zone_of_iface = zone_of_iface

        # Build vr_of_iface map
        vr_of_iface: dict[str, str] = {}
        for vr in entries(dev, "network/virtual-router"):
            vr_name = vr.get("name", "")
            for m in members(vr, "interface"):
                vr_of_iface[m] = vr_name

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
                raw_lines=[raw_xml(el)],
            )

        net = dev.find("network")
        if net is None:
            return ifaces

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

    def parse_bgp(self) -> list[BGPConfig]:
        dev = self._get_device()
        if dev is None:
            return []
        bgp_list: list[BGPConfig] = []

        for vr in entries(dev, "network/virtual-router"):
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

            neighbors: list[BGPNeighbor] = []
            # Peers live inside peer-group entries
            pg_container = bgp_el.find("peer-group")
            if pg_container is not None:
                for pg in (pg_container.findall("entry") or []):
                    for peer in entries(pg, "peer"):
                        peer_ip_str = text_val(peer, "peer-address/ip")
                        remote_as_str = text_val(peer, "connection-options/remote-as")
                        if not peer_ip_str or not remote_as_str:
                            continue
                        peer_ip = _safe_addr(peer_ip_str)
                        if peer_ip is None:
                            continue
                        try:
                            remote_as = int(remote_as_str)
                        except ValueError:
                            remote_as = remote_as_str  # type: ignore[assignment]
                        shutdown = (text_val(peer, "enable") == "no")
                        update_source = text_val(peer, "local-address/interface")
                        neighbors.append(BGPNeighbor(
                            peer_ip=peer_ip,
                            remote_as=remote_as,
                            description=peer.get("name", ""),
                            shutdown=shutdown,
                            update_source=update_source,
                        ))

            redistribute: list[BGPRedistribute] = []
            for redist in entries(bgp_el, "redistribution-rules"):
                proto = text_val(redist, "address-family-identifier")
                if proto:
                    redistribute.append(BGPRedistribute(protocol=proto))

            bgp_list.append(BGPConfig(
                object_id=f"bgp_{local_as}_{vr_name}",
                source_os=self.os_type,
                asn=local_as,
                router_id=router_id,
                vrf=vr_name if vr_name != "default" else None,
                neighbors=neighbors,
                redistribute=redistribute,
                raw_lines=[raw_xml(bgp_el)],
            ))

        return bgp_list

    # ------------------------------------------------------------------
    # 4. OSPF
    # ------------------------------------------------------------------

    def parse_ospf(self) -> list[OSPFConfig]:
        dev = self._get_device()
        if dev is None:
            return []
        ospf_list: list[OSPFConfig] = []

        for vr in entries(dev, "network/virtual-router"):
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
                areas.append(OSPFArea(
                    area_id=area_id,
                    interfaces=area_ifaces,
                ))

            redistrib: list[OSPFRedistribute] = []
            for redist in entries(ospf_el, "export-rules"):
                name = redist.get("name", "")
                if name:
                    redistrib.append(OSPFRedistribute(protocol=name))

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
        dev = self._get_device()
        if dev is None:
            return []
        routes: list[StaticRoute] = []

        for vr in entries(dev, "network/virtual-router"):
            vr_name = vr.get("name", "")
            for route_el in entries(vr, "routing-table/ip/static-route"):
                dest_str = text_val(route_el, "destination")
                dest = _safe_net(dest_str)
                if dest is None:
                    continue

                nexthop_ip_str = text_val(route_el, "nexthop/ip-address")
                nexthop_iface = text_val(route_el, "interface")
                metric_str = text_val(route_el, "metric")
                try:
                    distance = int(metric_str) if metric_str else 1
                except ValueError:
                    distance = 1

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
                    vrf=vr_name if vr_name != "default" else None,
                    raw_lines=[raw_xml(route_el)],
                ))

        return routes

    # ------------------------------------------------------------------
    # 6. Security policies → ACLConfig
    # ------------------------------------------------------------------

    def parse_acls(self) -> list[ACLConfig]:
        acls: list[ACLConfig] = []
        for vs in self._all_vsys():
            vs_name = vs.get("name", "vsys1")
            rulebase = vs.find("rulebase")
            if rulebase is None:
                continue
            security_el = rulebase.find("security")
            if security_el is None:
                continue

            ace_entries: list[ACLEntry] = []
            seq = 10
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
                    object_id=f"acl_security_{vs_name}",
                    source_os=self.os_type,
                    name=f"security-policy-{vs_name}",
                    acl_type="extended",
                    entries=ace_entries,
                    raw_lines=[raw_xml(security_el)],
                ))

        return acls

    # ------------------------------------------------------------------
    # 7. NAT policies → NATConfig
    # ------------------------------------------------------------------

    def parse_nat(self) -> NATConfig | None:
        static_entries: list[NATStaticEntry] = []
        dynamic_entries: list[NATDynamicEntry] = []

        for vs in self._all_vsys():
            rulebase = vs.find("rulebase")
            if rulebase is None:
                continue
            nat_el = rulebase.find("nat")
            if nat_el is None:
                continue

            for rule in entries(nat_el, "rules"):
                rule_name = rule.get("name", "")
                dst_trans = rule.find("destination-translation")
                src_trans = rule.find("source-translation")

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

                # PAN-OS source NAT (dynamic PAT) — no external ACL reference in PAN-OS;
                # source addresses are defined inline in the NAT rule.
                # We skip NATDynamicEntry to avoid false dangling refs.

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
        dev = self._get_device()
        if dev is None:
            return None

        net = dev.find("network")
        if net is None:
            return None

        ikev1_policies: list[IKEv1Policy] = []
        ikev2_proposals: list[IKEv2Proposal] = []
        ikev2_policies: list[IKEv2Policy] = []
        transform_sets: list[IPSecTransformSet] = []
        crypto_map_entries: list[CryptoMapEntry] = []

        priority = 10
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
            transforms = members(profile, "esp/encryption") + members(profile, "esp/authentication")
            transform_sets.append(IPSecTransformSet(
                name=profile_name,
                transforms=transforms,
                mode="tunnel",
            ))

        # IKE gateways → crypto map entries
        seq = 10
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
        for vs in self._all_vsys():
            vs_name = vs.get("name", "vsys1")
            for zone_el in entries(vs, "zone"):
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

    def parse_route_maps(self):
        return []

    def parse_prefix_lists(self):
        return []
