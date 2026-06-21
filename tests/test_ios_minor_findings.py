"""Tests for IOS/IOS-XR parser minor findings fixes (Phase 2.5/2.6).

Covers M4, M5, M6, M8, M9, M10, M11, M13 from
confgraph_ios_parser_minor_findings.md and X3 from
confgraph_iosxr_parser_minor_findings.md.
"""

from ipaddress import IPv4Address

from confgraph.parsers.ios_parser import IOSParser


# ---------------------------------------------------------------------------
# M4 — BGP unguarded int() (ebgp-multihop, maximum-prefix)
# ---------------------------------------------------------------------------


class TestBGPUnguardedInt:

    def _neighbors(self, config: str):
        pc = IOSParser(config).parse()
        assert pc.bgp_instances
        return pc.bgp_instances[0].neighbors

    def test_malformed_ebgp_multihop_does_not_crash(self):
        cfg = (
            "router bgp 65000\n"
            " neighbor 10.0.0.1 remote-as 65001\n"
            " neighbor 10.0.0.1 ebgp-multihop INVALID\n"
        )
        neighbors = self._neighbors(cfg)
        assert len(neighbors) == 1
        assert neighbors[0].ebgp_multihop is None

    def test_malformed_maximum_prefix_does_not_crash(self):
        cfg = (
            "router bgp 65000\n"
            " neighbor 10.0.0.1 remote-as 65001\n"
            " neighbor 10.0.0.1 maximum-prefix BAD\n"
        )
        neighbors = self._neighbors(cfg)
        assert len(neighbors) == 1
        assert neighbors[0].maximum_prefix is None

    def test_valid_ebgp_multihop_still_works(self):
        cfg = (
            "router bgp 65000\n"
            " neighbor 10.0.0.1 remote-as 65001\n"
            " neighbor 10.0.0.1 ebgp-multihop 2\n"
        )
        neighbors = self._neighbors(cfg)
        assert neighbors[0].ebgp_multihop == 2

    def test_valid_maximum_prefix_still_works(self):
        cfg = (
            "router bgp 65000\n"
            " neighbor 10.0.0.1 remote-as 65001\n"
            " neighbor 10.0.0.1 maximum-prefix 1000\n"
        )
        neighbors = self._neighbors(cfg)
        assert neighbors[0].maximum_prefix == 1000


# ---------------------------------------------------------------------------
# M5 — Static route with interface + next-hop IP
# ---------------------------------------------------------------------------


class TestStaticRouteInterfaceAndNextHop:

    def _routes(self, config: str):
        return IOSParser(config).parse_static_routes()

    def test_interface_and_nexthop_both_captured(self):
        cfg = "ip route 10.0.0.0 255.255.255.0 GigabitEthernet0/1 192.168.1.1\n"
        routes = self._routes(cfg)
        assert len(routes) == 1
        r = routes[0]
        assert r.next_hop_interface == "GigabitEthernet0/1"
        assert r.next_hop == IPv4Address("192.168.1.1")

    def test_interface_and_nexthop_with_distance(self):
        cfg = "ip route 10.0.0.0 255.255.255.0 GigabitEthernet0/1 192.168.1.1 200\n"
        routes = self._routes(cfg)
        assert len(routes) == 1
        r = routes[0]
        assert r.next_hop_interface == "GigabitEthernet0/1"
        assert r.next_hop == IPv4Address("192.168.1.1")
        assert r.distance == 200

    def test_interface_only_still_works(self):
        cfg = "ip route 10.0.0.0 255.255.255.0 Null0\n"
        routes = self._routes(cfg)
        assert len(routes) == 1
        r = routes[0]
        assert r.next_hop_interface == "Null0"
        assert r.next_hop is None

    def test_nexthop_ip_only_still_works(self):
        cfg = "ip route 10.0.0.0 255.255.255.0 192.168.1.1\n"
        routes = self._routes(cfg)
        assert len(routes) == 1
        r = routes[0]
        assert r.next_hop == IPv4Address("192.168.1.1")
        assert r.next_hop_interface is None


# ---------------------------------------------------------------------------
# M6 — HSRP version
# ---------------------------------------------------------------------------


class TestHSRPVersion:

    def _hsrp_groups(self, config: str):
        ifaces = IOSParser(config).parse_interfaces()
        for iface in ifaces:
            if iface.hsrp_groups:
                return iface.hsrp_groups
        return []

    def test_standby_version_2_captured(self):
        cfg = (
            "interface GigabitEthernet0/1\n"
            " ip address 10.0.0.1 255.255.255.0\n"
            " standby version 2\n"
            " standby 1 ip 10.0.0.100\n"
            " standby 1 priority 110\n"
        )
        groups = self._hsrp_groups(cfg)
        assert len(groups) == 1
        assert groups[0].version == 2
        assert groups[0].priority == 110

    def test_no_version_defaults_to_none(self):
        cfg = (
            "interface GigabitEthernet0/1\n"
            " ip address 10.0.0.1 255.255.255.0\n"
            " standby 1 ip 10.0.0.100\n"
        )
        groups = self._hsrp_groups(cfg)
        assert len(groups) == 1
        assert groups[0].version is None

    def test_version_applies_to_all_groups(self):
        cfg = (
            "interface GigabitEthernet0/1\n"
            " ip address 10.0.0.1 255.255.255.0\n"
            " standby version 2\n"
            " standby 1 ip 10.0.0.100\n"
            " standby 2 ip 10.0.0.200\n"
        )
        groups = self._hsrp_groups(cfg)
        assert len(groups) == 2
        assert all(g.version == 2 for g in groups)


# ---------------------------------------------------------------------------
# M8 — Legacy TACACS/RADIUS name collision
# ---------------------------------------------------------------------------


class TestLegacyServerNameCollision:

    def _parse_aaa(self, config: str):
        return IOSParser(config).parse_aaa()

    def test_legacy_tacacs_servers_have_unique_names(self):
        cfg = (
            "aaa new-model\n"
            "tacacs-server host 10.0.0.1 key Secret1\n"
            "tacacs-server host 10.0.0.2 key Secret2\n"
        )
        aaa = self._parse_aaa(cfg)
        assert aaa is not None
        assert len(aaa.tacacs_servers) == 2
        names = [s.name for s in aaa.tacacs_servers]
        assert names[0] == "10.0.0.1"
        assert names[1] == "10.0.0.2"
        assert len(set(names)) == 2  # all unique

    def test_legacy_radius_servers_have_unique_names(self):
        cfg = (
            "aaa new-model\n"
            "radius-server host 10.0.0.1 key Secret1\n"
            "radius-server host 10.0.0.2 key Secret2\n"
        )
        aaa = self._parse_aaa(cfg)
        assert aaa is not None
        assert len(aaa.radius_servers) == 2
        names = [s.name for s in aaa.radius_servers]
        assert names[0] == "10.0.0.1"
        assert names[1] == "10.0.0.2"
        assert len(set(names)) == 2

    def test_named_tacacs_server_keeps_block_name(self):
        """Named servers must still use their block name, not address."""
        cfg = (
            "aaa new-model\n"
            "tacacs server CORP\n"
            " address ipv4 10.0.0.1\n"
            " key Secret\n"
        )
        aaa = self._parse_aaa(cfg)
        assert aaa is not None
        assert len(aaa.tacacs_servers) == 1
        assert aaa.tacacs_servers[0].name == "CORP"


# ---------------------------------------------------------------------------
# M9 — DNS VRF prefix incorrectly included as name-server
# ---------------------------------------------------------------------------


class TestDNSVrfPrefix:

    def _parse_dns(self, config: str):
        return IOSParser(config).parse_dns()

    def test_vrf_prefix_stripped_from_nameservers(self):
        cfg = "ip name-server vrf MGMT 8.8.8.8 8.8.4.4\n"
        dns = self._parse_dns(cfg)
        assert dns is not None
        assert "vrf" not in dns.name_servers
        assert "MGMT" not in dns.name_servers
        assert "8.8.8.8" in dns.name_servers
        assert "8.8.4.4" in dns.name_servers

    def test_no_vrf_still_works(self):
        cfg = "ip name-server 8.8.8.8 1.1.1.1\n"
        dns = self._parse_dns(cfg)
        assert dns is not None
        assert dns.name_servers == ["8.8.8.8", "1.1.1.1"]


# ---------------------------------------------------------------------------
# M10 — IS-IS redistribute process_id grabs wrong digit
# ---------------------------------------------------------------------------


class TestISISRedistributeProcessId:

    def _isis_redistribute(self, config: str):
        instances = IOSParser(config).parse_isis()
        assert instances
        return instances[0].redistribute

    def test_connected_metric_not_read_as_process_id(self):
        cfg = (
            "router isis CORE\n"
            " redistribute connected metric 20\n"
        )
        redist = self._isis_redistribute(cfg)
        assert len(redist) == 1
        assert redist[0].protocol == "connected"
        assert redist[0].process_id is None
        assert redist[0].metric == 20

    def test_ospf_process_id_still_captured(self):
        cfg = (
            "router isis CORE\n"
            " redistribute ospf 1 metric 10\n"
        )
        redist = self._isis_redistribute(cfg)
        assert len(redist) == 1
        assert redist[0].protocol == "ospf"
        assert redist[0].process_id == 1
        assert redist[0].metric == 10

    def test_static_no_process_id(self):
        cfg = (
            "router isis CORE\n"
            " redistribute static route-map RM1\n"
        )
        redist = self._isis_redistribute(cfg)
        assert len(redist) == 1
        assert redist[0].protocol == "static"
        assert redist[0].process_id is None
        assert redist[0].route_map == "RM1"


# ---------------------------------------------------------------------------
# M11 — IS-IS redistribute level-1-2 mis-detected as level-1
# ---------------------------------------------------------------------------


class TestISISRedistributeLevel:

    def _isis_redistribute(self, config: str):
        instances = IOSParser(config).parse_isis()
        assert instances
        return instances[0].redistribute

    def test_level_1_2_detected_correctly(self):
        cfg = (
            "router isis CORE\n"
            " redistribute connected level-1-2\n"
        )
        redist = self._isis_redistribute(cfg)
        assert len(redist) == 1
        assert redist[0].level == "level-1-2"

    def test_level_1_still_works(self):
        cfg = (
            "router isis CORE\n"
            " redistribute connected level-1\n"
        )
        redist = self._isis_redistribute(cfg)
        assert len(redist) == 1
        assert redist[0].level == "level-1"

    def test_level_2_still_works(self):
        cfg = (
            "router isis CORE\n"
            " redistribute connected level-2\n"
        )
        redist = self._isis_redistribute(cfg)
        assert len(redist) == 1
        assert redist[0].level == "level-2"


# ---------------------------------------------------------------------------
# M13 — Primary IP regex anchor (secondary not mistaken for primary)
# ---------------------------------------------------------------------------


class TestPrimaryIPAnchor:

    def _iface(self, config: str, name: str):
        ifaces = IOSParser(config).parse_interfaces()
        for iface in ifaces:
            if iface.name == name:
                return iface
        return None

    def test_secondary_before_primary_still_gets_correct_primary(self):
        """Even if secondary appears first in config, primary is identified correctly."""
        cfg = (
            "interface GigabitEthernet0/1\n"
            " ip address 10.0.1.1 255.255.255.0 secondary\n"
            " ip address 10.0.0.1 255.255.255.0\n"
        )
        iface = self._iface(cfg, "GigabitEthernet0/1")
        assert iface is not None
        assert str(iface.ip_address.ip) == "10.0.0.1"

    def test_normal_order_primary_then_secondary(self):
        cfg = (
            "interface GigabitEthernet0/1\n"
            " ip address 10.0.0.1 255.255.255.0\n"
            " ip address 10.0.1.1 255.255.255.0 secondary\n"
        )
        iface = self._iface(cfg, "GigabitEthernet0/1")
        assert iface is not None
        assert str(iface.ip_address.ip) == "10.0.0.1"
        assert len(iface.secondary_ips) == 1


# ---------------------------------------------------------------------------
# X3 — IOS-XR LLDP/CDP enable detection (bare lldp / cdp)
# ---------------------------------------------------------------------------


class TestXRLLDPCDPEnable:

    def test_bare_lldp_detected_as_enabled(self):
        dns = IOSParser("lldp\n").parse_lldp()
        assert dns is not None
        assert dns.enabled is True

    def test_no_lldp_disables(self):
        dns = IOSParser("no lldp\n").parse_lldp()
        assert dns is not None
        assert dns.enabled is False

    def test_ios_lldp_run_still_works(self):
        dns = IOSParser("lldp run\n").parse_lldp()
        assert dns is not None
        assert dns.enabled is True

    def test_ios_no_lldp_run_still_works(self):
        dns = IOSParser("no lldp run\n").parse_lldp()
        assert dns is not None
        assert dns.enabled is False

    def test_bare_cdp_detected_as_enabled(self):
        cdp = IOSParser("cdp\n").parse_cdp()
        assert cdp is not None
        assert cdp.enabled is True

    def test_no_cdp_disables(self):
        cdp = IOSParser("no cdp\n").parse_cdp()
        assert cdp is not None
        assert cdp.enabled is False

    def test_ios_cdp_run_still_works(self):
        cdp = IOSParser("cdp run\n").parse_cdp()
        assert cdp is not None
        assert cdp.enabled is True
