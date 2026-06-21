"""Tests for EOS parser onboarding readiness (Phase 3).

Covers Gap 1 (interface CIDR IPv4), Gap 2 (BGP peer group two-word),
E1 (MLAG peer-address guard), and E2 (OSPF area without process ID)
from confgraph_eos_interface_cidr_and_peer_group.md and
confgraph_eos_parser_minor_findings.md.
"""

from ipaddress import IPv4Address, IPv4Interface

from confgraph.parsers.eos_parser import EOSParser


# ---------------------------------------------------------------------------
# Gap 1 — EOS interface IPv4 CIDR addresses
# ---------------------------------------------------------------------------


class TestEOSInterfaceCIDR:

    def _iface(self, config: str, name: str):
        ifaces = EOSParser(config).parse_interfaces()
        return next((i for i in ifaces if i.name == name), None)

    def test_cidr_primary_address_parsed(self):
        cfg = (
            "interface Ethernet1\n"
            " ip address 10.0.0.1/30\n"
        )
        iface = self._iface(cfg, "Ethernet1")
        assert iface is not None
        assert iface.ip_address == IPv4Interface("10.0.0.1/30")

    def test_cidr_loopback_address_parsed(self):
        cfg = (
            "interface Loopback0\n"
            " ip address 1.1.1.1/32\n"
        )
        iface = self._iface(cfg, "Loopback0")
        assert iface is not None
        assert iface.ip_address == IPv4Interface("1.1.1.1/32")

    def test_cidr_secondary_address_parsed(self):
        cfg = (
            "interface Ethernet1\n"
            " ip address 10.0.0.1/30\n"
            " ip address 10.0.1.1/24 secondary\n"
        )
        iface = self._iface(cfg, "Ethernet1")
        assert iface is not None
        assert iface.ip_address == IPv4Interface("10.0.0.1/30")
        assert len(iface.secondary_ips) == 1
        assert iface.secondary_ips[0] == IPv4Interface("10.0.1.1/24")

    def test_no_ip_address_returns_none(self):
        cfg = "interface Ethernet2\n no ip address\n"
        iface = self._iface(cfg, "Ethernet2")
        assert iface is not None
        assert iface.ip_address is None


# ---------------------------------------------------------------------------
# E2 — EOS OSPF area (no process ID)
# ---------------------------------------------------------------------------


class TestEOSOSPFArea:

    def _iface(self, config: str, name: str):
        ifaces = EOSParser(config).parse_interfaces()
        return next((i for i in ifaces if i.name == name), None)

    def test_ospf_area_without_process_id(self):
        cfg = (
            "interface Ethernet1\n"
            " ip address 10.0.0.1/30\n"
            " ip ospf area 0.0.0.0\n"
        )
        iface = self._iface(cfg, "Ethernet1")
        assert iface is not None
        assert iface.ospf_area == "0.0.0.0"

    def test_ospf_area_non_zero(self):
        cfg = (
            "interface Ethernet1\n"
            " ip address 10.0.0.1/30\n"
            " ip ospf area 0.0.0.1\n"
        )
        iface = self._iface(cfg, "Ethernet1")
        assert iface is not None
        assert iface.ospf_area == "0.0.0.1"

    def test_no_ospf_area_defaults_none(self):
        cfg = (
            "interface Ethernet1\n"
            " ip address 10.0.0.1/30\n"
        )
        iface = self._iface(cfg, "Ethernet1")
        assert iface is not None
        assert iface.ospf_area is None


# ---------------------------------------------------------------------------
# Gap 2 — EOS BGP "peer group" (two words)
# ---------------------------------------------------------------------------


class TestEOSBGPPeerGroup:

    def _bgp(self, config: str):
        pc = EOSParser(config).parse()
        assert pc.bgp_instances
        return pc.bgp_instances[0]

    def test_peer_group_definition_parsed(self):
        cfg = (
            "router bgp 65001\n"
            " neighbor LEAF peer group\n"
            " neighbor LEAF remote-as 65100\n"
        )
        bgp = self._bgp(cfg)
        pg_names = [pg.name for pg in bgp.peer_groups]
        assert "LEAF" in pg_names

    def test_peer_group_inherits_remote_as(self):
        cfg = (
            "router bgp 65001\n"
            " neighbor LEAF peer group\n"
            " neighbor LEAF remote-as 65100\n"
        )
        bgp = self._bgp(cfg)
        leaf_pg = next(pg for pg in bgp.peer_groups if pg.name == "LEAF")
        assert leaf_pg.remote_as == 65100

    def test_neighbor_with_peer_group_membership(self):
        cfg = (
            "router bgp 65001\n"
            " neighbor LEAF peer group\n"
            " neighbor LEAF remote-as 65100\n"
            " neighbor 10.0.0.2 peer group LEAF\n"
        )
        bgp = self._bgp(cfg)
        nbr_ips = [str(n.peer_ip) for n in bgp.neighbors]
        assert "10.0.0.2" in nbr_ips
        n = next(n for n in bgp.neighbors if str(n.peer_ip) == "10.0.0.2")
        assert n.peer_group == "LEAF"

    def test_inline_remote_as_neighbor_still_works(self):
        cfg = (
            "router bgp 65001\n"
            " neighbor 10.0.0.6 remote-as 65200\n"
        )
        bgp = self._bgp(cfg)
        nbr_ips = [str(n.peer_ip) for n in bgp.neighbors]
        assert "10.0.0.6" in nbr_ips
        n = next(n for n in bgp.neighbors if str(n.peer_ip) == "10.0.0.6")
        assert n.remote_as == 65200

    def test_mixed_peer_group_and_inline_neighbors(self):
        """Both EOS peer group and inline remote-as neighbors coexist."""
        cfg = (
            "router bgp 65001\n"
            " neighbor LEAF peer group\n"
            " neighbor LEAF remote-as 65100\n"
            " neighbor 10.0.0.2 peer group LEAF\n"
            " neighbor 10.0.0.6 remote-as 65200\n"
        )
        bgp = self._bgp(cfg)
        nbr_ips = sorted(str(n.peer_ip) for n in bgp.neighbors)
        assert nbr_ips == ["10.0.0.2", "10.0.0.6"]

    def test_peer_group_with_update_source(self):
        cfg = (
            "router bgp 65001\n"
            " neighbor SPINE peer group\n"
            " neighbor SPINE remote-as 65000\n"
            " neighbor SPINE update-source Loopback0\n"
            " neighbor 10.0.0.2 peer group SPINE\n"
        )
        bgp = self._bgp(cfg)
        pg = next(pg for pg in bgp.peer_groups if pg.name == "SPINE")
        assert pg.update_source == "Loopback0"


# ---------------------------------------------------------------------------
# E1 — MLAG peer-address guard
# ---------------------------------------------------------------------------


class TestEOSMLAGPeerAddressGuard:

    def test_malformed_peer_address_does_not_crash(self):
        cfg = (
            "mlag configuration\n"
            " domain-id MLAG\n"
            " peer-address INVALID\n"
            " peer-link Port-Channel1\n"
        )
        pc = EOSParser(cfg).parse()
        # Should not crash — VPC config may be None or have no peer address
        if pc.vpc:
            assert pc.vpc.peer_keepalive_destination is None

    def test_valid_peer_address_parsed(self):
        cfg = (
            "mlag configuration\n"
            " domain-id MLAG\n"
            " peer-address 10.0.0.2\n"
            " peer-link Port-Channel1\n"
        )
        pc = EOSParser(cfg).parse()
        assert pc.vpc is not None
        assert pc.vpc.peer_keepalive_destination == IPv4Address("10.0.0.2")
