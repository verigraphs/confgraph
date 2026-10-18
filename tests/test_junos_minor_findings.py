"""Tests for JunOS parser minor findings (CCR items J7, J9, J13–J16, 1b).

Each test class corresponds to one CCR item with brace-style and set-style
variants where applicable.
"""

from confgraph.parsers.junos_parser import JunOSParser


# ---------------------------------------------------------------------------
# J13 — Interface disable; → enabled=False
# ---------------------------------------------------------------------------


class TestJ13InterfaceDisable:

    def test_interface_level_disable(self):
        """Interface-level ``disable;`` sets enabled=False on all units."""
        cfg = (
            "interfaces {\n"
            "    ge-0/0/0 {\n"
            "        disable;\n"
            "        unit 0 {\n"
            "            family inet {\n"
            "                address 10.0.0.1/30;\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        pc = JunOSParser(cfg).parse()
        intf = next(i for i in pc.interfaces if i.name == "ge-0/0/0.0")
        assert intf.enabled is False

    def test_unit_level_disable(self):
        """Unit-level ``disable;`` sets enabled=False for that unit only."""
        cfg = (
            "interfaces {\n"
            "    ge-0/0/0 {\n"
            "        unit 0 {\n"
            "            disable;\n"
            "            family inet {\n"
            "                address 10.0.0.1/30;\n"
            "            }\n"
            "        }\n"
            "        unit 1 {\n"
            "            family inet {\n"
            "                address 10.0.1.1/30;\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        pc = JunOSParser(cfg).parse()
        u0 = next(i for i in pc.interfaces if i.name == "ge-0/0/0.0")
        u1 = next(i for i in pc.interfaces if i.name == "ge-0/0/0.1")
        assert u0.enabled is False
        assert u1.enabled is True

    def test_enabled_true_default(self):
        """Without ``disable;``, enabled defaults to True."""
        cfg = (
            "interfaces {\n"
            "    ge-0/0/0 {\n"
            "        unit 0 {\n"
            "            family inet {\n"
            "                address 10.0.0.1/30;\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        pc = JunOSParser(cfg).parse()
        intf = next(i for i in pc.interfaces if i.name == "ge-0/0/0.0")
        assert intf.enabled is True

    def test_set_style_disable(self):
        cfg = (
            "set interfaces ge-0/0/0 disable\n"
            "set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/30\n"
        )
        pc = JunOSParser(cfg).parse()
        intf = next(i for i in pc.interfaces if i.name == "ge-0/0/0.0")
        assert intf.enabled is False


# ---------------------------------------------------------------------------
# J14 — IPv6 BGP neighbors kept (not discarded)
# ---------------------------------------------------------------------------


class TestJ14IPv6BGPNeighbors:

    def test_ipv6_neighbor_parsed(self):
        cfg = (
            "routing-options {\n"
            "    autonomous-system 65001;\n"
            "}\n"
            "protocols {\n"
            "    bgp {\n"
            "        group EBGP6 {\n"
            "            neighbor 2001:db8::1 {\n"
            "                peer-as 65002;\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        pc = JunOSParser(cfg).parse()
        assert pc.bgp_instances
        nbr_ips = [str(n.peer_ip) for n in pc.bgp_instances[0].neighbors]
        assert "2001:db8::1" in nbr_ips

    def test_ipv6_neighbor_afi(self):
        """IPv6 neighbor gets afi='ipv6'."""
        cfg = (
            "routing-options {\n"
            "    autonomous-system 65001;\n"
            "}\n"
            "protocols {\n"
            "    bgp {\n"
            "        group EBGP6 {\n"
            "            neighbor 2001:db8::1 {\n"
            "                peer-as 65002;\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        pc = JunOSParser(cfg).parse()
        nbr = next(n for n in pc.bgp_instances[0].neighbors if str(n.peer_ip) == "2001:db8::1")
        assert nbr.address_families[0].afi == "ipv6"

    def test_mixed_v4_v6_neighbors(self):
        cfg = (
            "routing-options {\n"
            "    autonomous-system 65001;\n"
            "}\n"
            "protocols {\n"
            "    bgp {\n"
            "        group MIXED {\n"
            "            neighbor 10.0.0.1 {\n"
            "                peer-as 65002;\n"
            "            }\n"
            "            neighbor 2001:db8::1 {\n"
            "                peer-as 65003;\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        pc = JunOSParser(cfg).parse()
        nbr_ips = sorted(str(n.peer_ip) for n in pc.bgp_instances[0].neighbors)
        assert "10.0.0.1" in nbr_ips
        assert "2001:db8::1" in nbr_ips


# ---------------------------------------------------------------------------
# J7 — OSPF interface sub-attributes and area-type
# ---------------------------------------------------------------------------


class TestJ7OSPFInterfaceAttrs:

    def test_ospf_passive(self):
        cfg = (
            "protocols {\n"
            "    ospf {\n"
            "        area 0.0.0.0 {\n"
            "            interface ge-0/0/0.0 {\n"
            "                passive;\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}\n"
            "interfaces {\n"
            "    ge-0/0/0 {\n"
            "        unit 0 {\n"
            "            family inet {\n"
            "                address 10.0.0.1/30;\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        pc = JunOSParser(cfg).parse()
        intf = next(i for i in pc.interfaces if i.name == "ge-0/0/0.0")
        assert intf.ospf_passive is True
        # CCR-0227: area IDs are stored canonical (decimal); the config
        # still spells it as the vendor does.
        assert intf.ospf_area == "0"
        # Also verify passive_interfaces on the OSPF instance
        assert "ge-0/0/0.0" in pc.ospf_instances[0].passive_interfaces

    def test_ospf_metric(self):
        cfg = (
            "protocols {\n"
            "    ospf {\n"
            "        area 0.0.0.0 {\n"
            "            interface ge-0/0/0.0 {\n"
            "                metric 100;\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}\n"
            "interfaces {\n"
            "    ge-0/0/0 {\n"
            "        unit 0 {\n"
            "            family inet {\n"
            "                address 10.0.0.1/30;\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        pc = JunOSParser(cfg).parse()
        intf = next(i for i in pc.interfaces if i.name == "ge-0/0/0.0")
        assert intf.ospf_cost == 100

    def test_ospf_hello_dead_intervals(self):
        cfg = (
            "protocols {\n"
            "    ospf {\n"
            "        area 0.0.0.0 {\n"
            "            interface ge-0/0/0.0 {\n"
            "                hello-interval 5;\n"
            "                dead-interval 20;\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}\n"
            "interfaces {\n"
            "    ge-0/0/0 {\n"
            "        unit 0 {\n"
            "            family inet {\n"
            "                address 10.0.0.1/30;\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        pc = JunOSParser(cfg).parse()
        intf = next(i for i in pc.interfaces if i.name == "ge-0/0/0.0")
        assert intf.ospf_hello_interval == 5
        assert intf.ospf_dead_interval == 20

    def test_ospf_network_type_p2p(self):
        cfg = (
            "protocols {\n"
            "    ospf {\n"
            "        area 0.0.0.0 {\n"
            "            interface ge-0/0/0.0 {\n"
            "                interface-type p2p;\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}\n"
            "interfaces {\n"
            "    ge-0/0/0 {\n"
            "        unit 0 {\n"
            "            family inet {\n"
            "                address 10.0.0.1/30;\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        pc = JunOSParser(cfg).parse()
        intf = next(i for i in pc.interfaces if i.name == "ge-0/0/0.0")
        assert intf.ospf_network_type == "p2p"

    def test_ospf_authentication_md5(self):
        cfg = (
            "protocols {\n"
            "    ospf {\n"
            "        area 0.0.0.0 {\n"
            "            interface ge-0/0/0.0 {\n"
            "                authentication {\n"
            "                    md5 1 key secret;\n"
            "                }\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}\n"
            "interfaces {\n"
            "    ge-0/0/0 {\n"
            "        unit 0 {\n"
            "            family inet {\n"
            "                address 10.0.0.1/30;\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        pc = JunOSParser(cfg).parse()
        intf = next(i for i in pc.interfaces if i.name == "ge-0/0/0.0")
        assert intf.ospf_authentication == "message-digest"


class TestJ7OSPFAreaType:

    def test_stub_area(self):
        cfg = (
            "protocols {\n"
            "    ospf {\n"
            "        area 0.0.0.1 {\n"
            "            stub;\n"
            "            interface ge-0/0/0.0;\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        pc = JunOSParser(cfg).parse()
        area = pc.ospf_instances[0].areas[0]
        assert area.area_type == "stub"

    def test_totally_stub_area(self):
        cfg = (
            "protocols {\n"
            "    ospf {\n"
            "        area 0.0.0.1 {\n"
            "            stub {\n"
            "                no-summaries;\n"
            "            }\n"
            "            interface ge-0/0/0.0;\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        pc = JunOSParser(cfg).parse()
        area = pc.ospf_instances[0].areas[0]
        assert area.area_type == "totally_stub"
        assert area.stub_no_summary is True

    def test_nssa_area(self):
        cfg = (
            "protocols {\n"
            "    ospf {\n"
            "        area 0.0.0.2 {\n"
            "            nssa;\n"
            "            interface ge-0/0/0.0;\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        pc = JunOSParser(cfg).parse()
        area = pc.ospf_instances[0].areas[0]
        assert area.area_type == "nssa"

    def test_totally_nssa_area(self):
        cfg = (
            "protocols {\n"
            "    ospf {\n"
            "        area 0.0.0.2 {\n"
            "            nssa {\n"
            "                no-summaries;\n"
            "            }\n"
            "            interface ge-0/0/0.0;\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        pc = JunOSParser(cfg).parse()
        area = pc.ospf_instances[0].areas[0]
        assert area.area_type == "totally_nssa"
        assert area.nssa_no_summary is True

    def test_normal_area_default(self):
        cfg = (
            "protocols {\n"
            "    ospf {\n"
            "        area 0.0.0.0 {\n"
            "            interface ge-0/0/0.0;\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        pc = JunOSParser(cfg).parse()
        area = pc.ospf_instances[0].areas[0]
        assert area.area_type == "normal"

    def test_router_id_parsed(self):
        cfg = (
            "protocols {\n"
            "    ospf {\n"
            "        router-id 1.1.1.1;\n"
            "        area 0.0.0.0 {\n"
            "            interface ge-0/0/0.0;\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        pc = JunOSParser(cfg).parse()
        assert str(pc.ospf_instances[0].router_id) == "1.1.1.1"


# ---------------------------------------------------------------------------
# J15 — BGP authentication-key → password
# ---------------------------------------------------------------------------


class TestJ15BGPAuthKey:

    def test_neighbor_authentication_key(self):
        cfg = (
            "routing-options {\n"
            "    autonomous-system 65001;\n"
            "}\n"
            "protocols {\n"
            "    bgp {\n"
            "        group EBGP {\n"
            "            neighbor 10.0.0.1 {\n"
            "                peer-as 65002;\n"
            "                authentication-key s3cret;\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        pc = JunOSParser(cfg).parse()
        nbr = pc.bgp_instances[0].neighbors[0]
        assert nbr.password == "s3cret"

    def test_group_authentication_key_inherited(self):
        """Group-level authentication-key inherited by neighbor without one."""
        cfg = (
            "routing-options {\n"
            "    autonomous-system 65001;\n"
            "}\n"
            "protocols {\n"
            "    bgp {\n"
            "        group EBGP {\n"
            "            authentication-key grp_pass;\n"
            "            neighbor 10.0.0.1 {\n"
            "                peer-as 65002;\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        pc = JunOSParser(cfg).parse()
        nbr = pc.bgp_instances[0].neighbors[0]
        assert nbr.password == "grp_pass"

    def test_no_auth_key_default(self):
        cfg = (
            "routing-options {\n"
            "    autonomous-system 65001;\n"
            "}\n"
            "protocols {\n"
            "    bgp {\n"
            "        group EBGP {\n"
            "            neighbor 10.0.0.1 {\n"
            "                peer-as 65002;\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        pc = JunOSParser(cfg).parse()
        nbr = pc.bgp_instances[0].neighbors[0]
        assert nbr.password is None


# ---------------------------------------------------------------------------
# J16 — Interface MTU extraction
# ---------------------------------------------------------------------------


class TestJ16InterfaceMTU:

    def test_mtu_parsed(self):
        cfg = (
            "interfaces {\n"
            "    ge-0/0/0 {\n"
            "        mtu 9000;\n"
            "        unit 0 {\n"
            "            family inet {\n"
            "                address 10.0.0.1/30;\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        pc = JunOSParser(cfg).parse()
        intf = next(i for i in pc.interfaces if i.name == "ge-0/0/0.0")
        assert intf.mtu == 9000

    def test_mtu_default_none(self):
        cfg = (
            "interfaces {\n"
            "    ge-0/0/0 {\n"
            "        unit 0 {\n"
            "            family inet {\n"
            "                address 10.0.0.1/30;\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        pc = JunOSParser(cfg).parse()
        intf = next(i for i in pc.interfaces if i.name == "ge-0/0/0.0")
        assert intf.mtu is None

    def test_set_style_mtu(self):
        cfg = (
            "set interfaces ge-0/0/0 mtu 1500\n"
            "set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/30\n"
        )
        pc = JunOSParser(cfg).parse()
        intf = next(i for i in pc.interfaces if i.name == "ge-0/0/0.0")
        assert intf.mtu == 1500


# ---------------------------------------------------------------------------
# J9 — iBGP remote_as resolved to device ASN (not "internal")
# ---------------------------------------------------------------------------


class TestJ9IBGPRemoteAS:

    def test_ibgp_remote_as_is_device_asn(self):
        """iBGP neighbors get device's own ASN, not string 'internal'."""
        cfg = (
            "routing-options {\n"
            "    autonomous-system 65001;\n"
            "}\n"
            "protocols {\n"
            "    bgp {\n"
            "        group IBGP {\n"
            "            type internal;\n"
            "            neighbor 10.0.0.9;\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        pc = JunOSParser(cfg).parse()
        nbr = pc.bgp_instances[0].neighbors[0]
        assert nbr.remote_as == 65001
        assert isinstance(nbr.remote_as, int)

    def test_ebgp_remote_as_unchanged(self):
        """eBGP neighbors keep their explicit peer-as."""
        cfg = (
            "routing-options {\n"
            "    autonomous-system 65001;\n"
            "}\n"
            "protocols {\n"
            "    bgp {\n"
            "        group EBGP {\n"
            "            neighbor 10.0.0.1 {\n"
            "                peer-as 65002;\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        pc = JunOSParser(cfg).parse()
        nbr = pc.bgp_instances[0].neighbors[0]
        assert nbr.remote_as == 65002


# ---------------------------------------------------------------------------
# 1b — BGP local-address → reverse-resolve to update_source interface name
# ---------------------------------------------------------------------------


class TestJ1bLocalAddress:

    def test_local_address_resolved_to_interface(self):
        """Group-level local-address IP is reverse-resolved to interface name."""
        cfg = (
            "interfaces {\n"
            "    lo0 {\n"
            "        unit 0 {\n"
            "            family inet {\n"
            "                address 10.255.255.1/32;\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}\n"
            "routing-options {\n"
            "    autonomous-system 65001;\n"
            "}\n"
            "protocols {\n"
            "    bgp {\n"
            "        group IBGP {\n"
            "            type internal;\n"
            "            local-address 10.255.255.1;\n"
            "            neighbor 10.0.0.9;\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        pc = JunOSParser(cfg).parse()
        nbr = next(n for n in pc.bgp_instances[0].neighbors if str(n.peer_ip) == "10.0.0.9")
        assert nbr.update_source == "lo0.0"

    def test_neighbor_level_local_address(self):
        """Per-neighbor local-address overrides group."""
        cfg = (
            "interfaces {\n"
            "    lo0 {\n"
            "        unit 0 {\n"
            "            family inet {\n"
            "                address 10.255.255.1/32;\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "    ge-0/0/0 {\n"
            "        unit 0 {\n"
            "            family inet {\n"
            "                address 192.168.1.1/24;\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}\n"
            "routing-options {\n"
            "    autonomous-system 65001;\n"
            "}\n"
            "protocols {\n"
            "    bgp {\n"
            "        group EBGP {\n"
            "            local-address 10.255.255.1;\n"
            "            neighbor 10.0.0.1 {\n"
            "                peer-as 65002;\n"
            "                local-address 192.168.1.1;\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        pc = JunOSParser(cfg).parse()
        nbr = pc.bgp_instances[0].neighbors[0]
        assert nbr.update_source == "ge-0/0/0.0"

    def test_unresolvable_local_address_stays_none(self):
        """local-address that doesn't match any interface → update_source stays None."""
        cfg = (
            "interfaces {\n"
            "    lo0 {\n"
            "        unit 0 {\n"
            "            family inet {\n"
            "                address 10.255.255.1/32;\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}\n"
            "routing-options {\n"
            "    autonomous-system 65001;\n"
            "}\n"
            "protocols {\n"
            "    bgp {\n"
            "        group IBGP {\n"
            "            type internal;\n"
            "            local-address 10.99.99.99;\n"
            "            neighbor 10.0.0.9;\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        pc = JunOSParser(cfg).parse()
        nbr = pc.bgp_instances[0].neighbors[0]
        assert nbr.update_source is None

    def test_no_local_address(self):
        """No local-address → update_source stays None."""
        cfg = (
            "routing-options {\n"
            "    autonomous-system 65001;\n"
            "}\n"
            "protocols {\n"
            "    bgp {\n"
            "        group IBGP {\n"
            "            type internal;\n"
            "            neighbor 10.0.0.9;\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        pc = JunOSParser(cfg).parse()
        nbr = pc.bgp_instances[0].neighbors[0]
        assert nbr.update_source is None

    def test_ipv6_local_address_resolved(self):
        """IPv6 local-address is reverse-resolved to the loopback interface."""
        cfg = (
            "interfaces {\n"
            "    lo0 {\n"
            "        unit 0 {\n"
            "            family inet6 {\n"
            "                address 2001:db8::1/128;\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}\n"
            "routing-options {\n"
            "    autonomous-system 65001;\n"
            "}\n"
            "protocols {\n"
            "    bgp {\n"
            "        group IBGP6 {\n"
            "            type internal;\n"
            "            local-address 2001:db8::1;\n"
            "            neighbor 2001:db8::2 {\n"
            "                peer-as 65001;\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        pc = JunOSParser(cfg).parse()
        nbr = next(n for n in pc.bgp_instances[0].neighbors if str(n.peer_ip) == "2001:db8::2")
        assert nbr.update_source == "lo0.0"

    def test_ipv6_local_address_non_canonical_form(self):
        """Non-canonical IPv6 (uppercase) in local-address still resolves."""
        cfg = (
            "interfaces {\n"
            "    lo0 {\n"
            "        unit 0 {\n"
            "            family inet6 {\n"
            "                address 2001:db8::1/128;\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}\n"
            "routing-options {\n"
            "    autonomous-system 65001;\n"
            "}\n"
            "protocols {\n"
            "    bgp {\n"
            "        group IBGP6 {\n"
            "            type internal;\n"
            "            local-address 2001:DB8::1;\n"
            "            neighbor 2001:db8::2 {\n"
            "                peer-as 65001;\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        pc = JunOSParser(cfg).parse()
        nbr = next(n for n in pc.bgp_instances[0].neighbors if str(n.peer_ip) == "2001:db8::2")
        assert nbr.update_source == "lo0.0"
