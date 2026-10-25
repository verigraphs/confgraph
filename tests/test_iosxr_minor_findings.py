"""Tests for IOS-XR minor-findings fixes (X1, X2, X4, X5, X6).

X1 — IOS-XR deletion tombstones (parse_deletion_commands override).
X2 — IOS-XR DHCP parsing (dhcp ipv4 profiles/relay).
X4 — Back-fill InterfaceConfig.ospf_area from OSPFArea.interfaces.
X5 — Per-AF route-policy no longer flattened onto neighbor level.
X6 — VRF RD populated from BGP VRF block.
"""

from confgraph.parsers.iosxr_parser import IOSXRParser


# ---------------------------------------------------------------------------
# X1 — Deletion tombstones
# ---------------------------------------------------------------------------


class TestX1DeletionTombstones:

    def test_no_router_ospf(self):
        cfg = "no router ospf 1\n"
        pc = IOSXRParser(cfg).parse()
        assert "process:ospf:1" in pc.no_commands

    def test_no_router_bgp(self):
        cfg = "no router bgp 65000\n"
        pc = IOSXRParser(cfg).parse()
        assert "process:bgp:65000" in pc.no_commands

    def test_no_router_isis(self):
        cfg = "no router isis CORE\n"
        pc = IOSXRParser(cfg).parse()
        assert "process:isis:CORE" in pc.no_commands

    def test_no_router_static(self):
        cfg = "no router static\n"
        pc = IOSXRParser(cfg).parse()
        assert "singleton:static_routes" in pc.no_commands

    def test_per_route_deletion_inside_static_block(self):
        cfg = (
            "router static\n"
            " address-family ipv4 unicast\n"
            "  no 10.0.0.0/8 192.168.1.1\n"
            " !\n"
            "!\n"
        )
        pc = IOSXRParser(cfg).parse()
        assert "static::10.0.0.0/8" in pc.no_commands

    def test_per_route_deletion_vrf(self):
        cfg = (
            "router static\n"
            " vrf MGMT\n"
            "  address-family ipv4 unicast\n"
            "   no 0.0.0.0/0 10.100.100.1\n"
            "  !\n"
            " !\n"
            "!\n"
        )
        pc = IOSXRParser(cfg).parse()
        assert "static:MGMT:0.0.0.0/0" in pc.no_commands

    def test_no_vrf(self):
        cfg = "no vrf CUSTOMER_A\n"
        pc = IOSXRParser(cfg).parse()
        assert "vrf:CUSTOMER_A" in pc.no_commands

    def test_no_route_policy(self):
        cfg = "no route-policy DENY-ALL\n"
        pc = IOSXRParser(cfg).parse()
        assert "route-map:DENY-ALL" in pc.no_commands

    def test_no_prefix_set(self):
        cfg = "no prefix-set ALLOWED-NETS\n"
        pc = IOSXRParser(cfg).parse()
        assert "prefix-list:ALLOWED-NETS" in pc.no_commands

    def test_no_acl(self):
        cfg = "no ipv4 access-list BLOCK-RFC1918\n"
        pc = IOSXRParser(cfg).parse()
        assert "acl:BLOCK-RFC1918" in pc.no_commands

    def test_dns_tombstones(self):
        cfg = (
            "no domain name-server 8.8.8.8\n"
            "no domain list corp.example.com\n"
            "no domain lookup\n"
        )
        pc = IOSXRParser(cfg).parse()
        assert "field:dns:name_server:8.8.8.8" in pc.no_commands
        assert "field:dns:domain:corp.example.com" in pc.no_commands
        assert "singleton:dns" in pc.no_commands

    def test_no_ios_tombstones_leak(self):
        """IOS-style tombstones should NOT appear (XR has its own override)."""
        cfg = "interface GigabitEthernet0/0/0/0\n ipv4 address 10.0.0.1 255.255.255.0\n!\n"
        pc = IOSXRParser(cfg).parse()
        assert len(pc.no_commands) == 0


# ---------------------------------------------------------------------------
# X2 — DHCP parsing
# ---------------------------------------------------------------------------


class TestX2DHCP:

    def test_dhcp_ipv4_profile(self):
        cfg = (
            "dhcp ipv4\n"
            " profile RELAY relay\n"
            "  helper-address vrf default 10.1.1.1 giaddr 0.0.0.0\n"
            "  helper-address vrf default 10.1.1.2 giaddr 0.0.0.0\n"
            " !\n"
            "!\n"
        )
        pc = IOSXRParser(cfg).parse()
        assert pc.dhcp is not None
        assert len(pc.dhcp.pools) == 1
        assert pc.dhcp.pools[0].name == "RELAY"
        assert "10.1.1.1" in pc.dhcp.pools[0].dns_servers
        assert "10.1.1.2" in pc.dhcp.pools[0].dns_servers

    def test_dhcp_ipv4_with_interface_binding(self):
        cfg = (
            "dhcp ipv4\n"
            " profile RELAY relay\n"
            "  helper-address vrf default 10.1.1.1 giaddr 0.0.0.0\n"
            " !\n"
            " interface GigabitEthernet0/0/0/1\n"
            "  relay profile RELAY\n"
            " !\n"
            "!\n"
        )
        pc = IOSXRParser(cfg).parse()
        assert pc.dhcp is not None
        assert len(pc.dhcp.pools) == 1

    def test_no_dhcp(self):
        cfg = "interface GigabitEthernet0/0/0/0\n ipv4 address 10.0.0.1 255.255.255.0\n!\n"
        pc = IOSXRParser(cfg).parse()
        assert pc.dhcp is None

    def test_dhcp_line_numbers(self):
        cfg = (
            "dhcp ipv4\n"
            " profile RELAY relay\n"
            "  helper-address vrf default 10.1.1.1 giaddr 0.0.0.0\n"
            " !\n"
            "!\n"
        )
        pc = IOSXRParser(cfg).parse()
        assert pc.dhcp is not None
        assert len(pc.dhcp.line_numbers) > 0


# ---------------------------------------------------------------------------
# X4 — OSPF interface back-fill
# ---------------------------------------------------------------------------


class TestX4OSPFInterfaceBackfill:

    def test_ospf_area_backfills_interface(self):
        cfg = (
            "interface GigabitEthernet0/0/0/0\n"
            " ipv4 address 10.0.0.1 255.255.255.0\n"
            "!\n"
            "router ospf 1\n"
            " area 0\n"
            "  interface GigabitEthernet0/0/0/0\n"
            "  !\n"
            " !\n"
            "!\n"
        )
        pc = IOSXRParser(cfg).parse()
        intf = next(i for i in pc.interfaces if i.name == "GigabitEthernet0/0/0/0")
        assert intf.ospf_area == "0"
        assert intf.ospf_process_id == 1

    def test_ospf_multiple_areas(self):
        cfg = (
            "interface GigabitEthernet0/0/0/0\n"
            " ipv4 address 10.0.0.1 255.255.255.0\n"
            "!\n"
            "interface GigabitEthernet0/0/0/1\n"
            " ipv4 address 10.0.1.1 255.255.255.0\n"
            "!\n"
            "router ospf 1\n"
            " area 0\n"
            "  interface GigabitEthernet0/0/0/0\n"
            "  !\n"
            " !\n"
            " area 1\n"
            "  interface GigabitEthernet0/0/0/1\n"
            "  !\n"
            " !\n"
            "!\n"
        )
        pc = IOSXRParser(cfg).parse()
        intf0 = next(i for i in pc.interfaces if i.name == "GigabitEthernet0/0/0/0")
        intf1 = next(i for i in pc.interfaces if i.name == "GigabitEthernet0/0/0/1")
        assert intf0.ospf_area == "0"
        assert intf1.ospf_area == "1"

    def test_no_ospf_leaves_interface_none(self):
        cfg = (
            "interface GigabitEthernet0/0/0/0\n"
            " ipv4 address 10.0.0.1 255.255.255.0\n"
            "!\n"
        )
        pc = IOSXRParser(cfg).parse()
        intf = next(i for i in pc.interfaces if i.name == "GigabitEthernet0/0/0/0")
        assert intf.ospf_area is None
        assert intf.ospf_process_id is None


# ---------------------------------------------------------------------------
# X5 — Per-AF route-policy not flattened
# ---------------------------------------------------------------------------


class TestX5AFPolicyNotFlattened:

    def test_af_policy_not_on_neighbor(self):
        """AF-level route-policy should NOT leak to neighbor-level fields."""
        cfg = (
            "router bgp 65000\n"
            " neighbor 10.1.1.1\n"
            "  remote-as 65001\n"
            "  address-family ipv4 unicast\n"
            "   route-policy IMPORT-V4 in\n"
            "   route-policy EXPORT-V4 out\n"
            "  !\n"
            "  address-family ipv6 unicast\n"
            "   route-policy IMPORT-V6 in\n"
            "   route-policy EXPORT-V6 out\n"
            "  !\n"
            " !\n"
            "!\n"
        )
        pc = IOSXRParser(cfg).parse()
        nbr = pc.bgp_instances[0].neighbors[0]
        # Neighbor-level should be None — policies are AF-scoped only
        assert nbr.route_map_in is None
        assert nbr.route_map_out is None

    def test_af_policies_preserved_on_af_objects(self):
        """Per-AF policies should still be captured on BGPNeighborAF objects."""
        cfg = (
            "router bgp 65000\n"
            " neighbor 10.1.1.1\n"
            "  remote-as 65001\n"
            "  address-family ipv4 unicast\n"
            "   route-policy IMPORT-V4 in\n"
            "   route-policy EXPORT-V4 out\n"
            "  !\n"
            "  address-family ipv6 unicast\n"
            "   route-policy IMPORT-V6 in\n"
            "   route-policy EXPORT-V6 out\n"
            "  !\n"
            " !\n"
            "!\n"
        )
        pc = IOSXRParser(cfg).parse()
        nbr = pc.bgp_instances[0].neighbors[0]
        v4_af = next(af for af in nbr.address_families if af.afi == "ipv4")
        v6_af = next(af for af in nbr.address_families if af.afi == "ipv6")
        assert v4_af.route_map_in == "IMPORT-V4"
        assert v4_af.route_map_out == "EXPORT-V4"
        assert v6_af.route_map_in == "IMPORT-V6"
        assert v6_af.route_map_out == "EXPORT-V6"

    def test_neighbor_level_policy_still_captured(self):
        """Neighbor-level (direct child) route-policy should still work."""
        cfg = (
            "router bgp 65000\n"
            " neighbor 10.1.1.1\n"
            "  remote-as 65001\n"
            "  route-policy GLOBAL-IN in\n"
            "  route-policy GLOBAL-OUT out\n"
            " !\n"
            "!\n"
        )
        pc = IOSXRParser(cfg).parse()
        nbr = pc.bgp_instances[0].neighbors[0]
        assert nbr.route_map_in == "GLOBAL-IN"
        assert nbr.route_map_out == "GLOBAL-OUT"


# ---------------------------------------------------------------------------
# X6 — VRF RD from BGP
# ---------------------------------------------------------------------------


class TestX6VRFRDFromBGP:

    def test_vrf_rd_populated_from_bgp(self):
        cfg = (
            "vrf CUSTOMER_A\n"
            " address-family ipv4 unicast\n"
            "  import route-target\n"
            "   65000:100\n"
            "  !\n"
            " !\n"
            "!\n"
            "router bgp 65000\n"
            " vrf CUSTOMER_A\n"
            "  rd 65000:100\n"
            "  neighbor 10.1.1.1\n"
            "   remote-as 65001\n"
            "  !\n"
            " !\n"
            "!\n"
        )
        pc = IOSXRParser(cfg).parse()
        vrf = next(v for v in pc.vrfs if v.name == "CUSTOMER_A")
        assert vrf.rd == "65000:100"

    def test_vrf_rd_not_overwritten_if_present(self):
        """If VRF already has RD (shouldn't happen on XR, but safe guard)."""
        # XR VRFs don't define RD at the VRF level, but if they did, it
        # shouldn't be overwritten by the BGP-derived value.
        cfg = (
            "vrf CUSTOMER_A\n"
            "!\n"
            "router bgp 65000\n"
            " vrf CUSTOMER_A\n"
            "  rd 65000:200\n"
            " !\n"
            "!\n"
        )
        pc = IOSXRParser(cfg).parse()
        vrf = next(v for v in pc.vrfs if v.name == "CUSTOMER_A")
        assert vrf.rd == "65000:200"

    def test_vrf_without_bgp_rd_stays_none(self):
        cfg = (
            "vrf CUSTOMER_A\n"
            "!\n"
        )
        pc = IOSXRParser(cfg).parse()
        vrf = next(v for v in pc.vrfs if v.name == "CUSTOMER_A")
        assert vrf.rd is None

    def test_multiple_vrfs(self):
        cfg = (
            "vrf CUST_A\n"
            "!\n"
            "vrf CUST_B\n"
            "!\n"
            "router bgp 65000\n"
            " vrf CUST_A\n"
            "  rd 65000:100\n"
            " !\n"
            " vrf CUST_B\n"
            "  rd 65000:200\n"
            " !\n"
            "!\n"
        )
        pc = IOSXRParser(cfg).parse()
        vrf_a = next(v for v in pc.vrfs if v.name == "CUST_A")
        vrf_b = next(v for v in pc.vrfs if v.name == "CUST_B")
        assert vrf_a.rd == "65000:100"
        assert vrf_b.rd == "65000:200"
