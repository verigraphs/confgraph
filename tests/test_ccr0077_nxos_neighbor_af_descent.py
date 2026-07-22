"""CCR-0077 — NX-OS BGP per-neighbor address-family descent.

NX-OS nests ALL per-neighbor policy (prefix-list / route-map / send-community /
next-hop-self / default-originate / maximum-prefix) under
``neighbor <ip> / address-family <afi> <safi>``.  Before this fix the parser
flattened those grandchildren onto the session-level neighbor scalars and left
``neighbor.address_families == []`` — a confident wrong answer on a dual-stack
neighbor, where the ipv6 values clobbered the ipv4 ones.

These fixtures use device-EMITTED syntax verified on a Nexus 9000v (10.3(8) /
10.5(5) push+readback) and recorded in ``syntax-corpus/nxos/bgp.yaml``.
"""

import pytest
from confgraph.parsers.nxos_parser import NXOSParser


def _parse(config: str):
    return NXOSParser(config).parse()


def _neighbor(pc, ip_str: str):
    for bgp in pc.bgp_instances:
        for n in bgp.neighbors:
            if str(n.peer_ip) == ip_str:
                return n
    raise AssertionError(f"neighbor {ip_str} not found")


def _af(neighbor, afi: str, safi: str = "unicast"):
    for af in neighbor.address_families:
        if af.afi == afi and af.safi == safi:
            return af
    raise AssertionError(f"address-family {afi} {safi} not found on {neighbor.peer_ip}")


# ---------------------------------------------------------------------------
# Single-AF descent — the device-fact repro
# ---------------------------------------------------------------------------

class TestSingleAFDescent:
    CONFIG = (
        "router bgp 65535\n"
        "  neighbor 10.10.1.2\n"
        "    remote-as external\n"
        "    address-family ipv4 unicast\n"
        "      prefix-list PREFIX_FILTER in\n"
    )

    def test_af_entry_populated(self):
        n = _neighbor(_parse(self.CONFIG), "10.10.1.2")
        af = _af(n, "ipv4")
        assert af.prefix_list_in == "PREFIX_FILTER"

    def test_af_list_not_empty(self):
        n = _neighbor(_parse(self.CONFIG), "10.10.1.2")
        assert len(n.address_families) == 1

    def test_backcompat_scalar_still_readable(self):
        # Single-AF: the flattened scalar is kept populated from the ipv4 AF.
        n = _neighbor(_parse(self.CONFIG), "10.10.1.2")
        assert n.prefix_list_in == "PREFIX_FILTER"

    def test_remote_as_external(self):
        n = _neighbor(_parse(self.CONFIG), "10.10.1.2")
        assert n.remote_as == "external"


# ---------------------------------------------------------------------------
# Dual-stack — distinct per-AF policy, NO collision (the core bug)
# ---------------------------------------------------------------------------

class TestDualStackPrefixListNoCollision:
    CONFIG = (
        "router bgp 65077\n"
        "  neighbor 10.199.77.1\n"
        "    remote-as 65078\n"
        "    address-family ipv4 unicast\n"
        "      prefix-list PL_V4_IN in\n"
        "    address-family ipv6 unicast\n"
        "      prefix-list PL_V6_IN in\n"
    )

    def test_both_afs_present(self):
        n = _neighbor(_parse(self.CONFIG), "10.199.77.1")
        assert {(af.afi, af.safi) for af in n.address_families} == {
            ("ipv4", "unicast"), ("ipv6", "unicast")
        }

    def test_v4_prefix_list(self):
        n = _neighbor(_parse(self.CONFIG), "10.199.77.1")
        assert _af(n, "ipv4").prefix_list_in == "PL_V4_IN"

    def test_v6_prefix_list(self):
        n = _neighbor(_parse(self.CONFIG), "10.199.77.1")
        assert _af(n, "ipv6").prefix_list_in == "PL_V6_IN"

    def test_scalar_is_ipv4_not_ipv6(self):
        # The bug was that ipv6 clobbered the ipv4 scalar. Back-compat takes
        # ipv4-unicast only — the scalar must never carry the ipv6 value.
        n = _neighbor(_parse(self.CONFIG), "10.199.77.1")
        assert n.prefix_list_in == "PL_V4_IN"


class TestDualStackRouteMapNoCollision:
    # Device-verified emitted form (Nexus 9000v 10.5(5) push+readback, per CCR).
    CONFIG = (
        "router bgp 65077\n"
        "  neighbor 10.199.77.1\n"
        "    remote-as 65078\n"
        "    address-family ipv4 unicast\n"
        "      send-community\n"
        "      prefix-list PL_V4_IN in\n"
        "      route-map RM_V4_OUT out\n"
        "      next-hop-self\n"
        "    address-family ipv6 unicast\n"
        "      prefix-list PL_V6_IN in\n"
        "      route-map RM_V6_OUT out\n"
    )

    def test_v4_route_map_out(self):
        n = _neighbor(_parse(self.CONFIG), "10.199.77.1")
        assert _af(n, "ipv4").route_map_out == "RM_V4_OUT"

    def test_v6_route_map_out(self):
        n = _neighbor(_parse(self.CONFIG), "10.199.77.1")
        assert _af(n, "ipv6").route_map_out == "RM_V6_OUT"

    def test_next_hop_self_is_v4_only(self):
        # next-hop-self appears under ipv4 only; it must not leak to ipv6.
        n = _neighbor(_parse(self.CONFIG), "10.199.77.1")
        assert _af(n, "ipv4").next_hop_self is True
        assert _af(n, "ipv6").next_hop_self is False

    def test_send_community_is_v4_only(self):
        n = _neighbor(_parse(self.CONFIG), "10.199.77.1")
        assert _af(n, "ipv4").send_community is True
        assert _af(n, "ipv6").send_community is None

    def test_scalar_route_map_out_is_v4(self):
        n = _neighbor(_parse(self.CONFIG), "10.199.77.1")
        assert n.route_map_out == "RM_V4_OUT"


# ---------------------------------------------------------------------------
# AF-nested default-originate (the NX-OS half of CCR-0078, folded in)
# ---------------------------------------------------------------------------

class TestDefaultOriginate:
    CONFIG = (
        "router bgp 65055\n"
        "  neighbor 10.199.9.1\n"
        "    remote-as 65056\n"
        "    address-family ipv4 unicast\n"
        "      default-originate route-map RM_DO\n"
        "  neighbor 10.199.9.2\n"
        "    remote-as 65057\n"
        "    address-family ipv4 unicast\n"
        "      default-originate\n"
    )

    def test_conditional_af(self):
        n = _neighbor(_parse(self.CONFIG), "10.199.9.1")
        af = _af(n, "ipv4")
        assert af.default_originate is True
        assert af.default_originate_route_map == "RM_DO"

    def test_conditional_scalar(self):
        n = _neighbor(_parse(self.CONFIG), "10.199.9.1")
        assert n.default_originate is True
        assert n.default_originate_route_map == "RM_DO"

    def test_bare_af(self):
        n = _neighbor(_parse(self.CONFIG), "10.199.9.2")
        af = _af(n, "ipv4")
        assert af.default_originate is True
        assert af.default_originate_route_map is None

    def test_bare_scalar(self):
        n = _neighbor(_parse(self.CONFIG), "10.199.9.2")
        assert n.default_originate is True
        assert n.default_originate_route_map is None


# ---------------------------------------------------------------------------
# Neighbor with NO address-family sub-block — session fields intact
# ---------------------------------------------------------------------------

class TestNoAddressFamilyBlock:
    CONFIG = (
        "router bgp 65001\n"
        "  neighbor 10.0.0.9\n"
        "    remote-as 65900\n"
        "    description SESSION-ONLY\n"
        "    update-source loopback0\n"
    )

    def test_session_fields(self):
        n = _neighbor(_parse(self.CONFIG), "10.0.0.9")
        assert n.remote_as == 65900
        assert n.description == "SESSION-ONLY"
        assert n.update_source == "loopback0"

    def test_empty_af_list(self):
        n = _neighbor(_parse(self.CONFIG), "10.0.0.9")
        assert n.address_families == []

    def test_default_originate_false(self):
        n = _neighbor(_parse(self.CONFIG), "10.0.0.9")
        assert n.default_originate is False


# ---------------------------------------------------------------------------
# Inline (Form 1b) neighbor with an AF sub-block — descent applies there too
# ---------------------------------------------------------------------------

class TestRouteReflectorClientHoist:
    """route-reflector-client nests under the AF on NX-OS; the session scalar
    must stay populated via the ipv4-unicast back-compat hoist (regression:
    the all_children->children switch dropped it)."""

    CONFIG = (
        "router bgp 65001\n"
        "  neighbor 192.0.2.50\n"
        "    remote-as 65001\n"
        "    address-family ipv4 unicast\n"
        "      route-reflector-client\n"
    )

    def test_af_entry(self):
        n = _neighbor(_parse(self.CONFIG), "192.0.2.50")
        assert _af(n, "ipv4").route_reflector_client is True

    def test_session_scalar_preserved(self):
        n = _neighbor(_parse(self.CONFIG), "192.0.2.50")
        assert n.route_reflector_client is True


class TestNonUnicastAFPolicyPreserved:
    """A neighbor address-family whose header is outside ipv4/ipv6 unicast/
    multicast (l2vpn evpn, vpnv4 unicast, ipv4 labeled-unicast) must still be
    descended into address_families with its true afi/safi — not dropped."""

    EVPN_CONFIG = (
        "router bgp 65001\n"
        "  neighbor 192.0.2.60\n"
        "    remote-as 65002\n"
        "    address-family l2vpn evpn\n"
        "      send-community both\n"
        "      route-map RM_EVPN in\n"
    )

    def test_evpn_af_present_with_afi_safi(self):
        n = _neighbor(_parse(self.EVPN_CONFIG), "192.0.2.60")
        af = _af(n, "l2vpn", "evpn")
        assert af.send_community == "both"
        assert af.route_map_in == "RM_EVPN"

    def test_evpn_policy_not_lost_on_session(self):
        # Back-compat: with no ipv4-unicast AF the hoist falls back to the only
        # AF, so the session scalars stay populated (present, not absent).
        n = _neighbor(_parse(self.EVPN_CONFIG), "192.0.2.60")
        assert n.send_community == "both"
        assert n.route_map_in == "RM_EVPN"

    VPNV4_CONFIG = (
        "router bgp 65001\n"
        "  neighbor 192.0.2.61\n"
        "    remote-as 65003\n"
        "    address-family vpnv4 unicast\n"
        "      send-community extended\n"
    )

    def test_vpnv4_af_present(self):
        n = _neighbor(_parse(self.VPNV4_CONFIG), "192.0.2.61")
        af = _af(n, "vpnv4", "unicast")
        assert af.send_community == "extended"

    LABELED_CONFIG = (
        "router bgp 65001\n"
        "  neighbor 192.0.2.62\n"
        "    remote-as 65004\n"
        "    address-family ipv4 labeled-unicast\n"
        "      route-map RM_LU in\n"
    )

    def test_labeled_unicast_af_present(self):
        n = _neighbor(_parse(self.LABELED_CONFIG), "192.0.2.62")
        af = _af(n, "ipv4", "labeled-unicast")
        assert af.route_map_in == "RM_LU"

    def test_evpn_plus_ipv4_hoist_prefers_ipv4(self):
        # When both an ipv4-unicast and an evpn AF exist, the session scalar
        # must come from ipv4-unicast (unchanged hoist policy), and evpn policy
        # remains distinct in address_families.
        cfg = (
            "router bgp 65001\n"
            "  neighbor 192.0.2.63\n"
            "    remote-as 65005\n"
            "    address-family ipv4 unicast\n"
            "      route-map RM_V4 in\n"
            "    address-family l2vpn evpn\n"
            "      route-map RM_EVPN in\n"
        )
        n = _neighbor(_parse(cfg), "192.0.2.63")
        assert n.route_map_in == "RM_V4"
        assert _af(n, "ipv4", "unicast").route_map_in == "RM_V4"
        assert _af(n, "l2vpn", "evpn").route_map_in == "RM_EVPN"


class TestInlineFormAFDescent:
    CONFIG = (
        "router bgp 65001\n"
        "  neighbor 10.0.0.1 remote-as 65100\n"
        "    address-family ipv4 unicast\n"
        "      prefix-list PL_IN in\n"
        "      maximum-prefix 100\n"
    )

    def test_no_duplicate_neighbor(self):
        pc = _parse(self.CONFIG)
        alln = [n for bgp in pc.bgp_instances for n in bgp.neighbors]
        assert len(alln) == 1

    def test_af_descent_on_inline(self):
        n = _neighbor(_parse(self.CONFIG), "10.0.0.1")
        af = _af(n, "ipv4")
        assert af.prefix_list_in == "PL_IN"
        assert af.maximum_prefix == 100
