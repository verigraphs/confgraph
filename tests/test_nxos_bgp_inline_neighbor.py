"""Tests for NX-OS BGP inline neighbor child parsing fix.

CCR: confgraph_nxos_bgp_inline_neighbor_children_dropped.md

Verifies that both inline (``neighbor <ip> remote-as <as>``) and split
(bare ``neighbor <ip>`` + indented ``remote-as``) forms parse all child
attributes identically.
"""

import pytest
from confgraph.parsers.nxos_parser import NXOSParser


def _parse(config: str):
    return NXOSParser(config).parse()


def _get_neighbor(pc, ip_str: str):
    """Return the BGPNeighbor matching *ip_str*, or raise."""
    for bgp in pc.bgp_instances:
        for n in bgp.neighbors:
            if str(n.peer_ip) == ip_str:
                return n
    raise AssertionError(f"neighbor {ip_str} not found in parsed config")


# -----------------------------------------------------------------------
# Inline form — the broken path (Form 1b fix)
# -----------------------------------------------------------------------

class TestInlineNeighborChildren:
    """Inline ``neighbor <ip> remote-as <as>`` with indented children."""

    INLINE_CONFIG = (
        "router bgp 65001\n"
        "  neighbor 10.0.0.1 remote-as 65100\n"
        "    description PEER-SPINE\n"
        "    password 3 abc123\n"
        "    update-source loopback0\n"
        "    ebgp-multihop 2\n"
        "    next-hop-self\n"
        "    disable-connected-check\n"
        "    fall-over bfd\n"
        "    timers 10 30\n"
        "    local-as 65999 no-prepend replace-as\n"
        "    send-community both\n"
        "    address-family ipv4 unicast\n"
        "      route-map RM-IN in\n"
        "      route-map RM-OUT out\n"
        "      prefix-list PL-IN in\n"
        "      prefix-list PL-OUT out\n"
        "      maximum-prefix 100\n"
    )

    def test_remote_as(self):
        n = _get_neighbor(_parse(self.INLINE_CONFIG), "10.0.0.1")
        assert n.remote_as == 65100

    def test_description(self):
        n = _get_neighbor(_parse(self.INLINE_CONFIG), "10.0.0.1")
        assert n.description == "PEER-SPINE"

    def test_password(self):
        n = _get_neighbor(_parse(self.INLINE_CONFIG), "10.0.0.1")
        # CCR-0030 bug 4: the encryption-type token is no longer glommed on.
        assert n.password == "abc123"
        assert n.password_encryption_type == "3"

    def test_update_source(self):
        n = _get_neighbor(_parse(self.INLINE_CONFIG), "10.0.0.1")
        assert n.update_source == "loopback0"

    def test_ebgp_multihop(self):
        n = _get_neighbor(_parse(self.INLINE_CONFIG), "10.0.0.1")
        assert n.ebgp_multihop == 2

    def test_next_hop_self(self):
        n = _get_neighbor(_parse(self.INLINE_CONFIG), "10.0.0.1")
        assert n.next_hop_self is True

    def test_disable_connected_check(self):
        n = _get_neighbor(_parse(self.INLINE_CONFIG), "10.0.0.1")
        assert n.disable_connected_check is True

    def test_fall_over_bfd(self):
        n = _get_neighbor(_parse(self.INLINE_CONFIG), "10.0.0.1")
        assert n.fall_over_bfd is True

    def test_timers(self):
        n = _get_neighbor(_parse(self.INLINE_CONFIG), "10.0.0.1")
        assert n.timers is not None
        assert n.timers.keepalive == 10
        assert n.timers.holdtime == 30

    def test_local_as(self):
        n = _get_neighbor(_parse(self.INLINE_CONFIG), "10.0.0.1")
        assert n.local_as == 65999
        assert n.local_as_no_prepend is True
        assert n.local_as_replace_as is True

    def test_send_community(self):
        n = _get_neighbor(_parse(self.INLINE_CONFIG), "10.0.0.1")
        assert n.send_community == "both"

    def test_route_map_in(self):
        n = _get_neighbor(_parse(self.INLINE_CONFIG), "10.0.0.1")
        assert n.route_map_in == "RM-IN"

    def test_route_map_out(self):
        n = _get_neighbor(_parse(self.INLINE_CONFIG), "10.0.0.1")
        assert n.route_map_out == "RM-OUT"

    def test_prefix_list_in(self):
        n = _get_neighbor(_parse(self.INLINE_CONFIG), "10.0.0.1")
        assert n.prefix_list_in == "PL-IN"

    def test_prefix_list_out(self):
        n = _get_neighbor(_parse(self.INLINE_CONFIG), "10.0.0.1")
        assert n.prefix_list_out == "PL-OUT"

    def test_maximum_prefix(self):
        n = _get_neighbor(_parse(self.INLINE_CONFIG), "10.0.0.1")
        assert n.maximum_prefix == 100

    def test_no_duplicate_neighbors(self):
        """Form 1b must update, not append — neighbor count stays at 1."""
        pc = _parse(self.INLINE_CONFIG)
        all_neighbors = []
        for bgp in pc.bgp_instances:
            all_neighbors.extend(bgp.neighbors)
        assert len(all_neighbors) == 1


# -----------------------------------------------------------------------
# Split form — regression guard (Form 2 path)
# -----------------------------------------------------------------------

class TestSplitNeighborChildren:
    """Bare ``neighbor <ip>`` + indented ``remote-as`` and children."""

    SPLIT_CONFIG = (
        "router bgp 65001\n"
        "  neighbor 10.0.0.2\n"
        "    remote-as 65200\n"
        "    description PEER-LEAF\n"
        "    password 7 secretXYZ\n"
        "    update-source loopback1\n"
        "    ebgp-multihop 3\n"
        "    next-hop-self\n"
        "    route-reflector-client\n"
        "    send-community extended\n"
        "    address-family ipv4 unicast\n"
        "      route-map RM-LEAF-IN in\n"
        "      route-map RM-LEAF-OUT out\n"
        "      maximum-prefix 500\n"
    )

    def test_remote_as(self):
        n = _get_neighbor(_parse(self.SPLIT_CONFIG), "10.0.0.2")
        assert n.remote_as == 65200

    def test_description(self):
        n = _get_neighbor(_parse(self.SPLIT_CONFIG), "10.0.0.2")
        assert n.description == "PEER-LEAF"

    def test_password(self):
        n = _get_neighbor(_parse(self.SPLIT_CONFIG), "10.0.0.2")
        # CCR-0030 bug 4: encryption-type separated from key material.
        assert n.password == "secretXYZ"
        assert n.password_encryption_type == "7"

    def test_update_source(self):
        n = _get_neighbor(_parse(self.SPLIT_CONFIG), "10.0.0.2")
        assert n.update_source == "loopback1"

    def test_ebgp_multihop(self):
        n = _get_neighbor(_parse(self.SPLIT_CONFIG), "10.0.0.2")
        assert n.ebgp_multihop == 3

    def test_next_hop_self(self):
        n = _get_neighbor(_parse(self.SPLIT_CONFIG), "10.0.0.2")
        assert n.next_hop_self is True

    def test_route_reflector_client(self):
        n = _get_neighbor(_parse(self.SPLIT_CONFIG), "10.0.0.2")
        assert n.route_reflector_client is True

    def test_send_community(self):
        n = _get_neighbor(_parse(self.SPLIT_CONFIG), "10.0.0.2")
        assert n.send_community == "extended"

    def test_route_map_in(self):
        n = _get_neighbor(_parse(self.SPLIT_CONFIG), "10.0.0.2")
        assert n.route_map_in == "RM-LEAF-IN"

    def test_route_map_out(self):
        n = _get_neighbor(_parse(self.SPLIT_CONFIG), "10.0.0.2")
        assert n.route_map_out == "RM-LEAF-OUT"

    def test_maximum_prefix(self):
        n = _get_neighbor(_parse(self.SPLIT_CONFIG), "10.0.0.2")
        assert n.maximum_prefix == 500

    def test_no_duplicate_neighbors(self):
        pc = _parse(self.SPLIT_CONFIG)
        all_neighbors = []
        for bgp in pc.bgp_instances:
            all_neighbors.extend(bgp.neighbors)
        assert len(all_neighbors) == 1


# -----------------------------------------------------------------------
# Parity — both forms produce identical results
# -----------------------------------------------------------------------

class TestInlineSplitParity:
    """Same neighbor config in inline vs split form must parse identically."""

    INLINE = (
        "router bgp 65001\n"
        "  neighbor 10.0.0.5 remote-as 65500\n"
        "    description PARITY-TEST\n"
        "    password 3 paritykey\n"
        "    update-source loopback0\n"
        "    next-hop-self\n"
        "    address-family ipv4 unicast\n"
        "      route-map RM-PARITY in\n"
        "      maximum-prefix 200\n"
    )

    SPLIT = (
        "router bgp 65001\n"
        "  neighbor 10.0.0.5\n"
        "    remote-as 65500\n"
        "    description PARITY-TEST\n"
        "    password 3 paritykey\n"
        "    update-source loopback0\n"
        "    next-hop-self\n"
        "    address-family ipv4 unicast\n"
        "      route-map RM-PARITY in\n"
        "      maximum-prefix 200\n"
    )

    FIELDS = [
        "remote_as", "description", "password", "update_source",
        "next_hop_self", "route_map_in", "maximum_prefix",
    ]

    def test_parity(self):
        n_inline = _get_neighbor(_parse(self.INLINE), "10.0.0.5")
        n_split = _get_neighbor(_parse(self.SPLIT), "10.0.0.5")
        for field in self.FIELDS:
            assert getattr(n_inline, field) == getattr(n_split, field), (
                f"field {field}: inline={getattr(n_inline, field)!r} "
                f"vs split={getattr(n_split, field)!r}"
            )


# -----------------------------------------------------------------------
# Negative — inline neighbor with no children stays clean
# -----------------------------------------------------------------------

class TestInlineNoChildren:
    """Inline neighbor with no indented children — no crash, no extras."""

    CONFIG = (
        "router bgp 65001\n"
        "  neighbor 10.0.0.9 remote-as 65900\n"
    )

    def test_remote_as_only(self):
        n = _get_neighbor(_parse(self.CONFIG), "10.0.0.9")
        assert n.remote_as == 65900
        assert n.description is None
        assert n.password is None
        assert n.update_source is None
        assert n.route_map_in is None
        assert n.maximum_prefix is None


# -----------------------------------------------------------------------
# Mixed — inline and split neighbors coexist
# -----------------------------------------------------------------------

class TestMixedInlineAndSplit:
    """Config with both inline and split neighbors — both fully parsed."""

    CONFIG = (
        "router bgp 65001\n"
        "  neighbor 10.0.0.1 remote-as 65100\n"
        "    description INLINE-PEER\n"
        "    password 3 inlinepass\n"
        "  neighbor 10.0.0.2\n"
        "    remote-as 65200\n"
        "    description SPLIT-PEER\n"
        "    password 7 splitpass\n"
    )

    def test_inline_fields(self):
        n = _get_neighbor(_parse(self.CONFIG), "10.0.0.1")
        assert n.remote_as == 65100
        assert n.description == "INLINE-PEER"
        assert n.password == "inlinepass"
        assert n.password_encryption_type == "3"

    def test_split_fields(self):
        n = _get_neighbor(_parse(self.CONFIG), "10.0.0.2")
        assert n.remote_as == 65200
        assert n.description == "SPLIT-PEER"
        assert n.password == "splitpass"
        assert n.password_encryption_type == "7"

    def test_neighbor_count(self):
        pc = _parse(self.CONFIG)
        all_neighbors = []
        for bgp in pc.bgp_instances:
            all_neighbors.extend(bgp.neighbors)
        assert len(all_neighbors) == 2


# -----------------------------------------------------------------------
# Inherit peer — split form with peer-group inheritance
# -----------------------------------------------------------------------

class TestInheritPeer:
    """NX-OS ``inherit peer NAME`` in a split-form neighbor."""

    CONFIG = (
        "router bgp 65001\n"
        "  template peer SPINE-TEMPLATE\n"
        "    remote-as 65100\n"
        "    update-source loopback0\n"
        "  neighbor 10.0.0.3\n"
        "    inherit peer SPINE-TEMPLATE\n"
        "    description INHERITED-PEER\n"
    )

    def test_peer_group(self):
        n = _get_neighbor(_parse(self.CONFIG), "10.0.0.3")
        assert n.peer_group == "SPINE-TEMPLATE"

    def test_description(self):
        n = _get_neighbor(_parse(self.CONFIG), "10.0.0.3")
        assert n.description == "INHERITED-PEER"
