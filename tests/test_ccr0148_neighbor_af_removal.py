"""CCR-0148 — per-neighbor / peer-group address-family DEACTIVATION op.

Removing an address-family block under a BGP neighbor (or ``template peer``
peer-group) produced no deletion op — per-neighbor AF deactivation was
inexpressible.  ``no address-family <afi> [<safi>]`` inside a ``neighbor <ip>``
or ``template peer NAME`` block now emits an ops-only ``LIST_REMOVE`` keyed
(afi, safi):

    LIST_REMOVE ("bgp_instance", <asn>, <vrf>, "field",
                 "neighbor"|"peer_group", <name>, "address_family", <afi>, <safi>)

The op is built DIRECTLY (not via the tombstone-string codec, which cannot place
the trailing afi/safi after a variable-length, colon-bearing IPv6 peer).  It is
ops-only with NO legacy twin: NX-OS renders this removal by OMISSION — a real
device never emits ``no address-family`` into running-config (capture
2026-07-30-n9kv-10.5.5-evpn-l3vni-removals-extcomm, ITEM 2+4) — so the legacy
string channel never observes it and ``encode_legacy`` emits nothing.  The op
serves PROPOSAL text; the engine merge replay is the CCR-0148 entrp half (WI-E2),
until which the op is a benign no-op (the AF-deactivation verdict arm HOLDS).
"""

from __future__ import annotations

from confgraph.change_ir import (
    Verb,
    derive_ops,
    encode_legacy,
    is_native_bgp_neighbor_af_removal_op,
    is_native_bgp_op,
)
from confgraph.parsers.nxos_parser import NXOSParser


def _parse(config: str):
    return NXOSParser(config).parse()


def _af_removals(pc):
    return [
        op
        for op in (pc.native_change_ops or [])
        if is_native_bgp_neighbor_af_removal_op(op)
    ]


# ---------------------------------------------------------------------------
# Neighbor context — per-AF removal, one op per removed (afi, safi)
# ---------------------------------------------------------------------------

class TestNeighborContext:
    # The capture control block: neighbor with an l2vpn-evpn AF, then the AF
    # removed by omission (proposal spelling: `no address-family l2vpn evpn`).
    L2VPN_EVPN = (
        "feature bgp\n"
        "router bgp 65001\n"
        "  neighbor 10.99.99.1\n"
        "    remote-as 4200000001\n"
        "    no address-family l2vpn evpn\n"
    )

    def test_l2vpn_evpn_removal_emits_keyed_list_remove(self):
        removals = _af_removals(_parse(self.L2VPN_EVPN))
        assert len(removals) == 1
        op = removals[0]
        assert op.verb is Verb.LIST_REMOVE
        assert op.origin == "native"
        assert op.path == (
            "bgp_instance", "65001", "", "field", "neighbor",
            "10.99.99.1", "address_family", "l2vpn", "evpn",
        )

    def test_ipv4_unicast_removal(self):
        removals = _af_removals(_parse(
            "feature bgp\n"
            "router bgp 65001\n"
            "  neighbor 10.0.0.1\n"
            "    remote-as 65002\n"
            "    no address-family ipv4 unicast\n"
        ))
        assert [op.path for op in removals] == [(
            "bgp_instance", "65001", "", "field", "neighbor",
            "10.0.0.1", "address_family", "ipv4", "unicast",
        )]

    def test_ipv6_unicast_removal(self):
        removals = _af_removals(_parse(
            "feature bgp\n"
            "router bgp 65001\n"
            "  neighbor 10.0.0.1\n"
            "    remote-as 65002\n"
            "    no address-family ipv6 unicast\n"
        ))
        assert [op.path for op in removals] == [(
            "bgp_instance", "65001", "", "field", "neighbor",
            "10.0.0.1", "address_family", "ipv6", "unicast",
        )]

    def test_ipv6_peer_name_stays_one_segment(self):
        # The peer IS an IPv6 address (colon-bearing) — it must remain a SINGLE
        # path segment (CCR-0110 E6 value-collapse), with afi/safi trailing.
        removals = _af_removals(_parse(
            "feature bgp\n"
            "router bgp 65001\n"
            "  neighbor 2001:db8::1\n"
            "    remote-as 65002\n"
            "    no address-family l2vpn evpn\n"
        ))
        assert len(removals) == 1
        assert removals[0].path == (
            "bgp_instance", "65001", "", "field", "neighbor",
            "2001:db8::1", "address_family", "l2vpn", "evpn",
        )

    def test_safi_less_form_records_empty_safi(self):
        removals = _af_removals(_parse(
            "feature bgp\n"
            "router bgp 65001\n"
            "  neighbor 10.0.0.1\n"
            "    remote-as 65002\n"
            "    no address-family ipv4\n"
        ))
        assert len(removals) == 1
        assert removals[0].path[-2:] == ("ipv4", "")


# ---------------------------------------------------------------------------
# Peer-group (template peer) context — keys into peer_group, not neighbor
# ---------------------------------------------------------------------------

class TestPeerGroupContext:
    TEMPLATE = (
        "feature bgp\n"
        "router bgp 65001\n"
        "  template peer OVERLAY\n"
        "    remote-as 65002\n"
        "    no address-family l2vpn evpn\n"
    )

    def test_template_peer_removal_uses_peer_group_scope(self):
        removals = _af_removals(_parse(self.TEMPLATE))
        assert len(removals) == 1
        assert removals[0].path == (
            "bgp_instance", "65001", "", "field", "peer_group",
            "OVERLAY", "address_family", "l2vpn", "evpn",
        )


# ---------------------------------------------------------------------------
# Over-trigger discipline — restatement / activation must NOT fire a removal
# ---------------------------------------------------------------------------

class TestOverTrigger:
    def test_positive_af_block_emits_no_removal(self):
        # Restating (activating) the AF — no `no` line — must emit NO removal.
        pc = _parse(
            "feature bgp\n"
            "router bgp 65001\n"
            "  neighbor 10.99.99.1\n"
            "    remote-as 4200000001\n"
            "    address-family l2vpn evpn\n"
            "      send-community extended\n"
        )
        assert _af_removals(pc) == []

    def test_other_neighbor_negation_is_not_an_af_removal(self):
        # A sibling per-neighbor field reset stays an UNSET, not an AF removal.
        pc = _parse(
            "feature bgp\n"
            "router bgp 65001\n"
            "  neighbor 10.0.0.1\n"
            "    remote-as 65002\n"
            "    no description\n"
        )
        assert _af_removals(pc) == []

    def test_bare_no_address_family_without_afi_fires_nothing(self):
        # Nameless form (no afi token) must NOT fire a removal — the emission
        # requires at least an afi, so a bare/malformed `no address-family`
        # produces no op (over-trigger discipline).
        pc = _parse(
            "feature bgp\n"
            "router bgp 65001\n"
            "  neighbor 10.0.0.1\n"
            "    remote-as 65002\n"
            "    no address-family\n"
        )
        assert _af_removals(pc) == []


# ---------------------------------------------------------------------------
# VRF instance — the vrf name lands in path[2]
# ---------------------------------------------------------------------------

class TestVrfContext:
    def test_vrf_neighbor_af_removal_scopes_the_vrf(self):
        removals = _af_removals(_parse(
            "feature bgp\n"
            "router bgp 65001\n"
            "  vrf RED\n"
            "    neighbor 10.0.0.1\n"
            "      remote-as 65002\n"
            "      no address-family ipv4 unicast\n"
        ))
        assert len(removals) == 1
        assert removals[0].path == (
            "bgp_instance", "65001", "RED", "field", "neighbor",
            "10.0.0.1", "address_family", "ipv4", "unicast",
        )


# ---------------------------------------------------------------------------
# Codec: routed as a native BGP op; NO legacy twin (byte-identical artifacts)
# ---------------------------------------------------------------------------

class TestCodec:
    CONFIG = TestNeighborContext.L2VPN_EVPN

    def test_op_is_a_native_bgp_op(self):
        # is_native_bgp_op True => _proposal_from_ops skips it and
        # _apply_native_bgp_ops replays it (the WI-E2 handler), rather than
        # manufacturing a legacy tombstone string.
        removals = _af_removals(_parse(self.CONFIG))
        assert removals and is_native_bgp_op(removals[0])

    def test_encode_legacy_emits_nothing(self):
        pc = _parse(self.CONFIG)
        arts = encode_legacy(derive_ops(pc))
        # No legacy twin: the AF removal contributes NOTHING to any legacy
        # channel, and the legacy no_commands stays empty.
        assert arts.bgp_no_commands == {}
        assert pc.bgp_instances[0].no_commands == []

    def test_peer_group_removal_also_emits_nothing_legacy(self):
        pc = _parse(TestPeerGroupContext.TEMPLATE)
        arts = encode_legacy(derive_ops(pc))
        assert arts.bgp_no_commands == {}
