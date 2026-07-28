"""CCR-0114 — EOS VRF-scoped flat ``network`` / ``aggregate-address``.

Device verification (Arista cEOS 4.36.1F, multi-agent, containerlab, full
push + ``show running-config section bgp`` readback, 2026-07-28) established
that EOS emits a VRF-scoped ``network`` and ``aggregate-address`` **FLAT, as
direct children of the ``vrf <name>`` block** — NOT under an ``address-family``
sub-block.  Verified DEFINITIVELY: entering them under ``address-family ipv4``
inside the vrf STILL emits them flat (the AF block does not persist).  Capture
of record: ``syntax-corpus/captures/eos/2026-07-28-ceos-4.36.1F-vrf-bgp-network.txt``;
corpus entry ``syntax-corpus/eos/bgp.yaml:vrf-network-aggregate-flat``
(verified-capture).

The shared block-form walker ``ios_parser._parse_bgp_vrf_blocks`` (NX-OS /
IOS-XR / EOS, CCR-0032/0112) previously parsed ONLY the under-address-family
placement, so the flat-under-vrf ``network`` and ``aggregate-address`` were
DROPPED (``BGPConfig.networks == []``, no aggregate anywhere).  CCR-0114 mirrors
the GLOBAL instance path into the VRF path: a flat ``network`` lands on
``BGPConfig.networks`` and a flat ``aggregate-address`` folds onto the
synthesized ipv4/unicast ``BGPAddressFamily`` (the instance-level ``BGPConfig``
has no ``aggregate_addresses`` field), with correctly VRF-scoped native ops.
The new flat walk reads DIRECT children only, so an AF-nested VRF network
(NX-OS / IOS-XR) is never also swept — no double-count.
"""

from __future__ import annotations

from confgraph.change_ir import Verb
from confgraph.parsers.eos_parser import EOSParser
from confgraph.parsers.nxos_parser import NXOSParser


def _bgp_ops(pc):
    return [
        o
        for o in (pc.native_change_ops or [])
        if o.path and o.path[0] in ("bgp_instance", "bgp_instances")
    ]


def _net_ops(pc, vrf):
    return [
        o
        for o in _bgp_ops(pc)
        if o.verb is Verb.SET and o.path[2] == vrf and "network" in o.path
    ]


def _aggr_ops(pc, vrf):
    return [
        o
        for o in _bgp_ops(pc)
        if o.verb is Verb.SET and o.path[2] == vrf and "aggregate" in o.path
    ]


# ---------------------------------------------------------------------------
# Device-faithful — the exact cEOS 4.36.1F emitted form (capture of record).
# ---------------------------------------------------------------------------

class TestEosVrfFlatDeviceForm:
    # Verbatim from the 2026-07-28 capture of record. Global network/aggregate
    # (10.201.x) emit flat at the router-bgp session level; the VRF's
    # network/aggregate (10.114.x) emit flat as direct children of `vrf
    # CCR114_CUST` — no `address-family` sub-block present.
    CONFIG = (
        "router bgp 65000\n"
        "   router-id 1.1.1.1\n"
        "   network 10.201.1.0/24\n"
        "   aggregate-address 10.201.0.0/16 summary-only\n"
        "   !\n"
        "   vrf CCR114_CUST\n"
        "      rd 65000:114\n"
        "      neighbor 10.114.9.1 remote-as 65001\n"
        "      network 10.114.1.0/24\n"
        "      aggregate-address 10.114.0.0/16 summary-only\n"
        "      redistribute connected\n"
    )

    def _vrf(self, pc):
        return next(b for b in pc.bgp_instances if b.vrf == "CCR114_CUST")

    def test_flat_network_lands_on_vrf_bgpconfig_networks(self):
        pc = EOSParser(self.CONFIG).parse()
        bvrf = self._vrf(pc)
        assert [str(n.prefix) for n in bvrf.networks] == ["10.114.1.0/24"]

    def test_flat_aggregate_folds_onto_synthesized_vrf_af(self):
        pc = EOSParser(self.CONFIG).parse()
        bvrf = self._vrf(pc)
        # No `address-family` block was printed under the vrf, so the ipv4/unicast
        # AF is synthesized (vrf-scoped) to carry the aggregate.
        afs = [a for a in bvrf.address_families if (a.afi, a.safi) == ("ipv4", "unicast")]
        assert len(afs) == 1
        af = afs[0]
        assert af.vrf == "CCR114_CUST"
        assert [str(a.prefix) for a in af.aggregate_addresses] == ["10.114.0.0/16"]
        assert af.aggregate_addresses[0].summary_only is True

    def test_vrf_scoped_network_native_op(self):
        pc = EOSParser(self.CONFIG).parse()
        assert [o.path for o in _net_ops(pc, "CCR114_CUST")] == [
            ("bgp_instances", "65000", "CCR114_CUST", "network", "10.114.1.0/24")
        ]

    def test_vrf_scoped_aggregate_native_op(self):
        pc = EOSParser(self.CONFIG).parse()
        assert [o.path for o in _aggr_ops(pc, "CCR114_CUST")] == [
            ("bgp_instances", "65000", "CCR114_CUST", "af", "ipv4", "unicast",
             "CCR114_CUST", "aggregate", "10.114.0.0/16")
        ]

    def test_flat_forms_were_the_dropped_content(self):
        # Regression guard: the VRF instance also carries its rd / neighbor /
        # instance-level redistribute (never regressed), and now ALSO the two
        # previously-dropped flat forms — so the instance is complete.
        pc = EOSParser(self.CONFIG).parse()
        bvrf = self._vrf(pc)
        assert bvrf.rd == "65000:114"
        assert [r.protocol for r in bvrf.redistribute] == ["connected"]
        assert len(bvrf.networks) == 1
        assert any(a.aggregate_addresses for a in bvrf.address_families)


# ---------------------------------------------------------------------------
# Parity — a VRF instance reaches parity with the GLOBAL instance for the flat
# forms: same ops, differing only by the two vrf-bearing path segments.
# ---------------------------------------------------------------------------

class TestEosGlobalVsVrfParity:
    # Identical flat body placed once at GLOBAL scope and once under `vrf
    # CCR114_CUST`. Both are device-established EOS flat forms (the capture of
    # record shows flat network+aggregate at BOTH the global session level and
    # as direct children of the vrf block).
    BODY = (
        "   network 10.114.1.0/24\n"
        "   aggregate-address 10.114.0.0/16 summary-only\n"
    )
    GLOBAL = "router bgp 65000\n" + BODY
    VRF = (
        "router bgp 65000\n"
        "   vrf CCR114_CUST\n"
        + "".join("   " + line for line in BODY.splitlines(keepends=True))
    )

    def _norm(self, cfg):
        # Normalize away the instance-vrf segment (index 2) and, for AF ops, the
        # af-key vrf segment (index 6). What remains must be byte-identical
        # between the global and VRF op streams — parity, not a VRF-only spelling.
        pc = EOSParser(cfg).parse()
        out = set()
        for o in _bgp_ops(pc):
            if o.verb is not Verb.SET:
                continue
            if "network" not in o.path and "aggregate" not in o.path:
                continue
            p = list(o.path)
            p[2] = "<vrf>"
            if len(p) >= 7 and p[3] == "af":
                p[6] = "<vrf>"
            out.add(tuple(p))
        return out

    def test_global_flat_network_and_aggregate_parse(self):
        pc = EOSParser(self.GLOBAL).parse()
        g = next(b for b in pc.bgp_instances if b.vrf is None)
        assert [str(n.prefix) for n in g.networks] == ["10.114.1.0/24"]
        af = next(a for a in g.address_families if (a.afi, a.safi) == ("ipv4", "unicast"))
        assert [str(a.prefix) for a in af.aggregate_addresses] == ["10.114.0.0/16"]

    def test_vrf_ops_match_global_ops_except_vrf_segments(self):
        assert self._norm(self.VRF) == self._norm(self.GLOBAL)
        # And the normalized shape is exactly the two expected members.
        assert self._norm(self.GLOBAL) == {
            ("bgp_instances", "65000", "<vrf>", "network", "10.114.1.0/24"),
            ("bgp_instances", "65000", "<vrf>", "af", "ipv4", "unicast",
             "<vrf>", "aggregate", "10.114.0.0/16"),
        }


# ---------------------------------------------------------------------------
# Cross-OS safety — an AF-nested VRF network (NX-OS / IOS-XR shape) must NOT be
# double-counted by the new flat-under-vrf walk. It stays AF-scoped: exactly one
# network op, and the instance-level BGPConfig.networks stays empty.
# ---------------------------------------------------------------------------

class TestAfNestedVrfNetworkNotDoubleCounted:
    # Device-emitted NX-OS form (syntax-corpus/nxos/bgp.yaml, verified-capture):
    # NX-OS places a VRF `network` UNDER `address-family ipv4 unicast`, never flat
    # under the vrf block — the exact shape CCR-0112 item-3 parses at AF level.
    CONFIG = (
        "feature bgp\n"
        "router bgp 65001\n"
        "  vrf CUST\n"
        "    address-family ipv4 unicast\n"
        "      network 10.1.0.0/16\n"
    )

    def _vrf(self, pc):
        return next(b for b in pc.bgp_instances if b.vrf == "CUST")

    def test_exactly_one_network_op_and_it_is_af_scoped(self):
        pc = NXOSParser(self.CONFIG).parse()
        ops = _net_ops(pc, "CUST")
        assert len(ops) == 1
        # AF-scoped path (has the `af` segment) — NOT the flat instance-level
        # shape ("bgp_instances", asn, vrf, "network", prefix).
        assert "af" in ops[0].path
        assert ops[0].path == (
            "bgp_instances", "65001", "CUST", "af", "ipv4", "unicast", "CUST",
            "network", "10.1.0.0/16",
        )

    def test_instance_level_networks_field_stays_empty(self):
        # The flat walk (_parse_bgp_networks over DIRECT children of the vrf
        # block) must NOT sweep the AF-nested network into BGPConfig.networks.
        pc = NXOSParser(self.CONFIG).parse()
        assert self._vrf(pc).networks == []

    def test_af_still_carries_the_network(self):
        pc = NXOSParser(self.CONFIG).parse()
        af = next(
            a for a in self._vrf(pc).address_families
            if (a.afi, a.safi) == ("ipv4", "unicast")
        )
        assert [str(n.prefix) for n in af.networks] == ["10.1.0.0/16"]
