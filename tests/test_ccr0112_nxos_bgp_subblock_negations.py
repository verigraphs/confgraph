"""CCR-0112 — NX-OS BGP sub-block blindness.

Three NX-OS BGP sub-block parsing gaps sharing one root cause (the shared
``_parse_bgp_vrf_blocks`` walker + the neighbor sub-mode walker):

1. Indented neighbor sub-mode negations (``no next-hop-self`` under the
   neighbor address-family, ``no description`` at session level) emitted
   nothing.
2. VRF-block negations (``no neighbor <ip>`` / ``no neighbor <ip> <attr>``
   inside ``vrf NAME``) emitted nothing.
3. VRF-instance address-family positive content (``network``) was dropped
   (``address_families == []`` hardcoded).

Since v0.3.6 ``BGPConfig.no_commands`` is empty for every OS; the negation
surface is the native ``ChangeOp`` stream (``ParsedConfig.native_change_ops``).
The parity target is therefore the native op the equivalent flat/global-path
spelling emits:

    UNSET     (bgp_instance, <asn>, <vrf>, field, neighbor, <peer>, <field>)
    OBJECT_DELETE (bgp_instance, <asn>, <vrf>, neighbor, <peer>)

Fixture syntax note (novel-syntax gate): NX-OS emits ``next-hop-self`` UNDER
``address-family ipv4 unicast`` and ``description`` at the neighbor session
level (syntax-corpus/nxos/bgp.yaml, verified-capture n9kv 10.3(8)); the
negations here sit at those same, device-verified locations.
"""

from __future__ import annotations

from confgraph.change_ir import Verb
from confgraph.parsers.eos_parser import EOSParser
from confgraph.parsers.nxos_parser import NXOSParser


def _parse(config: str):
    return NXOSParser(config).parse()


def _bgp_ops(pc):
    return [
        o
        for o in (pc.native_change_ops or [])
        if o.path and o.path[0] in ("bgp_instance", "bgp_instances")
    ]


def _find_op(pc, verb, path):
    return [o for o in _bgp_ops(pc) if o.verb is verb and o.path == path]


# ---------------------------------------------------------------------------
# Item 1 — indented neighbor sub-mode negations
# ---------------------------------------------------------------------------

class TestSubModeNeighborNegations:
    # Session-level `no description` + address-family-level `no next-hop-self`,
    # both at the device-verified locations (corpus n9kv 10.3(8)).
    CONFIG = (
        "feature bgp\n"
        "router bgp 65001\n"
        "  neighbor 10.0.0.1\n"
        "    remote-as 65002\n"
        "    no description\n"
        "    address-family ipv4 unicast\n"
        "      no next-hop-self\n"
    )

    def test_session_level_no_description_emits_field_reset(self):
        pc = _parse(self.CONFIG)
        assert _find_op(
            pc,
            Verb.UNSET,
            ("bgp_instance", "65001", "", "field", "neighbor", "10.0.0.1", "description"),
        )

    def test_af_level_no_next_hop_self_emits_field_reset(self):
        pc = _parse(self.CONFIG)
        assert _find_op(
            pc,
            Verb.UNSET,
            ("bgp_instance", "65001", "", "field", "neighbor", "10.0.0.1", "next_hop_self"),
        )

    def test_parity_with_flat_global_spelling(self):
        # The sub-mode op is byte-identical (path + verb) to the op the flat
        # global-path spelling `no neighbor 10.0.0.1 next-hop-self` already
        # emits via _parse_bgp_neighbor_tombstones — same registry, same
        # emission path. Assert the produced op matches that documented shape.
        pc = _parse(self.CONFIG)
        submode = [
            o
            for o in _bgp_ops(pc)
            if o.verb is Verb.UNSET
            and o.path[3:] == ("field", "neighbor", "10.0.0.1", "next_hop_self")
        ]
        assert len(submode) == 1
        assert submode[0].path == (
            "bgp_instance", "65001", "", "field", "neighbor", "10.0.0.1", "next_hop_self",
        )

    def test_pre_fix_gap_is_closed_not_silent(self):
        # A neighbor with only a negation (no positive next-hop-self) is
        # indistinguishable from never-set at the model level (both read
        # next_hop_self=False); the negation now survives as an explicit op.
        pc = _parse(self.CONFIG)
        neg_ops = [
            o for o in _bgp_ops(pc)
            if o.verb is Verb.UNSET and "neighbor" in o.path and "10.0.0.1" in o.path
        ]
        assert len(neg_ops) == 2  # description + next_hop_self


# ---------------------------------------------------------------------------
# Item 2 — VRF-block negations
# ---------------------------------------------------------------------------

class TestVrfBlockNegations:
    CONFIG = (
        "feature bgp\n"
        "router bgp 65001\n"
        "  vrf CUST\n"
        "    no neighbor 10.0.0.2\n"
        "    neighbor 10.0.0.3\n"
        "      remote-as 65003\n"
        "      address-family ipv4 unicast\n"
        "        no next-hop-self\n"
    )

    def test_vrf_full_removal_emits_scoped_object_delete(self):
        pc = _parse(self.CONFIG)
        assert _find_op(
            pc,
            Verb.OBJECT_DELETE,
            ("bgp_instance", "65001", "CUST", "neighbor", "10.0.0.2"),
        )

    def test_vrf_scoped_field_reset_from_submode_negation(self):
        pc = _parse(self.CONFIG)
        assert _find_op(
            pc,
            Verb.UNSET,
            ("bgp_instance", "65001", "CUST", "field", "neighbor", "10.0.0.3", "next_hop_self"),
        )

    def test_vrf_negation_scope_is_not_global(self):
        # The VRF removal must NOT leak to the vrf="" (global) scope.
        pc = _parse(self.CONFIG)
        assert not _find_op(
            pc,
            Verb.OBJECT_DELETE,
            ("bgp_instance", "65001", "", "neighbor", "10.0.0.2"),
        )


# ---------------------------------------------------------------------------
# Item 3 — VRF-instance address-family positive content
# ---------------------------------------------------------------------------

class TestVrfAfNetwork:
    CONFIG = (
        "feature bgp\n"
        "router bgp 65001\n"
        "  vrf CUST\n"
        "    address-family ipv4 unicast\n"
        "      network 10.1.0.0/16\n"
    )

    def _vrf(self, pc):
        return next(b for b in pc.bgp_instances if b.vrf == "CUST")

    def test_vrf_address_family_parsed(self):
        pc = _parse(self.CONFIG)
        bvrf = self._vrf(pc)
        assert len(bvrf.address_families) == 1
        af = bvrf.address_families[0]
        assert (af.afi, af.safi, af.vrf) == ("ipv4", "unicast", "CUST")

    def test_vrf_af_network_parsed(self):
        pc = _parse(self.CONFIG)
        af = self._vrf(pc).address_families[0]
        assert [str(n.prefix) for n in af.networks] == ["10.1.0.0/16"]

    def test_vrf_af_network_emits_native_op(self):
        pc = _parse(self.CONFIG)
        net_ops = [
            o for o in _bgp_ops(pc)
            if o.path[2] == "CUST" and "network" in o.path and "10.1.0.0/16" in o.path
        ]
        assert len(net_ops) == 1


# ---------------------------------------------------------------------------
# Item 3 (parity extension) — a VRF-instance address-family parses the FULL
# global-path AF content (not just `network`) and emits the same VRF-scoped ops.
# ---------------------------------------------------------------------------

class TestVrfAfFullParity:
    # Device-EMITTED NX-OS forms (syntax-corpus/nxos/bgp.yaml):
    #   redistribute direct route-map <RM>       — verified-capture
    #     (global-af-network-redistribute, ctx "router bgp / address-family
    #      ipv4 unicast"; emitted verbatim)
    #   aggregate-address <cidr> summary-only     — verified-capture
    #     (af-network-aggregate-withdrawal, n9kv 10.5(5); classless CIDR)
    #   maximum-paths <n> / maximum-paths ibgp <n> — emitted verbatim inside the
    #     AF sub-mode (doc-only, slug af-maximum-paths-multipath: Nexus 9000
    #     10.3(x) cmd-ref `maximum-paths [ibgp] <n>`). The default is 1 for BOTH
    #     eBGP and iBGP, and NX-OS suppresses a value == default (same nvgen
    #     behaviour the corpus captured for IS-IS); 4 and 2 are non-default, so
    #     the device DOES echo them. Same token in a VRF, one nesting level deeper.
    # Same content is placed once at the GLOBAL scope and once inside `vrf CUST`;
    # the two parse + emit identically except for the vrf segments.
    AF_BODY = (
        "    network 10.1.0.0/16\n"
        "    redistribute direct route-map RM\n"
        "    aggregate-address 10.2.0.0/16 summary-only\n"
        "    maximum-paths 4\n"
        "    maximum-paths ibgp 2\n"
    )
    GLOBAL = (
        "feature bgp\n"
        "router bgp 65001\n"
        "  address-family ipv4 unicast\n"
        + AF_BODY
    )
    VRF = (
        "feature bgp\n"
        "router bgp 65001\n"
        "  vrf CUST\n"
        "    address-family ipv4 unicast\n"
        + "".join("  " + line for line in AF_BODY.splitlines(keepends=True))
    )

    def _vrf_af(self, pc):
        bvrf = next(b for b in pc.bgp_instances if b.vrf == "CUST")
        assert len(bvrf.address_families) == 1
        return bvrf.address_families[0]

    def test_model_carries_every_field(self):
        af = self._vrf_af(_parse(self.VRF))
        assert (af.afi, af.safi, af.vrf) == ("ipv4", "unicast", "CUST")
        assert [str(n.prefix) for n in af.networks] == ["10.1.0.0/16"]
        assert [r.protocol for r in af.redistribute] == ["direct"]
        assert [str(a.prefix) for a in af.aggregate_addresses] == ["10.2.0.0/16"]
        assert af.maximum_paths == 4
        assert af.maximum_paths_ibgp == 2

    def test_vrf_scoped_redistribute_op_emitted(self):
        pc = _parse(self.VRF)
        assert [
            o.path for o in _bgp_ops(pc)
            if o.path[2] == "CUST" and "af" in o.path and "redistribute" in o.path
        ] == [("bgp_instances", "65001", "CUST", "af", "ipv4", "unicast", "CUST",
               "redistribute", "direct", "")]

    def test_vrf_scoped_aggregate_op_emitted(self):
        pc = _parse(self.VRF)
        assert [
            o.path for o in _bgp_ops(pc)
            if o.path[2] == "CUST" and "af" in o.path and "aggregate" in o.path
        ] == [("bgp_instances", "65001", "CUST", "af", "ipv4", "unicast", "CUST",
               "aggregate", "10.2.0.0/16")]

    def test_vrf_scoped_scalar_ops_emitted(self):
        pc = _parse(self.VRF)
        scalars = {
            o.path[-1]: o.value for o in _bgp_ops(pc)
            if o.path[2] == "CUST" and "af" in o.path and "scalar" in o.path
        }
        assert scalars.get("maximum_paths") == 4
        assert scalars.get("maximum_paths_ibgp") == 2

    def test_parity_ops_identical_except_vrf_segments(self):
        # Normalize away the two vrf-bearing path segments (the instance vrf at
        # index 2 and the af-key vrf at index 6); the VRF AF's op stream must
        # then be byte-identical to the GLOBAL AF's — proving parity, not a
        # divergent VRF-only spelling.
        def norm_af_ops(cfg):
            pc = _parse(cfg)
            out = set()
            for o in _bgp_ops(pc):
                if len(o.path) >= 7 and o.path[3] == "af":
                    p = list(o.path)
                    p[2] = ""   # instance vrf scope
                    p[6] = ""   # af-key vrf
                    out.add((o.verb, tuple(p)))
            return out

        assert norm_af_ops(self.VRF) == norm_af_ops(self.GLOBAL)


# ---------------------------------------------------------------------------
# Item 3 (parity extension, instance-level redistribute double-count) — a VRF
# ``redistribute`` nested inside an ``address-family`` sub-block must emit ONLY
# the AF-level op (parity with global). The instance-level VRF redistribute walk
# now reads DIRECT children of the ``vrf NAME`` block, mirroring the global
# instance-level walk (``_parse_bgp_redistribute`` over ``bgp_obj.children``),
# so an AF-nested line no longer also emits a spurious instance-level op.
# ---------------------------------------------------------------------------

class TestVrfRedistributeInstanceVsAf:
    # ---- AF-nested (NX-OS) ----------------------------------------------
    # `redistribute direct route-map RM` inside a VRF's `address-family ipv4
    # unicast` is a verified-capture NX-OS form (syntax-corpus/nxos/bgp.yaml,
    # global-af-network-redistribute) — the same line the item-3 parity fixture
    # (TestVrfAfFullParity) already exercises. NX-OS emits `redistribute` ONLY
    # inside an address-family, never at the vrf instance level.
    VRF_AF_NESTED = (
        "feature bgp\n"
        "router bgp 65001\n"
        "  vrf CUST\n"
        "    address-family ipv4 unicast\n"
        "      redistribute direct route-map RM\n"
    )
    # ---- instance-level (EOS) -------------------------------------------
    # EOS is the OS in the shared `_parse_bgp_vrf_blocks` path that emits
    # `redistribute` DIRECTLY under `router bgp <asn>` / `vrf NAME` (not in an
    # address-family). `redistribute connected` is verified-capture from cEOS
    # 4.36.1F (syntax-corpus/eos/bgp.yaml, the `vrf <vrf-name>` block entry).
    EOS_VRF_INSTANCE_LEVEL = (
        "router bgp 65000\n"
        "   vrf CUSTOMER_A\n"
        "      rd 65000:100\n"
        "      neighbor 192.168.10.2 remote-as 65100\n"
        "      redistribute connected\n"
    )

    def _redist_ops(self, pc):
        return [o for o in _bgp_ops(pc) if "redistribute" in o.path]

    def _instance_level_redist_ops(self, pc, vrf):
        # instance-level VRF redistribute op has NO `af` segment; shape is
        # (bgp_instances, <asn>, <vrf>, redistribute, <proto>, <pid>)
        return [
            o for o in self._redist_ops(pc)
            if o.path[2] == vrf and "af" not in o.path
        ]

    def _af_level_redist_ops(self, pc, vrf):
        return [
            o for o in self._redist_ops(pc)
            if o.path[2] == vrf and "af" in o.path
        ]

    def test_af_nested_redistribute_emits_only_af_op(self):
        # The whole point of the fix: exactly ONE redistribute op for CUST, and
        # it is AF-scoped. No spurious instance-level duplicate.
        pc = _parse(self.VRF_AF_NESTED)
        assert len(self._redist_ops(pc)) == 1
        assert self._instance_level_redist_ops(pc, "CUST") == []
        assert [o.path for o in self._af_level_redist_ops(pc, "CUST")] == [
            ("bgp_instances", "65001", "CUST", "af", "ipv4", "unicast", "CUST",
             "redistribute", "direct", "")
        ]

    def test_af_nested_redistribute_absent_from_bgpconfig(self):
        # The VRF BGPConfig.redistribute field must NOT carry AF-nested entries —
        # matching the global instance, whose .redistribute also excludes them.
        pc = _parse(self.VRF_AF_NESTED)
        bvrf = next(b for b in pc.bgp_instances if b.vrf == "CUST")
        assert bvrf.redistribute == []

    def test_instance_level_redistribute_still_emits_instance_op(self):
        # A redistribute directly under `vrf NAME` (not in an AF) is unchanged by
        # the fix: it is a DIRECT child of the vrf block, so it still emits its
        # instance-level op and still populates BGPConfig.redistribute. Uses the
        # EOS device-emitted `redistribute connected` shape through the shared
        # `_parse_bgp_vrf_blocks` path.
        pc = EOSParser(self.EOS_VRF_INSTANCE_LEVEL).parse()
        inst_ops = self._instance_level_redist_ops(pc, "CUSTOMER_A")
        assert [o.path for o in inst_ops] == [
            ("bgp_instances", "65000", "CUSTOMER_A", "redistribute", "connected", "")
        ]
        assert self._af_level_redist_ops(pc, "CUSTOMER_A") == []
        bvrf = next(b for b in pc.bgp_instances if b.vrf == "CUSTOMER_A")
        assert [r.protocol for r in bvrf.redistribute] == ["connected"]


# ---------------------------------------------------------------------------
# Sibling guard — the sub-mode walk is NX-OS-scoped (IOSParser hook is a no-op)
# ---------------------------------------------------------------------------

def test_iosparser_submode_hook_is_noop():
    from confgraph.parsers.ios_parser import IOSParser
    # The base hook emits nothing; IOS / IOS-XR / EOS express neighbor
    # negations as flat `no neighbor X <attr>` lines, not indented sub-mode.
    parser = IOSParser("router bgp 65001\n neighbor 10.0.0.1 remote-as 65002\n")
    parser._pending_native_bgp_ops = []
    parser._emit_bgp_neighbor_submode_negations(
        parser._get_parse_obj().find_objects(r"^router bgp")[0],
        65001,
        None,
        set(),
    )
    assert parser._pending_native_bgp_ops == []
