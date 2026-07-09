"""WI-DB2 — family-6 deferred IGP withdrawal negations (CCR Appendix AD).

The five owner-approved withdrawal spellings deferred by Appendices N.8
(EIGRP ``no redistribute``), O.4/O.7 (OSPF ``no redistribute`` /
``no default-information originate``) and P.7 (OSPF ``no area N
virtual-link`` / ``no area N filter-list … in|out``):

- each emits a NATIVE line-numbered op whose path IS the colon-split of a
  byte-exact legacy twin tombstone ``field:{ospf|eigrp}:<id>:<vrf>:…``
  (VRF-SCOPED — the B1 posture: legacy gains the fix; unlike the ops-only
  family-6 ``no network`` / area-range removals),
- twins are regenerated FROM the ops via ``encode_legacy`` (single source)
  and drained into ``no_commands`` by ``parse_deletion_commands``,
- the WI-8 ``_readded_later`` suppression is shared by op AND twin: a
  refresh (negation, then positive re-add later in the block) emits NEITHER
  → re-add wins in BOTH modes; add-then-remove stands,
- over-trigger discipline: bare / trailered / non-whitelisted forms stay
  blind (enumerated in Appendix AD),
- ``derive_ops`` exact-path dedupe retires the derived twins (exactly one
  op per spelling in the composed ChangeSet, origin native).
"""

from __future__ import annotations

from confgraph.change_ir import (
    Verb,
    derive_ops,
    encode_legacy,
    is_native_eigrp_field_negation_op,
    is_native_eigrp_op,
    is_native_ospf_field_negation_op,
    is_native_ospf_op,
)
from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.iosxr_parser import IOSXRParser
from confgraph.parsers.nxos_parser import NXOSParser


def _parse(text: str, parser_cls=IOSParser):
    return parser_cls(text).parse()


def _neg_ops(pc):
    return [
        op
        for op in pc.native_change_ops
        if is_native_ospf_field_negation_op(op)
        or is_native_eigrp_field_negation_op(op)
    ]


WITHDRAWALS = (
    "router ospf 1\n"
    " network 192.0.2.0 0.0.0.255 area 0\n"
    " no redistribute static\n"
    " no redistribute bgp 65001\n"
    " no default-information originate\n"
    " no area 1 virtual-link 3.3.3.3\n"
    " no area 1 filter-list prefix BLOCK in\n"
    " no area 2 filter-list prefix BLOCK out\n"
    "router eigrp 100\n"
    " network 10.0.0.0\n"
    " no redistribute ospf 1\n"
    " no redistribute static\n"
)


class TestEmission:
    def test_all_five_spellings_emit_native_ops_with_twins(self):
        pc = _parse(WITHDRAWALS)
        ops = {op.path: op for op in _neg_ops(pc)}
        assert set(ops) == {
            ("field", "ospf", "1", "", "redistribute", "static", ""),
            ("field", "ospf", "1", "", "redistribute", "bgp", "65001"),
            ("field", "ospf", "1", "", "default_information_originate"),
            ("field", "ospf", "1", "", "area", "1", "virtual_link", "3.3.3.3"),
            ("field", "ospf", "1", "", "area", "1", "filter_list_in"),
            ("field", "ospf", "1", "", "area", "2", "filter_list_out"),
            ("field", "eigrp", "100", "", "redistribute", "ospf", "1"),
            ("field", "eigrp", "100", "", "redistribute", "static", ""),
        }
        # Verbs: keyed removals → LIST_REMOVE, field resets → UNSET.
        assert ops[("field", "ospf", "1", "", "redistribute", "static", "")].verb is Verb.LIST_REMOVE
        assert ops[("field", "ospf", "1", "", "default_information_originate")].verb is Verb.UNSET
        assert ops[("field", "ospf", "1", "", "area", "1", "virtual_link", "3.3.3.3")].verb is Verb.LIST_REMOVE
        assert ops[("field", "ospf", "1", "", "area", "1", "filter_list_in")].verb is Verb.UNSET
        assert ops[("field", "eigrp", "100", "", "redistribute", "ospf", "1")].verb is Verb.LIST_REMOVE
        # Line-anchored provenance, origin native.
        for op in ops.values():
            assert op.origin == "native"
            assert op.line_no >= 0
            assert op.source_line.startswith("no ")
        # Byte-exact twins in no_commands (drained by parse_deletion_commands),
        # exactly the colon-join of each path.
        for path in ops:
            assert ":".join(path) in pc.no_commands

    def test_twin_equals_encode_legacy_roundtrip(self):
        pc = _parse(WITHDRAWALS)
        composed = derive_ops(pc)
        art = encode_legacy(composed)
        for op in _neg_ops(pc):
            twin = ":".join(op.path)
            assert art.no_commands.count(twin) == 1  # exactly once — no double-encode
            assert pc.no_commands.count(twin) == 1

    def test_derived_twin_retired_by_exact_path_dedupe(self):
        pc = _parse(WITHDRAWALS)
        composed = derive_ops(pc)
        for op in composed:
            if op.path[:2] in (("field", "ospf"), ("field", "eigrp")):
                assert op.origin == "native"

    def test_predicates_owned_by_codec(self):
        pc = _parse(WITHDRAWALS)
        for op in _neg_ops(pc):
            if op.path[1] == "ospf":
                assert is_native_ospf_op(op)
                assert not is_native_eigrp_op(op)
            else:
                assert is_native_eigrp_op(op)
                assert not is_native_ospf_op(op)

    def test_vrf_scoped_emission(self):
        pc = _parse(
            "router ospf 1 vrf CUST\n"
            " network 10.0.0.0 0.0.0.255 area 0\n"
            " no redistribute static\n"
        )
        (op,) = _neg_ops(pc)
        assert op.path == ("field", "ospf", "1", "CUST", "redistribute", "static", "")
        assert "field:ospf:1:CUST:redistribute:static:" in pc.no_commands

    def test_virtual_link_rid_canonicalized_like_positive_parse(self):
        # Unparseable router-id → blind on BOTH walks (positive drops it too).
        pc = _parse(
            "router ospf 1\n"
            " no area 1 virtual-link not-an-ip\n"
        )
        assert _neg_ops(pc) == []
        assert pc.no_commands == []


class TestSuppressionShapes:
    def test_refresh_suppressed_neither_op_nor_twin(self):
        # negation first, positive re-add LATER → re-add wins in BOTH modes.
        pc = _parse(
            "router ospf 1\n"
            " no redistribute static\n"
            " redistribute static subnets\n"
            " no default-information originate\n"
            " default-information originate always\n"
            " no area 1 virtual-link 3.3.3.3\n"
            " area 1 virtual-link 3.3.3.3\n"
            " no area 1 filter-list prefix OLD in\n"
            " area 1 filter-list prefix NEW in\n"
            "router eigrp 100\n"
            " no redistribute static\n"
            " redistribute static\n"
        )
        assert _neg_ops(pc) == []
        assert pc.no_commands == []

    def test_add_then_remove_stands(self):
        pc = _parse(
            "router ospf 1\n"
            " redistribute static subnets\n"
            " no redistribute static\n"
        )
        (op,) = _neg_ops(pc)
        assert op.path == ("field", "ospf", "1", "", "redistribute", "static", "")

    def test_refresh_suppression_is_key_exact(self):
        # A LATER positive for a DIFFERENT key must NOT suppress the removal.
        pc = _parse(
            "router ospf 1\n"
            " no redistribute static\n"
            " redistribute connected subnets\n"
            " no area 1 filter-list prefix PL in\n"
            " area 1 filter-list prefix PL out\n"
            " no area 1 virtual-link 3.3.3.3\n"
            " area 1 virtual-link 4.4.4.4\n"
        )
        paths = {op.path for op in _neg_ops(pc)}
        assert ("field", "ospf", "1", "", "redistribute", "static", "") in paths
        assert ("field", "ospf", "1", "", "area", "1", "filter_list_in") in paths
        assert ("field", "ospf", "1", "", "area", "1", "virtual_link", "3.3.3.3") in paths

    def test_filter_suppression_is_direction_and_name_blind(self):
        # A later positive for the SAME (area, direction) suppresses even
        # with a different PL name — the fresh PL must win.
        pc = _parse(
            "router ospf 1\n"
            " no area 1 filter-list prefix OLD in\n"
            " area 1 filter-list prefix NEW in\n"
        )
        assert _neg_ops(pc) == []


class TestOverTriggerBoundary:
    """Forms that MUST stay blind (enumerated in Appendix AD)."""

    BLIND = (
        "router ospf 1\n"
        " no redistribute\n"                                   # bare
        " no redistribute maximum-prefix 100\n"                # non-protocol token
        " no redistribute static route-map RM\n"               # trailered (option removal)
        " no redistribute static subnets\n"                    # trailered
        " no redistribute rip 5\n"                             # pid on pid-less proto
        " no default-information\n"                            # bare
        " no default-information originate always\n"           # option negation
        " no default-information originate metric 5\n"         # option negation
        " no area 1 virtual-link\n"                            # router-id-less
        " no area 1 virtual-link 3.3.3.3 hello-interval 5\n"   # option negation
        " no area 1 filter-list\n"                             # bare
        " no area 1 filter-list prefix PL\n"                   # direction-less
        " no area 1 filter-list route-map RM in\n"             # NX-OS route-map form
        "router eigrp 100\n"
        " no redistribute\n"
        " no redistribute maximum-prefix 100\n"
        " no redistribute static metric 1 1 1 1 1\n"
        " no redistribute isis 1\n"                            # pid on pid-less proto (EIGRP)
    )

    def test_partial_and_trailered_forms_stay_blind(self):
        pc = _parse(self.BLIND)
        assert _neg_ops(pc) == []
        assert pc.no_commands == []

    def test_positive_walks_untouched_by_negations(self):
        pc = _parse(WITHDRAWALS)
        # The negation lines never leak into the positive model.
        (ospf,) = pc.ospf_instances
        assert ospf.redistribute == []
        assert ospf.default_information_originate is False
        assert ospf.areas == []  # no positive area content
        (eigrp,) = pc.eigrp_instances
        assert eigrp.redistribute == []


class TestPerOS:
    def test_nxos_inherits_the_walks(self):
        pc = _parse(
            "router ospf 1\n"
            " no redistribute static\n"
            " no default-information originate\n"
            "router eigrp 100\n"
            " no redistribute static\n",
            NXOSParser,
        )
        paths = {op.path for op in _neg_ops(pc)}
        assert ("field", "ospf", "1", "", "redistribute", "static", "") in paths
        assert ("field", "ospf", "1", "", "default_information_originate") in paths
        assert ("field", "eigrp", "100", "", "redistribute", "static", "") in paths
        for op in _neg_ops(pc):
            assert ":".join(op.path) in pc.no_commands

    def test_iosxr_ospf_absent_eigrp_ops_only(self):
        # IOS-XR has its OWN parse_ospf (no walks) and its OWN
        # parse_deletion_commands (no super → no twins).  The inherited
        # parse_eigrp still emits the native op — ops-only on XR (the
        # family-6b `no network` posture), disclosed in Appendix AD.
        pc = _parse(
            "router ospf 1\n"
            " no redistribute static\n"
            "router eigrp 100\n"
            " no redistribute static\n",
            IOSXRParser,
        )
        paths = {op.path for op in _neg_ops(pc)}
        assert ("field", "ospf", "1", "", "redistribute", "static", "") not in paths
        assert ("field", "eigrp", "100", "", "redistribute", "static", "") in paths
        assert all(not t.startswith("field:eigrp:") for t in pc.no_commands)
        assert all(not t.startswith("field:ospf:") for t in pc.no_commands)


class TestRegressionPins:
    def test_stub_nssa_resets_stay_derived_beside_db2_ops(self):
        # The K.3/P.2 machinery is untouched: stub/nssa resets keep their
        # DERIVED byte-exact tombstones beside the new native withdrawals.
        pc = _parse(
            "router ospf 1\n"
            " no area 1 stub\n"
            " no redistribute static\n"
        )
        assert "field:ospf:1:area:1:stub_reset" in pc.no_commands
        assert "field:ospf:1::redistribute:static:" in pc.no_commands
        composed = derive_ops(pc)
        stub = [op for op in composed if op.path == ("field", "ospf", "1", "area", "1", "stub_reset")]
        assert len(stub) == 1 and stub[0].origin == "derived"

    def test_ops_only_removals_still_twinless(self):
        # `no network` / `no area N range` stay ops-only (no legacy twin).
        pc = _parse(
            "router ospf 1\n"
            " no network 10.0.0.0 0.0.0.255 area 0\n"
            " no area 1 range 10.1.0.0 255.255.0.0\n"
        )
        assert pc.no_commands == []
        assert len([op for op in pc.native_change_ops if op.path[0] == "ospf_instance"]) == 2

    def test_no_spelling_no_artifacts(self):
        pc = _parse(
            "router ospf 1\n"
            " network 192.0.2.0 0.0.0.255 area 0\n"
            " redistribute static subnets\n"
            " default-information originate always\n"
            " area 1 virtual-link 3.3.3.3\n"
            " area 1 filter-list prefix PL in\n"
            "router eigrp 100\n"
            " network 10.0.0.0\n"
            " redistribute static\n"
        )
        assert _neg_ops(pc) == []
        assert pc.no_commands == []
