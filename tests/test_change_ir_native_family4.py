"""Change-IR Phase 3, family 4 — native static-route op emission.

CCR: ``change_ir_proposal_operations.md`` Appendix G (WI-17).

Covers:
- the family-4 boundary registry (``static_route_fields``), the key helper
  (``static_route_key``) and the codec-owned ``is_native_static_op`` predicate,
- native emission for BOTH sides: create-side ``SET ("static_routes", *key)``
  from final state and delete-side ``LIST_REMOVE ("static", …)`` at true
  script positions, line-ordered so delete-then-readd and add-then-delete are
  distinct sequences,
- single-source tombstones (byte-identical via ``encode_legacy``, emitted
  unconditionally — statics have no ``_readded_later`` guard),
- hybrid ``derive_ops`` composition: exact-path dedupe retires the derived
  static SET/LIST_REMOVE, anti-rot for families 1–4, natives-less fallback,
- NX-OS (global + ``vrf context``) and EOS inheritance.
"""

from __future__ import annotations

from confgraph.change_ir import (
    ChangeOp,
    Verb,
    derive_ops,
    encode_legacy,
    is_native_service_entity_op,
    is_native_static_op,
    static_route_fields,
    static_route_key,
)
from confgraph.parsers.eos_parser import EOSParser
from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.nxos_parser import NXOSParser


def _parse(text: str, parser_cls=IOSParser):
    return parser_cls(text).parse()


def _f4_ops(pc):
    return [op for op in pc.native_change_ops if is_native_static_op(op)]


def _sets(ops):
    return [op for op in ops if op.verb is Verb.SET and op.path[0] == "static_routes"]


def _removes(ops):
    return [op for op in ops if op.verb is Verb.LIST_REMOVE and op.path[0] == "static"]


KITCHEN_SINK = (
    "interface GigabitEthernet0/0\n"
    " mtu 9000\n"
    " no ip ospf cost\n"
    "ip route 10.50.0.0 255.255.0.0 10.1.1.253\n"
    "no ip route 10.99.0.0 255.255.0.0 10.1.1.254\n"
    "no ip route vrf CUST 192.168.0.0 255.255.0.0\n"
    "ip route 0.0.0.0 0.0.0.0 10.0.0.185 track 1\n"
    "ntp server 10.0.0.10\n"
    "no ip sla 10\n"
)

# delete-then-readd of the SAME (prefix+NH) route — device nets to PRESENT
# (W5).  Legacy adds-then-deletes drops it.
DEL_THEN_READD = (
    "no ip route 10.0.0.0 255.0.0.0 10.1.1.1\n"
    "ip route 10.0.0.0 255.0.0.0 10.1.1.1\n"
)

# add-then-delete — device nets to ABSENT.
ADD_THEN_DEL = (
    "ip route 20.0.0.0 255.0.0.0 10.9.9.9\n"
    "no ip route 20.0.0.0 255.0.0.0 10.9.9.9\n"
)


# ---------------------------------------------------------------------------
# Family boundary + codec
# ---------------------------------------------------------------------------


class TestFamilyBoundary:
    def test_boundary_is_static_routes(self):
        assert static_route_fields() == frozenset({"static_routes"})

    def test_disjoint_from_family3(self):
        # A static SET must NOT be misread as a service-entity op and vice-versa.
        pc = _parse(KITCHEN_SINK)
        for op in _f4_ops(pc):
            assert not is_native_service_entity_op(op)
        for op in pc.native_change_ops:
            if is_native_service_entity_op(op):
                assert not is_native_static_op(op)

    def test_key_matches_deriver_identity(self):
        pc = _parse("ip route 10.0.0.0 255.0.0.0 10.1.1.1\n")
        route = pc.static_routes[0]
        # ("static_routes", *key) is exactly the derived keyed-list SET path.
        assert static_route_key(route) == ("", "10.0.0.0/8", "10.1.1.1|")

    def test_predicate_shapes(self):
        for op in [
            ChangeOp(Verb.SET, ("static_routes", "", "10.0.0.0/8", "10.1.1.1|"),
                     origin="native"),
            ChangeOp(Verb.LIST_REMOVE, ("static", "", "10.0.0.0/8", "10.1.1.1"),
                     origin="native"),
            ChangeOp(Verb.LIST_REMOVE, ("static", "CUST", "192.168.0.0/16"),
                     origin="native"),
        ]:
            assert is_native_static_op(op)

    def test_predicate_rejects_derived_and_other_shapes(self):
        for op in [
            # origin gate: identical paths, derived — keep the legacy path.
            ChangeOp(Verb.SET, ("static_routes", "", "10.0.0.0/8", "10.1.1.1|")),
            ChangeOp(Verb.LIST_REMOVE, ("static", "", "10.0.0.0/8")),
            # other native families:
            ChangeOp(Verb.SET, ("ip_sla_operations", "10"), origin="native"),
            ChangeOp(Verb.OBJECT_DELETE, ("field", "vrfs", "GUEST"),
                     origin="native"),
            ChangeOp(Verb.LIST_ADD,
                     ("field", "interface", "Gi0/0", "trunk_allowed_vlans",
                      "add", "30"), origin="native"),
        ]:
            assert not is_native_static_op(op)


# ---------------------------------------------------------------------------
# Native emission — both sides, provenance, ordering
# ---------------------------------------------------------------------------


class TestNativeEmission:
    def test_both_sides_emitted(self):
        pc = _parse(KITCHEN_SINK)
        sets = _sets(_f4_ops(pc))
        removes = _removes(_f4_ops(pc))
        # two positive routes → two SETs; two `no ip route` → two LIST_REMOVEs.
        assert {op.path[1:] for op in sets} == {
            ("", "10.50.0.0/16", "10.1.1.253|"),
            ("", "0.0.0.0/0", "10.0.0.185|"),
        }
        assert {op.path for op in removes} == {
            ("static", "", "10.99.0.0/16", "10.1.1.254"),
            ("static", "CUST", "192.168.0.0/16"),
        }
        for op in sets + removes:
            assert op.origin == "native"

    def test_set_carries_final_state_and_block_provenance(self):
        pc = _parse("ip route 0.0.0.0 0.0.0.0 10.0.0.185 track 1\n")
        op = _sets(_f4_ops(pc))[0]
        assert op.value is pc.static_routes[0]
        assert op.value.track == 1
        assert op.source_line == "ip route 0.0.0.0 0.0.0.0 10.0.0.185 track 1"

    def test_delete_provenance_is_verbatim_line(self):
        pc = _parse("no ip route 10.99.0.0 255.255.0.0 10.1.1.254\n")
        op = _removes(_f4_ops(pc))[0]
        assert op.source_line == "no ip route 10.99.0.0 255.255.0.0 10.1.1.254"
        assert op.line_no >= 0

    def test_delete_then_readd_line_order(self):
        pc = _parse(DEL_THEN_READD)
        ops = _f4_ops(pc)
        # remove(line 0) then set(line 1) — script order preserved.
        assert ops[0].verb is Verb.LIST_REMOVE
        assert ops[1].verb is Verb.SET
        assert ops[0].line_no < ops[1].line_no

    def test_add_then_delete_line_order(self):
        pc = _parse(ADD_THEN_DEL)
        ops = _f4_ops(pc)
        assert ops[0].verb is Verb.SET
        assert ops[1].verb is Verb.LIST_REMOVE
        assert ops[0].line_no < ops[1].line_no

    def test_nh_less_delete_is_wildcard_path(self):
        pc = _parse("no ip route 10.0.0.0 255.0.0.0\n")
        op = _removes(_f4_ops(pc))[0]
        assert op.path == ("static", "", "10.0.0.0/8")  # no NH segment

    def test_vrf_scoped_delete(self):
        pc = _parse("no ip route vrf CUST 192.168.0.0 255.255.0.0 10.9.9.9\n")
        op = _removes(_f4_ops(pc))[0]
        assert op.path == ("static", "CUST", "192.168.0.0/16", "10.9.9.9")


# ---------------------------------------------------------------------------
# Single-source tombstones + byte-identity
# ---------------------------------------------------------------------------


class TestTombstoneSingleSource:
    def test_tombstone_regenerated_from_op_byte_exact(self):
        pc = _parse(KITCHEN_SINK)
        # Every static tombstone in no_commands is reproduced by encoding its
        # native op — the codec IS ":".join(path).
        static_tombs = [t for t in pc.no_commands if t.startswith("static:")]
        encoded = {
            ":".join(op.path) for op in _removes(_f4_ops(pc))
        }
        assert set(static_tombs) == encoded

    def test_tombstone_emitted_unconditionally_on_readd(self):
        # Statics have NO _readded_later suppression: delete-then-readd still
        # emits the tombstone (byte-identity), the ordered apply fixes the net.
        pc = _parse(DEL_THEN_READD)
        assert any(t.startswith("static:") for t in pc.no_commands)

    def test_channelized_nh_colon_survives_roundtrip(self):
        pc = _parse("no ip route 10.0.0.0 255.0.0.0 Serial0/0/0:0\n")
        tomb = next(t for t in pc.no_commands if t.startswith("static:"))
        op = _removes(_f4_ops(pc))[0]
        assert ":".join(op.path) == tomb  # colon in NH spec survives join


# ---------------------------------------------------------------------------
# Composition / dedupe / anti-rot
# ---------------------------------------------------------------------------


class TestComposition:
    def test_composed_set_has_no_derived_static_ops(self):
        pc = _parse(KITCHEN_SINK)
        ops = derive_ops(pc)
        for op in ops:
            if op.path and op.path[0] in ("static", "static_routes"):
                assert op.origin == "native", op.path

    def test_derived_static_paths_deduped(self):
        pc = _parse(KITCHEN_SINK)
        ops = derive_ops(pc)
        static_paths = [op.path for op in ops
                        if op.path and op.path[0] in ("static", "static_routes")]
        assert len(static_paths) == len(set(static_paths))  # no duplicates

    def test_anti_rot_family4_never_derived(self):
        """CCR §6 anti-rot: no family is handled by BOTH native emission and
        the deriver — every family-4 op in the composed ChangeSet is native."""
        pc = _parse(KITCHEN_SINK)
        ops = derive_ops(pc)
        seen = 0
        for op in ops:
            is_static_set = op.verb is Verb.SET and op.path[0] == "static_routes"
            is_static_del = op.verb is Verb.LIST_REMOVE and op.path[0] == "static"
            if is_static_set or is_static_del:
                assert op.origin == "native", op.path
                seen += 1
        assert seen >= 4  # 2 SET + 2 LIST_REMOVE

    def test_anti_rot_families_1_2_3_unaffected(self):
        pc = _parse(KITCHEN_SINK)
        ops = derive_ops(pc)
        for op in ops:
            if op.path[0] == "interface" and len(op.path) == 3:
                assert op.origin == "native", op.path
            if is_native_service_entity_op(
                ChangeOp(op.verb, op.path, origin="native")
            ):
                assert op.origin == "native", op.path

    def test_derived_fallback_without_natives(self):
        # A hand-built ParsedConfig with no native ops falls back to full
        # derived translation (natives-less producers keep legacy parity).
        pc = _parse(KITCHEN_SINK)
        pc.native_change_ops = None
        ops = derive_ops(pc)
        static_ops = [op for op in ops
                      if op.path and op.path[0] in ("static", "static_routes")]
        assert static_ops and all(op.origin == "derived" for op in static_ops)


# ---------------------------------------------------------------------------
# NX-OS / EOS inheritance
# ---------------------------------------------------------------------------


class TestMultiOS:
    def test_nxos_global_static(self):
        # Traditional MASK form parses on NX-OS via the shared walk → native
        # SET; global CIDR positives are the pre-existing Phase-5 debt (dropped
        # by the parser) — see test_nxos_global_cidr_positive_debt.
        pc = _parse(
            "ip route 10.0.0.0 255.255.255.0 192.0.2.1\n"
            "no ip route 10.1.0.0/24 192.0.2.2\n",
            NXOSParser,
        )
        assert _sets(_f4_ops(pc)) and _removes(_f4_ops(pc))
        for op in _f4_ops(pc):
            assert op.origin == "native"

    def test_nxos_global_cidr_positive_debt(self):
        # Pre-existing debt (Appendix G / Phase 5): NX-OS drops positive global
        # CIDR statics.  The emitter walks final state, so it emits NO SET —
        # neither fixing nor worsening the debt (legacy parity).
        pc = _parse("ip route 10.0.0.0/24 192.0.2.1\n", NXOSParser)
        assert pc.static_routes == []
        assert _sets(_f4_ops(pc)) == []

    def test_nxos_vrf_context_delete_is_native(self):
        pc = _parse(
            "vrf context TENANT\n  no ip route 10.5.0.0/24 10.9.9.9\n",
            NXOSParser,
        )
        removes = _removes(_f4_ops(pc))
        assert removes
        assert removes[0].path == ("static", "TENANT", "10.5.0.0/24", "10.9.9.9")
        assert removes[0].origin == "native"
        # tombstone byte-identity preserved
        assert "static:TENANT:10.5.0.0/24:10.9.9.9" in pc.no_commands

    def test_eos_global_static(self):
        pc = _parse(
            "ip route 10.0.0.0/24 192.0.2.1\nno ip route 10.2.0.0/24 192.0.2.9\n",
            EOSParser,
        )
        assert _removes(_f4_ops(pc))
        for op in _f4_ops(pc):
            assert op.origin == "native"
