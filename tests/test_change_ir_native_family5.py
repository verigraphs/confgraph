"""Change-IR Phase 3, family 5a — native BGP-neighbor op emission.

CCR: ``change_ir_proposal_operations.md`` Appendix H (WI-18a).

Covers:
- the family-5a boundary registry (``bgp_neighbor_fields``), the key helper
  (``bgp_neighbor_key``) and the codec-owned ``is_native_bgp_op`` predicate,
- native emission for BOTH sides: create/re-add ``SET ("bgp_instances", asn,
  vrf, "neighbor", peer)`` from final state and delete-side
  ``OBJECT_DELETE``/``UNSET`` at true script positions, line-ordered so
  delete-then-readd and reset-then-reassert are distinct sequences,
- single-source, byte-identical tombstones via ``encode_legacy`` (legacy
  ``BGPConfig.no_commands`` unchanged, including IPv6 peers),
- hybrid ``derive_ops`` composition: exact-path dedupe retires the derived
  neighbor tombstone ops AND the approved container-claim exclusion keeps the
  derived whole-instance SET alive, anti-rot for family 5a, families 1–4
  dedupe unchanged, natives-less fallback,
- NX-OS inheritance of the single-line ``no neighbor`` forms.
"""

from __future__ import annotations

from confgraph.change_ir import (
    Verb,
    bgp_neighbor_fields,
    bgp_neighbor_key,
    derive_ops,
    encode_legacy,
    is_native_bgp_op,
    is_native_service_entity_op,
    is_native_static_op,
)
from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.nxos_parser import NXOSParser


def _parse(text: str, parser_cls=IOSParser):
    return parser_cls(text).parse()


def _f5(pc):
    return [op for op in pc.native_change_ops if is_native_bgp_op(op)]


DELETE_READD = (
    "router bgp 65000\n"
    " no neighbor 10.0.0.2\n"
    " no neighbor 10.0.0.3 route-map FILTER in\n"
    " no neighbor 10.0.0.3 shutdown\n"
    " neighbor 10.0.0.2 remote-as 65001\n"
    " neighbor 10.0.0.2 description NEW\n"
    " neighbor 10.0.0.9 remote-as 65009\n"
)


class TestBoundaryAndPredicate:
    def test_boundary_registry(self):
        assert bgp_neighbor_fields() == frozenset({"neighbors"})

    def test_key_is_single_element_even_ipv6(self):
        pc = _parse("router bgp 65000\n neighbor 2001:db8::1 remote-as 65001\n")
        nb = pc.bgp_instances[0].neighbors[0]
        assert bgp_neighbor_key(nb) == ("2001:db8::1",)

    def test_predicate_shapes(self):
        setop = _parse(
            "router bgp 65000\n neighbor 10.0.0.9 remote-as 65009\n"
        ).native_change_ops
        assert any(
            is_native_bgp_op(o) and o.verb is Verb.SET for o in setop
        )
        # derived twin (same path, origin derived) is NOT recognised.
        for o in setop:
            if is_native_bgp_op(o):
                twin = o.__class__(o.verb, o.path, origin="derived")
                assert not is_native_bgp_op(twin)


class TestEmission:
    def test_both_sides_and_ordering(self):
        pc = _parse(DELETE_READD)
        ops = _f5(pc)
        # ordered by line: del 10.0.0.2 (l2), unset route_map_in (l3),
        # unset shutdown (l4), set 10.0.0.2 (l6 — the re-add), set 10.0.0.9.
        seq = [(o.verb, o.path[-1]) for o in ops]
        assert (Verb.OBJECT_DELETE, "10.0.0.2") in seq
        assert (Verb.UNSET, "route_map_in") in seq
        assert (Verb.SET, "10.0.0.2") in seq
        # the re-add SET comes AFTER the delete (positive-after-negation)
        del_idx = next(i for i, o in enumerate(ops)
                       if o.verb is Verb.OBJECT_DELETE and o.path[-1] == "10.0.0.2")
        set_idx = next(i for i, o in enumerate(ops)
                       if o.verb is Verb.SET and o.path[-1] == "10.0.0.2")
        assert del_idx < set_idx

    def test_set_path_and_value(self):
        pc = _parse("router bgp 65000\n neighbor 10.0.0.9 remote-as 65009\n")
        op = next(o for o in _f5(pc) if o.verb is Verb.SET)
        assert op.path == ("bgp_instances", "65000", "", "neighbor", "10.0.0.9")
        assert str(op.value.peer_ip) == "10.0.0.9"
        assert op.origin == "native"
        assert op.line_no > 0

    def test_delete_path_and_provenance(self):
        pc = _parse("router bgp 65000\n no neighbor 10.0.0.2\n")
        op = next(o for o in _f5(pc) if o.verb is Verb.OBJECT_DELETE)
        assert op.path == ("bgp_instance", "65000", "", "neighbor", "10.0.0.2")
        assert op.source_line == "no neighbor 10.0.0.2"
        assert op.line_no == 1  # 0-based: line 0 = router bgp, line 1 = no neighbor

    def test_field_reset_path(self):
        pc = _parse("router bgp 65000\n no neighbor 10.0.0.3 route-map FILTER in\n")
        op = next(o for o in _f5(pc) if o.verb is Verb.UNSET)
        assert op.path == (
            "bgp_instance", "65000", "", "field", "neighbor", "10.0.0.3", "route_map_in"
        )

    def test_vrf_scope_prefix(self):
        pc = _parse(
            "router bgp 65000\n"
            " address-family ipv4 vrf CUST\n"
            "  no neighbor 172.16.0.1\n"
        )
        op = next(o for o in _f5(pc) if o.verb is Verb.OBJECT_DELETE)
        assert op.path[:3] == ("bgp_instance", "65000", "CUST")


class TestByteIdentityAndComposition:
    def test_legacy_no_commands_byte_exact(self):
        pc = _parse(DELETE_READD)
        bgp = pc.bgp_instances[0]
        assert bgp.no_commands == [
            "neighbor:10.0.0.2",
            "field:neighbor:10.0.0.3:route_map_in",
            "field:neighbor:10.0.0.3:shutdown",
        ]
        # encode_legacy reproduces the scoped container byte-exactly.
        art = encode_legacy(derive_ops(pc))
        assert art.bgp_no_commands[("65000", "")] == bgp.no_commands

    def test_ipv6_peer_byte_exact(self):
        pc = _parse("router bgp 65000\n no neighbor 2001:db8::1\n")
        bgp = pc.bgp_instances[0]
        assert bgp.no_commands == ["neighbor:2001:db8::1"]
        art = encode_legacy(derive_ops(pc))
        assert art.bgp_no_commands[("65000", "")] == ["neighbor:2001:db8::1"]

    def test_derived_instance_set_retired(self):
        """5c-B.2 (CCR Appendix L): the derived whole-instance SET is now RETIRED
        for this fully-native IOS instance — the native whole-instance CREATE op
        claims the ``("bgp_instances", asn, vrf)`` prefix (H.3 narrowing).  This
        pin was ``…_survives`` through 5a/5b/5c (the SET co-existed); the atomic
        retirement flips it to asserting exactly one NATIVE create op and zero
        derived SET."""
        from confgraph.change_ir import is_native_bgp_instance_create_op

        pc = _parse(DELETE_READD)
        ops = derive_ops(pc)
        instance_sets = [
            o for o in ops
            if o.verb is Verb.SET and o.path == ("bgp_instances", "65000", "")
        ]
        assert instance_sets == []
        creates = [o for o in ops if is_native_bgp_instance_create_op(o)]
        assert len(creates) == 1 and creates[0].origin == "native"

    def test_derived_neighbor_tombstones_deduped(self):
        pc = _parse(DELETE_READD)
        ops = derive_ops(pc)
        # No DERIVED op carries a bgp_instance-scoped neighbor tombstone path —
        # the natives claim those exact paths.
        for o in ops:
            if o.path and o.path[0] == "bgp_instance":
                assert o.origin == "native", o.path

    def test_anti_rot_family5_never_derived(self):
        """Every family-5a-shaped op in the composed ChangeSet is native.

        Scoped to the 18a-migrated forms ONLY (neighbor SET/OBJECT_DELETE/UNSET);
        family-5b forms (peer-group create/delete, networks, whole-instance
        decomposition) stay derived and are deliberately NOT claimed here."""
        pc = _parse(DELETE_READD)
        ops = derive_ops(pc)
        seen = 0
        for o in ops:
            native_shape = (
                (o.verb is Verb.SET and len(o.path) == 5
                 and o.path[0] == "bgp_instances" and o.path[3] == "neighbor")
                or (o.verb is Verb.OBJECT_DELETE and o.path
                    and o.path[0] == "bgp_instance" and len(o.path) >= 5
                    and o.path[3] == "neighbor")
                or (o.verb is Verb.UNSET and o.path
                    and o.path[0] == "bgp_instance" and len(o.path) >= 7
                    and o.path[3] == "field" and o.path[4] == "neighbor")
            )
            if native_shape:
                assert o.origin == "native", o.path
                seen += 1
        assert seen >= 4  # 2 SET + 1 OBJECT_DELETE + 2 UNSET

    def test_families_1_4_dedupe_unchanged(self):
        """The container-claim exclusion is BGP-only: family-3 banner
        whole-object SET is still retired by its per-field natives, and
        family-1 interface SET ops stay native."""
        pc = _parse(
            "interface GigabitEthernet0/0\n mtu 9000\n no ip ospf cost\n"
            "banner motd ^HI^\n"
            + DELETE_READD
        )
        ops = derive_ops(pc)
        # No derived whole-object banner SET survives (per-field natives claim).
        banner_sets = [o for o in ops if o.path == ("banners",)]
        assert not banner_sets
        for o in ops:
            if o.path and o.path[0] == "interface" and len(o.path) == 3:
                assert o.origin == "native", o.path

    def test_derived_fallback_without_natives(self):
        pc = _parse(DELETE_READD)
        pc.native_change_ops = None
        ops = derive_ops(pc)
        # Natives-less: the deriver translates the bgp tombstones itself.
        bgp_del = [o for o in ops if o.path and o.path[0] == "bgp_instance"]
        assert bgp_del and all(o.origin == "derived" for o in bgp_del)


class TestMultiOS:
    def test_nxos_inherits_single_line_removal(self):
        pc = _parse(
            "feature bgp\n"
            "router bgp 65000\n"
            "  neighbor 10.0.0.2 remote-as 65001\n"
            "  no neighbor 10.0.0.3\n",
            NXOSParser,
        )
        bgp = pc.bgp_instances[0]
        assert "neighbor:10.0.0.3" in bgp.no_commands
        ops = _f5(pc)
        assert any(o.verb is Verb.OBJECT_DELETE and o.path[-1] == "10.0.0.3"
                   for o in ops)
        assert any(o.verb is Verb.SET and o.path[-1] == "10.0.0.2" for o in ops)


class TestNoCrossFamilyBleed:
    def test_static_and_bgp_coexist(self):
        pc = _parse(
            "ip route 10.0.0.0 255.255.255.0 192.0.2.1\n"
            + DELETE_READD
        )
        ops = pc.native_change_ops
        assert any(is_native_static_op(o) for o in ops)
        assert any(is_native_bgp_op(o) for o in ops)
        # predicates are disjoint
        for o in ops:
            assert not (is_native_static_op(o) and is_native_bgp_op(o))
            assert not (is_native_service_entity_op(o) and is_native_bgp_op(o))
