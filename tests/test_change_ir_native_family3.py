"""Change-IR Phase 3, family 3 — native service-entity op emission.

CCR: ``change_ir_proposal_operations.md`` Appendix F (WI-16).

Covers:
- the family-3 boundary registries (``service_entity_list_fields`` /
  ``service_entity_singleton_fields`` / ``banner_scalar_fields``) and the
  codec-owned ``is_native_service_entity_op`` predicate,
- native deletion emission at the four WI-8 walk sites: UNSUPPRESSED ops at
  true script positions, with the ``_readded_later`` guard now gating only
  the legacy tombstone encoding (byte-identical strings via encode_legacy),
- native creation emission from final parsed state (entity SETs, per-field
  banner SETs) and the line-order interleave that makes delete-then-recreate
  vs create-then-delete structurally different sequences,
- hybrid derive_ops composition: exact-path dedupe for entity SET/DELETE
  paths, the new container-claim (prefix) dedupe retiring the derived
  whole-object ``SET ("banners",)``, anti-rot for families 1+2+3, and the
  natives-less derived fallback,
- NX-OS/EOS inheritance.
"""

from __future__ import annotations

from confgraph.change_ir import (
    ChangeOp,
    Verb,
    banner_scalar_fields,
    derive_ops,
    encode_legacy,
    interface_list_replace_fields,
    interface_scalar_fields,
    is_native_service_entity_op,
    service_entity_key,
    service_entity_list_fields,
    service_entity_singleton_fields,
)
from confgraph.parsers.eos_parser import EOSParser
from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.nxos_parser import NXOSParser


def _parse(text: str, parser_cls=IOSParser):
    return parser_cls(text).parse()


def _f3_ops(pc):
    return [op for op in pc.native_change_ops if is_native_service_entity_op(op)]


# Canonical delete-then-recreate (retarget) — device nets to a fresh entity.
DEL_THEN_READD = """no ip sla 10
ip sla 10
 icmp-echo 198.51.100.77
 frequency 30
"""

# Create-then-delete — device nets to ABSENT (the shape the legacy batched
# adds-then-deletes order can only model via the emitted tombstone).
ADD_THEN_DEL = """ip sla 10
 icmp-echo 198.51.100.77
 frequency 30
no ip sla 10
"""

KITCHEN_SINK = """interface GigabitEthernet0/0
 mtu 9000
 no ip ospf cost
 switchport trunk allowed vlan add 30
no ip sla 10
ip sla 10
 icmp-echo 1.2.3.4
 frequency 30
track 7 ip sla 10 reachability
no track 9
no event manager applet FOO
event manager applet FOO
 event syslog pattern "UP"
 action 1.0 syslog msg "x"
banner motd #hello#
no banner login
"""


# ---------------------------------------------------------------------------
# Family boundary + predicate
# ---------------------------------------------------------------------------


class TestFamilyBoundary:
    def test_list_half_is_the_three_wi8_collections(self):
        assert service_entity_list_fields() == frozenset(
            {"ip_sla_operations", "object_tracks", "eem_applets"}
        )

    def test_singleton_half_is_banners(self):
        assert service_entity_singleton_fields() == frozenset({"banners"})

    def test_banner_fields_structural(self):
        assert banner_scalar_fields() == frozenset(
            {"motd", "login", "exec_banner", "incoming"}
        )

    def test_disjoint_from_families_1_and_2(self):
        f1 = interface_scalar_fields()
        f2 = interface_list_replace_fields()
        f3 = service_entity_list_fields() | service_entity_singleton_fields()
        assert not f3 & f1
        assert not f3 & f2

    def test_predicate_shapes(self):
        yes = [
            ChangeOp(Verb.SET, ("ip_sla_operations", "10"), origin="native"),
            ChangeOp(Verb.SET, ("object_tracks", "7"), origin="native"),
            ChangeOp(Verb.SET, ("eem_applets", "FOO"), origin="native"),
            ChangeOp(Verb.SET, ("banners", "motd"), origin="native"),
            ChangeOp(
                Verb.OBJECT_DELETE, ("field", "ip_sla_operations", "10"), origin="native"
            ),
            ChangeOp(Verb.UNSET, ("field", "banners", "motd"), origin="native"),
        ]
        assert all(is_native_service_entity_op(op) for op in yes)

    def test_predicate_rejects_derived_twins_and_other_shapes(self):
        no = [
            # origin gate: identical paths, derived — must keep legacy path
            ChangeOp(Verb.SET, ("ip_sla_operations", "10")),
            ChangeOp(Verb.OBJECT_DELETE, ("field", "ip_sla_operations", "10")),
            ChangeOp(Verb.UNSET, ("field", "banners", "motd")),
            # other families
            ChangeOp(Verb.SET, ("interface", "GigabitEthernet0/0", "mtu"), origin="native"),
            ChangeOp(Verb.UNSET, ("field", "interface", "Gi0/0", "mtu"), origin="native"),
            ChangeOp(Verb.SET, ("vlans", "10"), origin="native"),
            ChangeOp(Verb.OBJECT_DELETE, ("field", "vrfs", "GUEST"), origin="native"),
            ChangeOp(Verb.SET, ("banners",), origin="native"),  # whole-object — not a family-3 shape
        ]
        assert not any(is_native_service_entity_op(op) for op in no)

    def test_service_entity_key_matches_deriver_identity(self):
        pc = _parse(KITCHEN_SINK)
        sla = pc.ip_sla_operations[0]
        assert service_entity_key("ip_sla_operations", sla) == (str(sla.sla_id),)
        track = pc.object_tracks[0]
        assert service_entity_key("object_tracks", track) == (str(track.track_id),)
        applet = pc.eem_applets[0]
        assert service_entity_key("eem_applets", applet) == (applet.name,)


# ---------------------------------------------------------------------------
# Native deletion emission — unsuppressed, suppression on the encoding only
# ---------------------------------------------------------------------------


class TestNativeDeleteEmission:
    def test_delete_op_unsuppressed_on_readd(self):
        """The op exists even when the tombstone is suppressed — ops mode
        orders structurally and needs no guard."""
        pc = _parse(DEL_THEN_READD)
        deletes = [op for op in _f3_ops(pc) if op.verb is Verb.OBJECT_DELETE]
        assert [op.path for op in deletes] == [("field", "ip_sla_operations", "10")]
        assert deletes[0].source_line == "no ip sla 10"
        assert deletes[0].origin == "native"
        # …while the LEGACY encoding stays suppressed (byte-identity with WI-8)
        assert "field:ip_sla_operations:10" not in pc.no_commands

    def test_tombstone_still_emitted_without_readd(self):
        pc = _parse("no ip sla 10\n")
        assert pc.no_commands == ["field:ip_sla_operations:10"]
        deletes = [op for op in _f3_ops(pc) if op.verb is Verb.OBJECT_DELETE]
        assert len(deletes) == 1
        # single source: the tombstone is the op's legacy encoding
        assert encode_legacy(deletes).no_commands == ["field:ip_sla_operations:10"]

    def test_all_four_walks_emit_native_ops(self):
        pc = _parse(
            "no ip sla 10\nno track 9\nno event manager applet FOO\nno banner exec\n"
        )
        got = {(op.verb, op.path) for op in _f3_ops(pc)}
        assert got == {
            (Verb.OBJECT_DELETE, ("field", "ip_sla_operations", "10")),
            (Verb.OBJECT_DELETE, ("field", "object_tracks", "9")),
            (Verb.OBJECT_DELETE, ("field", "eem_applets", "FOO")),
            (Verb.UNSET, ("field", "banners", "exec_banner")),
        }
        assert pc.no_commands == [
            "field:ip_sla_operations:10",
            "field:object_tracks:9",
            "field:eem_applets:FOO",
            "field:banners:exec_banner",
        ]

    def test_subforms_still_excluded(self):
        """``no ip sla schedule`` / ``no track 1 ip sla`` are attribute
        removals — no entity op, no tombstone (WI-8 semantics pinned)."""
        pc = _parse("no ip sla schedule 10\nno track 1 ip sla 5\n")
        assert not _f3_ops(pc)
        assert pc.no_commands == []

    def test_provenance_is_verbatim_negation_line(self):
        pc = _parse("hostname r1\nno track 9\n")
        (op,) = _f3_ops(pc)
        assert op.source_line == "no track 9"
        assert op.line_no >= 0


# ---------------------------------------------------------------------------
# Native creation emission + script-order interleave
# ---------------------------------------------------------------------------


class TestNativeCreateEmissionAndOrder:
    def test_delete_then_readd_sequence(self):
        pc = _parse(DEL_THEN_READD)
        ops = _f3_ops(pc)
        assert [op.verb for op in ops] == [Verb.OBJECT_DELETE, Verb.SET]
        assert ops[1].path == ("ip_sla_operations", "10")
        assert ops[1].value.destination == "198.51.100.77"
        assert ops[0].line_no < ops[1].line_no

    def test_add_then_delete_sequence(self):
        """The other order — a different op sequence (the family's headline
        guarantee: ordering is structural, not guard-heuristic)."""
        pc = _parse(ADD_THEN_DEL)
        ops = _f3_ops(pc)
        assert [op.verb for op in ops] == [Verb.SET, Verb.OBJECT_DELETE]
        # legacy: the guard does NOT suppress (positive precedes negation)
        assert pc.no_commands == ["field:ip_sla_operations:10"]

    def test_entity_set_carries_final_state_and_block_provenance(self):
        pc = _parse("ip sla 10\n icmp-echo 1.2.3.4\n frequency 30\n")
        (op,) = _f3_ops(pc)
        assert op.verb is Verb.SET
        assert op.value is pc.ip_sla_operations[0]
        assert op.source_line == "ip sla 10"
        assert op.origin == "native"

    def test_banner_per_field_sets(self):
        pc = _parse("banner motd #hi#\nbanner exec #careful#\n")
        ops = _f3_ops(pc)
        assert {(op.verb, op.path) for op in ops} == {
            (Verb.SET, ("banners", "motd")),
            (Verb.SET, ("banners", "exec_banner")),
        }
        by_path = {op.path: op for op in ops}
        assert by_path[("banners", "motd")].value == "hi"
        assert by_path[("banners", "motd")].source_line.startswith("banner motd")

    def test_banner_delete_then_readd_sequence(self):
        pc = _parse("no banner motd\nbanner motd #new#\n")
        ops = _f3_ops(pc)
        assert [(op.verb, op.path) for op in ops] == [
            (Verb.UNSET, ("field", "banners", "motd")),
            (Verb.SET, ("banners", "motd")),
        ]
        assert "field:banners:motd" not in pc.no_commands  # suppressed encoding

    def test_banner_add_then_delete_sequence(self):
        pc = _parse("banner motd #new#\nno banner motd\n")
        ops = _f3_ops(pc)
        assert [(op.verb, op.path) for op in ops] == [
            (Verb.SET, ("banners", "motd")),
            (Verb.UNSET, ("field", "banners", "motd")),
        ]
        assert pc.no_commands == ["field:banners:motd"]

    def test_banner_types_order_independently(self):
        """Different banner fields interleave each with their OWN negation —
        the reason banner ops are per-field, not whole-object."""
        pc = _parse(
            "banner motd #a#\nno banner motd\nbanner login #b#\n"
        )
        ops = _f3_ops(pc)
        assert [(op.verb, op.path) for op in ops] == [
            (Verb.SET, ("banners", "motd")),
            (Verb.UNSET, ("field", "banners", "motd")),
            (Verb.SET, ("banners", "login")),
        ]

    def test_readded_sla_positioned_at_recreation_block(self):
        """parse_ip_sla is last-block-wins: the SET carries the re-creation
        block's position, so the sequence nets to PRESENT."""
        pc = _parse(
            "ip sla 10\n icmp-echo 1.1.1.1\nno ip sla 10\nip sla 10\n icmp-echo 2.2.2.2\n"
        )
        ops = _f3_ops(pc)
        assert [op.verb for op in ops] == [Verb.OBJECT_DELETE, Verb.SET]
        assert ops[1].value.destination == "2.2.2.2"

    def test_eem_duplicate_blocks_keep_own_positions(self):
        pc = _parse(
            'event manager applet FOO\n event syslog pattern "A"\n'
            "no event manager applet FOO\n"
            'event manager applet FOO\n event syslog pattern "B"\n'
        )
        ops = _f3_ops(pc)
        assert [op.verb for op in ops] == [Verb.SET, Verb.OBJECT_DELETE, Verb.SET]
        assert ops[2].value.event.raw == 'event syslog pattern "B"'


# ---------------------------------------------------------------------------
# Composition: dedupe, container claims, anti-rot, fallback
# ---------------------------------------------------------------------------


class TestHybridComposition:
    def test_composed_set_has_no_derived_family3_ops(self):
        for op in derive_ops(_parse(KITCHEN_SINK)):
            if is_native_service_entity_op(
                ChangeOp(op.verb, op.path, origin="native")
            ):
                assert op.origin == "native", op.path

    def test_banner_container_claim_drops_derived_whole_object(self):
        ops = derive_ops(_parse("banner motd #hi#\n"))
        assert not any(op.path == ("banners",) for op in ops)
        assert any(
            op.path == ("banners", "motd") and op.origin == "native" for op in ops
        )

    def test_anti_rot_family3_never_derived(self):
        """CI anti-rot check (CCR §6 risk table): no family is handled by
        BOTH native emission and the deriver's translation path — every
        family-3-shaped op in the composed ChangeSet is native, and the
        derived whole-object banners SET is retired by the container
        claim."""
        pc = _parse(KITCHEN_SINK)
        list_fields = service_entity_list_fields()
        for op in derive_ops(pc):
            if len(op.path) == 2 and op.path[0] in list_fields:
                assert op.origin == "native", op.path
            if len(op.path) == 2 and op.path[0] == "banners":
                assert op.origin == "native", op.path
            if (
                len(op.path) == 3
                and op.path[0] == "field"
                and (op.path[1] in list_fields or op.path[1] == "banners")
            ):
                assert op.origin == "native", op.path
            assert op.path != ("banners",)

    def test_anti_rot_families_1_and_2_unaffected(self):
        pc = _parse(KITCHEN_SINK)
        f1 = interface_scalar_fields()
        for op in derive_ops(pc):
            if op.verb is Verb.SET and op.path[0] == "interface" \
                    and len(op.path) == 3 and op.path[2] in f1:
                assert op.origin == "native", op.path
            if "trunk_allowed_vlans" in op.path:
                assert op.origin == "native", op.path

    def test_derived_fallback_without_natives(self):
        """Natives-less configs (JunOS/PAN-OS parses, hand-built models)
        keep full derived translation — graceful degradation."""
        pc = _parse(KITCHEN_SINK)
        pc.native_change_ops = None
        ops = derive_ops(pc)
        assert all(op.origin == "derived" for op in ops)
        assert any(op.path == ("ip_sla_operations", "10") for op in ops)
        assert any(op.path == ("field", "object_tracks", "9") for op in ops)
        assert any(op.path == ("banners",) for op in ops)

    def test_suppressed_delete_encodes_to_tombstone_in_composed_set(self):
        """Documented F.3 consequence: encode_legacy of a composed ChangeSet
        contains the suppressed tombstone (the op is unsuppressed intent);
        the PARSER artifact remains suppressed — the Phase-4 shim must
        apply the suppression at encode time (recorded follow-up)."""
        pc = _parse(DEL_THEN_READD)
        assert "field:ip_sla_operations:10" not in pc.no_commands
        art = encode_legacy(derive_ops(pc))
        assert "field:ip_sla_operations:10" in art.no_commands


# ---------------------------------------------------------------------------
# Inheritance
# ---------------------------------------------------------------------------


class TestInheritance:
    def test_nxos_both_orders(self):
        pc = _parse(
            "no ip sla 10\nip sla 10\n icmp-echo 10.0.0.1\n frequency 15\n",
            NXOSParser,
        )
        ops = _f3_ops(pc)
        assert [op.verb for op in ops] == [Verb.OBJECT_DELETE, Verb.SET]
        assert "field:ip_sla_operations:10" not in pc.no_commands

    def test_nxos_track_and_eem(self):
        pc = _parse(
            "no track 9\nno event manager applet FOO\n", NXOSParser
        )
        assert {op.path for op in _f3_ops(pc)} == {
            ("field", "object_tracks", "9"),
            ("field", "eem_applets", "FOO"),
        }
        assert pc.no_commands == [
            "field:object_tracks:9",
            "field:eem_applets:FOO",
        ]

    def test_eos_banner_and_track(self):
        pc = _parse("no banner motd\nno track 3\n", EOSParser)
        assert {(op.verb, op.path) for op in _f3_ops(pc)} == {
            (Verb.UNSET, ("field", "banners", "motd")),
            (Verb.OBJECT_DELETE, ("field", "object_tracks", "3")),
        }
