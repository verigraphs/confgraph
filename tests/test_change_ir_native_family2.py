"""Change-IR Phase 3, family 2 — native trunk allowed-VLAN op emission.

CCR: ``change_ir_proposal_operations.md`` Appendix E (WI-15).

Covers:
- the family-2 boundary registry (``interface_list_replace_fields``),
- native delta emission (un-anchored ``add``/``remove`` → LIST_ADD /
  LIST_REMOVE with verbatim provenance; tombstones generated from the ops,
  byte-identical INCLUDING their interleave position among family-1
  tombstones),
- native anchored SET emission (full replace / ``all`` / ``except`` /
  ``none`` / fold-to-empty — the last two being the new capability legacy
  artifacts are structurally blind to),
- encode_legacy behavior (SET ops never produce tombstones — legacy
  blindness to ``none`` is preserved byte-for-byte),
- hybrid derive_ops composition + the anti-rot check extended to family 2,
- NX-OS/EOS inheritance.
"""

from __future__ import annotations

from confgraph.change_ir import (
    Verb,
    derive_ops,
    encode_legacy,
    interface_list_replace_fields,
    interface_scalar_fields,
)
from confgraph.parsers.eos_parser import EOSParser
from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.nxos_parser import NXOSParser


def _parse(text: str, parser_cls=IOSParser):
    return parser_cls(text).parse()


def _trunk_ops(pc):
    return [
        op
        for op in pc.native_change_ops
        if "trunk_allowed_vlans" in op.path
    ]


_PFX = "field:interface:GigabitEthernet0/1:trunk_allowed_vlans"


# ---------------------------------------------------------------------------
# Family boundary
# ---------------------------------------------------------------------------


class TestFamilyBoundary:
    def test_family2_is_exactly_trunk_allowed_vlans(self):
        assert interface_list_replace_fields() == frozenset(
            {"trunk_allowed_vlans"}
        )

    def test_family2_disjoint_from_family1(self):
        assert not interface_list_replace_fields() & interface_scalar_fields()


# ---------------------------------------------------------------------------
# Native delta emission (un-anchored add/remove)
# ---------------------------------------------------------------------------


class TestNativeDeltaEmission:
    def test_add_and_remove_native_ops_with_provenance(self):
        pc = _parse(
            "interface GigabitEthernet0/1\n"
            " switchport trunk allowed vlan add 30,40-42\n"
            " switchport trunk allowed vlan remove 20\n"
        )
        add_op, rem_op = _trunk_ops(pc)
        assert add_op.verb is Verb.LIST_ADD
        assert add_op.path == (
            "field", "interface", "GigabitEthernet0/1",
            "trunk_allowed_vlans", "add", "30,40-42",
        )
        assert add_op.value == "30,40-42"
        assert add_op.source_line == "switchport trunk allowed vlan add 30,40-42"
        assert add_op.line_no > 0
        assert add_op.origin == "native"
        assert rem_op.verb is Verb.LIST_REMOVE
        assert rem_op.path[-2:] == ("remove", "20")
        assert rem_op.origin == "native"
        # Line order preserved (device apply order is semantic).
        assert add_op.line_no < rem_op.line_no

    def test_tombstones_byte_identical_from_ops(self):
        """The bespoke f-string emission is gone — the tombstones come from
        the ops via encode_legacy and must be byte-identical to the
        pre-family-2 strings, in line order."""
        pc = _parse(
            "interface GigabitEthernet0/1\n"
            " switchport trunk allowed vlan remove 20\n"
            " switchport trunk allowed vlan add 30,40-42\n"
        )
        assert pc.interfaces[0].no_commands == [
            f"{_PFX}:remove:20",
            f"{_PFX}:add:30,40-42",
        ]

    def test_interleave_position_pinned_among_family1_tombstones(self):
        """Trunk tombstones keep their emission position between the
        `no description` site and the later scalar-negation sites — the
        no_commands ORDER is byte-identical to committed HEAD."""
        pc = _parse(
            "interface GigabitEthernet0/1\n"
            " no description\n"
            " switchport trunk allowed vlan add 30\n"
            " no ip ospf cost\n"
            " no shutdown\n"
        )
        p = "field:interface:GigabitEthernet0/1"
        assert pc.interfaces[0].no_commands == [
            f"{p}:description",
            f"{p}:trunk_allowed_vlans:add:30",
            f"{p}:ospf_cost",
            f"{p}:enabled",
        ]
        # Native op order mirrors it (per-interface: SETs, then codec-path
        # ops in emission order).
        codec_ops = [
            op for op in pc.native_change_ops
            if op.path[:2] == ("field", "interface")
        ]
        assert [":".join(op.path) for op in codec_ops] == list(
            pc.interfaces[0].no_commands
        )

    def test_anchor_discards_pending_delta_ops(self):
        """An absolute form replaces device state — earlier deltas emit
        neither ops nor tombstones (same as legacy folding)."""
        pc = _parse(
            "interface GigabitEthernet0/1\n"
            " switchport trunk allowed vlan remove 20\n"
            " switchport trunk allowed vlan 10,20\n"
        )
        ops = _trunk_ops(pc)
        assert [op.verb for op in ops] == [Verb.SET]
        assert ops[0].value == [10, 20]
        assert pc.interfaces[0].no_commands == []


# ---------------------------------------------------------------------------
# Native anchored SET emission
# ---------------------------------------------------------------------------


class TestNativeAnchoredSetEmission:
    def test_full_replace_set_with_provenance(self):
        pc = _parse(
            "interface GigabitEthernet0/1\n"
            " switchport trunk allowed vlan 10,20\n"
        )
        (op,) = _trunk_ops(pc)
        assert op.verb is Verb.SET
        assert op.path == (
            "interface", "GigabitEthernet0/1", "trunk_allowed_vlans"
        )
        assert op.value == [10, 20]
        assert op.source_line == "switchport trunk allowed vlan 10,20"
        assert op.line_no > 0
        assert op.origin == "native"

    def test_except_folds_to_absolute_set(self):
        pc = _parse(
            "interface GigabitEthernet0/1\n"
            " switchport trunk allowed vlan except 100\n"
        )
        (op,) = _trunk_ops(pc)
        assert op.verb is Verb.SET
        assert len(op.value) == 4093
        assert 100 not in op.value

    def test_all_folds_to_full_range_set(self):
        pc = _parse(
            "interface GigabitEthernet0/1\n"
            " switchport trunk allowed vlan all\n"
        )
        (op,) = _trunk_ops(pc)
        assert op.verb is Verb.SET
        assert len(op.value) == 4094

    def test_none_emits_default_valued_set(self):
        """THE family-2 capability: `vlan none` anchors the list to [] ==
        the factory default — legacy state artifacts are structurally
        blind to it; the native SET [] op carries the intent."""
        pc = _parse(
            "interface GigabitEthernet0/1\n"
            " switchport trunk allowed vlan none\n"
        )
        (op,) = _trunk_ops(pc)
        assert op.verb is Verb.SET
        assert op.value == []
        assert op.source_line == "switchport trunk allowed vlan none"
        assert op.origin == "native"

    def test_delta_fold_to_empty_emits_set_empty(self):
        """Anchored deltas folding to nothing are the same blind shape."""
        pc = _parse(
            "interface GigabitEthernet0/1\n"
            " switchport trunk allowed vlan 10\n"
            " switchport trunk allowed vlan remove 10\n"
        )
        (op,) = _trunk_ops(pc)
        assert op.verb is Verb.SET
        assert op.value == []

    def test_none_then_add_folds_to_nonempty_single_set(self):
        pc = _parse(
            "interface GigabitEthernet0/1\n"
            " switchport trunk allowed vlan none\n"
            " switchport trunk allowed vlan add 30\n"
        )
        (op,) = _trunk_ops(pc)
        assert op.verb is Verb.SET
        assert op.value == [30]

    def test_set_empty_encodes_to_nothing_legacy(self):
        """SET [] must encode to set_fields only — no tombstone, no
        no_commands entry: exactly today's legacy blindness (required for
        byte-identity)."""
        pc = _parse(
            "interface GigabitEthernet0/1\n"
            " switchport trunk allowed vlan none\n"
        )
        assert pc.interfaces[0].no_commands == []
        art = encode_legacy(pc.native_change_ops)
        assert art.no_commands == []
        assert art.interface_no_commands == {}
        assert art.set_fields[
            ("interface", "GigabitEthernet0/1", "trunk_allowed_vlans")
        ] == []

    def test_unmentioned_trunk_emits_no_family2_ops(self):
        pc = _parse("interface GigabitEthernet0/1\n switchport mode trunk\n")
        assert _trunk_ops(pc) == []


# ---------------------------------------------------------------------------
# Hybrid composition + anti-rot (families 1 AND 2)
# ---------------------------------------------------------------------------


_KITCHEN_SINK = (
    "interface GigabitEthernet0/0\n"
    " description core uplink\n"
    " switchport mode trunk\n"
    " switchport trunk native vlan 99\n"
    " switchport trunk allowed vlan 10,20\n"
    "interface GigabitEthernet0/1\n"
    " no description\n"
    " switchport trunk allowed vlan add 30\n"
    " switchport trunk allowed vlan remove 20\n"
    " no shutdown\n"
    "interface GigabitEthernet0/2\n"
    " switchport trunk allowed vlan none\n"
    "ntp server 10.0.0.10\n"
)


class TestHybridComposition:
    def test_composition_dedupes_family2_paths(self):
        pc = _parse(_KITCHEN_SINK)
        ops = derive_ops(pc)
        trunk_paths = [
            op.path for op in ops if "trunk_allowed_vlans" in op.path
        ]
        assert len(trunk_paths) == len(set(trunk_paths))
        # All three shapes present exactly once, all native.
        assert (
            "interface", "GigabitEthernet0/0", "trunk_allowed_vlans"
        ) in trunk_paths
        assert (
            "interface", "GigabitEthernet0/2", "trunk_allowed_vlans"
        ) in trunk_paths

    def test_anti_rot_family2_never_derived(self):
        """CI anti-rot check (CCR §6 risk table), extended to family 2: no
        family is handled by BOTH native emission and the deriver — every
        family-2 op in the composed ChangeSet is native (3-seg trunk SET
        and 6-seg trunk delta shapes alike)."""
        pc = _parse(_KITCHEN_SINK)
        for op in derive_ops(pc):
            if "trunk_allowed_vlans" not in op.path:
                continue
            assert op.origin == "native", op.path

    def test_anti_rot_family1_unaffected(self):
        """Family-1 scalars around the trunk lines stay native — no
        double-handling of trunk_native_vlan / switchport_mode by
        family 2 (they are family-1 territory)."""
        pc = _parse(_KITCHEN_SINK)
        family = interface_scalar_fields()
        assert "trunk_native_vlan" in family and "switchport_mode" in family
        for op in derive_ops(pc):
            if op.verb is Verb.SET and len(op.path) == 3 \
                    and op.path[0] == "interface" and op.path[2] in family:
                assert op.origin == "native", op.path

    def test_derived_fallback_without_natives(self):
        """A config without native ops (pre-Phase-3 / JunOS parses) still
        derives the trunk delta ops from the tombstones — capability
        degrades to legacy parity, intent is never dropped."""
        pc = _parse(_KITCHEN_SINK)
        pc.native_change_ops = None
        ops = derive_ops(pc)
        deltas = [
            op for op in ops
            if len(op.path) == 6 and op.path[3] == "trunk_allowed_vlans"
        ]
        assert {op.verb for op in deltas} == {Verb.LIST_ADD, Verb.LIST_REMOVE}
        assert all(op.origin == "derived" for op in deltas)


# ---------------------------------------------------------------------------
# Inheritance: NX-OS / EOS
# ---------------------------------------------------------------------------


class TestInheritance:
    def test_nxos_delta_and_none(self):
        pc = _parse(
            "interface Ethernet1/1\n"
            "  switchport trunk allowed vlan remove 20\n"
            "interface Ethernet1/2\n"
            "  switchport trunk allowed vlan none\n",
            NXOSParser,
        )
        by_iface = {op.path[2] if len(op.path) == 6 else op.path[1]: op
                    for op in pc.native_change_ops
                    if "trunk_allowed_vlans" in op.path}
        rem = by_iface["Ethernet1/1"]
        assert rem.verb is Verb.LIST_REMOVE
        assert rem.origin == "native"
        assert pc.interfaces[0].no_commands == [
            "field:interface:Ethernet1/1:trunk_allowed_vlans:remove:20"
        ]
        none_op = by_iface["Ethernet1/2"]
        assert none_op.verb is Verb.SET
        assert none_op.value == []

    def test_eos_full_replace_native(self):
        pc = _parse(
            "interface Ethernet1\n"
            "   switchport mode trunk\n"
            "   switchport trunk allowed vlan 10,99\n",
            EOSParser,
        )
        ops = _trunk_ops(pc)
        assert [op.verb for op in ops] == [Verb.SET]
        assert ops[0].value == [10, 99]
        assert ops[0].origin == "native"
