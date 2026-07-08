"""Phase 3 family 8c — visibility + L2 globals + native VLAN ops (CCR Appendix V).

Parser-side pins for lldp / cdp / spanning_tree / vtp (singleton half),
lacp_system_priority (len-1 native scalar), and the VLAN database (keyed
collection + OBJECT_DELETE):

- native op emission (whole-section create + scalar + member SETs via the 8a
  codec, registry-extended),
- the tri-state line-detected booleans (``lldp.enabled`` / ``cdp.enabled`` /
  ``cdp.advertise_v2``) incl. the NX-OS ``feature`` spellings AND the NX-OS
  parser-absence-False anchor (the O.1 trap, Appendix V.2),
- byte-exact tombstone twins (string AND order): ``field:lldp:tlv:<t>`` and
  ``vlan:<id>`` (ranges expanded, each id line-numbered),
- inline retirement of the four derived whole-singleton SETs + the
  exact-path-dedupe retirement of the derived vlan / lacp SETs,
- the IOS-XR gate (no 8c natives; derived SETs survive),
- anti-rot completeness extended to the four new sections.
"""

import pytest

from confgraph.change_ir import (
    ChangeOp,
    Verb,
    derive_ops,
    encode_legacy,
    is_native_singleton_instance_create_op,
    is_native_singleton_section_op,
    is_native_vlan_op,
    singleton_line_detected_scalars,
    singleton_member_kinds,
    singleton_scalar_fields,
    singleton_section_fields,
)
from confgraph.parsers.eos_parser import EOSParser
from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.iosxr_parser import IOSXRParser
from confgraph.parsers.nxos_parser import NXOSParser

SECTIONS_8C = ("cdp", "lldp", "spanning_tree", "vtp")


def _parse(text: str):
    return IOSParser(text).parse()


def _native_sect(pc):
    return [op for op in pc.native_change_ops if is_native_singleton_section_op(op)]


def _native_vlan(pc):
    return [op for op in pc.native_change_ops if is_native_vlan_op(op)]


KITCHEN_SINK = """\
hostname r1
lldp run
lldp timer 30
lldp holdtime 120
lldp tlv-select system-name
lldp tlv-select port-description
no lldp tlv-select port-vlan
cdp run
cdp timer 60
no cdp advertise-v2
spanning-tree mode rapid-pvst
spanning-tree vlan 10 priority 4096
spanning-tree vlan 20 hello-time 1
spanning-tree portfast default
spanning-tree portfast bpduguard default
spanning-tree loopguard default
vtp domain CORP
vtp mode transparent
vtp version 2
lacp system-priority 100
vlan 10
 name USERS
vlan 20
 name SERVERS
vlan 30-32
no vlan 40
no vlan 50-51,55
"""

# The exact legacy tombstones, IN WALK ORDER (byte-identity pin — this list is
# what HEAD emitted before family 8c; strings AND sequence must survive).
KITCHEN_SINK_TOMBSTONES = [
    "vlan:40",
    "vlan:50",
    "vlan:51",
    "vlan:55",
    "field:lldp:tlv:port-vlan",
]


# ---------------------------------------------------------------------------
# Byte-identity of legacy artifacts (string AND order)
# ---------------------------------------------------------------------------


class TestTombstoneTwins:
    def test_kitchen_sink_tombstones_byte_identical_in_order(self):
        pc = _parse(KITCHEN_SINK)
        assert pc.no_commands == KITCHEN_SINK_TOMBSTONES

    def test_every_twin_regenerated_from_a_native_op(self):
        pc = _parse(KITCHEN_SINK)
        native_paths = {
            ":".join(op.path) for op in _native_sect(pc) + _native_vlan(pc)
        }
        for t in pc.no_commands:
            assert t in native_paths, t

    def test_roundtrip_multiset(self):
        pc = _parse(KITCHEN_SINK)
        art = encode_legacy(derive_ops(pc))
        assert sorted(art.no_commands) == sorted(pc.no_commands)

    def test_vlan_range_expansion_each_id_carries_the_spec_line(self):
        pc = _parse("no vlan 50-51,55\n")
        dels = {op.path: op for op in _native_vlan(pc)}
        assert set(dels) == {("vlan", "50"), ("vlan", "51"), ("vlan", "55")}
        lines = {op.line_no for op in dels.values()}
        assert len(lines) == 1 and lines != {-1}
        for op in dels.values():
            assert op.verb is Verb.OBJECT_DELETE
            assert op.source_line == "no vlan 50-51,55"


# ---------------------------------------------------------------------------
# Native op inventory + tri-state
# ---------------------------------------------------------------------------


class TestEmission:
    def test_create_op_per_parsed_section(self):
        pc = _parse(KITCHEN_SINK)
        creates = sorted(
            op.path
            for op in _native_sect(pc)
            if is_native_singleton_instance_create_op(op)
        )
        assert [(s, "instance") for s in SECTIONS_8C] == creates

    def test_scalar_and_member_ops(self):
        pc = _parse(KITCHEN_SINK)
        paths = {op.path for op in _native_sect(pc)}
        for expected in [
            ("lldp", "scalar", "timer"),
            ("lldp", "scalar", "holdtime"),
            ("lldp", "tlv_select", "system-name"),
            ("lldp", "tlv_select", "port-description"),
            ("cdp", "scalar", "timer"),
            ("spanning_tree", "scalar", "mode"),
            ("spanning_tree", "scalar", "portfast_default"),
            ("spanning_tree", "scalar", "bpduguard_default"),
            ("spanning_tree", "scalar", "loopguard_default"),
            ("spanning_tree", "vlan_configs", "10"),
            ("spanning_tree", "vlan_configs", "20"),
            ("vtp", "scalar", "domain"),
            ("vtp", "scalar", "mode"),
            ("vtp", "scalar", "version"),
        ]:
            assert expected in paths, expected
        # default-valued scalars are NOT state-emitted
        assert ("spanning_tree", "scalar", "bpdufilter_default") not in paths
        assert ("lldp", "scalar", "reinit") not in paths

    def test_tristate_positive_reassert_emitted(self):
        # `lldp run` / `cdp run` are state-invisible (enabled stays at the
        # True default) — the line detection emits SET True at the line.
        pc = _parse(KITCHEN_SINK)
        by_path = {op.path: op for op in _native_sect(pc)}
        assert by_path[("lldp", "scalar", "enabled")].value is True
        assert by_path[("lldp", "scalar", "enabled")].source_line == "lldp run"
        assert by_path[("cdp", "scalar", "enabled")].value is True
        assert by_path[("cdp", "scalar", "advertise_v2")].value is False
        assert (
            by_path[("cdp", "scalar", "advertise_v2")].source_line
            == "no cdp advertise-v2"
        )

    def test_tristate_last_line_wins(self):
        pc = _parse("no lldp run\nlldp run\nno cdp advertise-v2\ncdp advertise-v2\n")
        by_path = {op.path: op for op in _native_sect(pc)}
        assert by_path[("lldp", "scalar", "enabled")].value is True
        assert by_path[("cdp", "scalar", "advertise_v2")].value is True
        # parsed state stays order-blind False — legacy artifacts untouched
        assert pc.lldp.enabled is False
        assert pc.cdp.advertise_v2 is False

    def test_tristate_negation_wins_when_later(self):
        pc = _parse("lldp run\nno lldp run\ncdp run\nno cdp run\n")
        by_path = {op.path: op for op in _native_sect(pc)}
        assert by_path[("lldp", "scalar", "enabled")].value is False
        assert by_path[("cdp", "scalar", "enabled")].value is False

    def test_tristate_bare_no_forms(self):
        pc = _parse("no lldp\nno cdp\n")
        by_path = {op.path: op for op in _native_sect(pc)}
        assert by_path[("lldp", "scalar", "enabled")].value is False
        assert by_path[("cdp", "scalar", "enabled")].value is False

    def test_tristate_absent_line_no_op(self):
        # section exists via timer only — absence == True default on IOS,
        # NO enabled op is emitted (the state walk excludes the tri-states).
        pc = _parse("lldp timer 45\ncdp timer 90\n")
        paths = {op.path for op in _native_sect(pc)}
        assert ("lldp", "scalar", "enabled") not in paths
        assert ("cdp", "scalar", "enabled") not in paths
        assert ("cdp", "scalar", "advertise_v2") not in paths

    def test_lacp_native_scalar_op(self):
        pc = _parse("lacp system-priority 100\nlacp system-priority 200\n")
        ops = [
            op
            for op in pc.native_change_ops
            if op.path == ("lacp_system_priority",)
        ]
        assert len(ops) == 1
        # parse_lacp_system_priority reads the FIRST matching line — the
        # native op mirrors the parser (value AND provenance).
        assert ops[0].value == 100
        assert ops[0].source_line == "lacp system-priority 100"
        assert ops[0].origin == "native"

    def test_vlan_set_ops_last_occurrence_lines(self):
        pc = _parse("vlan 10\n name USERS\nvlan 20\nvlan 10\n name USERS2\n")
        sets = {op.path: op for op in _native_vlan(pc)}
        assert set(sets) == {("vlans", "10"), ("vlans", "20")}
        assert sets[("vlans", "10")].value.name == "USERS2"
        assert sets[("vlans", "10")].line_no > sets[("vlans", "20")].line_no

    def test_vlan_ops_sorted_by_line_delete_between_sets(self):
        pc = _parse("vlan 10\n name A\nno vlan 10\nvlan 10\n name B\n")
        ops = _native_vlan(pc)
        # dedupe by path keeps ONE SET (last occurrence) + the delete,
        # ordered by line: delete (line 3) precedes the re-created SET.
        verbs = [(op.verb, op.path) for op in ops]
        assert verbs == [
            (Verb.OBJECT_DELETE, ("vlan", "10")),
            (Verb.SET, ("vlans", "10")),
        ]
        assert ops[-1].value.name == "B"


# ---------------------------------------------------------------------------
# NX-OS: feature spellings + the parser-absence-False anchor (V.2)
# ---------------------------------------------------------------------------


class TestNXOS:
    def test_feature_lines_emit_enabled(self):
        pc = NXOSParser("feature lldp\nfeature cdp\nlldp timer 30\n").parse()
        by_path = {op.path: op for op in _native_sect(pc)}
        assert by_path[("lldp", "scalar", "enabled")].value is True
        assert by_path[("lldp", "scalar", "enabled")].source_line == "feature lldp"
        assert by_path[("cdp", "scalar", "enabled")].value is True

    def test_no_feature_emits_disabled(self):
        pc = NXOSParser("no feature lldp\n").parse()
        by_path = {op.path: op for op in _native_sect(pc)}
        assert by_path[("lldp", "scalar", "enabled")].value is False

    def test_absence_anchor_emits_false_unconditionally(self):
        # NX-OS parser-absence is False (≠ the True model default) — the
        # enabled op is ALWAYS emitted when the section exists, so the
        # engine's generic default-reset seed can never leak True.
        pc = NXOSParser("lldp timer 30\n").parse()
        assert pc.lldp.enabled is False
        by_path = {op.path: op for op in _native_sect(pc)}
        assert by_path[("lldp", "scalar", "enabled")].value is False

    def test_feature_refresh_last_line_wins(self):
        pc = NXOSParser("no feature lldp\nfeature lldp\n").parse()
        by_path = {op.path: op for op in _native_sect(pc)}
        assert by_path[("lldp", "scalar", "enabled")].value is True

    def test_nxos_vlan_ops_shared_walk(self):
        pc = NXOSParser("vlan 10\n  vn-segment 10010\nno vlan 99\n").parse()
        paths = {(op.verb, op.path) for op in _native_vlan(pc)}
        assert (Verb.SET, ("vlans", "10")) in paths
        assert (Verb.OBJECT_DELETE, ("vlan", "99")) in paths
        assert "vlan:99" in pc.no_commands


# ---------------------------------------------------------------------------
# EOS shares the IOS spellings
# ---------------------------------------------------------------------------


class TestEOS:
    def test_eos_lldp_disable_and_vlan(self):
        pc = EOSParser("no lldp run\nvlan 10\nno vlan 20\n").parse()
        by_path = {op.path: op for op in _native_sect(pc)}
        assert by_path[("lldp", "scalar", "enabled")].value is False
        paths = {(op.verb, op.path) for op in _native_vlan(pc)}
        assert (Verb.OBJECT_DELETE, ("vlan", "20")) in paths


# ---------------------------------------------------------------------------
# Retirement + composition
# ---------------------------------------------------------------------------


class TestRetirement:
    def test_derived_whole_singleton_sets_retired(self):
        pc = _parse(KITCHEN_SINK)
        ops = derive_ops(pc)
        for sect in SECTIONS_8C:
            assert not any(op.path == (sect,) for op in ops), sect
            assert sum(1 for op in ops if op.path == (sect, "instance")) == 1, sect

    def test_derived_vlan_sets_retired_by_exact_path_dedupe(self):
        pc = _parse(KITCHEN_SINK)
        ops = derive_ops(pc)
        for vid in ("10", "20", "30", "31", "32"):
            matches = [op for op in ops if op.path == ("vlans", vid)]
            assert len(matches) == 1 and matches[0].origin == "native", vid
        for vid in ("40", "50", "51", "55"):
            matches = [op for op in ops if op.path == ("vlan", vid)]
            assert len(matches) == 1 and matches[0].origin == "native", vid

    def test_derived_lacp_set_retired_by_exact_path_dedupe(self):
        pc = _parse("lacp system-priority 100\n")
        ops = derive_ops(pc)
        matches = [op for op in ops if op.path == ("lacp_system_priority",)]
        assert len(matches) == 1 and matches[0].origin == "native"

    def test_anti_rot_family8c_never_derived(self):
        pc = _parse(KITCHEN_SINK)
        ops = derive_ops(pc)
        sections = singleton_section_fields()
        for op in ops:
            if op.path[0] in sections or op.path[0] in ("vlans", "vlan"):
                assert op.origin == "native", op
            if (
                len(op.path) >= 2
                and op.path[0] in ("field", "singleton")
                and op.path[1] in sections
            ):
                assert op.origin == "native", op

    def test_create_op_encodes_to_set_fields(self):
        pc = _parse("vtp domain CORP\n")
        art = encode_legacy(derive_ops(pc))
        assert ("vtp", "instance") in art.set_fields
        assert art.no_commands == []


# ---------------------------------------------------------------------------
# Per-OS gate
# ---------------------------------------------------------------------------


class TestPerOS:
    def test_iosxr_gated_no_8c_natives_derived_sets_survive(self):
        pc = IOSXRParser("lldp\nvtp domain CORP\nlacp system-priority 100\n").parse()
        assert _native_sect(pc) == []
        assert not any(
            op.path == ("lacp_system_priority",) and op.origin == "native"
            for op in (pc.native_change_ops or [])
        )
        ops = derive_ops(pc)
        if pc.lldp is not None:
            assert any(
                op.path == ("lldp",) and op.origin == "derived" for op in ops
            )
        if pc.lacp_system_priority is not None:
            assert any(
                op.path == ("lacp_system_priority",) and op.origin == "derived"
                for op in ops
            )


# ---------------------------------------------------------------------------
# Codec anti-rot: registry completeness + rulings (the four new sections)
# ---------------------------------------------------------------------------


class TestCodec:
    @pytest.mark.parametrize("section", SECTIONS_8C)
    def test_registry_partitions_model_fields_completely(self, section):
        """Every model field is provenance, a structural scalar, or a
        registered member kind — the T.3/U.1 pin extended to family 8c."""
        from confgraph.change_ir import _PROVENANCE_FIELDS
        from confgraph.models.cdp import CDPConfig
        from confgraph.models.lldp import LLDPConfig
        from confgraph.models.stp import STPConfig
        from confgraph.models.vlan import VTPConfig

        model = {
            "lldp": LLDPConfig,
            "cdp": CDPConfig,
            "spanning_tree": STPConfig,
            "vtp": VTPConfig,
        }[section]
        scalars = singleton_scalar_fields(section)
        members = singleton_member_kinds(section)
        assert not (scalars & members)
        for name in model.model_fields:
            assert (
                name in _PROVENANCE_FIELDS or name in scalars or name in members
            ), f"{section}.{name} is not covered by the family-8c registry"

    def test_line_detected_registrations(self):
        assert singleton_line_detected_scalars("lldp") == frozenset({"enabled"})
        assert singleton_line_detected_scalars("cdp") == frozenset(
            {"enabled", "advertise_v2"}
        )
        assert singleton_line_detected_scalars("spanning_tree") == frozenset()
        assert singleton_line_detected_scalars("vtp") == frozenset()

    def test_vlan_op_origin_gate(self):
        derived_set = ChangeOp(verb=Verb.SET, path=("vlans", "10"), value=None)
        derived_del = ChangeOp(
            verb=Verb.OBJECT_DELETE, path=("vlan", "10"), value=None
        )
        assert not is_native_vlan_op(derived_set)
        assert not is_native_vlan_op(derived_del)
        assert is_native_vlan_op(
            ChangeOp(
                verb=Verb.SET, path=("vlans", "10"), value=None, origin="native"
            )
        )
        assert is_native_vlan_op(
            ChangeOp(
                verb=Verb.OBJECT_DELETE,
                path=("vlan", "10"),
                value=None,
                origin="native",
            )
        )

    def test_member_keys_are_string_tuples(self):
        pc = _parse(KITCHEN_SINK)
        for op in _native_sect(pc) + _native_vlan(pc):
            assert all(isinstance(seg, str) for seg in op.path), op.path
