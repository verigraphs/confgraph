"""Change-IR Phase 3, family 6d — native OSPF area decomposition (emission).

CCR: ``change_ir_proposal_operations.md`` Appendix P (WI-6d).

Covers:
- the codec key helpers (``ospf_area_range_key`` / ``ospf_area_virtual_link_key``)
  and predicates (``is_native_ospf_op`` area shapes /
  ``is_native_ospf_area_range_removal_op``),
- native emission of the nested keyed area decomposition (per-area
  create/final-state SHELL + scalar / range / virtual_link member SETs) on the
  PLURAL ``ospf_instances`` container, beside the SURVIVING derived
  whole-instance SET (co-existence — 6d does NOT retire it),
- parser-absence cleanliness (P.1): a NORMAL default area emits NO area_type
  scalar; unparsed fields (default_cost / nssa_translate / range not-advertise)
  never fire,
- the ops-only ``no area N range A M`` LIST_REMOVE with NO legacy twin
  (``encode_legacy`` silent — legacy stays byte-identically blind), its WI-8
  refresh suppression three-shape matrix, and canonicalization consistency
  (removal prefix normalized through the SAME ``IPv4Network(addr/mask)``
  construction as the positive range parse),
- the stub/nssa area-reset tombstones STAY DERIVED (byte-exact legacy twins;
  native ops never double-encode them — P.2 coexistence lives in the engine),
- anti-rot: every area-shaped op in the composed ChangeSet is native; the
  derived whole-instance SET survives composition,
- VRF instance keying + NX-OS inheritance.
"""

from __future__ import annotations

from ipaddress import IPv4Network

from confgraph.change_ir import (
    Verb,
    derive_ops,
    encode_legacy,
    is_native_ospf_area_range_removal_op,
    is_native_ospf_op,
    ospf_area_range_key,
    ospf_area_virtual_link_key,
)
from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.nxos_parser import NXOSParser


def _parse(text: str, parser_cls=IOSParser):
    return parser_cls(text).parse()


def _ospf_ops(pc):
    return [op for op in pc.native_change_ops if is_native_ospf_op(op)]


def _area_ops(pc):
    return [
        op for op in _ospf_ops(pc)
        if (op.verb is Verb.SET and op.path[3] == "area")
        or (op.verb is Verb.LIST_REMOVE and op.path[3] == "area")
    ]


OSPF_AREAS_FULL = (
    "router ospf 1\n"
    " router-id 1.1.1.1\n"
    " area 1 stub no-summary\n"
    " area 1 range 10.1.0.0 255.255.0.0\n"
    " area 1 range 10.2.0.0 255.255.0.0\n"
    " area 2 nssa default-information-originate always\n"
    " area 2 virtual-link 10.9.9.9 hello-interval 5 dead-interval 20\n"
    " area 3 authentication message-digest\n"
    " area 3 filter-list prefix PL-IN in\n"
    " area 3 filter-list prefix PL-OUT out\n"
    " network 192.0.2.0 0.0.0.255 area 1\n"
)


# --- codec key helpers -------------------------------------------------------

def test_ospf_area_range_key_is_str_prefix():
    pc = _parse(OSPF_AREAS_FULL)
    area1 = next(a for a in pc.ospf_instances[0].areas if a.area_id == "1")
    assert ospf_area_range_key(area1.ranges[0]) == ("10.1.0.0/16",)


def test_ospf_area_virtual_link_key_is_str_rid():
    pc = _parse(OSPF_AREAS_FULL)
    area2 = next(a for a in pc.ospf_instances[0].areas if a.area_id == "2")
    assert ospf_area_virtual_link_key(area2.virtual_links[0]) == ("10.9.9.9",)


# --- positive area decomposition --------------------------------------------

def test_area_shell_per_parsed_area():
    pc = _parse(OSPF_AREAS_FULL)
    shells = {
        op.path[4]: op.value
        for op in _area_ops(pc)
        if op.verb is Verb.SET and len(op.path) == 5
    }
    assert set(shells) == {"1", "2", "3"}
    # the shell carries the FULL parsed OSPFArea (the legacy append branch)
    assert shells["1"].area_type == "totally_stub"
    assert shells["1"].stub_no_summary is True
    assert [str(r.prefix) for r in shells["1"].ranges] == [
        "10.1.0.0/16", "10.2.0.0/16",
    ]


def test_area_member_ops_full_surface():
    pc = _parse(OSPF_AREAS_FULL)
    by_path = {op.path: op.value for op in _area_ops(pc) if op.verb is Verb.SET}
    p = ("ospf_instances", "1", "")
    assert by_path[p + ("area", "1", "scalar", "area_type")] == "totally_stub"
    assert by_path[p + ("area", "1", "scalar", "stub_no_summary")] is True
    assert str(by_path[p + ("area", "1", "range", "10.1.0.0/16")].prefix) == "10.1.0.0/16"
    assert str(by_path[p + ("area", "1", "range", "10.2.0.0/16")].prefix) == "10.2.0.0/16"
    assert by_path[p + ("area", "2", "scalar", "area_type")] == "nssa"
    assert by_path[p + ("area", "2", "scalar", "nssa_default_information_originate")] is True
    assert by_path[p + ("area", "2", "scalar", "nssa_default_information_originate_always")] is True
    vl = by_path[p + ("area", "2", "virtual_link", "10.9.9.9")]
    assert vl.hello_interval == 5 and vl.dead_interval == 20
    assert by_path[p + ("area", "3", "scalar", "authentication")] == "message-digest"
    assert by_path[p + ("area", "3", "scalar", "filter_list_in")] == "PL-IN"
    assert by_path[p + ("area", "3", "scalar", "filter_list_out")] == "PL-OUT"


def test_normal_default_area_emits_no_type_scalar():
    # P.1: parser-absence == model default for every OSPFArea field — an area
    # seeded only by a range line stays NORMAL and emits no area_type scalar
    # (and none of the unparsed fields ever fire).
    pc = _parse("router ospf 1\n area 5 range 10.5.0.0 255.255.0.0\n")
    scalars = [
        op.path[6]
        for op in _area_ops(pc)
        if op.verb is Verb.SET and len(op.path) == 7 and op.path[5] == "scalar"
    ]
    assert scalars == []
    shells = [op for op in _area_ops(pc) if op.verb is Verb.SET and len(op.path) == 5]
    assert len(shells) == 1 and shells[0].path[4] == "5"


def test_all_area_ops_are_native_and_line_numbered():
    pc = _parse(OSPF_AREAS_FULL)
    ops = _area_ops(pc)
    assert ops
    for op in ops:
        assert op.origin == "native"
        assert op.line_no >= 0


# --- ops-only ``no area N range`` withdrawal (P.3) ---------------------------

def _range_removals(pc):
    return [op for op in _ospf_ops(pc) if is_native_ospf_area_range_removal_op(op)]


def test_no_area_range_is_ops_only_list_remove():
    pc = _parse(
        "router ospf 1\n"
        " area 1 range 10.1.0.0 255.255.0.0\n"
        " no area 1 range 10.2.0.0 255.255.0.0\n"
    )
    rems = _range_removals(pc)
    assert len(rems) == 1
    op = rems[0]
    assert op.verb is Verb.LIST_REMOVE
    assert op.path == ("ospf_instance", "1", "", "area", "1", "range", "10.2.0.0/16")
    assert op.value is None
    assert op.source_line == "no area 1 range 10.2.0.0 255.255.0.0"
    # NO legacy twin: the tombstone containers stay empty and encode_legacy
    # emits nothing for the removal.
    assert pc.no_commands == []
    arts = encode_legacy(derive_ops(pc))
    assert all("range" not in ts for ts in arts.no_commands)


def test_no_area_range_refresh_suppressed():
    # no-then-readd LATER in the block → removal suppressed (re-add wins).
    pc = _parse(
        "router ospf 1\n"
        " no area 1 range 10.1.0.0 255.255.0.0\n"
        " area 1 range 10.1.0.0 255.255.0.0\n"
    )
    assert _range_removals(pc) == []


def test_no_area_range_withdrawal_stands():
    # removal of a range the block never re-adds → stands.
    pc = _parse("router ospf 1\n no area 1 range 10.1.0.0 255.255.0.0\n")
    assert len(_range_removals(pc)) == 1


def test_area_range_add_then_remove_removal_stands():
    # positive earlier, removal later → removal stands (line-ordered replay
    # nets to removed — device truth).
    pc = _parse(
        "router ospf 1\n"
        " area 1 range 10.1.0.0 255.255.0.0\n"
        " no area 1 range 10.1.0.0 255.255.0.0\n"
    )
    rems = _range_removals(pc)
    assert len(rems) == 1
    positive = [
        op for op in _area_ops(pc)
        if op.verb is Verb.SET and len(op.path) == 7 and op.path[5] == "range"
    ]
    assert positive and rems[0].line_no > positive[0].line_no


def test_no_area_range_different_area_not_suppressed():
    # same prefix re-added in a DIFFERENT area does not suppress the removal.
    pc = _parse(
        "router ospf 1\n"
        " no area 1 range 10.1.0.0 255.255.0.0\n"
        " area 2 range 10.1.0.0 255.255.0.0\n"
    )
    assert len(_range_removals(pc)) == 1


def test_no_area_range_mask_normalization_matches_positive_parse():
    # Canonicalization consistency: the removal walk builds the prefix through
    # the SAME IPv4Network(f"{addr}/{mask}") the positive range parse uses.
    pc = _parse("router ospf 1\n no area 1 range 10.128.0.0 255.128.0.0\n")
    (op,) = _range_removals(pc)
    assert op.path[6] == str(IPv4Network("10.128.0.0/255.128.0.0"))
    # an unparseable (host-bits-set, strict) range is dropped on BOTH walks
    pc2 = _parse(
        "router ospf 1\n"
        " area 1 range 10.1.0.1 255.255.0.0\n"
        " no area 1 range 10.1.0.1 255.255.0.0\n"
    )
    assert _range_removals(pc2) == []
    assert all(not a.ranges for o in pc2.ospf_instances for a in o.areas)


# --- stub/nssa resets stay DERIVED (P.2) -------------------------------------

def test_area_resets_stay_derived_byte_exact():
    pc = _parse(
        "router ospf 1\n"
        " area 1 stub\n"
        " no area 1 stub\n"
        " no area 2 nssa\n"
    )
    assert pc.no_commands == [
        "field:ospf:1:area:1:stub_reset",
        "field:ospf:1:area:2:nssa_reset",
    ]
    ops = derive_ops(pc)
    resets = [op for op in ops if op.path[-1] in ("stub_reset", "nssa_reset")]
    assert len(resets) == 2
    for op in resets:
        assert op.verb is Verb.UNSET
        assert op.origin == "derived"
        assert not is_native_ospf_op(op)
    # encode_legacy round-trips them byte-exact (no native double-encode).
    arts = encode_legacy(ops)
    assert arts.no_commands.count("field:ospf:1:area:1:stub_reset") == 1
    assert arts.no_commands.count("field:ospf:1:area:2:nssa_reset") == 1


def test_vrf_parent_reset_gap_documented():
    # Pre-existing VRF-blind parent-regex gap (tombstones.py:111/122): a
    # ``no area`` under ``router ospf N vrf M`` emits NO tombstone — blind in
    # BOTH modes.  Native POSITIVE area emission under the VRF instance works.
    pc = _parse(
        "router ospf 1 vrf CUST\n"
        " area 1 stub\n"
        " no area 1 stub\n"
    )
    assert pc.no_commands == []
    shells = [
        op for op in _area_ops(pc)
        if op.verb is Verb.SET and len(op.path) == 5
    ]
    assert shells and shells[0].path[:3] == ("ospf_instances", "1", "CUST")


# --- composition + anti-rot ---------------------------------------------------

def test_derived_whole_instance_set_retired_composition():
    # Pin flip (6e, CCR Appendix Q, the L.4 pattern): 6d rode the 6c
    # co-existence and this asserted "SET survives"; the create-op prefix
    # claim now retires the derived SET.
    pc = _parse(OSPF_AREAS_FULL)
    ops = derive_ops(pc)
    inst_sets = [
        op for op in ops
        if op.verb is Verb.SET and op.path == ("ospf_instances", "1", "")
    ]
    assert inst_sets == []  # RETIRED (6e)
    creates = [
        op for op in ops
        if op.verb is Verb.SET and op.path == ("ospf_instances", "1", "", "instance")
    ]
    assert len(creates) == 1 and creates[0].origin == "native"
    # The create-op VALUE still CARRIES areas at composition time — the engine
    # strips the natively-decomposed ones at seed time (P.4/Q.1), not the codec.
    assert creates[0].value.areas


def test_anti_rot_family6d_every_area_op_native():
    pc = _parse(OSPF_AREAS_FULL + " no area 1 range 10.9.0.0 255.255.0.0\n")
    ops = derive_ops(pc)
    area_shaped = [
        op for op in ops
        if (op.path[0] == "ospf_instances" and len(op.path) >= 5 and op.path[3] == "area")
        or (op.path[0] == "ospf_instance" and len(op.path) == 7 and op.path[3] == "area")
    ]
    assert area_shaped
    for op in area_shaped:
        assert op.origin == "native", op.path
        assert is_native_ospf_op(op), op.path


def test_vrf_instance_area_keys_carry_vrf():
    pc = _parse(
        "router ospf 2 vrf CUST\n"
        " area 0 stub\n"
        " no area 0 range 10.3.0.0 255.255.0.0\n"
    )
    shells = [op for op in _area_ops(pc) if op.verb is Verb.SET and len(op.path) == 5]
    assert shells[0].path == ("ospf_instances", "2", "CUST", "area", "0")
    (rem,) = _range_removals(pc)
    assert rem.path[:3] == ("ospf_instance", "2", "CUST")


def test_nxos_inherits_area_decomposition():
    pc = _parse(
        "router ospf 1\n"
        " area 1 stub\n"
        " area 1 range 10.1.0.0 255.255.0.0\n"
        " no area 1 range 10.2.0.0 255.255.0.0\n",
        parser_cls=NXOSParser,
    )
    shells = [op for op in _area_ops(pc) if op.verb is Verb.SET and len(op.path) == 5]
    assert shells and shells[0].path[4] == "1"
    assert len(_range_removals(pc)) == 1
