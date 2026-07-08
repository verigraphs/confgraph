"""Change-IR Phase 3, family 8f — policy objects (parser side).

CCR: ``change_ir_proposal_operations.md`` Appendix Y (WI-8f).

Covers:

- native whole-object CREATE + per-member SET emission for the five
  policy collections (``acls`` / ``route_maps`` / ``prefix_lists`` /
  ``community_lists`` / ``as_path_lists``) — path shapes, keys
  (seq-numbered vs positional), whole-item values, per-member
  last-occurrence lines (the re-added-later ordering basis),
- NO scalar ops ever (``acl_type`` / ``list_type`` / ``afi`` /
  ``description`` are creation-only in the legacy merge fns and ride the
  create value — anti-rot pinned),
- retirement of the derived whole-object SETs via the create op's
  ``path[:2]`` claim (anti-rot inverse: kitchen-sink IOS config composes
  with ZERO derived policy SETs),
- the FOUR native removal twins (``acl:`` / ``acl-seq:`` /
  ``route-map:…:seq:`` / ``prefix-list:…:seq:``) — byte-exact tombstones
  regenerated FROM the ops at the same walk positions, exact-path dedupe
  of the derived twins,
- the X.0 latent-claim class stays closed: a native seq removal never
  prefix-claims the IOS-XR derived whole-object delete path,
- per-OS: NX-OS/EOS share the walks via ``super()``; IOS-XR is GATED
  (ATOMIC_REPLACE strategy — no native 8f ops, derived whole-object SETs
  AND the D1 ``route-map:``/``prefix-list:``/``acl:`` shapes survive
  derived, Appendix Y.1).
"""

from __future__ import annotations

from confgraph.change_ir import (
    Verb,
    derive_ops,
    encode_legacy,
    is_native_acl_delete_op,
    is_native_policy_instance_create_op,
    is_native_policy_member_op,
    is_native_policy_op,
    is_native_policy_removal_op,
    policy_member_field,
    policy_member_key,
    policy_object_fields,
)
from confgraph.parsers.eos_parser import EOSParser
from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.iosxr_parser import IOSXRParser
from confgraph.parsers.nxos_parser import NXOSParser

KITCHEN_SINK = """hostname r1
ip access-list extended ACL-IN
 10 permit tcp any any eq 179
 20 deny ip any any
 permit ip host 1.1.1.1 any
 remark keep-me
ip access-list standard ACL-STD
 permit 10.0.0.0 0.0.0.255
route-map RM-OUT permit 10
 description first
 set metric 100
route-map RM-OUT deny 20
 match ip address prefix-list PL-A
route-map RM-B permit 5
 continue 10
ip prefix-list PL-A seq 5 permit 10.0.0.0/8 le 24
ip prefix-list PL-A seq 10 deny 0.0.0.0/0
ip community-list standard CL-A permit 65000:100 65000:200
ip community-list expanded CL-X deny _100_
ip as-path access-list 42 permit _65001_
ip as-path access-list 42 deny .*
"""

REMOVALS = """hostname r1
no ip access-list extended ACL-OLD
ip access-list extended ACL-IN
 no 10
no route-map RM-OUT permit 20
no ip prefix-list PL-A seq 10
"""


def _policy_ops(pc):
    return [op for op in pc.native_change_ops if is_native_policy_op(op)]


def _creates(ops):
    return [op for op in ops if is_native_policy_instance_create_op(op)]


def _members(ops, field=None, name=None):
    out = [op for op in ops if is_native_policy_member_op(op)]
    if field is not None:
        out = [op for op in out if op.path[0] == field]
    if name is not None:
        out = [op for op in out if op.path[1] == name]
    return out


class TestBoundary:
    def test_registry_and_helpers(self):
        assert policy_object_fields() == frozenset(
            {"acls", "route_maps", "prefix_lists", "community_lists", "as_path_lists"}
        )
        assert policy_member_field("route_maps") == "sequences"
        assert policy_member_field("prefix_lists") == "sequences"
        for f in ("acls", "community_lists", "as_path_lists"):
            assert policy_member_field(f) == "entries"


class TestEmission:
    def test_create_op_per_object_with_block_provenance(self):
        pc = IOSParser(KITCHEN_SINK).parse()
        creates = _creates(_policy_ops(pc))
        by_key = {(op.path[0], op.path[1]): op for op in creates}
        assert set(by_key) == {
            ("acls", "ACL-IN"),
            ("acls", "ACL-STD"),
            ("route_maps", "RM-OUT"),
            ("route_maps", "RM-B"),
            ("prefix_lists", "PL-A"),
            ("community_lists", "CL-A"),
            ("community_lists", "CL-X"),
            ("as_path_lists", "42"),
        }
        # value = the parsed object itself; block-head provenance.
        acl_op = by_key[("acls", "ACL-IN")]
        assert acl_op.value is pc.acls[0]
        assert acl_op.path[2] == "instance"
        assert acl_op.source_line.startswith("ip access-list extended ACL-IN")
        assert acl_op.line_no >= 0
        assert acl_op.origin == "native"

    def test_member_keys_seq_and_positional(self):
        pc = IOSParser(KITCHEN_SINK).parse()
        ops = _policy_ops(pc)
        rm = _members(ops, "route_maps", "RM-OUT")
        assert [op.path[2:] for op in rm] == [("sequences", "10"), ("sequences", "20")]
        pl = _members(ops, "prefix_lists", "PL-A")
        assert [op.path[3] for op in pl] == ["5", "10"]
        acl = _members(ops, "acls", "ACL-IN")
        # seq-numbered ACEs keyed by seq; unsequenced/remark positional.
        assert [op.path[3] for op in acl] == ["10", "20", "@2", "@3"]
        cl = _members(ops, "community_lists", "CL-A")
        assert [op.path[3] for op in cl] == ["@0"]
        ap = _members(ops, "as_path_lists", "42")
        assert [op.path[3] for op in ap] == ["@0", "@1"]

    def test_member_values_are_the_whole_parsed_items(self):
        pc = IOSParser(KITCHEN_SINK).parse()
        ops = _policy_ops(pc)
        rm_obj = next(r for r in pc.route_maps if r.name == "RM-OUT")
        rm_ops = _members(ops, "route_maps", "RM-OUT")
        assert [op.value for op in rm_ops] == rm_obj.sequences
        # per-entry content rides whole (ge/le/description; ACE flags).
        pl_entry = _members(ops, "prefix_lists", "PL-A")[0].value
        assert pl_entry.le == 24
        acl_e10 = _members(ops, "acls", "ACL-IN")[0].value
        assert acl_e10.destination_port == "eq 179"

    def test_member_key_helper_matches_registry(self):
        pc = IOSParser(KITCHEN_SINK).parse()
        for field in policy_object_fields():
            for obj in getattr(pc, field):
                attr = policy_member_field(field)
                for idx, item in enumerate(getattr(obj, attr)):
                    key = policy_member_key(field, item, idx)
                    assert isinstance(key, str) and key

    def test_member_lines_are_last_occurrence(self):
        cfg = """hostname r1
ip access-list extended ACL-IN
 10 permit tcp any any eq 179
 no 10
 10 permit tcp any any eq bgp
route-map RM permit 10
 set metric 1
no route-map RM permit 10
route-map RM permit 10
 set metric 2
ip prefix-list PL seq 5 permit 10.0.0.0/8
no ip prefix-list PL seq 5
ip prefix-list PL seq 5 permit 10.0.0.0/8 le 24
"""
        pc = IOSParser(cfg).parse()
        ops = _policy_ops(pc)
        removals = {op.path[0]: op for op in ops if is_native_policy_removal_op(op)}
        # every re-added member SET carries a line LATER than its removal
        for field, head, name, key in (
            ("acls", "acl-seq", "ACL-IN", "10"),
            ("route_maps", "route-map", "RM", "10"),
            ("prefix_lists", "prefix-list", "PL", "5"),
        ):
            mline = max(
                op.line_no for op in _members(ops, field, name) if op.path[3] == key
            )
            assert mline > removals[head].line_no >= 0

    def test_no_scalar_ops_ever(self):
        # Anti-rot (Appendix Y.2): every native policy SET is the create op
        # or a member op — a scalar op appearing means the blind-on-existing
        # parity ruling regressed.
        pc = IOSParser(KITCHEN_SINK).parse()
        for op in _policy_ops(pc):
            if op.verb is Verb.SET:
                assert is_native_policy_instance_create_op(
                    op
                ) or is_native_policy_member_op(op)

    def test_empty_collections_emit_nothing(self):
        pc = IOSParser("hostname r1\ninterface Loopback0\n").parse()
        assert _policy_ops(pc) == []


class TestRetirement:
    def test_anti_rot_inverse_no_whole_object_sets(self):
        pc = IOSParser(KITCHEN_SINK).parse()
        ops = derive_ops(pc)
        derived = [
            op
            for op in ops
            if op.origin == "derived" and op.path[0] in policy_object_fields()
        ]
        assert derived == []
        # exactly one create op per parsed object
        creates = _creates(ops)
        total = sum(len(getattr(pc, f)) for f in policy_object_fields())
        assert len(creates) == total == 8

    def test_removal_only_proposal_keeps_derived_free(self):
        pc = IOSParser(REMOVALS).parse()
        ops = derive_ops(pc)
        # the four twins are native, deduped exactly, byte-exact
        native_dels = [
            op
            for op in ops
            if is_native_policy_removal_op(op) or is_native_acl_delete_op(op)
        ]
        assert [":".join(op.path) for op in native_dels] == [
            "acl:ACL-OLD",
            "route-map:RM-OUT:seq:20",
            "prefix-list:PL-A:seq:10",
            "acl-seq:ACL-IN:10",
        ]
        derived_twins = [
            op
            for op in ops
            if op.origin == "derived"
            and op.path
            and op.path[0] in ("acl", "acl-seq", "route-map", "prefix-list")
        ]
        assert derived_twins == []

    def test_seq_removal_does_not_claim_whole_object_paths(self):
        # The 8e X.0 latent-claim class: a native seq removal path
        # ("route-map", <name>, "seq", <n>) must never claim
        # ("route-map", <name>) — the IOS-XR derived whole-object delete.
        from confgraph.change_ir import ChangeOp
        from confgraph.models.parsed_config import ParsedConfig

        pc = IOSParser(REMOVALS).parse()
        # hand-inject the XR-shape derived tombstone beside the native ops
        pc.no_commands.append("route-map:RM-OUT")
        ops = derive_ops(pc)
        xr_shape = [
            op
            for op in ops
            if op.verb is Verb.OBJECT_DELETE and op.path == ("route-map", "RM-OUT")
        ]
        assert len(xr_shape) == 1 and xr_shape[0].origin == "derived"


class TestRemovalTwins:
    def test_byte_exact_twins_and_walk_positions(self):
        pc = IOSParser(REMOVALS).parse()
        assert pc.no_commands == [
            "acl:ACL-OLD",
            "route-map:RM-OUT:seq:20",
            "prefix-list:PL-A:seq:10",
            "acl-seq:ACL-IN:10",
        ]
        # regenerated FROM the ops — single source, byte-exact round-trip
        ops = derive_ops(pc)
        art = encode_legacy(ops)
        assert sorted(
            t
            for t in art.no_commands
            if t.split(":")[0] in ("acl", "acl-seq", "route-map", "prefix-list")
        ) == sorted(pc.no_commands)

    def test_verbs_from_codec_registry(self):
        pc = IOSParser(REMOVALS).parse()
        ops = _policy_ops(pc)
        by_head = {op.path[0]: op for op in ops if op.verb is not Verb.SET}
        assert by_head["acl"].verb is Verb.OBJECT_DELETE
        assert by_head["acl-seq"].verb is Verb.LIST_REMOVE
        assert by_head["route-map"].verb is Verb.LIST_REMOVE
        assert by_head["prefix-list"].verb is Verb.LIST_REMOVE
        for op in by_head.values():
            assert op.line_no >= 0 and op.origin == "native"


class TestPerOS:
    def test_nxos_shares_the_walks(self):
        cfg = """hostname n9k
ip access-list ACL-NX
 10 permit tcp any any eq 179
route-map RM-NX permit 10
 set metric 5
no route-map RM-NX permit 20
"""
        pc = NXOSParser(cfg).parse()
        ops = _policy_ops(pc)
        assert {(op.path[0], op.path[1]) for op in _creates(ops)} == {
            ("acls", "ACL-NX"),
            ("route_maps", "RM-NX"),
        }
        assert "route-map:RM-NX:seq:20" in pc.no_commands
        assert any(is_native_policy_removal_op(op) for op in ops)

    def test_eos_shares_the_walks(self):
        cfg = """hostname eos1
ip access-list ACL-EOS
 10 permit tcp any any eq bgp
route-map RM-EOS permit 10
 set metric 5
ip community-list CL-EOS permit 65000:1
"""
        pc = EOSParser(cfg).parse()
        creates = _creates(_policy_ops(pc))
        assert {(op.path[0], op.path[1]) for op in creates} >= {
            ("acls", "ACL-EOS"),
            ("route_maps", "RM-EOS"),
            ("community_lists", "CL-EOS"),
        }
        # EOS derived SETs retired too
        derived = [
            op
            for op in derive_ops(pc)
            if op.origin == "derived" and op.path[0] in policy_object_fields()
        ]
        assert derived == []

    def test_iosxr_gated_fully_derived(self):
        cfg = """hostname xr1
route-policy RP-OUT
 pass
end-policy
prefix-set PS-A
 10.0.0.0/8 le 24
end-set
ipv4 access-list ACL-X
 10 permit ipv4 any any
no route-policy RP-OLD
no prefix-set PS-OLD
no ipv4 access-list ACL-GONE
"""
        pc = IOSXRParser(cfg).parse()
        assert pc.route_maps and pc.prefix_lists and pc.acls
        assert _policy_ops(pc) == []  # gated — Appendix Y.1
        ops = derive_ops(pc)
        # derived whole-object SETs SURVIVE (atomic-replace parity)
        survived = {
            op.path
            for op in ops
            if op.origin == "derived" and op.path[0] in policy_object_fields()
        }
        assert survived == {
            ("route_maps", "RP-OUT"),
            ("prefix_lists", "PS-A"),
            ("acls", "ACL-X"),
        }
        # the D1 whole-object shapes stay DERIVED (fix-forward path)
        d1 = [
            (op.verb, op.path)
            for op in ops
            if op.path and op.path[0] in ("acl", "route-map", "prefix-list")
        ]
        assert (Verb.OBJECT_DELETE, ("route-map", "RP-OLD")) in d1
        assert (Verb.OBJECT_DELETE, ("prefix-list", "PS-OLD")) in d1
        assert (Verb.OBJECT_DELETE, ("acl", "ACL-GONE")) in d1


class TestEncodeLegacy:
    def test_create_and_member_sets_encode_to_set_fields(self):
        pc = IOSParser(KITCHEN_SINK).parse()
        ops = derive_ops(pc)
        art = encode_legacy(ops)
        assert art.set_fields[("route_maps", "RM-OUT", "instance")] is next(
            r for r in pc.route_maps if r.name == "RM-OUT"
        )
        assert ("route_maps", "RM-OUT", "sequences", "10") in art.set_fields
        assert ("acls", "ACL-IN", "entries", "@2") in art.set_fields
