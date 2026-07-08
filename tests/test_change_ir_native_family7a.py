"""Change-IR Phase 3, family 7a — native VRF decomposition op emission.

CCR: ``change_ir_proposal_operations.md`` Appendix R (WI-7a).

Covers:
- the codec-owned predicates (``is_native_vrf_op`` /
  ``is_native_vrf_delete_op``) and the path shapes: member/scalar SETs on the
  PLURAL ``vrfs`` container, removals on the byte-exact ``("field","vrfs",…)``
  colon-split tombstone shapes,
- native emission for the positive decomposition (rd / route-maps / RT
  members with LAST-occurrence line provenance — the R.0 re-added-later
  ordering basis) beside the SURVIVING derived whole-VRF SET (co-existence —
  7a does NOT retire it; retirement is 7b),
- the WI-7 removals migrated to NATIVE line-numbered ops with byte-exact
  ``field:vrfs:…`` twins regenerated via ``encode_legacy`` (single source),
  emitted UNCONDITIONALLY (refresh is resolved in the engine replay — R.0
  design item 1, NOT emission suppression),
- colon-in-RT round-trip per RT form (R.0 design item 2),
- hybrid ``derive_ops`` composition + anti-rot (every family-7a op is
  native; the derived whole-VRF SET survives; families 1–6 dedupe unchanged),
- per-OS reality: NX-OS ``vrf context`` (nested-under-AF lines), EOS
  ``vrf instance`` (state-walk positives, no removals), IOS-XR (state-walk
  positives; the ``vrf:<name>`` D1 shape stays NON-native).
"""

from __future__ import annotations

from confgraph.change_ir import (
    Verb,
    derive_ops,
    encode_legacy,
    is_native_vrf_delete_op,
    is_native_vrf_op,
)
from confgraph.parsers.eos_parser import EOSParser
from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.iosxr_parser import IOSXRParser
from confgraph.parsers.junos_parser import JunOSParser
from confgraph.parsers.nxos_parser import NXOSParser


def _parse(text: str, parser_cls=IOSParser):
    return parser_cls(text).parse()


def _f7(pc):
    return [op for op in pc.native_change_ops if is_native_vrf_op(op)]


VRF_FULL = (
    "vrf definition GUEST\n"
    " rd 65400:1\n"
    " route-map RM-IN import\n"
    " route-map RM-OUT export\n"
    " address-family ipv4\n"
    "  route-target export 65400:10\n"
    "  route-target import 65400:10\n"
    "  route-target both 65400:77\n"
    "  no route-target export 65400:20\n"
    "  no rd\n"
    "no vrf definition OLD\n"
)


class TestPositiveEmission:
    def test_full_surface_member_sets(self):
        pc = _parse(VRF_FULL)
        sets = {
            (op.path[2], op.path[3]): op
            for op in _f7(pc)
            if op.verb is Verb.SET
        }
        assert ("scalar", "rd") in sets and sets[("scalar", "rd")].value == "65400:1"
        assert sets[("scalar", "route_map_import")].value == "RM-IN"
        assert sets[("scalar", "route_map_export")].value == "RM-OUT"
        assert sets[("route_target_export", "65400:10")].value == "65400:10"
        assert sets[("route_target_import", "65400:10")].value == "65400:10"
        assert sets[("route_target_both", "65400:77")].value == "65400:77"
        # RT value is ONE segment on the SET path (never colon-joined).
        assert sets[("route_target_export", "65400:10")].path == (
            "vrfs", "GUEST", "route_target_export", "65400:10",
        )
        for op in sets.values():
            assert op.origin == "native"

    def test_member_sets_carry_real_member_lines(self):
        pc = _parse(VRF_FULL)
        by_key = {
            (op.path[2], op.path[3]): op.line_no
            for op in _f7(pc)
            if op.verb is Verb.SET
        }
        # Lines are 0-based parse positions; assert strict per-member ordering
        # rather than absolute numbers: rd < rt export < rt import < rt both.
        assert (
            by_key[("scalar", "rd")]
            < by_key[("route_target_export", "65400:10")]
            < by_key[("route_target_import", "65400:10")]
            < by_key[("route_target_both", "65400:77")]
        )

    def test_readded_member_carries_last_occurrence_line(self):
        pc = _parse(
            "vrf definition GUEST\n"
            " address-family ipv4\n"
            "  no route-target export 65400:10\n"
            "  route-target export 65400:10\n"
        )
        removal = next(op for op in _f7(pc) if op.verb is Verb.LIST_REMOVE)
        positive = next(
            op
            for op in _f7(pc)
            if op.verb is Verb.SET and op.path[2] == "route_target_export"
        )
        # The R.0 ordering basis: the re-add line is AFTER the removal line.
        assert positive.line_no > removal.line_no >= 0

    def test_default_fields_emit_no_set(self):
        pc = _parse("vrf definition EMPTY\n")
        assert [op for op in _f7(pc) if op.verb is Verb.SET] == []


class TestRemovalEmission:
    def test_rt_removal_native_byte_exact(self):
        pc = _parse(VRF_FULL)
        removal = next(op for op in _f7(pc) if op.verb is Verb.LIST_REMOVE)
        assert removal.path == (
            "field", "vrfs", "GUEST", "route_target_export", "65400", "20",
        )
        assert removal.origin == "native"
        assert removal.line_no >= 0
        assert removal.source_line == "no route-target export 65400:20"
        assert encode_legacy([removal]).no_commands == [
            "field:vrfs:GUEST:route_target_export:65400:20"
        ]
        assert "field:vrfs:GUEST:route_target_export:65400:20" in pc.no_commands

    def test_rd_reset_native_byte_exact(self):
        pc = _parse(VRF_FULL)
        rd_unset = next(op for op in _f7(pc) if op.verb is Verb.UNSET)
        assert rd_unset.path == ("field", "vrfs", "GUEST", "rd")
        assert encode_legacy([rd_unset]).no_commands == ["field:vrfs:GUEST:rd"]
        assert "field:vrfs:GUEST:rd" in pc.no_commands

    def test_whole_vrf_delete_native_line_numbered(self):
        pc = _parse(VRF_FULL)
        delete = next(op for op in _f7(pc) if op.verb is Verb.OBJECT_DELETE)
        assert is_native_vrf_delete_op(delete)
        assert delete.path == ("field", "vrfs", "OLD")
        assert delete.line_no >= 0
        assert encode_legacy([delete]).no_commands == ["field:vrfs:OLD"]
        assert "field:vrfs:OLD" in pc.no_commands

    def test_refresh_removal_emitted_unconditionally(self):
        # R.0 design item 1: NO emission suppression — the op is always
        # emitted (its byte-exact twin keeps legacy identical and the
        # round-trip pin holds); the engine replay resolves the refresh.
        pc = _parse(
            "vrf definition GUEST\n"
            " address-family ipv4\n"
            "  no route-target export 65400:10\n"
            "  route-target export 65400:10\n"
        )
        removals = [op for op in _f7(pc) if op.verb is Verb.LIST_REMOVE]
        assert len(removals) == 1
        assert "field:vrfs:GUEST:route_target_export:65400:10" in pc.no_commands


class TestColonRoundTrip:
    def test_rt_forms_round_trip_byte_exact(self):
        # R.0 design item 2 — every RT form the parsers produce.
        for rt in ("65400:10", "192.0.2.1:10", "4200000000:99", "65400:10:extra"):
            pc = _parse(
                "vrf definition T\n"
                " address-family ipv4\n"
                f"  no route-target import {rt}\n"
            )
            expected = f"field:vrfs:T:route_target_import:{rt}"
            assert pc.no_commands == [expected]
            removal = next(op for op in _f7(pc) if op.verb is Verb.LIST_REMOVE)
            assert encode_legacy([removal]).no_commands == [expected]


class TestComposition:
    def test_derived_whole_vrf_set_survives(self):
        # 7a co-existence — retirement is 7b (H.3 exclusion).
        ops = derive_ops(_parse(VRF_FULL))
        survivors = [
            op
            for op in ops
            if op.verb is Verb.SET and op.path == ("vrfs", "GUEST")
        ]
        assert len(survivors) == 1
        assert survivors[0].origin == "derived"

    def test_derived_twins_deduped(self):
        # The native removals claim their derived twins via exact-path dedupe.
        ops = derive_ops(_parse(VRF_FULL))
        field_vrfs = [op for op in ops if op.path[:2] == ("field", "vrfs")]
        assert field_vrfs, "removal ops must be present"
        assert all(op.origin == "native" for op in field_vrfs)

    def test_anti_rot_family7a_never_derived(self):
        ops = derive_ops(_parse(VRF_FULL))
        for op in ops:
            if op.path and op.path[0] == "vrfs" and len(op.path) == 4:
                assert op.origin == "native", op
            if op.path[:2] == ("field", "vrfs"):
                assert op.origin == "native", op

    def test_families_1_6_dedupe_unchanged(self):
        pc = _parse(
            "interface GigabitEthernet0/1\n"
            " description uplink\n"
            " no cdp enable\n"
            "ip route 10.9.0.0 255.255.0.0 10.0.0.9\n"
            "router ospf 1\n"
            " network 10.0.0.0 0.0.0.255 area 0\n"
            "router bgp 65000\n"
            " neighbor 10.0.0.2 remote-as 65001\n"
            + VRF_FULL
        )
        ops = derive_ops(pc)
        # Family-7a natives present beside the other families' ops.
        assert any(is_native_vrf_op(op) for op in ops)
        # Derived whole-VRF SET survives; whole-instance OSPF/BGP creates are
        # the 6e/L retirement shapes (unchanged by 7a).
        assert any(op.path == ("vrfs", "GUEST") and op.origin == "derived" for op in ops)
        assert any(op.path[0] == "ospf_instances" and op.origin == "native" for op in ops)


class TestPerOS:
    def test_nxos_context_nested_af_lines(self):
        pc = _parse(
            "vrf context TEN\n"
            " rd 65400:9\n"
            " address-family ipv4 unicast\n"
            "  route-target both 65400:99\n"
            "  no route-target export 65400:7\n"
            "  route-target export 65400:7\n"
            "no vrf context DEAD\n",
            NXOSParser,
        )
        removal = next(op for op in _f7(pc) if op.verb is Verb.LIST_REMOVE)
        positive = next(
            op
            for op in _f7(pc)
            if op.verb is Verb.SET and op.path[2] == "route_target_export"
        )
        # The nested-under-AF member line comes from the parse-object scan
        # (NOT the base-helper raw_lines, which omit AF-nested lines).
        assert positive.line_no > removal.line_no >= 0
        delete = next(op for op in _f7(pc) if op.verb is Verb.OBJECT_DELETE)
        assert delete.path == ("field", "vrfs", "DEAD")
        assert "field:vrfs:DEAD" in pc.no_commands

    def test_eos_instance_state_walk_positives_no_removals(self):
        pc = _parse(
            "vrf instance CUST\n"
            " rd 65000:5\n"
            " route-target import evpn 65000:100\n"
            "no vrf instance CUST\n",
            EOSParser,
        )
        sets = [op for op in _f7(pc) if op.verb is Verb.SET]
        assert ("vrfs", "CUST", "route_target_import", "65000:100") in [
            op.path for op in sets
        ]
        # EOS removal spellings are Phase-5 parity debt — blind both modes.
        assert [op for op in _f7(pc) if op.verb is not Verb.SET] == []
        assert "field:vrfs:CUST" not in pc.no_commands

    def test_iosxr_state_walk_positives_and_d1_shape_not_native(self):
        pc = _parse(
            "vrf CUSTOMER_A\n"
            " address-family ipv4 unicast\n"
            "  import route-target\n"
            "   65000:100\n"
            "  !\n"
            "no vrf CUSTOMER_B\n",
            IOSXRParser,
        )
        sets = [op for op in _f7(pc) if op.verb is Verb.SET]
        assert ("vrfs", "CUSTOMER_A", "route_target_import", "65000:100") in [
            op.path for op in sets
        ]
        # The XR whole-VRF delete stays on the D1 derived path (vrf:<name>).
        assert "vrf:CUSTOMER_B" in pc.no_commands
        ops = derive_ops(pc)
        d1 = next(op for op in ops if op.path == ("vrf", "CUSTOMER_B"))
        assert d1.origin == "derived"
        assert not is_native_vrf_op(d1)

    def test_junos_natives_less(self):
        pc = _parse(
            "routing-instances {\n"
            "    CUST-A {\n"
            "        instance-type vrf;\n"
            "        interface ge-0/0/2.0;\n"
            "        route-distinguisher 65000:100;\n"
            "        vrf-target target:65000:100;\n"
            "    }\n"
            "}\n",
            JunOSParser,
        )
        assert not (pc.native_change_ops or [])
        # Derived whole-VRF SET carries the JunOS instance (legacy path).
        ops = derive_ops(pc)
        assert any(op.path == ("vrfs", "CUST-A") for op in ops)
