"""Change-IR Phase 3, family 7b — VRF whole-object-SET retirement (emission side).

CCR: ``change_ir_proposal_operations.md`` Appendix S (WI-7b).

Covers:
- the whole-VRF CREATE op codec (``is_native_vrf_instance_create_op``, the
  3-seg ``SET ("vrfs", name, "instance")`` shape, block provenance, value =
  the parsed VRFConfig),
- the create-scoped ``("vrfs", name)`` prefix claim in ``derive_ops`` (only
  the create op claims — member SETs never do; per-name scoping),
- the retirement gate: IOS-XR GATED (derived SET survives, no create op —
  the D1 ``vrf:`` deletion shape is Phase-5 surface), EOS UNGATED (state-walk
  positives + no possible deletions — the S.2 argument), JunOS natives-less,
- the anti-rot INVERSE pin (kitchen-sink config → zero derived whole-VRF
  SETs, exactly one create op per VRF),
- the Phase-4 shim shape (create op encodes to ``set_fields``),
- legacy-artifact neutrality (no tombstone from the create op).
"""

from __future__ import annotations

from confgraph.change_ir import (
    Verb,
    derive_ops,
    encode_legacy,
    is_native_vrf_instance_create_op,
    is_native_vrf_op,
)
from confgraph.models.vrf import VRFConfig
from confgraph.parsers.eos_parser import EOSParser
from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.iosxr_parser import IOSXRParser
from confgraph.parsers.nxos_parser import NXOSParser


def _parse(text: str, parser_cls=IOSParser):
    return parser_cls(text).parse()


VRF_TWO = (
    "vrf definition GUEST\n"
    " rd 65400:1\n"
    " address-family ipv4\n"
    "  route-target export 65400:10\n"
    "vrf definition CORP\n"
    " rd 65400:9\n"
)


class TestCreateOpCodec:
    def test_create_op_shape_value_and_provenance(self):
        pc = _parse(VRF_TWO)
        creates = [
            op for op in pc.native_change_ops if is_native_vrf_instance_create_op(op)
        ]
        assert sorted(op.path for op in creates) == [
            ("vrfs", "CORP", "instance"),
            ("vrfs", "GUEST", "instance"),
        ]
        guest = next(op for op in creates if op.path[1] == "GUEST")
        assert isinstance(guest.value, VRFConfig) and guest.value.name == "GUEST"
        # Block provenance (not blank) — order-independent pre-pass consumer.
        assert guest.source_line == "vrf definition GUEST"
        assert guest.line_no >= 0
        assert is_native_vrf_op(guest)

    def test_create_op_encodes_to_set_fields_no_tombstone(self):
        # Phase-4 shim shape (Appendix S.5): set_fields keyed by the op path;
        # NO tombstone — legacy artifacts stay byte-identical.
        pc = _parse(VRF_TWO)
        creates = [
            op for op in pc.native_change_ops if is_native_vrf_instance_create_op(op)
        ]
        art = encode_legacy(creates)
        assert set(art.set_fields) == {
            ("vrfs", "GUEST", "instance"),
            ("vrfs", "CORP", "instance"),
        }
        assert art.no_commands == []


class TestClaimScoping:
    def test_claim_is_per_name(self):
        # A hand-built ChangeSet: GUEST has a create op, PHANTOM only a
        # derived whole-VRF SET (natives-less producer) — PHANTOM's SET must
        # SURVIVE (the claim is create-op-scoped, per name).
        pc = _parse(VRF_TWO)
        ops = derive_ops(pc)
        assert not any(
            op.verb is Verb.SET and len(op.path) == 2 and op.path[0] == "vrfs"
            for op in ops
        )
        # Per-name scoping is pinned via the XR gate below (a gated VRF's SET
        # survives beside ungated retirement in the same registry) and the
        # 7a JunOS natives-less pin.

    def test_member_ops_do_not_claim(self):
        # A VRF whose ops are ONLY member SETs (hand-stripped create op) must
        # keep its derived whole-VRF SET — graceful degradation.
        pc = _parse(VRF_TWO)
        pc.native_change_ops = [
            op
            for op in pc.native_change_ops
            if not is_native_vrf_instance_create_op(op)
        ]
        ops = derive_ops(pc)
        survivors = [
            op
            for op in ops
            if op.verb is Verb.SET and len(op.path) == 2 and op.path[0] == "vrfs"
        ]
        assert sorted(op.path[1] for op in survivors) == ["CORP", "GUEST"]


class TestGates:
    def test_iosxr_gated_set_survives(self):
        pc = _parse(
            "vrf CUSTOMER_A\n"
            " address-family ipv4 unicast\n"
            "  import route-target\n"
            "   65000:100\n"
            "  !\n",
            IOSXRParser,
        )
        assert not any(
            is_native_vrf_instance_create_op(op) for op in pc.native_change_ops
        )
        ops = derive_ops(pc)
        assert any(
            op.verb is Verb.SET and op.path == ("vrfs", "CUSTOMER_A")
            for op in ops
        )

    def test_eos_ungated_retired(self):
        # S.2: EOS positives ride the parser-agnostic state walk and EOS has
        # no VRF deletion walk — creation can never fight a deletion.
        pc = _parse(
            "vrf instance CUST\n rd 65000:5\n route-target import evpn 65000:100\n",
            EOSParser,
        )
        ops = derive_ops(pc)
        assert any(op.path == ("vrfs", "CUST", "instance") for op in ops)
        assert not any(
            op.verb is Verb.SET and op.path == ("vrfs", "CUST") for op in ops
        )

    def test_nxos_ungated_retired(self):
        pc = _parse(
            "vrf context TEN\n rd 65400:9\n address-family ipv4 unicast\n"
            "  route-target both 65400:99\n",
            NXOSParser,
        )
        ops = derive_ops(pc)
        assert any(op.path == ("vrfs", "TEN", "instance") for op in ops)
        assert not any(
            op.verb is Verb.SET and op.path == ("vrfs", "TEN") for op in ops
        )


class TestCrossKindRegression:
    def test_cross_kind_readd_emits_both_sides(self):
        # Validator-added R.7 pin (emission half — the merge half is pinned in
        # the entrp family7b file): ``no route-target both X`` followed by
        # ``route-target import X`` emits BOTH the both-removal op AND the
        # import member SET, each with its real line — the engine's
        # re-added-later skip matches exact kind+value only, so the removal
        # must still arrive un-suppressed (emission is unconditional).
        pc = _parse(
            "vrf definition GUEST\n"
            " address-family ipv4\n"
            "  no route-target both 65400:77\n"
            "  route-target import 65400:77\n"
        )
        removal = next(
            op
            for op in pc.native_change_ops
            if op.verb is Verb.LIST_REMOVE
            and op.path[:4] == ("field", "vrfs", "GUEST", "route_target_both")
        )
        positive = next(
            op
            for op in pc.native_change_ops
            if op.verb is Verb.SET
            and op.path == ("vrfs", "GUEST", "route_target_import", "65400:77")
        )
        assert positive.line_no > removal.line_no >= 0
        assert "field:vrfs:GUEST:route_target_both:65400:77" in pc.no_commands


class TestAntiRot:
    def test_anti_rot_inverse_no_whole_vrf_sets(self):
        # Kitchen-sink config (families 1/4/5/6 + 7): ZERO derived whole-VRF
        # SETs, exactly ONE create op per parsed VRF.
        pc = _parse(
            "interface GigabitEthernet0/1\n"
            " description uplink\n"
            " vrf forwarding GUEST\n"
            "ip route 10.9.0.0 255.255.0.0 10.0.0.9\n"
            "router ospf 1\n"
            " network 10.0.0.0 0.0.0.255 area 0\n"
            "router bgp 65000\n"
            " neighbor 10.0.0.2 remote-as 65001\n"
            "router isis CORE\n"
            " net 49.0001.0000.0000.0001.00\n"
            "router eigrp 100\n"
            " network 10.50.0.0\n"
            + VRF_TWO
            + "no vrf definition OLD\n"
        )
        ops = derive_ops(pc)
        assert not any(
            op.verb is Verb.SET and len(op.path) == 2 and op.path[0] == "vrfs"
            for op in ops
        )
        creates = [op.path[1] for op in ops if is_native_vrf_instance_create_op(op)]
        assert sorted(creates) == ["CORP", "GUEST"]
        # Every field:vrfs deletion op is still native (7a anti-rot holds).
        for op in ops:
            if op.path[:2] == ("field", "vrfs"):
                assert op.origin == "native", op
