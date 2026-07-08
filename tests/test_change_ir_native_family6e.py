"""Change-IR Phase 3, family 6e — routing-process whole-instance-SET retirement.

CCR: ``change_ir_proposal_operations.md`` Appendix Q (WI-6e).

Covers (codec + parser side):
- the whole-instance CREATE-op predicates (``is_native_{isis,eigrp,ospf}_
  instance_create_op``) and their shapes (IS-IS 3-seg on the single tag incl.
  bare ""; EIGRP/OSPF 4-seg on the two-segment key),
- ``derive_ops`` prefix claims: the derived whole-instance SET is RETIRED for
  every fully-native instance (exactly one create op takes its place), while
  the claim is create-op-scoped (families 1–5 dedupe + gated coexistence
  untouched),
- the per-protocol gates (Appendix Q.2): IOS-XR OSPF + IS-IS and EOS IS-IS —
  own-parser paths — keep the derived SET and emit NO create op; EIGRP is
  never gated,
- anti-rot inverse pin (kitchen-sink config → zero derived whole-instance
  SETs, one create op per instance) and the Phase-4 shim note (the create op
  encodes to ``set_fields``).

Engine-side mirrors (creation pre-passes, delete-wins suppression, the OSPF
existing-instance residual) live in confgraph-entrp
``tests/test_change_ir_native_family6e.py``.
"""

from __future__ import annotations

from confgraph.change_ir import (
    Verb,
    derive_ops,
    encode_legacy,
    is_native_eigrp_instance_create_op,
    is_native_eigrp_op,
    is_native_isis_instance_create_op,
    is_native_isis_op,
    is_native_ospf_instance_create_op,
    is_native_ospf_op,
)
from confgraph.parsers.eos_parser import EOSParser
from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.iosxr_parser import IOSXRParser
from confgraph.parsers.nxos_parser import NXOSParser


def _parse(text: str, parser_cls=IOSParser):
    return parser_cls(text).parse()


KITCHEN_SINK = (
    "interface GigabitEthernet0/0\n"
    " mtu 9000\n"
    " ip router isis CORE\n"
    "ip route 10.0.0.0 255.0.0.0 10.1.1.1\n"
    "router bgp 65000\n"
    " neighbor 10.0.0.2 remote-as 65001\n"
    "router ospf 1\n"
    " router-id 1.1.1.1\n"
    " log-adjacency-changes\n"
    " network 10.0.0.0 0.0.0.255 area 0\n"
    " area 1 stub\n"
    " area 1 range 10.1.0.0 255.255.0.0\n"
    "router ospf 2 vrf CUST\n"
    " network 172.16.0.0 0.0.255.255 area 0\n"
    "router isis CORE\n"
    " net 49.0001.0000.0000.0001.00\n"
    " metric-style wide\n"
    "router eigrp 100\n"
    " network 10.0.0.0\n"
    " router-id 9.9.9.9\n"
)


# --- create-op emission (IOS + NX-OS) ---------------------------------------

def test_create_ops_emitted_per_instance():
    pc = _parse(KITCHEN_SINK)
    natives = pc.native_change_ops
    creates = [
        op.path
        for op in natives
        if is_native_isis_instance_create_op(op)
        or is_native_eigrp_instance_create_op(op)
        or is_native_ospf_instance_create_op(op)
    ]
    assert sorted(creates) == sorted(
        [
            ("isis_instances", "CORE", "instance"),
            ("eigrp_instances", "100", "", "instance"),
            ("ospf_instances", "1", "", "instance"),
            ("ospf_instances", "2", "CUST", "instance"),
        ]
    )
    # value = the FULL parsed instance (the engine's creation seed strips the
    # natively-rebuilt fields; the codec carries everything).
    ospf_create = next(
        op for op in natives
        if op.path == ("ospf_instances", "1", "", "instance")
    )
    assert str(ospf_create.value.process_id) == "1"
    assert ospf_create.value.areas  # areas ride the value (seeded engine-side)
    assert ospf_create.value.log_adjacency_changes is True  # parser truth
    # Block provenance (not blank) — the "SET provenance uses block raw
    # lines" contract holds for the first instance-scoped op.
    assert "router ospf 1" in ospf_create.source_line
    assert ospf_create.line_no >= 0


def test_nxos_inherits_create_ops():
    pc = _parse(
        "router ospf 1\n"
        " router-id 2.2.2.2\n"
        "router isis CORE\n"
        " net 49.0001.0000.0000.0001.00\n"
        "router eigrp 100\n"
        " network 10.0.0.0\n",
        parser_cls=NXOSParser,
    )
    paths = {op.path for op in pc.native_change_ops}
    assert ("ospf_instances", "1", "", "instance") in paths
    assert ("isis_instances", "CORE", "instance") in paths
    assert ("eigrp_instances", "100", "", "instance") in paths


def test_create_ops_are_native_family_ops():
    # The create shapes are members of their family predicates (the engine's
    # _proposal_from_ops skip and the H.3 exclusion both key on these).
    pc = _parse(KITCHEN_SINK)
    for op in pc.native_change_ops:
        if is_native_isis_instance_create_op(op):
            assert is_native_isis_op(op)
        if is_native_eigrp_instance_create_op(op):
            assert is_native_eigrp_op(op)
        if is_native_ospf_instance_create_op(op):
            assert is_native_ospf_op(op)


def test_bare_tag_isis_create_op():
    pc = _parse("router isis\n net 49.0002.0000.0000.0002.00\n")
    creates = [
        op for op in pc.native_change_ops
        if is_native_isis_instance_create_op(op)
    ]
    assert len(creates) == 1
    assert creates[0].path == ("isis_instances", "", "instance")


# --- retirement in composition ----------------------------------------------

def test_anti_rot_inverse_no_whole_instance_sets():
    # THE 6e inverse pin: the deriver emits ZERO whole-instance SETs for the
    # three protocols on a fully-native config — exactly one create op per
    # instance claims each prefix.
    pc = _parse(KITCHEN_SINK)
    ops = derive_ops(pc)
    whole_instance_sets = [
        op.path
        for op in ops
        if op.verb is Verb.SET
        and (
            (op.path[0] == "isis_instances" and len(op.path) == 2)
            or (op.path[0] == "eigrp_instances" and len(op.path) == 3)
            or (op.path[0] == "ospf_instances" and len(op.path) == 3)
        )
    ]
    assert whole_instance_sets == []
    creates = [
        op
        for op in ops
        if is_native_isis_instance_create_op(op)
        or is_native_eigrp_instance_create_op(op)
        or is_native_ospf_instance_create_op(op)
    ]
    assert len(creates) == 4  # 2×OSPF + IS-IS + EIGRP — exactly one each
    # BGP retirement (5c-B.2) unchanged beside the new claims.
    assert any(op.path == ("bgp_instances", "65000", "", "instance") for op in ops)
    assert not any(op.path == ("bgp_instances", "65000", "") for op in ops)


def test_claim_is_instance_scoped_no_cross_instance_overclaim():
    # Two OSPF instances sharing nothing: each create op claims only ITS
    # len-3 prefix — no len-1/len-2 partial claims that could swallow
    # unrelated derived content.
    pc = _parse(
        "router ospf 1\n network 10.0.0.0 0.0.0.255 area 0\n"
        "router ospf 2 vrf CUST\n network 172.16.0.0 0.0.255.255 area 0\n"
    )
    ops = derive_ops(pc)
    assert not any(
        op.verb is Verb.SET and op.path in (("ospf_instances", "1", ""), ("ospf_instances", "2", "CUST"))
        for op in ops
    )
    creates = {op.path for op in ops if is_native_ospf_instance_create_op(op)}
    assert creates == {
        ("ospf_instances", "1", "", "instance"),
        ("ospf_instances", "2", "CUST", "instance"),
    }


def test_families_1_5_dedupe_unchanged():
    # The claim is create-op-scoped: interface (F1), static (F4) and vlan
    # derived SETs are untouched by the 6e claims.  Family 8a (CCR Appendix
    # T) later retired the derived ntp whole-section SET too — that leg of
    # the pin flipped in place to the native create op (the L.4/Q.4
    # pattern); the un-migrated vlan SET is the surviving derived control.
    pc = _parse(
        "interface GigabitEthernet0/1\n mtu 9000\n"
        "ip route 10.50.0.0 255.255.0.0 10.1.1.253\n"
        "ntp server 10.0.0.1\n"
        "vlan 400\n name NEW-USERS\n"
        "router ospf 1\n network 10.0.0.0 0.0.0.255 area 0\n"
    )
    ops = derive_ops(pc)
    paths = {op.path for op in ops}
    assert ("interface", "GigabitEthernet0/1", "mtu") in paths
    assert ("ntp",) not in paths
    assert ("ntp", "instance") in paths
    assert ("vlans", "400") in paths
    assert any(p[0] == "static_routes" for p in paths)


def test_create_op_encodes_to_set_fields():
    # Phase-4 deprecation-shim note (the L.7 pattern): the create op encodes
    # to set_fields[(container, key…, "instance")]; the inverse ops→legacy
    # shim will reconstitute the whole-instance SET from it.
    pc = _parse("router ospf 1\n router-id 1.1.1.1\n")
    art = encode_legacy(derive_ops(pc))
    assert ("ospf_instances", "1", "", "instance") in art.set_fields
    assert art.no_commands == []  # no tombstone leakage


# --- gates (Appendix Q.2): own-parser paths keep the derived SET ------------

XR_IGP = (
    "router ospf 1\n"
    " router-id 1.1.1.1\n"
    " area 0\n"
    "  interface GigabitEthernet0/0/0/0\n"
    "router isis CORE\n"
    " net 49.0001.0000.0000.0001.00\n"
)


def test_gated_iosxr_keeps_derived_set_no_create_op():
    pc = _parse(XR_IGP, parser_cls=IOSXRParser)
    assert pc.ospf_instances and pc.isis_instances  # XR walks parsed them
    ops = derive_ops(pc)
    # NO create ops (gated)…
    assert not any(is_native_ospf_instance_create_op(op) for op in ops)
    assert not any(is_native_isis_instance_create_op(op) for op in ops)
    # …so the derived whole-instance SETs SURVIVE (coexistence, unchanged).
    assert any(
        op.verb is Verb.SET and op.path == ("ospf_instances", "1", "")
        for op in ops
    )
    assert any(
        op.verb is Verb.SET and op.path == ("isis_instances", "CORE")
        for op in ops
    )


def test_gated_eos_isis_keeps_derived_set_no_create_op():
    pc = _parse(
        "router isis CORE\n"
        "   net 49.0001.0000.0000.0001.00\n"
        "   is-type level-2\n",
        parser_cls=EOSParser,
    )
    assert pc.isis_instances
    ops = derive_ops(pc)
    assert not any(is_native_isis_instance_create_op(op) for op in ops)
    assert any(
        op.verb is Verb.SET and op.path == ("isis_instances", "CORE")
        for op in ops
    )


def test_eigrp_never_gated_all_ios_family():
    # No parser overrides parse_eigrp — the gate documents that invariant;
    # every IOS-family parser retires EIGRP.
    for cls in (IOSParser, NXOSParser):
        pc = _parse("router eigrp 100\n network 10.0.0.0\n", parser_cls=cls)
        ops = derive_ops(pc)
        assert any(is_native_eigrp_instance_create_op(op) for op in ops), cls
        assert not any(
            op.verb is Verb.SET and op.path == ("eigrp_instances", "100", "")
            for op in ops
        ), cls
