"""Change-IR Phase 3, family 5c-B.1 — native BGP AF-container decomposition
(WI-5c-B.1, task #21).

CCR: ``change_ir_proposal_operations.md`` Appendix K.

5c-B.1 decomposes the recursive AF container into per-AF keyed native ops while
the derived whole-instance ``SET ("bgp_instances", asn, vrf)`` STILL SURVIVES
(co-existing exactly like 5a/5b/5c-A — retirement is 5c-B.2 / task #23):

- AF create/final-state ``SET (…, "af", afi, safi, afvrf)`` (shell),
- AF-block ``network`` (closes the 5b instance-network deferral),
- AF ``redistribute`` positive; NEGATIVE stays derived (coexistence — delete-wins
  matching legacy; the ordering deviation is accepted, Appendix K),
- AF ``aggregate-address`` positive + ops-only ``no aggregate-address``
  LIST_REMOVE (no legacy twin — encode_legacy emits nothing, mirroring 5b
  ``no network``),
- AF scalars ``maximum_paths`` / ``maximum_paths_ibgp`` / tri-state None-default
  ``prefix_validate_allow_invalid``,
- byte-identity: AF SETs encode to ``set_fields`` only, the ops-only aggregate
  removal encodes to NOTHING; the derived whole-instance SET survives; anti-rot
  (no 5c-B.1 AF form derived); NX-OS VRF instances carry no AFs (no-op).

The three AF scalars (default_information_originate / auto_summary /
synchronization) were unparsed at 5c-B.1 time; task #22 (WI-DB3, Appendix Z)
delivered their parse + native emission — see ``test_af_flag_scalars_now_native``
below and ``test_change_ir_bgp_scalars.py`` for the full pins.
"""

from __future__ import annotations

from confgraph.change_ir import (
    Verb,
    bgp_af_key,
    derive_ops,
    encode_legacy,
    is_native_bgp_af_aggregate_removal_op,
    is_native_bgp_op,
)
from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.nxos_parser import NXOSParser


def _parse(text: str, parser_cls=IOSParser):
    return parser_cls(text).parse()


def _bgp_ops(pc):
    return [
        o
        for o in (pc.native_change_ops or [])
        if (o.path and o.path[0] in ("bgp_instances", "bgp_instance"))
    ]


def _af_ops(pc):
    return [o for o in _bgp_ops(pc) if len(o.path) > 3 and o.path[3] == "af"]


AF_CFG = """router bgp 65000
 address-family ipv4
  network 10.10.0.0 mask 255.255.0.0
  redistribute static route-map RM
  aggregate-address 10.0.0.0 255.0.0.0 summary-only
  no aggregate-address 172.16.0.0 255.240.0.0
  maximum-paths 4
  maximum-paths ibgp 2
  no bgp bestpath prefix-validate allow-invalid
"""


# ---------------------------------------------------------------------------
# Emission
# ---------------------------------------------------------------------------


def test_af_create_op_emitted_as_shell():
    pc = _parse(AF_CFG)
    creates = [o for o in _af_ops(pc) if o.verb is Verb.SET and len(o.path) == 7]
    assert len(creates) == 1
    op = creates[0]
    assert op.path == ("bgp_instances", "65000", "", "af", "ipv4", "unicast", "")
    assert op.origin == "native"
    # Shell carries identity only — no content (sub-ops fill it).
    assert op.value.afi == "ipv4" and op.value.safi == "unicast"
    assert op.value.networks == [] and op.value.redistribute == []
    assert op.value.aggregate_addresses == []
    assert op.value.maximum_paths is None


def test_af_network_op():
    pc = _parse(AF_CFG)
    nets = [o for o in _af_ops(pc) if len(o.path) > 7 and o.path[7] == "network"]
    assert [o.path[8] for o in nets] == ["10.10.0.0/16"]
    assert all(is_native_bgp_op(o) for o in nets)


def test_af_redistribute_positive_op():
    pc = _parse(AF_CFG)
    reds = [o for o in _af_ops(pc) if len(o.path) > 7 and o.path[7] == "redistribute"]
    assert [(o.path[8], o.path[9]) for o in reds] == [("static", "")]
    assert reds[0].value.route_map == "RM"


def test_af_aggregate_positive_and_ops_only_removal():
    pc = _parse(AF_CFG)
    aggs = [
        o
        for o in _af_ops(pc)
        if o.verb is Verb.SET and len(o.path) > 7 and o.path[7] == "aggregate"
    ]
    assert [o.path[8] for o in aggs] == ["10.0.0.0/8"]
    rems = [o for o in _af_ops(pc) if o.verb is Verb.LIST_REMOVE]
    assert len(rems) == 1
    op = rems[0]
    assert op.path == (
        "bgp_instance", "65000", "", "af", "ipv4", "unicast", "", "aggregate",
        "172.16.0.0/12",
    )
    assert is_native_bgp_op(op) and is_native_bgp_af_aggregate_removal_op(op)


def test_af_scalars():
    pc = _parse(AF_CFG)
    scal = {
        o.path[8]: o.value
        for o in _af_ops(pc)
        if len(o.path) > 7 and o.path[7] == "scalar"
    }
    assert scal == {
        "maximum_paths": 4,
        "maximum_paths_ibgp": 2,
        "prefix_validate_allow_invalid": False,
    }


def test_prefix_validate_tristate_permissive_and_absent():
    permissive = _parse(
        "router bgp 65000\n address-family ipv4\n"
        "  bgp bestpath prefix-validate allow-invalid\n"
    )
    scal = [o for o in _af_ops(permissive) if o.path[-1] == "prefix_validate_allow_invalid"]
    assert len(scal) == 1 and scal[0].value is True
    # Absent → None-default → no op (tri-state discipline).
    absent = _parse("router bgp 65000\n address-family ipv4\n  network 1.0.0.0 mask 255.0.0.0\n")
    assert not [o for o in _af_ops(absent) if o.path[-1] == "prefix_validate_allow_invalid"]


def test_af_flag_scalars_now_native():
    # PIN FLIPPED (WI-DB3, CCR Appendix Z): this test previously asserted the
    # task-#22 DEFERRAL (default_information_originate / auto_summary /
    # synchronization never parsed → no native op).  Task #22 delivers the
    # parser support, so the three AF flag lines now emit line-detected
    # AF-scalar SETs (True at their lines).
    pc = _parse(
        "router bgp 65000\n address-family ipv4\n"
        "  default-information originate\n  auto-summary\n  synchronization\n"
    )
    scal = [o for o in _af_ops(pc) if len(o.path) > 7 and o.path[7] == "scalar"]
    assert {(o.path[8], o.value) for o in scal} == {
        ("default_information_originate", True),
        ("auto_summary", True),
        ("synchronization", True),
    }
    af = _parse("router bgp 65000\n address-family ipv4\n").bgp_instances[0].address_families[0]
    assert (
        af.default_information_originate,
        af.auto_summary,
        af.synchronization,
    ) == (False, False, False)  # absence == model default (Z.0)


def test_ipv6_af_and_multi_af():
    pc = _parse(
        "router bgp 65000\n address-family ipv4\n  network 10.0.0.0 mask 255.0.0.0\n"
        " address-family ipv6\n  network 2001:db8::/48\n"
    )
    creates = [o for o in _af_ops(pc) if o.verb is Verb.SET and len(o.path) == 7]
    keys = {(o.path[4], o.path[5]) for o in creates}
    assert keys == {("ipv4", "unicast"), ("ipv6", "unicast")}


# ---------------------------------------------------------------------------
# Codec / byte-identity
# ---------------------------------------------------------------------------


def test_af_set_ops_do_not_pollute_no_commands():
    pc = _parse(AF_CFG)
    arts = encode_legacy(_af_ops(pc))
    # SET ops → set_fields only; ops-only aggregate removal → nothing.
    assert arts.no_commands == []
    assert arts.bgp_no_commands == {}


def test_ops_only_aggregate_removal_no_legacy_twin():
    pc = _parse(AF_CFG)
    rem = [o for o in _af_ops(pc) if o.verb is Verb.LIST_REMOVE][0]
    assert encode_legacy([rem]).no_commands == []
    assert encode_legacy([rem]).bgp_no_commands == {}


def test_no_aggregate_address_not_in_legacy_tombstones():
    # The AF-scoped `no aggregate-address` line is silently dropped by the legacy
    # parser (no tombstone) — the capability is ops-only.
    pc = _parse(AF_CFG)
    assert not any("aggregate" in t for t in pc.no_commands)
    assert not any("aggregate" in t for b in pc.bgp_instances for t in b.no_commands)


def test_whole_instance_set_retired_composition():
    # 5c-B.2 (CCR Appendix L) RETIRES the derived whole-instance SET for this
    # fully-native IOS instance — the native CREATE op claims the prefix (H.3
    # narrowing).  (Was ``…_survives`` under 5c-B.1, which kept it.)
    from confgraph.change_ir import is_native_bgp_instance_create_op

    pc = _parse(AF_CFG)
    ops = derive_ops(pc)
    inst_sets = [
        o
        for o in ops
        if o.verb is Verb.SET and o.path == ("bgp_instances", "65000", "")
    ]
    assert inst_sets == [], "derived whole-instance SET must be retired (5c-B.2)"
    assert len([o for o in ops if is_native_bgp_instance_create_op(o)]) == 1


def test_anti_rot_every_af_form_native():
    # Every AF-shaped op in the composed ChangeSet is native (the deriver
    # contributes no AF-decomposition op — inverse pin for 5c-B.2 comes later).
    pc = _parse(AF_CFG)
    ops = derive_ops(pc)
    af_forms = [
        o
        for o in ops
        if (o.path and o.path[0] in ("bgp_instances", "bgp_instance"))
        and len(o.path) > 3
        and o.path[3] == "af"
    ]
    assert af_forms, "expected AF ops in the composed set"
    assert all(o.origin == "native" for o in af_forms)


def test_nxos_vrf_instance_emits_no_af_ops():
    # NX-OS VRF instances carry no AFs (address_families=[]) — Finding 3; the AF
    # loop is a no-op there.  (Global NX-OS AF blocks DO decompose.)
    pc = _parse(
        "feature bgp\nrouter bgp 65000\n router-id 1.1.1.1\n"
        " address-family ipv4 unicast\n  network 10.1.0.0/16\n"
        " vrf CUST\n  address-family ipv4 unicast\n   network 10.9.0.0/16\n",
        NXOSParser,
    )
    vrf_af = [
        o for o in _af_ops(pc) if o.path[2] == "CUST"
    ]
    assert vrf_af == []
    glob_af = [o for o in _af_ops(pc) if o.path[2] == "" and o.verb is Verb.SET and len(o.path) == 7]
    assert len(glob_af) == 1  # global AF still decomposes


def test_bgp_af_key_identity():
    pc = _parse(AF_CFG)
    af = pc.bgp_instances[0].address_families[0]
    assert bgp_af_key(af) == ("ipv4", "unicast", "")


# ---------------------------------------------------------------------------
# 5c-B.2 retirement (CCR Appendix L) — whole-instance SET retirement + gate
# ---------------------------------------------------------------------------

from confgraph.change_ir import is_native_bgp_instance_create_op  # noqa: E402


def _whole_instance_sets(ops):
    return [
        o
        for o in ops
        if o.verb is Verb.SET and len(o.path) == 3 and o.path[0] == "bgp_instances"
    ]


def test_fully_native_ios_instance_retires_set_and_emits_create():
    pc = _parse(AF_CFG)
    ops = derive_ops(pc)
    assert _whole_instance_sets(ops) == []
    creates = [o for o in ops if is_native_bgp_instance_create_op(o)]
    assert len(creates) == 1
    assert creates[0].path == ("bgp_instances", "65000", "", "instance")
    assert creates[0].origin == "native"
    # The create op carries the parsed BGPConfig (the engine seeds from it).
    assert creates[0].value.asn == 65000


def test_ios_vrf_af_instance_is_fully_native_retired():
    pc = _parse(
        "router bgp 65000\n neighbor 2.2.2.2 remote-as 65000\n"
        " address-family ipv4 vrf CUST\n"
        "  neighbor 9.9.9.9 remote-as 65001\n  redistribute static\n"
    )
    ops = derive_ops(pc)
    # Both the global and the VRF-AF instance are fully native → 0 surviving SETs.
    assert _whole_instance_sets(ops) == []
    keys = {(o.path[1], o.path[2]) for o in ops if is_native_bgp_instance_create_op(o)}
    assert keys == {("65000", ""), ("65000", "CUST")}


def test_gated_nxos_vrf_instance_keeps_set_no_create():
    pc = _parse(
        "feature bgp\nrouter bgp 65000\n router-id 1.1.1.1\n"
        " neighbor 2.2.2.2\n  remote-as 65000\n"
        " vrf CUST\n  neighbor 9.9.9.9 remote-as 65001\n  redistribute static\n",
        NXOSParser,
    )
    ops = derive_ops(pc)
    # NX-OS VRF instance is GATED → its derived whole-instance SET SURVIVES and
    # it emits NO create op; the NX-OS GLOBAL instance is fully native → retired.
    surviving = {(o.path[1], o.path[2]) for o in _whole_instance_sets(ops)}
    assert surviving == {("65000", "CUST")}
    create_keys = {
        (o.path[1], o.path[2]) for o in ops if is_native_bgp_instance_create_op(o)
    }
    assert ("65000", "CUST") not in create_keys  # gated → no create op
    assert ("65000", "") in create_keys  # global retired


def test_anti_rot_inverse_no_whole_instance_set_for_fully_native():
    # Inverse pin (5c-B.2): the deriver emits NO whole-instance SET for a config
    # whose instances are all fully native.  Kitchen-sink IOS BGP.
    pc = _parse(
        "router bgp 65000\n bgp router-id 10.0.0.1\n bgp log-neighbor-changes\n"
        " neighbor 2.2.2.2 remote-as 65000\n neighbor UP peer-group\n"
        " network 100.64.0.0 mask 255.255.0.0\n redistribute connected\n"
        " address-family ipv4\n  network 10.1.0.0 mask 255.255.0.0\n"
        "  aggregate-address 10.0.0.0 255.0.0.0 summary-only\n  maximum-paths 4\n"
    )
    assert _whole_instance_sets(derive_ops(pc)) == []


def test_gated_predicate_matches_only_nxos_vrf():
    # Mechanical gate: NX-OS VRF only; IOS (global + VRF-AF) and NX-OS global
    # are ungated.
    ios = IOSParser("router bgp 1\n address-family ipv4 vrf V\n  neighbor 2.2.2.2 remote-as 2\n")
    ios_pc = ios.parse()
    assert not any(ios._bgp_instance_gated(b) for b in ios_pc.bgp_instances)
    nx = NXOSParser("feature bgp\nrouter bgp 1\n vrf V\n  neighbor 2.2.2.2 remote-as 2\n")
    nx_pc = nx.parse()
    gated = {(b.asn, b.vrf) for b in nx_pc.bgp_instances if nx._bgp_instance_gated(b)}
    assert gated == {(1, "V")}
