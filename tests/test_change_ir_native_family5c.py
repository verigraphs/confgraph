"""Change-IR Phase 3, family 5c-A — native BGP whole-instance scalar/bestpath/
global-redistribute ops (WI-5c-A).

CCR: ``change_ir_proposal_operations.md`` Appendix J.

5c-A migrates the ALREADY-PARSED whole-instance surface to native ops while the
derived whole-instance ``SET ("bgp_instances", asn, vrf)`` STILL SURVIVES
(co-existing exactly like 5a/5b — 5c-A does NOT retire it; AF-container
decomposition + retirement are 5c-B):

- parity scalars (router_id / cluster_id / confederation_id / confederation_peers
  / rpki_server) → native ``SET (…, "scalar", field)``, positive-only (no
  negation tombstone exists today),
- ``log_neighbor_changes`` tri-state True-default (family-1 mechanism): positive
  line → SET True, negation line → SET False, ordered replay device-correct,
- ``default_local_preference`` anchored non-falsy default 100 (family-2 mechanism):
  positive → SET N (even N==100), ``no`` → SET 100,
- ``bestpath_options`` → one native ``SET (…, "bestpath", option)`` per True option,
- GLOBAL (non-AF) ``redistribute`` positive → native ``SET (…, "redistribute",
  proto, pid)``; its NEGATIVE (``no redistribute`` → generic AF-scoped
  ``field:bgp:…:af:ipv4:redistribute:…`` tombstone) STAYS DERIVED (coexistence),
- codec ``is_native_bgp_op`` extension + ``bgp_redistribute_key``,
- byte-identity: scalar SETs encode to ``set_fields`` only (no ``no_commands``
  pollution), the derived whole-instance SET survives, anti-rot (no 5c-A form
  derived), NX-OS inheritance.
"""

from __future__ import annotations

from confgraph.change_ir import (
    Verb,
    bgp_redistribute_key,
    derive_ops,
    encode_legacy,
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


def _scalar_ops(pc, field):
    return [
        o
        for o in _bgp_ops(pc)
        if o.verb is Verb.SET
        and len(o.path) >= 5
        and o.path[3] == "scalar"
        and o.path[4] == field
    ]


GLOBAL = """router bgp 65001
 bgp router-id 10.0.0.1
 bgp cluster-id 7
 bgp confederation identifier 100
 bgp confederation peers 65002 65003
 bgp rpki server tcp 10.9.9.9 port 3323
 bgp log-neighbor-changes
 bgp default local-preference 150
 bgp bestpath compare-routerid
 bgp bestpath as-path multipath-relax
 neighbor 10.0.0.2 remote-as 65002
 redistribute ospf 1 metric 50
 redistribute connected
"""


# --------------------------------------------------------------------------- #
# Parity scalars — state-derived, positive-only native SETs
# --------------------------------------------------------------------------- #

def test_parity_scalars_emit_native_set():
    pc = _parse(GLOBAL)
    got = {
        o.path[4]: o.value
        for o in _bgp_ops(pc)
        if o.verb is Verb.SET and len(o.path) >= 5 and o.path[3] == "scalar"
    }
    assert str(got["router_id"]) == "10.0.0.1"
    assert got["cluster_id"] == 7
    assert got["confederation_id"] == 100
    assert got["confederation_peers"] == [65002, 65003]
    assert got["rpki_server"] == "10.9.9.9:3323"
    # every scalar op is native + recognized by the codec predicate
    for o in _bgp_ops(pc):
        if o.verb is Verb.SET and len(o.path) >= 5 and o.path[3] == "scalar":
            assert o.origin == "native"
            assert is_native_bgp_op(o)


def test_parity_scalar_absent_emits_nothing():
    pc = _parse("router bgp 65001\n neighbor 10.0.0.2 remote-as 65002\n")
    assert _scalar_ops(pc, "router_id") == []
    assert _scalar_ops(pc, "cluster_id") == []


# --------------------------------------------------------------------------- #
# Tri-state True-default: log_neighbor_changes
# --------------------------------------------------------------------------- #

def test_log_neighbor_changes_positive_reassert():
    pc = _parse("router bgp 65001\n bgp log-neighbor-changes\n")
    ops = _scalar_ops(pc, "log_neighbor_changes")
    assert [o.value for o in ops] == [True]
    assert ops[0].origin == "native"


def test_log_neighbor_changes_negation():
    pc = _parse("router bgp 65001\n no bgp log-neighbor-changes\n")
    ops = _scalar_ops(pc, "log_neighbor_changes")
    assert [o.value for o in ops] == [False]


def test_log_neighbor_changes_both_orders_device_correct():
    # positive THEN negation → last (False) wins under ordered replay
    pc1 = _parse(
        "router bgp 65001\n bgp log-neighbor-changes\n"
        " no bgp log-neighbor-changes\n"
    )
    o1 = _scalar_ops(pc1, "log_neighbor_changes")
    o1.sort(key=lambda o: o.line_no)
    assert [o.value for o in o1] == [True, False]
    # negation THEN positive → last (True) wins
    pc2 = _parse(
        "router bgp 65001\n no bgp log-neighbor-changes\n"
        " bgp log-neighbor-changes\n"
    )
    o2 = _scalar_ops(pc2, "log_neighbor_changes")
    o2.sort(key=lambda o: o.line_no)
    assert [o.value for o in o2] == [False, True]


# --------------------------------------------------------------------------- #
# Anchored non-falsy default: default_local_preference
# --------------------------------------------------------------------------- #

def test_default_local_preference_anchored_default_value_visible():
    # value == default (100) is invisible to a pure state walk — native emission
    # makes it structural.
    pc = _parse("router bgp 65001\n bgp default local-preference 100\n")
    ops = _scalar_ops(pc, "default_local_preference")
    assert [o.value for o in ops] == [100]


def test_default_local_preference_nondefault_and_reset():
    pc = _parse(
        "router bgp 65001\n bgp default local-preference 200\n"
        " no bgp default local-preference\n"
    )
    ops = _scalar_ops(pc, "default_local_preference")
    ops.sort(key=lambda o: o.line_no)
    assert [o.value for o in ops] == [200, 100]


# --------------------------------------------------------------------------- #
# bestpath sub-object
# --------------------------------------------------------------------------- #

def test_bestpath_options_emit_per_true_option():
    pc = _parse(GLOBAL)
    bp = {
        o.path[4]
        for o in _bgp_ops(pc)
        if o.verb is Verb.SET and o.path[3] == "bestpath"
    }
    assert bp == {"compare_routerid", "as_path_multipath_relax"}


# --------------------------------------------------------------------------- #
# Global redistribute coexistence (positive native / negative derived)
# --------------------------------------------------------------------------- #

def test_global_redistribute_positive_native():
    pc = _parse(GLOBAL)
    r = {
        (o.path[4], o.path[5]): o.value
        for o in _bgp_ops(pc)
        if o.verb is Verb.SET and o.path[3] == "redistribute"
    }
    assert set(r) == {("ospf", "1"), ("connected", "")}
    for o in _bgp_ops(pc):
        if o.verb is Verb.SET and o.path[3] == "redistribute":
            assert o.origin == "native" and is_native_bgp_op(o)


def test_redistribute_negative_stays_derived_top_level_tombstone():
    # `no redistribute` under router bgp → the generic AF-scoped tombstone in
    # ParsedConfig.no_commands, NOT a native bgp op (coexistence).
    pc = _parse(
        "router bgp 65001\n redistribute ospf 1\n"
        " no redistribute static\n"
    )
    assert "field:bgp:65001:af:ipv4:redistribute:static:" in "\n".join(
        pc.no_commands
    )
    # no native op claims the negative
    assert not any(
        o.verb is Verb.LIST_REMOVE and "redistribute" in o.path for o in _bgp_ops(pc)
    )


def test_redistribute_key_helper():
    from confgraph.models.bgp import BGPRedistribute

    assert bgp_redistribute_key(BGPRedistribute(protocol="ospf", process_id=1)) == (
        "ospf",
        "1",
    )
    assert bgp_redistribute_key(BGPRedistribute(protocol="connected")) == (
        "connected",
        "",
    )


# --------------------------------------------------------------------------- #
# Byte-identity + composition
# --------------------------------------------------------------------------- #

def test_scalar_sets_encode_to_set_fields_not_no_commands():
    # 5c-A native scalar/bestpath/redistribute SETs must NOT pollute no_commands
    # (they have no legacy twin) — byte-identity of the tombstone containers.
    pc = _parse(GLOBAL)
    la = encode_legacy(derive_ops(pc))
    assert la.no_commands == []
    assert la.bgp_no_commands == {}


def test_whole_instance_set_survives_composition():
    pc = _parse(GLOBAL)
    comp = derive_ops(pc)
    inst = [
        o
        for o in comp
        if o.verb is Verb.SET and o.path == ("bgp_instances", "65001", "")
    ]
    assert len(inst) == 1 and inst[0].origin == "derived"


def test_anti_rot_no_5c_a_form_derived():
    # Every 5c-A-shaped op (scalar/bestpath/redistribute SET) in the composed
    # ChangeSet is NATIVE; the deriver contributes none.
    pc = _parse(GLOBAL)
    for o in derive_ops(pc):
        if (
            o.verb is Verb.SET
            and o.path
            and o.path[0] == "bgp_instances"
            and len(o.path) >= 5
            and o.path[3] in ("scalar", "bestpath", "redistribute")
        ):
            assert o.origin == "native", o.path


# --------------------------------------------------------------------------- #
# Per-VRF-AF + NX-OS inheritance
# --------------------------------------------------------------------------- #

def test_vrf_af_redistribute_native():
    pc = _parse(
        "router bgp 65001\n"
        " address-family ipv4 vrf CUST\n"
        "  redistribute connected\n"
    )
    vrf_ops = [
        o
        for o in _bgp_ops(pc)
        if o.verb is Verb.SET and o.path[2] == "CUST" and o.path[3] == "redistribute"
    ]
    assert len(vrf_ops) == 1 and vrf_ops[0].value.protocol == "connected"


def test_nxos_inherits_scalar_emission():
    pc = _parse(
        "router bgp 65001\n router-id 10.0.0.1\n"
        "  log-neighbor-changes\n"
        "  address-family ipv4 unicast\n",
        parser_cls=NXOSParser,
    )
    # NX-OS uses the inherited IOS _native_bgp_ops path; at minimum it must not
    # crash and must produce a valid ChangeSet with all bgp ops native.
    for o in _bgp_ops(pc):
        assert o.origin == "native"
