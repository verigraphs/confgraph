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

The three UNPARSED AF scalars (default_information_originate / auto_summary /
synchronization) are never set by the AF parser → nothing emitted (task #22).
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


def test_unparsed_af_scalars_emit_nothing():
    # default_information_originate / auto_summary / synchronization are never
    # parsed for BGP AF (task #22) — no native op regardless of the lines.
    pc = _parse(
        "router bgp 65000\n address-family ipv4\n"
        "  default-information originate\n  auto-summary\n  synchronization\n"
    )
    scal = [o for o in _af_ops(pc) if len(o.path) > 7 and o.path[7] == "scalar"]
    assert scal == []


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


def test_whole_instance_set_survives_composition():
    # 5c-B.1 does NOT retire the derived whole-instance SET (H.3 unchanged).
    pc = _parse(AF_CFG)
    ops = derive_ops(pc)
    inst_sets = [
        o
        for o in ops
        if o.verb is Verb.SET and o.path == ("bgp_instances", "65000", "")
    ]
    assert len(inst_sets) == 1, "derived whole-instance SET must survive (co-existence)"
    assert inst_sets[0].origin == "derived"


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
