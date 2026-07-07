"""Change-IR Phase 3, family 6b — native EIGRP whole-protocol op emission.

CCR: ``change_ir_proposal_operations.md`` Appendix N (WI-6b).

Covers:
- the codec key helpers (``eigrp_redistribute_key`` / ``eigrp_network_key`` /
  ``eigrp_summary_key``) and the codec-owned predicates (``is_native_eigrp_op`` /
  ``is_native_eigrp_network_removal_op``),
- native emission for the positive decomposition (scalars / network / passive+
  non_passive / redistribute / summary_address) on the PLURAL ``eigrp_instances``
  container, beside the SURVIVING derived whole-instance SET (co-existence — 6b
  does NOT retire it; the H.3-style prefix-claim exclusion),
- the whole-process ``no router eigrp`` delete migrated to a NATIVE line-numbered
  OBJECT_DELETE with a byte-exact ``process:eigrp:<asn>`` tombstone, and the
  ops-only ``no network`` LIST_REMOVE with NO legacy twin (``encode_legacy``
  silent — legacy stays byte-identically blind),
- the ``no network`` refresh suppression (WI-8 ``_readded_later`` pattern),
- hybrid ``derive_ops`` composition + anti-rot (every family-6b op is native;
  families 1–6a dedupe unchanged),
- NX-OS inheritance of the shared deletion walk, named-mode AS resolution, VRF
  keying.
"""

from __future__ import annotations

from confgraph.change_ir import (
    Verb,
    derive_ops,
    encode_legacy,
    eigrp_network_key,
    eigrp_redistribute_key,
    eigrp_summary_key,
    is_native_eigrp_network_removal_op,
    is_native_eigrp_op,
    is_native_isis_op,
)
from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.nxos_parser import NXOSParser


def _parse(text: str, parser_cls=IOSParser):
    return parser_cls(text).parse()


def _f6b(pc):
    return [op for op in pc.native_change_ops if is_native_eigrp_op(op)]


EIGRP_FULL = (
    "router eigrp 100\n"
    " eigrp router-id 1.1.1.1\n"
    " network 10.0.0.0\n"
    " network 172.16.0.0 0.0.255.255\n"
    " passive-interface default\n"
    " no passive-interface GigabitEthernet1\n"
    " redistribute connected metric 10 10 255 1 1500\n"
    " redistribute ospf 1 route-map RM\n"
    " variance 4\n"
    " maximum-paths 6\n"
    " distance eigrp 90 170\n"
    " default-metric 100 10 255 1 1500\n"
    " metric weights 0 1 1 1 0 0\n"
    " auto-summary\n"
    " eigrp log-neighbor-changes\n"
    " eigrp stub connected summary\n"
    " summary-address 192.168.0.0 255.255.0.0 200\n"
    " no network 10.9.0.0\n"
)


# --- key helpers -----------------------------------------------------------

def test_eigrp_redistribute_key_protocol_pid():
    pc = _parse("router eigrp 100\n redistribute ospf 1\n redistribute connected\n")
    keys = {eigrp_redistribute_key(r) for r in pc.eigrp_instances[0].redistribute}
    assert keys == {("ospf", "1"), ("connected", "")}


def test_eigrp_network_key_is_cidr():
    pc = _parse("router eigrp 100\n network 10.0.0.0 0.0.255.255\n")
    net = pc.eigrp_instances[0].networks[0]
    assert eigrp_network_key(net) == ("10.0.0.0/16",)


def test_eigrp_summary_key_is_prefix():
    pc = _parse("router eigrp 100\n summary-address 192.168.0.0 255.255.0.0\n")
    sa = pc.eigrp_instances[0].summary_addresses[0]
    assert eigrp_summary_key(sa) == ("192.168.0.0/16",)


# --- positive decomposition ------------------------------------------------

def test_positive_decomposition_full_surface():
    pc = _parse(EIGRP_FULL)
    sets = {op.path for op in _f6b(pc) if op.verb is Verb.SET}
    a = ("eigrp_instances", "100", "")
    assert a + ("scalar", "router_id") in sets
    assert a + ("scalar", "passive_interface_default") in sets
    assert a + ("scalar", "auto_summary") in sets
    assert a + ("scalar", "variance") in sets
    assert a + ("scalar", "maximum_paths") in sets
    assert a + ("scalar", "distance_internal") in sets
    assert a + ("scalar", "distance_external") in sets
    assert a + ("scalar", "default_metric") in sets
    assert a + ("scalar", "log_neighbor_changes") in sets
    assert a + ("scalar", "k_values") in sets
    assert a + ("scalar", "stub") in sets
    assert a + ("network", "10.0.0.0/32") in sets
    assert a + ("network", "172.16.0.0/16") in sets
    assert a + ("non_passive_interface", "GigabitEthernet1") in sets
    assert a + ("redistribute", "connected", "") in sets
    assert a + ("redistribute", "ospf", "1") in sets
    assert a + ("summary_address", "192.168.0.0/16") in sets


def test_default_scalars_emit_no_set():
    pc = _parse("router eigrp 100\n network 10.0.0.0\n")
    scalars = [op for op in _f6b(pc)
               if op.verb is Verb.SET and op.path[3] == "scalar"]
    assert scalars == []


def test_native_set_values_are_model_objects():
    pc = _parse(EIGRP_FULL)
    by_path = {op.path: op.value for op in _f6b(pc)}
    redist = by_path[("eigrp_instances", "100", "", "redistribute", "ospf", "1")]
    assert redist.protocol == "ospf"
    sa = by_path[("eigrp_instances", "100", "", "summary_address", "192.168.0.0/16")]
    assert str(sa.prefix) == "192.168.0.0/16"


# --- ops-only `no network` (no legacy twin) --------------------------------

def _net_removals(pc):
    return [op for op in _f6b(pc) if is_native_eigrp_network_removal_op(op)]


def test_no_network_refresh_suppresses_removal():
    # `no network X` then `network X` (config-gen refresh): device keeps X.  The
    # removal is SUPPRESSED at emission (WI-8 pattern) so ops nets to [X].
    pc = _parse(
        "router eigrp 100\n"
        " no network 10.0.0.0\n"
        " network 10.0.0.0\n"
    )
    assert _net_removals(pc) == []


def test_no_network_withdrawal_removal_stands():
    pc = _parse("router eigrp 100\n no network 10.0.0.0\n")
    rem = _net_removals(pc)
    assert len(rem) == 1
    assert rem[0].path == ("eigrp_instance", "100", "", "network", "10.0.0.0/32")


def test_network_then_no_network_removal_stands():
    pc = _parse(
        "router eigrp 100\n"
        " network 10.0.0.0\n"
        " no network 10.0.0.0\n"
    )
    assert len(_net_removals(pc)) == 1


def test_no_network_is_ops_only_list_remove():
    pc = _parse(EIGRP_FULL)
    rem = _net_removals(pc)
    assert len(rem) == 1
    op = rem[0]
    assert op.verb is Verb.LIST_REMOVE
    assert op.path == ("eigrp_instance", "100", "", "network", "10.9.0.0/32")
    assert op.line_no >= 0
    # NO legacy twin — encode_legacy emits nothing.
    assert encode_legacy([op]).no_commands == []
    # And nothing leaks into the parsed no_commands (legacy stays blind).
    assert not any("network" in ts for ts in pc.no_commands)


# --- whole-process delete (native, byte-exact tombstone) -------------------

def test_process_delete_native_byte_exact():
    pc = _parse("no router eigrp 100\n")
    dels = [op for op in _f6b(pc) if op.verb is Verb.OBJECT_DELETE]
    assert len(dels) == 1
    op = dels[0]
    assert op.path == ("process", "eigrp", "100")
    assert op.origin == "native" and op.line_no >= 0
    assert pc.no_commands == ["process:eigrp:100"]
    assert encode_legacy([op]).no_commands == ["process:eigrp:100"]


def test_named_mode_as_resolution():
    # `router eigrp NAME` + address-family autonomous-system N → asn resolves to N,
    # so the positive decomposition path carries the RESOLVED asn.
    pc = _parse(
        "router eigrp CORP\n"
        " address-family ipv4 unicast autonomous-system 65001\n"
    )
    assert pc.eigrp_instances[0].as_number == 65001
    # Any SET/removal op for this instance keys on "65001".
    net_pc = _parse(
        "router eigrp CORP\n"
        " address-family ipv4 unicast autonomous-system 65001\n"
        " no network 10.0.0.0\n"
    )
    rem = _net_removals(net_pc)
    assert rem and rem[0].path[1] == "65001"


# --- retirement: derived whole-instance SET RETIRED (6e, CCR Appendix Q) ---
# Pin flip (the L.4 pattern): asserted "SET survives" through the 6b
# co-existence; 6e's create-op prefix claim retires it.

def test_derived_whole_instance_set_retired_composition():
    pc = _parse(EIGRP_FULL)
    ops = derive_ops(pc)
    inst_sets = [
        op for op in ops
        if op.path == ("eigrp_instances", "100", "") and op.verb is Verb.SET
    ]
    assert inst_sets == []  # RETIRED (6e)
    creates = [
        op for op in ops
        if op.path == ("eigrp_instances", "100", "", "instance")
        and op.verb is Verb.SET
    ]
    assert len(creates) == 1 and creates[0].origin == "native"
    assert str(creates[0].value.as_number) == "100"


# --- anti-rot: every family-6b-shaped op is native -------------------------

def test_anti_rot_family6b_never_derived():
    pc = _parse(EIGRP_FULL)
    ops = derive_ops(pc)
    for op in ops:
        if op.path[:1] == ("eigrp_instances",) and len(op.path) >= 5:
            assert op.origin == "native", op.path
        if op.path[:1] == ("eigrp_instance",):
            assert op.origin == "native", op.path
        if op.path[:2] == ("process", "eigrp"):
            assert op.origin == "native", op.path


def test_families_isis_eigrp_coexist():
    # Interleaved IS-IS + EIGRP: both RETIRED (6e, CCR Appendix Q — this pin
    # previously asserted the 6a/6b co-existence survival): one native CREATE
    # op each, no derived whole-instance SETs.
    pc = _parse(
        "router isis CORE\n net 49.0001.0000.0000.0001.00\n"
        "router eigrp 100\n network 10.0.0.0\n"
    )
    ops = derive_ops(pc)
    assert any(op.path == ("isis_instances", "CORE", "instance") for op in ops)
    assert any(op.path == ("eigrp_instances", "100", "", "instance") for op in ops)
    assert not any(op.path == ("isis_instances", "CORE") for op in ops)
    assert not any(op.path == ("eigrp_instances", "100", "") for op in ops)
    assert any(is_native_isis_op(op) for op in ops)
    assert any(is_native_eigrp_op(op) for op in ops)


# --- NX-OS inheritance + VRF keying ----------------------------------------

def test_nxos_inherits_process_eigrp_delete():
    pc = _parse("no router eigrp 100\n", parser_cls=NXOSParser)
    dels = [op for op in _f6b(pc) if op.verb is Verb.OBJECT_DELETE]
    assert dels and dels[0].path == ("process", "eigrp", "100")
    assert pc.no_commands == ["process:eigrp:100"]


def test_vrf_instance_keys_carry_vrf():
    # The parser attaches vrf=RED (from the address-family child) to the single
    # EIGRPConfig; a top-level scalar decomposes under the ("100","RED") key.
    # (Networks nested UNDER the vrf address-family are a pre-existing parser
    # grandchild-capture gap — task-#22, orthogonal to migration.)
    pc = _parse(
        "router eigrp 100\n"
        " variance 4\n"
        " address-family ipv4 vrf RED\n"
    )
    assert pc.eigrp_instances[0].vrf == "RED"
    sets = {op.path[:3] for op in _f6b(pc) if op.verb is Verb.SET}
    assert ("eigrp_instances", "100", "RED") in sets
