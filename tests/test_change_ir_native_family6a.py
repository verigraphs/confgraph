"""Change-IR Phase 3, family 6a — native IS-IS whole-protocol op emission.

CCR: ``change_ir_proposal_operations.md`` Appendix M (WI-6a).

Covers:
- the codec key helpers (``isis_interface_key`` / ``isis_redistribute_key``)
  and the codec-owned predicates (``is_native_isis_op`` /
  ``is_native_isis_net_removal_op``),
- native emission for the positive decomposition (scalars / net /
  passive+non_passive / interfaces / redistribute) on the PLURAL
  ``isis_instances`` container, beside the SURVIVING derived whole-instance SET
  (co-existence — 6a does NOT retire it; the H.3-style prefix-claim exclusion),
- the whole-process ``no router isis`` delete migrated to a NATIVE line-numbered
  OBJECT_DELETE with a byte-exact ``process:isis:<tag>`` tombstone (incl. the
  bare-tag ``""`` form), and the ops-only ``no net`` LIST_REMOVE with NO legacy
  twin (``encode_legacy`` silent — legacy stays byte-identically blind),
- hybrid ``derive_ops`` composition + anti-rot (every family-6a op is native;
  families 1–5 dedupe unchanged),
- NX-OS inheritance of the shared deletion walk.
"""

from __future__ import annotations

from confgraph.change_ir import (
    Verb,
    derive_ops,
    encode_legacy,
    is_native_bgp_op,
    is_native_isis_net_removal_op,
    is_native_isis_op,
    isis_interface_key,
    isis_redistribute_key,
)
from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.nxos_parser import NXOSParser


def _parse(text: str, parser_cls=IOSParser):
    return parser_cls(text).parse()


def _f6(pc):
    return [op for op in pc.native_change_ops if is_native_isis_op(op)]


ISIS_FULL = (
    "router isis CORE\n"
    " net 49.0001.0000.0000.0001.00\n"
    " is-type level-2-only\n"
    " metric-style wide\n"
    " log-adjacency-changes\n"
    " passive-interface default\n"
    " no passive-interface GigabitEthernet0/0\n"
    " redistribute connected metric 10\n"
    " redistribute ospf 1 metric 20 route-map RM\n"
    " no net 49.9999.0000.0000.0009.00\n"
    "interface GigabitEthernet0/0\n"
    " ip router isis CORE\n"
    " isis circuit-type level-2\n"
    " isis metric 15\n"
)


# --- key helpers -----------------------------------------------------------

def test_isis_interface_key_is_name():
    pc = _parse("router isis CORE\n net 49.0001.0000.0000.0001.00\n"
                "interface GigabitEthernet0/0\n ip router isis CORE\n")
    isis = pc.isis_instances[0]
    assert isis.interfaces
    assert isis_interface_key(isis.interfaces[0]) == (isis.interfaces[0].name,)


def test_isis_redistribute_key_protocol_pid():
    pc = _parse("router isis CORE\n net 49.0001.0000.0000.0001.00\n"
                " redistribute ospf 1\n redistribute connected\n")
    keys = {isis_redistribute_key(r) for r in pc.isis_instances[0].redistribute}
    assert keys == {("ospf", "1"), ("connected", "")}


# --- positive decomposition ------------------------------------------------

def test_positive_decomposition_full_surface():
    pc = _parse(ISIS_FULL)
    ops = _f6(pc)
    sets = {op.path for op in ops if op.verb is Verb.SET}
    tag = "CORE"
    assert ("isis_instances", tag, "scalar", "is_type") in sets
    assert ("isis_instances", tag, "scalar", "metric_style") in sets
    assert ("isis_instances", tag, "scalar", "log_adjacency_changes") in sets
    assert ("isis_instances", tag, "scalar", "passive_interface_default") in sets
    assert ("isis_instances", tag, "net", "49.0001.0000.0000.0001.00") in sets
    assert ("isis_instances", tag, "non_passive_interface", "GigabitEthernet0/0") in sets
    assert ("isis_instances", tag, "interface", "GigabitEthernet0/0") in sets
    assert ("isis_instances", tag, "redistribute", "connected", "") in sets
    assert ("isis_instances", tag, "redistribute", "ospf", "1") in sets


def test_default_scalars_emit_no_set():
    # is_type/metric_style unset, log-adjacency-changes absent → no scalar SETs.
    pc = _parse("router isis CORE\n net 49.0001.0000.0000.0001.00\n")
    scalars = [op for op in _f6(pc)
               if op.verb is Verb.SET and op.path[2] == "scalar"]
    assert scalars == []


def test_native_set_values_are_model_objects():
    pc = _parse(ISIS_FULL)
    by_path = {op.path: op.value for op in _f6(pc)}
    iface_val = by_path[("isis_instances", "CORE", "interface", "GigabitEthernet0/0")]
    assert iface_val.name == "GigabitEthernet0/0"
    redist_val = by_path[("isis_instances", "CORE", "redistribute", "ospf", "1")]
    assert redist_val.protocol == "ospf"


# --- ops-only `no net` (no legacy twin) ------------------------------------

def _net_removals(pc, tag="CORE"):
    return [
        op for op in _f6(pc)
        if is_native_isis_net_removal_op(op) and op.path[1] == tag
    ]


def test_no_net_refresh_suppresses_removal():
    # `no net X` then `net X` (config-gen refresh): device keeps X.  The removal
    # is SUPPRESSED at emission (WI-8 pattern, validator Finding 1) so ops nets
    # to [X] == legacy == device.
    pc = _parse(
        "router isis CORE\n"
        " no net 49.0001.0000.0000.0001.00\n"
        " net 49.0001.0000.0000.0001.00\n"
    )
    assert _net_removals(pc) == []  # suppressed


def test_no_net_withdrawal_removal_stands():
    # `no net X` with no later re-add: the removal op is emitted (capability).
    pc = _parse("router isis CORE\n no net 49.0001.0000.0000.0001.00\n")
    rem = _net_removals(pc)
    assert len(rem) == 1
    assert rem[0].path == ("isis_instance", "CORE", "net", "49.0001.0000.0000.0001.00")


def test_net_then_no_net_removal_stands():
    # `net X` then `no net X` (later removal): NOT suppressed — the removal
    # position is after the positive, so the withdrawal stands (capability).
    pc = _parse(
        "router isis CORE\n"
        " net 49.0001.0000.0000.0001.00\n"
        " no net 49.0001.0000.0000.0001.00\n"
    )
    assert len(_net_removals(pc)) == 1


def test_no_net_is_ops_only_list_remove():
    pc = _parse(ISIS_FULL)
    removals = [op for op in _f6(pc) if is_native_isis_net_removal_op(op)]
    assert len(removals) == 1
    op = removals[0]
    assert op.verb is Verb.LIST_REMOVE
    assert op.path == ("isis_instance", "CORE", "net", "49.9999.0000.0000.0009.00")
    assert op.line_no >= 0  # line-numbered
    # NO legacy twin — encode_legacy emits nothing for it.
    assert encode_legacy([op]).no_commands == []
    assert encode_legacy([op]).bgp_no_commands == {}
    # And nothing leaks into the parsed no_commands (legacy stays blind).
    assert not any("net" in ts for ts in pc.no_commands)


# --- whole-process delete (native, byte-exact tombstone) -------------------

def test_process_delete_native_byte_exact_tagged():
    pc = _parse("no router isis CORE\n")
    dels = [op for op in _f6(pc) if op.verb is Verb.OBJECT_DELETE]
    assert len(dels) == 1
    op = dels[0]
    assert op.path == ("process", "isis", "CORE")
    assert op.origin == "native" and op.line_no >= 0
    # Byte-exact legacy tombstone, unchanged from today.
    assert pc.no_commands == ["process:isis:CORE"]
    assert encode_legacy([op]).no_commands == ["process:isis:CORE"]


def test_process_delete_native_byte_exact_bare_tag():
    pc = _parse("no router isis\n")
    op = next(op for op in _f6(pc) if op.verb is Verb.OBJECT_DELETE)
    assert op.path == ("process", "isis", "")
    assert pc.no_commands == ["process:isis:"]
    assert encode_legacy([op]).no_commands == ["process:isis:"]


# --- co-existence: derived whole-instance SET SURVIVES ---------------------

def test_derived_whole_instance_set_survives_composition():
    pc = _parse(ISIS_FULL)
    ops = derive_ops(pc)
    inst_sets = [
        op for op in ops
        if op.path == ("isis_instances", "CORE") and op.verb is Verb.SET
    ]
    assert len(inst_sets) == 1  # co-exists (6a does NOT retire it)
    # …and it carries the full instance (retirement/decomposition is engine-side).
    assert inst_sets[0].value.tag == "CORE"


def test_bare_tag_instance_set_survives():
    pc = _parse("router isis\n net 49.0001.0000.0000.0001.00\n")
    ops = derive_ops(pc)
    assert any(op.path == ("isis_instances", "") for op in ops)


# --- anti-rot: every family-6a-shaped op is native -------------------------

def test_anti_rot_family6a_never_derived():
    pc = _parse(ISIS_FULL)
    ops = derive_ops(pc)
    for op in ops:
        # every isis_instances keyed-member SET (len>=4) and every
        # isis_instance / process:isis deletion must be native
        if op.path[:1] == ("isis_instances",) and len(op.path) >= 4:
            assert op.origin == "native", op.path
        if op.path[:1] == ("isis_instance",):
            assert op.origin == "native", op.path
        if op.path[:2] == ("process", "isis"):
            assert op.origin == "native", op.path


def test_families_1_5_dedupe_unchanged():
    # An interleaved config: interface scalar (F1), static (F4), BGP (F5), IS-IS.
    pc = _parse(
        "interface GigabitEthernet0/0\n mtu 9000\n ip router isis CORE\n"
        "ip route 10.0.0.0 255.0.0.0 10.1.1.1\n"
        "router bgp 65000\n neighbor 10.0.0.2 remote-as 65001\n"
        "router isis CORE\n net 49.0001.0000.0000.0001.00\n"
    )
    ops = derive_ops(pc)
    # BGP is fully retired (5c-B.2): a native whole-instance CREATE op, and NO
    # derived whole-instance SET.  IS-IS is co-existing (6a): the derived
    # whole-instance SET SURVIVES beside the native decomposition.
    assert any(
        op.path == ("bgp_instances", "65000", "", "instance") for op in ops
    )
    assert not any(op.path == ("bgp_instances", "65000", "") for op in ops)
    assert any(op.path == ("isis_instances", "CORE") for op in ops)
    # native BGP + native IS-IS ops both present and origin-native.
    assert any(is_native_bgp_op(op) for op in ops)
    assert any(is_native_isis_op(op) for op in ops)


# --- NX-OS inheritance -----------------------------------------------------

def test_nxos_inherits_process_isis_delete():
    pc = _parse("no router isis CORE\n", parser_cls=NXOSParser)
    dels = [op for op in _f6(pc) if op.verb is Verb.OBJECT_DELETE]
    assert dels and dels[0].path == ("process", "isis", "CORE")
    assert pc.no_commands == ["process:isis:CORE"]
