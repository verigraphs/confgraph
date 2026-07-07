"""Change-IR Phase 3, family 6c — native OSPF core (non-area) op emission.

CCR: ``change_ir_proposal_operations.md`` Appendix O (WI-6c).

Covers:
- the codec key helpers (``ospf_redistribute_key`` / ``ospf_network_key``) and
  the codec-owned predicates (``is_native_ospf_op`` /
  ``is_native_ospf_network_removal_op``),
- native emission for the positive NON-AREA decomposition (scalars / network
  statements / passive+non_passive / redistribute) on the PLURAL
  ``ospf_instances`` container, beside the SURVIVING derived whole-instance SET
  (co-existence — 6c does NOT retire it; H.3-style prefix-claim exclusion),
- THE TRAP (Appendix O.1): ``log_adjacency_changes`` (model default True,
  parser-absence False — the 5c-A Finding-2 replica) is LINE-detected
  (tri-state: positive line → SET True, ``no log-adjacency-changes`` → SET
  False, at their true lines) and NEVER state-derived,
- ``areas`` are NEVER emitted natively (Appendix O.0 — 6d's surface),
- the whole-process ``no router ospf`` delete migrated to a NATIVE
  line-numbered OBJECT_DELETE with a byte-exact ``process:ospf:<pid>``
  tombstone, and the ops-only ``no network A W area X`` LIST_REMOVE with NO
  legacy twin (``encode_legacy`` silent — legacy stays byte-identically blind),
- the ``no network`` refresh suppression (WI-8 ``_readded_later`` pattern)
  through the SAME wildcard normalization as the positive parse,
- hybrid ``derive_ops`` composition + anti-rot (every family-6c op is native;
  IS-IS/EIGRP/OSPF co-exist),
- NX-OS inheritance (nxos_parser.parse_ospf wraps super().parse_ospf()), VRF
  keying (``router ospf N vrf M``).
"""

from __future__ import annotations

from confgraph.change_ir import (
    Verb,
    derive_ops,
    encode_legacy,
    is_native_eigrp_op,
    is_native_isis_op,
    is_native_ospf_network_removal_op,
    is_native_ospf_op,
    ospf_network_key,
    ospf_redistribute_key,
)
from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.nxos_parser import NXOSParser


def _parse(text: str, parser_cls=IOSParser):
    return parser_cls(text).parse()


def _f6c(pc):
    return [op for op in pc.native_change_ops if is_native_ospf_op(op)]


OSPF_FULL = (
    "router ospf 1\n"
    " router-id 1.1.1.1\n"
    " log-adjacency-changes detail\n"
    " auto-cost reference-bandwidth 10000\n"
    " passive-interface default\n"
    " no passive-interface GigabitEthernet1\n"
    " passive-interface GigabitEthernet2\n"
    " network 10.0.0.0 0.0.0.255 area 0\n"
    " network 10.1.0.0 0.0.255.255 area 1\n"
    " no network 10.9.0.0 0.0.0.255 area 0\n"
    " redistribute static metric 20 subnets\n"
    " redistribute bgp 65001 route-map RM\n"
    " default-information originate always metric 5 metric-type 1 route-map DI\n"
    " default-metric 30\n"
    " distance 115\n"
    " distance ospf intra-area 100 inter-area 105 external 120\n"
    " max-lsa 5000\n"
    " max-metric router-lsa on-startup 300\n"
    " timers throttle spf 50 200 5000\n"
    " timers throttle lsa all 100\n"
    " shutdown\n"
    " nsf\n"
    " graceful-restart helper\n"
    " bfd all-interfaces\n"
    " area 1 stub no-summary\n"
)


# --- key helpers -----------------------------------------------------------

def test_ospf_redistribute_key_protocol_pid():
    pc = _parse("router ospf 1\n redistribute bgp 65001\n redistribute static\n")
    keys = {ospf_redistribute_key(r) for r in pc.ospf_instances[0].redistribute}
    assert keys == {("bgp", "65001"), ("static", "")}


def test_ospf_network_key_is_cidr_and_area():
    pc = _parse("router ospf 1\n network 10.0.0.0 0.0.255.255 area 0.0.0.5\n")
    stmt = pc.ospf_instances[0].network_statements[0]
    assert ospf_network_key(stmt) == ("10.0.0.0/16", "0.0.0.5")


# --- positive decomposition ------------------------------------------------

def test_positive_decomposition_full_surface():
    pc = _parse(OSPF_FULL)
    sets = {op.path for op in _f6c(pc) if op.verb is Verb.SET}
    a = ("ospf_instances", "1", "")
    for field in (
        "router_id",
        "log_adjacency_changes_detail",
        "auto_cost_reference_bandwidth",
        "passive_interface_default",
        "default_information_originate",
        "default_information_originate_always",
        "default_information_originate_metric",
        "default_information_originate_metric_type",
        "default_information_originate_route_map",
        "default_metric",
        "distance",
        "distance_intra_area",
        "distance_inter_area",
        "distance_external",
        "max_lsa",
        "max_metric_router_lsa",
        "max_metric_router_lsa_on_startup",
        "timers_throttle_spf_initial",
        "timers_throttle_spf_min",
        "timers_throttle_spf_max",
        "timers_throttle_lsa_all",
        "shutdown",
        "graceful_restart",
        "graceful_restart_helper",
        "bfd_all_interfaces",
    ):
        assert a + ("scalar", field) in sets, field
    assert a + ("network", "10.0.0.0/24", "0") in sets
    assert a + ("network", "10.1.0.0/16", "1") in sets
    assert a + ("passive_interface", "GigabitEthernet2") in sets
    assert a + ("non_passive_interface", "GigabitEthernet1") in sets
    assert a + ("redistribute", "static", "") in sets
    assert a + ("redistribute", "bgp", "65001") in sets


def test_default_scalars_emit_no_set():
    pc = _parse("router ospf 1\n network 10.0.0.0 0.0.0.255 area 0\n")
    scalars = [op for op in _f6c(pc)
               if op.verb is Verb.SET and op.path[3] == "scalar"]
    assert scalars == []


def test_areas_never_emitted_natively():
    # Appendix O.0: areas stay ENTIRELY on the derived whole-instance SET.
    pc = _parse(OSPF_FULL)
    assert pc.ospf_instances[0].areas  # the fixture parses an area
    for op in _f6c(pc):
        assert "area" not in op.path[3:4], op.path
        if op.verb is Verb.SET:
            assert op.path[3] in {
                "scalar", "network", "passive_interface",
                "non_passive_interface", "redistribute",
            }


def test_native_set_values_are_model_objects():
    pc = _parse(OSPF_FULL)
    by_path = {op.path: op.value for op in _f6c(pc)}
    redist = by_path[("ospf_instances", "1", "", "redistribute", "bgp", "65001")]
    assert redist.protocol == "bgp" and redist.route_map == "RM"
    stmt = by_path[("ospf_instances", "1", "", "network", "10.0.0.0/24", "0")]
    assert str(stmt[0]) == "10.0.0.0/24" and stmt[1] == "0"


# --- THE TRAP: log_adjacency_changes is line-detected (Appendix O.1) --------

def _lac_ops(pc):
    return [
        op for op in _f6c(pc)
        if op.verb is Verb.SET and op.path[3:] == ("scalar", "log_adjacency_changes")
    ]


def test_trap_positive_line_detected_true():
    pc = _parse("router ospf 1\n log-adjacency-changes\n")
    ops = _lac_ops(pc)
    assert len(ops) == 1
    assert ops[0].value is True
    assert ops[0].line_no >= 0
    assert ops[0].source_line == "log-adjacency-changes"


def test_trap_absence_emits_nothing():
    # Parser-absence is False but model default is True — a state walk against
    # EITHER default would be wrong (emit-noise vs Finding-2).  Line detection
    # emits nothing when no line exists; the engine strip keeps the parser
    # value so the batched path stays byte-identical to legacy.
    pc = _parse("router ospf 1\n network 10.0.0.0 0.0.0.255 area 0\n")
    assert pc.ospf_instances[0].log_adjacency_changes is False
    assert _lac_ops(pc) == []


def test_trap_negation_line_detected_false():
    # `no log-adjacency-changes` is silently dropped by the legacy parser (no
    # tombstone, no model effect beyond absence) — 6c line-detects it.
    pc = _parse("router ospf 1\n no log-adjacency-changes\n")
    ops = _lac_ops(pc)
    assert len(ops) == 1
    assert ops[0].value is False
    assert not pc.no_commands  # legacy stays blind (no tombstone)


def test_trap_tri_state_both_orders_line_numbered():
    pc = _parse(
        "router ospf 1\n log-adjacency-changes\n no log-adjacency-changes\n"
    )
    ops = _lac_ops(pc)
    assert [op.value for op in ops] == [True, False]
    assert ops[0].line_no < ops[1].line_no
    pc = _parse(
        "router ospf 1\n no log-adjacency-changes\n log-adjacency-changes\n"
    )
    assert [op.value for op in _lac_ops(pc)] == [False, True]


def test_trap_detail_line_counts_as_positive():
    pc = _parse("router ospf 1\n log-adjacency-changes detail\n")
    assert [op.value for op in _lac_ops(pc)] == [True]
    sets = {op.path for op in _f6c(pc) if op.verb is Verb.SET}
    assert ("ospf_instances", "1", "", "scalar", "log_adjacency_changes_detail") in sets


# --- ops-only `no network` (no legacy twin) --------------------------------

def _net_removals(pc):
    return [op for op in _f6c(pc) if is_native_ospf_network_removal_op(op)]


def test_no_network_refresh_suppresses_removal():
    pc = _parse(
        "router ospf 1\n"
        " no network 10.0.0.0 0.0.0.255 area 0\n"
        " network 10.0.0.0 0.0.0.255 area 0\n"
    )
    assert _net_removals(pc) == []


def test_no_network_withdrawal_removal_stands():
    pc = _parse("router ospf 1\n no network 10.0.0.0 0.0.0.255 area 0\n")
    rem = _net_removals(pc)
    assert len(rem) == 1
    assert rem[0].path == ("ospf_instance", "1", "", "network", "10.0.0.0/24", "0")


def test_network_then_no_network_removal_stands():
    pc = _parse(
        "router ospf 1\n"
        " network 10.0.0.0 0.0.0.255 area 0\n"
        " no network 10.0.0.0 0.0.0.255 area 0\n"
    )
    assert len(_net_removals(pc)) == 1


def test_no_network_different_area_not_suppressed():
    # Suppression identity is (cidr, area) — a re-add into a DIFFERENT area
    # must not suppress the removal (area move, both statements real intent).
    pc = _parse(
        "router ospf 1\n"
        " no network 10.0.0.0 0.0.0.255 area 0\n"
        " network 10.0.0.0 0.0.0.255 area 5\n"
    )
    rem = _net_removals(pc)
    assert len(rem) == 1 and rem[0].path[5] == "0"


def test_no_network_is_ops_only_list_remove():
    pc = _parse(OSPF_FULL)
    rem = _net_removals(pc)
    assert len(rem) == 1
    op = rem[0]
    assert op.verb is Verb.LIST_REMOVE
    assert op.path == ("ospf_instance", "1", "", "network", "10.9.0.0/24", "0")
    assert op.line_no >= 0
    # NO legacy twin — encode_legacy emits nothing.
    assert encode_legacy([op]).no_commands == []
    # And nothing leaks into the parsed no_commands (legacy stays blind).
    assert not any("network" in ts for ts in pc.no_commands)


def test_no_network_wildcard_normalization_matches_positive_parse():
    # The 6b _eigrp_net lesson: removal matching rides the SAME wildcard
    # inversion as the positive walk.
    pc = _parse("router ospf 1\n no network 172.16.4.0 0.0.3.255 area 2\n")
    rem = _net_removals(pc)
    assert rem[0].path[4:] == ("172.16.4.0/22", "2")


# --- whole-process delete (native, byte-exact tombstone) -------------------

def test_process_delete_native_byte_exact():
    pc = _parse("no router ospf 1\n")
    dels = [op for op in _f6c(pc) if op.verb is Verb.OBJECT_DELETE]
    assert len(dels) == 1
    op = dels[0]
    assert op.path == ("process", "ospf", "1")
    assert op.origin == "native" and op.line_no >= 0
    assert pc.no_commands == ["process:ospf:1"]
    assert encode_legacy([op]).no_commands == ["process:ospf:1"]


def test_vrf_instance_keys_carry_vrf():
    # `router ospf 10 vrf CUST` — the instance key is (str(pid), vrf).
    pc = _parse(
        "router ospf 10 vrf CUST\n"
        " router-id 3.3.3.3\n"
        " no network 10.0.0.0 0.0.0.255 area 0\n"
    )
    assert pc.ospf_instances[0].vrf == "CUST"
    sets = {op.path[:3] for op in _f6c(pc) if op.verb is Verb.SET}
    assert ("ospf_instances", "10", "CUST") in sets
    rem = _net_removals(pc)
    assert rem and rem[0].path[:3] == ("ospf_instance", "10", "CUST")


# --- co-existence: derived whole-instance SET SURVIVES ---------------------

def test_derived_whole_instance_set_survives_composition():
    pc = _parse(OSPF_FULL)
    ops = derive_ops(pc)
    inst_sets = [
        op for op in ops
        if op.path == ("ospf_instances", "1", "") and op.verb is Verb.SET
    ]
    assert len(inst_sets) == 1  # co-exists (6c does NOT retire it)
    assert str(inst_sets[0].value.process_id) == "1"
    # areas ride the surviving SET, untouched (O.0).
    assert inst_sets[0].value.areas


# --- anti-rot: every family-6c-shaped op is native -------------------------

def test_anti_rot_family6c_never_derived():
    pc = _parse(OSPF_FULL + "no router ospf 7\n")
    ops = derive_ops(pc)
    for op in ops:
        if op.path[:1] == ("ospf_instances",) and len(op.path) >= 5:
            assert op.origin == "native", op.path
        if op.path[:1] == ("ospf_instance",):
            assert op.origin == "native", op.path
        if op.path[:2] == ("process", "ospf"):
            assert op.origin == "native", op.path


def test_families_igp_coexist():
    # Interleaved IS-IS + EIGRP + OSPF: all co-existing (6a/6b/6c), derived
    # whole-instance SETs SURVIVE beside the native decompositions.
    pc = _parse(
        "router isis CORE\n net 49.0001.0000.0000.0001.00\n"
        "router eigrp 100\n network 10.0.0.0\n"
        "router ospf 1\n network 10.0.0.0 0.0.0.255 area 0\n"
    )
    ops = derive_ops(pc)
    assert any(op.path == ("isis_instances", "CORE") for op in ops)
    assert any(op.path == ("eigrp_instances", "100", "") for op in ops)
    assert any(op.path == ("ospf_instances", "1", "") for op in ops)
    assert any(is_native_isis_op(op) for op in ops)
    assert any(is_native_eigrp_op(op) for op in ops)
    assert any(is_native_ospf_op(op) for op in ops)


# --- NX-OS inheritance ------------------------------------------------------

def test_nxos_inherits_ospf_decomposition():
    # nxos_parser.parse_ospf wraps super().parse_ospf(), so the positive walk,
    # the line-detected trap and the `no network` removal apply verbatim.
    pc = _parse(
        "router ospf 1\n"
        " router-id 2.2.2.2\n"
        " log-adjacency-changes\n"
        " no network 10.0.0.0 0.0.0.255 area 0\n",
        parser_cls=NXOSParser,
    )
    sets = {op.path for op in _f6c(pc) if op.verb is Verb.SET}
    assert ("ospf_instances", "1", "", "scalar", "router_id") in sets
    assert ("ospf_instances", "1", "", "scalar", "log_adjacency_changes") in sets
    assert len(_net_removals(pc)) == 1


def test_nxos_inherits_process_ospf_delete():
    pc = _parse("no router ospf 1\n", parser_cls=NXOSParser)
    dels = [op for op in _f6c(pc) if op.verb is Verb.OBJECT_DELETE]
    assert dels and dels[0].path == ("process", "ospf", "1")
    assert pc.no_commands == ["process:ospf:1"]
