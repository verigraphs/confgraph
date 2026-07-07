"""Change-IR Phase 3, family 5b — native BGP peer-group + instance-level network ops.

CCR: ``change_ir_proposal_operations.md`` Appendix I (WI-18b, 5b-core).

Covers (5b-core scope — decomposition/AF-block are 5c):
- peer-group CREATE as native ``SET ("bgp_instances", asn, vrf, "peer_group",
  name)`` (symmetric to the 5a neighbor SET),
- instance-level ``network`` CREATE as native ``SET ("bgp_instances", asn, vrf,
  "network", <prefix>)`` (global router bgp + per-VRF-AF ``BGPConfig.networks``),
- Candidate-B peer-group DELETION: ``no neighbor GROUP peer-group`` (GROUP a
  peer-group name / non-IP token) → native ``OBJECT_DELETE`` at the
  ``field:neighbor:GROUP:peer_group`` path, byte-identical legacy string,
- ops-only ``no network`` → native ``LIST_REMOVE`` with NO legacy twin
  (encode_legacy emits nothing; legacy artifacts byte-identical),
- codec predicates ``is_native_bgp_op`` / ``is_native_bgp_network_removal_op``
  and the key helpers ``bgp_peer_group_key`` / ``bgp_network_key``,
- hybrid ``derive_ops`` composition: exact-path dedupe retires the derived
  Candidate-B twin, container-claim exclusion keeps the derived whole-instance
  SET alive, anti-rot (no 5b form derived), NX-OS inheritance.
"""

from __future__ import annotations

from confgraph.change_ir import (
    Verb,
    bgp_network_key,
    bgp_peer_group_key,
    derive_ops,
    encode_legacy,
    is_native_bgp_network_removal_op,
    is_native_bgp_op,
)
from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.nxos_parser import NXOSParser


def _parse(text: str, parser_cls=IOSParser):
    return parser_cls(text).parse()


def _bgp_ops(pc):
    return [op for op in pc.native_change_ops if is_native_bgp_op(op)]


PG_AND_NETWORK = (
    "router bgp 65000\n"
    " network 10.0.0.0 mask 255.0.0.0\n"
    " no network 172.16.0.0 mask 255.255.0.0\n"
    " neighbor UPSTREAM peer-group\n"
    " neighbor UPSTREAM remote-as 65002\n"
    " neighbor 10.0.0.2 remote-as 65002\n"
    " neighbor 10.0.0.2 peer-group UPSTREAM\n"
    " no neighbor UPSTREAM peer-group\n"
    " no neighbor 10.0.0.2 route-map RM in\n"
)


class TestKeysAndPredicates:
    def test_peer_group_key(self):
        pc = _parse("router bgp 65000\n neighbor PG peer-group\n neighbor PG remote-as 1\n")
        pg = pc.bgp_instances[0].peer_groups[0]
        assert bgp_peer_group_key(pg) == ("PG",)

    def test_network_key_is_canonical_prefix(self):
        pc = _parse("router bgp 65000\n network 10.0.0.0 mask 255.0.0.0\n")
        net = pc.bgp_instances[0].networks[0]
        assert bgp_network_key(net) == ("10.0.0.0/8",)

    def test_predicate_matches_peer_group_set(self):
        pc = _parse(PG_AND_NETWORK)
        pg_sets = [
            op for op in _bgp_ops(pc)
            if op.verb is Verb.SET and op.path[3] == "peer_group"
        ]
        assert len(pg_sets) == 1
        assert pg_sets[0].path == ("bgp_instances", "65000", "", "peer_group", "UPSTREAM")
        assert pg_sets[0].origin == "native"

    def test_predicate_matches_network_set(self):
        pc = _parse(PG_AND_NETWORK)
        net_sets = [
            op for op in _bgp_ops(pc)
            if op.verb is Verb.SET and op.path[3] == "network"
        ]
        assert [op.path for op in net_sets] == [
            ("bgp_instances", "65000", "", "network", "10.0.0.0/8")
        ]

    def test_network_removal_predicate(self):
        pc = _parse(PG_AND_NETWORK)
        removals = [op for op in pc.native_change_ops if is_native_bgp_network_removal_op(op)]
        assert len(removals) == 1
        assert removals[0].verb is Verb.LIST_REMOVE
        assert removals[0].path == ("bgp_instance", "65000", "", "network", "172.16.0.0/16")


class TestCandidateB:
    def test_no_neighbor_group_peergroup_is_object_delete(self):
        pc = _parse(PG_AND_NETWORK)
        deletes = [
            op for op in _bgp_ops(pc)
            if op.verb is Verb.OBJECT_DELETE and op.path[3] == "field"
        ]
        assert len(deletes) == 1
        assert deletes[0].path == (
            "bgp_instance", "65000", "", "field", "neighbor", "UPSTREAM", "peer_group",
        )

    def test_no_neighbor_ip_peergroup_stays_unset(self):
        # An IP argument = removing a neighbor from its group (per-neighbor
        # reset), NOT a peer-group deletion.
        pc = _parse(
            "router bgp 65000\n"
            " neighbor 10.0.0.2 remote-as 65002\n"
            " neighbor 10.0.0.2 peer-group PG\n"
            " neighbor PG peer-group\n"
            " neighbor PG remote-as 65002\n"
            " no neighbor 10.0.0.2 peer-group\n"
        )
        unsets = [
            op for op in _bgp_ops(pc)
            if op.verb is Verb.UNSET and op.path[5] == "10.0.0.2" and op.path[-1] == "peer_group"
        ]
        assert len(unsets) == 1
        deletes = [op for op in _bgp_ops(pc) if op.verb is Verb.OBJECT_DELETE and op.path[3] == "field"]
        assert deletes == []


class TestLegacyByteIdentity:
    def test_no_commands_unchanged(self):
        # Candidate-B keeps the exact legacy tombstone string; no network adds
        # NOTHING to no_commands (silently dropped, as today).
        pc = _parse(PG_AND_NETWORK)
        assert pc.bgp_instances[0].no_commands == [
            "field:neighbor:UPSTREAM:peer_group",
            "field:neighbor:10.0.0.2:route_map_in",
        ]

    def test_encode_legacy_roundtrip_byte_identical(self):
        pc = _parse(PG_AND_NETWORK)
        arts = encode_legacy(derive_ops(pc))
        assert arts.bgp_no_commands[("65000", "")] == pc.bgp_instances[0].no_commands

    def test_no_network_encodes_to_nothing(self):
        pc = _parse("router bgp 65000\n no network 172.16.0.0 mask 255.255.0.0\n")
        arts = encode_legacy(derive_ops(pc))
        assert arts.bgp_no_commands == {}
        assert pc.bgp_instances[0].no_commands == []


class TestCompositionAndAntiRot:
    def test_derived_whole_instance_set_retired(self):
        # 5c-B.2 (CCR Appendix L): retired for this fully-native IOS instance
        # (was ``…_survives`` through 5a/5b/5c — the native CREATE op now claims
        # the prefix; H.3 narrowing).
        from confgraph.change_ir import is_native_bgp_instance_create_op

        pc = _parse(PG_AND_NETWORK)
        ops = derive_ops(pc)
        whole = [
            op for op in ops
            if op.verb is Verb.SET and op.path == ("bgp_instances", "65000", "")
        ]
        assert whole == []
        assert len([o for o in ops if is_native_bgp_instance_create_op(o)]) == 1

    def test_candidate_b_derived_twin_deduped(self):
        # The derived UNSET twin (same path as the native OBJECT_DELETE) must be
        # dropped by exact-path dedupe — no double-handling.
        pc = _parse(PG_AND_NETWORK)
        ops = derive_ops(pc)
        cb_path = (
            "bgp_instance", "65000", "", "field", "neighbor", "UPSTREAM", "peer_group",
        )
        matching = [op for op in ops if op.path == cb_path]
        assert len(matching) == 1
        assert matching[0].verb is Verb.OBJECT_DELETE
        assert matching[0].origin == "native"

    def test_anti_rot_no_5b_form_derived(self):
        pc = _parse(PG_AND_NETWORK)
        for op in derive_ops(pc):
            p = op.path
            is_5b_shape = (
                (p[0] == "bgp_instances" and len(p) == 5 and p[3] in ("peer_group", "network"))
                or is_native_bgp_network_removal_op(op)
                or (op.verb is Verb.OBJECT_DELETE and len(p) == 7 and p[0] == "bgp_instance"
                    and p[3] == "field" and p[-1] == "peer_group")
            )
            if is_5b_shape:
                assert op.origin == "native", f"5b-shaped op is derived: {op.path}"

    def test_natives_less_producer_still_derives(self):
        # A hand-built ParsedConfig with no native_change_ops keeps full derived
        # translation (graceful degradation).
        pc = _parse(PG_AND_NETWORK)
        pc.native_change_ops = None
        ops = derive_ops(pc)
        # No native ops → the whole-instance SET is the only bgp_instances SET.
        set_paths = {op.path for op in ops if op.verb is Verb.SET and op.path[0] == "bgp_instances"}
        assert set_paths == {("bgp_instances", "65000", "")}


class TestPerVrfAndNxos:
    def test_per_vrf_networks_emit_native(self):
        pc = _parse(
            "router bgp 65000\n"
            " address-family ipv4 vrf CUST\n"
            "  network 10.9.0.0 mask 255.255.0.0\n"
            "  no network 10.8.0.0 mask 255.255.0.0\n"
        )
        vrf_inst = next(b for b in pc.bgp_instances if b.vrf == "CUST")
        ops = _bgp_ops(pc)
        net_sets = [op for op in ops if op.verb is Verb.SET and op.path[3] == "network" and op.path[2] == "CUST"]
        assert [op.path for op in net_sets] == [
            ("bgp_instances", "65000", "CUST", "network", "10.9.0.0/16")
        ]
        removals = [op for op in pc.native_change_ops if is_native_bgp_network_removal_op(op) and op.path[2] == "CUST"]
        assert len(removals) == 1

    def test_nxos_inherits_peer_group_and_network_emission(self):
        pc = _parse(PG_AND_NETWORK, parser_cls=NXOSParser)
        ops = _bgp_ops(pc)
        kinds = {op.path[3] for op in ops if op.verb is Verb.SET}
        assert "peer_group" in kinds
        assert "network" in kinds
