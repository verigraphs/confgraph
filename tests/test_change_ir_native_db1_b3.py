"""WI-DB1-B3 (task #42) — blind-negation batch 3: global scalar/singleton
resets (parser side).

CCR: ``change_ir_proposal_operations.md`` Appendix AC.

Two scope areas, one mechanism class (line-detected SET-to-post-line-state —
the V.2/Z pattern; parse fold and emission share ONE regex set/classifier):

1. DHCP snooping negations + the U.6(2) dead-branch fix:
   ``no ip dhcp snooping`` (line-detected SET False — ops-only, model
   default), ``no ip dhcp relay information option`` (anchored; fold False
   is state-visible → legacy twin), ``no ip dhcp snooping vlan <spec>``
   (LIST_REMOVE tombstone twin, exact spec string).
2. L2 global resets: ``no vtp mode|version`` (fold to server/1 —
   state-visible), ``no lacp system-priority`` (fold to 32768),
   ``no spanning-tree mode`` (fold to the per-OS device default),
   ``no spanning-tree portfast [bpduguard|bpdufilter] default`` /
   ``loopguard default`` (line-detected SET False ×4 — ops-only), and the
   ``vlan_configs`` removal surface (``no spanning-tree vlan <spec>
   [priority|hello-time|forward-time|max-age]`` tombstone twins).

Over-trigger negatives pin the AC.3 blind-disclosed boundary (the standing
validator attack class).
"""

from __future__ import annotations

from confgraph.change_ir import (
    Verb,
    _verb_for_top_tombstone,
    derive_ops,
    encode_legacy,
    is_native_singleton_section_op,
)
from confgraph.parsers.eos_parser import EOSParser
from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.iosxr_parser import IOSXRParser
from confgraph.parsers.nxos_parser import NXOSParser


def _native(pc):
    return [op for op in (pc.native_change_ops or []) if op.origin == "native"]


def _by_path(pc):
    return {op.path: op for op in _native(pc)}


def _removals(pc):
    return [
        op
        for op in _native(pc)
        if op.verb in (Verb.LIST_REMOVE, Verb.OBJECT_DELETE)
    ]


# ---------------------------------------------------------------------------
# 1. DHCP — snooping / relay-option tri-states + snooping-vlan removal
# ---------------------------------------------------------------------------


class TestDHCPSnooping:
    def test_negation_only_proposal_folds_and_emits(self):
        # The AC.0 mechanism wrinkle: a negation-only proposal must parse
        # the section to post-line-state (NOT None) so the line-detected op
        # has a carrier and legacy sees a section.
        pc = IOSParser("no ip dhcp snooping\n").parse()
        assert pc.dhcp is not None
        assert pc.dhcp.snooping_enabled is False
        op = _by_path(pc)[("dhcp", "scalar", "snooping_enabled")]
        assert op.value is False
        assert op.source_line == "no ip dhcp snooping"
        assert op.line_no == 0
        assert pc.no_commands == []  # scalar reset — never a tombstone

    def test_last_line_winner_both_orders(self):
        pc = IOSParser("no ip dhcp snooping\nip dhcp snooping\n").parse()
        assert pc.dhcp.snooping_enabled is True
        op = _by_path(pc)[("dhcp", "scalar", "snooping_enabled")]
        assert op.value is True and op.line_no == 1

        pc = IOSParser("ip dhcp snooping\nno ip dhcp snooping\n").parse()
        assert pc.dhcp.snooping_enabled is False
        op = _by_path(pc)[("dhcp", "scalar", "snooping_enabled")]
        assert op.value is False and op.line_no == 1

    def test_positive_only_unchanged_state_op_at_true_line(self):
        # Corpus shape: positives keep their pre-WI parsed state; the scalar
        # op keeps its path (moved from the block-head state walk to the
        # true line — value identical).
        pc = IOSParser("ip dhcp excluded-address 10.0.0.1\nip dhcp snooping\n").parse()
        assert pc.dhcp.snooping_enabled is True
        op = _by_path(pc)[("dhcp", "scalar", "snooping_enabled")]
        assert op.value is True and op.source_line == "ip dhcp snooping"

    def test_absence_no_op(self):
        pc = IOSParser("ip dhcp excluded-address 10.0.0.1\n").parse()
        assert ("dhcp", "scalar", "snooping_enabled") not in _by_path(pc)
        assert ("dhcp", "scalar", "relay_information_option") not in _by_path(pc)


class TestDHCPRelayOption:
    def test_dead_branch_fixed_negation_folds(self):
        # The U.6(2) dead branch is REACHABLE now (broadened scan) and
        # ANCHORED (AC.1 ruling: fix, not delete).
        pc = IOSParser("ip dhcp snooping\nno ip dhcp relay information option\n").parse()
        assert pc.dhcp.relay_information_option is False
        op = _by_path(pc)[("dhcp", "scalar", "relay_information_option")]
        assert op.value is False
        assert op.source_line == "no ip dhcp relay information option"

    def test_positive_reassert_emits_true(self):
        # The cdp.advertise_v2 shape: positive line is state-invisible
        # (True == default) but line-detected → device-truth op.
        pc = IOSParser("ip dhcp relay information option\n").parse()
        assert pc.dhcp.relay_information_option is True
        op = _by_path(pc)[("dhcp", "scalar", "relay_information_option")]
        assert op.value is True

    def test_suboption_forms_stay_blind(self):
        # The anchor kills the former substring over-trigger: the vpn /
        # option-insert suboptions do NOT disable option 82 on the device.
        pc = IOSParser(
            "ip dhcp snooping\n"
            "no ip dhcp relay information option vpn\n"
            "no ip dhcp relay information option-insert\n"
        ).parse()
        assert pc.dhcp.relay_information_option is True
        assert ("dhcp", "scalar", "relay_information_option") not in _by_path(pc)


class TestDHCPSnoopingVlanRemoval:
    def test_tombstone_twin_and_native_op(self):
        pc = IOSParser("no ip dhcp snooping vlan 10,20\n").parse()
        assert pc.no_commands == ["field:dhcp:snooping_vlan:10,20"]
        (op,) = _removals(pc)
        assert op.path == ("field", "dhcp", "snooping_vlan", "10,20")
        assert op.verb is Verb.LIST_REMOVE
        assert op.line_no == 0
        assert op.source_line == "no ip dhcp snooping vlan 10,20"
        assert is_native_singleton_section_op(op)

    def test_spec_guard_rejects_grammar_tokens(self):
        # The B2 validator-C2 lesson: non-[\d,\-] tokens in the spec
        # position (device-rejected CLI) must never fire a removal.
        pc = IOSParser(
            "no ip dhcp snooping vlan FOO\n"
            "no ip dhcp snooping trust\n"
            "no ip dhcp\n"
        ).parse()
        assert pc.no_commands == []
        assert _removals(pc) == []

    def test_interface_child_form_not_matched(self):
        # `no ip dhcp snooping trust` under an interface is indented —
        # the column-0 scans never see it (family-1 surface, untouched).
        pc = IOSParser(
            "interface GigabitEthernet0/1\n no ip dhcp snooping trust\n"
        ).parse()
        assert all(not t.startswith("field:dhcp:") for t in pc.no_commands)


# ---------------------------------------------------------------------------
# 2a. VTP
# ---------------------------------------------------------------------------


class TestVTPResets:
    def test_no_vtp_mode_resets_to_server(self):
        pc = IOSParser("vtp mode transparent\nno vtp mode\n").parse()
        assert pc.vtp.mode == "server"
        # State-visible → carried by the state walk (legacy twin).
        assert _by_path(pc)[("vtp", "scalar", "mode")].value == "server"

    def test_no_vtp_mode_with_operand_still_server(self):
        pc = IOSParser("no vtp mode client\n").parse()
        assert pc.vtp.mode == "server"

    def test_no_vtp_version_resets_to_one(self):
        pc = IOSParser("vtp version 3\nno vtp version 3\n").parse()
        assert pc.vtp.version == 1
        assert _by_path(pc)[("vtp", "scalar", "version")].value == 1

    def test_last_line_winner_both_orders(self):
        pc = IOSParser("no vtp mode\nvtp mode transparent\n").parse()
        assert pc.vtp.mode == "transparent"
        pc = IOSParser("vtp mode transparent\nno vtp mode\n").parse()
        assert pc.vtp.mode == "server"

    def test_blind_forms(self):
        # `no vtp` bare does not create the section; domain/password/pruning
        # negations fold nothing (AC.3 — device-questionable / no surface).
        assert IOSParser("no vtp\n").parse().vtp is None
        pc = IOSParser(
            "vtp domain CORP\n"
            "no vtp domain CORP\n"
            "no vtp password s3cret\n"
            "no vtp pruning\n"
        ).parse()
        assert pc.vtp.domain == "CORP"
        assert pc.vtp.mode is None and pc.vtp.version is None
        assert pc.no_commands == []


# ---------------------------------------------------------------------------
# 2b. LACP system-priority
# ---------------------------------------------------------------------------


class TestLACPReset:
    def test_negation_only_resets_to_default(self):
        pc = IOSParser("no lacp system-priority\n").parse()
        assert pc.lacp_system_priority == 32768
        op = _by_path(pc)[("lacp_system_priority",)]
        assert op.value == 32768 and op.source_line == "no lacp system-priority"

    def test_both_orders(self):
        pc = IOSParser("lacp system-priority 100\nno lacp system-priority 100\n").parse()
        assert pc.lacp_system_priority == 32768
        assert _by_path(pc)[("lacp_system_priority",)].line_no == 1

        pc = IOSParser("no lacp system-priority\nlacp system-priority 100\n").parse()
        assert pc.lacp_system_priority == 100
        op = _by_path(pc)[("lacp_system_priority",)]
        assert op.value == 100 and op.line_no == 1

    def test_bare_no_lacp_stays_blind(self):
        pc = IOSParser("no lacp\nno lacp system-priority 100 extra\n").parse()
        assert pc.lacp_system_priority is None
        assert ("lacp_system_priority",) not in _by_path(pc)


# ---------------------------------------------------------------------------
# 2c. Spanning-tree global scalars
# ---------------------------------------------------------------------------


class TestSTPModeReset:
    def test_ios_resets_to_pvst(self):
        pc = IOSParser("spanning-tree mode rapid-pvst\nno spanning-tree mode\n").parse()
        assert pc.spanning_tree.mode == "pvst"
        assert _by_path(pc)[("spanning_tree", "scalar", "mode")].value == "pvst"

    def test_per_os_device_defaults(self):
        assert NXOSParser("no spanning-tree mode\n").parse().spanning_tree.mode == "rapid-pvst"
        assert EOSParser("no spanning-tree mode\n").parse().spanning_tree.mode == "mstp"

    def test_last_line_winner_both_orders(self):
        pc = IOSParser("no spanning-tree mode\nspanning-tree mode mst\n").parse()
        assert pc.spanning_tree.mode == "mst"
        pc = IOSParser("spanning-tree mode mst\nno spanning-tree mode mst\n").parse()
        assert pc.spanning_tree.mode == "pvst"


class TestSTPBooleanResets:
    def test_all_four_resets_fold_and_emit(self):
        pc = IOSParser(
            "spanning-tree portfast default\n"
            "spanning-tree portfast bpduguard default\n"
            "spanning-tree portfast bpdufilter default\n"
            "spanning-tree loopguard default\n"
            "no spanning-tree portfast default\n"
            "no spanning-tree portfast bpduguard default\n"
            "no spanning-tree portfast bpdufilter default\n"
            "no spanning-tree loopguard default\n"
        ).parse()
        stp = pc.spanning_tree
        assert (
            stp.portfast_default,
            stp.bpduguard_default,
            stp.bpdufilter_default,
            stp.loopguard_default,
        ) == (False, False, False, False)
        by_path = _by_path(pc)
        for i, f in enumerate(
            ("portfast_default", "bpduguard_default", "bpdufilter_default",
             "loopguard_default")
        ):
            op = by_path[("spanning_tree", "scalar", f)]
            assert op.value is False, f
            assert op.line_no == 4 + i, f  # anchored at the negation line

    def test_positive_only_emits_true_at_line(self):
        pc = IOSParser("spanning-tree portfast bpduguard default\n").parse()
        assert pc.spanning_tree.bpduguard_default is True
        op = _by_path(pc)[("spanning_tree", "scalar", "bpduguard_default")]
        assert op.value is True and op.line_no == 0

    def test_refresh_last_line_wins(self):
        pc = IOSParser(
            "no spanning-tree portfast default\nspanning-tree portfast default\n"
        ).parse()
        assert pc.spanning_tree.portfast_default is True
        op = _by_path(pc)[("spanning_tree", "scalar", "portfast_default")]
        assert op.value is True and op.line_no == 1

    def test_partial_forms_stay_blind(self):
        # Bare / partial negations and the NX-OS `port type edge` family
        # (positives unparsed) fold nothing and emit nothing (AC.3).
        assert IOSParser("no spanning-tree\n").parse().spanning_tree is None
        pc = IOSParser(
            "spanning-tree portfast default\n"
            "no spanning-tree portfast\n"
            "no spanning-tree portfast bpduguard\n"
            "no spanning-tree port type edge default\n"
        ).parse()
        assert pc.spanning_tree.portfast_default is True
        op = _by_path(pc)[("spanning_tree", "scalar", "portfast_default")]
        assert op.value is True and op.line_no == 0


# ---------------------------------------------------------------------------
# 2d. Spanning-tree vlan_configs removal surface
# ---------------------------------------------------------------------------


class TestSTPVlanRemovals:
    def test_whole_entry_tombstone_twin(self):
        pc = IOSParser("no spanning-tree vlan 200\n").parse()
        assert pc.no_commands == ["field:spanning_tree:vlan:200"]
        (op,) = _removals(pc)
        assert op.path == ("field", "spanning_tree", "vlan", "200")
        assert op.verb is Verb.LIST_REMOVE
        assert is_native_singleton_section_op(op)

    def test_attr_reset_tombstones_all_four_params(self):
        pc = IOSParser(
            "no spanning-tree vlan 100 priority 4096\n"
            "no spanning-tree vlan 100 hello-time\n"
            "no spanning-tree vlan 10-20 forward-time 9\n"
            "no spanning-tree vlan 1,5 max-age\n"
        ).parse()
        assert pc.no_commands == [
            "field:spanning_tree:vlan_reset:100:priority",
            "field:spanning_tree:vlan_reset:100:hello_time",
            "field:spanning_tree:vlan_reset:10-20:forward_time",
            "field:spanning_tree:vlan_reset:1,5:max_age",
        ]
        for op in _removals(pc):
            assert op.verb is Verb.LIST_REMOVE
            assert op.line_no >= 0 and op.source_line.startswith("no ")

    def test_spec_guard_and_unparsed_params_stay_blind(self):
        pc = IOSParser(
            "no spanning-tree vlan\n"
            "no spanning-tree vlan priority\n"
            "no spanning-tree vlan 100 root primary\n"
            "no spanning-tree vlan 100 root\n"
        ).parse()
        assert pc.no_commands == []
        assert _removals(pc) == []

    def test_verb_registry(self):
        assert _verb_for_top_tombstone("field:dhcp:snooping_vlan:10,20") is Verb.LIST_REMOVE
        assert _verb_for_top_tombstone("field:spanning_tree:vlan:200") is Verb.LIST_REMOVE
        assert (
            _verb_for_top_tombstone("field:spanning_tree:vlan_reset:100:priority")
            is Verb.LIST_REMOVE
        )


# ---------------------------------------------------------------------------
# Cross-cutting: dedupe / round-trip / disclosure / per-OS reachability
# ---------------------------------------------------------------------------

BATCH_CFG = """no ip dhcp snooping
no ip dhcp relay information option
no ip dhcp snooping vlan 10,20
no vtp mode
no lacp system-priority
no spanning-tree mode
no spanning-tree portfast default
no spanning-tree vlan 100 priority 4096
no spanning-tree vlan 200
"""

BATCH_TOMBSTONES = [
    "field:dhcp:snooping_vlan:10,20",
    "field:spanning_tree:vlan_reset:100:priority",
    "field:spanning_tree:vlan:200",
]


class TestComposition:
    def test_derived_twins_deduped(self):
        pc = IOSParser(BATCH_CFG).parse()
        ops = derive_ops(pc)
        for t in BATCH_TOMBSTONES:
            matching = [op for op in ops if ":".join(op.path) == t]
            assert len(matching) == 1, t
            assert matching[0].origin == "native", t

    def test_encode_legacy_roundtrip_multiset(self):
        pc = IOSParser(BATCH_CFG).parse()
        art = encode_legacy(derive_ops(pc))
        assert sorted(art.no_commands) == sorted(pc.no_commands)

    def test_scalar_resets_never_pollute_no_commands(self):
        pc = IOSParser(BATCH_CFG).parse()
        assert sorted(pc.no_commands) == sorted(BATCH_TOMBSTONES)

    def test_unrecognized_disclosure_preserved(self):
        # The V.6/AB.2 posture: top-level no-lines stay unrecognized-flagged
        # (disclosed AND applied).
        pc = IOSParser(BATCH_CFG).parse()
        ops = derive_ops(pc)
        n_unrec = sum(1 for op in ops if op.verb is Verb.UNRECOGNIZED)
        assert n_unrec == len(BATCH_CFG.strip().splitlines())


class TestPerOSReachability:
    def test_nxos_inherits_the_batch(self):
        pc = NXOSParser(
            "no ip dhcp snooping\n"
            "no spanning-tree vlan 100 priority 4096\n"
            "no vtp mode\n"
        ).parse()
        assert pc.dhcp.snooping_enabled is False
        assert pc.vtp.mode == "server"
        assert "field:spanning_tree:vlan_reset:100:priority" in pc.no_commands

    def test_eos_inherits_the_batch(self):
        pc = EOSParser(
            "no ip dhcp snooping vlan 30\nno spanning-tree vlan 200\n"
        ).parse()
        assert sorted(pc.no_commands) == [
            "field:dhcp:snooping_vlan:30",
            "field:spanning_tree:vlan:200",
        ]

    def test_iosxr_gated_zero_batch_emission(self):
        # XR overrides parse_dhcp + parse_deletion_commands (no super) and
        # is singleton-gated — zero batch artifacts (Phase 5).
        pc = IOSXRParser(BATCH_CFG).parse()
        assert all(
            t not in (pc.no_commands or []) for t in BATCH_TOMBSTONES
        )
        assert not [
            op
            for op in (pc.native_change_ops or [])
            if op.path and op.path[0] in ("dhcp", "spanning_tree", "vtp")
        ]
