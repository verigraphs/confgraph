"""CCR-0203 — nested negations no walk consumes are DISCLOSED, never dropped.

The class half of user-test F-12: two fail-open layers deferred to each other
(the child-line collector skipped every ``no`` line; the tombstone/op walks
were match-or-vanish), so an unhandled nested withdrawal shipped a green
"appears contained" with the area claimed ANALYZED. Now every ``no`` line at
any depth under a claimed block is consumed-with-emission (the outcome-based
negation-claim ledger — an op/tombstone at that line is the proof), declared
benign (``_KNOWN_BENIGN_NEGATIONS`` — modelled-positive semantics), or
disclosed as an ``UnrecognizedBlock`` riding the existing UNRECOGNIZED
channel to coverage.
"""

from __future__ import annotations

from confgraph.change_ir import Verb, derive_ops
from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.iosxr_parser import IOSXRParser


def _negation_disclosures(pc) -> list[str]:
    return [
        b.block_header for b in pc.unrecognized_blocks if "> no" in b.block_header
    ]


class TestFailClosedDisclosure:
    def test_unconsumed_nested_negation_is_disclosed(self):
        # The corpus's real F-12 survivors: shapes no walk consumes today.
        cfg = (
            "router bgp 65002\n"
            " no bgp confederation identifier 65000\n"
        )
        pc = IOSParser(cfg, "ios").parse()
        assert _negation_disclosures(pc) == [
            "router bgp 65002 > no bgp confederation identifier 65000"
        ]

    def test_parity_an_invented_negation_needs_zero_code(self):
        # The structural promise: the NEXT unhandled withdrawal spelling is
        # disclosed by construction — this grammar exists nowhere.
        cfg = (
            "router bgp 65000\n"
            " no bgp totally-invented-knob 42\n"
        )
        pc = IOSParser(cfg, "ios").parse()
        assert _negation_disclosures(pc) == [
            "router bgp 65000 > no bgp totally-invented-knob 42"
        ]

    def test_grandchild_depth_is_walked(self):
        # all_children, not direct children — the F-12 probes lived two deep.
        cfg = (
            "router bgp 65000\n"
            " address-family ipv4\n"
            "  no bgp invented-af-knob\n"
        )
        pc = IOSParser(cfg, "ios").parse()
        assert _negation_disclosures(pc) == [
            "router bgp 65000 > no bgp invented-af-knob"
        ]

    def test_fires_on_iosxr_despite_empty_child_pattern_registry(self):
        # XR has _KNOWN_CHILD_PATTERNS = [] — the negation walk is gated on
        # the CLAIMED-block set only, or it would never fire for XR at all.
        cfg = (
            "router bgp 65000\n"
            " neighbor 10.0.0.9\n"
            "  no invented-xr-neighbor-knob\n"
        )
        pc = IOSXRParser(cfg).parse()
        assert _negation_disclosures(pc) == [
            "router bgp 65000 > no invented-xr-neighbor-knob"
        ]

    def test_disclosure_reaches_the_ops_channel(self):
        # The vehicle end-to-end on the confgraph side: the composer turns the
        # UnrecognizedBlock into the UNRECOGNIZED marker op the engine's
        # coverage consumes — zero new plumbing.
        cfg = "router bgp 65000\n no bgp totally-invented-knob 42\n"
        ops = derive_ops(IOSParser(cfg, "ios").parse())
        markers = [o for o in ops if o.verb is Verb.UNRECOGNIZED]
        assert any(
            "no bgp totally-invented-knob 42" in (o.source_line or "")
            for o in markers
        )


class TestBareAddressWithdrawalDiscloses:
    def test_no_ip_address_is_disclosed_not_silenced(self):
        # Harness-caught during registry curation: the draft registry listed
        # ``no ip address`` as benign, but NO parser consumes the bare form —
        # no op, no tombstone, the merged interface KEEPS its address. A real
        # unapplied withdrawal must amber, never silence (the one failure
        # direction this registry is forbidden: a spurious row fails silent).
        cfg = (
            "interface GigabitEthernet1\n"
            " ip address 10.0.0.1 255.255.255.0\n"
            " no ip address\n"
        )
        pc = IOSParser(cfg, "ios").parse()
        assert _negation_disclosures(pc) == [
            "interface GigabitEthernet1 > no ip address"
        ]


class TestTheLedgerKeepsConsumedNegationsQuiet:
    def test_registry_rule_consumption_is_not_disclosed(self):
        cfg = (
            "router bgp 65000\n"
            " address-family ipv4\n"
            "  no redistribute static route-map RM\n"
        )
        pc = IOSParser(cfg, "ios").parse()
        assert pc.no_commands == ["field:bgp:65000:af:ipv4:redistribute:static:"]
        assert _negation_disclosures(pc) == []

    def test_op_emitting_interface_negation_is_not_disclosed(self):
        # Outcome-based: the family-1 UNSET op at that line IS the claim.
        cfg = "interface GigabitEthernet1\n no bfd interval\n"
        pc = IOSParser(cfg, "ios").parse()
        assert _negation_disclosures(pc) == []

    def test_refresh_suppressed_removal_is_consumed_not_blind(self):
        # Suppressed-by-re-add emits nothing, but the walk UNDERSTOOD it —
        # the explicit claim in the suppression branch keeps it quiet.
        cfg = (
            "router ospf 1\n"
            " no network 10.30.1.0 0.0.0.255 area 0\n"
            " network 10.30.1.0 0.0.0.255 area 0\n"
        )
        pc = IOSParser(cfg, "ios").parse()
        assert _negation_disclosures(pc) == []


class TestValidationRoundConsumptions:
    """Two real withdrawals the validation round caught being mishandled —
    both now CONSUMED (the structural outcome), neither silenced nor ambered."""

    def test_no_neighbor_remote_as_is_full_neighbor_removal(self):
        # The standard IOS spelling for removing a neighbor; previously it
        # emitted nothing and only the platform corpus's positive re-add made
        # renumber_peering appear to work.
        cfg = "router bgp 64550\n no neighbor 10.0.1.150 remote-as 64512\n"
        pc = IOSParser(cfg, "ios").parse()
        deletes = [
            o.path
            for o in (pc.native_change_ops or [])
            if o.verb is Verb.OBJECT_DELETE and o.path[:1] == ("bgp_instance",)
        ]
        assert deletes == [("bgp_instance", "64550", "", "neighbor", "10.0.1.150")]
        assert _negation_disclosures(pc) == []

    def test_bare_no_switchport_is_consumed_as_the_l2_reset(self):
        # The routed-port conversion: withdraws the port's L2 personality.
        # It sat in the benign registry under a false modelled-positive
        # justification; now it emits one UNSET per L2 field and the merge
        # actually strips them.
        cfg = "interface GigabitEthernet1\n switchport mode access\n no switchport\n"
        pc = IOSParser(cfg, "ios").parse()
        unset_fields = {
            o.path[3]
            for o in (pc.native_change_ops or [])
            if o.verb is Verb.UNSET
            and o.path[:3] == ("field", "interface", "GigabitEthernet1")
            and (o.source_line or "") == "no switchport"
        }
        assert unset_fields == {
            "switchport_mode",
            "access_vlan",
            "trunk_allowed_vlans",
            "trunk_native_vlan",
        }
        assert _negation_disclosures(pc) == []


class TestBenignRegistry:
    def test_modelled_positive_negations_stay_quiet(self):
        cfg = (
            "interface GigabitEthernet1\n"
            " no shutdown\n"
            " no switchport\n"
            "router bgp 65000\n"
            " no auto-summary\n"
            " no synchronization\n"
            " address-family ipv4\n"
            "  no neighbor 10.0.0.2 activate\n"
            "router eigrp 100\n"
            " no passive-interface GigabitEthernet1\n"
        )
        pc = IOSParser(cfg, "ios").parse()
        assert _negation_disclosures(pc) == []

    def test_parity_one_registry_row_silences_a_grammar(self):
        # Adding a benign grammar is exactly one row — proven by adding it at
        # runtime on a subclass, the _KNOWN_CHILD_PATTERNS extension pattern.
        cfg = "router bgp 65000\n no bgp invented-benign-flag\n"
        assert _negation_disclosures(IOSParser(cfg, "ios").parse()) != []

        class _Extended(IOSParser):
            _KNOWN_BENIGN_NEGATIONS = IOSParser._KNOWN_BENIGN_NEGATIONS + [
                r"^no\s+bgp\s+invented-benign-flag$",
            ]

        assert _negation_disclosures(_Extended(cfg, "ios").parse()) == []
