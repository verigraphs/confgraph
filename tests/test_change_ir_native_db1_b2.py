"""WI-DB1-B2 (task #41) — blind-negation batch 2: whole-object + keyed
deletes (parser side).

CCR: ``change_ir_proposal_operations.md`` Appendix AB.

Four scope areas, all previously class-(a) blind (unrecognized-disclosed,
never applied):

1. ``no router rip`` — native ``OBJECT_DELETE ("process","rip","")`` +
   byte-exact ``process:rip:`` twin (the 6a-6c process-delete pattern).
2. NAT + crypto keyed-entry removals — the 8b
   ``_queue_native_singleton_removal`` shape (``field:nat:…`` /
   ``field:crypto:…`` LIST_REMOVEs).
3. Policy-object WHOLE-OBJECT deletes — seq-less ``no route-map <n>`` /
   ``no ip prefix-list <n>`` (the XR-D1 tombstone spellings, legacy
   blind-disclosed BY DESIGN) and whole ``no ip community-list …`` /
   ``no ip as-path access-list <n>`` (twinned via new accessors).
4. lines / class-map / policy-map OBJECT_DELETEs
   (``field:lines|class_maps|policy_maps:…`` — owner decision: lines are
   OBJECT_DELETE with a contract honesty note).

Every regex is anchored: the over-trigger negatives below pin that
partial/attr/seq forms stay exactly as blind as today.
"""

from __future__ import annotations

from confgraph.change_ir import (
    Verb,
    derive_ops,
    encode_legacy,
)
from confgraph.parsers.eos_parser import EOSParser
from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.iosxr_parser import IOSXRParser
from confgraph.parsers.nxos_parser import NXOSParser


ALL_SPELLINGS_CFG = """no router rip
no ip nat pool P0 203.0.113.1 203.0.113.10 netmask 255.255.255.0
no ip nat inside source list NATACL pool P0 overload
no ip nat outside source list ACL2 interface GigabitEthernet0/0 overload
no ip nat inside source static tcp 10.1.1.5 8080 203.0.113.5 80
no ip nat inside source static 10.1.1.6 203.0.113.6
no crypto map VPN
no crypto map VPN2 10 ipsec-isakmp
no crypto isakmp policy 10
no crypto ipsec transform-set TS esp-aes esp-sha-hmac
no route-map RM-OUT
no ip prefix-list PL-OUT
no ip community-list standard CL1
no ip community-list 22
no ip as-path access-list 10
no line vty 5 15
no line con 0
no class-map match-any VOICE
no policy-map EDGE
"""

EXPECTED_TOMBSTONES = [
    "process:rip:",
    "route-map:RM-OUT",
    "prefix-list:PL-OUT",
    "field:community_lists:CL1",
    "field:community_lists:22",
    "field:as_path_lists:10",
    "field:nat:pool:P0",
    "field:nat:dynamic:NATACL",
    "field:nat:dynamic:ACL2",
    "field:nat:static:10.1.1.5:8080",
    "field:nat:static:10.1.1.6",
    "field:crypto:crypto_map:VPN",
    "field:crypto:crypto_map:VPN2:10",
    "field:crypto:isakmp_policy:10",
    "field:crypto:transform_set:TS",
    "field:lines:vty:5:15",
    "field:lines:console:0",
    "field:class_maps:VOICE",
    "field:policy_maps:EDGE",
]


def _native_removals(pc):
    return [
        op
        for op in (pc.native_change_ops or [])
        if op.origin == "native"
        and op.verb in (Verb.LIST_REMOVE, Verb.OBJECT_DELETE)
    ]


class TestEmission:
    def test_all_tombstones_byte_exact(self):
        pc = IOSParser(ALL_SPELLINGS_CFG).parse()
        assert sorted(pc.no_commands) == sorted(EXPECTED_TOMBSTONES)

    def test_native_op_per_tombstone_path_verb_line(self):
        pc = IOSParser(ALL_SPELLINGS_CFG).parse()
        removals = _native_removals(pc)
        by_path = {":".join(op.path): op for op in removals}
        assert sorted(by_path) == sorted(EXPECTED_TOMBSTONES)
        # Verbs come from the codec registry.
        assert by_path["process:rip:"].verb is Verb.OBJECT_DELETE
        assert by_path["route-map:RM-OUT"].verb is Verb.OBJECT_DELETE
        assert by_path["prefix-list:PL-OUT"].verb is Verb.OBJECT_DELETE
        assert by_path["field:community_lists:CL1"].verb is Verb.OBJECT_DELETE
        assert by_path["field:as_path_lists:10"].verb is Verb.OBJECT_DELETE
        assert by_path["field:lines:vty:5:15"].verb is Verb.OBJECT_DELETE
        assert by_path["field:class_maps:VOICE"].verb is Verb.OBJECT_DELETE
        assert by_path["field:policy_maps:EDGE"].verb is Verb.OBJECT_DELETE
        for t in EXPECTED_TOMBSTONES:
            if t.startswith(("field:nat:", "field:crypto:")):
                assert by_path[t].verb is Verb.LIST_REMOVE, t
        # True line numbers + source lines.
        for op in removals:
            assert op.line_no >= 0, op.path
            assert op.source_line.startswith("no "), op.path

    def test_composed_changeset_dedupes_derived_twins(self):
        pc = IOSParser(ALL_SPELLINGS_CFG).parse()
        ops = derive_ops(pc)
        for t in EXPECTED_TOMBSTONES:
            matching = [op for op in ops if ":".join(op.path) == t]
            assert len(matching) == 1, t
            assert matching[0].origin == "native", t

    def test_unrecognized_double_count_disclosure_preserved(self):
        # The V.6 posture (``no vlan`` / dhcp-pool precedent): the batch
        # spellings remain flagged unrecognized — disclosed AND applied.
        pc = IOSParser(ALL_SPELLINGS_CFG).parse()
        ops = derive_ops(pc)
        n_unrec = sum(1 for op in ops if op.verb is Verb.UNRECOGNIZED)
        assert n_unrec == len(ALL_SPELLINGS_CFG.strip().splitlines())

    def test_encode_legacy_roundtrip_multiset(self):
        pc = IOSParser(ALL_SPELLINGS_CFG).parse()
        art = encode_legacy(derive_ops(pc))
        assert sorted(art.no_commands) == sorted(pc.no_commands)

    def test_line_type_normalization(self):
        pc = IOSParser("no line console 0\nno line aux 0\nno line tty 4\n").parse()
        assert sorted(pc.no_commands) == [
            "field:lines:aux:0",
            "field:lines:console:0",
            "field:lines:tty:4",
        ]


class TestOverTriggerNegatives:
    """Partial / attr / seq / bare forms must NOT fire whole-object deletes
    (the B1-validator attack class) — enumerated in Appendix AB.3."""

    def _artifacts(self, text):
        pc = IOSParser(text).parse()
        return list(pc.no_commands), _native_removals(pc)

    def test_route_map_seq_form_stays_seq_only(self):
        tombs, removals = self._artifacts("no route-map RM-OUT permit 10\n")
        assert tombs == ["route-map:RM-OUT:seq:10"]
        assert [op.verb for op in removals] == [Verb.LIST_REMOVE]

    def test_route_map_action_scoped_stays_blind(self):
        tombs, removals = self._artifacts("no route-map RM-OUT permit\n")
        assert tombs == [] and removals == []

    def test_prefix_list_seq_and_attr_forms(self):
        tombs, _ = self._artifacts(
            "no ip prefix-list PL-OUT seq 5 permit 10.99.0.0/16\n"
        )
        assert tombs == ["prefix-list:PL-OUT:seq:5"]
        tombs, removals = self._artifacts(
            "no ip prefix-list PL-OUT description foo\n"
            "no ip prefix-list PL-OUT permit 10.0.0.0/8\n"
        )
        assert tombs == [] and removals == []

    def test_crypto_attr_forms_stay_blind(self):
        tombs, removals = self._artifacts(
            "no crypto map VPN 10 set peer 1.2.3.4\n"
            "no crypto isakmp key secret address 1.2.3.4\n"
            "no crypto isakmp enable\n"
        )
        assert tombs == [] and removals == []

    def test_nat_bare_and_scalar_forms_stay_blind(self):
        tombs, removals = self._artifacts(
            "no ip nat inside\n"
            "no ip nat inside source list NATACL\n"
            "no ip nat translation timeout 999\n"
            "no ip nat inside source static network 10.1.0.0 203.0.113.0 /24\n"
        )
        assert tombs == [] and removals == []

    def test_class_map_bare_and_typed_forms_stay_blind(self):
        tombs, removals = self._artifacts(
            "no class-map match-any\n"
            "no class-map match-all\n"
            "no class-map type inspect CM1\n"
        )
        assert tombs == [] and removals == []

    def test_policy_map_class_form_stays_blind(self):
        tombs, removals = self._artifacts("no policy-map EDGE class VOICE\n")
        assert tombs == [] and removals == []

    def test_policy_list_entry_forms_stay_blind(self):
        tombs, removals = self._artifacts(
            "no ip community-list standard CL1 permit 65000:100\n"
            "no ip as-path access-list 10 permit ^65000_\n"
        )
        assert tombs == [] and removals == []

    def test_community_list_nameless_forms_stay_blind(self):
        # Validator C2 remediation (Appendix AB.3): keyword-only and
        # keyword+action lines are DEVICE-REJECTED ("% Incomplete command");
        # without the guard the optional keyword group backtracks and binds
        # the keyword / action word as the list NAME (silent wrong deletion).
        tombs, removals = self._artifacts(
            "no ip community-list standard\n"
            "no ip community-list expanded\n"
            "no ip community-list standard permit\n"
            "no ip community-list expanded deny\n"
        )
        assert tombs == [] and removals == []

    def test_community_list_grammar_token_names_undeletable_disclosed(self):
        # The disclosed guard trade-off: a list literally named
        # ``permit``/``deny``/``standard``/``expanded`` is undeletable by
        # negation (left blind — never wrongly deleted).
        tombs, removals = self._artifacts(
            "no ip community-list permit\nno ip community-list deny\n"
        )
        assert tombs == [] and removals == []

    def test_community_list_keyword_plus_name_still_fires(self):
        tombs, _ = self._artifacts("no ip community-list expanded CL-EXP\n")
        assert tombs == ["field:community_lists:CL-EXP"]

    def test_as_path_nameless_and_action_forms_stay_blind(self):
        # Same guard class: the nameless form never matches (needs a token);
        # action-in-name-position forms are rejected by the guard.  Real IOS
        # as-path names are numeric, so only action words can arrive via
        # incomplete CLI.
        tombs, removals = self._artifacts(
            "no ip as-path access-list \n"
            "no ip as-path access-list permit\n"
            "no ip as-path access-list deny\n"
        )
        assert tombs == [] and removals == []

    def test_rip_tagged_and_line_bare_forms_stay_blind(self):
        tombs, removals = self._artifacts(
            "no router rip Enterprise\nno line vty\n"
        )
        assert tombs == [] and removals == []


class TestAbsenceAndPositives:
    def test_positive_forms_emit_no_removal_artifacts(self):
        pc = IOSParser(
            "hostname r1\n"
            "router rip\n version 2\n network 10.0.12.0\n"
            "ip nat pool P0 203.0.113.1 203.0.113.10 netmask 255.255.255.0\n"
            "ip nat inside source list NATACL pool P0 overload\n"
            "crypto isakmp policy 10\n encryption aes\n"
            "crypto map VPN 10 ipsec-isakmp\n set peer 198.51.100.9\n"
            "route-map RM-OUT permit 10\n set metric 100\n"
            "ip prefix-list PL-OUT seq 5 permit 10.99.0.0/16\n"
            "ip community-list standard CL1 permit 65000:100\n"
            "ip as-path access-list 10 permit ^65000_\n"
            "line vty 0 4\n transport input ssh\n"
            "class-map match-any VOICE\n match dscp ef\n"
            "policy-map EDGE\n class VOICE\n  priority percent 30\n"
        ).parse()
        assert pc.no_commands == []
        assert _native_removals(pc) == []

    def test_interface_child_crypto_map_not_matched(self):
        # Interface-scoped ``no crypto map`` is indented — the column-0
        # walk must not see it (interface children ride other registries).
        pc = IOSParser(
            "interface GigabitEthernet0/0\n no crypto map VPN\n"
        ).parse()
        assert "field:crypto:crypto_map:VPN" not in pc.no_commands


class TestPerOSReachability:
    NEG_ONLY = "no router rip\nno class-map VOICE\nno crypto map VPN\n"

    def test_nxos_inherits_walk(self):
        pc = NXOSParser(self.NEG_ONLY).parse()
        assert "process:rip:" in pc.no_commands
        assert "field:class_maps:VOICE" in pc.no_commands
        assert "field:crypto:crypto_map:VPN" in pc.no_commands

    def test_eos_inherits_walk(self):
        pc = EOSParser(self.NEG_ONLY).parse()
        assert "process:rip:" in pc.no_commands
        assert "field:class_maps:VOICE" in pc.no_commands

    def test_iosxr_emits_no_batch_shapes(self):
        # IOS-XR overrides parse_deletion_commands without super() — the
        # batch stays Phase-5 on XR (exact parity by absence).
        pc = IOSXRParser(ALL_SPELLINGS_CFG).parse()
        for t in (
            "process:rip:",
            "field:nat:pool:P0",
            "field:crypto:crypto_map:VPN",
            "field:class_maps:VOICE",
            "field:lines:vty:5:15",
            "field:community_lists:CL1",
        ):
            assert t not in pc.no_commands, t
        assert _native_removals(pc) == []
