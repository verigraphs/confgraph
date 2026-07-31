"""CCR-0147 — extended-community list (``ip extcommunity-list``) parsing.

Covers the WI-C3 scope: the new ``ExtCommunityListConfig`` model, IOS + NX-OS
parsing (per-OS identifier rules, seq/no-seq forms, standard values vs expanded
regex), the ``no ip extcommunity-list`` whole-object delete tombstone, and the
confgraph-side Change-IR registry wiring.

Evidence: syntax-corpus cisco-ios/routing-policy.yaml and nxos/routing-policy.yaml
(both doc-only; the named 2026-07-30 capture does not exist and no capture contains
any ``extcommunity`` line — seq injection on NX-OS is doc+analogy from the
capture-verified community-list sibling). Parses both forms per the CCR-0064 lesson.
"""

from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.nxos_parser import NXOSParser
from confgraph.models.community_list import (
    ExtCommunityListConfig,
    ExtCommunityListEntry,
)
from confgraph.change_ir import Verb, _verb_for_top_tombstone


def _by_name(pc):
    return {e.name: e for e in pc.extcommunity_lists}


# --------------------------------------------------------------------------
# IOS — identifier rules (numbered-or-named) + values vs regex
# --------------------------------------------------------------------------

class TestIOSParse:
    def test_named_standard_rt_and_soo(self):
        pc = IOSParser(
            "ip extcommunity-list standard NAMED_LIST permit rt 65505:50\n"
        ).parse()
        ecl = _by_name(pc)["NAMED_LIST"]
        assert ecl.list_type == "standard"
        assert len(ecl.entries) == 1
        assert ecl.entries[0].action == "permit"
        assert ecl.entries[0].values == ["rt 65505:50"]
        assert ecl.entries[0].regex is None

    def test_multiple_values_one_statement_are_logical_and(self):
        # Doc: "ip extcommunity-list 2 deny rt 65424:30 soo 64524:40" — rt and
        # soo on ONE statement (logical AND). Both preserved, typed.
        pc = IOSParser(
            "ip extcommunity-list 2 deny rt 65424:30 soo 64524:40\n"
        ).parse()
        ecl = _by_name(pc)["2"]
        assert ecl.list_type == "standard"  # numbered 2 => 1-99 standard
        assert ecl.entries[0].values == ["rt 65424:30", "soo 64524:40"]

    def test_legacy_numbered_standard_and_expanded_type_inferred(self):
        # No standard|expanded keyword: the number range implies the type
        # (1-99 standard, 100-500 expanded).
        pc = IOSParser(
            "ip extcommunity-list 1 permit rt 64512:10\n"
            "ip extcommunity-list 500 deny _65412_\n"
        ).parse()
        byname = _by_name(pc)
        assert byname["1"].list_type == "standard"
        assert byname["1"].entries[0].values == ["rt 64512:10"]
        assert byname["500"].list_type == "expanded"
        assert byname["500"].entries[0].regex == "_65412_"
        assert byname["500"].entries[0].values == []

    def test_named_expanded_is_regex_not_values(self):
        pc = IOSParser(
            "ip extcommunity-list expanded EXP_LIST permit 65412:[0-9][0-9]_\n"
        ).parse()
        ecl = _by_name(pc)["EXP_LIST"]
        assert ecl.list_type == "expanded"
        assert ecl.entries[0].regex == "65412:[0-9][0-9]_"
        assert ecl.entries[0].values == []

    def test_multiple_entries_accrete_under_one_list(self):
        pc = IOSParser(
            "ip extcommunity-list standard L permit rt 65001:1\n"
            "ip extcommunity-list standard L deny soo 65001:2\n"
        ).parse()
        ecl = _by_name(pc)["L"]
        assert [e.action for e in ecl.entries] == ["permit", "deny"]
        assert ecl.entries[0].values == ["rt 65001:1"]
        assert ecl.entries[1].values == ["soo 65001:2"]

    def test_positive_lines_not_unrecognized(self):
        pc = IOSParser(
            "ip extcommunity-list standard L permit rt 65001:1\n"
            "ip extcommunity-list 1 permit soo 65001:2\n"
        ).parse()
        positive = [
            b.block_header
            for b in pc.unrecognized_blocks
            if not b.block_header.startswith("no ")
        ]
        assert positive == []


# --------------------------------------------------------------------------
# NX-OS — named-only, seq/no-seq (CCR-0064), 4byteas-generic + rmac
# --------------------------------------------------------------------------

class TestNXOSParse:
    def test_seq_and_noseq_both_parse(self):
        # The device injects ``seq <N>`` on readback; the typed form has none.
        # Both must land in the same list (the CCR-0064 lesson).
        pc = NXOSParser(
            "ip extcommunity-list standard EVPN_RT seq 5 permit rt 65001:10010\n"
            "ip extcommunity-list standard EVPN_RT permit soo 65000:7\n"
        ).parse()
        ecl = _by_name(pc)["EVPN_RT"]
        assert ecl.list_type == "standard"
        assert ecl.entries[0].values == ["rt 65001:10010"]
        assert ecl.entries[1].values == ["soo 65000:7"]

    def test_4byteas_generic_and_rmac_multivalue(self):
        pc = NXOSParser(
            "ip extcommunity-list standard M seq 10 permit "
            "4byteas-generic transitive 65001:100 rmac 00aa.bbcc.ddee\n"
        ).parse()
        ecl = _by_name(pc)["M"]
        assert ecl.entries[0].values == [
            "4byteas-generic transitive 65001:100",
            "rmac 00aa.bbcc.ddee",
        ]

    def test_4byteas_generic_non_transitive(self):
        pc = NXOSParser(
            "ip extcommunity-list standard M permit "
            "4byteas-generic non-transitive 65001:100\n"
        ).parse()
        assert _by_name(pc)["M"].entries[0].values == [
            "4byteas-generic non-transitive 65001:100"
        ]

    def test_expanded_regex_with_seq(self):
        pc = NXOSParser(
            "ip extcommunity-list expanded EXP_N seq 5 deny _65000_\n"
        ).parse()
        ecl = _by_name(pc)["EXP_N"]
        assert ecl.list_type == "expanded"
        assert ecl.entries[0].regex == "_65000_"

    def test_positive_lines_not_unrecognized(self):
        pc = NXOSParser(
            "ip extcommunity-list standard EVPN_RT seq 5 permit rt 65001:10010\n"
        ).parse()
        positive = [
            b.block_header
            for b in pc.unrecognized_blocks
            if not b.block_header.startswith("no ")
        ]
        assert positive == []


# --------------------------------------------------------------------------
# Tombstones — no ip extcommunity-list ...  (native keyed OBJECT_DELETE)
# --------------------------------------------------------------------------

def _native_removals(pc):
    return [
        op
        for op in (pc.native_change_ops or [])
        if op.origin == "native"
        and op.verb in (Verb.LIST_REMOVE, Verb.OBJECT_DELETE)
    ]


class TestDeletionTombstones:
    def test_whole_object_delete_named_and_numbered(self):
        pc = IOSParser(
            "no ip extcommunity-list standard OLD_LIST\n"
            "no ip extcommunity-list expanded OLD_EXP\n"
            "no ip extcommunity-list 1\n"
        ).parse()
        by_path = {":".join(op.path): op for op in _native_removals(pc)}
        assert "field:extcommunity_lists:OLD_LIST" in by_path
        assert "field:extcommunity_lists:OLD_EXP" in by_path
        assert "field:extcommunity_lists:1" in by_path
        for k in (
            "field:extcommunity_lists:OLD_LIST",
            "field:extcommunity_lists:OLD_EXP",
            "field:extcommunity_lists:1",
        ):
            assert by_path[k].verb is Verb.OBJECT_DELETE
            assert by_path[k].source_line.startswith("no ")
            assert by_path[k].line_no >= 0

    def test_nxos_inherits_delete_walk(self):
        pc = NXOSParser("no ip extcommunity-list standard EVPN_RT\n").parse()
        paths = {":".join(op.path) for op in _native_removals(pc)}
        assert "field:extcommunity_lists:EVPN_RT" in paths

    def test_incomplete_cli_does_not_delete_baseline(self):
        # Keyword-in-name-position guard (§6.2): device-rejected incomplete
        # lines must NOT bind the keyword/action word as a list name.
        pc = IOSParser(
            "no ip extcommunity-list standard\n"
            "no ip extcommunity-list standard permit\n"
            "no ip extcommunity-list expanded deny\n"
        ).parse()
        bad = {
            ":".join(op.path)
            for op in _native_removals(pc)
            if op.path[:2] == ("field", "extcommunity_lists")
        }
        assert bad == set()


# --------------------------------------------------------------------------
# Registry wiring (confgraph side)
# --------------------------------------------------------------------------

class TestRegistryWiring:
    def test_verb_map_object_delete(self):
        assert (
            _verb_for_top_tombstone("field:extcommunity_lists:FOO")
            is Verb.OBJECT_DELETE
        )

    def test_accessor_lookup(self):
        pc = IOSParser(
            "ip extcommunity-list standard FOO permit rt 65001:1\n"
        ).parse()
        assert pc.get_extcommunity_list_by_name("FOO") is not None
        assert pc.get_extcommunity_list_by_name("MISSING") is None

    def test_model_defaults_are_tristate_clean(self):
        # An absent list == the model default (empty list); a standard entry's
        # regex defaults None, an expanded entry's values default empty.
        assert ExtCommunityListConfig.model_fields["entries"].default_factory() == []
        e = ExtCommunityListEntry(action="permit")
        assert e.values == []
        assert e.regex is None
