"""CCR-0217 — a brace-routed document that states nothing is disclosed, not silent.

The last silent arm of CCR-0210's fail-closed story.  A proposal written in a
foreign idiom — Cisco ``no`` commands, an IOS ``interface`` block, anything an
operator working a mixed fleet might paste at a JunOS device — contains zero
``set``-family lines, so ``_is_set_style`` routes it to the BRACE tokenizer.
That tokenizer discards every statement that never reaches a ``;`` or a ``{``,
so the whole document evaporates: empty tree, zero disclosures, and the
CCR-0213 "no recognized configuration change" outcome for text that plainly
requested one.

The fix is stated on the OUTCOME rather than on a list of foreign keywords:
content in, nothing out, disclose the content.  That is what makes it a class
fix — the next foreign idiom is caught with no new code, which
``TestTheClassIsOutcomeNotKeyword`` is here to prove.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from confgraph.parsers.junos_hierarchy import (
    _is_set_style,
    parse_junos_config,
    unsupported_lines,
)
from confgraph.parsers.junos_parser import JunOSParser

# The same baselines CCR-0210's suite uses — legitimate JunOS in both
# renderings, so "discloses nothing new" is checked against real content.
SET_BASELINE = (
    "set routing-options autonomous-system 65000\n"
    "set protocols bgp group EXT type external\n"
    "set protocols bgp group EXT neighbor 10.0.0.1 peer-as 65001\n"
)

BRACE_BASELINE = """\
routing-options {
    autonomous-system 65000;
}
protocols {
    bgp {
        group EXT {
            type external;
            neighbor 10.0.0.1 {
                peer-as 65001;
            }
        }
    }
}
"""


def _disclosed(cfg: str) -> list[str]:
    return [b.block_header for b in JunOSParser(cfg).parse().unrecognized_blocks]


class TestForeignIdiomOnlyDocuments:
    def test_a_no_command_only_proposal_is_disclosed(self):
        """The CCR-0217 shape itself: one Cisco line, routed brace-ward,
        discarded at EOF — it is now named in the result."""
        cfg = "no router bgp 64512\n"
        assert _is_set_style(cfg) is False
        assert parse_junos_config(cfg) == {}
        assert _disclosed(cfg) == ["no router bgp 64512"]

    def test_every_foreign_line_is_disclosed_in_file_order(self):
        """One block per line, the CCR-0210 disclosure contract."""
        cfg = (
            "no router bgp 64512\n"
            "no interface GigabitEthernet0/1\n"
            "no ip route 10.0.0.0 255.0.0.0 192.0.2.1\n"
        )
        assert _disclosed(cfg) == [
            "no router bgp 64512",
            "no interface GigabitEthernet0/1",
            "no ip route 10.0.0.0 255.0.0.0 192.0.2.1",
        ]

    def test_the_disclosure_rides_the_shared_unrecognized_block_shape(self):
        """Not a bare line: the block is built by the same
        ``_collect_unrecognized_blocks`` as every other JunOS disclosure — one
        block per line, ``best_guess`` off the shared keyword table — so
        coverage and the verdict see it the way they see a ``delete``."""
        blocks = JunOSParser("no ntp server 10.0.0.1\n").parse().unrecognized_blocks
        assert len(blocks) == 1
        assert blocks[0].block_header == "no ntp server 10.0.0.1"
        assert blocks[0].raw_lines == ["no ntp server 10.0.0.1"]
        assert blocks[0].best_guess == "ntp"


class TestTheClassIsOutcomeNotKeyword:
    """The parity check.  None of these documents contains a ``no`` command or
    any JunOS verb — they are caught because nothing was represented, not
    because anything recognized them.  A new foreign idiom costs no code."""

    @pytest.mark.parametrize(
        "cfg,expected",
        [
            (
                "interface GigabitEthernet0/1\n description uplink\n",
                ["interface GigabitEthernet0/1", "description uplink"],
            ),
            (
                "router ospf 1\n network 10.0.0.0 0.0.0.255 area 0\n",
                ["router ospf 1", "network 10.0.0.0 0.0.0.255 area 0"],
            ),
            (
                "interface Ethernet1/1\n switchport mode trunk\n",
                ["interface Ethernet1/1", "switchport mode trunk"],
            ),
            ("wharrgarbl\n", ["wharrgarbl"]),
        ],
        ids=["ios-interface", "ios-ospf", "nxos-interface", "nonsense"],
    )
    def test_any_idiom_that_states_nothing_is_disclosed(self, cfg, expected):
        assert parse_junos_config(cfg) == {}
        assert _disclosed(cfg) == expected


class TestTheNoOpOutcomeSurvives:
    """The fix must not over-trigger: a document with no CONTENT is a genuine
    no-op proposal and has to stay silent, or CCR-0213's outcome becomes a lie
    in the other direction."""

    @pytest.mark.parametrize(
        "cfg",
        ["", "\n\n", "   \n\t\n", "# a shell comment\n", "/* a block comment */\n",
         "/* spanning\n   two lines */\n#  and one more\n"],
        ids=["empty", "blank", "whitespace", "hash", "block", "mixed-comments"],
    )
    def test_a_document_with_no_content_discloses_nothing(self, cfg):
        assert unsupported_lines(cfg) == []
        assert _disclosed(cfg) == []


class TestLegitimateCorporaAreUntouched:
    def test_both_renderings_of_a_real_config_disclose_nothing(self):
        assert _disclosed(SET_BASELINE) == []
        assert _disclosed(BRACE_BASELINE) == []

    def test_the_shipped_junos_sample_is_untouched(self):
        cfg = (Path(__file__).parent.parent / "samples" / "junos_test.cfg").read_text()
        assert JunOSParser(cfg).parse().unrecognized_blocks == []

    def test_an_inactive_only_document_keeps_its_tag_disclosure(self):
        """``inactive:`` parses to a NON-empty tree, so the new branch never
        sees it and the CCR-0210 tag disclosure is what fires — once."""
        cfg = "inactive: protocols {\n    bgp {\n    }\n}\n"
        assert parse_junos_config(cfg) != {}
        assert _disclosed(cfg) == ["inactive: protocols {"]

    def test_a_delete_only_document_still_routes_set_style(self):
        """Routing is still the single ``_is_set_style`` decision: the
        verb-family document never reaches the brace branch at all.

        [[CCR-0214]] moved the MODELLED half of that document off the
        disclosure channel and onto the op channel, so the disclosure arm is
        pinned here on a path the deletion registry does not carry.  Both arms
        are asserted, because what this test is really about is that neither
        document reached the brace tokenizer — and a document that did would
        produce no ops AND no disclosure, which is exactly the shape the two
        assertions together rule out."""
        modelled = "delete protocols bgp group EXT neighbor 10.0.0.1\n"
        assert _is_set_style(modelled) is True
        assert [op.path for op in JunOSParser(modelled).parse().native_change_ops] == [
            ("bgp_instance", "", "", "neighbor", "10.0.0.1")
        ]
        assert _disclosed(modelled) == []

        unmodelled = "delete policy-options policy-statement EXPORT-ALL\n"
        assert _is_set_style(unmodelled) is True
        assert _disclosed(unmodelled) == [unmodelled.strip()]

    def test_a_stray_foreign_line_inside_a_set_document_is_unchanged(self):
        """The set idiom's own catch-all still owns that case."""
        cfg = SET_BASELINE + "no router bgp 64512\n"
        assert _is_set_style(cfg) is True
        assert _disclosed(cfg) == ["no router bgp 64512"]


class TestCCR0236Residual:
    """CHARACTERIZATION — pins a hole that is still OPEN, so it cannot be lost.

    A document that MIXES a foreign line with a legitimate brace block parses
    to a non-empty GARBAGE tree: the foreign line's tokens run on into the
    block, which becomes its body.  The tree is not empty, so CCR-0217's
    outcome test does not fire, and the legitimate half is swallowed with zero
    disclosure.  That is CCR-0236, deliberately NOT fixed here.

    These assertions are written to FAIL when CCR-0236 lands — that is their
    job.  When it does, flip them to assert the disclosure and the correctly
    parsed ``system`` stanza, and delete this class's docstring caveat.
    """

    MIXED = "no router bgp 64512\nsystem {\n    host-name r1;\n}\n"

    def test_the_mixed_document_still_parses_to_a_garbage_tree(self):
        tree = parse_junos_config(self.MIXED)
        assert tree != {}, "CCR-0236 fixed? see this class's docstring"
        assert tree == {
            "no": {"router": {"bgp": {"64512": {"system": {"host-name": {"r1": {}}}}}}}
        }

    def test_the_mixed_document_still_discloses_nothing(self):
        assert _disclosed(self.MIXED) == []

    def test_the_legitimate_half_is_still_lost(self):
        assert JunOSParser(self.MIXED).parse().hostname is None
