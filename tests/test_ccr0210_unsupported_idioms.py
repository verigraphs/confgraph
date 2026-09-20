"""CCR-0210 — unsupported proposal idioms are disclosed or refused, never ignored.

Two silent failures from user-test F-20.

JunOS: the ``set``-idiom walk kept only lines starting ``set``, so ``delete`` /
``deactivate`` vanished without a trace — and a proposal made ONLY of those
lines never even reached that walk, because ``_is_set_style`` counted ``set``
alone and routed it to the brace tokenizer, which drops the whole document.
``deactivate protocols bgp group X`` therefore left the group ACTIVE in the
merged model: a semantic inversion, not a gap.  The brace idiom's ``inactive:``
/ ``replace:`` statement tags had no handling anywhere.  All of them now ride
the existing ``UnrecognizedBlock`` → UNRECOGNIZED-coverage → verdict-downgrade
channel, which the disclosure being disabled for JunOS alone had kept dark.

PAN-OS: set-CLI text reached ElementTree unguarded and came back blaming
``'hostname' at line 0``; the requirement — a full ``<config>`` XML document —
is now stated at the first touch of the text.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from confgraph.parsers.base import ParseError
from confgraph.parsers.junos_hierarchy import (
    BRACE_STATEMENT_TAGS,
    NON_SET_VERBS,
    _is_set_style,
    parse_junos_config,
)
from confgraph.parsers.junos_parser import JunOSParser
from confgraph.parsers.panos_parser import PANOSParser
from confgraph.parsers.panos_xml import PANOS_DOCUMENT_REQUIREMENT

# The same configuration in both renderings — the canonical-tree invariant the
# regression test below leans on.
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


class TestSetIdiomVerbFamily:
    @pytest.mark.parametrize("verb", sorted(NON_SET_VERBS))
    def test_every_verb_in_the_family_is_disclosed(self, verb):
        """Parity: the family is one frozenset, so the next verb added to it is
        covered here by construction — no new test, no new branch."""
        line = f"{verb} protocols bgp group EXT neighbor 10.0.0.1"
        assert _disclosed(SET_BASELINE + line + "\n") == [line]

    def test_a_verb_outside_the_family_is_still_disclosed(self):
        """The disclosure is a catch-all, not a blocklist: the frozenset only
        decides ROUTING, so an unheard-of verb is disclosed fail-closed."""
        line = "wharrgarbl protocols bgp group EXT"
        assert _disclosed(SET_BASELINE + line + "\n") == [line]

    def test_delete_only_proposal_routes_set_style_and_discloses(self):
        """The routing hole: with set_count==0 this document used to go to the
        brace tokenizer, which discarded every statement (no terminator) and
        returned an empty tree — silence by a second path."""
        delete_only = (
            "delete protocols bgp group EXT neighbor 10.0.0.1\n"
            "delete protocols bgp group EXT\n"
        )
        assert _is_set_style(delete_only) is True
        assert _disclosed(delete_only) == [
            "delete protocols bgp group EXT neighbor 10.0.0.1",
            "delete protocols bgp group EXT",
        ]

    def test_disclosure_is_additive_to_the_set_lines_around_it(self):
        cfg = SET_BASELINE + (
            "deactivate protocols bgp group EXT\n"
            "delete protocols bgp group EXT neighbor 10.0.0.1\n"
        )
        pc = JunOSParser(cfg).parse()
        assert [b.block_header for b in pc.unrecognized_blocks] == [
            "deactivate protocols bgp group EXT",
            "delete protocols bgp group EXT neighbor 10.0.0.1",
        ]
        assert pc.bgp_instances[0].asn == 65000
        assert [str(n.peer_ip) for n in pc.bgp_instances[0].neighbors] == ["10.0.0.1"]


class TestBraceIdiomStatementTags:
    @pytest.mark.parametrize("tag", sorted(BRACE_STATEMENT_TAGS))
    def test_every_statement_tag_is_disclosed(self, tag):
        cfg = BRACE_BASELINE.replace(
            "        group EXT {", f"        {tag} group EXT {{"
        )
        assert _disclosed(cfg) == [f"{tag} group EXT {{"]


class TestNotDisclosed:
    def test_comments_and_blank_lines_in_a_set_document(self):
        cfg = (
            "\n"
            "## Last commit: 2026-09-20 by admin\n"
            "# a shell-style comment\n"
            + SET_BASELINE
            + "set system host-name r1 ## SECRET-DATA\n"
            "\n"
        )
        pc = JunOSParser(cfg).parse()
        assert pc.unrecognized_blocks == []
        assert pc.hostname == "r1"

    def test_a_tag_word_inside_a_brace_comment(self):
        """The tags are matched on statements, not on text: a comment that
        happens to spell one is prose."""
        cfg = (
            "/* inactive: this is prose,\n"
            "   replace: and so is this */\n"
            "# inactive: protocols {\n" + BRACE_BASELINE
        )
        assert _disclosed(cfg) == []


class TestRegression:
    def test_untagged_corpora_disclose_nothing_and_the_two_idioms_agree(self):
        assert _disclosed(SET_BASELINE) == []
        assert _disclosed(BRACE_BASELINE) == []
        assert parse_junos_config(SET_BASELINE) == parse_junos_config(BRACE_BASELINE)

    def test_the_shipped_junos_sample_is_untouched(self):
        cfg = (Path(__file__).parent.parent / "samples" / "junos_test.cfg").read_text()
        assert JunOSParser(cfg).parse().unrecognized_blocks == []


VALID_PANOS = """\
<config>
  <devices><entry name="localhost.localdomain">
    <deviceconfig><system><hostname>fw1</hostname></system></deviceconfig>
    <vsys><entry name="vsys1"/></vsys>
  </entry></devices>
</config>
"""


class TestPANOSDocumentRequirement:
    def test_set_cli_text_names_the_requirement(self):
        with pytest.raises(ParseError) as exc:
            PANOSParser("set rulebase security rules R1 action allow\n").parse()
        assert exc.value.protocol == "panos-document"
        assert PANOS_DOCUMENT_REQUIREMENT in str(exc.value)

    def test_malformed_xml_gets_a_sane_message_not_a_hostname_at_line_0(self):
        with pytest.raises(ParseError) as exc:
            PANOSParser("<config><devices></config>\n").parse()
        message = str(exc.value)
        assert "not well-formed XML" in message
        assert "'hostname' at line 0" not in message

    def test_a_valid_document_is_unchanged(self):
        assert PANOSParser(VALID_PANOS).parse().hostname == "fw1"

    def test_wrong_root_still_reports_the_layout_error(self):
        """The UnrecognizedPANOSLayout path (CCR-0034) is untouched: it is a
        different mistake and keeps its own, already-good message."""
        with pytest.raises(ParseError) as exc:
            PANOSParser("<not-config/>\n").parse()
        assert exc.value.protocol == "layout"
        assert "expected a PAN-OS <config> document root" in str(exc.value)
