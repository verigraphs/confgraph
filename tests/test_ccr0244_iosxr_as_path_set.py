"""CCR-0244 — IOS-XR ``as-path-set`` members are unwrapped, and ``as-path in`` converts.

The defect had two halves and either one alone lands a no-op:

1. the parser stored the whole RPL wrapper as the entry's pattern, so
   ``ios-regex '_64702_'`` reached the matcher as a literal string. It COMPILES — so
   the engine's compile guard never fired and nothing was disclosed — and it matches
   nothing, because no AS path contains the text ``ios-regex``;
2. ``RPL_CONDITIONS`` had no ``as-path in`` row, so the set was referenced by no
   sequence at all and no filter's verdict could change however the set was stored.

So the unwrap and the row ship together. The engine-side half of the verdict (both
polarities, through ``apply_policy``) lives in confgraph-entrp's
``test_ccr0244_xr_as_path_evaluation.py``; what is pinned here is the parse output.

RPL member-form semantics are documentation-derived (the BATCH-A2 evidence standard):
``syntax-corpus/iosxr/routing-policy.yaml`` covers ``community-set`` /
``extcommunity-set`` and has NO entry for ``as-path-set`` or for the ``as-path in``
condition. That gap is recorded in the work report. The member shapes used below are
the ones the corpus file's own cited grammar establishes — a single-quoted regex token,
a comma separator after every member but the last, ``end-set`` at column 0 — plus the
two as-path-sets that already exist in the committed corpora.
"""

from __future__ import annotations

import pytest

from confgraph.models.community_list import ASPathListConfig
from confgraph.parsers import PARSER_BEHAVIOR_VERSION
from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.iosxr_parser import (
    RPL_CONDITIONS,
    IOSXRParser,
    _RPL_AS_PATH_MEMBERS,
)


def _set(cfg: str, name: str) -> ASPathListConfig:
    parsed = IOSXRParser(cfg).parse()
    apl = next((a for a in parsed.as_path_lists if a.name == name), None)
    assert apl is not None, f"as-path-set {name} did not parse"
    return apl


def _policy(cfg: str, name: str):
    rm = IOSXRParser(cfg).parse().get_route_map_by_name(name)
    assert rm is not None, f"route-policy {name} did not parse"
    return rm


def _as_path_clauses(rm) -> list[list[str]]:
    """The values of every ``as-path`` match clause in the policy, in order."""
    return [
        list(mc.values)
        for s in sorted(rm.sequences, key=lambda s: s.sequence)
        for mc in s.match_clauses
        if mc.match_type == "as-path"
    ]


# ---------------------------------------------------------------------------
# The unwrap
# ---------------------------------------------------------------------------

_BOGON = """\
as-path-set BOGON-ASNS
  ios-regex '_64702_'
end-set
!
"""


def test_the_wrapper_is_not_the_pattern():
    """The keyword and the quotes are RPL syntax; only the pattern is the pattern."""
    apl = _set(_BOGON, "BOGON-ASNS")
    assert [e.regex for e in apl.entries] == ["_64702_"]
    assert apl.untranslated_constructs == []


def test_the_stored_pattern_carries_no_trace_of_the_wrapper():
    """The control the old behaviour fails: the defect was that this SURVIVED.

    Asserted as absence of the wrapper rather than only as equality above, because
    the failure mode was a pattern that compiled and matched nothing — a shape that
    an equality assertion on a different spelling could still have let through.
    """
    (entry,) = _set(_BOGON, "BOGON-ASNS").entries
    assert "ios-regex" not in entry.regex
    assert "'" not in entry.regex


def test_a_member_keeps_action_permit_because_the_quantifier_lives_at_the_use_site():
    """An RPL set is a list of ALTERNATIVES; permit/deny is the policy's word, not the
    set's. ``as-path in SET`` is matches-any, which is what one permit entry per member
    plus the matcher's implicit deny already means."""
    assert [e.action for e in _set(_BOGON, "BOGON-ASNS").entries] == ["permit"]


_MULTI = """\
as-path-set TRANSIT-ASNS
  ios-regex '_64500_',
  ios-regex '_64501_',
  ios-regex '^65001_65002$'
end-set
!
"""


def test_every_member_of_a_multi_member_set_is_unwrapped_in_order():
    """One entry per member, order preserved, the separating comma consumed."""
    apl = _set(_MULTI, "TRANSIT-ASNS")
    assert [e.regex for e in apl.entries] == ["_64500_", "_64501_", "^65001_65002$"]
    assert apl.untranslated_constructs == []


def test_several_members_on_ONE_emitted_line_read_the_same_as_one_per_line():
    """The emitted layout is NOT established, so neither reading may be assumed.

    The config guide says one or more newlines *can* follow a comma separator in a
    named AS-path set, and the syntax corpus records that the only sanctioned fetcher
    collapses newlines — so no readable source says whether a device prints one member
    per line. Honouring the quotes is correct under both layouts.

    This is not a hypothetical: with a greedy pattern body the one-line layout stored
    ``_64500_', ios-regex '_64501_`` as a single pattern — a non-pattern that compiles,
    matches nothing and discloses nothing, which is this CCR's own defect arriving
    through the operand class.
    """
    one_line = _set(
        "as-path-set S\n  ios-regex '_64500_', ios-regex '_64501_'\nend-set\n!\n", "S"
    )
    per_line = _set(
        "as-path-set S\n  ios-regex '_64500_',\n  ios-regex '_64501_'\nend-set\n!\n", "S"
    )
    assert [e.regex for e in one_line.entries] == ["_64500_", "_64501_"]
    assert [e.regex for e in per_line.entries] == ["_64500_", "_64501_"]
    assert one_line.untranslated_constructs == per_line.untranslated_constructs == []


def test_a_comma_inside_the_pattern_survives_the_member_split():
    """Why the split honours quotes instead of splitting on every comma.

    ``_64702,_`` is a legal AS-path pattern (the device's ``_`` matches a comma among
    other boundaries), so the community-set style blind comma split would corrupt it.
    Both members below are in one set so the split is doing real work.
    """
    apl = _set(
        "as-path-set S\n  ios-regex '_64702,_', ios-regex '_1_'\nend-set\n!\n", "S"
    )
    assert [e.regex for e in apl.entries] == ["_64702,_", "_1_"]
    assert apl.untranslated_constructs == []


def test_an_empty_set_parses_to_an_empty_set_and_claims_nothing():
    """The two Cisco docs disagree on whether an empty set is legal; the parser takes
    no side. What it must not do is invent an entry or disclose an absence."""
    apl = _set("as-path-set EMPTY\nend-set\n!\n", "EMPTY")
    assert apl.entries == []
    assert apl.untranslated_constructs == []


@pytest.mark.parametrize(
    "member,pattern",
    [
        # Regex metacharacters are the engine's business, not the parser's: whatever
        # is between the quotes is stored as written.
        ("ios-regex '_(64702|64703)_'", "_(64702|64703)_"),
        ("ios-regex '^65000$'", "^65000$"),
        ("ios-regex '.*'", ".*"),
        # A COMMA INSIDE THE QUOTES IS PART OF THE PATTERN. This is why as-path
        # members are read one per line and not comma-split like a community-set:
        # splitting would corrupt exactly this member.
        ("ios-regex '_64702,_'", "_64702,_"),
        # An empty pattern is a member the device accepts and this parser does not
        # second-guess; the engine decides what an empty regex matches.
        ("ios-regex ''", ""),
        # Extra whitespace after the keyword is layout, not content.
        ("ios-regex   '_64702_'", "_64702_"),
    ],
)
def test_the_pattern_body_is_stored_verbatim(member, pattern):
    apl = _set(f"as-path-set S\n  {member}\nend-set\n!\n", "S")
    assert [e.regex for e in apl.entries] == [pattern]


def test_the_parser_does_not_translate_the_dialect_it_unwraps():
    """The parser's job ENDS at unwrapping.

    ``_`` is a word-boundary metacharacter on the device and a literal underscore in
    Python. That rewrite belongs to the engine's matcher, which applies it to every OS
    writing this dialect (CCR-0003); a parser-side copy would give one pattern two
    owners and two places to fix. So the stored pattern still says ``_``.
    """
    (entry,) = _set(_BOGON, "BOGON-ASNS").entries
    assert entry.regex == "_64702_"
    assert "(?:" not in entry.regex and "\\s" not in entry.regex


# ---------------------------------------------------------------------------
# Disclosure — the forms this model cannot express as a pattern
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "member",
    [
        # a DIFFERENT regex dialect — storing it as a Cisco-dialect pattern would be
        # the same silent mistranslation one layer along
        "dfa-regex '_64702_'",
        # not patterns at all: an AS-path property and three path-position operators
        "length eq 5",
        "length ge 3",
        "unique-length le 4",
        "neighbor-is '65001'",
        "originates-from '65001'",
        "passes-through '65001'",
        # a form nobody has anticipated: the whitelist discloses it with no new code
        "some-future-operator '65001'",
        # near-misses on the one form that IS supported — an unquoted body and a
        # keyword-only line are not patterns, and must not be stored as one
        "ios-regex _64702_",
        "ios-regex",
    ],
)
def test_a_member_that_is_not_a_pattern_is_disclosed_and_stored_as_nothing(member):
    """A stored non-pattern is worse than a recorded absence.

    That is the whole lesson of this defect: the wrapper COMPILED, which is precisely
    what stopped anything from reporting it. So a member no row claims becomes no
    entry and is named in full.
    """
    apl = _set(f"as-path-set S\n  {member}\nend-set\n!\n", "S")
    assert apl.entries == []
    assert apl.untranslated_constructs == [member]


def test_an_unrepresentable_member_is_recorded_IN_FULL_not_by_verb():
    """For a member the OPERAND is the information.

    ``neighbor-is '65001'`` and ``neighbor-is '65002'`` differ in exactly the part a
    verb-only label would throw away, so the set-level channel follows the condition
    rule rather than the statement rule.
    """
    apl = _set(
        "as-path-set S\n  neighbor-is '65001',\n  neighbor-is '65002'\nend-set\n!\n", "S"
    )
    assert apl.untranslated_constructs == ["neighbor-is '65001'", "neighbor-is '65002'"]


def test_a_mixed_set_keeps_what_it_understands_and_discloses_the_rest():
    """Per-member, not per-set: one unrepresentable member does not discard the others.

    The three ``ios-regex`` members still match; the two others are named. Both halves
    asserted together, because an implementation that disclosed the set wholesale would
    satisfy either half alone.
    """
    apl = _set(
        "as-path-set MIXED\n"
        "  ios-regex '_64500_',\n"
        "  length eq 5,\n"
        "  ios-regex '_64501_',\n"
        "  neighbor-is '65001',\n"
        "  ios-regex '_64502_'\n"
        "end-set\n!\n",
        "MIXED",
    )
    assert [e.regex for e in apl.entries] == ["_64500_", "_64501_", "_64502_"]
    assert apl.untranslated_constructs == ["length eq 5", "neighbor-is '65001'"]
    assert not any("length" in e.regex or "neighbor" in e.regex for e in apl.entries)


def test_an_empty_lossy_list_is_a_positive_claim_about_every_corpus_set():
    """The two as-path-sets that exist in the committed corpora are all-``ios-regex``.

    Pinned so that a later corpus addition of a form this parser cannot express shows
    up as a failure here rather than as a quietly shorter entry list.
    """
    for cfg, name, patterns in [
        (_BOGON, "BOGON-ASNS", ["_64702_"]),
        (_MULTI, "TRANSIT-ASNS", ["_64500_", "_64501_", "^65001_65002$"]),
    ]:
        apl = _set(cfg, name)
        assert apl.untranslated_constructs == []
        assert [e.regex for e in apl.entries] == patterns


# ---------------------------------------------------------------------------
# The one new dispatch row
# ---------------------------------------------------------------------------

_EDGE_IN = """\
as-path-set BOGON-ASNS
  ios-regex '_64702_'
end-set
!
route-policy EDGE-IN
  if as-path in BOGON-ASNS then
    drop
  endif
  pass
end-policy
!
"""


def test_as_path_in_converts_to_the_match_type_the_engine_dispatches_on():
    """``match_type="as-path"`` is not a new vocabulary word.

    ``apply_policy`` already resolves an ``as-path`` clause's values against
    ``parsed.as_path_lists``, which is exactly where an ``as-path-set`` lands. The row
    therefore adds a condition, not a consumer.
    """
    rm = _policy(_EDGE_IN, "EDGE-IN")
    assert _as_path_clauses(rm) == [["BOGON-ASNS"]]
    assert rm.untranslated_constructs == []


def test_the_condition_lands_on_the_arm_it_guards_and_not_on_the_fall_through():
    """The drop arm gains its match clause; the trailing ``pass`` keeps none.

    Before this row the condition was dropped and the drop arm became an
    UNCONDITIONAL deny — which only the lossy-leniency rule kept from denying every
    route. That shape is the sharpest statement of why the row and the unwrap ship
    together, so it is pinned rather than described.
    """
    rm = _policy(_EDGE_IN, "EDGE-IN")
    shape = [
        (s.sequence, s.action, s.continuation,
         [(m.match_type, list(m.values)) for m in s.match_clauses])
        for s in sorted(rm.sequences, key=lambda s: s.sequence)
    ]
    assert shape == [
        (10, "deny", None, [("as-path", ["BOGON-ASNS"])]),
        (20, "permit", "pass", []),
    ]


@pytest.mark.parametrize(
    "set_name",
    [
        "BOGON-ASNS",          # hyphen
        "AS_CUSTOMERS",        # underscore
        "as.set.1",            # dots
        "AS-SET:1",            # colon
        "A1",                  # minimal
    ],
)
def test_the_operand_class_admits_the_set_names_rpl_actually_allows(set_name):
    rm = _policy(
        f"route-policy RP\n  if as-path in {set_name} then\n    drop\n  endif\n"
        f"  pass\nend-policy\n!\n",
        "RP",
    )
    assert _as_path_clauses(rm) == [[set_name]]
    assert rm.untranslated_constructs == []


# ---------------------------------------------------------------------------
# Hazard operands — pinned BEHAVIOURALLY, through real conversion
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "condition",
    [
        # A PARAMETER is not a set name. The 3a lesson (F1): a row whose operand class
        # is loose parses this clean and the engine then resolves a set that does not
        # exist, which is lenient-by-accident rather than lenient-by-disclosure.
        "as-path in $as_set",
        "as-path in $1",
        # An INLINE set: the grammar allows it, this row does not claim it, and the
        # model has no place to put an anonymous set.
        "as-path in (ios-regex '_64702_')",
        "as-path in (AS-A, AS-B)",
        # Boolean composition — the anchored regex can claim neither side.
        "as-path in AS-A and destination in PS-B",
        "as-path in AS-A or as-path in AS-B",
        "not as-path in AS-A",
        # Other `as-path` OPERATORS. The row claims `in` and only `in`; each of these
        # is a different condition that this model cannot express.
        "as-path is-local",
        "as-path length eq 5",
        "as-path neighbor-is '65001'",
        "as-path originates-from '65001'",
        "as-path passes-through '65001'",
        "as-path unique-length ge 3",
        # Shape noise that must not be waved through: a space in the operand, a
        # trailing token, the keyword alone.
        "as-path in AS SET",
        "as-path in AS-A extra",
        "as-path in",
    ],
)
def test_a_hazard_operand_stays_lossy_and_produces_no_as_path_clause(condition):
    """Both halves, because either alone is satisfiable by the wrong implementation.

    A row that claimed these would emit a confident clause naming a set nothing
    defines — and the engine's "missing list -> lenient" default would then permit
    while disclosing NOTHING. Disclosure is the point; silence with a plausible clause
    is the defect this whole CCR is about.
    """
    rm = _policy(
        f"route-policy RP-HAZARD\n  if {condition} then\n    drop\n  endif\n"
        f"  pass\nend-policy\n!\n",
        "RP-HAZARD",
    )
    assert _as_path_clauses(rm) == []
    assert condition in rm.untranslated_constructs


def test_a_hazard_operand_is_pinned_by_behaviour_not_by_regex_spelling():
    """The control for the test above: the SAME condition with a legal operand works.

    Without this pair, a row that was simply broken would pass every hazard case.
    """
    legal = _policy(
        "route-policy RP-OK\n  if as-path in AS-A then\n    drop\n  endif\n"
        "  pass\nend-policy\n!\n",
        "RP-OK",
    )
    assert _as_path_clauses(legal) == [["AS-A"]]
    assert legal.untranslated_constructs == []


# ---------------------------------------------------------------------------
# The registries as a contract
# ---------------------------------------------------------------------------

def test_adding_as_path_in_was_exactly_one_condition_row():
    """[[CCR-0250]]'s design test, discharged by its named next change.

    One row, no walker edit. Pinned as the shape of the table so that a future
    condition added by reopening the walker's control flow fails here.
    """
    assert set(RPL_CONDITIONS) == {
        "destination in", "community matches-any", "as-path in",
    }
    pattern, build = RPL_CONDITIONS["as-path in"]
    assert pattern.pattern.startswith("^") and pattern.pattern.endswith("$")
    assert build(pattern.match("as-path in AS-A")).match_type == "as-path"


def test_the_member_table_is_a_whitelist_with_no_list_of_what_it_rejects():
    """One row per member form the parser can represent, and nothing else.

    A blacklist of unsupported forms would need updating for every RPL release; the
    whitelist discloses an unanticipated form with no code change, which the
    ``some-future-operator`` case above measures.
    """
    assert set(_RPL_AS_PATH_MEMBERS) == {"ios-regex"}
    for pattern in _RPL_AS_PATH_MEMBERS.values():
        assert pattern.pattern.startswith("^") and pattern.pattern.endswith("$")
        assert "pattern" in pattern.groupindex


def test_parser_behavior_version_ships_with_the_behaviour_change():
    assert PARSER_BEHAVIOR_VERSION == 22


# ---------------------------------------------------------------------------
# One fix, many OSes — why the siblings need nothing
# ---------------------------------------------------------------------------

def test_the_sibling_parsers_need_no_change_because_only_xr_wraps_the_pattern():
    """The wrapper is RPL syntax and exists on no other OS.

    IOS/IOS-XE/NX-OS/EOS write ``ip as-path access-list N permit <regex>``, whose
    operand is already the bare pattern — nothing to unwrap, and the entry below
    proves it rather than asserting it in prose. So this fix is correctly confined to
    the one parser that has the construct.
    """
    parsed = IOSParser(
        "ip as-path access-list 10 permit _64702_\n"
        "ip as-path access-list 10 deny _64703_\n"
    ).parse()
    apl = next(a for a in parsed.as_path_lists if a.name == "10")
    assert [(e.action, e.regex) for e in apl.entries] == [
        ("permit", "_64702_"), ("deny", "_64703_")
    ]
    assert apl.untranslated_constructs == []
