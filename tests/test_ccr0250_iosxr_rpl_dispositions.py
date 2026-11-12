"""CCR-0250 — IOS-XR RPL ``drop`` / ``pass`` / ``done`` reach the model.

The defect, as the BATCH-A2 design review measured it, is wrong in BOTH directions:
``parse_route_maps`` hardcoded ``action="permit"`` on every sequence, so a drop-filter
PERMITTED what it had to block, while the policies that said ``pass`` on the fall-through
arm emitted no catch-all sequence and the engine's implicit deny-all then DENIED routes
the device accepts. A third defect lived in the same function: the arms of one
``if``/``elseif``/``else`` chain merged into ONE sequence's clause list and were ANDed,
so an ``elseif`` arm's set-clauses landed on the ``if`` arm's routes.

RPL semantics here are documentation-derived (Cisco IOS-XR Routing Configuration Guide,
RPL chapter) — the BATCH-A2 evidence standard. No hardware capture of an RPL disposition
exists, and ``syntax-corpus/iosxr/routing-policy.yaml`` has no entry for these verbs;
that gap is recorded in the CCR.

Every claim below is paired with a control the change cannot reach.
"""

from __future__ import annotations

import pytest

from confgraph.parsers.iosxr_parser import (
    RPL_ACTIONS,
    RPL_CONDITIONS,
    IOSXRParser,
)


def _policy(cfg: str, name: str):
    rm = IOSXRParser(cfg).parse().get_route_map_by_name(name)
    assert rm is not None, f"{name} did not parse"
    return rm


def _shape(rm):
    """(sequence, action, continuation, exclusive_group) per entry, in order."""
    return [
        (s.sequence, s.action, s.continuation, s.exclusive_group)
        for s in sorted(rm.sequences, key=lambda s: s.sequence)
    ]


# ---------------------------------------------------------------------------
# The three dispositions
# ---------------------------------------------------------------------------

_DISPOSITIONS = """\
route-policy RP-DROP
  drop
end-policy
!
route-policy RP-DONE
  done
end-policy
!
route-policy RP-PASS
  pass
end-policy
!
"""


@pytest.mark.parametrize(
    "name,expected",
    [
        # drop  — discard, stop evaluating
        ("RP-DROP", [(10, "deny", None, None)]),
        # done  — accept, stop evaluating
        ("RP-DONE", [(10, "permit", None, None)]),
        # pass  — accept, KEEP evaluating
        ("RP-PASS", [(10, "permit", "pass", None)]),
    ],
)
def test_each_disposition_converts_to_its_own_shape(name, expected):
    assert _shape(_policy(_DISPOSITIONS, name)) == expected


def test_a_disposition_is_never_spelled_into_action_in_a_way_a_blind_reader_misreads():
    """`action` stays permit/deny for every RPL shape — the delivery-safety property.

    A consumer built before `continuation` existed decides with `action` alone. If a
    non-terminal `pass` carried any action value other than "permit", that consumer
    would read it as a deny and a pass-all policy would start filtering. Asserted over
    every shape the converter can emit, so a future row cannot quietly introduce a
    third spelling.
    """
    cfg = _DISPOSITIONS + """\
route-policy RP-MIXED
  if destination in PS-A then
    set local-preference 200
  elseif destination in PS-B then
    done
  else
    drop
  endif
  pass
end-policy
!
"""
    parsed = IOSXRParser(cfg).parse()
    actions = {s.action for rm in parsed.route_maps for s in rm.sequences}
    assert actions <= {"permit", "deny"}, actions


# ---------------------------------------------------------------------------
# The dual-direction defect, on a committed lab config's policy
# ---------------------------------------------------------------------------

_EDGE_IN = """\
prefix-set BOGONS
  10.0.0.0/8 le 32
end-set
!
prefix-set ISP-KNOWN
  198.51.100.0/24
end-set
!
route-policy EDGE-IN
  if destination in BOGONS then
    drop
  elseif destination in ISP-KNOWN then
    set local-preference 200
    pass
  else
    pass
  endif
end-policy
!
"""


def test_the_drop_arm_is_a_deny_and_carries_no_other_arms_set_clauses():
    """Direction 1 AND the accumulation defect, in one assertion.

    Before this change `EDGE-IN` produced a single sequence carrying BOTH the `drop`
    arm's match clause and the `elseif` arm's `set local-preference 200`, with
    action="permit" — a bogon was permitted and depreferenced in the same breath.
    """
    rm = _policy(_EDGE_IN, "EDGE-IN")
    drop_seq = rm.sequences[0]

    assert drop_seq.action == "deny"
    assert drop_seq.continuation is None, "drop ends evaluation"
    assert [c.values for c in drop_seq.match_clauses] == [["BOGONS"]]
    assert drop_seq.set_clauses == [], (
        "the elseif arm's set-clauses must not accumulate onto the if arm"
    )


def test_each_arm_of_the_chain_is_its_own_sequence_and_they_are_alternatives():
    """Direction 2: the `else pass` arm exists as a catch-all sequence.

    It did not before, which is why an unmatched route fell through to the engine's
    implicit deny-all. The arms also share an exclusive_group: once one has run, the
    rest of the chain must not be evaluated, which flat first-match-wins entries cannot
    express on their own once an entry continues.
    """
    rm = _policy(_EDGE_IN, "EDGE-IN")

    assert _shape(rm) == [
        (10, "deny", None, 1),
        (20, "permit", "pass", 1),
        (30, "permit", "pass", 1),
    ]
    assert [c.values for c in rm.sequences[1].match_clauses] == [["ISP-KNOWN"]]
    assert [s.values for s in rm.sequences[1].set_clauses] == [["200"]]
    assert rm.sequences[2].match_clauses == [], "the else arm is the catch-all"


def test_statements_after_endif_are_NOT_in_the_chain():
    """CONTROL for exclusive_group — the twin that must NOT be grouped.

    `pass` after `endif` runs whatever the chain did, so grouping it with the arms
    would make a matched arm swallow it. Without this row, a converter that grouped
    every sequence in the policy would pass the test above.
    """
    rm = _policy(
        "route-policy RP-AFTER\n"
        "  if destination in PS-A then\n"
        "    set local-preference 200\n"
        "  endif\n"
        "  pass\n"
        "end-policy\n",
        "RP-AFTER",
    )
    assert _shape(rm) == [
        (10, "permit", "fallthrough", 1),  # the if arm: no disposition, continue
        (20, "permit", "pass", None),      # after endif: ungrouped, always evaluated
    ]


def test_a_classic_route_map_keeps_terminal_semantics():
    """CONTROL across the OS boundary — one fix, and only where it belongs.

    IOS route-maps already carry permit/deny per entry and are terminal. If the new
    `continuation` ever appeared on them, every IOS policy in the corpus would start
    evaluating past its first match.
    """
    from confgraph.parsers.ios_parser import IOSParser

    pc = IOSParser(
        "route-map RM permit 10\n match ip address prefix-list PL\n set metric 50\n!\n"
        "route-map RM deny 20\n!\n"
    ).parse()
    rm = pc.get_route_map_by_name("RM")
    assert [(s.sequence, s.action, s.continuation, s.exclusive_group) for s in rm.sequences] == [
        (10, "permit", None, None),
        (20, "deny", None, None),
    ]
    assert rm.untranslated_constructs == []


# ---------------------------------------------------------------------------
# The whitelist
# ---------------------------------------------------------------------------

def test_an_unknown_statement_is_named_not_silently_dropped():
    rm = _policy(
        "route-policy RP-LOSSY\n"
        "  apply CUSTOMER-IN\n"
        "  set weight 100\n"
        "  pass\n"
        "end-policy\n",
        "RP-LOSSY",
    )
    assert rm.untranslated_constructs == ["apply CUSTOMER-IN", "set weight"]


@pytest.mark.parametrize(
    "condition,recorded",
    [
        # boolean composition — no row's anchored regex can claim it
        ("destination in PS-A and community matches-any CS-B",
         "destination in PS-A and community matches-any CS-B"),
        ("not destination in PS-A", "not destination in PS-A"),
        # an inline set: the operand class admits no parenthesis
        ("community matches-any (65000:100)", "community matches-any (65000:100)"),
        # a parameter: nor a dollar sign
        ("destination in $customer_prefixes", "destination in $customer_prefixes"),
        # a condition nobody has written a row for at all
        ("as-path in AS-CUSTOMERS", "as-path in AS-CUSTOMERS"),
    ],
)
def test_an_unrepresentable_condition_is_recorded_in_full(condition, recorded):
    """A condition is recorded whole, because for a condition the OPERATOR is the news.

    `destination in A` and `destination in A and B` differ in exactly the part a
    verb-only label would throw away.
    """
    rm = _policy(
        f"route-policy RP-C\n  if {condition} then\n    pass\n  endif\nend-policy\n",
        "RP-C",
    )
    assert rm.untranslated_constructs == [recorded]


def test_a_policy_the_converter_fully_understands_claims_so_with_an_EMPTY_list():
    """CONTROL for the whitelist — the twin a flag-everything converter fails.

    An empty `untranslated_constructs` is a POSITIVE claim. If the tests above were the
    only ones, a converter that recorded every line would pass all of them.
    """
    for name in ("EDGE-IN", "RP-DROP", "RP-DONE", "RP-PASS"):
        cfg = _EDGE_IN if name == "EDGE-IN" else _DISPOSITIONS
        assert _policy(cfg, name).untranslated_constructs == [], name


def test_a_parameterised_policy_is_lossy_and_named_without_its_parameter_list():
    """The body is only half a parameterised policy: the call site supplies the rest."""
    rm = _policy(
        "route-policy RP-PARAM($pfx)\n  if destination in PS-A then\n"
        "    pass\n  endif\nend-policy\n",
        "RP-PARAM",
    )
    assert rm.name == "RP-PARAM"
    assert "route-policy parameters" in rm.untranslated_constructs


def test_a_nested_if_is_lossy_rather_than_flattened():
    """Flat sequences cannot hold a condition tree, and guessing is worse than saying so."""
    rm = _policy(
        "route-policy RP-NEST\n"
        "  if destination in PS-A then\n"
        "    if community matches-any CS-B then\n"
        "      drop\n"
        "    endif\n"
        "  endif\n"
        "  pass\n"
        "end-policy\n",
        "RP-NEST",
    )
    assert "nested if" in rm.untranslated_constructs


# ---------------------------------------------------------------------------
# The dispatch tables as a contract
# ---------------------------------------------------------------------------

def test_the_registries_are_the_only_vocabulary_and_adding_one_is_one_row():
    """[[CCR-0244]] must be able to add `as-path in` as a single row.

    Pinned as the shape of the tables rather than as prose, so a change that reopens the
    walker's control flow to add a condition fails here instead of at review.
    """
    assert set(RPL_CONDITIONS) == {"destination in", "community matches-any"}
    assert set(RPL_ACTIONS) == {
        "drop", "done", "pass",
        "set local-preference", "set med", "set community", "set origin",
        "prepend as-path",
    }
    for pattern, _build in list(RPL_CONDITIONS.values()) + list(RPL_ACTIONS.values()):
        assert pattern.pattern.startswith("^") and pattern.pattern.endswith("$"), (
            f"{pattern.pattern!r} is not anchored — an unanchored row would claim a "
            "line it only partly understands, which is the loss the whitelist prevents"
        )


def test_set_community_additive_keeps_the_keyword_it_consumed():
    """A row whose regex eats a token it then discards is the silent loss, re-spelled."""
    rm = _policy(
        "route-policy RP-ADD\n  set community (65000:100) additive\n  pass\nend-policy\n",
        "RP-ADD",
    )
    assert [(s.set_type, s.values) for s in rm.sequences[0].set_clauses] == [
        ("community", ["65000:100", "additive"])
    ]
    assert rm.untranslated_constructs == []


def test_a_plain_set_community_does_not_grow_an_additive_token():
    """CONTROL for the row above — the non-additive twin stays a replace."""
    rm = _policy(
        "route-policy RP-PLAIN\n  set community (65000:100)\n  pass\nend-policy\n",
        "RP-PLAIN",
    )
    assert [(s.set_type, s.values) for s in rm.sequences[0].set_clauses] == [
        ("community", ["65000:100"])
    ]


# ---------------------------------------------------------------------------
# ROUND 2 — no full-comprehension claim over anything not fully comprehended
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "comment",
    ["!", "! block bogons learned from the peer", "!note", "!! TODO revisit"],
)
def test_an_operator_comment_does_not_make_a_policy_lossy(comment):
    """THE ROUND-1 BLOCKER. A comment made the whole policy lenient.

    Round 1's ignorable pattern admitted only a BARE `!`, so `! block bogons` was read
    as a statement, recorded as the construct `'! block'`, and the engine's
    lossy-can-never-deny rule then permitted the route the drop-filter names —
    CCR-0250's own defect, re-committed by one operator comment. A comment is `!`
    followed by anything.
    """
    rm = _policy(
        f"route-policy RP-COMMENTED\n  {comment}\n  pass\nend-policy\n",
        "RP-COMMENTED",
    )
    assert rm.untranslated_constructs == []
    assert _shape(rm) == [(10, "permit", "pass", None)]


@pytest.mark.parametrize(
    "line,recorded",
    [("# not xr comment syntax", "# not"), ("remark keep this", "remark keep"),
     ("description peer policy", "description peer")],
)
def test_the_comment_class_is_not_widened_past_the_bang(line, recorded):
    """CONTROL for the fix above — the boundary, measured rather than assumed.

    `#` is not IOS-XR comment syntax, and `remark` / `description` are not RPL verbs.
    All three stay lossy. Without this row the fix could have been "ignore anything
    that looks like prose", which would wave real unconverted statements through.
    """
    rm = _policy(
        f"route-policy RP-BOUNDARY\n  {line}\n  pass\nend-policy\n", "RP-BOUNDARY"
    )
    assert rm.untranslated_constructs == [recorded]


@pytest.mark.parametrize(
    "statement,recorded",
    [
        ("set local-preference $lp", "set local-preference"),
        ("set med $m", "set med"),
        ("set origin $o", "set origin"),
        ("set community ($c)", "set community"),
        ("prepend as-path $asn", "prepend as-path"),
        # non-parameter shapes the rows also must not pretend to understand
        ("set local-preference +50", "set local-preference"),
        ("set origin whatever", "set origin"),
        ("set med igp-cost", "set med"),
    ],
)
def test_an_action_operand_the_row_cannot_represent_lands_lossy(statement, recorded):
    """Round 1's action rows all used `\\S+`, and the module header claimed otherwise.

    Measured consequence: `set local-preference $lp` parsed with an EMPTY lossy list,
    and the engine's `int()` then swallowed the parameter and left local-preference
    untouched — a parameter confidently misread, disclosed nowhere. Operand classes
    are structural now, so every row above fails to match and is named.
    """
    rm = _policy(
        f"route-policy RP-OPERAND\n  {statement}\n  pass\nend-policy\n", "RP-OPERAND"
    )
    assert rm.untranslated_constructs == [recorded]


def test_the_representable_operands_still_parse():
    """CONTROL for the row above — the structural classes must not be too tight.

    A whitelist that rejects everything would pass the lossy tests and break the
    product. These are the spellings the corpora actually contain.
    """
    rm = _policy(
        "route-policy RP-OK\n"
        "  set local-preference 250\n"
        "  set med -50\n"
        "  set origin igp\n"
        "  set community CS-MARK\n"
        "  pass\n"
        "end-policy\n",
        "RP-OK",
    )
    assert rm.untranslated_constructs == []
    assert [(s.set_type, s.values) for s in rm.sequences[0].set_clauses] == [
        ("local-preference", ["250"]), ("metric", ["-50"]),
        ("origin", ["igp"]), ("community", ["CS-MARK"]),
    ]


# The module header's claim — every action row's operand class is structural, so a
# shape the row cannot represent goes lossy instead of being swallowed — is pinned by
# the four tests below.
#
# THEY TEST THE PROPERTY, NOT THE SPELLING, and that distinction is the whole point.
# The first version of this pin asserted `r"\S" not in pattern.pattern`: a substring
# test on regex SOURCE. Four equivalent operand classes walk straight through it —
# `[^\s]+`, `.+`, `[^ ]+`, `\w+` — and a row written with `.+` was measured
# reproducing the original defect end to end, `set weight $w` parsing to a set clause
# with an EMPTY lossy list. Origin and the measurement: the round-2 validator's
# `attack_pin.py`, kept in this item's scratch directory.
#
# The subtlety worth carrying away: `\w+` passes the tests below, legitimately. It
# genuinely rejects `$` and `(`, so a row written with it is not hazardous, even
# though it would have "looked wrong" to a reviewer grepping for character classes.
# The hazard was never a spelling — it is SWALLOWING an operand the row cannot
# represent — which is exactly why asking the source what it looks like was the wrong
# question and asking the conversion what it does is the right one.

_HAZARD_PARAMETER = "$param"
_HAZARD_SHAPELESS = "@@@~~~"
_HAZARD_PARENS = "(junk)"


def _hazard_outcome(verb: str, operand: str):
    """Run `<verb> <operand>` through the real conversion; return (lossy, set_clauses)."""
    rm = _policy(
        f"route-policy RP-HAZARD\n  {verb} {operand}\n  pass\nend-policy\n", "RP-HAZARD"
    )
    return rm.untranslated_constructs, [
        (s.set_type, s.values) for seq in rm.sequences for s in seq.set_clauses
    ]


def _assert_swallowed_nothing(verb, operand, lossy, set_clauses):
    assert lossy, (
        f"`{verb} {operand}` parsed with an EMPTY lossy list — the row claimed to "
        "understand an operand it cannot represent, and nothing was disclosed"
    )
    assert verb.split()[0] in " ".join(lossy), (
        f"the disclosure must name the construct; got {lossy}"
    )
    assert set_clauses == [], (
        f"`{verb} {operand}` produced {set_clauses}; an operand the row cannot "
        "represent must never reach a set clause"
    )


@pytest.mark.parametrize("verb", sorted(RPL_ACTIONS))
def test_every_action_row_refuses_a_parameter_operand(verb):
    """`$param` is RPL's parameter sigil and no row can resolve one.

    Round 1 measured the consequence of not refusing it: `set local-preference $lp`
    parsed clean, and the engine's `int()` then swallowed the parameter and left
    local-preference untouched — wrong, and silent.
    """
    lossy, set_clauses = _hazard_outcome(verb, _HAZARD_PARAMETER)
    _assert_swallowed_nothing(verb, _HAZARD_PARAMETER, lossy, set_clauses)


@pytest.mark.parametrize("verb", sorted(RPL_ACTIONS))
def test_every_action_row_refuses_a_shapeless_operand(verb):
    """Garbage in the operand position is not a thing any row may claim to read."""
    lossy, set_clauses = _hazard_outcome(verb, _HAZARD_SHAPELESS)
    _assert_swallowed_nothing(verb, _HAZARD_SHAPELESS, lossy, set_clauses)


@pytest.mark.parametrize(
    "verb", sorted(v for v in RPL_ACTIONS if v != "set community")
)
def test_every_action_row_but_community_refuses_a_parenthesised_operand(verb):
    """A parenthesised operand is an inline SET, which only the community row has.

    `set community` is excluded here and tested by its own grammar below: it is the
    one sanctioned exception, because RPL writes inline community sets parenthesised
    and `set community (64512:4242)` is the standard spelling.
    """
    lossy, set_clauses = _hazard_outcome(verb, _HAZARD_PARENS)
    _assert_swallowed_nothing(verb, _HAZARD_PARENS, lossy, set_clauses)


@pytest.mark.parametrize(
    "operand,values",
    [
        ("(65000:100)", ["65000:100"]),
        ("(65000:100, 65000:200)", ["65000:100", "65000:200"]),
        ("(no-export)", ["no-export"]),
        ("CS-NAMED-SET", ["CS-NAMED-SET"]),
        ("(65000:100) additive", ["65000:100", "additive"]),
    ],
)
def test_the_community_row_accepts_the_inline_set_grammar(operand, values):
    """The sanctioned exception, and the forms it must keep working."""
    lossy, set_clauses = _hazard_outcome("set community", operand)
    assert lossy == []
    assert set_clauses == [("community", values)]


@pytest.mark.parametrize("operand", ["($cs)", "((x))", "()", "(a) (b)", "$cs"])
def test_the_community_rows_exception_is_for_the_GRAMMAR_not_for_parentheses(operand):
    """CONTROL on the exception — it is strict, not "parentheses are allowed here".

    A parameter inside the parentheses, a nested set, an empty set and a doubled one
    are all shapes the row cannot represent, and the exception must not launder them.
    Without this, "the community row accepts parens" would be a hole the size of the
    one the other rows just closed.
    """
    lossy, set_clauses = _hazard_outcome("set community", operand)
    _assert_swallowed_nothing("set community", operand, lossy, set_clauses)


def test_an_inline_community_set_is_unwrapped_not_stored_with_its_parentheses():
    """`(…)` is RPL's syntax for "here is a set", not part of a member's value.

    Stored with the parentheses, `(65000:100)` compares equal to no community any
    route ever carries, so the set clause wrote a value nothing could match. The
    parenthesis is a grammar here, which is why these rows parse it rather than
    treating `(` as a banned character the way the condition rows do.
    """
    rm = _policy(
        "route-policy RP-INLINE\n"
        "  set community (65000:100, no-export) additive\n"
        "  pass\n"
        "end-policy\n",
        "RP-INLINE",
    )
    assert rm.untranslated_constructs == []
    assert [(s.set_type, s.values) for s in rm.sequences[0].set_clauses] == [
        ("community", ["65000:100", "no-export", "additive"])
    ]


@pytest.mark.parametrize(
    "statement,values",
    [
        ("prepend as-path 65000", ["65000"]),
        ("prepend as-path 65000 1", ["65000"]),
        ("prepend as-path 65000 3", ["65000", "65000", "65000"]),
        ("prepend as-path 65000 63", ["65000"] * 63),
    ],
)
def test_the_second_prepend_operand_is_a_COUNT_not_a_second_asn(statement, values):
    """`prepend as-path 65000 1` prepends AS 65000 once — it does not prepend AS 1.

    Round 1 split the operands and handed both to the engine as ASNs, so a config
    saying "prepend once" produced the AS-path `65000 1 …`.
    """
    rm = _policy(
        f"route-policy RP-PREPEND\n  {statement}\n  pass\nend-policy\n", "RP-PREPEND"
    )
    assert rm.untranslated_constructs == []
    assert [(s.set_type, s.values) for s in rm.sequences[0].set_clauses] == [
        ("as-path prepend", values)
    ]


@pytest.mark.parametrize("count", ["0", "64", "65200"])
def test_a_prepend_count_outside_the_documented_range_is_lossy_never_clamped(count):
    """CONTROL on the range, and on the refusal to invent a value.

    XR documents 1-63. A config outside it is one a device rejects, so there is no
    device behaviour to model; clamping to 63 would fabricate one. The row recognises
    the construct and declines the operand, which is a lossy outcome.
    """
    rm = _policy(
        f"route-policy RP-OVER\n  prepend as-path 65000 {count}\n  pass\nend-policy\n",
        "RP-OVER",
    )
    assert rm.untranslated_constructs == ["prepend as-path"]
    assert rm.sequences[0].set_clauses == []


def test_an_unterminated_if_is_lossy():
    """A truncated structure is an incomplete read, so it cannot claim completeness.

    The arms built before the body ran out are real, but whatever closes the chain —
    an `endif`, possibly more arms — is not in what we read. Round 1 emitted a bare
    deny arm with an EMPTY lossy list: the blocker's shape again, a full-comprehension
    claim over something not fully comprehended.
    """
    rm = _policy(
        "route-policy RP-TRUNC\n"
        "  if destination in PS-A then\n"
        "    drop\n"
        "end-policy\n",
        "RP-TRUNC",
    )
    assert rm.untranslated_constructs == ["unterminated if"]


def test_a_terminated_if_is_not():
    """CONTROL — the same body with its `endif`."""
    rm = _policy(
        "route-policy RP-TERM\n"
        "  if destination in PS-A then\n"
        "    drop\n"
        "  endif\n"
        "  pass\n"
        "end-policy\n",
        "RP-TERM",
    )
    assert rm.untranslated_constructs == []


def test_an_empty_policy_converts_to_no_sequences_at_all():
    """DECLARED MOVEMENT CLASS. Nothing is synthesised to represent the device rule.

    A policy with no body holds no statements, so it gets no sequences; the fact that
    the device drops every route through it is the ENGINE's end-of-policy rule, pinned
    in `test_ccr0250_rpl_evaluation.py`. Fabricating a sequence here would make the
    model say something the config does not.
    """
    rm = _policy("route-policy RP-EMPTY\nend-policy\n", "RP-EMPTY")
    assert rm.sequences == []
    assert rm.untranslated_constructs == []
