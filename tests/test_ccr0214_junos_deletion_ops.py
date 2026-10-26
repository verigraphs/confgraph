"""CCR-0214 — JunOS removals compile to change ops instead of only disclosing.

Before this, JunOS could not express a deletion at all.  The tombstone grammar
is Cisco syntax from end to end and the parser emitted no change ops, so
``delete protocols bgp group RR neighbor 10.0.0.1`` — a withdrawal, the most
outage-prone change class on the OS — could only ever be reported as content
the engine could not read.  The operator got amber and a shrug for the one
question they most needed answered.

What these pin, in the order they matter:

  * the four modelled paths compile to the exact op shapes the merger already
    dispatches, and ``deactivate`` compiles identically to ``delete``;
  * the registry IS the partition — a path no row claims is DISCLOSED, never
    silently dropped and never half-applied;
  * the inventory oracle below, so a row cannot be removed, retargeted, or
    quietly added without this file failing;
  * adding the next deletable path costs exactly one row and no other code;
  * the ASN sentinel: a proposal that states no ``routing-options
    autonomous-system`` emits ``""`` for the merger to resolve, rather than
    the engine inventing a number ([[CCR-0212]]);
  * real corpora are untouched — no baseline states a deletion verb, so no
    baseline parse moves.

Run only these tests:
    uv run --extra dev pytest tests/test_ccr0214_junos_deletion_ops.py
"""

from __future__ import annotations

from pathlib import Path

import pytest

from confgraph.change_ir import Verb
from confgraph.parsers.junos_deletions import (
    ANY,
    JUNOS_DELETION_RULES,
    DeletionScope,
    JunOSDeletionRule,
    collides_with_later_set,
    compile_deletion,
    match_rule,
)
from confgraph.parsers.junos_hierarchy import (
    DELETION_VERBS,
    NON_SET_VERBS,
    deletion_statements,
    set_statements,
)
from confgraph.parsers.junos_parser import JunOSParser

# ---------------------------------------------------------------- the oracle

#: One frozen row per registry row: (pattern, sample statement, verb, the op
#: path that sample compiles to under the ASN sentinel).
#:
#: This is the drift gate, and it exists because the obvious parity test —
#: "iterate the rules, assert each compiles" — is VACUOUS against the mutation
#: that matters: delete a row and the loop just gets shorter.  Here, deleting a
#: row, retargeting a pattern, or rewriting a builder all fail, and ADDING a
#: row fails too, which makes enrolling the next deletable path a deliberate
#: re-pin rather than a drift.  Same discipline as the entrp deletion-dispatch
#: inventory oracle, at the emission end of the same pipe.
EXPECTED_INVENTORY: tuple[tuple[tuple, str, str, tuple[str, ...]], ...] = (
    (
        ("protocols", "bgp", "group", ANY, "neighbor", ANY),
        "delete protocols bgp group RR neighbor 10.0.0.1",
        "object_delete",
        ("bgp_instance", "", "", "neighbor", "10.0.0.1"),
    ),
    (
        ("protocols", "bgp", "group", ANY),
        "delete protocols bgp group RR",
        "object_delete",
        ("bgp_instance", "", "", "field", "neighbor", "RR", "peer_group"),
    ),
    (
        ("routing-options", "static", "route", ANY),
        "delete routing-options static route 10.99.0.0/24",
        "list_remove",
        ("static", "", "10.99.0.0/24"),
    ),
    (
        ("interfaces", ANY, "unit", ANY),
        "delete interfaces ge-0/0/0 unit 0",
        "object_delete",
        ("interface", "ge-0/0/0.0"),
    ),
)


#: The same configuration in the brace rendering — which has no deletion verb,
#: and so can never produce one, which is why no BASELINE parse moves.
BRACE_DOC = (
    "protocols {\n    bgp {\n        group EXT {\n"
    "            neighbor 10.0.0.1 {\n                peer-as 65001;\n"
    "            }\n        }\n    }\n}\n"
)


def _ops(cfg: str):
    return JunOSParser(cfg).parse().native_change_ops or []


def _shapes(cfg: str) -> list[tuple[str, tuple[str, ...]]]:
    return [(op.verb.value, op.path) for op in _ops(cfg)]


def _disclosed(cfg: str) -> list[str]:
    return [b.block_header for b in JunOSParser(cfg).parse().unrecognized_blocks]


def _compile(statement: str, scope: DeletionScope | None = None):
    """Compile one statement exactly as the parser does, registry and all."""
    (line_no, line, path), = deletion_statements(statement + "\n")
    return compile_deletion(
        path, scope or DeletionScope(), source_line=line, line_no=line_no
    )


# ------------------------------------------------------------------ oracle


class TestTheRegistryInventory:
    def test_the_live_table_matches_the_frozen_inventory(self):
        """Row removed, pattern retargeted, builder rewritten, row added —
        every one of those shows up here, and nowhere else would catch all
        four."""
        live = tuple(
            (
                rule.pattern,
                rule.sample,
                op.verb.value,
                op.path,
            )
            for rule in JUNOS_DELETION_RULES
            for op in [_compile(rule.sample)]
        )
        assert live == EXPECTED_INVENTORY

    def test_every_rows_sample_matches_that_row_and_no_other(self):
        """A sample is evidence only while it exercises its own row.  This also
        pins the claim that row ORDER carries no meaning: if two patterns could
        ever match one path, the samples would start selecting the wrong rows
        and this would fail."""
        for rule in JUNOS_DELETION_RULES:
            (_line_no, _line, path), = deletion_statements(rule.sample + "\n")
            matched = match_rule(path)
            assert matched is not None, f"{rule.sample!r} matches no rule"
            assert matched[0] is rule, (
                f"{rule.sample!r} belongs to {rule.pattern} but selected "
                f"{matched[0].pattern}"
            )

    def test_no_two_rows_share_a_pattern(self):
        patterns = [rule.pattern for rule in JUNOS_DELETION_RULES]
        assert len(set(patterns)) == len(patterns)


class TestTheVerbSetIsPinned:
    """The membership of :data:`DELETION_VERBS` is a SEMANTIC claim, not a list.

    Promoting a verb into it makes that verb compile to a removal, and the two
    complementary parametrizations elsewhere in the suite move the verb between
    halves rather than failing — so adding ``activate`` passed every test in
    every repo while inverting the meaning of the statement: a request to
    RESTORE an inactive subtree would have been simulated as a removal, on the
    modelled paths, silently. Found in validation; this is the pin.
    """

    def test_exactly_delete_and_deactivate_compile(self):
        assert DELETION_VERBS == {"delete", "deactivate"}

    def test_every_removal_verb_is_part_of_the_disclosed_verb_family(self):
        """The removal set is a SUBSET of the family, never a sibling list: the
        family decides routing, this decides compilation, and a verb outside
        the family would reach neither."""
        assert DELETION_VERBS < NON_SET_VERBS

    def test_activate_is_not_a_removal_verb(self):
        """Named rather than left implicit, because it is the one verb that
        looks like it belongs: it is in the family, it is about the same
        inactive/active state ``deactivate`` is about, and it is the exact
        mutation that slipped through. Restoring an inactive subtree needs the
        subtree's contents, which the model — holding only the running
        configuration — never had."""
        assert "activate" not in DELETION_VERBS
        cfg = "activate protocols bgp group RR neighbor 10.0.0.1\n"
        assert _ops(cfg) == []
        assert _disclosed(cfg) == [cfg.strip()]


# ------------------------------------------------------- rewrite vs removal


class TestARewriteIsNotARemoval:
    """A ``delete`` the same document later re-states is a stanza REWRITE.

    JunOS applies candidate statements in order, so ``delete`` followed by
    ``set`` under the same path re-creates the thing with new contents. The
    model cannot hold "removed and then re-created differently", and applying
    the removal alone reports a confident teardown of something the device
    would still have — which is how the two commonest JunOS rewrite idioms
    (rebuild a BGP group, move a static route to a new next-hop) read before
    this guard. They now disclose, which is the honest answer and the one the
    pre-CCR-0214 engine gave.
    """

    GROUP_REWRITE = (
        "delete protocols bgp group RR\n"
        "set protocols bgp group RR type internal\n"
        "set protocols bgp group RR neighbor 10.255.0.9\n"
    )
    STATIC_MOVE = (
        "delete routing-options static route 10.99.0.0/24\n"
        "set routing-options static route 10.99.0.0/24 next-hop 10.0.18.9\n"
    )
    UNIT_REWRITE = (
        "delete interfaces ge-0/0/0 unit 0\n"
        "set interfaces ge-0/0/0 unit 0 family inet address 10.9.9.9/30\n"
    )

    @pytest.mark.parametrize(
        "cfg",
        [GROUP_REWRITE, STATIC_MOVE, UNIT_REWRITE],
        ids=["group-rebuild", "static-next-hop-move", "interface-unit-rebuild"],
    )
    def test_a_restated_removal_discloses_instead_of_compiling(self, cfg):
        assert _ops(cfg) == []
        assert _disclosed(cfg) == [cfg.splitlines()[0]]

    def test_the_set_lines_around_it_still_parse(self):
        """Disclosing the removal must not cost the rest of the document."""
        pc = JunOSParser(self.GROUP_REWRITE).parse()
        assert [pg.name for b in pc.bgp_instances for pg in b.peer_groups] == ["RR"]
        assert [
            str(n.peer_ip) for b in pc.bgp_instances for n in b.neighbors
        ] == ["10.255.0.9"]

    def test_order_is_load_bearing_set_then_delete_still_removes(self):
        """The reverse order is a REMOVAL on a device — written, then withdrawn
        — and the deletion op already produces exactly that. Guarding it too
        would throw away a correct answer, so the guard reads line numbers and
        not just paths."""
        cfg = (
            "set protocols bgp group RR neighbor 10.255.0.1 peer-as 64512\n"
            "delete protocols bgp group RR neighbor 10.255.0.1\n"
        )
        assert _shapes(cfg) == [
            ("object_delete", ("bgp_instance", "", "", "neighbor", "10.255.0.1"))
        ]
        assert _disclosed(cfg) == []

    def test_a_set_at_a_diverging_path_is_not_a_collision(self):
        """Sharing an ancestor is not re-stating. Here the removal is genuine
        and the edit beside it is unrelated, so the removal must still
        simulate — this is the over-trigger the guard has to avoid."""
        cfg = (
            "delete protocols bgp group RR neighbor 10.255.0.1\n"
            "set protocols bgp group RR type external\n"
        )
        assert _shapes(cfg) == [
            ("object_delete", ("bgp_instance", "", "", "neighbor", "10.255.0.1"))
        ]
        assert _disclosed(cfg) == []

    def test_a_set_on_a_different_object_entirely_is_not_a_collision(self):
        cfg = (
            "delete interfaces ge-0/0/0 unit 0\n"
            "set interfaces ge-0/0/1 unit 0 family inet address 10.9.9.9/30\n"
        )
        assert _shapes(cfg) == [("object_delete", ("interface", "ge-0/0/0.0"))]
        assert _disclosed(cfg) == []

    def test_a_deeper_delete_under_a_restated_parent_still_compiles(self):
        """``set`` at a SHALLOWER path than the deletion does not re-create
        what was deleted: creating the group and then removing a member from
        it is a removal, and the member never comes back."""
        cfg = (
            "delete protocols bgp group RR neighbor 10.255.0.1\n"
            "set protocols bgp group RR\n"
        )
        assert _shapes(cfg) == [
            ("object_delete", ("bgp_instance", "", "", "neighbor", "10.255.0.1"))
        ]

    def test_the_collision_predicate_reads_prefixes_and_order_directly(self):
        """The rule stated once, away from the parser, so its two halves are
        separable: prefix-or-equal on the path, strictly later in the file."""
        path = ("protocols", "bgp", "group", "RR")
        later_child = [(9, "", ("protocols", "bgp", "group", "RR", "type", "internal"))]
        later_exact = [(9, "", ("protocols", "bgp", "group", "RR"))]
        later_sibling = [(9, "", ("protocols", "bgp", "group", "EXT"))]
        later_ancestor = [(9, "", ("protocols", "bgp"))]
        earlier_child = [(1, "", ("protocols", "bgp", "group", "RR", "type", "internal"))]

        assert collides_with_later_set(path, 5, later_child) is True
        assert collides_with_later_set(path, 5, later_exact) is True
        assert collides_with_later_set(path, 5, later_sibling) is False
        assert collides_with_later_set(path, 5, later_ancestor) is False
        assert collides_with_later_set(path, 5, earlier_child) is False
        assert collides_with_later_set(path, 5, []) is False

    def test_set_statements_mirrors_deletion_statements(self):
        """The comparability the guard rests on: both sides come from one
        classification pass and one tokenizer, so a ``set`` and a ``delete``
        naming the same node produce the SAME tuple."""
        cfg = (
            "delete protocols bgp group RR neighbor 10.255.0.1\n"
            "set protocols bgp group RR neighbor 10.255.0.1 peer-as 64512\n"
        )
        (_dn, _dl, dpath), = deletion_statements(cfg)
        (_sn, _sl, spath), = set_statements(cfg)
        assert dpath == ("protocols", "bgp", "group", "RR", "neighbor", "10.255.0.1")
        assert spath[: len(dpath)] == dpath

    def test_a_brace_document_offers_no_set_statements(self):
        assert set_statements(BRACE_DOC) == []


# ------------------------------------------------------------- the positives


class TestTheModelledPathsCompile:
    @pytest.mark.parametrize("verb", sorted(DELETION_VERBS))
    @pytest.mark.parametrize(
        "statement,verb_name,path",
        [(row[1], row[2], row[3]) for row in EXPECTED_INVENTORY],
        ids=[row[1].split(" ", 1)[1] for row in EXPECTED_INVENTORY],
    )
    def test_both_removal_verbs_compile_every_modelled_path(
        self, verb, statement, verb_name, path
    ):
        """``deactivate`` is ``delete`` as far as the running configuration is
        concerned, and the running configuration is all the model holds — so
        the cross-product is the claim, not two separate ones."""
        cfg = statement.replace("delete ", f"{verb} ", 1) + "\n"
        ops = _ops(cfg)
        assert [(op.verb.value, op.path) for op in ops] == [(verb_name, path)]
        assert _disclosed(cfg) == []

    def test_the_op_carries_real_provenance(self):
        (op,) = _ops("delete interfaces ge-0/0/0 unit 0\n")
        assert op.origin == "native"
        assert op.source_line == "delete interfaces ge-0/0/0 unit 0"
        assert op.line_no == 1
        assert op.value is None

    def test_line_numbers_are_the_documents_own(self):
        cfg = (
            "# a comment\n"
            "set system host-name r1\n"
            "delete protocols bgp group RR neighbor 10.0.0.1\n"
        )
        (op,) = _ops(cfg)
        assert op.line_no == 3

    def test_several_removals_keep_document_order(self):
        cfg = (
            "delete interfaces ge-0/0/0 unit 0\n"
            "delete routing-options static route 10.99.0.0/24\n"
            "delete protocols bgp group RR neighbor 10.0.0.1\n"
        )
        assert [op.path[0] for op in _ops(cfg)] == [
            "interface",
            "static",
            "bgp_instance",
        ]


class TestTheASNSentinel:
    def test_a_proposal_that_states_no_autonomous_system_emits_the_sentinel(self):
        """JunOS keeps the ASN outside ``protocols bgp``, so a BGP-only
        proposal legitimately states none.  Emitting ``""`` hands the scope
        question to the merger, which resolves it against the baseline or
        refuses — the [[CCR-0212]] rule, now governing removals too.  Inventing
        a number here would address an instance that does not exist and drop
        the removal silently."""
        (op,) = _ops("delete protocols bgp group RR neighbor 10.0.0.1\n")
        assert op.path[1] == ""

    def test_a_restated_autonomous_system_is_used(self):
        cfg = (
            "set routing-options autonomous-system 65000\n"
            "delete protocols bgp group RR neighbor 10.0.0.1\n"
        )
        (op,) = _ops(cfg)
        assert op.path[1] == "65000"

    def test_the_brace_rendering_of_the_asn_is_read_too(self):
        """The two renderings are one tree, so the emitter reads the tree and
        not the ``set`` lines — but a brace document carries no deletion verb,
        so this is asserted at the registry seam instead of end to end."""
        parser = JunOSParser(
            "routing-options {\n    autonomous-system 65000;\n}\n"
        )
        assert parser._stated_autonomous_system() == "65000"

    def test_non_bgp_shapes_do_not_carry_the_asn_at_all(self):
        cfg = (
            "set routing-options autonomous-system 65000\n"
            "delete interfaces ge-0/0/0 unit 0\n"
        )
        (op,) = _ops(cfg)
        assert op.path == ("interface", "ge-0/0/0.0")


# ------------------------------------------------------------- the partition


class TestTheUnmodelledHalfIsDisclosed:
    @pytest.mark.parametrize(
        "statement",
        [
            # amendment 8 / the W2-J1 case: group→member inheritance is
            # flattened at parse with no provenance, so clearing the group
            # object alone would under-apply, silently.
            "delete protocols bgp group RR export EXPORT-BRANCH",
            # [[CCR-0218]] — primary interface-address removal is unmodelled at
            # both layers.
            "delete interfaces ge-0/0/0 unit 0 family inet address 10.0.18.2/30",
            # One token too deep on a modelled prefix: exact-length matching is
            # what stops this being half-applied as a whole-neighbour delete.
            "delete protocols bgp group RR neighbor 10.0.0.1 peer-as",
            # The whole port, named without a unit — one row away, deliberately
            # not taken this round.
            "delete interfaces ge-0/0/0",
            # A routing-instance scope: every row addresses the global one.
            "delete routing-instances CUST protocols bgp group CE neighbor 10.9.9.9",
            # Nothing near the modelled surface at all.
            "delete policy-options policy-statement EXPORT-BRANCH",
            "delete protocols ospf area 0.0.0.0 interface ge-0/0/0.0",
            "delete system ntp server 10.10.30.250",
        ],
    )
    def test_a_path_no_row_claims_is_disclosed_and_compiles_nothing(self, statement):
        cfg = statement + "\n"
        assert _ops(cfg) == []
        assert _disclosed(cfg) == [statement]

    def test_a_bracketed_removal_falls_through_to_disclosure(self):
        """A bracketed run addresses several nodes at once.  No row claims a
        path holding a bracket token, so it discloses — fail-closed, which is
        the only safe default for a removal."""
        statement = "delete protocols bgp group RR export [ A B ]"
        assert _ops(statement + "\n") == []
        assert _disclosed(statement + "\n") == [statement]

    def test_every_statement_is_on_exactly_one_side_of_the_partition(self):
        """The property that makes "nothing became silent" checkable rather
        than argued: for a document of mixed removals, compiled + disclosed
        accounts for every statement, with no overlap."""
        statements = [
            "delete protocols bgp group RR neighbor 10.0.0.1",
            "delete protocols bgp group RR export EXPORT-BRANCH",
            "deactivate interfaces ge-0/0/0 unit 0",
            "delete policy-options policy-statement EXPORT-BRANCH",
            "delete routing-options static route 10.99.0.0/24",
            "delete interfaces ge-0/0/0",
        ]
        cfg = "\n".join(statements) + "\n"
        compiled = [op.source_line for op in _ops(cfg)]
        disclosed = _disclosed(cfg)
        assert set(compiled) & set(disclosed) == set()
        assert sorted(compiled + disclosed) == sorted(statements)

    def test_a_repeated_statement_is_accounted_for_once_each(self):
        """Compiled lines are subtracted from the disclosure one at a time, so
        two identical statements produce two ops and no stray disclosure —
        and two identical UNMODELLED ones produce two disclosures."""
        cfg = (
            "delete interfaces ge-0/0/0 unit 0\n"
            "delete interfaces ge-0/0/0 unit 0\n"
            "delete policy-options policy-statement P\n"
            "delete policy-options policy-statement P\n"
        )
        assert len(_ops(cfg)) == 2
        assert _disclosed(cfg) == [
            "delete policy-options policy-statement P",
            "delete policy-options policy-statement P",
        ]


# ---------------------------------------------------------------- the parity


class TestOneRowIsTheWholeCost:
    def test_the_next_deletable_path_costs_exactly_one_row(self, monkeypatch):
        """The structural claim.  ``delete protocols ospf area <A> interface
        <I>`` is disclosed above; here it compiles, with the ONLY change being
        one row appended to the table — no parser edit, no classification
        change, no new branch anywhere.  (The op shape is a stand-in; what is
        under test is the cost of the row, not that shape's merger support,
        which the entrp guard test is what actually gates.)"""
        statement = "delete protocols ospf area 0.0.0.0 interface ge-0/0/0.0"
        assert _ops(statement + "\n") == []

        def _build(caps, scope):
            return Verb.OBJECT_DELETE, ("ospf_area_interface", caps[0], caps[1])

        new_row = JunOSDeletionRule(
            pattern=("protocols", "ospf", "area", ANY, "interface", ANY),
            build=_build,
            sample=statement,
        )
        monkeypatch.setattr(
            "confgraph.parsers.junos_deletions.JUNOS_DELETION_RULES",
            JUNOS_DELETION_RULES + (new_row,),
        )

        ops = _ops(statement + "\n")
        assert [(op.verb.value, op.path) for op in ops] == [
            ("object_delete", ("ospf_area_interface", "0.0.0.0", "ge-0/0/0.0"))
        ]
        assert _disclosed(statement + "\n") == []

    def test_removing_a_row_returns_its_path_to_disclosure(self, monkeypatch):
        """The inverse, and the thing that makes the partition trustworthy: a
        path the table stops claiming does not go quiet, it goes back to being
        disclosed."""
        statement = "delete routing-options static route 10.99.0.0/24"
        monkeypatch.setattr(
            "confgraph.parsers.junos_deletions.JUNOS_DELETION_RULES",
            tuple(
                r for r in JUNOS_DELETION_RULES if r.pattern[0] != "routing-options"
            ),
        )
        assert _ops(statement + "\n") == []
        assert _disclosed(statement + "\n") == [statement]


# ------------------------------------------------------------ the regressions


class TestNothingElseMoved:
    def test_a_set_only_document_emits_no_ops(self):
        cfg = (
            "set routing-options autonomous-system 65000\n"
            "set protocols bgp group EXT neighbor 10.0.0.1 peer-as 65001\n"
        )
        assert _ops(cfg) == []
        assert _disclosed(cfg) == []

    def test_the_shipped_junos_sample_emits_no_ops_and_discloses_nothing(self):
        cfg = (Path(__file__).parent.parent / "samples" / "junos_test.cfg").read_text()
        pc = JunOSParser(cfg).parse()
        assert pc.native_change_ops == []
        assert pc.unrecognized_blocks == []

    def test_a_brace_document_emits_no_ops(self):
        """The brace rendering has no deletion verb, so a saved configuration
        — which is the only thing written in braces — can never produce one.
        That is why no BASELINE parse moves under this change."""
        assert deletion_statements(BRACE_DOC) == []
        assert _ops(BRACE_DOC) == []

    def test_an_inactive_tag_is_still_only_disclosed(self):
        """The documented asymmetry: the set-idiom ``deactivate`` simulates,
        the brace-idiom ``inactive:`` statement tag does not.  It states a
        subtree the model cannot represent as absent-but-remembered, and it
        arrives through the brace branch, which compiles nothing."""
        cfg = "inactive: protocols {\n    bgp {\n    }\n}\n"
        assert _ops(cfg) == []
        assert _disclosed(cfg) == ["inactive: protocols {"]

    def test_an_empty_document_is_still_a_no_op(self):
        assert _ops("") == []
        assert _disclosed("") == []

    def test_a_comment_only_document_is_still_silent(self):
        cfg = "# delete protocols bgp group RR neighbor 10.0.0.1\n"
        assert _ops(cfg) == []
        assert _disclosed(cfg) == []
