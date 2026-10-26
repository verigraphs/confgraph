"""JunOS ``delete`` / ``deactivate`` paths → native change ops (CCR-0214).

JunOS states a removal as a verb plus the same token path a ``set`` statement
would address:

    set    protocols bgp group RR neighbor 10.0.0.1 peer-as 65001
    delete protocols bgp group RR neighbor 10.0.0.1

:func:`~confgraph.parsers.junos_hierarchy.deletion_statements` hands that path
over already tokenized.  What is missing is the only model knowledge in the
chain: WHICH of those paths the model can actually remove, and what op shape
expresses it.  This module is that knowledge, as one declarative table.

**The table IS the partition.**  A path a row matches compiles to a change op
and simulates.  A path no row matches is not compiled, and
:class:`~confgraph.parsers.junos_parser.JunOSParser` leaves it on the CCR-0210
disclosure channel, where it reads as content the engine could not act on.
There is no third outcome and no silent one: adding support for the next
deletable path is one row here, and forgetting to add it costs a disclosure,
never a wrong answer.

Every emitted shape must be one the merger already dispatches — an op shape
nothing claims is applied as a SILENT no-op while coverage still attributes the
area, which is a false green (CCR-0212's disease).  That constraint is not
documentation: ``confgraph-entrp``'s cross-repo guard test imports
:data:`JUNOS_DELETION_RULES`, builds each row's :attr:`JunOSDeletionRule.sample`
through the real parser, and fails if any resulting op selects no handler.

Deliberately OUT of the table, each for a stated reason rather than oversight:

``delete protocols bgp group RR export POLICY`` (and any other group-scope
    FIELD reset)
    ``export`` IS modelled (``BGPPeerGroup.route_map_out``), but group→member
    inheritance is flattened at parse with no provenance, so clearing the group
    object would leave every member neighbour holding the baked-in inherited
    value — a silent partial apply, strictly worse than disclosure.  Reopening
    this needs inheritance provenance in the model, not a row here.
``delete interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/30``
    primary interface-address removal is unmodelled at both layers
    ([[CCR-0218]]); a row would emit an op the merger drops.
``delete interfaces ge-0/0/0`` (whole port, no ``unit``)
    the merger WOULD handle it — ``_del_interface`` fans a parent name out over
    its ``<parent>.<unit>`` children — so this is one row away, deliberately
    left for the measurement that adds it rather than smuggled in here.
``delete routing-instances CUST …``
    every row below addresses the global routing instance; a routing-instance
    scope needs the vrf captured out of the path, which is one more row shape.
a removal the same document later RE-STATES
    ``delete … group RR`` followed by ``set … group RR …`` is a stanza
    rewrite, not a removal — see :func:`collides_with_later_set`. This one is
    not about the table's coverage: the path IS modelled, and the statement
    still does not compile, because what the document means as a whole is
    something the model cannot hold.
``activate`` / ``replace`` / ``rename`` / ``insert`` / ``copy`` / the brace
    ``inactive:`` and ``replace:`` statement tags
    not removals, or not expressible from a model that holds only the running
    configuration (see ``junos_hierarchy.DELETION_VERBS``).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from confgraph.change_ir import ChangeOp, Verb

__all__ = [
    "ANY",
    "DeletionScope",
    "JunOSDeletionRule",
    "JUNOS_DELETION_RULES",
    "collides_with_later_set",
    "compile_deletion",
    "match_rule",
]


#: Pattern wildcard: matches exactly one token and captures it.  Spelled as a
#: name rather than ``None`` inline so a row reads as a path.
ANY: None = None


@dataclass(frozen=True)
class DeletionScope:
    """What the PROPOSAL itself says about the instance its deletions address.

    JunOS keeps the autonomous-system number in ``routing-options``, outside
    ``protocols bgp``, so a proposal that only deletes BGP state legitimately
    states no ASN at all.  :attr:`asn` is then the empty-string SENTINEL, and
    the merger resolves it against the baseline (sole instance in the vrf
    scope, or a refusal) rather than the engine inventing a number — the same
    rule [[CCR-0212]] established for ASN-less additive BGP proposals.  ``vrf``
    uses ``""`` for the global instance, as every other op path does.
    """

    asn: str = ""
    vrf: str = ""


@dataclass(frozen=True)
class JunOSDeletionRule:
    """One modelled deletion path and the op it compiles to.

    ``pattern`` is matched against the canonical token path, element for
    element and EXACT IN LENGTH: a literal string must equal its token, and
    :data:`ANY` matches one token and captures it.  Exact length is what keeps
    the partition honest — ``delete protocols bgp group RR export POLICY`` is
    six tokens and matches neither the six-token neighbour row (whose fifth
    element is the literal ``neighbor``) nor the four-token group row, so it
    stays disclosed instead of being half-applied as a group delete.

    ``build`` receives the captured tokens in pattern order plus the
    :class:`DeletionScope` and returns ``(verb, path)``.

    ``sample`` is a real statement this row matches.  It is what the parity and
    cross-repo guard tests run, so a row cannot be added without a working
    example of itself, and a row whose op shape nothing dispatches fails before
    it can go silent.
    """

    pattern: tuple[str | None, ...]
    build: Callable[[tuple[str, ...], DeletionScope], tuple[Verb, tuple[str, ...]]]
    sample: str


# --------------------------------------------------------------------------
# Op builders — one per row.  Each returns (verb, path) and nothing else; the
# ChangeOp wrapper (provenance, origin) is applied once, in compile_deletion.
# --------------------------------------------------------------------------

def _bgp_neighbor_delete(
    caps: tuple[str, ...], scope: DeletionScope
) -> tuple[Verb, tuple[str, ...]]:
    """``delete protocols bgp group <G> neighbor <IP>`` → drop that session.

    The group name is captured but unused: on JunOS a neighbour lives in
    exactly one group, and the model keys neighbours by peer address, so the
    group is addressing detail rather than part of the identity.
    """
    _group, peer = caps
    return Verb.OBJECT_DELETE, ("bgp_instance", scope.asn, scope.vrf, "neighbor", peer)


def _bgp_group_delete(
    caps: tuple[str, ...], scope: DeletionScope
) -> tuple[Verb, tuple[str, ...]]:
    """``delete protocols bgp group <G>`` → drop the group AND its members.

    Deleting a JunOS group deletes the neighbours written inside it, which is
    exactly what this op shape (the merger's "Candidate-B" peer-group delete)
    already does for the Cisco ``no neighbor <G> peer-group`` spelling.
    """
    (group,) = caps
    return (
        Verb.OBJECT_DELETE,
        ("bgp_instance", scope.asn, scope.vrf, "field", "neighbor", group, "peer_group"),
    )


def _static_route_delete(
    caps: tuple[str, ...], scope: DeletionScope
) -> tuple[Verb, tuple[str, ...]]:
    """``delete routing-options static route <DEST>`` → withdraw the route.

    The destination alone, with no next-hop segment: JunOS writes the
    next-hops inside the route, so deleting the route removes all of them, and
    the merger's static removal already treats a missing next-hop spec as
    "every route to this destination".
    """
    (dest,) = caps
    return Verb.LIST_REMOVE, ("static", scope.vrf, dest)


def _interface_unit_delete(
    caps: tuple[str, ...], scope: DeletionScope
) -> tuple[Verb, tuple[str, ...]]:
    """``delete interfaces <IFD> unit <N>`` → drop the logical interface.

    JunOS logical interfaces are modelled under their device-visible name
    ``<ifd>.<unit>`` (``junos_parser`` builds them that way), so the unit
    delete addresses the interface object directly.
    """
    ifd, unit = caps
    return Verb.OBJECT_DELETE, ("interface", f"{ifd}.{unit}")


#: THE table.  Row order carries no meaning: every pattern is exact-length and
#: anchored on literal segments, so at most one row can match a path (pinned by
#: the parity test, which also fails on two rows sharing a pattern).
JUNOS_DELETION_RULES: tuple[JunOSDeletionRule, ...] = (
    JunOSDeletionRule(
        pattern=("protocols", "bgp", "group", ANY, "neighbor", ANY),
        build=_bgp_neighbor_delete,
        sample="delete protocols bgp group RR neighbor 10.0.0.1",
    ),
    JunOSDeletionRule(
        pattern=("protocols", "bgp", "group", ANY),
        build=_bgp_group_delete,
        sample="delete protocols bgp group RR",
    ),
    JunOSDeletionRule(
        pattern=("routing-options", "static", "route", ANY),
        build=_static_route_delete,
        sample="delete routing-options static route 10.99.0.0/24",
    ),
    JunOSDeletionRule(
        pattern=("interfaces", ANY, "unit", ANY),
        build=_interface_unit_delete,
        sample="delete interfaces ge-0/0/0 unit 0",
    ),
)


def match_rule(
    path: tuple[str, ...]
) -> tuple[JunOSDeletionRule, tuple[str, ...]] | None:
    """The rule *path* matches and the tokens it captures, or None.

    None is the unmodelled half of the partition — the caller discloses.
    """
    for rule in JUNOS_DELETION_RULES:
        if len(path) != len(rule.pattern):
            continue
        if any(
            expected is not ANY and expected != token
            for expected, token in zip(rule.pattern, path)
        ):
            continue
        captures = tuple(
            token for expected, token in zip(rule.pattern, path) if expected is ANY
        )
        return rule, captures
    return None


def collides_with_later_set(
    path: tuple[str, ...],
    line_no: int,
    set_statements: list[tuple[int, str, tuple[str, ...]]],
) -> bool:
    """True when this deletion is really half of a stanza REWRITE.

    JunOS applies the statements in a candidate configuration IN ORDER, so

        delete protocols bgp group RR
        set protocols bgp group RR type internal
        set protocols bgp group RR neighbor 10.255.0.9

    does not remove the group — it rebuilds it, and the sessions that survive
    the commit are the ones the new statements describe.  Same for the standard
    way to move a static route (``delete`` it, then ``set`` it with a new
    next-hop).  Those are the two commonest JunOS rewrite idioms, and the model
    has no way to express "removed and then re-created with different
    contents": applying the deletion alone reports a confident teardown of
    something the device would still have.  So a deletion in that shape does
    not compile at all, and falls back to the disclosure channel — the project
    rule that a wrong simulation is worse than an honest "could not read this".

    ORDER IS LOAD-BEARING, which is why this takes *line_no* rather than just
    comparing paths. The reverse document order

        set    protocols bgp group RR neighbor 10.255.0.1 peer-as 64512
        delete protocols bgp group RR neighbor 10.255.0.1

    is a REMOVAL on a device — the statement is written and then withdrawn —
    and the deletion op already produces exactly that, so guarding it too would
    throw away a correct answer. Only a ``set`` AFTER the deletion line
    collides.

    Collision is "equal to, or a prefix of": a ``set`` deeper under the deleted
    path re-creates it (``delete … group RR`` then
    ``set … group RR type internal``), while a ``set`` that merely shares an
    ANCESTOR does not (``delete … group RR neighbor 10.0.0.1`` beside
    ``set … group RR type external`` is a genuine removal plus an unrelated
    edit, and the paths diverge before either ends).
    """
    return any(
        set_line_no > line_no and set_path[: len(path)] == path
        for set_line_no, _line, set_path in set_statements
    )


def compile_deletion(
    path: tuple[str, ...],
    scope: DeletionScope,
    *,
    source_line: str,
    line_no: int,
) -> ChangeOp | None:
    """The native change op for a deletion *path*, or None when unmodelled.

    ``origin="native"`` is what makes the op real provenance rather than a
    guess reconstructed from state: the merger's ordered-replay passes and the
    classifier both gate on it.
    """
    matched = match_rule(path)
    if matched is None:
        return None
    rule, captures = matched
    verb, op_path = rule.build(captures, scope)
    return ChangeOp(
        verb=verb,
        path=op_path,
        value=None,
        source_line=source_line,
        line_no=line_no,
        origin="native",
    )
