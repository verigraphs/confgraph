"""Network configuration parsers.

``PARSER_BEHAVIOR_VERSION`` is a monotonic integer that identifies the observable
behavior of the parsers as a whole. Consumers key parse caches and input digests on
it (the platform parse cache folds it into its cache key as ``::pbv=<n>``; CCR-0082's
gate digest keys carry it as their parser-version input) so that a behavior-only
change — one that alters parse output for some OS but leaves the ``ParsedConfig``
JSON schema, the package version, and the pydantic version all unchanged — still
invalidates stale hits. Those three signals are already caught by the existing key
components; this constant closes the remaining hole.

Maintenance rule (review-checklist discipline, mirroring confgraph-entrp's
``STATE_SCHEMA_VERSION`` practice): bump ``PARSER_BEHAVIOR_VERSION``
in the same commit as the behavior change. A behavior change is ANY change that can alter parse
output for ANY OS without a corresponding ``ParsedConfig`` JSON-schema change —
parser bug fixes, new syntax support, normalization changes, and model-semantic
changes that are invisible to the schema all count. It is one shared integer across
all OS parsers by design; per-OS granularity was explicitly rejected in CCR-0097.
A missed bump means consumers serve stale cache hits, i.e. a wrong parse — so the
bump is not optional for a qualifying change.
"""

from confgraph.parsers.base import BaseParser, ParseError
from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.eos_parser import EOSParser
from confgraph.parsers.nxos_parser import NXOSParser
from confgraph.parsers.iosxr_parser import IOSXRParser
from confgraph.parsers.junos_parser import JunOSParser
from confgraph.parsers.panos_parser import PANOSParser

# 2 (CCR-0129): NX-OS ``ip dhcp relay address`` re-homed from the retired
# ``InterfaceConfig.dhcp_relay_addresses`` onto ``helper_addresses``.  A bump is not
# strictly REQUIRED by the rule above (the field removal also moves the ParsedConfig
# JSON schema, which the platform parse cache keys on independently), but
# confgraph-entrp's gate ``digest_key()`` carries pbv with NO schema component, so this
# is the only signal that moves there — and over-keying is the documented posture.
# 3 (CCR-0146): IOS/IOS-XE ``no bgp default ipv4-unicast`` now parses onto the new
# ``BGPConfig.default_ipv4_unicast`` field — observable parse output moves (a config
# that disables the default now yields False instead of the silent old True).  Same
# posture as the CCR-0129 bump: the new field also moves the ParsedConfig JSON schema
# (so the platform parse cache invalidates independently and a bump is not strictly
# required), but entrp's schema-less ``digest_key()`` only moves on pbv, so we bump.
# 4 (CCR-0165): ``BGPNeighborAF.activate`` is tri-state — EOS policy-only AF
# entries now parse activate=None (unstated) instead of False, and the
# block-presence OSes assert True explicitly. Schema also moves (bool -> bool|None),
# but entrp's schema-less ``digest_key()`` only moves on pbv — same posture as 2/3.
# Also under 4: the shared IOS/EOS AF walk no longer emits an EMPTY BGPNeighborAF
# for a peer whose only AF-block lines are vocabulary-invisible (13 such commands
# measured) — deliberate; a real config's ``activate`` line keeps the entry.
# 5 (CCR-0166): ``VXLANVniMapping`` distinguishes DECLARED bindings from parser
# joins — new ``binding_declared`` (True on EOS's two Vxlan1 binding forms) and
# ``associate_vrf`` (typed; NX-OS L3VNI membership) fields, and the NX-OS
# ``"(L3)"`` vrf sentinel is RETIRED (those entries now parse vrf=None,
# associate_vrf=True). Observable parse output moves for every NX-OS VTEP with
# an associate-vrf member; schema also moves, but entrp's schema-less
# ``digest_key()`` only moves on pbv — same posture as 2/3/4.
# 6 (CCR-0170): ``BGPNeighbor.remote_as`` / ``BGPPeerGroup.remote_as`` are
# ``int | None`` — a model validator normalizes asdot (RFC 5396) to int and
# REJECTS every other string (the old ``int | str`` union was fail-open:
# any non-int spelling silently bypassed all AS-agreement checks).  New
# ``remote_as_source`` provenance field on both models; the CCR-0159
# "inherited" sentinel and JunOS internal/external string arms retire onto
# it.  Observable parse output moves for every peer-group member, every
# asdot config, and every internal/external peer type; schema also moves,
# but entrp's schema-less ``digest_key()`` only moves on pbv — same
# posture as 2/3/4/5.
# 7 (CCR-0192): DHCP interface addressing parses onto the new
# ``InterfaceConfig.dynamic_address`` field instead of being recognized and
# discarded (IOS/IOS-XE/EOS/NX-OS ``ip address dhcp``, IOS-XR ``ipv4 address
# dhcp``, JunOS ``family inet { dhcp; }``, PAN-OS ``<dhcp-client>``).
# Observable parse output moves for every DHCP-addressed interface; the new
# field also moves the ParsedConfig JSON schema (so the platform parse cache
# invalidates independently and a bump is not strictly required), but entrp's
# schema-less ``digest_key()`` only moves on pbv — same posture as 2/3/4/5/6.
# 8 (CCR-0202): withdrawal-gap fixes move observable parse output on three
# fronts — the IOS-XR neighbor-AF ATTACH filter is outcome-based (an AF block
# whose only content is a boolean flag — an RR's ``route-reflector-client``
# — now attaches instead of being dropped), XR emits neighbor negations and
# NESTED_DELETION_RULES tombstones/ops for the first time, EOS emits the
# CIDR-form OSPF network removal, and the redistribute negation rule accepts
# operand tails.  The attach fix is the sharp case for this constant: it
# changes parsed MODELS with NO ParsedConfig JSON-schema change whatsoever,
# so pbv is the ONLY signal that invalidates the platform parse cache and
# entrp's digest keys for it.
# 9 (CCR-0210 + CCR-0212, co-landed): two JunOS honesty changes plus a PAN-OS
# message fix. CCR-0210 — the non-``set`` verb family (``delete``,
# ``deactivate``, …) and the brace idiom's ``inactive:`` / ``replace:``
# statement tags are DISCLOSED as UnrecognizedBlocks instead of being dropped,
# and ``_is_set_style`` counts the verb family so a delete-only proposal routes
# to the set idiom rather than becoming a garbage brace subtree. Observable
# parse output moves for every JunOS document carrying such a line, with NO
# ParsedConfig JSON-schema change — the sharp case pbv exists for. CCR-0212 —
# ``BGPConfig.asn`` is ``int | None`` and the JunOS parser emits None instead of
# fabricating AS 0 when ``routing-options autonomous-system`` is absent (the
# iBGP peer's inherited ``remote_as`` follows it to None); the schema also moves,
# but entrp's schema-less ``digest_key()`` only moves on pbv — same posture as
# 2/3/4/5/6/7.
# 10 (CCR-0211): three fabricated defaults retire — ``RIPConfig.version``,
# ``VLANEntry.state`` and ``ClassMapConfig.match_type`` are set only when the
# config states them (the IOS walk stamped 1, "active" and "match-all"
# unconditionally).  Under the new field-level keyed merge a fabricated default
# is indistinguishable from an explicit restate, so ``version 2`` over a
# baseline ``version 1`` — or ``class-map match-all X`` over a ``match-any``
# baseline — silently lost.  Observable parse output moves for every
# IOS/IOS-XE/EOS/NX-OS config with a ``router rip`` block, a VLAN block that
# omits ``state``, or a ``class-map`` line that omits the mode — the COVERED
# fidelity family, which is why this is a bump and not a schema-only change.
# Persisted baseline snapshots are invalidated by the pbv move itself (it is a
# digest-key component), which subsumes the Tier-A digest shift these fields
# cause.
# 11 (CCR-0222): ``InterfaceConfig.ospf_passive`` becomes tri-state
# (``bool | None``, default None) and the shared interface walk extracts BOTH
# polarities of the per-interface ``[no] ip ospf passive-interface`` override
# (NX-OS/EOS inherit it).  Observable parse output moves three ways: every
# interface that says nothing now reads None rather than False; an interface
# exempted from a process-level ``passive-interface default`` reads an explicit
# False and gains a native SET op for it (False != the new default); and the
# ``no`` line it was emitting as an UnrecognizedBlock disappears, claimed by
# that op's line provenance (CCR-0203 ledger).  No ParsedConfig JSON-schema
# change beyond the field's own type, so pbv is what invalidates the platform
# parse cache and entrp's digest keys.
# 12 (CCR-0227): OSPF area IDs are CANONICALIZED at parse to the decimal
# spelling, by one shared ``canonical_area_id`` applied via model validators on
# all four storage points (OSPFArea.area_id, OSPFInterfaceConfig.area_id,
# InterfaceConfig.ospf_area, the area half of OSPFConfig.network_statements).
# `0.0.0.0` and `0` are the same area on hardware; stored raw they were two
# keys, so every mixed-vendor estate (NX-OS/JunOS dotted, IOS/IOS-XR decimal)
# modelled one real area as two — no adjacency across the spellings and wrong
# ABR/inter-area computation. Observable parse output moves for every config
# that spells an area as a dotted quad, with NO ParsedConfig JSON-schema
# change — the sharp case this constant exists for. Decimal is canonical
# precisely so the existing tombstone/golden keys (`ospf:1:area:0:...`) do not
# move.
# 13 (CCR-0227 completion): the two OPS-ONLY area-scoped removals —
# ``no network A W area <aid>`` (and the EOS ``no network A/M area <aid>``
# twin) and ``no area <aid> range A M`` — build their LIST_REMOVE key
# directly in the parser rather than through the tombstone registry, and were
# left spelling the area as the proposal wrote it while 12 made storage
# canonical. A dotted withdrawal therefore addressed an area that no longer
# existed under that spelling and removed NOTHING, silently — including the
# dotted-baseline/dotted-proposal pair that worked before 12. The removal key
# and the refresh-suppression map on both sides of each walk are now
# canonical. Observable parse output moves (those op paths) with no schema
# change. Bumped rather than riding 12 — unreleased though 12 is, the rule in
# this module's header is per-commit and not optional for a qualifying
# change, and deciding otherwise would mean re-deriving "was the predecessor
# released?" at every review.
# 14 (CCR-0217): the JunOS brace branch of ``unsupported_lines`` is fail-closed
# on the parse OUTCOME — a document routed to the brace tokenizer that yields
# an EMPTY canonical tree while carrying at least one non-blank
# comment-stripped line discloses those lines as UnrecognizedBlocks instead of
# returning silence. The hole was the document with no JunOS idiom in it at all
# (Cisco ``no`` commands, an IOS ``interface`` block): zero set-family lines
# routes it brace-ward, every statement is discarded at EOF for want of a ``;``
# or ``{``, and the result read "no recognized configuration change" for text
# that plainly requested one — the last silent arm of CCR-0210's fail-closed
# story, modulo the CCR-0236 mixed-document residual. Observable parse output
# moves for every such document, with NO ParsedConfig JSON-schema change — the
# sharp case this constant exists for. Comment-only and whitespace-only
# documents carry no content and stay silent; ``inactive:``-only documents
# parse non-empty and keep their existing tag disclosure.
# 15 (CCR-0214): JunOS ``delete`` / ``deactivate`` statements on MODELLED
# paths compile to native change ops instead of being disclosed. JunOS emitted
# no deletion artifact of any kind before this — no tombstones (the grammar is
# Cisco syntax throughout) and no ops — so a withdrawal, the most outage-prone
# change class on the OS, could only ever be reported as content the engine
# could not read. The modelled set is one declarative table
# (``parsers/junos_deletions.py``): a BGP neighbour, a whole BGP group, a
# static route, an interface unit. Every path outside it stays on the CCR-0210
# disclosure channel, so nothing became silent and nothing is half-applied;
# ``deactivate`` compiles to the same op as ``delete`` because an inactive
# subtree makes no contribution to the running configuration, which is the
# only configuration the model holds. Observable parse output moves for any
# JunOS document carrying one of those statements —
# ``native_change_ops`` gains entries and ``unrecognized_blocks`` loses the
# matching lines — with NO ParsedConfig JSON-schema change. No BASELINE moves:
# a saved configuration states no deletion verb (the brace idiom has none),
# and the ``inactive:`` statement tag is untouched and still disclosed.
# 16 (CCR-0214, validation round 1 finding R1): a JunOS removal that the SAME
# document later re-states no longer compiles — it falls back to the CCR-0210
# disclosure channel. JunOS applies candidate statements in order, so
# ``delete protocols bgp group RR`` followed by ``set protocols bgp group RR …``
# rebuilds the group rather than removing it, and the same idiom moves a static
# route to a new next-hop. Those are the two commonest JunOS rewrite idioms, and
# compiling the deletion alone reported a confident teardown of something the
# device would still have — measured in validation as a CRITICAL full-teardown
# verdict on a group rebuild. The guard is order-aware (``set`` strictly AFTER
# the deletion line, at an equal or deeper path): the reverse order really is a
# removal on a device, so it still compiles. Observable parse output moves for
# any JunOS document mixing a removal with a later restatement of the same
# path — ``native_change_ops`` loses that op and ``unrecognized_blocks`` gains
# the line back — with NO ParsedConfig JSON-schema change, and no baseline
# motion (a saved configuration states no deletion verb).
# 17 (CCR-0239 + CCR-0240, bump landed late — caught at the v0.3.9 release
# audit, 2026-11-06): both landings changed parse output without moving this
# constant, so PBV-16 parse-cache blobs minted before them could be served as
# hits carrying the pre-fix models. CCR-0239: NX-OS named OSPF instance tags
# (``ip router ospf CORE area …``) enroll their interfaces — previously the
# named-instance spelling bound nothing, so those interfaces were
# OSPF-invisible. CCR-0240: IOS-XR OSPF passive resolves at all four scopes
# (process default, area, interface ``passive enable`` AND ``passive
# disable``) — previously the process-scope default was hardwired False and
# ``passive disable`` was not in the vocabulary, so suppressed interfaces
# formed phantom adjacencies while exempted uplinks read as suppressed.
# Observable parse output moves for any NX-OS config using named instance
# tags and any IOS-XR config using process/area-scope passive — BASELINES
# included (both spellings exist in saved configurations). No ParsedConfig
# JSON-schema change.
PARSER_BEHAVIOR_VERSION: int = 17

__all__ = [
    "BaseParser",
    "ParseError",
    "IOSParser",
    "EOSParser",
    "NXOSParser",
    "IOSXRParser",
    "JunOSParser",
    "PANOSParser",
    "PARSER_BEHAVIOR_VERSION",
]
