"""Change-IR — operation-based representation of proposal intent (Phase 0).

CCR: ``change_ir_proposal_operations.md`` (platform ``_internal_docs/core_change_requests/``).

A change script is a sequence of commands ("what to DO"); the legacy pipeline
parses it into a ``ParsedConfig`` state snapshot ("what the config IS") plus a
side-channel of string tombstones (``no_commands``).  The Change-IR replaces
that representation with an ordered list of :class:`ChangeOp` operations.

Phase 0 (this module) is **shadow mode**: it defines the IR types plus a
*derivation adapter* that mechanically translates the EXISTING parse artifacts
(non-default fields, every tombstone family, trunk-VLAN delta strings,
unrecognized-line records) into ops, and an exact inverse
(:func:`encode_legacy`) used by the round-trip CI check and, later, by the
Phase-4 OSS deprecation shim.  Nothing consumes ops yet — the deriver encodes
today's semantics exactly, including today's blind spots.

Design decisions (documented per CCR §2)
-----------------------------------------
UNRECOGNIZED marker
    Unparseable/unclaimed config still produces a record.  We encode it as a
    **sentinel verb** (``Verb.UNRECOGNIZED``) rather than a separate marker
    class, so a ``ChangeSet`` stays a homogeneous ``list[ChangeOp]`` for every
    consumer.  ``UNRECOGNIZED`` is a *marker*, not an action: ``value`` carries
    the ``UnrecognizedBlock`` and ``source_line`` carries the block header.

Derived deletion paths mirror legacy tombstones 1:1
    For ops derived from tombstones, ``path`` is the exact colon-split of the
    legacy tombstone string (including transport prefixes such as ``field:``,
    ``process:``, ``singleton:``).  This makes :func:`encode_legacy` a pure
    ``":".join(path)`` — byte-exact by construction for every family,
    including values that themselves contain colons (route-targets, IPv6
    peers, channelized interface next-hops).  Phase-3 native emission will
    switch to clean model paths; the transport prefixes die with the deriver.

    Tombstones scoped to a BGP instance (``BGPConfig.no_commands``) carry a
    ``("bgp_instance", <asn>, <vrf-or-"">)`` path prefix so the encoder can
    return each tombstone to the correct scoped container.  Interface-scoped
    tombstones need no prefix: their shapes (``field:interface:<name>:<attr>``
    with exactly 4 segments, and the 6-segment trunk-VLAN delta ops) are
    disjoint from every top-level shape, so container routing is inferable
    from the path alone (see ``_is_interface_scoped_path``).

Verb mapping policy for legacy tombstones
    - ``OBJECT_DELETE``: the target is an entry in a *top-level* ParsedConfig
      collection of keyed config objects (interfaces, vrfs, routing
      processes, ACLs, VLAN entries, IP SLA ops, tracks, EEM applets).
    - ``LIST_REMOVE``: the target is a member of a list *nested inside*
      another object (ntp.servers, snmp.communities, vrf route-targets,
      interface helper addresses, BGP AF redistribute, ACE/route-map/
      prefix-list sequences, dhcp pools, bfd templates, vxlan VNIs, …).
      Exception (documented): static routes are top-level but map to
      ``LIST_REMOVE`` — the NH-less form removes *all* routes for a prefix,
      which is a keyed-member wildcard removal, not a single-object delete.
    - ``UNSET``: scalar field resets (``field:<section>:<field>``, banner
      fields, VRF rd, OSPF area type resets, per-interface/per-neighbor field
      resets) and ``singleton:<field>`` whole-section null-outs.
    - ``LIST_ADD`` / ``LIST_REMOVE``: trunk allowed-VLAN delta ops
      (``…:trunk_allowed_vlans:add|remove:<spec>``).  The never-emitted (but
      merger-supported) ``except`` form maps to ``SET`` (it is an absolute
      replacement); its op still routes back to the interface container.
    - Unknown/future tombstone shapes fall back to ``UNSET`` with the full
      split path — lossless, and Phase-1 shadow diffing will surface them.

Known deriver limitations (fixed by Phase-3 native emission)
    - ``source_line`` cannot be recovered from state artifacts.  Deletion ops
      carry the tombstone string itself; SET ops carry the owning block's
      first raw line when available.  ``line_no`` is ``-1`` when unknown.
    - Op *order* within the ChangeSet is canonical (SET ops, BGP-scoped
      deletions, top-level deletions, interface-scoped deletions,
      UNRECOGNIZED markers) — mirroring the legacy merge's apply order
      (additive pass, then deletions) rather than script line order, which
      the state artifacts no longer retain.
    - SET granularity mirrors today's merge semantics: field-level for
      interfaces (the legacy field-selective merge), object-level for keyed
      top-level collections and singletons.  List-union / sub-collection
      subtleties remain the merger's business until Phase 1.
    - Provenance metadata fields (``object_id``, ``raw_lines``,
      ``line_numbers``, ``source_os``) and ``hostname`` do not produce SET
      ops — they are not config intent.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field as dc_field
from enum import Enum
from functools import lru_cache as _lru_cache
from typing import Any, Callable, TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from confgraph.models.parsed_config import ParsedConfig

__all__ = [
    "Verb",
    "ChangeOp",
    "ChangeSet",
    "LegacyArtifacts",
    "derive_ops",
    "encode_legacy",
    "is_interface_scoped_path",
    "interface_scalar_fields",
    "interface_list_replace_fields",
    "service_entity_list_fields",
    "service_entity_singleton_fields",
    "banner_scalar_fields",
    "service_entity_key",
    "is_native_service_entity_op",
    "static_route_fields",
    "static_route_key",
    "is_native_static_op",
    "bgp_neighbor_fields",
    "bgp_neighbor_key",
    "bgp_peer_group_key",
    "bgp_network_key",
    "bgp_redistribute_key",
    "bgp_af_key",
    "bgp_af_network_key",
    "bgp_af_aggregate_key",
    "is_native_bgp_op",
    "is_native_bgp_network_removal_op",
    "is_native_bgp_af_aggregate_removal_op",
    "is_native_bgp_instance_create_op",
]


class Verb(Enum):
    """Operation verbs (CCR §2) plus the UNRECOGNIZED sentinel marker."""

    SET = "set"                      # scalar/field/object assignment (explicit, even to default)
    UNSET = "unset"                  # remove/reset a field ("no <cmd>")
    LIST_ADD = "list_add"            # add member to an unordered/keyed collection
    LIST_REMOVE = "list_remove"      # remove member (by identity key)
    OBJECT_DELETE = "object_delete"  # remove a whole keyed object (interface, vrf, process, sla, …)
    BLOCK_REPLACE = "block_replace"  # atomic named-object replacement (XR/JunOS/PAN-OS; unused in Phase 0)
    UNRECOGNIZED = "unrecognized"    # MARKER, not an action: "we could not read this line/block"


@dataclass(frozen=True)
class ChangeOp:
    """One operation in a change script.

    Attributes:
        verb:        What the operation does (or ``Verb.UNRECOGNIZED`` marker).
        path:        Keyed addressing, e.g. ``("interface", "GigabitEthernet0/1",
                     "lldp_transmit")``.  For tombstone-derived deletion ops this
                     is the exact colon-split of the legacy tombstone (see module
                     docstring).
        value:       Payload for SET / LIST_ADD / BLOCK_REPLACE (model object,
                     scalar, or spec string); ``UnrecognizedBlock`` for markers.
        source_line: Verbatim config line when known; best-effort reconstruction
                     (tombstone string / block first line) in Phase 0.
        line_no:     1-based config line number, ``-1`` when unknown.
        origin:      ``"native"`` for ops the parser emitted directly from a
                     command line (Phase 3 — real provenance, migrated family),
                     ``"derived"`` for ops translated from legacy state
                     artifacts by :func:`derive_ops`.  This is the
                     discriminator consumers gate on: for native ops,
                     op-existence == "the command was written" (structural),
                     so e.g. the classifier counts them touched without the
                     legacy ``_is_set`` value heuristic.  Provenance fields
                     are NOT a reliable discriminator (derived SET ops carry
                     real block line numbers too).
    """

    verb: Verb
    path: tuple[str, ...]
    value: Any = None
    source_line: str = ""
    line_no: int = -1
    origin: str = "derived"


# Ordered — device apply order is semantic (Phase 0 deriver emits canonical
# order; see "Known deriver limitations" above).
ChangeSet = list[ChangeOp]


# ---------------------------------------------------------------------------
# Tombstone-family → verb registries
# ---------------------------------------------------------------------------
# Mirrors the consumption vocabulary in confgraph-entrp merger._DELETION_RULES
# and merger._FIELD_PATH_ACCESSORS.  First match wins — specific shapes MUST
# precede generic catch-alls (same discipline as the merger registries).

_TOP_TOMBSTONE_VERBS: tuple[tuple[re.Pattern[str], Verb], ...] = (
    # --- non-"field:" families (merger._DELETION_RULES prefixes) ---
    (re.compile(r"^interface:"), Verb.OBJECT_DELETE),          # whole interface (+subifs)
    (re.compile(r"^static:"), Verb.LIST_REMOVE),               # static route(s) by (vrf, dest[, nh])
    (re.compile(r"^vlan:"), Verb.OBJECT_DELETE),               # VLAN database entry
    (re.compile(r"^vrf:"), Verb.OBJECT_DELETE),                # IOS-XR whole-VRF removal
    (re.compile(r"^process:(ospf|bgp|isis|eigrp):"), Verb.OBJECT_DELETE),
    (re.compile(r"^acl-seq:"), Verb.LIST_REMOVE),              # single ACE
    (re.compile(r"^acl:"), Verb.OBJECT_DELETE),                # whole named ACL
    (re.compile(r"^route-map:.+:seq:\d+$"), Verb.LIST_REMOVE),
    (re.compile(r"^route-map:"), Verb.OBJECT_DELETE),          # IOS-XR whole route-policy
    (re.compile(r"^prefix-list:.+:seq:\d+$"), Verb.LIST_REMOVE),
    (re.compile(r"^prefix-list:"), Verb.OBJECT_DELETE),        # IOS-XR whole prefix-set
    (re.compile(r"^singleton:\w+$"), Verb.UNSET),              # whole-section null-out
    # --- "field:" families (merger._FIELD_PATH_ACCESSORS shapes) ---
    (re.compile(r"^field:bgp:\d+:af:\w+:redistribute:"), Verb.LIST_REMOVE),
    (re.compile(r"^field:interface:[^:]+:(helper|nhrp_nhs):"), Verb.LIST_REMOVE),
    (re.compile(r"^field:ospf:[^:]+:area:[^:]+:(stub_reset|nssa_reset)$"), Verb.UNSET),
    (re.compile(r"^field:ntp:(server|peer|auth_key):"), Verb.LIST_REMOVE),
    (re.compile(r"^field:snmp:(community|host|view|group|user):"), Verb.LIST_REMOVE),
    (
        re.compile(
            r"^field:aaa:(authentication|authorization|accounting"
            r"|tacacs_named|tacacs|radius_named|radius):"
        ),
        Verb.LIST_REMOVE,
    ),
    (re.compile(r"^field:syslog:host:"), Verb.LIST_REMOVE),
    (re.compile(r"^field:dns:(name_server|domain):"), Verb.LIST_REMOVE),
    (re.compile(r"^field:netflow:destination:"), Verb.LIST_REMOVE),
    (re.compile(r"^field:dhcp:(pool|excluded):"), Verb.LIST_REMOVE),
    (re.compile(r"^field:vxlan:vni:"), Verb.LIST_REMOVE),
    (re.compile(r"^field:multicast:(rp|msdp):"), Verb.LIST_REMOVE),
    (re.compile(r"^field:bfd:template:"), Verb.LIST_REMOVE),
    (re.compile(r"^field:lldp:tlv:"), Verb.LIST_REMOVE),
    # VRF shapes — WI-7 RT removals, rd reset, whole-VRF delete (order matters)
    (re.compile(r"^field:vrfs:[^:]+:route_target_(import|export|both):"), Verb.LIST_REMOVE),
    (re.compile(r"^field:vrfs:[^:]+:rd$"), Verb.UNSET),
    (re.compile(r"^field:vrfs:[^:]+$"), Verb.OBJECT_DELETE),
    # Service entity removals — WI-8 (top-level keyed collections)
    (re.compile(r"^field:ip_sla_operations:\d+$"), Verb.OBJECT_DELETE),
    (re.compile(r"^field:object_tracks:\d+$"), Verb.OBJECT_DELETE),
    (re.compile(r"^field:eem_applets:[^:]+$"), Verb.OBJECT_DELETE),
    # Generic scalar-field reset — MUST BE LAST among field: shapes.  Serves
    # field:banners:<field>, field:vpc:<field>, field:vxlan:host_reachability, …
    (re.compile(r"^field:\w+:\w+$"), Verb.UNSET),
)

# Interface-scoped trunk allowed-VLAN delta ops (F2).  ``except`` is supported
# by the merger but never emitted by any parser — mapped to SET (absolute
# replacement) for completeness.
_TRUNK_OP_RE = re.compile(
    r"^field:interface:.+:trunk_allowed_vlans:(?P<op>add|remove|except):(?P<spec>[\d,\-]+)$"
)
_TRUNK_OP_VERB = {
    "add": Verb.LIST_ADD,
    "remove": Verb.LIST_REMOVE,
    "except": Verb.SET,
}


def _verb_for_top_tombstone(tombstone: str) -> Verb:
    for pattern, verb in _TOP_TOMBSTONE_VERBS:
        if pattern.match(tombstone):
            return verb
    # Unknown/future family — lossless fallback (see module docstring).
    return Verb.UNSET


def _verb_and_value_for_interface_tombstone(tombstone: str) -> tuple[Verb, Any]:
    m = _TRUNK_OP_RE.match(tombstone)
    if m:
        return _TRUNK_OP_VERB[m.group("op")], m.group("spec")
    # Scalar field reset: field:interface:<name>:<field_name>
    return Verb.UNSET, None


def _verb_for_bgp_tombstone(tombstone: str) -> Verb:
    if tombstone.startswith("neighbor:"):
        return Verb.OBJECT_DELETE  # full neighbor removal
    # field:neighbor:<peer>:<field> — per-neighbor/peer-group field reset
    return Verb.UNSET


# ---------------------------------------------------------------------------
# SET derivation registries
# ---------------------------------------------------------------------------

# ParsedConfig fields that never produce SET ops (metadata / transport / IR).
# ("change_ops" is a private attribute today — invisible to model_fields —
#  but is kept here defensively for when it is promoted to a real field.)
_SKIP_TOP_FIELDS: frozenset[str] = frozenset(
    {
        "source_os",
        "hostname",
        "raw_config",
        "no_commands",
        "unrecognized_blocks",
        "change_ops",
        "native_change_ops",
    }
)

# Per-object metadata fields excluded from interface field-level SET emission.
_PROVENANCE_FIELDS: frozenset[str] = frozenset(
    {"object_id", "raw_lines", "line_numbers", "source_os", "no_commands", "name"}
)


@_lru_cache(maxsize=1)
def interface_scalar_fields() -> frozenset[str]:
    """Family-1 boundary: InterfaceConfig scalar/boolean field names.

    Phase-3 family 1 (CCR Appendix D) — the fields the line-based parsers
    emit NATIVE ops for.  Defined structurally so a future scalar model
    field automatically joins the family: a model field with a declared
    Pydantic default and no ``default_factory``, excluding provenance /
    identity fields (``_PROVENANCE_FIELDS`` + ``interface_type``).

    Collection-shaped fields (lists/dicts — trunk_allowed_vlans,
    secondary_ips, ipv6_addresses, FHRP groups, helper_addresses,
    nhrp_nhs/nhrp_map, igmp groups, ospf_message_digest_keys) all carry
    ``default_factory`` and are therefore excluded — they belong to later
    families.
    """
    from pydantic_core import PydanticUndefined

    from confgraph.models.interface import InterfaceConfig

    fields: set[str] = set()
    for name, info in InterfaceConfig.model_fields.items():
        if name in _PROVENANCE_FIELDS or name == "interface_type":
            continue
        if info.default_factory is not None:
            continue  # collection-shaped — later families
        if info.default is PydanticUndefined:
            continue  # required identity field — no default to compare against
        fields.add(name)
    return frozenset(fields)


@_lru_cache(maxsize=1)
def interface_list_replace_fields() -> frozenset[str]:
    """Family-2 boundary: InterfaceConfig list fields with FULL-REPLACE
    merge semantics plus stateful delta command spellings.

    Phase-3 family 2 (CCR Appendix E) — today exactly
    ``trunk_allowed_vlans``: ``switchport trunk allowed vlan <list>`` is an
    absolute replacement on the device (see the merger's
    ``_IFACE_INCREMENTAL_LISTS`` exclusion note), while un-anchored
    ``add``/``remove`` lines are stateful deltas emitted as native
    LIST_ADD/LIST_REMOVE ops.

    Unlike family 1 this boundary is an explicit set, not structural: the
    other ``default_factory`` list fields (secondary_ips, helper_addresses,
    FHRP groups, …) have union/keyed merge semantics and belong to later
    families.
    """
    return frozenset({"trunk_allowed_vlans"})


@_lru_cache(maxsize=1)
def service_entity_list_fields() -> frozenset[str]:
    """Family-3 boundary, keyed-collection half (CCR Appendix F).

    The top-level ParsedConfig collections whose WI-8 whole-entity removal
    walks carry the ``_readded_later`` suppression guard: IP SLA operations
    (``no ip sla <id>``), object tracks (``no track <id>``) and EEM applets
    (``no event manager applet <name>``).  Their merge semantics are keyed
    whole-object replace (``_SIMPLE_LIST_FIELDS`` in the engine merger).
    """
    return frozenset({"ip_sla_operations", "object_tracks", "eem_applets"})


@_lru_cache(maxsize=1)
def service_entity_singleton_fields() -> frozenset[str]:
    """Family-3 boundary, singleton half: ``banners`` (per-FIELD ops).

    ``no banner <type>`` resets one BannerConfig scalar; the native create
    side emits one ``SET ("banners", <field>)`` per non-default banner
    field so different banner types order independently against their own
    negations (a single whole-object op provably cannot — see Appendix F).
    """
    return frozenset({"banners"})


@_lru_cache(maxsize=1)
def banner_scalar_fields() -> frozenset[str]:
    """Structural walk of BannerConfig scalar fields (family 3, banners).

    Same discipline as :func:`interface_scalar_fields`: declared default,
    no ``default_factory``, provenance/identity excluded — a future banner
    type added to the model automatically joins the family.
    """
    from pydantic_core import PydanticUndefined

    from confgraph.models.banner import BannerConfig

    fields: set[str] = set()
    for name, info in BannerConfig.model_fields.items():
        if name in _PROVENANCE_FIELDS:
            continue
        if info.default_factory is not None:
            continue
        if info.default is PydanticUndefined:
            continue
        fields.add(name)
    return frozenset(fields)


def service_entity_key(field_name: str, item: Any) -> tuple[str, ...]:
    """Identity path segments for a family-3 keyed entity.

    Delegates to the same key functions the deriver uses
    (``_TOP_LIST_KEYS``), so native create-op paths are identical to the
    derived SET paths by construction (the composition dedupe relies on
    this).
    """
    return _TOP_LIST_KEYS[field_name](item)


def is_native_service_entity_op(op: "ChangeOp") -> bool:
    """True iff *op* is a parser-emitted family-3 service-entity op.

    The four shapes (all ``origin == "native"``):

    - ``SET (<list_field>, <key>)``          — entity (re)creation
    - ``SET ("banners", <field>)``           — banner field write
    - ``OBJECT_DELETE ("field", <list_field>, <key>)`` — entity removal
    - ``UNSET ("field", "banners", <field>)``          — banner field reset

    Owned by the codec module (CCR Appendix F): the engine's ordered-apply
    pass and its ``_proposal_from_ops`` skip MUST share this predicate,
    never re-implement the shapes.  Derived ops with identical paths
    return False (origin gate) and keep flowing through the batched
    legacy apply path.
    """
    if getattr(op, "origin", "derived") != "native":
        return False
    path = op.path
    if op.verb is Verb.SET and len(path) == 2:
        return (
            path[0] in service_entity_list_fields()
            or path[0] in service_entity_singleton_fields()
        )
    if len(path) == 3 and path[0] == "field":
        if op.verb is Verb.OBJECT_DELETE and path[1] in service_entity_list_fields():
            return True
        if op.verb is Verb.UNSET and path[1] in service_entity_singleton_fields():
            return True
    return False


@_lru_cache(maxsize=1)
def static_route_fields() -> frozenset[str]:
    """Family-4 boundary (CCR Appendix G): the keyed static-route collection.

    Today exactly ``static_routes`` — every IPv4 ``ip route`` / ``no ip route``
    line (global, ``vrf NAME`` IOS keyword, NX-OS ``vrf context``, EOS) that
    the shared static walk parses.  Enumerated like family 2/3 (not
    structural): a future IPv6-static model field would be added here.
    ``ipv6 route`` is not modelled today, so it is out of family 4.
    """
    return frozenset({"static_routes"})


def static_route_key(item: Any) -> tuple[str, ...]:
    """Identity path segments for a static route (mirrors ``_TOP_LIST_KEYS``).

    ``("static_routes", *static_route_key(r))`` is the native create-op path,
    identical by construction to the derived keyed-list SET path — the
    composition dedupe relies on it.  Codec-owned; the parser must not
    re-implement the key.
    """
    return _TOP_LIST_KEYS["static_routes"](item)


def is_native_static_op(op: "ChangeOp") -> bool:
    """True iff *op* is a parser-emitted family-4 static-route op.

    Two shapes (both ``origin == "native"``):

    - ``SET ("static_routes", <vrf>, <dest>, <nh_key>)``   — route (re)creation
    - ``LIST_REMOVE ("static", <vrf>, <dest>[, <nh_spec>…])`` — route removal

    Owned by the codec module (CCR Appendix G): the engine's ordered-apply
    pass and its ``_proposal_from_ops`` skip MUST share this predicate.
    Derived ops with identical paths return False (origin gate) and keep
    flowing through the batched legacy apply path so natives-less producers
    retain exact legacy parity.
    """
    if getattr(op, "origin", "derived") != "native":
        return False
    path = op.path
    if not path:
        return False
    if op.verb is Verb.SET and path[0] in static_route_fields():
        return True
    if op.verb is Verb.LIST_REMOVE and path[0] == "static":
        return True
    return False


@_lru_cache(maxsize=1)
def bgp_neighbor_fields() -> frozenset[str]:
    """Family-5a boundary (CCR Appendix H): the per-neighbor lifecycle surface.

    Phase-3 family 5a (WI-18a) migrates the BGP *neighbor* lifecycle only —
    neighbor add/re-add, full removal, and per-neighbor field reset — at both
    parser emission call sites (global ``router bgp`` and per-VRF
    ``address-family ipv4 vrf N``), IOS + inherited NX-OS single-line forms.
    The boundary is the model sub-collection ``BGPConfig.neighbors``; the
    remaining BGP surface (peer-group create/delete, ``network`` statements,
    AF-scoped neighbor migration, the whole-instance positive decomposition)
    stays derived until family 5b — see Appendix H boundary lists.
    """
    return frozenset({"neighbors"})


def bgp_neighbor_key(neighbor: Any) -> tuple[str, ...]:
    """Identity path segment for a BGP neighbor (the peer address, as-written).

    ``("bgp_instances", str(asn), vrf or "", "neighbor", *bgp_neighbor_key(n))``
    is the native create/re-add op path.  The peer address is kept as a SINGLE
    tuple element even for IPv6 peers (whose text contains colons) so the
    consumer never has to re-split it — codec-owned; the parser must not
    re-implement the key.
    """
    return (str(neighbor.peer_ip),)


def bgp_peer_group_key(peer_group: Any) -> tuple[str, ...]:
    """Identity path segment for a BGP peer-group (its name — family 5b).

    ``("bgp_instances", str(asn), vrf or "", "peer_group", *bgp_peer_group_key(pg))``
    is the native create/re-add op path, symmetric to :func:`bgp_neighbor_key`.
    Codec-owned; the parser must not re-implement the key.
    """
    return (peer_group.name,)


def bgp_network_key(network: Any) -> tuple[str, ...]:
    """Identity path segment for a BGP ``network`` statement (family 5b).

    ``("bgp_instances", str(asn), vrf or "", "network", *bgp_network_key(n))``
    is the native create op path.  The identity is the canonical prefix string
    (``str(BGPNetwork.prefix)``) — the same key ``_merge_bgp_instances`` uses
    for its ``networks`` incremental merge.  Codec-owned.
    """
    return (str(network.prefix),)


def bgp_redistribute_key(redist: Any) -> tuple[str, ...]:
    """Identity path segments for a GLOBAL BGP ``redistribute`` member (5c-A).

    ``("bgp_instances", str(asn), vrf or "", "redistribute", *bgp_redistribute_key(r))``
    is the native create op path for a ``BGPConfig.redistribute`` (instance-level,
    NON-AF) member.  The identity is ``(protocol, str(process_id) or "")`` — the
    same key ``_merge_bgp_instances`` uses for its ``redistribute`` incremental
    merge.  The NEGATIVE side (``no redistribute`` → the generic
    ``field:bgp:<asn>:af:ipv4:redistribute:<proto>:<pid>`` tombstone) STAYS DERIVED
    (it targets AF redistribute via ``_access_bgp_af_redistribute``, disjoint from
    this instance-level positive) — the family-5c-A coexistence.  Codec-owned.
    """
    pid = getattr(redist, "process_id", None)
    return (redist.protocol, str(pid) if pid is not None else "")


def bgp_af_key(af: Any) -> tuple[str, ...]:
    """Identity path segments for a BGP address-family block (family 5c-B.1).

    ``("bgp_instances", str(asn), vrf or "", "af", *bgp_af_key(af))`` is the
    native AF *create* op path (a 7-segment SET carrying a SHELL
    ``BGPAddressFamily`` — identity + default scalars, empty sub-collections —
    so ``_apply_native_bgp_ops`` materializes the AF on the merged instance and
    the per-member ops below fill its content).  Identity = ``(afi, safi,
    af.vrf or "")`` — the exact key ``_merge_bgp_address_families`` matches on
    (``merger.py``).  ``af.vrf`` is structurally ``None`` for every AF the IOS
    parser emits today (global ``address-family ipv4`` blocks set ``vrf=None``;
    per-VRF instances are separate ``BGPConfig`` objects) — the segment is kept
    for exact key parity and future-proofing.  Codec-owned.
    """
    return (af.afi, af.safi, af.vrf or "")


def bgp_af_network_key(network: Any) -> tuple[str, ...]:
    """Identity segment for an AF-block ``network`` statement (family 5c-B.1).

    ``(…, "af", afi, safi, afvrf, "network", *bgp_af_network_key(n))`` — the
    canonical prefix string, the key ``_merge_bgp_af`` uses for its incremental
    ``networks`` merge.  Closes the 5b instance-network deferral for AF-block
    networks (Appendix I boundary).  Codec-owned.
    """
    return (str(network.prefix),)


def bgp_af_aggregate_key(aggregate: Any) -> tuple[str, ...]:
    """Identity segment for an AF ``aggregate-address`` (family 5c-B.1).

    ``(…, "af", afi, safi, afvrf, "aggregate", *bgp_af_aggregate_key(a))`` — the
    canonical prefix string, the key ``_merge_bgp_af`` uses for its incremental
    ``aggregate_addresses`` merge.  Also the identity for the ops-only
    ``no aggregate-address`` LIST_REMOVE (singular ``bgp_instance`` prefix, no
    legacy twin — the AF-scoped ``no aggregate-address`` line is silently
    dropped by every legacy parser today).  Codec-owned.
    """
    return (str(aggregate.prefix),)


def _is_bgp_af_aggregate_removal(path: tuple[str, ...]) -> bool:
    """True for the family-5c-B.1 ops-only AF ``no aggregate-address`` op path.

    ``("bgp_instance", asn, vrf, "af", afi, safi, afvrf, "aggregate", <prefix>)``
    — a LIST_REMOVE with NO legacy twin (``encode_legacy`` emits nothing;
    legacy mode stays blind exactly as today, mirroring the 5b ``no network``
    discipline).
    """
    return (
        len(path) == 9
        and path[0] == "bgp_instance"
        and path[3] == "af"
        and path[7] == "aggregate"
    )


def is_native_bgp_af_aggregate_removal_op(op: "ChangeOp") -> bool:
    """True iff *op* is the family-5c-B.1 ops-only AF ``no aggregate-address`` op.

    Consumed by :func:`encode_legacy` to emit NOTHING (no legacy twin), so ops
    mode gains an AF-aggregate-withdrawal capability legacy cannot see while
    legacy-mode artifacts stay byte-identical.
    """
    return (
        getattr(op, "origin", "derived") == "native"
        and op.verb is Verb.LIST_REMOVE
        and _is_bgp_af_aggregate_removal(op.path)
    )


def is_native_bgp_instance_create_op(op: "ChangeOp") -> bool:
    """True iff *op* is the family-5c-B.2 whole-instance CREATE op.

    ``SET ("bgp_instances", asn, vrf, "instance")`` (4-seg) — emitted by the
    parser for every FULLY-NATIVE BGP instance (retirement gate: NOT emitted for
    gated shapes, e.g. NX-OS VRF instances whose neighbors/AFs are unparsed, so
    their derived whole-instance SET survives).  value = the parsed
    ``BGPConfig`` (the engine seeds a new instance from it, parser-absence
    scalars intact).  This op CLAIMS its ``("bgp_instances", asn, vrf)`` prefix
    in :func:`derive_ops` so the derived whole-instance SET is RETIRED for
    fully-native instances (CCR Appendix L) — the one BGP native op that claims
    the container prefix; the neighbor/af/scalar/etc. ops still do not (they
    address inside the container, and for a gated instance the surviving SET
    must not be claimed away).
    """
    path = op.path
    return (
        getattr(op, "origin", "derived") == "native"
        and op.verb is Verb.SET
        and len(path) == 4
        and path[0] == "bgp_instances"
        and path[3] == "instance"
    )


def _is_bgp_peer_group_delete(path: tuple[str, ...]) -> bool:
    """True for the family-5b Candidate-B peer-group-deletion op path.

    ``("bgp_instance", asn, vrf, "field", "neighbor", GROUP, "peer_group")`` —
    an OBJECT_DELETE emitted for ``no neighbor GROUP peer-group`` when GROUP
    names a peer-group.  The path is DELIBERATELY the same shape the derived
    ``field:neighbor:GROUP:peer_group`` tombstone produces (so ``encode_legacy``
    reproduces that legacy string byte-exact and exact-path dedupe retires the
    derived UNSET twin); only the VERB differs (OBJECT_DELETE, not UNSET).
    """
    return (
        len(path) == 7
        and path[0] == "bgp_instance"
        and path[3] == "field"
        and path[4] == "neighbor"
        and path[6] == "peer_group"
    )


def _is_bgp_network_removal(path: tuple[str, ...]) -> bool:
    """True for the family-5b ops-only ``no network`` op path.

    ``("bgp_instance", asn, vrf, "network", <prefix>)`` — a LIST_REMOVE with
    NO legacy twin (``encode_legacy`` emits nothing; legacy mode stays blind,
    exactly as today — the line is silently dropped by the legacy parser).
    """
    return len(path) == 5 and path[0] == "bgp_instance" and path[3] == "network"


def is_native_bgp_network_removal_op(op: "ChangeOp") -> bool:
    """True iff *op* is the family-5b ops-only ``no network`` removal op.

    Consumed by :func:`encode_legacy` to emit NOTHING (no legacy twin): the
    ``no network`` / ``no aggregate-address`` single-line forms are silently
    dropped by every legacy parser today, so ops mode gains a route-withdrawal
    capability legacy cannot see, and legacy-mode artifacts stay byte-identical.
    """
    return (
        getattr(op, "origin", "derived") == "native"
        and op.verb is Verb.LIST_REMOVE
        and _is_bgp_network_removal(op.path)
    )


def is_native_bgp_op(op: "ChangeOp") -> bool:
    """True iff *op* is a parser-emitted family-5a/5b BGP op.

    Family 5a (neighbor lifecycle):

    - ``SET ("bgp_instances", asn, vrf, "neighbor", peer)``
          neighbor (re)creation / field write — value = the ``BGPNeighbor``.
    - ``OBJECT_DELETE ("bgp_instance", asn, vrf, "neighbor", peer…)``
          full neighbor removal (``no neighbor X``).  ``peer…`` may span
          several path segments for IPv6 peers (colon-split); the consumer
          rejoins ``path[3:]`` into the legacy tombstone string.
    - ``UNSET ("bgp_instance", asn, vrf, "field", "neighbor", peer…, field)``
          per-neighbor / peer-group field reset (``no neighbor X <attr>``).

    Family 5b (peer-groups + instance-level networks — CCR Appendix I):

    - ``SET ("bgp_instances", asn, vrf, "peer_group", name)``
          peer-group (re)creation — value = the ``BGPPeerGroup``.
    - ``SET ("bgp_instances", asn, vrf, "network", <prefix>)``
          instance-level ``network`` statement — value = the ``BGPNetwork``.
    - ``OBJECT_DELETE ("bgp_instance", asn, vrf, "field", "neighbor", GROUP,
          "peer_group")`` — Candidate-B peer-group deletion (``no neighbor
          GROUP peer-group``): removes the group AND its member neighbors.
    - ``LIST_REMOVE ("bgp_instance", asn, vrf, "network", <prefix>)``
          ops-only ``no network`` withdrawal (no legacy twin).

    Family 5c-A (whole-instance scalar/bestpath/redistribute surface — CCR
    Appendix J), positive-only SETs on the PLURAL container (the whole-instance
    derived SET still survives — 5c-A does NOT retire it):

    - ``SET ("bgp_instances", asn, vrf, "scalar", <field>)``
          instance scalar (router_id / cluster_id / confederation_id /
          confederation_peers / rpki_server — parity scalars; and the
          new-capability ``log_neighbor_changes`` tri-state True-default +
          ``default_local_preference`` anchored default).  value = the scalar.
    - ``SET ("bgp_instances", asn, vrf, "bestpath", <option_field>)``
          one ``bgp bestpath …`` option → the ``bestpath_options`` sub-object.
    - ``SET ("bgp_instances", asn, vrf, "redistribute", <proto>, <pid>)``
          GLOBAL (non-AF) ``redistribute`` member.  value = ``BGPRedistribute``.
          Its NEGATIVE (``no redistribute``) stays DERIVED (AF-scoped generic
          tombstone, disjoint) — the 5c-A coexistence.

    Family 5c-B.1 (AF-container decomposition — CCR Appendix K), the recursive
    second-level surface.  All SETs on the PLURAL container (the whole-instance
    derived SET STILL survives — 5c-B.1 does NOT retire it; retirement is 5c-B.2
    / task #23):

    - ``SET ("bgp_instances", asn, vrf, "af", afi, safi, afvrf)``
          AF create / final-state (7-seg).  value = a SHELL ``BGPAddressFamily``
          (identity + default scalars, empty sub-collections) — materializes the
          AF; the per-member ops below fill it.
    - ``SET (…, "af", afi, safi, afvrf, "network", <prefix>)``
          AF-block ``network`` (closes the 5b instance-network deferral).
    - ``SET (…, "af", afi, safi, afvrf, "redistribute", <proto>, <pid>)``
          AF ``redistribute`` positive member.  Its NEGATIVE stays DERIVED
          (generic ``field:bgp:<asn>:af:<afi>:redistribute:…`` tombstone, SAME
          list) — the 5c-B.1 coexistence: ``_apply_native_bgp_ops`` suppresses a
          same-key native re-add when a same-scope derived removal is present, so
          same-key delete/re-add resolves delete-wins IDENTICALLY to legacy (both
          engines are order-blind here — the accepted ordering deviation).
    - ``SET (…, "af", afi, safi, afvrf, "aggregate", <prefix>)``
          AF ``aggregate-address`` positive member.
    - ``SET (…, "af", afi, safi, afvrf, "scalar", <field>)``
          AF scalar (``maximum_paths`` / ``maximum_paths_ibgp`` — positive-only;
          tri-state None-default ``prefix_validate_allow_invalid``).
    - ``LIST_REMOVE ("bgp_instance", asn, vrf, "af", afi, safi, afvrf,
          "aggregate", <prefix>)`` — ops-only AF ``no aggregate-address``
          withdrawal (SINGULAR scope prefix, no legacy twin — encode_legacy
          emits nothing), mirroring the 5b ``no network`` discipline.

    Owned by the codec module (CCR Appendix H/I): the engine's ordered-apply
    pass (``_apply_native_bgp_ops``) and its ``_proposal_from_ops`` skip MUST
    share this predicate.  Derived twins (same path, ``origin="derived"``)
    return False (origin gate) and keep flowing through the batched legacy
    apply path so natives-less producers retain exact legacy parity.

    Note the SET side uses the PLURAL ``bgp_instances`` container name (a
    keyed top-level list-member SET, classifier-routed to BGP by existence),
    while the deletion sides carry the SINGULAR ``bgp_instance`` scope prefix
    (``encode_legacy`` returns them to ``BGPConfig.no_commands`` byte-exact,
    except the network-removal LIST_REMOVE which has no legacy twin).
    """
    if getattr(op, "origin", "derived") != "native":
        return False
    path = op.path
    if not path:
        return False
    if op.verb is Verb.SET:
        if len(path) == 4 and path[0] == "bgp_instances" and path[3] == "instance":
            return True  # family 5c-B.2 whole-instance CREATE op
        return (
            len(path) >= 5
            and path[0] == "bgp_instances"
            and path[3]
            in (
                "neighbor",
                "peer_group",
                "network",
                "scalar",
                "bestpath",
                "redistribute",
                "af",
            )
        )
    if op.verb is Verb.OBJECT_DELETE:
        if len(path) >= 5 and path[0] == "bgp_instance" and path[3] == "neighbor":
            return True
        return _is_bgp_peer_group_delete(path)
    if op.verb is Verb.UNSET:
        return (
            len(path) >= 7
            and path[0] == "bgp_instance"
            and path[3] == "field"
            and path[4] == "neighbor"
        )
    if op.verb is Verb.LIST_REMOVE:
        return _is_bgp_network_removal(path) or _is_bgp_af_aggregate_removal(path)
    return False


def _static_nh_key(r: Any) -> str:
    """Stable NH identity segment for a static route (mirrors merger identity)."""
    nh = r.next_hop
    iface = r.next_hop_interface
    parts = [str(nh) if nh is not None else "", (iface or "").lower()]
    return "|".join(parts)


# Identity key functions for keyed top-level list fields.  Mirrors the
# merger's key registries (_SIMPLE_LIST_FIELDS + the explicit rules).  Each
# returns a tuple of strings appended to the path after the field name.
_TOP_LIST_KEYS: dict[str, Callable[[Any], tuple[str, ...]]] = {
    "vrfs": lambda v: (v.name,),
    "bgp_instances": lambda b: (str(b.asn), b.vrf or ""),
    "ospf_instances": lambda o: (str(o.process_id), o.vrf or ""),
    "isis_instances": lambda i: (i.tag or "",),
    "eigrp_instances": lambda e: (str(e.as_number), e.vrf or ""),
    "rip_instances": lambda r: (r.vrf or "",),
    "route_maps": lambda r: (r.name,),
    "prefix_lists": lambda p: (p.name,),
    "acls": lambda a: (a.name,),
    "community_lists": lambda c: (c.name,),
    "as_path_lists": lambda a: (a.name,),
    "static_routes": lambda r: (r.vrf or "", str(r.destination), _static_nh_key(r)),
    "lines": lambda l: (str(l.line_type), str(l.first_line)),
    "class_maps": lambda c: (c.name,),
    "policy_maps": lambda p: (p.name,),
    "ip_sla_operations": lambda s: (str(s.sla_id),),
    "eem_applets": lambda e: (e.name,),
    "object_tracks": lambda t: (str(t.track_id),),
    "zones": lambda z: (z.name, getattr(z, "vsys", None) or ""),
    "vlans": lambda v: (str(v.vlan_id),),
}

_REQUIRED = object()  # sentinel: field has no safe default


def _field_default(field_info: Any) -> Any:
    """Declared default for a Pydantic field (factory first — mirrors merger)."""
    from pydantic_core import PydanticUndefined

    if field_info.default_factory is not None:
        return field_info.default_factory()
    if field_info.default is PydanticUndefined:
        return _REQUIRED
    return field_info.default


def _generic_key(item: Any, index: int) -> str:
    name = getattr(item, "name", None)
    if isinstance(name, str) and name:
        return name
    object_id = getattr(item, "object_id", None)
    if isinstance(object_id, str) and object_id:
        return object_id
    return str(index)


def _provenance(item: Any) -> tuple[str, int]:
    """Best-effort (source_line, line_no) from a config object's raw block."""
    raw_lines = getattr(item, "raw_lines", None) or []
    line_numbers = getattr(item, "line_numbers", None) or []
    source_line = raw_lines[0] if raw_lines else ""
    line_no = line_numbers[0] if line_numbers else -1
    return source_line, line_no


def _derive_interface_set_ops(iface: Any) -> ChangeSet:
    """Field-level SET ops for one interface (mirrors _merge_interface_fields)."""
    from confgraph.utils.interface import normalize_interface_name

    ops: ChangeSet = []
    norm = normalize_interface_name(iface.name)
    source_line, line_no = _provenance(iface)
    for field_name, field_info in type(iface).model_fields.items():
        if field_name in _PROVENANCE_FIELDS:
            continue
        default = _field_default(field_info)
        if default is _REQUIRED:
            continue
        value = getattr(iface, field_name)
        if value != default:
            ops.append(
                ChangeOp(
                    verb=Verb.SET,
                    path=("interface", norm, field_name),
                    value=value,
                    source_line=source_line,
                    line_no=line_no,
                )
            )
    return ops


def _derive_set_ops(proposal: "ParsedConfig") -> ChangeSet:
    ops: ChangeSet = []
    for field_name, field_info in type(proposal).model_fields.items():
        if field_name in _SKIP_TOP_FIELDS:
            continue
        value = getattr(proposal, field_name)
        if field_name == "interfaces":
            for iface in value:
                ops.extend(_derive_interface_set_ops(iface))
            continue
        if isinstance(value, list):
            key_fn = _TOP_LIST_KEYS.get(field_name)
            for index, item in enumerate(value):
                key = key_fn(item) if key_fn else (_generic_key(item, index),)
                source_line, line_no = _provenance(item)
                ops.append(
                    ChangeOp(
                        verb=Verb.SET,
                        path=(field_name, *key),
                        value=item,
                        source_line=source_line,
                        line_no=line_no,
                    )
                )
            continue
        # Scalar / singleton section
        default = _field_default(field_info)
        if default is _REQUIRED:
            continue
        if value != default:
            source_line, line_no = _provenance(value)
            ops.append(
                ChangeOp(
                    verb=Verb.SET,
                    path=(field_name,),
                    value=value,
                    source_line=source_line,
                    line_no=line_no,
                )
            )
    return ops


# ---------------------------------------------------------------------------
# derive_ops — legacy artifacts → ChangeSet (the Phase-0 compatibility bridge)
# ---------------------------------------------------------------------------


def derive_ops(proposal: "ParsedConfig") -> ChangeSet:
    """Translate a legacy-parsed proposal into the full, composed ChangeSet.

    Two sources compose (CCR Appendix D — Phase 3 hybrid derivation):

    1. **Native ops** (``proposal.native_change_ops``) — emitted directly by
       the parser for migrated families (family 1: interface scalars /
       booleans; family 2: trunk allowed-VLAN SETs and delta ops), with
       real provenance.  They come FIRST in the result.
    2. **Derived ops** — the Phase-0 mechanical translation of the remaining
       legacy artifacts, reproducing today's semantics exactly (including
       blind spots).  Canonical order mirrors the legacy merge apply order:
       SET ops (additive pass), BGP-scoped deletions, top-level deletions,
       interface-scoped deletions, then UNRECOGNIZED markers.

    Composition rule: a derived op whose ``path`` collides with a native
    op's path is dropped (the native op is the same intent with better
    provenance — family-1 SET paths are identical by construction, and
    family-1 tombstones are themselves regenerated from the native UNSET
    ops, byte-exact).  Path-dedupe is deliberately used instead of a
    family-list skip: if native emission ever under-covers, the derived op
    SURVIVES and behavior degrades to legacy parity instead of silently
    dropping intent.  The anti-rot test pins that family-1 ops are in fact
    all native.

    Crash-free on any ParsedConfig, including baselines (which simply
    produce SET ops and no deletions).
    """
    natives: ChangeSet = list(getattr(proposal, "native_change_ops", None) or [])
    ops: ChangeSet = []

    # 1. Additive intent → SET ops.
    ops.extend(_derive_set_ops(proposal))

    # 2. BGP-scoped tombstones (BGPConfig.no_commands — applied by the legacy
    #    merger inside _merge_bgp_instances, before top-level deletions).
    for bgp in proposal.bgp_instances:
        prefix = ("bgp_instance", str(bgp.asn), bgp.vrf or "")
        for tombstone in bgp.no_commands:
            ops.append(
                ChangeOp(
                    verb=_verb_for_bgp_tombstone(tombstone),
                    path=prefix + tuple(tombstone.split(":")),
                    value=None,
                    source_line=tombstone,
                    line_no=-1,
                )
            )

    # 3. Top-level tombstones (ParsedConfig.no_commands), in emission order.
    for tombstone in proposal.no_commands:
        ops.append(
            ChangeOp(
                verb=_verb_for_top_tombstone(tombstone),
                path=tuple(tombstone.split(":")),
                value=None,
                source_line=tombstone,
                line_no=-1,
            )
        )

    # 4. Interface-scoped tombstones (InterfaceConfig.no_commands): scalar
    #    field resets (F1 negations) and trunk-VLAN delta ops (F2).
    for iface in proposal.interfaces:
        for tombstone in iface.no_commands:
            verb, value = _verb_and_value_for_interface_tombstone(tombstone)
            ops.append(
                ChangeOp(
                    verb=verb,
                    path=tuple(tombstone.split(":")),
                    value=value,
                    source_line=tombstone,
                    line_no=-1,
                )
            )

    # 5. Unrecognized-line records (WI-2 disclosure path) → marker ops.
    for block in proposal.unrecognized_blocks:
        ops.append(
            ChangeOp(
                verb=Verb.UNRECOGNIZED,
                path=("unrecognized",),
                value=block,
                source_line=block.block_header,
                line_no=-1,
            )
        )

    if not natives:
        return ops

    # Compose: natives first, then every derived op whose path a native op
    # does not already claim (see docstring — dedupe, not family-skip).
    #
    # Container-claim extension (family 3, CCR Appendix F): a derived op
    # whose path is a proper PREFIX of a native op's path is also dropped —
    # the native ops address INSIDE the container the derived op would
    # overwrite wholesale.  Today this retires exactly the derived
    # whole-object ``SET ("banners",)`` when native per-field banner ops
    # exist; those are emitted structurally for every non-default banner
    # field, so the whole-object op is redundant by construction.
    native_paths = {op.path for op in natives}
    # Container-claim (prefix) dedupe — family 3.  EXCLUDE BGP native ops
    # (CCR Appendix H codec adjustment): a native BGP sub-op path such as
    # ``("bgp_instances", asn, vrf, "neighbor", peer)`` must NOT claim its
    # ``("bgp_instances", asn, vrf)`` prefix on its own — see the retirement
    # narrowing below.  Family 1-4 ops are not BGP ops, so their container-claim
    # semantics are unchanged.
    native_prefix_claims = {
        op.path[:i]
        for op in natives
        if not is_native_bgp_op(op)
        for i in range(1, len(op.path))
    }
    # 5c-B.2 retirement (CCR Appendix L — the one authorized derive_ops touch):
    # the native whole-instance CREATE op claims its ``("bgp_instances", asn,
    # vrf)`` prefix, so the derived whole-instance SET is DROPPED for every
    # FULLY-NATIVE instance.  GATED instances (NX-OS VRF etc.) emit no create op
    # → their prefix is not claimed → the derived SET SURVIVES (today's 5a/5b/5c
    # coexistence, unchanged).  Only the len-3 instance prefix is claimed (not
    # the len-1/2 partials), so no cross-instance over-claim.
    native_prefix_claims |= {
        op.path[:3] for op in natives if is_native_bgp_instance_create_op(op)
    }
    return natives + [
        op
        for op in ops
        if op.path not in native_paths and op.path not in native_prefix_claims
    ]


# ---------------------------------------------------------------------------
# encode_legacy — ChangeSet → legacy artifacts (round-trip / Phase-4 shim)
# ---------------------------------------------------------------------------


@dataclass
class LegacyArtifacts:
    """Legacy encoding of a ChangeSet — the inverse of :func:`derive_ops`.

    ``no_commands`` / ``interface_no_commands`` / ``bgp_no_commands`` are the
    tombstone containers exactly as the legacy parser would have emitted them
    (byte-exact, order-preserving).  ``set_fields`` is the positive-intent
    field set (path → value).  ``unrecognized_blocks`` carries the marker-op
    payloads.
    """

    no_commands: list[str] = dc_field(default_factory=list)
    interface_no_commands: dict[str, list[str]] = dc_field(default_factory=dict)
    bgp_no_commands: dict[tuple[str, str], list[str]] = dc_field(default_factory=dict)
    set_fields: dict[tuple[str, ...], Any] = dc_field(default_factory=dict)
    unrecognized_blocks: list[Any] = dc_field(default_factory=list)


def _is_interface_scoped_path(path: tuple[str, ...]) -> bool:
    """True for paths derived from InterfaceConfig.no_commands tombstones.

    Two shapes, both disjoint from every top-level tombstone shape:
      - scalar reset:  ("field", "interface", <name>, <field_name>)      len 4
      - trunk delta:   ("field", "interface", <name>, "trunk_allowed_vlans",
                        <add|remove|except>, <spec>)                     len 6
    (Top-level interface shapes have 5 segments: helper / nhrp_nhs.)
    """
    if len(path) < 4 or path[0] != "field" or path[1] != "interface":
        return False
    if len(path) == 4:
        return True
    return (
        len(path) == 6
        and path[3] == "trunk_allowed_vlans"
        and path[4] in ("add", "remove", "except")
    )


# Public alias — the op consumer (confgraph-entrp ``apply_ops``, Phase 1)
# needs the same container-routing predicate the encoder uses.  The codec
# stays owned by this module; consumers must not re-implement path shapes.
is_interface_scoped_path = _is_interface_scoped_path


def encode_legacy(ops: ChangeSet) -> LegacyArtifacts:
    """Encode a ChangeSet back into the legacy artifact vocabulary.

    Exact inverse of :func:`derive_ops` for tombstone-derived ops (byte-exact
    string reconstruction, correct container placement) and a faithful
    path→value map for SET ops.  This is a real public function — Phase 4's
    OSS deprecation shim uses it to keep ``no_commands`` populated after the
    parsers stop emitting tombstones natively.
    """
    artifacts = LegacyArtifacts()
    for op in ops:
        if op.verb is Verb.UNRECOGNIZED:
            artifacts.unrecognized_blocks.append(op.value)
            continue
        # Family-5b ops-only ``no network`` / family-5c-B.1 ops-only AF
        # ``no aggregate-address``: NO legacy twin (both lines are silently
        # dropped by every legacy parser today) — emit nothing so legacy-mode
        # artifacts stay byte-identical.
        if is_native_bgp_network_removal_op(op) or is_native_bgp_af_aggregate_removal_op(op):
            continue
        if op.path and op.path[0] == "bgp_instance":
            key = (op.path[1], op.path[2])
            artifacts.bgp_no_commands.setdefault(key, []).append(":".join(op.path[3:]))
            continue
        if _is_interface_scoped_path(op.path):
            iface_name = op.path[2]
            artifacts.interface_no_commands.setdefault(iface_name, []).append(
                ":".join(op.path)
            )
            continue
        if op.verb is Verb.SET:
            artifacts.set_fields[op.path] = op.value
            continue
        # All remaining deletion verbs — top-level tombstones.
        artifacts.no_commands.append(":".join(op.path))
    return artifacts
