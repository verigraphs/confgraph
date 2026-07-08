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
    "interface_member_fields",
    "interface_member_key",
    "IFACE_MEMBER_REMOVAL_FIELDS",
    "is_native_iface_member_op",
    "is_native_interface_delete_op",
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
    "isis_interface_key",
    "isis_redistribute_key",
    "is_native_isis_op",
    "is_native_isis_net_removal_op",
    "is_native_isis_instance_create_op",
    "eigrp_redistribute_key",
    "eigrp_network_key",
    "eigrp_summary_key",
    "is_native_eigrp_op",
    "is_native_eigrp_network_removal_op",
    "is_native_eigrp_instance_create_op",
    "ospf_redistribute_key",
    "ospf_network_key",
    "ospf_area_range_key",
    "ospf_area_virtual_link_key",
    "is_native_ospf_op",
    "is_native_ospf_network_removal_op",
    "is_native_ospf_area_range_removal_op",
    "is_native_ospf_instance_create_op",
    "is_native_vrf_op",
    "is_native_vrf_delete_op",
    "is_native_vrf_instance_create_op",
    "singleton_section_fields",
    "singleton_member_kinds",
    "singleton_member_key",
    "singleton_scalar_fields",
    "singleton_line_detected_scalars",
    "singleton_create_mode",
    "is_native_singleton_section_op",
    "is_native_singleton_instance_create_op",
    "is_native_vlan_op",
    "simple_keyed_list_fields",
    "simple_keyed_list_key",
    "policy_object_fields",
    "policy_member_field",
    "policy_member_key",
    "is_native_policy_op",
    "is_native_policy_instance_create_op",
    "is_native_policy_member_op",
    "is_native_policy_removal_op",
    "is_native_acl_delete_op",
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


# ---------------------------------------------------------------------------
# Family 8e — interface collection members (CCR Appendix X)
# ---------------------------------------------------------------------------
# InterfaceConfig collection fields migrated to per-MEMBER native SET ops
# ``("interface", <norm>, <field>, <key>)``.  Key functions mirror the
# engine's ``_IFACE_INCREMENTAL_LISTS`` identities:
#   None      — value-identity union lists (the member IS its key:
#               ``str(item)`` — dotted-quad / CIDR / group string).
#   Callable  — keyed-object lists (FHRP groups by ``group_number``).
# ``glbp_groups`` is keyed here for op identity even though its legacy
# merge is the generic ATOMIC replace (it is absent from
# ``_IFACE_INCREMENTAL_LISTS`` — pre-existing asymmetry vs hsrp/vrrp,
# preserved: the batched reconstruction rebuilds the FULL list, so the
# atomic arm sees exactly the legacy proposal list).
# ``ospf_message_digest_keys`` (dict[int, str]) is handled beside this
# registry — key = ``str(key_id)``, value = the md5 string.
_IFACE_MEMBER_KEYS: dict[str, "Callable[[Any], str] | None"] = {
    "secondary_ips": None,
    "ipv6_addresses": None,
    "helper_addresses": None,
    "nhrp_nhs": None,
    "nhrp_map": None,
    "igmp_join_groups": None,
    "igmp_static_groups": None,
    "hsrp_groups": lambda g: str(g.group_number),
    "vrrp_groups": lambda g: str(g.group_number),
    "glbp_groups": lambda g: str(g.group_number),
}

# The two interface member-removal tombstone kinds (NESTED_DELETION_RULES
# templates) and the model fields they target — the ONLY negation surface
# in the family (X.0; every other collection negation is parser-blind).
IFACE_MEMBER_REMOVAL_FIELDS: dict[str, str] = {
    "helper": "helper_addresses",
    "nhrp_nhs": "nhrp_nhs",
}


@_lru_cache(maxsize=1)
def interface_member_fields() -> frozenset[str]:
    """Family-8e boundary: InterfaceConfig collection fields with per-member
    native SET ops (CCR Appendix X) — the 10 ``_IFACE_MEMBER_KEYS`` lists
    plus the ``ospf_message_digest_keys`` dict.  Together with families 1
    and 2 this completes the interface container: every non-provenance
    InterfaceConfig field is native-emitting on the IOS-family parsers.
    """
    return frozenset(_IFACE_MEMBER_KEYS) | {"ospf_message_digest_keys"}


def interface_member_key(field_name: str, item: Any) -> str:
    """Identity path segment for one family-8e list member.

    Codec-owned (the parser and the engine replay must share it): the
    member key is what the removal replay and the derived-twin claim
    reason over.  For the dict field the caller passes the dict KEY, not
    this function.
    """
    key_fn = _IFACE_MEMBER_KEYS[field_name]
    return key_fn(item) if key_fn is not None else str(item)


def is_native_iface_member_op(op: "ChangeOp") -> bool:
    """True iff *op* is a parser-emitted family-8e interface member op.

    Two shapes (both ``origin == "native"`` — CCR Appendix X.1):

    - ``SET ("interface", <norm>, <field>, <key>)`` — one collection member
      (whole parsed item as value; md-key dict entries carry the md5
      string).  Routed INTO the reconstructed proposal interface by
      ``_proposal_from_ops`` (batched parity — the rebuilt list IS the
      parsed list); the derived whole-list ``("interface", <norm>,
      <field>)`` twin is retired by the generic container prefix-claim.
    - ``LIST_REMOVE ("field", "interface", <as-written>, "helper"|"nhrp_nhs",
      <ip>)`` — byte-exact colon-split of the legacy 5-segment tombstone
      (regenerated via ``encode_legacy`` at the same walk position).
      SKIPPED from the batched reconstruction and replayed by the engine
      with the R.0 re-added-later rule (member-SET lines) — the helper/nhs
      refresh capability; withdrawal applies == legacy.

    Derived twins (same paths, ``origin="derived"``) return False (origin
    gate) and keep the batched legacy path so natives-less producers
    (JunOS/PAN-OS; XR for the removal half) retain exact parity.
    """
    if getattr(op, "origin", "derived") != "native":
        return False
    path = op.path
    if op.verb is Verb.SET:
        return (
            len(path) == 4
            and path[0] == "interface"
            and path[2] in interface_member_fields()
        )
    if op.verb is Verb.LIST_REMOVE:
        return (
            len(path) == 5
            and path[0] == "field"
            and path[1] == "interface"
            and path[3] in IFACE_MEMBER_REMOVAL_FIELDS
        )
    return False


def is_native_interface_delete_op(op: "ChangeOp") -> bool:
    """True iff *op* is the parser-emitted family-8e whole-interface delete.

    ``OBJECT_DELETE ("interface", <norm>)`` at the ``no interface <name>``
    line — byte-exact colon-split of the legacy ``interface:<norm>``
    tombstone (implicit sub-interface fan-out stays a CONSUMER semantic,
    ``_del_interface``).  SKIPPED from the batched reconstruction and
    replayed by ``_apply_native_interface_ops``: delete-wins == legacy,
    EXCEPT an interface re-created later in the script (any native
    interface SET with a later line), which is rebuilt FRESH from the
    post-delete ops — the ordered delete+recreate capability (the 8c vlan
    class).  Emitting natively also closes the latent ops-mode claim bug
    (X.0): the derived delete twin was dropped by the generic prefix-claim
    whenever the same proposal carried any field SET for that interface.

    Derived twins return False (origin gate) and keep the batched path.
    """
    return (
        getattr(op, "origin", "derived") == "native"
        and op.verb is Verb.OBJECT_DELETE
        and len(op.path) == 2
        and op.path[0] == "interface"
    )


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


# ---------------------------------------------------------------------------
# Family 6a — IS-IS whole-protocol decomposition (CCR Appendix M)
# ---------------------------------------------------------------------------


def isis_interface_key(iface: Any) -> tuple[str, ...]:
    """Identity segment for an IS-IS per-interface config (family 6a).

    ``("isis_instances", tag, "interface", *isis_interface_key(i))`` is the
    native create/re-add op path.  Identity = the interface name — the same key
    the legacy ``_fieldlevel_list_rule("isis_instances")`` uses for its keyed
    ``interfaces`` merge.  Codec-owned; the parser must not re-implement it.
    """
    return (iface.name,)


def isis_redistribute_key(redist: Any) -> tuple[str, ...]:
    """Identity segments for an IS-IS ``redistribute`` member (family 6a).

    ``("isis_instances", tag, "redistribute", *isis_redistribute_key(r))`` — the
    identity is ``(protocol, str(process_id) or "")``, the same key the legacy
    ``_fieldlevel_list_rule("isis_instances")`` uses for its keyed
    ``redistribute`` merge.  Positive-only (the ``no redistribute`` negation has
    no tombstone today AND no reachable service consumer — merge-only, documented
    in Appendix M).  Codec-owned.
    """
    pid = getattr(redist, "process_id", None)
    return (redist.protocol, str(pid) if pid is not None else "")


# IS-IS instance-decomposition ``kind`` tokens carried at ``path[2]`` of a
# ``("isis_instances", tag, kind, *key)`` native SET (mirrors the BGP
# ``bgp_instances`` keyed-member precedent, one identity segment shorter — the
# IS-IS instance key is the single ``tag``, not ``(asn, vrf)``).
_ISIS_SET_KINDS: frozenset[str] = frozenset(
    {
        "scalar",
        "net",
        "passive_interface",
        "non_passive_interface",
        "interface",
        "redistribute",
    }
)


def _is_isis_net_removal(path: tuple[str, ...]) -> bool:
    """True for the family-6a ops-only ``no net <addr>`` op path.

    ``("isis_instance", tag, "net", <addr>)`` — a LIST_REMOVE with NO legacy twin
    (``encode_legacy`` emits nothing; the line is silently dropped by the legacy
    parser today, exactly like the 5b ``no network`` discipline).  NET strings
    contain dots but never colons, so the address is a single path segment.
    """
    return len(path) == 4 and path[0] == "isis_instance" and path[2] == "net"


def is_native_isis_net_removal_op(op: "ChangeOp") -> bool:
    """True iff *op* is the family-6a ops-only ``no net`` removal op.

    Consumed by :func:`encode_legacy` to emit NOTHING (no legacy twin): a bare
    ``no net <addr>`` under ``router isis`` is silently dropped by every legacy
    parser today (the positive ``net`` walk does not match a ``no net`` line and
    the list is additive), so ops mode gains a NET-withdrawal capability legacy
    cannot see while legacy-mode artifacts stay byte-identical.
    """
    return (
        getattr(op, "origin", "derived") == "native"
        and op.verb is Verb.LIST_REMOVE
        and _is_isis_net_removal(op.path)
    )


def is_native_isis_instance_create_op(op: "ChangeOp") -> bool:
    """True iff *op* is the family-6e IS-IS whole-instance CREATE op.

    ``SET ("isis_instances", tag, "instance")`` (3-seg — the IS-IS instance key
    is the single tag, incl. the bare-tag ``""`` form) — emitted by the parser
    for every FULLY-NATIVE IS-IS instance (retirement gate: NOT emitted for
    gated shapes — IOS-XR and EOS instances, whose OWN ``parse_isis`` walks are
    Phase-5 surface — so their derived whole-instance SET survives).  value =
    the parsed ``ISISConfig`` (the engine seeds a new instance from it via
    ``_isis_creation_seed``).  This op CLAIMS its ``("isis_instances", tag)``
    prefix in :func:`derive_ops` so the derived whole-instance SET is RETIRED
    for fully-native instances (CCR Appendix Q — the Appendix L pattern); the
    scalar/net/interface/etc. sub-ops still do not claim (they address inside
    the container, and a gated instance's surviving SET must not be claimed
    away).
    """
    path = op.path
    return (
        getattr(op, "origin", "derived") == "native"
        and op.verb is Verb.SET
        and len(path) == 3
        and path[0] == "isis_instances"
        and path[2] == "instance"
    )


def _is_isis_process_delete(path: tuple[str, ...]) -> bool:
    """True for the whole-process ``no router isis [<tag>]`` op path.

    ``("process", "isis", <tag>)`` — the byte-exact colon-split of the legacy
    ``process:isis:<tag>`` tombstone (``<tag>`` is ``""`` for a bare
    ``no router isis``).  Emitted NATIVE + line-numbered (family 6a) so 6e can
    build ordered instance delete/recreate on it; in 6a it is applied
    DELETE-WINS (the surviving derived SET still creates the instance, and the
    native delete removes it last — parity with legacy, both orders).
    """
    return len(path) == 3 and path[0] == "process" and path[1] == "isis"


def is_native_isis_op(op: "ChangeOp") -> bool:
    """True iff *op* is a parser-emitted family-6a/6e IS-IS op (CCR Appendix M/Q).

    Family 6e RETIRED the derived whole-instance SET for fully-native instances:
    the 3-seg ``SET ("isis_instances", tag, "instance")`` CREATE op claims the
    instance prefix in ``derive_ops`` (gated IOS-XR/EOS instances emit no create
    op — their derived SET still survives and co-exists like 5a/5b/5c-A).
    Shapes (all ``origin == "native"``), on the PLURAL ``isis_instances``
    container for SETs (classifier-routed to ISIS by keyed-member existence) and
    the SINGULAR ``isis_instance`` / top-level ``process`` scope for deletions:

    - ``SET ("isis_instances", tag, "scalar", <field>)``
          instance scalar (is_type / metric_style / log_adjacency_changes /
          passive_interface_default / authentication_mode / authentication_key /
          max_lsp_lifetime / lsp_refresh_interval / spf_interval /
          default_information_originate(+_route_map)) — state-derived,
          positive-only (no negation tombstone exists today).
    - ``SET ("isis_instances", tag, "net", <addr>)``          additive NET member.
    - ``SET ("isis_instances", tag, "passive_interface", <name>)``     additive.
    - ``SET ("isis_instances", tag, "non_passive_interface", <name>)`` additive.
    - ``SET ("isis_instances", tag, "interface", <name>)``   keyed ISISInterface.
    - ``SET ("isis_instances", tag, "redistribute", <proto>, <pid>)``  keyed.
    - ``OBJECT_DELETE ("process", "isis", <tag>)``  whole-process removal
          (``no router isis`` — applied DELETE-WINS in 6a).
    - ``LIST_REMOVE ("isis_instance", tag, "net", <addr>)``  ops-only ``no net``
          NET withdrawal (SINGULAR scope prefix, no legacy twin).

    Owned by the codec module: the engine's ``_apply_native_isis_ops`` pass and
    its ``_proposal_from_ops`` skip MUST share this predicate.  Derived twins
    (same path, ``origin="derived"``) return False (origin gate) and keep flowing
    through the batched legacy apply path so natives-less producers (JunOS/PAN-OS,
    hand-built configs) retain exact legacy parity.
    """
    if getattr(op, "origin", "derived") != "native":
        return False
    path = op.path
    if not path:
        return False
    if op.verb is Verb.SET:
        if len(path) == 3 and path[0] == "isis_instances" and path[2] == "instance":
            return True  # family 6e whole-instance CREATE op
        return (
            len(path) >= 4
            and path[0] == "isis_instances"
            and path[2] in _ISIS_SET_KINDS
        )
    if op.verb is Verb.OBJECT_DELETE:
        return _is_isis_process_delete(path)
    if op.verb is Verb.LIST_REMOVE:
        return _is_isis_net_removal(path)
    return False


# ---------------------------------------------------------------------------
# Family 6b — EIGRP whole-protocol decomposition (CCR Appendix N)
# ---------------------------------------------------------------------------
# Mirrors family 6a (IS-IS) but on the two-segment ``(str(as_number), vrf or "")``
# instance key (like BGP, one segment richer than IS-IS's single ``tag``).  The
# derived whole-instance EIGRP SET SURVIVES (co-existence — 6b does NOT retire it;
# retirement is 6e).  Parser-absence == model default for every migrated field
# (audited in Appendix N — no Finding-2-class trap), so the engine strips the
# surviving SET to defaults and native ops rebuild it value-identically.


def eigrp_redistribute_key(redist: Any) -> tuple[str, ...]:
    """Identity segments for an EIGRP ``redistribute`` member (family 6b).

    ``("eigrp_instances", asn, vrf, "redistribute", *eigrp_redistribute_key(r))``
    — identity ``(protocol, str(process_id) or "")``, the same key the legacy
    ``_fieldlevel_list_rule("eigrp_instances")`` uses for its keyed ``redistribute``
    merge (merger.py:2365).  Codec-owned.
    """
    pid = getattr(redist, "process_id", None)
    return (redist.protocol, str(pid) if pid is not None else "")


def eigrp_network_key(network: Any) -> tuple[str, ...]:
    """Identity segment for an EIGRP ``network`` statement (family 6b).

    ``networks`` is an ADDITIVE list (merger.py:2363 set-union) — identity is the
    network CIDR string (``str(EIGRPNetwork.network)``), which is the segment the
    ops-only ``no network`` LIST_REMOVE matches on.  CIDR strings contain dots but
    never colons, so the address is one path segment.  Codec-owned.
    """
    return (str(network.network),)


def eigrp_summary_key(sa: Any) -> tuple[str, ...]:
    """Identity segment for an EIGRP ``summary-address`` member (family 6b).

    ``("eigrp_instances", asn, vrf, "summary_address", *eigrp_summary_key(s))`` —
    identity ``str(prefix)``, the same key the legacy
    ``_fieldlevel_list_rule("eigrp_instances")`` uses for its keyed
    ``summary_addresses`` merge (merger.py:2366).  Positive-only (``no
    summary-address`` withdrawal is reachable but benign — Appendix N).
    Codec-owned.
    """
    return (str(sa.prefix),)


# EIGRP instance-decomposition ``kind`` tokens carried at ``path[3]`` of a
# ``("eigrp_instances", asn, vrf, kind, *key)`` native SET (the BGP two-segment
# keyed-member precedent).
_EIGRP_SET_KINDS: frozenset[str] = frozenset(
    {
        "scalar",
        "network",
        "passive_interface",
        "non_passive_interface",
        "redistribute",
        "summary_address",
    }
)

# EIGRP ops-only removal ``kind`` tokens carried at ``path[3]`` of an
# ``("eigrp_instance", asn, vrf, kind, <key>)`` LIST_REMOVE.  Only ``network`` is
# emitted in 6b (the CONFIRMED NET-withdrawal → adjacency capability); the other
# reachable removals (redistribute) are documented deferrals (Appendix N).
_EIGRP_REMOVAL_KINDS: frozenset[str] = frozenset({"network"})


def _is_eigrp_network_removal(path: tuple[str, ...]) -> bool:
    """True for the family-6b ops-only ``no network <addr>`` removal path.

    ``("eigrp_instance", asn, vrf, "network", <addr>)`` — a LIST_REMOVE with NO
    legacy twin (``encode_legacy`` emits nothing; a bare ``no network`` under
    ``router eigrp`` is silently dropped by every legacy parser today, exactly
    like the 5b ``no network`` and 6a ``no net`` discipline).
    """
    return (
        len(path) == 5
        and path[0] == "eigrp_instance"
        and path[3] in _EIGRP_REMOVAL_KINDS
    )


def is_native_eigrp_network_removal_op(op: "ChangeOp") -> bool:
    """True iff *op* is the family-6b ops-only ``no network`` removal op.

    Consumed by :func:`encode_legacy` to emit NOTHING (no legacy twin): a bare
    ``no network <addr>`` under ``router eigrp`` is silently dropped by every
    legacy parser today (the positive ``network`` walk does not match a ``no
    network`` line and the list is additive), so ops mode gains a
    network-withdrawal capability legacy cannot see while legacy-mode artifacts
    stay byte-identical.
    """
    return (
        getattr(op, "origin", "derived") == "native"
        and op.verb is Verb.LIST_REMOVE
        and _is_eigrp_network_removal(op.path)
    )


def is_native_eigrp_instance_create_op(op: "ChangeOp") -> bool:
    """True iff *op* is the family-6e EIGRP whole-instance CREATE op.

    ``SET ("eigrp_instances", asn, vrf, "instance")`` (4-seg — the BGP
    Appendix-L shape on the EIGRP two-segment key) — emitted for EVERY parsed
    EIGRP instance (never gated: no parser overrides ``parse_eigrp``, so parse
    and native emission are the same IOS-family code path; JunOS/PAN-OS emit no
    native ops at all and keep the derived SET).  value = the parsed
    ``EIGRPConfig`` (the engine seeds a new instance from it via
    ``_eigrp_creation_seed``).  Claims its ``("eigrp_instances", asn, vrf)``
    prefix in :func:`derive_ops` → the derived whole-instance SET is RETIRED
    (CCR Appendix Q).
    """
    path = op.path
    return (
        getattr(op, "origin", "derived") == "native"
        and op.verb is Verb.SET
        and len(path) == 4
        and path[0] == "eigrp_instances"
        and path[3] == "instance"
    )


def _is_eigrp_process_delete(path: tuple[str, ...]) -> bool:
    """True for the whole-process ``no router eigrp <asn>`` op path.

    ``("process", "eigrp", <asn>)`` — the byte-exact colon-split of the legacy
    ``process:eigrp:<asn>`` tombstone.  Emitted NATIVE + line-numbered (family
    6b) so 6e can build ordered instance delete/recreate on it; in 6b it is
    applied DELETE-WINS (VRF-blind, matching the legacy ``_del_process_eigrp``
    which compares ``str(as_number)`` only — Appendix N).
    """
    return len(path) == 3 and path[0] == "process" and path[1] == "eigrp"


def is_native_eigrp_op(op: "ChangeOp") -> bool:
    """True iff *op* is a parser-emitted family-6b EIGRP op (CCR Appendix N).

    Shapes (all ``origin == "native"``), on the PLURAL ``eigrp_instances``
    container for SETs (classifier-routed to EIGRP by keyed-member existence) and
    the SINGULAR ``eigrp_instance`` / top-level ``process`` scope for deletions:

    - ``SET ("eigrp_instances", asn, vrf, "scalar", <field>)``  instance scalar
          (router_id / passive_interface_default / auto_summary / variance /
          maximum_paths / distance_internal / distance_external / default_metric /
          log_neighbor_changes / k_values / stub) — state-derived, positive-only.
    - ``SET ("eigrp_instances", asn, vrf, "network", <cidr>)``       additive.
    - ``SET ("eigrp_instances", asn, vrf, "passive_interface", <name>)`` additive.
    - ``SET ("eigrp_instances", asn, vrf, "non_passive_interface", <name>)`` "".
    - ``SET ("eigrp_instances", asn, vrf, "redistribute", <proto>, <pid>)`` keyed.
    - ``SET ("eigrp_instances", asn, vrf, "summary_address", <prefix>)``  keyed.
    - ``OBJECT_DELETE ("process", "eigrp", <asn>)``  whole-process removal
          (``no router eigrp`` — applied DELETE-WINS, VRF-blind, in 6b).
    - ``LIST_REMOVE ("eigrp_instance", asn, vrf, "network", <cidr>)``  ops-only
          ``no network`` withdrawal (SINGULAR scope prefix, no legacy twin).

    Owned by the codec module: the engine's ``_apply_native_eigrp_ops`` pass and
    its ``_proposal_from_ops`` skip MUST share this predicate.  Derived twins
    (same path, ``origin="derived"``) return False (origin gate).
    """
    if getattr(op, "origin", "derived") != "native":
        return False
    path = op.path
    if not path:
        return False
    if op.verb is Verb.SET:
        if len(path) == 4 and path[0] == "eigrp_instances" and path[3] == "instance":
            return True  # family 6e whole-instance CREATE op
        return (
            len(path) >= 5
            and path[0] == "eigrp_instances"
            and path[3] in _EIGRP_SET_KINDS
        )
    if op.verb is Verb.OBJECT_DELETE:
        return _is_eigrp_process_delete(path)
    if op.verb is Verb.LIST_REMOVE:
        return _is_eigrp_network_removal(path)
    return False


# ---------------------------------------------------------------------------
# Families 6c + 6d — native OSPF op codec (CCR Appendices O and P)
# ---------------------------------------------------------------------------
# Mirrors family 6b (EIGRP) on the two-segment ``(str(process_id), vrf or "")``
# instance key.  The derived whole-instance OSPF SET SURVIVES (co-existence —
# neither 6c nor 6d retires it; retirement is 6e).  Family 6d (Appendix P)
# lifts ``areas`` off that surviving SET: nested keyed decomposition
# (``kind == "area"``, the 5c-B.1 AF-container pattern) plus the ops-only
# ``no area N range`` withdrawal; the stub/nssa area-reset tombstones stay
# DERIVED (coexistence handled by the engine's replay suppress-set — P.2).
# Parser-absence == model default for every migrated field EXCEPT
# ``log_adjacency_changes`` (model default True, parser-absence False — the
# 5c-A Finding-2 trap, Appendix O.1): that field is LINE-detected at emission
# and KEPT (not reset) by the engine's ``_strip_native_ospf``.


def ospf_redistribute_key(redist: Any) -> tuple[str, ...]:
    """Identity segments for an OSPF ``redistribute`` member (family 6c).

    ``("ospf_instances", pid, vrf, "redistribute", *ospf_redistribute_key(r))``
    — identity ``(protocol, str(process_id) or "")``, the same key the legacy
    ``_fieldlevel_list_rule("ospf_instances")`` uses for its keyed ``redistribute``
    merge (merger.py:2350).  Codec-owned.
    """
    pid = getattr(redist, "process_id", None)
    return (redist.protocol, str(pid) if pid is not None else "")


def ospf_network_key(statement: Any) -> tuple[str, ...]:
    """Identity segments for an OSPF ``network`` statement (family 6c).

    ``network_statements`` is an ADDITIVE list (merger.py:2344 set-union) of
    ``(IPv4Network, area_id)`` TUPLES — identity is ``(str(network), area_id)``,
    the segments the ops-only ``no network A W area X`` LIST_REMOVE matches on.
    CIDR and area-id tokens contain dots but never colons, so each is one path
    segment.  Codec-owned.
    """
    return (str(statement[0]), statement[1])


def ospf_area_range_key(rng: Any) -> tuple[str, ...]:
    """Identity segment for an ``OSPFArea.ranges`` member (family 6d).

    ``("ospf_instances", pid, vrf, "area", aid, "range", *key)`` — identity
    ``(str(prefix),)``, the same key the legacy nested keyed merge uses
    (merger.py:2348 ``{"ranges": (lambda r: str(r.prefix), True)}``).  The
    ops-only ``no area N range A M`` LIST_REMOVE matches on the same segment,
    normalized through the SAME ``IPv4Network(f"{addr}/{mask}")`` construction
    the positive range parse uses (Appendix P.3 — matching can never drift).
    Codec-owned.
    """
    return (str(rng.prefix),)


def ospf_area_virtual_link_key(vl: Any) -> tuple[str, ...]:
    """Identity segment for an ``OSPFArea.virtual_links`` member (family 6d).

    ``("ospf_instances", pid, vrf, "area", aid, "virtual_link", *key)`` —
    identity ``(str(neighbor_router_id),)``, the same key the legacy nested
    keyed merge uses (merger.py:2349).  Codec-owned.
    """
    return (str(vl.neighbor_router_id),)


# OSPF instance-decomposition ``kind`` tokens carried at ``path[3]`` of a
# ``("ospf_instances", pid, vrf, kind, *key)`` native SET (the EIGRP two-segment
# keyed-member precedent).  Family 6d (CCR Appendix P) adds the nested-keyed
# ``area`` kind — the recursive second-level surface, mirroring the 5c-B.1 BGP
# AF container (Appendix K):
#
# - ``SET (…, "area", <aid>)``                       create / final-state shell
#       (value = the full parsed OSPFArea; applied only when the area is absent).
# - ``SET (…, "area", <aid>, "scalar", <field>)``    per non-default area scalar.
# - ``SET (…, "area", <aid>, "range", <prefix>)``    nested keyed OSPFRange.
# - ``SET (…, "area", <aid>, "virtual_link", <rid>)`` nested keyed OSPFVirtualLink.
# - ``SET (…, "area", <aid>, "interface", <name>)``  additive (IOS-XR only in
#       practice — the IOS/NX-OS parsers never populate ``OSPFArea.interfaces``).
_OSPF_SET_KINDS: frozenset[str] = frozenset(
    {
        "scalar",
        "network",
        "passive_interface",
        "non_passive_interface",
        "redistribute",
        "area",
    }
)

# OSPF ops-only removal ``kind`` tokens carried at ``path[3]`` of an
# ``("ospf_instance", pid, vrf, kind, <cidr>, <area>)`` LIST_REMOVE.  Only
# ``network`` is emitted in 6c (the CONFIRMED withdrawal → adjacency capability);
# the other reachable removals (redistribute / default-information originate)
# are documented deferrals (Appendix O.4).  The family-6d area-range removal
# carries the nested ``(…, "area", <aid>, "range", <prefix>)`` shape and is
# recognized by ``_is_ospf_area_range_removal`` instead.
_OSPF_REMOVAL_KINDS: frozenset[str] = frozenset({"network"})


def _is_ospf_network_removal(path: tuple[str, ...]) -> bool:
    """True for the family-6c ops-only ``no network A W area X`` removal path.

    ``("ospf_instance", pid, vrf, "network", <cidr>, <area>)`` — a LIST_REMOVE
    with NO legacy twin (``encode_legacy`` emits nothing; a ``no network``
    under ``router ospf`` is silently dropped by every legacy parser today,
    exactly like the 5b/6a/6b discipline).  The area id is one extra identity
    segment vs EIGRP (the model member is the ``(network, area)`` tuple).
    """
    return (
        len(path) == 6
        and path[0] == "ospf_instance"
        and path[3] in _OSPF_REMOVAL_KINDS
    )


def is_native_ospf_network_removal_op(op: "ChangeOp") -> bool:
    """True iff *op* is the family-6c ops-only ``no network`` removal op.

    Consumed by :func:`encode_legacy` to emit NOTHING (no legacy twin): a
    ``no network A W area X`` under ``router ospf`` is silently dropped by
    every legacy parser today (the positive walk is anchored and the merged
    ``network_statements`` list is additive), so ops mode gains a
    network-withdrawal capability legacy cannot see while legacy-mode
    artifacts stay byte-identical.
    """
    return (
        getattr(op, "origin", "derived") == "native"
        and op.verb is Verb.LIST_REMOVE
        and _is_ospf_network_removal(op.path)
    )


def _is_ospf_area_range_removal(path: tuple[str, ...]) -> bool:
    """True for the family-6d ops-only ``no area N range A M`` removal path.

    ``("ospf_instance", pid, vrf, "area", <aid>, "range", <prefix>)`` — a
    LIST_REMOVE with NO legacy twin (``encode_legacy`` emits nothing; a
    ``no area N range`` under ``router ospf`` is silently dropped by every
    legacy parser today — the positive area walk is anchored ``^\\s+area`` and
    no NESTED_DELETION_RULES entry exists for ranges).  Appendix P.3: the
    CONFIRMED ABR-summarization withdrawal capability.
    """
    return (
        len(path) == 7
        and path[0] == "ospf_instance"
        and path[3] == "area"
        and path[5] == "range"
    )


def is_native_ospf_area_range_removal_op(op: "ChangeOp") -> bool:
    """True iff *op* is the family-6d ops-only area-range removal op.

    Consumed by :func:`encode_legacy` to emit NOTHING (no legacy twin): a
    ``no area N range A M`` under ``router ospf`` is silently dropped by every
    legacy parser today, so ops mode gains an ABR-summarization-withdrawal
    capability legacy cannot see while legacy-mode artifacts stay
    byte-identical (CCR Appendix P.3).
    """
    return (
        getattr(op, "origin", "derived") == "native"
        and op.verb is Verb.LIST_REMOVE
        and _is_ospf_area_range_removal(op.path)
    )


def is_native_ospf_instance_create_op(op: "ChangeOp") -> bool:
    """True iff *op* is the family-6e OSPF whole-instance CREATE op.

    ``SET ("ospf_instances", pid, vrf, "instance")`` (4-seg — the BGP
    Appendix-L shape on the OSPF two-segment key) — emitted for every
    FULLY-NATIVE OSPF instance (retirement gate: NOT emitted for IOS-XR
    instances, whose OWN ``parse_ospf`` is Phase-5 surface — no line-detected
    ``log_adjacency_changes`` tri-state for the XR spelling, no removals — so
    their derived whole-instance SET survives with the keep-parser-value
    strip).  value = the parsed ``OSPFConfig`` (the engine seeds a new
    instance from it via ``_ospf_creation_seed``, which keeps the O.1 trap
    field at the parser value and strips natively-decomposed areas; for an
    EXISTING instance the engine applies only the audited residual — the
    parser-absence ``log_adjacency_changes=False`` non-default override the
    retired SET performed through ``_merge_entry_fields``).  Claims its
    ``("ospf_instances", pid, vrf)`` prefix in :func:`derive_ops` → the
    derived whole-instance SET is RETIRED (CCR Appendix Q).
    """
    path = op.path
    return (
        getattr(op, "origin", "derived") == "native"
        and op.verb is Verb.SET
        and len(path) == 4
        and path[0] == "ospf_instances"
        and path[3] == "instance"
    )


def _is_ospf_process_delete(path: tuple[str, ...]) -> bool:
    """True for the whole-process ``no router ospf <pid>`` op path.

    ``("process", "ospf", <pid>)`` — the byte-exact colon-split of the legacy
    ``process:ospf:<pid>`` tombstone.  Emitted NATIVE + line-numbered (family
    6c) so 6e can build ordered instance delete/recreate on it; in 6c it is
    applied DELETE-WINS (VRF-blind, matching the legacy ``_del_process_ospf``
    which compares ``str(process_id)`` only — Appendix O.3).
    """
    return len(path) == 3 and path[0] == "process" and path[1] == "ospf"


def is_native_ospf_op(op: "ChangeOp") -> bool:
    """True iff *op* is a parser-emitted family-6c OSPF op (CCR Appendix O).

    Shapes (all ``origin == "native"``), on the PLURAL ``ospf_instances``
    container for SETs (classifier-routed to OSPF by keyed-member existence) and
    the SINGULAR ``ospf_instance`` / top-level ``process`` scope for deletions:

    - ``SET ("ospf_instances", pid, vrf, "scalar", <field>)``  instance scalar —
          state-derived positive-only for every non-default scalar EXCEPT
          ``log_adjacency_changes``, which is LINE-detected (positive line →
          True, ``no log-adjacency-changes`` → False; tri-state, Appendix O.1).
    - ``SET ("ospf_instances", pid, vrf, "network", <cidr>, <area>)`` additive
          ``(IPv4Network, area)`` tuple member.
    - ``SET ("ospf_instances", pid, vrf, "passive_interface", <name>)`` additive.
    - ``SET ("ospf_instances", pid, vrf, "non_passive_interface", <name>)`` "".
    - ``SET ("ospf_instances", pid, vrf, "redistribute", <proto>, <pid>)`` keyed.
    - ``SET ("ospf_instances", pid, vrf, "area", <aid>[, sub…])``  family-6d
          nested keyed area decomposition (shell / scalar / range /
          virtual_link / interface — see ``_OSPF_SET_KINDS``, CCR Appendix P).
    - ``OBJECT_DELETE ("process", "ospf", <pid>)``  whole-process removal
          (``no router ospf`` — applied DELETE-WINS, VRF-blind, in 6c).
    - ``LIST_REMOVE ("ospf_instance", pid, vrf, "network", <cidr>, <area>)``
          ops-only ``no network`` withdrawal (SINGULAR scope, no legacy twin).
    - ``LIST_REMOVE ("ospf_instance", pid, vrf, "area", <aid>, "range",
          <prefix>)``  family-6d ops-only area-range withdrawal (no legacy twin).

    The stub/nssa area-reset tombstones stay DERIVED (Appendix P.2 — the
    coexistence suppress-set lives in the engine replay, not here).  Owned by
    the codec module: the engine's ``_apply_native_ospf_ops`` pass and its
    ``_proposal_from_ops`` skip MUST share this predicate.  Derived twins
    (same path, ``origin="derived"``) return False (origin gate).
    """
    if getattr(op, "origin", "derived") != "native":
        return False
    path = op.path
    if not path:
        return False
    if op.verb is Verb.SET:
        if len(path) == 4 and path[0] == "ospf_instances" and path[3] == "instance":
            return True  # family 6e whole-instance CREATE op
        return (
            len(path) >= 5
            and path[0] == "ospf_instances"
            and path[3] in _OSPF_SET_KINDS
        )
    if op.verb is Verb.OBJECT_DELETE:
        return _is_ospf_process_delete(path)
    if op.verb is Verb.LIST_REMOVE:
        return _is_ospf_network_removal(path) or _is_ospf_area_range_removal(path)
    return False


# VRF decomposition ``kind`` tokens carried at ``path[2]`` of a
# ``("vrfs", name, kind, *key)`` native SET (family 7a, CCR Appendix R).  The
# VRF identity is the single-segment ``name`` (``_TOP_LIST_KEYS["vrfs"]``).
_VRF_SET_KINDS: frozenset[str] = frozenset(
    {
        "scalar",
        "route_target_import",
        "route_target_export",
        "route_target_both",
        "interface",
    }
)

_VRF_RT_KINDS: frozenset[str] = frozenset(
    {"route_target_import", "route_target_export", "route_target_both"}
)


def _is_vrf_member_removal(path: tuple[str, ...]) -> bool:
    """True for the family-7a native RT-removal op path.

    ``("field", "vrfs", <name>, "route_target_<kind>", *rt_segments)`` — the
    byte-exact colon-split of the WI-7 legacy tombstone
    ``field:vrfs:<name>:route_target_<kind>:<rt>`` (the RT value's embedded
    colon splits into ≥2 segments; ``encode_legacy``'s ``":".join`` rejoins it
    byte-exactly — CCR Appendix R.0 design item 2).
    """
    return (
        len(path) >= 5
        and path[0] == "field"
        and path[1] == "vrfs"
        and path[3] in _VRF_RT_KINDS
    )


def _is_vrf_rd_reset(path: tuple[str, ...]) -> bool:
    """True for the family-7a native rd-reset op path.

    ``("field", "vrfs", <name>, "rd")`` — byte-exact colon-split of the WI-7
    ``field:vrfs:<name>:rd`` tombstone (``no rd [<rd>]`` inside a VRF block).
    """
    return (
        len(path) == 4
        and path[0] == "field"
        and path[1] == "vrfs"
        and path[3] == "rd"
    )


def _is_vrf_delete(path: tuple[str, ...]) -> bool:
    """True for the family-7a native whole-VRF removal op path.

    ``("field", "vrfs", <name>)`` — byte-exact colon-split of the WI-7
    ``field:vrfs:<name>`` tombstone (``no vrf definition|context <name>``).
    Emitted NATIVE + line-numbered (7b builds on it); in 7a it is applied
    DELETE-WINS-last (delete-then-recreate both orders → ABSENT == legacy;
    the ordering capability stays deferred, the L.7 posture).  The IOS-XR
    ``vrf:<name>`` shape is NOT matched — it stays on the D1 fix-forward
    path (``_OPS_OBJECT_DELETE_FIX_FORWARD``), regression-pinned.
    """
    return len(path) == 3 and path[0] == "field" and path[1] == "vrfs"


def is_native_vrf_delete_op(op: "ChangeOp") -> bool:
    """True iff *op* is the family-7a native whole-VRF OBJECT_DELETE."""
    return (
        getattr(op, "origin", "derived") == "native"
        and op.verb is Verb.OBJECT_DELETE
        and _is_vrf_delete(op.path)
    )


def is_native_vrf_instance_create_op(op: "ChangeOp") -> bool:
    """True iff *op* is the family-7b whole-VRF CREATE op (CCR Appendix S).

    ``SET ("vrfs", <name>, "instance")`` (3-seg — the VRF key is the single
    name) — emitted by the parser for every FULLY-NATIVE VRF (retirement
    gate: NOT emitted for gated shapes — IOS-XR, whose own
    ``parse_deletion_commands`` emits the DERIVED ``vrf:<name>`` D1 shape —
    so their derived whole-VRF SET survives).  value = the parsed
    ``VRFConfig`` (the engine seeds a new VRF from it via
    ``_vrf_creation_seed``).  This op CLAIMS its ``("vrfs", name)`` prefix in
    :func:`derive_ops` so the derived whole-VRF SET is RETIRED for
    fully-native VRFs (the Appendix L/Q pattern); the member sub-ops still do
    not claim (a gated VRF's surviving SET must not be claimed away).
    """
    path = op.path
    return (
        getattr(op, "origin", "derived") == "native"
        and op.verb is Verb.SET
        and len(path) == 3
        and path[0] == "vrfs"
        and path[2] == "instance"
    )


def is_native_vrf_op(op: "ChangeOp") -> bool:
    """True iff *op* is a parser-emitted family-7a VRF op (CCR Appendix R).

    Shapes (all ``origin == "native"``), on the PLURAL ``vrfs`` container for
    SETs (classifier-routed to VRF by keyed-member existence via
    ``_TOP_FIELD_AREA["vrfs"]``) and the byte-exact ``("field", "vrfs", …)``
    tombstone shapes for removals (classifier rejoins them to the legacy
    tombstone → ``_tombstone_area`` → VRF, the WI-7 routing — zero classifier
    change):

    - ``SET ("vrfs", name, "scalar", <field>)``  rd / route_map_import /
          route_map_export / description / vpnid — state-derived,
          positive-only (non-default).
    - ``SET ("vrfs", name, "route_target_import"|"route_target_export"|
          "route_target_both", <rt>)``  additive RT member (the RT is ONE
          segment here — SET paths never colon-join), carrying the member's
          LAST-occurrence line (the R.0 re-added-later ordering basis).
    - ``SET ("vrfs", name, "interface", <ifname>)``  additive member (IOS-family
          parsers never populate ``VRFConfig.interfaces``; emitted for
          completeness/symmetry with the strip).
    - ``LIST_REMOVE ("field", "vrfs", name, "route_target_<kind>", *rt)``
          ``no route-target …`` (byte-exact WI-7 twin regenerated via
          ``encode_legacy``; unconditional — refresh is resolved structurally
          in the engine replay, R.0 design item 1).
    - ``UNSET ("field", "vrfs", name, "rd")``  ``no rd``.
    - ``OBJECT_DELETE ("field", "vrfs", name)``  whole-VRF removal,
          applied DELETE-WINS-last.

    The derived whole-VRF ``SET ("vrfs", name)`` (len 2) is NOT matched — it
    survives composition (7a co-existence; retirement is 7b).  Owned by the
    codec module: the engine's ``_apply_native_vrf_ops`` pass and its
    ``_proposal_from_ops`` skip MUST share this predicate.  Derived twins
    (same path, ``origin="derived"``) return False (origin gate) and keep
    flowing through the batched legacy apply path so natives-less producers
    (JunOS/PAN-OS) retain exact legacy parity.
    """
    if getattr(op, "origin", "derived") != "native":
        return False
    path = op.path
    if not path:
        return False
    if op.verb is Verb.SET:
        if len(path) == 3 and path[0] == "vrfs" and path[2] == "instance":
            return True  # family 7b whole-VRF CREATE op
        return len(path) == 4 and path[0] == "vrfs" and path[2] in _VRF_SET_KINDS
    if op.verb is Verb.LIST_REMOVE:
        return _is_vrf_member_removal(path)
    if op.verb is Verb.UNSET:
        return _is_vrf_rd_reset(path)
    if op.verb is Verb.OBJECT_DELETE:
        return _is_vrf_delete(path)
    return False


# ---------------------------------------------------------------------------
# Families 8a/8b — singleton sections (CCR Appendices T + U)
# ---------------------------------------------------------------------------
# The five comms/service sections migrated by WI-8a (ntp / snmp / syslog /
# dns / aaa) plus the seven infra sections migrated by WI-8b (dhcp, netflow,
# multicast, bfd, mpls, vxlan, vpc) — one registry entry per section, no new
# mechanism (Appendix U).
#
# Member kinds are the MODEL LIST-FIELD NAMES (path[1] of a member SET); the
# key functions mirror the engine merger's ``list_keys`` identity functions
# EXACTLY (``_SINGLETON_SECTION_LIST_KEYS`` in confgraph-entrp merger.py) so
# native member paths and the replay's keyed merges can never drift.  Keys
# are stringified for path segments; values that contain colons (IPv6 hosts)
# stay ONE segment — SET paths never colon-join.

_SINGLETON_MEMBER_KEYS: dict[str, dict[str, Callable[[Any], tuple[str, ...]]]] = {
    "ntp": {
        "servers": lambda s: (str(s.address),),
        "peers": lambda s: (str(s.address),),
        "authentication_keys": lambda k: (str(k.key_id),),
        "trusted_keys": lambda k: (str(k),),
    },
    "snmp": {
        "communities": lambda c: (c.community_string,),
        "hosts": lambda h: (str(h.address), h.version),
        "views": lambda v: (v.name,),
        "groups": lambda g: (g.name, g.version),
        "users": lambda u: (u.username, u.group),
        "enable_traps": lambda t: (str(t),),
    },
    "syslog": {
        "hosts": lambda h: (str(h.address),),
    },
    "dns": {
        "domain_list": lambda d: (str(d),),
        "name_servers": lambda n: (str(n),),
    },
    "aaa": {
        "authentication_lists": lambda a: (a.service, a.name),
        "authorization_lists": lambda a: (a.service, a.name),
        "accounting_lists": lambda a: (a.service, a.name),
        "tacacs_servers": lambda s: (s.address,),
        "radius_servers": lambda s: (s.address,),
    },
    # Family 8b (CCR Appendix U) — infra singletons.  Same discipline: keys
    # mirror the merger ``_SINGLETON_SECTION_LIST_KEYS`` identities exactly
    # (stringified; ``None``-able key parts use the ``or ""`` idiom of
    # ``_TOP_LIST_KEYS``).  ``mpls`` / ``vpc`` are scalar-only sections —
    # registered with no member kinds.
    "dhcp": {
        "pools": lambda p: (p.name,),
        "excluded_ranges": lambda r: (r.low,),
        "snooping_vlans": lambda v: (str(v),),
    },
    "netflow": {
        "destinations": lambda d: (str(d.address), str(d.port)),
    },
    "multicast": {
        "pim_rp_addresses": lambda r: (str(r.rp_address), r.acl or ""),
        "msdp_peers": lambda p: (str(p.peer_address),),
        "multicast_routing_vrfs": lambda v: (str(v),),
    },
    "bfd": {
        "templates": lambda t: (t.name,),
        "maps": lambda m: (m.afi, str(m.destination), str(m.source)),
    },
    "mpls": {},
    "vxlan": {
        "vni_mappings": lambda v: (str(v.vni),),
        "flood_vtep_list": lambda f: (str(f),),
    },
    "vpc": {},
    # Family 8c (CCR Appendix V) — visibility + L2 global singletons.  Same
    # discipline: keys mirror the merger ``_SINGLETON_SECTION_LIST_KEYS``
    # identities exactly.  ``cdp`` / ``vtp`` are scalar-only sections.
    # ``spanning_tree``'s legacy merge is the CUSTOM ``_spanning_tree_rule``;
    # its ``vlan_configs`` arm is a keyed whole-object replace on
    # ``vlan_id`` — the registry entry feeds ONLY the engine replay (the
    # legacy rule is untouched; equivalence pinned in the engine tests).
    # STPVlanConfig.vlan_id is already a str (may be a range spec like
    # "10-20" — one path segment either way).
    "lldp": {
        "tlv_select": lambda t: (str(t),),
    },
    "cdp": {},
    "spanning_tree": {
        "vlan_configs": lambda v: (str(v.vlan_id),),
    },
    "vtp": {},
    # Family 8d (CCR Appendix W) — the two non-additive singletons.  ``nat``
    # is create-mode "adopt" (legacy ``_nat_rule``): member kinds mirror the
    # rule's keyed dict-merges EXACTLY (pools by name, dynamic entries by
    # ACL, static entries by (local_ip, local_port) — ``None`` port uses the
    # ``or ""`` idiom); NO scalar ops are ever emitted (scalars ride the
    # create op value on adoption and are legacy-blind on an existing
    # baseline in BOTH modes — W.2).  ``crypto`` is create-mode "replace"
    # (legacy ``_singleton_rule`` atomic overwrite): create-op-only, no
    # member kinds.
    "nat": {
        "pools": lambda p: (p.name,),
        "dynamic_entries": lambda e: (e.acl,),
        "static_entries": lambda e: (
            str(e.local_ip),
            str(e.local_port) if e.local_port is not None else "",
        ),
    },
    "crypto": {},
}

# Family 8d (CCR Appendix W): per-section CREATE-MODE — how the engine's
# creation pre-pass consumes the ``SET (<sect>, "instance")`` op, mirroring
# the section's LEGACY merge rule exactly:
#
# - "seed" (default, 8a/8b/8c): seed an ABSENT section via the generic
#   reset-to-default seed; existing sections NO-OP (the retired SET was
#   inert — scalars and members are natively rebuilt).
# - "adopt" (legacy ``_nat_rule``): an ABSENT section adopts the create op's
#   value WHOLESALE (scalars/nested sub-objects the walk cannot rebuild —
#   nat.timeouts et al. — ride the value, exactly the legacy deepcopy-adopt
#   arm); an existing section NO-OPs and ONLY the member ops merge onto it
#   (the legacy keyed dict-merges; scalars stay legacy-blind in both modes).
#   The parser emits NO scalar ops for adopt sections.
# - "replace" (legacy ``_singleton_rule``): the create op's value replaces
#   the section UNCONDITIONALLY (atomic overwrite).  The parser emits the
#   create op ONLY (no scalar/member decomposition — the value IS the op).
#
# Adopt/replace sections are SEED-IMMUNE by construction: every model field
# rides the create value, so a future model field can never be silently
# dropped (the T.3 completeness partition is unnecessary for them; the
# anti-rot pins assert the mode registrations and the no-scalar-op rule
# instead).
_SINGLETON_CREATE_MODES: dict[str, str] = {
    "nat": "adopt",
    "crypto": "replace",
}


def singleton_create_mode(section: str) -> str:
    """Create-mode for a migrated singleton section (CCR Appendix W).

    ``"seed"`` / ``"adopt"`` / ``"replace"`` — codec-owned; the parser's
    emission walk and the engine's creation pre-pass MUST share this
    registry, never re-implement the mode split.
    """
    return _SINGLETON_CREATE_MODES.get(section, "seed")

# Scalars whose native op is LINE-DETECTED (tri-state), not state-derived —
# the two True-default booleans whose positive re-assert/refresh is invisible
# to the parsed state (CCR Appendix T.2).  The parser's structural scalar
# walk skips them; dedicated line scans emit them at their true lines.
_SINGLETON_LINE_DETECTED_SCALARS: dict[str, frozenset[str]] = {
    "syslog": frozenset({"enabled"}),
    "dns": frozenset({"lookup_enabled"}),
    # Family 8c (CCR Appendix V.2): the visibility True-default booleans.
    # ``lldp.enabled`` / ``cdp.enabled`` are tri-state on the IOS family
    # (positive ``lldp run``/``cdp run`` re-assert vs ``no … run`` negation)
    # and carry the NX-OS parser-absence trap (``feature lldp``/``feature
    # cdp`` — absence parses to False ≠ model default True), so the parser
    # emits them from dedicated line scans (NX-OS: unconditionally when the
    # section exists).  ``cdp.advertise_v2`` is a plain tri-state
    # (absence == default True on every OS).
    "lldp": frozenset({"enabled"}),
    "cdp": frozenset({"enabled", "advertise_v2"}),
}


@_lru_cache(maxsize=1)
def singleton_section_fields() -> frozenset[str]:
    """Family-8a boundary: the migrated singleton ParsedConfig sections.

    Each flows as native ops (whole-section CREATE + per-scalar SETs +
    keyed/scalar member SETs + byte-exact removal twins) and its derived
    whole-singleton ``SET (<field>,)`` is RETIRED (inline — the Appendix F
    banners precedent): the CREATE op claims the ``(<field>,)`` prefix in
    :func:`derive_ops`.  Gated producers (IOS-XR) and natives-less parsers
    (JunOS/PAN-OS) emit no family-8a ops → their derived SET survives →
    exact legacy parity.
    """
    return frozenset(_SINGLETON_MEMBER_KEYS)


def singleton_member_kinds(section: str) -> frozenset[str]:
    """Member-kind tokens (model list-field names) for a migrated section."""
    return frozenset(_SINGLETON_MEMBER_KEYS[section])


def singleton_member_key(section: str, list_field: str, item: Any) -> tuple[str, ...]:
    """Identity path segments for a singleton-section list member.

    ``(<section>, <list_field>, *singleton_member_key(...))`` is the native
    member-SET path.  Codec-owned — the parser and the engine replay must
    not re-implement the keys (they mirror the merger ``list_keys`` exactly).
    """
    return _SINGLETON_MEMBER_KEYS[section][list_field](item)


def singleton_line_detected_scalars(section: str) -> frozenset[str]:
    """Scalars excluded from the state-derived walk (line-detected, T.2)."""
    return _SINGLETON_LINE_DETECTED_SCALARS.get(section, frozenset())


@_lru_cache(maxsize=None)
def singleton_scalar_fields(section: str) -> frozenset[str]:
    """Structural walk of a migrated section's scalar fields (families 8a/8b).

    Same discipline as :func:`banner_scalar_fields`: declared Pydantic
    default, no ``default_factory``, provenance/identity excluded — a future
    scalar model field automatically joins the family.  Together with
    :func:`singleton_member_kinds` this partitions the section's model
    fields completely (anti-rot completeness pin in the family-8a/8b tests):
    every field is provenance, a structural scalar, or a registered member
    kind — so the engine's generic creation seed (reset-everything-to-
    default) can never silently drop content.

    REQUIRED business fields (``default is PydanticUndefined``, no factory —
    today exactly ``vpc.domain_id``) are structural scalars too (family 8b,
    CCR Appendix U.1): the state walk's non-default test is vacuously true
    for them, so their SET is ALWAYS emitted — mirroring the legacy
    ``_merge_singleton_additive`` arm that overrides required fields from
    the proposal unconditionally.  The engine's creation seed keeps the
    parsed value for required fields (it cannot reset them).  No 8a section
    has a required field, so this is behavior-neutral for 8a.
    """
    from confgraph.models.aaa import AAAConfig
    from confgraph.models.bfd import BFDConfig
    from confgraph.models.cdp import CDPConfig
    from confgraph.models.crypto import CryptoConfig
    from confgraph.models.dhcp import DHCPConfig
    from confgraph.models.dns import DNSConfig
    from confgraph.models.lldp import LLDPConfig
    from confgraph.models.logging_config import SyslogConfig
    from confgraph.models.mpls import MPLSConfig
    from confgraph.models.multicast import MulticastConfig
    from confgraph.models.nat import NATConfig
    from confgraph.models.netflow import NetFlowConfig
    from confgraph.models.ntp import NTPConfig
    from confgraph.models.snmp import SNMPConfig
    from confgraph.models.stp import STPConfig
    from confgraph.models.vlan import VTPConfig
    from confgraph.models.vpc import VPCConfig
    from confgraph.models.vxlan import VXLANConfig

    models = {
        "ntp": NTPConfig,
        "snmp": SNMPConfig,
        "syslog": SyslogConfig,
        "dns": DNSConfig,
        "aaa": AAAConfig,
        "dhcp": DHCPConfig,
        "netflow": NetFlowConfig,
        "multicast": MulticastConfig,
        "bfd": BFDConfig,
        "mpls": MPLSConfig,
        "vxlan": VXLANConfig,
        "vpc": VPCConfig,
        "lldp": LLDPConfig,
        "cdp": CDPConfig,
        "spanning_tree": STPConfig,
        "vtp": VTPConfig,
        # Family 8d (CCR Appendix W) — registered for completeness pins only:
        # the parser NEVER emits scalar ops for adopt/replace sections (their
        # scalars ride the create op value — W.1/W.2).
        "nat": NATConfig,
        "crypto": CryptoConfig,
    }
    fields: set[str] = set()
    for name, info in models[section].model_fields.items():
        if name in _PROVENANCE_FIELDS:
            continue
        if info.default_factory is not None:
            continue
        fields.add(name)
    return frozenset(fields)


def is_native_singleton_instance_create_op(op: "ChangeOp") -> bool:
    """True iff *op* is the family-8a whole-section CREATE op.

    ``SET (<section>, "instance")`` (2-seg — singletons carry no identity
    key) — emitted by the parser for every parsed, ungated section.  value =
    the parsed section object (the engine seeds an absent section from it
    via ``_singleton_creation_seed`` — parser-absence == model default for
    every migrated field, CCR Appendix T.2; an EXISTING section is a NO-OP,
    the retired SET was fully inert).  Claims its ``(<section>,)`` prefix in
    :func:`derive_ops` → the derived whole-singleton SET is RETIRED (the
    Appendix L/Q/S pattern, inline per Appendix F).
    """
    path = op.path
    return (
        getattr(op, "origin", "derived") == "native"
        and op.verb is Verb.SET
        and len(path) == 2
        and path[0] in _SINGLETON_MEMBER_KEYS
        and path[1] == "instance"
    )


def is_native_singleton_section_op(op: "ChangeOp") -> bool:
    """True iff *op* is a parser-emitted family-8a singleton-section op.

    Shapes (all ``origin == "native"`` — CCR Appendix T.1):

    - ``SET (<sect>, "instance")``                 whole-section CREATE op.
    - ``SET (<sect>, "scalar", <field>)``          per-scalar (state-derived
          non-default; ``dns.lookup_enabled`` / ``syslog.enabled`` are
          line-detected tri-state — T.2).
    - ``SET (<sect>, <list_field>, *key)``         keyed/scalar list member.
    - ``LIST_REMOVE ("field", <sect>, …)``         entry removal — byte-exact
          colon-split of the legacy tombstone (regenerated via
          ``encode_legacy`` at the same walk position).
    - ``UNSET ("field", <sect>, <action>)``        today exactly
          ``field:dns:lookup_disable`` (the WI-8-pre action tombstone).
    - ``UNSET ("singleton", <sect>)``              whole-section null-out
          (IOS ``singleton:snmp`` / ``singleton:aaa``; the IOS-XR
          ``singleton:ntp`` / ``singleton:dns`` stay DERIVED — XR is gated).

    Owned by the codec module: the engine's ``_apply_native_singleton_ops``
    pass and its ``_proposal_from_ops`` skip MUST share this predicate.
    Derived twins (same path, ``origin="derived"``) return False (origin
    gate) and keep flowing through the batched legacy apply path so
    natives-less producers retain exact legacy parity.
    """
    if getattr(op, "origin", "derived") != "native":
        return False
    path = op.path
    if not path:
        return False
    if op.verb is Verb.SET:
        if len(path) == 2:
            return path[0] in _SINGLETON_MEMBER_KEYS and path[1] == "instance"
        return (
            len(path) >= 3
            and path[0] in _SINGLETON_MEMBER_KEYS
            and (
                path[1] == "scalar"
                or path[1] in _SINGLETON_MEMBER_KEYS[path[0]]
            )
        )
    if op.verb is Verb.LIST_REMOVE:
        return (
            len(path) >= 3
            and path[0] == "field"
            and path[1] in _SINGLETON_MEMBER_KEYS
        )
    if op.verb is Verb.UNSET:
        if len(path) == 2 and path[0] == "singleton":
            return path[1] in _SINGLETON_MEMBER_KEYS
        return (
            len(path) == 3
            and path[0] == "field"
            and path[1] in _SINGLETON_MEMBER_KEYS
        )
    return False


def is_native_vlan_op(op: "ChangeOp") -> bool:
    """True iff *op* is a parser-emitted family-8c VLAN-database op.

    Two shapes (both ``origin == "native"`` — CCR Appendix V.1):

    - ``SET ("vlans", <id>)``          — VLAN (re)creation.  value = the
          parsed ``VLANEntry``; the path is IDENTICAL to the derived keyed
          SET (``_TOP_LIST_KEYS["vlans"]`` — ``str(vlan_id)``), so the
          exact-path dedupe in :func:`derive_ops` retires the derived twin
          (no creation seed / prefix claim needed — keyed top-level
          collection, the family-3 shape).  Carries the entry's
          LAST-occurrence line (``VLANEntry`` has no provenance fields; the
          parser re-scans the ``vlan <spec>`` lines for line numbers).
    - ``OBJECT_DELETE ("vlan", <id>)`` — ``no vlan <spec>`` per expanded id
          (ranges/commas expand; each id carries the spec line's number).
          Byte-exact colon-split of the legacy ``vlan:<id>`` tombstone —
          ``encode_legacy`` reproduces it via the top-level fall-through.

    The engine replays both IN ChangeSet order (``_apply_native_vlan_ops``,
    the family-3 in-order mechanism): delete-then-recreate in one proposal →
    the VLAN SURVIVES (device truth — the legacy batched adds-then-deletes
    order false-removes it, the W5 class); recreate-then-delete → REMOVED,
    parity with legacy.  Owned by the codec module: the engine's replay pass
    and its ``_proposal_from_ops`` skip MUST share this predicate.  Derived
    twins (same path, ``origin="derived"``) return False (origin gate) and
    keep the batched legacy path so natives-less producers retain exact
    legacy parity.
    """
    if getattr(op, "origin", "derived") != "native":
        return False
    path = op.path
    if len(path) != 2:
        return False
    if op.verb is Verb.SET:
        return path[0] == "vlans"
    if op.verb is Verb.OBJECT_DELETE:
        return path[0] == "vlan"
    return False


@_lru_cache(maxsize=1)
def simple_keyed_list_fields() -> frozenset[str]:
    """Family-8d boundary, shape 1 (CCR Appendix W): the remaining simple
    keyed top-level collections migrated to native emission.

    ``lines`` / ``class_maps`` / ``policy_maps`` / ``rip_instances`` — all
    ``_SIMPLE_LIST_FIELDS`` keyed-replace collections with ZERO negation
    surface (no deletion-walk shape or merger accessor targets them, W.0),
    populated only by the IOS-family parsers.  The native op is a per-entry
    ``SET (<field>, *simple_keyed_list_key(...))`` at the EXACT derived
    path, so the exact-path dedupe in :func:`derive_ops` retires the
    derived twin; the op deliberately flows the BATCHED engine path
    (no ``is_native_*`` predicate — the 8c ``lacp_system_priority``
    posture): zero engine change, parity by construction.

    ``zones`` is deliberately NOT here: only PAN-OS populates it and
    PANOSParser is a natives-less BaseParser subclass (Phase-5 gate) — its
    derived keyed SETs keep exact legacy behavior, pinned.
    """
    return frozenset({"lines", "class_maps", "policy_maps", "rip_instances"})


def simple_keyed_list_key(field_name: str, item: Any) -> tuple[str, ...]:
    """Identity path segments for a family-8d shape-1 entry.

    Delegates to the deriver's ``_TOP_LIST_KEYS`` so native paths are
    identical to the derived SET paths by construction (the exact-path
    dedupe relies on this).  Codec-owned; the parser must not re-implement
    the keys.
    """
    return _TOP_LIST_KEYS[field_name](item)


# ---------------------------------------------------------------------------
# Family 8f — policy objects (CCR Appendix Y)
# ---------------------------------------------------------------------------
# The five named policy-object collections decomposed to a whole-object
# CREATE op + per-member SETs.  ``(member_attr, key_fn(item, idx))`` per
# field; key functions are op-identity labels (the engine reconstructs the
# member LIST by appending values in op order — the merge identities live
# in the merger's own key logic, applied on the batched path):
#   - route_maps / prefix_lists: the sequence number (the seq-removal
#     replay and the re-added-later refresh reason over it).
#   - acls: the ACE sequence when present (``acl-seq:`` twins address it);
#     positional ``@<idx>`` for unsequenced/remark ACEs (no negation
#     surface addresses them — the legacy dedup key stays a MERGE
#     semantic, applied by ``_merge_acls`` on the batched path).
#   - community_lists / as_path_lists: positional (zero negation surface).
_POLICY_MEMBER_KEYS: dict[str, tuple[str, "Callable[[Any, int], str]"]] = {
    "route_maps": ("sequences", lambda s, i: str(s.sequence)),
    "prefix_lists": ("sequences", lambda e, i: str(e.sequence)),
    "acls": (
        "entries",
        lambda e, i: str(e.sequence) if e.sequence is not None else f"@{i}",
    ),
    "community_lists": ("entries", lambda e, i: f"@{i}"),
    "as_path_lists": ("entries", lambda e, i: f"@{i}"),
}

# Removal-twin path heads (the FOUR IOS walk shapes — CCR Appendix Y.0).
# ``route-map:``/``prefix-list:`` whole-object shapes (IOS-XR, D1) are NOT
# here: XR is gated and its derived deletes keep the legacy/fix-forward
# paths untouched.
_POLICY_SEQ_REMOVAL_HEADS: frozenset[str] = frozenset(
    {"acl-seq", "route-map", "prefix-list"}
)


@_lru_cache(maxsize=1)
def policy_object_fields() -> frozenset[str]:
    """Family-8f boundary (CCR Appendix Y): the five named policy-object
    collections — ``acls`` / ``route_maps`` / ``prefix_lists`` /
    ``community_lists`` / ``as_path_lists``.  The LAST derived whole-object
    SETs of Phase 3: on the IOS family (INCREMENTAL merge strategy) each
    parsed object emits a whole-object CREATE op + per-member SETs and the
    derived SET is retired via the create op's ``path[:2]`` claim.
    ATOMIC_REPLACE producers (IOS-XR gated; JunOS/PAN-OS natives-less) keep
    their derived SETs → the batched ``_os_aware_rule`` applies the atomic
    replace verbatim (``Verb.BLOCK_REPLACE`` stays dormant until Phase 5).
    """
    return frozenset(_POLICY_MEMBER_KEYS)


def policy_member_field(field_name: str) -> str:
    """The member-list attribute of one family-8f collection
    (``sequences`` for route_maps/prefix_lists, ``entries`` otherwise).
    Codec-owned — the parser emission and the engine routing share it.
    """
    return _POLICY_MEMBER_KEYS[field_name][0]


def policy_member_key(field_name: str, item: Any, index: int) -> str:
    """Identity path segment for one family-8f member SET (see
    ``_POLICY_MEMBER_KEYS``).  Codec-owned; the parser must not
    re-implement the keys — the engine's seq-removal replay matches
    removal tombstone seqs against these segments.
    """
    return _POLICY_MEMBER_KEYS[field_name][1](item, index)


def is_native_policy_instance_create_op(op: "ChangeOp") -> bool:
    """True iff *op* is the family-8f whole-object CREATE op.

    ``SET (<field>, <name>, "instance")`` — value = the parsed object
    (block provenance).  Claims its ``(<field>, <name>)`` prefix in
    :func:`derive_ops` (the L/Q/S create-op mechanism) so the derived
    whole-object SET is retired inline.  The engine appends a creation
    seed (member list emptied — the members ride their own SETs) to the
    reconstructed proposal in ``_proposal_from_ops``: creation keeps the
    legacy additive-pass POSITION, so whole-object delete-wins ordering
    is preserved by construction (CCR Appendix Y.2).
    """
    return (
        getattr(op, "origin", "derived") == "native"
        and op.verb is Verb.SET
        and len(op.path) == 3
        and op.path[0] in policy_object_fields()
        and op.path[2] == "instance"
    )


def is_native_policy_member_op(op: "ChangeOp") -> bool:
    """True iff *op* is a family-8f per-member SET.

    ``SET (<field>, <name>, <member_attr>, <key>)`` — value = the parsed
    member model (whole — no per-field reconstruction, no parser-absence
    exposure).  Routed INTO the object created by the sibling create op in
    ``_proposal_from_ops`` (append in op order — the rebuilt list IS the
    parsed list, so the batched OS-aware merge applies exact legacy
    semantics).  Carries the member's LAST-occurrence line where a
    negation surface exists (route-map/prefix-list seqs, sequenced ACEs)
    — the re-added-later ordering basis for the seq-removal replay.
    """
    return (
        getattr(op, "origin", "derived") == "native"
        and op.verb is Verb.SET
        and len(op.path) == 4
        and op.path[0] in policy_object_fields()
        and op.path[2] == policy_member_field(op.path[0])
    )


def is_native_policy_removal_op(op: "ChangeOp") -> bool:
    """True iff *op* is a native family-8f seq-level removal.

    ``LIST_REMOVE`` on the byte-exact colon-split of one of the three
    seq-shaped legacy twins (``acl-seq:<name>:<seq>``,
    ``route-map:<name>:seq:<n>``, ``prefix-list:<name>:seq:<n>`` — the
    verb comes from the codec's own tombstone→verb registry).  SKIPPED
    from the batched reconstruction and replayed by the engine with the
    re-added-later rule (refresh capability); a removal with no later
    re-add applies via the exact legacy handlers (delete-wins == legacy).
    DERIVED twins (same paths) return False (origin gate) and keep the
    batched tombstone path — the IOS-XR whole-object OBJECT_DELETE shapes
    (D1) never match (different verb) and stay fully derived.
    """
    return (
        getattr(op, "origin", "derived") == "native"
        and op.verb is Verb.LIST_REMOVE
        and len(op.path) >= 3
        and op.path[0] in _POLICY_SEQ_REMOVAL_HEADS
    )


def is_native_acl_delete_op(op: "ChangeOp") -> bool:
    """True iff *op* is the native family-8f whole-ACL delete.

    ``OBJECT_DELETE ("acl", <name…>)`` at the ``no ip access-list
    standard|extended <name>`` line — byte-exact colon-split of the legacy
    ``acl:<name>`` tombstone.  SKIPPED from the batched reconstruction and
    replayed by ``_apply_native_policy_ops``: delete-wins == legacy,
    EXCEPT an ACL re-defined LATER in the script (create op with a later
    line), which is rebuilt FRESH from the post-delete ops — the ordered
    delete+recreate capability (the 8c-vlan/8e-interface class).  The
    IOS-XR derived ``acl:<name>`` twin returns False (origin gate) and
    keeps the batched tombstone path (``_del_acl`` — honored in BOTH
    modes today, unchanged).
    """
    return (
        getattr(op, "origin", "derived") == "native"
        and op.verb is Verb.OBJECT_DELETE
        and len(op.path) >= 2
        and op.path[0] == "acl"
    )


def is_native_policy_op(op: "ChangeOp") -> bool:
    """True iff *op* belongs to family 8f (any of the four shapes).

    Excluded from the generic container prefix-claim in
    :func:`derive_ops` (the H/M/R exclusion pattern): a member SET must
    not claim its ``(<field>, <name>)`` prefix on its own (graceful
    degradation — retirement is create-op-scoped), and a native seq
    removal such as ``("route-map", <name>, "seq", <n>)`` must never
    prefix-claim ``("route-map", <name>)`` — that path IS the IOS-XR
    derived whole-object delete (the 8e X.0 latent-claim class, closed
    here by exclusion).
    """
    return (
        is_native_policy_instance_create_op(op)
        or is_native_policy_member_op(op)
        or is_native_policy_removal_op(op)
        or is_native_acl_delete_op(op)
    )


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
    # (CCR Appendix H codec adjustment) AND IS-IS native ops (CCR Appendix M,
    # same adjustment): a native BGP sub-op path such as
    # ``("bgp_instances", asn, vrf, "neighbor", peer)`` — or an IS-IS sub-op
    # ``("isis_instances", tag, "scalar", field)`` — must NOT claim its
    # ``("bgp_instances", asn, vrf)`` / ``("isis_instances", tag)`` prefix on its
    # own, so the co-existing derived whole-instance SET SURVIVES (6a does NOT
    # retire it; BGP retirement is the create-op narrowing below, IS-IS
    # retirement is 6e).  Family 7a (CCR Appendix R) extends the same
    # exclusion to VRF ops: a native ``("vrfs", name, kind, *key)`` member SET
    # must not claim its ``("vrfs", name)`` prefix — the derived whole-VRF SET
    # survives (retirement is 7b).  Family 1-4 ops are not BGP/IS-IS/VRF ops,
    # so their container-claim semantics are unchanged.
    native_prefix_claims = {
        op.path[:i]
        for op in natives
        if not is_native_bgp_op(op)
        and not is_native_isis_op(op)
        and not is_native_eigrp_op(op)
        and not is_native_ospf_op(op)
        and not is_native_vrf_op(op)
        and not is_native_singleton_section_op(op)
        # Family 8f (CCR Appendix Y): policy-object ops must not claim
        # generically — retirement is create-op-scoped (below), and a
        # native seq removal ("route-map", <name>, "seq", <n>) would
        # otherwise prefix-claim ("route-map", <name>) — the IOS-XR
        # derived whole-object delete path (the 8e X.0 latent-claim
        # class, excluded here).
        and not is_native_policy_op(op)
        for i in range(1, len(op.path))
    }
    # 5c-B.2 retirement (CCR Appendix L — the one authorized derive_ops touch),
    # extended by family 6e (CCR Appendix Q) to the three routing protocols:
    # the native whole-instance CREATE op claims its instance prefix
    # (``("bgp_instances", asn, vrf)`` / ``("ospf_instances", pid, vrf)`` /
    # ``("eigrp_instances", asn, vrf)`` — len 3; ``("isis_instances", tag)`` —
    # len 2, the IS-IS key is the single tag), so the derived whole-instance
    # SET is DROPPED for every FULLY-NATIVE instance.  GATED instances (NX-OS
    # VRF BGP; IOS-XR OSPF/IS-IS; EOS IS-IS) emit no create op → their prefix
    # is not claimed → the derived SET SURVIVES (the 5a/5b/5c coexistence,
    # unchanged).  Only the exact instance prefix is claimed (not the len-1
    # partials), so no cross-instance over-claim; the claim is
    # create-op-scoped, so families 1–5 dedupe semantics are untouched.
    native_prefix_claims |= {
        op.path[:3]
        for op in natives
        if is_native_bgp_instance_create_op(op)
        or is_native_eigrp_instance_create_op(op)
        or is_native_ospf_instance_create_op(op)
    }
    # Family 7b (CCR Appendix S): the whole-VRF CREATE op claims its
    # ``("vrfs", name)`` prefix — same len-2 shape as the IS-IS single-tag
    # claim.  Gated VRFs (IOS-XR) emit no create op → their derived SET
    # survives (the 7a coexistence, unchanged).  Family 8f (CCR Appendix
    # Y): the policy-object CREATE op claims its ``(<field>, <name>)``
    # prefix — the SAME len-2 shape — retiring the derived whole-object
    # SET for the five policy collections.  Gated (IOS-XR) / natives-less
    # (JunOS, PAN-OS) producers emit no create op → their derived SETs
    # survive → the batched OS-aware ATOMIC_REPLACE keeps exact legacy
    # behavior (BLOCK_REPLACE stays dormant until Phase 5).
    native_prefix_claims |= {
        op.path[:2]
        for op in natives
        if is_native_isis_instance_create_op(op)
        or is_native_vrf_instance_create_op(op)
        or is_native_policy_instance_create_op(op)
    }
    # Family 8a (CCR Appendix T): the whole-SECTION create op claims its
    # ``(<section>,)`` len-1 prefix — exactly the derived whole-singleton
    # SET's path — so the SET is RETIRED inline for native-emitting parsers
    # (the Appendix F banners precedent, via the L/Q/S create-op mechanism).
    # Gated (IOS-XR) / natives-less (JunOS, PAN-OS) producers emit no create
    # op → their derived whole-section SET survives (exact legacy parity).
    native_prefix_claims |= {
        op.path[:1]
        for op in natives
        if is_native_singleton_instance_create_op(op)
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
        # Family-6a ops-only ``no net`` (CCR Appendix M): NO legacy twin (the
        # bare ``no net`` line is silently dropped by every legacy parser today)
        # — emit nothing so legacy-mode artifacts stay byte-identical.
        if is_native_isis_net_removal_op(op):
            continue
        # Family-6b ops-only ``no network`` (CCR Appendix N): NO legacy twin (the
        # bare ``no network`` line is silently dropped by every legacy parser
        # today) — emit nothing so legacy-mode artifacts stay byte-identical.
        if is_native_eigrp_network_removal_op(op):
            continue
        # Family-6c ops-only ``no network A W area X`` (CCR Appendix O) and
        # family-6d ops-only ``no area N range A M`` (CCR Appendix P): NO
        # legacy twin (both lines are silently dropped by every legacy parser
        # today) — emit nothing so legacy-mode artifacts stay byte-identical.
        # (The stub/nssa area-reset tombstones are DERIVED ops and keep their
        # byte-exact legacy twins via the top-level fall-through below.)
        if is_native_ospf_network_removal_op(op) or is_native_ospf_area_range_removal_op(op):
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
