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
    """

    verb: Verb
    path: tuple[str, ...]
    value: Any = None
    source_line: str = ""
    line_no: int = -1


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
    }
)

# Per-object metadata fields excluded from interface field-level SET emission.
_PROVENANCE_FIELDS: frozenset[str] = frozenset(
    {"object_id", "raw_lines", "line_numbers", "source_os", "no_commands", "name"}
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
    """Mechanically translate a legacy-parsed proposal into a ChangeSet.

    Reproduces today's semantics exactly (including blind spots) — this is
    the compatibility bridge, not the improvement.  Canonical op order
    mirrors the legacy merge apply order: SET ops (additive pass), BGP-scoped
    deletions, top-level deletions, interface-scoped deletions, then
    UNRECOGNIZED markers.  Crash-free on any ParsedConfig, including
    baselines (which simply produce SET ops and no deletions).
    """
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

    return ops


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
