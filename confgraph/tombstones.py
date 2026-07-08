"""Registry for nested block deletion tombstones.

Tombstones capture deletions that cannot be expressed as the absence of a
parsed field value.  Because the incremental merger interprets a field at its
Pydantic default as "not mentioned — keep baseline", a ``no redistribute ospf 1``
inside a BGP AF block would otherwise leave the baseline redistribution entry
untouched.

How tombstones flow
-------------------
1. **Parser**: ``parse_deletion_commands()`` in ``ios_parser.IOSParser`` (shared
   by IOS-XR via inheritance) traverses ``NESTED_DELETION_RULES`` and emits
   ``field:<template>`` strings into ``ParsedConfig.no_commands``.

2. **Merger**: ``_apply_deletions()`` dispatches every ``field:`` tombstone to
   ``_del_field()``, which matches the rest against ``_FIELD_PATH_ACCESSORS``
   and calls the appropriate accessor to mutate the merged ``ParsedConfig``.

Adding a new nested deletion
-----------------------------
Add exactly **one** ``NestedDeletionRule`` entry to ``NESTED_DELETION_RULES``
and **one** ``(pattern, accessor)`` entry to ``_FIELD_PATH_ACCESSORS`` in
``merger.py``.  No other files need to change.

Tombstone format
----------------
``field:<template>``  — where *template* is the rule's ``template`` field with
Python ``str.format`` substitutions applied from the matched groups.

Example (BGP AF redistribute removal)::

    field:bgp:65001:af:ipv4:redistribute:ospf:1

Stored in: ``ParsedConfig.no_commands``
Resolved in: ``merger._del_field`` → ``_access_bgp_af_redistribute``
"""

from typing import Any, Callable, NamedTuple


class NestedDeletionRule(NamedTuple):
    """Describes one class of nested ``no`` command that emits a tombstone.

    Attributes:
        parent_pattern: Regex matched against top-level config block text
            (e.g. ``router bgp``).  Groups are captured into *parent_groups*.
        parent_groups:  Names for the capture groups in *parent_pattern*,
            in order.  Used as format keys in *template*.
        child_pattern:  Regex matched against stripped child/grandchild text
            under the matched parent block.  Groups → *child_groups*.
        child_groups:   Names for the capture groups in *child_pattern*.
        template:       ``str.format``-style template whose keys are the union
            of *parent_groups* and *child_groups*.  Prefixed with ``field:``
            before being appended to ``ParsedConfig.no_commands``.
        derive:         Optional normalizer (WI-DB1-B1, CCR Appendix AA.2):
            called with the captured-groups dict, returns EXTRA template keys
            (e.g. a canonical CIDR string computed from ip+mask captures so
            the tombstone key byte-matches the positive member-op key), or
            ``None`` to skip the matched line entirely (unparseable operand
            stays blind — identical to today).  Default ``None`` — every
            rule without a normalizer behaves exactly as before.
    """

    parent_pattern: str
    parent_groups: list
    child_pattern: str
    child_groups: list
    template: str
    derive: "Callable[[dict], dict[str, Any] | None] | None" = None


def _derive_secondary_cidr(ctx: dict) -> "dict[str, Any] | None":
    """Canonical ``str(IPv4Interface)`` key for a secondary-IP removal.

    Accepts either the IOS dotted form (``ip`` + ``mask`` captures) or the
    NX-OS/EOS CIDR form (``addr`` capture).  Returns ``None`` when the
    operand does not parse — the line stays blind, as today.
    """
    from ipaddress import IPv4Interface

    try:
        if ctx.get("addr"):
            return {"cidr": str(IPv4Interface(ctx["addr"]))}
        return {"cidr": str(IPv4Interface(f"{ctx['ip']}/{ctx['mask']}"))}
    except (KeyError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------
# Each rule maps a (parent_block, child_no_command) pair to a tombstone.
# parse_deletion_commands() in ios_parser.IOSParser iterates this list,
# using all_children to traverse every descendant of the matched parent block.
#
# To add a new nested deletion:
#   1. Append a NestedDeletionRule here.
#   2. Add one (pattern, accessor) entry to _FIELD_PATH_ACCESSORS in merger.py.
#   That is all — no changes to parse_deletion_commands() or _apply_deletions().

NESTED_DELETION_RULES: list[NestedDeletionRule] = [
    # BGP AF redistribute removal
    # Proposal: ``no redistribute ospf 1`` inside ``router bgp / address-family ipv4``
    # Tombstone: ``field:bgp:65001:af:ipv4:redistribute:ospf:1``
    NestedDeletionRule(
        parent_pattern=r"^router\s+bgp\s+(\d+)\s*$",
        parent_groups=["asn"],
        child_pattern=r"^no\s+redistribute\s+(\S+)(?:\s+(\d+))?\s*$",
        child_groups=["proto", "pid"],
        template="bgp:{asn}:af:ipv4:redistribute:{proto}:{pid}",
    ),
    # Per-interface ip helper-address removal
    # Proposal: ``no ip helper-address X.X.X.X`` inside ``interface <name>``
    # Tombstone: ``field:interface:Vlan10:helper:10.0.0.100``
    NestedDeletionRule(
        parent_pattern=r"^interface\s+(\S+)\s*$",
        parent_groups=["name"],
        child_pattern=r"^no\s+ip\s+helper-address\s+(\d+\.\d+\.\d+\.\d+)\s*$",
        child_groups=["ip"],
        template="interface:{name}:helper:{ip}",
    ),
    # Per-interface NHRP NHS removal (DMVPN spoke loses hub registration target)
    # Proposal: ``no ip nhrp nhs X.X.X.X`` inside ``interface <name>``
    # Tombstone: ``field:interface:Tunnel0:nhrp_nhs:203.0.113.1``
    NestedDeletionRule(
        parent_pattern=r"^interface\s+(\S+)\s*$",
        parent_groups=["name"],
        child_pattern=r"^no\s+ip\s+nhrp\s+nhs\s+(\d+\.\d+\.\d+\.\d+)\s*$",
        child_groups=["ip"],
        template="interface:{name}:nhrp_nhs:{ip}",
    ),
    # OSPF area type reset — 'no area N stub' / 'no area N stub no-summary'
    # Proposal: ``no area 1 stub`` inside ``router ospf 1``
    # Tombstone: ``field:ospf:1:area:1:stub_reset``
    NestedDeletionRule(
        parent_pattern=r"^router\s+ospf\s+(\d+)\s*$",
        parent_groups=["pid"],
        child_pattern=r"^no\s+area\s+(\S+)\s+stub",
        child_groups=["area_id"],
        template="ospf:{pid}:area:{area_id}:stub_reset",
    ),
    # OSPF area type reset — 'no area N nssa' / 'no area N nssa no-summary'
    # Proposal: ``no area 2 nssa`` inside ``router ospf 1``
    # Tombstone: ``field:ospf:1:area:2:nssa_reset``
    # Uses the same merger accessor as stub_reset (both reset area_type to NORMAL).
    NestedDeletionRule(
        parent_pattern=r"^router\s+ospf\s+(\d+)\s*$",
        parent_groups=["pid"],
        child_pattern=r"^no\s+area\s+(\S+)\s+nssa",
        child_groups=["area_id"],
        template="ospf:{pid}:area:{area_id}:nssa_reset",
    ),
    # VRF route-target removals (CCR confgraph_vrf_rt_removal_tombstones.md).
    # The WI-4 merge made route_target_* lists ADDITIVE (device-faithful), so
    # the only way an RT set can shrink/replace is the ``no route-target``
    # form — which must tombstone or tenant fragmentation is invisible.
    # Parent covers IOS ``vrf definition NAME`` and NX-OS ``vrf context NAME``;
    # the traversal walks all_children, so removals nested under
    # ``address-family ipv4`` are found.  Template uses ``vrfs`` (plural — the
    # ParsedConfig field name) so the engine classifier attributes the
    # tombstone to the VRF coverage area via _TOP_FIELD_AREA.
    # Proposal: ``no route-target import 65400:10`` inside ``vrf definition GUEST``
    # Tombstone: ``field:vrfs:GUEST:route_target_import:65400:10``
    NestedDeletionRule(
        parent_pattern=r"^vrf\s+(?:definition|context)\s+(\S+)\s*$",
        parent_groups=["name"],
        child_pattern=r"^no\s+route-target\s+import\s+(\S+)\s*$",
        child_groups=["rt"],
        template="vrfs:{name}:route_target_import:{rt}",
    ),
    NestedDeletionRule(
        parent_pattern=r"^vrf\s+(?:definition|context)\s+(\S+)\s*$",
        parent_groups=["name"],
        child_pattern=r"^no\s+route-target\s+export\s+(\S+)\s*$",
        child_groups=["rt"],
        template="vrfs:{name}:route_target_export:{rt}",
    ),
    NestedDeletionRule(
        parent_pattern=r"^vrf\s+(?:definition|context)\s+(\S+)\s*$",
        parent_groups=["name"],
        child_pattern=r"^no\s+route-target\s+both\s+(\S+)\s*$",
        child_groups=["rt"],
        template="vrfs:{name}:route_target_both:{rt}",
    ),
    # VRF RD reset — ``no rd`` / ``no rd 65400:1`` inside a VRF block.
    # Scalar reset: the merger sets the named VRF's rd back to None.
    # Tombstone: ``field:vrfs:GUEST:rd``
    NestedDeletionRule(
        parent_pattern=r"^vrf\s+(?:definition|context)\s+(\S+)\s*$",
        parent_groups=["name"],
        child_pattern=r"^no\s+rd(?:\s+(\S+))?\s*$",
        child_groups=["rd"],
        template="vrfs:{name}:rd",
    ),
    # ------------------------------------------------------------------
    # WI-DB1-B1 (CCR Appendix AA.2) — interface container removals.
    # All templates start ``interface:`` so the shared walk queues a native
    # line-numbered LIST_REMOVE (family-8e member machinery) and regenerates
    # the byte-exact tombstone FROM the op.  Kind tokens are the model field
    # names (classifier attribution via _tombstone_area for free); the one
    # exception is ``hsrp_vip`` (attr-reset, no model-field twin).
    # Child patterns are $-anchored: FHRP attr-reset grammar beyond the HSRP
    # VIP (priority/preempt/timers/track/authentication/…) deliberately does
    # NOT match — left blind and disclosed (AA.3).
    # ------------------------------------------------------------------
    # Whole HSRP group removal — ``no standby 10`` (IOS) / ``no hsrp 10``
    # (NX-OS sub-block header negation, a direct interface child).
    # Tombstone: ``field:interface:Vlan100:hsrp_groups:10``
    NestedDeletionRule(
        parent_pattern=r"^interface\s+(\S+)\s*$",
        parent_groups=["name"],
        child_pattern=r"^no\s+standby\s+(\d+)\s*$",
        child_groups=["group"],
        template="interface:{name}:hsrp_groups:{group}",
    ),
    NestedDeletionRule(
        parent_pattern=r"^interface\s+(\S+)\s*$",
        parent_groups=["name"],
        child_pattern=r"^no\s+hsrp\s+(\d+)\s*$",
        child_groups=["group"],
        template="interface:{name}:hsrp_groups:{group}",
    ),
    # HSRP VIP attr-reset — ``no standby 1 ip [10.40.1.254]``: resets the
    # group's virtual_ip to None (the group itself survives).  The stated
    # address is not baseline-checked (the device errors on a mismatch; a
    # parse cannot).  Tombstone: ``field:interface:Vlan100:hsrp_vip:1``
    NestedDeletionRule(
        parent_pattern=r"^interface\s+(\S+)\s*$",
        parent_groups=["name"],
        child_pattern=r"^no\s+standby\s+(\d+)\s+ip(?:\s+\d+\.\d+\.\d+\.\d+)?\s*$",
        child_groups=["group"],
        template="interface:{name}:hsrp_vip:{group}",
    ),
    # Whole VRRP / GLBP group removals — ``no vrrp 20`` / ``no glbp 30``.
    NestedDeletionRule(
        parent_pattern=r"^interface\s+(\S+)\s*$",
        parent_groups=["name"],
        child_pattern=r"^no\s+vrrp\s+(\d+)\s*$",
        child_groups=["group"],
        template="interface:{name}:vrrp_groups:{group}",
    ),
    NestedDeletionRule(
        parent_pattern=r"^interface\s+(\S+)\s*$",
        parent_groups=["name"],
        child_pattern=r"^no\s+glbp\s+(\d+)\s*$",
        child_groups=["group"],
        template="interface:{name}:glbp_groups:{group}",
    ),
    # Secondary-address removal — IOS dotted-mask and NX-OS/EOS CIDR forms.
    # ``derive`` computes ONE canonical ``str(IPv4Interface)`` key so the
    # tombstone byte-matches the positive member-SET key (the R.0 basis).
    # Tombstone: ``field:interface:Gi0/1:secondary_ips:10.0.1.5/24``
    NestedDeletionRule(
        parent_pattern=r"^interface\s+(\S+)\s*$",
        parent_groups=["name"],
        child_pattern=(
            r"^no\s+ip\s+address\s+(\d+\.\d+\.\d+\.\d+)"
            r"\s+(\d+\.\d+\.\d+\.\d+)\s+secondary\s*$"
        ),
        child_groups=["ip", "mask"],
        template="interface:{name}:secondary_ips:{cidr}",
        derive=_derive_secondary_cidr,
    ),
    NestedDeletionRule(
        parent_pattern=r"^interface\s+(\S+)\s*$",
        parent_groups=["name"],
        child_pattern=r"^no\s+ip\s+address\s+(\d+\.\d+\.\d+\.\d+/\d+)\s+secondary\s*$",
        child_groups=["addr"],
        template="interface:{name}:secondary_ips:{cidr}",
        derive=_derive_secondary_cidr,
    ),
    # IGMP group-membership removals — dotted-quad operands only (SSM
    # ``… source S`` and non-address operands stay blind, disclosed).
    # Tombstone: ``field:interface:Gi0/1:igmp_join_groups:239.1.1.1``
    NestedDeletionRule(
        parent_pattern=r"^interface\s+(\S+)\s*$",
        parent_groups=["name"],
        child_pattern=r"^no\s+ip\s+igmp\s+join-group\s+(\d+\.\d+\.\d+\.\d+)\s*$",
        child_groups=["group"],
        template="interface:{name}:igmp_join_groups:{group}",
    ),
    NestedDeletionRule(
        parent_pattern=r"^interface\s+(\S+)\s*$",
        parent_groups=["name"],
        child_pattern=r"^no\s+ip\s+igmp\s+static-group\s+(\d+\.\d+\.\d+\.\d+)\s*$",
        child_groups=["group"],
        template="interface:{name}:igmp_static_groups:{group}",
    ),
]
