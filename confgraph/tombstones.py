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

from typing import NamedTuple


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
    """

    parent_pattern: str
    parent_groups: list
    child_pattern: str
    child_groups: list
    template: str


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
]
