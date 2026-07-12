"""JunOS configuration-group inheritance (``groups`` / ``apply-groups``).

``show configuration`` does **not** expand inheritance.  It prints the
``groups { … }`` definitions and the ``apply-groups`` statements separately, as
authored.  Juniper is explicit that the expanded form is the real one: *"The
individual software processes that perform the actions directed by the
configuration receive the expanded form of the configuration; they have no
knowledge of configuration groups."*  So a parser that does not expand groups is
not looking at the device's effective configuration — it is looking at a partial
device.  This module performs that expansion, on the canonical tree produced by
:mod:`confgraph.parsers.junos_hierarchy`, so every extractor downstream sees the
effective config in both the brace and the ``set`` rendering.

Precedence rules implemented (Junos OS CLI User Guide, "Use Configuration Groups
to Quickly Configure Devices"):

1. ``apply-groups [ a b c ]`` — names are in priority order; the **first** group
   wins over later ones.
2. Groups named in a **nested** ``apply-groups`` take priority over those named
   in an outer one.
3. A value configured **explicitly** at the target level overrides the inherited
   value.
4. **Sets merge** rather than override: a group contributing
   ``snmp { interface so-1/1/1.0; }`` to a local ``snmp { interface so-0/0/0.0; }``
   yields ``interface [ so-0/0/0.0 so-1/1/1.0 ];``.
5. ``apply-groups-except [ names ];`` suppresses inheritance at a level.

All five fall out of two mechanisms, which is why this is not five special cases:

* **Post-order walk** (children before parents) — deeper ``apply-groups`` are
  applied first, so rule 2 holds.
* **Fill-only merge in insertion order** — a key that already exists is never
  replaced or reordered, only recursed into.  The explicitly configured value was
  inserted at parse time, so it stays *first* among the keys of its statement;
  the first-listed group's contribution lands before a later group's.  Since the
  canonical tree makes a statement's value its first child key, and every reader
  takes the first key (``_str_val``), rules 1 and 3 hold — while a multi-valued
  statement keeps the union of local and inherited members, so rule 4 holds too.

A group body mirrors the hierarchy it will be merged into, and may use
angle-bracketed wildcards for names (``groups { g { interfaces { <ge-*> { … } } } }``).
A wildcard matches *existing* nodes only — it never creates one.
"""

from __future__ import annotations

import copy
import fnmatch
from typing import Any

#: Statements that are inheritance control, never inheritable content.
_CONTROL_KEYS = ("apply-groups", "apply-groups-except")


def expand_apply_groups(tree: dict[str, Any]) -> dict[str, Any]:
    """Expand ``groups`` / ``apply-groups`` inheritance into *tree*, in place.

    Returns *tree* (the effective configuration).  A tree with no ``groups``
    stanza, or with no ``apply-groups`` anywhere, is returned unchanged.
    """
    groups = tree.get("groups")
    if not isinstance(groups, dict) or not groups:
        return tree
    _expand_node(tree, groups, path=[])
    return tree


def _expand_node(
    node: dict[str, Any],
    groups: dict[str, Any],
    path: list[str],
) -> None:
    """Post-order: expand every child of *node*, then *node*'s own apply-groups."""
    for key, child in list(node.items()):
        # ``groups`` holds definitions, not active configuration; the control
        # statements are not hierarchy levels.
        if (not path and key == "groups") or key in _CONTROL_KEYS:
            continue
        if isinstance(child, dict):
            _expand_node(child, groups, [*path, key])

    names = _names(node.get("apply-groups"))
    if not names:
        return
    suppressed = _names(node.get("apply-groups-except"))
    for name in names:
        if name in suppressed:
            continue
        body = _descend(groups.get(name), path)
        if isinstance(body, dict) and body:
            _fill(node, body, name)


def _names(value: Any) -> list[str]:
    """Group names from an ``apply-groups`` node, in configured order."""
    if not isinstance(value, dict):
        return []
    return [k for k in value if k]


def _descend(body: Any, path: list[str]) -> dict[str, Any] | None:
    """Return the part of a group *body* that sits at hierarchy *path*.

    A group's content mirrors the hierarchy it is applied to, so an
    ``apply-groups`` at ``protocols bgp group EXT`` inherits only
    ``groups <name> protocols bgp group EXT { … }``.  Wildcard keys match here
    too, so a group written against ``<*>`` applies at a named level.
    """
    node = body
    for key in path:
        if not isinstance(node, dict):
            return None
        child = node.get(key)
        if child is None:
            child = next(
                (v for k, v in node.items() if _wildcard_match(k, key)), None
            )
        if child is None:
            return None
        node = child
    return node if isinstance(node, dict) else None


def _wildcard_match(group_key: str, target_key: str) -> bool:
    """True if an angle-bracketed group key (``<ge-*>``) matches *target_key*."""
    if not (group_key.startswith("<") and group_key.endswith(">")):
        return False
    return fnmatch.fnmatchcase(target_key, group_key[1:-1])


def _fill(target: dict[str, Any], src: dict[str, Any], group: str) -> None:
    """Merge *src* (a group body) into *target*, adding only what is missing.

    Never replaces or reorders an existing key — that is what makes an explicit
    local value win over the inherited one, and an earlier group win over a
    later one (see module docstring).
    """
    if group in _names(target.get("apply-groups-except")):
        return  # rule 5: this subtree opted out of this group
    for key, val in src.items():
        if key in _CONTROL_KEYS:
            continue
        if key.startswith("<") and key.endswith(">"):
            # A wildcard applies to existing siblings; it never creates a node.
            for tkey, tval in list(target.items()):
                if isinstance(tval, dict) and _wildcard_match(key, tkey):
                    _fill(tval, val, group)
            continue
        existing = target.get(key)
        if existing is None:
            target[key] = copy.deepcopy(val)
        elif isinstance(existing, dict) and isinstance(val, dict):
            _fill(existing, val, group)
