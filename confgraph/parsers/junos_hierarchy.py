"""JunOS configuration tokenizer — one canonical tree for both renderings.

A JunOS device prints its single configuration database in two forms, and both
are device-emitted (``show configuration`` and ``show configuration | display
set``); real automation stores both.  They are two renderings of ONE tree:

    protocols { bgp { group EXT { peer-as 65001; } } }      # brace
    set protocols bgp group EXT peer-as 65001               # set

The two carry exactly the same token sequence, so this module parses both into
exactly the same nested dict — the *canonical tree*:

**Every node is a dict.  A statement's trailing tokens are its nested keys.**

    keyword;                     → {keyword: {}}
    keyword a;                   → {keyword: {a: {}}}
    keyword a b;                 → {keyword: {a: {b: {}}}}
    keyword name { child x; }    → {keyword: {name: {child: {x: {}}}}}
    keyword [ a b ];             → {keyword: {a: {}, b: {}}}
    set … keyword a b            → {keyword: {a: {b: {}}}}      (identical)

Consequences the parser layer relies on:

- There are **no ``str`` or ``list`` values** in the tree, so extractors need no
  per-statement shape branch; ``_str_val()`` yields a scalar from any node.
- A leaf statement's inline options survive as a key chain, so
  ``stub default-metric 10 no-summaries;`` and the two ``set`` lines that mean
  the same thing both flatten (DFS pre-order) to the token list
  ``["default-metric", "10", "no-summaries"]`` — see ``_stmt_tokens()`` in
  ``junos_parser``.
- Duplicate statements merge into sibling keys rather than degrading into a
  list, so ``route`` is a dict whether the block form is used or not.

Group inheritance (``groups`` / ``apply-groups``) is expanded here as well:
``show configuration`` prints groups UNEXPANDED, and the JunOS software
processes only ever see the expanded form, so the effective configuration is the
expanded one (see :mod:`confgraph.parsers.junos_groups`).

Comments (``/* … */`` and ``#``-to-EOL) are stripped before tokenising.
"""

from __future__ import annotations

import re
from typing import Any


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_junos_config(text: str) -> dict[str, Any]:
    """Parse JunOS config *text* — auto-detects brace-style vs ``set``-style.

    Returns the canonical tree described in the module docstring: a
    ``dict[str, dict]`` in which *every* value is a dict, for both input forms.

    ``groups`` / ``apply-groups`` inheritance is expanded before the tree is
    returned, so callers always see the **effective** configuration.
    """
    from confgraph.parsers.junos_groups import expand_apply_groups

    if _is_set_style(text):
        tree = _parse_set_style(text)
    else:
        tokens = _tokenize(text)
        tree, _ = _parse_block(tokens, 0)
    return expand_apply_groups(tree)


def _is_set_style(text: str) -> bool:
    """Return True if *text* looks like JunOS ``set``-style (flat set commands)."""
    set_count = 0
    brace_count = 0
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("set "):
            set_count += 1
        if "{" in stripped or "}" in stripped:
            brace_count += 1
        if set_count >= 3:
            return True
        if brace_count >= 3:
            return False
    return set_count > 0


def _tokenize_set_line(line: str) -> list[str]:
    """Tokenize a single set-style line into a list of string tokens.

    Handles quoted strings like ``set system host-name "my router"``.
    """
    tokens: list[str] = []
    i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        if ch in " \t":
            i += 1
            continue
        if ch == '"':
            j = i + 1
            while j < n:
                if line[j] == "\\" and j + 1 < n:
                    j += 2
                    continue
                if line[j] == '"':
                    break
                j += 1
            # Strip surrounding quotes
            tokens.append(line[i + 1 : j])
            i = j + 1
            continue
        j = i
        while j < n and line[j] not in " \t\"":
            j += 1
        tokens.append(line[i:j])
        i = j
    return [t for t in tokens if t]


def _parse_set_style(text: str) -> dict[str, Any]:
    """Convert JunOS ``set``-style config into the canonical tree.

    Each ``set A B C … Z`` line is the path ``A → B → C → … → Z``.  This is the
    same operation the brace parser performs on a leaf statement's token
    sequence — which is why the two forms converge on one tree.

    A bracketed list (``set … apply-groups [ a b ]``) becomes sibling keys, as
    it does in brace form.
    """
    result: dict[str, Any] = {}

    for raw_line in text.splitlines():
        line = raw_line.strip()
        # Strip inline ## comments (e.g. the ## SECRET-DATA marker)
        comment_idx = line.find("##")
        if comment_idx != -1:
            line = line[:comment_idx].strip()
        if not line.startswith("set "):
            continue

        parts = _tokenize_set_line(line[4:])  # strip leading 'set '
        if not parts:
            continue

        _merge_at_path(result, _fold_brackets(parts), {})

    return result


def _fold_brackets(parts: list[str]) -> list[str | list[str]]:
    """Fold a bracketed run ``[ a b ]`` in a token list into one list element."""
    if "[" not in parts:
        return list(parts)
    path: list[str | list[str]] = []
    items: list[str] | None = None
    for tok in parts:
        if tok == "[":
            items = []
        elif tok == "]":
            if items:
                path.append(items)
            items = None
        elif items is not None:
            items.append(tok)
        else:
            path.append(tok)
    if items:
        path.append(items)
    return path


# ---------------------------------------------------------------------------
# Tokenizer
# ---------------------------------------------------------------------------

def _tokenize(text: str) -> list[str]:
    """Tokenise JunOS config text into a flat list of string tokens."""
    # Strip C-style block comments
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    # Strip shell-style line comments
    text = re.sub(r"#[^\n]*", "", text)

    tokens: list[str] = []
    i = 0
    n = len(text)

    while i < n:
        ch = text[i]

        if ch in " \t\n\r":
            i += 1
            continue

        if ch in "{}[];":
            tokens.append(ch)
            i += 1
            continue

        if ch == '"':
            # Quoted string — scan to closing quote, respecting backslash
            # escapes.  The quotes are stripped so that a quoted value produces
            # the same canonical key as the ``set`` rendering of the same
            # statement, where ``_tokenize_set_line`` also strips them.
            j = i + 1
            while j < n:
                if text[j] == "\\" and j + 1 < n:
                    j += 2
                    continue
                if text[j] == '"':
                    break
                j += 1
            tokens.append(text[i + 1 : j])
            i = j + 1
            continue

        # Bare token (keyword, identifier, number, IP address, …)
        j = i
        while j < n and text[j] not in " \t\n\r{}[];\"":
            j += 1
        tokens.append(text[i:j])
        i = j

    return tokens


# ---------------------------------------------------------------------------
# Recursive block parser
# ---------------------------------------------------------------------------

def _parse_block(tokens: list[str], pos: int) -> tuple[dict[str, Any], int]:
    """Parse tokens from *pos* into a dict.  Stops at ``}`` or end of list.

    Returns ``(result_dict, next_pos)`` where *next_pos* points past the
    closing ``}`` (or to ``len(tokens)`` if EOF is reached first).
    """
    result: dict[str, Any] = {}

    while pos < len(tokens):
        tok = tokens[pos]

        if tok == "}":
            return result, pos + 1

        if tok == ";":
            # Stray semicolon — skip
            pos += 1
            continue

        # tok is a keyword
        keyword = tok
        pos += 1

        # Collect value-part tokens until we hit ``{``, ``;``, ``}``, or EOF.
        # A bracketed list becomes ONE value-part holding several alternatives.
        value_parts: list[str | list[str]] = []
        while pos < len(tokens) and tokens[pos] not in ("{", ";", "}"):
            if tokens[pos] == "[":
                # Bracketed value list: [ a b c ]
                pos += 1  # consume '['
                list_items: list[str] = []
                while pos < len(tokens) and tokens[pos] != "]":
                    if tokens[pos] != ";":
                        list_items.append(tokens[pos])
                    pos += 1
                pos += 1  # consume ']'
                value_parts.append(list_items)
            else:
                value_parts.append(tokens[pos])
                pos += 1

        if pos < len(tokens) and tokens[pos] == "{":
            pos += 1  # consume '{'
            child, pos = _parse_block(tokens, pos)
            # Named block ``keyword name { … }`` and anonymous block
            # ``keyword { … }`` are the same operation on the canonical tree:
            # walk the path [keyword, *name_tokens] and merge the body in.
            _merge_at_path(result, [keyword, *value_parts], child)

        elif pos < len(tokens) and tokens[pos] == ";":
            pos += 1  # consume ';'
            # Leaf statement: the trailing tokens ARE the nested path, exactly
            # as the ``set`` rendering of the same statement would produce.
            _merge_at_path(result, [keyword, *value_parts], {})

        # else: EOF before semicolon or brace — discard incomplete statement

    return result, pos


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _merge_at_path(
    root: dict[str, Any],
    path: list[str | list[str]],
    body: dict[str, Any],
) -> None:
    """Merge *body* into *root* at *path*, creating intermediate dicts.

    *path* is the statement's token sequence (keyword first).  A path element
    that is a ``list`` is a bracketed value list: its members become sibling
    keys at that position, so ``export [ A B ];`` and the two ``set … export A``
    / ``set … export B`` lines both yield ``{export: {A: {}, B: {}}}``.
    """
    if not path:
        return
    head, rest = path[0], path[1:]
    names = head if isinstance(head, list) else [head]
    for name in names:
        child = root.get(name)
        if not isinstance(child, dict):
            child = {}
            root[name] = child
        if rest:
            _merge_at_path(child, rest, body)
        else:
            _deep_merge(child, body)


def _deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> None:
    """Merge *overlay* into *base* in-place (recursive)."""
    for key, val in overlay.items():
        existing = base.get(key)
        if isinstance(existing, dict) and isinstance(val, dict):
            _deep_merge(existing, val)
        else:
            base[key] = val
