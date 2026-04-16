"""JunOS brace-style configuration tokenizer.

Converts JunOS hierarchical (brace-delimited) config text into a nested
dict structure that downstream parsers can navigate.

Structure rules
---------------
- Leaf statement  ``keyword value;``  → ``{keyword: value_str}``
- Anonymous block ``keyword { ... }`` → ``{keyword: {…}}``
- Named block     ``keyword name { … }`` → ``{keyword: {name: {…}}}``
- Bracketed list  ``keyword [ a b c ];`` → ``{keyword: "a b c"}``
- Duplicate keys: first occurrence wins for scalars; blocks accumulate
  under the same dict so later children are merged in.

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

    Returns a ``dict[str, Any]`` where values are:
    - ``str``   — leaf statement value (brace-style only)
    - ``dict``  — child block / named block
    - ``list``  — multiple values for the same keyword (brace-style)

    In set-style output every node is a ``dict``; leaf values are single-key
    dicts, e.g. ``{'peer-as': {'65006': {}}}`` instead of ``{'peer-as': '65006'}``.
    Use ``_str_val()`` in the parser layer to transparently handle both shapes.
    """
    if _is_set_style(text):
        return _parse_set_style(text)
    tokens = _tokenize(text)
    result, _ = _parse_block(tokens, 0)
    return result


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
    """Convert JunOS ``set``-style config into the same nested dict as brace-style.

    Each ``set A B C … Z`` line becomes a path ``A → B → C → … → Z`` of nested
    dicts.  The last token is stored as a key pointing to ``{}`` so that the
    caller can always use ``.get(key)`` and get either a dict of children or an
    empty dict representing the presence of a leaf.

    The parser layer uses :func:`_str_val` to extract a scalar from either a
    plain string (brace-style leaf) or the first key of such a dict (set-style).
    """
    result: dict[str, Any] = {}

    for raw_line in text.splitlines():
        line = raw_line.strip()
        # Strip inline ## comments
        comment_idx = line.find("##")
        if comment_idx != -1:
            line = line[:comment_idx].strip()
        if not line.startswith("set "):
            continue

        parts = _tokenize_set_line(line[4:])  # strip leading 'set '
        if not parts:
            continue

        # Navigate / create nested dicts for each token in the path
        node = result
        for part in parts[:-1]:
            if part not in node or not isinstance(node[part], dict):
                node[part] = {}
            node = node[part]

        # Last token: insert as key → {} (merges if already present as dict)
        last = parts[-1]
        if last not in node:
            node[last] = {}
        elif not isinstance(node[last], dict):
            node[last] = {}  # overwrite stray scalar (shouldn't happen)

    return result


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
            # Quoted string — scan to closing quote, respecting backslash escapes
            j = i + 1
            while j < n:
                if text[j] == "\\" and j + 1 < n:
                    j += 2
                    continue
                if text[j] == '"':
                    break
                j += 1
            tokens.append(text[i : j + 1])
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

        # Collect value-part tokens until we hit ``{``, ``;``, ``}``, or EOF
        value_parts: list[str] = []
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
                value_parts.append(" ".join(list_items))
            else:
                value_parts.append(tokens[pos])
                pos += 1

        if pos < len(tokens) and tokens[pos] == "{":
            pos += 1  # consume '{'
            child, pos = _parse_block(tokens, pos)

            if value_parts:
                # Named block: keyword  name  { … }
                # Store as result[keyword][name] = child
                name = " ".join(value_parts)
                if keyword not in result:
                    result[keyword] = {}
                container = result[keyword]
                if not isinstance(container, dict):
                    # Shouldn't normally happen; replace scalar with dict
                    container = {}
                    result[keyword] = container
                if name in container:
                    # Merge duplicate named blocks
                    existing = container[name]
                    if isinstance(existing, dict):
                        _deep_merge(existing, child)
                    else:
                        container[name] = child
                else:
                    container[name] = child
            else:
                # Anonymous block: keyword  { … }
                if keyword not in result:
                    result[keyword] = child
                elif isinstance(result[keyword], dict):
                    _deep_merge(result[keyword], child)
                else:
                    result[keyword] = child

        elif pos < len(tokens) and tokens[pos] == ";":
            pos += 1  # consume ';'
            value = " ".join(value_parts)
            _set_leaf(result, keyword, value)

        # else: EOF before semicolon or brace — discard incomplete statement

    return result, pos


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _set_leaf(result: dict[str, Any], key: str, value: str) -> None:
    """Insert *value* under *key*, converting to list on duplicates."""
    if key not in result:
        result[key] = value
    else:
        existing = result[key]
        if isinstance(existing, list):
            existing.append(value)
        else:
            result[key] = [existing, value]


def _deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> None:
    """Merge *overlay* into *base* in-place (recursive for nested dicts)."""
    for key, val in overlay.items():
        if key in base and isinstance(base[key], dict) and isinstance(val, dict):
            _deep_merge(base[key], val)
        elif key in base:
            existing = base[key]
            if isinstance(existing, list):
                existing.append(val)
            else:
                base[key] = [existing, val]
        else:
            base[key] = val
