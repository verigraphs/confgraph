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
    """Parse JunOS brace-style config *text* into a nested dict.

    Returns a ``dict[str, Any]`` where values are:
    - ``str``   — leaf statement value
    - ``dict``  — child block
    - ``list``  — multiple values for the same keyword (leaves or blocks)
    """
    tokens = _tokenize(text)
    result, _ = _parse_block(tokens, 0)
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
