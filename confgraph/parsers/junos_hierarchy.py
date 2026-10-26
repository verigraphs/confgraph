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
# Idioms the canonical tree cannot represent
# ---------------------------------------------------------------------------
#
# Both renderings can carry statements that CHANGE the configuration database
# rather than state a value.  The canonical tree holds values only, so folding
# such a statement in under its own keyword inverts its meaning: a dropped
# ``delete`` leaves the object present, a folded ``inactive:`` moves the real
# subtree out from under the extractors.  They are disclosed instead
# (CCR-0210) — see ``unsupported_lines`` below.

#: JunOS configuration-mode verbs other than ``set``.  This set is the whole
#: family: adding the next verb is one entry, and it is what routes a document
#: of nothing but ``delete`` lines to the ``set`` idiom (where it gets
#: disclosed) instead of to the brace tokenizer, which — the lines carrying no
#: ``;`` or ``{`` — discards every one of them at EOF and returns an empty tree.
NON_SET_VERBS: frozenset[str] = frozenset({
    "delete", "deactivate", "activate", "replace",
    "rename", "annotate", "insert", "copy",
})

#: The subset of :data:`NON_SET_VERBS` that REMOVES configuration, and so can
#: be expressed as a change op instead of only disclosed (CCR-0214).
#:
#: ``deactivate`` is in here with ``delete`` because the two have the same
#: effect on the RUNNING configuration, which is the only configuration this
#: model holds: an inactive subtree does not contribute to it.  The config
#: DATABASE keeps a deactivated subtree and ``delete`` does not, but confgraph
#: renders no JunOS text from the model, so that distinction has nowhere to
#: leak to.  ``activate`` is NOT here and cannot be: restoring an inactive
#: subtree needs the inactive content, which the model never held.
#:
#: Membership here only says "this verb removes something".  WHICH removals
#: compile is decided in one place — the path registry in
#: :mod:`confgraph.parsers.junos_deletions` — and everything it does not match
#: stays on the CCR-0210 disclosure channel.
DELETION_VERBS: frozenset[str] = frozenset({"delete", "deactivate"})

#: Brace-idiom statement tags — a prefix on an ordinary statement that changes
#: its STATE rather than its value.
BRACE_STATEMENT_TAGS: frozenset[str] = frozenset({"inactive:", "replace:"})


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
        tree = _parse_brace_style(text)
    return expand_apply_groups(tree)


def unsupported_lines(text: str) -> list[str]:
    """Config lines in *text* the canonical tree cannot represent, in file order.

    The ``set`` idiom's non-``set`` verbs and the brace idiom's
    :data:`BRACE_STATEMENT_TAGS` are returned comment-stripped and whitespace-
    stripped, for the parser to disclose as ``UnrecognizedBlock``\\ s.  Routing
    is the same :func:`_is_set_style` decision :func:`parse_junos_config`
    makes, so the two never disagree about which idiom a document is.

    The brace branch is additionally fail-closed on the PARSE OUTCOME
    (CCR-0217).  A document carrying no JunOS idiom at all — Cisco ``no``
    commands, an IOS ``interface`` block, anything an operator on a mixed
    fleet might paste — reaches the brace tokenizer, which drops every
    statement that never reaches a ``;`` or ``{`` and returns an empty tree.
    So the question "was anything represented?" is asked of the tree rather
    than of a list of foreign keywords to recognize: content in, nothing out,
    disclose the content.  The next foreign idiom costs no code.

    ``delete`` / ``deactivate`` lines are returned here TOO, even though some
    of them now compile to change ops (CCR-0214).  This function is the
    fail-closed answer on its own — a caller that compiles nothing discloses
    everything — and :class:`~confgraph.parsers.junos_parser.JunOSParser`
    subtracts exactly the lines it compiled, so the modelled/unmodelled
    partition is applied in ONE place and no line can end up both compiled and
    disclosed, or neither.
    """
    if _is_set_style(text):
        return [
            line
            for line, kind in (_classify_set_line(raw) for raw in text.splitlines())
            if kind in ("unsupported", "deletion")
        ]
    content = [
        stripped
        for stripped in (line.strip() for line in _strip_comments(text).splitlines())
        if stripped
    ]
    if content and not _parse_brace_style(text):
        return content
    return [
        line for line in content if line.split(" ", 1)[0] in BRACE_STATEMENT_TAGS
    ]


def _is_set_style(text: str) -> bool:
    """Return True if *text* looks like JunOS ``set``-style (flat set commands).

    The whole configuration-mode verb family counts, not just ``set``: a
    proposal written entirely of ``delete`` lines is the ``set`` idiom too.
    """
    set_count = 0
    brace_count = 0
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("set ") or stripped.split(" ", 1)[0] in NON_SET_VERBS:
            set_count += 1
        if "{" in stripped or "}" in stripped:
            brace_count += 1
        if set_count >= 3:
            return True
        if brace_count >= 3:
            return False
    return set_count > 0


def _classify_set_line(raw_line: str) -> tuple[str, str]:
    """Classify one line of a ``set``-style document.

    Returns ``(text, kind)`` for the comment-stripped line:

    ``"set"``
        a statement the canonical tree carries;
    ``"deletion"``
        a :data:`DELETION_VERBS` statement — it REMOVES configuration, so it
        may compile to a change op (CCR-0214);
    ``"skip"``
        blank or comment-only;
    ``"unsupported"``
        everything else.

    One classification, three consumers — :func:`_parse_set_style` keeps the
    ``set`` lines, :func:`deletion_statements` hands the deletions to the op
    emitter, and :func:`unsupported_lines` discloses everything the tree
    cannot represent.  A line can never be both dropped and undisclosed, and
    the router stays model-blind: it says a line removes something, never
    whether the model can express that removal.
    """
    line = raw_line.strip()
    # Strip inline ## comments (e.g. the ## SECRET-DATA marker)
    comment_idx = line.find("##")
    if comment_idx != -1:
        line = line[:comment_idx].strip()
    if not line or line.startswith("#") or line.startswith("/*"):
        return line, "skip"
    if line.startswith("set "):
        return line, "set"
    if line.split(" ", 1)[0] in DELETION_VERBS:
        return line, "deletion"
    return line, "unsupported"


def deletion_statements(text: str) -> list[tuple[int, str, tuple[str, ...]]]:
    """Every ``delete`` / ``deactivate`` statement in *text*, in file order.

    Returns ``(line_no, line, path)`` triples — the 1-based config line number,
    the comment-stripped line, and the statement's CANONICAL TOKEN PATH: the
    tokens after the verb, tokenized by exactly the function that tokenizes a
    ``set`` line (:func:`_tokenize_set_line`), because ``delete A B C`` and
    ``set A B C`` address the same node of the same tree.  That is the whole
    reason deletion support costs a path registry rather than a second parser.

    Bracketed runs are left as their literal ``[`` / ``]`` tokens rather than
    folded: a bracketed deletion addresses several nodes at once, no registry
    row claims a path containing a bracket token, and so it falls through to
    disclosure — fail-closed, which is the right default for a removal.

    Brace-idiom documents return nothing: the brace rendering has no deletion
    verb (its nearest equivalent, the ``inactive:`` statement tag, stays
    disclosed — see :data:`BRACE_STATEMENT_TAGS`).
    """
    return _statements_of_kind(text, "deletion")


def set_statements(text: str) -> list[tuple[int, str, tuple[str, ...]]]:
    """Every ``set`` statement in *text*, in file order, shaped like a deletion.

    The exact mirror of :func:`deletion_statements`, from the same
    classification pass and the same tokenizer, so the two kinds of statement
    produce COMPARABLE paths.  That comparability is the point: a ``delete``
    and a later ``set`` under the same path are a stanza REWRITE, which the
    model cannot represent, and recognizing one means comparing the two paths
    (:func:`confgraph.parsers.junos_deletions.collides_with_later_set`).

    Tokens only — no bracket folding and no tree building — because the
    comparison is positional.  :func:`_parse_set_style` remains the function
    that turns these lines into the canonical tree; this one never does.
    """
    return _statements_of_kind(text, "set")


def _statements_of_kind(
    text: str, kind: str
) -> list[tuple[int, str, tuple[str, ...]]]:
    """``(line_no, line, token path)`` for every line of one classification.

    The path is the tokens AFTER the leading verb, so ``set`` and ``delete``
    lines addressing the same node yield the same tuple.
    """
    if not _is_set_style(text):
        return []
    out: list[tuple[int, str, tuple[str, ...]]] = []
    for line_no, raw in enumerate(text.splitlines(), start=1):
        line, line_kind = _classify_set_line(raw)
        if line_kind != kind:
            continue
        _verb, _, remainder = line.partition(" ")
        out.append((line_no, line, tuple(_tokenize_set_line(remainder))))
    return out


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
        line, kind = _classify_set_line(raw_line)
        if kind != "set":
            continue

        parts = _tokenize_set_line(line[4:])  # strip leading 'set '
        if not parts:
            continue

        _merge_at_path(result, _fold_brackets(parts), {})

    return result


def _parse_brace_style(text: str) -> dict[str, Any]:
    """Convert JunOS brace-style config into the canonical tree.

    The tree as the tokenizer builds it, BEFORE group expansion — the form
    :func:`unsupported_lines` asks about, since expansion only ever fills a
    tree in and so cannot answer "did this document state anything at all?".
    """
    tree, _ = _parse_block(_tokenize(text), 0)
    return tree


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

def _strip_comments(text: str) -> str:
    """Remove JunOS comments — C-style ``/* … */`` spans and ``#``-to-EOL."""
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    return re.sub(r"#[^\n]*", "", text)


def _tokenize(text: str) -> list[str]:
    """Tokenise JunOS config text into a flat list of string tokens."""
    text = _strip_comments(text)

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
