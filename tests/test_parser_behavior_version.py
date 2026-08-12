"""PARSER_BEHAVIOR_VERSION contract (CCR-0097).

The constant is the parser-version input to parse-cache and input-digest keys
(platform parse_cache ``::pbv=<n>``; CCR-0082 digest keys). These tests pin its
exported shape and the same-commit bump rule against silent regression.
"""

import confgraph.parsers as parsers
from confgraph.parsers import PARSER_BEHAVIOR_VERSION


def test_constant_is_a_positive_int_not_bool():
    # bool is a subclass of int; exclude it explicitly.
    assert type(PARSER_BEHAVIOR_VERSION) is int
    # Monotonic floor — raised in the same commit as each behavior change so a
    # revert/merge cannot silently roll the constant backwards (last: CCR-0192).
    assert PARSER_BEHAVIOR_VERSION >= 7


def test_constant_is_exported():
    assert "PARSER_BEHAVIOR_VERSION" in parsers.__all__
    assert parsers.PARSER_BEHAVIOR_VERSION is PARSER_BEHAVIOR_VERSION


def test_docstring_pins_same_commit_bump_rule():
    # Guards the maintenance rule against silent docstring deletion.
    assert "in the same commit as the behavior change" in parsers.__doc__
