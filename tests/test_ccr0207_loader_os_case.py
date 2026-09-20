"""CCR-0207 — load_and_parse and as_os_type must be ONE normalizer.

The inline variant lowercased the alias lookup but not the enum fallback, so
"IOS_XE" passed `as_os_type` (a consumer's pre-validation) and then crashed
`load_and_parse` — a hole between the engine's own two answers to the same
question. `load_and_parse` now delegates.
"""

from __future__ import annotations

import pytest

from confgraph.loader import as_os_type, load_and_parse
from confgraph.models.base import OSType


def _parse(tmp_path, os_type):
    p = tmp_path / "c.txt"
    p.write_text("hostname r1\n", encoding="utf-8")
    return load_and_parse(p, os_type=os_type)


def test_every_spelling_as_os_type_accepts_parses_too(tmp_path):
    # The parity property: whatever the public normalizer accepts, the public
    # entry point accepts — including mixed case with no alias row, the exact
    # divergence ("IOS_XE") that crashed before. The normalization happens
    # BEFORE parser dispatch, so PAN-OS spellings (whose parser demands a full
    # XML layout this test has no business constructing) are proven through
    # `as_os_type` equality alone — the delegation is one shared code path.
    spellings = [m.value for m in OSType]
    spellings += [s.upper() for s in spellings] + ["iosxr", "NX-OS", "Pan-Os"]
    for spelling in spellings:
        expected = as_os_type(spelling)
        assert expected is not None, spelling
        if expected is OSType.PANOS:
            continue
        _, detected = _parse(tmp_path, spelling)
        assert detected == expected, spelling


def test_unrecognized_value_raises_the_same_error_shape(tmp_path):
    with pytest.raises(ValueError, match="is not a valid OSType"):
        _parse(tmp_path, "definitely-not-an-os")


def test_ccr0209_document_level_failures_are_parse_errors(tmp_path):
    """CCR-0209 — hostname extraction is inside parse()'s fail-fast contract.

    PAN-OS touches its lazy XML root first during hostname extraction, which ran
    BEFORE the steps loop's ParseError funnel: malformed XML escaped as raw
    ElementTree.ParseError and a wrong-layout document as a bare ValueError
    subclass — invisible to every consumer classifying on the documented
    contract (the platform's device-scoped exclusion among them)."""
    from confgraph.parsers.base import ParseError

    for text in ("<config><garbage></config>",
                 "<config><devices><entry/></devices></config>"):
        p = tmp_path / "c.xml"
        p.write_text(text, encoding="utf-8")
        with pytest.raises(ParseError):
            load_and_parse(p, os_type="panos")
