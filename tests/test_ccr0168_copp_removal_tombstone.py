"""CCR-0168 — ``no service-policy input`` under ``control-plane`` tombstones.

One registry row closes the deletion half of the CoPP surface (CCR-0151
landed the additive half): the removal emits
``field:control_plane:service_policy_input``, which the engine's reflective
scalar-reset catch-all already applies — ZERO entrp changes (the design
review measured the catch-all resolving this path end-to-end; a specific
table row would shadow a working generic handler).
"""

import tempfile
from pathlib import Path

from confgraph.loader import load_and_parse


def _parse(text: str, os_type: str = "nxos"):
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "dev.cfg"
        p.write_text(text, encoding="utf-8")
        res = load_and_parse(p, os_type=os_type)
        return res[0] if isinstance(res, tuple) else res


TOMBSTONE = "field:control_plane:service_policy_input"


class TestCoppRemovalTombstone:
    def test_removal_emits_the_tombstone(self):
        pc = _parse("control-plane\n  no service-policy input PM_COPP\n")
        assert TOMBSTONE in pc.no_commands

    def test_pm_name_is_grammar_anchor_only(self):
        """The reset is unconditional — a different PM name emits the SAME
        tombstone (the capture anchors the grammar, as on the device)."""
        pc = _parse("control-plane\n  no service-policy input SOMETHING_ELSE\n")
        assert TOMBSTONE in pc.no_commands

    def test_positive_binding_does_not_tombstone(self):
        """NEGATIVE: the positive form must not emit a deletion."""
        pc = _parse("control-plane\n  service-policy input PM_COPP\n")
        assert TOMBSTONE not in pc.no_commands
        assert pc.control_plane is not None

    def test_ios_spelling_rides_the_same_rule(self):
        """PARITY: parse_deletion_commands is shared — the IOS control-plane
        block form emits the identical tombstone with zero extra code."""
        pc = _parse("control-plane\n no service-policy input COPP-POLICY\n",
                    os_type="ios")
        assert TOMBSTONE in pc.no_commands
