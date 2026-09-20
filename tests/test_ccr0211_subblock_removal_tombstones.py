"""CCR-0211 follow-up — the two sub-block removals field-level merge exposed.

While keyed-list merge was WHOLESALE, re-entering a block and omitting an
attribute removed it as a side effect, so two real ``no`` commands were never
needed and never parsed.  Once the merge became field-level (correct: on a
device, omitting an attribute does NOT remove it) those removals had no way in
— both lines parsed to an UnrecognizedBlock and were silently never applied.

Two registry rows close them:

- ``no class <name>`` inside ``policy-map <name>``
  → ``field:policy_maps:<pm>:classes:<class>``
- ``no access-class [<acl>] in|out`` inside ``line <type> <first>``
  → ``field:lines:<type>:<first>:access_class_{in|out}``
"""

import tempfile
from pathlib import Path

from confgraph.change_ir import derive_ops
from confgraph.loader import load_and_parse


def _del_paths(pc):
    """Deletion-verb op paths (the whole-object removals ride the NATIVE op
    channel, not ``no_commands``)."""
    return [o.path for o in derive_ops(pc) if o.verb.name in ("OBJECT_DELETE", "UNSET")]


def _parse(text: str, os_type: str = "ios"):
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "dev.cfg"
        p.write_text(text, encoding="utf-8")
        res = load_and_parse(p, os_type=os_type)
        return res[0] if isinstance(res, tuple) else res


class TestPolicyMapClassRemoval:
    TOMBSTONE = "field:policy_maps:EDGE:classes:VOICE"

    def test_removal_emits_the_tombstone(self):
        pc = _parse("policy-map EDGE\n no class VOICE\n")
        assert self.TOMBSTONE in pc.no_commands

    def test_whole_map_removal_is_the_other_shape(self):
        """The whole-map delete must stay distinct from the member one — they
        bind different dispatch rows (and different verbs)."""
        pc = _parse("no policy-map EDGE\n")
        assert ("field", "policy_maps", "EDGE") in _del_paths(pc)
        assert self.TOMBSTONE not in pc.no_commands

    def test_positive_class_does_not_tombstone(self):
        """NEGATIVE: configuring a class must not emit a deletion."""
        pc = _parse("policy-map EDGE\n class VOICE\n  bandwidth percent 30\n")
        assert self.TOMBSTONE not in pc.no_commands
        assert [c.class_name for c in pc.policy_maps[0].classes] == ["VOICE"]

    def test_second_class_needs_no_new_code(self):
        """PARITY: a second class of the same shape rides the same row."""
        pc = _parse("policy-map EDGE\n no class VOICE\n no class DATA\n")
        assert self.TOMBSTONE in pc.no_commands
        assert "field:policy_maps:EDGE:classes:DATA" in pc.no_commands

    def test_typed_policy_map_stays_blind(self):
        """The ``policy-map type …`` form is outside the positive-parse
        boundary, so it stays blind — the ``no class-map`` precedent."""
        pc = _parse("policy-map type qos EDGE\n no class VOICE\n")
        assert self.TOMBSTONE not in pc.no_commands


class TestLineAccessClassRemoval:
    TOMBSTONE = "field:lines:vty:0:access_class_in"

    def test_removal_emits_the_tombstone(self):
        pc = _parse("line vty 0 4\n no access-class MGMT-NET in\n")
        assert self.TOMBSTONE in pc.no_commands

    def test_acl_name_is_grammar_anchor_only(self):
        """The reset is unconditional on the device, so the bare form and a
        different ACL name emit the SAME tombstone."""
        for child in ("no access-class in", "no access-class OTHER in"):
            pc = _parse(f"line vty 0 4\n {child}\n")
            assert self.TOMBSTONE in pc.no_commands

    def test_outbound_direction_rides_the_same_row(self):
        """PARITY: the out direction needs no new rule."""
        pc = _parse("line vty 0 4\n no access-class MGMT-NET out\n")
        assert "field:lines:vty:0:access_class_out" in pc.no_commands

    def test_console_abbreviation_normalizes_to_the_merge_identity(self):
        """``line con 0`` and ``line console 0`` are one block; the key must
        byte-match the merge identity (line_type, first_line)."""
        for header in ("line con 0", "line console 0"):
            pc = _parse(f"{header}\n no access-class MGMT in\n")
            assert "field:lines:console:0:access_class_in" in pc.no_commands

    def test_positive_binding_does_not_tombstone(self):
        """NEGATIVE: the positive form must not emit a deletion."""
        pc = _parse("line vty 0 4\n access-class MGMT-NET in\n")
        assert self.TOMBSTONE not in pc.no_commands
        assert pc.lines[0].access_class_in == "MGMT-NET"

    def test_whole_line_removal_is_the_other_shape(self):
        pc = _parse("no line vty 0 4\n")
        assert ("field", "lines", "vty", "0", "4") in _del_paths(pc)
        assert self.TOMBSTONE not in pc.no_commands
