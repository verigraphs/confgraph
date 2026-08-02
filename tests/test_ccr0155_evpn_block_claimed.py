"""CCR-0155 — the NX-OS ``evpn`` block is claimed, not double-recorded.

Before: parse_evpn parsed the top-level ``evpn`` block into ``parsed.evpn``
AND the unrecognized collector recorded the same lines — a report could say
"evpn analyzed" and "unrecognized config present" about the same text, and
the raw block moved digest family F6 alongside F9 on every EVPN edit.
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


EVPN_CFG = """hostname leaf1
feature nv overlay
evpn
  vni 90901 l2
    rd auto
    route-target import auto
    route-target export auto
"""


class TestEvpnBlockClaimed:
    def test_parsed_and_not_unrecognized(self):
        """Both surfaces, one truth: the block parses AND no unrecognized
        entry references it."""
        pc = _parse(EVPN_CFG)
        assert pc.evpn is not None
        assert [v.vni for v in pc.evpn.l2vnis] == [90901]
        assert not [
            b for b in pc.unrecognized_blocks if b.block_header.startswith("evpn")
        ]

    def test_unknown_direct_child_still_discloses(self):
        """Claiming the block must not silence UNPARSED lines inside it —
        an unknown direct child still surfaces as `evpn > <line>`."""
        pc = _parse(EVPN_CFG + "  fabric-forwarding-mode bogus\n")
        assert any(
            "fabric-forwarding-mode bogus" in b.block_header
            for b in pc.unrecognized_blocks
        )

    def test_known_child_is_not_flagged(self):
        """PRECISION: the consumed ``vni <n> l2`` child is never flagged."""
        pc = _parse(EVPN_CFG)
        assert not [
            b for b in pc.unrecognized_blocks if "vni 90901" in b.block_header
        ]

    def test_unrelated_unknown_block_still_discloses(self):
        """REGRESSION: a genuinely unknown top-level block still surfaces."""
        pc = _parse(EVPN_CFG + "totally-unknown-block\n  some line\n")
        assert any(
            b.block_header.startswith("totally-unknown-block")
            for b in pc.unrecognized_blocks
        )
