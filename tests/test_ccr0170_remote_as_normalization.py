"""CCR-0170 — remote_as is fail-closed: int | None, never a string.

The old ``int | str`` union let ANY non-int spelling (asdot was the
measured case) silently bypass every AS-agreement check and form
sessions with no AS validation at all.  Now a model validator — the
single seam, shared by every parser through construction — normalizes
decimal and RFC 5396 asdot spellings to int and REJECTS everything
else; provenance/peer-type facts live on the new ``remote_as_source``.
"""

import tempfile
from pathlib import Path

import pytest

from confgraph.loader import load_and_parse
from confgraph.models.bgp import BGPNeighbor, BGPPeerGroup, normalize_remote_as

ASDOT_INT = 65002 * 65536 + 100  # "65002.100" per RFC 5396


def _parse(text: str, os_type: str):
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "dev.cfg"
        p.write_text(text, encoding="utf-8")
        res = load_and_parse(p, os_type=os_type)
        return res[0] if isinstance(res, tuple) else res


class TestValidatorSeam:
    def test_asdot_normalizes(self):
        n = BGPNeighbor(peer_ip="10.0.0.1", remote_as="65002.100")
        assert n.remote_as == ASDOT_INT
        assert isinstance(n.remote_as, int)

    def test_decimal_string_normalizes(self):
        assert BGPNeighbor(peer_ip="10.0.0.1", remote_as="65010").remote_as == 65010

    def test_asdot_bounds(self):
        assert normalize_remote_as("65535.65535") == 4294967295
        with pytest.raises(ValueError):
            normalize_remote_as("70000.1")
        with pytest.raises(ValueError):
            normalize_remote_as("1.70000")

    def test_legacy_sentinels_rejected(self):
        """The retired string arms must FAIL LOUDLY — a parser passing
        them through is a bug, not a neighbor that silently skips every
        AS check (the fail-open class this CCR closes)."""
        for legacy in ("inherited", "internal", "external", "garbage"):
            with pytest.raises(ValueError):
                BGPNeighbor(peer_ip="10.0.0.1", remote_as=legacy)

    def test_peer_group_shares_the_seam(self):
        """PARITY: BGPPeerGroup runs the same validator — zero extra code."""
        assert BGPPeerGroup(name="PG", remote_as="1.1").remote_as == 65537
        with pytest.raises(ValueError):
            BGPPeerGroup(name="PG", remote_as="inherited")

    def test_peer_type_lives_on_source(self):
        n = BGPNeighbor(peer_ip="10.0.0.1", remote_as=None,
                        remote_as_source="external")
        assert n.remote_as is None and n.remote_as_source == "external"


class TestParserParity:
    """asdot through REAL parsers — the fix is the shared seam, so each
    OS needs zero parser-specific normalization code."""

    def test_ios_asdot(self):
        pc = _parse(
            "hostname r1\n"
            "router bgp 65001\n"
            " neighbor 10.0.0.2 remote-as 65002.100\n",
            "ios",
        )
        (n,) = pc.bgp_instances[0].neighbors
        assert n.remote_as == ASDOT_INT
        assert n.remote_as_source == "declared"

    def test_junos_asdot(self):
        pc = _parse(
            "set system host-name j1\n"
            "set routing-options autonomous-system 65001\n"
            "set protocols bgp group EXT type external\n"
            "set protocols bgp group EXT peer-as 65002.100\n"
            "set protocols bgp group EXT neighbor 10.0.0.2\n",
            "junos",
        )
        (n,) = pc.bgp_instances[0].neighbors
        assert n.remote_as == ASDOT_INT
        assert n.remote_as_source == "declared"


class TestJunosPeerTypes:
    def test_type_internal_resolves_to_own_asn_with_provenance(self):
        """J9 behavior preserved (value = device's own ASN) — provenance
        now stamped instead of a magic 0/'internal' arm."""
        pc = _parse(
            "set system host-name j1\n"
            "set routing-options autonomous-system 65001\n"
            "set protocols bgp group IBGP type internal\n"
            "set protocols bgp group IBGP neighbor 10.0.0.2\n",
            "junos",
        )
        (n,) = pc.bgp_instances[0].neighbors
        assert n.remote_as == 65001
        assert n.remote_as_source == "internal"
        pg = next(g for g in pc.bgp_instances[0].peer_groups
                  if g.name == "IBGP")
        assert pg.remote_as is None
        assert pg.remote_as_source == "internal"


class TestTrailingTokens:
    """Validation finding 1 (BLOCKER): the AS spelling is the FIRST token —
    trailing sub-options or inline comments must not abort the device."""

    def test_alternate_as_suboption_survives(self):
        pc = _parse(
            "hostname r1\n"
            "router bgp 65001\n"
            " neighbor 10.0.0.2 remote-as 65002 alternate-as 65003\n",
            "ios",
        )
        (n,) = pc.bgp_instances[0].neighbors
        assert n.remote_as == 65002
        assert n.remote_as_source == "declared"

    def test_inline_comment_survives(self):
        pc = _parse(
            "hostname r1\n"
            "router bgp 65001\n"
            " neighbor 10.0.0.2 remote-as 65002 ! isp uplink\n",
            "ios",
        )
        (n,) = pc.bgp_instances[0].neighbors
        assert n.remote_as == 65002

    def test_garbage_first_token_still_fails_closed(self):
        with pytest.raises(ValueError):
            from confgraph.parsers.base import parse_remote_as_token
            parse_remote_as_token("banana 65002")


class TestBoundsAndSpelling:
    def test_decimal_arm_bounded_like_asdot(self):
        """Validation finding 6: both string arms cap at the 32-bit AS
        space."""
        assert normalize_remote_as("4294967295") == 4294967295
        with pytest.raises(ValueError):
            normalize_remote_as("4294967296")

    def test_unicode_digits_rejected(self):
        """Validation finding 9 + R2-1: ASCII digits only — BOTH arms."""
        with pytest.raises(ValueError):
            normalize_remote_as("٦٥٠٠٢")
        with pytest.raises(ValueError):
            normalize_remote_as("٦٥.١")   # asdot arm (\\d is Unicode-aware)
        with pytest.raises(ValueError):
            normalize_remote_as("١.١")


class TestInheritedPeerType:
    def test_nxos_template_peer_type_propagates(self):
        """Validation finding 2: a member inheriting from a peer-TYPE
        template must carry the TYPE — not read as missing remote-as."""
        pc = _parse(
            "hostname n1\n"
            "feature bgp\n"
            "router bgp 65001\n"
            "  template peer EXT\n"
            "    remote-as external\n"
            "  neighbor 10.0.0.2\n"
            "    inherit peer EXT\n",
            "nxos",
        )
        (n,) = pc.bgp_instances[0].neighbors
        assert n.remote_as is None
        assert n.remote_as_source == "external"


    def test_member_own_type_wins_over_template_type(self):
        """R2-2 gate pin: the elif is gated on the member still being
        source='inherited' — a member DECLARING its own peer type must
        not have it overwritten by the template's."""
        pc = _parse(
            "hostname n1\n"
            "feature bgp\n"
            "router bgp 65001\n"
            "  template peer EXT\n"
            "    remote-as external\n"
            "  neighbor 10.0.0.2\n"
            "    remote-as internal\n"
            "    inherit peer EXT\n",
            "nxos",
        )
        (n,) = pc.bgp_instances[0].neighbors
        assert n.remote_as_source == "internal"
