"""Tests for NH-scoped static-route deletion tombstones (Fable-5 review F7, WI-5).

IOS ground truth: the identity of a static route is (prefix, next-hop-or-
interface).  ``no ip route DEST MASK NH`` removes ONLY the route via that
next-hop (ECMP/floating siblings survive); the NH-less ``no ip route DEST
MASK`` removes ALL routes for the prefix.

parse_deletion_commands() must therefore emit:
  - ``static:<vrf>:<dest>:<nh_spec>`` when an NH is present (nh_spec is the
    space-joined NH tokens: "10.0.99.2", "Null0", or
    "GigabitEthernet0/0 10.1.1.1"; trailing AD/tag/name/permanent/track
    tokens are excluded — AD is not identity), and
  - ``static:<vrf>:<dest>`` (unchanged legacy form) when no NH is given.

Run:
    uv run pytest tests/test_static_route_nh_tombstones.py -v
"""

from __future__ import annotations

from confgraph.parsers.ios_parser import IOSParser


def _tombstones(cfg: str) -> list[str]:
    return IOSParser(cfg).parse_deletion_commands()


class TestNHCarryingTombstones:
    def test_nh_ip_is_carried(self):
        ts = _tombstones("no ip route 10.0.40.0 255.255.255.0 192.168.1.2\n")
        assert "static::10.0.40.0/24:192.168.1.2" in ts

    def test_nh_with_trailing_ad_excludes_ad(self):
        """AD is not part of the route identity — it must not be in the tombstone."""
        ts = _tombstones("no ip route 0.0.0.0 0.0.0.0 10.0.99.2 250\n")
        assert "static::0.0.0.0/0:10.0.99.2" in ts

    def test_nh_with_trailing_track_excludes_track(self):
        ts = _tombstones("no ip route 0.0.0.0 0.0.0.0 10.0.0.185 track 1\n")
        assert "static::0.0.0.0/0:10.0.0.185" in ts

    def test_vrf_and_nh_both_carried(self):
        ts = _tombstones("no ip route vrf RED 1.1.1.0 255.255.255.0 10.0.0.1\n")
        assert "static:RED:1.1.1.0/24:10.0.0.1" in ts

    def test_interface_next_hop_is_carried(self):
        ts = _tombstones("no ip route 10.9.0.0 255.255.0.0 Null0\n")
        assert "static::10.9.0.0/16:Null0" in ts

    def test_interface_plus_nh_ip_both_carried(self):
        ts = _tombstones(
            "no ip route 10.5.0.0 255.255.0.0 GigabitEthernet0/0 10.1.1.1\n"
        )
        assert "static::10.5.0.0/16:GigabitEthernet0/0 10.1.1.1" in ts

    def test_interface_plus_ad_excludes_ad(self):
        ts = _tombstones("no ip route 10.5.0.0 255.255.0.0 GigabitEthernet0/0 200\n")
        assert "static::10.5.0.0/16:GigabitEthernet0/0" in ts


class TestNHLessTombstones:
    def test_nh_less_form_has_no_nh_segment(self):
        """NH-less ``no ip route`` removes ALL routes for the prefix on IOS —
        the tombstone must keep the two-segment form."""
        ts = _tombstones("no ip route 10.0.40.0 255.255.255.0\n")
        assert "static::10.0.40.0/24" in ts
        assert not any(t.startswith("static::10.0.40.0/24:") for t in ts)

    def test_vrf_nh_less_form(self):
        ts = _tombstones("no ip route vrf RED 1.1.1.0 255.255.255.0\n")
        assert "static:RED:1.1.1.0/24" in ts

    def test_pure_numeric_token_treated_as_nh_less(self):
        """A pure-numeric token can never be a next-hop (it would be an AD,
        which is invalid without an NH) — defensively treat as NH-less."""
        ts = _tombstones("no ip route 10.0.40.0 255.255.255.0 200\n")
        assert "static::10.0.40.0/24" in ts
