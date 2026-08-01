"""CCR-0162 — EOS EVPN address-family policy attachments.

CCR-0157 landed the EVPN AF *activation* (``neighbor X activate`` inside
``address-family evpn`` → ``BGPNeighborAF(l2vpn/evpn)``), but the per-hop policy
attachments in the SAME block were dropped — and, worse, they never surfaced on
the UNRECOGNIZED channel either (the double-miss the CCR closes).

A ``neighbor <peer-group|ip> route-map <rm> in|out`` inside EOS's single-token
``address-family evpn`` block is emitted verbatim, direction keyword LAST. This
must attach to the SAME ``BGPNeighborAF(l2vpn/evpn)`` entry the activation
creates, populating ``route_map_in`` / ``route_map_out``; anything in the block
the parser does not consume must land in ``unrecognized_blocks``.

Syntax provenance: every EVPN AF policy line here is device-emitted, per
``syntax-corpus/eos/bgp.yaml`` ``neighbor-route-map`` (status verified-capture,
cEOS 4.36.1F) whose ``example_emitted`` shows exactly this form under
``address-family evpn``. Names/IPs/route-maps are this test's own copy.
"""

import pytest

from confgraph.parsers.eos_parser import EOSParser


# cEOS 4.36.1F emitted form: peer-group activation PLUS route-map in/out under
# `address-family evpn`, plus a directly-activated neighbor carrying its own
# route-map, plus a non-EVPN `address-family ipv4` route-map (cross-contamination
# guard), plus a nonsense line that must be disclosed.
EVPN_CONFIG = """router bgp 65102
   neighbor EVPN-OVERLAY peer group
   neighbor EVPN-OVERLAY remote-as 65001
   neighbor EVPN-OVERLAY update-source Loopback0
   neighbor 10.0.0.9 peer group EVPN-OVERLAY
   neighbor 10.0.0.9 remote-as 65001
   neighbor 203.0.113.7 remote-as 65003
   !
   address-family ipv4
      neighbor 203.0.113.7 route-map RM-V4-IN in
   !
   address-family evpn
      neighbor EVPN-OVERLAY activate
      neighbor EVPN-OVERLAY route-map RM-EVPN-IN in
      neighbor EVPN-OVERLAY route-map RM-EVPN-OUT out
      neighbor 10.0.0.9 activate
      neighbor 10.0.0.9 route-map RM-DIRECT-OUT out
      neighbor EVPN-OVERLAY frobnicate 5
!
"""


@pytest.fixture
def parsed():
    return EOSParser(EVPN_CONFIG).parse()


def _evpn_af(target):
    afs = [af for af in target.address_families
           if af.afi == "l2vpn" and af.safi == "evpn"]
    assert len(afs) == 1, f"expected exactly one l2vpn/evpn AF, got {len(afs)}"
    return afs[0]


def _global_bgp(parsed):
    return next(b for b in parsed.bgp_instances if b.vrf is None)


def test_peer_group_evpn_af_carries_route_map_in_and_out(parsed):
    """The peer group's l2vpn/evpn AF gets both route-maps, on ONE entry."""
    bgp = _global_bgp(parsed)
    pg = next(pg for pg in bgp.peer_groups if pg.name == "EVPN-OVERLAY")
    af = _evpn_af(pg)
    assert af.activate is True                    # `activate` line present
    assert af.route_map_in == "RM-EVPN-IN"
    assert af.route_map_out == "RM-EVPN-OUT"


def test_direct_neighbor_evpn_af_carries_route_map(parsed):
    """A direct-neighbor (IP) route-map under evpn attaches to that neighbor."""
    bgp = _global_bgp(parsed)
    nb = next(n for n in bgp.neighbors if str(n.peer_ip) == "10.0.0.9")
    af = _evpn_af(nb)
    assert af.activate is True
    assert af.route_map_out == "RM-DIRECT-OUT"
    assert af.route_map_in is None


def test_non_evpn_af_route_map_is_not_cross_contaminated(parsed):
    """The ipv4 AF route-map stays ipv4 — it must not leak into the evpn AF."""
    bgp = _global_bgp(parsed)
    nb = next(n for n in bgp.neighbors if str(n.peer_ip) == "203.0.113.7")
    ipv4 = [af for af in nb.address_families
            if af.afi == "ipv4" and af.safi == "unicast"]
    assert len(ipv4) == 1
    assert ipv4[0].route_map_in == "RM-V4-IN"
    # and this neighbor has NO evpn AF (it was never in the evpn block).
    assert not any(af.afi == "l2vpn" and af.safi == "evpn"
                   for af in nb.address_families)


def test_unparsed_line_under_evpn_af_surfaces_as_unrecognized(parsed):
    """`neighbor EVPN-OVERLAY frobnicate 5` must be disclosed, not dropped."""
    headers = [u.block_header for u in parsed.unrecognized_blocks]
    assert any("frobnicate 5" in h for h in headers), headers
    # and the header is scoped to the router bgp block.
    assert any(h.startswith("router bgp 65102 >") and "frobnicate" in h
               for h in headers)


def test_recognized_evpn_af_lines_do_not_leak_to_unrecognized(parsed):
    """The activation and the route-map lines are consumed, not flagged."""
    headers = " ".join(u.block_header for u in parsed.unrecognized_blocks)
    assert "RM-EVPN-IN" not in headers
    assert "RM-EVPN-OUT" not in headers
    assert "RM-DIRECT-OUT" not in headers
    assert "activate" not in headers


def test_activation_only_case_still_yields_af_with_no_route_maps():
    """CCR-0157 shape preserved: bare activation → AF entry, route_map_* None."""
    cfg = """router bgp 65101
   neighbor EVPN-OVERLAY peer group
   neighbor EVPN-OVERLAY remote-as 65001
   !
   address-family evpn
      neighbor EVPN-OVERLAY activate
!
"""
    parsed = EOSParser(cfg).parse()
    bgp = _global_bgp(parsed)
    pg = next(pg for pg in bgp.peer_groups if pg.name == "EVPN-OVERLAY")
    af = _evpn_af(pg)
    assert af.activate is True
    assert af.route_map_in is None
    assert af.route_map_out is None


def test_policy_only_peer_group_gets_af_without_inventing_activation():
    """A route-map with NO `activate` line: AF entry present, activate reflects
    that no activation was shown (item 2 — do not invent activation state)."""
    cfg = """router bgp 65101
   neighbor EVPN-OVERLAY peer group
   neighbor EVPN-OVERLAY remote-as 65001
   !
   address-family evpn
      neighbor EVPN-OVERLAY route-map RM-EVPN-OUT out
!
"""
    parsed = EOSParser(cfg).parse()
    bgp = _global_bgp(parsed)
    pg = next(pg for pg in bgp.peer_groups if pg.name == "EVPN-OVERLAY")
    af = _evpn_af(pg)
    assert af.route_map_out == "RM-EVPN-OUT"
    assert af.activate is False
