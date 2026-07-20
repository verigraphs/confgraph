"""CCR-0078 (parser half): BGP `default-originate` must populate the model.

Before this fix, ``default_originate`` existed only on ``BGPNeighborAF`` and NO
parser ever set the boolean True; the AF-block handler wrote only the route-map
for the conditional form. The engine-side CCR-0078 fix (confgraph-entrp) depends
on the parser exposing this, so the parser must set:

  * ``BGPNeighbor.default_originate`` / ``.default_originate_route_map``  (classic path)
  * ``BGPNeighborAF.default_originate`` / ``.default_originate_route_map`` (AF-block path)
  * ``BGPPeerGroup.default_originate``  / ``.default_originate_route_map`` (peer-group path)

The fields are dialect-neutral: IOS/EOS emit ``route-map`` for the conditional
form, IOS-XR emits ``route-policy``; both land in ``default_originate_route_map``.

Fixture lines are device-EMITTED forms:
  * cisco-ios classic ``neighbor <ip> default-originate [route-map <rm>]``
  * cisco-ios AF-block ``neighbor <ip> default-originate [route-map <rm>]``
    inside ``address-family ipv4``
  * IOS-XR neighbor AF sub-block ``default-originate`` / ``default-originate
    route-policy <rp>`` (bare ``default-originate`` witnessed in
    syntax-corpus/iosxr/bgp.yaml).
"""

from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.iosxr_parser import IOSXRParser


def _global_bgp(bgp_list):
    """Return the global (non-VRF) BGPConfig from a parse_bgp() result."""
    globals_ = [b for b in bgp_list if b.vrf is None]
    assert globals_, "expected a global BGP instance"
    return globals_[0]


def _neighbors_by_ip(bgp):
    return {str(n.peer_ip): n for n in bgp.neighbors}


# ---------------------------------------------------------------------------
# Criterion 1 — classic-mode unconditional
# ---------------------------------------------------------------------------
def test_classic_unconditional_sets_boolean_only():
    cfg = """router bgp 65001
 neighbor 10.0.0.1 remote-as 65002
 neighbor 10.0.0.1 default-originate
"""
    bgp = _global_bgp(IOSParser(cfg).parse_bgp())
    nb = _neighbors_by_ip(bgp)["10.0.0.1"]
    assert nb.default_originate is True
    assert nb.default_originate_route_map is None


# ---------------------------------------------------------------------------
# Criterion 2 — classic-mode conditional (route-map)
# ---------------------------------------------------------------------------
def test_classic_conditional_sets_boolean_and_route_map():
    cfg = """router bgp 65001
 neighbor 10.0.0.1 remote-as 65002
 neighbor 10.0.0.1 default-originate route-map RM-DEFAULT
"""
    bgp = _global_bgp(IOSParser(cfg).parse_bgp())
    nb = _neighbors_by_ip(bgp)["10.0.0.1"]
    assert nb.default_originate is True
    assert nb.default_originate_route_map == "RM-DEFAULT"


# ---------------------------------------------------------------------------
# Criterion 3 — AF-block unconditional
# ---------------------------------------------------------------------------
def test_af_block_unconditional_sets_boolean_on_af():
    cfg = """router bgp 65001
 neighbor 10.0.0.1 remote-as 65002
 address-family ipv4
  neighbor 10.0.0.1 default-originate
"""
    bgp = _global_bgp(IOSParser(cfg).parse_bgp())
    nb = _neighbors_by_ip(bgp)["10.0.0.1"]
    afs = [af for af in nb.address_families if af.afi == "ipv4"]
    assert len(afs) == 1
    assert afs[0].default_originate is True
    assert afs[0].default_originate_route_map is None


# ---------------------------------------------------------------------------
# Criterion 4 — AF-block conditional (route-map). This path partially existed
# (route-map recorded) but the boolean was NEVER set — a real fix, not a pin.
# ---------------------------------------------------------------------------
def test_af_block_conditional_sets_boolean_and_route_map():
    cfg = """router bgp 65001
 neighbor 10.0.0.1 remote-as 65002
 address-family ipv4
  neighbor 10.0.0.1 default-originate route-map RM-DEFAULT
"""
    bgp = _global_bgp(IOSParser(cfg).parse_bgp())
    nb = _neighbors_by_ip(bgp)["10.0.0.1"]
    afs = [af for af in nb.address_families if af.afi == "ipv4"]
    assert len(afs) == 1
    assert afs[0].default_originate is True
    assert afs[0].default_originate_route_map == "RM-DEFAULT"


# ---------------------------------------------------------------------------
# Criterion 5 — negative: no default-originate line anywhere
# ---------------------------------------------------------------------------
def test_negative_no_default_originate_at_neighbor_and_af():
    cfg = """router bgp 65001
 neighbor 10.0.0.1 remote-as 65002
 address-family ipv4
  neighbor 10.0.0.1 activate
"""
    bgp = _global_bgp(IOSParser(cfg).parse_bgp())
    nb = _neighbors_by_ip(bgp)["10.0.0.1"]
    assert nb.default_originate is False
    assert nb.default_originate_route_map is None
    for af in nb.address_families:
        assert af.default_originate is False
        assert af.default_originate_route_map is None


# ---------------------------------------------------------------------------
# Criterion 6 — peer-group definition. Proves the field lives on BGPPeerGroup
# (extra='ignore' would otherwise SILENTLY drop it from BGPPeerGroup(**pg_data)).
# ---------------------------------------------------------------------------
def test_peer_group_definition_sets_boolean():
    cfg = """router bgp 65001
 neighbor RR peer-group
 neighbor RR remote-as 65002
 neighbor RR default-originate
"""
    bgp = _global_bgp(IOSParser(cfg).parse_bgp())
    pgs = {p.name: p for p in bgp.peer_groups}
    assert pgs["RR"].default_originate is True
    assert pgs["RR"].default_originate_route_map is None


def test_peer_group_definition_conditional_sets_route_map():
    cfg = """router bgp 65001
 neighbor RR peer-group
 neighbor RR remote-as 65002
 neighbor RR default-originate route-map RM-DEFAULT
"""
    bgp = _global_bgp(IOSParser(cfg).parse_bgp())
    pgs = {p.name: p for p in bgp.peer_groups}
    assert pgs["RR"].default_originate is True
    assert pgs["RR"].default_originate_route_map == "RM-DEFAULT"


# ---------------------------------------------------------------------------
# Criterion 7 — parity across IOS and IOS-XR (each dialect's emitted form).
# IOS: classic flat `neighbor <ip> default-originate`.
# IOS-XR: `default-originate` (and route-policy) inside the neighbor AF sub-block.
# ---------------------------------------------------------------------------
def test_iosxr_af_block_unconditional_sets_boolean():
    cfg = """router bgp 65001
 neighbor 192.0.2.2
  remote-as 65002
  address-family ipv4 unicast
   default-originate
"""
    bgp = _global_bgp(IOSXRParser(cfg).parse_bgp())
    nb = _neighbors_by_ip(bgp)["192.0.2.2"]
    afs = [af for af in nb.address_families if af.afi == "ipv4"]
    assert len(afs) == 1
    assert afs[0].default_originate is True
    assert afs[0].default_originate_route_map is None


def test_iosxr_af_block_conditional_sets_boolean_and_route_policy():
    cfg = """router bgp 65001
 neighbor 192.0.2.2
  remote-as 65002
  address-family ipv4 unicast
   default-originate route-policy RP-DEFAULT
"""
    bgp = _global_bgp(IOSXRParser(cfg).parse_bgp())
    nb = _neighbors_by_ip(bgp)["192.0.2.2"]
    afs = [af for af in nb.address_families if af.afi == "ipv4"]
    assert len(afs) == 1
    assert afs[0].default_originate is True
    assert afs[0].default_originate_route_map == "RP-DEFAULT"


def test_parity_ios_classic_and_iosxr_af_agree_on_boolean():
    """IOS (classic flat) and IOS-XR (AF sub-block) must both surface an
    enabled default-originate as a truthy flag the engine can read — regardless
    of where each dialect emits it."""
    ios_cfg = """router bgp 65001
 neighbor 10.0.0.1 remote-as 65002
 neighbor 10.0.0.1 default-originate
"""
    xr_cfg = """router bgp 65001
 neighbor 192.0.2.2
  remote-as 65002
  address-family ipv4 unicast
   default-originate
"""
    ios_nb = _neighbors_by_ip(_global_bgp(IOSParser(ios_cfg).parse_bgp()))["10.0.0.1"]
    xr_nb = _neighbors_by_ip(_global_bgp(IOSXRParser(xr_cfg).parse_bgp()))["192.0.2.2"]

    ios_enabled = ios_nb.default_originate or any(
        af.default_originate for af in ios_nb.address_families
    )
    xr_enabled = xr_nb.default_originate or any(
        af.default_originate for af in xr_nb.address_families
    )
    assert ios_enabled is True
    assert xr_enabled is True
