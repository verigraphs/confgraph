"""CCR-0078 parser-half — INDEPENDENT validator suite.

Own device names / IPs / identifiers (must not collide with the author's test):
  local ASN 64500, remote ASN 64600/64610
  IOS neighbor 198.51.100.7, 198.51.100.20; IPv6 2001:db8:beef::2
  IOS-XR neighbor 203.0.113.9; IPv6 2001:db8:cafe::9
  peer-group SPOKE-DO ; route-map MAP-DEF-COND ; route-policy RP-DEF-COND

Emitted-form provenance (both re-verified against the cited docs by the validator):
  cisco-ios  syntax-corpus/cisco-ios/bgp.yaml  neighbor-default-originate (doc-only,
             citation sha ac0bc40c… re-fetched): `neighbor <ip|pg> default-originate
             [route-map <name>]`, valid flat under `router bgp` AND inside
             `address-family ipv4`; tokens emitted == typed (forms_diverge:false).
  iosxr      syntax-corpus/iosxr/bgp.yaml        default-originate (doc-only + Ansible
             transcript sha b271b838…): bare `default-originate` and
             `default-originate route-policy <name>` inside neighbor AF sub-block.

Tests are grouped:
  ACCEPTANCE (red pre-fix, green post-fix) — the value that was wrong.
  GUARD      (green pre AND post) — deviation-A regression guards; behaviour unchanged.
"""

from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.iosxr_parser import IOSXRParser


def _global(bgp_list):
    g = [b for b in bgp_list if b.vrf is None]
    assert g, "expected a global BGP instance"
    return g[0]


def _nbrs(bgp):
    return {str(n.peer_ip): n for n in bgp.neighbors}


def _ipv4_afs(nb):
    return [af for af in nb.address_families if af.afi == "ipv4"]


def _ipv6_afs(nb):
    return [af for af in nb.address_families if af.afi == "ipv6"]


# =====================================================================
# ACCEPTANCE — criterion 1: classic flat unconditional (IOS)
# =====================================================================
def test_c1_ios_classic_flat_unconditional():
    cfg = """router bgp 64500
 neighbor 198.51.100.7 remote-as 64600
 neighbor 198.51.100.7 default-originate
"""
    nb = _nbrs(_global(IOSParser(cfg).parse_bgp()))["198.51.100.7"]
    assert nb.default_originate is True
    assert nb.default_originate_route_map is None


# criterion 2: classic flat conditional (route-map) — value, not presence
def test_c2_ios_classic_flat_conditional_route_map():
    cfg = """router bgp 64500
 neighbor 198.51.100.7 remote-as 64600
 neighbor 198.51.100.7 default-originate route-map MAP-DEF-COND
"""
    nb = _nbrs(_global(IOSParser(cfg).parse_bgp()))["198.51.100.7"]
    assert nb.default_originate is True
    assert nb.default_originate_route_map == "MAP-DEF-COND"


# criterion 3: AF-block unconditional (IOS-XE address-family shape)
def test_c3_ios_afblock_unconditional():
    cfg = """router bgp 64500
 neighbor 198.51.100.7 remote-as 64600
 address-family ipv4
  neighbor 198.51.100.7 default-originate
"""
    nb = _nbrs(_global(IOSParser(cfg).parse_bgp()))["198.51.100.7"]
    afs = _ipv4_afs(nb)
    assert len(afs) == 1
    assert afs[0].default_originate is True
    assert afs[0].default_originate_route_map is None


# criterion 4 / DEVIATION B: AF-block conditional must yield BOTH bool AND route-map
def test_c4_ios_afblock_conditional_bool_and_route_map():
    cfg = """router bgp 64500
 neighbor 198.51.100.7 remote-as 64600
 address-family ipv4
  neighbor 198.51.100.7 default-originate route-map MAP-DEF-COND
"""
    nb = _nbrs(_global(IOSParser(cfg).parse_bgp()))["198.51.100.7"]
    afs = _ipv4_afs(nb)
    assert len(afs) == 1
    assert afs[0].default_originate is True                      # was NEVER set pre-fix
    assert afs[0].default_originate_route_map == "MAP-DEF-COND"  # was the only thing pre-fix


# criterion 5: negative — genuinely False (value), field present, not absent-key
def test_c5_ios_negative_genuinely_false():
    cfg = """router bgp 64500
 neighbor 198.51.100.7 remote-as 64600
 address-family ipv4
  neighbor 198.51.100.7 activate
"""
    nb = _nbrs(_global(IOSParser(cfg).parse_bgp()))["198.51.100.7"]
    assert "default_originate" in nb.model_fields
    assert nb.default_originate is False
    assert nb.default_originate_route_map is None
    for af in nb.address_families:
        assert af.default_originate is False
        assert af.default_originate_route_map is None


# criterion 6: peer-group unconditional
def test_c6_ios_peer_group_unconditional():
    cfg = """router bgp 64500
 neighbor SPOKE-DO peer-group
 neighbor SPOKE-DO remote-as 64600
 neighbor SPOKE-DO default-originate
"""
    pgs = {p.name: p for p in _global(IOSParser(cfg).parse_bgp()).peer_groups}
    assert pgs["SPOKE-DO"].default_originate is True
    assert pgs["SPOKE-DO"].default_originate_route_map is None


# criterion 6b / ADVERSARIAL: peer-group conditional — does pg path capture route-map?
def test_c6b_ios_peer_group_conditional_route_map():
    cfg = """router bgp 64500
 neighbor SPOKE-DO peer-group
 neighbor SPOKE-DO remote-as 64600
 neighbor SPOKE-DO default-originate route-map MAP-DEF-COND
"""
    pgs = {p.name: p for p in _global(IOSParser(cfg).parse_bgp()).peer_groups}
    assert pgs["SPOKE-DO"].default_originate is True
    assert pgs["SPOKE-DO"].default_originate_route_map == "MAP-DEF-COND"


# criterion 7: IOS-XR AF sub-block unconditional (bare) — transcript-witnessed form
def test_x1_iosxr_afblock_unconditional_bare():
    cfg = """router bgp 64500
 neighbor 203.0.113.9
  remote-as 64600
  address-family ipv4 unicast
   default-originate
"""
    nb = _nbrs(_global(IOSXRParser(cfg).parse_bgp()))["203.0.113.9"]
    afs = _ipv4_afs(nb)
    assert len(afs) == 1
    assert afs[0].default_originate is True
    assert afs[0].default_originate_route_map is None


# criterion 7: IOS-XR AF sub-block conditional (route-policy) — value into route_map field
def test_x2_iosxr_afblock_conditional_route_policy():
    cfg = """router bgp 64500
 neighbor 203.0.113.9
  remote-as 64600
  address-family ipv4 unicast
   default-originate route-policy RP-DEF-COND
"""
    nb = _nbrs(_global(IOSXRParser(cfg).parse_bgp()))["203.0.113.9"]
    afs = _ipv4_afs(nb)
    assert len(afs) == 1
    assert afs[0].default_originate is True
    assert afs[0].default_originate_route_map == "RP-DEF-COND"


# criterion 7: parity — both dialects surface an enabled flag
def test_c7_parity_ios_and_iosxr():
    ios = """router bgp 64500
 neighbor 198.51.100.7 remote-as 64600
 neighbor 198.51.100.7 default-originate
"""
    xr = """router bgp 64500
 neighbor 203.0.113.9
  remote-as 64600
  address-family ipv4 unicast
   default-originate
"""
    ios_nb = _nbrs(_global(IOSParser(ios).parse_bgp()))["198.51.100.7"]
    xr_nb = _nbrs(_global(IOSXRParser(xr).parse_bgp()))["203.0.113.9"]
    ios_on = ios_nb.default_originate or any(a.default_originate for a in ios_nb.address_families)
    xr_on = xr_nb.default_originate or any(a.default_originate for a in xr_nb.address_families)
    assert ios_on is True
    assert xr_on is True


# =====================================================================
# ADVERSARIAL
# =====================================================================
# neighbor-level flat AND per-AF override coexist (IOS)
def test_adv_neighbor_flat_and_af_override_coexist():
    cfg = """router bgp 64500
 neighbor 198.51.100.7 remote-as 64600
 neighbor 198.51.100.7 default-originate
 address-family ipv4
  neighbor 198.51.100.7 default-originate route-map MAP-DEF-COND
"""
    nb = _nbrs(_global(IOSParser(cfg).parse_bgp()))["198.51.100.7"]
    # flat, unconditional -> bool True, no route-map at neighbor level
    assert nb.default_originate is True
    assert nb.default_originate_route_map is None
    # AF override -> bool True AND the route-map
    afs = _ipv4_afs(nb)
    assert len(afs) == 1
    assert afs[0].default_originate is True
    assert afs[0].default_originate_route_map == "MAP-DEF-COND"


# IPv6 AF (IOS-XR) unconditional
def test_adv_iosxr_ipv6_af_unconditional():
    cfg = """router bgp 64500
 neighbor 2001:db8:cafe::9
  remote-as 64600
  address-family ipv6 unicast
   default-originate
"""
    nb = _nbrs(_global(IOSXRParser(cfg).parse_bgp()))["2001:db8:cafe::9"]
    afs = _ipv6_afs(nb)
    assert len(afs) == 1
    assert afs[0].default_originate is True
    assert afs[0].default_originate_route_map is None


# IPv6 AF (IOS-XE address-family shape) conditional route-map
def test_adv_ios_ipv6_afblock_conditional():
    cfg = """router bgp 64500
 neighbor 2001:db8:beef::2 remote-as 64600
 address-family ipv6
  neighbor 2001:db8:beef::2 default-originate route-map MAP-DEF-COND
"""
    nb = _nbrs(_global(IOSParser(cfg).parse_bgp()))["2001:db8:beef::2"]
    afs = _ipv6_afs(nb)
    assert len(afs) == 1
    assert afs[0].default_originate is True
    assert afs[0].default_originate_route_map == "MAP-DEF-COND"


# DEVIATION A widening: IOS-XR MIX block (next-hop-self + bare default-originate)
# pre-fix the ENTIRE block was dropped (both flags lost); post-fix it attaches
# with BOTH set. Red pre-fix (no ipv4 AF), green post-fix.
def test_adv_iosxr_mix_nexthopself_and_default_originate():
    cfg = """router bgp 64500
 neighbor 203.0.113.9
  remote-as 64600
  address-family ipv4 unicast
   next-hop-self
   default-originate
"""
    nb = _nbrs(_global(IOSXRParser(cfg).parse_bgp()))["203.0.113.9"]
    afs = _ipv4_afs(nb)
    assert len(afs) == 1
    assert afs[0].default_originate is True
    assert afs[0].next_hop_self is True


# =====================================================================
# GUARD — deviation A: next-hop-self-ONLY / rrc-ONLY IOS-XR AF blocks
# The shared attach filter drops these both PRE and POST fix. The author's
# OR-in of default_originate must NOT change that (green pre AND post).
# =====================================================================
def test_guard_iosxr_nexthopself_only_block_unchanged():
    cfg = """router bgp 64500
 neighbor 203.0.113.9
  remote-as 64600
  address-family ipv4 unicast
   next-hop-self
"""
    nb = _nbrs(_global(IOSXRParser(cfg).parse_bgp()))["203.0.113.9"]
    # No default-originate present -> the bare-bool block is still filtered out,
    # exactly as before the fix.
    assert _ipv4_afs(nb) == []


def test_guard_iosxr_rrclient_only_block_unchanged():
    cfg = """router bgp 64500
 neighbor 203.0.113.9
  remote-as 64600
  address-family ipv4 unicast
   route-reflector-client
"""
    nb = _nbrs(_global(IOSXRParser(cfg).parse_bgp()))["203.0.113.9"]
    assert _ipv4_afs(nb) == []


# GUARD: IOS-XR AF block with a route-policy (string) attaches, as it always did
def test_guard_iosxr_routepolicy_block_still_attaches():
    cfg = """router bgp 64500
 neighbor 203.0.113.9
  remote-as 64600
  address-family ipv4 unicast
   route-policy RP-IN in
"""
    nb = _nbrs(_global(IOSXRParser(cfg).parse_bgp()))["203.0.113.9"]
    afs = _ipv4_afs(nb)
    assert len(afs) == 1
    assert afs[0].route_map_in == "RP-IN"
    assert afs[0].default_originate is False
