"""CCR-0157 — Arista EOS EVPN control-plane parsing.

EOS states its MP-BGP EVPN control-plane UNDER ``router bgp`` (unlike NX-OS,
which uses a top-level ``evpn`` block), and the VNI numbers live on
``interface Vxlan1`` — so each VNI family is JOINED to a VXLAN mapping:

  - L2VNI (MAC-VRF): a ``vlan <id>`` sub-block (``rd`` / ``route-target both``,
    NO ``evpn`` keyword); its VNI comes from ``vxlan vlan <id> vni <n>``.
  - L3VNI: a ``vrf <name>`` sub-block whose route-targets carry the ``evpn``
    keyword BETWEEN direction and value (``route-target import evpn <rt>``); its
    VNI comes from ``vxlan vrf <name> vni <n>``, and that binding is the
    fabric association (``associate_vrf``).
  - Overlay activation: ``address-family evpn`` (single token) with
    ``neighbor <x> activate`` — normalised to ``BGPNeighborAF(l2vpn/evpn)``.

Before the fix: ``parsed.evpn`` was ``None`` (EOS inherited the base stub); the
``vlan`` sub-block landed in ``unrecognized_blocks``; the EVPN ``vrf`` sub-block
mis-split BGP into a phantom second instance; and the ``evpn`` activation was
lost.

Syntax provenance: every config line below is device-emitted, taken from the
live cEOS 4.36.1F capture
``syntax-corpus/captures/eos/2026-08-01-ceos-4.36.1F-evpn-controlplane.txt``.
Names, IPs, VLANs and VNIs are this test's own copy of that emitted form.
"""

import pytest

from confgraph.parsers.eos_parser import EOSParser
from confgraph.parsers.ios_parser import IOSParser
from confgraph.models.bgp import BGPNeighborAF


# The router-bgp + Vxlan1 sections exactly as cEOS 4.36.1F emits them.
EVPN_CONFIG = """router bgp 65101
   neighbor EVPN-OVERLAY peer group
   neighbor EVPN-OVERLAY remote-as 65001
   neighbor EVPN-OVERLAY update-source Loopback0
   neighbor EVPN-OVERLAY ebgp-multihop 3
   neighbor EVPN-OVERLAY send-community extended
   neighbor 10.0.0.2 peer group EVPN-OVERLAY
   !
   vlan 10
      rd 1.1.1.1:10010
      route-target both 10010:10010
      redistribute learned
   !
   address-family evpn
      neighbor EVPN-OVERLAY activate
   !
   vrf ZZ-TENANT
      rd 1.1.1.1:50001
      route-target import evpn 50001:50001
      route-target export evpn 50001:50001
!
interface Vxlan1
   vxlan source-interface Loopback1
   vxlan udp-port 4789
   vxlan vlan 10 vni 10010
   vxlan vrf ZZ-TENANT vni 50001
!
"""


@pytest.fixture
def parsed():
    return EOSParser(EVPN_CONFIG).parse()


def test_l2vni_is_parsed_with_vni_joined_from_vxlan(parsed):
    """The ``vlan 10`` MAC-VRF becomes an L2VNI, VNI joined from Vxlan1."""
    assert parsed.evpn is not None
    l2vnis = parsed.evpn.l2vnis
    assert len(l2vnis) == 1
    l2 = l2vnis[0]
    assert l2.vni == 10010                    # joined from `vxlan vlan 10 vni 10010`
    assert l2.rd == "1.1.1.1:10010"
    # `route-target both` populates BOTH lists, kept unexpanded (no `evpn` kw).
    assert l2.route_target_import == ["10010:10010"]
    assert l2.route_target_export == ["10010:10010"]


def test_l3vni_is_parsed_with_separate_import_export(parsed):
    """The ``vrf ZZ-TENANT`` EVPN block becomes an L3VNI with split RTs."""
    l3vnis = parsed.evpn.l3vnis
    assert len(l3vnis) == 1
    l3 = l3vnis[0]
    assert l3.vni == 50001                     # joined from `vxlan vrf ZZ-TENANT vni 50001`
    assert l3.rd == "1.1.1.1:50001"
    assert l3.route_target_import == ["50001:50001"]
    assert l3.route_target_export == ["50001:50001"]
    assert l3.vrf == "ZZ-TENANT"
    # The VXLAN vrf binding IS the EOS L3VNI↔fabric association.
    assert l3.associate_vrf is True


def test_evpn_af_activation_reaches_the_peer_group(parsed):
    """``address-family evpn`` + ``neighbor EVPN-OVERLAY activate`` → l2vpn/evpn AF."""
    bgp = [b for b in parsed.bgp_instances if b.vrf is None][0]
    pg = next(pg for pg in bgp.peer_groups if pg.name == "EVPN-OVERLAY")
    evpn_afs = [af for af in pg.address_families
                if af.afi == "l2vpn" and af.safi == "evpn"]
    assert len(evpn_afs) == 1
    assert evpn_afs[0].activate is True


def test_evpn_subblocks_do_not_mis_split_bgp_or_leak_to_unrecognized(parsed):
    """One BGP instance, and none of the EVPN sub-blocks are unrecognized."""
    assert len(parsed.bgp_instances) == 1
    assert parsed.bgp_instances[0].vrf is None

    headers = " ".join(u.block_header for u in parsed.unrecognized_blocks)
    assert "vlan 10" not in headers
    assert "address-family evpn" not in headers
    assert "ZZ-TENANT" not in headers


def test_plain_eos_config_keeps_evpn_absent():
    """A non-EVPN EOS config — including a real L3VPN VRF — keeps evpn None.

    The L3VPN VRF here has a plain ``route-target import <rt>`` (no ``evpn``
    keyword) and real BGP content, so it is NOT an L3VNI and it DOES remain its
    own BGP instance — the EVPN discriminator must not swallow it.
    """
    cfg = """router bgp 65000
   router-id 1.1.1.1
   neighbor 10.0.0.1 remote-as 65001
   vrf CUSTOMER_A
      rd 65000:100
      route-target import 65000:100
      route-target export 65000:100
      neighbor 192.168.10.2 remote-as 65100
      redistribute connected
!
"""
    parsed = EOSParser(cfg).parse()
    assert parsed.evpn is None
    # global + the real L3VPN VRF instance both survive.
    assert {b.vrf for b in parsed.bgp_instances} == {None, "CUSTOMER_A"}


def test_l2vni_skipped_when_no_vxlan_vni_mapping():
    """A ``vlan`` sub-block with no Vxlan1 mapping is skipped, not fabricated.

    ``EVPNL2VNI.vni`` is a required int; without a ``vxlan vlan <id> vni <n>``
    join there is no VNI to assign, so the L2VNI is dropped rather than invented.
    """
    cfg = """router bgp 65101
   vlan 20
      rd 1.1.1.1:10020
      route-target both 10020:10020
!
interface Vxlan1
   vxlan source-interface Loopback1
   vxlan vlan 10 vni 10010
!
"""
    parsed = EOSParser(cfg).parse()
    # vlan 20 has no vni mapping → no L2VNI produced.
    assert parsed.evpn is None or parsed.evpn.l2vnis == []


def test_vlan_child_pattern_is_anchored_to_the_bare_numeric_macvrf():
    """The ``router bgp`` ``vlan`` child pattern must match ONLY ``vlan <id>``.

    A broad ``^vlan\\b`` would swallow ``vlan``-prefixed forms the parser does
    NOT consume (the ``vlan-aware-bundle`` L2VNI form, malformed ``vlan`` lines),
    turning a visible unrecognized-gap into an invisible one. The bare numeric
    header (which ``parse_evpn`` consumes) stays recognized; everything else
    stays flagged.
    """
    cfg = """router bgp 65101
   vlan 30
      rd 1.1.1.1:10030
      route-target both 10030:10030
   !
   vlan-aware-bundle TENANT-BUNDLE
      rd 1.1.1.1:99999
   !
   vlan abc
   !
   vlan 30 extra-garbage
   !
   vlanx 5
!
interface Vxlan1
   vxlan source-interface Loopback1
   vxlan vlan 30 vni 10030
!
"""
    parsed = EOSParser(cfg).parse()

    # The bare numeric MAC-VRF block IS recognized and parses to an L2VNI.
    assert parsed.evpn is not None
    assert [v.vni for v in parsed.evpn.l2vnis] == [10030]

    headers = [u.block_header for u in parsed.unrecognized_blocks]
    # The bare `vlan 30` header is NOT flagged (it is consumed).
    assert "router bgp 65101 > vlan 30" not in headers
    # Every non-numeric / malformed `vlan`-prefixed form remains disclosed.
    assert any("vlan-aware-bundle TENANT-BUNDLE" in h for h in headers)
    assert any(h.endswith("> vlan abc") for h in headers)
    assert any("vlan 30 extra-garbage" in h for h in headers)
    assert any(h.endswith("> vlanx 5") for h in headers)


def test_eos_does_not_fork_the_neighbor_or_peer_group_walk():
    """CCR-0157's EVPN activation must not re-fork the CCR-0044 shared walks.

    EVPN peer-group activation is attached in a thin ``parse_bgp`` wrapper that
    delegates every field to the shared walks; the neighbor and peer-group
    command parsers themselves stay inherited unchanged.
    """
    assert EOSParser._parse_bgp_neighbors is IOSParser._parse_bgp_neighbors
    assert EOSParser._parse_bgp_peer_groups is IOSParser._parse_bgp_peer_groups
