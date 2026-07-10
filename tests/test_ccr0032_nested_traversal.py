"""CCR-0032 — parsers must descend into recognized nested sub-blocks.

Each test reproduces a nesting/block-descent mechanism with its own config
(names/IPs deliberately distinct from the coverage fixtures) and asserts the
CHILD's *value*, not mere presence (handbook §7.5).

The OSPF-VRF tests are the parity/structural check: OSPF-under-VRF reuses the
SAME `_iter_router_vrf_blocks` traversal that BGP-under-VRF uses, so a second
protocol's VRF sub-block is a reuse, not a new hand-coded walk.
"""

from ipaddress import IPv4Address

from confgraph.parsers.nxos_parser import NXOSParser
from confgraph.parsers.iosxr_parser import IOSXRParser
from confgraph.parsers.eos_parser import EOSParser
from confgraph.parsers.junos_parser import JunOSParser


# ---------------------------------------------------------------------------
# NX-OS: router bgp -> vrf NAME -> neighbor (nested block) must descend
# ---------------------------------------------------------------------------

NXOS_BGP_VRF = """\
hostname nx1
router bgp 65010
  router-id 9.9.9.9
  vrf TENANT_X
    address-family ipv4 unicast
      redistribute direct route-map RM_T
    neighbor 198.51.100.2
      remote-as 65020
      description TENANT-X-CE
      address-family ipv4 unicast
        route-map RM_IN in
        route-map RM_OUT out
"""


def test_nxos_bgp_vrf_neighbor_block_descended():
    p = NXOSParser(NXOS_BGP_VRF).parse()
    vrf_inst = next(b for b in p.bgp_instances if b.vrf == "TENANT_X")
    assert len(vrf_inst.neighbors) == 1
    nbr = vrf_inst.neighbors[0]
    assert str(nbr.peer_ip) == "198.51.100.2"
    assert nbr.remote_as == 65020
    # AF-nested route-maps must reach the neighbor (value, not presence).
    assert nbr.route_map_in == "RM_IN"
    assert nbr.route_map_out == "RM_OUT"


# ---------------------------------------------------------------------------
# IOS-XR: global address-family children (network/redistribute/aggregate)
# ---------------------------------------------------------------------------

IOSXR_BGP_AF = """\
hostname xr1
router bgp 65010
 bgp router-id 9.9.9.9
 address-family ipv4 unicast
  network 172.20.0.0/16 route-policy RP-OUT
  redistribute connected route-policy RP-IN
  aggregate-address 172.16.0.0/12 summary-only
  maximum-paths ebgp 8
 vrf TENANT_X
  rd 65010:77
  neighbor 198.51.100.2
   remote-as 65020
"""


def test_iosxr_global_af_children_descended():
    p = IOSXRParser(IOSXR_BGP_AF).parse()
    bgp = next(b for b in p.bgp_instances if b.vrf is None)
    af = next(a for a in bgp.address_families if a.afi == "ipv4")
    assert [str(n.prefix) for n in af.networks] == ["172.20.0.0/16"]
    assert af.networks[0].route_map == "RP-OUT"
    assert [r.protocol for r in af.redistribute] == ["connected"]
    assert af.redistribute[0].route_map == "RP-IN"
    assert [str(a.prefix) for a in af.aggregate_addresses] == ["172.16.0.0/12"]
    assert af.aggregate_addresses[0].summary_only is True
    assert af.maximum_paths == 8


def test_iosxr_bgp_vrf_rd_surfaced():
    p = IOSXRParser(IOSXR_BGP_AF).parse()
    vrf_inst = next(b for b in p.bgp_instances if b.vrf == "TENANT_X")
    assert vrf_inst.rd == "65010:77"
    assert [str(n.peer_ip) for n in vrf_inst.neighbors] == ["198.51.100.2"]


# ---------------------------------------------------------------------------
# EOS: router bgp -> vrf NAME (block form) instance + neighbors
# ---------------------------------------------------------------------------

EOS_BGP_VRF = """\
hostname eos1
router bgp 65010
   router-id 9.9.9.9
   vrf TENANT_X
      rd 65010:77
      router-id 10.9.9.9
      neighbor 198.51.100.2 remote-as 65020
      neighbor 198.51.100.2 description TENANT-X-CE
"""


def test_eos_bgp_vrf_block_instance_and_neighbors():
    p = EOSParser(EOS_BGP_VRF).parse()
    vrf_inst = next((b for b in p.bgp_instances if b.vrf == "TENANT_X"), None)
    assert vrf_inst is not None
    assert vrf_inst.rd == "65010:77"
    assert len(vrf_inst.neighbors) == 1
    nbr = vrf_inst.neighbors[0]
    assert str(nbr.peer_ip) == "198.51.100.2"
    assert nbr.remote_as == 65020
    assert nbr.description == "TENANT-X-CE"


# ---------------------------------------------------------------------------
# JunOS: nested route { } AND flat sibling — ALL parse (anti-corruption)
# ---------------------------------------------------------------------------

JUNOS_STATIC_BOTH = """\
system {
    host-name jn1;
}
routing-options {
    static {
        route 0.0.0.0/0 {
            next-hop 198.51.100.1;
            preference 240;
            tag 777;
        }
        route 203.0.113.0/24 discard;
        route 192.0.2.0/24 next-hop 198.51.100.9;
    }
}
"""


def test_junos_nested_route_does_not_poison_flat_siblings():
    """One attributed route must NOT erase the flat siblings in the block."""
    p = JunOSParser(JUNOS_STATIC_BOTH).parse()
    globals_ = {str(s.destination): s for s in p.static_routes if s.vrf is None}
    # All three destinations must be present — the corruption dropped them all.
    assert set(globals_) == {"0.0.0.0/0", "203.0.113.0/24", "192.0.2.0/24"}
    # Block-form attributes descended: preference -> distance, tag.
    default = globals_["0.0.0.0/0"]
    assert default.next_hop == IPv4Address("198.51.100.1")
    assert default.distance == 240
    assert default.tag == 777
    # Flat discard sibling: present, no next-hop.
    assert globals_["203.0.113.0/24"].next_hop is None
    # Flat next-hop sibling.
    assert globals_["192.0.2.0/24"].next_hop == IPv4Address("198.51.100.9")


# ---------------------------------------------------------------------------
# OSPF-VRF via the SAME traversal as BGP-VRF (NX-OS + IOS-XR)
# ---------------------------------------------------------------------------

NXOS_OSPF_VRF = """\
hostname nx1
router ospf 7
  router-id 9.9.9.9
  vrf TENANT_X
    router-id 10.9.9.9
    redistribute bgp 65010 route-map RM_T
    area 0.0.0.9 stub
"""


def test_nxos_ospf_vrf_instance_via_shared_traversal():
    p = NXOSParser(NXOS_OSPF_VRF).parse()
    glob = next(o for o in p.ospf_instances if o.vrf is None)
    assert glob.process_id == 7 and str(glob.router_id) == "9.9.9.9"
    vrf_inst = next((o for o in p.ospf_instances if o.vrf == "TENANT_X"), None)
    assert vrf_inst is not None
    assert vrf_inst.process_id == 7
    assert str(vrf_inst.router_id) == "10.9.9.9"
    assert [a.area_id for a in vrf_inst.areas] == ["0.0.0.9"]
    assert len(vrf_inst.redistribute) == 1


IOSXR_OSPF_VRF = """\
hostname xr1
router ospf 7
 router-id 9.9.9.9
 area 0
  interface Loopback0
 vrf TENANT_X
  router-id 10.9.9.9
  area 0
   interface GigabitEthernet0/0/0/9
"""


def test_iosxr_ospf_vrf_instance_via_shared_traversal():
    p = IOSXRParser(IOSXR_OSPF_VRF).parse()
    glob = next(o for o in p.ospf_instances if o.vrf is None)
    assert glob.process_id == 7 and str(glob.router_id) == "9.9.9.9"
    vrf_inst = next((o for o in p.ospf_instances if o.vrf == "TENANT_X"), None)
    assert vrf_inst is not None
    assert vrf_inst.process_id == 7
    assert str(vrf_inst.router_id) == "10.9.9.9"
    assert [a.area_id for a in vrf_inst.areas] == ["0"]
