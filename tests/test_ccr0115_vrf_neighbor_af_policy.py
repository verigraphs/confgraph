"""CCR-0115 — VRF-scoped BGP neighbor address-family policy.

The shared block-form VRF walker (``_parse_bgp_vrf_blocks``) parsed neighbors
but never fired the polymorphic ``_apply_bgp_af_neighbor_policies`` hook the
global instance fires, so a VRF neighbor lost its entire per-AF policy while
the identical neighbor block at global scope parsed correctly.

The fix is ONE call in the shared walker; each OS's existing convention is
applied by its own hook implementation:

  * IOS-XR — override descends each neighbor's ``address-family`` sub-block
    into ``BGPNeighborAF`` entries (the parity tests here);
  * EOS — base walk reads ``neighbor X <policy>`` lines inside the VRF's
    ``address-family`` blocks (previously silently dropped too);
  * NX-OS — its VRF AF blocks carry no ``neighbor`` lines, so the hook is a
    no-op and the flattened session-level convention is untouched.
"""

from __future__ import annotations

from confgraph.parsers.eos_parser import EOSParser
from confgraph.parsers.iosxr_parser import IOSXRParser
from confgraph.parsers.nxos_parser import NXOSParser

_XR_NEIGHBOR_BODY = """\
  remote-as 65001
  description ISP-PEER
  address-family ipv4 unicast
   route-policy RM-IN in
   route-policy RM-OUT out
   prefix-set PL-IN in
   next-hop-self
   route-reflector-client
   send-community-ebgp
"""

_XR_GLOBAL = "router bgp 65000\n neighbor 10.0.0.1\n" + _XR_NEIGHBOR_BODY

_XR_VRF = "router bgp 65000\n vrf CORP\n  neighbor 10.0.0.1\n" + "\n".join(
    " " + line for line in _XR_NEIGHBOR_BODY.splitlines()
) + "\n"


def _vrf_instance(pc):
    insts = [b for b in pc.bgp_instances if b.vrf and b.vrf != "global"]
    assert insts, f"No VRF BGP instance parsed; got {pc.bgp_instances}"
    return insts[0]


def _single_af(nbr):
    assert len(nbr.address_families) == 1, (
        f"Expected exactly one BGPNeighborAF; got {nbr.address_families!r}"
    )
    return nbr.address_families[0]


class TestIOSXRVRFNeighborAF:
    """Positive: the CCR-0115 repro — VRF neighbor AF policy is populated."""

    def test_vrf_neighbor_af_fields(self):
        pc = IOSXRParser(_XR_VRF).parse()
        nbr = _vrf_instance(pc).neighbors[0]
        af = _single_af(nbr)
        assert (af.afi, af.safi) == ("ipv4", "unicast")
        assert af.route_map_in == "RM-IN"
        assert af.route_map_out == "RM-OUT"
        assert af.prefix_list_in == "PL-IN"
        assert af.next_hop_self is True
        assert af.route_reflector_client is True
        assert af.send_community is True

    def test_session_level_fields_still_parse(self):
        pc = IOSXRParser(_XR_VRF).parse()
        nbr = _vrf_instance(pc).neighbors[0]
        assert nbr.remote_as == 65001
        assert nbr.description == "ISP-PEER"


class TestIOSXRGlobalVRFAFParity:
    """Parity: the same neighbor block at global vs VRF scope produces a
    field-identical BGPNeighborAF — proof both scopes run the same hook."""

    def test_af_entries_identical(self):
        g_nbr = IOSXRParser(_XR_GLOBAL).parse().bgp_instances[0].neighbors[0]
        v_nbr = _vrf_instance(IOSXRParser(_XR_VRF).parse()).neighbors[0]
        g_af, v_af = _single_af(g_nbr), _single_af(v_nbr)
        assert g_af.model_dump() == v_af.model_dump()


class TestEOSVRFNeighborAF:
    """The same single hook call gives EOS its VRF AF-block neighbor policy
    (base implementation), previously dropped on the VRF path as well."""

    def test_vrf_af_block_neighbor_policy(self):
        cfg = """\
router bgp 65000
   vrf RED
      rd 65000:100
      neighbor 10.1.1.1 remote-as 65001
      address-family ipv4
         neighbor 10.1.1.1 route-map RM-IN in
         neighbor 10.1.1.1 activate
         network 10.10.0.0/16
"""
        pc = EOSParser(cfg).parse()
        nbr = _vrf_instance(pc).neighbors[0]
        af = _single_af(nbr)
        assert (af.afi, af.safi) == ("ipv4", "unicast")
        assert af.route_map_in == "RM-IN"
        assert af.activate is True


class TestNXOSVRFNoOp:
    """Regression: NX-OS VRF parsing is unchanged — the flattened session-level
    convention stands, and the hook attaches nothing extra (its VRF-level AF
    blocks carry no ``neighbor`` lines)."""

    def test_vrf_neighbor_unchanged(self):
        cfg = """\
router bgp 65000
  vrf CORP
    address-family ipv4 unicast
      network 10.0.0.0/24
      redistribute direct route-map RM-CONN
    neighbor 10.2.2.2
      remote-as 65002
      address-family ipv4 unicast
        route-map RM-IN in
"""
        pc = NXOSParser(cfg).parse()
        inst = _vrf_instance(pc)
        assert len(inst.neighbors) == 1
        nbr = inst.neighbors[0]
        # NX-OS convention: AF policy flattened onto the session-level fields
        # by its own neighbor parser (which also records the AF entry itself).
        assert nbr.route_map_in == "RM-IN"
        assert len(nbr.address_families) == 1


class TestNegativeNoAFBlock:
    """Negative: a VRF neighbor without an address-family sub-block keeps an
    empty address_families list on every OS that stores AF entries."""

    def test_xr_vrf_neighbor_without_af(self):
        cfg = """\
router bgp 65000
 vrf CORP
  neighbor 10.0.0.1
   remote-as 65001
"""
        pc = IOSXRParser(cfg).parse()
        nbr = _vrf_instance(pc).neighbors[0]
        assert nbr.address_families == []
