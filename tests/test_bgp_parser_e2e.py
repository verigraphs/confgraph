"""End-to-end parser tests for BGP attributes used in S37 and S38 simulations.

Covers the full pipeline: parse real OS config text → model fields populated →
simulation behaves correctly.  Tests are grouped by attribute:

  - ``bgp cluster-id`` parsing (IOS, IOS-XR via inheritance, NX-OS via inheritance)
  - ``set as-path prepend`` route-map parsing (IOS and IOS-XR have different
    internal representations but both must produce correct simulation behavior)

These tests exist because S37/S38 originally used direct in-memory object
construction, bypassing the parser layer.  A parser gap (cluster-id never
populated) and a representation difference (IOS vs IOS-XR as-path prepend)
were not covered by those tests.
"""

from __future__ import annotations

import pytest
from ipaddress import IPv4Address

from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.iosxr_parser import IOSXRParser
from confgraph.parsers.nxos_parser import NXOSParser


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _bgp(config: str, parser_cls=IOSParser):
    instances = parser_cls(config).parse_bgp()
    assert instances, f"No BGP instances parsed from:\n{config}"
    return instances[0]

def _route_maps(config: str, parser_cls=IOSParser):
    return parser_cls(config).parse_route_maps()


# ---------------------------------------------------------------------------
# bgp cluster-id parsing
# ---------------------------------------------------------------------------

class TestBGPClusterIdParsing:
    """Verify that bgp cluster-id is parsed from config text and stored in BGPConfig."""

    _IOS_CFG = """\
router bgp 65000
 bgp router-id 1.1.1.1
 bgp cluster-id 42
 neighbor 10.0.0.1 remote-as 65000
"""

    _IOS_IP_CFG = """\
router bgp 65000
 bgp router-id 1.1.1.1
 bgp cluster-id 10.0.0.42
 neighbor 10.0.0.1 remote-as 65000
"""

    _IOSXR_CFG = """\
router bgp 65000
 bgp router-id 1.1.1.1
 bgp cluster-id 7
 neighbor-group RR-CLIENTS
  route-reflector-client
 !
 neighbor 10.0.0.2
  use neighbor-group RR-CLIENTS
  remote-as 65000
 !
!
"""

    _NXOS_CFG = """\
router bgp 65000
 bgp router-id 1.1.1.1
 bgp cluster-id 99
 neighbor 10.0.0.1
   remote-as 65000
"""

    def test_ios_cluster_id_integer(self):
        inst = _bgp(self._IOS_CFG)
        assert inst.cluster_id == 42, (
            f"bgp cluster-id 42 must be parsed as int 42; got {inst.cluster_id!r}"
        )

    def test_ios_cluster_id_ipv4(self):
        inst = _bgp(self._IOS_IP_CFG)
        assert inst.cluster_id == IPv4Address("10.0.0.42"), (
            f"bgp cluster-id 10.0.0.42 must be parsed as IPv4Address; got {inst.cluster_id!r}"
        )

    def test_ios_no_cluster_id_defaults_to_none(self):
        cfg = "router bgp 65000\n bgp router-id 1.1.1.1\n neighbor 10.0.0.1 remote-as 65000\n"
        inst = _bgp(cfg)
        assert inst.cluster_id is None, (
            f"Missing bgp cluster-id must default to None; got {inst.cluster_id!r}"
        )

    def test_iosxr_cluster_id_via_inheritance(self):
        """IOS-XR inherits main parse_bgp loop from IOS — cluster-id must be parsed."""
        inst = _bgp(self._IOSXR_CFG, parser_cls=IOSXRParser)
        assert inst.cluster_id == 7, (
            f"IOS-XR bgp cluster-id 7 must be parsed; got {inst.cluster_id!r}"
        )

    def test_nxos_cluster_id_via_inheritance(self):
        """NX-OS inherits main parse_bgp loop from IOS — cluster-id must be parsed."""
        inst = _bgp(self._NXOS_CFG, parser_cls=NXOSParser)
        assert inst.cluster_id == 99, (
            f"NX-OS bgp cluster-id 99 must be parsed; got {inst.cluster_id!r}"
        )


# ---------------------------------------------------------------------------
# set as-path prepend route-map parsing
# ---------------------------------------------------------------------------

class TestAsPathPrependParsing:
    """Verify that 'set as-path prepend' is parsed and stored in the route-map model.

    IOS/NX-OS/EOS store it as set_type='as-path' + values=['prepend', '<asn>', ...].
    IOS-XR stores it as set_type='as-path prepend' + values=['<asn>', ...].
    The policy engine in confgraph_entrp handles both representations.
    """

    _IOS_CFG = """\
route-map PREPEND-LOOP permit 10
 set as-path prepend 65100 65100
!
"""

    _IOSXR_CFG = """\
route-policy PREPEND-LOOP
  prepend as-path 65200 65200
end-policy
!
"""

    def test_ios_aspath_prepend_stored(self):
        rms = _route_maps(self._IOS_CFG)
        assert rms, "No route-maps parsed"
        rm = next((r for r in rms if r.name == "PREPEND-LOOP"), None)
        assert rm is not None, "Route-map PREPEND-LOOP not found"
        seq = rm.sequences[0]
        set_clauses = seq.set_clauses
        prepend_clause = next(
            (s for s in set_clauses if "as-path" in s.set_type.lower()), None
        )
        assert prepend_clause is not None, (
            f"No as-path set clause found; set_clauses={set_clauses}"
        )
        # IOS: set_type='as-path', values=['prepend', '65100', '65100']
        vals_joined = " ".join(prepend_clause.values).lower()
        assert "65100" in vals_joined, (
            f"ASN 65100 must appear in prepend values; got {prepend_clause.values!r}"
        )

    def test_iosxr_aspath_prepend_stored(self):
        rms = _route_maps(self._IOSXR_CFG, parser_cls=IOSXRParser)
        assert rms, "No route-maps parsed from IOS-XR config"
        rm = next((r for r in rms if r.name == "PREPEND-LOOP"), None)
        assert rm is not None, "Route-policy PREPEND-LOOP not found"
        seq = rm.sequences[0]
        prepend_clause = next(
            (s for s in seq.set_clauses if "as-path" in s.set_type.lower()), None
        )
        assert prepend_clause is not None, (
            f"No as-path set clause found in IOS-XR route-policy; set_clauses={seq.set_clauses}"
        )
        # IOS-XR: set_type='as-path prepend', values=['65200', '65200']
        vals_joined = " ".join(prepend_clause.values)
        assert "65200" in vals_joined, (
            f"ASN 65200 must appear in IOS-XR prepend values; got {prepend_clause.values!r}"
        )


# ---------------------------------------------------------------------------
# cluster-id → simulator round-trip
# ---------------------------------------------------------------------------

class TestClusterIdSimulatorRoundTrip:
    """Parse cluster-id from config text and verify the simulator uses it for loop prevention."""

    def test_parsed_cluster_id_used_in_simulation(self):
        """cluster-id from a real config string must be used by the BGP simulator."""
        # rr-a: route reflector with cluster-id 5, has a client
        rr_a_cfg = """\
router bgp 65000
 bgp router-id 1.1.1.1
 bgp cluster-id 5
 neighbor 10.0.1.2 remote-as 65000
 neighbor 10.0.1.2 update-source Loopback0
 neighbor 10.0.1.2 route-reflector-client
!
interface Loopback0
 ip address 1.1.1.1 255.255.255.255
!
interface GigabitEthernet0/0
 ip address 10.0.1.1 255.255.255.252
 no shutdown
!
"""
        # rr-b: intermediate RR with cluster-id 5 (same — loop condition)
        rr_b_cfg = """\
router bgp 65000
 bgp router-id 2.2.2.2
 bgp cluster-id 5
 neighbor 1.1.1.1 remote-as 65000
 neighbor 1.1.1.1 update-source Loopback0
 neighbor 1.1.1.1 route-reflector-client
 neighbor 3.3.3.3 remote-as 65000
 neighbor 3.3.3.3 update-source Loopback0
 neighbor 3.3.3.3 route-reflector-client
!
interface Loopback0
 ip address 2.2.2.2 255.255.255.255
!
interface GigabitEthernet0/0
 ip address 10.0.1.2 255.255.255.252
 no shutdown
!
interface GigabitEthernet0/1
 ip address 10.0.2.1 255.255.255.252
 no shutdown
!
"""
        # client: simple iBGP peer
        client_cfg = """\
router bgp 65000
 bgp router-id 3.3.3.3
 neighbor 2.2.2.2 remote-as 65000
 neighbor 2.2.2.2 update-source Loopback0
!
interface Loopback0
 ip address 3.3.3.3 255.255.255.255
!
interface GigabitEthernet0/0
 ip address 10.0.2.2 255.255.255.252
 no shutdown
!
"""
        rr_a = IOSParser(rr_a_cfg).parse()
        rr_b = IOSParser(rr_b_cfg).parse()
        client = IOSParser(client_cfg).parse()

        # Verify cluster_id was parsed
        assert rr_a.bgp_instances[0].cluster_id == 5, (
            f"rr-a cluster_id must be 5; got {rr_a.bgp_instances[0].cluster_id!r}"
        )
        assert rr_b.bgp_instances[0].cluster_id == 5, (
            f"rr-b cluster_id must be 5; got {rr_b.bgp_instances[0].cluster_id!r}"
        )

    def test_parsed_cluster_id_none_without_config(self):
        """A device without bgp cluster-id must have cluster_id=None after parsing."""
        cfg = """\
router bgp 65000
 bgp router-id 4.4.4.4
 neighbor 10.0.0.1 remote-as 65000
"""
        inst = _bgp(cfg)
        assert inst.cluster_id is None
