"""Tests for VXLAN VTEP attribute parsing — vn-segment on VLANEntry and
host-reachability on VXLANConfig.

CCR: confgraph_entrp_vxlan_vtep_attributes_not_evaluated.md (parser side)
"""

from confgraph.parsers.nxos_parser import NXOSParser


NXOS_VXLAN_CONFIG = """
hostname leaf-01

vlan 10
  name SERVERS
  vn-segment 10010
vlan 20
  name MGMT
  vn-segment 10020
vlan 30
  name NO_VNI

interface nve1
  no shutdown
  host-reachability protocol bgp
  source-interface loopback0
  member vni 10010
    suppress-arp
    mcast-group 239.1.1.1
  member vni 10020
  member vni 50001 associate-vrf
"""


class TestVnSegmentOnVLANEntry:
    """VLANEntry.vn_segment is populated from 'vlan X / vn-segment Y'."""

    def test_vn_segment_parsed(self):
        parser = NXOSParser(NXOS_VXLAN_CONFIG)
        vlans = parser.parse_vlans()
        by_id = {v.vlan_id: v for v in vlans}

        assert by_id[10].vn_segment == 10010
        assert by_id[20].vn_segment == 10020

    def test_vlan_without_vn_segment_is_none(self):
        parser = NXOSParser(NXOS_VXLAN_CONFIG)
        vlans = parser.parse_vlans()
        by_id = {v.vlan_id: v for v in vlans}

        assert by_id[30].vn_segment is None

    def test_vlan_name_still_parsed(self):
        """vn-segment parsing does not break name parsing."""
        parser = NXOSParser(NXOS_VXLAN_CONFIG)
        vlans = parser.parse_vlans()
        by_id = {v.vlan_id: v for v in vlans}

        assert by_id[10].name == "SERVERS"
        assert by_id[30].name == "NO_VNI"


class TestHostReachabilityParsed:
    """VXLANConfig.host_reachability is populated from NVE interface."""

    def test_host_reachability_bgp(self):
        parser = NXOSParser(NXOS_VXLAN_CONFIG)
        vxlan = parser.parse_vxlan()
        assert vxlan is not None
        assert vxlan.host_reachability == "bgp"

    def test_host_reachability_absent(self):
        config = """
hostname leaf-02

interface nve1
  no shutdown
  source-interface loopback0
  member vni 10010
"""
        parser = NXOSParser(config)
        vxlan = parser.parse_vxlan()
        assert vxlan is not None
        assert vxlan.host_reachability is None

    def test_source_interface_still_parsed(self):
        """host-reachability parsing does not break source-interface."""
        parser = NXOSParser(NXOS_VXLAN_CONFIG)
        vxlan = parser.parse_vxlan()
        assert vxlan.source_interface == "loopback0"


class TestHostReachabilityTombstone:
    """'no host-reachability protocol bgp' emits field:vxlan:host_reachability."""

    def test_tombstone_emitted(self):
        config = """
hostname leaf-01

interface nve1
  no shutdown
  source-interface loopback0
  no host-reachability protocol bgp
  member vni 10010
"""
        parser = NXOSParser(config)
        tombstones = parser.parse_deletion_commands()
        assert "field:vxlan:host_reachability" in tombstones

    def test_no_tombstone_when_present(self):
        parser = NXOSParser(NXOS_VXLAN_CONFIG)
        tombstones = parser.parse_deletion_commands()
        assert "field:vxlan:host_reachability" not in tombstones
