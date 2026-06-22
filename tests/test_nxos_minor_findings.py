"""Tests for NX-OS parser minor findings (N2–N9).

Each test class covers one CCR item with positive, negative, and
where applicable parity/regression cases.
"""

import pytest
from confgraph.parsers.nxos_parser import NXOSParser


def _parse(config: str):
    return NXOSParser(config).parse()


# -----------------------------------------------------------------------
# N2 — AAA group server members
# -----------------------------------------------------------------------


class TestN2AAAGroupServerMembers:
    """aaa group server tacacs+/radius NAME → child server <ip> parsed."""

    def test_tacacs_group_servers_added(self):
        pc = _parse(
            "aaa new-model\n"
            "aaa authentication login default group TACGROUP local\n"
            "aaa group server tacacs+ TACGROUP\n"
            "  server 10.0.0.1\n"
            "  server 10.0.0.2\n"
        )
        assert pc.aaa is not None
        addrs = {s.address for s in pc.aaa.tacacs_servers}
        assert "10.0.0.1" in addrs
        assert "10.0.0.2" in addrs

    def test_radius_group_servers_added(self):
        pc = _parse(
            "aaa new-model\n"
            "aaa authentication login default group RADGROUP local\n"
            "aaa group server radius RADGROUP\n"
            "  server 10.1.1.1\n"
            "  server 10.1.1.2\n"
        )
        assert pc.aaa is not None
        addrs = {s.address for s in pc.aaa.radius_servers}
        assert "10.1.1.1" in addrs
        assert "10.1.1.2" in addrs

    def test_no_duplicate_if_server_already_defined(self):
        """If tacacs-server host already defines the server, don't duplicate."""
        pc = _parse(
            "aaa new-model\n"
            "tacacs-server host 10.0.0.1 key Secret\n"
            "aaa group server tacacs+ TACGROUP\n"
            "  server 10.0.0.1\n"
        )
        assert pc.aaa is not None
        addrs = [s.address for s in pc.aaa.tacacs_servers]
        assert addrs.count("10.0.0.1") == 1

    def test_no_aaa_returns_none(self):
        pc = _parse("hostname SWITCH1\n")
        assert pc.aaa is None


# -----------------------------------------------------------------------
# N3 — VXLAN: all NVEs, mcast-group, suppress-arp, vn-segment
# -----------------------------------------------------------------------


class TestN3VXLANCompleteness:
    """VXLAN vn-segment, mcast-group, suppress-arp, multiple NVEs."""

    def test_vn_segment_populates_vlan(self):
        pc = _parse(
            "vlan 10\n"
            "  vn-segment 10010\n"
            "vlan 20\n"
            "  vn-segment 10020\n"
            "interface nve1\n"
            "  source-interface loopback1\n"
            "  member vni 10010\n"
            "  member vni 10020\n"
        )
        assert pc.vxlan is not None
        vni_map = {v.vni: v for v in pc.vxlan.vni_mappings}
        assert vni_map[10010].vlan == 10
        assert vni_map[10020].vlan == 20

    def test_mcast_group_parsed(self):
        pc = _parse(
            "interface nve1\n"
            "  source-interface loopback1\n"
            "  member vni 10010\n"
            "    mcast-group 239.1.1.1\n"
        )
        assert pc.vxlan is not None
        assert pc.vxlan.vni_mappings[0].mcast_group == "239.1.1.1"

    def test_suppress_arp_parsed(self):
        pc = _parse(
            "interface nve1\n"
            "  source-interface loopback1\n"
            "  member vni 10010\n"
            "    suppress-arp\n"
        )
        assert pc.vxlan is not None
        assert pc.vxlan.vni_mappings[0].suppress_arp is True

    def test_l3_vni_associate_vrf(self):
        pc = _parse(
            "interface nve1\n"
            "  source-interface loopback1\n"
            "  member vni 50001 associate-vrf\n"
        )
        assert pc.vxlan is not None
        assert pc.vxlan.vni_mappings[0].vrf == "(L3)"
        assert pc.vxlan.vni_mappings[0].vlan is None

    def test_no_vn_segment_vlan_is_none(self):
        """VNI without a corresponding vlan/vn-segment → vlan=None."""
        pc = _parse(
            "interface nve1\n"
            "  source-interface loopback1\n"
            "  member vni 99999\n"
        )
        assert pc.vxlan is not None
        assert pc.vxlan.vni_mappings[0].vlan is None

    def test_no_nve_returns_none(self):
        pc = _parse("hostname SWITCH1\n")
        assert pc.vxlan is None

    def test_line_numbers_populated(self):
        pc = _parse(
            "interface nve1\n"
            "  source-interface loopback1\n"
            "  member vni 10010\n"
        )
        assert pc.vxlan is not None
        assert len(pc.vxlan.line_numbers) > 0


# -----------------------------------------------------------------------
# N4 — VPC unguarded IPv4Address
# -----------------------------------------------------------------------


class TestN4VPCGuardedIPv4:
    """Malformed peer-keepalive address does not abort parse."""

    def test_malformed_keepalive_dst_skipped(self):
        pc = _parse(
            "vpc domain 100\n"
            "  role priority 1000\n"
            "  peer-keepalive destination BADADDR source 10.0.0.1\n"
        )
        assert pc.vpc is not None
        assert pc.vpc.peer_keepalive_destination is None

    def test_malformed_keepalive_src_skipped(self):
        pc = _parse(
            "vpc domain 100\n"
            "  peer-keepalive destination 10.0.0.2 source BADADDR\n"
        )
        assert pc.vpc is not None
        assert pc.vpc.peer_keepalive_destination is not None
        assert pc.vpc.peer_keepalive_source is None

    def test_valid_keepalive_still_works(self):
        pc = _parse(
            "vpc domain 100\n"
            "  peer-keepalive destination 10.0.0.2 source 10.0.0.1 vrf management\n"
        )
        assert pc.vpc is not None
        assert str(pc.vpc.peer_keepalive_destination) == "10.0.0.2"
        assert str(pc.vpc.peer_keepalive_source) == "10.0.0.1"
        assert pc.vpc.peer_keepalive_vrf == "management"


# -----------------------------------------------------------------------
# N6 — Per-VRF DNS in vrf context blocks
# -----------------------------------------------------------------------


class TestN6VRFContextDNS:
    """DNS entries inside vrf context blocks are captured."""

    def test_vrf_context_name_server(self):
        pc = _parse(
            "vrf context management\n"
            "  ip name-server 8.8.8.8 8.8.4.4\n"
        )
        assert pc.dns is not None
        assert "8.8.8.8" in pc.dns.name_servers
        assert "8.8.4.4" in pc.dns.name_servers

    def test_vrf_context_domain_name(self):
        pc = _parse(
            "vrf context management\n"
            "  ip domain-name example.com\n"
        )
        assert pc.dns is not None
        assert pc.dns.domain_name == "example.com"

    def test_vrf_context_domain_list(self):
        pc = _parse(
            "vrf context management\n"
            "  ip domain-list corp.local\n"
            "  ip domain-list lab.local\n"
        )
        assert pc.dns is not None
        assert "corp.local" in pc.dns.domain_list
        assert "lab.local" in pc.dns.domain_list

    def test_global_and_vrf_merged(self):
        pc = _parse(
            "ip name-server 1.1.1.1\n"
            "vrf context management\n"
            "  ip name-server 8.8.8.8\n"
        )
        assert pc.dns is not None
        assert "1.1.1.1" in pc.dns.name_servers
        assert "8.8.8.8" in pc.dns.name_servers

    def test_no_dns_returns_none(self):
        pc = _parse("hostname SWITCH1\n")
        assert pc.dns is None


# -----------------------------------------------------------------------
# N7 — LLDP/CDP feature enable
# -----------------------------------------------------------------------


class TestN7LLDPFeatureEnable:
    """NX-OS LLDP enabled via ``feature lldp``."""

    def test_feature_lldp_enables(self):
        pc = _parse("feature lldp\n")
        assert pc.lldp is not None
        assert pc.lldp.enabled is True

    def test_no_feature_lldp_disabled(self):
        pc = _parse("no feature lldp\n")
        assert pc.lldp is not None
        assert pc.lldp.enabled is False

    def test_no_feature_returns_none(self):
        """No LLDP config at all → None."""
        pc = _parse("hostname SWITCH1\n")
        assert pc.lldp is None

    def test_feature_lldp_with_timer(self):
        pc = _parse(
            "feature lldp\n"
            "lldp timer 30\n"
            "lldp holdtime 120\n"
        )
        assert pc.lldp is not None
        assert pc.lldp.enabled is True
        assert pc.lldp.timer == 30
        assert pc.lldp.holdtime == 120

    def test_default_disabled_without_feature(self):
        """NX-OS defaults LLDP off — bare 'lldp timer' without 'feature lldp'."""
        pc = _parse("lldp timer 30\n")
        assert pc.lldp is not None
        assert pc.lldp.enabled is False
        assert pc.lldp.timer == 30


class TestN7CDPFeatureEnable:
    """NX-OS CDP enabled via ``feature cdp``."""

    def test_feature_cdp_enables(self):
        pc = _parse("feature cdp\n")
        assert pc.cdp is not None
        assert pc.cdp.enabled is True

    def test_no_feature_cdp_disabled(self):
        pc = _parse("no feature cdp\n")
        assert pc.cdp is not None
        assert pc.cdp.enabled is False

    def test_no_feature_returns_none(self):
        pc = _parse("hostname SWITCH1\n")
        assert pc.cdp is None

    def test_feature_cdp_with_timer(self):
        pc = _parse(
            "feature cdp\n"
            "cdp timer 90\n"
            "cdp holdtime 300\n"
        )
        assert pc.cdp is not None
        assert pc.cdp.enabled is True
        assert pc.cdp.timer == 90
        assert pc.cdp.holdtime == 300


# -----------------------------------------------------------------------
# N8 — line_numbers populated in VPC/MPLS
# -----------------------------------------------------------------------


class TestN8LineNumbers:
    """VPC and MPLS line_numbers are no longer empty."""

    def test_vpc_line_numbers(self):
        pc = _parse(
            "vpc domain 100\n"
            "  role priority 1000\n"
        )
        assert pc.vpc is not None
        assert len(pc.vpc.line_numbers) >= 2

    def test_mpls_line_numbers(self):
        pc = _parse(
            "mpls ldp configuration\n"
            "  router-id Loopback0\n"
        )
        assert pc.mpls is not None
        assert len(pc.mpls.line_numbers) >= 2


# -----------------------------------------------------------------------
# N9 — Syslog dead branch
# -----------------------------------------------------------------------


class TestN9SyslogDeadBranch:
    """Syslog enabled detection is correct."""

    def test_logging_off_disables(self):
        pc = _parse(
            "logging server 10.0.0.1\n"
            "logging off\n"
        )
        assert pc.syslog is not None
        assert pc.syslog.enabled is False

    def test_no_logging_on_disables(self):
        pc = _parse("no logging on\n")
        assert pc.syslog is not None
        assert pc.syslog.enabled is False

    def test_logging_server_only_enabled(self):
        pc = _parse("logging server 10.0.0.1\n")
        assert pc.syslog is not None
        assert pc.syslog.enabled is True

    def test_logging_source_interface_not_disabled(self):
        """'logging source-interface' should NOT trigger disabled."""
        pc = _parse(
            "logging server 10.0.0.1\n"
            "logging source-interface mgmt0\n"
        )
        assert pc.syslog is not None
        assert pc.syslog.enabled is True
