"""Tests for EOS minor-findings fixes (E3, E5, E6).

E3 — _extract_interface_vrf regex tightened with end-of-line anchor.
E5 — line_numbers populated in parse_vxlan, parse_mpls, parse_vpc.
E6 — parse_dns override scans vrf instance blocks for per-VRF DNS entries.
"""

from confgraph.parsers.eos_parser import EOSParser


# ---------------------------------------------------------------------------
# E3 — _extract_interface_vrf regex
# ---------------------------------------------------------------------------


class TestE3VRFRegex:

    def test_basic_vrf_extraction(self):
        cfg = (
            "interface Ethernet1\n"
            " vrf MGMT\n"
            " ip address 10.0.0.1/24\n"
            "!\n"
        )
        pc = EOSParser(cfg).parse()
        intf = next(i for i in pc.interfaces if i.name == "Ethernet1")
        assert intf.vrf == "MGMT"

    def test_no_vrf(self):
        cfg = (
            "interface Ethernet1\n"
            " ip address 10.0.0.1/24\n"
            "!\n"
        )
        pc = EOSParser(cfg).parse()
        intf = next(i for i in pc.interfaces if i.name == "Ethernet1")
        assert intf.vrf is None


# ---------------------------------------------------------------------------
# E5 — line_numbers populated
# ---------------------------------------------------------------------------


class TestE5LineNumbers:

    def test_vxlan_line_numbers(self):
        cfg = (
            "interface Vxlan1\n"
            " vxlan source-interface Loopback1\n"
            " vxlan udp-port 4789\n"
            " vxlan vlan 10 vni 10010\n"
            "!\n"
        )
        pc = EOSParser(cfg).parse()
        assert pc.vxlan is not None
        assert len(pc.vxlan.line_numbers) > 0
        assert len(pc.vxlan.line_numbers) == len(pc.vxlan.raw_lines)

    def test_mpls_line_numbers(self):
        cfg = (
            "mpls ldp\n"
            " router-id 10.0.0.1\n"
            " transport-address 10.0.0.1\n"
            "!\n"
        )
        pc = EOSParser(cfg).parse()
        assert pc.mpls is not None
        assert len(pc.mpls.line_numbers) > 0
        assert len(pc.mpls.line_numbers) == len(pc.mpls.raw_lines)

    def test_vpc_line_numbers(self):
        cfg = (
            "mlag configuration\n"
            " domain-id MLAG1\n"
            " local-interface Vlan4094\n"
            " peer-address 10.0.0.2\n"
            " peer-link Port-Channel1\n"
            "!\n"
        )
        pc = EOSParser(cfg).parse()
        assert pc.vpc is not None
        assert len(pc.vpc.line_numbers) > 0
        assert len(pc.vpc.line_numbers) == len(pc.vpc.raw_lines)


# ---------------------------------------------------------------------------
# E6 — parse_dns with vrf instance blocks
# ---------------------------------------------------------------------------


class TestE6DNSVrfInstance:

    def test_global_dns_only(self):
        cfg = (
            "ip name-server 8.8.8.8\n"
            "ip domain name example.com\n"
        )
        pc = EOSParser(cfg).parse()
        assert pc.dns is not None
        assert "8.8.8.8" in pc.dns.name_servers
        assert pc.dns.domain_name == "example.com"

    def test_vrf_instance_dns_servers(self):
        cfg = (
            "vrf instance MGMT\n"
            " ip name-server 10.1.1.1\n"
            " ip name-server 10.1.1.2\n"
            "!\n"
        )
        pc = EOSParser(cfg).parse()
        assert pc.dns is not None
        assert "10.1.1.1" in pc.dns.name_servers
        assert "10.1.1.2" in pc.dns.name_servers

    def test_vrf_instance_domain_name(self):
        cfg = (
            "vrf instance MGMT\n"
            " ip domain name mgmt.example.com\n"
            "!\n"
        )
        pc = EOSParser(cfg).parse()
        assert pc.dns is not None
        assert pc.dns.domain_name == "mgmt.example.com"

    def test_vrf_instance_domain_list(self):
        cfg = (
            "vrf instance MGMT\n"
            " ip domain list corp.example.com\n"
            " ip domain list lab.example.com\n"
            "!\n"
        )
        pc = EOSParser(cfg).parse()
        assert pc.dns is not None
        assert "corp.example.com" in pc.dns.domain_list
        assert "lab.example.com" in pc.dns.domain_list

    def test_vrf_instance_no_domain_lookup(self):
        cfg = (
            "vrf instance MGMT\n"
            " no ip domain lookup\n"
            "!\n"
        )
        pc = EOSParser(cfg).parse()
        assert pc.dns is not None
        assert pc.dns.lookup_enabled is False

    def test_global_and_vrf_merged(self):
        cfg = (
            "ip name-server 8.8.8.8\n"
            "ip domain name example.com\n"
            "!\n"
            "vrf instance MGMT\n"
            " ip name-server 10.1.1.1\n"
            " ip domain list mgmt.example.com\n"
            "!\n"
        )
        pc = EOSParser(cfg).parse()
        assert pc.dns is not None
        assert "8.8.8.8" in pc.dns.name_servers
        assert "10.1.1.1" in pc.dns.name_servers
        assert pc.dns.domain_name == "example.com"
        assert "mgmt.example.com" in pc.dns.domain_list

    def test_vrf_domain_name_does_not_override_global(self):
        cfg = (
            "ip domain name example.com\n"
            "!\n"
            "vrf instance MGMT\n"
            " ip domain name mgmt.example.com\n"
            "!\n"
        )
        pc = EOSParser(cfg).parse()
        assert pc.dns is not None
        # Global domain_name takes precedence
        assert pc.dns.domain_name == "example.com"

    def test_multiple_vrf_instances(self):
        cfg = (
            "vrf instance MGMT\n"
            " ip name-server 10.1.1.1\n"
            "!\n"
            "vrf instance PROD\n"
            " ip name-server 10.2.2.2\n"
            "!\n"
        )
        pc = EOSParser(cfg).parse()
        assert pc.dns is not None
        assert "10.1.1.1" in pc.dns.name_servers
        assert "10.2.2.2" in pc.dns.name_servers

    def test_no_dns_at_all(self):
        cfg = (
            "interface Ethernet1\n"
            " ip address 10.0.0.1/24\n"
            "!\n"
        )
        pc = EOSParser(cfg).parse()
        assert pc.dns is None

    def test_vrf_dns_line_numbers_populated(self):
        cfg = (
            "vrf instance MGMT\n"
            " ip name-server 10.1.1.1\n"
            "!\n"
        )
        pc = EOSParser(cfg).parse()
        assert pc.dns is not None
        assert len(pc.dns.line_numbers) > 0
