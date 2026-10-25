"""Tests for Phase 3 new-model parser implementations.

Covers parse_aaa / parse_dns / parse_dhcp / parse_lldp / parse_cdp /
parse_spanning_tree on IOS (inherited by IOS-XR, EOS, NX-OS).
"""

import pytest
from confgraph.parsers.ios_parser import IOSParser


# ---------------------------------------------------------------------------
# AAA
# ---------------------------------------------------------------------------

class TestParseAAA:

    def _parse(self, config: str):
        return IOSParser(config).parse_aaa()

    def test_new_model_detected(self):
        cfg = "aaa new-model\n"
        result = self._parse(cfg)
        assert result is not None
        assert result.new_model is True

    def test_authentication_list_login(self):
        cfg = "aaa new-model\naaa authentication login default local tacacs+\n"
        result = self._parse(cfg)
        assert result is not None
        assert len(result.authentication_lists) == 1
        al = result.authentication_lists[0]
        assert al.service == "login"
        assert al.name == "default"
        assert al.methods == ["local", "tacacs+"]

    def test_multiple_auth_lists(self):
        cfg = (
            "aaa new-model\n"
            "aaa authentication login default local tacacs+\n"
            "aaa authentication enable default enable\n"
        )
        result = self._parse(cfg)
        assert result is not None
        assert len(result.authentication_lists) == 2

    def test_tacacs_named_server(self):
        cfg = (
            "aaa new-model\n"
            "tacacs server CORP\n"
            " address ipv4 10.0.0.1\n"
            " key Secret123\n"
        )
        result = self._parse(cfg)
        assert result is not None
        assert len(result.tacacs_servers) == 1
        srv = result.tacacs_servers[0]
        assert srv.address == "10.0.0.1"
        assert srv.key == "Secret123"

    def test_tacacs_legacy_server(self):
        cfg = "aaa new-model\ntacacs-server host 192.168.1.1 key LegacyKey\n"
        result = self._parse(cfg)
        assert result is not None
        assert len(result.tacacs_servers) == 1
        assert result.tacacs_servers[0].address == "192.168.1.1"

    def test_radius_named_server(self):
        cfg = (
            "aaa new-model\n"
            "radius server RAD\n"
            " address ipv4 10.0.0.2 auth-port 1812 acct-port 1813\n"
            " key RadKey\n"
        )
        result = self._parse(cfg)
        assert result is not None
        assert len(result.radius_servers) == 1
        srv = result.radius_servers[0]
        assert srv.address == "10.0.0.2"
        assert srv.auth_port == 1812
        assert srv.acct_port == 1813

    def test_local_auth_enabled_flag(self):
        cfg = "aaa new-model\naaa authentication login default local\n"
        result = self._parse(cfg)
        assert result is not None
        assert result.local_auth_enabled is True

    def test_no_local_auth(self):
        cfg = "aaa new-model\naaa authentication login default tacacs+\n"
        result = self._parse(cfg)
        assert result is not None
        assert result.local_auth_enabled is False

    def test_no_aaa_returns_none(self):
        cfg = "hostname router\n"
        assert self._parse(cfg) is None

    def test_authorization_list(self):
        cfg = "aaa new-model\naaa authorization exec default local\n"
        result = self._parse(cfg)
        assert result is not None
        assert len(result.authorization_lists) == 1
        assert result.authorization_lists[0].service == "exec"

    def test_accounting_list(self):
        cfg = "aaa new-model\naaa accounting exec default start-stop group tacacs+\n"
        result = self._parse(cfg)
        assert result is not None
        assert len(result.accounting_lists) == 1
        acct = result.accounting_lists[0]
        assert acct.service == "exec"
        assert acct.trigger == "start-stop"


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------

class TestParseDNS:

    def _parse(self, config: str):
        return IOSParser(config).parse_dns()

    def test_domain_name(self):
        cfg = "ip domain name corp.example.com\n"
        result = self._parse(cfg)
        assert result is not None
        assert result.domain_name == "corp.example.com"

    def test_domain_hyphen_form(self):
        """'ip domain-name' (hyphenated) must also be captured."""
        cfg = "ip domain-name corp.example.com\n"
        result = self._parse(cfg)
        assert result is not None
        assert result.domain_name == "corp.example.com"

    def test_name_servers_multiple(self):
        cfg = "ip name-server 8.8.8.8 8.8.4.4\n"
        result = self._parse(cfg)
        assert result is not None
        assert "8.8.8.8" in result.name_servers
        assert "8.8.4.4" in result.name_servers

    def test_name_servers_multiple_lines(self):
        cfg = "ip name-server 1.1.1.1\nip name-server 9.9.9.9\n"
        result = self._parse(cfg)
        assert result is not None
        assert "1.1.1.1" in result.name_servers
        assert "9.9.9.9" in result.name_servers

    def test_lookup_disabled(self):
        cfg = "no ip domain lookup\nip name-server 8.8.8.8\n"
        result = self._parse(cfg)
        assert result is not None
        assert result.lookup_enabled is False

    def test_lookup_enabled_by_default(self):
        cfg = "ip domain name example.com\n"
        result = self._parse(cfg)
        assert result is not None
        assert result.lookup_enabled is True

    def test_no_dns_returns_none(self):
        cfg = "hostname router\n"
        assert self._parse(cfg) is None


# ---------------------------------------------------------------------------
# DHCP
# ---------------------------------------------------------------------------

class TestParseDHCP:

    def _parse(self, config: str):
        return IOSParser(config).parse_dhcp()

    def test_excluded_range(self):
        cfg = "ip dhcp excluded-address 10.1.1.1 10.1.1.10\n"
        result = self._parse(cfg)
        assert result is not None
        assert len(result.excluded_ranges) == 1
        assert result.excluded_ranges[0].low == "10.1.1.1"
        assert result.excluded_ranges[0].high == "10.1.1.10"

    def test_single_excluded_address(self):
        cfg = "ip dhcp excluded-address 10.1.1.1\n"
        result = self._parse(cfg)
        assert result is not None
        assert result.excluded_ranges[0].high is None

    def test_pool_name(self):
        cfg = "ip dhcp pool VLAN10\n network 10.1.1.0 255.255.255.0\n"
        result = self._parse(cfg)
        assert result is not None
        assert len(result.pools) == 1
        assert result.pools[0].name == "VLAN10"

    def test_pool_network(self):
        cfg = "ip dhcp pool VLAN10\n network 192.168.1.0 255.255.255.0\n"
        result = self._parse(cfg)
        assert result is not None
        assert result.pools[0].network == "192.168.1.0 255.255.255.0"

    def test_pool_dns_servers(self):
        cfg = "ip dhcp pool P1\n network 10.0.0.0 255.0.0.0\n dns-server 8.8.8.8 8.8.4.4\n"
        result = self._parse(cfg)
        assert result is not None
        assert "8.8.8.8" in result.pools[0].dns_servers
        assert "8.8.4.4" in result.pools[0].dns_servers

    def test_pool_default_router(self):
        cfg = "ip dhcp pool P1\n network 10.0.0.0 255.0.0.0\n default-router 10.0.0.1\n"
        result = self._parse(cfg)
        assert result is not None
        assert "10.0.0.1" in result.pools[0].default_router

    def test_snooping_enabled(self):
        cfg = "ip dhcp snooping\nip dhcp snooping vlan 10,20\n"
        result = self._parse(cfg)
        assert result is not None
        assert result.snooping_enabled is True
        assert "10,20" in result.snooping_vlans

    def test_no_dhcp_returns_none(self):
        cfg = "hostname router\n"
        assert self._parse(cfg) is None

    def test_multiple_pools(self):
        cfg = (
            "ip dhcp pool VLAN10\n network 10.1.0.0 255.255.255.0\n"
            "ip dhcp pool VLAN20\n network 10.2.0.0 255.255.255.0\n"
        )
        result = self._parse(cfg)
        assert result is not None
        assert len(result.pools) == 2
        names = {p.name for p in result.pools}
        assert "VLAN10" in names
        assert "VLAN20" in names


# ---------------------------------------------------------------------------
# LLDP
# ---------------------------------------------------------------------------

class TestParseLLDP:

    def _parse(self, config: str):
        return IOSParser(config).parse_lldp()

    def test_lldp_run_enabled(self):
        cfg = "lldp run\n"
        result = self._parse(cfg)
        assert result is not None
        assert result.enabled is True

    def test_no_lldp_run_disabled(self):
        cfg = "no lldp run\n"
        result = self._parse(cfg)
        assert result is not None
        assert result.enabled is False

    def test_timer(self):
        cfg = "lldp run\nlldp timer 30\n"
        result = self._parse(cfg)
        assert result is not None
        assert result.timer == 30

    def test_holdtime(self):
        cfg = "lldp run\nlldp holdtime 120\n"
        result = self._parse(cfg)
        assert result is not None
        assert result.holdtime == 120

    def test_reinit(self):
        cfg = "lldp run\nlldp reinit 2\n"
        result = self._parse(cfg)
        assert result is not None
        assert result.reinit == 2

    def test_no_lldp_returns_none(self):
        cfg = "hostname switch\n"
        assert self._parse(cfg) is None


# ---------------------------------------------------------------------------
# CDP
# ---------------------------------------------------------------------------

class TestParseCDP:

    def _parse(self, config: str):
        return IOSParser(config).parse_cdp()

    def test_cdp_run_enabled(self):
        cfg = "cdp run\n"
        result = self._parse(cfg)
        assert result is not None
        assert result.enabled is True

    def test_no_cdp_run_disabled(self):
        cfg = "no cdp run\n"
        result = self._parse(cfg)
        assert result is not None
        assert result.enabled is False

    def test_timer(self):
        cfg = "cdp run\ncdp timer 60\n"
        result = self._parse(cfg)
        assert result is not None
        assert result.timer == 60

    def test_holdtime(self):
        cfg = "cdp run\ncdp holdtime 180\n"
        result = self._parse(cfg)
        assert result is not None
        assert result.holdtime == 180

    def test_advertise_v2_disabled(self):
        cfg = "cdp run\nno cdp advertise-v2\n"
        result = self._parse(cfg)
        assert result is not None
        assert result.advertise_v2 is False

    def test_no_cdp_returns_none(self):
        cfg = "hostname router\n"
        assert self._parse(cfg) is None


# ---------------------------------------------------------------------------
# Spanning Tree
# ---------------------------------------------------------------------------

class TestParseSpanningTree:

    def _parse(self, config: str):
        return IOSParser(config).parse_spanning_tree()

    def test_mode(self):
        cfg = "spanning-tree mode rapid-pvst\n"
        result = self._parse(cfg)
        assert result is not None
        assert result.mode == "rapid-pvst"

    def test_vlan_priority(self):
        cfg = "spanning-tree mode pvst\nspanning-tree vlan 1 priority 4096\n"
        result = self._parse(cfg)
        assert result is not None
        assert len(result.vlan_configs) == 1
        assert result.vlan_configs[0].vlan_id == "1"
        assert result.vlan_configs[0].priority == 4096

    def test_multiple_vlan_priorities(self):
        cfg = (
            "spanning-tree mode pvst\n"
            "spanning-tree vlan 10 priority 4096\n"
            "spanning-tree vlan 20 priority 8192\n"
        )
        result = self._parse(cfg)
        assert result is not None
        assert len(result.vlan_configs) == 2
        priorities = {v.vlan_id: v.priority for v in result.vlan_configs}
        assert priorities["10"] == 4096
        assert priorities["20"] == 8192

    def test_portfast_default(self):
        cfg = "spanning-tree portfast default\n"
        result = self._parse(cfg)
        assert result is not None
        assert result.portfast_default is True

    def test_bpduguard_default(self):
        cfg = "spanning-tree portfast bpduguard default\n"
        result = self._parse(cfg)
        assert result is not None
        assert result.bpduguard_default is True

    def test_bpdufilter_default(self):
        cfg = "spanning-tree portfast bpdufilter default\n"
        result = self._parse(cfg)
        assert result is not None
        assert result.bpdufilter_default is True

    def test_loopguard_default(self):
        cfg = "spanning-tree loopguard default\n"
        result = self._parse(cfg)
        assert result is not None
        assert result.loopguard_default is True

    def test_no_stp_returns_none(self):
        cfg = "hostname router\n"
        assert self._parse(cfg) is None
