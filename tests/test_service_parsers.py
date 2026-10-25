"""Tests for Phase 2 service parser gap-fill.

Covers parse_ntp / parse_snmp / parse_syslog / parse_bfd implementations
added to IOS-XR, EOS, and NX-OS parsers.
"""

import pytest
from confgraph.parsers.iosxr_parser import IOSXRParser
from confgraph.parsers.eos_parser import EOSParser
from confgraph.parsers.nxos_parser import NXOSParser


# ---------------------------------------------------------------------------
# IOS-XR NTP
# ---------------------------------------------------------------------------

class TestIOSXRNTP:

    def _parse(self, config: str):
        return IOSXRParser(config).parse_ntp()

    def test_hierarchical_block_servers(self):
        cfg = """\
ntp
 server 10.0.0.1 prefer
 server 10.0.0.2
!
"""
        result = self._parse(cfg)
        assert result is not None
        assert len(result.servers) == 2
        addrs = [str(s.address) for s in result.servers]
        assert "10.0.0.1" in addrs
        assert "10.0.0.2" in addrs

    def test_prefer_flag_captured(self):
        cfg = """\
ntp
 server 10.0.0.1 prefer
!
"""
        result = self._parse(cfg)
        assert result is not None
        assert result.servers[0].prefer is True

    def test_source_interface(self):
        cfg = """\
ntp
 server 10.0.0.1
 source Loopback0
!
"""
        result = self._parse(cfg)
        assert result is not None
        assert result.source_interface == "Loopback0"

    def test_authenticate_flag(self):
        cfg = """\
ntp
 server 10.0.0.1
 authenticate
 authentication-key 1 md5 Secret
 trusted-key 1
!
"""
        result = self._parse(cfg)
        assert result is not None
        assert result.authenticate is True
        assert len(result.authentication_keys) == 1
        assert result.authentication_keys[0].key_id == 1
        assert 1 in result.trusted_keys

    def test_vrf_on_server(self):
        cfg = """\
ntp
 server vrf MGMT 192.168.1.1
!
"""
        result = self._parse(cfg)
        assert result is not None
        assert result.servers[0].vrf == "MGMT"

    def test_peer_parsed(self):
        cfg = """\
ntp
 peer 10.1.1.1
!
"""
        result = self._parse(cfg)
        assert result is not None
        assert len(result.peers) == 1
        assert str(result.peers[0].address) == "10.1.1.1"

    def test_no_ntp_returns_none(self):
        cfg = "hostname router\n"
        assert self._parse(cfg) is None

    def test_update_calendar(self):
        cfg = """\
ntp
 server 10.0.0.1
 update-calendar
!
"""
        result = self._parse(cfg)
        assert result is not None
        assert result.update_calendar is True

    def test_access_group_peer(self):
        cfg = """\
ntp
 server 10.0.0.1
 access-group peer ACL_NTP
!
"""
        result = self._parse(cfg)
        assert result is not None
        assert result.access_group_peer == "ACL_NTP"


# ---------------------------------------------------------------------------
# IOS-XR BFD
# ---------------------------------------------------------------------------

class TestIOSXRBFD:

    def _parse(self, config: str):
        return IOSXRParser(config).parse_bfd()

    def test_hierarchical_slow_timers(self):
        cfg = """\
bfd
 slow-timers 2000
 echo disable
!
"""
        result = self._parse(cfg)
        assert result is not None
        assert result.slow_timers == 2000

    def test_flat_slow_timers(self):
        cfg = "bfd slow-timers 1500\n"
        result = self._parse(cfg)
        assert result is not None
        assert result.slow_timers == 1500

    def test_no_bfd_returns_none(self):
        cfg = "hostname router\n"
        assert self._parse(cfg) is None

    def test_no_templates_in_result(self):
        cfg = """\
bfd
 slow-timers 2000
!
"""
        result = self._parse(cfg)
        assert result is not None
        assert result.templates == []
        assert result.maps == []

    def test_bfd_block_without_slow_timers(self):
        """A bfd block with only 'echo disable' still returns a BFDConfig."""
        cfg = """\
bfd
 echo disable
 multipath include location 0/0/CPU0
!
"""
        result = self._parse(cfg)
        assert result is not None
        assert result.slow_timers is None


# ---------------------------------------------------------------------------
# EOS BFD
# ---------------------------------------------------------------------------

class TestEOSBFD:

    def _parse(self, config: str):
        return EOSParser(config).parse_bfd()

    def test_slow_timer_singular(self):
        """EOS uses 'bfd slow-timer' (singular) not 'bfd slow-timers'."""
        cfg = "bfd slow-timer 2000\n"
        result = self._parse(cfg)
        assert result is not None
        assert result.slow_timers == 2000

    def test_no_bfd_returns_none(self):
        cfg = "hostname switch\n"
        assert self._parse(cfg) is None

    def test_eos_does_not_parse_ios_plural(self):
        """EOS parser must NOT match IOS-style 'bfd slow-timers' (plural)."""
        cfg = "bfd slow-timers 2000\n"
        # 'slow-timers' (plural) should not match EOS parser
        result = self._parse(cfg)
        assert result is None

    def test_no_templates_in_result(self):
        cfg = "bfd slow-timer 1000\n"
        result = self._parse(cfg)
        assert result is not None
        assert result.templates == []
        assert result.maps == []


# ---------------------------------------------------------------------------
# NX-OS NTP
# ---------------------------------------------------------------------------

class TestNXOSNTP:

    def _parse(self, config: str):
        return NXOSParser(config).parse_ntp()

    def test_server_with_use_vrf(self):
        cfg = "ntp server 10.0.0.1 prefer use-vrf management\n"
        result = self._parse(cfg)
        assert result is not None
        assert len(result.servers) == 1
        assert result.servers[0].vrf == "management"
        assert result.servers[0].prefer is True

    def test_server_without_vrf(self):
        cfg = "ntp server 10.0.0.2\n"
        result = self._parse(cfg)
        assert result is not None
        assert result.servers[0].vrf is None

    def test_source_interface_hyphenated(self):
        """NX-OS uses 'ntp source-interface' (hyphen), not 'ntp source'."""
        cfg = "ntp source-interface mgmt0\nntp server 10.0.0.1\n"
        result = self._parse(cfg)
        assert result is not None
        assert result.source_interface == "mgmt0"

    def test_authenticate_and_keys(self):
        cfg = (
            "ntp authenticate\n"
            "ntp authentication-key 1 md5 password 3 abc123\n"
            "ntp trusted-key 1\n"
            "ntp server 10.0.0.1\n"
        )
        result = self._parse(cfg)
        assert result is not None
        assert result.authenticate is True
        assert len(result.authentication_keys) == 1
        assert result.authentication_keys[0].key_id == 1
        assert 1 in result.trusted_keys

    def test_multiple_servers_different_vrfs(self):
        cfg = (
            "ntp server 10.0.0.1 use-vrf management\n"
            "ntp server 10.0.0.2 use-vrf default\n"
        )
        result = self._parse(cfg)
        assert result is not None
        assert len(result.servers) == 2
        vrfs = {s.vrf for s in result.servers}
        assert "management" in vrfs
        assert "default" in vrfs

    def test_no_ntp_returns_none(self):
        cfg = "hostname nxos-sw\n"
        assert self._parse(cfg) is None


# ---------------------------------------------------------------------------
# NX-OS Syslog
# ---------------------------------------------------------------------------

class TestNXOSSyslog:

    def _parse(self, config: str):
        return NXOSParser(config).parse_syslog()

    def test_logging_server_basic(self):
        cfg = "logging server 10.0.0.1\n"
        result = self._parse(cfg)
        assert result is not None
        assert len(result.hosts) == 1
        assert str(result.hosts[0].address) == "10.0.0.1"

    def test_logging_server_with_use_vrf(self):
        cfg = "logging server 10.0.0.1 5 use-vrf management\n"
        result = self._parse(cfg)
        assert result is not None
        assert result.hosts[0].vrf == "management"

    def test_logging_server_severity_captured(self):
        cfg = "logging server 10.0.0.1 5 use-vrf management\n"
        result = self._parse(cfg)
        assert result is not None
        assert result.hosts[0].level == "5"

    def test_logging_server_with_port(self):
        cfg = "logging server 10.0.0.2 use-vrf default port 1514\n"
        result = self._parse(cfg)
        assert result is not None
        assert result.hosts[0].port == 1514

    def test_source_interface(self):
        cfg = "logging source-interface mgmt0\nlogging server 10.0.0.1\n"
        result = self._parse(cfg)
        assert result is not None
        assert result.source_interface == "mgmt0"

    def test_multiple_servers(self):
        cfg = (
            "logging server 10.0.0.1 use-vrf management\n"
            "logging server 10.0.0.2 use-vrf management\n"
        )
        result = self._parse(cfg)
        assert result is not None
        assert len(result.hosts) == 2

    def test_console_level(self):
        cfg = "logging console 6\nlogging server 10.0.0.1\n"
        result = self._parse(cfg)
        assert result is not None
        assert result.console_level == "6"

    def test_no_logging_returns_none(self):
        cfg = "hostname nxos-sw\n"
        assert self._parse(cfg) is None

    def test_ios_logging_host_not_parsed_as_server(self):
        """NX-OS parser should not treat 'logging host' as 'logging server'."""
        # NX-OS doesn't use 'logging host'; this config would have no hosts
        # since the NX-OS parser looks for 'logging server' specifically.
        cfg = "logging host 10.0.0.1\n"
        result = self._parse(cfg)
        # 'logging host' is not a valid NX-OS command — no hosts captured
        assert result is not None  # logging block found but no 'server' entries
        assert result.hosts == []


# ---------------------------------------------------------------------------
# IOS-XR: inherited SNMP and Syslog from IOS
# ---------------------------------------------------------------------------

class TestIOSXRInheritedParsers:
    """Verify that SNMP and syslog are inherited correctly from IOSParser."""

    def test_snmp_community_parsed(self):
        cfg = (
            "snmp-server community public ro\n"
            "snmp-server community private rw\n"
        )
        result = IOSXRParser(cfg).parse_snmp()
        assert result is not None
        assert len(result.communities) == 2
        names = {c.community_string for c in result.communities}
        assert "public" in names
        assert "private" in names

    def test_snmp_host_parsed(self):
        cfg = (
            "snmp-server community public ro\n"
            "snmp-server host 10.0.0.1 traps version 2c public\n"
        )
        result = IOSXRParser(cfg).parse_snmp()
        assert result is not None
        assert len(result.hosts) == 1
        assert str(result.hosts[0].address) == "10.0.0.1"

    def test_syslog_host_parsed(self):
        cfg = "logging 10.0.0.1\nlogging trap informational\n"
        result = IOSXRParser(cfg).parse_syslog()
        assert result is not None
        assert len(result.hosts) == 1
        assert result.trap_level == "informational"


# ---------------------------------------------------------------------------
# EOS: inherited NTP, SNMP, Syslog from IOS
# ---------------------------------------------------------------------------

class TestEOSInheritedParsers:
    """Verify that NTP, SNMP, and syslog are inherited correctly from IOSParser."""

    def test_ntp_server_parsed(self):
        cfg = "ntp server 10.0.0.1 prefer\nntp server 10.0.0.2\n"
        result = EOSParser(cfg).parse_ntp()
        assert result is not None
        assert len(result.servers) == 2

    def test_snmp_community_parsed(self):
        cfg = "snmp-server community public ro\n"
        result = EOSParser(cfg).parse_snmp()
        assert result is not None
        assert result.communities[0].access == "ro"

    def test_syslog_host_parsed(self):
        cfg = "logging host 10.0.0.1\nlogging buffered 32000 informational\n"
        result = EOSParser(cfg).parse_syslog()
        assert result is not None
        assert len(result.hosts) == 1
        assert result.buffered_level == "informational"
