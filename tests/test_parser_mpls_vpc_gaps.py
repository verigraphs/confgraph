"""Tests for MPLS/LDP and VPC/MLAG parser gap-fill.

Covers:
- IOS-XR hierarchical ``mpls ldp`` block parsing
- EOS hierarchical ``mpls ldp`` block parsing (router-id interface syntax)
- NX-OS ``mpls ldp configuration`` block parsing
- EOS ``mlag configuration`` → VPCConfig

Run:
    uv run pytest tests/test_parser_mpls_vpc_gaps.py -v
"""

import pytest
from confgraph.parsers.iosxr_parser import IOSXRParser
from confgraph.parsers.eos_parser import EOSParser
from confgraph.parsers.nxos_parser import NXOSParser


# ---------------------------------------------------------------------------
# IOS-XR MPLS/LDP — hierarchical block
# ---------------------------------------------------------------------------


class TestIOSXRMPLS:

    def _parse(self, config: str):
        return IOSXRParser(config).parse_mpls()

    def test_basic_ldp_block(self):
        cfg = """\
mpls ldp
 router-id 10.0.0.1
 graceful-restart
!
"""
        result = self._parse(cfg)
        assert result is not None
        assert result.ldp_router_id == "10.0.0.1"
        assert result.ldp_graceful_restart is True
        assert result.ldp_enabled is True

    def test_router_id_force(self):
        cfg = """\
mpls ldp
 router-id 10.0.0.1 force
!
"""
        result = self._parse(cfg)
        assert result is not None
        assert result.ldp_router_id == "10.0.0.1"
        assert result.ldp_router_id_force is True

    def test_session_protection(self):
        cfg = """\
mpls ldp
 router-id 10.0.0.1
 session protection
!
"""
        result = self._parse(cfg)
        assert result is not None
        assert result.ldp_session_protection is True

    def test_password(self):
        cfg = """\
mpls ldp
 router-id 10.0.0.1
 password required for PEERS
!
"""
        result = self._parse(cfg)
        assert result is not None
        assert result.ldp_password is not None
        assert "required" in result.ldp_password

    def test_no_mpls_ldp_returns_none(self):
        cfg = """\
hostname router1
!
"""
        result = self._parse(cfg)
        assert result is None

    def test_no_router_id_ldp_not_enabled(self):
        cfg = """\
mpls ldp
 graceful-restart
!
"""
        result = self._parse(cfg)
        assert result is not None
        assert result.ldp_router_id is None
        assert result.ldp_enabled is False
        assert result.ldp_graceful_restart is True

    def test_full_config(self):
        cfg = """\
mpls ldp
 router-id 10.0.0.1
 graceful-restart
 session protection
 address-family ipv4
 !
 interface GigabitEthernet0/0/0/0
 !
 interface GigabitEthernet0/0/0/1
 !
!
"""
        result = self._parse(cfg)
        assert result is not None
        assert result.ldp_router_id == "10.0.0.1"
        assert result.ldp_graceful_restart is True
        assert result.ldp_session_protection is True
        assert result.source_os == "ios_xr"


# ---------------------------------------------------------------------------
# EOS MPLS/LDP — hierarchical block with "router-id interface" syntax
# ---------------------------------------------------------------------------


class TestEOSMPLS:

    def _parse(self, config: str):
        return EOSParser(config).parse_mpls()

    def test_router_id_interface_syntax(self):
        """EOS: ``router-id interface Loopback0`` extracts the interface name."""
        cfg = """\
mpls ldp
   router-id interface Loopback0
   no shutdown
!
"""
        result = self._parse(cfg)
        assert result is not None
        assert result.ldp_router_id == "Loopback0"
        assert result.ldp_enabled is True
        assert result.source_os == "eos"

    def test_router_id_ip_syntax(self):
        """EOS also supports ``router-id <IP>`` without 'interface' keyword."""
        cfg = """\
mpls ldp
   router-id 10.0.0.1
!
"""
        result = self._parse(cfg)
        assert result is not None
        assert result.ldp_router_id == "10.0.0.1"

    def test_graceful_restart(self):
        cfg = """\
mpls ldp
   router-id interface Loopback0
   graceful-restart
!
"""
        result = self._parse(cfg)
        assert result is not None
        assert result.ldp_graceful_restart is True

    def test_session_protection(self):
        cfg = """\
mpls ldp
   router-id interface Loopback0
   session protection
!
"""
        result = self._parse(cfg)
        assert result is not None
        assert result.ldp_session_protection is True

    def test_no_mpls_returns_none(self):
        cfg = """\
hostname switch1
!
"""
        result = self._parse(cfg)
        assert result is None

    def test_transport_address_ignored(self):
        """Non-LDP sub-commands are silently ignored."""
        cfg = """\
mpls ldp
   router-id interface Loopback0
   transport-address interface Loopback0
!
"""
        result = self._parse(cfg)
        assert result is not None
        assert result.ldp_router_id == "Loopback0"


# ---------------------------------------------------------------------------
# NX-OS MPLS/LDP — "mpls ldp configuration" block
# ---------------------------------------------------------------------------


class TestNXOSMPLS:

    def _parse(self, config: str):
        return NXOSParser(config).parse_mpls()

    def test_nxos_ldp_configuration_block(self):
        cfg = """\
feature mpls ldp
mpls ldp configuration
  router-id Loopback0
  graceful-restart
"""
        result = self._parse(cfg)
        assert result is not None
        assert result.ldp_router_id == "Loopback0"
        assert result.ldp_graceful_restart is True
        assert result.ldp_enabled is True
        assert result.source_os == "nxos"

    def test_session_protection(self):
        cfg = """\
mpls ldp configuration
  router-id Loopback0
  session protection
"""
        result = self._parse(cfg)
        assert result is not None
        assert result.ldp_session_protection is True

    def test_no_mpls_returns_none(self):
        cfg = """\
hostname switch1
!
"""
        result = self._parse(cfg)
        assert result is None

    def test_no_router_id_ldp_not_enabled(self):
        cfg = """\
mpls ldp configuration
  graceful-restart
"""
        result = self._parse(cfg)
        assert result is not None
        assert result.ldp_router_id is None
        assert result.ldp_enabled is False


# ---------------------------------------------------------------------------
# EOS MLAG → VPCConfig
# ---------------------------------------------------------------------------


class TestEOSMLAG:

    def _parse(self, config: str):
        return EOSParser(config).parse_vpc()

    def test_basic_mlag(self):
        cfg = """\
mlag configuration
   domain-id MLAG_DOMAIN
   local-interface Vlan4094
   peer-address 10.0.0.2
   peer-link Port-Channel1
!
"""
        result = self._parse(cfg)
        assert result is not None
        assert result.domain_id == "MLAG_DOMAIN"
        assert result.peer_link == "Port-Channel1"
        assert str(result.peer_keepalive_destination) == "10.0.0.2"
        assert result.source_os == "eos"

    def test_reload_delay(self):
        cfg = """\
mlag configuration
   domain-id MLAG1
   peer-link Port-Channel1
   reload-delay mlag 300
!
"""
        result = self._parse(cfg)
        assert result is not None
        assert result.delay_restore == 300

    def test_no_mlag_returns_none(self):
        cfg = """\
hostname switch1
!
"""
        result = self._parse(cfg)
        assert result is None

    def test_no_domain_id_returns_none(self):
        """MLAG block without domain-id is invalid → None."""
        cfg = """\
mlag configuration
   peer-link Port-Channel1
!
"""
        result = self._parse(cfg)
        assert result is None

    def test_peer_address_only(self):
        cfg = """\
mlag configuration
   domain-id DC1
   peer-address 192.168.1.1
!
"""
        result = self._parse(cfg)
        assert result is not None
        assert result.domain_id == "DC1"
        assert str(result.peer_keepalive_destination) == "192.168.1.1"
        assert result.peer_link is None
