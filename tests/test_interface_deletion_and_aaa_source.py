"""Tests for interface deletion tombstones (CCR1 parser side) and
AAA source-interface parsing (CCR-AAA).

CCR1: ``no interface Loopback0`` must produce a tombstone ``interface:Loopback0``.
CCR-AAA: ``ip tacacs source-interface`` and ``ip radius source-interface``
         must populate AAAConfig.tacacs_source_interface / radius_source_interface.

Run:
    uv run pytest tests/test_interface_deletion_and_aaa_source.py -v
"""

from __future__ import annotations

import pytest

from confgraph.parsers.ios_parser import IOSParser
from tests._ccr0110_e_helpers import reconstruct_tombstones


def _parse(config_text: str):
    # CCR-0110 Phase E: op-primary parsers no longer populate no_commands —
    # repopulate it from the composed ChangeSet via the golden-pinned shim codec
    # (byte-exact vs ``test_change_ir_shim_phase4``) so these deletion-tombstone
    # assertions still exercise the exact legacy vocabulary.
    return reconstruct_tombstones(IOSParser(config_text).parse())


# ---------------------------------------------------------------------------
# CCR1 — Interface deletion tombstone
# ---------------------------------------------------------------------------


class TestInterfaceDeletionTombstone:
    """Parser must emit ``interface:<name>`` tombstone for ``no interface``."""

    def test_no_interface_loopback(self):
        pc = _parse("no interface Loopback0\n")
        assert "interface:Loopback0" in pc.no_commands

    def test_no_interface_svi(self):
        pc = _parse("no interface Vlan100\n")
        assert "interface:Vlan100" in pc.no_commands

    def test_no_interface_physical(self):
        pc = _parse("no interface GigabitEthernet0/0/1\n")
        assert "interface:GigabitEthernet0/0/1" in pc.no_commands

    def test_no_interface_preserves_other_tombstones(self):
        """Interface tombstone coexists with other tombstones."""
        pc = _parse("no interface Loopback0\nno vlan 100\n")
        assert "interface:Loopback0" in pc.no_commands
        assert "vlan:100" in pc.no_commands

    def test_positive_interface_no_tombstone(self):
        """Positive interface config does not produce interface tombstone."""
        pc = _parse("interface Loopback0\n ip address 10.0.0.1 255.255.255.255\n")
        iface_tombstones = [t for t in pc.no_commands if t.startswith("interface:")]
        assert iface_tombstones == []

    def test_no_interface_multiple(self):
        pc = _parse("no interface Loopback0\nno interface Loopback1\n")
        assert "interface:Loopback0" in pc.no_commands
        assert "interface:Loopback1" in pc.no_commands

    def test_abbreviated_name_normalized(self):
        """Abbreviated names like Lo0, Gi0/0 are expanded to canonical form."""
        pc = _parse("no interface Lo0\n")
        assert "interface:Loopback0" in pc.no_commands

    def test_abbreviated_gi_normalized(self):
        pc = _parse("no interface Gi0/0\n")
        assert "interface:GigabitEthernet0/0" in pc.no_commands


# ---------------------------------------------------------------------------
# CCR-AAA — Source-interface parsing
# ---------------------------------------------------------------------------


class TestAAASourceInterface:
    """Parser must extract ip tacacs/radius source-interface into AAAConfig."""

    def test_tacacs_source_interface(self):
        pc = _parse(
            "aaa new-model\n"
            "ip tacacs source-interface Loopback0\n"
        )
        assert pc.aaa is not None
        assert pc.aaa.tacacs_source_interface == "Loopback0"

    def test_radius_source_interface(self):
        pc = _parse(
            "aaa new-model\n"
            "ip radius source-interface Loopback0\n"
        )
        assert pc.aaa is not None
        assert pc.aaa.radius_source_interface == "Loopback0"

    def test_both_source_interfaces(self):
        pc = _parse(
            "aaa new-model\n"
            "ip tacacs source-interface Loopback0\n"
            "ip radius source-interface Loopback1\n"
        )
        assert pc.aaa is not None
        assert pc.aaa.tacacs_source_interface == "Loopback0"
        assert pc.aaa.radius_source_interface == "Loopback1"

    def test_source_interface_without_aaa_new_model(self):
        """Source-interface lines alone should still create an AAAConfig."""
        pc = _parse("ip tacacs source-interface Loopback0\n")
        assert pc.aaa is not None
        assert pc.aaa.tacacs_source_interface == "Loopback0"
        assert pc.aaa.new_model is False

    def test_no_source_interface_fields_default_none(self):
        """AAAConfig without source-interface lines has None fields."""
        pc = _parse("aaa new-model\n")
        assert pc.aaa is not None
        assert pc.aaa.tacacs_source_interface is None
        assert pc.aaa.radius_source_interface is None

    def test_tacacs_source_interface_abbreviated_is_normalized(self):
        """CCR-0002: captured token is normalized to the canonical interface
        name so it cross-references the interface table (Lo0 -> Loopback0)."""
        pc = _parse(
            "aaa new-model\n"
            "ip tacacs source-interface Lo0\n"
        )
        assert pc.aaa is not None
        assert pc.aaa.tacacs_source_interface == "Loopback0"

    def test_radius_source_interface_abbreviated_is_normalized(self):
        """CCR-0002: RADIUS analogue (Gi0/0 -> GigabitEthernet0/0)."""
        pc = _parse(
            "aaa new-model\n"
            "ip radius source-interface Gi0/0\n"
        )
        assert pc.aaa is not None
        assert pc.aaa.radius_source_interface == "GigabitEthernet0/0"
