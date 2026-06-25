"""Tests for `no mpls ip` interface-level deletion tombstone.

CCR: confgraph_ios_interface_no_mpls_ip_deletion.md
"""

from confgraph.parsers.ios_parser import IOSParser


def _parse(config: str):
    return IOSParser(config).parse()


def _get_interface(pc, name: str):
    for i in pc.interfaces:
        if i.name == name:
            return i
    raise AssertionError(f"interface {name} not found")


class TestNoMplsIpTombstone:
    """``no mpls ip`` emits a field-reset tombstone on the interface."""

    def test_mpls_ip_positive(self):
        """Baseline: ``mpls ip`` sets mpls_ip=True."""
        pc = _parse(
            "interface GigabitEthernet1\n"
            " ip address 10.0.0.1 255.255.255.252\n"
            " mpls ip\n"
        )
        intf = _get_interface(pc, "GigabitEthernet1")
        assert intf.mpls_ip is True

    def test_no_mpls_ip_tombstone(self):
        """``no mpls ip`` emits field:interface:GigabitEthernet1:mpls_ip tombstone."""
        pc = _parse(
            "interface GigabitEthernet1\n"
            " no mpls ip\n"
        )
        intf = _get_interface(pc, "GigabitEthernet1")
        assert "field:interface:GigabitEthernet1:mpls_ip" in intf.no_commands

    def test_no_mpls_ip_field_false(self):
        """``no mpls ip`` leaves mpls_ip=False (no positive match)."""
        pc = _parse(
            "interface GigabitEthernet1\n"
            " ip address 10.0.0.1 255.255.255.252\n"
            " no mpls ip\n"
        )
        intf = _get_interface(pc, "GigabitEthernet1")
        assert intf.mpls_ip is False

    def test_no_tombstone_when_mpls_ip_present(self):
        """When ``mpls ip`` is set (no negation), no tombstone emitted."""
        pc = _parse(
            "interface GigabitEthernet1\n"
            " ip address 10.0.0.1 255.255.255.252\n"
            " mpls ip\n"
        )
        intf = _get_interface(pc, "GigabitEthernet1")
        mpls_tombstones = [t for t in intf.no_commands if "mpls_ip" in t]
        assert mpls_tombstones == []

    def test_other_interfaces_unaffected(self):
        """Only the interface with ``no mpls ip`` gets the tombstone."""
        pc = _parse(
            "interface GigabitEthernet1\n"
            " ip address 10.0.0.1 255.255.255.252\n"
            " mpls ip\n"
            "interface GigabitEthernet2\n"
            " ip address 10.0.0.5 255.255.255.252\n"
            " no mpls ip\n"
        )
        gi1 = _get_interface(pc, "GigabitEthernet1")
        gi2 = _get_interface(pc, "GigabitEthernet2")
        assert gi1.mpls_ip is True
        assert "field:interface:GigabitEthernet1:mpls_ip" not in gi1.no_commands
        assert "field:interface:GigabitEthernet2:mpls_ip" in gi2.no_commands
