"""Tests for per-interface LLDP/CDP, IP-unnumbered parsing (Phase 4.2).

Covers: unnumbered_source, cdp_enabled, lldp_transmit, lldp_receive
across IOS, NX-OS (inherits), EOS (inherits), IOS-XR (inherits), JunOS.
"""

from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.nxos_parser import NXOSParser
from confgraph.parsers.iosxr_parser import IOSXRParser
from confgraph.parsers.junos_parser import JunOSParser


# ---------------------------------------------------------------------------
# IOS — IP unnumbered
# ---------------------------------------------------------------------------


class TestIOSIPUnnumbered:

    def test_ip_unnumbered(self):
        cfg = (
            "interface Loopback0\n"
            " ip address 10.0.0.1 255.255.255.255\n"
            "!\n"
            "interface Tunnel0\n"
            " ip unnumbered Loopback0\n"
            "!\n"
        )
        pc = IOSParser(cfg).parse()
        tun = next(i for i in pc.interfaces if i.name == "Tunnel0")
        assert tun.unnumbered_source == "Loopback0"

    def test_no_unnumbered_default(self):
        cfg = (
            "interface GigabitEthernet0/0\n"
            " ip address 10.0.0.1 255.255.255.0\n"
            "!\n"
        )
        pc = IOSParser(cfg).parse()
        intf = pc.interfaces[0]
        assert intf.unnumbered_source is None


# ---------------------------------------------------------------------------
# IOS — per-port CDP
# ---------------------------------------------------------------------------


class TestIOSCDP:

    def test_cdp_disabled(self):
        cfg = (
            "interface GigabitEthernet0/0\n"
            " no cdp enable\n"
            "!\n"
        )
        pc = IOSParser(cfg).parse()
        intf = pc.interfaces[0]
        assert intf.cdp_enabled is False

    def test_cdp_enabled_default(self):
        cfg = (
            "interface GigabitEthernet0/0\n"
            " ip address 10.0.0.1 255.255.255.0\n"
            "!\n"
        )
        pc = IOSParser(cfg).parse()
        intf = pc.interfaces[0]
        assert intf.cdp_enabled is True


# ---------------------------------------------------------------------------
# IOS — per-port LLDP
# ---------------------------------------------------------------------------


class TestIOSLLDP:

    def test_lldp_transmit_disabled(self):
        cfg = (
            "interface GigabitEthernet0/0\n"
            " no lldp transmit\n"
            "!\n"
        )
        pc = IOSParser(cfg).parse()
        intf = pc.interfaces[0]
        assert intf.lldp_transmit is False
        assert intf.lldp_receive is True  # only transmit disabled

    def test_lldp_receive_disabled(self):
        cfg = (
            "interface GigabitEthernet0/0\n"
            " no lldp receive\n"
            "!\n"
        )
        pc = IOSParser(cfg).parse()
        intf = pc.interfaces[0]
        assert intf.lldp_transmit is True
        assert intf.lldp_receive is False

    def test_lldp_both_disabled(self):
        cfg = (
            "interface GigabitEthernet0/0\n"
            " no lldp transmit\n"
            " no lldp receive\n"
            "!\n"
        )
        pc = IOSParser(cfg).parse()
        intf = pc.interfaces[0]
        assert intf.lldp_transmit is False
        assert intf.lldp_receive is False

    def test_lldp_defaults(self):
        cfg = (
            "interface GigabitEthernet0/0\n"
            " ip address 10.0.0.1 255.255.255.0\n"
            "!\n"
        )
        pc = IOSParser(cfg).parse()
        intf = pc.interfaces[0]
        assert intf.lldp_transmit is True
        assert intf.lldp_receive is True


# ---------------------------------------------------------------------------
# NX-OS — inherits from IOS
# ---------------------------------------------------------------------------


class TestNXOSInterfaceAdvanced:

    def test_inherits_cdp_lldp(self):
        cfg = (
            "interface Ethernet1/1\n"
            " no cdp enable\n"
            " no lldp transmit\n"
            "!\n"
        )
        pc = NXOSParser(cfg).parse()
        intf = next(i for i in pc.interfaces if "Ethernet1/1" in i.name)
        assert intf.cdp_enabled is False
        assert intf.lldp_transmit is False


# ---------------------------------------------------------------------------
# IOS-XR — inherits from IOS
# ---------------------------------------------------------------------------


class TestIOSXRInterfaceAdvanced:

    def test_ip_unnumbered(self):
        cfg = (
            "interface Loopback0\n"
            " ipv4 address 10.0.0.1 255.255.255.255\n"
            "!\n"
            "interface GigabitEthernet0/0/0/0\n"
            " ip unnumbered Loopback0\n"
            "!\n"
        )
        pc = IOSXRParser(cfg).parse()
        gi = next(i for i in pc.interfaces if "GigabitEthernet0/0/0/0" in i.name)
        assert gi.unnumbered_source == "Loopback0"


# ---------------------------------------------------------------------------
# JunOS — IP unnumbered
# ---------------------------------------------------------------------------


class TestJunOSInterfaceAdvanced:

    def test_unnumbered_address(self):
        cfg = (
            "interfaces {\n"
            "    ge-0/0/0 {\n"
            "        unit 0 {\n"
            "            family inet {\n"
            "                unnumbered-address lo0.0;\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        pc = JunOSParser(cfg).parse()
        intf = next(i for i in pc.interfaces if i.name == "ge-0/0/0.0")
        assert intf.unnumbered_source == "lo0.0"

    def test_no_unnumbered_default(self):
        cfg = (
            "interfaces {\n"
            "    ge-0/0/0 {\n"
            "        unit 0 {\n"
            "            family inet {\n"
            "                address 10.0.0.1/30;\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        pc = JunOSParser(cfg).parse()
        intf = next(i for i in pc.interfaces if i.name == "ge-0/0/0.0")
        assert intf.unnumbered_source is None
