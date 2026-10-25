"""Tests for per-interface BFD parsing.

Covers IOSParser (IOS / EOS / NX-OS style: ``bfd interval N min_rx N multiplier N``)
and IOSXRParser (``bfd minimum-interval N`` + ``bfd multiplier N`` on separate lines).
"""

import pytest
from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.iosxr_parser import IOSXRParser


# ---------------------------------------------------------------------------
# IOS / EOS / NX-OS style
# ---------------------------------------------------------------------------

class TestIOSIfaceBFD:

    def _ifaces(self, config: str):
        return {i.name: i for i in IOSParser(config).parse_interfaces()}

    def test_bfd_interval_parsed(self):
        cfg = (
            "interface GigabitEthernet0/1\n"
            " bfd interval 300 min_rx 300 multiplier 3\n"
        )
        iface = self._ifaces(cfg)["GigabitEthernet0/1"]
        assert iface.bfd_interval == 300
        assert iface.bfd_min_rx == 300
        assert iface.bfd_multiplier == 3

    def test_bfd_asymmetric_intervals(self):
        cfg = (
            "interface GigabitEthernet0/2\n"
            " bfd interval 200 min_rx 500 multiplier 5\n"
        )
        iface = self._ifaces(cfg)["GigabitEthernet0/2"]
        assert iface.bfd_interval == 200
        assert iface.bfd_min_rx == 500
        assert iface.bfd_multiplier == 5

    def test_bfd_template_parsed(self):
        cfg = (
            "interface GigabitEthernet0/3\n"
            " bfd template FAST-BFD\n"
        )
        iface = self._ifaces(cfg)["GigabitEthernet0/3"]
        assert iface.bfd_template == "FAST-BFD"
        assert iface.bfd_interval is None

    def test_bfd_interval_and_template(self):
        cfg = (
            "interface GigabitEthernet0/4\n"
            " bfd interval 150 min_rx 150 multiplier 3\n"
            " bfd template MY-TMPL\n"
        )
        iface = self._ifaces(cfg)["GigabitEthernet0/4"]
        assert iface.bfd_interval == 150
        assert iface.bfd_template == "MY-TMPL"

    def test_no_bfd_fields_are_none(self):
        cfg = "interface GigabitEthernet0/5\n ip address 10.0.0.1 255.255.255.0\n"
        iface = self._ifaces(cfg)["GigabitEthernet0/5"]
        assert iface.bfd_interval is None
        assert iface.bfd_min_rx is None
        assert iface.bfd_multiplier is None
        assert iface.bfd_template is None

    def test_multiple_interfaces_only_uplink_has_bfd(self):
        cfg = (
            "interface GigabitEthernet0/0\n"
            " ip address 192.168.1.1 255.255.255.0\n"
            "interface GigabitEthernet0/1\n"
            " ip address 10.0.0.1 255.255.255.0\n"
            " bfd interval 300 min_rx 300 multiplier 3\n"
        )
        ifaces = self._ifaces(cfg)
        assert ifaces["GigabitEthernet0/0"].bfd_interval is None
        assert ifaces["GigabitEthernet0/1"].bfd_interval == 300

    def test_pim_bfd_does_not_set_bfd_interval(self):
        """ip pim bfd is for PIM-BFD, not general BFD — must not set bfd_interval."""
        cfg = (
            "interface GigabitEthernet0/6\n"
            " ip pim bfd\n"
        )
        iface = self._ifaces(cfg)["GigabitEthernet0/6"]
        assert iface.pim_bfd is True
        assert iface.bfd_interval is None


# ---------------------------------------------------------------------------
# IOS-XR style
# ---------------------------------------------------------------------------

class TestIOSXRIfaceBFD:

    def _ifaces(self, config: str):
        return {i.name: i for i in IOSXRParser(config).parse_interfaces()}

    def test_minimum_interval_and_multiplier(self):
        cfg = (
            "interface GigabitEthernet0/0/0/1\n"
            " bfd fast-detect\n"
            " bfd minimum-interval 300\n"
            " bfd multiplier 3\n"
        )
        iface = self._ifaces(cfg)["GigabitEthernet0/0/0/1"]
        assert iface.bfd_interval == 300
        assert iface.bfd_min_rx == 300   # XR minimum-interval applies to both tx and rx
        assert iface.bfd_multiplier == 3

    def test_fast_detect_without_interval(self):
        """bfd fast-detect alone (uses defaults) — interval stays None."""
        cfg = (
            "interface GigabitEthernet0/0/0/2\n"
            " bfd fast-detect\n"
        )
        iface = self._ifaces(cfg)["GigabitEthernet0/0/0/2"]
        assert iface.bfd_interval is None
        assert iface.bfd_multiplier is None

    def test_no_bfd_fields_are_none(self):
        cfg = "interface GigabitEthernet0/0/0/3\n description uplink\n"
        iface = self._ifaces(cfg)["GigabitEthernet0/0/0/3"]
        assert iface.bfd_interval is None
        assert iface.bfd_multiplier is None
        assert iface.bfd_template is None

    def test_xr_does_not_parse_ios_interval_syntax(self):
        """IOS-style 'bfd interval' line should not be parsed by XR parser."""
        cfg = (
            "interface GigabitEthernet0/0/0/4\n"
            " bfd interval 300 min_rx 300 multiplier 3\n"
        )
        iface = self._ifaces(cfg)["GigabitEthernet0/0/0/4"]
        # XR parser looks for 'bfd minimum-interval', not 'bfd interval'
        assert iface.bfd_interval is None
