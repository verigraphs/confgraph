"""CCR-0076 — NX-OS `spanning-tree port type edge` must map to stp_portfast.

NX-OS renamed IOS's `spanning-tree portfast` to `spanning-tree port type edge`.
The portfast mapping lived only in IOSParser (IOS spelling), so on NX-OS an
explicitly-configured edge port read back as stp_portfast=None ("unknown"),
indistinguishable from an unconfigured port.

Fixture lines are device-EMITTED forms:
  - `spanning-tree port type edge`        — verified-capture, syntax-corpus/nxos/spanning-tree.yaml
  - IOS `spanning-tree portfast`          — already exercised by committed IOS fixtures
"""

from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.nxos_parser import NXOSParser


def _nxos_intf(stp_line: str):
    cfg = (
        "feature lacp\n"
        "interface port-channel198\n"
        f"  {stp_line}\n"
        "  spanning-tree bpduguard enable\n"
    )
    p = NXOSParser(cfg).parse()
    return next(i for i in p.interfaces if i.name == "port-channel198")


def _ios_intf(stp_line: str):
    cfg = f"interface GigabitEthernet0/1\n  {stp_line}\n"
    p = IOSParser(cfg).parse()
    return next(i for i in p.interfaces if i.name == "GigabitEthernet0/1")


class TestNXOSPortTypeEdge:
    def test_port_type_edge_maps_to_portfast_true(self):
        intf = _nxos_intf("spanning-tree port type edge")
        assert intf.stp_portfast is True

    def test_port_type_edge_does_not_regress_bpduguard(self):
        # Both fields must be read from the same interface block.
        intf = _nxos_intf("spanning-tree port type edge")
        assert intf.stp_portfast is True
        assert intf.stp_bpduguard is True

    def test_no_port_type_line_leaves_portfast_none(self):
        # Sentinel None ("inherit") must survive when the port sets neither form.
        p = NXOSParser(
            "feature lacp\ninterface port-channel198\n  no shutdown\n"
        ).parse()
        intf = next(i for i in p.interfaces if i.name == "port-channel198")
        assert intf.stp_portfast is None


class TestIOSPortfastRegression:
    def test_ios_portfast_still_true(self):
        assert _ios_intf("spanning-tree portfast").stp_portfast is True

    def test_ios_no_portfast_still_false(self):
        assert _ios_intf("no spanning-tree portfast").stp_portfast is False
