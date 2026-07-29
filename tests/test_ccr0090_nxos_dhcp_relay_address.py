"""CCR-0090 — NX-OS interface DHCP relay helper addresses were dropped.

NX-OS emits per-interface DHCP relay targets as the repeatable child line
`ip dhcp relay address <ip>` under a `interface <svi>` block. The parser
previously modelled only the *global* DHCP toggles (snooping, relay information
option), so `InterfaceConfig` carried no field for the relay targets and the
addresses a DHCP request is forwarded to were silently lost.

The fix adds `InterfaceConfig.dhcp_relay_addresses: list[IPv4Address]` and reads
each `ip dhcp relay address` line, in config order, in the NX-OS
`parse_interfaces` override.

Values assert exactly (handbook §7.5 — no presence-only checks), from the
device-emitted shape recorded in
`syntax-corpus/nxos/dhcp.yaml::dhcp-relay-address` (verified-capture,
n9kv 10.5(5), emitted_form == typed_form).
"""
from ipaddress import IPv4Address

from confgraph.parsers.nxos_parser import NXOSParser


def _svi(interfaces, name):
    return next(i for i in interfaces if i.name == name)


# Device-emitted shape (n9kv 10.5(5)): two repeatable relay targets on an SVI.
NXOS_RELAY = """interface Vlan210
  ip dhcp relay address 10.199.99.1
  ip dhcp relay address 10.199.99.2
"""


def test_interface_dhcp_relay_addresses_populated_in_order():
    interfaces = NXOSParser(NXOS_RELAY).parse_interfaces()
    svi = _svi(interfaces, "Vlan210")
    # the CCR-0090 gap: both relay targets were dropped (empty list) before fix
    assert svi.dhcp_relay_addresses == [
        IPv4Address("10.199.99.1"),
        IPv4Address("10.199.99.2"),
    ]


def test_single_relay_address():
    cfg = "interface Vlan310\n  ip dhcp relay address 10.50.0.10\n"
    svi = _svi(NXOSParser(cfg).parse_interfaces(), "Vlan310")
    assert svi.dhcp_relay_addresses == [IPv4Address("10.50.0.10")]


def test_interface_without_relay_has_empty_list():
    cfg = "interface Vlan400\n  ip address 10.0.0.1/24\n"
    svi = _svi(NXOSParser(cfg).parse_interfaces(), "Vlan400")
    assert svi.dhcp_relay_addresses == []
