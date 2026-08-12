"""CCR-0192 — DHCP interface addressing must reach the model, not be discarded.

Before this change every parser recognized its DHCP addressing spelling and
then destroyed it: no ``InterfaceConfig`` field could hold it, so a
DHCP-addressed device was byte-for-byte indistinguishable from an unaddressed
one, and consumers asking "does this device have addressing?" got a
confidently wrong answer (the CCR-0190 coverage disclosure reported healthy
devices as unreadable).

Two properties pinned here, straight from the CCR's "exact change needed":

  1. A consumer asking "is this interface addressed?" gets YES for a DHCP
     interface WITHOUT knowing DHCP exists — via the ``is_addressed``
     property, the single point of truth.
  2. The next non-literal addressing form is a new VALUE of
     ``dynamic_address``, not a new field — constructing an instance with an
     unheard-of value ("slaac") must satisfy ``is_addressed`` with zero
     model/consumer edits (the parity test).
"""

from ipaddress import IPv4Interface

import pytest

from confgraph.models.base import OSType
from confgraph.models.interface import InterfaceConfig, InterfaceType
from confgraph.parsers.eos_parser import EOSParser
from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.iosxr_parser import IOSXRParser
from confgraph.parsers.junos_parser import JunOSParser
from confgraph.parsers.nxos_parser import NXOSParser
from confgraph.parsers.panos_parser import PANOSParser


# ---------------------------------------------------------------------------
# Fixtures — one DHCP-addressed interface and one statically addressed one,
# in each OS's device-emitted spelling.
# ---------------------------------------------------------------------------

IOS_CFG = (
    "interface Vlan99\n"
    " ip address dhcp\n"
    "!\n"
    "interface GigabitEthernet0/1\n"
    " ip address 10.0.0.1 255.255.255.0\n"
    "!\n"
)

# IOS also emits option-bearing forms; the detection must not anchor on EOL.
IOS_CFG_CLIENT_ID = (
    "interface Vlan99\n"
    " ip address dhcp client-id GigabitEthernet0/1\n"
    "!\n"
)

EOS_CFG = (
    "interface Management1\n"
    "   ip address dhcp\n"
    "!\n"
    "interface Ethernet1\n"
    "   no switchport\n"
    "   ip address 10.0.0.1/24\n"
    "!\n"
)

NXOS_CFG = (
    "interface mgmt0\n"
    "  ip address dhcp\n"
    "\n"
    "interface Ethernet1/1\n"
    "  no switchport\n"
    "  ip address 10.0.0.1/24\n"
    "\n"
)

IOSXR_CFG = (
    "interface MgmtEth0/RP0/CPU0/0\n"
    " ipv4 address dhcp\n"
    "!\n"
    "interface GigabitEthernet0/0/0/0\n"
    " ipv4 address 10.0.0.1 255.255.255.0\n"
    "!\n"
)

JUNOS_CFG = (
    "interfaces {\n"
    "    ge-0/0/0 {\n"
    "        unit 0 {\n"
    "            family inet {\n"
    "                dhcp;\n"
    "            }\n"
    "        }\n"
    "    }\n"
    "    ge-0/0/1 {\n"
    "        unit 0 {\n"
    "            family inet {\n"
    "                address 10.0.0.1/24;\n"
    "            }\n"
    "        }\n"
    "    }\n"
    "}\n"
)

PANOS_CFG = """\
<config version="10.1.0">
  <devices>
    <entry name="localhost.localdomain">
      <deviceconfig><system><hostname>pa-dhcp-1</hostname></system></deviceconfig>
      <network>
        <interface>
          <ethernet>
            <entry name="ethernet1/1">
              <layer3><dhcp-client><enable>yes</enable></dhcp-client></layer3>
            </entry>
            <entry name="ethernet1/2">
              <layer3><ip><entry name="10.0.0.1/24"/></ip></layer3>
            </entry>
          </ethernet>
        </interface>
      </network>
    </entry>
  </devices>
</config>
"""


def _iface(parsed, name):
    return next(i for i in parsed.interfaces if i.name == name)


# ---------------------------------------------------------------------------
# Per-OS positive: the DHCP spelling parses into dynamic_address == "dhcp",
# and the same parse's static interface stays dynamic_address None (negative).
# IOS covers IOS-XE (same parser class).  The EOS and NX-OS cases execute the
# subclasses' address-patching overrides over the SAME parse, proving those
# overrides do not clobber dynamic_address.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "parser_cls, cfg, dhcp_if, static_if",
    [
        (IOSParser, IOS_CFG, "Vlan99", "GigabitEthernet0/1"),
        (EOSParser, EOS_CFG, "Management1", "Ethernet1"),
        (NXOSParser, NXOS_CFG, "mgmt0", "Ethernet1/1"),
        (IOSXRParser, IOSXR_CFG, "MgmtEth0/RP0/CPU0/0", "GigabitEthernet0/0/0/0"),
        (JunOSParser, JUNOS_CFG, "ge-0/0/0.0", "ge-0/0/1.0"),
        (PANOSParser, PANOS_CFG, "ethernet1/1", "ethernet1/2"),
    ],
    ids=["ios", "eos", "nxos", "iosxr", "junos", "panos"],
)
def test_dhcp_addressing_parses_on_every_os(parser_cls, cfg, dhcp_if, static_if):
    parsed = parser_cls(cfg).parse()

    dhcp = _iface(parsed, dhcp_if)
    assert dhcp.dynamic_address == "dhcp"
    assert dhcp.ip_address is None
    assert dhcp.is_addressed is True

    static = _iface(parsed, static_if)
    assert static.dynamic_address is None
    assert static.ip_address == IPv4Interface("10.0.0.1/24")
    assert static.is_addressed is True


def test_ios_dhcp_with_client_id_option_still_parses():
    parsed = IOSParser(IOS_CFG_CLIENT_ID).parse()
    vlan = _iface(parsed, "Vlan99")
    assert vlan.dynamic_address == "dhcp"
    assert vlan.ip_address is None


def test_ios_unnumbered_stays_intact_next_to_dhcp_detection():
    """The unnumbered walk sits beside the new detection — both must survive."""
    cfg = (
        "interface Serial0/0\n"
        " ip unnumbered Loopback0\n"
        "!\n"
    )
    intf = _iface(IOSParser(cfg).parse(), "Serial0/0")
    assert intf.unnumbered_source == "Loopback0"
    assert intf.dynamic_address is None
    assert intf.is_addressed is True


# ---------------------------------------------------------------------------
# is_addressed truth table — the single point of truth, exercised per form.
# ---------------------------------------------------------------------------

def _mk(**kwargs) -> InterfaceConfig:
    return InterfaceConfig(
        object_id="interface_Test0",
        source_os=OSType.IOS,
        name="Test0",
        interface_type=InterfaceType.PHYSICAL,
        **kwargs,
    )


@pytest.mark.parametrize(
    "kwargs, expected",
    [
        ({"ip_address": "10.0.0.1/24"}, True),
        ({"dynamic_address": "dhcp"}, True),
        ({"unnumbered_source": "Loopback0"}, True),
        ({"ipv6_addresses": ["2001:db8::1/64"]}, True),
        ({"secondary_ips": ["10.0.1.1/24"]}, True),
        ({}, False),
    ],
    ids=["static", "dhcp", "unnumbered", "v6-only", "secondary-only", "nothing"],
)
def test_is_addressed_truth_table(kwargs, expected):
    assert _mk(**kwargs).is_addressed is expected


def test_is_addressed_is_not_a_serialized_field():
    """Plain property by design: absent from model_dump and the field set."""
    m = _mk(dynamic_address="dhcp")
    assert "is_addressed" not in m.model_dump()
    assert "is_addressed" not in type(m).model_fields
    # …but reachable structurally, which is how consumers find it.
    assert getattr(m, "is_addressed") is True


# ---------------------------------------------------------------------------
# PARITY — the next dynamic form is a new VALUE, not a new field.  An
# unheard-of value must satisfy is_addressed with zero model/consumer edits.
# ---------------------------------------------------------------------------

def test_next_dynamic_form_is_a_value_not_a_field():
    m = _mk(dynamic_address="slaac")
    assert m.is_addressed is True
