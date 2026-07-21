"""VALIDATOR (CCR-0067) — sibling / base-class non-regression.

The fix lands the AF-transparent view in the shared IOS-family `parse_eigrp`
(guarded by `_nested_block`, which is the IDENTITY on IOSParser/EOSParser and
the AF splice only on NX-OS/IOS-XR). These tests prove the base IOSParser is
unaffected: classic numeric EIGRP and IOS named-mode EIGRP (autonomous-system
on the AF HEADER line, not a nested child) both behave as before.

IOS emitted forms taken from the committed reference tests
(tests/test_ios_minor_findings.py): `router eigrp <name>` /
` address-family ipv4 unicast autonomous-system <n>`. Own identifiers.
"""
from __future__ import annotations

from confgraph.parsers.ios_parser import IOSParser


IOS_CLASSIC = "router eigrp 63100\n network 10.7.7.0 0.0.0.255\n!\n"


def test_ios_classic_numeric_unchanged():
    insts = IOSParser(IOS_CLASSIC).parse().eigrp_instances
    assert len(insts) == 1
    e = insts[0]
    assert e.as_number == 63100
    assert e.name is None            # numeric mode gains no spurious name


# IOS named-mode: autonomous-system is ON the AF header line (IOS dialect), not
# a nested child (NX-OS dialect). The first regex branch must still resolve it.
IOS_NAMED = (
    "router eigrp EDGENET\n"
    " address-family ipv4 unicast autonomous-system 63200\n"
    "  network 10.8.8.0 0.0.0.255\n"
    " !\n"
    "!\n"
)


def test_ios_named_mode_af_header_asn_unchanged():
    insts = IOSParser(IOS_NAMED).parse().eigrp_instances
    assert len(insts) == 1
    e = insts[0]
    assert e.as_number == 63200      # resolved from the AF-header autonomous-system
    assert e.name == "EDGENET"       # tag preserved as the name


# IOS named-mode with NO address-family at all: the ASN cannot be resolved, so
# as_number falls back to the name string (established legacy behavior). Guards
# that the new `_nested_block` identity call did not change this.
IOS_NAMED_NO_AF = "router eigrp EDGENET\n!\n"


def test_ios_named_mode_no_af_falls_back_to_name_string():
    insts = IOSParser(IOS_NAMED_NO_AF).parse().eigrp_instances
    assert len(insts) == 1
    e = insts[0]
    assert e.as_number == "EDGENET"
    assert e.name == "EDGENET"
