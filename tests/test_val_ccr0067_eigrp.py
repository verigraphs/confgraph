"""VALIDATOR (CCR-0067) — NX-OS EIGRP tag-vs-ASN + address-family descent.

Own identifiers only (SPINE7 / 64920 / RM_SP_V4, numeric 63055 / RM_NUM_V4,
DUALSTK / 64810 / 64811, DARKV6 / 64950) — none shared with the fixer
(CORE / 100 / RM_EIGRP).

Emitted forms grounded in syntax-corpus/nxos/eigrp.yaml (verified-capture,
Nexus 9000v 10.5(5)) for the IPv4 AF: `router eigrp <NAME>` with
`autonomous-system <n>` and `redistribute <proto> route-map <RM>` nested under
`address-family ipv4 unicast` (device MOVES autonomous-system inside the AF on
readback).

The IPv6 AF forms below are DOC-ONLY (Cisco Nexus 9000 NX-OS Unicast Routing
Config Guide 10.5(x), EIGRP chapter, content_sha 2662e160…, re-verified by the
validator via fetch.py): "You must configure EIGRP for IPv6 in address family
mode"; "For IPv6, this number [autonomous-system] must be configured under the
address family". No device capture of an EIGRP IPv6 readback exists, so the
exact emitted bytes/indentation are an expectation. These tests assert
WITHHOLDING (the parser must NOT splice the ipv6 AF), which is robust to
indentation: the ipv4-unicast splice regex cannot match an ipv6 header. The
withholding mechanism itself is capture-verified via the IS-IS ipv6 case.
"""
from __future__ import annotations

from confgraph.parsers.nxos_parser import NXOSParser


def _eigrp(text: str):
    insts = NXOSParser(text).parse().eigrp_instances
    assert len(insts) == 1, f"expected exactly one EIGRP instance, got {len(insts)}"
    return insts[0]


NAMED_AF = """feature eigrp
route-map RM_SP_V4 permit 10
router eigrp SPINE7
  address-family ipv4 unicast
    autonomous-system 64920
    redistribute static route-map RM_SP_V4
"""


def test_named_eigrp_asn_from_af_not_the_name():
    # RED pre-fix: as_number == 'SPINE7' (the NAME mis-stored), redistribute == [].
    # GREEN post-fix: the AF-nested autonomous-system is the ASN.
    e = _eigrp(NAMED_AF)
    assert e.as_number == 64920                # NOT the string 'SPINE7'
    assert len(e.redistribute) == 1
    assert e.redistribute[0].protocol == "static"
    assert e.redistribute[0].route_map == "RM_SP_V4"
    assert e.name == "SPINE7"                  # tag lands in the new name field


NUMERIC_AF = """feature eigrp
route-map RM_NUM_V4 permit 10
router eigrp 63055
  address-family ipv4 unicast
    redistribute direct route-map RM_NUM_V4
"""


def test_numeric_eigrp_name_none_and_af_redistribute_read():
    # Numeric tag: ASN is the tag itself, name stays None (no spurious name on
    # the common case). RED pre-fix on redistribute (AF child dropped).
    e = _eigrp(NUMERIC_AF)
    assert e.as_number == 63055
    assert e.name is None
    assert len(e.redistribute) == 1
    assert e.redistribute[0].protocol == "direct"
    assert e.redistribute[0].route_map == "RM_NUM_V4"


# DUAL-STACK, DIFFERENT ASN per family. The ipv4-unicast splice must surface
# ONLY the ipv4 autonomous-system (64810) and ipv4 redistribute — never the ipv6
# ASN (64811) or ipv6 route-map in the single-valued ipv4-meaning fields.
DUAL_AF = """feature eigrp
route-map RM_DS_V4 permit 10
route-map RM_DS_V6 permit 10
router eigrp DUALSTK
  address-family ipv4 unicast
    autonomous-system 64810
    redistribute static route-map RM_DS_V4
  address-family ipv6 unicast
    autonomous-system 64811
    redistribute direct route-map RM_DS_V6
"""


def test_dual_stack_ipv4_wins_never_ipv6_asn():
    e = _eigrp(DUAL_AF)
    assert e.name == "DUALSTK"
    assert e.as_number == 64810                       # NOT 64811 (the ipv6 ASN)
    assert len(e.redistribute) == 1
    assert e.redistribute[0].route_map == "RM_DS_V4"  # NOT RM_DS_V6
    assert all(r.route_map != "RM_DS_V6" for r in e.redistribute)


# IPv6-ONLY: no ipv4 unicast AF. The ipv6 ASN and redistribute have no IPv4 home,
# so they must be WITHHELD. as_number falls back to the NAME string (the honest
# "no numeric ASN found" state), NOT the ipv6 ASN. Over-splice regression guard:
# if the fix spliced ipv6, as_number would be 64950 and redistribute non-empty.
IPV6_ONLY = """feature eigrp
route-map RM_DARK_V6 permit 10
router eigrp DARKV6
  address-family ipv6 unicast
    autonomous-system 64950
    redistribute static route-map RM_DARK_V6
"""


def test_ipv6_only_eigrp_asn_not_attributed_to_ipv4():
    e = _eigrp(IPV6_ONLY)
    assert e.name == "DARKV6"
    assert e.as_number == "DARKV6"     # name fallback — NOT 64950 (the ipv6 ASN)
    assert e.as_number != 64950
    assert e.redistribute == []        # ipv6 redistribute withheld, not doubled
