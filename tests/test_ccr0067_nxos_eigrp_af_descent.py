"""CCR-0067 (EIGRP half) — NX-OS named EIGRP: tag vs ASN + AF descent.

`router eigrp <NAME>` takes a NAME; the real ASN is `autonomous-system N`, which
NX-OS nests inside `address-family ipv4 unicast` alongside `redistribute`
(device-verified on Nexus 9000v 10.5(5)). Before the fix, confgraph stored the
NAME in `as_number` and dropped both the ASN and the AF-nested redistribute. The
fix reuses the same `_AFTransparentBlock` seam as router-isis (ipv4-unicast
splice) and stores the tag in the new `name` field.
"""
from __future__ import annotations

from confgraph.parsers.nxos_parser import NXOSParser


def _eigrp(text: str):
    return NXOSParser(text).parse().eigrp_instances[0]


NAMED = """feature eigrp
route-map RM_EIGRP permit 10
router eigrp CORE
  address-family ipv4 unicast
    autonomous-system 100
    redistribute direct route-map RM_EIGRP
"""


def test_named_eigrp_tag_asn_and_af_redistribute():
    e = _eigrp(NAMED)
    # The tag is a NAME -> stored in `name`; the real ASN comes from the
    # AF-nested `autonomous-system` -> `as_number` (was 'CORE', dropping the ASN).
    assert e.name == "CORE"
    assert e.as_number == 100
    # AF-nested redistribute now read (was []).
    assert len(e.redistribute) == 1
    assert e.redistribute[0].protocol == "direct"
    assert e.redistribute[0].route_map == "RM_EIGRP"


NUMERIC = """feature eigrp
route-map RM_EIGRP permit 10
router eigrp 65000
  address-family ipv4 unicast
    redistribute static route-map RM_EIGRP
"""


def test_numeric_eigrp_name_is_none_asn_unchanged():
    # Classic numeric-AS mode: as_number is the number, name stays None (the
    # common case must not gain a spurious name).
    e = _eigrp(NUMERIC)
    assert e.as_number == 65000
    assert e.name is None
    assert len(e.redistribute) == 1
    assert e.redistribute[0].protocol == "static"


DUAL_AF = """feature eigrp
route-map RM_V4 permit 10
route-map RM_V6 permit 10
router eigrp CORE
  address-family ipv4 unicast
    autonomous-system 100
    redistribute direct route-map RM_V4
  address-family ipv6 unicast
    redistribute static route-map RM_V6
"""


def test_ipv4_only_splice_ipv6_af_withheld():
    # Only the ipv4-unicast AF is spliced: the ipv6 AF's redistribute is withheld
    # (the CCR-0049 guard), so exactly one entry — the IPv4 one.
    e = _eigrp(DUAL_AF)
    assert e.as_number == 100
    assert len(e.redistribute) == 1
    assert e.redistribute[0].route_map == "RM_V4"
