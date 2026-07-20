"""CCR-0067 — NX-OS IS-IS nests its own attributes under `address-family`.

NX-OS emits `redistribute` / `default-information originate` inside
`address-family ipv4 unicast` (device-verified on Nexus 9000v 10.5(5)). The shared
`parse_isis` direct-child extractors stopped at the AF door and dropped all of it.
The fix gives NXOSParser the same `_AFTransparentBlock` view IOS-XR uses (CCR-0046):
splice ONLY the ipv4-unicast AF, so instance-level IPv4 values are read
deterministically and the IPv6 AF is withheld until IS-IS gains an AF dimension
(CCR-0049's guard).
"""
from __future__ import annotations

from confgraph.parsers.nxos_parser import NXOSParser


def _isis(text: str):
    return NXOSParser(text).parse().isis_instances[0]


DUAL_STACK = """feature isis
route-map RM_ISIS permit 10
router isis CORE
  net 49.0001.0000.0000.000a.00
  is-type level-2
  address-family ipv4 unicast
    redistribute direct route-map RM_ISIS
    default-information originate
  address-family ipv6 unicast
    redistribute direct route-map RM_ISIS
    default-information originate
"""


def test_af_nested_redistribute_and_default_information_read():
    i = _isis(DUAL_STACK)
    assert i.tag == "CORE"
    assert i.net == ["49.0001.0000.0000.000a.00"]
    assert i.is_type == "level-2"
    # Previously dropped (redistribute == [], default_information == False).
    assert len(i.redistribute) == 1
    assert i.redistribute[0].protocol == "direct"
    assert i.redistribute[0].route_map == "RM_ISIS"
    assert i.default_information_originate is True


def test_only_ipv4_af_spliced_no_dual_stack_collapse():
    # The IPv6 AF also carries redistribute; the splice takes ONLY ipv4 unicast,
    # so exactly one entry — never the IPv6 value in an IPv4-meaning field.
    assert len(_isis(DUAL_STACK).redistribute) == 1


IPV6_FIRST = """feature isis
route-map RM_V4 permit 10
route-map RM_V6 permit 10
router isis CORE
  net 49.0001.0000.0000.000a.00
  address-family ipv6 unicast
    redistribute direct route-map RM_V6
  address-family ipv4 unicast
    redistribute static route-map RM_V4
"""


def test_ipv4_splice_is_order_independent():
    # IPv6 AF written FIRST; the splice still reads the IPv4 AF's value
    # deterministically (CCR-0049 acceptance: order-independence).
    i = _isis(IPV6_FIRST)
    assert len(i.redistribute) == 1
    assert i.redistribute[0].protocol == "static"
    assert i.redistribute[0].route_map == "RM_V4"


FLAT = """feature isis
route-map RM_ISIS permit 10
router isis CORE
  net 49.0001.0000.0000.000a.00
  is-type level-2
  redistribute static route-map RM_ISIS
"""


def test_flat_no_af_instance_unchanged():
    # A flat NX-OS IS-IS (redistribute a direct child, no address-family) is
    # unaffected — the AF-transparent view is additive/identity with no ipv4 AF.
    i = _isis(FLAT)
    assert i.is_type == "level-2"
    assert len(i.redistribute) == 1
    assert i.redistribute[0].protocol == "static"
    assert i.redistribute[0].route_map == "RM_ISIS"
