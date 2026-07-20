"""VALIDATOR (CCR-0067) — NX-OS IS-IS address-family descent.

Independent adversarial validation. Own identifiers only (tag WESTPOP,
net 49.0047.0000.0000.00b4.00, route-maps RM_WP_INET4 / RM_WP_INET6) — none
shared with the fixer's fixtures (CORE / RM_ISIS / 49.0001...000a.00).

Emitted forms grounded in syntax-corpus/nxos/isis.yaml (verified-capture,
Nexus 9000v 10.5(5)): instance-level net/is-type at 2-space indent; redistribute
+ default-information originate nested under `address-family {ipv4|ipv6} unicast`
at 4-space indent.
"""
from __future__ import annotations

from confgraph.parsers.nxos_parser import NXOSParser


def _isis(text: str):
    insts = NXOSParser(text).parse().isis_instances
    assert len(insts) == 1, f"expected exactly one IS-IS instance, got {len(insts)}"
    return insts[0]


# ipv4 AF written first; ipv6 second. Different route-map per family so the
# spliced value is distinguishable from the withheld one.
DUAL_STACK = """feature isis
route-map RM_WP_INET4 permit 10
route-map RM_WP_INET6 permit 10
router isis WESTPOP
  net 49.0047.0000.0000.00b4.00
  is-type level-2
  address-family ipv4 unicast
    redistribute static route-map RM_WP_INET4
    default-information originate
  address-family ipv6 unicast
    redistribute direct route-map RM_WP_INET6
    default-information originate
"""


def test_af_nested_redistribute_read():
    # RED pre-fix: redistribute == [] (AF child dropped). GREEN post-fix.
    i = _isis(DUAL_STACK)
    assert i.tag == "WESTPOP"
    assert i.net == ["49.0047.0000.0000.00b4.00"]
    assert i.is_type == "level-2"
    assert len(i.redistribute) == 1
    assert i.redistribute[0].protocol == "static"
    assert i.redistribute[0].route_map == "RM_WP_INET4"


def test_af_nested_default_information_read():
    # RED pre-fix: default_information_originate == False. GREEN post-fix.
    assert _isis(DUAL_STACK).default_information_originate is True


def test_ipv6_af_withheld_not_doubled_not_ipv6_value():
    # ipv6 unicast ALSO carries a redistribute; only ipv4 unicast is spliced.
    # Exactly one entry, and it is the IPv4 one — never the IPv6 route-map in an
    # IPv4-meaning field, never both.
    i = _isis(DUAL_STACK)
    assert len(i.redistribute) == 1
    assert all(r.route_map != "RM_WP_INET6" for r in i.redistribute)


# ipv6 AF written FIRST — proves the splice keys on the AF name, not on order.
IPV6_FIRST = """feature isis
route-map RM_WP_INET4 permit 10
route-map RM_WP_INET6 permit 10
router isis WESTPOP
  net 49.0047.0000.0000.00b4.00
  address-family ipv6 unicast
    redistribute direct route-map RM_WP_INET6
    default-information originate
  address-family ipv4 unicast
    redistribute static route-map RM_WP_INET4
    default-information originate
"""


def test_ipv4_splice_order_independent():
    i = _isis(IPV6_FIRST)
    assert len(i.redistribute) == 1
    assert i.redistribute[0].protocol == "static"
    assert i.redistribute[0].route_map == "RM_WP_INET4"


# IPv6-ONLY: no ipv4 unicast AF at all. The ipv6 value has no IPv4 home, so it
# must be WITHHELD (honest absence), never attributed to the IPv4-meaning field.
# Over-splice regression guard: if the fix spliced ipv6 too, redistribute would
# be [RM_WP_INET6] and this fails.
IPV6_ONLY = """feature isis
route-map RM_WP_INET6 permit 10
router isis WESTPOP
  net 49.0047.0000.0000.00b4.00
  is-type level-2
  address-family ipv6 unicast
    redistribute direct route-map RM_WP_INET6
    default-information originate
"""


def test_ipv6_only_yields_empty_not_wrong_value():
    i = _isis(IPV6_ONLY)
    assert i.tag == "WESTPOP"
    assert i.redistribute == []
    assert i.default_information_originate is False


# FLAT (no AF) — the AF-transparent view is the identity here; instance parses
# unchanged. Non-regression guard.
FLAT = """feature isis
router isis WESTPOP
  net 49.0047.0000.0000.00b4.00
  is-type level-2
"""


def test_flat_no_af_unchanged():
    i = _isis(FLAT)
    assert i.tag == "WESTPOP"
    assert i.net == ["49.0047.0000.0000.00b4.00"]
    assert i.is_type == "level-2"
    assert i.redistribute == []
    assert i.default_information_originate is False
