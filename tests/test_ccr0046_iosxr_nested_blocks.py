"""CCR-0046 — IOS-XR: the parser must descend into nested blocks, not stop at the door.

IOS-XR nests configuration one level deeper than the rest of the Cisco family.
An attribute *of the enclosing object* is emitted INSIDE an `address-family`
sub-block, and every IOS-family extractor reads DIRECT children only
(`find_child_objects` defaults to `recurse=False`).  So the parser captured the
container and dropped the contents:

    router isis CORE
     address-family ipv4 unicast
      metric-style wide          <- an attribute of the INSTANCE   -> was None
     interface TenGigE0/0/0/3
      address-family ipv4 unicast
       metric 42                 <- an attribute of the INTERFACE  -> was None

Every assertion below is a VALUE assertion.  A presence check (`bool(x)`,
`len(x) >= 1`) passes on a wrong value, and several of these fields were not
absent but WRONG — which nothing downstream can detect.

Config syntax is device-EMITTED form, per the syntax consultations recorded in
the CCR (`syntax-corpus/iosxr/{isis,routing-policy,static}.yaml`):

  * `metric-style` and `redistribute` are emitted ONLY inside the process-level
    `address-family` block — never as direct children of `router isis <tag>`.
  * A per-interface `address-family` block IS EMITTED EVEN WHEN EMPTY: entering
    the AF is what enables IS-IS for that AF on the interface.  "No metric line"
    and "no address-family block" are different states, and both are exercised.
  * A static route's administrative distance is a BARE positional integer, while
    `tag` and `metric` carry their keywords; a fully-specified route emits the
    output interface BEFORE the next-hop IP.
  * In RPL, the COMMA is the member separator and a newline after it is OPTIONAL
    — so the members-per-line layout is not something a parser may depend on.
    Both layouts are asserted to parse identically, which is why no assertion
    here rests on the (unestablished) emitted layout.

Names, IPs and IDs are this test's own — none are shared with the coverage
fixture, so nothing here can pass by being tuned to it.
"""

from ipaddress import IPv4Address, IPv4Network

import pytest

from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.iosxr_parser import IOSXRParser


# ---------------------------------------------------------------------------
# Theme 1 — the AF descent: IS-IS instance and IS-IS interface (rows 1-3)
# ---------------------------------------------------------------------------

IOSXR_ISIS = """\
router isis BACKBONE
 net 49.0002.0000.0000.0007.00
 is-type level-2-only
 address-family ipv4 unicast
  metric-style wide
  redistribute bgp 64512 route-policy RP-CORE-IN
 !
 interface Loopback7
  passive
  address-family ipv4 unicast
  !
 !
 interface TenGigE0/0/0/3
  point-to-point
  address-family ipv4 unicast
   metric 42
  !
 !
!
"""


@pytest.fixture(scope="module")
def isis():
    instances = IOSXRParser(IOSXR_ISIS).parse().isis_instances
    assert len(instances) == 1
    return instances[0]


def test_isis_metric_style_is_read_through_the_address_family(isis):
    """`metric-style wide` lives in the process AF block. It was None."""
    assert isis.metric_style == "wide"


def test_isis_redistribute_is_read_through_the_address_family(isis):
    """`redistribute bgp … route-policy …` lives in the process AF block.

    It was an EMPTY list — so an IOS-XR node carried no redistribution at all.
    The value, not the count, is what is asserted.
    """
    assert len(isis.redistribute) == 1
    redist = isis.redistribute[0]
    assert redist.protocol == "bgp"
    assert redist.process_id == 64512
    assert redist.route_map == "RP-CORE-IN"


def test_isis_interface_metric_is_read_through_the_interface_address_family(isis):
    """`metric 42` lives in the INTERFACE's own AF block, two levels down."""
    ten_gig = next(i for i in isis.interfaces if i.name == "TenGigE0/0/0/3")
    assert ten_gig.metric == 42


def test_isis_interface_with_an_empty_address_family_block_has_no_metric(isis):
    """An empty per-interface AF block is EMITTED, and means "no metric set".

    The device prints `address-family ipv4 unicast` + `!` for an interface with
    no metric, because entering the AF is what enables IS-IS on it.  The descent
    must not invent a value for that, and must not lose the interface either.
    """
    loopback = next(i for i in isis.interfaces if i.name == "Loopback7")
    assert loopback.metric is None
    assert loopback.passive is True


def test_isis_direct_children_still_read_through_the_af_view(isis):
    """The AF view ADDS the AF's children; it removes nothing.

    `net` and `is-type` are direct children of `router isis` and must survive.
    """
    assert isis.net == ["49.0002.0000.0000.0007.00"]
    assert isis.is_type == "level-2-only"


def test_af_view_does_not_corrupt_raw_line_capture(isis):
    """Raw capture is untouched: the AF header is still a raw line of the block.

    The view answers `find_child_objects`; it forwards `.children`, `.text` and
    `.linenum`, so raw_lines / line_numbers / change-IR provenance are unchanged.
    """
    assert " address-family ipv4 unicast" in isis.raw_lines
    assert len(isis.raw_lines) == len(isis.line_numbers)


# ---------------------------------------------------------------------------
# Theme 1b — dual-stack: the descent must splice IPv4 ONLY
#
# `ISISConfig.metric_style` and `ISISInterface.metric` have no address-family
# dimension — they are single-valued, and every consumer reads them as the
# device's IPv4 values. A dual-stack instance carries two answers. Splicing both
# merges them and lets whichever block the vendor wrote FIRST win, which hands a
# consumer IPv6's answer to an IPv4 question — silently, and with nothing to
# alert on. Pre-fix these fields were None: a loud, honest absence. A confident
# wrong answer is a regression in kind, not an improvement.
#
# The IPv6 block is deliberately written FIRST in every fixture here: that is the
# order under which a naive splice fails. Order-independence is the property.
# ---------------------------------------------------------------------------

IOSXR_ISIS_DUAL_STACK_IPV6_FIRST = """\
router isis DUALSTACK
 net 49.0003.0000.0000.0009.00
 address-family ipv6 unicast
  metric-style narrow
  redistribute bgp 64999 route-policy RP-V6-IN
 !
 address-family ipv4 unicast
  metric-style wide
  redistribute bgp 64512 route-policy RP-CORE-IN
 !
 interface TenGigE0/0/0/9
  address-family ipv6 unicast
   metric 45
  !
  address-family ipv4 unicast
   metric 15
  !
 !
!
"""


@pytest.fixture(scope="module")
def dual_stack_isis():
    return IOSXRParser(IOSXR_ISIS_DUAL_STACK_IPV6_FIRST).parse().isis_instances[0]


def test_dual_stack_metric_style_is_the_ipv4_value_not_the_first_one(dual_stack_isis):
    """IPv6 says `narrow` and is written first. The model must still say `wide`."""
    assert dual_stack_isis.metric_style == "wide"


def test_dual_stack_interface_metric_is_the_ipv4_value_not_the_first_one(dual_stack_isis):
    """IPv6 says 45 and is written first. The model must still say 15."""
    interface = next(
        i for i in dual_stack_isis.interfaces if i.name == "TenGigE0/0/0/9"
    )
    assert interface.metric == 15


def test_dual_stack_redistribute_carries_only_the_ipv4_statement(dual_stack_isis):
    """The IPv6 AF's redistribute must not join the IPv4 list.

    A merged list would give the instance two redistributions where the device
    has one per AF — and the model has no dimension to tell them apart.
    """
    assert len(dual_stack_isis.redistribute) == 1
    redist = dual_stack_isis.redistribute[0]
    assert redist.process_id == 64512
    assert redist.route_map == "RP-CORE-IN"


IOSXR_ISIS_IPV6_ONLY = """\
router isis V6ONLY
 net 49.0004.0000.0000.0011.00
 address-family ipv6 unicast
  metric-style narrow
  redistribute bgp 64999 route-policy RP-V6-IN
 !
 interface TenGigE0/0/0/11
  address-family ipv6 unicast
   metric 45
  !
 !
!
"""


def test_ipv6_only_isis_reports_nothing_rather_than_ipv6_values_as_ipv4():
    """The honest answer when the model has no home for the value is silence.

    An IPv6-only instance has no IPv4 metric-style, no IPv4 metric and no IPv4
    redistribution. Reporting IPv6's numbers in fields every consumer reads as
    IPv4 would be worse than reporting nothing — so the fields stay empty.
    """
    isis = IOSXRParser(IOSXR_ISIS_IPV6_ONLY).parse().isis_instances[0]

    assert isis.metric_style is None
    assert isis.redistribute == []

    interface = next(i for i in isis.interfaces if i.name == "TenGigE0/0/0/11")
    assert interface.metric is None
    # The interface itself is still discovered — it is enrolled in the process.
    assert interface.name == "TenGigE0/0/0/11"


# ---------------------------------------------------------------------------
# Theme 2 — the descent must NOT flatten a BGP neighbor's AF (row 4)
# ---------------------------------------------------------------------------

IOSXR_BGP = """\
router bgp 64512
 bgp router-id 7.7.7.7
 neighbor 198.51.100.7
  remote-as 64513
  description PEERING-EXCHANGE
  address-family ipv4 unicast
   route-policy RP-CORE-IN in
   maximum-prefix 250000 85
  !
 !
!
"""


@pytest.fixture(scope="module")
def bgp_neighbor():
    parsed = IOSXRParser(IOSXR_BGP).parse()
    bgp = next(b for b in parsed.bgp_instances if b.vrf is None)
    return next(n for n in bgp.neighbors if str(n.peer_ip) == "198.51.100.7")


def test_bgp_neighbor_maximum_prefix_lands_on_the_address_family(bgp_neighbor):
    """`maximum-prefix` is emitted inside the neighbor's AF block and was None."""
    af = next(a for a in bgp_neighbor.address_families if a.afi == "ipv4")
    assert af.maximum_prefix == 250000
    assert af.maximum_prefix_threshold == 85
    assert af.maximum_prefix_warning_only is False


def test_bgp_neighbor_af_value_is_not_promoted_onto_the_neighbor(bgp_neighbor):
    """The AF-scoped limit must NOT be copied up onto BGPNeighbor.

    IOS-XR scopes maximum-prefix per address-family: a neighbor can carry a
    different limit for ipv4 and ipv6.  Promoting one AF's value to the neighbor
    would assert it for all of them.  Where an AF-scoped value belongs on the
    neighbor is [[CCR-0045]]'s question — this fix parses it, and deliberately
    does not answer that.
    """
    assert bgp_neighbor.maximum_prefix is None


# ---------------------------------------------------------------------------
# Theme 3 — OSPF `area` is a nested block on IOS-XR (row 5)
# ---------------------------------------------------------------------------

IOSXR_OSPF = """\
router ospf 7
 router-id 7.7.7.7
 area 3
  stub
  default-cost 25
  interface TenGigE0/0/0/3
   cost 150
  !
 !
!
"""


def test_ospf_area_default_cost_is_read_from_the_nested_area_block():
    """IOS-XR spells `area 3` / `default-cost 25` as a BLOCK.

    CCR-0044 closed this concept on IOS/NX-OS/EOS, which emit the one-liner
    `area 3 default-cost 25`; the shared extraction did not reach IOS-XR because
    of the different shape.  Same field, same keyword, one vocabulary.
    """
    parsed = IOSXRParser(IOSXR_OSPF).parse()
    ospf = next(o for o in parsed.ospf_instances if o.process_id == 7)
    area = next(a for a in ospf.areas if a.area_id == "3")
    assert area.default_cost == 25


def test_ospf_area_interface_cost_is_not_mistaken_for_an_area_scalar():
    """`cost 150` inside `area 3 > interface X` belongs to the INTERFACE.

    The area-body walk reads DIRECT children of the area block, so a setting one
    level further down cannot leak up into the area.
    """
    parsed = IOSXRParser(IOSXR_OSPF).parse()
    ospf = next(o for o in parsed.ospf_instances if o.process_id == 7)
    area = next(a for a in ospf.areas if a.area_id == "3")
    assert area.default_cost == 25
    assert area.interface_settings["TenGigE0/0/0/3"].cost == 150


# ---------------------------------------------------------------------------
# Theme 4 — static route trailing modifiers (rows 6-7)
# ---------------------------------------------------------------------------

IOSXR_STATIC = """\
router static
 address-family ipv4 unicast
  0.0.0.0/0 203.0.113.1
  172.31.0.0/16 Null0 tag 4242
  10.99.0.0/16 203.0.113.2 210 description DR-FAILOVER
  10.98.0.0/16 TenGigE0/0/0/3 203.0.113.3 120 tag 77 description DUAL-HOMED
 !
!
"""


@pytest.fixture(scope="module")
def static_routes():
    return {
        str(r.destination): r
        for r in IOSXRParser(IOSXR_STATIC).parse().static_routes
    }


def test_static_route_tag_is_parsed(static_routes):
    """`tag 4242` on an interface next-hop with no distance."""
    route = static_routes["172.31.0.0/16"]
    assert route.tag == 4242
    assert route.next_hop_interface == "Null0"
    assert route.distance == 1  # no bare integer emitted -> the default


def test_static_route_description_is_parsed(static_routes):
    """`description DR-FAILOVER` — the model spells a route's description `name`."""
    route = static_routes["10.99.0.0/16"]
    assert route.name == "DR-FAILOVER"
    assert route.distance == 210
    assert route.next_hop == IPv4Address("203.0.113.2")


def test_static_route_distance_is_the_bare_integer_not_the_tag(static_routes):
    """The distance is positional and bare; `tag` and `metric` carry keywords.

    A walk that takes "the first trailing integer" as the distance reads 4242 as
    a distance on the tagged route above; one that takes "any integer" reads the
    tag as one here.  Both are wrong, and both are silent.
    """
    assert static_routes["172.31.0.0/16"].distance == 1
    assert static_routes["10.99.0.0/16"].distance == 210
    assert static_routes["10.99.0.0/16"].tag is None


def test_fully_specified_static_route_keeps_both_next_hops(static_routes):
    """IOS-XR emits the output interface BEFORE the next-hop IP.

    Reading only the first token after the prefix dropped the next hop entirely
    and then read the IP as the administrative distance.
    """
    route = static_routes["10.98.0.0/16"]
    assert route.next_hop_interface == "TenGigE0/0/0/3"
    assert route.next_hop == IPv4Address("203.0.113.3")
    assert route.distance == 120
    assert route.tag == 77
    assert route.name == "DUAL-HOMED"


def test_plain_static_route_is_unchanged(static_routes):
    """The no-modifier case must keep working."""
    route = static_routes["0.0.0.0/0"]
    assert route.destination == IPv4Network("0.0.0.0/0")
    assert route.next_hop == IPv4Address("203.0.113.1")
    assert route.distance == 1
    assert route.tag is None
    assert route.name is None


# ---------------------------------------------------------------------------
# Theme 5 — community-set members are members, not one conjunction (row 8)
# ---------------------------------------------------------------------------

# The RPL member separator is the COMMA; a newline after it is OPTIONAL, so the
# same set is legal (and these tests assert, identical) either way.  No assertion
# here depends on the emitted layout, which no readable source establishes.
IOSXR_COMMSET_ONE_PER_LINE = """\
community-set CS-TRANSIT
  64512:300,
  64512:400,
  no-export
end-set
!
"""

IOSXR_COMMSET_MEMBERS_SHARING_A_LINE = """\
community-set CS-TRANSIT
  64512:300, 64512:400, no-export
end-set
!
"""


@pytest.mark.parametrize(
    "config",
    [IOSXR_COMMSET_ONE_PER_LINE, IOSXR_COMMSET_MEMBERS_SHARING_A_LINE],
    ids=["one-member-per-line", "members-sharing-a-line"],
)
def test_community_set_yields_one_entry_per_member(config):
    """Three members must be three entries, not one entry holding three.

    In this model a CommunityListEntry is one CLAUSE — the IOS parser builds it
    from `ip community-list standard X permit A B`, where a route must carry
    A *and* B.  An IOS-XR community-set asserts no conjunction: it is a list of
    specifications, and the quantifier lives at the use site (`matches-any` /
    `matches-every`).  Collapsing the members into one entry states a conjunction
    the device never wrote, and makes len(entries) mean "1" on IOS-XR where it
    means "number of alternatives" everywhere else.

    This was the one row that was silently WRONG rather than absent: the set
    looked valid and a consumer had nothing to alert on.
    """
    community_lists = IOSXRParser(config).parse().community_lists
    cs = next(c for c in community_lists if c.name == "CS-TRANSIT")

    assert [e.communities for e in cs.entries] == [
        ["64512:300"],
        ["64512:400"],
        ["no-export"],
    ]
    assert [e.action for e in cs.entries] == ["permit", "permit", "permit"]


def test_extcommunity_set_yields_one_entry_per_member():
    """Same block shape, same member walk, same rule."""
    config = """\
extcommunity-set rt ECS-VPN
  64512:100,
  64512:200
end-set
!
"""
    community_lists = IOSXRParser(config).parse().community_lists
    ecs = next(c for c in community_lists if c.name == "ECS-VPN")
    assert ecs.list_type == "extended"
    assert [e.communities for e in ecs.entries] == [["64512:100"], ["64512:200"]]


# ---------------------------------------------------------------------------
# Theme 6 — the seam is the IDENTITY everywhere else
# ---------------------------------------------------------------------------

IOS_ISIS = """\
router isis 1
 net 49.0001.0000.0000.0001.00
 is-type level-2-only
 metric-style wide
 redistribute bgp 64512 route-map RM-CORE-IN
!
"""


def test_ios_isis_still_reads_its_attributes_as_direct_children():
    """`_nested_block` is the identity on IOS: this must be bit-for-bit unaffected.

    The AF descent is reached through one shared walk (IOSParser.parse_isis), and
    IOS/NX-OS/EOS emit an instance's attributes as DIRECT children — there is no
    address-family block to descend into.  If this ever changes, the descent has
    leaked out of IOS-XR.
    """
    isis = IOSParser(IOS_ISIS).parse().isis_instances[0]
    assert isis.metric_style == "wide"
    assert isis.is_type == "level-2-only"
    assert len(isis.redistribute) == 1
    assert isis.redistribute[0].protocol == "bgp"
    assert isis.redistribute[0].route_map == "RM-CORE-IN"
