"""CCR-0035 — PAN-OS routing surface: policy nodes, peer-groups, session attrs,
redistribution, OSPF area type + interface metric.

Every element below is the shape a PAN-OS device EMITS, per
`syntax-corpus/panos/{bgp,ospf}.yaml` (cited to pango's Go struct tags and
pan-os-python's xpath profiles). The three mistakes this file locks down:

  * the peer AS is ``<peer-as>`` on the peer entry — NOT
    ``<connection-options><remote-as>``, which no device emits (gap #8; the old
    coverage fixture agreed with the parser and so certified a broken path);
  * enumerations are ELEMENT NAMES, not text: ``<type><stub/></type>``,
    ``<action><deny/></action>`` — reading the text yields "" on every device
    (gaps #5, #1);
  * the redistributed protocol is in the referenced ``<redist-profile>``'s
    ``<filter><type>`` members — ``address-family-identifier`` is ipv4|ipv6, an
    address family, not a protocol (gap #4).
"""

import pytest

from confgraph.analysis import DependencyResolver
from confgraph.models.ospf import OSPFAreaType
from confgraph.parsers.panos_parser import PANOSParser


ROUTING = """\
<config version="10.1.0">
  <devices>
    <entry name="localhost.localdomain">
      <deviceconfig><system><hostname>pa-core-09</hostname></system></deviceconfig>
      <network>
        <interface>
          <ethernet>
            <entry name="ethernet1/8">
              <layer3><ip><entry name="198.51.100.21/30"/></ip></layer3>
            </entry>
          </ethernet>
        </interface>
        <virtual-router>
          <entry name="vr-core">
            <interface><member>ethernet1/8</member></interface>
            <protocol>
              <redist-profile>
                <entry name="RP-CONNECT">
                  <priority>1</priority>
                  <action><redist/></action>
                  <filter><type><member>connect</member></type></filter>
                </entry>
                <entry name="RP-STATIC">
                  <priority>2</priority>
                  <action><redist/></action>
                  <filter><type><member>static</member></type></filter>
                </entry>
              </redist-profile>
              <bgp>
                <enable>yes</enable>
                <router-id>10.9.9.9</router-id>
                <local-as>64512</local-as>
                <auth-profile>
                  <entry name="TRANSIT-MD5">
                    <secret>-AQ==transitsecret9876543210=</secret>
                  </entry>
                </auth-profile>
                <peer-group>
                  <entry name="TRANSIT">
                    <enable>yes</enable>
                    <type>
                      <ebgp>
                        <import-nexthop>original</import-nexthop>
                        <export-nexthop>use-self</export-nexthop>
                        <remove-private-as>yes</remove-private-as>
                      </ebgp>
                    </type>
                    <peer>
                      <entry name="transit-a">
                        <enable>yes</enable>
                        <peer-as>64513</peer-as>
                        <peer-address><ip>198.51.100.22</ip></peer-address>
                        <local-address><interface>ethernet1/8</interface></local-address>
                        <max-prefixes>5000</max-prefixes>
                        <connection-options>
                          <authentication>TRANSIT-MD5</authentication>
                          <keep-alive-interval>20</keep-alive-interval>
                          <hold-time>60</hold-time>
                          <multihop>4</multihop>
                        </connection-options>
                      </entry>
                      <entry name="transit-b">
                        <enable>no</enable>
                        <peer-as>64514</peer-as>
                        <peer-address><ip>198.51.100.26</ip></peer-address>
                      </entry>
                    </peer>
                  </entry>
                </peer-group>
                <policy>
                  <import>
                    <rules>
                      <entry name="IN-TRANSIT">
                        <enable>yes</enable>
                        <used-by><member>TRANSIT</member></used-by>
                        <match>
                          <as-path><regex>^64513(_[0-9]+)*$</regex></as-path>
                          <address-prefix>
                            <entry name="192.0.2.0/24"><exact>no</exact></entry>
                          </address-prefix>
                        </match>
                        <action>
                          <allow>
                            <update><local-preference>150</local-preference></update>
                          </allow>
                        </action>
                      </entry>
                      <entry name="IN-BLOCKHOLE">
                        <enable>no</enable>
                        <used-by><member>TRANSIT</member></used-by>
                        <action><deny/></action>
                      </entry>
                    </rules>
                  </import>
                  <export>
                    <rules>
                      <entry name="OUT-LOCAL">
                        <enable>yes</enable>
                        <used-by><member>TRANSIT</member></used-by>
                        <action>
                          <allow>
                            <update>
                              <med>70</med>
                              <as-path><prepend>3</prepend></as-path>
                            </update>
                          </allow>
                        </action>
                      </entry>
                    </rules>
                  </export>
                </policy>
                <redist-rules>
                  <entry name="RP-STATIC">
                    <enable>yes</enable>
                    <address-family-identifier>ipv4</address-family-identifier>
                    <route-table>unicast</route-table>
                    <metric>25</metric>
                  </entry>
                </redist-rules>
              </bgp>
              <ospf>
                <enable>yes</enable>
                <router-id>10.9.9.9</router-id>
                <area>
                  <entry name="0.0.0.0">
                    <type><normal/></type>
                    <interface>
                      <entry name="ethernet1/8">
                        <enable>yes</enable>
                        <passive>no</passive>
                        <metric>45</metric>
                        <link-type><broadcast/></link-type>
                      </entry>
                    </interface>
                  </entry>
                  <entry name="0.0.0.7">
                    <type>
                      <stub>
                        <accept-summary>yes</accept-summary>
                        <default-route>
                          <advertise><metric>30</metric></advertise>
                        </default-route>
                      </stub>
                    </type>
                  </entry>
                  <entry name="0.0.0.8">
                    <type>
                      <stub>
                        <accept-summary>no</accept-summary>
                        <default-route><disable/></default-route>
                      </stub>
                    </type>
                  </entry>
                </area>
                <export-rules>
                  <entry name="RP-CONNECT">
                    <new-path-type>ext-1</new-path-type>
                    <new-tag>77</new-tag>
                    <metric>15</metric>
                  </entry>
                </export-rules>
              </ospf>
            </protocol>
          </entry>
        </virtual-router>
      </network>
      <vsys><entry name="vsys1"/></vsys>
    </entry>
  </devices>
</config>
"""


@pytest.fixture(scope="module")
def parsed():
    return PANOSParser(ROUTING).parse()


@pytest.fixture(scope="module")
def bgp(parsed):
    return parsed.bgp_instances[0]


# ---------------------------------------------------------------------------
# #8 — the peer AS is <peer-as>, on the peer entry
# ---------------------------------------------------------------------------

def test_peer_as_is_read_from_peer_as_element(bgp):
    peer = next(n for n in bgp.neighbors if n.description == "transit-a")
    assert peer.remote_as == 64513
    assert str(peer.peer_ip) == "198.51.100.22"


def test_connection_options_remote_as_is_not_a_thing():
    """The fabricated shape the old fixture carried must yield NO neighbor.

    If this ever passes, the parser has re-acquired a path no device feeds it —
    and a fixture written against that path would certify it as working.
    """
    fabricated = ROUTING.replace(
        "<peer-as>64513</peer-as>",
        "",
    ).replace(
        "<multihop>4</multihop>",
        "<multihop>4</multihop><remote-as>64513</remote-as>",
    )
    parsed = PANOSParser(fabricated).parse()
    peers = [n for n in parsed.bgp_instances[0].neighbors if n.description == "transit-a"]
    assert peers == []


# ---------------------------------------------------------------------------
# #2, #3 — peer-groups and session attributes
# ---------------------------------------------------------------------------

def test_peer_group_is_modeled_and_its_attributes_reach_the_peer(bgp):
    assert [g.name for g in bgp.peer_groups] == ["TRANSIT"]
    group = bgp.peer_groups[0]
    # <type><ebgp><export-nexthop>use-self — the type is an element name, and
    # the group-level setting is inherited by its members.
    assert group.next_hop_self is True

    peer = next(n for n in bgp.neighbors if n.description == "transit-a")
    assert peer.peer_group == "TRANSIT"
    assert peer.next_hop_self is True


def test_session_attributes_come_from_connection_options(bgp):
    peer = next(n for n in bgp.neighbors if n.description == "transit-a")
    assert peer.timers is not None
    assert (peer.timers.keepalive, peer.timers.holdtime) == (20, 60)
    # <multihop> is a TTL, not a boolean
    assert peer.ebgp_multihop == 4
    assert peer.update_source == "ethernet1/8"
    assert peer.shutdown is False

    disabled = next(n for n in bgp.neighbors if n.description == "transit-b")
    assert disabled.shutdown is True
    assert disabled.timers is None


def test_max_prefixes_is_a_flat_element_on_the_peer(bgp):
    """<max-prefixes> is a direct child of the peer entry — not inside
    connection-options, and not the Cisco maximum-prefix/threshold/action triple
    (that exists only in the 11.x advanced-routing tree, on another object)."""
    peer = next(n for n in bgp.neighbors if n.description == "transit-a")
    assert peer.maximum_prefix == 5000


def test_max_prefixes_unlimited_is_not_a_number():
    """The vendor allows the literal 'unlimited'; the model's int field cannot
    hold it, so it must come back as None (no limit) rather than crash."""
    unlimited = ROUTING.replace(
        "<max-prefixes>5000</max-prefixes>",
        "<max-prefixes>unlimited</max-prefixes>",
    )
    peer = next(
        n for n in PANOSParser(unlimited).parse().bgp_instances[0].neighbors
        if n.description == "transit-a"
    )
    assert peer.maximum_prefix is None


def test_peer_password_is_resolved_through_the_auth_profile_reference(bgp):
    """PAN-OS puts no secret on the peer: connection-options/authentication is a
    NAME, and the secret lives in bgp/auth-profile/entry[@name]/secret."""
    peer = next(n for n in bgp.neighbors if n.description == "transit-a")
    assert peer.password == "-AQ==transitsecret9876543210="


def test_an_unresolvable_auth_profile_name_yields_no_password():
    orphan = ROUTING.replace(
        "<authentication>TRANSIT-MD5</authentication>",
        "<authentication>NO-SUCH-PROFILE</authentication>",
    )
    peer = next(
        n for n in PANOSParser(orphan).parse().bgp_instances[0].neighbors
        if n.description == "transit-a"
    )
    assert peer.password is None


# ---------------------------------------------------------------------------
# #1 — BGP policy rules become the same policy nodes the Cisco parsers produce
# ---------------------------------------------------------------------------

def test_policy_rules_become_route_map_policy_nodes(parsed):
    by_name = {rm.name: rm for rm in parsed.route_maps}
    assert set(by_name) == {"IN-TRANSIT", "IN-BLOCKHOLE", "OUT-LOCAL"}

    seq = by_name["IN-TRANSIT"].sequences[0]
    assert seq.action == "permit"
    matches = {m.match_type: m.values for m in seq.match_clauses}
    assert matches["address-prefix"] == ["192.0.2.0/24"]
    assert matches["as-path-regex"] == ["^64513(_[0-9]+)*$"]
    assert {s.set_type: s.values for s in seq.set_clauses}["local-preference"] == ["150"]

    # <action><deny/></action> — the action is an element name, not text.
    assert by_name["IN-BLOCKHOLE"].sequences[0].action == "deny"

    out = by_name["OUT-LOCAL"].sequences[0]
    sets = {s.set_type: s.values for s in out.set_clauses}
    assert sets["metric"] == ["70"]           # <med> → set metric
    assert sets["as-path"] == ["prepend", "3"]  # element-name-as-value + arg


def test_used_by_binds_the_policy_to_the_peers_of_the_peer_group(bgp):
    """<used-by> is PAN-OS's policy→peer edge: it names PEER-GROUPS."""
    peer = next(n for n in bgp.neighbors if n.description == "transit-a")
    assert peer.route_map_in == "IN-TRANSIT"
    assert peer.route_map_out == "OUT-LOCAL"
    group = bgp.peer_groups[0]
    assert (group.route_map_in, group.route_map_out) == ("IN-TRANSIT", "OUT-LOCAL")


def test_a_disabled_rule_is_a_node_but_not_a_binding(bgp, parsed):
    # IN-BLOCKHOLE is <enable>no</enable> and must not win the import binding,
    # even though it is used-by the same group and appears second.
    assert any(rm.name == "IN-BLOCKHOLE" for rm in parsed.route_maps)
    peer = next(n for n in bgp.neighbors if n.description == "transit-a")
    assert peer.route_map_in == "IN-TRANSIT"


def test_policy_nodes_resolve_without_dangling_refs(parsed):
    """The policy edges must land on real nodes, and the INLINE as-path regex
    must not be mistaken for a reference to a named as-path list — that would
    manufacture one dangling ref per rule."""
    report = DependencyResolver(parsed).resolve()
    assert [(d.ref_type, d.ref_name) for d in report.dangling_refs] == []
    edges = {
        (link.source_field, link.ref_name)
        for link in report.links if link.ref_type == "route_map"
    }
    assert ("route_map_in", "IN-TRANSIT") in edges
    assert ("route_map_out", "OUT-LOCAL") in edges


# ---------------------------------------------------------------------------
# #4 — redistribution: the protocol is in the referenced redist-profile
# ---------------------------------------------------------------------------

def test_bgp_redist_rules_resolve_the_protocol_through_the_profile(bgp):
    assert [(r.protocol, r.metric) for r in bgp.redistribute] == [("static", 25)]


def test_ospf_export_rules_use_the_same_profile_resolver(parsed):
    ospf = parsed.ospf_instances[0]
    redist = ospf.redistribute[0]
    assert redist.protocol == "connect"      # from RP-CONNECT's filter/type
    assert (redist.metric, redist.metric_type, redist.tag) == (15, 1, 77)


def test_address_family_identifier_is_not_the_protocol(bgp):
    """ipv4 is an address family. If it ever shows up as a redistributed
    protocol, the category error is back."""
    assert "ipv4" not in [r.protocol for r in bgp.redistribute]


# ---------------------------------------------------------------------------
# #5, #6 — OSPF area type (element-name-as-value) and per-interface metric
# ---------------------------------------------------------------------------

def test_ospf_area_type_is_read_from_the_child_element_name(parsed):
    areas = {a.area_id: a for a in parsed.ospf_instances[0].areas}
    assert areas["0.0.0.0"].area_type == OSPFAreaType.NORMAL
    assert areas["0.0.0.7"].area_type == OSPFAreaType.STUB
    assert areas["0.0.0.7"].default_cost == 30       # type/stub/default-route/advertise/metric
    assert areas["0.0.0.7"].stub_no_summary is False


def test_accept_summary_no_is_the_totally_stubby_area(parsed):
    """PAN-OS has no `no-summary` keyword: a stub area with
    <accept-summary>no</accept-summary> behaves as a TSA, per the vendor doc."""
    area = next(a for a in parsed.ospf_instances[0].areas if a.area_id == "0.0.0.8")
    assert area.area_type == OSPFAreaType.TOTALLY_STUB
    assert area.stub_no_summary is True
    assert area.default_cost is None                 # <default-route><disable/>


def test_ospf_interface_metric_comes_from_inside_the_area(parsed):
    """There is no per-interface OSPF block under network/interface — the cost
    is <metric> on the interface entry nested in the area."""
    iface = next(i for i in parsed.interfaces if i.name == "ethernet1/8")
    assert iface.ospf_cost == 45
    assert iface.ospf_area == "0.0.0.0"
    assert iface.ospf_passive is False


# ---------------------------------------------------------------------------
# #7 — source / PAT NAT (was skipped entirely, "to avoid false dangling refs")
# ---------------------------------------------------------------------------

# <source-translation> has three mutually exclusive branches, selected by element
# name. <translated-address> is a MEMBER LIST under the two dynamic branches and
# a TEXT NODE under static-ip — one element name, two shapes
# (syntax-corpus/panos/nat.yaml).
NAT = """\
<config version="10.1.0">
  <devices>
    <entry name="localhost.localdomain">
      <network>
        <interface>
          <ethernet>
            <entry name="ethernet1/9">
              <layer3><ip><entry name="192.0.2.65/26"/></ip></layer3>
            </entry>
          </ethernet>
        </interface>
      </network>
      <vsys>
        <entry name="vsys1">
          <rulebase>
            <nat>
              <rules>
                <entry name="pat-to-internet">
                  <from><member>lan-z</member></from>
                  <to><member>wan-z</member></to>
                  <source><member>10.30.0.0/16</member></source>
                  <destination><member>any</member></destination>
                  <service>any</service>
                  <source-translation>
                    <dynamic-ip-and-port>
                      <interface-address>
                        <interface>ethernet1/9</interface>
                        <ip>192.0.2.65</ip>
                      </interface-address>
                    </dynamic-ip-and-port>
                  </source-translation>
                </entry>
                <entry name="pat-to-pool">
                  <from><member>lan-z</member></from>
                  <to><member>wan-z</member></to>
                  <source><member>10.31.0.0/16</member></source>
                  <destination><member>any</member></destination>
                  <source-translation>
                    <dynamic-ip-and-port>
                      <translated-address>
                        <member>PUBLIC-POOL</member>
                      </translated-address>
                    </dynamic-ip-and-port>
                  </source-translation>
                </entry>
                <entry name="dyn-no-port">
                  <from><member>lan-z</member></from>
                  <to><member>wan-z</member></to>
                  <source><member>10.32.0.0/16</member></source>
                  <source-translation>
                    <dynamic-ip>
                      <translated-address>
                        <member>192.0.2.128/27</member>
                      </translated-address>
                      <fallback>
                        <interface-address>
                          <interface>ethernet1/9</interface>
                          <floating-ip>192.0.2.66</floating-ip>
                        </interface-address>
                      </fallback>
                    </dynamic-ip>
                  </source-translation>
                </entry>
                <entry name="static-src">
                  <from><member>dmz-z</member></from>
                  <to><member>wan-z</member></to>
                  <source><member>10.33.0.9</member></source>
                  <source-translation>
                    <static-ip>
                      <translated-address>192.0.2.99</translated-address>
                      <bi-directional>yes</bi-directional>
                    </static-ip>
                  </source-translation>
                </entry>
              </rules>
            </nat>
          </rulebase>
        </entry>
      </vsys>
    </entry>
  </devices>
</config>
"""


@pytest.fixture(scope="module")
def nat():
    return PANOSParser(NAT).parse()


def test_pat_on_an_interface_becomes_a_dynamic_overload_entry(nat):
    entry = next(d for d in nat.nat.dynamic_entries if d.interface == "ethernet1/9")
    assert entry.overload is True                     # dynamic-ip-and-port = PAT
    assert entry.acl == "nat-source-pat-to-internet"


def test_translated_address_is_a_member_list_under_the_dynamic_branches(nat):
    pool = next(d for d in nat.nat.dynamic_entries if d.pool == "PUBLIC-POOL")
    assert pool.overload is True                      # dynamic-ip-and-port
    assert pool.interface is None

    dyn = next(d for d in nat.nat.dynamic_entries if d.pool == "192.0.2.128/27")
    assert dyn.overload is False                      # dynamic-ip: no port overload


def test_static_source_nat_is_a_static_entry_with_a_text_translated_address(nat):
    entry = next(s for s in nat.nat.static_entries if str(s.global_ip) == "192.0.2.99")
    assert str(entry.local_ip) == "10.33.0.9"
    assert entry.direction == "inside"


def test_every_source_nat_rule_carries_its_own_address_set_as_an_acl(nat):
    """NATDynamicEntry.acl must name the addresses being translated. PAN-OS keeps
    them inline on the rule, so the parser materializes them — and the nat→acl
    edge resolves instead of dangling, which is why source NAT was skipped before.
    """
    acl_names = {a.name for a in nat.acls}
    assert "nat-source-pat-to-internet" in acl_names

    acl = next(a for a in nat.acls if a.name == "nat-source-pat-to-internet")
    remark = acl.entries[0].remark
    assert "src:10.30.0.0/16" in remark and "from:lan-z" in remark and "to:wan-z" in remark

    report = DependencyResolver(nat).resolve()
    assert [(d.ref_type, d.ref_name) for d in report.dangling_refs] == []
    assert ("acl", "nat-source-pat-to-internet") in {
        (link.ref_type, link.ref_name) for link in report.links
        if link.source_type == "nat" and link.resolved
    }


def test_destination_nat_still_produces_no_acl(nat):
    """Only source-NAT rules get a materialized address set — a destination-NAT
    rule references none, so inventing one would be an orphan node."""
    assert not any(a.name.startswith("nat-source-dnat") for a in nat.acls)
