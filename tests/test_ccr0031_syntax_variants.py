"""CCR-0031 — per-command syntax-variant pattern sets.

Each test feeds an alternate valid vendor spelling of a command and asserts it
parses to the SAME model as its canonical twin (value assertions, handbook
§7.5), plus:
  - a subclass-inheritance test proving a subclass picked up the shared
    interface-VRF pattern set (§7.3);
  - an over-trigger negative: a malformed spelling must still NOT parse.
"""
from ipaddress import IPv4Address, IPv4Interface

from confgraph.parsers.base import PatternSet
from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.eos_parser import EOSParser
from confgraph.parsers.nxos_parser import NXOSParser
from confgraph.parsers.iosxr_parser import IOSXRParser


def _ios(body):
    return IOSParser("hostname T\n!\n" + body + "\n").parse()


def _eos(body):
    return EOSParser("hostname T\n!\n" + body + "\n").parse()


def _nxos(body):
    return NXOSParser("hostname T\n!\n" + body + "\n").parse()


def _iosxr(body):
    return IOSXRParser("hostname T\n!\n" + body + "\n").parse()


# --------------------------------------------------------------------------
# The mechanism itself
# --------------------------------------------------------------------------

def test_patternset_first_match_and_union_dedupes_group_names():
    ps = PatternSet(r"^a\s+(?P<x>\d+)", r"^b\s+(?P<x>\d+)")
    assert ps.match("b 7").group("x") == "7"
    assert ps.match("c 7") is None
    # union demotes the duplicate named group so it compiles as one regex
    import re
    assert re.compile(ps.union).match("a 1") and re.compile(ps.union).match("b 2")


def test_patternset_extended_leaves_parent_untouched():
    parent = PatternSet(r"^p\s+(?P<x>\d+)")
    child = parent.extended(r"^q\s+(?P<x>\d+)")
    assert child.match("q 1") is not None
    assert parent.match("q 1") is None  # parent unchanged — safe to share


# --------------------------------------------------------------------------
# IOS: alternate spelling == canonical twin
# --------------------------------------------------------------------------

def test_ios_ip_vrf_equals_vrf_definition():
    old = _ios("ip vrf C\n rd 65000:1\n route-target import 1:1")
    new = _ios("vrf definition C\n rd 65000:1\n address-family ipv4\n  route-target import 1:1")
    assert [v.name for v in old.vrfs] == [v.name for v in new.vrfs] == ["C"]
    assert old.vrfs[0].rd == new.vrfs[0].rd == "65000:1"
    assert old.vrfs[0].route_target_import == new.vrfs[0].route_target_import == ["1:1"]


def test_ios_ip_vrf_forwarding_equals_vrf_forwarding():
    old = _ios("interface Gig0/0\n ip vrf forwarding C\n ip address 1.1.1.1 255.255.255.0")
    new = _ios("interface Gig0/0\n vrf forwarding C\n ip address 1.1.1.1 255.255.255.0")
    assert old.interfaces[0].vrf == new.interfaces[0].vrf == "C"


def test_ios_numbered_acl_parses():
    pc = _ios("access-list 10 permit 10.0.0.0 0.0.0.255")
    assert [a.name for a in pc.acls] == ["10"]
    assert pc.acls[0].acl_type == "standard"
    assert pc.acls[0].entries[0].action == "permit"


def test_ios_prefix_list_noseq_equals_seq():
    noseq = _ios("ip prefix-list PL permit 10.0.0.0/8")
    seq = _ios("ip prefix-list PL seq 5 permit 10.0.0.0/8")
    assert str(noseq.prefix_lists[0].sequences[0].prefix) == \
        str(seq.prefix_lists[0].sequences[0].prefix) == "10.0.0.0/8"
    assert noseq.prefix_lists[0].sequences[0].action == "permit"


def test_ios_ospf_legacy_spf_timers():
    old = _ios("router ospf 1\n timers spf 5 10")
    assert old.ospf_instances[0].timers_throttle_spf_initial == 5
    assert old.ospf_instances[0].timers_throttle_spf_min == 10


def test_ios_ip_sla_monitor_equals_ip_sla():
    old = _ios("ip sla monitor 1\n type echo protocol ipIcmpEcho 10.0.0.1")
    new = _ios("ip sla 1\n icmp-echo 10.0.0.1")
    assert old.ip_sla_operations[0].sla_id == new.ip_sla_operations[0].sla_id == 1
    assert old.ip_sla_operations[0].operation_type == new.ip_sla_operations[0].operation_type == "icmp-echo"
    assert str(old.ip_sla_operations[0].destination) == "10.0.0.1"


def test_ios_numbered_community_list():
    pc = _ios("ip community-list 1 permit 65000:1")
    assert [c.name for c in pc.community_lists] == ["1"]
    assert pc.community_lists[0].entries[0].communities == ["65000:1"]


# --------------------------------------------------------------------------
# EOS: EOS-native spelling == IOS-inherited twin
# --------------------------------------------------------------------------

def test_eos_vrf_definition_equals_vrf_instance():
    old = _eos("vrf definition C\n   rd 65000:1")
    new = _eos("vrf instance C\n   rd 65000:1")
    assert [v.name for v in old.vrfs] == [v.name for v in new.vrfs] == ["C"]
    assert old.vrfs[0].rd == new.vrfs[0].rd == "65000:1"


def test_eos_bare_router_id_equals_bgp_router_id():
    bare = _eos("router bgp 65000\n   router-id 1.1.1.1")
    pref = _eos("router bgp 65000\n   bgp router-id 1.1.1.1")
    assert bare.bgp_instances[0].router_id == pref.bgp_instances[0].router_id == IPv4Address("1.1.1.1")


def test_eos_maximum_routes_alias_equals_maximum_prefix():
    native = _eos("router bgp 65000\n   neighbor 2.2.2.2 remote-as 65001\n   neighbor 2.2.2.2 maximum-routes 12000")
    ios = _eos("router bgp 65000\n   neighbor 2.2.2.2 remote-as 65001\n   neighbor 2.2.2.2 maximum-prefix 12000")
    n1 = native.bgp_instances[0].neighbors[0]
    n2 = ios.bgp_instances[0].neighbors[0]
    assert n1.maximum_prefix == n2.maximum_prefix == 12000


def test_eos_prefix_list_single_line_equals_block():
    line = _eos("ip prefix-list PL seq 10 permit 10.0.0.0/8")
    block = _eos("ip prefix-list PL\n   seq 10 permit 10.0.0.0/8")
    assert str(line.prefix_lists[0].sequences[0].prefix) == str(block.prefix_lists[0].sequences[0].prefix)
    assert line.prefix_lists[0].sequences[0].sequence == block.prefix_lists[0].sequences[0].sequence == 10


def test_eos_community_list_expanded():
    pc = _eos("ip community-list expanded CE permit _65000:.*_")
    assert pc.community_lists[0].name == "CE"
    assert pc.community_lists[0].list_type == "expanded"


def test_eos_vxlan_vlan_add_equals_plain():
    add = _eos("interface Vxlan1\n   vxlan source-interface Loopback0\n   vxlan vlan add 10 vni 10010")
    plain = _eos("interface Vxlan1\n   vxlan source-interface Loopback0\n   vxlan vlan 10 vni 10010")
    assert add.vxlan.vni_mappings[0].vni == plain.vxlan.vni_mappings[0].vni == 10010
    assert add.vxlan.vni_mappings[0].vlan == plain.vxlan.vni_mappings[0].vlan == 10


# --------------------------------------------------------------------------
# NX-OS: native spelling parses (inherited pattern sets)
# --------------------------------------------------------------------------

def test_nxos_global_cidr_static_route():
    pc = _nxos("ip route 10.0.0.0/8 192.168.1.1")
    assert str(pc.static_routes[0].destination) == "10.0.0.0/8"
    assert pc.static_routes[0].next_hop == IPv4Address("192.168.1.1")


def test_nxos_hsrp_block_equals_ios_standby():
    block = _nxos("interface Ethernet1/1\n  no switchport\n  hsrp 1\n    ip 10.0.0.254\n    priority 110\n    preempt")
    flat = _ios("interface Gig0/0\n standby 1 ip 10.0.0.254\n standby 1 priority 110\n standby 1 preempt")
    bg = block.interfaces[0].hsrp_groups[0]
    fg = flat.interfaces[0].hsrp_groups[0]
    assert bg.group_number == fg.group_number == 1
    assert bg.virtual_ip == fg.virtual_ip == IPv4Address("10.0.0.254")
    assert bg.priority == fg.priority == 110
    assert bg.preempt == fg.preempt is True


def test_nxos_hsrp_version():
    pc = _nxos("interface Ethernet1/1\n  no switchport\n  hsrp version 2\n  hsrp 10\n    ip 10.0.0.254")
    g = pc.interfaces[0].hsrp_groups[0]
    assert g.group_number == 10 and g.version == 2


def test_nxos_vrrp_block():
    pc = _nxos("interface Ethernet1/1\n  no switchport\n  vrrp 5\n    address 10.0.0.254\n    priority 120")
    g = pc.interfaces[0].vrrp_groups[0]
    assert g.group_number == 5
    assert g.virtual_ip == IPv4Address("10.0.0.254")
    assert g.priority == 120


def test_nxos_interface_secondary_cidr():
    pc = _nxos("interface Ethernet1/1\n  no switchport\n  ip address 10.0.0.1/24\n  ip address 10.0.1.1/24 secondary")
    assert pc.interfaces[0].secondary_ips == [IPv4Interface("10.0.1.1/24")]


def test_nxos_ospf_string_tag():
    pc = _nxos("router ospf UNDERLAY\n  router-id 1.1.1.1")
    assert pc.ospf_instances[0].process_id == "UNDERLAY"


def test_nxos_numbered_acl_inherited():
    pc = _nxos("access-list 100 permit ip any any")
    assert [a.name for a in pc.acls] == ["100"]
    assert pc.acls[0].acl_type == "extended"


# --------------------------------------------------------------------------
# IOS-XR
# --------------------------------------------------------------------------

def test_iosxr_ospf_named():
    pc = _iosxr("router ospf CORE\n router-id 1.1.1.1\n!")
    assert pc.ospf_instances[0].process_id == "CORE"


def test_iosxr_ipv4_secondary():
    pc = _iosxr(
        "interface GigabitEthernet0/0/0/0\n"
        " ipv4 address 10.0.0.1 255.255.255.0\n"
        " ipv4 address 10.0.1.1 255.255.255.0 secondary\n!"
    )
    assert pc.interfaces[0].ip_address == IPv4Interface("10.0.0.1/24")
    assert pc.interfaces[0].secondary_ips == [IPv4Interface("10.0.1.1/24")]


# --------------------------------------------------------------------------
# Subclass inheritance (§7.3): EOS extends the shared interface-VRF set
# --------------------------------------------------------------------------

def test_eos_interface_vrf_uses_inherited_pattern_set():
    # EOS does NOT override _extract_interface_vrf; it only extends
    # _IFACE_VRF_PATTERNS. Both the in-scope old "vrf forwarding" spelling
    # (from the parent set) and EOS-native bare "vrf" resolve to the same VRF.
    assert "_extract_interface_vrf" not in EOSParser.__dict__
    old = _eos("interface Ethernet1\n   no switchport\n   vrf forwarding C\n   ip address 1.1.1.1/30")
    native = _eos("interface Ethernet1\n   no switchport\n   vrf C\n   ip address 1.1.1.1/30")
    assert old.interfaces[0].vrf == native.interfaces[0].vrf == "C"


# --------------------------------------------------------------------------
# Over-trigger negatives — a dialect fix must not swallow malformed forms
# --------------------------------------------------------------------------

def test_over_trigger_malformed_forms_do_not_parse():
    assert _ios("ip vrffoo BAR\n rd 1:1").vrfs == []           # not "ip vrf"
    assert _ios("access-list 10 xyz 1.2.3.4").acls == []        # invalid action
    assert _ios("access-list 700 permit 0000.0000.0000").acls == []  # MAC range, not IP ACL
    assert _ios("ip route garbage").static_routes == []         # malformed static
    assert _nxos("ip routX 10.0.0.0/8 1.1.1.1").static_routes == []
