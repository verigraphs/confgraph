"""CCR-0086 — NX-OS ACL gaps.

Device-verified n9kv 10.5(5) (own containerlab, full push+readback). Config
lines below are device-EMITTED forms recorded verified-capture in
``syntax-corpus/nxos/acl.yaml`` (ipv4-access-list / ipv6-access-list /
mac-access-list / object-group entries).

Before this fix, on NX-OS:
  * ``ipv6 access-list`` and ``mac access-list`` were dropped (walk matched
    only ``^ip access-list``);
  * ``object-group`` blocks were unmodeled (no ``ParsedConfig.object_groups``);
  * ``permit ... addrgroup OG ...`` mis-parsed (source='addrgroup',
    source_wildcard='<NAME>');
  * a standalone ``<seq> remark <text>`` ACE was dropped.

The ACL walk is SHARED IOS-family code (NX-OS inherits ``IOSParser``); the last
test pins that IPv4 ``ip access-list`` parsing is unchanged.
"""

from confgraph.parsers.nxos_parser import NXOSParser
from confgraph.parsers.ios_parser import IOSParser


def _parse_nxos(cfg: str):
    return NXOSParser(cfg).parse()


def _acl(p, name):
    return next((a for a in p.acls if a.name == name), None)


# (a) IPv6 access-list parsed with ACEs + family --------------------------------
def test_ipv6_access_list_parsed_with_family_and_aces():
    cfg = (
        "ipv6 access-list ACL_V6\n"
        "  10 permit tcp 2001:db8::/32 any eq 443\n"
        "  20 deny ipv6 any any\n"
    )
    p = _parse_nxos(cfg)
    acl = _acl(p, "ACL_V6")
    assert acl is not None, "ipv6 access-list must be modeled (was dropped)"
    assert acl.family == "ipv6"
    assert len(acl.entries) == 2
    e1, e2 = acl.entries
    assert (e1.sequence, e1.action, e1.protocol) == (10, "permit", "tcp")
    assert e1.source == "2001:db8::/32"
    assert e1.destination == "any"
    assert e1.destination_port == "eq 443"
    assert (e2.sequence, e2.action, e2.protocol) == (20, "deny", "ipv6")


# (b) MAC access-list parsed ----------------------------------------------------
def test_mac_access_list_parsed_with_family():
    cfg = (
        "mac access-list ACL_MAC\n"
        "  10 permit 0000.1111.2222 0000.0000.0000 any\n"
    )
    p = _parse_nxos(cfg)
    acl = _acl(p, "ACL_MAC")
    assert acl is not None, "mac access-list must be modeled (was dropped)"
    assert acl.family == "mac"
    assert len(acl.entries) == 1
    e = acl.entries[0]
    assert (e.sequence, e.action) == (10, "permit")
    # L2 address + mask captured; not shoehorned into IP protocol/port fields.
    assert e.source == "0000.1111.2222"
    assert e.source_wildcard == "0000.0000.0000"
    assert e.destination == "any"
    assert e.protocol is None
    assert e.source_port is None and e.destination_port is None


# (c) object-group ip address / ip port modeled with members --------------------
def test_object_groups_modeled_with_members():
    cfg = (
        "object-group ip address OG_HOSTS\n"
        "  10 host 10.199.1.1\n"
        "  20 10.199.2.0/24\n"
        "object-group ip port OG_PORTS\n"
        "  10 eq 443\n"
    )
    p = _parse_nxos(cfg)
    assert len(p.object_groups) == 2

    hosts = next(g for g in p.object_groups if g.name == "OG_HOSTS")
    assert hosts.group_type == "ip address"
    assert [(m.sequence, m.value) for m in hosts.members] == [
        (10, "host 10.199.1.1"),
        (20, "10.199.2.0/24"),
    ]

    ports = next(g for g in p.object_groups if g.name == "OG_PORTS")
    assert ports.group_type == "ip port"
    assert [(m.sequence, m.value) for m in ports.members] == [(10, "eq 443")]


# (d) addrgroup ACE recognized as a group reference, not a literal source -------
def test_addrgroup_reference_not_literal_source():
    cfg = (
        "ip access-list ACL_V4\n"
        "  20 permit tcp addrgroup OG_HOSTS any eq 443\n"
    )
    p = _parse_nxos(cfg)
    e = _acl(p, "ACL_V4").entries[0]
    assert e.protocol == "tcp"
    # The mis-parse to guard against: source='addrgroup', wildcard=name.
    assert e.source != "addrgroup"
    assert e.source_wildcard != "OG_HOSTS"
    # The correct shape: a named-group reference on the source.
    assert e.source_group == "OG_HOSTS"
    assert e.source is None
    assert e.destination == "any"
    assert e.destination_port == "eq 443"


def test_portgroup_reference_preserved_not_dropped():
    cfg = (
        "ip access-list ACL_V4\n"
        "  25 permit tcp any any portgroup OG_PORTS\n"
    )
    p = _parse_nxos(cfg)
    e = _acl(p, "ACL_V4").entries[0]
    assert e.source == "any"
    assert e.destination == "any"
    # portgroup name preserved on the port field rather than falling into flags.
    assert e.destination_port == "portgroup OG_PORTS"
    assert "portgroup" not in e.flags


# (e) standalone remark modeled as its own sequenced entry ----------------------
def test_standalone_remark_is_its_own_entry():
    cfg = (
        "ip access-list ACL_V4\n"
        "  10 remark allow web\n"
        "  20 permit ip 10.199.0.0/16 any\n"
    )
    p = _parse_nxos(cfg)
    acl = _acl(p, "ACL_V4")
    assert len(acl.entries) == 2, "standalone remark must be its own entry (was dropped)"
    remark = acl.entries[0]
    assert remark.sequence == 10
    assert remark.action == "remark"
    assert remark.remark == "allow web"


# (f) REGRESSION: IPv4 ip access-list parses identically to before --------------
def test_ipv4_ip_access_list_unchanged():
    """IPv4 named ACL semantics must be untouched by the family broadening:
    default family 'ipv4', extended grammar, per-ACE fields as before, and the
    new group fields left None for literal addresses."""
    cfg = (
        "ip access-list ACL_V4\n"
        "  30 permit ip 10.199.0.0/16 any log\n"
        "  40 deny ip any any\n"
    )
    for parser in (NXOSParser, IOSParser):
        p = parser(cfg).parse()
        acl = next(a for a in p.acls if a.name == "ACL_V4")
        assert acl.family == "ipv4"
        assert acl.acl_type == "extended"
        assert len(acl.entries) == 2

        e30 = acl.entries[0]
        assert (e30.sequence, e30.action, e30.protocol) == (30, "permit", "ip")
        assert e30.source == "10.199.0.0/16"
        assert e30.source_wildcard is None
        assert e30.destination == "any"
        assert e30.flags == ["log"]
        # New object-group fields stay None for literal addresses.
        assert e30.source_group is None and e30.destination_group is None

        e40 = acl.entries[1]
        assert (e40.sequence, e40.action, e40.protocol) == (40, "deny", "ip")
        assert e40.source == "any"
        assert e40.destination == "any"


def test_object_groups_empty_for_plain_ipv4_config():
    """No object-group lines -> empty collection, not None or an error."""
    cfg = "ip access-list ACL_V4\n  10 permit ip any any\n"
    assert _parse_nxos(cfg).object_groups == []
