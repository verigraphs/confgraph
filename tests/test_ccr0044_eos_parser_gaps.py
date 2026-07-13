"""CCR-0044 — Arista EOS parser gaps.

The headline defect: EOS BGP neighbor policy (route-map, prefix-list, timers,
local-as) was parsed into nothing.  ``EOSParser`` overrode
``_parse_bgp_neighbors`` and rebuilt the neighbor list in its own loop, and that
loop knew only six commands.  The override existed for **one** genuine Arista
difference — EOS emits ``neighbor X peer group NAME`` (two words) where IOS
emits ``peer-group`` (hyphen) — and the copied loop then rotted: it never
learned the commands the shared IOS loop learned, so every policy binding on
every Arista peer came back ``None`` while the route-maps and prefix-lists they
named parsed perfectly as standalone objects.

The fix deletes the fork.  The two-word spelling is declared as a **verb alias**
(``_BGP_CMD_ALIASES``), normalised in one place — ``_bgp_neighbor_commands`` —
and EOS then runs the shared walk unchanged, inheriting every neighbor command
the Cisco family understands, now and in future.

The load-bearing test here is therefore not "route_map_in is RM-IN"; it is
``test_eos_does_not_fork_the_neighbor_walk`` plus
``test_eos_and_ios_agree_once_the_dialect_is_normalised``: re-forking the walk
breaks them even if the forker remembers to copy today's commands across.

Syntax provenance: every EOS config line below is device-emitted syntax already
exercised by the committed coverage fixtures ``_work/eos_full.cfg`` and
``_work/eos_variants.py`` (two-word ``peer group``, ``maximum-routes``,
``password 7 <hash>``, ``route-map … in|out``, ``prefix-list … in``,
``timers``, ``local-as … no-prepend replace-as``, ``bfd default``,
``area … default-cost``).  Names, IPs and ASNs are this file's own, so a fix
that hardcodes fixture values fails here.
"""

from ipaddress import IPv4Address

from confgraph.parsers.eos_parser import EOSParser
from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.nxos_parser import NXOSParser


# EOS as the device emits it: peer groups declared with two words.
EOS_BGP = """\
router bgp 64500
   router-id 10.255.0.9
   neighbor UPSTREAM peer group
   neighbor UPSTREAM remote-as 64501
   neighbor UPSTREAM ebgp-multihop 3
   neighbor UPSTREAM maximum-routes 250000
   neighbor UPSTREAM send-community
   neighbor 198.51.100.7 peer group UPSTREAM
   neighbor 198.51.100.7 description TRANSIT-A
   neighbor 198.51.100.7 password 7 0A5C1B0E1D2F
   neighbor 198.51.100.7 route-map RM-TRANSIT-IN in
   neighbor 198.51.100.7 route-map RM-TRANSIT-OUT out
   neighbor 198.51.100.7 prefix-list PL-TRANSIT in
   neighbor 198.51.100.7 timers 5 15
   neighbor 198.51.100.7 local-as 64599 no-prepend replace-as
   neighbor 198.51.100.7 update-source Loopback0
"""

# The identical device, de-dialected — built by applying the parser's OWN alias
# table to the text. If the two entries in _BGP_CMD_ALIASES are the whole EOS
# dialect (the claim this fix rests on), then this is a valid IOS rendering of
# the same session and both parsers must produce the same model.
IOS_BGP = EOS_BGP
for _native, _canonical in EOSParser._BGP_CMD_ALIASES.items():
    IOS_BGP = IOS_BGP.replace(f" {_native} ", f" {_canonical} ").replace(
        f" {_native}\n", f" {_canonical}\n"
    )


def _nbr(parsed, ip="198.51.100.7"):
    bgp = parsed.bgp_instances[0]
    return next(n for n in bgp.neighbors if str(n.peer_ip) == ip)


def _pg(parsed, name="UPSTREAM"):
    bgp = parsed.bgp_instances[0]
    return next(p for p in bgp.peer_groups if p.name == name)


# ---------------------------------------------------------------------------
# The mechanism: EOS must not own a neighbor walk at all.
# ---------------------------------------------------------------------------

def test_eos_does_not_fork_the_neighbor_walk():
    """EOS inherits the shared Cisco-family neighbor/peer-group walk.

    A future EOS-only re-implementation of either method reintroduces CCR-0044
    the moment IOS learns a command EOS's copy does not.
    """
    assert EOSParser._parse_bgp_neighbors is IOSParser._parse_bgp_neighbors
    assert EOSParser._parse_bgp_peer_groups is IOSParser._parse_bgp_peer_groups


def test_eos_bgp_dialect_is_exactly_two_verb_aliases():
    """The whole EOS-vs-IOS neighbor dialect is data, not control flow."""
    assert EOSParser._BGP_CMD_ALIASES == {
        "maximum-routes": "maximum-prefix",
        "peer group": "peer-group",
    }


def test_eos_and_ios_agree_once_the_dialect_is_normalised():
    """The CCR's own proof: feed the same session to both parsers, changing only
    the one token that genuinely differs, and every field must match."""
    eos_n = _nbr(EOSParser(EOS_BGP).parse())
    ios_n = _nbr(IOSParser(IOS_BGP).parse())

    fields = (
        "remote_as", "peer_group", "description", "update_source", "password",
        "password_encryption_type", "route_map_in", "route_map_out",
        "prefix_list_in", "prefix_list_out", "timers", "local_as",
        "local_as_no_prepend", "local_as_replace_as",
    )
    assert {f: getattr(eos_n, f) for f in fields} == {
        f: getattr(ios_n, f) for f in fields
    }

    eos_pg, ios_pg = _pg(EOSParser(EOS_BGP).parse()), _pg(IOSParser(IOS_BGP).parse())
    assert eos_pg.model_dump() == ios_pg.model_dump()


# ---------------------------------------------------------------------------
# E-1: the policy bindings themselves (values, never presence — CCR-0030).
# ---------------------------------------------------------------------------

def test_eos_neighbor_policy_is_attached():
    n = _nbr(EOSParser(EOS_BGP).parse())

    assert n.route_map_in == "RM-TRANSIT-IN"
    assert n.route_map_out == "RM-TRANSIT-OUT"
    assert n.prefix_list_in == "PL-TRANSIT"
    assert n.timers is not None
    assert (n.timers.keepalive, n.timers.holdtime) == (5, 15)
    assert n.local_as == 64599
    assert n.local_as_no_prepend is True
    assert n.local_as_replace_as is True


def test_eos_neighbor_keeps_what_the_old_fork_did_parse():
    """The six commands the fork knew must survive the fork's removal."""
    n = _nbr(EOSParser(EOS_BGP).parse())

    assert n.peer_ip == IPv4Address("198.51.100.7")
    assert n.peer_group == "UPSTREAM"
    assert n.description == "TRANSIT-A"
    assert n.update_source == "Loopback0"
    # password splits into key + encryption type (CCR-0030 bug 4), not one blob
    assert n.password == "0A5C1B0E1D2F"
    assert n.password_encryption_type == "7"
    # remote-as is inherited from the peer group, not restated on the neighbor
    assert n.remote_as == "inherited"


def test_eos_peer_group_two_word_form_and_maximum_routes():
    """``neighbor NAME peer group`` declares the group; ``maximum-routes`` is
    EOS's spelling of ``maximum-prefix`` and must reach the group, not just the
    neighbor — the peer-group walk never applied the alias before."""
    pg = _pg(EOSParser(EOS_BGP).parse())

    assert pg.remote_as == 64501
    assert pg.ebgp_multihop == 3
    assert pg.maximum_prefix == 250000
    assert pg.send_community is True
    # the bare "neighbor UPSTREAM peer group" declaration is not an attribute
    assert pg.description is None


def test_eos_peer_group_is_not_mistaken_for_a_neighbor():
    bgp = EOSParser(EOS_BGP).parse().bgp_instances[0]

    assert [str(n.peer_ip) for n in bgp.neighbors] == ["198.51.100.7"]
    assert [p.name for p in bgp.peer_groups] == ["UPSTREAM"]


def test_eos_still_accepts_the_hyphenated_ios_spelling():
    """EOS tolerates the IOS spelling; normalising the dialect must not lose it."""
    n = _nbr(EOSParser(IOS_BGP).parse())

    assert n.peer_group == "UPSTREAM"
    assert n.route_map_in == "RM-TRANSIT-IN"


# ---------------------------------------------------------------------------
# Siblings: the shared walk is inherited by four parsers — prove they still work.
# ---------------------------------------------------------------------------

def test_ios_peer_group_walk_unchanged():
    n = _nbr(IOSParser(IOS_BGP).parse())
    pg = _pg(IOSParser(IOS_BGP).parse())

    assert n.peer_group == "UPSTREAM"
    assert n.route_map_in == "RM-TRANSIT-IN"
    assert pg.remote_as == 64501
    assert pg.maximum_prefix == 250000


def test_the_dialect_is_additive_not_universal():
    """An alias belongs to the OS that declares it. IOS has none, so EOS's
    ``maximum-routes`` must NOT become readable on IOS as a side effect."""
    assert IOSParser._BGP_CMD_ALIASES == {}

    pg = _pg(IOSParser(
        "router bgp 64500\n"
        " neighbor UPSTREAM peer-group\n"
        " neighbor UPSTREAM remote-as 64501\n"
        " neighbor UPSTREAM maximum-routes 250000\n"
    ).parse())

    assert pg.remote_as == 64501
    assert pg.maximum_prefix is None


def test_nxos_neighbor_walk_unchanged():
    """NX-OS calls the shared IOS walk via super(); it declares no aliases."""
    cfg = """\
router bgp 64500
  neighbor 198.51.100.7 remote-as 64501
    description TRANSIT-A
    route-map RM-TRANSIT-IN in
"""
    n = _nbr(NXOSParser(cfg).parse())

    assert n.remote_as == 64501
    assert n.description == "TRANSIT-A"
    assert n.route_map_in == "RM-TRANSIT-IN"


# ---------------------------------------------------------------------------
# E-2: OSPF — area default-cost (shared IOS walk) and EOS's "bfd default".
# ---------------------------------------------------------------------------

EOS_OSPF = """\
router ospf 3
   router-id 10.255.0.9
   area 0.0.0.7 stub no-summary
   area 0.0.0.7 default-cost 25
   bfd default
"""


def test_eos_ospf_area_default_cost_and_bfd_default():
    o = EOSParser(EOS_OSPF).parse().ospf_instances[0]
    area = next(a for a in o.areas if a.area_id == "0.0.0.7")

    assert area.default_cost == 25
    assert area.area_type == "totally_stub"
    assert area.stub_no_summary is True
    # EOS spells process-wide BFD "bfd default"; IOS spells it "bfd all-interfaces"
    assert o.bfd_all_interfaces is True


def test_ios_ospf_area_default_cost_shares_the_fix():
    """``area X default-cost N`` had no branch in the shared walk at all, so IOS
    and NX-OS dropped it too. One branch, three OSes (handbook §7.3)."""
    o = IOSParser(
        "router ospf 3\n"
        " area 7 stub no-summary\n"
        " area 7 default-cost 25\n"
        " bfd all-interfaces\n"
    ).parse().ospf_instances[0]
    area = next(a for a in o.areas if a.area_id == "7")

    assert area.default_cost == 25
    assert o.bfd_all_interfaces is True


def test_ios_does_not_accept_the_eos_bfd_spelling():
    """The dialect is additive on EOS, not universal: "bfd default" is not IOS."""
    o = IOSParser("router ospf 3\n bfd default\n").parse().ospf_instances[0]

    assert o.bfd_all_interfaces is False


# ---------------------------------------------------------------------------
# E-2: banner, VARP, BFD, prefix-list — each an EOS rendering the parser was
# looking for in Cisco's spelling. Syntax per syntax-corpus/eos/.
# ---------------------------------------------------------------------------

def test_eos_banner_is_terminated_by_eof_not_a_delimiter():
    """EOS emits a BARE "banner motd" header and closes with a literal EOF line;
    IOS puts a delimiter char on the header. The body may contain "!" and even a
    repeat of any character — only EOF ends it (syntax-corpus/eos/system.yaml)."""
    p = EOSParser(
        "banner motd\n"
        "Authorized access only!\n"
        "Contact netops@example.net\n"
        "EOF\n"
        "!\n"
        "hostname sw1\n"
    ).parse()

    assert p.banners is not None
    assert p.banners.motd == "Authorized access only!\nContact netops@example.net"


def test_eos_still_accepts_the_ios_delimiter_banner():
    """Adding the EOS rendering must not cost the delimiter one, which EOS also
    tolerates. (Single-char delimiter: with `^C` the parser has always taken `^`
    as the delimiter and left the `C` in the body — pre-existing, out of scope.)"""
    p = EOSParser("banner motd #Authorized access only#\n").parse()

    assert p.banners.motd == "Authorized access only"


def test_ios_banner_unchanged():
    p = IOSParser("banner motd #Authorized access only#\n").parse()

    assert p.banners.motd == "Authorized access only"


def test_ios_does_not_accept_the_eos_eof_banner():
    """The EOF rendering belongs to the OS that declares it."""
    p = IOSParser("banner motd\nAuthorized access only\nEOF\n").parse()

    assert p.banners is None


def test_eos_varp_addresses_accumulate():
    """VARP is emitted one line per address, so the field is a list. It is also
    NOT the PAN-OS `virtual_router` field (a routing-instance name) — writing an
    Arista anycast IP into that field is the CCR-0030 class of error."""
    p = EOSParser(
        "interface Vlan24\n"
        "   ip address 10.73.0.123/24\n"
        "   ip virtual-router address 10.73.0.1\n"
        "   ip virtual-router address 10.73.0.2\n"
    ).parse()
    vlan = next(i for i in p.interfaces if i.name == "Vlan24")

    assert [str(a) for a in vlan.varp_addresses] == ["10.73.0.1", "10.73.0.2"]
    assert vlan.virtual_router is None  # PAN-OS field, untouched


def test_eos_interface_bfd_reads_both_min_rx_spellings():
    """BOTH spellings are Arista's and the difference is EOS VERSION, not vendor:
    EOS-4.13 emits "min_rx" (underscore, same as IOS/NX-OS), modern EOS renders
    "min-rx" (syntax-corpus/eos/bfd.yaml). A fleet carries both, so EOS reads
    both — which extending the parent PatternSet gives for free."""
    for line, want in (
        ("   bfd interval 500 min-rx 500 multiplier 5\n", (500, 500, 5)),
        ("   bfd interval 300 min_rx 300 multiplier 3\n", (300, 300, 3)),
    ):
        p = EOSParser("interface Ethernet1\n   no switchport\n" + line).parse()
        e1 = next(i for i in p.interfaces if i.name == "Ethernet1")

        assert (e1.bfd_interval, e1.bfd_min_rx, e1.bfd_multiplier) == want

    ios = IOSParser(
        "interface GigabitEthernet0/0\n"
        " bfd interval 300 min_rx 300 multiplier 3\n"
    ).parse()
    g0 = next(i for i in ios.interfaces if i.name == "GigabitEthernet0/0")

    assert (g0.bfd_interval, g0.bfd_min_rx, g0.bfd_multiplier) == (300, 300, 3)


def test_eos_ospf_reads_both_bfd_spellings():
    """`bfd all-interfaces` is EOS < 4.23; `bfd default` is EOS >= 4.23
    (syntax-corpus/eos/ospf.yaml: bfd-default). Both are Arista's, so EOS must
    read both — while IOS still must not read `bfd default`."""
    for line in ("   bfd default\n", "   bfd all-interfaces\n"):
        o = EOSParser("router ospf 3\n" + line).parse().ospf_instances[0]

        assert o.bfd_all_interfaces is True


def test_eos_global_bfd_reads_the_router_bfd_block():
    """Global BFD on EOS is a BLOCK whose children do not repeat the word "bfd".
    parse_bfd used to look only for a flat "bfd slow-timer" line, so it never
    fired on a real EOS config (syntax-corpus/eos/bfd.yaml: router-bfd)."""
    bfd = EOSParser(
        "router bfd\n"
        "   interval 900 min-rx 900 multiplier 50 default\n"
        "   slow-timer 5000\n"
    ).parse().bfd

    assert bfd is not None
    assert bfd.slow_timers == 5000


def test_eos_global_bfd_still_reads_the_flat_form():
    """Both renderings parse — reading the block form must not cost the flat one."""
    bfd = EOSParser("bfd slow-timer 2000\n").parse().bfd

    assert bfd is not None
    assert bfd.slow_timers == 2000


def test_eos_prefix_list_block_form_has_entries():
    """EOS emits a two-level block: bare header, then indented "seq N …" children.
    A parser that only knows Cisco's flat one-liner finds the prefix-list OBJECT
    and ZERO entries — a named-but-empty list, which is the safe-looking failure
    (syntax-corpus/eos/routing-policy.yaml: ip-prefix-list)."""
    p = EOSParser(
        "ip prefix-list PL-LOOPBACKS\n"
        "   seq 10 permit 192.168.255.0/24 eq 32\n"
        "   seq 20 deny 10.10.0.0/16\n"
    ).parse()
    pl = next(x for x in p.prefix_lists if x.name == "PL-LOOPBACKS")

    assert [(s.sequence, s.action, str(s.prefix)) for s in pl.sequences] == [
        (10, "permit", "192.168.255.0/24"),
        (20, "deny", "10.10.0.0/16"),
    ]


def test_eos_prefix_list_flat_form_still_parses():
    """A real config may carry either rendering."""
    p = EOSParser(
        "ip prefix-list PL-FLAT seq 10 permit 10.0.0.0/8 le 24\n"
    ).parse()
    pl = next(x for x in p.prefix_lists if x.name == "PL-FLAT")

    assert [(s.sequence, s.action, s.le) for s in pl.sequences] == [(10, "permit", 24)]


def test_eos_isis_is_type_is_level_2_not_level_2_only():
    """Arista's valid values are exactly level-1 | level-1-2 | level-2. The Cisco
    spelling `level-2-only` appears in no Arista source; the parser stores the
    native spelling either way (syntax-corpus/eos/isis.yaml: is-type)."""
    isis = EOSParser(
        "router isis CORE\n"
        "   net 49.0001.0000.0000.0001.00\n"
        "   is-type level-2\n"
    ).parse().isis_instances[0]

    assert isis.is_type == "level-2"
