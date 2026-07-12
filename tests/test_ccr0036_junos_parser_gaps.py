"""CCR-0036 — JunOS parser gaps.

The eight gaps in the CCR share one root cause: JunOS renders a single
configuration database in two device-emitted forms — the brace hierarchy
(``show configuration``) and the flat form (``show configuration | display
set``) — and the tokenizer used to build a DIFFERENT tree for each, so every
extractor grew per-statement shape branches and the awkward statements fell
through the gaps between them.

The parser now builds ONE canonical tree from either form: every node is a dict,
and a statement's trailing tokens are its nested keys.  These tests therefore
assert, above all, the CCR's own acceptance criterion — **the same device in
brace form and in set form parses to the same model** — and then pin each gap.

Syntax provenance: every config line below is device-EMITTED syntax, either
already exercised by the committed coverage fixtures or taken from
``syntax-corpus/junos/`` (which cites Juniper's own ``show`` output).  Notably:

* ``source-address`` is emitted as a CONTAINER even for one prefix, while the
  ``set`` rendering flattens it to a trailing token — the two forms genuinely
  have different tree shapes for one statement.
* ``then`` collapses to a leaf for one action and is a block for several.
* ``authentication-key`` is emitted ``$9$``-obfuscated; a device never prints a
  cleartext BGP key.
* ``multihop``: two Juniper pages disagree (container vs leaf), so the parser
  accepts both rather than betting on one.
"""

from confgraph.parsers.junos_parser import JunOSParser
from confgraph.parsers.junos_hierarchy import parse_junos_config


def P(cfg: str):
    return JunOSParser(cfg).parse()


# ---------------------------------------------------------------------------
# The acceptance criterion: brace form and set form → the same model
# ---------------------------------------------------------------------------

BRACE = """\
groups {
    COMMON {
        snmp {
            location "DC-1";
        }
    }
}
apply-groups COMMON;
system {
    host-name R99;
    ntp {
        server 10.9.0.1 prefer;
        server 10.9.0.2;
    }
}
snmp {
    community pub-r {
        authorization read-only;
    }
}
interfaces {
    ge-0/0/9 {
        mtu 9192;
        unit 0 {
            family inet {
                address 172.31.9.1/30;
            }
        }
    }
    lo0 {
        unit 0 {
            family inet {
                address 9.9.9.9/32;
            }
        }
    }
}
routing-options {
    autonomous-system 64599;
    static {
        route 0.0.0.0/0 next-hop 172.31.9.2;
        route 10.99.0.0/16 discard;
    }
}
protocols {
    bgp {
        group RR {
            type internal;
            local-address 9.9.9.9;
            hold-time 30;
            authentication-key "$9$XyZ0aBcDeFgHiJk";
            import RP-IN;
            neighbor 192.0.2.99 {
                description "RR-CLIENT";
            }
        }
        group TRANSIT {
            type external;
            peer-as 64699;
            multihop {
                ttl 3;
            }
            family inet {
                unicast {
                    prefix-limit {
                        maximum 250000;
                    }
                }
            }
            neighbor 198.51.100.99;
        }
    }
    ospf {
        export RP-OUT;
        area 0.0.0.0 {
            interface ge-0/0/9.0 {
                metric 55;
            }
        }
        area 0.0.0.9 {
            stub default-metric 25;
            interface lo0.0;
        }
    }
}
policy-options {
    community CM-TAG members [ 64599:1 64599:2 ];
    as-path AP-OWN "^64599$";
    prefix-list PL-9 {
        10.99.0.0/16;
    }
    policy-statement RP-IN {
        term t1 {
            from {
                prefix-list PL-9;
            }
            then {
                local-preference 150;
                community add CM-TAG;
                accept;
            }
        }
    }
    policy-statement RP-OUT {
        term t1 {
            then accept;
        }
    }
}
firewall {
    family inet {
        filter FW-9 {
            term ssh-term {
                from {
                    source-address {
                        192.168.99.0/24;
                    }
                    protocol tcp;
                    destination-port ssh;
                }
                then accept;
            }
            term drop-rest {
                then {
                    log;
                    discard;
                }
            }
        }
    }
}
"""

# The same device, as `show configuration | display set` prints it: one line per
# leaf statement, each carrying its full hierarchy path.  Note that the
# `source-address` container FLATTENS here — that divergence is the whole point.
SET = """\
set groups COMMON snmp location "DC-1"
set apply-groups COMMON
set system host-name R99
set system ntp server 10.9.0.1 prefer
set system ntp server 10.9.0.2
set snmp community pub-r authorization read-only
set interfaces ge-0/0/9 mtu 9192
set interfaces ge-0/0/9 unit 0 family inet address 172.31.9.1/30
set interfaces lo0 unit 0 family inet address 9.9.9.9/32
set routing-options autonomous-system 64599
set routing-options static route 0.0.0.0/0 next-hop 172.31.9.2
set routing-options static route 10.99.0.0/16 discard
set protocols bgp group RR type internal
set protocols bgp group RR local-address 9.9.9.9
set protocols bgp group RR hold-time 30
set protocols bgp group RR authentication-key "$9$XyZ0aBcDeFgHiJk"
set protocols bgp group RR import RP-IN
set protocols bgp group RR neighbor 192.0.2.99 description "RR-CLIENT"
set protocols bgp group TRANSIT type external
set protocols bgp group TRANSIT peer-as 64699
set protocols bgp group TRANSIT multihop ttl 3
set protocols bgp group TRANSIT family inet unicast prefix-limit maximum 250000
set protocols bgp group TRANSIT neighbor 198.51.100.99
set protocols ospf export RP-OUT
set protocols ospf area 0.0.0.0 interface ge-0/0/9.0 metric 55
set protocols ospf area 0.0.0.9 stub default-metric 25
set protocols ospf area 0.0.0.9 interface lo0.0
set policy-options community CM-TAG members 64599:1
set policy-options community CM-TAG members 64599:2
set policy-options as-path AP-OWN "^64599$"
set policy-options prefix-list PL-9 10.99.0.0/16
set policy-options policy-statement RP-IN term t1 from prefix-list PL-9
set policy-options policy-statement RP-IN term t1 then local-preference 150
set policy-options policy-statement RP-IN term t1 then community add CM-TAG
set policy-options policy-statement RP-IN term t1 then accept
set policy-options policy-statement RP-OUT term t1 then accept
set firewall family inet filter FW-9 term ssh-term from source-address 192.168.99.0/24
set firewall family inet filter FW-9 term ssh-term from protocol tcp
set firewall family inet filter FW-9 term ssh-term from destination-port ssh
set firewall family inet filter FW-9 term ssh-term then accept
set firewall family inet filter FW-9 term drop-rest then log
set firewall family inet filter FW-9 term drop-rest then discard
"""


class TestBraceSetEquivalence:
    """CCR-0036 acceptance: the two renderings must produce the same model."""

    def test_same_model(self):
        brace = P(BRACE).model_dump(mode="json")
        flat = P(SET).model_dump(mode="json")

        # raw_config / raw_lines / line_numbers echo the input text, which
        # legitimately differs between the two renderings.  Every *parsed* field
        # must be equal.
        echoes = ("raw_config", "raw_lines", "line_numbers", "config_text", "syntax")

        def scrub(node):
            if isinstance(node, dict):
                return {k: scrub(v) for k, v in node.items() if k not in echoes}
            if isinstance(node, list):
                return [scrub(v) for v in node]
            return node

        assert scrub(brace) == scrub(flat)

    def test_equivalence_is_not_vacuous(self):
        """Guard: the shared model is actually populated, not two empty configs."""
        pc = P(BRACE)
        assert pc.hostname == "R99"
        assert len(pc.static_routes) == 2
        assert len(pc.bgp_instances[0].neighbors) == 2
        assert pc.ospf_instances and pc.acls and pc.route_maps and pc.snmp


# ---------------------------------------------------------------------------
# Gap #1 — set-form static routes
# ---------------------------------------------------------------------------


class TestGap1SetFormStatics:

    def test_set_form_statics_parse(self):
        pc = P(
            "set routing-options static route 0.0.0.0/0 next-hop 192.168.1.1\n"
            "set routing-options static route 10.0.0.0/8 discard\n"
        )
        routes = {str(r.destination): r for r in pc.static_routes}
        assert set(routes) == {"0.0.0.0/0", "10.0.0.0/8"}
        assert str(routes["0.0.0.0/0"].next_hop) == "192.168.1.1"
        assert routes["10.0.0.0/8"].next_hop is None  # discard

    def test_set_form_static_attributes(self):
        pc = P(
            "set routing-options static route 0.0.0.0/0 next-hop 192.168.1.1\n"
            "set routing-options static route 0.0.0.0/0 preference 250\n"
            "set routing-options static route 0.0.0.0/0 tag 666\n"
        )
        route = pc.static_routes[0]
        assert route.distance == 250
        assert route.tag == 666


# ---------------------------------------------------------------------------
# Gap #2 — firewall filters: family wrapper, IPv6, and the source-address shape
# ---------------------------------------------------------------------------


class TestGap2FirewallFilters:

    def test_family_inet_filter(self):
        pc = P(
            "firewall {\n"
            "    family inet {\n"
            "        filter F4 {\n"
            "            term t1 {\n"
            "                from {\n"
            "                    source-address {\n"
            "                        10.0.0.0/8;\n"
            "                    }\n"
            "                    protocol tcp;\n"
            "                }\n"
            "                then accept;\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        acl = pc.acls[0]
        assert acl.name == "F4"
        assert acl.entries[0].action == "permit"
        # The single-prefix CONTAINER is read, not skipped.
        assert acl.entries[0].source == "10.0.0.0/8"
        assert acl.entries[0].protocol == "tcp"

    def test_family_inet6_filter(self):
        pc = P(
            "firewall {\n"
            "    family inet6 {\n"
            "        filter F6 {\n"
            "            term t1 {\n"
            "                then {\n"
            "                    log;\n"
            "                    discard;\n"
            "                }\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        assert [a.name for a in pc.acls] == ["F6"]
        assert pc.acls[0].entries[0].action == "deny"  # then-block, several actions

    def test_family_less_filter_still_parses(self):
        """[edit firewall] and [edit firewall family inet] are equivalent levels.

        The family statement is required only for a family other than IPv4, and
        the device emits back whichever form was configured — it does not
        rewrite the family-less one.  Both must parse.
        """
        pc = P(
            "firewall {\n"
            "    filter LEGACY {\n"
            "        term t1 {\n"
            "            then accept;\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        assert [a.name for a in pc.acls] == ["LEGACY"]

    def test_both_levels_coexist(self):
        pc = P(
            "firewall {\n"
            "    family inet6 {\n"
            "        filter V6 {\n"
            "            term t1 { then accept; }\n"
            "        }\n"
            "    }\n"
            "    filter V4 {\n"
            "        term t1 { then accept; }\n"
            "    }\n"
            "}\n"
        )
        assert sorted(a.name for a in pc.acls) == ["V4", "V6"]

    def test_set_form_filter(self):
        pc = P(
            "set firewall family inet filter F4 term t1 from source-address 10.0.0.0/8\n"
            "set firewall family inet filter F4 term t1 from protocol tcp\n"
            "set firewall family inet filter F4 term t1 then accept\n"
        )
        entry = pc.acls[0].entries[0]
        # Same statement, flattened rendering — same model.
        assert entry.source == "10.0.0.0/8"
        assert entry.protocol == "tcp"
        assert entry.action == "permit"

    def test_multi_prefix_source_keeps_every_prefix(self):
        """A source-address container holds one prefix per line — keep them ALL.

        ACLEntry.source is a single string (a Cisco ACE has one source), so the
        term is expanded to one entry per prefix.  Keeping only the first would
        answer "does this filter permit 10.1.2.5?" with a confident no.
        """
        pc = P(
            "firewall {\n"
            "    filter FBF {\n"
            "        term t1 {\n"
            "            from {\n"
            "                source-address {\n"
            "                    10.1.1.0/24;\n"
            "                    10.1.2.0/24;\n"
            "                }\n"
            "            }\n"
            "            then accept;\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        entries = pc.acls[0].entries
        assert [e.source for e in entries] == ["10.1.1.0/24", "10.1.2.0/24"]
        # Same term: one action, one name, one sequence.
        assert {e.action for e in entries} == {"permit"}
        assert {e.remark for e in entries} == {"t1"}
        assert {e.sequence for e in entries} == {10}

    def test_multi_prefix_set_form_agrees(self):
        pc = P(
            "set firewall filter FBF term t1 from source-address 10.1.1.0/24\n"
            "set firewall filter FBF term t1 from source-address 10.1.2.0/24\n"
            "set firewall filter FBF term t1 then accept\n"
        )
        assert [e.source for e in pc.acls[0].entries] == ["10.1.1.0/24", "10.1.2.0/24"]

    def test_source_and_destination_prefixes_cross_product(self):
        pc = P(
            "firewall {\n"
            "    filter FX {\n"
            "        term t1 {\n"
            "            from {\n"
            "                source-address {\n"
            "                    10.1.1.0/24;\n"
            "                    10.1.2.0/24;\n"
            "                }\n"
            "                destination-address {\n"
            "                    192.168.5.0/24;\n"
            "                }\n"
            "            }\n"
            "            then accept;\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        pairs = [(e.source, e.destination) for e in pc.acls[0].entries]
        assert pairs == [
            ("10.1.1.0/24", "192.168.5.0/24"),
            ("10.1.2.0/24", "192.168.5.0/24"),
        ]

    def test_excepted_prefix_is_not_emitted_as_a_match(self):
        """`except` is an EXCLUSION; ACLEntry cannot express one.

        Emitting it as a match would invert its meaning, so it is left out — the
        entry over-matches rather than mis-matching.  Recorded as a model
        limitation in CCR-0036 (see also the ACLConfig follow-ups).
        """
        pc = P(
            "firewall {\n"
            "    filter FE {\n"
            "        term t1 {\n"
            "            from {\n"
            "                source-address {\n"
            "                    0.0.0.0/0;\n"
            "                    10.0.0.0/8 except;\n"
            "                }\n"
            "            }\n"
            "            then accept;\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        assert [e.source for e in pc.acls[0].entries] == ["0.0.0.0/0"]

    def test_term_without_address_match_still_yields_one_entry(self):
        pc = P(
            "firewall {\n"
            "    filter FD {\n"
            "        term drop-rest {\n"
            "            then {\n"
            "                log;\n"
            "                discard;\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        entries = pc.acls[0].entries
        assert len(entries) == 1
        assert entries[0].source is None
        assert entries[0].action == "deny"


# ---------------------------------------------------------------------------
# Gap #3 — top-level snmp stanza
# ---------------------------------------------------------------------------


class TestGap3TopLevelSNMP:

    def test_top_level_snmp(self):
        """`snmp` is a TOP-LEVEL stanza — hierarchy level [edit snmp]."""
        pc = P(
            "snmp {\n"
            "    location \"West of Nowhere\";\n"
            "    contact \"My Engineering Group\";\n"
            "    community BasicAccess {\n"
            "        authorization read-only;\n"
            "    }\n"
            "}\n"
        )
        assert pc.snmp is not None
        assert pc.snmp.location == "West of Nowhere"
        assert pc.snmp.contact == "My Engineering Group"
        assert [(c.community_string, c.access) for c in pc.snmp.communities] == [
            ("BasicAccess", "ro")
        ]

    def test_read_write_community(self):
        pc = P(
            "set snmp community priv-rw authorization read-write\n"
        )
        assert [(c.community_string, c.access) for c in pc.snmp.communities] == [
            ("priv-rw", "rw")
        ]


# ---------------------------------------------------------------------------
# Gap #4 — apply-groups inheritance is expanded
# ---------------------------------------------------------------------------


class TestGap4ApplyGroups:
    """`show configuration` prints groups UNEXPANDED.

    The software processes only ever see the expanded form, so an unexpanded
    parse is not the device's effective configuration.
    """

    def test_inherited_value_is_visible(self):
        pc = P(
            "groups {\n"
            "    GLOBAL {\n"
            "        system {\n"
            "            host-name FROMGROUP;\n"
            "        }\n"
            "    }\n"
            "}\n"
            "apply-groups GLOBAL;\n"
            "system {\n"
            "}\n"
        )
        assert pc.hostname == "FROMGROUP"

    def test_group_body_alone_is_not_active_config(self):
        """A group is inert until an apply-groups references it."""
        pc = P(
            "groups {\n"
            "    UNUSED {\n"
            "        protocols {\n"
            "            bgp {\n"
            "                group NOPE {\n"
            "                    type internal;\n"
            "                    neighbor 10.0.0.1;\n"
            "                }\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}\n"
            "routing-options {\n"
            "    autonomous-system 65000;\n"
            "}\n"
        )
        assert pc.bgp_instances == []

    def test_explicit_value_overrides_group(self):
        pc = P(
            "groups {\n"
            "    G {\n"
            "        protocols {\n"
            "            bgp {\n"
            "                group RR {\n"
            "                    hold-time 90;\n"
            "                }\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}\n"
            "apply-groups G;\n"
            "routing-options { autonomous-system 65000; }\n"
            "protocols {\n"
            "    bgp {\n"
            "        group RR {\n"
            "            type internal;\n"
            "            hold-time 30;\n"
            "            neighbor 10.0.0.1;\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        pg = pc.bgp_instances[0].peer_groups[0]
        assert pg.timers.holdtime == 30  # explicit local value wins

    def test_first_listed_group_wins(self):
        pc = P(
            "groups {\n"
            "    A {\n"
            "        protocols { bgp { group RR { hold-time 30; } } }\n"
            "    }\n"
            "    B {\n"
            "        protocols { bgp { group RR { hold-time 90; } } }\n"
            "    }\n"
            "}\n"
            "apply-groups [ A B ];\n"
            "routing-options { autonomous-system 65000; }\n"
            "protocols {\n"
            "    bgp {\n"
            "        group RR {\n"
            "            type internal;\n"
            "            neighbor 10.0.0.1;\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        pg = pc.bgp_instances[0].peer_groups[0]
        assert pg.timers.holdtime == 30  # first name listed has priority

    def test_nested_apply_groups_beats_outer(self):
        pc = P(
            "groups {\n"
            "    OUTER {\n"
            "        protocols { bgp { group RR { hold-time 90; } } }\n"
            "    }\n"
            "    INNER {\n"
            "        protocols { bgp { group RR { hold-time 30; } } }\n"
            "    }\n"
            "}\n"
            "apply-groups OUTER;\n"
            "routing-options { autonomous-system 65000; }\n"
            "protocols {\n"
            "    bgp {\n"
            "        group RR {\n"
            "            apply-groups INNER;\n"
            "            type internal;\n"
            "            neighbor 10.0.0.1;\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        pg = pc.bgp_instances[0].peer_groups[0]
        assert pg.timers.holdtime == 30  # the nested group outranks the outer one

    def test_sets_merge_rather_than_override(self):
        pc = P(
            "groups {\n"
            "    G {\n"
            "        snmp {\n"
            "            community from-group {\n"
            "                authorization read-only;\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}\n"
            "apply-groups G;\n"
            "snmp {\n"
            "    community local {\n"
            "        authorization read-write;\n"
            "    }\n"
            "}\n"
        )
        assert sorted(c.community_string for c in pc.snmp.communities) == [
            "from-group",
            "local",
        ]

    def test_apply_groups_except_suppresses(self):
        pc = P(
            "groups {\n"
            "    G {\n"
            "        interfaces {\n"
            "            <*> {\n"
            "                mtu 9000;\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}\n"
            "apply-groups G;\n"
            "interfaces {\n"
            "    ge-0/0/0 {\n"
            "        unit 0 { family inet { address 10.0.0.1/24; } }\n"
            "    }\n"
            "    ge-0/0/1 {\n"
            "        apply-groups-except G;\n"
            "        unit 0 { family inet { address 10.0.1.1/24; } }\n"
            "    }\n"
            "}\n"
        )
        mtus = {i.name: i.mtu for i in pc.interfaces}
        assert mtus["ge-0/0/0.0"] == 9000
        assert mtus["ge-0/0/1.0"] is None  # opted out of the group

    def test_wildcard_matches_existing_nodes_only(self):
        pc = P(
            "groups {\n"
            "    G {\n"
            "        interfaces {\n"
            "            <ge-*> {\n"
            "                mtu 9192;\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}\n"
            "apply-groups G;\n"
            "interfaces {\n"
            "    ge-0/0/0 {\n"
            "        unit 0 { family inet { address 10.0.0.1/24; } }\n"
            "    }\n"
            "    xe-0/0/1 {\n"
            "        unit 0 { family inet { address 10.0.1.1/24; } }\n"
            "    }\n"
            "}\n"
        )
        mtus = {i.name: i.mtu for i in pc.interfaces}
        assert mtus["ge-0/0/0.0"] == 9192
        assert mtus["xe-0/0/1.0"] is None
        # The wildcard must not have been planted as a literal interface.
        assert not any("<" in i.name for i in pc.interfaces)

    def test_set_form_apply_groups(self):
        pc = P(
            "set groups COMMON snmp location \"DC-1\"\n"
            "set apply-groups COMMON\n"
            "set snmp community pub authorization read-only\n"
        )
        assert pc.snmp.location == "DC-1"

    def test_no_groups_is_a_no_op(self):
        tree = parse_junos_config("system { host-name R1; }")
        assert tree == {"system": {"host-name": {"R1": {}}}}


# ---------------------------------------------------------------------------
# Gap #5 — BGP group-level session attributes, and peer inheritance
# ---------------------------------------------------------------------------

BGP_GROUPS = """\
interfaces {
    lo0 {
        unit 0 {
            family inet {
                address 10.255.0.1/32;
            }
        }
    }
}
routing-options {
    autonomous-system 65000;
}
protocols {
    bgp {
        group INTERNAL {
            type internal;
            local-address 10.255.0.1;
            hold-time 30;
            authentication-key "$9$aH1j8gqQ1gjyjgjhgjgiiiii";
            neighbor 10.255.0.2;
            neighbor 10.255.0.3 {
                hold-time 60;
            }
        }
        group EXT {
            type external;
            peer-as 65001;
            multihop {
                ttl 2;
            }
            family inet {
                unicast {
                    prefix-limit {
                        maximum 500000;
                    }
                }
            }
            neighbor 192.0.2.1;
        }
    }
}
"""


class TestGap5BGPGroupAttributes:

    def test_group_attributes_on_the_group(self):
        pc = P(BGP_GROUPS)
        groups = {g.name: g for g in pc.bgp_instances[0].peer_groups}

        internal = groups["INTERNAL"]
        # local-address is an ADDRESS; update_source names an INTERFACE, so it
        # is resolved through the interface that owns the address.
        assert internal.update_source == "lo0.0"
        assert internal.password == "$9$aH1j8gqQ1gjyjgjhgjgiiiii"
        assert internal.timers.holdtime == 30
        # JunOS has no keepalive statement: it is one third of the hold time.
        assert internal.timers.keepalive == 10

        ext = groups["EXT"]
        assert ext.ebgp_multihop == 2
        assert ext.maximum_prefix == 500000

    def test_members_inherit_group_attributes(self):
        pc = P(BGP_GROUPS)
        nbrs = {str(n.peer_ip): n for n in pc.bgp_instances[0].neighbors}

        inherited = nbrs["10.255.0.2"]
        assert inherited.update_source == "lo0.0"
        assert inherited.password == "$9$aH1j8gqQ1gjyjgjhgjgiiiii"
        assert inherited.timers.holdtime == 30

        transit = nbrs["192.0.2.1"]
        assert transit.ebgp_multihop == 2
        assert transit.maximum_prefix == 500000

    def test_peer_overrides_group(self):
        pc = P(BGP_GROUPS)
        nbrs = {str(n.peer_ip): n for n in pc.bgp_instances[0].neighbors}
        # 10.255.0.3 sets its own hold-time; it still inherits the rest.
        assert nbrs["10.255.0.3"].timers.holdtime == 60
        assert nbrs["10.255.0.3"].password == "$9$aH1j8gqQ1gjyjgjhgjgiiiii"

    def test_instance_level_attribute_reaches_peers(self):
        """Session attributes are legal at bgp / group / neighbor level."""
        pc = P(
            "routing-options { autonomous-system 65000; }\n"
            "protocols {\n"
            "    bgp {\n"
            "        hold-time 45;\n"
            "        group G {\n"
            "            type internal;\n"
            "            neighbor 10.0.0.1;\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        assert pc.bgp_instances[0].peer_groups[0].timers.holdtime == 45
        assert pc.bgp_instances[0].neighbors[0].timers.holdtime == 45

    def test_multihop_container_leaf_and_set_forms_all_read(self):
        """Two Juniper pages disagree on multihop's emitted shape; accept both."""
        container = P(
            "routing-options { autonomous-system 65000; }\n"
            "protocols { bgp { group G { type external; peer-as 65001;\n"
            "    multihop {\n"
            "        ttl 2;\n"
            "    }\n"
            "    neighbor 192.0.2.1; } } }\n"
        )
        leaf = P(
            "routing-options { autonomous-system 65000; }\n"
            "protocols { bgp { group G { type external; peer-as 65001;\n"
            "    multihop 2;\n"
            "    neighbor 192.0.2.1; } } }\n"
        )
        flat = P(
            "set routing-options autonomous-system 65000\n"
            "set protocols bgp group G type external\n"
            "set protocols bgp group G peer-as 65001\n"
            "set protocols bgp group G multihop ttl 2\n"
            "set protocols bgp group G neighbor 192.0.2.1\n"
        )
        for pc in (container, leaf, flat):
            assert pc.bgp_instances[0].peer_groups[0].ebgp_multihop == 2

    def test_bare_multihop_means_default_ttl(self):
        pc = P(
            "routing-options { autonomous-system 65000; }\n"
            "protocols { bgp { group G { type external; peer-as 65001;\n"
            "    multihop;\n"
            "    neighbor 192.0.2.1; } } }\n"
        )
        assert pc.bgp_instances[0].peer_groups[0].ebgp_multihop == 64

    def test_accepted_prefix_limit_is_not_a_prefix_limit(self):
        """The soft limit must NOT be reported as a hard limit.

        `prefix-limit` tears the session down; `accepted-prefix-limit` merely
        stops accepting further routes.  They are identically shaped siblings, so
        reading `maximum` by searching for the key name — rather than walking
        family/<afi>/<safi>/prefix-limit/maximum — invents a hard limit the device
        does not have.
        """
        pc = P(
            "routing-options { autonomous-system 65000; }\n"
            "protocols {\n"
            "    bgp {\n"
            "        group G {\n"
            "            type external;\n"
            "            peer-as 65001;\n"
            "            family inet {\n"
            "                unicast {\n"
            "                    accepted-prefix-limit {\n"
            "                        maximum 900;\n"
            "                    }\n"
            "                }\n"
            "            }\n"
            "            neighbor 192.0.2.1;\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        assert pc.bgp_instances[0].peer_groups[0].maximum_prefix is None
        assert pc.bgp_instances[0].neighbors[0].maximum_prefix is None

    def test_hard_limit_alongside_soft_limit(self):
        pc = P(
            "set routing-options autonomous-system 65000\n"
            "set protocols bgp group G type external\n"
            "set protocols bgp group G peer-as 65001\n"
            "set protocols bgp group G family inet unicast prefix-limit maximum 500000\n"
            "set protocols bgp group G family inet unicast accepted-prefix-limit maximum 900\n"
            "set protocols bgp group G neighbor 192.0.2.1\n"
        )
        assert pc.bgp_instances[0].peer_groups[0].maximum_prefix == 500000

    def test_teardown_percentage_is_not_the_maximum(self):
        """`teardown <pct>` is a sibling of `maximum` inside prefix-limit."""
        pc = P(
            "routing-options { autonomous-system 65000; }\n"
            "protocols {\n"
            "    bgp {\n"
            "        group G {\n"
            "            type external;\n"
            "            peer-as 65001;\n"
            "            family inet {\n"
            "                unicast {\n"
            "                    prefix-limit {\n"
            "                        maximum 500000;\n"
            "                        teardown 90;\n"
            "                    }\n"
            "                }\n"
            "            }\n"
            "            neighbor 192.0.2.1;\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        assert pc.bgp_instances[0].peer_groups[0].maximum_prefix == 500000

    def test_unresolvable_local_address_does_not_fake_an_interface(self):
        """update_source names an interface; an unowned address is not one."""
        pc = P(
            "routing-options { autonomous-system 65000; }\n"
            "protocols {\n"
            "    bgp {\n"
            "        group G {\n"
            "            type internal;\n"
            "            local-address 10.255.0.9;\n"
            "            neighbor 10.0.0.1;\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        assert pc.bgp_instances[0].peer_groups[0].update_source is None
        assert pc.bgp_instances[0].neighbors[0].update_source is None


# ---------------------------------------------------------------------------
# Gaps #6 / #7 — OSPF export policy and stub default-metric
# ---------------------------------------------------------------------------


class TestGap6OSPFExport:

    def test_export_policy_captured(self):
        """`export` IS redistribution on JunOS — there is no `redistribute`."""
        pc = P(
            "protocols {\n"
            "    ospf {\n"
            "        export SEND-STATICS;\n"
            "        area 0.0.0.0 {\n"
            "            interface ge-0/0/1.0;\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        redist = pc.ospf_instances[0].redistribute
        assert [r.route_map for r in redist] == ["SEND-STATICS"]

    def test_multiple_export_policies(self):
        pc = P(
            "protocols {\n"
            "    ospf {\n"
            "        export [ SEND-STATICS SEND-DIRECT ];\n"
            "        area 0.0.0.0 {\n"
            "            interface ge-0/0/1.0;\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        assert [r.route_map for r in pc.ospf_instances[0].redistribute] == [
            "SEND-STATICS",
            "SEND-DIRECT",
        ]


class TestGap7OSPFStubDefaultMetric:

    def test_stub_default_metric(self):
        """`stub default-metric 10;` is a LEAF with inline options, not a block."""
        pc = P(
            "protocols {\n"
            "    ospf {\n"
            "        area 0.0.0.1 {\n"
            "            stub default-metric 10;\n"
            "            interface ge-0/0/2.0;\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        area = pc.ospf_instances[0].areas[0]
        assert area.area_type == "stub"
        assert area.default_cost == 10

    def test_totally_stubby(self):
        pc = P(
            "protocols {\n"
            "    ospf {\n"
            "        area 0.0.0.1 {\n"
            "            stub default-metric 10 no-summaries;\n"
            "            interface ge-0/0/2.0;\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        area = pc.ospf_instances[0].areas[0]
        assert area.area_type == "totally_stub"
        assert area.stub_no_summary is True
        assert area.default_cost == 10

    def test_plain_stub_has_no_default_metric(self):
        pc = P(
            "protocols {\n"
            "    ospf {\n"
            "        area 0.0.0.1 {\n"
            "            stub;\n"
            "            interface ge-0/0/2.0;\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        area = pc.ospf_instances[0].areas[0]
        assert area.area_type == "stub"
        assert area.default_cost is None

    def test_set_form_stub(self):
        """The set rendering splits the inline options across two lines."""
        pc = P(
            "set protocols ospf area 0.0.0.1 stub default-metric 10\n"
            "set protocols ospf area 0.0.0.1 stub no-summaries\n"
            "set protocols ospf area 0.0.0.1 interface ge-0/0/2.0\n"
        )
        area = pc.ospf_instances[0].areas[0]
        assert area.default_cost == 10
        assert area.stub_no_summary is True


# ---------------------------------------------------------------------------
# Gap #8 — policy community actions
# ---------------------------------------------------------------------------


class TestGap8PolicyCommunityActions:

    def test_community_add(self):
        pc = P(
            "policy-options {\n"
            "    policy-statement RP {\n"
            "        term t1 {\n"
            "            then {\n"
            "                local-preference 200;\n"
            "                community add CL-NOEXP;\n"
            "                accept;\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        sets = pc.route_maps[0].sequences[0].set_clauses
        assert [(s.set_type, s.values) for s in sets] == [
            ("local-preference", ["200"]),
            ("community add", ["CL-NOEXP"]),
        ]

    def test_community_delete_and_set(self):
        pc = P(
            "set policy-options policy-statement RP term t1 then community delete CL-OLD\n"
            "set policy-options policy-statement RP term t1 then community set CL-NEW\n"
            "set policy-options policy-statement RP term t1 then accept\n"
        )
        sets = {s.set_type: s.values for s in pc.route_maps[0].sequences[0].set_clauses}
        assert sets["community delete"] == ["CL-OLD"]
        assert sets["community set"] == ["CL-NEW"]

    def test_reject_term_is_a_deny(self):
        pc = P(
            "policy-options {\n"
            "    policy-statement RP {\n"
            "        term t1 {\n"
            "            then reject;\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        assert pc.route_maps[0].sequences[0].action == "deny"


# ---------------------------------------------------------------------------
# The canonical tree itself
# ---------------------------------------------------------------------------


class TestCanonicalTree:
    """One tree for both renderings — the property the fix is built on."""

    def test_leaf_tokens_become_nested_keys(self):
        assert parse_junos_config("routing-options { static { route 0.0.0.0/0 next-hop 1.1.1.1; } }") == {
            "routing-options": {"static": {"route": {"0.0.0.0/0": {"next-hop": {"1.1.1.1": {}}}}}}
        }

    def test_brace_and_set_agree_on_the_tree(self):
        brace = parse_junos_config(
            "protocols { bgp { group EXT { peer-as 65001; neighbor 2.2.2.2; } } }"
        )
        flat = parse_junos_config(
            "set protocols bgp group EXT peer-as 65001\n"
            "set protocols bgp group EXT neighbor 2.2.2.2\n"
        )
        assert brace == flat

    def test_bracketed_list_becomes_siblings(self):
        assert parse_junos_config("policy-options { community C members [ 1:1 2:2 ]; }") == {
            "policy-options": {"community": {"C": {"members": {"1:1": {}, "2:2": {}}}}}
        }

    def test_quoted_value_is_one_key_without_quotes(self):
        assert parse_junos_config('system { host-name "my router"; }') == {
            "system": {"host-name": {"my router": {}}}
        }

    def test_block_and_flat_route_forms_coexist(self):
        """CCR-0032's sibling poisoning cannot recur: `route` is always a dict."""
        tree = parse_junos_config(
            "routing-options {\n"
            "    static {\n"
            "        route 0.0.0.0/0 {\n"
            "            next-hop 172.16.1.2;\n"
            "            preference 250;\n"
            "        }\n"
            "        route 192.168.0.0/16 discard;\n"
            "    }\n"
            "}\n"
        )
        routes = tree["routing-options"]["static"]["route"]
        assert set(routes) == {"0.0.0.0/0", "192.168.0.0/16"}
        assert routes["0.0.0.0/0"]["preference"] == {"250": {}}
        assert routes["192.168.0.0/16"] == {"discard": {}}
