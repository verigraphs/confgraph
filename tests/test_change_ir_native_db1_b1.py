"""WI-DB1-B1 (task #40) — blind-negation batch 1: interface-child negations.

CCR: ``change_ir_proposal_operations.md`` Appendix AA.

Parser side.  Two sub-classes, both previously silently dropped
(base.py skips interface-child ``no …`` lines from unrecognized flagging;
no tombstone registry entry existed):

- sub-class A — interface boolean UNSETs (`no spanning-tree guard root`,
  `no switchport port-security mac-address sticky`, `no mab` /
  `no dot1x mab`, `no ip pim bfd`) — the family-1 mechanism (native UNSET +
  byte-exact len-4 tombstone in InterfaceConfig.no_commands),
- sub-class B — interface container removals (`no standby N`, NX-OS
  `no hsrp N`, `no vrrp N`, `no glbp N`, `no standby N ip [A]` VIP reset,
  `no ip address A M secondary` dotted+CIDR, `no ip igmp
  join-group|static-group G`) — NestedDeletionRule entries riding the
  family-8e member machinery (native LIST_REMOVE + byte-exact 5-segment
  tombstone regenerated FROM the op).
"""

from __future__ import annotations

from confgraph.change_ir import (
    IFACE_MEMBER_REMOVAL_FIELDS,
    Verb,
    derive_ops,
    encode_legacy,
    is_native_iface_member_op,
)
from confgraph.parsers.eos_parser import EOSParser
from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.iosxr_parser import IOSXRParser
from confgraph.parsers.nxos_parser import NXOSParser


def _unsets(ops, iface=None, field=None):
    out = [
        op
        for op in ops
        if op.origin == "native"
        and op.verb is Verb.UNSET
        and len(op.path) == 4
        and op.path[:2] == ("field", "interface")
    ]
    if iface is not None:
        out = [op for op in out if op.path[2] == iface]
    if field is not None:
        out = [op for op in out if op.path[3] == field]
    return out


def _removals(ops, kind=None):
    out = [
        op
        for op in ops
        if is_native_iface_member_op(op) and op.verb is Verb.LIST_REMOVE
    ]
    if kind is not None:
        out = [op for op in out if op.path[3] == kind]
    return out


# ---------------------------------------------------------------------------
# Sub-class A — boolean UNSETs
# ---------------------------------------------------------------------------

SUBCLASS_A_CFG = """hostname r1
interface GigabitEthernet0/1
 no spanning-tree guard root
 no switchport port-security mac-address sticky
 no mab
 no ip pim bfd
interface GigabitEthernet0/2
 no dot1x mab
"""


class TestSubclassAEmission:
    def test_all_four_unsets_emitted_with_provenance(self):
        pc = IOSParser(SUBCLASS_A_CFG).parse()
        ops = derive_ops(pc)
        got = {
            op.path[3]: (op.source_line, op.line_no)
            for op in _unsets(ops, "GigabitEthernet0/1")
        }
        assert set(got) == {
            "stp_root_guard",
            "port_security_sticky",
            "dot1x_mab",
            "pim_bfd",
        }
        assert got["stp_root_guard"][0] == "no spanning-tree guard root"
        assert all(line_no >= 0 for _, line_no in got.values())

    def test_both_mab_spellings(self):
        pc = IOSParser(SUBCLASS_A_CFG).parse()
        ops = derive_ops(pc)
        (dot1x_form,) = _unsets(ops, "GigabitEthernet0/2", "dot1x_mab")
        assert dot1x_form.source_line == "no dot1x mab"

    def test_tombstones_land_in_interface_no_commands_byte_exact(self):
        pc = IOSParser(SUBCLASS_A_CFG).parse()
        gi1 = next(i for i in pc.interfaces if i.name == "GigabitEthernet0/1")
        assert gi1.no_commands == [
            "field:interface:GigabitEthernet0/1:stp_root_guard",
            "field:interface:GigabitEthernet0/1:port_security_sticky",
            "field:interface:GigabitEthernet0/1:dot1x_mab",
            "field:interface:GigabitEthernet0/1:pim_bfd",
        ]
        # Single-source: encode_legacy over the ops reproduces the container.
        art = encode_legacy(_unsets(derive_ops(pc), "GigabitEthernet0/1"))
        assert art.interface_no_commands["GigabitEthernet0/1"] == gi1.no_commands

    def test_fields_parse_to_default_false(self):
        # The negation lines themselves must not leak into the positive parse.
        pc = IOSParser(SUBCLASS_A_CFG).parse()
        gi1 = next(i for i in pc.interfaces if i.name == "GigabitEthernet0/1")
        assert gi1.stp_root_guard is False
        assert gi1.port_security_sticky is False
        assert gi1.dot1x_mab is False
        assert gi1.pim_bfd is False

    def test_positive_parse_untouched_and_absence_emits_nothing(self):
        cfg = (
            "interface GigabitEthernet0/1\n"
            " spanning-tree guard root\n"
            " switchport port-security mac-address sticky\n"
            " mab\n"
            " ip pim bfd\n"
        )
        pc = IOSParser(cfg).parse()
        gi = pc.interfaces[0]
        assert gi.stp_root_guard is True
        assert gi.port_security_sticky is True
        assert gi.dot1x_mab is True
        assert gi.pim_bfd is True
        assert gi.no_commands == []
        assert not _unsets(derive_ops(pc))

    def test_bare_port_security_negation_unaffected(self):
        # The pre-existing bare form and the new sticky form are disjoint.
        cfg = (
            "interface GigabitEthernet0/1\n"
            " no switchport port-security\n"
        )
        pc = IOSParser(cfg).parse()
        (op,) = _unsets(derive_ops(pc), "GigabitEthernet0/1")
        assert op.path[3] == "port_security_enabled"

    def test_nxos_and_eos_inherit(self):
        cfg = "interface Ethernet1/1\n no spanning-tree guard root\n no mab\n"
        for parser in (NXOSParser, EOSParser):
            pc = parser(cfg).parse()
            fields = {op.path[3] for op in _unsets(derive_ops(pc))}
            assert fields == {"stp_root_guard", "dot1x_mab"}, parser


# ---------------------------------------------------------------------------
# Sub-class B — container removals
# ---------------------------------------------------------------------------

SUBCLASS_B_CFG = """hostname r1
interface Vlan100
 no standby 1 ip 10.40.1.254
 no standby 3
 no vrrp 20
 no glbp 30
 no ip address 192.168.5.1 255.255.255.0 secondary
 no ip address 192.168.6.1/24 secondary
 no ip igmp join-group 239.1.1.1
 no ip igmp static-group 239.2.2.2
"""

EXPECTED_B_TOMBSTONES = [
    "field:interface:Vlan100:hsrp_groups:3",
    "field:interface:Vlan100:hsrp_vip:1",
    "field:interface:Vlan100:vrrp_groups:20",
    "field:interface:Vlan100:glbp_groups:30",
    "field:interface:Vlan100:secondary_ips:192.168.5.1/24",
    "field:interface:Vlan100:secondary_ips:192.168.6.1/24",
    "field:interface:Vlan100:igmp_join_groups:239.1.1.1",
    "field:interface:Vlan100:igmp_static_groups:239.2.2.2",
]


class TestSubclassBEmission:
    def test_registry_kinds(self):
        for kind, field in (
            ("hsrp_groups", "hsrp_groups"),
            ("hsrp_vip", "hsrp_groups"),
            ("vrrp_groups", "vrrp_groups"),
            ("glbp_groups", "glbp_groups"),
            ("secondary_ips", "secondary_ips"),
            ("igmp_join_groups", "igmp_join_groups"),
            ("igmp_static_groups", "igmp_static_groups"),
        ):
            assert IFACE_MEMBER_REMOVAL_FIELDS[kind] == field

    def test_tombstones_byte_exact(self):
        pc = IOSParser(SUBCLASS_B_CFG).parse()
        assert sorted(pc.no_commands) == sorted(EXPECTED_B_TOMBSTONES)

    def test_native_ops_line_numbered_with_provenance(self):
        pc = IOSParser(SUBCLASS_B_CFG).parse()
        removals = _removals(derive_ops(pc))
        assert {op.path for op in removals} == {
            tuple(t.split(":")) for t in EXPECTED_B_TOMBSTONES
        }
        for op in removals:
            assert op.line_no >= 0
            assert op.source_line.startswith("no ")
        # Single-source: the tombstones regenerate byte-exactly from the ops.
        assert sorted(encode_legacy(removals).no_commands) == sorted(
            EXPECTED_B_TOMBSTONES
        )

    def test_secondary_ip_keys_are_canonical_cidr(self):
        # Dotted-mask and CIDR spellings normalize to the SAME key form —
        # the member-SET key (str(IPv4Interface)) — via the rule's `derive`.
        pc = IOSParser(SUBCLASS_B_CFG).parse()
        keys = {op.path[4] for op in _removals(derive_ops(pc), "secondary_ips")}
        assert keys == {"192.168.5.1/24", "192.168.6.1/24"}

    def test_invalid_secondary_mask_stays_blind(self):
        pc = IOSParser(
            "interface Vlan1\n no ip address 10.0.0.1 999.0.0.0 secondary\n"
        ).parse()
        assert pc.no_commands == []

    def test_derived_twin_retired_exactly_one_op_per_path(self):
        pc = IOSParser(SUBCLASS_B_CFG).parse()
        ops = derive_ops(pc)
        for t in EXPECTED_B_TOMBSTONES:
            path = tuple(t.split(":"))
            matching = [op for op in ops if op.path == path]
            assert len(matching) == 1, t
            assert matching[0].origin == "native"

    def test_no_unrecognized_disclosure_needed(self):
        # The base.py child-negation skip premise is now TRUE for the batch:
        # registry entries exist, and nothing lands in unrecognized_blocks.
        pc = IOSParser(SUBCLASS_B_CFG).parse()
        assert not pc.unrecognized_blocks


class TestFhrpGrammarBoundary:
    """Attr-reset forms beyond the HSRP VIP are deliberately LEFT BLIND
    (CCR Appendix AA.3) — the group-removal patterns must not over-match."""

    BLIND_LINES = [
        "no standby 1 priority",
        "no standby 1 priority 110",
        "no standby 1 preempt",
        "no standby 1 timers 1 3",
        "no standby 1 track 10",
        "no standby 1 authentication md5 key-string K",
        "no standby 1 name GROUP",
        "no standby version 2",
        "no standby 1 ip 10.0.0.1 secondary",
        "no standby",
        "no vrrp 1 ip 10.0.0.1",
        "no vrrp 1 priority 90",
        "no glbp 1 ip 10.0.0.1",
        "no glbp 1 weighting 80",
        "no ip igmp join-group 239.1.1.1 source 10.0.0.9",
    ]

    def test_blind_forms_emit_nothing(self):
        cfg = "interface Vlan100\n" + "".join(
            f" {line}\n" for line in self.BLIND_LINES
        )
        pc = IOSParser(cfg).parse()
        assert pc.no_commands == []
        assert not _removals(derive_ops(pc))

    def test_group_removal_and_vip_reset_are_distinct(self):
        pc = IOSParser(
            "interface Vlan100\n no standby 1\n no standby 2 ip\n"
        ).parse()
        assert sorted(pc.no_commands) == [
            "field:interface:Vlan100:hsrp_groups:1",
            "field:interface:Vlan100:hsrp_vip:2",
        ]


class TestRefreshEmission:
    def test_remove_then_readd_emits_both_sides(self):
        # NOT emission suppression (R.0): the removal op AND tombstone keep
        # flowing; the refresh resolves in the ENGINE replay by line order.
        cfg = (
            "interface Vlan100\n"
            " no standby 1\n"
            " standby 1 ip 10.0.0.254\n"
        )
        pc = IOSParser(cfg).parse()
        assert "field:interface:Vlan100:hsrp_groups:1" in pc.no_commands
        ops = derive_ops(pc)
        (removal,) = _removals(ops, "hsrp_groups")
        positive = next(
            op
            for op in ops
            if is_native_iface_member_op(op)
            and op.verb is Verb.SET
            and op.path[2] == "hsrp_groups"
        )
        assert positive.line_no > removal.line_no >= 0


class TestPerOS:
    def test_nxos_hsrp_spelling_and_inherited_walks(self):
        cfg = (
            "hostname n9k\n"
            "interface Vlan100\n"
            " no hsrp 5\n"
            " no vrrp 7\n"
            " no ip address 10.1.1.2/24 secondary\n"
        )
        pc = NXOSParser(cfg).parse()
        assert sorted(pc.no_commands) == [
            "field:interface:Vlan100:hsrp_groups:5",
            "field:interface:Vlan100:secondary_ips:10.1.1.2/24",
            "field:interface:Vlan100:vrrp_groups:7",
        ]
        assert len(_removals(derive_ops(pc))) == 3

    def test_eos_inherits(self):
        cfg = (
            "hostname sw1\n"
            "interface Vlan100\n"
            " no vrrp 9\n"
            " no ip address 10.2.2.2/24 secondary\n"
        )
        pc = EOSParser(cfg).parse()
        assert sorted(pc.no_commands) == [
            "field:interface:Vlan100:secondary_ips:10.2.2.2/24",
            "field:interface:Vlan100:vrrp_groups:9",
        ]

    def test_iosxr_emits_nothing(self):
        # XR overrides parse_deletion_commands without super() — exact
        # parity by absence (Phase 5).  Sub-class A detections likewise do
        # not fire through XR's own interface negation path.
        cfg = (
            "hostname xr1\n"
            "interface GigabitEthernet0/0/0/0\n"
            " no standby 1\n"
            " no ip igmp join-group 239.1.1.1\n"
        )
        pc = IOSXRParser(cfg).parse()
        assert not [
            t for t in pc.no_commands if t.startswith("field:interface:")
        ]
        assert not _removals(derive_ops(pc))


class TestDemoCorpusShape:
    def test_megacorp_cam_b1_dist_01_snippet(self):
        # The live demo proposal shape (proposals.json cam-b1-dist-01):
        # the VIP withdrawal is now visible, the group-2 add unchanged.
        cfg = (
            "interface Vlan100\n"
            " no standby 1 ip 10.40.1.254\n"
            " standby 2 ip 10.40.1.254\n"
        )
        pc = IOSParser(cfg).parse()
        assert pc.no_commands == ["field:interface:Vlan100:hsrp_vip:1"]
        gi = pc.interfaces[0]
        assert [g.group_number for g in gi.hsrp_groups] == [2]
