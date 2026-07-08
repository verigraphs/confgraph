"""Change-IR Phase 3, family 8e — interface container completion (parser side).

CCR: ``change_ir_proposal_operations.md`` Appendix X (WI-8e).

Covers:

- native per-MEMBER SET emission for the 11 InterfaceConfig collection
  fields (union lists / FHRP keyed lists / the md-key dict) — path shapes,
  keys, whole-item values, per-member last-occurrence lines,
- retirement of the derived whole-list twins via the generic container
  prefix-claim (anti-rot: EVERY composed interface op is native),
- the two native member-removal twins (helper / nhrp_nhs) — byte-exact
  tombstones regenerated FROM the ops at the same walk positions,
- the native whole-interface OBJECT_DELETE (``no interface``) — byte-exact
  ``interface:<norm>`` twin, line-numbered, exact-path dedupe of the
  derived twin (closing the latent ops-mode prefix-claim drop, X.0),
- per-OS: NX-OS/EOS share the walks via ``super()``; IOS-XR emits member
  SETs (batched parity) but no removal/delete ops (gated by its own
  ``parse_deletion_commands`` override).
"""

from __future__ import annotations

from ipaddress import IPv4Address, IPv4Interface

from confgraph.change_ir import (
    IFACE_MEMBER_REMOVAL_FIELDS,
    Verb,
    derive_ops,
    encode_legacy,
    interface_member_fields,
    interface_member_key,
    is_native_iface_member_op,
    is_native_interface_delete_op,
)
from confgraph.parsers.eos_parser import EOSParser
from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.iosxr_parser import IOSXRParser
from confgraph.parsers.nxos_parser import NXOSParser

KITCHEN_SINK = """hostname r1
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
 ip address 10.0.1.1 255.255.255.0 secondary
 ipv6 address 2001:db8::1/64
 ip helper-address 10.9.9.9
 ip helper-address 10.9.9.8
 ip ospf message-digest-key 1 md5 SECRET
 ip ospf message-digest-key 2 md5 OTHER
 standby 10 ip 10.0.0.254
 standby 10 priority 110
 vrrp 5 ip 10.0.0.253
 glbp 7 ip 10.0.0.252
 ip igmp join-group 239.1.1.1
 ip igmp static-group 239.2.2.2
interface Tunnel0
 ip address 172.16.0.1 255.255.255.0
 tunnel source GigabitEthernet0/0
 tunnel destination 203.0.113.9
 ip nhrp map 10.1.1.1 203.0.113.1
 ip nhrp nhs 10.1.1.1
"""


def _member_ops(ops, norm=None, field=None):
    out = [
        op
        for op in ops
        if is_native_iface_member_op(op) and op.verb is Verb.SET
    ]
    if norm is not None:
        out = [op for op in out if op.path[1] == norm]
    if field is not None:
        out = [op for op in out if op.path[2] == field]
    return out


class TestBoundary:
    def test_family_boundary_is_the_full_container(self):
        # Families 1 + 2 + 8e must jointly cover every non-provenance
        # InterfaceConfig field — the interface container is COMPLETE.
        from confgraph.change_ir import (
            _PROVENANCE_FIELDS,
            interface_list_replace_fields,
            interface_scalar_fields,
        )
        from confgraph.models.interface import InterfaceConfig

        covered = (
            interface_scalar_fields()
            | interface_list_replace_fields()
            | interface_member_fields()
        )
        expected = {
            n
            for n in InterfaceConfig.model_fields
            if n not in _PROVENANCE_FIELDS and n != "interface_type"
        }
        assert covered == expected

    def test_member_fields_registry(self):
        assert interface_member_fields() == {
            "secondary_ips",
            "ipv6_addresses",
            "helper_addresses",
            "nhrp_nhs",
            "nhrp_map",
            "igmp_join_groups",
            "igmp_static_groups",
            "hsrp_groups",
            "vrrp_groups",
            "glbp_groups",
            "ospf_message_digest_keys",
        }
        # Pin flipped in place by WI-DB1-B1 (CCR Appendix AA): the registry
        # gained the previously parser-blind interface-child negation kinds
        # (FHRP group removals, the hsrp_vip attr-reset, secondary-IP and
        # IGMP-group removals) beside the original 8e pair.
        assert IFACE_MEMBER_REMOVAL_FIELDS == {
            "helper": "helper_addresses",
            "nhrp_nhs": "nhrp_nhs",
            "hsrp_groups": "hsrp_groups",
            "hsrp_vip": "hsrp_groups",
            "vrrp_groups": "vrrp_groups",
            "glbp_groups": "glbp_groups",
            "secondary_ips": "secondary_ips",
            "igmp_join_groups": "igmp_join_groups",
            "igmp_static_groups": "igmp_static_groups",
        }


class TestMemberEmission:
    def test_all_collections_emit_member_ops(self):
        pc = IOSParser(KITCHEN_SINK).parse()
        ops = derive_ops(pc)
        gi = "GigabitEthernet0/0"
        assert {op.path[3] for op in _member_ops(ops, gi, "secondary_ips")} == {
            "10.0.1.1/24"
        }
        assert {op.path[3] for op in _member_ops(ops, gi, "ipv6_addresses")} == {
            "2001:db8::1/64"
        }
        assert {op.path[3] for op in _member_ops(ops, gi, "helper_addresses")} == {
            "10.9.9.9",
            "10.9.9.8",
        }
        assert {op.path[3] for op in _member_ops(ops, gi, "hsrp_groups")} == {"10"}
        assert {op.path[3] for op in _member_ops(ops, gi, "vrrp_groups")} == {"5"}
        assert {op.path[3] for op in _member_ops(ops, gi, "glbp_groups")} == {"7"}
        assert {
            op.path[3] for op in _member_ops(ops, gi, "igmp_join_groups")
        } == {"239.1.1.1"}
        assert {
            op.path[3] for op in _member_ops(ops, gi, "igmp_static_groups")
        } == {"239.2.2.2"}
        tu = "Tunnel0"
        assert {op.path[3] for op in _member_ops(ops, tu, "nhrp_nhs")} == {"10.1.1.1"}
        assert {op.path[3] for op in _member_ops(ops, tu, "nhrp_map")} == {
            "10.1.1.1 203.0.113.1"
        }

    def test_member_values_are_the_whole_parsed_items(self):
        pc = IOSParser(KITCHEN_SINK).parse()
        ops = derive_ops(pc)
        gi = "GigabitEthernet0/0"
        (sec,) = _member_ops(ops, gi, "secondary_ips")
        assert sec.value == IPv4Interface("10.0.1.1/24")
        (hsrp,) = _member_ops(ops, gi, "hsrp_groups")
        assert hsrp.value.group_number == 10
        assert hsrp.value.priority == 110
        assert hsrp.value.virtual_ip == IPv4Address("10.0.0.254")
        helpers = {op.path[3]: op.value for op in _member_ops(ops, gi, "helper_addresses")}
        assert helpers["10.9.9.9"] == IPv4Address("10.9.9.9")

    def test_md_key_dict_entries(self):
        pc = IOSParser(KITCHEN_SINK).parse()
        ops = derive_ops(pc)
        md = {
            op.path[3]: op.value
            for op in _member_ops(ops, "GigabitEthernet0/0", "ospf_message_digest_keys")
        }
        assert md == {"1": "SECRET", "2": "OTHER"}

    def test_member_line_numbers_are_per_member(self):
        pc = IOSParser(KITCHEN_SINK).parse()
        ops = derive_ops(pc)
        gi = "GigabitEthernet0/0"
        helpers = {
            op.path[3]: op.line_no for op in _member_ops(ops, gi, "helper_addresses")
        }
        # ``ip helper-address 10.9.9.9`` precedes ``… 10.9.9.8`` in the block.
        assert helpers["10.9.9.9"] < helpers["10.9.9.8"]
        (hsrp,) = _member_ops(ops, gi, "hsrp_groups")
        # LAST-occurrence line for keyed members: the ``standby 10 priority``
        # line, after ``standby 10 ip``.
        assert "priority" in hsrp.source_line

    def test_key_helper_matches_registry(self):
        pc = IOSParser(KITCHEN_SINK).parse()
        gi = next(i for i in pc.interfaces if i.name == "GigabitEthernet0/0")
        assert interface_member_key("hsrp_groups", gi.hsrp_groups[0]) == "10"
        assert (
            interface_member_key("secondary_ips", gi.secondary_ips[0])
            == "10.0.1.1/24"
        )

    def test_empty_collections_emit_nothing(self):
        pc = IOSParser("interface Loopback0\n ip address 1.1.1.1 255.255.255.255\n").parse()
        assert not _member_ops(derive_ops(pc))


class TestRetirement:
    def test_every_composed_interface_op_is_native(self):
        # Anti-rot (the D.6 pattern, extended to 8e): the deriver contributes
        # NOTHING for the interface container — every composed op touching an
        # interface path is native.
        pc = IOSParser(KITCHEN_SINK + "no interface Loopback9\n").parse()
        for op in derive_ops(pc):
            if op.path and op.path[0] == "interface":
                assert op.origin == "native", op
            if (
                len(op.path) >= 2
                and op.path[0] == "field"
                and op.path[1] == "interface"
            ):
                assert op.origin == "native", op

    def test_derived_whole_list_twin_retired(self):
        pc = IOSParser(KITCHEN_SINK).parse()
        ops = derive_ops(pc)
        for op in ops:
            # No 3-segment whole-list SET survives for any member field.
            if (
                op.verb is Verb.SET
                and len(op.path) == 3
                and op.path[0] == "interface"
            ):
                assert op.path[2] not in interface_member_fields(), op


class TestRemovalTwins:
    def test_helper_and_nhrp_removals(self):
        cfg = (
            "interface Vlan10\n"
            " no ip helper-address 10.0.0.100\n"
            "interface Tunnel0\n"
            " no ip nhrp nhs 203.0.113.1\n"
        )
        pc = IOSParser(cfg).parse()
        assert "field:interface:Vlan10:helper:10.0.0.100" in pc.no_commands
        assert "field:interface:Tunnel0:nhrp_nhs:203.0.113.1" in pc.no_commands
        removals = [
            op
            for op in derive_ops(pc)
            if is_native_iface_member_op(op) and op.verb is Verb.LIST_REMOVE
        ]
        assert {op.path for op in removals} == {
            ("field", "interface", "Vlan10", "helper", "10.0.0.100"),
            ("field", "interface", "Tunnel0", "nhrp_nhs", "203.0.113.1"),
        }
        for op in removals:
            assert op.line_no >= 0
            assert op.source_line.startswith("no ip")
        # Byte-exact regeneration through the codec.
        art = encode_legacy(removals)
        assert sorted(art.no_commands) == sorted(
            t for t in pc.no_commands if t.startswith("field:interface:")
        )

    def test_refresh_idiom_still_emits_both_sides(self):
        # NOT emission suppression (R.0): the removal op AND its tombstone
        # keep flowing; the refresh is resolved by the ENGINE replay.
        cfg = (
            "interface Vlan10\n"
            " no ip helper-address 10.0.0.100\n"
            " ip helper-address 10.0.0.100\n"
        )
        pc = IOSParser(cfg).parse()
        assert "field:interface:Vlan10:helper:10.0.0.100" in pc.no_commands
        ops = derive_ops(pc)
        removal = next(
            op
            for op in ops
            if is_native_iface_member_op(op) and op.verb is Verb.LIST_REMOVE
        )
        (positive,) = _member_ops(ops, "Vlan10", "helper_addresses")
        assert positive.line_no > removal.line_no >= 0


class TestInterfaceDelete:
    def test_native_delete_op_and_twin(self):
        pc = IOSParser("no interface Loopback5\n").parse()
        assert pc.no_commands == ["interface:Loopback5"]
        ops = derive_ops(pc)
        deletes = [op for op in ops if is_native_interface_delete_op(op)]
        assert len(deletes) == 1
        (d,) = deletes
        assert d.path == ("interface", "Loopback5")
        assert d.line_no == 0
        assert d.source_line == "no interface Loopback5"
        assert encode_legacy([d]).no_commands == ["interface:Loopback5"]
        # Exactly one op carries the intent (the derived twin is deduped).
        assert (
            sum(1 for op in ops if op.path == ("interface", "Loopback5")) == 1
        )

    def test_abbreviated_spelling_normalizes(self):
        pc = IOSParser("no interface Gi0/1\n").parse()
        assert pc.no_commands == ["interface:GigabitEthernet0/1"]
        (d,) = [op for op in derive_ops(pc) if is_native_interface_delete_op(op)]
        assert d.path == ("interface", "GigabitEthernet0/1")

    def test_latent_claim_bug_closed(self):
        # X.0: modify + delete of the SAME interface in one proposal.  At the
        # 8d HEAD the derived OBJECT_DELETE was dropped by the generic
        # prefix-claim from the family-1 SET — the deletion intent vanished
        # from the composed ChangeSet.  Native emission keeps it.
        cfg = (
            "interface Loopback5\n"
            " description newdesc\n"
            "no interface Loopback5\n"
        )
        ops = derive_ops(IOSParser(cfg).parse())
        assert any(is_native_interface_delete_op(op) for op in ops)


class TestPerOS:
    def test_nxos_shares_the_walks(self):
        cfg = (
            "hostname n9k\n"
            "interface Vlan10\n"
            " no ip helper-address 10.0.0.100\n"
            "no interface Vlan20\n"
        )
        pc = NXOSParser(cfg).parse()
        assert "field:interface:Vlan10:helper:10.0.0.100" in pc.no_commands
        assert "interface:Vlan20" in pc.no_commands
        ops = derive_ops(pc)
        assert any(is_native_interface_delete_op(op) for op in ops)
        assert any(
            is_native_iface_member_op(op) and op.verb is Verb.LIST_REMOVE
            for op in ops
        )

    def test_eos_shares_the_walks(self):
        pc = EOSParser("hostname sw1\nno interface Loopback3\n").parse()
        assert "interface:Loopback3" in pc.no_commands
        assert any(is_native_interface_delete_op(op) for op in derive_ops(pc))

    def test_iosxr_member_sets_but_no_deletion_ops(self):
        # XR inherits the interface state walk (member SETs — batched
        # parity) but overrides parse_deletion_commands without super():
        # no removal/delete shapes exist there (pre-existing, pinned).
        cfg = (
            "hostname xr1\n"
            "interface GigabitEthernet0/0/0/0\n"
            " ipv4 address 10.0.0.1 255.255.255.0\n"
            " ip helper-address 10.9.9.9\n"
            "no interface Loopback5\n"
        )
        pc = IOSXRParser(cfg).parse()
        ops = derive_ops(pc)
        assert not any(is_native_interface_delete_op(op) for op in ops)
        assert not any(
            is_native_iface_member_op(op) and op.verb is Verb.LIST_REMOVE
            for op in ops
        )
        assert "interface:Loopback5" not in pc.no_commands  # XR never walked it
        if any(i.helper_addresses for i in pc.interfaces):
            assert _member_ops(ops, field="helper_addresses")


class TestEncodeLegacy:
    def test_member_sets_encode_to_set_fields(self):
        pc = IOSParser(KITCHEN_SINK).parse()
        ops = derive_ops(pc)
        art = encode_legacy(ops)
        assert (
            art.set_fields[
                ("interface", "GigabitEthernet0/0", "helper_addresses", "10.9.9.9")
            ]
            == IPv4Address("10.9.9.9")
        )
        # No member op leaks into any tombstone container.
        assert not any(
            t.startswith("field:interface:") for t in art.no_commands
        )
