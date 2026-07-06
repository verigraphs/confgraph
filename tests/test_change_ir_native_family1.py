"""Change-IR Phase 3, family 1 — native op emission for interface scalars/booleans.

CCR: ``change_ir_proposal_operations.md`` Appendix D (WI-14).

Covers:
- the family-1 boundary registry (``interface_scalar_fields``),
- native SET emission (state-derived parity with the deriver, positive
  re-asserts of True-default visibility booleans, real provenance),
- native UNSET emission (tombstones generated from ops, byte-identical),
- hybrid derive_ops composition (natives first, path-dedupe, trap-1 fix),
- the anti-rot check: no family handled by BOTH native emission and the
  deriver's translation path,
- NX-OS/EOS/IOS-XR inheritance.
"""

from __future__ import annotations

import copy

import pytest

from confgraph.change_ir import (
    ChangeOp,
    Verb,
    derive_ops,
    encode_legacy,
    interface_scalar_fields,
    _derive_interface_set_ops,
)
from confgraph.parsers.eos_parser import EOSParser
from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.iosxr_parser import IOSXRParser
from confgraph.parsers.nxos_parser import NXOSParser


def _parse(text: str, parser_cls=IOSParser):
    return parser_cls(text).parse()


KITCHEN_SINK = (
    "interface GigabitEthernet0/0\n"
    " description core uplink\n"
    " ip address 10.0.0.1 255.255.255.252\n"
    " mtu 9000\n"
    " bandwidth 10000\n"
    " speed 1000\n"
    " duplex full\n"
    " ip ospf cost 20\n"
    " no shutdown\n"
    "interface GigabitEthernet0/1\n"
    " shutdown\n"
    " switchport mode trunk\n"
    " switchport trunk native vlan 99\n"
    " switchport trunk allowed vlan add 30\n"
    " no lldp transmit\n"
    "interface GigabitEthernet0/2\n"
    " lldp transmit\n"
    " lldp receive\n"
    " cdp enable\n"
    " no ip ospf cost\n"
    " no mpls ip\n"
    " no bfd interval\n"
    "ntp server 10.0.0.10\n"
    "no ip route 10.9.0.0 255.255.0.0 10.0.0.9\n"
)


# ---------------------------------------------------------------------------
# Family boundary
# ---------------------------------------------------------------------------


class TestFamilyBoundary:
    def test_scalars_and_booleans_in_family(self):
        family = interface_scalar_fields()
        for f in (
            "enabled", "description", "vrf", "ip_address", "mtu", "ip_mtu",
            "speed", "duplex", "bandwidth", "delay", "switchport_mode",
            "access_vlan", "trunk_native_vlan", "ospf_cost", "ospf_passive",
            "mpls_ip", "cdp_enabled", "lldp_transmit", "lldp_receive",
            "port_security_enabled", "nat_direction", "acl_in", "acl_out",
            "service_policy_input", "service_policy_output", "bfd_interval",
        ):
            assert f in family, f

    def test_collections_and_identity_excluded(self):
        family = interface_scalar_fields()
        for f in (
            # collections — later families (trunk VLANs are family 2)
            "trunk_allowed_vlans", "secondary_ips", "ipv6_addresses",
            "hsrp_groups", "vrrp_groups", "glbp_groups", "helper_addresses",
            "nhrp_nhs", "nhrp_map", "igmp_join_groups", "igmp_static_groups",
            "ospf_message_digest_keys",
            # identity / provenance / transport
            "name", "interface_type", "object_id", "raw_lines",
            "line_numbers", "source_os", "no_commands",
        ):
            assert f not in family, f

    def test_boundary_is_structural(self):
        """The registry equals: declared default + no factory + not meta."""
        from pydantic_core import PydanticUndefined
        from confgraph.models.interface import InterfaceConfig

        meta = {"object_id", "raw_lines", "line_numbers", "source_os",
                "no_commands", "name", "interface_type"}
        expected = {
            n for n, i in InterfaceConfig.model_fields.items()
            if n not in meta
            and i.default_factory is None
            and i.default is not PydanticUndefined
        }
        assert interface_scalar_fields() == frozenset(expected)


# ---------------------------------------------------------------------------
# Native SET emission
# ---------------------------------------------------------------------------


class TestNativeSetEmission:
    def test_state_derived_sets_cover_deriver_output(self):
        """Parity by construction: every family-1 SET the Phase-0 deriver
        would emit exists natively with the same path AND value."""
        pc = _parse(KITCHEN_SINK)
        native = {
            (op.path, repr(op.value))
            for op in pc.native_change_ops
            if op.verb is Verb.SET
        }
        family = interface_scalar_fields()
        for iface in pc.interfaces:
            for op in _derive_interface_set_ops(iface):
                if op.path[2] in family:
                    assert (op.path, repr(op.value)) in native, op.path

    def test_real_provenance(self):
        pc = _parse(KITCHEN_SINK)
        by_path = {op.path: op for op in pc.native_change_ops}
        op = by_path[("interface", "GigabitEthernet0/0", "mtu")]
        assert op.source_line == "mtu 9000"
        assert op.line_no > 0
        assert op.origin == "native"
        op = by_path[("interface", "GigabitEthernet0/1", "enabled")]
        assert op.value is False
        assert op.source_line == "shutdown"

    def test_positive_reassert_emits_default_valued_set(self):
        """THE capability: `lldp transmit` (== model default True) emits a
        native SET — legacy state artifacts are structurally blind to it."""
        pc = _parse(KITCHEN_SINK)
        by_path = {op.path: op for op in pc.native_change_ops}
        for field, line in (
            ("lldp_transmit", "lldp transmit"),
            ("lldp_receive", "lldp receive"),
            ("cdp_enabled", "cdp enable"),
        ):
            op = by_path[("interface", "GigabitEthernet0/2", field)]
            assert op.verb is Verb.SET
            assert op.value is True
            assert op.source_line == line
            assert op.line_no > 0
            assert op.origin == "native"

    def test_reassert_encodes_to_nothing_legacy(self):
        """value==default SET ops encode to set_fields only — no tombstone,
        no no_commands entry: exactly today's legacy blindness (required)."""
        pc = _parse("interface GigabitEthernet0/2\n lldp transmit\n")
        assert pc.interfaces[0].no_commands == []
        art = encode_legacy(pc.native_change_ops)
        assert art.no_commands == []
        assert art.interface_no_commands == {}
        assert art.set_fields[("interface", "GigabitEthernet0/2", "lldp_transmit")] is True

    def test_negation_wins_over_positive_restate(self):
        """`no lldp transmit` anywhere in the block wins (extraction is
        negative-presence): SET False, never a True restate op."""
        pc = _parse(
            "interface GigabitEthernet0/2\n lldp transmit\n no lldp transmit\n"
        )
        ops = [
            op for op in pc.native_change_ops
            if op.path == ("interface", "GigabitEthernet0/2", "lldp_transmit")
        ]
        assert len(ops) == 1
        assert ops[0].value is False

    def test_unmentioned_fields_emit_no_ops(self):
        """A bare interface header emits nothing — 'mentioned' stays
        structural; defaults carry no intent."""
        pc = _parse("interface GigabitEthernet0/5\n")
        assert pc.native_change_ops == []


# ---------------------------------------------------------------------------
# Native UNSET emission + tombstone byte-identity
# ---------------------------------------------------------------------------


class TestNativeUnsetEmission:
    def test_no_shutdown_unset_with_real_provenance(self):
        pc = _parse("interface GigabitEthernet0/0\n no shutdown\n")
        (op,) = pc.native_change_ops
        assert op.verb is Verb.UNSET
        assert op.path == ("field", "interface", "GigabitEthernet0/0", "enabled")
        assert op.source_line == "no shutdown"
        assert op.line_no > 0
        assert op.origin == "native"
        # tombstone regenerated from the op — byte-identical to pre-Phase-3
        assert pc.interfaces[0].no_commands == [
            "field:interface:GigabitEthernet0/0:enabled"
        ]

    def test_tombstone_list_byte_identical_including_order(self):
        """Exact no_commands content AND order pinned against the pre-change
        emission (description → trunk deltas → ospf_cost → mpls_ip → bfd×3 →
        negation-detector families)."""
        pc = _parse(
            "interface GigabitEthernet0/1\n"
            " no description\n"
            " switchport trunk allowed vlan add 30\n"
            " no ip ospf cost\n"
            " no mpls ip\n"
            " no bfd interval\n"
            " no ip access-group EDGE-IN in\n"
            " no service-policy input QOS-IN\n"
            " no ip nat inside\n"
            " no shutdown\n"
            " no switchport port-security\n"
            " no ip ospf mtu-ignore\n"
        )
        p = "field:interface:GigabitEthernet0/1"
        assert pc.interfaces[0].no_commands == [
            f"{p}:description",
            f"{p}:trunk_allowed_vlans:add:30",
            f"{p}:ospf_cost",
            f"{p}:mpls_ip",
            f"{p}:bfd_interval",
            f"{p}:bfd_min_rx",
            f"{p}:bfd_multiplier",
            f"{p}:acl_in",
            f"{p}:service_policy_input",
            f"{p}:nat_direction",
            f"{p}:enabled",
            f"{p}:port_security_enabled",
            f"{p}:ospf_mtu_ignore",
        ]

    def test_shutdown_then_no_shutdown_last_match_wins(self):
        pc = _parse("interface GigabitEthernet0/0\n shutdown\n no shutdown\n")
        assert pc.interfaces[0].enabled is True
        (op,) = pc.native_change_ops
        assert op.verb is Verb.UNSET
        assert op.path[-1] == "enabled"


# ---------------------------------------------------------------------------
# Hybrid derivation / composition (trap-1 fix) + anti-rot
# ---------------------------------------------------------------------------


class TestHybridComposition:
    def test_composition_native_first_then_derived_rest(self):
        pc = _parse(KITCHEN_SINK)
        ops = derive_ops(pc)
        n_native = len(pc.native_change_ops)
        assert [op.origin for op in ops[:n_native]] == ["native"] * n_native
        assert all(op.origin == "derived" for op in ops[n_native:])
        # Family 2 migrated (WI-15): the trunk delta is NATIVE now.
        natives = ops[:n_native]
        assert any(op.verb is Verb.LIST_ADD and "trunk_allowed_vlans" in op.path
                   for op in natives)
        # Non-migrated families still derived: top-level SET (ntp),
        # static-route removal.
        derived = ops[n_native:]
        assert not any("trunk_allowed_vlans" in op.path for op in derived)
        assert any(op.path == ("ntp",) for op in derived)
        assert any(op.verb is Verb.LIST_REMOVE and op.path[0] == "static"
                   for op in derived)

    def test_no_duplicate_paths_after_dedupe(self):
        pc = _parse(KITCHEN_SINK)
        ops = derive_ops(pc)
        iface_paths = [
            op.path for op in ops
            if (op.path[0] == "interface" and len(op.path) == 3)
            or (op.path[:2] == ("field", "interface") and len(op.path) == 4)
        ]
        assert len(iface_paths) == len(set(iface_paths))

    def test_anti_rot_family1_never_derived(self):
        """CI anti-rot check (CCR §6 risk table): no family is handled by
        BOTH native emission and the deriver's translation path — every
        family-1 interface op in the composed ChangeSet is native."""
        pc = _parse(KITCHEN_SINK)
        family = interface_scalar_fields()
        for op in derive_ops(pc):
            if op.verb is Verb.SET and op.path[0] == "interface" \
                    and len(op.path) == 3 and op.path[2] in family:
                assert op.origin == "native", op.path
            if op.path[:2] == ("field", "interface") and len(op.path) == 4 \
                    and op.path[3] in family:
                assert op.origin == "native", op.path

    def test_trap1_ops_cache_stays_empty_until_derive(self):
        """The parser populates native_change_ops, NEVER change_ops — the
        engine's ops_for_proposal cache always goes through derive_ops, so
        non-migrated families cannot be silently skipped (trap 1)."""
        pc = _parse(KITCHEN_SINK)
        assert pc.change_ops is None
        assert pc.native_change_ops

    def test_derive_ops_without_natives_unchanged(self):
        """A config without native ops (simulating pre-Phase-3 / JunOS
        parses) derives exactly as before."""
        pc = _parse(KITCHEN_SINK)
        pc.native_change_ops = None
        ops = derive_ops(pc)
        assert all(op.origin == "derived" for op in ops)
        assert any(op.path == ("interface", "GigabitEthernet0/0", "mtu")
                   for op in ops)

    def test_native_ops_survive_deepcopy(self):
        pc = _parse("interface GigabitEthernet0/0\n mtu 9000\n")
        clone = copy.deepcopy(pc)
        assert [op.path for op in clone.native_change_ops] == \
               [op.path for op in pc.native_change_ops]

    def test_baseline_parses_get_ops_but_never_consumed_shape(self):
        """Baselines carry native ops too (unconditional emission) — they
        are inert unless something derives ops for the config."""
        pc = _parse("hostname r1\ninterface GigabitEthernet0/0\n mtu 9000\n")
        assert pc.native_change_ops
        assert pc.change_ops is None


# ---------------------------------------------------------------------------
# Inheritance: NX-OS / EOS / IOS-XR
# ---------------------------------------------------------------------------


class TestInheritance:
    def test_nxos_reassert_and_final_state_values(self):
        pc = _parse(
            "interface Ethernet1/1\n"
            "  ip address 10.0.0.1/30\n"
            "  lldp transmit\n"
            "  no shutdown\n",
            NXOSParser,
        )
        by_path = {op.path: op for op in pc.native_change_ops}
        # NX-OS CIDR address is patched AFTER the IOS-level pass — finalization
        # emission must carry the FINAL value.
        ip_op = by_path[("interface", "Ethernet1/1", "ip_address")]
        assert str(ip_op.value) == "10.0.0.1/30"
        assert by_path[("interface", "Ethernet1/1", "lldp_transmit")].value is True
        assert ("field", "interface", "Ethernet1/1", "enabled") in by_path
        assert pc.interfaces[0].no_commands == [
            "field:interface:Ethernet1/1:enabled"
        ]

    def test_eos_inherits(self):
        pc = _parse(
            "interface Ethernet1\n"
            "   ip address 10.0.0.1/30\n"
            "   no lldp transmit\n",
            EOSParser,
        )
        by_path = {op.path: op for op in pc.native_change_ops}
        assert by_path[("interface", "Ethernet1", "lldp_transmit")].value is False
        assert str(by_path[("interface", "Ethernet1", "ip_address")].value) == "10.0.0.1/30"

    def test_iosxr_negation_ops_native(self):
        pc = _parse(
            "interface GigabitEthernet0/0/0/0\n"
            " no ipv4 access-group EDGE-IN ingress\n",
            IOSXRParser,
        )
        ops = [op for op in pc.native_change_ops if op.verb is Verb.UNSET]
        (op,) = ops
        assert op.path == ("field", "interface", "GigabitEthernet0/0/0/0", "acl_in")
        assert op.source_line == "no ipv4 access-group EDGE-IN ingress"
        assert op.origin == "native"
        assert pc.interfaces[0].no_commands == [
            "field:interface:GigabitEthernet0/0/0/0:acl_in"
        ]
