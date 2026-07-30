"""CCR-0129 — per-interface DHCP relay targets live in ONE field across OS spellings.

One operational fact — "DHCP requests on this interface are relayed to these
servers" — used to live in two `InterfaceConfig` fields depending on which vendor
spelled it:

    IOS/IOS-XE/EOS   ip helper-address <ip>      -> helper_addresses
    NX-OS            ip dhcp relay address <ip>  -> dhcp_relay_addresses  (CCR-0090)

Only `helper_addresses` had consumers, so removing relay servers from an NX-OS SVI
simulated as NO service impact while the identical change in IOS spelling was
flagged — a per-OS verdict divergence. CCR-0129 re-homes the NX-OS spelling onto
`helper_addresses` and REMOVES `dhcp_relay_addresses` (owner decision: one field for
one fact, no compatibility alias — an assessor-side union was explicitly rejected
because it would institutionalize two fields for one fact).

Direction of the re-home: the surviving field is `helper_addresses` because every
existing consumer already keys on it by name (the DHCP relay assessor, the
relay-loop check, the merge union, the Change-IR member registry, the removal
tombstone kind) — so IOS-derived op paths, tombstone strings and goldens stay
byte-identical, and only the field with zero readers is retired.
"""

from __future__ import annotations

from ipaddress import IPv4Address

from confgraph.change_ir import (
    Verb,
    derive_ops,
    interface_member_fields,
    interface_member_key,
    is_native_iface_member_op,
)
from confgraph.models.interface import InterfaceConfig
from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.nxos_parser import NXOSParser

# The SAME operational fact, in each vendor's own spelling, with the same two
# relay targets in the same order.
IOS_RELAY = """hostname r1
interface Vlan10
 ip address 10.0.10.1 255.255.255.0
 ip helper-address 10.199.99.1
 ip helper-address 10.199.99.2
"""

NXOS_RELAY = """hostname r1
interface Vlan10
  ip address 10.0.10.1/24
  ip dhcp relay address 10.199.99.1
  ip dhcp relay address 10.199.99.2
"""

RELAY_TARGETS = [IPv4Address("10.199.99.1"), IPv4Address("10.199.99.2")]


def _iface(parsed, name):
    return next(i for i in parsed.interfaces if i.name == name)


def _member_keys(ops, norm, field):
    return {
        op.path[3]
        for op in ops
        if is_native_iface_member_op(op)
        and op.verb is Verb.SET
        and op.path[1] == norm
        and op.path[2] == field
    }


class TestTheRetiredFieldIsGone:
    """Replace-don't-layer: no field, no alias, no property shim."""

    def test_model_has_no_dhcp_relay_addresses_field(self):
        assert "dhcp_relay_addresses" not in InterfaceConfig.model_fields

    def test_no_attribute_alias_survives(self):
        # A property/alias would keep two names for one fact alive and let a
        # consumer keep reading the old one — the debt this CCR removes.
        iface = InterfaceConfig(
            object_id="interface:Vlan10",
            source_os="nxos",
            interface_type="vlan",
            name="Vlan10",
        )
        assert not hasattr(iface, "dhcp_relay_addresses")

    def test_change_ir_member_registry_dropped_the_retired_field(self):
        assert "dhcp_relay_addresses" not in interface_member_fields()
        assert "helper_addresses" in interface_member_fields()


class TestBothSpellingsLandInOneField:
    def test_ios_helper_address_populates_helper_addresses(self):
        iface = _iface(IOSParser(IOS_RELAY).parse(), "Vlan10")
        assert iface.helper_addresses == RELAY_TARGETS

    def test_nxos_relay_address_populates_helper_addresses(self):
        iface = _iface(NXOSParser(NXOS_RELAY).parse(), "Vlan10")
        assert iface.helper_addresses == RELAY_TARGETS

    def test_cross_os_same_fact_parses_to_the_same_model_state(self):
        """THE point of the CCR: one fact, two spellings, one indistinguishable
        model state — so a consumer cannot behave differently per OS."""
        ios = _iface(IOSParser(IOS_RELAY).parse(), "Vlan10")
        nxos = _iface(NXOSParser(NXOS_RELAY).parse(), "Vlan10")
        assert ios.helper_addresses == nxos.helper_addresses == RELAY_TARGETS

    def test_nxos_relay_order_and_dedupe_preserved(self):
        cfg = """interface Vlan20
  ip dhcp relay address 10.1.1.2
  ip dhcp relay address 10.1.1.1
  ip dhcp relay address 10.1.1.2
"""
        iface = _iface(NXOSParser(cfg).parse(), "Vlan20")
        # config order, first occurrence wins, no duplicate member
        assert iface.helper_addresses == [
            IPv4Address("10.1.1.2"),
            IPv4Address("10.1.1.1"),
        ]

    def test_interface_without_relay_stays_at_the_model_default(self):
        """Tri-state discipline: parser-absence == the model default."""
        iface = _iface(NXOSParser("interface Vlan30\n  ip address 10.0.30.1/24\n").parse(), "Vlan30")
        assert iface.helper_addresses == []
        assert iface.helper_addresses == InterfaceConfig.model_fields[
            "helper_addresses"
        ].default_factory()


class TestEmissionFollowsTheField:
    """The Change-IR member ops must be indistinguishable across the two
    spellings too — the emission side of the same unification."""

    def test_nxos_relay_emits_helper_addresses_member_ops(self):
        ops = derive_ops(NXOSParser(NXOS_RELAY).parse())
        assert _member_keys(ops, "Vlan10", "helper_addresses") == {
            "10.199.99.1",
            "10.199.99.2",
        }

    def test_cross_os_member_op_paths_are_identical(self):
        ios_ops = derive_ops(IOSParser(IOS_RELAY).parse())
        nxos_ops = derive_ops(NXOSParser(NXOS_RELAY).parse())
        assert _member_keys(ios_ops, "Vlan10", "helper_addresses") == _member_keys(
            nxos_ops, "Vlan10", "helper_addresses"
        )

    def test_no_op_is_emitted_on_the_retired_path(self):
        ops = derive_ops(NXOSParser(NXOS_RELAY).parse())
        assert not [
            op
            for op in ops
            if len(op.path) > 2 and op.path[2] == "dhcp_relay_addresses"
        ]

    def test_member_key_is_value_identity_for_the_survivor(self):
        # Key FUNCTION equivalence, not merely registration (CCR-0136 lesson):
        # the survivor keeps value-identity keying, which is what the engine's
        # own _IFACE_INCREMENTAL_LISTS entry and the removal replay assume.
        assert interface_member_key("helper_addresses", IPv4Address("10.9.9.9")) == "10.9.9.9"


class TestIosSpellingIsUntouched:
    """The re-home must be invisible to IOS-only configs — the field name that
    every IOS artifact (op path, tombstone string, golden key) is built from did
    not move."""

    def test_ios_member_removal_tombstone_still_targets_helper_addresses(self):
        from confgraph.change_ir import IFACE_MEMBER_REMOVAL_FIELDS

        assert IFACE_MEMBER_REMOVAL_FIELDS["helper"] == "helper_addresses"

    def test_ios_member_removal_still_emits_its_removal_op(self):
        pc = IOSParser(
            "interface Vlan10\n"
            " ip helper-address 10.199.99.1\n"
            " ip helper-address 10.199.99.2\n"
            " no ip helper-address 10.199.99.1\n"
        ).parse()
        # 5-segment member-removal op keyed by the ``helper`` tombstone KIND
        # (not the field name) — unchanged by the re-home.
        assert [
            op
            for op in pc.native_change_ops or []
            if op.verb is Verb.LIST_REMOVE
            and op.path == ("field", "interface", "Vlan10", "helper", "10.199.99.1")
        ]


class TestKnownGapNotClosedHere:
    def test_nxos_member_negation_is_still_parse_blind(self):
        """`no ip dhcp relay address <ip>` parses to NOTHING — CCR-0135, which is
        out of scope for this CCR. Pinned so the gap is visible and so the day
        CCR-0135 lands, this test fails and must be flipped to a real removal
        assertion (with the sim-coverage parse-blind control flipped alongside).

        Consequence to keep in mind: the NX-OS relay REMOVAL verdict is reachable
        from constructed states and unit tests, but not yet from a device-realistic
        NX-OS proposal snippet. The POSITIVE spelling parses fine, so the
        relay-loop verdict IS reachable end-to-end.
        """
        pc = NXOSParser(
            "interface Vlan10\n"
            "  ip dhcp relay address 10.199.99.1\n"
            "  ip dhcp relay address 10.199.99.2\n"
            "  no ip dhcp relay address 10.199.99.1\n"
        ).parse()
        iface = _iface(pc, "Vlan10")
        # The negation is inert: BOTH targets survive the parse (on a real device
        # only .2 would remain).
        assert iface.helper_addresses == RELAY_TARGETS
        # and no removal op / tombstone is emitted for it
        assert not [
            op
            for op in pc.native_change_ops or []
            if op.verb is Verb.LIST_REMOVE and "helper" in op.path
        ]
        assert not [nc for nc in iface.no_commands if "helper" in nc]
