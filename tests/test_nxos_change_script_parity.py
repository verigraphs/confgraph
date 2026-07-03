"""NX-OS (and EOS) parity for the change-script fidelity fixes (Fable-5 WI-6).

Three surfaces, all reached through NXOSParser/EOSParser:

1. F1 mirror — negation tombstones (`no shutdown`, `no switchport
   port-security`, `no ip ospf mtu-ignore`) flow through
   ``super().parse_interfaces()`` into ``InterfaceConfig.no_commands``.
2. F2 mirror — un-anchored ``switchport trunk allowed vlan add/remove`` in a
   proposal snippet emit interface-scoped delta ops; anchored running-config
   forms still fold into ``trunk_allowed_vlans``.
3. CIDR static deletions — ``no ip route DEST/PLEN [NH [AD]]`` (the native
   NX-OS/EOS form, single prefix token) emits the same
   ``static:<vrf>:<dest>[:<nh_spec>]`` tombstones as the IOS ``DEST MASK``
   form, including nested under ``vrf context NAME`` blocks (NX-OS only —
   that's where NX-OS VRF statics live).

Run:
    uv run pytest tests/test_nxos_change_script_parity.py -v
"""

from __future__ import annotations

from confgraph.parsers.eos_parser import EOSParser
from confgraph.parsers.nxos_parser import NXOSParser


def _nxos_ifaces(cfg: str):
    return {i.name: i for i in NXOSParser(cfg).parse_interfaces()}


def _nxos_tombstones(cfg: str) -> list[str]:
    return NXOSParser(cfg).parse_deletion_commands()


# ---------------------------------------------------------------------------
# 1. F1 mirror — interface negation tombstones
# ---------------------------------------------------------------------------


class TestNXOSInterfaceNegationTombstones:
    def test_no_shutdown_emits_enabled_tombstone(self):
        ifaces = _nxos_ifaces("interface Ethernet1/1\n  no shutdown\n")
        assert (
            "field:interface:Ethernet1/1:enabled"
            in ifaces["Ethernet1/1"].no_commands
        )

    def test_shutdown_then_no_shutdown_last_match_wins(self):
        ifaces = _nxos_ifaces(
            "interface Ethernet1/1\n  shutdown\n  no shutdown\n"
        )
        assert (
            "field:interface:Ethernet1/1:enabled"
            in ifaces["Ethernet1/1"].no_commands
        )

    def test_no_shutdown_then_shutdown_emits_no_tombstone(self):
        ifaces = _nxos_ifaces(
            "interface Ethernet1/1\n  no shutdown\n  shutdown\n"
        )
        assert (
            "field:interface:Ethernet1/1:enabled"
            not in ifaces["Ethernet1/1"].no_commands
        )
        assert ifaces["Ethernet1/1"].enabled is False

    def test_no_switchport_port_security_tombstone(self):
        ifaces = _nxos_ifaces(
            "interface Ethernet1/1\n  no switchport port-security\n"
        )
        assert (
            "field:interface:Ethernet1/1:port_security_enabled"
            in ifaces["Ethernet1/1"].no_commands
        )

    def test_no_ip_ospf_mtu_ignore_tombstone(self):
        ifaces = _nxos_ifaces(
            "interface Ethernet1/1\n  no ip ospf mtu-ignore\n"
        )
        assert (
            "field:interface:Ethernet1/1:ospf_mtu_ignore"
            in ifaces["Ethernet1/1"].no_commands
        )

    def test_running_config_shutdown_emits_no_tombstones(self):
        """A plain running config (positive lines only) must be unchanged."""
        ifaces = _nxos_ifaces(
            "interface Ethernet1/1\n"
            "  ip address 10.0.12.1/30\n"
            "  shutdown\n"
        )
        assert ifaces["Ethernet1/1"].no_commands == []
        assert ifaces["Ethernet1/1"].enabled is False
        assert str(ifaces["Ethernet1/1"].ip_address) == "10.0.12.1/30"


# ---------------------------------------------------------------------------
# 2. F2 mirror — trunk allowed-VLAN delta ops
# ---------------------------------------------------------------------------


class TestNXOSTrunkVlanDeltaOps:
    def test_unanchored_remove_emits_delta_op(self):
        ifaces = _nxos_ifaces(
            "interface Ethernet1/2\n"
            "  switchport trunk allowed vlan remove 20\n"
        )
        intf = ifaces["Ethernet1/2"]
        assert (
            "field:interface:Ethernet1/2:trunk_allowed_vlans:remove:20"
            in intf.no_commands
        )
        assert intf.trunk_allowed_vlans == []  # stays "not mentioned"

    def test_unanchored_add_emits_delta_op(self):
        ifaces = _nxos_ifaces(
            "interface Ethernet1/2\n"
            "  switchport trunk allowed vlan add 30\n"
        )
        assert (
            "field:interface:Ethernet1/2:trunk_allowed_vlans:add:30"
            in ifaces["Ethernet1/2"].no_commands
        )

    def test_anchored_running_config_folds_as_before(self):
        ifaces = _nxos_ifaces(
            "interface Ethernet1/2\n"
            "  switchport mode trunk\n"
            "  switchport trunk allowed vlan 10,20\n"
            "  switchport trunk allowed vlan add 30\n"
        )
        intf = ifaces["Ethernet1/2"]
        assert intf.trunk_allowed_vlans == [10, 20, 30]
        assert not [c for c in intf.no_commands if "trunk_allowed_vlans" in c]


# ---------------------------------------------------------------------------
# 3. CIDR static-route deletion tombstones
# ---------------------------------------------------------------------------


class TestNXOSCIDRStaticDeletionTombstones:
    def test_cidr_with_nh_ip(self):
        ts = _nxos_tombstones("no ip route 1.1.1.0/24 10.0.0.1\n")
        assert "static::1.1.1.0/24:10.0.0.1" in ts

    def test_cidr_without_nh_removes_all(self):
        ts = _nxos_tombstones("no ip route 2.2.2.0/24\n")
        assert "static::2.2.2.0/24" in ts

    def test_cidr_with_interface_nh(self):
        ts = _nxos_tombstones("no ip route 3.3.3.0/24 Null0\n")
        assert "static::3.3.3.0/24:Null0" in ts

    def test_cidr_with_trailing_ad_excludes_ad(self):
        ts = _nxos_tombstones("no ip route 0.0.0.0/0 10.0.99.2 250\n")
        assert "static::0.0.0.0/0:10.0.99.2" in ts

    def test_traditional_form_still_works(self):
        ts = _nxos_tombstones("no ip route 3.3.3.0 255.255.255.0 10.0.0.9\n")
        assert "static::3.3.3.0/24:10.0.0.9" in ts

    def test_vrf_keyword_form_with_cidr(self):
        ts = _nxos_tombstones("no ip route vrf RED 1.1.1.0/24 10.0.0.1\n")
        assert "static:RED:1.1.1.0/24:10.0.0.1" in ts

    def test_vrf_context_nested_cidr_deletion(self):
        ts = _nxos_tombstones(
            "vrf context CUST-A\n  no ip route 4.4.4.0/24 10.0.0.5\n"
        )
        assert "static:CUST-A:4.4.4.0/24:10.0.0.5" in ts

    def test_vrf_context_nested_cidr_deletion_no_nh(self):
        ts = _nxos_tombstones(
            "vrf context CUST-A\n  no ip route 4.4.4.0/24\n"
        )
        assert "static:CUST-A:4.4.4.0/24" in ts

    def test_vrf_context_nested_traditional_deletion(self):
        ts = _nxos_tombstones(
            "vrf context CUST-A\n"
            "  no ip route 4.4.4.0 255.255.255.0 10.0.0.5\n"
        )
        assert "static:CUST-A:4.4.4.0/24:10.0.0.5" in ts

    def test_garbage_destination_emits_nothing(self):
        ts = _nxos_tombstones("no ip route bogus/24 10.0.0.1\n")
        assert not [t for t in ts if t.startswith("static:")]

    def test_positive_routes_emit_no_tombstones(self):
        """A running config with positive statics must emit no static tombstones."""
        ts = _nxos_tombstones(
            "ip route 5.5.5.0/24 10.0.0.7\n"
            "vrf context CUST-A\n  ip route 7.7.7.0/24 10.0.0.9\n"
        )
        assert not [t for t in ts if t.startswith("static:")]


# ---------------------------------------------------------------------------
# 4. EOS inherits the same fixes (audit — WI-6 item 4)
# ---------------------------------------------------------------------------


class TestEOSParity:
    def test_eos_no_shutdown_tombstone(self):
        ifaces = {
            i.name: i
            for i in EOSParser(
                "interface Ethernet1\n   no shutdown\n"
            ).parse_interfaces()
        }
        assert (
            "field:interface:Ethernet1:enabled" in ifaces["Ethernet1"].no_commands
        )

    def test_eos_unanchored_trunk_remove_delta_op(self):
        ifaces = {
            i.name: i
            for i in EOSParser(
                "interface Ethernet1\n"
                "   switchport trunk allowed vlan remove 20\n"
            ).parse_interfaces()
        }
        assert (
            "field:interface:Ethernet1:trunk_allowed_vlans:remove:20"
            in ifaces["Ethernet1"].no_commands
        )

    def test_eos_cidr_deletion_with_nh(self):
        ts = EOSParser("no ip route 1.1.1.0/24 10.0.0.1\n").parse_deletion_commands()
        assert "static::1.1.1.0/24:10.0.0.1" in ts

    def test_eos_cidr_deletion_without_nh(self):
        ts = EOSParser("no ip route 2.2.2.0/24\n").parse_deletion_commands()
        assert "static::2.2.2.0/24" in ts
