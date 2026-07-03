"""Tests for proposal-semantics parser fixes (Fable-5 review F1/F2, WI-1).

F1: an explicit ``no shutdown`` (and other silent default-valued boolean
    negations) must emit a ``field:interface:<name>:<attr>`` tombstone so the
    merger/coverage can see a change that restates the model default.

F2: un-anchored ``switchport trunk allowed vlan add|remove|except`` lines in a
    proposal snippet must be emitted as interface-scoped delta operations
    (``field:interface:<name>:trunk_allowed_vlans:<op>:<spec>``) instead of
    being folded against an empty set.  Running-config parsing (delta lines
    preceded by an absolute form) is unchanged.

Run:
    uv run pytest tests/test_proposal_negation_and_trunk_ops.py -v
"""

from __future__ import annotations

from confgraph.parsers.ios_parser import IOSParser


def _iface(config_text: str, name: str):
    ifaces = IOSParser(config_text).parse_interfaces()
    iface = next((i for i in ifaces if i.name == name), None)
    assert iface is not None, f"Interface {name} not found"
    return iface


# ---------------------------------------------------------------------------
# F1 — no shutdown (and other silent default restatements) emit tombstones
# ---------------------------------------------------------------------------


class TestNoShutdownTombstone:
    def test_no_shutdown_emits_enabled_tombstone(self):
        iface = _iface(
            "interface GigabitEthernet0/0\n no shutdown\n", "GigabitEthernet0/0"
        )
        assert iface.enabled is True
        assert "field:interface:GigabitEthernet0/0:enabled" in iface.no_commands

    def test_shutdown_does_not_emit_tombstone(self):
        iface = _iface(
            "interface GigabitEthernet0/0\n shutdown\n", "GigabitEthernet0/0"
        )
        assert iface.enabled is False
        assert "field:interface:GigabitEthernet0/0:enabled" not in iface.no_commands

    def test_absent_shutdown_does_not_emit_tombstone(self):
        iface = _iface(
            "interface GigabitEthernet0/0\n ip address 10.0.0.1 255.255.255.0\n",
            "GigabitEthernet0/0",
        )
        assert iface.enabled is True
        assert "field:interface:GigabitEthernet0/0:enabled" not in iface.no_commands

    def test_shutdown_then_no_shutdown_last_wins(self):
        iface = _iface(
            "interface GigabitEthernet0/0\n shutdown\n no shutdown\n",
            "GigabitEthernet0/0",
        )
        assert iface.enabled is True
        assert "field:interface:GigabitEthernet0/0:enabled" in iface.no_commands

    def test_no_shutdown_then_shutdown_last_wins(self):
        iface = _iface(
            "interface GigabitEthernet0/0\n no shutdown\n shutdown\n",
            "GigabitEthernet0/0",
        )
        assert iface.enabled is False
        assert "field:interface:GigabitEthernet0/0:enabled" not in iface.no_commands


class TestOtherSilentBooleanNegations:
    def test_no_switchport_port_security(self):
        iface = _iface(
            "interface GigabitEthernet0/1\n no switchport port-security\n",
            "GigabitEthernet0/1",
        )
        assert iface.port_security_enabled is False
        assert (
            "field:interface:GigabitEthernet0/1:port_security_enabled"
            in iface.no_commands
        )

    def test_positive_port_security_no_tombstone(self):
        iface = _iface(
            "interface GigabitEthernet0/1\n switchport port-security\n",
            "GigabitEthernet0/1",
        )
        assert iface.port_security_enabled is True
        assert (
            "field:interface:GigabitEthernet0/1:port_security_enabled"
            not in iface.no_commands
        )

    def test_no_ip_ospf_mtu_ignore(self):
        iface = _iface(
            "interface GigabitEthernet0/0\n no ip ospf mtu-ignore\n",
            "GigabitEthernet0/0",
        )
        assert iface.ospf_mtu_ignore is False
        assert (
            "field:interface:GigabitEthernet0/0:ospf_mtu_ignore" in iface.no_commands
        )

    def test_positive_mtu_ignore_no_tombstone(self):
        iface = _iface(
            "interface GigabitEthernet0/0\n ip ospf mtu-ignore\n",
            "GigabitEthernet0/0",
        )
        assert iface.ospf_mtu_ignore is True
        assert (
            "field:interface:GigabitEthernet0/0:ospf_mtu_ignore"
            not in iface.no_commands
        )


# ---------------------------------------------------------------------------
# F2 — trunk allowed vlan delta ops (proposal snippets) vs folding (running cfg)
# ---------------------------------------------------------------------------

_PFX = "field:interface:GigabitEthernet0/1:trunk_allowed_vlans"


class TestTrunkAllowedVlanDeltaOps:
    """Un-anchored add/remove/except emit ops; the parsed list stays []."""

    def test_unanchored_remove_emits_op(self):
        iface = _iface(
            "interface GigabitEthernet0/1\n"
            " switchport trunk allowed vlan remove 20\n",
            "GigabitEthernet0/1",
        )
        assert iface.trunk_allowed_vlans == []
        assert f"{_PFX}:remove:20" in iface.no_commands

    def test_unanchored_add_emits_op(self):
        iface = _iface(
            "interface GigabitEthernet0/1\n"
            " switchport trunk allowed vlan add 30\n",
            "GigabitEthernet0/1",
        )
        assert iface.trunk_allowed_vlans == []
        assert f"{_PFX}:add:30" in iface.no_commands

    def test_lone_except_is_absolute(self):
        """'except' is state-independent on the device — parsed absolutely,
        no op emitted, even without a preceding absolute form."""
        iface = _iface(
            "interface GigabitEthernet0/1\n"
            " switchport trunk allowed vlan except 100\n",
            "GigabitEthernet0/1",
        )
        assert 100 not in iface.trunk_allowed_vlans
        assert len(iface.trunk_allowed_vlans) == 4093
        assert not [t for t in iface.no_commands if t.startswith(_PFX)]

    def test_multiple_unanchored_ops_preserve_order(self):
        iface = _iface(
            "interface GigabitEthernet0/1\n"
            " switchport trunk allowed vlan remove 20\n"
            " switchport trunk allowed vlan add 30,40-42\n",
            "GigabitEthernet0/1",
        )
        ops = [t for t in iface.no_commands if t.startswith(_PFX)]
        assert ops == [f"{_PFX}:remove:20", f"{_PFX}:add:30,40-42"]

    def test_restated_mode_trunk_does_not_anchor(self):
        """T2c shape: a restated benign line must not swallow the delta op."""
        iface = _iface(
            "interface GigabitEthernet0/1\n"
            " switchport mode trunk\n"
            " switchport trunk allowed vlan remove 20\n",
            "GigabitEthernet0/1",
        )
        assert iface.trunk_allowed_vlans == []
        assert f"{_PFX}:remove:20" in iface.no_commands


class TestTrunkAllowedVlanRunningConfigUnchanged:
    """Anchored folding — full running-config semantics must be exactly as before."""

    def test_absolute_then_add_folds(self):
        iface = _iface(
            "interface GigabitEthernet0/1\n"
            " switchport trunk allowed vlan 10,20\n"
            " switchport trunk allowed vlan add 30\n",
            "GigabitEthernet0/1",
        )
        assert iface.trunk_allowed_vlans == [10, 20, 30]
        assert not [t for t in iface.no_commands if t.startswith(_PFX)]

    def test_absolute_then_remove_folds(self):
        iface = _iface(
            "interface GigabitEthernet0/1\n"
            " switchport trunk allowed vlan 10,20\n"
            " switchport trunk allowed vlan remove 20\n",
            "GigabitEthernet0/1",
        )
        assert iface.trunk_allowed_vlans == [10]
        assert not [t for t in iface.no_commands if t.startswith(_PFX)]

    def test_none_anchors(self):
        iface = _iface(
            "interface GigabitEthernet0/1\n"
            " switchport trunk allowed vlan none\n"
            " switchport trunk allowed vlan add 30\n",
            "GigabitEthernet0/1",
        )
        assert iface.trunk_allowed_vlans == [30]
        assert not [t for t in iface.no_commands if t.startswith(_PFX)]

    def test_all_anchors(self):
        iface = _iface(
            "interface GigabitEthernet0/1\n"
            " switchport trunk allowed vlan all\n"
            " switchport trunk allowed vlan remove 100\n",
            "GigabitEthernet0/1",
        )
        assert 100 not in iface.trunk_allowed_vlans
        assert len(iface.trunk_allowed_vlans) == 4093
        assert not [t for t in iface.no_commands if t.startswith(_PFX)]

    def test_anchored_except_folds(self):
        iface = _iface(
            "interface GigabitEthernet0/1\n"
            " switchport trunk allowed vlan 10,20\n"
            " switchport trunk allowed vlan except 100\n",
            "GigabitEthernet0/1",
        )
        assert 100 not in iface.trunk_allowed_vlans
        assert len(iface.trunk_allowed_vlans) == 4093

    def test_absolute_after_delta_discards_pending_ops(self):
        """An absolute form replaces device state — earlier deltas are moot."""
        iface = _iface(
            "interface GigabitEthernet0/1\n"
            " switchport trunk allowed vlan remove 20\n"
            " switchport trunk allowed vlan 10,20\n",
            "GigabitEthernet0/1",
        )
        assert iface.trunk_allowed_vlans == [10, 20]
        assert not [t for t in iface.no_commands if t.startswith(_PFX)]

    def test_plain_absolute_unchanged(self):
        iface = _iface(
            "interface GigabitEthernet0/1\n"
            " switchport trunk allowed vlan 10,20\n",
            "GigabitEthernet0/1",
        )
        assert iface.trunk_allowed_vlans == [10, 20]
        assert not [t for t in iface.no_commands if t.startswith(_PFX)]
