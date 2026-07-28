"""CCR-0113 — whole-list reset for the default_factory interface list fields.

The IOS parser (and its NX-OS/EOS inheritors) emitted NO whole-list reset for a
bare (operand-LESS) negation of a ``default_factory`` InterfaceConfig list
field, and folded a ``reset-then-add`` sequence into a bare add (so
``vlan 1,2,3`` + ``no switchport trunk allowed vlan`` + ``... add 10`` merged to
``[1,2,3,10]`` instead of ``[10]``).

This pins the emission fix:

(a) a bare whole-list negation emits the 4-segment
    ``field:interface:<name>:<field>`` reset tombstone AND a native ``UNSET``
    op at ``("field","interface",<name>,<field>)``;
(b) a ``reset-then-add`` sequence emits the reset FOLLOWED BY the add delta,
    ordered by line number, and the parsed list no longer folds (so the merger,
    which orders interface ops by line number, yields the add-only set);
(c) operand-bearing MEMBER negations (``no ip helper-address 10.0.0.1``) still
    route through the member-removal handler — the reset is disjoint.

Only fields with a vendor-established bare whole-list-reset spelling are
covered (syntax-corpus / consultant grounded, CCR-0113):
  * ``trunk_allowed_vlans`` — ``no switchport trunk allowed vlan`` (cisco-ios)
  * ``ipv6_addresses``      — ``no ipv6 address`` (cisco-ios + EOS)
  * ``helper_addresses``    — ``no ip helper-address`` (EOS)

Run:
    uv run pytest tests/test_ccr0113_interface_whole_list_reset.py -v
"""

from __future__ import annotations

from confgraph.change_ir import Verb
from confgraph.parsers.eos_parser import EOSParser
from confgraph.parsers.ios_parser import IOSParser
from tests._ccr0110_e_helpers import iface_nc


def _parse(config_text: str, cls=IOSParser):
    return cls(config_text).parse()


def _iface_ops(pc, name: str, field: str):
    """Native ops touching interface *name*'s *field* (whole-list reset or
    delta), in ChangeSet order.  Matches both the reset shape
    ``("field","interface",name,field[,...])`` and the whole-instance/member
    SET shapes ``("interface",norm,field[,...])``."""
    out = []
    for op in pc.native_change_ops or []:
        p = op.path
        if len(p) >= 4 and p[0] == "field" and p[1] == "interface" and p[3] == field and name in p:
            out.append(op)
        elif len(p) >= 3 and p[0] == "interface" and p[2] == field and name in p:
            out.append(op)
    return out


def _reset_op(pc, name: str, field: str):
    for op in pc.native_change_ops or []:
        if op.path == ("field", "interface", name, field):
            return op
    return None


# ---------------------------------------------------------------------------
# trunk_allowed_vlans — the operationally common case (cisco-ios)
# ---------------------------------------------------------------------------

_GI = "GigabitEthernet0/1"
_TPFX = f"field:interface:{_GI}:trunk_allowed_vlans"


class TestTrunkWholeListReset:
    def test_bare_negation_emits_reset_tombstone_and_unset_op(self):
        pc = _parse(
            f"interface {_GI}\n"
            " switchport mode trunk\n"
            " switchport trunk allowed vlan 1,2,3\n"
            " no switchport trunk allowed vlan\n"
        )
        iface = next(i for i in pc.interfaces if i.name == _GI)
        # The list no longer clings to the pre-reset anchor.
        assert iface.trunk_allowed_vlans == []
        # 4-segment whole-list reset tombstone (distinct from a 5-segment member form).
        assert _TPFX in iface_nc(pc, _GI)
        # native UNSET op on the reset path.
        op = _reset_op(pc, _GI, "trunk_allowed_vlans")
        assert op is not None and op.verb is Verb.UNSET

    def test_reset_then_add_emits_reset_before_add_ordered(self):
        pc = _parse(
            f"interface {_GI}\n"
            " switchport mode trunk\n"
            " switchport trunk allowed vlan 1,2,3\n"   # L3 (pre-reset anchor)
            " no switchport trunk allowed vlan\n"      # L4 (reset)
            " switchport trunk allowed vlan add 10\n"  # L5 (delta)
        )
        iface = next(i for i in pc.interfaces if i.name == _GI)
        # The fold to [1,2,3,10] is gone: no whole-instance SET, list stays [].
        assert iface.trunk_allowed_vlans == []
        tombs = iface_nc(pc, _GI)
        assert _TPFX in tombs                 # reset present
        assert f"{_TPFX}:add:10" in tombs     # add delta present
        # No spurious [1,2,3] absolute SET tombstone survives.
        assert f"{_TPFX}:add:1,2,3" not in tombs
        # Ordered by line number: reset op precedes the add-delta op.
        ops = _iface_ops(pc, _GI, "trunk_allowed_vlans")
        reset = next(o for o in ops if o.verb is Verb.UNSET)
        add = next(o for o in ops if o.verb is Verb.LIST_ADD)
        assert reset.line_no < add.line_no
        assert add.value == "10"

    def test_control_add_only_unchanged(self):
        pc = _parse(
            f"interface {_GI}\n"
            " switchport mode trunk\n"
            " switchport trunk allowed vlan add 10\n"
        )
        iface = next(i for i in pc.interfaces if i.name == _GI)
        assert iface.trunk_allowed_vlans == []
        tombs = iface_nc(pc, _GI)
        assert f"{_TPFX}:add:10" in tombs
        assert _TPFX not in tombs             # NO reset when there was no negation
        assert _reset_op(pc, _GI, "trunk_allowed_vlans") is None

    def test_bare_negation_alone_resets(self):
        pc = _parse(f"interface {_GI}\n no switchport trunk allowed vlan\n")
        iface = next(i for i in pc.interfaces if i.name == _GI)
        assert iface.trunk_allowed_vlans == []
        assert _TPFX in iface_nc(pc, _GI)

    def test_running_config_fold_without_negation_unchanged(self):
        # Regression: with NO bare negation present, the anchored fold is intact.
        pc = _parse(
            f"interface {_GI}\n"
            " switchport trunk allowed vlan 10,20\n"
            " switchport trunk allowed vlan add 30\n"
        )
        iface = next(i for i in pc.interfaces if i.name == _GI)
        assert iface.trunk_allowed_vlans == [10, 20, 30]
        assert _TPFX not in iface_nc(pc, _GI)

    def test_reset_then_absolute_reanchors(self):
        pc = _parse(
            f"interface {_GI}\n"
            " switchport trunk allowed vlan 1,2,3\n"
            " no switchport trunk allowed vlan\n"
            " switchport trunk allowed vlan 5,6\n"
        )
        iface = next(i for i in pc.interfaces if i.name == _GI)
        assert iface.trunk_allowed_vlans == [5, 6]      # re-anchored after reset
        assert _TPFX in iface_nc(pc, _GI)               # reset still emitted


# ---------------------------------------------------------------------------
# ipv6_addresses — cisco-ios "no ipv6 address removes all manually configured…"
# ---------------------------------------------------------------------------


class TestIpv6WholeListReset:
    _PFX = f"field:interface:{_GI}:ipv6_addresses"

    def test_bare_negation_emits_reset(self):
        pc = _parse(
            f"interface {_GI}\n"
            " ipv6 address 2001:DB8::1/64\n"
            " no ipv6 address\n"
        )
        assert self._PFX in iface_nc(pc, _GI)
        op = _reset_op(pc, _GI, "ipv6_addresses")
        assert op is not None and op.verb is Verb.UNSET

    def test_add_then_reset_ordered(self):
        pc = _parse(
            f"interface {_GI}\n"
            " ipv6 address 2001:DB8::1/64\n"   # L2 member SET
            " no ipv6 address\n"               # L3 reset
        )
        ops = _iface_ops(pc, _GI, "ipv6_addresses")
        member_set = next(o for o in ops if o.verb is Verb.SET)
        reset = next(o for o in ops if o.verb is Verb.UNSET)
        assert member_set.line_no < reset.line_no   # reset wins (later line)

    def test_no_negation_no_reset(self):
        pc = _parse(f"interface {_GI}\n ipv6 address 2001:DB8::1/64\n")
        assert self._PFX not in iface_nc(pc, _GI)
        assert _reset_op(pc, _GI, "ipv6_addresses") is None

    def test_member_negation_is_not_whole_list_reset(self):
        # Operand-bearing form must NOT trigger the whole-list reset op.
        pc = _parse(
            f"interface {_GI}\n"
            " ipv6 address 2001:DB8::1/64\n"
            " no ipv6 address 2001:DB8::1/64\n"
        )
        assert self._PFX not in iface_nc(pc, _GI)
        assert _reset_op(pc, _GI, "ipv6_addresses") is None


# ---------------------------------------------------------------------------
# helper_addresses — EOS emits the bare "no ip helper-address" (parity)
# ---------------------------------------------------------------------------


class TestHelperWholeListResetEOS:
    _ETH = "Ethernet1"
    _PFX = f"field:interface:Ethernet1:helper_addresses"

    def test_eos_bare_negation_emits_reset(self):
        pc = _parse(
            f"interface {self._ETH}\n"
            " ip helper-address 10.0.0.1\n"
            " no ip helper-address\n",
            cls=EOSParser,
        )
        assert self._PFX in iface_nc(pc, self._ETH)
        op = _reset_op(pc, self._ETH, "helper_addresses")
        assert op is not None and op.verb is Verb.UNSET

    def test_member_negation_still_routes_member_removal(self):
        # Regression: the operand-bearing member form keeps its 5-segment
        # member-removal op (LIST_REMOVE on the ``helper`` member path) and does
        # NOT emit a whole-list reset.
        pc = _parse(
            f"interface {self._ETH}\n"
            " ip helper-address 10.0.0.1\n"
            " ip helper-address 10.0.0.2\n"
            " no ip helper-address 10.0.0.1\n",
            cls=EOSParser,
        )
        member_removals = [
            op
            for op in pc.native_change_ops or []
            if op.verb is Verb.LIST_REMOVE
            and op.path == ("field", "interface", self._ETH, "helper", "10.0.0.1")
        ]
        assert len(member_removals) == 1
        # No whole-list reset op for the operand-bearing form.
        assert _reset_op(pc, self._ETH, "helper_addresses") is None


# ---------------------------------------------------------------------------
# Cross-OS: the reset is inherited by NX-OS/EOS (shared IOSParser walk).
# ---------------------------------------------------------------------------


def test_ipv6_reset_inherited_by_eos():
    pc = _parse(
        f"interface {_GI}\n ipv6 address 2001:DB8::1/64\n no ipv6 address\n",
        cls=EOSParser,
    )
    assert f"field:interface:{_GI}:ipv6_addresses" in iface_nc(pc, _GI)
