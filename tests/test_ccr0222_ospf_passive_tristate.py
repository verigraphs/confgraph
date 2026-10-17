"""CCR-0222 (confgraph half) — per-interface ``[no] ip ospf passive-interface``.

``InterfaceConfig.ospf_passive`` is tri-state (``bool | None``): True = passive,
False = EXPLICITLY non-passive, None = the interface said nothing, so the
process-level passive config decides. Before this fix the field was
``bool = False``, the per-interface override was parsed by nobody, the ``no``
spelling surfaced as an UnrecognizedBlock, and the M3 back-fill from the
process-level lists had nothing to lose to.

The engine half (the ``_ospf_iface_passive`` resolver that consumes this) lives
in confgraph-entrp; the pairing hazard it creates is pinned there by a boundary
test on this very model default.
"""

from confgraph.models.interface import InterfaceConfig
from confgraph.parsers.eos_parser import EOSParser
from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.nxos_parser import NXOSParser

# The lab shape: an NX-OS aggregation switch hardened with
# ``passive-interface default``, two uplinks exempted per-interface, one
# interface left to the default, and two L2 ports outside OSPF entirely.
NX_LAB_SHAPE = """\
hostname nx-agg-1
!
interface loopback0
  ip address 10.255.0.11/32
  ip router ospf 1 area 0.0.0.0
!
interface Ethernet1/1
  description to xr-core-1
  no switchport
  ip address 10.0.6.2/30
  ip router ospf 1 area 0.0.0.0
  no ip ospf passive-interface
  no shutdown
!
interface Ethernet1/2
  description p2p to nx-agg-2
  no switchport
  ip address 10.0.13.1/30
  ip router ospf 1 area 0.0.0.0
  no ip ospf passive-interface
  no shutdown
!
interface Ethernet1/5
  description to panos-fw-1
  no switchport
  ip address 10.0.20.1/30
  ip router ospf 1 area 0.0.0.0
  no shutdown
!
interface Ethernet1/3
  switchport
  switchport mode trunk
!
router ospf 1
  router-id 10.255.0.11
  passive-interface default
!
"""


def _by_name(pc):
    return {i.name: i for i in pc.interfaces}


# ---------------------------------------------------------------------------
# The six parse outcomes: both polarities x with/without a process default,
# plus the two "nothing stated" cases.
# ---------------------------------------------------------------------------


def test_negation_under_process_default_is_explicit_false():
    """`no ip ospf passive-interface` beats `passive-interface default`."""
    pc = NXOSParser(NX_LAB_SHAPE).parse()
    ifaces = _by_name(pc)
    assert ifaces["Ethernet1/1"].ospf_passive is False
    assert ifaces["Ethernet1/2"].ospf_passive is False


def test_process_default_still_reaches_unexempted_members():
    """The M3 back-fill is guarded on None, not disabled."""
    pc = NXOSParser(NX_LAB_SHAPE).parse()
    ifaces = _by_name(pc)
    assert ifaces["Ethernet1/5"].ospf_passive is True
    assert ifaces["loopback0"].ospf_passive is True


def test_negation_without_any_process_default_is_still_explicit_false():
    cfg = (
        "interface Ethernet1/1\n"
        "  ip address 10.0.6.2/30\n"
        "  ip router ospf 1 area 0.0.0.0\n"
        "  no ip ospf passive-interface\n"
        "!\n"
        "router ospf 1\n"
        "!\n"
    )
    iface = _by_name(NXOSParser(cfg).parse())["Ethernet1/1"]
    assert iface.ospf_passive is False


def test_positive_form_without_process_default_is_true():
    """The POSITIVE spelling was dropped silently before this fix."""
    cfg = (
        "interface Ethernet1/1\n"
        "  ip address 10.0.6.2/30\n"
        "  ip router ospf 1 area 0.0.0.0\n"
        "  ip ospf passive-interface\n"
        "!\n"
        "router ospf 1\n"
        "!\n"
    )
    iface = _by_name(NXOSParser(cfg).parse())["Ethernet1/1"]
    assert iface.ospf_passive is True


def test_positive_form_under_process_default_is_true():
    cfg = (
        "interface Ethernet1/1\n"
        "  ip address 10.0.6.2/30\n"
        "  ip router ospf 1 area 0.0.0.0\n"
        "  ip ospf passive-interface\n"
        "!\n"
        "router ospf 1\n"
        "  passive-interface default\n"
        "!\n"
    )
    iface = _by_name(NXOSParser(cfg).parse())["Ethernet1/1"]
    assert iface.ospf_passive is True


def test_unmentioned_interface_outside_ospf_is_none():
    pc = NXOSParser(NX_LAB_SHAPE).parse()
    assert _by_name(pc)["Ethernet1/3"].ospf_passive is None


def test_last_line_wins_across_polarities():
    """Same semantics as every sibling `ip ospf *` scalar."""
    cfg = (
        "interface Ethernet1/1\n"
        "  ip address 10.0.6.2/30\n"
        "  ip ospf passive-interface\n"
        "  no ip ospf passive-interface\n"
        "!\n"
    )
    assert _by_name(NXOSParser(cfg).parse())["Ethernet1/1"].ospf_passive is False

    flipped = (
        "interface Ethernet1/1\n"
        "  ip address 10.0.6.2/30\n"
        "  no ip ospf passive-interface\n"
        "  ip ospf passive-interface\n"
        "!\n"
    )
    assert _by_name(NXOSParser(flipped).parse())["Ethernet1/1"].ospf_passive is True


# ---------------------------------------------------------------------------
# Disclosure + provenance: consumption and the CCR-0203 claim ledger move
# together. The `no` lines must leave unrecognized_blocks EXACTLY when the ops
# that consume them appear.
# ---------------------------------------------------------------------------


def test_no_lines_vanish_from_unrecognized_blocks():
    pc = NXOSParser(NX_LAB_SHAPE).parse()
    disclosed = [
        b for b in pc.unrecognized_blocks
        if "passive-interface" in (b.block_header or "")
        or any("passive-interface" in line for line in (b.raw_lines or []))
    ]
    assert disclosed == []


def test_set_ops_carry_the_real_negation_line():
    pc = NXOSParser(NX_LAB_SHAPE).parse()
    ops = {
        op.path[1]: op
        for op in pc.native_change_ops
        if len(op.path) == 3 and op.path[0] == "interface" and op.path[2] == "ospf_passive"
    }
    for name in ("Ethernet1/1", "Ethernet1/2"):
        op = ops[name]
        assert op.value is False
        assert op.source_line == "no ip ospf passive-interface"
        assert op.line_no > 0
    # The derived True (process default, no interface line) falls back to the
    # block header — provenance quality, never semantics.
    assert ops["Ethernet1/5"].value is True


def test_unstated_interfaces_emit_no_op():
    """None == the model default, so no SET op is derived."""
    pc = NXOSParser(NX_LAB_SHAPE).parse()
    names = [
        op.path[1]
        for op in pc.native_change_ops
        if len(op.path) == 3 and op.path[2] == "ospf_passive"
    ]
    assert "Ethernet1/3" not in names


# ---------------------------------------------------------------------------
# PARITY — the fix is in the SHARED walk, so NX-OS and EOS get it with zero
# additional code, and the IOS process-level spelling is untouched.
# ---------------------------------------------------------------------------


def test_eos_inherits_the_shared_walk_with_zero_new_code():
    """Same lab shape in EOS's own spelling — no EOS-side code was added."""
    eos_cfg = (
        "hostname eos-agg-1\n"
        "!\n"
        "interface Ethernet1\n"
        "   ip address 10.0.6.2/30\n"
        "   ip ospf area 0.0.0.0\n"
        "   no ip ospf passive-interface\n"
        "!\n"
        "interface Ethernet2\n"
        "   ip address 10.0.13.1/30\n"
        "   ip ospf area 0.0.0.0\n"
        "   ip ospf passive-interface\n"
        "!\n"
        "interface Ethernet5\n"
        "   ip address 10.0.20.1/30\n"
        "   ip ospf area 0.0.0.0\n"
        "!\n"
        "interface Ethernet3\n"
        "   switchport mode trunk\n"
        "!\n"
        "router ospf 1\n"
        "   passive-interface default\n"
        "!\n"
    )
    ifaces = _by_name(EOSParser(eos_cfg).parse())
    assert ifaces["Ethernet1"].ospf_passive is False
    assert ifaces["Ethernet2"].ospf_passive is True
    assert ifaces["Ethernet5"].ospf_passive is True   # M3 process default
    assert ifaces["Ethernet3"].ospf_passive is None   # outside OSPF


def test_ios_process_level_spelling_regression():
    """The IOS spelling lives in the OSPF process block and still decides."""
    cfg = (
        "interface GigabitEthernet0/0\n"
        " ip address 10.0.0.1 255.255.255.0\n"
        " ip ospf 1 area 0\n"
        "!\n"
        "interface GigabitEthernet0/1\n"
        " ip address 10.0.1.1 255.255.255.0\n"
        " ip ospf 1 area 0\n"
        "!\n"
        "router ospf 1\n"
        " passive-interface default\n"
        " no passive-interface GigabitEthernet0/1\n"
        "!\n"
    )
    ifaces = _by_name(IOSParser(cfg).parse())
    assert ifaces["GigabitEthernet0/0"].ospf_passive is True
    assert ifaces["GigabitEthernet0/1"].ospf_passive is False


def test_interface_line_beats_the_process_level_lists():
    """On hardware the interface block has the last word — so does the model."""
    cfg = (
        "interface Ethernet1/1\n"
        "  ip address 10.0.6.2/30\n"
        "  ip router ospf 1 area 0.0.0.0\n"
        "  no ip ospf passive-interface\n"
        "!\n"
        "router ospf 1\n"
        "  passive-interface Ethernet1/1\n"
        "!\n"
    )
    assert _by_name(NXOSParser(cfg).parse())["Ethernet1/1"].ospf_passive is False


# ---------------------------------------------------------------------------
# NEGATIVE / regression on the surrounding machinery.
# ---------------------------------------------------------------------------


def test_operand_bearing_spellings_do_not_match():
    """`$`-anchored: a passive-interface line with an operand is not this."""
    cfg = (
        "interface Ethernet1/1\n"
        "  ip address 10.0.6.2/30\n"
        "  ip ospf passive-interface detail\n"
        "!\n"
    )
    assert _by_name(NXOSParser(cfg).parse())["Ethernet1/1"].ospf_passive is None


def test_model_default_is_none():
    """The silent-skew tripwire's confgraph-side anchor (see the entrp twin)."""
    assert InterfaceConfig.model_fields["ospf_passive"].default is None


def test_backfill_guard_still_protects_an_explicit_zero():
    """The default-aware guard must not regress `ip ospf priority 0`.

    IOS-XR writes OSPF interface settings inside the process; the back-fill
    attributes them onto the interface, but never over a value the interface
    block itself set — and 0 is a real priority ("never become DR"), not an
    unset field.
    """
    cfg = (
        "interface GigabitEthernet0/0/0/0\n"
        " ipv4 address 10.0.0.1 255.255.255.252\n"
        " ip ospf priority 0\n"
        "!\n"
        "router ospf 1\n"
        " area 0\n"
        "  interface GigabitEthernet0/0/0/0\n"
        "   priority 33\n"
        "!\n"
    )
    iface = _by_name(IOSParser(cfg).parse())["GigabitEthernet0/0/0/0"]
    assert iface.ospf_priority == 0
