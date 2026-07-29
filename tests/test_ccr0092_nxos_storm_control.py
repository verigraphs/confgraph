"""CCR-0092 — NX-OS interface storm-control is unmodeled and dropped.

Device-verified on n9kv 10.5(5) (own containerlab, push+readback). ``InterfaceConfig``
had no storm-control field, so ``storm-control {broadcast|multicast|unicast} level
<threshold>`` under an interface was silently dropped (the line was on the interface
known-child allowlist, so not even disclosed).

The fix adds ``InterfaceConfig.storm_control`` — a per-traffic-type list of
``StormControlLevel(traffic_type, level, unit)`` — and reads the lines in
``NXOSParser.parse_interfaces``. The field is registered in change_ir family-8e
(``_IFACE_MEMBER_KEYS`` / mirror boundary tests), keyed by ``traffic_type``, the same
per-member shape as the FHRP group lists.

Emitted syntax authority — ``syntax-corpus/nxos/interface-security.yaml``:
  * ``storm-control`` (verified-capture, 2026-07-20-n9kv-10.5.5-ifsec.txt): the PERCENT
    form emits a fixed two-decimal percent — typed ``level 5`` prints ``level 5.00``,
    ``level 10`` prints ``level 10.00``, ``level 100`` prints ``level 100.00``. All the
    percent fixtures below use that emitted ``.NN`` formatting.
  * The packets-per-second variant ``level pps <value>`` is doc-sourced only (Cisco NX-OS
    9000 security config guide 10.5x — keyword ``pps`` precedes the value), and its
    EMITTED numeric formatting is capture-pending (no device capture exists). No ``bps``
    form is documented for NX-OS 9000 storm-control (percent + pps only). Per the
    novel-syntax gate — fixtures must be device-EMITTED — this test suite therefore ships
    ONLY the verified-capture percent fixtures. The parser still handles the ``pps``/``bps``
    unit keywords leniently (defensive, doc-structured), but no non-verified fixture line is
    authored here.

Values assert exactly (handbook §7.5 — no presence-only checks).
"""
from confgraph.models.interface import StormControlLevel
from confgraph.parsers.nxos_parser import NXOSParser


def _iface(interfaces, name):
    return next(i for i in interfaces if i.name == name)


# Device-emitted percent forms for all three traffic types, two-decimal .NN
# formatting (verified-capture). port-security lines are the CCR's CLEAN block —
# they must keep parsing unchanged when storm-control is added beside them.
NXOS_STORM_PERCENT = """feature port-security
interface Ethernet1/10
  switchport port-security
  switchport port-security maximum 5
  switchport port-security violation restrict
  switchport port-security mac-address sticky
  spanning-tree bpduguard enable
  storm-control broadcast level 5.00
  storm-control multicast level 10.00
  storm-control unicast level 100.00
"""


def _storm_by_type(iface):
    return {s.traffic_type: s for s in iface.storm_control}


def test_broadcast_multicast_unicast_percent_levels_populate():
    p = NXOSParser(NXOS_STORM_PERCENT).parse()
    eth = _iface(p.interfaces, "Ethernet1/10")
    sc = _storm_by_type(eth)
    assert set(sc) == {"broadcast", "multicast", "unicast"}
    assert sc["broadcast"].level == 5.0
    assert sc["broadcast"].unit == "percent"
    assert sc["multicast"].level == 10.0
    assert sc["multicast"].unit == "percent"
    assert sc["unicast"].level == 100.0
    assert sc["unicast"].unit == "percent"


def test_storm_control_members_are_stormcontrollevel_objects():
    p = NXOSParser(NXOS_STORM_PERCENT).parse()
    eth = _iface(p.interfaces, "Ethernet1/10")
    assert len(eth.storm_control) == 3
    assert all(isinstance(s, StormControlLevel) for s in eth.storm_control)


def test_port_security_still_clean_beside_storm_control():
    # The CCR's CLEAN block must not regress when storm-control is parsed.
    p = NXOSParser(NXOS_STORM_PERCENT).parse()
    eth = _iface(p.interfaces, "Ethernet1/10")
    assert eth.port_security_enabled is True
    assert eth.port_security_max_mac == 5
    assert eth.port_security_violation == "restrict"
    assert eth.port_security_sticky is True
    assert eth.stp_bpduguard is True


def test_interface_without_storm_control_stays_empty():
    p = NXOSParser("interface Ethernet1/12\n  no shutdown\n").parse()
    eth = _iface(p.interfaces, "Ethernet1/12")
    assert eth.storm_control == []
