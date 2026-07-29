"""CCR-0091 — NX-OS IP SLA operation sub-parameters (port, frequency) dropped.

NX-OS emits an IP SLA operation as a config *submode*: the operation line
(`udp-jitter <dst> <port>`) is a child of `ip sla <id>`, and the timing
sub-parameters (`frequency`, `timeout`, `tag`) are nested one level deeper
BENEATH the operation line. The shared `parse_ip_sla` walk previously inspected
only the direct children of `ip sla <id>`, so on NX-OS it never reached the
nested timing lines, and it never extracted the trailing UDP/TCP port token at
all. Both `IPSLAOperation.port` and `.frequency` already exist on the model but
stayed `None`.

These assert exact device values (handbook §7.5 — no presence-only checks), from
the device-emitted shape recorded in
`syntax-corpus/nxos/pbr-sla-track.yaml::ip-sla-operation` (verified-capture,
n9kv 10.5(5)).
"""
from confgraph.parsers.nxos_parser import NXOSParser
from confgraph.parsers.ios_parser import IOSParser


def _find_sla(ops, sla_id):
    return next(op for op in ops if op.sla_id == sla_id)


# NX-OS device-emitted submode shape (frequency/timeout/tag nested under the op)
NXOS_SLA = """ip sla 100
  udp-jitter 10.199.60.1 5000
    frequency 30
    timeout 5000
    tag PROBE
"""


def test_nxos_udp_jitter_populates_port_and_frequency():
    ops = NXOSParser(NXOS_SLA).parse_ip_sla()
    op = _find_sla(ops, 100)
    # identity (already worked — pin so a regression here is loud)
    assert op.operation_type == "udp-jitter"
    assert op.destination == "10.199.60.1"
    # the CCR-0091 gap: these were dropped (None) before the fix
    assert op.port == 5000
    assert op.frequency == 30
    # sibling timing sub-parameters nested under the operation line
    assert op.timeout == 5000
    assert op.tag == "PROBE"


def test_nxos_udp_echo_port_extracted():
    cfg = "ip sla 200\n  udp-echo 10.199.60.2 7\n    frequency 15\n"
    op = _find_sla(NXOSParser(cfg).parse_ip_sla(), 200)
    assert op.operation_type == "udp-echo"
    assert op.destination == "10.199.60.2"
    assert op.port == 7
    assert op.frequency == 15


def test_nxos_icmp_echo_has_no_port():
    # ICMP operations carry no destination port; the port field must stay None
    # rather than mis-capturing a following keyword token.
    cfg = "ip sla 300\n  icmp-echo 10.199.60.3\n    frequency 60\n"
    op = _find_sla(NXOSParser(cfg).parse_ip_sla(), 300)
    assert op.operation_type == "icmp-echo"
    assert op.port is None
    assert op.frequency == 60


def test_ios_flat_form_not_regressed():
    # IOS emits the timing params FLAT as siblings of the operation line; the
    # all_children walk must keep parsing that shape, and icmp-echo has no port.
    cfg = (
        "ip sla 1\n"
        " icmp-echo 10.0.0.1 source-interface GigabitEthernet0/0\n"
        " frequency 10\n"
    )
    op = _find_sla(IOSParser(cfg).parse_ip_sla(), 1)
    assert op.operation_type == "icmp-echo"
    assert op.destination == "10.0.0.1"
    assert op.source_interface == "GigabitEthernet0/0"
    assert op.frequency == 10
    assert op.port is None
