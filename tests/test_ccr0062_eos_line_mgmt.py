"""CCR-0062 — EOS spells the `line vty` concept `management ssh|console|telnet`.

IOS numbers its session blocks (`line vty 0 4` / `exec-timeout 10 0` /
`transport input ssh`). EOS has no such block — the same concept (how long an
idle admin session survives, and over which transport) is emitted as top-level
`management ssh|console|telnet` blocks with an `idle-timeout <minutes>` child,
and the transport is named by the block itself rather than by a `transport
input` child (verified cEOS 4.36.1F, CCR-0062). Before this fix EOS produced
`ParsedConfig.lines == []` on every device.

Every config line here is a device-EMITTED form (matches the `management …` /
`idle-timeout …` shape in `_work/eos_full.cfg`). The EOS dialect is expressed as
four class-attribute table extensions over the shared `parse_lines` walk — no
EOS fork (CCR-0038 built the walk; CCR-0044/0059 deleted EOS forks).

Assertions are on VALUES, never on presence.
"""

from confgraph.parsers.eos_parser import EOSParser
from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.nxos_parser import NXOSParser
from confgraph.parsers.iosxr_parser import IOSXRParser
from confgraph.models.line import LineType


def _eos_lines(cfg: str):
    return EOSParser(cfg).parse().lines


# ---------------------------------------------------------------------------
# Positive — EOS `management ssh` is a remote-session line with the transport
# named by the block and the idle-timeout read as the exec timeout.
# ---------------------------------------------------------------------------

def test_eos_management_ssh_idle_timeout():
    lines = _eos_lines("management ssh\n   idle-timeout 15\n")
    ln = next(l for l in lines if "ssh" in l.transport_input)
    assert ln.line_type == LineType.VTY
    assert ln.transport_input == ["ssh"]
    assert ln.exec_timeout_minutes == 15
    assert ln.first_line is None  # EOS does not number lines


def test_eos_management_console_idle_timeout():
    lines = _eos_lines("management console\n   idle-timeout 20\n")
    ln = next(l for l in lines if l.line_type == LineType.CONSOLE)
    assert ln.exec_timeout_minutes == 20
    assert ln.transport_input == []  # console names no transport
    assert ln.first_line is None


# ---------------------------------------------------------------------------
# Parity — a THIRD transport (telnet) works with zero per-transport code,
# proving the transport is table-driven off the block name, not hardcoded.
# ---------------------------------------------------------------------------

def test_eos_management_telnet_parity():
    lines = _eos_lines("management telnet\n   idle-timeout 5\n")
    ln = next(l for l in lines if "telnet" in l.transport_input)
    assert ln.line_type == LineType.VTY
    assert ln.transport_input == ["telnet"]
    assert ln.exec_timeout_minutes == 5


# ---------------------------------------------------------------------------
# Disambiguation — the sibling `management api …` blocks must NOT become lines.
# ---------------------------------------------------------------------------

def test_eos_management_api_produces_no_line():
    lines = _eos_lines("management api http-commands\n   no shutdown\n")
    assert lines == []


def test_eos_management_api_gnmi_and_netconf_produce_no_line():
    cfg = (
        "management api gnmi\n   transport grpc default\n"
        "management api netconf\n   transport ssh default\n"
    )
    assert _eos_lines(cfg) == []


# ---------------------------------------------------------------------------
# Negative — a `management ssh` block with NO idle-timeout child leaves the
# timeout None (no crash, no invented 0).
# ---------------------------------------------------------------------------

def test_eos_management_ssh_without_idle_timeout_is_none():
    lines = _eos_lines("management ssh\n   shutdown\n")
    ln = next(l for l in lines if "ssh" in l.transport_input)
    assert ln.exec_timeout_minutes is None
    assert ln.exec_timeout_seconds is None


# ---------------------------------------------------------------------------
# No leak — the EOS spelling must not reach the IOS/NX-OS/IOS-XR paths, and the
# IOS `line vty` walk is unchanged.
# ---------------------------------------------------------------------------

def test_ios_line_vty_unchanged():
    cfg = "line vty 0 4\n exec-timeout 10 0\n transport input ssh\n"
    lines = IOSParser(cfg).parse().lines
    ln = next(l for l in lines if l.line_type == LineType.VTY)
    assert ln.first_line == 0
    assert ln.last_line == 4
    assert ln.exec_timeout_minutes == 10
    assert ln.exec_timeout_seconds == 0
    assert ln.transport_input == ["ssh"]


def test_ios_ignores_eos_management_ssh():
    cfg = "management ssh\n   idle-timeout 15\n"
    assert IOSParser(cfg).parse().lines == []


def test_nxos_ignores_eos_management_ssh():
    cfg = "management ssh\n   idle-timeout 15\n"
    assert NXOSParser(cfg).parse().lines == []


def test_iosxr_ignores_eos_management_ssh():
    cfg = "management ssh\n   idle-timeout 15\n"
    assert IOSXRParser(cfg).parse().lines == []
