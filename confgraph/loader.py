"""confgraph.loader — public API for loading and parsing device config files.

This module is the single point of truth for OS detection and parser dispatch.
Import from here, not from confgraph.cli.

    from confgraph.loader import load_and_parse

    parsed, detected_os = load_and_parse(Path("router.cfg"), os_type="ios")
"""

from __future__ import annotations

import csv
import os
import re
import warnings
from pathlib import Path
from typing import Callable

from confgraph.models.base import OSType

# ---------------------------------------------------------------------------
# Public: OS alias map
# ---------------------------------------------------------------------------

OS_ALIASES: dict[str, str] = {
    "iosxr":  "ios_xr",
    "ios_xr": "ios_xr",
    "ios":    "ios",
    "nxos":   "nxos",
    "nx-os":  "nxos",
    "eos":    "eos",
    "junos":  "junos",
    "panos":  "panos",
    "pan-os": "panos",
}

# Column name sets for inventory CSV parsing (public so callers can reuse them)
DEVICE_COLS: frozenset[str] = frozenset({"device_name", "device", "devicename", "hostname", "host_name"})
OS_COLS: frozenset[str] = frozenset({"os_type", "ostype", "os-type"})

# Private aliases for internal use
_DEVICE_COLS = DEVICE_COLS
_OS_COLS = OS_COLS


# ---------------------------------------------------------------------------
# Private helpers (inventory + hostname extraction)
# ---------------------------------------------------------------------------

def _load_inventory(log_fn: Callable | None = None) -> dict[str, str]:
    """Return hostname→os_type mapping from the CSV pointed to by CONFGRAPH_INVENTORY.

    Returns an empty dict if the env var is unset or the file cannot be read.
    """
    path = os.environ.get("CONFGRAPH_INVENTORY", "").strip()
    if not path:
        return {}
    try:
        with open(path, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            if reader.fieldnames is None:
                return {}

            device_col = next(
                (f for f in reader.fieldnames if f.strip().lower() in _DEVICE_COLS), None
            )
            os_col = next(
                (f for f in reader.fieldnames if f.strip().lower() in _OS_COLS), None
            )
            if not device_col or not os_col:
                if log_fn:
                    log_fn(
                        f"Warning: Inventory CSV '{path}' missing required columns "
                        f"(need a device name column and an os_type column).",
                        err=True,
                    )
                return {}

            inventory: dict[str, str] = {}
            for row in reader:
                host = row.get(device_col, "").strip()
                os_raw = row.get(os_col, "").strip().lower()
                os_val = OS_ALIASES.get(os_raw)
                if host and os_val:
                    inventory[host] = os_val
            return inventory
    except OSError as exc:
        if log_fn:
            log_fn(f"Warning: Could not read inventory file '{path}': {exc}", err=True)
        return {}


def _hostname_from_config(text: str, path_stem: str) -> str:
    """Extract hostname from config text, falling back to filename stem."""
    m = re.search(r"^hostname\s+(\S+)", text, re.MULTILINE)
    return m.group(1) if m else path_stem


# ---------------------------------------------------------------------------
# Public: OS detection
# ---------------------------------------------------------------------------

def _detect_os_internal(text: str) -> tuple[OSType, bool]:
    """Heuristic OS detection. Returns (OSType, confident) where confident=False
    means no signal matched and IOS is the default fallback."""
    # PAN-OS
    for sig in ("<config version=", "<devices>", "<vsys>", "<rulebase>",
                "panos", "PAN-OS", "<virtual-router>"):
        if sig in text:
            return OSType.PANOS, True

    # EOS
    for sig in ("Arista", "EOS-", "vEOS", "daemon Accounting",
                "ip virtual-router", "transceiver qsfp"):
        if sig in text:
            return OSType.EOS, True

    # NX-OS
    for sig in ("vrf context ", "feature ", " vdc ", "Nexus"):
        if sig in text:
            return OSType.NXOS, True

    # JunOS (brace-style and set-style)
    for sig in ("system {", "interfaces {", "protocols {",
                "routing-options {", "set system host-name"):
        if sig in text:
            return OSType.JUNOS, True
    set_junos_sigs = ("set routing-instances ", "set policy-options ",
                      "set protocols bgp ", "set protocols ospf ",
                      "set interfaces ", "set routing-options ")
    if sum(1 for s in set_junos_sigs if s in text) >= 2:
        return OSType.JUNOS, True

    # IOS-XR
    for sig in ("RP/0/", "route-policy\n", "prefix-set\n",
                "ipv4 address ", "neighbor-group "):
        if sig in text:
            return OSType.IOS_XR, True

    # IOS / IOS-XE (explicit signal → confident)
    for sig in ("Cisco IOS", "IOS-XE", "IOS XE"):
        if sig in text:
            return OSType.IOS, True

    # No signal matched — IOS is the default fallback (not confident)
    return OSType.IOS, False


def detect_os(text: str) -> OSType:
    """Heuristically detect OS type from config text.

    Returns the detected OSType. Falls back to IOS when no signal is found;
    does not emit any warnings — callers are responsible for logging.
    """
    os_type, _ = _detect_os_internal(text)
    return os_type


# ---------------------------------------------------------------------------
# Public: load and parse
# ---------------------------------------------------------------------------

def load_and_parse(
    config_path: Path,
    os_type: str | None,
    *,
    log_fn: Callable | None = None,
):
    """Read a config file, detect its OS type, and return a parsed config.

    Args:
        config_path: Path to the device config file.
        os_type:     Explicit OS type string (e.g. "ios", "iosxr", "eos").
                     Pass None to trigger inventory lookup then heuristic detection.
        log_fn:      Optional callable for diagnostic messages (e.g. click.echo).
                     When None (default), all messages are suppressed — suitable
                     for library use. The CLI passes click.echo to preserve output.

    Returns:
        (ParsedConfig, OSType) tuple.
    """
    text = config_path.read_text(encoding="utf-8", errors="replace")

    if os_type:
        detected = OSType(OS_ALIASES.get(os_type.lower(), os_type))
    else:
        inventory = _load_inventory(log_fn=log_fn)
        if inventory:
            hostname = _hostname_from_config(text, config_path.stem)
            os_from_inv = inventory.get(hostname)
            if os_from_inv:
                detected = OSType(os_from_inv)
                if log_fn:
                    log_fn(
                        f"  OS resolved from inventory: {detected.value} (hostname: {hostname})",
                        err=True,
                    )
            else:
                if log_fn:
                    log_fn(
                        f"  Warning: Hostname '{hostname}' not found in inventory — "
                        "falling back to auto-detection.",
                        err=True,
                    )
                detected, confident = _detect_os_internal(text)
                if not confident and log_fn:
                    log_fn(
                        "Warning: OS type could not be auto-detected — defaulting to IOS. "
                        "Use --os to specify explicitly.",
                        err=True,
                    )
        else:
            detected, confident = _detect_os_internal(text)
            if not confident and log_fn:
                log_fn(
                    "Warning: OS type could not be auto-detected — defaulting to IOS. "
                    "Use --os to specify explicitly.",
                    err=True,
                )

    if detected == OSType.PANOS:
        from confgraph.parsers.panos_parser import PANOSParser
        parsed = PANOSParser(text).parse()
    elif detected == OSType.EOS:
        from confgraph.parsers.eos_parser import EOSParser
        parsed = EOSParser(text).parse()
    elif detected == OSType.NXOS:
        from confgraph.parsers.nxos_parser import NXOSParser
        parsed = NXOSParser(text).parse()
    elif detected == OSType.IOS_XR:
        from confgraph.parsers.iosxr_parser import IOSXRParser
        parsed = IOSXRParser(text).parse()
    elif detected == OSType.JUNOS:
        from confgraph.parsers.junos_parser import JunOSParser
        parsed = JunOSParser(text).parse()
    else:
        from confgraph.parsers.ios_parser import IOSParser
        parsed = IOSParser(text).parse()

    return parsed, detected
