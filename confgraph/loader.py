"""confgraph.loader — public API for loading and parsing device config files.

This module is the single point of truth for OS detection and parser dispatch.
Import from here, not from confgraph.cli.

    from confgraph.loader import load_and_parse

    parsed, detected_os = load_and_parse(Path("router.cfg"), os_type="ios")
"""

from __future__ import annotations

import csv
import importlib
import os
import re
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Mapping

from confgraph.models.base import OSType

# ---------------------------------------------------------------------------
# Public: parser registry
# ---------------------------------------------------------------------------
#
# One entry per OS. An entry owns BOTH the parser class and the file extensions
# that OS's configs arrive in, so the two can never drift apart: config
# discovery derives its accepted extensions from this table (see
# ``config_extensions``) rather than from a literal tuple maintained elsewhere.
# Registering a seventh parser is one new entry — its file type is discoverable
# by construction.

# Extensions used by the CLI-style (plain-text) OSes. "" matches a file with no
# extension at all (e.g. ``configs/r1``).
TEXT_CONFIG_EXTENSIONS: tuple[str, ...] = (".cfg", ".conf", ".txt", "")


@dataclass(frozen=True)
class ParserRegistration:
    """How one OS is parsed and what its config files are called on disk."""

    os_type: OSType
    module: str
    class_name: str
    extensions: tuple[str, ...] = TEXT_CONFIG_EXTENSIONS

    def parser_class(self) -> type:
        """Import and return the parser class (lazy — parsers are heavy)."""
        return getattr(importlib.import_module(self.module), self.class_name)


PARSER_REGISTRY: dict[OSType, ParserRegistration] = {
    r.os_type: r
    for r in (
        ParserRegistration(OSType.IOS, "confgraph.parsers.ios_parser", "IOSParser"),
        ParserRegistration(OSType.IOS_XE, "confgraph.parsers.ios_parser", "IOSParser"),
        ParserRegistration(OSType.IOS_XR, "confgraph.parsers.iosxr_parser", "IOSXRParser"),
        ParserRegistration(OSType.NXOS, "confgraph.parsers.nxos_parser", "NXOSParser"),
        ParserRegistration(OSType.EOS, "confgraph.parsers.eos_parser", "EOSParser"),
        ParserRegistration(OSType.JUNOS, "confgraph.parsers.junos_parser", "JunOSParser"),
        # PAN-OS exports an XML document, not a CLI-style text config.
        ParserRegistration(
            OSType.PANOS, "confgraph.parsers.panos_parser", "PANOSParser",
            extensions=(".xml",) + TEXT_CONFIG_EXTENSIONS,
        ),
    )
}


def parser_for(os_type: OSType) -> type:
    """Return the parser class registered for *os_type*.

    Raises:
        KeyError: if no parser is registered for *os_type*.
    """
    return PARSER_REGISTRY[os_type].parser_class()


def config_extensions(os_type: OSType | None = None) -> tuple[str, ...]:
    """Return the config-file extensions discovery should accept.

    With *os_type*: that OS's extensions, most specific first.
    Without: the union across every registered parser, de-duplicated and
    order-stable. This is the *only* definition of "a file confgraph can read" —
    nothing else may hard-code an extension tuple.
    """
    if os_type is not None:
        reg = PARSER_REGISTRY.get(os_type)
        if reg is not None:
            return reg.extensions
    ordered: list[str] = []
    for reg in PARSER_REGISTRY.values():
        for ext in reg.extensions:
            if ext not in ordered:
                ordered.append(ext)
    return tuple(ordered)


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


def as_os_type(os_type: str | OSType | None) -> OSType | None:
    """Normalize an os_type string ('nx-os', 'iosxr', …) to an ``OSType``.

    Returns None when *os_type* is falsy or unrecognized.
    """
    if os_type is None or os_type == "":
        return None
    if isinstance(os_type, OSType):
        return os_type
    try:
        return OSType(OS_ALIASES.get(os_type.lower(), os_type.lower()))
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Public: config discovery
# ---------------------------------------------------------------------------

@dataclass
class DiscoveredConfigs:
    """What a config directory scan found — and, explicitly, what it did not.

    ``configs``  hostname → config file, for every inventory device with a file.
    ``missing``  (hostname, [filenames searched]) for every inventory device
                 with no file. An absent device is a *reported* absence.
    ``skipped``  (path, reason) for every file in the directory that was not
                 used: unreadable extension, or no inventory device claims it.

    The three states used to be one silence. Callers are expected to report
    ``missing`` and ``skipped`` — see ``confgraph.cli.cmd_topology``.
    """

    configs: dict[str, Path] = field(default_factory=dict)
    missing: list[tuple[str, list[str]]] = field(default_factory=list)
    skipped: list[tuple[Path, str]] = field(default_factory=list)


def discover_device_configs(
    configs_dir: Path,
    inventory: Mapping[str, str | OSType],
) -> DiscoveredConfigs:
    """Locate one config file per inventory device inside *configs_dir*.

    For each device the candidate filenames are ``<hostname><ext>`` for every
    extension in ``config_extensions()`` — the device's own OS extensions first
    (so ``fw1.xml`` is found for a PAN-OS box), then the rest of the registered
    set. The extension only *locates* the file; the inventory's os_type decides
    how it is parsed.

    Nothing here reads or parses a file; it only reports what is there.
    """
    result = DiscoveredConfigs()
    all_extensions = config_extensions()
    claimed: set[Path] = set()

    for hostname, os_type in inventory.items():
        os_enum = as_os_type(os_type)
        preferred = config_extensions(os_enum)
        ordered_exts = list(preferred) + [e for e in all_extensions if e not in preferred]

        searched: list[str] = []
        for ext in ordered_exts:
            candidate = configs_dir / f"{hostname}{ext}"
            searched.append(candidate.name)
            if candidate.is_file():
                result.configs[hostname] = candidate
                claimed.add(candidate)
                break
        else:
            result.missing.append((hostname, searched))

    for path in sorted(configs_dir.iterdir()):
        if not path.is_file() or path in claimed or path.name.startswith("."):
            continue
        used = result.configs.get(path.stem)
        if path.suffix not in all_extensions:
            reason = (
                f"unsupported extension '{path.suffix}' (no registered parser reads it; "
                f"accepted: {', '.join(e or '<no extension>' for e in all_extensions)})"
            )
        elif used is not None:
            # The device IS in the inventory — a second file for it was shadowed by
            # a higher-priority extension. Saying "no device named …" here would be
            # a confidently wrong warning, which is worse than the silence T1 removed.
            reason = (
                f"a second config file for '{path.stem}', which was read from "
                f"'{used.name}' instead"
            )
        else:
            reason = f"no device named '{path.stem}' in the inventory"
        result.skipped.append((path, reason))

    return result


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

    # Dispatch through the registry — the same table config discovery reads its
    # extensions from, so a registered parser is always both reachable and
    # discoverable. IOS is the fallback for anything unregistered.
    registration = PARSER_REGISTRY.get(detected) or PARSER_REGISTRY[OSType.IOS]
    parsed = registration.parser_class()(text).parse()

    return parsed, detected
