"""confgraph CLI — parse, visualize, and lint vendor network configs.

Usage:
    confgraph map  ./router.cfg --lint
    confgraph map  ./router.cfg --os eos --out both --output-dir /tmp
    confgraph info ./router.cfg
"""

from __future__ import annotations

import logging
import sys
import warnings
from pathlib import Path

import click

# Silence noisy deprecation warnings from ciscoconfparse2 internals
warnings.filterwarnings("ignore", category=UserWarning, module="ciscoconfparse2")
logging.getLogger("ciscoconfparse2").setLevel(logging.CRITICAL)
try:
    from loguru import logger as _loguru_logger
    _loguru_logger.disable("ciscoconfparse2")
except ImportError:
    pass

from confgraph.models.base import OSType
from confgraph.parsers.base import ParseError


# ---------------------------------------------------------------------------
# Inventory lookup (CONFGRAPH_INVENTORY env var → CSV file)
# ---------------------------------------------------------------------------

_DEVICE_COLS  = {"device_name", "device", "devicename", "hostname", "host_name"}
_OS_COLS      = {"os_type", "ostype", "os-type"}
_OS_ALIAS     = {"iosxr": "ios_xr", "ios_xr": "ios_xr", "ios": "ios",
                 "nxos": "nxos", "nx-os": "nxos", "eos": "eos",
                 "junos": "junos"}


def _load_inventory() -> dict[str, str]:
    """Return hostname→os_type mapping from the CSV pointed to by CONFGRAPH_INVENTORY.

    Returns an empty dict if the env var is unset or the file cannot be read.
    """
    import csv, os
    path = os.environ.get("CONFGRAPH_INVENTORY", "").strip()
    if not path:
        return {}
    try:
        with open(path, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            if reader.fieldnames is None:
                return {}

            # Find the actual column names (case-insensitive)
            device_col = next(
                (f for f in reader.fieldnames if f.strip().lower() in _DEVICE_COLS), None
            )
            os_col = next(
                (f for f in reader.fieldnames if f.strip().lower() in _OS_COLS), None
            )
            if not device_col or not os_col:
                click.echo(
                    f"Warning: Inventory CSV '{path}' missing required columns "
                    f"(need a device name column and an os_type column).",
                    err=True,
                )
                return {}

            inventory: dict[str, str] = {}
            for row in reader:
                host = row.get(device_col, "").strip()
                os_raw = row.get(os_col, "").strip().lower()
                os_val = _OS_ALIAS.get(os_raw)
                if host and os_val:
                    inventory[host] = os_val
            return inventory
    except OSError as exc:
        click.echo(f"Warning: Could not read inventory file '{path}': {exc}", err=True)
        return {}


def _hostname_from_config(text: str, path_stem: str) -> str:
    """Extract hostname from config text, falling back to filename stem."""
    import re
    m = re.search(r"^hostname\s+(\S+)", text, re.MULTILINE)
    return m.group(1) if m else path_stem


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _detect_os(text: str) -> OSType:
    """Heuristically detect OS type from config text."""
    # EOS signals
    for sig in ("Arista", "EOS-", "vEOS", "daemon Accounting",
                "ip virtual-router", "transceiver qsfp"):
        if sig in text:
            return OSType.EOS

    # NX-OS signals
    for sig in ("vrf context ", "feature ", " vdc ", "Nexus"):
        if sig in text:
            return OSType.NXOS

    # JunOS signals — brace-style and set-style
    for sig in ("system {", "interfaces {", "protocols {",
                "routing-options {", "set system host-name"):
        if sig in text:
            return OSType.JUNOS
    # set-style JunOS: require at least 2 characteristic set prefixes
    set_junos_sigs = ("set routing-instances ", "set policy-options ",
                      "set protocols bgp ", "set protocols ospf ",
                      "set interfaces ", "set routing-options ")
    if sum(1 for s in set_junos_sigs if s in text) >= 2:
        return OSType.JUNOS

    # IOS-XR signals
    for sig in ("RP/0/", "route-policy\n", "prefix-set\n",
                "ipv4 address ", "neighbor-group "):
        if sig in text:
            return OSType.IOS_XR

    # IOS / IOS-XE signals
    for sig in ("Cisco IOS", "IOS-XE", "IOS XE"):
        if sig in text:
            return OSType.IOS

    click.echo(
        "Warning: OS type could not be auto-detected — defaulting to IOS. "
        "Use --os to specify explicitly.",
        err=True,
    )
    return OSType.IOS


def _load_and_parse(config_path: Path, os_type: str | None):
    """Read config file, detect OS, parse, return (parsed, detected_os)."""
    text = config_path.read_text(encoding="utf-8", errors="replace")

    if os_type:
        # CLI uses "iosxr" but the enum value is "ios_xr"
        detected = OSType(_OS_ALIAS.get(os_type.lower(), os_type))
    else:
        # 1. Inventory lookup (CONFGRAPH_INVENTORY env var)
        inventory = _load_inventory()
        if inventory:
            hostname = _hostname_from_config(text, config_path.stem)
            os_from_inv = inventory.get(hostname)
            if os_from_inv:
                detected = OSType(os_from_inv)
                click.echo(
                    f"  OS resolved from inventory: {detected.value} (hostname: {hostname})",
                    err=True,
                )
            else:
                click.echo(
                    f"  Warning: Hostname '{hostname}' not found in inventory — "
                    "falling back to auto-detection.",
                    err=True,
                )
                detected = _detect_os(text)
        else:
            # 2. Heuristic fallback
            detected = _detect_os(text)

    if detected == OSType.EOS:
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


# ---------------------------------------------------------------------------
# CLI root
# ---------------------------------------------------------------------------

@click.group()
@click.version_option(version="0.1.0", prog_name="confgraph")
def main() -> None:
    """confgraph — local-first network config dependency mapper."""


# ---------------------------------------------------------------------------
# map command
# ---------------------------------------------------------------------------

@main.command("map")
@click.argument("config_file", type=click.Path(exists=True, path_type=Path))
@click.option("--os", "os_type", type=click.Choice(["eos", "ios", "nxos", "iosxr", "junos"]),
              default=None, help="OS type (auto-detected if omitted)")
@click.option("--out", "output_format", type=click.Choice(["html", "json", "both"]),
              default="html", show_default=True, help="Output format")
@click.option("--output-dir", type=click.Path(path_type=Path), default=None,
              help="Directory for output files (default: current dir)")
@click.option("--lint", is_flag=True, help="Surface orphans and dangling refs")
@click.option("--lint-severity", type=click.Choice(["error", "warn", "all"]),
              default="all", show_default=True, help="Lint issue filter")
def cmd_map(config_file: Path, os_type, output_format, output_dir, lint, lint_severity):
    """Parse a config file and generate a dependency graph."""
    from confgraph.graph import GraphBuilder, HTMLExporter, JSONExporter
    from confgraph.analysis import DependencyResolver

    output_dir = output_dir or Path.cwd()
    output_dir.mkdir(parents=True, exist_ok=True)
    stem = config_file.stem

    click.echo(f"Parsing {config_file.name} ...", err=True)
    try:
        parsed, detected = _load_and_parse(config_file, os_type)
    except ParseError as exc:
        click.echo(f"Error: Cannot parse {config_file.name}", err=True)
        click.echo(f"  Protocol : {exc.protocol}", err=True)
        if exc.line_number:
            click.echo(f"  Line {exc.line_number}: {exc.line_text}", err=True)
        click.echo(f"  Cause    : {exc.original}", err=True)
        sys.exit(1)
    except Exception as exc:
        click.echo(f"Error: Failed to parse {config_file.name}: {exc}", err=True)
        sys.exit(1)

    click.echo(f"  OS: {detected.value}  |  hostname: {parsed.hostname or '(unknown)'}", err=True)

    report = DependencyResolver(parsed).resolve()
    graph = GraphBuilder(parsed, report).build()

    written: list[Path] = []

    if output_format in ("html", "both"):
        html_path = output_dir / f"{stem}.html"
        html_path.write_text(HTMLExporter().export(graph), encoding="utf-8")
        written.append(html_path)

    if output_format in ("json", "both"):
        json_path = output_dir / f"{stem}.json"
        json_path.write_text(JSONExporter().export(graph), encoding="utf-8")
        written.append(json_path)

    for p in written:
        click.echo(f"  Written: {p}")

    if lint:
        _print_lint(config_file.name, report, lint_severity)


def _print_lint(filename: str, report, severity: str) -> None:
    """Print lint results to stdout."""
    errors = [
        (link.source_type, link.source_id, link.ref_type, link.ref_name)
        for link in report.dangling_refs
    ]
    warnings = [
        (obj.object_type, obj.name)
        for obj in report.orphaned
    ]

    # Apply severity filter
    show_errors = severity in ("error", "all")
    show_warnings = severity in ("warn", "all")

    total = (len(errors) if show_errors else 0) + (len(warnings) if show_warnings else 0)

    click.echo(f"\nLINT — {filename}")
    click.echo("─" * (len(filename) + 8))

    if total == 0:
        click.echo("  No issues found.")
        return

    if show_errors:
        for src_type, src_id, ref_type, ref_name in errors:
            click.echo(
                f"  [ERROR] Dangling ref:  {src_type} '{src_id}' → "
                f"{ref_type} '{ref_name}' (not defined)"
            )

    if show_warnings:
        for obj_type, name in warnings:
            click.echo(f"  [WARN]  Orphaned object: {obj_type} '{name}' (defined but never referenced)")

    click.echo(f"\n  {total} issue(s) found.")
    if errors and show_errors:
        sys.exit(1)


# ---------------------------------------------------------------------------
# info command
# ---------------------------------------------------------------------------

@main.command("info")
@click.argument("config_file", type=click.Path(exists=True, path_type=Path))
@click.option("--os", "os_type", type=click.Choice(["eos", "ios", "nxos", "iosxr", "junos"]),
              default=None, help="OS type (auto-detected if omitted)")
def cmd_info(config_file: Path, os_type):
    """Print a summary of parsed objects in a config file."""
    from confgraph.analysis import DependencyResolver

    try:
        parsed, detected = _load_and_parse(config_file, os_type)
    except ParseError as exc:
        click.echo(f"Error: Cannot parse {config_file.name}", err=True)
        click.echo(f"  Protocol : {exc.protocol}", err=True)
        if exc.line_number:
            click.echo(f"  Line {exc.line_number}: {exc.line_text}", err=True)
        click.echo(f"  Cause    : {exc.original}", err=True)
        sys.exit(1)
    except Exception as exc:
        click.echo(f"Error: Failed to parse {config_file.name}: {exc}", err=True)
        sys.exit(1)

    report = DependencyResolver(parsed).resolve()

    click.echo(f"\n{'─' * 40}")
    click.echo(f"  {config_file.name}")
    click.echo(f"{'─' * 40}")
    click.echo(f"  Hostname : {parsed.hostname or '(unknown)'}")
    click.echo(f"  OS       : {detected.value}")
    click.echo()

    counts = [
        ("Interfaces",    len(parsed.interfaces)),
        ("VRFs",          len(parsed.vrfs)),
        ("BGP instances", len(parsed.bgp_instances)),
        ("OSPF instances",len(parsed.ospf_instances)),
        ("Route-maps",    len(parsed.route_maps)),
        ("Prefix-lists",  len(parsed.prefix_lists)),
        ("ACLs",          len(parsed.acls)),
        ("Community-lists",len(parsed.community_lists)),
        ("AS-path-lists", len(parsed.as_path_lists)),
        ("Static routes", len(parsed.static_routes)),
        ("Class-maps",    len(parsed.class_maps)),
        ("Policy-maps",   len(parsed.policy_maps)),
        ("NTP",           1 if parsed.ntp else 0),
        ("SNMP",          1 if parsed.snmp else 0),
    ]

    for label, count in counts:
        if count:
            click.echo(f"  {label:<18} {count}")

    click.echo()
    dangling = len(report.dangling_refs)
    orphaned = len(report.orphaned)
    if dangling or orphaned:
        click.echo(f"  Dependency issues: {dangling} dangling ref(s), {orphaned} orphan(s)")
        click.echo("  Run with: confgraph map --lint  for details")
    else:
        click.echo("  No dependency issues found.")
    click.echo(f"{'─' * 40}\n")
