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

import warnings

from confgraph.loader import OS_ALIASES as _OS_ALIAS, detect_os as _detect_os, load_and_parse
from confgraph.models.base import OSType
from confgraph.parsers.base import ParseError


# ---------------------------------------------------------------------------
# Backward-compat shims (kept for any code still importing from confgraph.cli)
# ---------------------------------------------------------------------------

def _load_and_parse(config_path: Path, os_type: str | None):
    """Deprecated: use confgraph.loader.load_and_parse instead."""
    warnings.warn(
        "confgraph.cli._load_and_parse is deprecated and will be removed in a "
        "future release. Use 'from confgraph.loader import load_and_parse' instead.",
        DeprecationWarning,
        stacklevel=2,
    )
    return load_and_parse(config_path, os_type, log_fn=click.echo)


# ---------------------------------------------------------------------------
# CLI root
# ---------------------------------------------------------------------------

@click.group()
@click.version_option(version="0.2.0", prog_name="confgraph")
def main() -> None:
    """confgraph — local-first network config dependency mapper."""


# ---------------------------------------------------------------------------
# map command
# ---------------------------------------------------------------------------

@main.command("map")
@click.argument("config_file", type=click.Path(exists=True, path_type=Path))
@click.option("--os", "os_type", type=click.Choice(["eos", "ios", "nxos", "iosxr", "junos", "panos"]),
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
@click.option("--os", "os_type", type=click.Choice(["eos", "ios", "nxos", "iosxr", "junos", "panos"]),
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


# ---------------------------------------------------------------------------
# topology command
# ---------------------------------------------------------------------------

@main.command("topology")
@click.option("--inventory", "inventory_path", required=True,
              type=click.Path(exists=True, path_type=Path),
              help="CSV inventory file (hostname, os_type columns)")
@click.option("--configs-dir", "configs_dir", required=True,
              type=click.Path(exists=True, file_okay=False, path_type=Path),
              help="Directory containing device config files")
@click.option("--cdp", "cdp_path", default=None,
              type=click.Path(exists=True, path_type=Path),
              help="CDP neighbors CSV (local_device, local_port, remote_device, remote_port)")
@click.option("--lldp", "lldp_path", default=None,
              type=click.Path(exists=True, path_type=Path),
              help="LLDP neighbors CSV (local_device, local_port, remote_device, remote_port)")
@click.option("--mac-arp", "mac_arp_path", default=None,
              type=click.Path(exists=True, path_type=Path),
              help="MAC-ARP CSV for supplementary validation (device, interface, mac_address, ip_address)")
@click.option("--output", "html_path", default="topology.html",
              type=click.Path(path_type=Path),
              help="Output HTML file path [default: topology.html]")
@click.option("--json", "json_path", default=None,
              type=click.Path(path_type=Path),
              help="Output JSON file path (optional; consumed by enterprise simulator)")
@click.option("--title", default="Network Topology",
              help="Title shown in the HTML graph")
def cmd_topology(
    inventory_path: Path,
    configs_dir: Path,
    cdp_path: Path | None,
    lldp_path: Path | None,
    mac_arp_path: Path | None,
    html_path: Path,
    json_path: Path | None,
    title: str,
) -> None:
    """Build a multi-device topology graph from configs + optional discovery data.

    Produces a static HTML graph showing physical links, BGP sessions, and
    IGP adjacencies across all devices in the inventory.  Optionally exports
    a JSON file for use with the enterprise simulator (--json).
    """
    import csv as _csv
    from confgraph.loader import discover_device_configs
    from confgraph.topology.graph import TopologyGraphBuilder
    from confgraph.topology.exporters import export_topology_html, export_topology_json
    from confgraph.topology.ingest import load_physical_topology

    # --- Load inventory ---
    inventory: dict[str, str] = {}
    with open(inventory_path, newline="", encoding="utf-8") as fh:
        reader = _csv.DictReader(fh)
        for row in reader:
            row_lower = {k.strip().lower(): v.strip() for k, v in row.items()}
            host = (
                row_lower.get("hostname")
                or row_lower.get("device_name")
                or row_lower.get("device")
                or ""
            )
            os_raw = row_lower.get("os_type") or row_lower.get("os") or ""
            os_val = _OS_ALIAS.get(os_raw.lower())
            if host and os_val:
                inventory[host] = os_val

    if not inventory:
        click.echo("Error: inventory is empty or columns not recognized.", err=True)
        raise SystemExit(1)

    click.echo(f"Loaded {len(inventory)} devices from inventory.", err=True)

    # --- Discover device configs ---
    # Accepted extensions come from the parser registry (confgraph.loader), not
    # from a literal tuple here: a registered parser's file type is discoverable
    # by construction. Everything the scan does *not* use is reported, never
    # silently dropped.
    discovery = discover_device_configs(configs_dir, inventory)

    for hostname, searched in discovery.missing:
        click.echo(
            f"  Warning: No config file found for '{hostname}' in {configs_dir} "
            f"(searched: {', '.join(searched)}) — device omitted from the topology.",
            err=True,
        )
    for path, reason in discovery.skipped:
        click.echo(f"  Warning: Ignoring '{path.name}' — {reason}.", err=True)

    # --- Parse all device configs ---
    devices: dict = {}
    for hostname, cfg_file in discovery.configs.items():
        os_type = inventory[hostname]
        try:
            parsed, _ = load_and_parse(cfg_file, os_type)
        except OSError as exc:
            click.echo(
                f"  Warning: Skipping unreadable config file '{cfg_file.name}' "
                f"for '{hostname}': {exc}",
                err=True,
            )
            continue
        except Exception as exc:
            click.echo(f"  Warning: Could not parse {cfg_file.name}: {exc}", err=True)
            continue
        devices[hostname] = parsed
        click.echo(f"  Parsed: {hostname} ({os_type}) from {cfg_file.name}", err=True)

    if not devices:
        click.echo("Error: no device configs could be parsed.", err=True)
        raise SystemExit(1)

    # --- Load physical topology (optional) ---
    physical = None
    if cdp_path or lldp_path:
        try:
            physical = load_physical_topology(
                inventory=set(devices.keys()),
                devices=devices,
                cdp_path=cdp_path,
                lldp_path=lldp_path,
            )
            click.echo(f"  Physical links loaded: {len(physical)}", err=True)
        except Exception as exc:
            click.echo(f"  Warning: Could not load physical topology: {exc}", err=True)

    # --- Build graph ---
    builder = TopologyGraphBuilder(devices, physical_topology=physical)
    g = builder.build()
    for message in builder.warnings:
        click.echo(f"  Warning: {message}", err=True)
    click.echo(
        f"  Graph: {g.number_of_nodes()} devices, {g.number_of_edges()} edges",
        err=True,
    )

    # --- Export HTML ---
    html_path.parent.mkdir(parents=True, exist_ok=True)
    html_path.write_text(export_topology_html(g, title=title), encoding="utf-8")
    click.echo(f"  Written: {html_path}")

    # --- Export JSON (optional) ---
    if json_path is not None:
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(export_topology_json(g), encoding="utf-8")
        click.echo(f"  Written: {json_path}")


