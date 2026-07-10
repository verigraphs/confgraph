"""Regression tests for CCR-0033.

Two resolver defects in ``DependencyResolver``:

A. A ``Null0`` (discard) static-route next hop was emitted as an ``interface``
   reference; since ``Null0`` never exists as an ``InterfaceConfig`` it read as
   a dangling reference -> ERROR -> ``confgraph map --lint`` exited 1 on a
   perfectly valid blackhole/aggregate config.
B. VRF ``route-map import`` / ``route-map export`` references were never turned
   into resolved edges, so the named route-maps were wrongly reported orphaned.

The fix adds a shared discard predicate (``is_discard_interface``) in
``confgraph.utils.interface`` and a new ``_resolve_vrfs`` method to the resolver.
"""

from __future__ import annotations

from ipaddress import IPv4Network

from click.testing import CliRunner

from confgraph.analysis.dependency_resolver import DependencyResolver
from confgraph.cli import main
from confgraph.models.base import OSType
from confgraph.models.parsed_config import ParsedConfig
from confgraph.models.route_map import RouteMapConfig
from confgraph.models.static_route import StaticRoute
from confgraph.models.vrf import VRFConfig
from confgraph.utils.interface import is_discard_interface


# ---------------------------------------------------------------------------
# The discard predicate itself
# ---------------------------------------------------------------------------

def test_is_discard_interface_recognizes_vendor_spellings():
    # IOS / IOS-XE / EOS / IOS-XR
    assert is_discard_interface("Null0") is True
    assert is_discard_interface("Null1") is True
    assert is_discard_interface("null0") is True
    assert is_discard_interface("Null") is True
    # JunOS
    assert is_discard_interface("discard") is True
    assert is_discard_interface("dsc") is True


def test_is_discard_interface_does_not_over_trigger():
    # A real interface must never be classified as discard (over-trigger guard).
    assert is_discard_interface("Ethernet0") is False
    assert is_discard_interface("GigabitEthernet0/1") is False
    assert is_discard_interface("Loopback0") is False
    # Near-miss: shares the "Null" prefix but is a different type token.
    assert is_discard_interface("Nullipsis0") is False
    assert is_discard_interface("") is False


# ---------------------------------------------------------------------------
# Finding A — Null0 next hop is not dangling
# ---------------------------------------------------------------------------

def _config_with_next_hop_iface(next_hop_iface: str) -> ParsedConfig:
    return ParsedConfig(
        source_os=OSType.IOS,
        hostname="r1",
        static_routes=[
            StaticRoute(
                object_id="sr1",
                source_os=OSType.IOS,
                destination=IPv4Network("10.0.0.0/8"),
                next_hop_interface=next_hop_iface,
            ),
        ],
    )


def test_null0_next_hop_not_dangling():
    report = DependencyResolver(_config_with_next_hop_iface("Null0")).resolve()
    # No dangling reference at all...
    assert report.dangling_refs == []
    # ...and specifically no interface link was emitted for the discard target.
    assert not any(
        l.ref_type == "interface" and l.ref_name == "Null0" for l in report.links
    )


def test_genuine_dangling_next_hop_still_dangling():
    # Points at an interface that does not exist -> must still be dangling.
    report = DependencyResolver(_config_with_next_hop_iface("GigabitEthernet9/9")).resolve()
    dangling = report.dangling_refs
    assert len(dangling) == 1
    assert dangling[0].ref_type == "interface"
    assert dangling[0].ref_name == "GigabitEthernet9/9"


# ---------------------------------------------------------------------------
# Finding B — VRF import/export route-maps resolve and are not orphaned
# ---------------------------------------------------------------------------

def _rm(name: str) -> RouteMapConfig:
    return RouteMapConfig(object_id=f"rm_{name}", source_os=OSType.IOS, name=name)


def test_vrf_route_map_import_export_resolved_and_not_orphaned():
    config = ParsedConfig(
        source_os=OSType.IOS,
        hostname="r1",
        route_maps=[_rm("RM_IN"), _rm("RM_OUT")],
        vrfs=[
            VRFConfig(
                object_id="vrf_BLUE",
                source_os=OSType.IOS,
                name="BLUE",
                route_map_import="RM_IN",
                route_map_export="RM_OUT",
            ),
        ],
    )
    report = DependencyResolver(config).resolve()

    import_links = [
        l for l in report.links
        if l.source_type == "vrf" and l.source_field == "route_map_import"
    ]
    export_links = [
        l for l in report.links
        if l.source_type == "vrf" and l.source_field == "route_map_export"
    ]
    assert len(import_links) == 1
    assert import_links[0].ref_type == "route_map"
    assert import_links[0].ref_name == "RM_IN"
    assert import_links[0].resolved is True
    assert len(export_links) == 1
    assert export_links[0].ref_name == "RM_OUT"
    assert export_links[0].resolved is True

    # Both route-maps must now be absent from the orphan report.
    orphaned_rms = {o.name for o in report.orphaned if o.object_type == "route_map"}
    assert "RM_IN" not in orphaned_rms
    assert "RM_OUT" not in orphaned_rms


def test_vrf_without_route_map_emits_no_edge():
    config = ParsedConfig(
        source_os=OSType.IOS,
        vrfs=[VRFConfig(object_id="vrf_RED", source_os=OSType.IOS, name="RED")],
    )
    report = DependencyResolver(config).resolve()
    assert not any(
        l.source_type == "vrf" and l.source_field in ("route_map_import", "route_map_export")
        for l in report.links
    )


def test_vrf_import_route_map_missing_is_dangling():
    # If the referenced route-map does not exist, the edge must be dangling
    # (the fix must not resolve names that are not defined).
    config = ParsedConfig(
        source_os=OSType.IOS,
        vrfs=[
            VRFConfig(
                object_id="vrf_BLUE",
                source_os=OSType.IOS,
                name="BLUE",
                route_map_import="RM_MISSING",
            ),
        ],
    )
    report = DependencyResolver(config).resolve()
    dangling = [l for l in report.dangling_refs if l.ref_name == "RM_MISSING"]
    assert len(dangling) == 1
    assert dangling[0].ref_type == "route_map"


# ---------------------------------------------------------------------------
# Behavioral — `confgraph map --lint` exit codes via the CLI
# ---------------------------------------------------------------------------

_NULL0_CFG = """\
hostname r1
!
interface GigabitEthernet0/0
 ip address 192.0.2.1 255.255.255.0
!
ip route 10.0.0.0 255.0.0.0 Null0
"""

_DANGLING_CFG = """\
hostname r1
!
interface GigabitEthernet0/0
 ip address 192.0.2.1 255.255.255.0
!
ip route 10.0.0.0 255.0.0.0 GigabitEthernet9/9
"""


def _run_lint(tmp_path, cfg_text: str, name: str):
    cfg = tmp_path / name
    cfg.write_text(cfg_text)
    runner = CliRunner()
    return runner.invoke(
        main,
        ["map", str(cfg), "--os", "ios", "--out", "json",
         "--output-dir", str(tmp_path), "--lint"],
    )


def test_lint_null0_exits_zero(tmp_path):
    result = _run_lint(tmp_path, _NULL0_CFG, "null0.cfg")
    assert result.exit_code == 0, result.output
    assert "Dangling ref" not in result.output


def test_lint_genuine_dangling_exits_one(tmp_path):
    result = _run_lint(tmp_path, _DANGLING_CFG, "dangling.cfg")
    assert result.exit_code == 1, result.output
    assert "GigabitEthernet9/9" in result.output
