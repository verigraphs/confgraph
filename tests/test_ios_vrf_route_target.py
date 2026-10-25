"""Parser tests for IOS ``vrf definition`` route-target extraction.

Regression coverage for the CCR where the IOS parser dropped the nested
``address-family ipv4`` / ``route-target import|export|both`` lines, leaving
``VRFConfig.route_target_import/export/both`` empty. The route-target lines on
IOS live one level below the VRF block (under ``address-family ipv4``), so the
parser must descend into the AF sub-block — matching NX-OS behavior.
"""

from __future__ import annotations

from confgraph.parsers.ios_parser import IOSParser


def _vrfs(config: str):
    return IOSParser(config).parse_vrfs()


def test_vrf_definition_route_targets_parsed():
    config = """\
vrf definition GUEST
 rd 65400:1
 address-family ipv4
  route-target export 65400:10
  route-target import 65400:10
"""
    vrfs = _vrfs(config)
    assert len(vrfs) == 1
    vrf = vrfs[0]
    assert vrf.name == "GUEST"
    assert vrf.rd == "65400:1"
    assert vrf.route_target_import == ["65400:10"]
    assert vrf.route_target_export == ["65400:10"]
    # Nested AF lines must also be captured in raw_lines.
    assert any("route-target import" in ln for ln in vrf.raw_lines)
    assert any("route-target export" in ln for ln in vrf.raw_lines)


def test_vrf_definition_route_target_both():
    config = """\
vrf definition SHARED
 rd 65400:2
 address-family ipv4
  route-target both 65400:99
"""
    vrf = _vrfs(config)[0]
    assert vrf.route_target_both == ["65400:99"]
    assert vrf.route_target_import == []
    assert vrf.route_target_export == []


def test_vrf_definition_multiple_route_targets():
    config = """\
vrf definition MULTI
 rd 65400:3
 address-family ipv4
  route-target import 65400:10
  route-target import 65400:20
  route-target export 65400:30
"""
    vrf = _vrfs(config)[0]
    assert vrf.route_target_import == ["65400:10", "65400:20"]
    assert vrf.route_target_export == ["65400:30"]
