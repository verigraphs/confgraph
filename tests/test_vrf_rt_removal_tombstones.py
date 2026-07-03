"""Parser tombstone emission for VRF / route-target removals.

CCR: confgraph_vrf_rt_removal_tombstones.md (Fable-5 review, F6 follow-up / WI-7).

Since the WI-4 merge made ``route_target_*`` lists additive (device-faithful:
RT lines accumulate on IOS), the only way an RT set can shrink or be replaced
is the ``no route-target …`` form.  These tests pin that the parsers emit the
``field:vrfs:…`` tombstones for every removal shape:

  - ``no route-target import <rt>``  → ``field:vrfs:<name>:route_target_import:<rt>``
  - ``no route-target export <rt>``  → ``field:vrfs:<name>:route_target_export:<rt>``
  - ``no route-target both <rt>``    → ``field:vrfs:<name>:route_target_both:<rt>``
  - ``no rd [<rd>]``                 → ``field:vrfs:<name>:rd``
  - ``no vrf definition <name>``     → ``field:vrfs:<name>``          (IOS)
  - ``no vrf context <name>``        → ``field:vrfs:<name>``          (NX-OS)

The ``vrfs`` (plural) segment matches the ParsedConfig field name so the
engine classifier routes the tombstones to the VRF coverage area.
"""

from __future__ import annotations

from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.nxos_parser import NXOSParser


def _ios_tombstones(config: str) -> list[str]:
    return IOSParser(config).parse_deletion_commands()


def _nxos_tombstones(config: str) -> list[str]:
    return NXOSParser(config).parse_deletion_commands()


# ---------------------------------------------------------------------------
# IOS — nested route-target / rd removals inside ``vrf definition``
# ---------------------------------------------------------------------------

class TestIOSRouteTargetRemoval:
    def test_no_route_target_import_emits_tombstone(self):
        config = """\
vrf definition GUEST
 rd 65400:1
 address-family ipv4
  no route-target import 65400:10
"""
        assert "field:vrfs:GUEST:route_target_import:65400:10" in _ios_tombstones(config)

    def test_no_route_target_export_emits_tombstone(self):
        config = """\
vrf definition GUEST
 address-family ipv4
  no route-target export 65400:10
"""
        assert "field:vrfs:GUEST:route_target_export:65400:10" in _ios_tombstones(config)

    def test_no_route_target_both_emits_tombstone(self):
        config = """\
vrf definition SHARED
 address-family ipv4
  no route-target both 65400:99
"""
        assert "field:vrfs:SHARED:route_target_both:65400:99" in _ios_tombstones(config)

    def test_removal_directly_under_vrf_block(self):
        """IOS accepts route-target lines at VRF level too (ip vrf style)."""
        config = """\
vrf definition GUEST
 no route-target import 65400:10
"""
        assert "field:vrfs:GUEST:route_target_import:65400:10" in _ios_tombstones(config)

    def test_no_rd_emits_scalar_reset_tombstone(self):
        config = """\
vrf definition GUEST
 no rd 65400:1
"""
        assert "field:vrfs:GUEST:rd" in _ios_tombstones(config)

    def test_no_rd_bare_emits_scalar_reset_tombstone(self):
        config = """\
vrf definition GUEST
 no rd
"""
        assert "field:vrfs:GUEST:rd" in _ios_tombstones(config)

    def test_mixed_removal_and_addition(self):
        """The device-true RT replacement shape: no-old + new in one block."""
        config = """\
vrf definition GUEST
 rd 65400:1
 address-family ipv4
  no route-target export 65400:10
  no route-target import 65400:10
  route-target export 65400:20
  route-target import 65400:20
"""
        tombs = _ios_tombstones(config)
        assert "field:vrfs:GUEST:route_target_export:65400:10" in tombs
        assert "field:vrfs:GUEST:route_target_import:65400:10" in tombs
        # positive lines must NOT tombstone…
        assert not any("65400:20" in t for t in tombs)
        # …and must still parse as additions.
        vrf = IOSParser(config).parse_vrfs()[0]
        assert vrf.route_target_import == ["65400:20"]
        assert vrf.route_target_export == ["65400:20"]

    def test_positive_only_block_emits_no_vrf_tombstones(self):
        config = """\
vrf definition GUEST
 rd 65400:1
 address-family ipv4
  route-target import 65400:10
"""
        assert not any(t.startswith("field:vrfs:") for t in _ios_tombstones(config))


# ---------------------------------------------------------------------------
# IOS — top-level whole-VRF deletion
# ---------------------------------------------------------------------------

class TestIOSVRFDefinitionRemoval:
    def test_no_vrf_definition_emits_tombstone(self):
        assert "field:vrfs:CUST-A" in _ios_tombstones("no vrf definition CUST-A\n")

    def test_other_vrfs_not_tombstoned(self):
        tombs = _ios_tombstones(
            "no vrf definition CUST-A\nvrf definition CUST-B\n rd 65400:2\n"
        )
        assert tombs.count("field:vrfs:CUST-A") == 1
        assert not any(t.startswith("field:vrfs:CUST-B") for t in tombs)


# ---------------------------------------------------------------------------
# NX-OS — ``vrf context`` spelling (nested + top-level)
# ---------------------------------------------------------------------------

class TestNXOSVRFRemoval:
    def test_no_route_target_import_inside_vrf_context(self):
        config = """\
vrf context GUEST
  address-family ipv4 unicast
    no route-target import 65400:10
"""
        assert "field:vrfs:GUEST:route_target_import:65400:10" in _nxos_tombstones(config)

    def test_no_route_target_export_inside_vrf_context(self):
        config = """\
vrf context GUEST
  no route-target export 65400:10
"""
        assert "field:vrfs:GUEST:route_target_export:65400:10" in _nxos_tombstones(config)

    def test_no_route_target_both_inside_vrf_context(self):
        config = """\
vrf context SHARED
  no route-target both 65400:99
"""
        assert "field:vrfs:SHARED:route_target_both:65400:99" in _nxos_tombstones(config)

    def test_no_rd_inside_vrf_context(self):
        config = """\
vrf context GUEST
  no rd 65400:1
"""
        assert "field:vrfs:GUEST:rd" in _nxos_tombstones(config)

    def test_no_vrf_context_emits_tombstone(self):
        assert "field:vrfs:CUST-A" in _nxos_tombstones("no vrf context CUST-A\n")
