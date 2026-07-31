"""Parser tombstone emission for EVPN L2VNI / L3VNI removals (CCR-0145).

The ``evpn`` block merges device-faithfully additive (CCR-0142): RT lists inside
L2VNI / L3VNI entries are ``additive_lists`` members, so the ONLY way an RT set
can shrink is a ``no route-target …`` tombstone — exactly the VRF precedent
(``test_vrf_rt_removal_tombstones``).  These tests pin that the NX-OS parser emits
the ``field:evpn:…`` tombstones (and the N1 dual-tombstone for the ``vrf context``
copy-coherence surface) for every removal shape.

Device grounding: capture 2026-07-30 n9kv 10.5(5) — every removal renders by
OMISSION on the device, so the ``no`` forms below are PROPOSAL text only; the
device ACCEPTED each of them (``no route-target import <rt>`` / ``no rd`` under
``evpn / vni N l2``; ``no vni N l2`` under ``evpn``; ``no route-target both <rt>
evpn`` under a ``vrf context`` address-family).

Verb mapping (change_ir ``_TOP_TOMBSTONE_VERBS``): RT removals -> LIST_REMOVE,
``rd`` -> UNSET, whole-VNI -> OBJECT_DELETE.
"""

from __future__ import annotations

from confgraph.change_ir import Verb, derive_ops, encode_legacy_shim
from confgraph.parsers.nxos_parser import NXOSParser


def _tombstones(config: str) -> list[str]:
    """Byte-exact legacy tombstone strings reconstructed from the ChangeSet."""
    return encode_legacy_shim(derive_ops(NXOSParser(config).parse())).no_commands


def _verb_by_path(config: str) -> dict[str, Verb]:
    """Map ``":".join(op.path)`` -> verb for every derived op."""
    out: dict[str, Verb] = {}
    for op in derive_ops(NXOSParser(config).parse()):
        out[":".join(str(x) for x in op.path)] = op.verb
    return out


# ---------------------------------------------------------------------------
# L2VNI — removals under ``evpn / vni N l2``
# ---------------------------------------------------------------------------

class TestL2VNIRemoval:
    def test_no_route_target_import(self):
        cfg = "evpn\n  vni 920010 l2\n    no route-target import 65001:100\n"
        assert "field:evpn:l2vnis:920010:route_target_import:65001:100" in _tombstones(cfg)

    def test_no_route_target_export(self):
        cfg = "evpn\n  vni 920010 l2\n    no route-target export auto\n"
        assert "field:evpn:l2vnis:920010:route_target_export:auto" in _tombstones(cfg)

    def test_no_route_target_both_clears_the_pair(self):
        # Capture: the device treats ``both`` as the import/export pair; the
        # ``route_target_both`` template lets the engine accessor clear both.
        cfg = "evpn\n  vni 920010 l2\n    no route-target both 65001:200\n"
        assert "field:evpn:l2vnis:920010:route_target_both:65001:200" in _tombstones(cfg)

    def test_no_rd(self):
        cfg = "evpn\n  vni 920010 l2\n    no rd\n"
        assert "field:evpn:l2vnis:920010:rd" in _tombstones(cfg)

    def test_no_vni_l2_whole_entry(self):
        cfg = "evpn\n  no vni 30000 l2\n"
        assert "field:evpn:l2vnis:30000" in _tombstones(cfg)

    def test_no_vni_l3_under_evpn_is_permissive_l3vnis(self):
        # ``l3`` under ``evpn`` is not a device positive form (L3VNIs live under
        # ``vrf context``); a proposal that spells it still reaches a removal.
        cfg = "evpn\n  no vni 40000 l3\n"
        assert "field:evpn:l3vnis:40000" in _tombstones(cfg)

    def test_verbs(self):
        cfg = (
            "evpn\n"
            "  vni 920010 l2\n"
            "    no route-target import 65001:100\n"
            "    no rd\n"
            "  no vni 30000 l2\n"
        )
        verbs = _verb_by_path(cfg)
        assert verbs["field:evpn:l2vnis:920010:route_target_import:65001:100"] is Verb.LIST_REMOVE
        assert verbs["field:evpn:l2vnis:920010:rd"] is Verb.UNSET
        assert verbs["field:evpn:l2vnis:30000"] is Verb.OBJECT_DELETE


# ---------------------------------------------------------------------------
# L3VNI — the ``vrf context`` copy-coherence surface (N1)
# ---------------------------------------------------------------------------

class TestL3VNIDualTombstone:
    _CFG = (
        "vrf context TENANT\n"
        "  vni 950001\n"
        "  address-family ipv4 unicast\n"
        "    no route-target both 65001:50001 evpn\n"
        "    no route-target import 4200000001:10 evpn\n"
    )

    def test_evpn_suffixed_removal_clears_both_copies(self):
        ts = _tombstones(self._CFG)
        # Authoritative EVPN copy (keyed by vni).
        assert "field:evpn:l3vnis:950001:route_target_both:65001:50001" in ts
        assert "field:evpn:l3vnis:950001:route_target_import:4200000001:10" in ts
        # Parse-consistency shadow (VRFConfig copy, keyed by name).
        assert "field:vrfs:TENANT:route_target_both:65001:50001" in ts
        assert "field:vrfs:TENANT:route_target_import:4200000001:10" in ts
        # Exactly ONE vrfs op per line — the inherited plain-pattern walk must not
        # ALSO fire on the evpn-suffixed line (the N1 false-match guard).
        assert ts.count("field:vrfs:TENANT:route_target_both:65001:50001") == 1

    def test_svi_less_no_vni_l3_removes_entry(self):
        cfg = "vrf context TENANT\n  vni 950001 L3\n  no vni 950001 L3\n"
        assert "field:evpn:l3vnis:950001" in _tombstones(cfg)

    def test_no_rd_dual_copy(self):
        # The vrfs twin comes from the inherited vrfs walk; the evpn copy is the
        # CCR-0145 addition (only when the VRF declares an L3VNI ``vni N``).
        cfg = "vrf context TENANT\n  vni 950001\n  no rd\n"
        ts = _tombstones(cfg)
        assert "field:vrfs:TENANT:rd" in ts
        assert "field:evpn:l3vnis:950001:rd" in ts

    def test_no_vni_removes_l3vni_entry(self):
        cfg = "vrf context TENANT\n  vni 950001\n  no vni 950001\n"
        ts = _tombstones(cfg)
        assert "field:evpn:l3vnis:950001" in ts

    def test_verbs(self):
        verbs = _verb_by_path(self._CFG)
        assert verbs["field:evpn:l3vnis:950001:route_target_both:65001:50001"] is Verb.LIST_REMOVE
        assert verbs["field:vrfs:TENANT:route_target_both:65001:50001"] is Verb.LIST_REMOVE


# ---------------------------------------------------------------------------
# False-match regression — the plain vs evpn-suffixed split (N1, both directions)
# ---------------------------------------------------------------------------

class TestFalseMatchBothDirections:
    def test_plain_rt_removal_is_vrfs_only(self):
        # A plain (non-``evpn``) ``no route-target`` under ``vrf context`` is
        # L3VPN — it must NOT reach an EVPN copy, even when the VRF has an L3VNI.
        cfg = (
            "vrf context PLAIN\n"
            "  vni 60000\n"
            "  address-family ipv4 unicast\n"
            "    no route-target import 65001:7\n"
        )
        ts = _tombstones(cfg)
        assert "field:vrfs:PLAIN:route_target_import:65001:7" in ts
        assert not any(t.startswith("field:evpn:") for t in ts), ts

    def test_evpn_suffixed_removal_never_leaves_the_evpn_copy_out(self):
        # The mirror direction: an ``evpn``-suffixed removal MUST reach the EVPN
        # copy (not just the vrfs copy) whenever the VRF declares an L3VNI.
        cfg = (
            "vrf context TEN\n"
            "  vni 70000\n"
            "  address-family ipv4 unicast\n"
            "    no route-target export 65001:8 evpn\n"
        )
        ts = _tombstones(cfg)
        assert "field:evpn:l3vnis:70000:route_target_export:65001:8" in ts
        assert "field:vrfs:TEN:route_target_export:65001:8" in ts

    def test_evpn_suffixed_without_vni_clears_vrfs_copy_only(self):
        # No ``vni N`` => no L3VNI parsed => the value lives only in VRFConfig;
        # the removal clears that single copy.
        cfg = (
            "vrf context NOVNI\n"
            "  address-family ipv4 unicast\n"
            "    no route-target both 65001:9 evpn\n"
        )
        ts = _tombstones(cfg)
        assert "field:vrfs:NOVNI:route_target_both:65001:9" in ts
        assert not any(t.startswith("field:evpn:") for t in ts), ts


# ---------------------------------------------------------------------------
# Byte-exactness — the legacy shim reproduces every tombstone verbatim
# ---------------------------------------------------------------------------

def test_roundtrip_byte_exact_colon_valued_rt():
    # The RT value carries its own colon; ``":".join(op.path)`` must reproduce
    # the tombstone byte-for-byte (native path stays split, join is the inverse).
    cfg = "evpn\n  vni 920010 l2\n    no route-target import 65001:100\n"
    assert "field:evpn:l2vnis:920010:route_target_import:65001:100" in _tombstones(cfg)
