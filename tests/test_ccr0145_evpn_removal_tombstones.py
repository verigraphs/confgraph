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

import pytest

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

    def test_evpn_suffixed_without_vni_uses_the_by_vrf_keying(self):
        """EXPECTATION CHANGED IN WI-E2 (validation V-1) — deliberately.

        This test previously asserted that with no ``vni N`` in scope the
        removal clears the VRFConfig copy ONLY and emits no ``field:evpn:``
        tombstone at all.  That reasoning ("no vni line, so no L3VNI") holds
        only for a WHOLE-CONFIG parse.  Product proposals are PARTIAL SNIPPETS,
        where the L3VNI exists in the BASELINE and the snippet simply does not
        restate it — so the old behaviour left the authoritative EVPN copy
        stale while the shadow copy was cleared: the very N1 incoherence this
        CCR exists to close, reachable from the most ordinary input shape.

        The EVPN half is now emitted VRF-NAME-keyed, and the engine resolves it
        against the baseline's L3VNIs by ``vrf``.  The VNI-KEYED form is still
        (correctly) absent — that part of the original assertion stands.
        """
        cfg = (
            "vrf context NOVNI\n"
            "  address-family ipv4 unicast\n"
            "    no route-target both 65001:9 evpn\n"
        )
        ts = _tombstones(cfg)
        assert "field:vrfs:NOVNI:route_target_both:65001:9" in ts
        assert "field:evpn:l3vnis_by_vrf:NOVNI:route_target_both:65001:9" in ts
        # No VNI was in scope, so no VNI-keyed tombstone may be invented.
        assert not any(t.startswith("field:evpn:l3vnis:") for t in ts), ts


# ---------------------------------------------------------------------------
# Byte-exactness — the legacy shim reproduces every tombstone verbatim
# ---------------------------------------------------------------------------

def test_roundtrip_byte_exact_colon_valued_rt():
    # The RT value carries its own colon; ``":".join(op.path)`` must reproduce
    # the tombstone byte-for-byte.  WI-E2 added the ``_COLON_VALUE_SHAPES`` rows
    # that COLLAPSE the RT tail into one segment, and the join is the inverse of
    # both forms — which is exactly why the flip is byte-invariant here.
    cfg = "evpn\n  vni 920010 l2\n    no route-target import 65001:100\n"
    assert "field:evpn:l2vnis:920010:route_target_import:65001:100" in _tombstones(cfg)


# ---------------------------------------------------------------------------
# WI-E2 additions — the paired colon-collapse rows and the two F2/F3 fixes.
# ---------------------------------------------------------------------------

class TestNativePathCollapse:
    """The EVPN ``_COLON_VALUE_SHAPES`` rows (WI-E2) keep the colon-valued RT
    tail as ONE op-path segment — the SET convention (CCR-0110 E6).

    These rows are HALF of a cross-repo pair: the engine's matching
    ``_FIELD_TABLE`` TAIL rows must land in the SAME change, or the entrp
    cross-source pin (``tests/deletion_dispatch/test_native_path_convention.py``)
    fails naming both files.  Pinned here too, so a one-sided revert of the
    confgraph half is caught in THIS repo.
    """

    def _paths(self, cfg: str) -> list[tuple]:
        return [tuple(op.path) for op in derive_ops(NXOSParser(cfg).parse())
                if op.verb is Verb.LIST_REMOVE]

    def test_l2vni_rt_value_is_one_segment(self):
        cfg = ("evpn\n  vni 920010 l2\n"
               "    no route-target import 65001:100\n"
               "    no route-target export 4200000001:10\n")
        assert self._paths(cfg) == [
            ("field", "evpn", "l2vnis", "920010", "route_target_import", "65001:100"),
            ("field", "evpn", "l2vnis", "920010", "route_target_export", "4200000001:10"),
        ]

    def test_l3vni_dual_tombstone_both_halves_collapse(self):
        cfg = ("vrf context TEN\n  vni 70000\n"
               "  address-family ipv4 unicast\n"
               "    no route-target both 64086.59905:20010 evpn\n")
        assert self._paths(cfg) == [
            ("field", "vrfs", "TEN", "route_target_both", "64086.59905:20010"),
            ("field", "evpn", "l3vnis", "70000", "route_target_both", "64086.59905:20010"),
        ]

    def test_rd_and_whole_entry_shapes_are_unaffected(self):
        # Colon-free values: no row matches, so split already equals collapsed.
        paths = {tuple(op.path) for op in
                 derive_ops(NXOSParser("evpn\n  vni 920010 l2\n    no rd\n"
                                       "  no vni 920011 l2\n").parse())}
        assert ("field", "evpn", "l2vnis", "920010", "rd") in paths
        assert ("field", "evpn", "l2vnis", "920011") in paths


class TestOverTriggerAndCaseHandling:
    def test_no_vni_with_trailing_garbage_fires_nothing(self):
        """F2 (WI-E2): the ``no vni N l2|l3`` regex is END-ANCHORED now.  A bare
        ``\\b`` let a trailing token still fire a real OBJECT_DELETE — the
        grammar-token-in-name-position over-trigger class."""
        ts = _tombstones("evpn\n  no vni 920011 l2 bogus\n")
        assert not any(t.startswith("field:evpn:") for t in ts), ts

    def test_no_vni_exact_form_still_fires(self):
        """Non-vacuity control for the anchor above."""
        assert "field:evpn:l2vnis:920011" in _tombstones("evpn\n  no vni 920011 l2\n")

    def test_uppercase_evpn_suffix_emits_both_tombstones(self):
        """F3 (WI-E2): the trailing token is case-insensitive now.  ``EVPN`` used
        to fail the anchored match outright and drop BOTH halves silently — the
        inherited plain vrfs patterns end ``(\\S+)\\s*$`` so they never saw the
        line either, making a removal look applied when nothing was."""
        cfg = ("vrf context TEN\n  vni 70000\n"
               "  address-family ipv4 unicast\n"
               "    no route-target both 65001:7 EVPN\n")
        ts = _tombstones(cfg)
        assert "field:vrfs:TEN:route_target_both:65001:7" in ts
        assert "field:evpn:l3vnis:70000:route_target_both:65001:7" in ts

    def test_a_plain_removal_is_still_vrfs_only(self):
        """The case fix must not turn a PLAIN (L3VPN) removal into an EVPN one."""
        cfg = ("vrf context TEN\n  vni 70000\n"
               "  address-family ipv4 unicast\n"
               "    no route-target both 65001:7\n")
        ts = _tombstones(cfg)
        assert "field:vrfs:TEN:route_target_both:65001:7" in ts
        assert not any(t.startswith("field:evpn:") for t in ts), ts


# ---------------------------------------------------------------------------
# WI-E2 round 2 — the BY-VRF fallback (V-1) and the ``no rd`` value slot (V-2).
# ---------------------------------------------------------------------------

class TestByVrfFallback:
    """Product proposals are PARTIAL SNIPPETS, so the common real shape is a
    ``vrf context`` block carrying only the ``no`` line — no sibling ``vni N``
    to key the EVPN half on.  Keying on an absent VNI emitted the vrfs half
    ALONE and left the two parsed copies incoherent: the exact N1 harm, reached
    from ordinary input.  The EVPN half is now VRF-NAME-keyed when no VNI is in
    scope, and the engine resolves it against the baseline's L3VNIs by ``vrf``.
    """

    SNIPPET_RT = (
        "vrf context TEN\n  address-family ipv4 unicast\n"
        "    no route-target both 65001:7 evpn\n"
    )

    def test_rt_removal_without_a_vni_emits_both_halves(self):
        ts = _tombstones(self.SNIPPET_RT)
        assert "field:vrfs:TEN:route_target_both:65001:7" in ts
        assert "field:evpn:l3vnis_by_vrf:TEN:route_target_both:65001:7" in ts

    def test_rd_removal_without_a_vni_emits_both_halves(self):
        ts = _tombstones("vrf context TEN\n  no rd\n")
        assert "field:vrfs:TEN:rd" in ts
        assert "field:evpn:l3vnis_by_vrf:TEN:rd" in ts

    def test_a_declared_vni_still_takes_the_vni_keying(self):
        """The fallback is a fallback — when the VNI IS in scope the precise
        keying wins, so nothing about the previous behaviour changes."""
        ts = _tombstones(
            "vrf context TEN\n  vni 70000\n  address-family ipv4 unicast\n"
            "    no route-target both 65001:7 evpn\n"
        )
        assert "field:evpn:l3vnis:70000:route_target_both:65001:7" in ts
        assert not any("l3vnis_by_vrf" in t for t in ts), ts

    def test_verb_mapping_matches_the_vni_keyed_forms(self):
        verbs = _verb_by_path(self.SNIPPET_RT)
        assert verbs["field:evpn:l3vnis_by_vrf:TEN:route_target_both:65001:7"] \
            is Verb.LIST_REMOVE
        assert _verb_by_path("vrf context TEN\n  no rd\n")[
            "field:evpn:l3vnis_by_vrf:TEN:rd"] is Verb.UNSET

    def test_rt_value_tail_collapses_like_the_vni_keyed_form(self):
        paths = [tuple(op.path) for op in derive_ops(NXOSParser(
            "vrf context TEN\n  address-family ipv4 unicast\n"
            "    no route-target import 64086.59905:20011 evpn\n"
        ).parse()) if op.verb is Verb.LIST_REMOVE]
        assert paths == [
            ("field", "vrfs", "TEN", "route_target_import", "64086.59905:20011"),
            ("field", "evpn", "l3vnis_by_vrf", "TEN",
             "route_target_import", "64086.59905:20011"),
        ]

    def test_plain_removal_without_a_vni_stays_vrfs_only(self):
        """The fallback must not widen the plain/evpn split."""
        ts = _tombstones(
            "vrf context TEN\n  address-family ipv4 unicast\n"
            "    no route-target both 65001:7\n"
        )
        assert "field:vrfs:TEN:route_target_both:65001:7" in ts
        assert not any(t.startswith("field:evpn:") for t in ts), ts

    def test_whole_vni_delete_has_no_by_vrf_form(self):
        """``no vni N`` names its own key — nothing to fall back from."""
        ts = _tombstones("vrf context TEN\n  no vni 70000\n")
        assert "field:evpn:l3vnis:70000" in ts
        assert not any("l3vnis_by_vrf" in t for t in ts), ts


class TestRdValueSlot:
    """V-2: the optional value after ``no rd`` was ``\\S+`` — ANY single token —
    so ``no rd bogus`` emitted a real reset.  It is now constrained to the RD
    grammar (``auto`` or a colon-bearing ASN2:NN / ASN4:NN / IPV4:NN)."""

    @pytest.mark.parametrize(
        "line,fires",
        [
            ("no rd", True),
            ("no rd auto", True),
            ("no rd 65000:66", True),
            ("no rd 4200000001:10", True),
            ("no rd 10.0.0.1:5", True),
            ("no rd bogus", False),
            ("no rd permit", False),
        ],
    )
    def test_value_slot_is_grammar_constrained(self, line, fires):
        ts = _tombstones(f"evpn\n  vni 920010 l2\n    {line}\n")
        assert (("field:evpn:l2vnis:920010:rd" in ts) is fires), ts
