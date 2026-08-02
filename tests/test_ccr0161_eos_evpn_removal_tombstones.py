"""Parser tombstone emission for EOS EVPN removals (CCR-0161).

EOS states the whole EVPN control-plane UNDER ``router bgp``: an L2VNI (MAC-VRF)
is a ``vlan <id>`` sub-block keyed by VLAN, an L3VNI is a ``vrf <name>`` sub-block
keyed by tenant VRF, and the overlay is an ``address-family evpn`` activation. The
VNI itself lives on ``interface Vxlan1``. CCR-0157 landed the ADDITIVE parse; this
CCR wires the REMOVAL forms to change-IR deletion verbs so an EVPN-teardown
proposal no longer simulates as no-impact.

Device grounding (capture 2026-08-01 cEOS 4.36.1F,
``2026-08-01-ceos-4.36.1F-evpn-deletion-forms.txt``): every removal is accepted
and renders by OMISSION EXCEPT ``no neighbor <x> activate`` under
``address-family evpn``, which EOS emits explicitly. The ``no`` spellings below
are therefore device-verified; ``default route-target …`` == the ``no`` form.

Verb mapping (change_ir ``_TOP_TOMBSTONE_VERBS``): RT removals -> LIST_REMOVE,
``rd`` -> UNSET, whole-VNI -> OBJECT_DELETE. AF deactivation is the CCR-0148
per-neighbor/peer-group AF-removal op (LIST_REMOVE, ops-only, no legacy twin).
"""

from __future__ import annotations

import pytest

from confgraph.change_ir import Verb, derive_ops, encode_legacy_shim
from confgraph.parsers.eos_parser import EOSParser


def _tombstones(config: str) -> list[str]:
    """Byte-exact legacy tombstone strings reconstructed from the ChangeSet."""
    return encode_legacy_shim(derive_ops(EOSParser(config).parse())).no_commands


def _verb_by_path(config: str) -> dict[str, Verb]:
    """Map ``":".join(op.path)`` -> verb for every derived op."""
    return {
        ":".join(str(x) for x in op.path): op.verb
        for op in derive_ops(EOSParser(config).parse())
    }


def _op_paths(config: str) -> list[tuple]:
    return [tuple(op.path) for op in derive_ops(EOSParser(config).parse())]


# ---------------------------------------------------------------------------
# L3VNI — ``router bgp / vrf <name>`` (VRF-NAME-keyed; the ``evpn`` keyword marks
# the EVPN RTs, distinguishing them from plain L3VPN)
# ---------------------------------------------------------------------------

class TestL3VNIRemoval:
    def test_no_route_target_import_evpn(self):
        cfg = (
            "router bgp 65101\n"
            "   vrf ZZ-TENANT\n"
            "      no route-target import evpn 50001:50001\n"
        )
        assert (
            "field:evpn:l3vnis_by_vrf:ZZ-TENANT:route_target_import:50001:50001"
            in _tombstones(cfg)
        )

    def test_no_route_target_export_evpn(self):
        cfg = (
            "router bgp 65101\n"
            "   vrf ZZ-TENANT\n"
            "      no route-target export evpn 50001:50001\n"
        )
        assert (
            "field:evpn:l3vnis_by_vrf:ZZ-TENANT:route_target_export:50001:50001"
            in _tombstones(cfg)
        )

    def test_no_rd_with_evpn_evidence(self):
        # ``no rd`` carries no ``evpn`` marker of its own, so the block must show
        # EVPN evidence (a ``route-target … evpn`` line) for the evpn copy to fire.
        cfg = (
            "router bgp 65101\n"
            "   vrf ZZ-TENANT\n"
            "      no route-target import evpn 50001:50001\n"
            "      no rd\n"
        )
        assert "field:evpn:l3vnis_by_vrf:ZZ-TENANT:rd" in _tombstones(cfg)

    def test_whole_l3vni_delete(self):
        cfg = "router bgp 65101\n   no vrf OTHER-TENANT\n"
        ts = _tombstones(cfg)
        assert "field:evpn:l3vnis_by_vrf:OTHER-TENANT" in ts

    def test_verbs(self):
        cfg = (
            "router bgp 65101\n"
            "   vrf ZZ-TENANT\n"
            "      no route-target import evpn 50001:50001\n"
            "      no rd\n"
            "   no vrf OTHER-TENANT\n"
        )
        verbs = _verb_by_path(cfg)
        assert verbs[
            "field:evpn:l3vnis_by_vrf:ZZ-TENANT:route_target_import:50001:50001"
        ] is Verb.LIST_REMOVE
        assert verbs["field:evpn:l3vnis_by_vrf:ZZ-TENANT:rd"] is Verb.UNSET
        assert verbs["field:evpn:l3vnis_by_vrf:OTHER-TENANT"] is Verb.OBJECT_DELETE


# ---------------------------------------------------------------------------
# L2VNI — ``router bgp / vlan <id>``; VNI joined from ``interface Vxlan1`` when
# the snippet carries the mapping, else VLAN-keyed
# ---------------------------------------------------------------------------

class TestL2VNIRemovalWithMapping:
    _CFG = (
        "router bgp 65101\n"
        "   vlan 10\n"
        "      no route-target both 10010:10010\n"
        "      no rd\n"
        "interface Vxlan1\n"
        "   vxlan vlan 10 vni 10010\n"
    )

    def test_rt_removal_resolves_to_vni(self):
        ts = _tombstones(self._CFG)
        assert "field:evpn:l2vnis:10010:route_target_both:10010:10010" in ts

    def test_rd_removal_resolves_to_vni(self):
        assert "field:evpn:l2vnis:10010:rd" in _tombstones(self._CFG)

    def test_whole_vlan_delete_resolves_to_vni(self):
        cfg = (
            "router bgp 65101\n"
            "   no vlan 10\n"
            "interface Vxlan1\n"
            "   vxlan vlan 10 vni 10010\n"
        )
        ts = _tombstones(cfg)
        assert "field:evpn:l2vnis:10010" in ts

    def test_verbs(self):
        verbs = _verb_by_path(self._CFG)
        assert verbs[
            "field:evpn:l2vnis:10010:route_target_both:10010:10010"
        ] is Verb.LIST_REMOVE
        assert verbs["field:evpn:l2vnis:10010:rd"] is Verb.UNSET


class TestL2VNIRemovalWithoutMapping:
    """Partial snippet: the ``vlan <id>`` removal without the Vxlan1 mapping — the
    VNI cannot be resolved, so the removal is VLAN-keyed and the engine resolves
    it against the baseline's L2VNIs by the VLAN binding."""

    def test_rt_removal_falls_back_to_by_vlan(self):
        cfg = (
            "router bgp 65101\n"
            "   vlan 10\n"
            "      no route-target both 10010:10010\n"
        )
        ts = _tombstones(cfg)
        assert "field:evpn:l2vnis_by_vlan:10:route_target_both:10010:10010" in ts
        # No VNI in scope, so no VNI-keyed tombstone may be invented.
        assert not any(
            t.startswith("field:evpn:l2vnis:") for t in ts
        ), ts

    def test_rd_removal_falls_back_to_by_vlan(self):
        cfg = "router bgp 65101\n   vlan 10\n      no rd\n"
        assert "field:evpn:l2vnis_by_vlan:10:rd" in _tombstones(cfg)

    def test_whole_vlan_delete_falls_back_to_by_vlan(self):
        cfg = "router bgp 65101\n   no vlan 10\n"
        ts = _tombstones(cfg)
        assert "field:evpn:l2vnis_by_vlan:10" in ts
        assert not any(t.startswith("field:evpn:l2vnis:") for t in ts), ts

    def test_verbs(self):
        cfg = (
            "router bgp 65101\n"
            "   vlan 10\n"
            "      no route-target both 10010:10010\n"
            "      no rd\n"
            "   no vlan 20\n"
        )
        verbs = _verb_by_path(cfg)
        assert verbs[
            "field:evpn:l2vnis_by_vlan:10:route_target_both:10010:10010"
        ] is Verb.LIST_REMOVE
        assert verbs["field:evpn:l2vnis_by_vlan:10:rd"] is Verb.UNSET
        assert verbs["field:evpn:l2vnis_by_vlan:20"] is Verb.OBJECT_DELETE

    def test_rt_value_tail_is_one_segment(self):
        # The colon-valued RT tail must stay ONE op-path segment (SET convention),
        # exactly like the VNI-keyed and l3vnis_by_vrf forms.
        cfg = (
            "router bgp 65101\n"
            "   vlan 10\n"
            "      no route-target both 4200000001:10\n"
        )
        paths = [
            tuple(op.path)
            for op in derive_ops(EOSParser(cfg).parse())
            if op.verb is Verb.LIST_REMOVE
        ]
        assert (
            "field", "evpn", "l2vnis_by_vlan", "10",
            "route_target_both", "4200000001:10",
        ) in paths


# ---------------------------------------------------------------------------
# Overlay deactivation — ``no neighbor <x> activate`` under ``address-family evpn``
# ---------------------------------------------------------------------------

class TestOverlayDeactivation:
    def test_peer_group_target_removes_l2vpn_evpn_af(self):
        cfg = (
            "router bgp 65101\n"
            "   address-family evpn\n"
            "      no neighbor EVPN-OVERLAY activate\n"
        )
        assert (
            "bgp_instance", "65101", "", "field", "peer_group", "EVPN-OVERLAY",
            "address_family", "l2vpn", "evpn",
        ) in _op_paths(cfg)

    def test_ip_neighbor_target_keys_into_neighbor_scope(self):
        cfg = (
            "router bgp 65101\n"
            "   address-family evpn\n"
            "      no neighbor 10.0.0.2 activate\n"
        )
        assert (
            "bgp_instance", "65101", "", "field", "neighbor", "10.0.0.2",
            "address_family", "l2vpn", "evpn",
        ) in _op_paths(cfg)

    def test_deactivation_op_is_list_remove(self):
        cfg = (
            "router bgp 65101\n"
            "   address-family evpn\n"
            "      no neighbor EVPN-OVERLAY activate\n"
        )
        af_ops = [
            op for op in derive_ops(EOSParser(cfg).parse())
            if "address_family" in op.path and "evpn" in op.path
        ]
        assert af_ops and all(op.verb is Verb.LIST_REMOVE for op in af_ops)


# ---------------------------------------------------------------------------
# Anti-over-trigger — the validator will attack this surface
# ---------------------------------------------------------------------------

class TestOverTrigger:
    def test_no_vlan_with_trailing_garbage_fires_nothing(self):
        ts = _tombstones("router bgp 65101\n   no vlan 20 bogus\n")
        assert not any("l2vnis" in t for t in ts), ts

    def test_no_vrf_with_trailing_garbage_fires_nothing(self):
        ts = _tombstones("router bgp 65101\n   no vrf TEN bogus\n")
        assert not any("l3vnis_by_vrf" in t for t in ts), ts

    @pytest.mark.parametrize(
        "line,fires",
        [
            ("no rd", True),
            ("no rd auto", True),
            ("no rd 1.1.1.1:50001", True),
            ("no rd 65000:66", True),
            ("no rd bananas", False),
            ("no rd permit", False),
        ],
    )
    def test_no_rd_value_slot_is_grammar_constrained(self, line, fires):
        cfg = (
            "router bgp 65101\n"
            "   vrf TEN\n"
            "      no route-target import evpn 5:5\n"
            f"      {line}\n"
        )
        assert (
            ("field:evpn:l3vnis_by_vrf:TEN:rd" in _tombstones(cfg)) is fires
        )

    def test_plain_l3vpn_rt_removal_is_not_claimed_as_evpn(self):
        # A plain ``no route-target import <rt>`` (no ``evpn``) under a bgp vrf is
        # L3VPN — it must not reach an EVPN tombstone.
        cfg = (
            "router bgp 65101\n"
            "   vrf TEN\n"
            "      no route-target import 65001:7\n"
        )
        assert not any(
            t.startswith("field:evpn:") for t in _tombstones(cfg)
        ), _tombstones(cfg)

    def test_plain_l3vpn_no_rd_is_not_claimed_as_evpn(self):
        # No ``evpn`` evidence in the block, so ``no rd`` is left to the inherited
        # (L3VPN) path — no EVPN copy.
        cfg = "router bgp 65101\n   vrf TEN\n      no rd\n"
        assert not any(
            t.startswith("field:evpn:") for t in _tombstones(cfg)
        ), _tombstones(cfg)


# ---------------------------------------------------------------------------
# ``default`` spelling — an alias of ``no`` for the value-bearing removals
# ---------------------------------------------------------------------------

class TestDefaultSpelling:
    """EOS accepts ``default …`` as an equivalent of ``no …`` for these
    value-bearing removals (device-verified 2026-08-01: ``default route-target
    both <rt>`` removes the line by omission exactly like the ``no`` form). Both
    spellings MUST emit the identical tombstone."""

    def test_default_l2vni_rt_matches_no(self):
        base = "router bgp 65101\n   vlan 10\n      {line}\n"
        no = _tombstones(base.format(line="no route-target both 10010:10010"))
        default = _tombstones(base.format(line="default route-target both 10010:10010"))
        assert "field:evpn:l2vnis_by_vlan:10:route_target_both:10010:10010" in default
        assert default == no

    def test_default_l3vni_rt_matches_no(self):
        base = "router bgp 65101\n   vrf ZZ-TENANT\n      {line}\n"
        no = _tombstones(base.format(line="no route-target import evpn 50001:50001"))
        default = _tombstones(
            base.format(line="default route-target import evpn 50001:50001")
        )
        assert (
            "field:evpn:l3vnis_by_vrf:ZZ-TENANT:route_target_import:50001:50001"
            in default
        )
        assert default == no

    def test_default_rd_matches_no(self):
        base = (
            "router bgp 65101\n   vrf ZZ-TENANT\n"
            "      default route-target import evpn 50001:50001\n"
            "      {line}\n"
        )
        no = _tombstones(base.format(line="no rd"))
        default = _tombstones(base.format(line="default rd"))
        assert "field:evpn:l3vnis_by_vrf:ZZ-TENANT:rd" in default
        assert default == no

    def test_default_whole_vlan_delete_matches_no(self):
        base = "router bgp 65101\n   {line}\n"
        no = _tombstones(base.format(line="no vlan 20"))
        default = _tombstones(base.format(line="default vlan 20"))
        assert "field:evpn:l2vnis_by_vlan:20" in default
        assert default == no

    def test_default_whole_vrf_delete_matches_no(self):
        base = "router bgp 65101\n   {line}\n"
        no = _tombstones(base.format(line="no vrf OTHER-TENANT"))
        default = _tombstones(base.format(line="default vrf OTHER-TENANT"))
        assert "field:evpn:l3vnis_by_vrf:OTHER-TENANT" in default
        assert default == no

    def test_default_neighbor_activate_matches_no(self):
        base = "router bgp 65101\n   address-family evpn\n      {line}\n"
        no = _op_paths(base.format(line="no neighbor EVPN-OVERLAY activate"))
        default = _op_paths(base.format(line="default neighbor EVPN-OVERLAY activate"))
        af = (
            "bgp_instance", "65101", "", "field", "peer_group", "EVPN-OVERLAY",
            "address_family", "l2vpn", "evpn",
        )
        assert af in default
        assert default == no

    def test_default_over_trigger_stays_closed(self):
        # Garbage after a ``default`` form must fire nothing, and the RD grammar
        # constraint still holds for the ``default`` spelling.
        assert not any(
            "l2vnis" in t
            for t in _tombstones("router bgp 65101\n   default vlan 20 bogus\n")
        )
        cfg = (
            "router bgp 65101\n   vrf TEN\n"
            "      default route-target import evpn 5:5\n"
            "      default rd bananas\n"
        )
        assert "field:evpn:l3vnis_by_vrf:TEN:rd" not in _tombstones(cfg)


# ---------------------------------------------------------------------------
# Round-trip sanity — every emitted EVPN path resolves to a change-IR verb
# ---------------------------------------------------------------------------

def test_every_emitted_evpn_path_has_a_mapped_verb():
    """A ``field:evpn:…`` tombstone with no verb row is a silent no-op. Every
    path this parser emits must map to a concrete deletion verb (not the lossless
    UNSET fallback that would apply to an unregistered shape by accident)."""
    cfg = (
        "router bgp 65101\n"
        "   vlan 10\n"
        "      no route-target both 10010:10010\n"
        "      no rd\n"
        "   no vlan 20\n"
        "   vrf ZZ-TENANT\n"
        "      no route-target import evpn 50001:50001\n"
        "      no rd\n"
        "   no vrf OTHER-TENANT\n"
        "interface Vxlan1\n"
        "   vxlan vlan 10 vni 10010\n"
    )
    verbs = _verb_by_path(cfg)
    evpn_paths = {p: v for p, v in verbs.items() if p.startswith("field:evpn:")}
    assert evpn_paths  # non-vacuous
    for path, verb in evpn_paths.items():
        assert verb in (Verb.LIST_REMOVE, Verb.UNSET, Verb.OBJECT_DELETE), (
            path, verb,
        )


# ---------------------------------------------------------------------------
# Additive-parse regression — CCR-0157's positive EVPN parse must stay intact
# ---------------------------------------------------------------------------

def test_additive_evpn_parse_still_produces_the_control_plane():
    cfg = (
        "router bgp 65101\n"
        "   vlan 10\n"
        "      rd 1.1.1.1:10010\n"
        "      route-target both 10010:10010\n"
        "   vrf ZZ-TENANT\n"
        "      rd 1.1.1.1:50001\n"
        "      route-target import evpn 50001:50001\n"
        "      route-target export evpn 50001:50001\n"
        "interface Vxlan1\n"
        "   vxlan vlan 10 vni 10010\n"
        "   vxlan vrf ZZ-TENANT vni 50001\n"
    )
    evpn = EOSParser(cfg).parse().evpn
    assert evpn is not None
    assert {v.vni for v in evpn.l2vnis} == {10010}
    assert {v.vni for v in evpn.l3vnis} == {50001}
    l3 = next(v for v in evpn.l3vnis if v.vni == 50001)
    assert l3.vrf == "ZZ-TENANT"
    assert l3.route_target_import == ["50001:50001"]
