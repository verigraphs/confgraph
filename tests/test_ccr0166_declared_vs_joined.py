"""CCR-0166 — ``VXLANVniMapping`` distinguishes DECLARED bindings from joins.

``binding_declared`` is True only when the config line itself binds the
subject (vlan/vrf) to the VNI — EOS's two ``interface Vxlan1`` forms, where
the device enforces one VNI per subject and re-typing REPLACES the binding.
The NX-OS ``vlan`` value is a vn-segment JOIN (parser artifact, not
subject-authoritative) and stays undeclared. ``associate_vrf`` is the typed
replacement for the retired ``"(L3)"`` vrf sentinel.

The consumer this exists for: confgraph-entrp's CCR-0163 subject-ownership
eviction keys on ``binding_declared`` instead of ``source_os``, deleting its
OS gate.
"""

import tempfile
from pathlib import Path

from confgraph.loader import load_and_parse
from confgraph.models.vxlan import VXLANVniMapping


def _parse(text: str, os_type: str):
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "dev.cfg"
        p.write_text(text, encoding="utf-8")
        res = load_and_parse(p, os_type=os_type)
        return res[0] if isinstance(res, tuple) else res


class TestModelDefaults:
    def test_defaults_are_undeclared_and_not_l3(self):
        m = VXLANVniMapping(vni=10010)
        assert m.binding_declared is False
        assert m.associate_vrf is False
        assert m.vrf is None


class TestEOSDeclaredBindings:
    def test_vlan_binding_is_declared(self):
        cfg = _parse(
            "hostname leaf1\n"
            "interface Vxlan1\n"
            "   vxlan source-interface Loopback1\n"
            "   vxlan vlan 10 vni 10010\n",
            "eos",
        )
        (m,) = cfg.vxlan.vni_mappings
        assert (m.vlan, m.vni) == (10, 10010)
        assert m.binding_declared is True
        assert m.associate_vrf is False

    def test_vrf_binding_is_declared(self):
        """PARITY: the second EOS binding form rides the same flag."""
        cfg = _parse(
            "hostname leaf1\n"
            "interface Vxlan1\n"
            "   vxlan source-interface Loopback1\n"
            "   vxlan vrf ZZ-TENANT vni 50001\n",
            "eos",
        )
        (m,) = cfg.vxlan.vni_mappings
        assert (m.vrf, m.vni) == ("ZZ-TENANT", 50001)
        assert m.binding_declared is True

    def test_vlan_add_form_is_declared(self):
        cfg = _parse(
            "hostname leaf1\n"
            "interface Vxlan1\n"
            "   vxlan vlan add 20 vni 10020\n",
            "eos",
        )
        (m,) = cfg.vxlan.vni_mappings
        assert (m.vlan, m.binding_declared) == (20, True)


NX_BASE = """hostname leaf1
feature nv overlay
feature vn-segment-vlan-based
vlan 10
  vn-segment 10010
interface nve1
  source-interface loopback0
  member vni 10010
  member vni 50001 associate-vrf
"""


class TestNXOSJoinsStayUndeclared:
    def test_vn_segment_join_is_not_declared(self):
        """The NX vlan value comes from the vn-segment JOIN — carrying it must
        never read as a declaration (the CCR-0163 round-1 eviction defect)."""
        cfg = _parse(NX_BASE, "nxos")
        l2 = next(m for m in cfg.vxlan.vni_mappings if m.vni == 10010)
        assert l2.vlan == 10                  # the join itself is unchanged
        assert l2.binding_declared is False

    def test_l3_sentinel_retired_for_typed_flag(self):
        """``member vni <n> associate-vrf`` → vrf=None + associate_vrf=True.
        The "(L3)" string must be gone from parse output entirely."""
        cfg = _parse(NX_BASE, "nxos")
        l3 = next(m for m in cfg.vxlan.vni_mappings if m.vni == 50001)
        assert l3.vrf is None
        assert l3.associate_vrf is True
        assert l3.binding_declared is False
        assert "(L3)" not in cfg.model_dump_json()

    def test_l3vni_control_plane_join_still_fires(self):
        """REGRESSION: parse_evpn's Source-3 enrichment (NVE associate-vrf →
        EVPNL3VNI.associate_vrf) now reads the typed flag — same output."""
        cfg = _parse(
            NX_BASE
            + "vrf context TEN-A\n"
            + "  vni 50001\n"
            + "  rd auto\n",
            "nxos",
        )
        l3 = next(v for v in cfg.evpn.l3vnis if v.vni == 50001)
        assert l3.associate_vrf is True
