"""CCR-0118 — NX-OS EVPN L3VNI (``vni <n> l3`` under ``evpn``) control-plane.

Builds directly on CCR-0087, which modeled the EVPN **L2VNI** (``vni <n> l2``)
into ``EVPNConfig.l2vnis`` and had ``NXOSParser.parse_evpn`` deliberately match
only ``l2``. This adds the **L3VNI** (``vni <n> l3``) counterpart —
``EVPNConfig.l3vnis`` + ``EVPNL3VNI`` — routing each ``evpn`` sub-block to the
right list by its ``l2`` / ``l3`` keyword. The L2VNI path is unchanged.

DOC-GROUNDED POSTURE (no device fact — same as CCR-0094 NetFlow):
  The L2VNI form was device-verified on n9kv 10.5(5) (CCR-0087). The L3VNI's
  emitted ``rd`` / ``route-target`` sub-block was NOT captured on the 9000v, so
  the fixtures below are NOT a device readback. They are grounded in:
    * The device-adjacent L2VNI capture note (``syntax-corpus/nxos/vxlan.yaml``,
      ``evpn-l2vni-control-plane``, verified-capture): under the ``evpn`` block
      "the ``l2`` keyword is required; ``l3`` selects an L3VNI" — establishing
      ``l3`` as a valid keyword position beside ``l2``.
    * The L2VNI ``rd`` / ``route-target`` grammar (verified-capture), reused by
      analogy for the L3VNI sub-lines.
    * syntax-consultant (2026-07-29, doc-only, Cisco Nexus 9000 VXLAN Config
      Guide 10.5(x)): the L3VNI/tenant-VRF RD/route-targets, and that the
      NVE→VRF binding is ``member vni <n> associate-vrf`` (flat line). The
      consultant flagged that whether ``route-target both`` expands and whether
      ``auto`` nvgens is UNVERIFIED for the L3VNI context — so the exact emitted
      form remains promotable-when-captured. The parser stays form-agnostic and
      the model keeps every field optional to be robust to that uncertainty.

Values assert exactly (handbook §7 — no presence-only checks).
"""
from confgraph.models.evpn import EVPNConfig, EVPNL2VNI, EVPNL3VNI
from confgraph.parsers.nxos_parser import NXOSParser


def _l2vni(evpn, vni):
    return next(v for v in evpn.l2vnis if v.vni == vni)


def _l3vni(evpn, vni):
    return next(v for v in evpn.l3vnis if v.vni == vni)


# --------------------------------------------------------------------------
# (a) L3VNI block with rd + separate import/export lines -> exact values
# --------------------------------------------------------------------------

# `auto` form — mirrors the device-EMITTED L2VNI separate-line shape.
NXOS_EVPN_L3VNI_AUTO = """evpn
  vni 50001 l3
    rd auto
    route-target import auto
    route-target export auto
"""


def test_l3vni_block_is_modeled_into_l3vnis():
    p = NXOSParser(NXOS_EVPN_L3VNI_AUTO).parse()
    assert p.evpn is not None
    assert isinstance(p.evpn, EVPNConfig)
    assert len(p.evpn.l3vnis) == 1
    assert isinstance(p.evpn.l3vnis[0], EVPNL3VNI)
    # An L3VNI block must NOT leak into the L2VNI list.
    assert p.evpn.l2vnis == []


def test_l3vni_auto_rd_and_route_targets_preserved_literally():
    p = NXOSParser(NXOS_EVPN_L3VNI_AUTO).parse()
    v = _l3vni(p.evpn, 50001)
    assert v.vni == 50001
    assert v.rd == "auto"
    assert v.route_target_import == ["auto"]
    assert v.route_target_export == ["auto"]
    # VRF correlation is a documented follow-up — unpopulated in this pass.
    assert v.vrf is None


def test_l3vni_explicit_rd_and_route_targets():
    # Operator override: literal <rd>/<rt> values on separate import/export lines.
    p = NXOSParser(
        "evpn\n"
        "  vni 50002 l3\n"
        "    rd 65001:50002\n"
        "    route-target import 65001:50002\n"
        "    route-target export 65001:50002\n"
    ).parse()
    v = _l3vni(p.evpn, 50002)
    assert v.rd == "65001:50002"
    assert v.route_target_import == ["65001:50002"]
    assert v.route_target_export == ["65001:50002"]


# --------------------------------------------------------------------------
# (b) route-target both -> both lists; auto preserved
# --------------------------------------------------------------------------

def test_l3vni_route_target_both_expands_to_import_and_export():
    # `route-target both <rt>` is the typed convenience form; the parser expands
    # it into BOTH lists (form-agnostic, mirroring the L2VNI defensive path).
    p = NXOSParser(
        "evpn\n"
        "  vni 50003 l3\n"
        "    rd auto\n"
        "    route-target both auto\n"
    ).parse()
    v = _l3vni(p.evpn, 50003)
    assert v.rd == "auto"
    assert v.route_target_import == ["auto"]
    assert v.route_target_export == ["auto"]


def test_bare_l3vni_declaration_parses_with_empty_rt():
    # Robustness to the doc-grounded uncertainty: a bare `vni <n> l3` with no
    # rd/route-target children still yields an L3VNI entry (all fields optional).
    p = NXOSParser("evpn\n  vni 50004 l3\n").parse()
    v = _l3vni(p.evpn, 50004)
    assert v.vni == 50004
    assert v.rd is None
    assert v.route_target_import == []
    assert v.route_target_export == []


# --------------------------------------------------------------------------
# (c) mixed L2 + L3 block -> each lands in the right list, L2 unchanged
# --------------------------------------------------------------------------

NXOS_EVPN_L2_AND_L3 = """evpn
  vni 90901 l2
    rd auto
    route-target import auto
    route-target export auto
  vni 50001 l3
    rd 65001:50001
    route-target import 65001:50001
    route-target export 65001:50001
"""


def test_mixed_l2_and_l3_split_into_their_lists():
    p = NXOSParser(NXOS_EVPN_L2_AND_L3).parse()
    assert {v.vni for v in p.evpn.l2vnis} == {90901}
    assert {v.vni for v in p.evpn.l3vnis} == {50001}


def test_mixed_l2vni_path_not_regressed():
    # The CCR-0087 L2VNI parsing must be byte-identical beside an L3VNI block.
    p = NXOSParser(NXOS_EVPN_L2_AND_L3).parse()
    l2 = _l2vni(p.evpn, 90901)
    assert l2.rd == "auto"
    assert l2.route_target_import == ["auto"]
    assert l2.route_target_export == ["auto"]


def test_mixed_l3vni_values_exact():
    p = NXOSParser(NXOS_EVPN_L2_AND_L3).parse()
    l3 = _l3vni(p.evpn, 50001)
    assert l3.rd == "65001:50001"
    assert l3.route_target_import == ["65001:50001"]
    assert l3.route_target_export == ["65001:50001"]


def test_l2_only_config_leaves_l3vnis_empty():
    # Guards the "keep L2VNI path byte-identical" contract: an L2-only evpn block
    # produces an empty l3vnis list (new field default), no behavioural change.
    p = NXOSParser(
        "evpn\n"
        "  vni 90901 l2\n"
        "    rd auto\n"
        "    route-target import auto\n"
        "    route-target export auto\n"
    ).parse()
    assert [v.vni for v in p.evpn.l2vnis] == [90901]
    assert p.evpn.l3vnis == []


# --------------------------------------------------------------------------
# (d) Canonical vrf-context L3VNI control-plane + NVE join  (CCR-0118 expansion)
#
# Consultant-cited (2026-07-29, doc-only, Cisco Nexus 9000 VXLAN Config Guide
# 10.5(x); corpus entries `l3vni-vrf-context-control-plane` +
# `nve-member-vni-associate-vrf`): the tenant-VRF L3VNI RD/route-targets live
# under `vrf context <name>` with the trailing `evpn` keyword on the RTs, and the
# NVE binds the L3VNI with `member vni <n> associate-vrf`. No device capture — the
# exact emitted form is promotable-when-captured.
# --------------------------------------------------------------------------

# Full chain: vrf-context declaration + evpn-suffixed RTs + NVE associate-vrf.
NXOS_L3VNI_FULL_CHAIN = """vrf context TENANT
  vni 50001
  rd 65001:50001
  address-family ipv4 unicast
    route-target both 65001:50001 evpn
  address-family ipv6 unicast
    route-target both 65001:50001 evpn
interface nve1
  source-interface loopback0
  host-reachability protocol bgp
  member vni 50001 associate-vrf
"""


def test_full_chain_vrf_context_l3vni_joined_by_vni():
    p = NXOSParser(NXOS_L3VNI_FULL_CHAIN).parse()
    assert p.evpn is not None
    # Exactly one L3VNI, joined across vrf-context + NVE by VNI number.
    assert len(p.evpn.l3vnis) == 1
    v = _l3vni(p.evpn, 50001)
    assert v.vni == 50001
    assert v.vrf == "TENANT"
    assert v.rd == "65001:50001"
    # `both ... evpn` populates both lists; ipv4/ipv6 dedup to one value.
    assert v.route_target_import == ["65001:50001"]
    assert v.route_target_export == ["65001:50001"]
    assert v.associate_vrf is True


def test_vrf_context_l3vni_auto_rts_and_both_expansion():
    p = NXOSParser(
        "vrf context CUST\n"
        "  vni 50002\n"
        "  rd auto\n"
        "  address-family ipv4 unicast\n"
        "    route-target both auto evpn\n"
        "interface nve1\n"
        "  member vni 50002 associate-vrf\n"
    ).parse()
    v = _l3vni(p.evpn, 50002)
    assert v.vrf == "CUST"
    assert v.rd == "auto"
    assert v.route_target_import == ["auto"]  # both -> both lists
    assert v.route_target_export == ["auto"]
    assert v.associate_vrf is True


def test_vrf_context_l3vni_explicit_import_export_evpn():
    # Separate import/export evpn-suffixed RTs (operator override).
    p = NXOSParser(
        "vrf context CUST\n"
        "  vni 50003\n"
        "  rd 65001:50003\n"
        "  address-family ipv4 unicast\n"
        "    route-target import 65001:1 evpn\n"
        "    route-target export 65001:2 evpn\n"
    ).parse()
    v = _l3vni(p.evpn, 50003)
    assert v.route_target_import == ["65001:1"]
    assert v.route_target_export == ["65001:2"]


def test_vrf_context_only_l3vni_is_modeled_without_evpn_block():
    # The common real case: no top-level `evpn` block at all, only the
    # vrf-context L3VNI. p.evpn must still be populated.
    p = NXOSParser(
        "vrf context TENANT\n"
        "  vni 50004\n"
        "  rd 65001:50004\n"
        "  address-family ipv4 unicast\n"
        "    route-target both 65001:50004 evpn\n"
    ).parse()
    assert p.evpn is not None
    v = _l3vni(p.evpn, 50004)
    assert v.vrf == "TENANT"
    assert v.rd == "65001:50004"
    assert v.associate_vrf is False  # no NVE associate-vrf line


def test_evpn_block_and_vrf_context_same_vni_merge_into_one():
    # An L3VNI declared BOTH via `evpn / vni <n> l3` AND via `vrf context` must
    # merge into ONE EVPNL3VNI (join by VNI) — not double-listed.
    p = NXOSParser(
        "evpn\n"
        "  vni 50005 l3\n"
        "    rd auto\n"
        "    route-target import auto\n"
        "    route-target export auto\n"
        "vrf context TENANT\n"
        "  vni 50005\n"
        "  rd 65001:50005\n"
        "  address-family ipv4 unicast\n"
        "    route-target both 65001:50005 evpn\n"
        "interface nve1\n"
        "  member vni 50005 associate-vrf\n"
    ).parse()
    assert len(p.evpn.l3vnis) == 1
    v = _l3vni(p.evpn, 50005)
    assert v.vrf == "TENANT"
    # rd first-wins: the evpn-block `rd auto` is set before the vrf-context rd.
    assert v.rd == "auto"
    # RTs unioned from both sources.
    assert set(v.route_target_import) == {"auto", "65001:50005"}
    assert set(v.route_target_export) == {"auto", "65001:50005"}
    assert v.associate_vrf is True


def test_plain_vrf_route_targets_not_pulled_into_l3vni():
    # Distinctness: PLAIN `route-target` lines (no trailing `evpn`) are L3VPN RTs
    # owned by parse_vrfs — they must NOT leak into the L3VNI's EVPN RTs.
    p = NXOSParser(
        "vrf context TENANT\n"
        "  vni 50006\n"
        "  rd 65001:50006\n"
        "  address-family ipv4 unicast\n"
        "    route-target import 65001:999\n"          # plain L3VPN RT (no evpn)
        "    route-target both 65001:50006 evpn\n"      # L3VNI/EVPN RT
    ).parse()
    v = _l3vni(p.evpn, 50006)
    # Only the evpn-suffixed value; the plain 65001:999 stays out of the L3VNI.
    assert v.route_target_import == ["65001:50006"]
    assert "65001:999" not in v.route_target_import


def test_associate_vrf_only_does_not_synthesise_l3vni():
    # An NVE `member vni <n> associate-vrf` with no control-plane declaration
    # must not fabricate an EVPNL3VNI (associate-vrf enriches, never creates).
    p = NXOSParser(
        "interface nve1\n"
        "  member vni 60001 associate-vrf\n"
    ).parse()
    assert p.evpn is None


# --------------------------------------------------------------------------
# (e) VRF-context no-regression — parse_vrfs / VRFConfig untouched
# --------------------------------------------------------------------------

# A rich vrf context: DNS (CCR-0093) + rd + PLAIN L3VPN route-targets, alongside
# the new L3VNI vni decl + evpn-suffixed RT. The L3VNI extraction must not disturb
# any of the pre-existing VRF parsing.
NXOS_VRF_RICH = """vrf context TENANT
  vni 50007
  rd 65001:50007
  ip name-server 10.50.0.1 10.50.0.2
  ip domain-name tenant.example.com
  ip domain-list corp.example.com
  address-family ipv4 unicast
    route-target import 65001:111
    route-target export 65001:222
    route-target both 65001:50007 evpn
interface nve1
  member vni 50007 associate-vrf
"""


def _vrf(pc, name):
    return next(v for v in pc.vrfs if v.name == name)


def test_vrf_context_dns_and_plain_rts_unchanged_beside_l3vni():
    pc = NXOSParser(NXOS_VRF_RICH).parse()
    vrf = _vrf(pc, "TENANT")
    # CCR-0093 DNS attribution — untouched.
    assert vrf.name_servers == ["10.50.0.1", "10.50.0.2"]
    assert vrf.domain_name == "tenant.example.com"
    assert vrf.domain_list == ["corp.example.com"]
    # rd + PLAIN L3VPN route-targets — untouched (existing parse_vrfs behaviour;
    # note: parse_vrfs also captures the evpn-suffixed value into its generic RT
    # lists exactly as before — that pre-existing behaviour is deliberately NOT
    # changed here, only additively read into the L3VNI).
    assert vrf.rd == "65001:50007"
    assert "65001:111" in vrf.route_target_import
    assert "65001:222" in vrf.route_target_export
    # And the L3VNI EVPN control-plane is modeled distinctly on the evpn side.
    v = _l3vni(pc.evpn, 50007)
    assert v.vrf == "TENANT"
    assert v.route_target_import == ["65001:50007"]
    assert v.associate_vrf is True
