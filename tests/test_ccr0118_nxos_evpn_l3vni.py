"""CCR-0118 — NX-OS EVPN L3VNI control-plane (lives under ``vrf context``).

Builds on CCR-0087 (which modeled the EVPN **L2VNI** ``vni <n> l2`` into
``EVPNConfig.l2vnis``). This adds the **L3VNI** (routing / tenant-VRF VNI) via a
new ``EVPNConfig.l3vnis`` + ``EVPNL3VNI``.

WHERE THE L3VNI LIVES: the top-level ``evpn`` block carries **only** L2VNIs —
there is NO ``vni <n> l3`` form under ``evpn`` (vendor doc + validator re-fetch).
The L3VNI control-plane lives under ``vrf context <name>``:

    vrf context TENANT
      vni 50001                              # traditional; new mode: `vni <n> L3`
      rd 65001:50001
      address-family ipv4 unicast
        route-target both 65001:50001 evpn   # trailing `evpn` = L3VNI/EVPN RT
      address-family ipv6 unicast
        route-target both 65001:50001 evpn

and is bound to the fabric by the NVE line ``member vni <n> associate-vrf``.
``NXOSParser.parse_evpn`` joins the ``vrf context`` declaration and the NVE signal
into one ``EVPNL3VNI`` per VNI.

DOC-GROUNDED POSTURE (no device fact — same as CCR-0094 NetFlow). The L2VNI form
was device-verified on n9kv 10.5(5) (CCR-0087). The L3VNI ``vrf context`` emitted
``rd`` / ``route-target ... evpn`` block was NOT captured on the 9000v; fixtures
are grounded in the syntax-consultant citation (2026-07-29, doc-only, Cisco Nexus
9000 VXLAN Config Guide 10.5(x); corpus entries ``l3vni-vrf-context-control-plane``
+ ``nve-member-vni-associate-vrf``), promotable-when-captured.

Values assert exactly (handbook §7 — no presence-only checks).
"""
from confgraph.parsers.nxos_parser import NXOSParser


def _l2vni(evpn, vni):
    return next(v for v in evpn.l2vnis if v.vni == vni)


def _l3vni(evpn, vni):
    return next(v for v in evpn.l3vnis if v.vni == vni)


# --------------------------------------------------------------------------
# (a) The `evpn` block is L2VNI-only; a `vni <n> l3` line there is NOT a form
# --------------------------------------------------------------------------

def test_l2vni_under_evpn_unchanged_and_no_l3vni():
    # CCR-0087 L2VNI path byte-identical; no L3VNI is produced from `evpn`.
    p = NXOSParser(
        "evpn\n"
        "  vni 90901 l2\n"
        "    rd auto\n"
        "    route-target import auto\n"
        "    route-target export auto\n"
    ).parse()
    assert [v.vni for v in p.evpn.l2vnis] == [90901]
    assert p.evpn.l3vnis == []


def test_l3_keyword_under_evpn_yields_no_l3vni():
    # `vni <n> l3` under the top-level `evpn` block is NOT a device-emitted form
    # — it must be ignored (no l3vni, and it must not leak into l2vnis either).
    p = NXOSParser(
        "evpn\n"
        "  vni 50001 l3\n"
        "    rd auto\n"
        "    route-target import auto\n"
        "    route-target export auto\n"
    ).parse()
    assert p.evpn is not None
    assert p.evpn.l2vnis == []
    assert p.evpn.l3vnis == []


def test_evpn_block_with_both_l2_and_l3_keeps_only_l2():
    # Mixed under `evpn`: the L2VNI parses; the (non-form) `vni <n> l3` is ignored.
    p = NXOSParser(
        "evpn\n"
        "  vni 90901 l2\n"
        "    rd auto\n"
        "    route-target import auto\n"
        "    route-target export auto\n"
        "  vni 50001 l3\n"
        "    rd 65001:50001\n"
        "    route-target import 65001:50001\n"
        "    route-target export 65001:50001\n"
    ).parse()
    l2 = _l2vni(p.evpn, 90901)
    assert l2.rd == "auto"
    assert l2.route_target_import == ["auto"]
    assert l2.route_target_export == ["auto"]
    assert p.evpn.l3vnis == []


# --------------------------------------------------------------------------
# (b) Canonical vrf-context L3VNI control-plane + NVE join
#
# Consultant-cited (2026-07-29, doc-only, Cisco Nexus 9000 VXLAN Config Guide
# 10.5(x); corpus entries `l3vni-vrf-context-control-plane` +
# `nve-member-vni-associate-vrf`): the tenant-VRF L3VNI RD/route-targets live
# under `vrf context <name>` with the trailing `evpn` keyword on the RTs, and the
# NVE binds the L3VNI with `member vni <n> associate-vrf`.
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
# (c) VRF-context no-regression — parse_vrfs / VRFConfig untouched
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
