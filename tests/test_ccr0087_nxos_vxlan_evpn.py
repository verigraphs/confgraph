"""CCR-0087 — NX-OS VXLAN ingress-replication mode + EVPN L2VNI control-plane.

Device-verified on n9kv 10.5(5) (own containerlab, push+readback). Two gaps:

1. ``ingress-replication protocol bgp`` under ``interface nve1 / member vni <n>``
   was silently dropped — ``VXLANVniMapping`` had no replication-mode field, so
   the BUM-replication method (BGP-EVPN vs static head-end) was invisible.
   The fix adds ``VXLANVniMapping.ingress_replication`` (+ ``ingress_replication_peers``)
   and reads the line in ``NXOSParser.parse_vxlan``.

2. The top-level ``evpn`` MP-BGP EVPN control-plane block (``evpn / vni <n> l2 /
   rd / route-target import|export``) was entirely unmodeled — parsing it yielded
   ``p.vxlan == None`` and no ``evpn`` attribute at all. The fix adds the
   ``EVPNConfig`` / ``EVPNL2VNI`` models, a top-level ``ParsedConfig.evpn`` field,
   and ``NXOSParser.parse_evpn``.

Emitted-syntax authority — ``syntax-corpus/nxos/vxlan.yaml``:
  * ``nve-ingress-replication`` (verified-capture, 10.5(5)): ``ingress-replication
    protocol bgp`` under ``member vni`` — emitted == typed.
  * ``evpn-l2vni-control-plane`` (verified-capture, capture
    ``captures/nxos/2026-07-20-n9kv-10.5.5-vrrpv3-evpn-l2vni.txt``): the DEVICE
    EMITS ``rd auto`` / ``route-target import auto`` / ``route-target export auto``
    as three separate lines (``auto`` DOES nvgen on 10.5(5)). ``route-target both``
    is a TYPED convenience that the device renders as the two separate import/export
    lines — it never emits. The evpn correctness fixtures below use the device-EMITTED
    separate-line form; the ``both``-expansion behaviour is exercised in its own test
    that documents it as the typed (non-emitted) form the parser expands defensively,
    per the CCR device finding.

Values assert exactly (handbook §7 — no presence-only checks).
"""
from confgraph.models.evpn import EVPNConfig, EVPNL2VNI
from confgraph.parsers.nxos_parser import NXOSParser


# --------------------------------------------------------------------------
# Part 1 — ingress-replication replication mode (device-emitted: protocol bgp)
# --------------------------------------------------------------------------

NXOS_IR_BGP = """feature nv overlay
vlan 2010
  vn-segment 20010
interface nve1
  source-interface loopback0
  host-reachability protocol bgp
  member vni 20010
    ingress-replication protocol bgp
"""


def _vni(vxlan, vni):
    return next(m for m in vxlan.vni_mappings if m.vni == vni)


def test_ingress_replication_protocol_bgp_sets_replication_mode():
    p = NXOSParser(NXOS_IR_BGP).parse()
    m = _vni(p.vxlan, 20010)
    assert m.ingress_replication == "bgp"
    assert m.ingress_replication_peers == []


def test_vxlan_dataplane_not_regressed_beside_ingress_replication():
    # The CCR's CLEAN data-plane must keep parsing when the replication mode
    # is read beside it.
    p = NXOSParser(NXOS_IR_BGP).parse()
    assert p.vxlan is not None
    assert p.vxlan.source_interface == "loopback0"
    assert p.vxlan.host_reachability == "bgp"
    m = _vni(p.vxlan, 20010)
    assert m.vlan == 2010
    assert m.vrf is None


def test_member_vni_without_ingress_replication_stays_none():
    p = NXOSParser(
        "feature nv overlay\n"
        "interface nve1\n"
        "  source-interface loopback0\n"
        "  member vni 30030\n"
        "    mcast-group 239.1.1.1\n"
    ).parse()
    m = _vni(p.vxlan, 30030)
    assert m.ingress_replication is None
    assert m.mcast_group == "239.1.1.1"


# --------------------------------------------------------------------------
# Part 2 — EVPN L2VNI control-plane (device-emitted: rd/rt auto, separate lines)
# --------------------------------------------------------------------------

# Verbatim from capture 2026-07-20-n9kv-10.5.5-vrrpv3-evpn-l2vni.txt.
NXOS_EVPN_AUTO = """evpn
  vni 90901 l2
    rd auto
    route-target import auto
    route-target export auto
"""


def _l2vni(evpn, vni):
    return next(v for v in evpn.l2vnis if v.vni == vni)


def test_evpn_block_is_modeled_as_top_level_field():
    p = NXOSParser(NXOS_EVPN_AUTO).parse()
    assert p.evpn is not None
    assert isinstance(p.evpn, EVPNConfig)
    assert len(p.evpn.l2vnis) == 1
    assert isinstance(p.evpn.l2vnis[0], EVPNL2VNI)


def test_evpn_l2vni_auto_rd_and_route_targets_preserved_literally():
    # `auto` DOES nvgen on 10.5(5) — it must be kept as the literal token,
    # not dropped or resolved.
    p = NXOSParser(NXOS_EVPN_AUTO).parse()
    v = _l2vni(p.evpn, 90901)
    assert v.rd == "auto"
    assert v.route_target_import == ["auto"]
    assert v.route_target_export == ["auto"]


def test_evpn_l2vni_explicit_rd_and_route_targets():
    # Operator override: device emits the literal <rd>/<rt> value (not `auto`),
    # as separate import/export lines.
    p = NXOSParser(
        "evpn\n"
        "  vni 5001 l2\n"
        "    rd 65001:5001\n"
        "    route-target import 65001:5001\n"
        "    route-target export 65001:5001\n"
    ).parse()
    v = _l2vni(p.evpn, 5001)
    assert v.rd == "65001:5001"
    assert v.route_target_import == ["65001:5001"]
    assert v.route_target_export == ["65001:5001"]


def test_route_target_both_expands_to_import_and_export():
    # `route-target both <rt>` is the TYPED convenience form (the device renders
    # it as separate import/export lines and never emits `both`). The parser
    # expands it into BOTH lists so a typed config is modeled identically to the
    # emitted separate-line form. Device finding, CCR-0087.
    p = NXOSParser(
        "evpn\n"
        "  vni 7002 l2\n"
        "    rd auto\n"
        "    route-target both auto\n"
    ).parse()
    v = _l2vni(p.evpn, 7002)
    assert v.rd == "auto"
    assert v.route_target_import == ["auto"]
    assert v.route_target_export == ["auto"]


def test_multiple_l2vnis_parse_independently():
    p = NXOSParser(
        "evpn\n"
        "  vni 90901 l2\n"
        "    rd auto\n"
        "    route-target import auto\n"
        "    route-target export auto\n"
        "  vni 90902 l2\n"
        "    rd 65001:90902\n"
        "    route-target import 65001:90902\n"
        "    route-target export 65001:90902\n"
    ).parse()
    assert {v.vni for v in p.evpn.l2vnis} == {90901, 90902}
    assert _l2vni(p.evpn, 90901).rd == "auto"
    assert _l2vni(p.evpn, 90902).rd == "65001:90902"


def test_no_evpn_block_leaves_field_none():
    p = NXOSParser("feature nv overlay\ninterface nve1\n  member vni 10\n").parse()
    assert p.evpn is None
