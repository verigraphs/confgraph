"""CCR-0025 Phase 4 (WI-A2) — OSS deprecation shim acceptance suite.

`encode_legacy_shim` keeps the deprecated OSS fields ``no_commands`` /
``interface_no_commands`` / ``bgp_no_commands`` populated once Batch B removes
native parser tombstone emission.  These tests PROVE, while native emission
still exists as ground truth, that the shim reproduces the parser-populated
tombstone containers byte-exact and (for the natively-hoisted families)
order-inert-multiset — the established ``test_change_ir._roundtrip`` contract —
and that whole-object ``set_fields`` reconstitution (CCR Appendices L/Q/S/T/U/
V/W/Y) and ``_readded_later`` suppression (Appendix F.6) match the pre-native
parser family for family.

The tombstone proof is a systematic sweep over a family-covering corpus × every
tombstone-emitting parser OS (IOS/NX-OS/EOS/IOS-XR) plus the shipped running
sample configs, NOT hand-picked assertions.
"""

import json
from pathlib import Path

import pytest

import confgraph.change_ir as ci
from confgraph.change_ir import (
    Verb,
    derive_ops,
    encode_legacy,
    encode_legacy_shim,
    is_native_whole_object_create_op,
)
from confgraph.parsers.eos_parser import EOSParser
from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.iosxr_parser import IOSXRParser
from confgraph.parsers.nxos_parser import NXOSParser

# Reuse the canonical reordered-native reconciliation (natively hoisted families
# encode as an order-inert multiset; every other family is order-exact).
from tests._ccr0110_e_helpers import _is_reordered_native_tombstone

TOMBSTONE_OSES = (IOSParser, NXOSParser, EOSParser, IOSXRParser)


# ---------------------------------------------------------------------------
# Corpus — every tombstone family + interface/bgp scoping, one text per case
# ---------------------------------------------------------------------------

TOMBSTONE_CORPUS: dict[str, str] = {
    "interface_delete": "no interface Loopback9\n",
    "static_routes": (
        "no ip route 10.0.0.0 255.255.255.0 192.0.2.1\n"
        "no ip route vrf CUST 10.1.0.0 255.255.0.0\n"
    ),
    "vlan_delete": "no vlan 100\nno vlan 200\n",
    "process_deletes": (
        "no router ospf 3\nno router bgp 65010\n"
        "no router isis DEADTAG\nno router eigrp 44\n"
    ),
    "acl_and_ace": (
        "no ip access-list extended DEAD\n"
        "ip access-list extended EDIT\n no 20 permit ip any any\n"
    ),
    "policy_seq_deletes": (
        "route-map RM-EDGE permit 10\n set local-preference 50\n"
        "no route-map RM-EDGE permit 20\n"
    ),
    "singleton_nullouts": "no ntp\nno snmp-server\n",
    "nested_field_deletes": (
        "interface Vlan10\n no ip helper-address 10.0.0.100\n"
        "no ntp server 9.9.9.9\nno snmp-server community PUBLIC ro\n"
    ),
    "service_entities": (
        "no ip sla 5\nno track 9\n"
        "no event manager applet OLD\nno banner motd\n"
    ),
    "vrf_delete": "no vrf definition GUEST\n",
    "interface_scoped": (
        "interface GigabitEthernet0/1\n"
        " no shutdown\n"
        " no switchport trunk allowed vlan 50\n"
        " no ip helper-address 10.9.9.9\n"
    ),
    "bgp_scoped": (
        "router bgp 65000\n"
        " no neighbor 10.0.0.9\n"
        " address-family ipv4\n"
        "  no network 1.2.3.0\n"
    ),
    "mixed_kitchen_sink": (
        "no interface Loopback9\n"
        "no ip sla 5\n"
        "no router ospf 3\n"
        "no vrf definition OLD\n"
        "no ip access-list extended DEAD\n"
        "no route-map RM-OLD permit 10\n"
        "no ntp server 9.9.9.9\n"
        "router bgp 65000\n"
        " no neighbor 10.0.0.9\n"
        "interface Gi0/2\n no shutdown\n"
    ),
}

# One positive create case per retired family LETTER (Appendices L/Q/S/T–W/Y).
CREATE_CORPUS: dict[str, str] = {
    "L_bgp_instance": (
        "router bgp 65000\n neighbor 10.0.0.1 remote-as 65001\n"
    ),
    "Q_ospf_process": "router ospf 1\n network 10.0.0.0 0.0.0.255 area 0\n",
    "Q_eigrp_process": "router eigrp 100\n network 10.0.0.0\n",
    "Q_isis_process": "router isis TAG1\n net 49.0001.0000.0000.0001.00\n",
    "S_vrf": "vrf definition CUST\n rd 100:1\n address-family ipv4\n",
    "T_singleton_ntp": "ntp server 1.1.1.1\nntp server 2.2.2.2\n",
    "U_singleton_dhcp": "ip dhcp pool POOL1\n network 10.0.0.0 255.255.255.0\n",
    "V_singleton_lldp": "lldp run\nlldp holdtime 120\n",
    "W_nat": "ip nat pool NP 1.1.1.1 1.1.1.9 netmask 255.255.255.0\n",
    "Y_route_map": "route-map RM permit 10\n set local-preference 200\n",
    "Y_acl": "ip access-list extended ACL1\n permit ip any any\n",
    "Y_prefix_list": "ip prefix-list PL seq 5 permit 10.0.0.0/8\n",
}

SAMPLE_DIR = Path(__file__).resolve().parent.parent / "samples"

# CCR-0110 Phase E4/E5 (R3): op-primary parsers no longer populate the
# deprecated tombstone containers, so the shim's identity target is no longer
# live ``pc.no_commands`` — it is the FROZEN pre-removal parser emission
# captured at v0.3.5 (commit c12acc8) and checked in beside this file.  The
# shim remains the CODEC ARTIFACT: it reconstructs, from the (unchanged)
# ChangeSet, the byte-exact legacy strings the parser used to emit.  The
# goldens are the independent historical reference proving that.
GOLDENS = json.loads(
    (Path(__file__).resolve().parent / "change_ir_shim_goldens.json").read_text()
)


def _golden_bgp(golden: dict) -> dict:
    """Rehydrate the JSON ``"asn|vrf"`` bgp keys into the (asn, vrf) tuples the
    encoder produces."""
    return {
        (k.split("|", 1)[0], k.split("|", 1)[1]): v
        for k, v in golden["bgp_no_commands"].items()
    }


# ---------------------------------------------------------------------------
# Shared assertions
# ---------------------------------------------------------------------------


def _assert_tombstones_match_golden(pc, golden):
    """The shim reconstructs the FROZEN pre-removal parser emission (*golden*).

    Post-Phase-E the parser no longer populates the tombstone containers, so the
    identity target is the checked-in golden (the byte-exact v0.3.5 emission),
    not live ``pc.*``.  The shim's ChangeSet source (``derive_ops``) is
    unchanged, so this stays a real byte-identity contract over the codec.

    - top-level ``no_commands``: byte-exact SEQUENCE for non-hoisted families,
      byte-exact MULTISET for the natively hoisted ones (the ``_roundtrip``
      contract — order among them is semantically inert, disjoint handlers).
    - ``interface_no_commands`` / ``bgp_no_commands``: exact against the golden.
    - ``unrecognized_blocks``: unaffected by emission removal, checked live.
    """
    art = encode_legacy_shim(derive_ops(pc))
    g_no = golden["no_commands"]

    stable_shim = [t for t in art.no_commands if not _is_reordered_native_tombstone(t)]
    stable_gold = [t for t in g_no if not _is_reordered_native_tombstone(t)]
    assert stable_shim == stable_gold

    hoisted_shim = sorted(t for t in art.no_commands if _is_reordered_native_tombstone(t))
    hoisted_gold = sorted(t for t in g_no if _is_reordered_native_tombstone(t))
    assert hoisted_shim == hoisted_gold

    assert art.interface_no_commands == golden["interface_no_commands"]
    assert art.bgp_no_commands == _golden_bgp(golden)
    assert art.unrecognized_blocks == list(pc.unrecognized_blocks)


# ---------------------------------------------------------------------------
# Systematic tombstone-identity sweep (corpus × OS)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("os_cls", TOMBSTONE_OSES, ids=lambda c: c.__name__)
@pytest.mark.parametrize(
    "case_key,case", TOMBSTONE_CORPUS.items(), ids=TOMBSTONE_CORPUS.keys()
)
def test_shim_tombstones_match_parser(case_key, case, os_cls):
    _assert_tombstones_match_golden(
        os_cls(case).parse(), GOLDENS["corpus"][os_cls.__name__][case_key]
    )


@pytest.mark.parametrize("os_cls", TOMBSTONE_OSES, ids=lambda c: c.__name__)
@pytest.mark.parametrize(
    "case_key,case", CREATE_CORPUS.items(), ids=CREATE_CORPUS.keys()
)
def test_shim_create_cases_emit_no_tombstones(case_key, case, os_cls):
    """Retired-family create ops (SET, path ending ``instance``) must never leak
    a spurious tombstone into any ``no_commands`` container."""
    _assert_tombstones_match_golden(
        os_cls(case).parse(), GOLDENS["create"][os_cls.__name__][case_key]
    )


@pytest.mark.parametrize("name", sorted(SAMPLE_DIR.glob("*.txt")), ids=lambda p: p.name)
def test_shim_tombstones_match_parser_samples(name):
    """Whole shipped running-configs (all OSes incl. IOS-XR gated families) —
    exercises rich set_fields reconstitution and the empty-tombstone path."""
    from confgraph.loader import detect_os, parser_for

    text = Path(name).read_text(encoding="utf-8", errors="replace")
    parser_cls = parser_for(detect_os(text))
    _assert_tombstones_match_golden(
        parser_cls(text).parse(), GOLDENS["samples"][name.name]
    )


# ---------------------------------------------------------------------------
# Whole-object SET reconstitution (deliverable 1a) — per family letter
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("case", CREATE_CORPUS.values(), ids=CREATE_CORPUS.keys())
def test_shim_reconstitutes_whole_object_set_fields(case):
    """For every whole-object create op the shim rebuilds the legacy
    ``set_fields[(<container>, <key…>)] = <object>`` entry, drops the
    ``"instance"`` sentinel key and the subsumed per-member SETs, and the value
    equals what the pre-native (natives-less) deriver produced."""
    pc = IOSParser(case).parse()
    ops = derive_ops(pc)
    creates = [op for op in ops if is_native_whole_object_create_op(op)]
    assert creates, "corpus case must exercise at least one whole-object create op"

    art = encode_legacy_shim(ops)

    # Natives-less ground truth = the pre-native legacy set_fields.
    pc_legacy = IOSParser(case).parse()
    pc_legacy.native_change_ops = None
    legacy = encode_legacy(derive_ops(pc_legacy))

    for create in creates:
        whole = create.path[:-1]
        # legacy whole-object entry present, byte-value identical to legacy
        assert whole in art.set_fields
        assert whole in legacy.set_fields
        assert art.set_fields[whole] == legacy.set_fields[whole]
        # sentinel + subsumed member entries gone
        assert create.path not in art.set_fields  # ("…","instance") retired
        assert not any(
            len(p) > len(whole) and p[: len(whole)] == whole for p in art.set_fields
        )


def test_shim_interface_members_stay_decomposed_not_reconstituted():
    """Family X (interface collection members) has no create op — its members
    stay per-member 4-segment ``set_fields`` entries (CCR Appendix X shim note),
    never collapsed into a whole-list SET."""
    pc = IOSParser(
        "interface GigabitEthernet0/1\n"
        " ip address 10.0.0.1 255.255.255.0 secondary\n"
        " ip address 10.0.0.2 255.255.255.0 secondary\n"
    ).parse()
    art = encode_legacy_shim(derive_ops(pc))
    member_keys = [
        p for p in art.set_fields
        if p[0] == "interface" and len(p) == 4 and p[2] == "secondary_ips"
    ]
    assert member_keys, "expected per-member 4-segment interface set_fields entries"
    assert ("interface", "GigabitEthernet0/1", "secondary_ips") not in art.set_fields


# ---------------------------------------------------------------------------
# _readded_later suppression (deliverable 1b, CCR Appendix F.6) — both orders
# ---------------------------------------------------------------------------

# (config, entity tombstone) for each of the four unconditionally-emitted
# service-entity delete families.
_ENTITY_CASES = {
    "ip_sla": ("ip sla {n}\n icmp-echo 1.1.1.1\n", "no ip sla {n}\n", "field:ip_sla_operations:{n}"),
    "track": ("track {n} ip route 10.0.0.0 255.0.0.0 reachability\n", "no track {n}\n", "field:object_tracks:{n}"),
    "eem": ("event manager applet {n}\n action 1 syslog msg X\n", "no event manager applet {n}\n", "field:eem_applets:{n}"),
    "banner": ("banner motd ^C hi ^C\n", "no banner motd\n", "field:banners:motd"),
}


@pytest.mark.parametrize("family", _ENTITY_CASES.keys())
def test_shim_suppresses_delete_then_readd(family):
    """delete THEN re-add (later positive) → tombstone SUPPRESSED by the shim
    (whereas the raw ``encode_legacy`` still shows it — the F.6 gap the shim
    closes).  Post-Phase-E the parser no longer emits the string at all
    (``pc.no_commands`` empty), so the suppression contract lives entirely in
    the shim codec — which is exactly what this asserts."""
    add, delete, tomb = _ENTITY_CASES[family]
    tomb = tomb.format(n=7)
    pc = IOSParser(delete.format(n=7) + add.format(n=7)).parse()
    assert tomb not in pc.no_commands  # op-primary no longer emits (empty)
    assert tomb in encode_legacy(derive_ops(pc)).no_commands  # raw encode does not
    assert tomb not in encode_legacy_shim(derive_ops(pc)).no_commands  # shim does


@pytest.mark.parametrize("family", _ENTITY_CASES.keys())
def test_shim_keeps_readd_then_delete(family):
    """re-add THEN delete (delete-wins, no later positive) → tombstone KEPT by
    the shim (the parser no longer emits it — op-primary; the shim codec is now
    the sole producer of the legacy string)."""
    add, delete, tomb = _ENTITY_CASES[family]
    tomb = tomb.format(n=7)
    pc = IOSParser(add.format(n=7) + delete.format(n=7)).parse()
    assert tomb not in pc.no_commands  # op-primary no longer emits (empty)
    assert tomb in encode_legacy_shim(derive_ops(pc)).no_commands


# ---------------------------------------------------------------------------
# Structural / zero-behavior-change guards
# ---------------------------------------------------------------------------


def test_create_predicate_registry_matches_derive_ops_claims():
    """Registry change-detector: freezes the current membership of
    ``_WHOLE_OBJECT_CREATE_PREDICATES`` so any edit is a deliberate act.

    This is a literal pin, NOT a derived check against ``derive_ops`` — the
    real registry↔deriver coupling is enforced by the corpus ``set_fields``
    sweep (a forgotten registry entry leaks the ``"instance"`` sentinel and
    subsumed members there). A new retired family must be added in both
    places (one entry each) AND get a CREATE_CORPUS case, which is what
    actually protects it."""
    assert set(ci._WHOLE_OBJECT_CREATE_PREDICATES) == {
        ci.is_native_bgp_instance_create_op,
        ci.is_native_ospf_instance_create_op,
        ci.is_native_eigrp_instance_create_op,
        ci.is_native_isis_instance_create_op,
        ci.is_native_vrf_instance_create_op,
        ci.is_native_policy_instance_create_op,
        ci.is_native_singleton_instance_create_op,
    }


def test_shim_degrades_to_encode_legacy_without_natives():
    """Natives-less producers (JunOS/PAN-OS, hand-built models): both shim
    wrappers are no-ops and the shim is byte-identical to ``encode_legacy``."""
    pc = IOSParser(TOMBSTONE_CORPUS["mixed_kitchen_sink"]).parse()
    pc.native_change_ops = None
    ops = derive_ops(pc)
    shim = encode_legacy_shim(ops)
    plain = encode_legacy(ops)
    assert shim.no_commands == plain.no_commands
    assert shim.interface_no_commands == plain.interface_no_commands
    assert shim.bgp_no_commands == plain.bgp_no_commands
    assert shim.set_fields == plain.set_fields


def test_shim_is_pure_no_input_mutation():
    """The shim must not mutate its input ChangeSet."""
    pc = IOSParser(CREATE_CORPUS["L_bgp_instance"] + "no ip sla 5\n").parse()
    ops = derive_ops(pc)
    before = list(ops)
    encode_legacy_shim(ops)
    assert ops == before


# ---------------------------------------------------------------------------
# Metamorphic drift guard — proves the identity sweep actually catches drift
# ---------------------------------------------------------------------------

# (config, victim tombstone, drifted replacement, expected-hoisted).  One case
# per arm of ``_assert_tombstones_match_golden``: a NON-hoisted family
# (order-exact sequence arm) and a natively-hoisted family (order-inert multiset
# arm).  ``expected_hoisted`` is asserted below so a future tombstone-format
# rename makes THIS test fail loudly instead of silently degrading into a no-op.
_DRIFT_CASES = {
    "sequence_arm_acl": (
        "no ip access-list extended DEAD\n", "acl:DEAD", "acl:DEAF", False,
    ),
    "multiset_arm_ip_sla": (
        "no ip sla 5\n", "field:ip_sla_operations:5",
        "field:ip_sla_operations:55", True,
    ),
}


@pytest.mark.parametrize(
    "case", _DRIFT_CASES.values(), ids=_DRIFT_CASES.keys()
)
def test_identity_sweep_catches_native_emission_drift(case):
    """If the shim reconstruction drifts from the frozen golden, the byte-identity
    assertion MUST fail — otherwise the whole sweep is a rubber stamp.

    Post-Phase-E the parser no longer emits the strings, so drift is injected
    into the GOLDEN (the identity target) rather than into ``pc.no_commands``.
    The golden reference for this ad-hoc case is the byte-exact shim
    reconstruction (== the pre-removal parser emission by construction); a
    one-token mutation of it must trip the assertion on the arm this case names.
    Guarded against silent decay: the victim must actually be present and live in
    its expected arm before the drift is injected.
    """
    text, victim, drifted, expected_hoisted = case

    pc = IOSParser(text).parse()
    art = encode_legacy_shim(derive_ops(pc))
    golden = {
        "no_commands": list(art.no_commands),
        "interface_no_commands": dict(art.interface_no_commands),
        "bgp_no_commands": {
            f"{k[0]}|{k[1]}": list(v) for k, v in art.bgp_no_commands.items()
        },
    }

    # Baseline: shim reconstruction is byte-identical to its golden.
    _assert_tombstones_match_golden(pc, golden)

    # Precondition — the victim exists and lives in the arm this case names.
    assert victim in golden["no_commands"], (
        f"drift-guard victim {victim!r} not in golden {golden['no_commands']!r} "
        "— tombstone format changed; update this case, do not delete it"
    )
    assert _is_reordered_native_tombstone(victim) is expected_hoisted, (
        f"{victim!r} changed arm (hoisted={not expected_hoisted}); "
        "this case no longer exercises the arm it claims"
    )

    # Inject a one-token drift into the golden; shim output is unchanged, so the
    # identity assertion must now fail on the arm this case targets.
    drifted_golden = dict(golden)
    drifted_golden["no_commands"] = [
        t.replace(victim, drifted) for t in golden["no_commands"]
    ]
    with pytest.raises(AssertionError):
        _assert_tombstones_match_golden(pc, drifted_golden)
