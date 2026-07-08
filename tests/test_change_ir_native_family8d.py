"""Phase 3 family 8d — simple keyed lists + nat/crypto (CCR Appendix W).

Parser-side pins:

- shape 1 (``lines`` / ``class_maps`` / ``policy_maps`` / ``rip_instances``):
  native per-entry keyed SETs at the EXACT derived paths (real block
  provenance, parse order), retirement by exact-path dedupe, the
  batched-path posture (NO ``is_native_*`` predicate matches them),
- nat (create-mode "adopt"): create op + the three member kinds, NO scalar
  ops EVER (the mode anti-rot pin — scalars ride the create value),
- crypto (create-mode "replace"): create op ONLY,
- inline retirement of the derived ``("nat",)`` / ``("crypto",)`` SETs,
- legacy artifacts untouched (no tombstones exist for any 8d surface —
  ``no_commands`` empty, byte-identity trivial),
- per-OS: NX-OS/EOS inherit the walks; IOS-XR emits shape-1 natively
  (harmless, path-identical) but keeps nat/crypto DERIVED (the 8a gate);
  PAN-OS is natives-less → ``zones`` stays derived (W.0 pin),
- codec anti-rot: mode registrations, key mirrors, seed-immunity rulings.
"""

import pytest

from confgraph.change_ir import (
    Verb,
    derive_ops,
    encode_legacy,
    is_native_singleton_instance_create_op,
    is_native_singleton_section_op,
    simple_keyed_list_fields,
    simple_keyed_list_key,
    singleton_create_mode,
    singleton_line_detected_scalars,
    singleton_member_kinds,
    singleton_section_fields,
)
from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.iosxr_parser import IOSXRParser
from confgraph.parsers.nxos_parser import NXOSParser

SHAPE1 = ("class_maps", "lines", "policy_maps", "rip_instances")


def _parse(text: str):
    return IOSParser(text).parse()


KITCHEN_SINK = """\
hostname r1
line vty 0 4
 login local
 transport input ssh
line con 0
 login local
class-map match-any VOICE
 match dscp ef
policy-map EDGE
 class VOICE
  priority percent 30
router rip
 version 2
 network 10.0.0.0
ip nat pool P1 10.1.1.1 10.1.1.10 netmask 255.255.255.0
ip nat inside source list NATACL pool P1 overload
ip nat inside source static tcp 10.0.0.5 443 192.0.2.5 443
ip nat translation timeout 300
ip nat translation max-entries 1000
crypto isakmp policy 10
 encryption aes
crypto ipsec transform-set TS esp-aes esp-sha-hmac
crypto map VPN 10 ipsec-isakmp
 set peer 203.0.113.9
 set transform-set TS
 match address CRYPTOACL
"""


def _native(pc):
    return list(pc.native_change_ops or [])


class TestShape1Emission:
    def test_native_keyed_sets_emitted_with_provenance(self):
        pc = _parse(KITCHEN_SINK)
        native = _native(pc)
        by_path = {op.path: op for op in native}
        for path in (
            ("lines", "vty", "0"),
            ("lines", "console", "0"),
            ("class_maps", "VOICE"),
            ("policy_maps", "EDGE"),
            ("rip_instances", ""),
        ):
            assert path in by_path, path
            op = by_path[path]
            assert op.verb is Verb.SET and op.origin == "native"
            assert op.line_no >= 0 and op.source_line

    def test_paths_mirror_codec_keys_and_values_are_entries(self):
        pc = _parse(KITCHEN_SINK)
        native = {op.path: op for op in _native(pc)}
        for field in simple_keyed_list_fields():
            for item in getattr(pc, field):
                path = (field, *simple_keyed_list_key(field, item))
                assert native[path].value is item

    def test_derived_twins_retired_exact_path(self):
        pc = _parse(KITCHEN_SINK)
        ops = derive_ops(pc)
        for field in SHAPE1:
            for op in ops:
                if op.path[0] == field:
                    assert op.origin == "native", op
        # exactly one composed op per entry path (no dupes, no leftovers)
        assert sum(1 for op in ops if op.path == ("class_maps", "VOICE")) == 1

    def test_duplicate_key_blocks_keep_multiplicity_and_order(self):
        pc = _parse(
            "class-map match-any VOICE\n match dscp ef\n"
            "class-map match-any VOICE\n match dscp cs5\n"
        )
        ops = [op for op in derive_ops(pc) if op.path == ("class_maps", "VOICE")]
        assert len(ops) == len(pc.class_maps)
        assert all(op.origin == "native" for op in ops)
        # parse order preserved — the last block wins downstream, == legacy
        assert [op.value for op in ops] == list(pc.class_maps)

    def test_encode_legacy_roundtrip_no_tombstones(self):
        pc = _parse(KITCHEN_SINK)
        art = encode_legacy(derive_ops(pc))
        assert art.no_commands == []
        assert ("lines", "vty", "0") in art.set_fields
        assert ("rip_instances", "") in art.set_fields

    def test_no_native_predicate_matches_shape1(self):
        # The batched-path posture (W.0): shape-1 ops must NOT be skipped by
        # any engine replay predicate — they flow the generic keyed-list
        # reconstruction.  A predicate matching them = a posture regression.
        from confgraph.change_ir import (
            is_native_bgp_op,
            is_native_eigrp_op,
            is_native_isis_op,
            is_native_ospf_op,
            is_native_service_entity_op,
            is_native_static_op,
            is_native_vlan_op,
            is_native_vrf_op,
        )

        pc = _parse(KITCHEN_SINK)
        preds = (
            is_native_service_entity_op,
            is_native_static_op,
            is_native_bgp_op,
            is_native_isis_op,
            is_native_eigrp_op,
            is_native_ospf_op,
            is_native_vrf_op,
            is_native_singleton_section_op,
            is_native_vlan_op,
        )
        for op in _native(pc):
            if op.path[0] in SHAPE1:
                assert not any(p(op) for p in preds), op.path


class TestNatEmission:
    def test_create_plus_members_no_scalars(self):
        pc = _parse(KITCHEN_SINK)
        nat_ops = [op for op in _native(pc) if op.path[0] == "nat"]
        paths = {op.path for op in nat_ops}
        assert ("nat", "instance") in paths
        assert ("nat", "pools", "P1") in paths
        assert ("nat", "dynamic_entries", "NATACL") in paths
        assert ("nat", "static_entries", "10.0.0.5", "443") in paths
        # the mode anti-rot pin (W.1): NO scalar op may EVER be emitted for
        # an adopt-mode section — scalars ride the create value.
        assert not any(op.path[1] == "scalar" for op in nat_ops)
        create = next(op for op in nat_ops if op.path == ("nat", "instance"))
        assert create.value is pc.nat
        assert create.value.timeouts.default == 300

    def test_portless_static_entry_key_uses_empty_segment(self):
        pc = _parse("ip nat inside source static 10.0.0.9 192.0.2.9\n")
        paths = {op.path for op in _native(pc)}
        assert ("nat", "static_entries", "10.0.0.9", "") in paths

    def test_derived_nat_set_retired(self):
        pc = _parse(KITCHEN_SINK)
        ops = derive_ops(pc)
        assert not any(op.path == ("nat",) for op in ops)
        assert sum(1 for op in ops if op.path == ("nat", "instance")) == 1


class TestCryptoEmission:
    def test_create_op_only(self):
        pc = _parse(KITCHEN_SINK)
        crypto_ops = [op for op in _native(pc) if op.path[0] == "crypto"]
        assert [op.path for op in crypto_ops] == [("crypto", "instance")]
        assert crypto_ops[0].value is pc.crypto
        assert is_native_singleton_instance_create_op(crypto_ops[0])

    def test_derived_crypto_set_retired(self):
        pc = _parse(KITCHEN_SINK)
        ops = derive_ops(pc)
        assert not any(op.path == ("crypto",) for op in ops)
        assert sum(1 for op in ops if op.path == ("crypto", "instance")) == 1

    def test_create_op_encodes_to_set_fields(self):
        pc = _parse("crypto isakmp policy 10\n encryption aes\n")
        art = encode_legacy(derive_ops(pc))
        assert ("crypto", "instance") in art.set_fields
        assert art.no_commands == []


class TestPerOS:
    def test_nxos_inherits_walks(self):
        pc = NXOSParser(
            "hostname n1\n"
            "line vty\n exec-timeout 15\n"
            "ip nat pool P1 10.1.1.1 10.1.1.10 netmask 255.255.255.0\n"
        ).parse()
        paths = {op.path for op in _native(pc)}
        if pc.lines:
            assert any(p[0] == "lines" for p in paths)
        if pc.nat is not None:
            assert ("nat", "instance") in paths

    def test_iosxr_shape1_native_but_nat_crypto_gated(self):
        pc = IOSXRParser(
            "hostname x1\n"
            "line console\n exec-timeout 10 0\n"
            "class-map match-any VOICE\n match dscp ef\n"
        ).parse()
        # shape-1: harmless native emission (path-identical keyed-replace
        # parity — the 8c vlan posture)
        if pc.class_maps:
            assert any(
                op.path == ("class_maps", "VOICE") and op.origin == "native"
                for op in _native(pc)
            )
        # nat/crypto ride the GATED singleton walk: no section natives on XR
        assert not any(
            op.path[0] in ("nat", "crypto") for op in _native(pc)
        )

    def test_iosxr_nat_stays_derived(self):
        pc = IOSXRParser(
            "ip nat pool P1 10.1.1.1 10.1.1.10 netmask 255.255.255.0\n"
        ).parse()
        if pc.nat is not None:
            ops = derive_ops(pc)
            assert any(
                op.path == ("nat",) and op.origin == "derived" for op in ops
            )

    def test_zones_stay_derived_natives_less_producer(self):
        # zones are PAN-OS-only (W.0) and PANOSParser subclasses BaseParser →
        # natives-less by construction.  A hand-built ParsedConfig models the
        # natives-less producer: the derived keyed zones SET must survive.
        from confgraph.models.panos_zone import PANOSZoneConfig
        from confgraph.models.parsed_config import ParsedConfig

        pc = ParsedConfig(
            source_os="panos",
            zones=[
                PANOSZoneConfig(
                    object_id="zone_trust",
                    source_os="panos",
                    name="trust",
                    vsys="vsys1",
                )
            ],
        )
        ops = derive_ops(pc)
        zone_ops = [op for op in ops if op.path[0] == "zones"]
        assert zone_ops and all(op.origin == "derived" for op in zone_ops)
        assert zone_ops[0].path == ("zones", "trust", "vsys1")


class TestCodec:
    def test_create_mode_registrations(self):
        assert singleton_create_mode("nat") == "adopt"
        assert singleton_create_mode("crypto") == "replace"
        for sect in sorted(singleton_section_fields() - {"nat", "crypto"}):
            assert singleton_create_mode(sect) == "seed", sect

    def test_boundary_and_keys(self):
        assert simple_keyed_list_fields() == frozenset(
            {"lines", "class_maps", "policy_maps", "rip_instances"}
        )
        # zones deliberately excluded (natives-less producer only — W.0)
        assert "zones" not in simple_keyed_list_fields()

    def test_nat_member_kinds_mirror_nat_rule(self):
        assert singleton_member_kinds("nat") == frozenset(
            {"pools", "dynamic_entries", "static_entries"}
        )
        assert singleton_member_kinds("crypto") == frozenset()

    def test_no_line_detected_scalars(self):
        assert singleton_line_detected_scalars("nat") == frozenset()
        assert singleton_line_detected_scalars("crypto") == frozenset()

    @pytest.mark.parametrize("section", ["nat", "crypto"])
    def test_adopt_replace_sections_are_seed_immune(self, section):
        """Adopt/replace sections carry EVERY model field on the create op's
        value (the engine never applies the generic reset seed to them —
        W.1), so the T.3 completeness partition is unnecessary: a future
        model field automatically rides the create value.  The pin instead
        asserts the mode registration + that the parser walk emitted no
        scalar/unregistered-member decomposition (checked per-parse in
        TestNatEmission/TestCryptoEmission)."""
        assert singleton_create_mode(section) != "seed"

    def test_anti_rot_family8d_never_derived(self):
        pc = _parse(KITCHEN_SINK)
        ops = derive_ops(pc)
        for op in ops:
            if op.path[0] in SHAPE1 + ("nat", "crypto"):
                assert op.origin == "native", op

    def test_legacy_artifacts_byte_identical(self):
        # No 8d surface has a negation shape (W.0): the parse's legacy
        # artifacts are tombstone-free and unchanged by the migration.
        pc = _parse(KITCHEN_SINK)
        assert pc.no_commands == []
        assert not pc.unrecognized_blocks or all(
            "nat" not in b.block_header and "crypto" not in b.block_header
            for b in pc.unrecognized_blocks
        )
