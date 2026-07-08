"""Phase 3 family 8b — infra singleton decomposition (CCR Appendix U).

Parser-side pins for dhcp / netflow / multicast / bfd / mpls / vxlan / vpc:
native op emission (whole-section create + scalar + member SETs — the 8a
codec, registry-extended), byte-exact tombstone twins (string AND order),
inline retirement of the derived whole-singleton SETs, the required-field
scalar ruling (``vpc.domain_id`` always-emitted), the NO-tri-state ruling
(dhcp negative lines are parser-invisible — blind in both modes), the
IOS-XR gate (``singleton:multicast`` stays derived), and the anti-rot
completeness / never-derived pins extended to all twelve migrated sections.
"""

import pytest

from confgraph.change_ir import (
    Verb,
    derive_ops,
    encode_legacy,
    is_native_singleton_instance_create_op,
    is_native_singleton_section_op,
    singleton_line_detected_scalars,
    singleton_member_kinds,
    singleton_scalar_fields,
    singleton_section_fields,
)
from confgraph.parsers.eos_parser import EOSParser
from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.iosxr_parser import IOSXRParser
from confgraph.parsers.nxos_parser import NXOSParser

SECTIONS_8B = ("bfd", "dhcp", "mpls", "multicast", "netflow", "vpc", "vxlan")
SECTIONS_ALL = ("aaa", "dns", "ntp", "snmp", "syslog") + SECTIONS_8B


def _parse(text: str):
    return IOSParser(text).parse()


def _native(pc):
    return [op for op in pc.native_change_ops if is_native_singleton_section_op(op)]


KITCHEN_SINK = """\
hostname r1
ip dhcp excluded-address 10.1.1.1 10.1.1.10
ip dhcp pool LAN
 network 10.1.1.0 255.255.255.0
 default-router 10.1.1.1
 dns-server 8.8.8.8 8.8.4.4
 domain-name corp.example
 lease 7
ip dhcp snooping
ip dhcp snooping vlan 10,20
ip flow-export source GigabitEthernet0/1
ip flow-export version 9
ip flow-export destination 10.0.0.100 9996
ip multicast-routing distributed
ip pim rp-address 10.5.5.5 MCAST-ACL
ip pim ssm range SSM-ACL
ip msdp peer 10.4.4.4 connect-source Loopback0 remote-as 65001
bfd-template single-hop FAST
 interval min-tx 100 min-rx 100 multiplier 3
 no echo
bfd map ipv4 10.0.0.0/24 10.1.0.0/24 FAST
bfd slow-timers 2000
mpls ldp router-id Loopback0 force
mpls label range 100 199
mpls ldp graceful-restart
no ip pim rp-address 10.9.9.9
no ip msdp peer 10.9.9.8
no bfd-template single-hop OLD
no ip flow-export destination 10.9.9.7 9996
no ip dhcp pool OLD
no ip dhcp excluded-address 10.9.9.6
"""

# The exact legacy tombstones, IN WALK ORDER (byte-identity pin — this list is
# what HEAD emitted before family 8b; the strings AND sequence must survive).
KITCHEN_SINK_TOMBSTONES = [
    "field:multicast:rp:10.9.9.9",
    "field:multicast:msdp:10.9.9.8",
    "field:bfd:template:OLD",
    "field:netflow:destination:10.9.9.7:9996",
    "field:dhcp:pool:OLD",
    "field:dhcp:excluded:10.9.9.6",
]

NXOS_SINK = """\
hostname n9k
vlan 10
  vn-segment 10010
interface nve1
  no shutdown
  host-reachability protocol bgp
  source-interface loopback1
  member vni 10010
    suppress-arp
    mcast-group 239.1.1.1
  no member vni 10099
  no host-reachability protocol
vpc domain 100
  role priority 1000
  peer-keepalive destination 10.0.0.2 source 10.0.0.1 vrf management
  auto-recovery
  no peer-keepalive
mpls ldp configuration
  router-id Loopback0
  graceful-restart
"""

EOS_SINK = """\
hostname eos1
interface Vxlan1
   vxlan source-interface Loopback1
   vxlan udp-port 4789
   vxlan vlan 10 vni 10010
   vxlan flood vtep 10.0.0.2 10.0.0.3
   no vxlan vlan 100 vni 10100
   no vxlan vrf T1 vni 50001
mlag configuration
   domain-id MLAG1
   peer-address 10.0.0.2
   peer-link Port-Channel1
   no peer-address
bfd slow-timer 2000
mpls ldp
   router-id interface Loopback0
"""


# ---------------------------------------------------------------------------
# Byte-identity of legacy artifacts (string AND order)
# ---------------------------------------------------------------------------


class TestTombstoneTwins:
    def test_kitchen_sink_tombstones_byte_identical_in_order(self):
        pc = _parse(KITCHEN_SINK)
        assert pc.no_commands == KITCHEN_SINK_TOMBSTONES

    def test_singleton_nullouts_byte_identical_in_order(self):
        # walk order: the multicast null-out site precedes the netflow one
        pc = _parse("no ip flow-export\nno ip multicast-routing\n")
        assert pc.no_commands == ["singleton:multicast", "singleton:netflow"]

    def test_nxos_twins_byte_identical_in_order(self):
        pc = NXOSParser(NXOS_SINK).parse()
        assert pc.no_commands == [
            "field:vxlan:vni:10099",
            "field:vxlan:host_reachability",
            "field:vpc:peer_keepalive_destination",
            "field:vpc:peer_keepalive_source",
            "field:vpc:peer_keepalive_vrf",
        ]

    def test_eos_twins_byte_identical_in_order(self):
        pc = EOSParser(EOS_SINK).parse()
        assert pc.no_commands == [
            "field:vxlan:vni:10100",
            "field:vxlan:vni:50001",
            "field:vpc:peer_keepalive_destination",
        ]

    def test_every_twin_regenerated_from_a_native_op(self):
        for pc in (
            _parse(KITCHEN_SINK + "no ip multicast-routing\nno ip flow-export\n"),
            NXOSParser(NXOS_SINK).parse(),
            EOSParser(EOS_SINK).parse(),
        ):
            native_paths = {":".join(op.path) for op in _native(pc)}
            for t in pc.no_commands:
                assert t in native_paths, t

    def test_roundtrip_multiset(self):
        pc = _parse(KITCHEN_SINK + "no ip multicast-routing\nno ip flow-export\n")
        art = encode_legacy(derive_ops(pc))
        assert sorted(art.no_commands) == sorted(pc.no_commands)


# ---------------------------------------------------------------------------
# Native op inventory + verbs
# ---------------------------------------------------------------------------


class TestEmission:
    def test_create_op_per_parsed_section(self):
        pc = _parse(KITCHEN_SINK)
        creates = sorted(
            op.path for op in _native(pc) if is_native_singleton_instance_create_op(op)
        )
        # vxlan / vpc are NX-OS/EOS sections — absent from an IOS parse
        assert creates == [
            (s, "instance") for s in ("bfd", "dhcp", "mpls", "multicast", "netflow")
        ]

    def test_scalar_ops_state_derived_non_default_only(self):
        pc = _parse(KITCHEN_SINK)
        scalar_paths = {
            op.path for op in _native(pc) if len(op.path) == 3 and op.path[1] == "scalar"
        }
        for expected in [
            ("dhcp", "scalar", "snooping_enabled"),
            ("netflow", "scalar", "source_interface"),
            ("netflow", "scalar", "version"),
            ("multicast", "scalar", "multicast_routing_enabled"),
            ("multicast", "scalar", "multicast_routing_distributed"),
            ("multicast", "scalar", "pim_ssm_range"),
            ("bfd", "scalar", "slow_timers"),
            ("mpls", "scalar", "ldp_router_id"),
            ("mpls", "scalar", "ldp_router_id_force"),
            ("mpls", "scalar", "label_range_min"),
            ("mpls", "scalar", "label_range_max"),
            ("mpls", "scalar", "ldp_enabled"),
            ("mpls", "scalar", "ldp_graceful_restart"),
        ]:
            assert expected in scalar_paths, expected
        # default-valued scalars are NOT emitted (state-derived rule):
        # relay_information_option stays True (the negative line is
        # parser-invisible — U.2), autorp/bsr unset, session protection off.
        assert ("dhcp", "scalar", "relay_information_option") not in scalar_paths
        assert ("multicast", "scalar", "pim_autorp") not in scalar_paths
        assert ("mpls", "scalar", "ldp_session_protection") not in scalar_paths

    def test_member_ops_cover_every_list_member(self):
        pc = _parse(KITCHEN_SINK)
        paths = {op.path for op in _native(pc)}
        for expected in [
            ("dhcp", "excluded_ranges", "10.1.1.1"),
            ("dhcp", "pools", "LAN"),
            ("dhcp", "snooping_vlans", "10,20"),
            ("netflow", "destinations", "10.0.0.100", "9996"),
            ("multicast", "pim_rp_addresses", "10.5.5.5", "MCAST-ACL"),
            ("multicast", "msdp_peers", "10.4.4.4"),
            ("bfd", "templates", "FAST"),
            ("bfd", "maps", "ipv4", "10.0.0.0/24", "10.1.0.0/24"),
        ]:
            assert expected in paths, expected

    def test_rp_key_none_acl_uses_empty_segment(self):
        pc = _parse("ip pim rp-address 10.5.5.5\n")
        paths = {op.path for op in _native(pc)}
        assert ("multicast", "pim_rp_addresses", "10.5.5.5", "") in paths

    def test_removal_verbs_match_the_codec_registry(self):
        pc = _parse(KITCHEN_SINK + "no ip multicast-routing\nno ip flow-export\n")
        by_path = {op.path: op for op in _native(pc)}
        assert by_path[("field", "multicast", "rp", "10.9.9.9")].verb is Verb.LIST_REMOVE
        assert by_path[("field", "multicast", "msdp", "10.9.9.8")].verb is Verb.LIST_REMOVE
        assert by_path[("field", "bfd", "template", "OLD")].verb is Verb.LIST_REMOVE
        assert (
            by_path[("field", "netflow", "destination", "10.9.9.7", "9996")].verb
            is Verb.LIST_REMOVE
        )
        assert by_path[("field", "dhcp", "pool", "OLD")].verb is Verb.LIST_REMOVE
        assert by_path[("field", "dhcp", "excluded", "10.9.9.6")].verb is Verb.LIST_REMOVE
        assert by_path[("singleton", "multicast")].verb is Verb.UNSET
        assert by_path[("singleton", "netflow")].verb is Verb.UNSET

    def test_scalar_reset_removals_are_unsets(self):
        pc = NXOSParser(NXOS_SINK).parse()
        by_path = {op.path: op for op in _native(pc)}
        assert by_path[("field", "vxlan", "host_reachability")].verb is Verb.UNSET
        assert by_path[("field", "vpc", "peer_keepalive_destination")].verb is Verb.UNSET
        assert by_path[("field", "vpc", "peer_keepalive_source")].verb is Verb.UNSET
        assert by_path[("field", "vpc", "peer_keepalive_vrf")].verb is Verb.UNSET
        assert by_path[("field", "vxlan", "vni", "10099")].verb is Verb.LIST_REMOVE

    def test_removal_ops_carry_true_lines(self):
        pc = _parse("ip dhcp pool LAN\n network 10.1.1.0 255.255.255.0\nno ip dhcp pool OLD\n")
        op = next(o for o in _native(pc) if o.path == ("field", "dhcp", "pool", "OLD"))
        assert op.line_no >= 0
        assert op.source_line == "no ip dhcp pool OLD"

    def test_vpc_domain_id_always_emitted(self):
        # REQUIRED business field (PydanticUndefined default) — structural
        # scalar, always-emitted (U.1; mirrors the legacy unconditional
        # override arm of _merge_singleton_additive).
        pc = NXOSParser("vpc domain 100\n  role priority 1000\n").parse()
        by_path = {op.path: op for op in _native(pc)}
        assert by_path[("vpc", "scalar", "domain_id")].value == 100
        assert by_path[("vpc", "scalar", "role_priority")].value == 1000


# ---------------------------------------------------------------------------
# NO tri-state in family 8b (Appendix U.2)
# ---------------------------------------------------------------------------


class TestNoTriState:
    def test_no_line_detected_scalars_registered(self):
        for sect in SECTIONS_8B:
            assert singleton_line_detected_scalars(sect) == frozenset()

    def test_dhcp_negative_lines_parser_invisible_blind_both(self):
        # `no ip dhcp snooping` / `no ip dhcp relay information option` never
        # match the anchored ^ip\s+dhcp\s+ scan: no state effect, no
        # tombstone, no native op — blind in BOTH modes (U.2, enumerated).
        pc = _parse(
            "ip dhcp snooping\n"
            "no ip dhcp snooping\n"
            "no ip dhcp relay information option\n"
        )
        assert pc.dhcp.snooping_enabled is True
        assert pc.dhcp.relay_information_option is True
        assert pc.no_commands == []
        scalar_paths = {op.path for op in _native(pc)}
        assert ("dhcp", "scalar", "relay_information_option") not in scalar_paths


# ---------------------------------------------------------------------------
# Retirement + composition
# ---------------------------------------------------------------------------


class TestRetirement:
    def test_derived_whole_singleton_sets_retired(self):
        pc = _parse(KITCHEN_SINK)
        ops = derive_ops(pc)
        for sect in ("bfd", "dhcp", "mpls", "multicast", "netflow"):
            assert not any(op.path == (sect,) for op in ops), sect
            assert sum(1 for op in ops if op.path == (sect, "instance")) == 1, sect

    def test_nxos_derived_sets_retired(self):
        pc = NXOSParser(NXOS_SINK).parse()
        ops = derive_ops(pc)
        for sect in ("vxlan", "vpc", "mpls"):
            assert not any(op.path == (sect,) for op in ops), sect
            assert sum(1 for op in ops if op.path == (sect, "instance")) == 1, sect

    def test_unmigrated_singletons_still_derived(self):
        # Pin flipped by WI-8c (controls were ``vtp``/``cdp``) and AGAIN by
        # WI-8d (CCR Appendix W: ``nat``/``crypto`` — the last un-migrated
        # singletons — are now native).  The singleton universe is FULLY
        # migrated, so the control becomes the NATIVES-LESS PRODUCER (a
        # hand-built ParsedConfig — JunOS/PAN-OS/hand-built shape): with no
        # native ops, the derived whole-singleton SETs must SURVIVE
        # composition — the graceful-degradation guarantee this pin always
        # protected.
        from confgraph.models.dhcp import DHCPConfig
        from confgraph.models.nat import NATConfig, NATPool
        from confgraph.models.parsed_config import ParsedConfig

        pc = ParsedConfig(
            source_os="ios",
            nat=NATConfig(
                object_id="nat",
                source_os="ios",
                pools=[
                    NATPool(
                        name="POOL1",
                        start_address="10.1.1.1",
                        end_address="10.1.1.10",
                        netmask="255.255.255.0",
                    )
                ],
            ),
            dhcp=DHCPConfig(
                object_id="dhcp", source_os="ios", snooping_enabled=True
            ),
        )
        ops = derive_ops(pc)
        assert any(op.path == ("nat",) and op.origin == "derived" for op in ops)
        assert any(op.path == ("dhcp",) and op.origin == "derived" for op in ops)

    def test_anti_rot_family8b_never_derived(self):
        pc = _parse(KITCHEN_SINK + "no ip multicast-routing\nno ip flow-export\n")
        ops = derive_ops(pc)
        sections = singleton_section_fields()
        for op in ops:
            if op.path[0] in sections:
                assert op.origin == "native", op
            if (
                len(op.path) >= 2
                and op.path[0] in ("field", "singleton")
                and op.path[1] in sections
            ):
                assert op.origin == "native", op

    def test_derived_twins_deduped_exact_path(self):
        pc = _parse("no ip dhcp pool OLD\nip dhcp pool LAN\n network 10.1.1.0 255.255.255.0\n")
        ops = derive_ops(pc)
        matches = [op for op in ops if op.path == ("field", "dhcp", "pool", "OLD")]
        assert len(matches) == 1 and matches[0].origin == "native"

    def test_create_op_encodes_to_set_fields(self):
        pc = _parse("ip flow-export version 9\n")
        art = encode_legacy(derive_ops(pc))
        assert ("netflow", "instance") in art.set_fields
        assert art.no_commands == []


# ---------------------------------------------------------------------------
# Per-OS gates
# ---------------------------------------------------------------------------


class TestPerOS:
    def test_nxos_own_walks_and_state_walk(self):
        pc = NXOSParser(NXOS_SINK).parse()
        native = _native(pc)
        assert any(op.path == ("vxlan", "instance") for op in native)
        assert any(op.path == ("vxlan", "vni_mappings", "10010") for op in native)
        assert any(op.path == ("vpc", "instance") for op in native)
        assert any(op.path == ("mpls", "instance") for op in native)
        assert any(op.path == ("field", "vxlan", "vni", "10099") for op in native)
        ops = derive_ops(pc)
        assert not any(op.path == ("vxlan",) for op in ops)

    def test_eos_own_walks_and_state_walk(self):
        pc = EOSParser(EOS_SINK).parse()
        native = _native(pc)
        assert any(op.path == ("vxlan", "instance") for op in native)
        assert any(op.path == ("vxlan", "flood_vtep_list", "10.0.0.2") for op in native)
        assert any(op.path == ("vpc", "scalar", "domain_id") for op in native)
        assert any(op.path == ("bfd", "scalar", "slow_timers") for op in native)
        assert any(
            op.path == ("field", "vpc", "peer_keepalive_destination") for op in native
        )
        # explicitly-written default (udp-port 4789) is NOT emitted — the
        # blind-both parity class (U.2), same as legacy's non-default rule.
        assert not any(op.path == ("vxlan", "scalar", "udp_port") for op in native)

    def test_iosxr_gated_no_natives_derived_set_survives(self):
        pc = IOSXRParser(
            "multicast-routing\n address-family ipv4\n  interface all enable\n"
            "router pim\n address-family ipv4\n  rp-address 10.5.5.5\n"
        ).parse()
        assert _native(pc) == []
        ops = derive_ops(pc)
        if pc.multicast is not None:
            assert any(
                op.path == ("multicast",) and op.origin == "derived" for op in ops
            )

    def test_iosxr_multicast_nullout_stays_derived_and_positioned(self):
        pc = IOSXRParser("no router pim\n").parse()
        assert "singleton:multicast" in pc.no_commands
        assert _native(pc) == []
        ops = derive_ops(pc)
        null = [op for op in ops if op.path == ("singleton", "multicast")]
        assert len(null) == 1 and null[0].origin == "derived"


# ---------------------------------------------------------------------------
# Codec anti-rot: registry completeness + rulings (all twelve sections)
# ---------------------------------------------------------------------------


class TestCodec:
    @pytest.mark.parametrize("section", sorted(SECTIONS_ALL))
    def test_registry_partitions_model_fields_completely(self, section):
        """Every model field of every migrated section (8a + 8b) is
        provenance, a structural scalar, or a registered member kind — so the
        engine's generic creation seed can never silently drop content (CCR
        Appendix U.1 extends the T.3 pin).  A future model field added
        without a registry entry breaks HERE, loudly."""
        from confgraph.change_ir import _PROVENANCE_FIELDS
        from confgraph.models.aaa import AAAConfig
        from confgraph.models.bfd import BFDConfig
        from confgraph.models.dhcp import DHCPConfig
        from confgraph.models.dns import DNSConfig
        from confgraph.models.logging_config import SyslogConfig
        from confgraph.models.mpls import MPLSConfig
        from confgraph.models.multicast import MulticastConfig
        from confgraph.models.netflow import NetFlowConfig
        from confgraph.models.ntp import NTPConfig
        from confgraph.models.snmp import SNMPConfig
        from confgraph.models.vpc import VPCConfig
        from confgraph.models.vxlan import VXLANConfig

        model = {
            "ntp": NTPConfig,
            "snmp": SNMPConfig,
            "syslog": SyslogConfig,
            "dns": DNSConfig,
            "aaa": AAAConfig,
            "dhcp": DHCPConfig,
            "netflow": NetFlowConfig,
            "multicast": MulticastConfig,
            "bfd": BFDConfig,
            "mpls": MPLSConfig,
            "vxlan": VXLANConfig,
            "vpc": VPCConfig,
        }[section]
        scalars = singleton_scalar_fields(section)
        members = singleton_member_kinds(section)
        assert not (scalars & members)
        for name in model.model_fields:
            assert (
                name in _PROVENANCE_FIELDS or name in scalars or name in members
            ), f"{section}.{name} is not covered by the family-8a/8b registry"

    def test_required_fields_are_structural_scalars_only_vpc(self):
        # today exactly vpc.domain_id (U.1); 8a sections carry none, so the
        # generalized predicate is behavior-neutral for them.
        from pydantic_core import PydanticUndefined

        assert "domain_id" in singleton_scalar_fields("vpc")
        from confgraph.models.aaa import AAAConfig
        from confgraph.models.dns import DNSConfig
        from confgraph.models.logging_config import SyslogConfig
        from confgraph.models.ntp import NTPConfig
        from confgraph.models.snmp import SNMPConfig

        for model in (NTPConfig, SNMPConfig, SyslogConfig, DNSConfig, AAAConfig):
            assert not any(
                i.default is PydanticUndefined and i.default_factory is None
                for n, i in model.model_fields.items()
                if n not in ("object_id", "raw_lines", "source_os", "line_numbers", "no_commands", "name")
            )

    def test_member_keys_are_string_tuples(self):
        for pc in (
            _parse(KITCHEN_SINK),
            NXOSParser(NXOS_SINK).parse(),
            EOSParser(EOS_SINK).parse(),
        ):
            for op in _native(pc):
                assert all(isinstance(seg, str) for seg in op.path), op.path

    def test_origin_gate(self):
        from confgraph.change_ir import ChangeOp

        derived_twin = ChangeOp(
            verb=Verb.LIST_REMOVE,
            path=("field", "dhcp", "pool", "OLD"),
            value=None,
            source_line="field:dhcp:pool:OLD",
            line_no=-1,
        )
        assert not is_native_singleton_section_op(derived_twin)
        native = ChangeOp(
            verb=Verb.LIST_REMOVE,
            path=("field", "dhcp", "pool", "OLD"),
            value=None,
            source_line="no ip dhcp pool OLD",
            line_no=3,
            origin="native",
        )
        assert is_native_singleton_section_op(native)
