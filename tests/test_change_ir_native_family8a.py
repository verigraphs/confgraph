"""Phase 3 family 8a — comms/service singleton decomposition (CCR Appendix T).

Parser-side pins: native op emission (whole-section create + scalar + member
SETs), byte-exact tombstone twins (string AND order), inline retirement of the
derived whole-singleton SETs, the line-detected tri-state booleans
(``syslog.enabled`` / ``dns.lookup_enabled``), the IOS-XR gate, and the
anti-rot completeness / never-derived pins.
"""

import pytest

from confgraph.change_ir import (
    Verb,
    derive_ops,
    encode_legacy,
    is_native_singleton_instance_create_op,
    is_native_singleton_section_op,
    singleton_member_kinds,
    singleton_scalar_fields,
    singleton_section_fields,
)
from confgraph.parsers.eos_parser import EOSParser
from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.iosxr_parser import IOSXRParser
from confgraph.parsers.nxos_parser import NXOSParser

SECTIONS = ("aaa", "dns", "ntp", "snmp", "syslog")


def _parse(text: str):
    return IOSParser(text).parse()


def _native(pc):
    return [op for op in pc.native_change_ops if is_native_singleton_section_op(op)]


KITCHEN_SINK = """\
hostname r1
aaa new-model
aaa authentication login default local tacacs+
aaa authorization exec default local
aaa accounting exec default start-stop group tacacs+
tacacs server T1
 address ipv4 10.0.0.1
 key S1
tacacs-server host 10.0.0.2 key S2
radius server R1
 address ipv4 10.0.0.3 auth-port 1812 acct-port 1813
 key S3
radius-server host 10.0.0.4 key S4
ntp server 10.0.0.10 prefer
ntp peer 10.0.0.11
ntp authenticate
ntp authentication-key 1 md5 SECRET
ntp trusted-key 1
ntp source Loopback0
snmp-server community public ro
snmp-server host 10.1.1.1 version 2c public
snmp-server location DC1
snmp-server view V iso included
snmp-server group G v3 priv
snmp-server user U G v3 auth sha PW
snmp-server enable traps bgp
logging host 10.2.2.2
logging trap informational
ip domain name corp.example
ip domain list corp2.example
ip name-server 8.8.8.8 8.8.4.4
no ntp server 10.9.9.1
no ntp peer 10.9.9.2
no ntp authentication-key 9
no snmp-server community old
no snmp-server host 10.9.9.3
no snmp-server view VOLD
no snmp-server group GOLD
no snmp-server user UOLD
no logging host 10.9.9.4
no ip name-server 10.9.9.5
no ip domain list old.example
no aaa authentication login OLD
no aaa authorization exec OLD
no aaa accounting exec OLD
no tacacs server TOLD
no tacacs-server host 10.9.9.6
no radius server ROLD
no radius-server host 10.9.9.7
"""

# The exact legacy tombstones, IN WALK ORDER (byte-identity pin — this list is
# what HEAD emitted before family 8a; the strings AND sequence must survive).
KITCHEN_SINK_TOMBSTONES = [
    "field:syslog:host:10.9.9.4",
    "field:dns:name_server:10.9.9.5",
    "field:dns:domain:old.example",
    "field:ntp:server:10.9.9.1",
    "field:ntp:peer:10.9.9.2",
    "field:ntp:auth_key:9",
    "field:snmp:community:old",
    "field:snmp:host:10.9.9.3",
    "field:snmp:view:VOLD",
    "field:snmp:group:GOLD",
    "field:snmp:user:UOLD",
    "field:aaa:authentication:login:OLD",
    "field:aaa:authorization:exec:OLD",
    "field:aaa:accounting:exec:OLD",
    "field:aaa:tacacs_named:TOLD",
    "field:aaa:tacacs:10.9.9.6",
    "field:aaa:radius_named:ROLD",
    "field:aaa:radius:10.9.9.7",
]


# ---------------------------------------------------------------------------
# Byte-identity of legacy artifacts (string AND order)
# ---------------------------------------------------------------------------


class TestTombstoneTwins:
    def test_kitchen_sink_tombstones_byte_identical_in_order(self):
        pc = _parse(KITCHEN_SINK)
        assert pc.no_commands == KITCHEN_SINK_TOMBSTONES

    def test_singleton_nullouts_byte_identical(self):
        pc = _parse("no snmp-server\nno aaa new-model\nsnmp-server community c ro\n")
        assert pc.no_commands == ["singleton:aaa", "singleton:snmp"]

    def test_lookup_disable_twin_byte_identical(self):
        pc = _parse("no ip domain-lookup\n")
        assert pc.no_commands == ["field:dns:lookup_disable"]

    def test_every_twin_regenerated_from_a_native_op(self):
        pc = _parse(KITCHEN_SINK)
        native_paths = {":".join(op.path) for op in _native(pc)}
        for t in pc.no_commands:
            assert t in native_paths

    def test_roundtrip_multiset(self):
        pc = _parse(KITCHEN_SINK + "no snmp-server\nno aaa new-model\n")
        art = encode_legacy(derive_ops(pc))
        assert sorted(art.no_commands) == sorted(pc.no_commands)


# ---------------------------------------------------------------------------
# Native op inventory + verbs
# ---------------------------------------------------------------------------


class TestEmission:
    def test_create_op_per_parsed_section(self):
        pc = _parse(KITCHEN_SINK)
        creates = [
            op.path for op in _native(pc) if is_native_singleton_instance_create_op(op)
        ]
        assert sorted(creates) == [(s, "instance") for s in SECTIONS]

    def test_scalar_ops_state_derived_non_default_only(self):
        pc = _parse(KITCHEN_SINK)
        scalar_paths = {
            op.path for op in _native(pc) if len(op.path) == 3 and op.path[1] == "scalar"
        }
        assert ("ntp", "scalar", "authenticate") in scalar_paths
        assert ("ntp", "scalar", "source_interface") in scalar_paths
        assert ("snmp", "scalar", "location") in scalar_paths
        assert ("syslog", "scalar", "trap_level") in scalar_paths
        assert ("dns", "scalar", "domain_name") in scalar_paths
        assert ("aaa", "scalar", "new_model") in scalar_paths
        assert ("aaa", "scalar", "local_auth_enabled") in scalar_paths
        # default-valued scalars are NOT emitted (state-derived rule)
        assert ("ntp", "scalar", "master") not in scalar_paths
        assert ("snmp", "scalar", "if_index_persist") not in scalar_paths
        # the two line-detected booleans never ride the state walk
        assert ("syslog", "scalar", "enabled") not in scalar_paths  # no line present
        assert ("dns", "scalar", "lookup_enabled") not in scalar_paths

    def test_member_ops_cover_every_list_member(self):
        pc = _parse(KITCHEN_SINK)
        paths = {op.path for op in _native(pc)}
        for expected in [
            ("ntp", "servers", "10.0.0.10"),
            ("ntp", "peers", "10.0.0.11"),
            ("ntp", "authentication_keys", "1"),
            ("ntp", "trusted_keys", "1"),
            ("snmp", "communities", "public"),
            ("snmp", "hosts", "10.1.1.1", "2c"),
            ("snmp", "views", "V"),
            ("snmp", "groups", "G", "v3"),
            ("snmp", "users", "U", "G"),
            ("snmp", "enable_traps", "bgp"),
            ("syslog", "hosts", "10.2.2.2"),
            ("dns", "domain_list", "corp2.example"),
            ("dns", "name_servers", "8.8.8.8"),
            ("dns", "name_servers", "8.8.4.4"),
            ("aaa", "authentication_lists", "login", "default"),
            ("aaa", "authorization_lists", "exec", "default"),
            ("aaa", "accounting_lists", "exec", "default"),
            ("aaa", "tacacs_servers", "10.0.0.1"),
            ("aaa", "tacacs_servers", "10.0.0.2"),
            ("aaa", "radius_servers", "10.0.0.3"),
            ("aaa", "radius_servers", "10.0.0.4"),
        ]:
            assert expected in paths, expected

    def test_removal_verbs_match_the_codec_registry(self):
        pc = _parse(KITCHEN_SINK + "no snmp-server\nno ip domain-lookup\n")
        by_path = {op.path: op for op in _native(pc)}
        assert by_path[("field", "ntp", "server", "10.9.9.1")].verb is Verb.LIST_REMOVE
        assert (
            by_path[("field", "aaa", "authentication", "login", "OLD")].verb
            is Verb.LIST_REMOVE
        )
        assert by_path[("singleton", "snmp")].verb is Verb.UNSET
        assert by_path[("field", "dns", "lookup_disable")].verb is Verb.UNSET

    def test_removal_ops_carry_true_lines(self):
        pc = _parse("ntp server 10.0.0.1\nno ntp server 10.9.9.1\n")
        op = next(
            o for o in _native(pc) if o.path == ("field", "ntp", "server", "10.9.9.1")
        )
        assert op.line_no >= 0
        assert op.source_line == "no ntp server 10.9.9.1"

    def test_ipv6_member_value_stays_one_segment_and_twin_rejoins(self):
        pc = _parse("ntp server 2001:db8::1\nno ntp server 2001:db8::2\n")
        paths = {op.path for op in _native(pc)}
        assert ("ntp", "servers", "2001:db8::1") in paths  # SET key = ONE segment
        # the removal path is the colon-split; encode_legacy rejoins byte-exact
        assert pc.no_commands == ["field:ntp:server:2001:db8::2"]
        art = encode_legacy(derive_ops(pc))
        assert art.no_commands == ["field:ntp:server:2001:db8::2"]


# ---------------------------------------------------------------------------
# Line-detected tri-state booleans (Appendix T.2)
# ---------------------------------------------------------------------------


class TestTriState:
    def _enabled_op(self, pc, sect, field):
        ops = [
            op
            for op in _native(pc)
            if op.path == (sect, "scalar", field)
        ]
        assert len(ops) <= 1
        return ops[0] if ops else None

    def test_syslog_pure_disable_emits_false(self):
        pc = _parse("logging host 10.2.2.2\nno logging on\n")
        op = self._enabled_op(pc, "syslog", "enabled")
        assert op is not None and op.value is False
        assert pc.syslog.enabled is False  # parsed state untouched

    def test_syslog_refresh_emits_true_at_later_line(self):
        pc = _parse("logging host 10.2.2.2\nno logging on\nlogging on\n")
        op = self._enabled_op(pc, "syslog", "enabled")
        assert op is not None and op.value is True
        assert pc.syslog.enabled is False  # legacy state stays False (byte-identity)

    def test_syslog_disable_after_enable_emits_false(self):
        pc = _parse("logging on\nno logging on\nlogging host 10.2.2.2\n")
        op = self._enabled_op(pc, "syslog", "enabled")
        assert op is not None and op.value is False

    def test_syslog_no_line_emits_nothing(self):
        pc = _parse("logging host 10.2.2.2\n")
        assert self._enabled_op(pc, "syslog", "enabled") is None

    def test_dns_positive_lookup_line_emits_true(self):
        pc = _parse("ip domain lookup\nip name-server 8.8.8.8\n")
        op = self._enabled_op(pc, "dns", "lookup_enabled")
        assert op is not None and op.value is True

    def test_dns_refresh_positive_after_negation(self):
        pc = _parse("no ip domain-lookup\nip domain-lookup\n")
        pos = self._enabled_op(pc, "dns", "lookup_enabled")
        neg = next(
            op for op in _native(pc) if op.path == ("field", "dns", "lookup_disable")
        )
        assert pos is not None and pos.value is True
        assert pos.line_no > neg.line_no  # the replay's skip basis
        assert pc.dns.lookup_enabled is False  # parsed state untouched
        assert pc.no_commands == ["field:dns:lookup_disable"]  # twin intact

    def test_dns_no_positive_line_emits_nothing(self):
        pc = _parse("ip name-server 8.8.8.8\n")
        assert self._enabled_op(pc, "dns", "lookup_enabled") is None


# ---------------------------------------------------------------------------
# Retirement + composition
# ---------------------------------------------------------------------------


class TestRetirement:
    def test_derived_whole_singleton_sets_retired(self):
        pc = _parse(KITCHEN_SINK)
        ops = derive_ops(pc)
        for sect in SECTIONS:
            assert not any(op.path == (sect,) for op in ops), sect
            assert (
                sum(1 for op in ops if op.path == (sect, "instance")) == 1
            ), sect

    def test_unmigrated_singletons_still_derived(self):
        pc = _parse("vtp domain CORP\nntp server 10.0.0.1\n")
        ops = derive_ops(pc)
        assert any(op.path == ("vtp",) and op.origin == "derived" for op in ops)

    def test_anti_rot_family8a_never_derived(self):
        pc = _parse(KITCHEN_SINK + "no snmp-server\nno ip domain-lookup\n")
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
        pc = _parse("no ntp server 10.9.9.1\nntp server 10.0.0.1\n")
        ops = derive_ops(pc)
        matches = [op for op in ops if op.path == ("field", "ntp", "server", "10.9.9.1")]
        assert len(matches) == 1 and matches[0].origin == "native"

    def test_create_op_encodes_to_set_fields(self):
        pc = _parse("ntp server 10.0.0.1\n")
        art = encode_legacy(derive_ops(pc))
        assert ("ntp", "instance") in art.set_fields
        assert art.no_commands == []


# ---------------------------------------------------------------------------
# Per-OS gates
# ---------------------------------------------------------------------------


class TestPerOS:
    def test_nxos_inherits_walks_and_state_walk(self):
        pc = NXOSParser(
            "ntp server 10.0.0.1 use-vrf management\n"
            "snmp-server community public group network-operator\n"
            "no ntp server 10.9.9.1\n"
            "no snmp-server community old\n"
        ).parse()
        native = _native(pc)
        assert any(op.path == ("ntp", "instance") for op in native)
        assert any(op.path == ("snmp", "communities", "public") for op in native)
        assert any(
            op.path == ("field", "snmp", "community", "old") for op in native
        )
        assert "field:snmp:community:old" in pc.no_commands
        ops = derive_ops(pc)
        assert not any(op.path == ("ntp",) for op in ops)

    def test_eos_inherits_walks_and_state_walk(self):
        pc = EOSParser(
            "ntp server 10.0.0.1\nno ntp server 10.9.9.1\n"
        ).parse()
        native = _native(pc)
        assert any(op.path == ("ntp", "instance") for op in native)
        assert any(op.path == ("field", "ntp", "server", "10.9.9.1") for op in native)

    def test_iosxr_gated_no_natives_derived_set_survives(self):
        pc = IOSXRParser(
            "ntp\n server 10.0.0.1\n"
            "domain name corp.example\n"
            "domain name-server 8.8.8.8\n"
        ).parse()
        assert _native(pc) == []
        ops = derive_ops(pc)
        if pc.ntp is not None:
            assert any(
                op.path == ("ntp",) and op.origin == "derived" for op in ops
            )

    def test_iosxr_singleton_nullouts_stay_derived_and_positioned(self):
        pc = IOSXRParser("no ntp\nno domain lookup\n").parse()
        assert "singleton:ntp" in pc.no_commands
        assert "singleton:dns" in pc.no_commands
        assert _native(pc) == []
        ops = derive_ops(pc)
        ntp_null = [op for op in ops if op.path == ("singleton", "ntp")]
        assert len(ntp_null) == 1 and ntp_null[0].origin == "derived"


# ---------------------------------------------------------------------------
# Codec anti-rot: registry completeness + origin gate
# ---------------------------------------------------------------------------


class TestCodec:
    @pytest.mark.parametrize("section", sorted(SECTIONS))
    def test_registry_partitions_model_fields_completely(self, section):
        """Every model field is provenance, a structural scalar, or a
        registered member kind — so the engine's generic creation seed can
        never silently drop content (CCR Appendix T.3).  A future model
        field added without a registry entry breaks HERE, loudly."""
        from confgraph.change_ir import _PROVENANCE_FIELDS
        from confgraph.models.aaa import AAAConfig
        from confgraph.models.dns import DNSConfig
        from confgraph.models.logging_config import SyslogConfig
        from confgraph.models.ntp import NTPConfig
        from confgraph.models.snmp import SNMPConfig

        model = {
            "ntp": NTPConfig,
            "snmp": SNMPConfig,
            "syslog": SyslogConfig,
            "dns": DNSConfig,
            "aaa": AAAConfig,
        }[section]
        scalars = singleton_scalar_fields(section)
        members = singleton_member_kinds(section)
        assert not (scalars & members)
        for name in model.model_fields:
            assert (
                name in _PROVENANCE_FIELDS or name in scalars or name in members
            ), f"{section}.{name} is not covered by the family-8a registry"

    def test_member_keys_are_string_tuples(self):
        pc = _parse(KITCHEN_SINK)
        for op in _native(pc):
            assert all(isinstance(seg, str) for seg in op.path), op.path

    def test_origin_gate(self):
        from confgraph.change_ir import ChangeOp

        derived_twin = ChangeOp(
            verb=Verb.LIST_REMOVE,
            path=("field", "ntp", "server", "10.0.0.1"),
            value=None,
            source_line="field:ntp:server:10.0.0.1",
            line_no=-1,
        )
        assert not is_native_singleton_section_op(derived_twin)
        native = ChangeOp(
            verb=Verb.LIST_REMOVE,
            path=("field", "ntp", "server", "10.0.0.1"),
            value=None,
            source_line="no ntp server 10.0.0.1",
            line_no=3,
            origin="native",
        )
        assert is_native_singleton_section_op(native)
