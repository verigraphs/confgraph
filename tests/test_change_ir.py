"""Change-IR Phase 0 — derive_ops / encode_legacy round-trip tests.

CCR: change_ir_proposal_operations.md (Phase 0 — shadow mode, zero behavior
change).  Three layers:

1. Per-tombstone-family unit tests: the parser emits the legacy artifact, the
   deriver maps it to the documented verb/path, and ``encode_legacy`` restores
   the artifact byte-exactly (including container placement: top-level vs
   per-interface vs per-BGP-instance).
2. SET-derivation tests: non-default fields become SET ops with normalized
   interface paths / keyed collection paths.
3. Corpus smoke: derive+round-trip over representative proposal and baseline
   configs across IOS / NX-OS / EOS / IOS-XR / JunOS — crash-free and
   round-trip-exact on every one.

Run:
    uv run pytest tests/test_change_ir.py -v
"""

from __future__ import annotations

import pytest

from confgraph.change_ir import (
    ChangeOp,
    Verb,
    derive_ops,
    encode_legacy,
)
from confgraph.parsers.eos_parser import EOSParser
from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.iosxr_parser import IOSXRParser
from confgraph.parsers.junos_parser import JunOSParser
from confgraph.parsers.nxos_parser import NXOSParser


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_FAMILY3_TOMBSTONE_PREFIXES = (
    "field:ip_sla_operations:",
    "field:object_tracks:",
    "field:eem_applets:",
    "field:banners:",
)


def _is_reordered_native_tombstone(t: str) -> bool:
    """Tombstones whose emitting family is native since Phase 3 and therefore
    hoisted to the front of the composed ChangeSet (multiset, not sequence).

    Family 3 (service entities) + family 4 (``static:`` route removals,
    CCR Appendix G) + family 6a (``process:isis:`` whole-process removal,
    CCR Appendix M) — each encodes byte-exactly but no longer at its legacy
    walk-group position in ``no_commands``.  (Only ``process:isis:`` is native;
    ``process:ospf/bgp/eigrp:`` stay derived until families 6b/6c.)
    """
    return (
        t.startswith(_FAMILY3_TOMBSTONE_PREFIXES)
        or t.startswith("static:")
        or t.startswith("process:isis:")
    )


def _roundtrip(cfg):
    """derive → encode and assert every legacy tombstone artifact is
    reproduced byte-exactly, in order, in the right container.

    Native-family exception (CCR Appendices F/G): service-entity (family 3)
    and static-route (family 4) deletion ops are NATIVE and sit in the
    composed ChangeSet at their true script positions, ahead of the derived
    remainder — so their tombstones encode byte-exactly but not at their
    legacy walk-group position in ``no_commands``.  Order among them and
    other families is semantically inert (each dispatches to an independent
    handler over disjoint fields), so the contract here is: byte-exact
    multiset for those subsequences, byte-exact SEQUENCE for everything else.
    """
    ops = derive_ops(cfg)
    art = encode_legacy(ops)

    assert [t for t in art.no_commands if not _is_reordered_native_tombstone(t)] == [
        t for t in cfg.no_commands if not _is_reordered_native_tombstone(t)
    ]
    assert sorted(
        t for t in art.no_commands if _is_reordered_native_tombstone(t)
    ) == sorted(
        t for t in cfg.no_commands if _is_reordered_native_tombstone(t)
    )
    assert art.interface_no_commands == {
        i.name: list(i.no_commands) for i in cfg.interfaces if i.no_commands
    }
    assert art.bgp_no_commands == {
        (str(b.asn), b.vrf or ""): list(b.no_commands)
        for b in cfg.bgp_instances
        if b.no_commands
    }
    assert art.unrecognized_blocks == list(cfg.unrecognized_blocks)
    return ops, art


def _parse_ios(text: str):
    return IOSParser(text).parse()


def _ops_with_verb(ops, verb):
    return [op for op in ops if op.verb is verb]


def _op_for_tombstone(ops, tombstone: str) -> ChangeOp:
    """Find the op for a given tombstone.

    Phase-0 derived ops carry the tombstone in ``source_line``; Phase-3
    NATIVE ops carry the real command line instead, so match on the codec
    path too (``":".join(path)`` IS the tombstone, byte-exact).  Family-5a
    BGP-neighbor ops carry the ``("bgp_instance", asn, vrf)`` scope prefix, so
    the tombstone is the rejoin of ``path[3:]`` (what ``encode_legacy`` uses).
    """
    matches = [
        op for op in ops
        if op.source_line == tombstone
        or ":".join(op.path) == tombstone
        or (
            op.path
            and op.path[0] == "bgp_instance"
            and ":".join(op.path[3:]) == tombstone
        )
    ]
    assert matches, f"No op derived for tombstone {tombstone!r}"
    return matches[0]


# ---------------------------------------------------------------------------
# IR type basics
# ---------------------------------------------------------------------------


class TestIRTypes:
    def test_change_op_is_frozen(self):
        op = ChangeOp(verb=Verb.SET, path=("interface", "GigabitEthernet0/1", "mtu"), value=9000)
        with pytest.raises(Exception):
            op.verb = Verb.UNSET  # type: ignore[misc]

    def test_verb_vocabulary(self):
        assert {v.name for v in Verb} == {
            "SET",
            "UNSET",
            "LIST_ADD",
            "LIST_REMOVE",
            "OBJECT_DELETE",
            "BLOCK_REPLACE",
            "UNRECOGNIZED",
        }

    def test_parsed_config_change_ops_defaults_none(self):
        cfg = _parse_ios("interface GigabitEthernet0/1\n mtu 9000\n")
        assert cfg.change_ops is None

    def test_change_ops_excluded_from_model_dump(self):
        """Zero-serialization-change guarantee: the Phase-0 shadow slot never
        appears in model_dump(), even when populated."""
        cfg = _parse_ios("interface GigabitEthernet0/1\n mtu 9000\n")
        assert "change_ops" not in cfg.model_dump()
        cfg.change_ops = derive_ops(cfg)
        assert cfg.change_ops
        assert "change_ops" not in cfg.model_dump()

    def test_change_ops_invisible_to_model_fields(self):
        """Zero-ripple guarantee: downstream registries that enumerate
        ParsedConfig.model_fields (e.g. the engine's field→area completeness
        checker) must not see the Phase-0 shadow slot."""
        from confgraph.models.parsed_config import ParsedConfig

        assert "change_ops" not in ParsedConfig.model_fields

    def test_change_ops_survives_deepcopy(self):
        import copy

        cfg = _parse_ios("interface GigabitEthernet0/1\n mtu 9000\n")
        cfg.change_ops = derive_ops(cfg)
        assert copy.deepcopy(cfg).change_ops == cfg.change_ops

    def test_empty_config_derives_empty_changeset(self):
        cfg = _parse_ios("!\n")
        assert derive_ops(cfg) == []


# ---------------------------------------------------------------------------
# Tombstone families — top-level ParsedConfig.no_commands
# ---------------------------------------------------------------------------


class TestTopLevelTombstoneFamilies:
    def test_interface_delete(self):
        cfg = _parse_ios("no interface Loopback0\n")
        assert "interface:Loopback0" in cfg.no_commands
        ops, _ = _roundtrip(cfg)
        op = _op_for_tombstone(ops, "interface:Loopback0")
        assert op.verb is Verb.OBJECT_DELETE
        assert op.path == ("interface", "Loopback0")
        assert op.line_no == -1

    def test_static_route_removal_with_next_hop(self):
        cfg = _parse_ios("no ip route 10.0.0.0 255.0.0.0 10.1.1.1\n")
        assert any(t.startswith("static:") for t in cfg.no_commands)
        ops, _ = _roundtrip(cfg)
        op = _ops_with_verb(ops, Verb.LIST_REMOVE)[0]
        assert op.path[0] == "static"

    def test_static_route_removal_vrf(self):
        cfg = _parse_ios("no ip route vrf CUST 192.168.0.0 255.255.0.0\n")
        assert any(t.startswith("static:CUST:") for t in cfg.no_commands)
        _roundtrip(cfg)

    def test_vlan_delete_including_ranges(self):
        cfg = _parse_ios("no vlan 100\nno vlan 200-202\n")
        assert "vlan:100" in cfg.no_commands
        assert "vlan:201" in cfg.no_commands
        ops, _ = _roundtrip(cfg)
        vlan_ops = [op for op in ops if op.path[0] == "vlan"]
        assert len(vlan_ops) == 4
        assert all(op.verb is Verb.OBJECT_DELETE for op in vlan_ops)

    def test_process_deletions(self):
        cfg = _parse_ios(
            "no router ospf 1\nno router bgp 65000\nno router isis CORE\nno router eigrp 10\n"
        )
        assert {
            "process:ospf:1",
            "process:bgp:65000",
            "process:isis:CORE",
            "process:eigrp:10",
        } <= set(cfg.no_commands)
        ops, _ = _roundtrip(cfg)
        proc_ops = [op for op in ops if op.path[0] == "process"]
        assert len(proc_ops) == 4
        assert all(op.verb is Verb.OBJECT_DELETE for op in proc_ops)
        assert ("process", "ospf", "1") in [op.path for op in proc_ops]

    def test_acl_and_ace_deletion(self):
        cfg = _parse_ios(
            "no ip access-list extended OLD-ACL\n"
            "ip access-list extended EDIT-ACL\n"
            " no 20\n"
        )
        assert "acl:OLD-ACL" in cfg.no_commands
        assert "acl-seq:EDIT-ACL:20" in cfg.no_commands
        ops, _ = _roundtrip(cfg)
        assert _op_for_tombstone(ops, "acl:OLD-ACL").verb is Verb.OBJECT_DELETE
        ace = _op_for_tombstone(ops, "acl-seq:EDIT-ACL:20")
        assert ace.verb is Verb.LIST_REMOVE
        assert ace.path == ("acl-seq", "EDIT-ACL", "20")

    def test_route_map_and_prefix_list_seq_deletion(self):
        cfg = _parse_ios(
            "no route-map RM-EDGE permit 10\nno ip prefix-list PL-CORE seq 5\n"
        )
        assert "route-map:RM-EDGE:seq:10" in cfg.no_commands
        assert "prefix-list:PL-CORE:seq:5" in cfg.no_commands
        ops, _ = _roundtrip(cfg)
        assert _op_for_tombstone(ops, "route-map:RM-EDGE:seq:10").verb is Verb.LIST_REMOVE
        assert _op_for_tombstone(ops, "prefix-list:PL-CORE:seq:5").verb is Verb.LIST_REMOVE

    def test_singleton_removals(self):
        cfg = _parse_ios("no ip multicast-routing\nno aaa new-model\n")
        assert {"singleton:multicast", "singleton:aaa"} <= set(cfg.no_commands)
        ops, _ = _roundtrip(cfg)
        for ts in ("singleton:multicast", "singleton:aaa"):
            assert _op_for_tombstone(ops, ts).verb is Verb.UNSET

    def test_nested_field_deletions(self):
        """NESTED_DELETION_RULES families: BGP AF redistribute, interface
        helper / NHRP NHS, OSPF area type resets."""
        cfg = _parse_ios(
            "router bgp 65001\n"
            " address-family ipv4\n"
            "  no redistribute ospf 1\n"
            "interface Vlan10\n"
            " no ip helper-address 10.0.0.100\n"
            "interface Tunnel0\n"
            " no ip nhrp nhs 203.0.113.1\n"
            "router ospf 1\n"
            " no area 1 stub\n"
            " no area 2 nssa\n"
        )
        expected = {
            "field:bgp:65001:af:ipv4:redistribute:ospf:1": Verb.LIST_REMOVE,
            "field:interface:Vlan10:helper:10.0.0.100": Verb.LIST_REMOVE,
            "field:interface:Tunnel0:nhrp_nhs:203.0.113.1": Verb.LIST_REMOVE,
            "field:ospf:1:area:1:stub_reset": Verb.UNSET,
            "field:ospf:1:area:2:nssa_reset": Verb.UNSET,
        }
        assert set(expected) <= set(cfg.no_commands)
        ops, art = _roundtrip(cfg)
        for ts, verb in expected.items():
            assert _op_for_tombstone(ops, ts).verb is verb
        # helper/nhrp_nhs shapes are TOP-LEVEL (5 segments) — never routed to
        # the per-interface container.
        assert "field:interface:Vlan10:helper:10.0.0.100" in art.no_commands

    def test_service_singleton_entry_removals(self):
        cfg = _parse_ios(
            "no ntp server 10.0.0.1\n"
            "no ntp peer 10.0.0.2\n"
            "no ntp authentication-key 5\n"
            "no snmp-server community public\n"
            "no snmp-server host 10.9.9.9\n"
            "no aaa authentication login VTY\n"
            "no tacacs server TAC1\n"
            "no radius-server host 10.8.8.8\n"
            "no logging host 10.7.7.7\n"
            "no ip name-server 8.8.8.8\n"
            "no ip domain-list corp.example\n"
            "no ip flow-export destination 10.6.6.6 9996\n"
            "no ip dhcp pool LAN\n"
            "no ip dhcp excluded-address 10.1.1.1\n"
            "no lldp tlv-select port-description\n"
            "no ip pim rp-address 10.5.5.5\n"
            "no ip msdp peer 10.4.4.4\n"
            "no bfd-template single-hop FAST\n"
        )
        expected_list_removes = {
            "field:ntp:server:10.0.0.1",
            "field:ntp:peer:10.0.0.2",
            "field:ntp:auth_key:5",
            "field:snmp:community:public",
            "field:snmp:host:10.9.9.9",
            "field:aaa:authentication:login:VTY",
            "field:aaa:tacacs_named:TAC1",
            "field:aaa:radius:10.8.8.8",
            "field:syslog:host:10.7.7.7",
            "field:dns:name_server:8.8.8.8",
            "field:dns:domain:corp.example",
            "field:netflow:destination:10.6.6.6:9996",
            "field:dhcp:pool:LAN",
            "field:dhcp:excluded:10.1.1.1",
            "field:lldp:tlv:port-description",
            "field:multicast:rp:10.5.5.5",
            "field:multicast:msdp:10.4.4.4",
            "field:bfd:template:FAST",
        }
        assert expected_list_removes <= set(cfg.no_commands)
        ops, _ = _roundtrip(cfg)
        for ts in expected_list_removes:
            assert _op_for_tombstone(ops, ts).verb is Verb.LIST_REMOVE, ts

    def test_entity_removals_wi8(self):
        """WI-8 service entity removals: SLA / track / EEM → OBJECT_DELETE;
        banner → UNSET (scalar reset)."""
        cfg = _parse_ios(
            "no ip sla 10\n"
            "no track 7\n"
            "no event manager applet WATCHDOG\n"
            "no banner motd\n"
        )
        assert {
            "field:ip_sla_operations:10",
            "field:object_tracks:7",
            "field:eem_applets:WATCHDOG",
            "field:banners:motd",
        } <= set(cfg.no_commands)
        ops, _ = _roundtrip(cfg)
        assert _op_for_tombstone(ops, "field:ip_sla_operations:10").verb is Verb.OBJECT_DELETE
        assert _op_for_tombstone(ops, "field:object_tracks:7").verb is Verb.OBJECT_DELETE
        assert _op_for_tombstone(ops, "field:eem_applets:WATCHDOG").verb is Verb.OBJECT_DELETE
        assert _op_for_tombstone(ops, "field:banners:motd").verb is Verb.UNSET

    def test_vrf_family_wi7(self):
        """WI-7 VRF shapes: RT removals (colons in values survive the
        round-trip), rd reset, whole-VRF delete."""
        cfg = _parse_ios(
            "vrf definition GUEST\n"
            " no route-target import 65400:10\n"
            " no route-target export 65400:20\n"
            " no route-target both 65400:30\n"
            " no rd\n"
            "no vrf definition OLDVRF\n"
        )
        expected = {
            "field:vrfs:GUEST:route_target_import:65400:10": Verb.LIST_REMOVE,
            "field:vrfs:GUEST:route_target_export:65400:20": Verb.LIST_REMOVE,
            "field:vrfs:GUEST:route_target_both:65400:30": Verb.LIST_REMOVE,
            "field:vrfs:GUEST:rd": Verb.UNSET,
            "field:vrfs:OLDVRF": Verb.OBJECT_DELETE,
        }
        assert set(expected) <= set(cfg.no_commands)
        ops, _ = _roundtrip(cfg)
        for ts, verb in expected.items():
            assert _op_for_tombstone(ops, ts).verb is verb, ts

    def test_generic_scalar_reset_catch_all(self):
        """NX-OS vpc/vxlan scalar resets ride the generic 2-segment shape."""
        cfg = NXOSParser(
            "vpc domain 10\n"
            " no peer-keepalive destination 10.0.0.2\n"
            "interface nve1\n"
            " no member vni 10100\n"
        ).parse()
        assert "field:vpc:peer_keepalive_destination" in cfg.no_commands
        assert "field:vxlan:vni:10100" in cfg.no_commands
        ops, _ = _roundtrip(cfg)
        assert (
            _op_for_tombstone(ops, "field:vpc:peer_keepalive_destination").verb
            is Verb.UNSET
        )
        assert _op_for_tombstone(ops, "field:vxlan:vni:10100").verb is Verb.LIST_REMOVE

    def test_unknown_tombstone_falls_back_lossless(self):
        """Future/unknown families still derive (UNSET fallback) and encode
        byte-exactly."""
        cfg = _parse_ios("!\n")
        cfg.no_commands.append("future-family:some:new:shape")
        ops, art = _roundtrip(cfg)
        op = _op_for_tombstone(ops, "future-family:some:new:shape")
        assert op.verb is Verb.UNSET
        assert art.no_commands == ["future-family:some:new:shape"]


# ---------------------------------------------------------------------------
# Tombstone families — BGP-instance-scoped (BGPConfig.no_commands)
# ---------------------------------------------------------------------------


class TestBGPScopedTombstones:
    def test_neighbor_removal_and_field_reset(self):
        cfg = _parse_ios(
            "router bgp 65000\n"
            " no neighbor 10.0.0.1\n"
            " no neighbor 10.0.0.2 route-map FILTER in\n"
            " no neighbor 10.0.0.2 shutdown\n"
        )
        bgp = cfg.bgp_instances[0]
        assert "neighbor:10.0.0.1" in bgp.no_commands
        assert "field:neighbor:10.0.0.2:route_map_in" in bgp.no_commands
        assert "field:neighbor:10.0.0.2:shutdown" in bgp.no_commands

        ops, art = _roundtrip(cfg)
        full_removal = _op_for_tombstone(ops, "neighbor:10.0.0.1")
        assert full_removal.verb is Verb.OBJECT_DELETE
        assert full_removal.path == ("bgp_instance", "65000", "", "neighbor", "10.0.0.1")
        field_reset = _op_for_tombstone(ops, "field:neighbor:10.0.0.2:route_map_in")
        assert field_reset.verb is Verb.UNSET
        assert field_reset.path[:3] == ("bgp_instance", "65000", "")
        # Container placement round-trips to the scoped BGPConfig.
        assert art.bgp_no_commands[("65000", "")] == list(bgp.no_commands)

    def test_vrf_scoped_bgp_instance_container(self):
        cfg = _parse_ios(
            "router bgp 65000\n"
            " address-family ipv4 vrf CUST\n"
            "  no neighbor 172.16.0.1\n"
        )
        vrf_bgp = next(b for b in cfg.bgp_instances if b.vrf == "CUST")
        assert "neighbor:172.16.0.1" in vrf_bgp.no_commands
        ops, art = _roundtrip(cfg)
        op = _op_for_tombstone(ops, "neighbor:172.16.0.1")
        assert op.path[:3] == ("bgp_instance", "65000", "CUST")
        assert art.bgp_no_commands[("65000", "CUST")] == ["neighbor:172.16.0.1"]


# ---------------------------------------------------------------------------
# Tombstone families — interface-scoped (InterfaceConfig.no_commands)
# ---------------------------------------------------------------------------


class TestInterfaceScopedTombstones:
    def test_negation_tombstones_are_unset(self):
        """F1/WI-1 negations: no shutdown, no ip access-group, no service-policy,
        no description, no ip ospf cost, no mpls ip, bfd resets."""
        cfg = _parse_ios(
            "interface GigabitEthernet0/1\n"
            " no shutdown\n"
            " no description\n"
            " no ip access-group EDGE-IN in\n"
            " no service-policy input QOS-IN\n"
            " no ip nat inside\n"
            " no ip ospf cost\n"
            " no mpls ip\n"
            " no bfd interval\n"
            " no switchport port-security\n"
            " no ip ospf mtu-ignore\n"
        )
        iface = cfg.interfaces[0]
        expected = {
            "field:interface:GigabitEthernet0/1:enabled",
            "field:interface:GigabitEthernet0/1:description",
            "field:interface:GigabitEthernet0/1:acl_in",
            "field:interface:GigabitEthernet0/1:service_policy_input",
            "field:interface:GigabitEthernet0/1:nat_direction",
            "field:interface:GigabitEthernet0/1:ospf_cost",
            "field:interface:GigabitEthernet0/1:mpls_ip",
            "field:interface:GigabitEthernet0/1:port_security_enabled",
            "field:interface:GigabitEthernet0/1:ospf_mtu_ignore",
        }
        assert expected <= set(iface.no_commands)

        ops, art = _roundtrip(cfg)
        for ts in expected:
            op = _op_for_tombstone(ops, ts)
            assert op.verb is Verb.UNSET, ts
            assert op.path == tuple(ts.split(":"))
        # Container placement: per-interface, not top-level.
        assert art.interface_no_commands["GigabitEthernet0/1"] == list(iface.no_commands)
        for ts in expected:
            assert ts not in art.no_commands

    def test_trunk_vlan_delta_ops_f2(self):
        cfg = _parse_ios(
            "interface GigabitEthernet0/2\n"
            " switchport trunk allowed vlan add 30,40-42\n"
            " switchport trunk allowed vlan remove 20\n"
        )
        iface = cfg.interfaces[0]
        add_ts = "field:interface:GigabitEthernet0/2:trunk_allowed_vlans:add:30,40-42"
        rem_ts = "field:interface:GigabitEthernet0/2:trunk_allowed_vlans:remove:20"
        assert add_ts in iface.no_commands
        assert rem_ts in iface.no_commands

        ops, art = _roundtrip(cfg)
        add_op = _op_for_tombstone(ops, add_ts)
        assert add_op.verb is Verb.LIST_ADD
        assert add_op.value == "30,40-42"
        rem_op = _op_for_tombstone(ops, rem_ts)
        assert rem_op.verb is Verb.LIST_REMOVE
        assert rem_op.value == "20"
        # Order within the container is preserved (add before remove).
        encoded = art.interface_no_commands["GigabitEthernet0/2"]
        assert encoded.index(add_ts) < encoded.index(rem_ts)


# ---------------------------------------------------------------------------
# UNRECOGNIZED markers (WI-2 disclosure path)
# ---------------------------------------------------------------------------


class TestUnrecognizedMarkers:
    def test_unclaimed_block_produces_marker_op(self):
        cfg = _parse_ios("wombat protocol enable\n frobnicate level 9\n")
        assert cfg.unrecognized_blocks, "expected an unrecognized block"
        ops, art = _roundtrip(cfg)
        markers = _ops_with_verb(ops, Verb.UNRECOGNIZED)
        assert len(markers) == len(cfg.unrecognized_blocks)
        marker = markers[0]
        assert marker.path == ("unrecognized",)
        assert marker.source_line == cfg.unrecognized_blocks[0].block_header
        assert marker.value is cfg.unrecognized_blocks[0]
        assert art.unrecognized_blocks == list(cfg.unrecognized_blocks)


# ---------------------------------------------------------------------------
# SET derivation
# ---------------------------------------------------------------------------


class TestSetDerivation:
    def test_interface_fields_are_field_level_sets_with_normalized_path(self):
        cfg = _parse_ios("interface Gi0/1\n description uplink\n mtu 9000\n")
        ops = derive_ops(cfg)
        set_paths = {op.path: op.value for op in _ops_with_verb(ops, Verb.SET)}
        assert set_paths[("interface", "GigabitEthernet0/1", "description")] == "uplink"
        assert set_paths[("interface", "GigabitEthernet0/1", "mtu")] == 9000

    def test_default_valued_fields_do_not_emit_set(self):
        """Legacy blind spot preserved: explicit `no shutdown` restates the
        default (enabled=True) — no SET op, only the UNSET tombstone op."""
        cfg = _parse_ios("interface GigabitEthernet0/1\n no shutdown\n")
        ops = derive_ops(cfg)
        assert ("interface", "GigabitEthernet0/1", "enabled") not in [
            op.path for op in _ops_with_verb(ops, Verb.SET)
        ]
        assert (
            _op_for_tombstone(ops, "field:interface:GigabitEthernet0/1:enabled").verb
            is Verb.UNSET
        )

    def test_singleton_and_keyed_collection_sets(self):
        cfg = _parse_ios(
            "ntp server 10.0.0.1\n"
            "vlan 100\n"
            " name USERS\n"
            "ip route 10.0.0.0 255.0.0.0 10.1.1.1\n"
        )
        ops = derive_ops(cfg)
        set_paths = [op.path for op in _ops_with_verb(ops, Verb.SET)]
        assert ("ntp",) in set_paths
        assert ("vlans", "100") in set_paths
        assert any(p[0] == "static_routes" and p[1] == "" for p in set_paths)

    def test_set_provenance_uses_block_raw_lines(self):
        cfg = _parse_ios("router ospf 1\n network 10.0.0.0 0.255.255.255 area 0\n")
        ops = derive_ops(cfg)
        ospf_op = next(
            op for op in _ops_with_verb(ops, Verb.SET) if op.path[0] == "ospf_instances"
        )
        assert "router ospf 1" in ospf_op.source_line
        assert ospf_op.line_no >= 0

    def test_set_fields_survive_encode(self):
        cfg = _parse_ios("interface GigabitEthernet0/1\n mtu 9000\n")
        ops, art = _roundtrip(cfg)
        assert art.set_fields[("interface", "GigabitEthernet0/1", "mtu")] == 9000


# ---------------------------------------------------------------------------
# Corpus smoke — representative proposals/baselines, all OSes: crash-free +
# round-trip green on each (CCR Phase 0 CI gate).
# ---------------------------------------------------------------------------


_IOS_KITCHEN_SINK_PROPOSAL = """\
interface GigabitEthernet0/1
 description uplink to core
 ip address 10.1.1.1 255.255.255.0
 no shutdown
 no ip access-group EDGE-IN in
interface GigabitEthernet0/2
 switchport mode trunk
 switchport trunk allowed vlan add 30,40-42
 switchport trunk allowed vlan remove 20
no interface Loopback99
no ip route 10.99.0.0 255.255.0.0 10.1.1.254
ip route 10.50.0.0 255.255.0.0 10.1.1.253
no vlan 300
vlan 400
 name NEW-USERS
no router eigrp 10
router bgp 65000
 no neighbor 10.0.0.1
 no neighbor 10.0.0.2 route-map FILTER in
 neighbor 10.0.0.3 remote-as 65001
 address-family ipv4
  no redistribute ospf 1
router ospf 1
 network 10.0.0.0 0.255.255.255 area 0
 no area 1 stub
vrf definition GUEST
 no route-target import 65400:10
 no rd
no vrf definition OLDVRF
no ip access-list extended OLD-ACL
ip access-list extended EDIT-ACL
 permit ip any any
 no 20
no route-map RM-OLD permit 10
no ip prefix-list PL-OLD seq 5
no ip multicast-routing
no ntp server 10.0.0.1
no snmp-server community public
no aaa authentication login VTY
no logging host 10.7.7.7
no ip name-server 8.8.8.8
no ip flow-export destination 10.6.6.6 9996
no ip dhcp pool LAN
no lldp tlv-select port-description
no ip pim rp-address 10.5.5.5
no bfd-template single-hop FAST
no ip sla 10
no track 7
no event manager applet WATCHDOG
no banner motd
wombat protocol enable
 frobnicate level 9
"""

_NXOS_PROPOSAL = """\
interface Ethernet1/1
 description peer-link
 no shutdown
no vrf context TENANT-OLD
vpc domain 10
 no peer-keepalive destination 10.0.0.2
interface nve1
 no member vni 10100
no router ospf 1
"""

_EOS_PROPOSAL = """\
interface Ethernet1
 description spine-1
 no shutdown
interface Vxlan1
 no vxlan vlan 100 vni 10100
no router bgp 65000
"""

_IOSXR_PROPOSAL = """\
no router ospf 1
no router static
no ipv4 access-list OLD-ACL
no route-policy RP-OLD
no prefix-set PS-OLD
no vrf TENANT-A
no ntp
no domain name-server 8.8.8.8
no domain lookup
"""

_IOS_BASELINE = """\
hostname core-1
interface GigabitEthernet0/0
 description WAN
 ip address 192.0.2.1 255.255.255.252
router ospf 1
 router-id 1.1.1.1
 network 192.0.2.0 0.0.0.3 area 0
router bgp 65000
 neighbor 192.0.2.2 remote-as 65001
ip route 0.0.0.0 0.0.0.0 192.0.2.2
ntp server 10.0.0.1
snmp-server community secret ro
line vty 0 4
 transport input ssh
"""

_JUNOS_BASELINE = """\
system {
    host-name edge-1;
}
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 198.51.100.1/30;
            }
        }
    }
}
"""

_CORPUS = [
    ("ios-kitchen-sink-proposal", IOSParser, _IOS_KITCHEN_SINK_PROPOSAL),
    ("nxos-proposal", NXOSParser, _NXOS_PROPOSAL),
    ("eos-proposal", EOSParser, _EOS_PROPOSAL),
    ("iosxr-proposal", IOSXRParser, _IOSXR_PROPOSAL),
    ("ios-baseline", IOSParser, _IOS_BASELINE),
    ("junos-baseline", JunOSParser, _JUNOS_BASELINE),
]


class TestCorpusSmoke:
    @pytest.mark.parametrize(
        "label,parser_cls,text", _CORPUS, ids=[c[0] for c in _CORPUS]
    )
    def test_derive_and_roundtrip(self, label, parser_cls, text):
        cfg = parser_cls(text).parse()
        ops, _ = _roundtrip(cfg)  # crash-free + byte-exact round-trip
        # Every op is well-formed.
        for op in ops:
            assert isinstance(op, ChangeOp)
            assert isinstance(op.verb, Verb)
            assert op.path and all(isinstance(seg, str) for seg in op.path)

    def test_kitchen_sink_covers_every_verb_class(self):
        cfg = IOSParser(_IOS_KITCHEN_SINK_PROPOSAL).parse()
        ops = derive_ops(cfg)
        verbs = {op.verb for op in ops}
        assert {
            Verb.SET,
            Verb.UNSET,
            Verb.LIST_ADD,
            Verb.LIST_REMOVE,
            Verb.OBJECT_DELETE,
            Verb.UNRECOGNIZED,
        } <= verbs

    def test_baseline_derivation_has_no_deletions(self):
        cfg = IOSParser(_IOS_BASELINE).parse()
        ops = derive_ops(cfg)
        assert not [
            op
            for op in ops
            if op.verb in (Verb.UNSET, Verb.LIST_REMOVE, Verb.OBJECT_DELETE)
        ]
