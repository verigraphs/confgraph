"""CCR-0110 Phase E step E6 — the colon-convention flip (NATIVE emission).

Native deletion op paths adopt the SET convention: a colon-valued VALUE tail is
ONE path segment.  This closes the codec's latent non-injectivity (a colon value
could bleed into extra structural segments).  The flip is invisible to consumers
(``encode_legacy`` is ``":".join(path)`` — byte-invariant) and to the engine
(its tuple dispatch re-canonicalizes); the derived channel stays split (F5).

These tests pin: the helper's per-shape collapse + byte-invariance, the
DELETION-scoped no-shared-joined-path property, the join-normalized dedupe that
keeps a collapsed native and its split derived twin from duplicating, and the
non-injectivity closure the flip exists for.
"""
import json
from pathlib import Path

import pytest

from confgraph.change_ir import (
    Verb,
    derive_ops,
    encode_legacy,
    _native_deletion_path,
)
from confgraph.parsers.eos_parser import EOSParser
from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.iosxr_parser import IOSXRParser
from confgraph.parsers.nxos_parser import NXOSParser

_DEL = {Verb.UNSET, Verb.LIST_REMOVE, Verb.OBJECT_DELETE}
_OSES = (IOSParser, NXOSParser, EOSParser, IOSXRParser)
_SAMPLE_DIR = Path(__file__).resolve().parent.parent / "samples"


# ---------------------------------------------------------------------------
# Helper: per-shape value-tail collapse + byte-invariance.
# ---------------------------------------------------------------------------

# (tombstone, expected collapsed path) — one per colon-capable native family,
# incl. the two multi-position shapes (netflow trailing port; bgp field trailing
# field name) and the top-level static channelized next-hop.
_COLLAPSE_CASES = [
    ("field:ntp:server:2001:db8::9",
     ("field", "ntp", "server", "2001:db8::9")),
    ("field:ntp:peer:2001:db8::a",
     ("field", "ntp", "peer", "2001:db8::a")),
    ("field:snmp:host:2001:db8::c",
     ("field", "snmp", "host", "2001:db8::c")),
    ("field:snmp:community:FOO:BAR",
     ("field", "snmp", "community", "FOO:BAR")),
    ("field:syslog:host:2001:db8::d",
     ("field", "syslog", "host", "2001:db8::d")),
    ("field:dns:name_server:2001:4860:4860::8888",
     ("field", "dns", "name_server", "2001:4860:4860::8888")),
    ("field:multicast:rp:2001:db8::5",
     ("field", "multicast", "rp", "2001:db8::5")),
    ("field:multicast:msdp:2001:db8::6",
     ("field", "multicast", "msdp", "2001:db8::6")),
    ("field:bfd:template:T:1",
     ("field", "bfd", "template", "T:1")),
    ("field:dhcp:pool:P:1",
     ("field", "dhcp", "pool", "P:1")),
    ("field:aaa:tacacs:S:1",
     ("field", "aaa", "tacacs", "S:1")),
    ("field:vrfs:BLUE:route_target_import:65000:100",
     ("field", "vrfs", "BLUE", "route_target_import", "65000:100")),
    ("field:vrfs:BLUE:route_target_export:65000:200",
     ("field", "vrfs", "BLUE", "route_target_export", "65000:200")),
    # multi-position: value span + trailing structural NUM port.
    ("field:netflow:destination:2001:db8::9:9995",
     ("field", "netflow", "destination", "2001:db8::9", "9995")),
    # top-level static channel: nh tail (dest is IPv4-only == colon-free).
    ("static::10.0.0.0/24:Serial0/0:0",
     ("static", "", "10.0.0.0/24", "Serial0/0:0")),
    # bgp channel (before the bgp_instance prefix): full removal + field reset.
    ("neighbor:2001:db8::1",
     ("neighbor", "2001:db8::1")),
    ("field:neighbor:2001:db8::1:route_map_in",
     ("field", "neighbor", "2001:db8::1", "route_map_in")),
]


@pytest.mark.parametrize("tombstone,expected", _COLLAPSE_CASES,
                         ids=[c[0] for c in _COLLAPSE_CASES])
def test_native_path_collapses_value_tail(tombstone, expected):
    assert _native_deletion_path(tombstone) == expected


@pytest.mark.parametrize("tombstone,_expected", _COLLAPSE_CASES,
                         ids=[c[0] for c in _COLLAPSE_CASES])
def test_native_path_byte_invariant(tombstone, _expected):
    # The whole point of the flip being consumption-invisible: ":".join of the
    # collapsed path reproduces the tombstone byte-for-byte.
    assert ":".join(map(str, _native_deletion_path(tombstone))) == tombstone


# Shapes with a colon-free value domain (or a two-value-span boundary that is
# unrecoverable from the joined string) are DELIBERATELY not in the registry:
# plain split == collapsed for them, so the helper must fall through unchanged.
_FALLTHROUGH = [
    "field:interface:Vlan10:helper:10.0.0.100",   # interface member (excluded)
    "field:aaa:authentication:login:default",     # two value spans (excluded)
    "field:class_maps:CM",                        # object-key name, no value tail
    "acl:DEAD",                                   # prefix-channel object delete
    "singleton:ntp",                             # whole-section null-out
    "process:bgp:65010",                         # derived survivor
    "field:vxlan:vni:100",                       # NUM value, colon-free
]


@pytest.mark.parametrize("tombstone", _FALLTHROUGH)
def test_native_path_fallthrough_plain_split(tombstone):
    assert _native_deletion_path(tombstone) == tuple(tombstone.split(":"))


# ---------------------------------------------------------------------------
# Non-injectivity closure — WHY the flip exists.
# ---------------------------------------------------------------------------

def test_structural_footprint_invariant_to_value_colons():
    # Pre-flip, a colon value inflated the segment count, so a value could bleed
    # into extra structural segments (the latent collision).  Post-flip the
    # structural footprint is FIXED regardless of how many colons the value has.
    for val in ("9.9.9.9", "2001:db8::9", "2001:4860:4860::8888", "a:b:c:d:e"):
        assert _native_deletion_path(f"field:ntp:server:{val}") == (
            "field", "ntp", "server", val,
        )
    # Even with a trailing structural token the value stays atomic and the
    # trailing token is unambiguously recovered.
    for host in ("10.0.0.1", "2001:db8::9"):
        assert _native_deletion_path(
            f"field:netflow:destination:{host}:9995"
        ) == ("field", "netflow", "destination", host, "9995")


def test_colon_value_cannot_collide_with_structural_layout():
    # The shape that WAS ambiguous pre-flip: an RT value 65000:100 split into two
    # segments, so the tuple footprint of a value-carrying shape could coincide
    # with a (hypothetical) one-segment-longer structural shape.  Post-flip the
    # value is a single atomic segment, so the two are unambiguously distinct.
    flipped = _native_deletion_path(
        "field:vrfs:BLUE:route_target_import:65000:100"
    )
    naive = tuple("field:vrfs:BLUE:route_target_import:65000:100".split(":"))
    assert len(flipped) == 5 and flipped[-1] == "65000:100"
    assert len(naive) == 6              # the pre-flip, collision-prone footprint
    assert flipped != naive


# ---------------------------------------------------------------------------
# Dedupe hardening — join-normalized comparison.
# ---------------------------------------------------------------------------

def test_join_normalized_dedupe_retires_split_derived_twin():
    # After the flip a NATIVE op collapses its colon tail while a DERIVED twin
    # (kept split) does not.  A mixed-convention pair with the same JOINED path
    # is the same intent; the composition must keep exactly one (the native).
    pc = IOSParser(
        "vrf definition GUEST\n"
        " address-family ipv4\n"
        "  no route-target export 65400:20\n"
    ).parse()
    native_rt = next(
        op for op in (getattr(pc, "native_change_ops", None) or [])
        if op.verb is Verb.LIST_REMOVE
        and op.path[:4] == ("field", "vrfs", "GUEST", "route_target_export")
    )
    assert native_rt.path[-1] == "65400:20"           # collapsed
    # Inject the SPLIT derived twin (what a degraded/derived channel would emit).
    pc.no_commands.append("field:vrfs:GUEST:route_target_export:65400:20")
    ops = derive_ops(pc)
    matching = [
        op for op in ops
        if ":".join(map(str, op.path))
        == "field:vrfs:GUEST:route_target_export:65400:20"
    ]
    assert len(matching) == 1
    assert matching[0] is native_rt                   # the derived twin dropped


def test_no_two_deletion_ops_share_a_joined_path():
    # Permanent property: within any composed ChangeSet, no two DELETION ops
    # share a joined path (the invariant the join-normalized dedupe guarantees).
    # Scoped to deletions: SET/UNRECOGNIZED ops legitimately repeat paths.
    srcs = [p.read_text(encoding="utf-8", errors="replace")
            for p in sorted(_SAMPLE_DIR.glob("*.txt"))]
    for cls in _OSES:
        for text in srcs:
            seen: dict[str, int] = {}
            for op in derive_ops(cls(text).parse()):
                if op.verb not in _DEL:
                    continue
                j = ":".join(map(str, op.path))
                seen[j] = seen.get(j, 0) + 1
            dups = {k: v for k, v in seen.items() if v > 1}
            assert not dups, f"{cls.__name__}: duplicate deletion joined paths {dups}"


# ---------------------------------------------------------------------------
# End-to-end: real parses emit collapsed native paths, byte-identical legacy.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("cls", _OSES, ids=[c.__name__ for c in _OSES])
def test_bgp_neighbor_removal_collapsed_all_oses(cls):
    pc = cls("router bgp 65000\n no neighbor 2001:db8::1\n").parse()
    dels = [op for op in derive_ops(pc)
            if op.verb in _DEL and op.path[:1] == ("bgp_instance",)]
    assert dels, f"{cls.__name__}: no native bgp neighbor deletion"
    op = dels[0]
    assert op.path == ("bgp_instance", "65000", "", "neighbor", "2001:db8::1")
    # legacy string byte-identical to the pre-flip split emission.
    assert ":".join(map(str, op.path)) == "bgp_instance:65000::neighbor:2001:db8::1"
