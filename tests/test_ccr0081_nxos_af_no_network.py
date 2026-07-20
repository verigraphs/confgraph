"""CCR-0081 — NX-OS address-family-scoped ``no network <cidr>`` withdrawal.

The family-5b instance walk only saw router-bgp-level ``no network``; NX-OS
nests ``network`` statements under the ``address-family`` block, so the
AF-scoped ``no network <cidr>`` parsed as a silent no-op (no deletion op ⇒
``merge_config`` never withdrew the origination — a false-SAME on the whole
withdrawal class). This mirrors the AF ``no aggregate-address`` walk: an
ops-only LIST_REMOVE with NO legacy twin.

These are OSS ops-emission tests (the parser emits the correct ChangeOp with
the AF-scoped path + discipline). The end-to-end merge application lives in the
entrp replay engine, which already applies AF-scoped removals (the aggregate
withdrawal works today) and is exercised by its own suite.
"""
from __future__ import annotations

from confgraph.change_ir import (
    Verb,
    encode_legacy,
    is_native_bgp_af_network_removal_op,
    is_native_bgp_op,
)
from confgraph.parsers.nxos_parser import NXOSParser


def _bgp_ops(text: str):
    pc = NXOSParser(text).parse()
    return [
        o
        for o in (pc.native_change_ops or [])
        if o.path and o.path[0] in ("bgp_instance", "bgp_instances")
    ]


# NX-OS: network statements live UNDER the address-family, and the withdrawal
# is the AF-scoped `no network <cidr>` spelling (classless — NX-OS never uses
# the IOS `mask` form here).
NXOS_AF_NO_NETWORK = """feature bgp
router bgp 65001
  address-family ipv4 unicast
    network 10.199.0.0/24
    no network 10.199.199.0/24
"""


def test_af_no_network_emits_scoped_list_remove():
    rems = [o for o in _bgp_ops(NXOS_AF_NO_NETWORK) if o.verb is Verb.LIST_REMOVE]
    assert len(rems) == 1
    op = rems[0]
    # Singular `bgp_instance` head (distinguishes removal from the positive
    # `bgp_instances` SET); AF-scoped path with the `network` segment + prefix.
    assert op.path == (
        "bgp_instance", "65001", "", "af", "ipv4", "unicast", "",
        "network", "10.199.199.0/24",
    )
    assert op.origin == "native"
    assert is_native_bgp_af_network_removal_op(op)
    assert is_native_bgp_op(op)


def test_af_no_network_is_ops_only_no_legacy_twin():
    pc = NXOSParser(NXOS_AF_NO_NETWORK).parse()
    ops = pc.native_change_ops or []
    assert sum(is_native_bgp_af_network_removal_op(o) for o in ops) == 1
    # encode_legacy must emit NOTHING for the withdrawal (no legacy twin) so
    # legacy-mode `bgp_no_commands` stays byte-identical to pre-ops behaviour.
    arts = encode_legacy(ops)
    flat = [s for lst in arts.bgp_no_commands.values() for s in lst]
    assert not any("10.199.199.0/24" in s for s in flat)


def test_positive_af_network_not_regressed():
    # The surviving positive `network 10.199.0.0/24` still emits its SET; the
    # `no network` line is not mis-parsed as a positive network.
    sets = [
        o
        for o in _bgp_ops(NXOS_AF_NO_NETWORK)
        if o.verb is Verb.SET and len(o.path) > 7 and o.path[7] == "network"
    ]
    assert [o.path[8] for o in sets] == ["10.199.0.0/24"]


def test_af_no_network_bad_prefix_ignored():
    # A malformed `no network` line yields no op (parity with the aggregate
    # walk's None-prefix guard) rather than a crash or a junk removal.
    rems = [
        o
        for o in _bgp_ops(
            "feature bgp\nrouter bgp 65001\n"
            "  address-family ipv4 unicast\n    no network not-an-ip\n"
        )
        if o.verb is Verb.LIST_REMOVE
    ]
    assert rems == []
