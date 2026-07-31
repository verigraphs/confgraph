"""CCR-0146 — parse ``no bgp default ipv4-unicast`` (IOS ipv4 activation default).

On IOS/IOS-XE the IPv4-unicast address family is auto-activated for every
``neighbor remote-as`` unless the operator writes ``no bgp default
ipv4-unicast`` (after which per-neighbor IPv4 AF activation is explicit,
NX-OS-style). Evidence: syntax-corpus ``cisco-ios/bgp.yaml:
bgp-default-ipv4-unicast`` (doc-only, vendor ``show running-config``
transcript) — absence of the line == enabled (the affirmative
``bgp default ipv4-unicast`` never nvgens), the ``no`` line == disabled.

The field ``BGPConfig.default_ipv4_unicast`` (default True) rides the Task #22
scalar mechanism: the shared classifier ``_bgp_instance_scalar22_updates``
drives BOTH the parse-fold (last-line-wins) and the native line-detected op
emission, so parse and emission cannot disagree. It is a tri-state True-default
(Appendix T discipline — absence stays True, never the log_neighbor_changes
trap).

NX-OS is unaffected: the command does not exist on NX-OS (activation is always
explicit there), so a NX-OS running-config never carries the line and the field
stays at its default True.
"""

from __future__ import annotations

from confgraph.change_ir import Verb, derive_ops, encode_legacy
from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.nxos_parser import NXOSParser


def _parse(text: str, parser_cls=IOSParser):
    return parser_cls(text).parse()


def _scalar_ops(pc, field):
    return [
        o
        for o in (pc.native_change_ops or [])
        if o.verb is Verb.SET
        and len(o.path) == 5
        and o.path[0] == "bgp_instances"
        and o.path[3] == "scalar"
        and o.path[4] == field
    ]


# --------------------------------------------------------------------------- #
# Parse — both states + absence default
# --------------------------------------------------------------------------- #


class TestParse:
    def test_no_line_disables(self):
        b = _parse(
            "router bgp 65001\n"
            " bgp log-neighbor-changes\n"
            " no bgp default ipv4-unicast\n"
            " neighbor 172.16.255.1 remote-as 65001\n"
        ).bgp_instances[0]
        assert b.default_ipv4_unicast is False

    def test_affirmative_line_enables(self):
        # Robustness / proposal text: the affirmative spelling is accepted and
        # yields True (it never renders in running-config, but a proposal may
        # restate it to re-enable).
        b = _parse(
            "router bgp 65001\n"
            " bgp default ipv4-unicast\n"
            " neighbor 10.0.0.2 remote-as 65002\n"
        ).bgp_instances[0]
        assert b.default_ipv4_unicast is True

    def test_absence_yields_default_true(self):
        # Tri-state True-default: no line ⇒ model default True (never the
        # log_neighbor_changes trap).
        b = _parse(
            "router bgp 65001\n neighbor 10.0.0.2 remote-as 65002\n"
        ).bgp_instances[0]
        assert b.default_ipv4_unicast is True

    def test_last_line_wins_both_orders(self):
        off = _parse(
            "router bgp 65001\n"
            " bgp default ipv4-unicast\n"
            " no bgp default ipv4-unicast\n"
        ).bgp_instances[0]
        on = _parse(
            "router bgp 65001\n"
            " no bgp default ipv4-unicast\n"
            " bgp default ipv4-unicast\n"
        ).bgp_instances[0]
        assert off.default_ipv4_unicast is False
        assert on.default_ipv4_unicast is True

    def test_evpn_leaf_shape(self):
        # The exact running-config shape the corpus cites (Catalyst 9300 IRB
        # example): the `no` line sits flat under `router bgp`, between
        # log-neighbor-changes and the neighbor lines.
        b = _parse(
            "router bgp 65001\n"
            " bgp log-neighbor-changes\n"
            " no bgp default ipv4-unicast\n"
            " neighbor 172.16.255.1 remote-as 65001\n"
            " neighbor 172.16.255.1 update-source Loopback0\n"
        ).bgp_instances[0]
        assert b.default_ipv4_unicast is False


# --------------------------------------------------------------------------- #
# Over-trigger discipline (§6 #2)
# --------------------------------------------------------------------------- #


class TestOverTrigger:
    def test_default_local_preference_does_not_touch_field(self):
        b = _parse(
            "router bgp 65001\n"
            " bgp default local-preference 200\n"
            " neighbor 10.0.0.2 remote-as 65002\n"
        ).bgp_instances[0]
        assert b.default_ipv4_unicast is True
        assert b.default_local_preference == 200

    def test_no_default_local_preference_does_not_touch_field(self):
        b = _parse(
            "router bgp 65001\n"
            " no bgp default local-preference\n"
            " neighbor 10.0.0.2 remote-as 65002\n"
        ).bgp_instances[0]
        assert b.default_ipv4_unicast is True


# --------------------------------------------------------------------------- #
# NX-OS unaffected (command is IOS-family)
# --------------------------------------------------------------------------- #


class TestNXOSUnaffected:
    def test_nxos_config_keeps_default_true(self):
        # NX-OS never carries the line (explicit activation always); a normal
        # NX-OS BGP config leaves the field at its default True.
        b = _parse(
            "router bgp 65001\n"
            " neighbor 10.0.0.2\n"
            "  remote-as 65002\n"
            "  address-family ipv4 unicast\n",
            NXOSParser,
        ).bgp_instances[0]
        assert b.default_ipv4_unicast is True


# --------------------------------------------------------------------------- #
# Native op emission + merge-override semantics
# --------------------------------------------------------------------------- #


class TestEmission:
    def test_no_line_emits_set_false(self):
        pc = _parse(
            "router bgp 65001\n no bgp default ipv4-unicast\n"
        )
        ops = _scalar_ops(pc, "default_ipv4_unicast")
        assert [o.value for o in ops] == [False]
        assert ops[0].origin == "native" and ops[0].line_no >= 0
        assert "default ipv4-unicast" in ops[0].source_line

    def test_affirmative_line_emits_set_true(self):
        pc = _parse("router bgp 65001\n bgp default ipv4-unicast\n")
        assert [o.value for o in _scalar_ops(pc, "default_ipv4_unicast")] == [True]

    def test_absence_emits_no_op(self):
        pc = _parse(
            "router bgp 65001\n neighbor 10.0.0.2 remote-as 65002\n"
        )
        assert _scalar_ops(pc, "default_ipv4_unicast") == []

    def test_one_op_per_line_both_orders(self):
        pc = _parse(
            "router bgp 65001\n"
            " bgp default ipv4-unicast\n"
            " no bgp default ipv4-unicast\n"
        )
        ops = _scalar_ops(pc, "default_ipv4_unicast")
        assert [o.value for o in ops] == [True, False]
        assert ops[0].line_no < ops[1].line_no  # ChangeSet order = script order

    def test_merge_override_reaches_legacy_set_fields(self):
        # A proposal restating `no bgp default ipv4-unicast` produces a SET op
        # that overrides a base True — and it survives the legacy codec (so the
        # override reaches the merge path, not just the native stream).
        pc = _parse("router bgp 65001\n no bgp default ipv4-unicast\n")
        ops = [
            o
            for o in derive_ops(pc)
            if o.path[0] == "bgp_instances"
            and len(o.path) == 5
            and o.path[3] == "scalar"
            and o.path[4] == "default_ipv4_unicast"
        ]
        assert [o.value for o in ops] == [False]
        arts = encode_legacy(ops)
        assert not arts.no_commands
        key = ("bgp_instances", "65001", "", "scalar", "default_ipv4_unicast")
        assert arts.set_fields.get(key) is False

    def test_vrf_scope_not_emitted(self):
        # Z.1 VRF guard: the VRF-AF scope does not fold these scalars, so no op
        # is emitted there (parse ⟺ emission symmetry).
        pc = _parse(
            "router bgp 65001\n"
            " neighbor 10.0.0.2 remote-as 65002\n"
            " address-family ipv4 vrf CUST\n"
            "  no bgp default ipv4-unicast\n"
        )
        vrf_ops = [
            o
            for o in pc.native_change_ops
            if len(o.path) == 5
            and o.path[0] == "bgp_instances"
            and o.path[2] == "CUST"
            and o.path[3] == "scalar"
            and o.path[4] == "default_ipv4_unicast"
        ]
        assert vrf_ops == []
