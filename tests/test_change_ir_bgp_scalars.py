"""Task #22 (WI-DB3) — the nine formerly-unparsed BGP scalars: parser support
+ native line-detected emission.

CCR: ``change_ir_proposal_operations.md`` Appendix Z.

Instance-level (BGPConfig, GLOBAL instances only — Z.1 VRF guard):

- ``bgp graceful-restart [restart-time N] [stalepath-time N]`` (+ NX-OS bare
  spelling) → ``graceful_restart`` True + timers; bare ``no`` resets flag AND
  both timers; per-token ``no … restart-time`` / ``no … stalepath-time``,
- tri-state True-defaults ``enforce_first_as`` / ``fast_external_fallover``
  (Appendix T discipline: absence → model default True, positive/negation
  lines → True/False at their line, last-line-wins),
- ``bgp deterministic-med`` / ``bgp dampening [params…]`` (flag only, params
  UNPARSED) / ``default-metric N`` (classic direct-child spelling) + ``no``
  forms.

AF-level (BGPAddressFamily): ``default-information originate`` /
``auto-summary`` / ``synchronization`` + ``no`` forms (False-defaults).

Emission is LINE-DETECTED from the SAME classifier the parse folds
(``_bgp_instance_scalar22_updates`` / ``_bgp_af_flag22_updates``) — one native
``SET (…, "scalar", field)`` per update per line, so ChangeSet-ordered replay
reproduces last-line-wins.  Negations are SET-to-post-line-state (the
log_neighbor_changes convention) — NO UNSET verbs, NO tombstones, zero
``no_commands`` pollution.
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


def _af_scalar_ops(pc, field):
    return [
        o
        for o in (pc.native_change_ops or [])
        if o.verb is Verb.SET
        and len(o.path) == 9
        and o.path[0] == "bgp_instances"
        and o.path[3] == "af"
        and o.path[7] == "scalar"
        and o.path[8] == field
    ]


KITCHEN_SINK = """router bgp 65001
 bgp graceful-restart restart-time 120 stalepath-time 360
 bgp enforce-first-as
 bgp fast-external-fallover
 bgp deterministic-med
 bgp dampening 15 750 2000 60
 default-metric 5
 neighbor 10.0.0.2 remote-as 65002
 address-family ipv4
  default-information originate
  auto-summary
  synchronization
"""


# --------------------------------------------------------------------------- #
# Baseline parse — positives
# --------------------------------------------------------------------------- #


class TestParsePositive:
    def test_kitchen_sink_instance_values(self):
        b = _parse(KITCHEN_SINK).bgp_instances[0]
        assert b.graceful_restart is True
        assert b.graceful_restart_restart_time == 120
        assert b.graceful_restart_stalepath_time == 360
        assert b.enforce_first_as is True
        assert b.fast_external_fallover is True
        assert b.deterministic_med is True
        assert b.dampening is True  # parameterized form → flag only (Z.4)
        assert b.default_metric == 5

    def test_kitchen_sink_af_flags(self):
        af = _parse(KITCHEN_SINK).bgp_instances[0].address_families[0]
        assert af.default_information_originate is True
        assert af.auto_summary is True
        assert af.synchronization is True

    def test_graceful_restart_bare_and_separate_timer_lines(self):
        b = _parse(
            "router bgp 65001\n"
            " bgp graceful-restart\n"
            " bgp graceful-restart restart-time 130\n"
            " bgp graceful-restart stalepath-time 400\n"
        ).bgp_instances[0]
        assert (
            b.graceful_restart,
            b.graceful_restart_restart_time,
            b.graceful_restart_stalepath_time,
        ) == (True, 130, 400)

    def test_dampening_bare_flag(self):
        b = _parse("router bgp 65001\n bgp dampening\n").bgp_instances[0]
        assert b.dampening is True


# --------------------------------------------------------------------------- #
# Baseline parse — absence == model default (tri-state discipline)
# --------------------------------------------------------------------------- #


class TestParseAbsence:
    def test_absence_yields_model_defaults(self):
        b = _parse(
            "router bgp 65001\n neighbor 10.0.0.2 remote-as 65002\n"
        ).bgp_instances[0]
        # The two True-defaults MUST stay True on absence (never the
        # log_neighbor_changes trap — 5c-A Finding-2).
        assert b.enforce_first_as is True
        assert b.fast_external_fallover is True
        assert b.graceful_restart is False
        assert b.graceful_restart_restart_time is None
        assert b.graceful_restart_stalepath_time is None
        assert b.deterministic_med is False
        assert b.dampening is False
        assert b.default_metric is None

    def test_af_absence_yields_false(self):
        af = _parse(
            "router bgp 65001\n address-family ipv4\n"
            "  network 10.0.0.0 mask 255.0.0.0\n"
        ).bgp_instances[0].address_families[0]
        assert af.default_information_originate is False
        assert af.auto_summary is False
        assert af.synchronization is False

    def test_absence_emits_no_scalar22_ops(self):
        pc = _parse("router bgp 65001\n neighbor 10.0.0.2 remote-as 65002\n")
        for f in (
            "graceful_restart",
            "graceful_restart_restart_time",
            "graceful_restart_stalepath_time",
            "enforce_first_as",
            "fast_external_fallover",
            "deterministic_med",
            "dampening",
            "default_metric",
        ):
            assert _scalar_ops(pc, f) == []


# --------------------------------------------------------------------------- #
# Baseline parse — negations + last-line-wins
# --------------------------------------------------------------------------- #


class TestParseNegation:
    def test_all_no_forms(self):
        b = _parse(
            "router bgp 65001\n"
            " no bgp enforce-first-as\n"
            " no bgp fast-external-fallover\n"
            " no bgp graceful-restart\n"
            " no bgp deterministic-med\n"
            " no bgp dampening\n"
            " no default-metric\n"
        ).bgp_instances[0]
        assert b.enforce_first_as is False
        assert b.fast_external_fallover is False
        assert b.graceful_restart is False
        assert b.deterministic_med is False
        assert b.dampening is False
        assert b.default_metric is None

    def test_bare_no_graceful_restart_resets_both_timers(self):
        b = _parse(
            "router bgp 65001\n"
            " bgp graceful-restart restart-time 120 stalepath-time 360\n"
            " no bgp graceful-restart\n"
        ).bgp_instances[0]
        assert (
            b.graceful_restart,
            b.graceful_restart_restart_time,
            b.graceful_restart_stalepath_time,
        ) == (False, None, None)

    def test_per_token_timer_reset_keeps_flag(self):
        b = _parse(
            "router bgp 65001\n"
            " bgp graceful-restart restart-time 120 stalepath-time 360\n"
            " no bgp graceful-restart restart-time\n"
        ).bgp_instances[0]
        assert (
            b.graceful_restart,
            b.graceful_restart_restart_time,
            b.graceful_restart_stalepath_time,
        ) == (True, None, 360)

    def test_last_line_wins_both_orders(self):
        on = _parse(
            "router bgp 65001\n no bgp dampening\n bgp dampening\n"
        ).bgp_instances[0]
        off = _parse(
            "router bgp 65001\n bgp dampening\n no bgp dampening\n"
        ).bgp_instances[0]
        assert on.dampening is True and off.dampening is False
        re_en = _parse(
            "router bgp 65001\n no bgp enforce-first-as\n bgp enforce-first-as\n"
        ).bgp_instances[0]
        dis = _parse(
            "router bgp 65001\n bgp enforce-first-as\n no bgp enforce-first-as\n"
        ).bgp_instances[0]
        assert re_en.enforce_first_as is True and dis.enforce_first_as is False

    def test_af_no_forms(self):
        af = _parse(
            "router bgp 65001\n address-family ipv4\n"
            "  no default-information originate\n"
            "  no auto-summary\n"
            "  no synchronization\n"
        ).bgp_instances[0].address_families[0]
        assert af.default_information_originate is False
        assert af.auto_summary is False
        assert af.synchronization is False


# --------------------------------------------------------------------------- #
# Native op emission — line-detected, one SET per update per line
# --------------------------------------------------------------------------- #


class TestEmission:
    def test_kitchen_sink_ops_values_and_anchors(self):
        pc = _parse(KITCHEN_SINK)
        gr = _scalar_ops(pc, "graceful_restart")
        rt = _scalar_ops(pc, "graceful_restart_restart_time")
        st = _scalar_ops(pc, "graceful_restart_stalepath_time")
        assert [o.value for o in gr] == [True]
        assert [o.value for o in rt] == [120]
        assert [o.value for o in st] == [360]
        # all three anchored at the same (real) line
        assert gr[0].line_no == rt[0].line_no == st[0].line_no >= 0
        assert "graceful-restart" in gr[0].source_line
        for f, v in (
            ("enforce_first_as", True),
            ("fast_external_fallover", True),
            ("deterministic_med", True),
            ("dampening", True),
            ("default_metric", 5),
        ):
            ops = _scalar_ops(pc, f)
            assert [o.value for o in ops] == [v], f
            assert ops[0].line_no >= 0 and ops[0].origin == "native"

    def test_af_flag_ops(self):
        pc = _parse(KITCHEN_SINK)
        for f in ("default_information_originate", "auto_summary", "synchronization"):
            ops = _af_scalar_ops(pc, f)
            assert [o.value for o in ops] == [True], f
            assert ops[0].path[4:7] == ("ipv4", "unicast", "")

    def test_negation_lines_emit_set_false_or_none(self):
        pc = _parse(
            "router bgp 65001\n"
            " no bgp enforce-first-as\n"
            " no bgp dampening\n"
            " no default-metric\n"
            " address-family ipv4\n"
            "  no auto-summary\n"
        )
        assert [o.value for o in _scalar_ops(pc, "enforce_first_as")] == [False]
        assert [o.value for o in _scalar_ops(pc, "dampening")] == [False]
        assert [o.value for o in _scalar_ops(pc, "default_metric")] == [None]
        assert [o.value for o in _af_scalar_ops(pc, "auto_summary")] == [False]

    def test_bare_no_graceful_restart_emits_three_sets_at_one_line(self):
        pc = _parse("router bgp 65001\n no bgp graceful-restart\n")
        gr = _scalar_ops(pc, "graceful_restart")
        rt = _scalar_ops(pc, "graceful_restart_restart_time")
        st = _scalar_ops(pc, "graceful_restart_stalepath_time")
        assert [o.value for o in gr] == [False]
        assert [o.value for o in rt] == [None]
        assert [o.value for o in st] == [None]
        assert gr[0].line_no == rt[0].line_no == st[0].line_no

    def test_one_op_per_line_both_orders(self):
        pc = _parse("router bgp 65001\n bgp dampening\n no bgp dampening\n")
        ops = _scalar_ops(pc, "dampening")
        assert [o.value for o in ops] == [True, False]
        assert ops[0].line_no < ops[1].line_no  # ChangeSet order = script order

    def test_vrf_scope_not_emitted_or_parsed(self):
        # Z.1 VRF guard: the VRF-AF scope does not parse these fields, so no
        # ops may be emitted there either (parse ⟺ emission symmetry).
        pc = _parse(
            "router bgp 65001\n"
            " neighbor 10.0.0.2 remote-as 65002\n"
            " address-family ipv4 vrf CUST\n"
            "  neighbor 10.1.0.2 remote-as 65003\n"
            "  default-metric 7\n"
            "  bgp dampening\n"
        )
        vrf = next(b for b in pc.bgp_instances if b.vrf == "CUST")
        assert vrf.default_metric is None and vrf.dampening is False
        vrf_scalar_ops = [
            o
            for o in pc.native_change_ops
            if len(o.path) == 5
            and o.path[0] == "bgp_instances"
            and o.path[2] == "CUST"
            and o.path[3] == "scalar"
        ]
        assert vrf_scalar_ops == []

    def test_nxos_bare_spellings(self):
        pc = _parse(
            "router bgp 65001\n"
            " graceful-restart restart-time 240\n"
            " no enforce-first-as\n"
            " fast-external-fallover\n",
            NXOSParser,
        )
        b = pc.bgp_instances[0]
        assert (b.graceful_restart, b.graceful_restart_restart_time) == (True, 240)
        assert b.enforce_first_as is False
        assert b.fast_external_fallover is True
        assert [o.value for o in _scalar_ops(pc, "enforce_first_as")] == [False]
        assert [o.value for o in _scalar_ops(pc, "graceful_restart_restart_time")] == [240]

    def test_graceful_restart_helper_not_matched(self):
        b = _parse(
            "router bgp 65001\n graceful-restart-helper\n", NXOSParser
        ).bgp_instances[0]
        assert b.graceful_restart is False


# --------------------------------------------------------------------------- #
# Codec / byte-identity
# --------------------------------------------------------------------------- #


class TestCodec:
    def test_ops_encode_to_set_fields_only(self):
        pc = _parse(KITCHEN_SINK + " no bgp dampening\n")
        ops = derive_ops(pc)
        arts = encode_legacy(
            [
                o
                for o in ops
                if o.path[0] == "bgp_instances"
                and (
                    (len(o.path) == 5 and o.path[3] == "scalar")
                    or (len(o.path) == 9 and o.path[3] == "af" and o.path[7] == "scalar")
                )
            ]
        )
        assert not arts.no_commands
        assert ("bgp_instances", "65001", "", "scalar", "dampening") in arts.set_fields

    def test_composed_scalar22_ops_all_native(self):
        # anti-rot: every task-#22-shaped op in the composed ChangeSet is native.
        ops = derive_ops(_parse(KITCHEN_SINK))
        fields22 = {
            "graceful_restart",
            "graceful_restart_restart_time",
            "graceful_restart_stalepath_time",
            "enforce_first_as",
            "fast_external_fallover",
            "deterministic_med",
            "dampening",
            "default_metric",
            "default_information_originate",
            "auto_summary",
            "synchronization",
        }
        shaped = [
            o
            for o in ops
            if o.path
            and o.path[0] == "bgp_instances"
            and o.path[-1] in fields22
        ]
        assert shaped and all(o.origin == "native" for o in shaped)
