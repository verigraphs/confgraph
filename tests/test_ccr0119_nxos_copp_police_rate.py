"""CCR-0119 — NX-OS CoPP police rate (pps/packets units) was dropped.

The shared IOS-family policy-map `police` parser (ios_parser.py
`parse_policy_maps`) expected a bps-style positional rate and dropped the NX-OS
CoPP form, which emits its rate in packets-per-second / packets:

    policy-map type control-plane PM_COPP
      class CM_COPP
        police cir 50 pps bc 16 packets conform transmit violate drop

The fix extends the shared parse to also recognize the keyworded
`police cir <n> {pps|kbps|mbps|gbps|bps} [bc <n> {packets|bytes|ms}]` form and
records an explicit unit on rate (`rate_unit`) and burst (`burst_unit`), so
pps/packets vs bps/bytes is distinguishable.

Fixture provenance (device-EMITTED, corpus-traceable):
  - `police cir 50 pps bc 16 packets conform transmit violate drop` is the
    verbatim device-emitted line captured on n9kv 10.5(5)
    (syntax-corpus/captures/nxos/2026-07-20-n9kv-10.5.5-copp.txt L6, cited by
    the `control-plane-service-policy` verified-capture entry in
    syntax-corpus/nxos/copp.yaml). The device REWRITES the typed
    `police cir 512 kbps bc 200 ms` into this pps/packets form, so pps/packets
    is the only device-emitted CoPP police form — kbps/ms are typed-only and
    are deliberately NOT asserted here.
  - The IOS bare `police <bps> <burst> <excess>` regression line is the classic
    device-emitted single-rate policer form the parser already handled.
"""
from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.nxos_parser import NXOSParser


# Verbatim device-emitted CoPP config, n9kv 10.5(5).
NXOS_COPP = """policy-map type control-plane PM_COPP
  class CM_COPP
    police cir 50 pps bc 16 packets conform transmit violate drop
"""


def _police(parser_cls, cfg):
    p = parser_cls(cfg).parse()
    return p.policy_maps[0].classes[0].police


# --- (a) the fix: pps/packets rate+burst populate with explicit units ---------

def test_nxos_copp_police_pps_packets_exact():
    pol = _police(NXOSParser, NXOS_COPP)
    assert pol is not None
    assert pol.rate == 50
    assert pol.rate_unit == "pps"
    assert pol.burst == 16
    assert pol.burst_unit == "packets"
    # CoPP form has no excess burst.
    assert pol.excess_burst is None


def test_nxos_copp_police_rate_only_no_bc():
    """`police cir <n> pps` without a `bc` clause: rate populated, burst absent."""
    cfg = "policy-map type control-plane PM\n  class CM\n    police cir 50 pps\n"
    pol = _police(NXOSParser, cfg)
    assert pol.rate == 50
    assert pol.rate_unit == "pps"
    assert pol.burst is None
    assert pol.burst_unit is None


# --- (c) REGRESSION (make-or-break): IOS bare bps police is byte-identical -----

IOS_BPS = """policy-map SHAPE
  class VOICE
    police 8000 1500 3000 conform-action transmit exceed-action drop
"""


def test_ios_bare_bps_police_unchanged():
    """The legacy single-rate bps policer parses exactly as before the fix.

    The pre-fix model_dump for this line was:
      rate=8000, burst=1500, excess_burst=3000, rate_unit=None,
      conform_actions=[], exceed_actions=[], violate_actions=[]
    The only post-fix difference is the additive `burst_unit=None`; every
    pre-existing field keeps its exact value.
    """
    pol = _police(IOSParser, IOS_BPS)
    assert pol.rate == 8000
    assert pol.burst == 1500
    assert pol.excess_burst == 3000
    # bps default is represented as no explicit unit — unchanged.
    assert pol.rate_unit is None
    # additive field, defaults to None for the legacy bytes-burst form.
    assert pol.burst_unit is None
    # child-line conform/exceed actions still parse unchanged.
    assert pol.conform_actions == []
    assert pol.exceed_actions == []


def test_ios_police_cir_bps_no_unit_stays_dropped():
    """`police cir <bps>` with NO unit token is left byte-identical to main.

    The cir branch requires an explicit unit token, so this bare two-rate form
    falls through and (as before the fix) yields an all-empty policer rather
    than newly guessing a bps rate — guaranteeing no behavioural drift on the
    IOS `police cir <bps>` form.
    """
    cfg = "policy-map SHAPE\n  class VOICE\n    police cir 8000\n"
    pol = _police(IOSParser, cfg)
    assert pol.rate is None
    assert pol.rate_unit is None
    assert pol.burst is None
    assert pol.burst_unit is None
