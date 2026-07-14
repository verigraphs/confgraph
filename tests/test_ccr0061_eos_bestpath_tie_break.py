"""CCR-0061 — EOS spells compare-routerid ``bgp bestpath tie-break router-id``.

The router-id best-path tie-break is one concept with two vendor spellings: IOS
``bgp bestpath compare-routerid`` and EOS ``bgp bestpath tie-break router-id``
(EOS rejects the IOS spelling outright). The model carries it as
``bestpath_options.compare_routerid``. Before this fix confgraph read only the
IOS spelling, so an Arista box with the tie-break enabled reported a confident
wrong ``False`` — and no bestpath negation (``no bgp bestpath …``) parsed at all.

Every config line here is a device-EMITTED form, taken from the cEOS 4.36.1F
capture ``syntax-corpus/captures/eos/2026-07-14-ceos-4.36.1F-bestpath-tie-break-probe.txt``:
``bgp bestpath tie-break router-id`` (Probe 1) and the negated family
``no bgp bestpath as-path ignore`` / ``… multipath-relax`` (Probe 2).

Assertions are on VALUES (``is True`` / ``is False``), never on presence.
"""

from confgraph.parsers.eos_parser import EOSParser
from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.nxos_parser import NXOSParser


def _eos_bgp(*body_lines: str):
    cfg = "router bgp 65000\n   router-id 1.1.1.1\n" + "".join(
        f"   {ln}\n" for ln in body_lines
    )
    return EOSParser(cfg).parse().bgp_instances[0]


# ---------------------------------------------------------------------------
# Positive — EOS reads its own spelling of the router-id tie-break.
# ---------------------------------------------------------------------------

def test_eos_tie_break_router_id_sets_compare_routerid_true():
    bgp = _eos_bgp("bgp bestpath tie-break router-id")
    assert bgp.bestpath_options.compare_routerid is True


# ---------------------------------------------------------------------------
# Negated — the EOS spelling's `no` form, through the shared mechanism.
# ---------------------------------------------------------------------------

def test_eos_no_tie_break_router_id_sets_compare_routerid_false():
    bgp = _eos_bgp("no bgp bestpath tie-break router-id")
    assert bgp.bestpath_options.compare_routerid is False


# ---------------------------------------------------------------------------
# CCR-0060 item 1 — a default-ON member disabled emits `no <form>`; read it.
# ---------------------------------------------------------------------------

def test_eos_no_as_path_multipath_relax_sets_false():
    bgp = _eos_bgp("no bgp bestpath as-path multipath-relax")
    assert bgp.bestpath_options.as_path_multipath_relax is False


# ---------------------------------------------------------------------------
# Parity — a SECOND member's `no` form parses to False with no field-specific
# code: proof the negation handling is one mechanism over the whole table.
# ---------------------------------------------------------------------------

def test_eos_no_as_path_ignore_sets_false_parity():
    bgp = _eos_bgp("no bgp bestpath as-path ignore")
    assert bgp.bestpath_options.as_path_ignore is False


def test_eos_positive_as_path_multipath_relax_still_true():
    # Positive form of a table member still reads True (default-ON member the
    # device emits without a `no` prefix when enabled).
    bgp = _eos_bgp("bgp bestpath as-path multipath-relax")
    assert bgp.bestpath_options.as_path_multipath_relax is True


# ---------------------------------------------------------------------------
# Regression — IOS keeps its own spelling; EOS spelling must NOT leak.
# ---------------------------------------------------------------------------

def test_ios_compare_routerid_still_true():
    cfg = "router bgp 65000\n bgp bestpath compare-routerid\n"
    bgp = IOSParser(cfg).parse().bgp_instances[0]
    assert bgp.bestpath_options.compare_routerid is True


def test_ios_does_not_read_eos_tie_break_spelling():
    # No real Cisco OS accepts `tie-break`; the EOS spelling must stay scoped to
    # the EOS parser and never set compare_routerid on the IOS path.
    cfg = "router bgp 65000\n bgp bestpath tie-break router-id\n"
    bgp = IOSParser(cfg).parse().bgp_instances[0]
    assert bgp.bestpath_options.compare_routerid is False


def test_nxos_bare_bestpath_forms_unchanged():
    # NX-OS emits the same `bgp bestpath …` positive spellings as IOS; the fix
    # must leave them reading exactly as before.
    cfg = (
        "router bgp 65000\n"
        "  bgp bestpath as-path multipath-relax\n"
        "  bgp bestpath compare-routerid\n"
    )
    bgp = NXOSParser(cfg).parse().bgp_instances[0]
    assert bgp.bestpath_options.as_path_multipath_relax is True
    assert bgp.bestpath_options.compare_routerid is True
    # NX-OS never emits `tie-break`; it stays default False.
    assert bgp.bestpath_options.med_confed is False
