"""CCR-0240 — IOS-XR OSPF ``passive`` is inheritable, and ``disable`` is a value.

IOS-XR makes ``passive`` configurable at FOUR scopes and the innermost one wins.
The vendor states the chain outright:

    "If this command is not specified in interface configuration mode, then the
    interface adopts the passive parameter specified by the area.  If this
    command is not specified in area configuration mode, then the interface
    adopts the passive parameter specified for the process.  If this command is
    not specified at any level, then the passive parameter is disabled and OSPF
    updates are sent on the interface."
    -- ASR9000 routing command reference, "passive (OSPF)".
       Command Modes: Interface / Area / Router / VRF configuration.

The parser read ONLY the interface scope, and read it as a bare presence flag.
So the standard XR hardening idiom -- suppress OSPF everywhere at process scope,
re-enable it per uplink -- produced ``passive_interface_default=False`` and an
empty ``passive_interfaces``: nothing passive anywhere.  That is wrong in BOTH
directions, which is what makes it worse than a plain omission:

* interfaces the device suppresses formed adjacencies in the model -> PHANTOM
  adjacencies, so a change that breaks nothing reads as breaking a session;
* the uplink that is genuinely non-passive carried no distinguishing state --
  ``passive disable`` was in no pattern at all -- so it was byte-for-byte
  identical in the model to a non-exempted one, and a change that genuinely
  breaks adjacency reads as contained.

``disable`` must therefore be a FIRST-CLASS VALUE, not "the absence of enable".
A model that encodes it as absence cannot express the exempted uplink, which is
half the bug.

**What the engine consumes, and why BOTH lists are populated.**  The three model
fields already exist and ``confgraph-entrp``'s resolver already reads them
correctly::

    if proc.passive_interface_default:
        return iface.name not in proc.non_passive_interfaces
    return iface.name in proc.passive_interfaces

So the parser resolves the chain per interface and projects the answer onto both
lists: resolved-passive goes in ``passive_interfaces``, resolved-NOT-passive in
``non_passive_interfaces``, and an interface no scope spoke about goes in
neither.  Filling both means the engine lands on the same answer whichever
branch it takes.  ``non_passive_interfaces`` is load-bearing and not decorative:
the shared ``_backfill_ospf_interface_settings`` walk deliberately skips a
``False`` source value ("None/False = the vendor did not say"), so a resolved
non-passive interface does NOT reach ``InterfaceConfig.ospf_passive`` and the
engine falls through to this list to un-gate the uplink.

**Fixture provenance** (handbook: lines must be what a device PRINTS):

* ``passive disable`` -- WITNESSED in device output.  ``syntax-corpus/iosxr/
  ospf.yaml`` -> ``passive`` cites a ``show running-config router ospf``
  transcript emitting ``router ospf 30 / ... / passive disable / priority 1 /
  mtu-ignore enable``.  Re-verified 2026-11-01; the cited page still hashes to
  the recorded ``content_sha``.
* ``passive enable`` -- NOT witnessed anywhere.  It is the canonical form derived
  from Cisco's unified YANG model (which has no valueless ``passive`` node, only
  ``container enable`` / ``container disable``) plus the witnessed
  ``passive disable``.  That is documentation-grade, which BATCH-A1 accepts by
  owner decision -- recorded here so nobody later reads it as device-verified.
* a bare ``passive`` -- the TYPED form only (both keywords are marked
  "(Optional)" and Cisco's own example types it).  Covered for tolerance; it is
  not a claim about emitted output.
* everything else (``router ospf N``, ``area 0``, ``interface Gi0/0/0/N``,
  ``ipv4 address A M``, a ``vrf NAME`` sub-block) is ordinary emitted IOS-XR.

Identifiers here (``xr-edge-4..9``, ``10.77.0.0/16``, ``router ospf 7``) are
used by no other fixture in this repo or in the audit harness, so a failure
here names this file and nothing else.
"""

from confgraph.parsers.iosxr_parser import IOSXRParser

# ---------------------------------------------------------------------------
# Polarity (a): the hardening idiom -- suppress at process scope, exempt one
# uplink.  Gi0/0/0/6 is exempted; Gi0/0/0/7 says nothing and inherits.
# ---------------------------------------------------------------------------
XR_PROCESS_PASSIVE = """\
hostname xr-edge-7
!
interface Loopback0
 ipv4 address 10.77.0.7 255.255.255.255
!
interface GigabitEthernet0/0/0/6
 description to xr-edge-8
 ipv4 address 10.77.6.1 255.255.255.252
!
interface GigabitEthernet0/0/0/7
 description to xr-edge-9
 ipv4 address 10.77.7.1 255.255.255.252
!
router ospf 7
 router-id 10.77.0.7
 passive enable
 area 0
  interface GigabitEthernet0/0/0/6
   passive disable
  !
  interface GigabitEthernet0/0/0/7
  !
 !
!
"""

# ---------------------------------------------------------------------------
# Polarity (b): NO process default; one interface passive at interface scope.
# This is the shape the pre-fix parser already handled, so it is a guard
# against a differently-wrong default rather than a reproduction.
# ---------------------------------------------------------------------------
XR_INTERFACE_PASSIVE = """\
hostname xr-edge-5
!
interface GigabitEthernet0/0/0/4
 description to the firewall
 ipv4 address 10.77.4.1 255.255.255.252
!
interface GigabitEthernet0/0/0/5
 description to xr-edge-6
 ipv4 address 10.77.5.1 255.255.255.252
!
router ospf 7
 router-id 10.77.0.5
 area 0
  interface GigabitEthernet0/0/0/4
   passive enable
  !
  interface GigabitEthernet0/0/0/5
  !
 !
!
"""

# Area scope sits between the two: area 0 opts out of the process-wide passive,
# and one interface inside it opts back in.  area 1 says nothing and inherits.
XR_AREA_SCOPE = """\
hostname xr-edge-9
!
router ospf 7
 router-id 10.77.0.9
 passive enable
 area 0
  passive disable
  interface GigabitEthernet0/0/0/6
  !
  interface GigabitEthernet0/0/0/7
   passive enable
  !
 !
 area 1
  interface Loopback0
  !
 !
!
"""

XR_NOTHING_SAID = """\
hostname xr-edge-8
!
router ospf 7
 router-id 10.77.0.8
 area 0
  interface GigabitEthernet0/0/0/6
   cost 100
  !
 !
!
"""

# A VRF sub-block is a scope of its own, INSIDE the process block.
XR_VRF = """\
hostname xr-edge-4
!
router ospf 7
 router-id 10.77.0.4
 passive enable
 area 0
  interface GigabitEthernet0/0/0/4
  !
 !
 vrf CUSTOMER_Q
  router-id 10.77.1.4
  area 0
   interface GigabitEthernet0/0/0/5
   !
   interface GigabitEthernet0/0/0/6
    passive disable
   !
  !
 !
!
"""

XR_VRF_OPTS_OUT = """\
hostname xr-edge-6
!
router ospf 7
 passive enable
 vrf CUSTOMER_R
  passive disable
  area 0
   interface GigabitEthernet0/0/0/5
   !
  !
 !
!
"""


def _ospf(cfg, *, vrf=None):
    return next(
        o for o in IOSXRParser(cfg).parse_ospf() if o.vrf == vrf
    )


def _settings(ospf, area_id, name):
    area = next(a for a in ospf.areas if a.area_id == area_id)
    return area.interface_settings[name]


# ---------------------------------------------------------------------------
# Process scope -- the hardwired False (iosxr_parser.py, parse_ospf) is the
# first of the three root-cause sites.
# ---------------------------------------------------------------------------


def test_process_scope_passive_enable_becomes_the_process_default():
    """RED pre-fix: `passive_interface_default` was hardwired to False."""
    ospf = _ospf(XR_PROCESS_PASSIVE)
    assert ospf.passive_interface_default is True


def test_an_interface_that_says_nothing_inherits_the_process_default():
    """RED pre-fix: the inherited leg was the phantom-adjacency half."""
    ospf = _ospf(XR_PROCESS_PASSIVE)
    assert "GigabitEthernet0/0/0/7" in ospf.passive_interfaces
    assert _settings(ospf, "0", "GigabitEthernet0/0/0/7").passive is True


def test_interface_passive_disable_exempts_the_uplink():
    """RED pre-fix: `passive disable` matched no pattern, so the exempted uplink
    was indistinguishable from a non-exempted one."""
    ospf = _ospf(XR_PROCESS_PASSIVE)
    assert ospf.non_passive_interfaces == ["GigabitEthernet0/0/0/6"]
    assert _settings(ospf, "0", "GigabitEthernet0/0/0/6").passive is False
    assert "GigabitEthernet0/0/0/6" not in ospf.passive_interfaces


def test_every_area_interface_lands_in_exactly_one_list():
    """The engine's resolver branches on `passive_interface_default` and reads a
    DIFFERENT list on each branch, so an interface missing from both would be
    answered by the default alone.  Under a configured process default every
    interface must be classified."""
    ospf = _ospf(XR_PROCESS_PASSIVE)
    names = [n for a in ospf.areas for n in a.interfaces]
    assert names
    for name in names:
        in_passive = name in ospf.passive_interfaces
        in_non = name in ospf.non_passive_interfaces
        assert in_passive != in_non, name


# ---------------------------------------------------------------------------
# Polarity (b) -- the control.  Green pre-fix AND post-fix by design: it proves
# the fix did not install a differently-wrong default.
# ---------------------------------------------------------------------------


def test_interface_scope_passive_with_no_process_default():
    """GUARD (green pre-fix): interface-level passive, nothing at process scope."""
    ospf = _ospf(XR_INTERFACE_PASSIVE)
    assert ospf.passive_interface_default is False
    assert ospf.passive_interfaces == ["GigabitEthernet0/0/0/4"]
    assert ospf.non_passive_interfaces == []
    assert _settings(ospf, "0", "GigabitEthernet0/0/0/4").passive is True
    assert _settings(ospf, "0", "GigabitEthernet0/0/0/5").passive is False


def test_nothing_said_at_any_scope_claims_nothing():
    """GUARD: the vendor's "not specified at any level" case.  Neither list may
    name the interface -- an empty `non_passive_interfaces` here is the honest
    answer, not a missing one, because no scope made a claim."""
    ospf = _ospf(XR_NOTHING_SAID)
    assert ospf.passive_interface_default is False
    assert ospf.passive_interfaces == []
    assert ospf.non_passive_interfaces == []
    assert _settings(ospf, "0", "GigabitEthernet0/0/0/6").passive is False
    # and the rest of the interface body is untouched by the passive work
    assert _settings(ospf, "0", "GigabitEthernet0/0/0/6").cost == 100


# ---------------------------------------------------------------------------
# Area scope -- the second root-cause site: never consulted at all.
# ---------------------------------------------------------------------------


def test_area_scope_passive_disable_overrides_the_process_default():
    """RED pre-fix: area scope was never read."""
    ospf = _ospf(XR_AREA_SCOPE)
    assert ospf.passive_interface_default is True          # process still says so
    assert "GigabitEthernet0/0/0/6" in ospf.non_passive_interfaces
    assert _settings(ospf, "0", "GigabitEthernet0/0/0/6").passive is False


def test_interface_scope_beats_area_scope():
    """GUARD (green pre-fix, for the wrong reason): the area opts out and the
    interface opts back in.

    This passed pre-fix only because interface-scope `passive enable` was the
    ONE scope the old parser did read, and there was no area value for it to
    beat.  Post-fix it is a real precedence assertion -- the area's `disable`
    must not reach an interface that states its own value."""
    ospf = _ospf(XR_AREA_SCOPE)
    assert "GigabitEthernet0/0/0/7" in ospf.passive_interfaces
    assert _settings(ospf, "0", "GigabitEthernet0/0/0/7").passive is True


def test_a_second_area_still_inherits_the_process_default():
    """RED pre-fix: an area-scope override must not leak to a sibling area."""
    ospf = _ospf(XR_AREA_SCOPE)
    assert "Loopback0" in ospf.passive_interfaces
    assert _settings(ospf, "1", "Loopback0").passive is True


# ---------------------------------------------------------------------------
# VRF scope -- a scope the vendor lists and the model reaches through a second
# OSPFConfig.  Not threading the process default through it would leave the
# identical defect in a second place.
# ---------------------------------------------------------------------------


def test_vrf_ospf_inherits_the_enclosing_process_default():
    """RED pre-fix: the VRF instance set no passive fields at all."""
    ospf = _ospf(XR_VRF, vrf="CUSTOMER_Q")
    assert ospf.passive_interface_default is True
    assert ospf.passive_interfaces == ["GigabitEthernet0/0/0/5"]
    assert ospf.non_passive_interfaces == ["GigabitEthernet0/0/0/6"]


def test_vrf_scope_passive_disable_overrides_the_process():
    """RED pre-fix: VRF scope was never read."""
    ospf = _ospf(XR_VRF_OPTS_OUT, vrf="CUSTOMER_R")
    assert ospf.passive_interface_default is False
    assert ospf.non_passive_interfaces == ["GigabitEthernet0/0/0/5"]
    assert ospf.passive_interfaces == []


def test_the_global_instance_is_unaffected_by_a_vrf_sub_block():
    """RED pre-fix (on the default), and a containment guard: the global
    instance applies the process default to its OWN direct-child areas and
    must not pick up the VRF's interfaces."""
    ospf = _ospf(XR_VRF)
    assert ospf.passive_interface_default is True
    assert ospf.passive_interfaces == ["GigabitEthernet0/0/0/4"]
    assert ospf.non_passive_interfaces == []


# ---------------------------------------------------------------------------
# Disclosure (CCR-0240 item 4) and the shared spelling.
# ---------------------------------------------------------------------------


def test_passive_disable_is_in_the_recognised_interface_body_vocabulary():
    """CCR-0240 item 4.  The `area > interface` body table IS the record of which
    lines the parser consumes, so the `disable` form has to be a row in it --
    otherwise a line the parser now acts on is still, by that table's account,
    unparsed.  Pinned against the table rather than only against the parsed
    value, because the two can drift apart in opposite directions.

    The import is local so the REST of this module still loads against a pre-fix
    parser -- `_IOSXR_PASSIVE_RE` does not exist there, and a module-level import
    would turn every test in the file into a collection error instead of the
    per-assertion red/green split this file is meant to give."""
    from confgraph.parsers.iosxr_parser import _IOSXR_PASSIVE_RE

    rows = dict(IOSXRParser._OSPF_AREA_IFACE_PATTERNS)
    assert "passive" in rows
    assert _IOSXR_PASSIVE_RE.pattern == rows["passive"], (
        "the scope reader and the body table must share ONE spelling"
    )
    assert _IOSXR_PASSIVE_RE.match("   passive disable")
    assert _IOSXR_PASSIVE_RE.match("   passive enable")
    assert "passive" in IOSXRParser._OSPF_ENABLE_DISABLE_FIELDS


def test_a_bare_passive_is_read_as_enable():
    """RED pre-fix: a bare `passive` matched `passive\\s+enable` nowhere.

    TYPED form, not an emitted one -- Cisco marks both keywords "(Optional)" and
    its own example types a bare `passive`, while the running-config emits the
    keyword.  Tolerance, deliberately, so a hand-pasted or tooling-normalised
    config is not silently read as "not passive"."""
    ospf = _ospf("""\
hostname xr-edge-5
!
router ospf 7
 area 0
  interface GigabitEthernet0/0/0/4
   passive
  !
 !
!
""")
    assert ospf.passive_interfaces == ["GigabitEthernet0/0/0/4"]
    assert _settings(ospf, "0", "GigabitEthernet0/0/0/4").passive is True


def test_a_repeated_statement_takes_the_last_value():
    """GUARD: a device applies the last statement in a scope, so the reader must
    not stop at the first match."""
    ospf = _ospf("""\
hostname xr-edge-5
!
router ospf 7
 passive disable
 passive enable
 area 0
  interface GigabitEthernet0/0/0/4
  !
 !
!
""")
    assert ospf.passive_interface_default is True
    assert ospf.passive_interfaces == ["GigabitEthernet0/0/0/4"]


def test_an_areas_interface_passive_is_not_read_as_the_areas_own():
    """GUARD on the one way the area-scope read can go wrong: `area N`'s
    descendants include its `interface X` sub-blocks, so a recursive child
    search would read the interface's `passive enable` as the AREA's and
    passivate every sibling interface in that area."""
    ospf = _ospf(XR_INTERFACE_PASSIVE)
    assert "GigabitEthernet0/0/0/5" not in ospf.passive_interfaces
    assert _settings(ospf, "0", "GigabitEthernet0/0/0/5").passive is False
