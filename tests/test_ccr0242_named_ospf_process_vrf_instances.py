"""CCR-0242 — named OSPF process ids through the shared IOS-base walks.

An OSPF process identifier is a NUMBER on IOS/IOS-XE and an *instance tag* — a
word — on NX-OS, IOS-XR and EOS (``router ospf DCFABRIC``). CCR-0239 taught the
NX-OS interface-enrollment scan and the NX-OS VRF re-scan to accept a tag, but
three sites in the **shared IOS base parser**, which every one of those OSes
inherits, still accepted digits only:

* ``_parse_ospf_vrf_instances`` located and extracted the process with
  ``^router\\s+ospf\\s+(\\d+)``, so on a named-instance device the per-VRF OSPF
  instance was **not created at all** — not mis-attributed, absent. This is the
  form a Nexus emits natively (``router ospf DCFABRIC`` with nested ``vrf``
  blocks) and the normal shape on IOS-XR, where named processes are routine;
* ``parse_ospf`` read the header-qualified VRF with a digit-only pid, so a
  named process lost a ``router ospf <tag> vrf <name>`` qualifier;
* the Change-IR interface-op provenance pattern for ``ospf_process_id`` was
  digit-only while the ``ospf_area`` entry beside it already accepted a token,
  so a named enrollment's SET operation quoted the block header instead of the
  line that caused it.

**The oracle is CCR-0239's parity pattern.** Every claim below parses the same
construct twice — once named, once numeric — and asserts the two agree on
everything except the identity itself. A one-sided assertion ("the named form
now produces a VRF instance") cannot tell a working fix from a differently
broken one; agreement with a spelling that was never broken can.

The second thing these tests guard is the **equality round-trip**. Consumers
decide OSPF process membership by equality — the parser's own passive-default
walk and the engine's ``_ospf_member`` both ask
``ospf.process_id == iface.ospf_process_id`` — so every producer must agree on
WHICH spelling it stores. A producer storing ``"1"`` where another stores ``1``
partitions one process in two, the exact failure CCR-0227 fixed for area ids.
All of them now go through ``canonical_process_id``, the single named home for
the digit-or-verbatim rule.

**Evidence grade — stated plainly.** ``ip router ospf <tag> area <id>`` is
device-emitted with a named tag on a Nexus 9000v 10.3(8) (CCR-0239's capture).
The ``router ospf <instance-tag>`` header, the IOS-XR named-process spelling and
the NX-OS ``vrf`` sub-block under ``router ospf`` are **documentation-derived,
not device-verified** — ``syntax-corpus/nxos/ospf.yaml`` has no ``vrf``
sub-block entry at all — and are accepted at that grade by owner decision
2026-11-07. confgraph's own source comment calling the nested form "NX-OS
native" is code, not device evidence.

Each test says whether it **DISCRIMINATES** (fails on the pre-fix tree, with
the pre-fix observation quoted) or is a **GUARD**.
"""

from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.iosxr_parser import IOSXRParser
from confgraph.parsers.nxos_parser import NXOSParser
from confgraph.utils.ospf import canonical_process_id

# ---------------------------------------------------------------------------
# Fixtures. One shape per OS, parameterized ONLY by the process identity, so a
# named/numeric difference in any assertion below is the spelling and nothing
# else.
# ---------------------------------------------------------------------------

NXOS_NESTED = """\
hostname nx-242-leaf
feature ospf
vrf context TENANT-ROSE
router ospf {proc}
  router-id 10.242.0.1
  vrf TENANT-ROSE
    router-id 10.242.1.1
    area 0.0.0.0 stub
interface Ethernet1/1
  no switchport
  vrf member TENANT-ROSE
  ip address 10.242.10.1/30
  ip router ospf {proc} area 0.0.0.0
"""

IOSXR_NESTED = """\
hostname xr-242-edge
router ospf {proc}
 router-id 10.242.2.1
 area 0
  interface Loopback0
 vrf TENANT-ROSE
  router-id 10.242.3.1
  area 0
   interface GigabitEthernet0/0/0/1
"""

# IOS-XE puts a VRF in the process HEADER and emits no nested ``vrf`` block.
IOS_HEADER_QUALIFIED = """\
hostname ios-242-pe
!
router ospf {proc} vrf TENANT-ROSE
 router-id 10.242.4.1
 network 10.242.20.0 0.0.0.3 area 0
!
"""


def _identities(parsed) -> list[tuple]:
    return [(o.process_id, o.vrf) for o in parsed.ospf_instances]


def _vrf_instance(parsed, vrf="TENANT-ROSE"):
    return next((o for o in parsed.ospf_instances if o.vrf == vrf), None)


_IDENTITY_FIELDS = ("process_id", "object_id", "raw_lines")


def _mask_identity(value):
    """Replace every ``process_id`` ANYWHERE in a dumped model with a sentinel.

    The oracle is "the two spellings agree on everything except the identity
    itself", so the masking has to find the identity wherever it is stored —
    and on IOS-XR it is stored twice, because the per-area
    ``interface_settings`` carry the enclosing process's id down with them. A
    top-level ``pop`` left that nested copy in and the parity assertion failed
    on a difference that WAS the identity; this walk is the correction (found
    by the assertion firing, 2026-11-07).
    """
    if isinstance(value, dict):
        return {
            key: ("<identity>" if key in _IDENTITY_FIELDS else _mask_identity(item))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_mask_identity(item) for item in value]
    return value


def _parity_view(parsed) -> list[dict]:
    """Every OSPF instance's fields with the IDENTITY masked out, at any depth.

    The named/numeric parity oracle: two parses of one construct must produce
    the same list of these, because the only thing that legitimately differs
    between the spellings is the process identity (and the ``object_id`` and
    ``raw_lines`` that quote it).
    """
    return [_mask_identity(inst.model_dump()) for inst in parsed.ospf_instances]


# ---------------------------------------------------------------------------
# Site 1 — the per-VRF instance, on both OSes that inherit the shared helper.
# ---------------------------------------------------------------------------


class TestTheNxosNativeNestedVrfForm:
    """The material site, and the form a Nexus actually emits.

    NX-OS carries two VRF spellings: ``router ospf TAG vrf NAME``
    (header-qualified, which CCR-0239's subclass re-scan covers and which may
    not be emitted by a Nexus at all — no corpus entry, no capture) and
    ``router ospf TAG`` with nested ``vrf NAME`` blocks, which confgraph's own
    call site calls the native form and which is delegated to the shared base.
    CCR-0239 fixed the first; this is the second.
    """

    def test_a_named_process_produces_its_per_vrf_instance(self):
        """DISCRIMINATES. Pre-fix the named parse produced exactly ONE instance,
        ``[('DCFABRIC', None)]`` — the per-VRF instance was absent, so adjacency,
        blast-radius and path verdicts inside that VRF were computed from
        nothing, with no disclosure that a whole routing process was missing."""
        named = NXOSParser(NXOS_NESTED.format(proc="DCFABRIC")).parse()

        assert _identities(named) == [("DCFABRIC", None), ("DCFABRIC", "TENANT-ROSE")]
        assert str(_vrf_instance(named).router_id) == "10.242.1.1"

    def test_the_named_and_numeric_spellings_agree_on_everything_else(self):
        """DISCRIMINATES, and it is the oracle rather than an extra assertion.

        The numeric spelling was never broken, so it is an uncontaminated
        reference: with the identity removed, the two parses must be
        field-for-field identical. A fix that produced the instance but filled
        it differently — a missed area, a dropped redistribute, the VRF name
        read from the wrong token — passes the test above and fails here.
        """
        named = NXOSParser(NXOS_NESTED.format(proc="DCFABRIC")).parse()
        numeric = NXOSParser(NXOS_NESTED.format(proc="7")).parse()

        assert _parity_view(named) == _parity_view(numeric)
        assert [vrf for _pid, vrf in _identities(named)] == [
            vrf for _pid, vrf in _identities(numeric)
        ]

    def test_the_interface_and_the_instance_still_compare_equal(self):
        """GUARD on the equality round-trip, in both spellings.

        Membership is decided by ``==`` between two independently written
        values, so the test that matters is not "what type is it" but "do the
        two sides match". A digit tag must land as ``int`` on BOTH sides and a
        word tag as ``str`` on both; either producer drifting partitions one
        process in two.
        """
        for proc in ("DCFABRIC", "7"):
            parsed = NXOSParser(NXOS_NESTED.format(proc=proc)).parse()
            iface = next(i for i in parsed.interfaces if i.name == "Ethernet1/1")
            for inst in parsed.ospf_instances:
                assert inst.process_id == iface.ospf_process_id
                assert inst.process_id == canonical_process_id(proc)
            assert isinstance(iface.ospf_process_id, int if proc.isdigit() else str)

    def test_the_vrf_instance_body_is_read_in_both_spellings(self):
        """GUARD against a fix that creates an empty shell.

        A named per-VRF instance that exists but carries nothing is the failure
        this item was explicitly warned about: it would replace a configured
        value with a per-OS default and disclose nothing. Both spellings carry
        the sub-block's own router-id and area.
        """
        for proc in ("DCFABRIC", "7"):
            vrf = _vrf_instance(NXOSParser(NXOS_NESTED.format(proc=proc)).parse())
            assert str(vrf.router_id) == "10.242.1.1"
            assert [a.area_id for a in vrf.areas] == ["0"]
            assert vrf.areas[0].area_type == "stub"


class TestADigitLeadingInstanceTag:
    """A tag that STARTS with digits must stay one identity.

    Found by the CCR-0242 validator, 2026-11-10. The process-header pattern set
    tries its numeric arm first, and an unanchored ``\\d+`` prefix-matched
    ``router ospf 100x`` to ``100`` — while the interface walk, which reads the
    whole token, kept ``'100x'``. Two producers, two identities, one process:
    the equality every consumer uses to decide membership saw two processes, so
    the interface was enrolled in neither, and once this item started minting
    per-VRF instances there was a vrf-scoped instance carrying the truncated id
    as well.

    The fix is at the LOCATOR rather than the normalizer: ``\\d+(?=\\s|$)``, so
    the numeric arm matches only when digits are the whole token and a
    digit-leading tag falls through to the tag arm. One pattern set, so all four
    OSes that use it are fixed together. Digit-leading tags are legal NX-OS
    instance tags (documentation-grade, per this file's header).
    """

    def test_a_digit_leading_tag_is_one_identity_everywhere(self):
        """DISCRIMINATES. Pre-fix: instances ``[(100, None), (100, 'TENANT-ROSE')]``
        against an interface holding ``'100x'`` — equal on neither."""
        parsed = NXOSParser(NXOS_NESTED.format(proc="100x")).parse()
        iface = next(i for i in parsed.interfaces if i.name == "Ethernet1/1")

        assert iface.ospf_process_id == "100x"
        assert isinstance(iface.ospf_process_id, str)
        assert _identities(parsed) == [("100x", None), ("100x", "TENANT-ROSE")]
        for inst in parsed.ospf_instances:
            assert inst.process_id == iface.ospf_process_id

    def test_the_digit_leading_tag_agrees_with_a_word_tag_on_everything_else(self):
        """GUARD, and a worked example of why a parity oracle is not enough.

        ``100x`` and ``DCFABRIC`` are both tags, so with the identity masked the
        two parses must be identical — and they **already were** on the pre-fix
        tree, measured. The truncation was self-consistent *inside* the instance
        list (both instances read ``100``), and the mask hides the one field
        that moved, so this oracle could not see the defect at all: it validates
        consistency, not correctness, exactly as the handbook says of
        warm-vs-cold and A-vs-B oracles.

        The discriminator is the test above, which compares the instance
        against the INTERFACE — the second producer, outside this view. Kept
        because it still guards everything the identity is not.
        """
        digit_leading = NXOSParser(NXOS_NESTED.format(proc="100x")).parse()
        word = NXOSParser(NXOS_NESTED.format(proc="DCFABRIC")).parse()

        assert _parity_view(digit_leading) == _parity_view(word)

    def test_a_leading_zero_id_normalizes_the_same_way_on_both_sides(self):
        """GUARD on the claim that actually matters — AGREEMENT, not a spelling.

        ``0042`` is all digits, so ``canonical_process_id`` makes it ``42`` on
        every producer. The test is not that 42 is what a device prints (this
        file claims no such thing); it is that both sides reach the same value,
        so the process is not partitioned. Correct before this fix too, and
        pinned so a future anchor change cannot split it.
        """
        parsed = NXOSParser(NXOS_NESTED.format(proc="0042")).parse()
        iface = next(i for i in parsed.interfaces if i.name == "Ethernet1/1")

        assert iface.ospf_process_id == 42
        assert _identities(parsed) == [(42, None), (42, "TENANT-ROSE")]
        for inst in parsed.ospf_instances:
            assert inst.process_id == iface.ospf_process_id

    def test_a_pure_digit_id_is_still_an_int_on_both_sides(self):
        """GUARD — the control the anchor must not move. A plain numeric process
        still takes the numeric arm and still lands as ``int`` everywhere."""
        parsed = NXOSParser(NXOS_NESTED.format(proc="7")).parse()
        iface = next(i for i in parsed.interfaces if i.name == "Ethernet1/1")

        assert iface.ospf_process_id == 7
        assert isinstance(iface.ospf_process_id, int)
        assert _identities(parsed) == [(7, None), (7, "TENANT-ROSE")]

    def test_the_header_qualified_form_still_matches_the_numeric_arm(self):
        """GUARD on the anchor's boundary case. ``router ospf 1 vrf X`` has a
        token-final digit id followed by whitespace, so ``(?=\\s|$)`` must still
        accept it — an anchor written as ``$`` alone would have broken every
        header-qualified process."""
        parsed = IOSParser(IOS_HEADER_QUALIFIED.format(proc="1")).parse()

        assert _identities(parsed) == [(1, "TENANT-ROSE")]


class TestTheIOSXRNamedProcess:
    """The other inheriting call site. Named processes are the norm on IOS-XR,
    and this path had never been exercised with a tag."""

    def test_a_named_xr_process_produces_its_per_vrf_instance(self):
        """DISCRIMINATES. Pre-fix: ``[('CORE-A', None)]`` — one instance, the
        VRF's absent."""
        named = IOSXRParser(IOSXR_NESTED.format(proc="CORE-A")).parse()

        assert _identities(named) == [("CORE-A", None), ("CORE-A", "TENANT-ROSE")]
        assert str(_vrf_instance(named).router_id) == "10.242.3.1"

    def test_the_named_and_numeric_xr_spellings_agree_on_everything_else(self):
        """DISCRIMINATES — the parity oracle on XR, whose per-VRF builder is its
        own override (nested ``area > interface``), so the agreement is a
        separate fact from the NX-OS one and not implied by it."""
        named = IOSXRParser(IOSXR_NESTED.format(proc="CORE-A")).parse()
        numeric = IOSXRParser(IOSXR_NESTED.format(proc="7")).parse()

        assert _parity_view(named) == _parity_view(numeric)

    def test_the_xr_vrf_instance_carries_its_nested_area_interface(self):
        """GUARD against the empty shell on XR too — the VRF's area and its
        nested interface, in both spellings."""
        for proc in ("CORE-A", "7"):
            vrf = _vrf_instance(IOSXRParser(IOSXR_NESTED.format(proc=proc)).parse())
            assert [a.area_id for a in vrf.areas] == ["0"]
            assert vrf.areas[0].interfaces == ["GigabitEthernet0/0/0/1"]

    def test_the_nested_interface_settings_carry_the_same_identity(self):
        """GUARD on the equality round-trip at XR's SECOND storage point.

        XR writes the process identity twice — on the instance and again on
        each area's ``interface_settings`` entry — and both are read by
        consumers that compare identities. The parity oracle above masks the
        identity, so this is where the propagation itself is asserted: the
        named instance's nested copy is the tag, not ``None`` and not a
        stringified something-else.
        """
        for proc in ("CORE-A", "7"):
            parsed = IOSXRParser(IOSXR_NESTED.format(proc=proc)).parse()
            for inst in parsed.ospf_instances:
                for area in inst.areas:
                    for settings in area.interface_settings.values():
                        assert settings.process_id == inst.process_id
                        assert settings.process_id == canonical_process_id(proc)


# ---------------------------------------------------------------------------
# Site 2 — the header-qualified VRF.
# ---------------------------------------------------------------------------


class TestTheHeaderQualifiedVrf:
    def test_a_named_process_keeps_its_header_vrf_qualifier(self):
        """DISCRIMINATES. Pre-fix the named spelling parsed ``vrf=None`` — the
        process read as a default-VRF process, so its networks were attributed
        to the global table."""
        named = IOSParser(IOS_HEADER_QUALIFIED.format(proc="UNDERLAY")).parse()

        assert _identities(named) == [("UNDERLAY", "TENANT-ROSE")]

    def test_the_header_qualified_spellings_agree_on_everything_else(self):
        """DISCRIMINATES — the parity oracle for this site."""
        named = IOSParser(IOS_HEADER_QUALIFIED.format(proc="UNDERLAY")).parse()
        numeric = IOSParser(IOS_HEADER_QUALIFIED.format(proc="1")).parse()

        assert _parity_view(named) == _parity_view(numeric)

    def test_the_header_form_produces_no_duplicate_vrf_instance(self):
        """GUARD. The header form emits no nested ``vrf`` block, so widening the
        nested walk must not make the same VRF appear twice — exactly one
        instance, for both spellings."""
        for proc in ("UNDERLAY", "1"):
            parsed = IOSParser(IOS_HEADER_QUALIFIED.format(proc=proc)).parse()
            assert len(parsed.ospf_instances) == 1


# ---------------------------------------------------------------------------
# Site 3 — Change-IR operation provenance.
# ---------------------------------------------------------------------------


class TestTheEnrollmentLineProvenance:
    """Semantics-neutral by the base's own contract — path and value were always
    correct — but a generated change script that quotes ``source_line`` back to
    an operator quoted the wrong line.
    """

    @staticmethod
    def _op(parsed, field: str):
        return next(
            o
            for o in (parsed.native_change_ops or [])
            if tuple(o.path) == ("interface", "Ethernet1/1", field)
        )

    def test_a_named_enrollment_op_names_the_enrollment_line(self):
        """DISCRIMINATES. Pre-fix the op carried ``'interface Ethernet1/1'`` —
        the block-header fallback — while the ``ospf_area`` op on the SAME line
        already quoted it correctly. That asymmetry is the whole defect."""
        parsed = NXOSParser(NXOS_NESTED.format(proc="DCFABRIC")).parse()
        pid_op = self._op(parsed, "ospf_process_id")
        area_op = self._op(parsed, "ospf_area")

        assert pid_op.source_line == "ip router ospf DCFABRIC area 0.0.0.0"
        assert (pid_op.source_line, pid_op.line_no) == (
            area_op.source_line,
            area_op.line_no,
        )

    def test_the_numeric_enrollment_op_is_unchanged(self):
        """GUARD — correct before and after. The numeric spelling always matched
        the digit-only pattern, so this is the row that proves the widening did
        not move the case that already worked."""
        parsed = NXOSParser(NXOS_NESTED.format(proc="7")).parse()
        pid_op = self._op(parsed, "ospf_process_id")

        assert pid_op.source_line == "ip router ospf 7 area 0.0.0.0"


# ---------------------------------------------------------------------------
# Plain IOS — digit-only was never broken there, and must stay unmoved.
# ---------------------------------------------------------------------------


class TestPlainIOSIsUnchanged:
    """This is a shared-base change, so the OS that never had the defect is
    part of the acceptance, not an afterthought.

    One correction found by running this class against the pre-fix tree, worth
    recording because it is easy to assume otherwise: **plain IOS/IOS-XE never
    builds a nested-VRF OSPF instance at all.** ``_parse_ospf_vrf_instances``
    lives in the shared base but is CALLED only by the NX-OS and IOS-XR
    ``parse_ospf`` overrides — IOS-XE expresses a per-VRF process as
    ``router ospf N vrf NAME`` in the header, which produces no nested block,
    which is also why there is no double-count. So the IOS claim below is about
    the header form; a nested ``vrf`` sub-block is not an IOS-XE construct and
    this change gives it no instance on IOS, before or after.
    """

    IOS_NUMERIC = """\
hostname ios-242-core
!
router ospf 7
 router-id 10.242.5.1
 network 10.242.30.0 0.0.0.3 area 0
!
router ospf 8 vrf TENANT-ROSE
 router-id 10.242.6.1
!
"""

    def test_the_numeric_header_forms_still_parse(self):
        """GUARD — the global process and the header-qualified per-VRF one, both
        numeric, both unmoved."""
        parsed = IOSParser(self.IOS_NUMERIC).parse()

        assert _identities(parsed) == [(7, None), (8, "TENANT-ROSE")]
        assert str(_vrf_instance(parsed).router_id) == "10.242.6.1"

    def test_a_digit_process_id_is_still_an_int_everywhere(self):
        """GUARD on the consolidation. Four producers carried the
        digit-or-verbatim rule inline and now share ``canonical_process_id``;
        if any of them had started storing ``"7"`` instead of ``7``, the
        equality every consumer relies on would break silently."""
        parsed = IOSParser(self.IOS_NUMERIC).parse()

        for inst in parsed.ospf_instances:
            assert isinstance(inst.process_id, int)
        assert {i.process_id for i in parsed.ospf_instances} == {7, 8}

    def test_a_nested_vrf_sub_block_gives_IOS_no_instance_either_way(self):
        """GUARD on the correction in this class's docstring, so the next reader
        does not have to rediscover it from a failing assertion. Measured
        identical on the pre-fix tree."""
        nested = """\
hostname ios-242-edge
!
router ospf 7
 vrf TENANT-ROSE
  router-id 10.242.6.1
!
"""
        parsed = IOSParser(nested).parse()

        assert _identities(parsed) == [(7, None)]
