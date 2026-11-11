"""CCR-0246 — statements inside an NX-OS OSPF ``vrf`` sub-block, disclosed then parsed.

NX-OS scopes a routing process to a VRF with a ``vrf <name>`` sub-block under
``router ospf <tag>``. The parser already modelled the shape — it emits a second
``OSPFConfig`` carrying ``vrf='RED'`` — so this was never an unrecognised
construct. But the sub-block's BODY was discarded: ``router-id`` and ``area``
were read, and every per-process scalar was dropped **with nothing in
``unrecognized_blocks``**, because the sub-block header ``vrf`` is a listed known
child of ``router ospf`` and claiming the header silenced everything under it.
A config carrying a nested ``auto-cost reference-bandwidth 20000`` and one
carrying no nested line at all parsed to byte-identical models.

Two halves, two phases, both here:

* **disclosure** — any line inside the sub-block the walk does not digest is
  emitted as an ``UnrecognizedBlock`` naming both scopes
  (``router ospf 88 > vrf TENANT-IRIS > <line>``), so a dropped routing
  statement can never again be invisible;
* **parsing** — ``passive-interface default``, ``shutdown``,
  ``max-metric router-lsa``, ``auto-cost reference-bandwidth`` and
  ``log-adjacency-changes [detail]`` are read into the vrf-scoped instance.

**The oracle is the SCOPE EQUIVALENCE, not a value.** Every parsing claim below
writes the identical statement twice — once in the sub-block, once at process
level — and asserts the two instances carry it identically. A value assertion
alone would only state that the author of the fix and the author of the test
agreed. The method matters because one of the five defeats the obvious probe:
``log_adjacency_changes`` has model default ``True``, so comparing "statement
present" against "statement absent" cannot distinguish parsed from discarded
for that field (CCR-0246's own first measurement got it wrong this way). Its
twin is the only honest oracle, and the ``detail`` qualifier is the part that
was actually lost.

**Evidence grade — stated plainly, per owner decision 2026-11-07.** The NX-OS
OSPF ``vrf`` sub-block syntax is **documentation-derived, not device-verified**:
``syntax-corpus/nxos/ospf.yaml`` carries entries for the ``router ospf`` and
``interface`` contexts only and has no ``vrf`` sub-block entry, and there is no
capture of this scope on any device. confgraph's own source comment calling the
nested form "NX-OS native" is code, not device evidence, and is not cited as
such. What IS measured here is the parser's behaviour: every pre-fix value
quoted in a docstring below was observed by running the same fixture against the
pre-fix tree (``confgraph`` ``5a4998f``).

The individual statements are better attested than the scope that holds them:
``default-information originate always`` under ``router ospf`` is
``verified-capture`` on a Nexus 9000v 10.5(5) (``syntax-corpus/nxos/ospf.yaml``,
entry ``redistribute-and-default-information``), and ``auto-cost
reference-bandwidth`` / ``max-metric router-lsa`` / ``shutdown`` /
``passive-interface default`` are documentation-grade at process level and are
the spellings this repo's fixtures already use. Their validity *inside the
``vrf`` sub-block* is the documentation-derived part.

Each test says whether it **DISCRIMINATES** (fails on the pre-fix tree, with the
pre-fix value quoted) or is a **GUARD** (passes on both trees, and exists so a
later change cannot quietly move it).
"""

from confgraph.parsers.eos_parser import EOSParser
from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.iosxr_parser import IOSXRParser
from confgraph.parsers.nxos_parser import NXOSParser

# ---------------------------------------------------------------------------
# Fixtures. One device shape; the only variable is which lines sit inside the
# `vrf` sub-block and which sit at process level, so any difference between a
# pair of instances is the SCOPE and nothing else.
# ---------------------------------------------------------------------------

_PROC = 88
_VRF = "TENANT-IRIS"


def nxos(*, nested: tuple[str, ...] = (), process: tuple[str, ...] = ()) -> str:
    """A Nexus with one OSPF process, one ``vrf`` sub-block and two interfaces.

    *nested* lines go inside ``vrf TENANT-IRIS``; *process* lines go at process
    level beside it. Ethernet1/1 is a VRF member, Ethernet1/2 is not, so the
    default-VRF scope always has its own interface to speak for.
    """
    nested_body = "".join(f"    {line}\n" for line in nested)
    process_body = "".join(f"  {line}\n" for line in process)
    return (
        "hostname nx-246-iris\n"
        "feature ospf\n"
        f"vrf context {_VRF}\n"
        f"router ospf {_PROC}\n"
        "  router-id 10.246.0.1\n"
        f"{process_body}"
        f"  vrf {_VRF}\n"
        f"{nested_body}"
        "interface Ethernet1/1\n"
        "  no switchport\n"
        f"  vrf member {_VRF}\n"
        "  bandwidth 1000000\n"
        "  ip address 10.246.10.1/30\n"
        f"  ip router ospf {_PROC} area 0.0.0.0\n"
        "interface Ethernet1/2\n"
        "  no switchport\n"
        "  bandwidth 1000000\n"
        "  ip address 10.246.11.1/30\n"
        f"  ip router ospf {_PROC} area 0.0.0.0\n"
    )


def _parsed(**kwargs):
    return NXOSParser(nxos(**kwargs)).parse()


def _vrf_instance(parsed):
    return next(o for o in parsed.ospf_instances if o.vrf == _VRF)


def _default_instance(parsed):
    return next(o for o in parsed.ospf_instances if o.vrf is None)


def _disclosures(parsed) -> list[str]:
    return [b.block_header for b in parsed.unrecognized_blocks]


def _sub_block_disclosures(parsed) -> list[str]:
    marker = f"vrf {_VRF} > "
    return [h for h in _disclosures(parsed) if marker in h]


# ---------------------------------------------------------------------------
# The disclosure half. A dropped line must be visible as dropped.
# ---------------------------------------------------------------------------


class TestTheSubBlockBodyIsDisclosed:
    """Before this, the sub-block's body was outside every disclosure walk.

    The positive child-line collector reads DIRECT children of a claimed
    top-level block, by documented design, so a line two levels down was a
    grandchild and invisible to it — while the registry's ``^vrf\\b`` entry
    claimed the sub-block header and reported the scope as understood. Two
    fail-open layers meeting at the same line.
    """

    def test_an_undigested_sub_block_statement_is_disclosed(self):
        """DISCRIMINATES. Pre-fix: ``unrecognized_blocks == []``.

        ``default-information originate always`` is the durable probe: it is a
        real NX-OS OSPF statement (``verified-capture`` at process level, see the
        module docstring) that this change does **not** teach the sub-block walk
        to read, so it must still disclose after the parsing half lands. A probe
        written against a statement the same change starts parsing would stop
        testing disclosure the moment the second half shipped.
        """
        parsed = _parsed(nested=("default-information originate always",))

        assert _sub_block_disclosures(parsed) == [
            "router ospf 88 > vrf TENANT-IRIS > default-information originate always"
        ]

    def test_the_auto_cost_silent_drop_probe(self):
        """DISCRIMINATES. CCR-0246's headline measurement, reproduced exactly.

        Pre-fix, these two configs — one with a nested ``auto-cost
        reference-bandwidth 20000``, one with nothing inside the sub-block —
        parsed to BYTE-IDENTICAL models, with ``unrecognized_blocks == []`` in
        both. A configured reference bandwidth had been discarded and no channel
        said so.

        Both halves of that sentence have moved, and this test records the end
        state rather than the intermediate one: the value is READ (the parsing
        half), so the two models now differ in the field itself and the line is
        no longer disclosed — a consumed line must never be reported as unread.
        At the disclosure half alone this test asserted the complement (models
        still equal, one disclosure row), which is what made it the red probe
        for that commit.
        """
        with_stmt = _parsed(nested=("auto-cost reference-bandwidth 20000",))
        without = _parsed()

        assert _vrf_instance(with_stmt).auto_cost_reference_bandwidth == 20000
        assert _vrf_instance(without).auto_cost_reference_bandwidth is None
        assert _disclosures(with_stmt) == []
        assert _disclosures(without) == []

    def test_the_disclosure_names_the_process_and_the_vrf_scope(self):
        """DISCRIMINATES. The header is the whole value of the disclosure.

        A bare ``default-information originate always`` would tell an operator
        that a line was lost without saying which of a multi-tenant device's
        per-VRF processes lost it. Both scopes appear, in order, and the raw line
        is carried verbatim.
        """
        parsed = _parsed(nested=("default-information originate always",))
        block = next(
            b for b in parsed.unrecognized_blocks if "default-information" in b.block_header
        )

        assert block.block_header.startswith(f"router ospf {_PROC} > vrf {_VRF} > ")
        assert block.raw_lines == ["    default-information originate always"]

    def test_the_statement_absent_discloses_nothing(self):
        """GUARD on the other direction — no statement, no disclosure, on both
        trees. Without this the test above could pass on a walk that disclosed
        the sub-block header itself on every device that has one."""
        assert _disclosures(_parsed()) == []

    def test_the_digested_sub_block_statements_are_not_disclosed(self):
        """GUARD on PRECISION. ``router-id``, ``area`` and ``redistribute`` are
        read by the sub-block walk, so disclosing them would be noise — and
        noise is what makes a disclosure channel get ignored.

        Passes pre-fix too (nothing was disclosed at all then); it exists so the
        registry cannot later be widened into flagging consumed lines.
        """
        parsed = _parsed(
            nested=(
                "router-id 10.246.0.2",
                "area 0.0.0.0 stub",
                "redistribute bgp 65246 route-map RM_IRIS",
            )
        )

        assert _disclosures(parsed) == []
        vrf = _vrf_instance(parsed)
        assert str(vrf.router_id) == "10.246.0.2"
        assert [a.area_id for a in vrf.areas] == ["0"]
        assert len(vrf.redistribute) == 1

    def test_the_process_level_scope_is_untouched(self):
        """GUARD — identical on both trees. The same statement at process level
        is consumed by the process walk and was never the defect; a sub-block
        descent that also re-flagged the parent's own children would show up
        here."""
        parsed = _parsed(process=("default-information originate always",))

        assert _disclosures(parsed) == []
        assert _default_instance(parsed).default_information_originate is True

    def test_a_nested_negation_was_already_disclosed_and_still_is(self):
        """GUARD on the neighbouring channel. ``no`` lines at any depth belong to
        the fail-closed negation walk (CCR-0203), which already descended into
        sub-blocks, so the positive descent added here must not double-report
        them."""
        parsed = _parsed(nested=("no default-information originate",))
        headers = [h for h in _disclosures(parsed) if "default-information" in h]

        assert len(headers) == 1
        assert headers[0].endswith("> no default-information originate")


# ---------------------------------------------------------------------------
# The parsing half. Each claim is one statement written twice — once in the
# sub-block, once at process level — and the oracle is that the two instances
# carry it IDENTICALLY. Each test also asserts the statement does NOT leak into
# the other scope's instance, which a shared walk applied to the wrong block
# would show up as.
# ---------------------------------------------------------------------------


class TestTheSubBlockScalarsParse:
    """Four statements were discarded in VRF scope and one lost its qualifier,
    so a per-VRF process that was shut, drained or hardened modelled as a
    plain running process with default timers.

    ``router-id`` and ``area`` already worked, which is what makes every row
    here a SCOPE asymmetry rather than a reading of a vendor PDF: the parser
    demonstrably understands the statement and loses it only in this scope.
    """

    def _pair(self, statement: str):
        """The same line in both scopes: (nested instance, process-level twin)."""
        return (
            _vrf_instance(_parsed(nested=(statement,))),
            _default_instance(_parsed(process=(statement,))),
        )

    def test_auto_cost_reference_bandwidth_matches_its_twin(self):
        """DISCRIMINATES. Pre-fix: vrf-scoped None, process-level 20000."""
        nested, twin = self._pair("auto-cost reference-bandwidth 20000")

        assert nested.auto_cost_reference_bandwidth == 20000
        assert (
            nested.auto_cost_reference_bandwidth == twin.auto_cost_reference_bandwidth
        )

    def test_shutdown_matches_its_twin(self):
        """DISCRIMINATES. Pre-fix: vrf-scoped False — an administratively down
        per-VRF process modelled as running."""
        nested, twin = self._pair("shutdown")

        assert nested.shutdown is True
        assert nested.shutdown == twin.shutdown

    def test_passive_interface_default_matches_its_twin(self):
        """DISCRIMINATES. Pre-fix: vrf-scoped False.

        The worst of the five: this is the standard hardening idiom — suppress
        adjacencies everywhere, exempt named uplinks — so dropping it makes the
        simulator report an adjacency, and reachability, across a link where the
        hardware forms none. The engine-side consequence is asserted in
        confgraph-entrp (``test_ccr0243_ospf_cost_membership_gate.py``), which
        is where the adjacency predicate lives.
        """
        nested, twin = self._pair("passive-interface default")

        assert nested.passive_interface_default is True
        assert nested.passive_interface_default == twin.passive_interface_default

    def test_max_metric_router_lsa_matches_its_twin(self):
        """DISCRIMINATES. Pre-fix: vrf-scoped False — a maintenance-window drain
        on a per-VRF process showed no drain at all."""
        nested, twin = self._pair("max-metric router-lsa")

        assert nested.max_metric_router_lsa is True
        assert nested.max_metric_router_lsa == twin.max_metric_router_lsa

    def test_the_max_metric_on_startup_operand_matches_its_twin(self):
        """DISCRIMINATES. The operand too, not only the flag — a boolean-only
        fix would satisfy the test above and still lose the timer."""
        nested, twin = self._pair("max-metric router-lsa on-startup 600")

        assert nested.max_metric_router_lsa is True
        assert nested.max_metric_router_lsa_on_startup == 600
        assert (
            nested.max_metric_router_lsa_on_startup
            == twin.max_metric_router_lsa_on_startup
        )

    def test_the_log_adjacency_changes_detail_qualifier_matches_its_twin(self):
        """DISCRIMINATES on the qualifier, which is the real defect here.

        CCR-0246's first probe called this statement dropped by comparing the
        field with the line present against the field with it absent — and
        ``log_adjacency_changes`` has model default ``True``, so that comparison
        cannot distinguish parsed from discarded. Measured against its twin
        instead, the keyword was being read all along and only ``detail`` was
        lost: vrf-scoped ``detail=False`` against a process-level ``True``.
        """
        nested, twin = self._pair("log-adjacency-changes detail")

        assert nested.log_adjacency_changes_detail is True
        assert nested.log_adjacency_changes_detail == twin.log_adjacency_changes_detail
        assert nested.log_adjacency_changes == twin.log_adjacency_changes is True

    def test_no_log_adjacency_statement_reads_the_same_in_both_scopes(self):
        """DISCRIMINATES, and pins a KNOWN WART symmetrically.

        ``log_adjacency_changes`` has model default ``True`` and parser-absence
        ``False`` — the documented trap the merger's creation seed handles by
        name. The vrf-scoped instance used to skip the walk entirely and so
        carried the model default ``True`` while its process-level twin carried
        ``False`` for the identical (absent) input: the two scopes disagreed
        about a device that says nothing. Both now read ``False``.

        This is a deliberate movement, not a fix of the wart: the engine's
        merger already assumes parser-absence ``False`` for every instance, so
        the vrf scope was the inconsistent one. Whoever corrects the wart must
        move both scopes together, and will fail here if they move one.
        """
        parsed = _parsed()

        assert _vrf_instance(parsed).log_adjacency_changes is False
        assert _default_instance(parsed).log_adjacency_changes is False

    def test_a_nested_statement_does_not_leak_into_the_default_vrf_instance(self):
        """GUARD on the scope boundary, the failure mode a shared extraction
        invites. All five statements nested at once: the default-VRF instance on
        the same device must read every one of them as unset.

        Passes pre-fix (nothing was read at all then), and would fail on a walk
        that descended from the process block into the sub-block.
        """
        parsed = _parsed(
            nested=(
                "passive-interface default",
                "shutdown",
                "max-metric router-lsa",
                "auto-cost reference-bandwidth 20000",
                "log-adjacency-changes detail",
            )
        )
        default = _default_instance(parsed)

        assert default.passive_interface_default is False
        assert default.shutdown is False
        assert default.max_metric_router_lsa is False
        assert default.auto_cost_reference_bandwidth is None
        assert default.log_adjacency_changes_detail is False

    def test_a_process_level_statement_does_not_leak_into_the_vrf_instance(self):
        """GUARD on the other direction, and the reason the engine needed this
        fix at all: a per-VRF process inherits none of these from the process
        scope, so reading the parent's value would be a different wrong answer
        from reading none. All five at process level; the vrf instance unset."""
        parsed = _parsed(
            process=(
                "passive-interface default",
                "shutdown",
                "max-metric router-lsa",
                "auto-cost reference-bandwidth 100000",
                "log-adjacency-changes detail",
            )
        )
        vrf = _vrf_instance(parsed)

        assert vrf.passive_interface_default is False
        assert vrf.shutdown is False
        assert vrf.max_metric_router_lsa is False
        assert vrf.auto_cost_reference_bandwidth is None
        assert vrf.log_adjacency_changes_detail is False

    def test_the_now_digested_statements_stop_disclosing(self):
        """DISCRIMINATES against the disclosure half alone. A statement the walk
        reads must not also be reported as unread — a channel that cries wolf
        about consumed lines is a channel operators learn to ignore."""
        parsed = _parsed(
            nested=(
                "passive-interface default",
                "shutdown",
                "max-metric router-lsa",
                "auto-cost reference-bandwidth 20000",
                "log-adjacency-changes detail",
            )
        )

        assert _disclosures(parsed) == []

    def test_an_undigested_statement_beside_the_five_still_discloses(self):
        """DISCRIMINATES against the disclosure half alone, where all six of
        these lines were reported — and against the parsing half alone, where
        none would be. With the five parsed statements in the sub-block AND one
        this change does not teach it, exactly the undigested line is
        disclosed: the two halves coexist rather than one superseding the
        other."""
        parsed = _parsed(
            nested=(
                "passive-interface default",
                "shutdown",
                "max-metric router-lsa",
                "auto-cost reference-bandwidth 20000",
                "log-adjacency-changes detail",
                "default-information originate always",
            )
        )

        assert _sub_block_disclosures(parsed) == [
            "router ospf 88 > vrf TENANT-IRIS > default-information originate always"
        ]

    def test_the_per_interface_passive_form_is_not_silenced_by_the_default_form(self):
        """GUARD on registry PRECISION. The sub-block entry lists
        ``passive-interface default`` exactly, not ``passive-interface`` —
        ``passive-interface Ethernet1/1`` is NOT read into the vrf-scoped
        instance, so it must still disclose. Listing the broader pattern would
        have silenced a per-interface suppression, which is the same silent drop
        one statement over."""
        parsed = _parsed(nested=("passive-interface Ethernet1/1",))

        assert _sub_block_disclosures(parsed) == [
            "router ospf 88 > vrf TENANT-IRIS > passive-interface Ethernet1/1"
        ]
        assert _vrf_instance(parsed).passive_interfaces == []


class TestTheKnownListIsScopedToTheOSThatDigests:
    """A known-child entry is a CLAIM THAT THE LINE IS DIGESTED, so it belongs
    to the parser that digests it and to no other.

    ``_parse_ospf_vrf_instances`` lives in the shared IOS base but is called
    only by the NX-OS and IOS-XR ``parse_ospf`` overrides. IOS/IOS-XE and EOS
    express a per-VRF process in the process HEADER, so a nested ``vrf``
    sub-block yields no instance there and nothing inside it is read. Round 1
    of this item registered the digested vocabulary on the IOS base, where
    every subclass inherited it — so EOS silenced a nested ``shutdown`` while
    disclosing an unknown knob on the line below it: pre-existing silence
    turned into a NEW false claim of comprehension, on the one feature whose
    entire purpose is honest disclosure. Found by the CCR-0246 validator,
    2026-11-10.

    The vocabulary now sits on NX-OS. These tests are the scope asymmetry
    itself: one config, three parsers, each asserting BOTH halves — whether the
    line was read, and whether it was disclosed. The two must never disagree.
    """

    SUB = """\
hostname box-246-scope
feature ospf
vrf context COBALT
router ospf 13
  vrf COBALT
    shutdown
    auto-cost reference-bandwidth 20000
    nonsense-knob 3
"""

    def _parse_with(self, cls):
        """Return (the vrf-scoped instance or None, the SUB-BLOCK's disclosures).

        Filtered to the sub-block deliberately: on IOS and EOS the fixture's
        ``feature ospf`` and ``vrf context COBALT`` are themselves unrecognized
        top-level lines, correctly — they are NX-OS constructs — and counting
        them here would make this test about OS detection rather than about the
        scope of a known-child list.
        """
        parsed = cls(self.SUB).parse()
        vrf = next((o for o in parsed.ospf_instances if o.vrf == "COBALT"), None)
        marker = "vrf COBALT > "
        tails = [
            b.block_header.split(marker, 1)[1]
            for b in parsed.unrecognized_blocks
            if marker in b.block_header
        ]
        return vrf, tails

    def test_nxos_digests_the_scalars_and_therefore_stays_silent(self):
        """GUARD — unchanged from round 1, and the half that must NOT move. NX-OS
        reads both scalars, so silencing them is honest; only the unknown knob
        discloses."""
        vrf, tails = self._parse_with(NXOSParser)

        assert vrf is not None
        assert (vrf.shutdown, vrf.auto_cost_reference_bandwidth) == (True, 20000)
        assert tails == ["nonsense-knob 3"]

    def test_eos_digests_nothing_and_therefore_discloses_everything(self):
        """DISCRIMINATES against round 1, where EOS silenced ``shutdown`` and
        ``auto-cost reference-bandwidth 20000`` and disclosed only
        ``nonsense-knob 3`` — a config whose per-VRF process is administratively
        down, reported as fully understood.

        EOS builds no vrf-scoped instance at all, so all three lines are
        dropped and all three must say so.
        """
        vrf, tails = self._parse_with(EOSParser)

        assert vrf is None, "EOS builds no nested-VRF instance; if it ever does, move the vocabulary"
        assert tails == [
            "shutdown",
            "auto-cost reference-bandwidth 20000",
            "nonsense-knob 3",
        ]

    def test_ios_digests_nothing_and_therefore_discloses_everything(self):
        """DISCRIMINATES against round 1, same mechanism as EOS — IOS inherits
        the same registry and the same (uncalled) builder."""
        vrf, tails = self._parse_with(IOSParser)

        assert vrf is None
        assert tails == [
            "shutdown",
            "auto-cost reference-bandwidth 20000",
            "nonsense-knob 3",
        ]

    def test_the_claim_and_the_parse_agree_on_every_os(self):
        """The invariant behind the three tests above, stated once: a line is
        silenced if and only if an instance exists to have read it. This is what
        a future per-OS registry edit has to keep true."""
        for cls in (NXOSParser, EOSParser, IOSParser):
            vrf, tails = self._parse_with(cls)
            digested = {"shutdown", "auto-cost reference-bandwidth 20000"}
            silenced = digested - set(tails)
            assert silenced == (digested if vrf is not None else set()), cls.__name__

    def test_nxos_carries_over_every_base_sub_block_entry(self):
        """GUARD on the composition, mechanically. NX-OS REPLACES the base's
        OSPF entry rather than appending, so a second (non-OSPF) entry added to
        the base later must still reach NX-OS. Pinning the key sets makes that a
        test failure instead of a silent per-OS hole."""
        base_keys = {(blk, sub) for blk, sub, _ in IOSParser._KNOWN_SUB_BLOCK_PATTERNS}
        nxos_keys = {(blk, sub) for blk, sub, _ in NXOSParser._KNOWN_SUB_BLOCK_PATTERNS}

        assert base_keys == nxos_keys
        assert IOSParser._KNOWN_SUB_BLOCK_PATTERNS != NXOSParser._KNOWN_SUB_BLOCK_PATTERNS


class TestIOSXROptsOutOfSubBlockDisclosure:
    """GUARD on a deliberate per-OS decision, so it is a recorded choice rather
    than an oversight someone re-discovers.

    IOS-XR disables child-line disclosure wholesale (``_KNOWN_CHILD_PATTERNS =
    []``) because its block bodies are nested differently from IOS — interfaces
    under OSPF areas, ``address-family`` bodies — so the inherited IOS lists
    would false-flag consumed lines. The same reasoning applies one level down,
    and more strongly: an XR ``vrf`` sub-block holds ``area`` sub-blocks with
    their own ``interface`` children, all of them consumed by the XR area walk.
    XR therefore opts out of the sub-block registry too, and its per-VRF scalar
    gap (its own override reads neither ``auto-cost`` nor ``shutdown`` in VRF
    scope) is recorded as a follow-up rather than fixed here with NX-OS
    spellings that XR does not emit.
    """

    XR = """\
hostname xr-246
router ospf 7
 router-id 10.246.1.1
 area 0
  interface Loopback0
 vrf TENANT-IRIS
  router-id 10.246.1.2
  auto-cost reference-bandwidth 20000
  area 0
   interface GigabitEthernet0/0/0/1
"""

    def test_an_xr_vrf_sub_block_discloses_nothing(self):
        parsed = IOSXRParser(self.XR).parse()

        assert parsed.unrecognized_blocks == []
        assert {(o.process_id, o.vrf) for o in parsed.ospf_instances} == {
            (7, None),
            (7, "TENANT-IRIS"),
        }
