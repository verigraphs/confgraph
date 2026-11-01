"""CCR-0239 — NX-OS named OSPF instance tags must enroll interfaces.

NX-OS spells its OSPF process identifier as an *instance tag*, which is a word
and not only a number (``router ospf UNDERLAY``), and data-center fabrics name
their instances as a matter of routine. The process header was parsed correctly
— the shared base walk keeps a tag verbatim and types ``process_id`` as
``int | str`` — but both NX-OS interface-enrollment scans accepted digits only,
so **no interface on a named-instance device was ever enrolled in OSPF**, and
nothing disclosed it: the enrollment line is claimed, so it never surfaced as an
UnrecognizedBlock either. Such a device contributed zero OSPF adjacencies behind
a green verdict.

The gap was therefore an asymmetry between two spellings of one construct, which
is why most tests below parse the SAME topology twice — once named, once numeric
— and assert the two agree on everything but the identity itself.

Fixing the parser is also the first time a string process identity reaches the
membership tests that compare identities for EQUALITY. There are two such tests
and this file reaches only ONE of them: this parser's own passive-default walk in
``BaseParser.parse`` is exercised here (CCR-0222's per-interface passive override
still resolves on a *named* instance), and the adjacency assertion below runs
through ``confgraph.topology.graph``, which is a presence check.

The engine's ``_ospf_member`` — the other equality test, and the one that had
never executed with a string operand — is NOT pinned by this file, which imports
nothing from ``confgraph_entrp``. That behaviour was verified by execution during
CCR-0239 (pre-fix: no adjacency; post-fix: identical to the numeric control), but
a committed engine-side regression test is a SCHEDULED FOLLOW-UP, not something
this file delivers. Do not read the adjacency test below as covering it.

Syntax: ``ip router ospf <tag> area <id>`` is device-emitted with a named tag on
a Nexus 9000v 10.3(8) (``syntax-corpus/captures/nxos/2026-07-15-n9kv-10.3.8-
shared-box-probes.txt``, readback-confirmed twice). The construct also carries a
``verified-capture`` corpus entry (``syntax-corpus/nxos/ospf.yaml``,
``interface-ospf-settings``) — but note that entry sources a DIFFERENT capture
(10.5(5), with a generic ``<proc>`` placeholder); the named tag itself comes from
the 10.3(8) capture above. Two captures, two facts, not one. The ``router ospf <instance-tag>`` header is
documentation-grade device truth per CCR-0239 (Cisco Nexus 9000 OSPF
configuration guide), accepted for this batch by owner decision.
"""

from confgraph.parsers.nxos_parser import NXOSParser
from confgraph.topology.graph import TopologyGraphBuilder
from confgraph.utils.ospf import canonical_process_id


# ---------------------------------------------------------------------------
# Fixtures. One leaf shape, parameterized only by the process identity, so a
# named/numeric difference in any assertion is the spelling and nothing else.
# Interface cost is pinned explicitly: the per-OS reference-bandwidth default
# that would otherwise decide a Nexus link's cost is moving under a sibling
# work item, and this file is not about cost.
# ---------------------------------------------------------------------------

LEAF_A = """\
hostname nx-leaf-1
feature ospf
!
interface Ethernet1/1
  description p2p to nx-leaf-2
  no switchport
  ip address 10.30.1.1/30
  ip router ospf {proc} area 0.0.0.0
  ip ospf cost 15
  no shutdown
!
router ospf {proc}
  router-id 10.30.255.1
!
"""

LEAF_B = """\
hostname nx-leaf-2
feature ospf
!
interface Ethernet1/1
  description p2p to nx-leaf-1
  no switchport
  ip address 10.30.1.2/30
  ip router ospf {proc} area 0.0.0.0
  ip ospf cost 15
  no shutdown
!
router ospf {proc}
  router-id 10.30.255.2
!
"""

# A named instance inside a VRF, header-qualified form, with a NON-zero dotted
# quad area so the CCR-0227 canonicalisation is exercised on something whose
# decimal spelling differs from its own first octet. Note the interface's
# enrollment line carries NO vrf keyword — the interface's VRF comes from
# `vrf member`, and `ip router ospf <tag> area <id>` is the whole enrollment
# grammar (the captured form).
VRF_LEAF = """\
hostname nx-border-1
feature ospf
!
vrf context TENANTRED
!
interface Ethernet1/4
  no switchport
  vrf member TENANTRED
  ip address 10.30.4.1/30
  ip router ospf {proc} area 0.0.0.9
  no shutdown
!
router ospf {proc} vrf TENANTRED
  router-id 10.30.255.4
!
"""

# The hardening shape CCR-0222 exists for, on a NAMED instance: the process is
# `passive-interface default`, one uplink is exempted per-interface, one member
# is left to the default, and an L2 access port sits outside OSPF entirely.
PASSIVE_SHAPE = """\
hostname nx-agg-9
feature ospf
!
interface Ethernet1/1
  description exempted uplink
  no switchport
  ip address 10.30.9.1/30
  ip router ospf {proc} area 0.0.0.0
  no ip ospf passive-interface
  no shutdown
!
interface Ethernet1/2
  description member left to the process default
  no switchport
  ip address 10.30.9.5/30
  ip router ospf {proc} area 0.0.0.0
  no shutdown
!
interface Ethernet1/3
  description access port, no OSPF
  switchport
  switchport mode access
  switchport access vlan 90
!
router ospf {proc}
  router-id 10.30.255.9
  passive-interface default
!
"""

NAMED = "DCFABRIC"
NUMERIC = "19"


def _ifaces(pc):
    return {i.name: i for i in pc.interfaces}


def _parse(template, proc):
    return NXOSParser(template.format(proc=proc)).parse()


def _igp_edges(graph):
    return [
        attrs for _u, _v, attrs in graph.edges(data=True)
        if attrs.get("edge_type") == "igp"
    ]


# ---------------------------------------------------------------------------
# 1. Enrollment — the parse-level defect itself.
# ---------------------------------------------------------------------------


def test_named_instance_tag_enrolls_the_interface():
    """`ip router ospf DCFABRIC area 0.0.0.0` binds the interface to DCFABRIC."""
    iface = _ifaces(_parse(LEAF_A, NAMED))["Ethernet1/1"]
    assert iface.ospf_process_id == "DCFABRIC"
    # CCR-0227 still runs on the enrollment's area: dotted quad -> decimal.
    assert iface.ospf_area == "0"


def test_numeric_process_id_keeps_its_int_identity():
    """The digit spelling is still stored as an int, not as the token "19"."""
    iface = _ifaces(_parse(LEAF_A, NUMERIC))["Ethernet1/1"]
    assert iface.ospf_process_id == 19
    assert isinstance(iface.ospf_process_id, int)


def test_the_two_spellings_differ_only_in_the_identity():
    """Everything else the enrollment line sets is identical either way."""
    named = _ifaces(_parse(LEAF_A, NAMED))["Ethernet1/1"]
    numeric = _ifaces(_parse(LEAF_A, NUMERIC))["Ethernet1/1"]
    assert (named.ospf_area, named.ospf_cost) == (numeric.ospf_area, numeric.ospf_cost)
    assert named.ospf_area == "0"
    assert named.ospf_cost == 15


def test_process_and_interface_identities_compare_equal():
    """The equality every membership test performs holds for BOTH spellings.

    ``ospf.process_id == iface.ospf_process_id`` is how this parser's
    passive-default walk and the engine's ``_ospf_member`` decide membership. A
    producer that stored the tag on one side and nothing (or a differently typed
    value) on the other would partition one process in two.
    """
    for proc in (NAMED, NUMERIC):
        pc = _parse(LEAF_A, proc)
        iface = _ifaces(pc)["Ethernet1/1"]
        assert [o.process_id for o in pc.ospf_instances] == [iface.ospf_process_id]


def test_named_instance_under_vrf_keeps_its_vrf_attribution():
    """`router ospf <tag> vrf NAME` attributes the VRF to the named instance."""
    pc = _parse(VRF_LEAF, NAMED)
    assert [(o.process_id, o.vrf) for o in pc.ospf_instances] == [
        ("DCFABRIC", "TENANTRED")
    ]
    iface = _ifaces(pc)["Ethernet1/4"]
    assert iface.ospf_process_id == "DCFABRIC"
    assert iface.ospf_area == "9"          # 0.0.0.9 canonicalised


def test_named_vrf_instance_matches_the_numeric_spelling():
    pc_named = _parse(VRF_LEAF, NAMED)
    pc_numeric = _parse(VRF_LEAF, NUMERIC)
    assert [o.vrf for o in pc_named.ospf_instances] == [
        o.vrf for o in pc_numeric.ospf_instances
    ]
    assert _ifaces(pc_named)["Ethernet1/4"].ospf_area == (
        _ifaces(pc_numeric)["Ethernet1/4"].ospf_area
    )


# ---------------------------------------------------------------------------
# 2. The unmasking — an adjacency, not a populated field.
# ---------------------------------------------------------------------------


def test_two_named_instance_devices_form_an_ospf_adjacency():
    """Enrollment is only the mechanism; the deliverable is the adjacency.

    Both leaves name their instance, so before this fix neither interface was
    enrolled, no side had OSPF on the shared /30, and the pair contributed no
    IGP adjacency to the topology at all.
    """
    devices = {
        "nx-leaf-1": _parse(LEAF_A, NAMED),
        "nx-leaf-2": _parse(LEAF_B, NAMED),
    }
    edges = _igp_edges(TopologyGraphBuilder(devices).build())
    assert len(edges) == 1
    assert edges[0]["protocol"] == "OSPF"
    assert edges[0]["subnet"] == "10.30.1.0/30"
    assert edges[0]["cost"] == 15


def test_the_adjacency_comes_from_the_enrollment_and_nothing_else():
    """Strip the enrollment lines and the same pair yields no IGP edge.

    The control for the test above: the two devices still share the subnet and
    still run an OSPF process, so an edge that survived this would not be
    evidence of enrollment.
    """
    devices = {
        "nx-leaf-1": NXOSParser(
            LEAF_A.format(proc=NAMED).replace(
                "  ip router ospf DCFABRIC area 0.0.0.0\n", ""
            )
        ).parse(),
        "nx-leaf-2": NXOSParser(
            LEAF_B.format(proc=NAMED).replace(
                "  ip router ospf DCFABRIC area 0.0.0.0\n", ""
            )
        ).parse(),
    }
    assert _igp_edges(TopologyGraphBuilder(devices).build()) == []


def test_named_and_numeric_estates_produce_the_same_adjacency():
    """A named fabric and a numbered fabric are the same network."""
    named = _igp_edges(TopologyGraphBuilder({
        "nx-leaf-1": _parse(LEAF_A, NAMED),
        "nx-leaf-2": _parse(LEAF_B, NAMED),
    }).build())
    numeric = _igp_edges(TopologyGraphBuilder({
        "nx-leaf-1": _parse(LEAF_A, NUMERIC),
        "nx-leaf-2": _parse(LEAF_B, NUMERIC),
    }).build())
    assert [(e["protocol"], e["subnet"], e["cost"]) for e in named] == [
        (e["protocol"], e["subnet"], e["cost"]) for e in numeric
    ]


# ---------------------------------------------------------------------------
# 3. CCR-0222 on a named instance — the second resolver that had only ever
#    seen numbers. Membership here is decided by the same equality.
# ---------------------------------------------------------------------------


def test_passive_default_reaches_members_of_a_named_instance():
    """`passive-interface default` marks the unexempted named-instance member."""
    ifaces = _ifaces(_parse(PASSIVE_SHAPE, NAMED))
    assert ifaces["Ethernet1/2"].ospf_passive is True


def test_interface_override_still_beats_a_named_process_default():
    """CCR-0222's override survives the unmasking.

    `no ip ospf passive-interface` is the interface's own word and wins over the
    process's `passive-interface default` — which is exactly how a Nexus estate
    exempts its uplinks. Before this fix the interface was in no process at all,
    so the process default could not reach it and the override had nothing to
    beat; the override must not now lose to a default that can finally see it.
    """
    ifaces = _ifaces(_parse(PASSIVE_SHAPE, NAMED))
    assert ifaces["Ethernet1/1"].ospf_passive is False


def test_l2_port_outside_a_named_instance_stays_undecided():
    """Correctness over coverage: a non-member is never inferred passive."""
    ifaces = _ifaces(_parse(PASSIVE_SHAPE, NAMED))
    assert ifaces["Ethernet1/3"].ospf_process_id is None
    assert ifaces["Ethernet1/3"].ospf_passive is None


def test_passive_resolution_is_identical_under_both_spellings():
    named = _ifaces(_parse(PASSIVE_SHAPE, NAMED))
    numeric = _ifaces(_parse(PASSIVE_SHAPE, NUMERIC))
    assert {n: i.ospf_passive for n, i in named.items()} == {
        n: i.ospf_passive for n, i in numeric.items()
    }


# ---------------------------------------------------------------------------
# 4. The shared rule itself.
# ---------------------------------------------------------------------------


def test_canonical_process_id_is_digit_or_verbatim():
    """One rule, so no two producers can disagree about one process."""
    assert canonical_process_id("19") == 19
    assert isinstance(canonical_process_id("19"), int)
    assert canonical_process_id("DCFABRIC") == "DCFABRIC"
    assert canonical_process_id("0") == 0          # falsy, still an identity
    assert canonical_process_id(19) == 19
    assert canonical_process_id(None) is None
