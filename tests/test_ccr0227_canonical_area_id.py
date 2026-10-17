"""CCR-0227 — OSPF area IDs are stored canonical, not as the vendor spelled them.

``0.0.0.0`` and ``0`` are the same 32-bit area on hardware. Stored raw they are
two keys, so a mixed-vendor estate (NX-OS/JunOS dotted, IOS/IOS-XR decimal)
partitions one real area in two: the adjacency gate refuses the neighbor and
every area-keyed structure computes against half the area.

Canonicalization happens AT PARSE, through one shared ``canonical_area_id()``
applied by model validators on all four storage points — so every consumer in
both repos inherits it with no code of its own. Decimal is canonical because it
leaves tombstone and golden keys (``ospf:1:area:0:stub_reset``) byte-identical.
"""

from ipaddress import IPv4Network

from confgraph.models.interface import InterfaceConfig, InterfaceType
from confgraph.models.base import OSType
from confgraph.models.ospf import OSPFArea, OSPFConfig, OSPFInterfaceConfig
from confgraph.parsers.eos_parser import EOSParser
from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.iosxr_parser import IOSXRParser
from confgraph.parsers.nxos_parser import NXOSParser
from confgraph.utils.ospf import canonical_area_id


# ---------------------------------------------------------------------------
# The normalizer itself.
# ---------------------------------------------------------------------------


def test_backbone_spellings_converge():
    assert canonical_area_id("0.0.0.0") == "0"
    assert canonical_area_id("0") == "0"


def test_dotted_quad_becomes_its_32_bit_decimal():
    assert canonical_area_id("0.0.0.51") == "51"
    assert canonical_area_id("0.0.1.0") == "256"
    assert canonical_area_id("10.0.0.1") == "167772161"
    assert canonical_area_id("255.255.255.255") == "4294967295"


def test_non_area_values_pass_through_untouched():
    """A normalizer, not a validator — it never rejects or invents."""
    assert canonical_area_id("51") == "51"
    assert canonical_area_id("backbone") == "backbone"
    assert canonical_area_id("0.0.0.999") == "0.0.0.999"   # not an area ID
    assert canonical_area_id("0.0.0") == "0.0.0"
    assert canonical_area_id("") == ""
    assert canonical_area_id(None) is None
    assert canonical_area_id(7) == 7


# ---------------------------------------------------------------------------
# The four storage points. Adding a fifth is one validator line — these pin
# that the existing four go through the SAME function.
# ---------------------------------------------------------------------------


def test_storage_point_ospf_area():
    assert OSPFArea(area_id="0.0.0.0").area_id == "0"
    assert OSPFArea(area_id="0.0.0.51").area_id == "51"


def test_storage_point_ospf_interface_config():
    assert OSPFInterfaceConfig(area_id="0.0.0.0").area_id == "0"
    assert OSPFInterfaceConfig(area_id="0.0.0.51").area_id == "51"


def test_storage_point_interface_config():
    def _iface(area):
        return InterfaceConfig(
            object_id="interface_Et1", source_os=OSType.NXOS,
            name="Ethernet1", interface_type=InterfaceType.PHYSICAL,
            ospf_area=area,
        )
    assert _iface("0.0.0.0").ospf_area == "0"
    assert _iface("0.0.0.51").ospf_area == "51"
    assert _iface(None).ospf_area is None


def test_storage_point_network_statements():
    cfg = OSPFConfig(
        object_id="ospf_1", source_os=OSType.IOS, process_id=1,
        network_statements=[
            (IPv4Network("10.0.0.0/24"), "0.0.0.0"),
            (IPv4Network("10.0.1.0/24"), "0.0.0.51"),
        ],
    )
    assert cfg.network_statements == [
        (IPv4Network("10.0.0.0/24"), "0"),
        (IPv4Network("10.0.1.0/24"), "51"),
    ]


# ---------------------------------------------------------------------------
# Parse-time, per OS — including the three sites that mutate a built model in
# place and therefore run no field validator.
# ---------------------------------------------------------------------------


def test_nxos_interface_post_patch_canonicalizes():
    """`ip router ospf 1 area 0.0.0.0` is assigned onto a built model."""
    cfg = (
        "interface Ethernet1/1\n"
        "  ip address 10.0.6.2/30\n"
        "  ip router ospf 1 area 0.0.0.0\n"
        "!\n"
        "router ospf 1\n"
        "!\n"
    )
    iface = next(i for i in NXOSParser(cfg).parse().interfaces if i.name == "Ethernet1/1")
    assert iface.ospf_area == "0"


def test_eos_interface_post_patch_canonicalizes():
    cfg = (
        "interface Ethernet1\n"
        "   ip address 10.0.6.2/30\n"
        "   ip ospf area 0.0.0.51\n"
        "!\n"
        "router ospf 1\n"
        "!\n"
    )
    iface = next(i for i in EOSParser(cfg).parse().interfaces if i.name == "Ethernet1")
    assert iface.ospf_area == "51"


def test_eos_prefix_network_statement_append_canonicalizes():
    """EOS appends into a LIVE model's list — no validator runs there."""
    cfg = (
        "router ospf 1\n"
        "   network 10.10.2.0/24 area 0.0.0.0\n"
        "   network 10.10.3.0/24 area 0.0.0.51\n"
        "!\n"
    )
    stmts = EOSParser(cfg).parse().ospf_instances[0].network_statements
    assert (IPv4Network("10.10.2.0/24"), "0") in stmts
    assert (IPv4Network("10.10.3.0/24"), "51") in stmts


def test_ios_decimal_spelling_is_unchanged():
    cfg = (
        "interface GigabitEthernet0/0\n"
        " ip address 10.0.6.1 255.255.255.252\n"
        " ip ospf 1 area 0\n"
        "!\n"
        "router ospf 1\n"
        " network 10.0.6.0 0.0.0.3 area 0\n"
        "!\n"
    )
    pc = IOSParser(cfg).parse()
    iface = next(i for i in pc.interfaces if i.name == "GigabitEthernet0/0")
    assert iface.ospf_area == "0"
    assert pc.ospf_instances[0].network_statements == [(IPv4Network("10.0.6.0/30"), "0")]


# ---------------------------------------------------------------------------
# The point of the whole fix: two vendors, two spellings, ONE key.
# ---------------------------------------------------------------------------


def _nx_area(area: str) -> str:
    cfg = (
        "interface Ethernet1/1\n"
        "  ip address 10.0.6.2/30\n"
        f"  ip router ospf 1 area {area}\n"
        "!\n"
        "router ospf 1\n"
        "!\n"
    )
    return next(
        i for i in NXOSParser(cfg).parse().interfaces if i.name == "Ethernet1/1"
    ).ospf_area


def _xr_area(area: str) -> str:
    cfg = (
        "interface GigabitEthernet0/0/0/3\n"
        " ipv4 address 10.0.6.1 255.255.255.252\n"
        "!\n"
        "router ospf 1\n"
        f" area {area}\n"
        "  interface GigabitEthernet0/0/0/3\n"
        "  !\n"
        " !\n"
        "!\n"
    )
    return next(
        i for i in IOSXRParser(cfg).parse().interfaces
        if i.name == "GigabitEthernet0/0/0/3"
    ).ospf_area


def test_backbone_matches_across_vendor_spellings():
    """The lab's nx-agg (0.0.0.0) <-> xr-core (0) link."""
    assert _nx_area("0.0.0.0") == _xr_area("0") == "0"


def test_parity_a_second_area_needs_zero_new_code():
    """Area 51 behaves exactly like area 0 — no per-area special case."""
    assert _nx_area("0.0.0.51") == _xr_area("51") == "51"


def test_genuinely_different_areas_still_differ():
    """Canonicalization must not collapse real area mismatches."""
    assert _nx_area("0.0.0.1") != _xr_area("2")
    assert _nx_area("0.0.0.0") != _nx_area("0.0.0.1")
    assert canonical_area_id("0.0.0.1") != canonical_area_id("0.0.1.0")


def test_decimal_canonical_preserves_tombstone_and_golden_keys():
    """Why decimal and not dotted: `ospf:1:area:0:...` keys do not move."""
    area = OSPFArea(area_id="0.0.0.0")
    assert f"ospf:1:area:{area.area_id}:stub_reset" == "ospf:1:area:0:stub_reset"


# ---------------------------------------------------------------------------
# The deletion path. Area-scoped tombstones and ops are keyed from the
# PROPOSAL TEXT while the positive member ops key off the stored (canonical)
# area — so both ends canonicalize or a dotted `no area …` addresses an area
# that no longer exists under that spelling.
# ---------------------------------------------------------------------------


OSPF_DELETIONS = (
    "router ospf 1\n"
    " area 0.0.0.3 virtual-link 1.1.1.1\n"
    " no area 0.0.0.1 stub\n"
    " no area 0.0.0.2 nssa\n"
    " no area 0.0.0.3 virtual-link 2.2.2.2\n"
    " no area 0.0.0.4 filter-list prefix PL in\n"
    "!\n"
)


def test_area_reset_tombstones_carry_the_canonical_key():
    parser = IOSParser(OSPF_DELETIONS)
    parser.parse()
    assert parser.parse_deletion_commands() == [
        "field:ospf:1:area:1:stub_reset",
        "field:ospf:1:area:2:nssa_reset",
    ]


def test_area_scoped_negation_ops_carry_the_canonical_key():
    ops = IOSParser(OSPF_DELETIONS).parse().native_change_ops
    paths = [op.path for op in ops]
    assert ("field", "ospf", "1", "", "area", "3", "virtual_link", "2.2.2.2") in paths
    assert ("field", "ospf", "1", "", "area", "4", "filter_list_in") in paths


def test_positive_and_negative_area_keys_agree():
    """The whole point: one area, one key, whichever side wrote it."""
    ops = IOSParser(OSPF_DELETIONS).parse().native_change_ops
    positive = {op.path for op in ops if op.path[0] == "ospf_instances"}
    assert ("ospf_instances", "1", "", "area", "3") in positive
    assert ("ospf_instances", "1", "", "area", "3", "virtual_link", "1.1.1.1") in positive


def test_decimal_spelled_deletions_are_unchanged():
    """Regression: the spelling that already matched must not move."""
    parser = IOSParser(
        "router ospf 1\n"
        " no area 1 stub\n"
        " no area 2 nssa\n"
        "!\n"
    )
    parser.parse()
    assert parser.parse_deletion_commands() == [
        "field:ospf:1:area:1:stub_reset",
        "field:ospf:1:area:2:nssa_reset",
    ]
