"""CCR-0110 Phase E4/E5 — op-primary tombstone-string emission removal.

Pins the two acceptance invariants of the emission removal:

  * **Per-OS A/B (composed ChangeSet identity):** removing the deprecated
    tombstone-string channel MUST NOT change the composed ChangeSet. Every
    string that was dropped had a native op behind it, so ``derive_ops`` still
    produces the byte-identical operation sequence. The golden ChangeSet was
    captured from the pre-removal tree (v0.3.5 / c12acc8) and is byte-identical
    to what the current tree produces.

  * **IOS-XR R1 exception:** IOS-XR's deletion capability is carried by derived
    tombstone strings (no native op behind them), so its composed ChangeSet is
    likewise identical pre/post AND its ``no_commands`` stays populated — the
    strings are NOT removed for XR (excepted pending Phase 5).

  * **Fields empty (op-primary):** IOS/NX-OS/EOS parses leave
    ``no_commands`` / ``interface_no_commands`` / ``bgp_no_commands`` empty,
    EXCEPT the one residual derived-only channel: the whole-process
    ``no router bgp <asn>`` delete (``process:bgp:<asn>``), which has no native
    op behind it (same class as the XR-excepted strings).

The golden lives beside this file; ``value``-bearing SET ops are avoided by
using pure-deletion configs, so the ChangeSet golden is fully serializable.
"""
import json
from pathlib import Path

import pytest

from confgraph.change_ir import derive_ops
from confgraph.parsers.eos_parser import EOSParser
from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.iosxr_parser import IOSXRParser
from confgraph.parsers.nxos_parser import NXOSParser

GOLDENS = json.loads(
    (Path(__file__).resolve().parent / "ccr0110_phase_e_pin_goldens.json").read_text()
)

# Rich pure-deletion configs (all ops value=None). Must match capture_pin.py.
IOS_DEL = (
    "no ip route 10.0.0.0 255.255.255.0 192.0.2.1\n"
    "no ip route vrf CUST 10.1.0.0 255.255.0.0\n"
    "no vlan 100\n"
    "no router ospf 3\n"
    "no router bgp 65010\n"
    "no router isis DEADTAG\n"
    "no router eigrp 44\n"
    "no ip access-list extended DEAD\n"
    "no route-map RM-EDGE permit 20\n"
    "no ip prefix-list PL seq 5\n"
    "no vrf definition GUEST\n"
    "no interface Loopback9\n"
    "no ip sla 5\n"
    "no track 9\n"
    "no event manager applet OLD\n"
    "no banner motd\n"
    "no ntp server 9.9.9.9\n"
    "no snmp-server community PUBLIC ro\n"
    "no ip nat pool NP\n"
    "no class-map CM\n"
)
XR_DEL = (
    "no router ospf 3\n"
    "no router bgp 65010\n"
    "no router isis DEADTAG\n"
    "no ntp\n"
    "no route-policy RP\n"
    "no prefix-set PS\n"
)

OP_PRIMARY = {"IOS": IOSParser, "NXOS": NXOSParser, "EOS": EOSParser}


def _changeset(pc):
    return [
        {"verb": op.verb.name, "path": list(op.path), "origin": op.origin}
        for op in derive_ops(pc)
    ]


def _all_container_strings(pc):
    out = list(pc.no_commands)
    for i in pc.interfaces:
        out += list(i.no_commands)
    for b in pc.bgp_instances:
        out += list(b.no_commands)
    return out


@pytest.mark.parametrize("os_name,cls", OP_PRIMARY.items())
def test_op_primary_changeset_identical_to_pre_removal_golden(os_name, cls):
    """A/B: the composed ChangeSet is byte-identical to the pre-removal golden."""
    assert _changeset(cls(IOS_DEL).parse()) == GOLDENS[os_name]["changeset"]


@pytest.mark.parametrize("os_name,cls", OP_PRIMARY.items())
def test_op_primary_containers_empty_except_process_bgp(os_name, cls):
    """Op-primary parses leave the deprecated string containers empty except the
    one derived-only survivor (``process:bgp:<asn>`` — no native op behind it)."""
    pc = cls(IOS_DEL).parse()
    assert pc.no_commands == ["process:bgp:65010"]
    assert all(not i.no_commands for i in pc.interfaces)
    assert all(not b.no_commands for b in pc.bgp_instances)


def test_iosxr_changeset_identical_to_pre_removal_golden():
    """R1: IOS-XR's composed ChangeSet is IDENTICAL pre/post emission removal."""
    assert _changeset(IOSXRParser(XR_DEL).parse()) == GOLDENS["IOSXR"]["changeset"]


def test_iosxr_keeps_derived_only_deletion_strings():
    """R1 exception: IOS-XR still populates ``no_commands`` with its derived-only
    top-level deletions (no native op behind them — its deletion capability)."""
    pc = IOSXRParser(XR_DEL).parse()
    for expected in (
        "process:ospf:3",
        "process:bgp:65010",
        "process:isis:DEADTAG",
        "singleton:ntp",
        "route-map:RP",
        "prefix-list:PS",
    ):
        assert expected in pc.no_commands
