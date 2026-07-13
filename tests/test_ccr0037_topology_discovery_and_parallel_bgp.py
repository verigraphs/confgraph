"""CCR-0037 — the `topology` command's own two defects.

T1  Config discovery accepted a hard-coded ``(".txt", ".cfg", ".conf", "")`` tuple, so a PAN-OS
    device (whose config is an XML export) was never read, never warned about, and never appeared
    in the graph. The accepted extensions are now derived from ``confgraph.loader.PARSER_REGISTRY``
    — registering a parser cannot leave its file type undiscoverable — and discovery *reports*
    every file it did not use and every device it found no file for.

T5  ``TopologyGraphBuilder._add_bgp_edges`` deduplicated sessions on ``frozenset([host_a, host_b])``,
    one edge per device *pair*, so two parallel BGP sessions between the same two routers collapsed
    into one edge and one session's attributes were discarded. A session is now identified by the
    unordered device pair AND the unordered endpoint-address pair: neither half is sufficient
    alone — the device pair is the coarse key itself, and an address pair is not unique across an
    estate (two pods numbered 10.0.0.1 <-> 10.0.0.2 are two sessions, not one).

    Address ownership is global-table only (VRF-bound addresses excluded). When one global address
    has several owners, the neighbor's ``remote-as`` is used as EVIDENCE — exactly one candidate
    whose local ASN matches it *is* the peer, and nothing is ambiguous. When the ASN does not single
    one out (same-AS estate; peer-group member whose ``remote_as`` is the string ``'inherited'``),
    the session is reported and omitted — never handed to a winner picked alphabetically.

Config syntax used below is the emitted form already exercised by the committed coverage fixtures
(``_work/ios_full.cfg``, ``_work/eos_full.cfg``); the PAN-OS XML follows the shape verified in
``tests/test_ccr0035_panos_routing_surface.py`` (``<peer-as>`` on the peer entry, cited there to
``syntax-corpus/panos/bgp.yaml``).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from confgraph.cli import main
from confgraph.loader import (
    PARSER_REGISTRY,
    config_extensions,
    discover_device_configs,
    parser_for,
)
from confgraph.models.base import OSType
from confgraph.parsers.eos_parser import EOSParser
from confgraph.parsers.ios_parser import IOSParser
from confgraph.topology.graph import TopologyGraphBuilder


# ---------------------------------------------------------------------------
# Fixtures — two routers with TWO parallel iBGP sessions, plus a firewall.
#
# rtr-a and rtr-b run one loopback-sourced iBGP session (10.9.9.1 <-> 10.9.9.2)
# and a second, directly-connected one (172.31.0.1 <-> 172.31.0.2). The two
# sessions carry *different* route-maps, which is what proves they did not merge.
# ---------------------------------------------------------------------------

RTR_A = """\
hostname rtr-a
!
interface Loopback0
 ip address 10.9.9.1 255.255.255.255
!
interface GigabitEthernet0/3
 description to-rtr-b
 ip address 172.31.0.1 255.255.255.252
!
route-map RM-LOOP-IN permit 10
 set local-preference 300
!
route-map RM-DIRECT-OUT permit 10
 set metric 55
!
router bgp 64900
 bgp router-id 10.9.9.1
 neighbor 10.9.9.2 remote-as 64900
 neighbor 10.9.9.2 description loopback-session
 neighbor 10.9.9.2 update-source Loopback0
 neighbor 10.9.9.2 route-map RM-LOOP-IN in
 neighbor 172.31.0.2 remote-as 64900
 neighbor 172.31.0.2 description direct-session
 neighbor 172.31.0.2 route-map RM-DIRECT-OUT out
!
end
"""

RTR_B = """\
hostname rtr-b
!
interface Loopback0
   ip address 10.9.9.2/32
!
interface Ethernet7
   description to-rtr-a
   no switchport
   ip address 172.31.0.2/30
!
route-map RM-LOOP-OUT permit 10
   set metric 77
!
router bgp 64900
   bgp router-id 10.9.9.2
   neighbor 10.9.9.1 remote-as 64900
   neighbor 10.9.9.1 update-source Loopback0
   neighbor 10.9.9.1 route-map RM-LOOP-OUT out
   neighbor 172.31.0.1 remote-as 64900
!
end
"""

# PAN-OS export. Shape per tests/test_ccr0035_panos_routing_surface.py.
FW_XML = """\
<config version="10.1.0">
  <devices>
    <entry name="localhost.localdomain">
      <deviceconfig><system><hostname>pa-edge-77</hostname></system></deviceconfig>
      <network>
        <interface>
          <ethernet>
            <entry name="ethernet1/4">
              <layer3><ip><entry name="192.0.2.9/30"/></ip></layer3>
            </entry>
          </ethernet>
        </interface>
        <virtual-router>
          <!-- The stock VR. PANOSParser maps virtual-router "default" to the
               global table (vrf=None); a named VR is a routing instance, and its
               BGP would not be the device's global ASN. -->
          <entry name="default">
            <interface><member>ethernet1/4</member></interface>
            <protocol>
              <bgp>
                <enable>yes</enable>
                <router-id>192.0.2.9</router-id>
                <local-as>64777</local-as>
                <peer-group>
                  <entry name="EDGE">
                    <type><ebgp/></type>
                    <peer>
                      <entry name="upstream">
                        <enable>yes</enable>
                        <peer-as>64778</peer-as>
                        <peer-address><ip>192.0.2.10</ip></peer-address>
                        <local-address><interface>ethernet1/4</interface></local-address>
                      </entry>
                    </peer>
                  </entry>
                </peer-group>
              </bgp>
            </protocol>
          </entry>
        </virtual-router>
      </network>
    </entry>
  </devices>
</config>
"""


@pytest.fixture()
def estate(tmp_path: Path) -> Path:
    """A configs dir + inventory: two IOS/EOS routers, one PAN-OS firewall (.xml)."""
    configs = tmp_path / "configs"
    configs.mkdir()
    (configs / "rtr-a.cfg").write_text(RTR_A, encoding="utf-8")
    (configs / "rtr-b.cfg").write_text(RTR_B, encoding="utf-8")
    (configs / "fw-edge.xml").write_text(FW_XML, encoding="utf-8")
    (tmp_path / "inventory.csv").write_text(
        "hostname,os_type\nrtr-a,ios\nrtr-b,eos\nfw-edge,panos\nrtr-gone,ios\n",
        encoding="utf-8",
    )
    return tmp_path


def _run_topology(estate: Path, out: Path) -> tuple[dict, str]:
    """Run `confgraph topology` over *estate*; return (parsed JSON, stderr)."""
    runner = CliRunner()  # click >= 8.2 keeps stderr separate by default
    result = runner.invoke(
        main,
        [
            "topology",
            "--inventory", str(estate / "inventory.csv"),
            "--configs-dir", str(estate / "configs"),
            "--output", str(out / "topology.html"),
            "--json", str(out / "topology.json"),
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    return json.loads((out / "topology.json").read_text()), result.stderr


# ---------------------------------------------------------------------------
# T1 — the extension set is derived from the parser registry
# ---------------------------------------------------------------------------

def test_every_registered_parser_has_a_discoverable_extension():
    """The structural claim: no registered parser can be undiscoverable."""
    accepted = config_extensions()
    for os_type, registration in PARSER_REGISTRY.items():
        assert registration.extensions, f"{os_type} registers no file extension"
        for ext in registration.extensions:
            assert ext in accepted, f"{os_type}'s '{ext}' is not discoverable"


def test_panos_registers_xml_and_dispatches_to_the_panos_parser():
    from confgraph.parsers.panos_parser import PANOSParser

    assert ".xml" in config_extensions(OSType.PANOS)
    assert ".xml" in config_extensions()          # and in the union used by discovery
    assert parser_for(OSType.PANOS) is PANOSParser
    assert parser_for(OSType.IOS_XE) is IOSParser  # IOS-XE has no parser of its own


def test_discovery_finds_the_xml_config_and_reports_the_missing_one(estate: Path):
    found = discover_device_configs(
        estate / "configs",
        {"rtr-a": "ios", "rtr-b": "eos", "fw-edge": "panos", "rtr-gone": "ios"},
    )

    assert found.configs["fw-edge"].name == "fw-edge.xml"   # T1: was never found before
    assert found.configs["rtr-a"].name == "rtr-a.cfg"
    assert found.configs["rtr-b"].name == "rtr-b.cfg"
    assert "rtr-gone" not in found.configs

    missing = dict(found.missing)
    assert list(missing) == ["rtr-gone"]
    assert "rtr-gone.cfg" in missing["rtr-gone"]   # the names it actually looked for
    assert found.skipped == []


def test_discovery_reports_a_file_no_parser_can_read(estate: Path):
    (estate / "configs" / "lab-notes.md").write_text("not a config\n", encoding="utf-8")
    (estate / "configs" / "rtr-zz.cfg").write_text("hostname rtr-zz\n", encoding="utf-8")

    found = discover_device_configs(estate / "configs", {"rtr-a": "ios"})
    skipped = {path.name: reason for path, reason in found.skipped}

    assert "unsupported extension '.md'" in skipped["lab-notes.md"]
    assert "no device named 'rtr-zz' in the inventory" == skipped["rtr-zz.cfg"]


def test_a_shadowed_second_file_for_a_known_device_is_reported_accurately(estate: Path):
    """Two files for one device: the unused one is shadowed, NOT unclaimed.

    Reporting `no device named 'rtr-a' in the inventory` for rtr-a.xml — when rtr-a is
    plainly in the inventory and was read from rtr-a.cfg — is a confidently wrong
    warning, which is worse than the silence T1 removed.
    """
    (estate / "configs" / "rtr-a.xml").write_text(FW_XML, encoding="utf-8")

    found = discover_device_configs(estate / "configs", {"rtr-a": "ios"})

    assert found.configs["rtr-a"].name == "rtr-a.cfg"       # .cfg wins for an IOS device
    skipped = {path.name: reason for path, reason in found.skipped}
    assert skipped["rtr-a.xml"] == (
        "a second config file for 'rtr-a', which was read from 'rtr-a.cfg' instead"
    )
    assert "no device named" not in skipped["rtr-a.xml"]


# ---------------------------------------------------------------------------
# T1 — end to end: the firewall is a node, and the skips are on stderr
# ---------------------------------------------------------------------------

def test_panos_device_is_a_node_in_the_topology(estate: Path, tmp_path: Path):
    out = tmp_path / "out"
    topo, _stderr = _run_topology(estate, out)

    assert topo["devices"]["fw-edge"] == {
        "os": "panos",
        "asn": 64777,
        "router_id": "192.0.2.9",
        "color": "#0369a1",
    }
    assert sorted(topo["devices"]) == ["fw-edge", "rtr-a", "rtr-b"]


def test_skipped_and_missing_configs_warn_on_stderr(estate: Path, tmp_path: Path):
    (estate / "configs" / "lab-notes.md").write_text("not a config\n", encoding="utf-8")
    unreadable = estate / "configs" / "rtr-gone.cfg"
    unreadable.write_text("hostname rtr-gone\n", encoding="utf-8")
    unreadable.chmod(0o000)
    try:
        _topo, stderr = _run_topology(estate, tmp_path / "out")
    finally:
        unreadable.chmod(0o644)

    assert "Warning: Skipping unreadable config file 'rtr-gone.cfg' for 'rtr-gone'" in stderr
    assert "Warning: Ignoring 'lab-notes.md' — unsupported extension '.md'" in stderr


def test_device_with_no_config_file_at_all_warns_on_stderr(estate: Path, tmp_path: Path):
    _topo, stderr = _run_topology(estate, tmp_path / "out")

    assert "Warning: No config file found for 'rtr-gone'" in stderr
    assert "rtr-gone.cfg" in stderr          # names the candidates it searched
    assert "device omitted from the topology" in stderr


# ---------------------------------------------------------------------------
# T5 — parallel sessions are two edges, each with its own attributes
# ---------------------------------------------------------------------------

def test_parallel_bgp_sessions_are_two_edges_with_their_own_attributes(
    estate: Path, tmp_path: Path
):
    topo, _stderr = _run_topology(estate, tmp_path / "out")

    bgp = [
        link for link in topo["links"]
        if link["edge_type"] == "bgp"
        and {link["device_a"], link["device_b"]} == {"rtr-a", "rtr-b"}
    ]
    assert len(bgp) == 2, [link["label"] for link in bgp]

    by_addr = {(link["local_ip_a"], link["local_ip_b"]): link for link in bgp}
    loopback = by_addr[("10.9.9.1", "10.9.9.2")]
    direct = by_addr[("172.31.0.1", "172.31.0.2")]

    # The loopback session's policies belong to the loopback session only …
    assert loopback["description"] == "loopback-session"
    assert loopback["session_type"] == "iBGP"
    assert loopback["route_map_in_a"] == "RM-LOOP-IN"
    assert loopback["route_map_out_b"] == "RM-LOOP-OUT"
    assert loopback["route_map_out_a"] == ""
    assert loopback["route_map_in_b"] == ""

    # … and the directly-connected session's to that one. Before the fix a single
    # merged edge carried whichever set was encountered first.
    assert direct["description"] == "direct-session"
    assert direct["session_type"] == "iBGP"
    assert direct["route_map_out_a"] == "RM-DIRECT-OUT"
    assert direct["route_map_in_a"] == ""
    assert direct["route_map_out_b"] == ""
    assert direct["route_map_in_b"] == ""

    assert loopback["label"] == (
        "iBGP 10.9.9.1 ↔ 10.9.9.2 — loopback-session [rtr-b→out:RM-LOOP-OUT, rtr-a←in:RM-LOOP-IN]"
    )
    assert direct["label"] == "iBGP 172.31.0.1 ↔ 172.31.0.2 — direct-session [rtr-a→out:RM-DIRECT-OUT]"


def test_one_session_seen_from_both_sides_is_still_one_edge():
    """The dedup must still dedup: two neighbor statements, one session, one edge."""
    devices = {
        "rtr-a": IOSParser(RTR_A).parse(),
        "rtr-b": EOSParser(RTR_B).parse(),
    }
    g = TopologyGraphBuilder(devices).build()

    bgp_edges = [
        (u, v, attrs) for u, v, attrs in g.edges(data=True)
        if attrs.get("edge_type") == "bgp"
    ]
    # rtr-a states 2 neighbors and rtr-b states 2 neighbors — 4 statements, but only
    # 2 sessions. Coarse dedup gave 1 edge; no dedup would give 4.
    assert len(bgp_edges) == 2
    assert sorted(attrs["local_ip_a"] for _u, _v, attrs in bgp_edges) == [
        "10.9.9.1", "172.31.0.1",
    ]


# A decoy that duplicates rtr-a's loopback address 10.9.9.1/32 in the GLOBAL table.
# It sorts before "rtr-a", which is what makes it a good decoy: any tiebreak that
# degrades to alphabetical order hands rtr-b's session to it and deletes the real one.
ROGUE = """\
hostname rogue
!
interface Loopback0
 ip address 10.9.9.1 255.255.255.255
!
interface GigabitEthernet0/9
 ip address 172.31.9.1 255.255.255.252
!
router bgp 64900
 bgp router-id 10.9.9.1
!
end
"""

# The same address, but inside a VRF. A VRF-bound address is not in the global table
# and therefore is NOT a duplicate of anything in it.
VRF_DECOY = """\
hostname cust-vrf-gw
!
interface Loopback5
 vrf forwarding CUST-A
 ip address 10.9.9.1 255.255.255.255
!
interface GigabitEthernet0/9
 ip address 172.31.5.1 255.255.255.252
!
router bgp 64900
 bgp router-id 172.31.5.1
!
end
"""


def _bgp_edges(g) -> list[tuple[str, str, dict]]:
    return [
        (u, v, attrs) for u, v, attrs in g.edges(data=True)
        if attrs.get("edge_type") == "bgp"
    ]


def test_a_vrf_bound_address_is_not_a_global_table_duplicate():
    """10.9.9.1 in VRF CUST-A and 10.9.9.1 in the global table are different addresses.

    Only the global one can be a global-table BGP peer, so there is nothing ambiguous
    here: no warning, and rtr-b's loopback session still binds to the real rtr-a with
    both sides' policies intact.
    """
    devices = {
        "rtr-a": IOSParser(RTR_A).parse(),
        "rtr-b": EOSParser(RTR_B).parse(),
        "cust-vrf-gw": IOSParser(VRF_DECOY).parse(),
    }
    builder = TopologyGraphBuilder(devices)
    g = builder.build()

    assert builder.warnings == []
    loopback = [
        attrs for _u, _v, attrs in _bgp_edges(g) if attrs["local_ip_a"] == "10.9.9.1"
    ]
    assert len(loopback) == 1
    assert loopback[0]["local_ip_b"] == "10.9.9.2"
    assert loopback[0]["route_map_in_a"] == "RM-LOOP-IN"
    assert loopback[0]["route_map_out_b"] == "RM-LOOP-OUT"   # rtr-b's own side, kept
    partners = {
        v if u == "rtr-b" else u
        for u, v, attrs in _bgp_edges(g) if "rtr-b" in (u, v)
    }
    assert partners == {"rtr-a"}


def test_a_duplicate_address_is_resolved_when_the_remote_as_identifies_the_peer():
    """Overlapping addressing across two sites, but the ASNs differ — nothing is ambiguous.

    A peer's local ASN must equal the remote-as configured for it, so exactly one
    candidate matching is *evidence*, not a guess: both sites keep their real session
    and no warning is owed. (Declining here would discard two real BGP sessions and
    warn about an ambiguity that does not exist.)
    """
    def site(host: str, local: str, peer: str, asn: int, desc: str) -> str:
        return f"""\
hostname {host}
!
interface Loopback0
 ip address {local} 255.255.255.255
!
router bgp {asn}
 bgp router-id {local}
 neighbor {peer} remote-as {asn}
 neighbor {peer} description {desc}
 neighbor {peer} update-source Loopback0
!
end
"""

    devices = {
        "site1-a": IOSParser(site("site1-a", "10.77.0.1", "10.77.0.2", 65110, "site1-link")).parse(),
        "site1-b": IOSParser(site("site1-b", "10.77.0.2", "10.77.0.1", 65110, "site1-link")).parse(),
        "site2-a": IOSParser(site("site2-a", "10.77.0.1", "10.77.0.2", 65220, "site2-link")).parse(),
        "site2-b": IOSParser(site("site2-b", "10.77.0.2", "10.77.0.1", 65220, "site2-link")).parse(),
    }
    builder = TopologyGraphBuilder(devices)
    g = builder.build()

    assert builder.warnings == []
    by_pair = {frozenset((u, v)): attrs for u, v, attrs in _bgp_edges(g)}
    assert sorted(sorted(p) for p in by_pair) == [
        ["site1-a", "site1-b"], ["site2-a", "site2-b"],
    ]
    assert by_pair[frozenset(("site1-a", "site1-b"))]["description"] == "site1-link"
    assert by_pair[frozenset(("site2-a", "site2-b"))]["description"] == "site2-link"
    for attrs in by_pair.values():
        assert attrs["session_type"] == "iBGP"
        assert {attrs["local_ip_a"], attrs["local_ip_b"]} == {"10.77.0.1", "10.77.0.2"}


def test_a_peer_group_member_never_accidentally_decides_the_ambiguity():
    """`remote_as` is the string 'inherited' for a peer-group member — not evidence.

    The peer-group's own remote-as (65300) would match core-x, but the neighbor
    statement does not carry it, so the config as parsed cannot identify the peer.
    Declining and saying so is the honest answer; a loose comparison that let
    'inherited' stand in for an ASN would silently pick one.
    """
    pgw = """\
hostname pg-edge
!
interface Loopback0
 ip address 10.88.0.1 255.255.255.255
!
router bgp 65300
 bgp router-id 10.88.0.1
 neighbor PG-CORE peer-group
 neighbor PG-CORE remote-as 65300
 neighbor 10.88.0.9 peer-group PG-CORE
 neighbor 10.88.0.9 update-source Loopback0
!
end
"""
    core = """\
hostname {host}
!
interface Loopback0
 ip address 10.88.0.9 255.255.255.255
!
router bgp {asn}
 bgp router-id 10.88.0.9
!
end
"""
    devices = {
        "pg-edge": IOSParser(pgw).parse(),
        "core-x": IOSParser(core.format(host="core-x", asn=65300)).parse(),
        "core-y": IOSParser(core.format(host="core-y", asn=65999)).parse(),
    }
    # Precondition: the parser really does hand us the string, not an int.
    neighbor = devices["pg-edge"].bgp_instances[0].neighbors[0]
    assert neighbor.remote_as == "inherited"

    builder = TopologyGraphBuilder(devices)
    g = builder.build()

    assert builder.warnings == [
        "Address 10.88.0.9 is configured in the global table of more than one device "
        "(core-x, core-y) — the BGP peer it names is ambiguous, so 'pg-edge's session "
        "to it is omitted from the graph."
    ]
    assert _bgp_edges(g) == []


def test_a_genuine_duplicate_address_is_declined_and_reported_never_guessed():
    """Two devices claiming one global address, **same ASN**: warn and decline.

    Here `remote-as` is no evidence at all — both candidates carry 64900, which is the
    ordinary single-AS estate. The session that names the ambiguous address is omitted
    and said out loud; the sessions that name unambiguous addresses are untouched. No
    winner is picked: an alphabetical fallback would hand this one to the decoy.
    """
    devices = {
        "rogue": IOSParser(ROGUE).parse(),      # duplicates 10.9.9.1, same ASN 64900
        "rtr-a": IOSParser(RTR_A).parse(),
        "rtr-b": EOSParser(RTR_B).parse(),
    }
    builder = TopologyGraphBuilder(devices)
    g = builder.build()

    assert builder.warnings == [
        "Address 10.9.9.1 is configured in the global table of more than one device "
        "(rogue, rtr-a) — the BGP peer it names is ambiguous, so 'rtr-b's session to "
        "it is omitted from the graph."
    ]
    # Nothing was handed to the decoy…
    assert [(u, v) for u, v, _a in _bgp_edges(g) if "rogue" in (u, v)] == []

    # …and rtr-b's *unambiguous* session (the directly-connected one) is intact, while
    # the loopback session survives only as rtr-a saw it: rtr-b's declined side leaves
    # its route-map off the edge rather than putting it on the wrong one.
    by_addr = {attrs["local_ip_a"]: attrs for _u, _v, attrs in _bgp_edges(g)}
    assert sorted(by_addr) == ["10.9.9.1", "172.31.0.1"]
    assert by_addr["10.9.9.1"]["route_map_in_a"] == "RM-LOOP-IN"
    assert by_addr["10.9.9.1"]["route_map_out_b"] == ""
    assert by_addr["172.31.0.1"]["route_map_out_a"] == "RM-DIRECT-OUT"


# ---------------------------------------------------------------------------
# T5 — the session key is scoped to the device pair, not just the address pair
# ---------------------------------------------------------------------------

# Two pods that reuse the same loopback numbering — normal in a real estate — each
# peering to the same hub. Both sessions have the address pair {10.0.0.1, 10.0.0.8}
# and differ only by which device is at the near end.
POD_A = """\
hostname pod-a-edge
!
interface Loopback0
 ip address 10.0.0.1 255.255.255.255
!
router bgp 65010
 bgp router-id 10.0.0.1
 neighbor 10.0.0.8 remote-as 65099
 neighbor 10.0.0.8 description pod-a-to-hub
 neighbor 10.0.0.8 update-source Loopback0
!
end
"""

POD_B = """\
hostname pod-b-edge
!
interface Loopback0
 ip address 10.0.0.1 255.255.255.255
!
router bgp 65020
 bgp router-id 10.0.0.1
 neighbor 10.0.0.8 remote-as 65099
 neighbor 10.0.0.8 description pod-b-to-hub
 neighbor 10.0.0.8 update-source Loopback0
!
end
"""

HUB = """\
hostname hub
!
interface Loopback0
 ip address 10.0.0.8 255.255.255.255
!
router bgp 65099
 bgp router-id 10.0.0.8
!
end
"""


def test_two_device_pairs_reusing_one_address_pair_are_two_sessions():
    """The address pair is not unique across an estate; the device pair scopes it.

    Keyed on the address pair alone, both pods' sessions to the hub hash to
    {10.0.0.1, 10.0.0.8} and one of them disappears from the graph with nothing said.
    """
    devices = {
        "pod-a-edge": IOSParser(POD_A).parse(),
        "pod-b-edge": IOSParser(POD_B).parse(),
        "hub": IOSParser(HUB).parse(),
    }
    builder = TopologyGraphBuilder(devices)
    g = builder.build()

    edges = _bgp_edges(g)
    assert len(edges) == 2, [attrs["label"] for _u, _v, attrs in edges]

    by_pair = {frozenset((u, v)): attrs for u, v, attrs in edges}
    pod_a = by_pair[frozenset(("pod-a-edge", "hub"))]
    pod_b = by_pair[frozenset(("pod-b-edge", "hub"))]

    assert pod_a["description"] == "pod-a-to-hub"
    assert pod_b["description"] == "pod-b-to-hub"
    assert pod_a["session_type"] == "eBGP"       # 65010 vs 65099
    assert pod_b["session_type"] == "eBGP"       # 65020 vs 65099
    for attrs in (pod_a, pod_b):
        assert (attrs["local_ip_a"], attrs["local_ip_b"]) == ("10.0.0.1", "10.0.0.8")

    # Neither pod's loopback is *peered at* by anyone, so nothing is ambiguous and
    # nothing is dropped — no warning is owed here.
    assert builder.warnings == []
