"""Tests for child-line disclosure inside claimed blocks (Fable-5 review F3, WI-2).

A recognized top-level block ("router ospf 1", "interface Gi0/0", ...) may contain
child lines no parse method consumes. Those must surface on
``ParsedConfig.unrecognized_blocks`` with a ``"<block header> > <child line>"``
header instead of vanishing — the engine's coverage layer default-denies via that
field. Precision over recall: a line a parse method DOES consume must never be
flagged.

Run:
    uv run pytest tests/test_unrecognized_child_lines.py -v
"""

from __future__ import annotations

from confgraph.parsers.eos_parser import EOSParser
from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.iosxr_parser import IOSXRParser
from confgraph.parsers.nxos_parser import NXOSParser


def _child_flags(parser) -> list[str]:
    """Headers of child-line disclosures (the 'header > line' entries) only."""
    return [
        b.block_header
        for b in parser.parse().unrecognized_blocks
        if " > " in b.block_header
    ]


# ---------------------------------------------------------------------------
# The F3 repro — distribute-list under router ospf must be disclosed
# ---------------------------------------------------------------------------


class TestOspfDistributeListDisclosed:
    def test_distribute_list_is_flagged(self):
        config = (
            "router ospf 1\n"
            " network 10.0.0.0 0.255.255.255 area 0\n"
            " distribute-list prefix BLOCK-ALL in\n"
        )
        flags = _child_flags(IOSParser(config))
        assert flags == ["router ospf 1 > distribute-list prefix BLOCK-ALL in"]

    def test_flag_carries_raw_line(self):
        config = "router ospf 1\n distribute-list prefix BLOCK-ALL in\n"
        blocks = [
            b for b in IOSParser(config).parse().unrecognized_blocks
            if " > " in b.block_header
        ]
        assert len(blocks) == 1
        assert blocks[0].raw_lines == [" distribute-list prefix BLOCK-ALL in"]


# ---------------------------------------------------------------------------
# Known child lines are NOT flagged — one probe per registered block type
# ---------------------------------------------------------------------------


class TestKnownChildLinesNotFlagged:
    def test_router_ospf_known_children(self):
        config = (
            "router ospf 1\n"
            " router-id 1.1.1.1\n"
            " log-adjacency-changes detail\n"
            " auto-cost reference-bandwidth 100000\n"
            " passive-interface default\n"
            " no passive-interface GigabitEthernet0/0\n"
            " network 10.0.0.0 0.255.255.255 area 0\n"
            " area 1 stub\n"
            " redistribute connected subnets\n"
            " max-metric router-lsa on-startup 300\n"
            " default-information originate always\n"
            " distance 110\n"
            " default-metric 20\n"
            " max-lsa 12000\n"
            " maximum-paths 4\n"
            " timers throttle spf 50 200 5000\n"
            " nsf\n"
            " bfd all-interfaces\n"
        )
        assert _child_flags(IOSParser(config)) == []

    def test_router_bgp_known_children(self):
        config = (
            "router bgp 65000\n"
            " bgp router-id 1.1.1.1\n"
            " bgp log-neighbor-changes\n"
            " neighbor 2.2.2.2 remote-as 65000\n"
            " neighbor 2.2.2.2 update-source Loopback0\n"
            " no neighbor 3.3.3.3\n"
            " network 100.64.1.0 mask 255.255.255.0\n"
            " redistribute connected\n"
            " aggregate-address 100.64.0.0 255.255.0.0 summary-only\n"
            " timers bgp 10 30\n"
            " maximum-paths 4\n"
            " address-family ipv4\n"
            "  neighbor 2.2.2.2 activate\n"
            " exit-address-family\n"
            " auto-summary\n"
            " synchronization\n"
        )
        assert _child_flags(IOSParser(config)) == []

    def test_router_isis_known_children(self):
        config = (
            "router isis CORE\n"
            " net 49.0001.0000.0000.0001.00\n"
            " is-type level-2-only\n"
            " metric-style wide\n"
            " log-adjacency-changes\n"
            " passive-interface Loopback0\n"
            " redistribute static ip\n"
            " spf-interval 5 50 200\n"
            " lsp-refresh-interval 65000\n"
            " max-lsp-lifetime 65535\n"
            " default-information originate\n"
            " summary-address 10.0.0.0 255.0.0.0\n"
        )
        assert _child_flags(IOSParser(config)) == []

    def test_router_eigrp_known_children(self):
        config = (
            "router eigrp 100\n"
            " network 10.0.0.0\n"
            " eigrp router-id 1.1.1.1\n"
            " eigrp stub connected summary\n"
            " passive-interface default\n"
            " redistribute static\n"
            " metric weights 0 1 0 1 0 0\n"
            " variance 2\n"
            " maximum-paths 4\n"
            " distance eigrp 90 170\n"
            " auto-summary\n"
            " summary-address 10.0.0.0 255.0.0.0\n"
        )
        assert _child_flags(IOSParser(config)) == []

    def test_interface_known_children(self):
        config = (
            "interface GigabitEthernet0/0\n"
            " description uplink\n"
            " ip address 10.0.12.1 255.255.255.252\n"
            " ip ospf cost 10\n"
            " ipv6 address 2001:db8::1/64\n"
            " mtu 9000\n"
            " bandwidth 10000\n"
            " speed 1000\n"
            " duplex full\n"
            " switchport mode trunk\n"
            " switchport trunk allowed vlan 10,20\n"
            " channel-group 1 mode active\n"
            " lacp rate fast\n"
            " service-policy output SHAPE\n"
            " standby 1 ip 10.0.12.254\n"
            " vrrp 1 ip 10.0.12.253\n"
            " glbp 1 ip 10.0.12.252\n"
            " tunnel source Loopback0\n"
            " mpls ip\n"
            " bfd interval 300 min_rx 300 multiplier 3\n"
            " vrf forwarding CUST-A\n"
            " spanning-tree portfast\n"
            " storm-control broadcast level 1.00\n"
            " encapsulation dot1Q 100\n"
            " keepalive 10\n"
            " load-interval 30\n"
            " cdp enable\n"
            " shutdown\n"
        )
        assert _child_flags(IOSParser(config)) == []

    def test_nxos_interface_and_ospf_known_children(self):
        config = (
            "interface Ethernet1/1\n"
            " description peer-link\n"
            " switchport mode trunk\n"
            " vpc peer-link\n"
            " ip address 10.0.0.1/30\n"
            " ip router ospf 1 area 0.0.0.0\n"
            " hsrp 10\n"
            "  ip 10.0.0.254\n"
            " no shutdown\n"
            "interface nve1\n"
            " source-interface loopback1\n"
            " host-reachability protocol bgp\n"
            " member vni 10100\n"
            "  mcast-group 239.1.1.1\n"
            " no shutdown\n"
            "router ospf 1\n"
            " router-id 1.1.1.1\n"
            " vrf CUST-A\n"
            "  router-id 2.2.2.2\n"
        )
        assert _child_flags(NXOSParser(config)) == []

    def test_eos_interface_known_children(self):
        config = (
            "interface Vxlan1\n"
            " vxlan source-interface Loopback1\n"
            " vxlan udp-port 4789\n"
            " vxlan vlan 100 vni 10100\n"
            "interface Port-Channel10\n"
            " mlag 10\n"
            " switchport mode trunk\n"
        )
        assert _child_flags(EOSParser(config)) == []


# ---------------------------------------------------------------------------
# Collector rules
# ---------------------------------------------------------------------------


class TestCollectorRules:
    def test_no_lines_never_flagged(self):
        """Negations are the tombstone surface — never child-line disclosure."""
        config = (
            "router ospf 1\n"
            " no some-unknown-thing enable\n"
            "interface GigabitEthernet0/0\n"
            " no obscure-unparsed-feature\n"
        )
        assert _child_flags(IOSParser(config)) == []

    def test_grandchildren_not_flagged(self):
        """v1 checks direct children only — sub-block bodies are not descended."""
        config = (
            "router bgp 65000\n"
            " address-family ipv4\n"
            "  totally-unknown-af-line 42\n"
            " exit-address-family\n"
        )
        assert _child_flags(IOSParser(config)) == []

    def test_unregistered_claimed_blocks_not_checked(self):
        """Blocks without a registry entry (e.g. router rip) flag nothing."""
        config = (
            "router rip\n"
            " some-unknown-rip-line 1\n"
        )
        assert _child_flags(IOSParser(config)) == []

    def test_unclaimed_top_level_blocks_still_whole_block(self):
        """The existing top-level walk is unchanged — one entry, no ' > '."""
        config = "wobbly-new-feature enable\n mode aggressive\n"
        blocks = IOSParser(config).parse().unrecognized_blocks
        assert [b.block_header for b in blocks] == ["wobbly-new-feature enable"]

    def test_multiple_unknown_children_each_flagged(self):
        config = (
            "router ospf 1\n"
            " distribute-list prefix BLOCK-ALL in\n"
            " capability vrf-lite\n"
        )
        assert _child_flags(IOSParser(config)) == [
            "router ospf 1 > distribute-list prefix BLOCK-ALL in",
            "router ospf 1 > capability vrf-lite",
        ]

    def test_iosxr_child_disclosure_disabled(self):
        """XR override keeps an empty registry — no child flags (v1)."""
        config = (
            "router ospf 1\n"
            " distribute-list prefix BLOCK-ALL in\n"
        )
        assert _child_flags(IOSXRParser(config)) == []
