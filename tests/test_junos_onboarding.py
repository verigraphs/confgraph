"""Tests for JunOS parser onboarding readiness (Phase 3).

Covers the brace-style bare statement fix from
confgraph_junos_bracestyle_bare_statements.md:
- Symptom A: OSPF bare interface statements
- Symptom B: Mixed bare + block BGP neighbors

Both brace-style and set-style are tested to ensure no regressions.
"""

from confgraph.parsers.junos_parser import JunOSParser


# ---------------------------------------------------------------------------
# Symptom A — OSPF bare interface statements (brace-style)
# ---------------------------------------------------------------------------


class TestJunOSBraceStyleOSPF:

    def test_bare_interface_statements_parsed(self):
        """Bare ``interface ge-0/0/0.0;`` leaves are captured as area interfaces."""
        cfg = (
            "protocols {\n"
            "    ospf {\n"
            "        area 0.0.0.0 {\n"
            "            interface ge-0/0/0.0;\n"
            "            interface ge-0/0/1.0;\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        pc = JunOSParser(cfg).parse()
        assert pc.ospf_instances
        area = pc.ospf_instances[0].areas[0]
        assert sorted(area.interfaces) == ["ge-0/0/0.0", "ge-0/0/1.0"]

    def test_single_bare_interface(self):
        cfg = (
            "protocols {\n"
            "    ospf {\n"
            "        area 0.0.0.0 {\n"
            "            interface ge-0/0/0.0;\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        pc = JunOSParser(cfg).parse()
        assert pc.ospf_instances
        area = pc.ospf_instances[0].areas[0]
        assert area.interfaces == ["ge-0/0/0.0"]

    def test_mixed_bare_and_block_interfaces(self):
        """Bare + block interfaces coexist (mixed case from CCR facet B pattern)."""
        cfg = (
            "protocols {\n"
            "    ospf {\n"
            "        area 0.0.0.0 {\n"
            "            interface ge-0/0/0.0;\n"
            "            interface ge-0/0/1.0 {\n"
            "                metric 10;\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        pc = JunOSParser(cfg).parse()
        assert pc.ospf_instances
        area = pc.ospf_instances[0].areas[0]
        assert sorted(area.interfaces) == ["ge-0/0/0.0", "ge-0/0/1.0"]

    def test_set_style_ospf_unchanged(self):
        """Set-style OSPF interfaces must continue to work."""
        cfg = (
            "set protocols ospf area 0.0.0.0 interface ge-0/0/0.0\n"
            "set protocols ospf area 0.0.0.0 interface ge-0/0/1.0\n"
        )
        pc = JunOSParser(cfg).parse()
        assert pc.ospf_instances
        area = pc.ospf_instances[0].areas[0]
        assert sorted(area.interfaces) == ["ge-0/0/0.0", "ge-0/0/1.0"]


# ---------------------------------------------------------------------------
# Symptom B — Bare BGP neighbors (brace-style)
# ---------------------------------------------------------------------------


class TestJunOSBraceStyleBGP:

    def test_bare_neighbor_not_dropped(self):
        """Bare ``neighbor 10.0.0.9;`` must not be lost."""
        cfg = (
            "routing-options {\n"
            "    autonomous-system 65001;\n"
            "}\n"
            "protocols {\n"
            "    bgp {\n"
            "        group IBGP {\n"
            "            type internal;\n"
            "            neighbor 10.0.0.9;\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        pc = JunOSParser(cfg).parse()
        assert pc.bgp_instances
        nbr_ips = [str(n.peer_ip) for n in pc.bgp_instances[0].neighbors]
        assert "10.0.0.9" in nbr_ips

    def test_mixed_bare_and_block_neighbors(self):
        """Both bare and block neighbors are present."""
        cfg = (
            "routing-options {\n"
            "    autonomous-system 65001;\n"
            "}\n"
            "protocols {\n"
            "    bgp {\n"
            "        group IBGP {\n"
            "            type internal;\n"
            "            neighbor 10.0.0.9;\n"
            "            neighbor 10.0.0.10 {\n"
            "                description peer-2;\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        pc = JunOSParser(cfg).parse()
        assert pc.bgp_instances
        nbr_ips = sorted(str(n.peer_ip) for n in pc.bgp_instances[0].neighbors)
        assert nbr_ips == ["10.0.0.10", "10.0.0.9"]

        # Verify block neighbor has description
        n10 = next(n for n in pc.bgp_instances[0].neighbors if str(n.peer_ip) == "10.0.0.10")
        assert n10.description == "peer-2"

    def test_block_only_neighbors_unchanged(self):
        """All-block neighbors (no bare leaves) still work."""
        cfg = (
            "routing-options {\n"
            "    autonomous-system 65001;\n"
            "}\n"
            "protocols {\n"
            "    bgp {\n"
            "        group EBGP {\n"
            "            neighbor 10.0.0.1 {\n"
            "                peer-as 65002;\n"
            "            }\n"
            "            neighbor 10.0.0.2 {\n"
            "                peer-as 65003;\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        pc = JunOSParser(cfg).parse()
        assert pc.bgp_instances
        nbr_ips = sorted(str(n.peer_ip) for n in pc.bgp_instances[0].neighbors)
        assert nbr_ips == ["10.0.0.1", "10.0.0.2"]

    def test_set_style_bgp_unchanged(self):
        """Set-style BGP neighbors must continue to work."""
        cfg = (
            "set routing-options autonomous-system 65001\n"
            "set protocols bgp group IBGP type internal\n"
            "set protocols bgp group IBGP neighbor 10.0.0.9\n"
            "set protocols bgp group IBGP neighbor 10.0.0.10 description peer-2\n"
        )
        pc = JunOSParser(cfg).parse()
        assert pc.bgp_instances
        nbr_ips = sorted(str(n.peer_ip) for n in pc.bgp_instances[0].neighbors)
        assert nbr_ips == ["10.0.0.10", "10.0.0.9"]


# ---------------------------------------------------------------------------
# Hierarchy layer — bare leaf promotion
# ---------------------------------------------------------------------------


class TestJunOSHierarchyPromotion:

    def test_leaf_then_block_promotes_leaf(self):
        """A bare leaf followed by a named block of the same keyword keeps both."""
        from confgraph.parsers.junos_hierarchy import parse_junos_config

        cfg = "foo bar; foo baz { qux 1; }"
        result = parse_junos_config(cfg)
        assert isinstance(result["foo"], dict)
        assert "bar" in result["foo"]
        assert "baz" in result["foo"]

    def test_block_then_leaf_adds_to_dict(self):
        """A named block followed by a bare leaf of the same keyword keeps both."""
        from confgraph.parsers.junos_hierarchy import parse_junos_config

        cfg = "foo baz { qux 1; } foo bar;"
        result = parse_junos_config(cfg)
        assert isinstance(result["foo"], dict)
        assert "bar" in result["foo"]
        assert "baz" in result["foo"]

    def test_multiple_bare_leaves_then_block(self):
        """Multiple bare leaves promoted when a block arrives."""
        from confgraph.parsers.junos_hierarchy import parse_junos_config

        cfg = "intf a; intf b; intf c { metric 10; }"
        result = parse_junos_config(cfg)
        assert isinstance(result["intf"], dict)
        assert "a" in result["intf"]
        assert "b" in result["intf"]
        assert "c" in result["intf"]
