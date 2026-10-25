"""Tests for OSPF-advanced field parsing (Phase 4.1).

Covers: distance, distance_intra_area, distance_inter_area, distance_external,
default_metric, max_lsa, timers_throttle_spf_*, timers_throttle_lsa_all,
shutdown, graceful_restart, graceful_restart_helper, bfd_all_interfaces.

Each OS gets a test class covering the fields it supports.
"""

from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.nxos_parser import NXOSParser
from confgraph.parsers.eos_parser import EOSParser
from confgraph.parsers.iosxr_parser import IOSXRParser
from confgraph.parsers.junos_parser import JunOSParser


# ---------------------------------------------------------------------------
# IOS — full OSPF-advanced field suite
# ---------------------------------------------------------------------------


class TestIOSOSPFAdvanced:

    def test_distance_ospf(self):
        cfg = (
            "router ospf 1\n"
            " distance ospf intra-area 90 inter-area 100 external 150\n"
        )
        pc = IOSParser(cfg).parse()
        ospf = pc.ospf_instances[0]
        assert ospf.distance_intra_area == 90
        assert ospf.distance_inter_area == 100
        assert ospf.distance_external == 150

    def test_distance_simple(self):
        cfg = (
            "router ospf 1\n"
            " distance 115\n"
        )
        pc = IOSParser(cfg).parse()
        ospf = pc.ospf_instances[0]
        assert ospf.distance == 115

    def test_default_metric(self):
        cfg = (
            "router ospf 1\n"
            " default-metric 20\n"
        )
        pc = IOSParser(cfg).parse()
        assert pc.ospf_instances[0].default_metric == 20

    def test_max_lsa(self):
        cfg = (
            "router ospf 1\n"
            " max-lsa 12000\n"
        )
        pc = IOSParser(cfg).parse()
        assert pc.ospf_instances[0].max_lsa == 12000

    def test_timers_throttle_spf(self):
        cfg = (
            "router ospf 1\n"
            " timers throttle spf 50 200 5000\n"
        )
        pc = IOSParser(cfg).parse()
        ospf = pc.ospf_instances[0]
        assert ospf.timers_throttle_spf_initial == 50
        assert ospf.timers_throttle_spf_min == 200
        assert ospf.timers_throttle_spf_max == 5000

    def test_timers_throttle_lsa_all(self):
        cfg = (
            "router ospf 1\n"
            " timers throttle lsa all 100\n"
        )
        pc = IOSParser(cfg).parse()
        assert pc.ospf_instances[0].timers_throttle_lsa_all == 100

    def test_shutdown(self):
        cfg = (
            "router ospf 1\n"
            " shutdown\n"
        )
        pc = IOSParser(cfg).parse()
        assert pc.ospf_instances[0].shutdown is True

    def test_no_shutdown_default(self):
        cfg = "router ospf 1\n"
        pc = IOSParser(cfg).parse()
        assert pc.ospf_instances[0].shutdown is False

    def test_graceful_restart(self):
        cfg = (
            "router ospf 1\n"
            " graceful-restart\n"
        )
        pc = IOSParser(cfg).parse()
        assert pc.ospf_instances[0].graceful_restart is True

    def test_graceful_restart_helper(self):
        cfg = (
            "router ospf 1\n"
            " graceful-restart helper\n"
        )
        pc = IOSParser(cfg).parse()
        assert pc.ospf_instances[0].graceful_restart_helper is True

    def test_nsf_as_graceful_restart(self):
        cfg = (
            "router ospf 1\n"
            " nsf\n"
        )
        pc = IOSParser(cfg).parse()
        assert pc.ospf_instances[0].graceful_restart is True

    def test_bfd_all_interfaces(self):
        cfg = (
            "router ospf 1\n"
            " bfd all-interfaces\n"
        )
        pc = IOSParser(cfg).parse()
        assert pc.ospf_instances[0].bfd_all_interfaces is True

    def test_all_advanced_fields_combined(self):
        """All OSPF-advanced fields in a single config block."""
        cfg = (
            "router ospf 1\n"
            " distance 110\n"
            " distance ospf intra-area 90 inter-area 100 external 150\n"
            " default-metric 25\n"
            " max-lsa 5000\n"
            " timers throttle spf 50 200 5000\n"
            " timers throttle lsa all 100\n"
            " shutdown\n"
            " graceful-restart\n"
            " graceful-restart helper\n"
            " bfd all-interfaces\n"
        )
        pc = IOSParser(cfg).parse()
        ospf = pc.ospf_instances[0]
        assert ospf.distance == 110
        assert ospf.distance_intra_area == 90
        assert ospf.distance_inter_area == 100
        assert ospf.distance_external == 150
        assert ospf.default_metric == 25
        assert ospf.max_lsa == 5000
        assert ospf.timers_throttle_spf_initial == 50
        assert ospf.timers_throttle_spf_min == 200
        assert ospf.timers_throttle_spf_max == 5000
        assert ospf.timers_throttle_lsa_all == 100
        assert ospf.shutdown is True
        assert ospf.graceful_restart is True
        assert ospf.graceful_restart_helper is True
        assert ospf.bfd_all_interfaces is True

    def test_defaults_when_absent(self):
        """When no advanced fields are present, all default to None/False."""
        cfg = "router ospf 1\n"
        pc = IOSParser(cfg).parse()
        ospf = pc.ospf_instances[0]
        assert ospf.distance is None
        assert ospf.distance_intra_area is None
        assert ospf.distance_inter_area is None
        assert ospf.distance_external is None
        assert ospf.default_metric is None
        assert ospf.max_lsa is None
        assert ospf.timers_throttle_spf_initial is None
        assert ospf.timers_throttle_spf_min is None
        assert ospf.timers_throttle_spf_max is None
        assert ospf.timers_throttle_lsa_all is None
        assert ospf.shutdown is False
        assert ospf.graceful_restart is False
        assert ospf.graceful_restart_helper is False
        assert ospf.bfd_all_interfaces is False


# ---------------------------------------------------------------------------
# NX-OS — inherits IOS parse_ospf via super()
# ---------------------------------------------------------------------------


class TestNXOSOSPFAdvanced:

    def test_inherits_advanced_fields(self):
        """NX-OS delegates to IOS parse_ospf — advanced fields propagate."""
        cfg = (
            "router ospf 1\n"
            " timers throttle spf 100 300 10000\n"
            " bfd all-interfaces\n"
            " graceful-restart\n"
        )
        pc = NXOSParser(cfg).parse()
        ospf = pc.ospf_instances[0]
        assert ospf.timers_throttle_spf_initial == 100
        assert ospf.timers_throttle_spf_min == 300
        assert ospf.timers_throttle_spf_max == 10000
        assert ospf.bfd_all_interfaces is True
        assert ospf.graceful_restart is True


# ---------------------------------------------------------------------------
# EOS — inherits IOS parse_ospf
# ---------------------------------------------------------------------------


class TestEOSOSPFAdvanced:

    def test_inherits_advanced_fields(self):
        """EOS delegates to IOS parse_ospf — advanced fields propagate."""
        cfg = (
            "router ospf 1\n"
            " max-lsa 8000\n"
            " shutdown\n"
            " distance ospf intra-area 80 external 200\n"
        )
        pc = EOSParser(cfg).parse()
        ospf = pc.ospf_instances[0]
        assert ospf.max_lsa == 8000
        assert ospf.shutdown is True
        assert ospf.distance_intra_area == 80
        assert ospf.distance_external == 200


# ---------------------------------------------------------------------------
# IOS-XR — full override, should also parse advanced fields
# ---------------------------------------------------------------------------


class TestIOSXROSPFAdvanced:

    def test_distance_ospf(self):
        cfg = (
            "router ospf 1\n"
            " distance ospf intra-area 85 inter-area 95 external 170\n"
        )
        pc = IOSXRParser(cfg).parse()
        ospf = pc.ospf_instances[0]
        assert ospf.distance_intra_area == 85
        assert ospf.distance_inter_area == 95
        assert ospf.distance_external == 170

    def test_timers_throttle_spf(self):
        cfg = (
            "router ospf 1\n"
            " timers throttle spf 50 200 5000\n"
        )
        pc = IOSXRParser(cfg).parse()
        ospf = pc.ospf_instances[0]
        assert ospf.timers_throttle_spf_initial == 50
        assert ospf.timers_throttle_spf_min == 200
        assert ospf.timers_throttle_spf_max == 5000

    def test_graceful_restart(self):
        cfg = (
            "router ospf 1\n"
            " graceful-restart\n"
        )
        pc = IOSXRParser(cfg).parse()
        assert pc.ospf_instances[0].graceful_restart is True

    def test_nsf_as_graceful_restart(self):
        cfg = (
            "router ospf 1\n"
            " nsf ietf\n"
        )
        pc = IOSXRParser(cfg).parse()
        assert pc.ospf_instances[0].graceful_restart is True

    def test_bfd_fast_detect(self):
        """IOS-XR uses 'bfd fast-detect' instead of 'bfd all-interfaces'."""
        cfg = (
            "router ospf 1\n"
            " bfd fast-detect\n"
        )
        pc = IOSXRParser(cfg).parse()
        assert pc.ospf_instances[0].bfd_all_interfaces is True

    def test_shutdown(self):
        cfg = (
            "router ospf 1\n"
            " shutdown\n"
        )
        pc = IOSXRParser(cfg).parse()
        assert pc.ospf_instances[0].shutdown is True

    def test_defaults_when_absent(self):
        cfg = "router ospf 1\n"
        pc = IOSXRParser(cfg).parse()
        ospf = pc.ospf_instances[0]
        assert ospf.distance is None
        assert ospf.shutdown is False
        assert ospf.graceful_restart is False
        assert ospf.bfd_all_interfaces is False


# ---------------------------------------------------------------------------
# JunOS — hierarchy-based parsing
# ---------------------------------------------------------------------------


class TestJunOSOSPFAdvanced:

    def test_graceful_restart(self):
        cfg = (
            "protocols {\n"
            "    ospf {\n"
            "        graceful-restart;\n"
            "        area 0.0.0.0 {\n"
            "            interface ge-0/0/0.0;\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        pc = JunOSParser(cfg).parse()
        assert pc.ospf_instances[0].graceful_restart is True

    def test_overload_as_max_metric(self):
        """JunOS 'overload' maps to max_metric_router_lsa."""
        cfg = (
            "protocols {\n"
            "    ospf {\n"
            "        overload;\n"
            "        area 0.0.0.0 {\n"
            "            interface ge-0/0/0.0;\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        pc = JunOSParser(cfg).parse()
        assert pc.ospf_instances[0].max_metric_router_lsa is True

    def test_reference_bandwidth(self):
        cfg = (
            "protocols {\n"
            "    ospf {\n"
            "        reference-bandwidth 10g;\n"
            "        area 0.0.0.0 {\n"
            "            interface ge-0/0/0.0;\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        pc = JunOSParser(cfg).parse()
        assert pc.ospf_instances[0].auto_cost_reference_bandwidth == 10000000000

    def test_defaults_when_absent(self):
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
        ospf = pc.ospf_instances[0]
        assert ospf.graceful_restart is False
        assert ospf.max_metric_router_lsa is False
        assert ospf.bfd_all_interfaces is False
        assert ospf.auto_cost_reference_bandwidth is None
