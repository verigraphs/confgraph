"""CCR-0094 — NX-OS Flexible NetFlow (flow record / exporter / monitor).

Before the fix, parsing any NX-OS ``flow record`` / ``flow exporter`` /
``flow monitor`` block left ``ParsedConfig.netflow`` at ``None`` — the whole
flow-telemetry configuration was dropped. These tests pin the model + parser
that captures the three block types and the per-interface application.

DOC-GROUNDED: NetFlow was rejected by the virtual Nexus 9000v 10.5(5), so
there is no device capture. Every config line below traces to the
doc-verified corpus ``syntax-corpus/nxos/netflow.yaml`` (flow-record /
flow-exporter / flow-monitor entries, status doc-only, consultant-cited):

- ``flow record <name>`` / ``match ipv4 source address`` /
  ``match ipv4 destination address`` / ``collect counter bytes`` /
  ``collect counter packets``   (flow-record emitted_form + notes)
- ``flow exporter <name>`` / ``destination <ip> [use-vrf <name>]`` /
  ``source <if>`` / ``version 9``   (flow-exporter emitted_form + notes)
- ``flow monitor <name>`` / ``record <name>`` / ``exporter <name>`` and the
  interface application ``ip flow monitor <name> input``
  (flow-monitor emitted_form + notes)
"""

from confgraph.parsers.nxos_parser import NXOSParser


def _parse(text: str):
    return NXOSParser(text).parse()


class TestFlowRecord:
    def test_flow_record_match_and_collect_fields(self):
        pc = _parse(
            "feature netflow\n"
            "flow record FR_1\n"
            "  match ipv4 source address\n"
            "  match ipv4 destination address\n"
            "  collect counter bytes\n"
            "  collect counter packets\n"
        )
        assert pc.netflow is not None
        assert len(pc.netflow.flow_records) == 1
        rec = pc.netflow.flow_records[0]
        assert rec.name == "FR_1"
        # match/collect kept verbatim (leading keyword stripped), config order
        assert rec.match_fields == [
            "ipv4 source address",
            "ipv4 destination address",
        ]
        assert rec.collect_fields == ["counter bytes", "counter packets"]


class TestFlowExporter:
    def test_flow_exporter_destination_use_vrf_source_version(self):
        pc = _parse(
            "feature netflow\n"
            "flow exporter FE_1\n"
            "  destination 10.199.70.1 use-vrf management\n"
            "  source loopback0\n"
            "  version 9\n"
        )
        assert pc.netflow is not None
        assert len(pc.netflow.flow_exporters) == 1
        exp = pc.netflow.flow_exporters[0]
        assert exp.name == "FE_1"
        assert exp.destination == "10.199.70.1"
        assert exp.use_vrf == "management"
        assert exp.source == "loopback0"
        assert exp.version == 9

    def test_flow_exporter_destination_without_use_vrf(self):
        pc = _parse(
            "feature netflow\n"
            "flow exporter FE_2\n"
            "  destination 10.199.70.2\n"
            "  source loopback0\n"
        )
        exp = pc.netflow.flow_exporters[0]
        assert exp.destination == "10.199.70.2"
        assert exp.use_vrf is None
        assert exp.version is None


class TestFlowMonitor:
    def test_flow_monitor_binds_record_and_exporter(self):
        pc = _parse(
            "feature netflow\n"
            "flow monitor FM_1\n"
            "  record FR_1\n"
            "  exporter FE_1\n"
        )
        assert pc.netflow is not None
        assert len(pc.netflow.flow_monitors) == 1
        mon = pc.netflow.flow_monitors[0]
        assert mon.name == "FM_1"
        assert mon.record == "FR_1"
        assert mon.exporter == "FE_1"


class TestInterfaceApplication:
    def test_ip_flow_monitor_input_applies_to_interface(self):
        pc = _parse(
            "feature netflow\n"
            "flow monitor FM_1\n"
            "  record FR_1\n"
            "  exporter FE_1\n"
            "interface Ethernet1/1\n"
            "  ip flow monitor FM_1 input\n"
        )
        eth = next(i for i in pc.interfaces if i.name == "Ethernet1/1")
        assert len(eth.flow_monitors) == 1
        binding = eth.flow_monitors[0]
        assert binding.monitor == "FM_1"
        assert binding.direction == "input"

    def test_interface_flow_monitor_line_not_flagged_unrecognized(self):
        pc = _parse(
            "interface Ethernet1/1\n"
            "  ip flow monitor FM_1 input\n"
        )
        headers = [b.block_header for b in pc.unrecognized_blocks]
        assert not any("flow monitor" in h for h in headers)


class TestBoundary:
    def test_no_netflow_blocks_leaves_field_absent(self):
        # A device with no Flexible NetFlow blocks keeps netflow at None
        # (the block set is empty -> parse_netflow returns None).
        pc = _parse("hostname n9k\ninterface Ethernet1/1\n  no shutdown\n")
        assert pc.netflow is None

    def test_full_stack_all_three_blocks_and_binding(self):
        pc = _parse(
            "feature netflow\n"
            "flow record FR_1\n"
            "  match ipv4 source address\n"
            "  collect counter bytes\n"
            "flow exporter FE_1\n"
            "  destination 10.199.70.1\n"
            "  source loopback0\n"
            "flow monitor FM_1\n"
            "  record FR_1\n"
            "  exporter FE_1\n"
            "interface Ethernet1/1\n"
            "  ip flow monitor FM_1 input\n"
        )
        assert pc.netflow is not None
        assert [r.name for r in pc.netflow.flow_records] == ["FR_1"]
        assert [e.name for e in pc.netflow.flow_exporters] == ["FE_1"]
        assert [m.name for m in pc.netflow.flow_monitors] == ["FM_1"]
        eth = next(i for i in pc.interfaces if i.name == "Ethernet1/1")
        assert [(b.monitor, b.direction) for b in eth.flow_monitors] == [
            ("FM_1", "input")
        ]
        # top-level flow blocks are claimed, not disclosed as unrecognized
        assert [b.block_header for b in pc.unrecognized_blocks] == []
