"""CCR-0075 — NX-OS vPC peer-gateway modeling.

Device (Nexus 9000v, NX-OS 10.3(8)) emits a bare ``peer-gateway`` line under
``vpc domain``; ``VPCConfig`` previously had no field for it so the line was
dropped. These tests assert the value is captured and that the existing vPC
fields (domain_id, peer-keepalive dest/source) do not regress.

Emitted form per syntax-corpus/nxos/vpc.yaml (verified-capture): bare
``peer-gateway``.
"""

from confgraph.parsers.nxos_parser import NXOSParser


def _parse(config: str):
    return NXOSParser(config).parse()


# Device-emitted block, read read-only off the box per the CCR capture.
_VPC_WITH_PEER_GATEWAY = """\
feature vpc
vpc domain 10
  peer-keepalive destination 10.255.255.2 source 10.255.255.1
  peer-gateway
"""

_VPC_NO_PEER_GATEWAY = """\
feature vpc
vpc domain 10
  peer-keepalive destination 10.255.255.2 source 10.255.255.1
"""

_VPC_EXPLICIT_NO = """\
feature vpc
vpc domain 10
  peer-keepalive destination 10.255.255.2 source 10.255.255.1
  no peer-gateway
"""


class TestVPCPeerGateway:
    def test_peer_gateway_present_sets_true(self):
        p = _parse(_VPC_WITH_PEER_GATEWAY)
        assert p.vpc is not None
        assert p.vpc.peer_gateway is True

    def test_absent_peer_gateway_defaults_false(self):
        p = _parse(_VPC_NO_PEER_GATEWAY)
        assert p.vpc is not None
        assert p.vpc.peer_gateway is False

    def test_explicit_no_peer_gateway_false(self):
        p = _parse(_VPC_EXPLICIT_NO)
        assert p.vpc is not None
        assert p.vpc.peer_gateway is False

    def test_existing_vpc_fields_not_regressed(self):
        """peer-gateway must not disturb domain_id or peer-keepalive parsing."""
        p = _parse(_VPC_WITH_PEER_GATEWAY)
        assert str(p.vpc.domain_id) == "10"
        assert str(p.vpc.peer_keepalive_destination) == "10.255.255.2"
        assert str(p.vpc.peer_keepalive_source) == "10.255.255.1"
