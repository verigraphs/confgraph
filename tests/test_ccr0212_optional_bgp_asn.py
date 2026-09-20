"""CCR-0212 (confgraph half) — an omitted ASN stays omitted.

``routing-options autonomous-system`` lives OUTSIDE ``protocols bgp``, so a
JunOS ``set``-idiom proposal that edits BGP alone never restates it.  The parser
used to fabricate ``asn = 0`` because ``BGPConfig.asn`` was a required int, and
AS 0 matches no baseline — the merger then grafted a phantom second BGP
instance, the real process was never touched, and the job reported green.  This
is the CCR-0170 ``remote_as`` discipline applied to instance identity: a value
the source idiom can omit must be Optional, never defaulted to a sentinel.

The scope-matched merge that consumes the None lives in confgraph-entrp
(``tests/test_ccr0212_scope_matched_bgp_instance.py``).
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from confgraph.models.base import OSType
from confgraph.models.bgp import BGPConfig
from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.junos_parser import JunOSParser

PROPOSAL_WITHOUT_ASN = (
    "set protocols bgp group EXT type external\n"
    "set protocols bgp group EXT neighbor 10.0.0.1 peer-as 65099\n"
    "set protocols bgp group EXT neighbor 10.0.0.1 description repointed\n"
)

PROPOSAL_WITH_ASN = "set routing-options autonomous-system 65000\n" + PROPOSAL_WITHOUT_ASN


class TestModel:
    def test_asn_accepts_none(self):
        bgp = BGPConfig(object_id="bgp_none", source_os=OSType.JUNOS, asn=None)
        assert bgp.asn is None

    def test_an_explicit_asn_is_unchanged(self):
        bgp = BGPConfig(object_id="bgp_65000", source_os=OSType.IOS, asn=65000)
        assert bgp.asn == 65000

    def test_asn_is_still_required_to_be_stated(self):
        """Required-but-nullable: nullable so "unknown" is expressible, required
        so a parser cannot forget the field and silently mean None."""
        with pytest.raises(ValidationError):
            BGPConfig(object_id="bgp_x", source_os=OSType.JUNOS)


class TestJunOSParser:
    def test_absent_autonomous_system_parses_to_none_not_zero(self):
        bgp = JunOSParser(PROPOSAL_WITHOUT_ASN).parse().bgp_instances[0]
        assert bgp.asn is None

    def test_a_stated_autonomous_system_is_unchanged(self):
        bgp = JunOSParser(PROPOSAL_WITH_ASN).parse().bgp_instances[0]
        assert bgp.asn == 65000

    def test_an_ibgp_peers_inherited_remote_as_follows_the_absent_asn(self):
        """``remote_as`` is already ``int | None`` (CCR-0170); a peer that
        inherits the device's own AS inherits its absence too, rather than
        reporting a session with AS 0."""
        cfg = (
            "set protocols bgp group INT type internal\n"
            "set protocols bgp group INT neighbor 10.1.1.1 description ibgp-peer\n"
        )
        nbr = JunOSParser(cfg).parse().bgp_instances[0].neighbors[0]
        assert nbr.remote_as is None


class TestIOSFamilyUnaffected:
    def test_the_asn_rides_in_the_router_bgp_header_and_is_always_parsed(self):
        cfg = "router bgp 65000\n neighbor 10.0.0.1 remote-as 65001\n"
        assert IOSParser(cfg, "ios").parse().bgp_instances[0].asn == 65000

    def test_a_vrf_sub_instance_carries_the_same_asn(self):
        cfg = (
            "router bgp 65000\n"
            " address-family ipv4 vrf CUST\n"
            "  neighbor 10.2.2.2 remote-as 65002\n"
        )
        pc = IOSParser(cfg, "ios").parse()
        assert {b.asn for b in pc.bgp_instances} == {65000}
        assert all(b.asn is not None for b in pc.bgp_instances)
