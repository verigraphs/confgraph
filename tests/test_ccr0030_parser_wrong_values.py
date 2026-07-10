"""CCR-0030 — parsers write wrong values into the model.

Regression tests for the four confirmed correctness bugs, each asserting the
*exact* extracted value (presence-only assertions are what hid bug 4 on two
parsers). Config lines here use names/IPs distinct from the coverage fixtures.

Bugs:
  1. JunOS vrf-import/vrf-export policy names stored as route-targets.
  2. JunOS NTP `prefer` glommed into the server address.
  3. PAN-OS static route `metric` mis-mapped to `distance`; `admin-dist` ignored.
  4. BGP md5 key: encryption type glommed (IOS/NX-OS) / dropped (EOS) — fixed by
     one shared extractor inherited from IOSParser.
"""

from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.nxos_parser import NXOSParser
from confgraph.parsers.eos_parser import EOSParser
from confgraph.parsers.junos_parser import JunOSParser
from confgraph.parsers.panos_parser import PANOSParser


# ---------------------------------------------------------------------------
# Bug 1 — JunOS vrf-import / vrf-export are policy references, not route-targets
# ---------------------------------------------------------------------------

JUNOS_VRF = """\
routing-instances {
    BLUE {
        instance-type vrf;
        interface ge-0/0/9.0;
        route-distinguisher 64500:7;
        vrf-target target:64500:7;
        vrf-import IMPORT-POLICY-BLUE;
        vrf-export EXPORT-POLICY-BLUE;
    }
}
"""


def test_junos_vrf_import_export_are_policy_refs_not_rts():
    p = JunOSParser(JUNOS_VRF).parse()
    v = next(x for x in p.vrfs if x.name == "BLUE")
    # Policy names land in the policy-reference fields.
    assert v.route_map_import == "IMPORT-POLICY-BLUE"
    assert v.route_map_export == "EXPORT-POLICY-BLUE"
    # ...and never pollute the route-target fields.
    assert v.route_target_import == []
    assert v.route_target_export == []
    assert "IMPORT-POLICY-BLUE" not in v.route_target_import
    assert "EXPORT-POLICY-BLUE" not in v.route_target_export
    # The genuine RT is still captured from vrf-target.
    assert v.route_target_both == ["64500:7"]


# ---------------------------------------------------------------------------
# Bug 2 — JunOS NTP `prefer` (and other trailing keywords) are attributes
# ---------------------------------------------------------------------------

JUNOS_NTP = """\
system {
    ntp {
        server 198.51.100.7 prefer;
        server 198.51.100.8 key 5 version 4;
    }
}
"""


def test_junos_ntp_prefer_not_glommed_into_address():
    p = JunOSParser(JUNOS_NTP).parse()
    assert p.ntp is not None
    by_addr = {str(s.address): s for s in p.ntp.servers}
    assert "198.51.100.7" in by_addr
    s7 = by_addr["198.51.100.7"]
    assert str(s7.address) == "198.51.100.7"  # no " prefer" suffix
    assert s7.prefer is True
    s8 = by_addr["198.51.100.8"]
    assert str(s8.address) == "198.51.100.8"
    assert s8.prefer is False
    assert s8.key_id == 5
    assert s8.version == 4


# ---------------------------------------------------------------------------
# Bug 3 — PAN-OS static route: admin-dist -> distance, metric -> metric
# ---------------------------------------------------------------------------

PANOS_STATIC = """\
<config>
  <devices>
    <entry name="localhost.localdomain">
      <network>
        <virtual-router>
          <entry name="default">
            <routing-table>
              <ip>
                <static-route>
                  <entry name="def">
                    <destination>0.0.0.0/0</destination>
                    <nexthop><ip-address>203.0.113.9</ip-address></nexthop>
                    <metric>15</metric>
                    <admin-dist>115</admin-dist>
                  </entry>
                </static-route>
              </ip>
            </routing-table>
          </entry>
        </virtual-router>
      </network>
    </entry>
  </devices>
</config>
"""


def test_panos_static_admin_dist_is_distance_metric_is_metric():
    p = PANOSParser(PANOS_STATIC).parse()
    r = next(s for s in p.static_routes if str(s.destination) == "0.0.0.0/0")
    assert r.distance == 115   # from <admin-dist>, not <metric>
    assert r.metric == 15      # <metric> now has its own field


# ---------------------------------------------------------------------------
# Bug 4 — one shared BGP md5 password extractor across IOS / NX-OS / EOS
# ---------------------------------------------------------------------------

IOS_BGP = """\
router bgp 64512
 neighbor 203.0.113.20 remote-as 64513
 neighbor 203.0.113.20 password 7 070C285F4D06
"""

NXOS_BGP = """\
feature bgp
router bgp 64512
  neighbor 203.0.113.30
    remote-as 64513
    password 3 MyEncPass
"""

EOS_BGP = """\
router bgp 64512
   neighbor 203.0.113.40 peer group UPSTREAM
   neighbor 203.0.113.40 remote-as 64513
   neighbor 203.0.113.40 password 7 121A0C041104
"""


def _nbr(parser_cls, cfg, ip):
    p = parser_cls(cfg).parse()
    for b in p.bgp_instances:
        for n in b.neighbors:
            if str(n.peer_ip) == ip:
                return n
    raise AssertionError(f"neighbor {ip} not found")


def test_ios_bgp_password_key_only_type_separate():
    n = _nbr(IOSParser, IOS_BGP, "203.0.113.20")
    assert n.password == "070C285F4D06"          # key material only
    assert n.password_encryption_type == "7"      # type in its own field


def test_nxos_bgp_password_key_only_type_separate():
    n = _nbr(NXOSParser, NXOS_BGP, "203.0.113.30")
    assert n.password == "MyEncPass"              # not "3 MyEncPass"
    assert n.password_encryption_type == "3"


def test_eos_bgp_password_captured_not_dropped():
    # EOS had no password branch — the key was dropped entirely (was None).
    n = _nbr(EOSParser, EOS_BGP, "203.0.113.40")
    assert n.password == "121A0C041104"
    assert n.password_encryption_type == "7"


def test_bgp_password_extractor_is_shared_not_reimplemented():
    # The subclasses inherit the *same* extractor object — no per-parser copy.
    assert NXOSParser._split_bgp_password is IOSParser._split_bgp_password
    assert EOSParser._split_bgp_password is IOSParser._split_bgp_password


def test_bgp_password_extractor_handles_plain_key_without_type():
    # A key with no leading encryption-type token keeps the whole value.
    assert IOSParser._split_bgp_password("PlainKey123") == ("PlainKey123", None)
    assert IOSParser._split_bgp_password("7 AABBCC") == ("AABBCC", "7")
    assert IOSParser._split_bgp_password("") == (None, None)
