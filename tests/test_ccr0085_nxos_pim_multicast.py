"""CCR-0085 — NX-OS PIM/multicast: anycast-rp + spt-threshold modeling and
rp-address group-list group-range attribution.

Device-verified forms (Nexus 9000v 10.5(5), full push+readback) are recorded in
syntax-corpus/nxos/multicast.yaml (all `verified-capture`). The shared
IOSParser.parse_multicast is inherited by NXOSParser; EOS and IOS-XR override it,
so they are unaffected. Value-asserting, plus the IOS bare-acl non-regression.
"""

from confgraph.parsers.nxos_parser import NXOSParser
from confgraph.parsers.ios_parser import IOSParser


def _nxos(config: str):
    return NXOSParser(config).parse()


def _ios(config: str):
    return IOSParser(config).parse()


# ---------------------------------------------------------------------------
# Fix 1 — ip pim anycast-rp <rp> <peer> (previously DROPPED)
# ---------------------------------------------------------------------------


class TestAnycastRP:
    def test_anycast_rp_parsed(self):
        p = _nxos("feature pim\nip pim anycast-rp 10.199.200.1 10.199.200.2\n")
        entries = p.multicast.pim_anycast_rp
        assert len(entries) == 1
        assert str(entries[0].anycast_address) == "10.199.200.1"
        assert str(entries[0].peer_address) == "10.199.200.2"

    def test_multiple_peers_accumulate(self):
        p = _nxos(
            "feature pim\n"
            "ip pim anycast-rp 10.199.200.1 10.199.200.2\n"
            "ip pim anycast-rp 10.199.200.1 10.199.200.3\n"
        )
        peers = {str(e.peer_address) for e in p.multicast.pim_anycast_rp}
        assert peers == {"10.199.200.2", "10.199.200.3"}
        # both share the one logical (anycast) RP address
        assert {str(e.anycast_address) for e in p.multicast.pim_anycast_rp} == {"10.199.200.1"}

    def test_dump_key_populated(self):
        # mirrors the device-fact assertion: a populated key containing 'anycast'
        p = _nxos("feature pim\nip pim anycast-rp 10.199.200.1 10.199.200.2\n")
        dump = p.multicast.model_dump()
        assert any("anycast" in str(k).lower() and dump.get(k) for k in dump)


# ---------------------------------------------------------------------------
# Fix 2 — ip pim spt-threshold [infinity|<n>] [group-list <X>] (previously DROPPED)
# ---------------------------------------------------------------------------


class TestSPTThreshold:
    def test_infinity_with_group_list(self):
        p = _nxos("feature pim\nip pim spt-threshold infinity group-list PIM_SPT\n")
        thr = p.multicast.pim_spt_threshold
        assert len(thr) == 1
        assert thr[0].threshold == "infinity"
        assert thr[0].group_list == "PIM_SPT"

    def test_infinity_without_group_list(self):
        p = _nxos("feature pim\nip pim spt-threshold infinity\n")
        thr = p.multicast.pim_spt_threshold
        assert len(thr) == 1
        assert thr[0].threshold == "infinity"
        assert thr[0].group_list is None

    def test_dump_key_populated(self):
        # mirrors the device-fact assertion: a populated key containing 'spt'
        p = _nxos("feature pim\nip pim spt-threshold infinity group-list PIM_SPT\n")
        dump = p.multicast.model_dump()
        assert any("spt" in str(k).lower() and dump.get(k) for k in dump)


# ---------------------------------------------------------------------------
# Fix 3 — ip pim rp-address <rp> group-list <prefix> -> group_range (not acl)
# ---------------------------------------------------------------------------


class TestRPAddressGroupList:
    def test_group_list_prefix_goes_to_group_range(self):
        p = _nxos("feature pim\nip pim rp-address 10.199.200.1 group-list 239.0.0.0/8\n")
        rp = next(
            r for r in p.multicast.pim_rp_addresses if str(r.rp_address) == "10.199.200.1"
        )
        assert rp.group_range == "239.0.0.0/8"
        assert rp.acl is None  # a prefix must NOT land in the ACL-name field

    def test_group_list_with_acl_name_value(self):
        # group-list introduces a group-selector; whatever token follows the keyword
        # is a group range, never an acl-positional. (ios_full.cfg uses ACL_MGMT here.)
        p = _ios("ip pim rp-address 1.1.1.1 group-list ACL_MGMT\n")
        rp = next(r for r in p.multicast.pim_rp_addresses if str(r.rp_address) == "1.1.1.1")
        assert rp.group_range == "ACL_MGMT"
        assert rp.acl is None


class TestIOSBareACLNonRegression:
    """IOS/IOS-XE `ip pim rp-address <rp> [<access-list>] [override] [bidir]` — the
    ACL is a BARE trailing token (there is no group-list keyword; Cisco IOS IP
    Multicast Command Reference). Bare token must still land in `acl`, group_range None.
    """

    def test_bare_named_acl(self):
        # emitted form example: `ip pim rp-address 10.0.0.1 SM_ACL`
        p = _ios("ip pim rp-address 10.0.0.1 SM_ACL\n")
        rp = p.multicast.pim_rp_addresses[0]
        assert rp.acl == "SM_ACL"
        assert rp.group_range is None

    def test_bare_numeric_acl(self):
        # emitted form example: `ip pim rp-address 172.16.0.2 10`
        p = _ios("ip pim rp-address 172.16.0.2 10\n")
        rp = p.multicast.pim_rp_addresses[0]
        assert rp.acl == "10"
        assert rp.group_range is None

    def test_override_only(self):
        p = _ios("ip pim rp-address 4.4.4.4 override\n")
        rp = p.multicast.pim_rp_addresses[0]
        assert rp.acl is None
        assert rp.group_range is None
        assert rp.override is True

    def test_no_trailing_token(self):
        p = _ios("ip pim rp-address 10.0.0.3\n")
        rp = p.multicast.pim_rp_addresses[0]
        assert rp.acl is None
        assert rp.group_range is None


# ---------------------------------------------------------------------------
# Combined device block — all constructs coexist, the two CLEAN facts stay clean
# ---------------------------------------------------------------------------


class TestFullDeviceBlock:
    CFG = (
        "feature pim\n"
        "ip pim rp-address 10.199.200.1 group-list 239.0.0.0/8\n"
        "ip pim ssm range 232.0.0.0/8\n"
        "ip pim anycast-rp 10.199.200.1 10.199.200.2\n"
        "ip pim spt-threshold infinity group-list PIM_SPT\n"
        "interface loopback120\n"
        "  ip pim sparse-mode\n"
    )

    def test_all_constructs(self):
        p = _nxos(self.CFG)
        m = p.multicast
        # fix 3
        rp = next(r for r in m.pim_rp_addresses if str(r.rp_address) == "10.199.200.1")
        assert rp.group_range == "239.0.0.0/8" and rp.acl is None
        # fix 1 + 2
        assert [str(e.peer_address) for e in m.pim_anycast_rp] == ["10.199.200.2"]
        assert m.pim_spt_threshold[0].threshold == "infinity"
        # CLEAN facts still clean
        assert m.pim_ssm_range == "232.0.0.0/8"
        lo = next(i for i in p.interfaces if i.name == "loopback120")
        assert getattr(lo, "pim_mode", None) == "sparse-mode"
