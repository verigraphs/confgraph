"""CCR-0059 — the seven constructs a real Arista switch EMITS and the parser could not read.

Every config line below is copied **verbatim from a device capture**: the
``show running-config`` of an Arista cEOS 4.36.1F (containerlab, 2026-07-14), stored at
``syntax-corpus/captures/eos/2026-07-14-ceos-4.36.1F-running-config.txt``. Where a test
needs a form the capture does not contain, that form was pushed to the same live switch
and its emitted rendering read back (each such line is annotated below).

That provenance is the whole point of the CCR. The previous EOS fixture was hand-written,
19 of its lines are rejected outright by a real switch, and Arista scored 100% against it
while the parser could not read a VRF's route-targets, an interface's PIM mode, a BGP
aggregate, a VRF-scoped syslog server, the DNS domain, a passive IS-IS interface or any
multicast configuration at all.

Assertions are on VALUES, never on presence: a presence check is what let these seven
survive — ``multicast is not None`` and ``len(hosts) >= 1`` are both satisfied by a parser
that reads the wrong thing, or half of it.
"""

from confgraph.parsers.eos_parser import EOSParser
from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.iosxr_parser import IOSXRParser
from confgraph.parsers.nxos_parser import NXOSParser


# ---------------------------------------------------------------------------
# 1 + 2 — RD and route-targets live under `router bgp <asn> / vrf NAME` on EOS,
#         NOT under `vrf instance`. (Capture lines 40-41, 223-231.)
# ---------------------------------------------------------------------------

EOS_VRF_RD_RT = """
vrf instance CUSTOMER_A
   description Customer A L3VPN VRF
!
vrf instance MGMT
!
router bgp 65000
   router-id 1.1.1.1
   vrf CUSTOMER_A
      rd 65000:100
      route-target import 65000:100
      route-target export 65000:100
      router-id 192.168.10.1
      neighbor 192.168.10.2 remote-as 65100
      redistribute connected
"""


def test_eos_vrf_rd_and_route_targets_come_from_the_bgp_vrf_block():
    p = EOSParser(EOS_VRF_RD_RT).parse()

    vrf = next(v for v in p.vrfs if v.name == "CUSTOMER_A")
    assert vrf.rd == "65000:100"
    assert vrf.route_target_import == ["65000:100"]
    assert vrf.route_target_export == ["65000:100"]
    # The `vrf instance` block still owns what it really does declare.
    assert vrf.description == "Customer A L3VPN VRF"

    # And they are recorded where they were DECLARED, too.
    bgp_vrf = next(b for b in p.bgp_instances if b.vrf == "CUSTOMER_A")
    assert bgp_vrf.rd == "65000:100"
    assert bgp_vrf.route_target_import == ["65000:100"]
    assert bgp_vrf.route_target_export == ["65000:100"]


def test_eos_vrf_with_no_bgp_block_keeps_an_empty_rd():
    """The back-fill fills; it never invents."""
    p = EOSParser(EOS_VRF_RD_RT).parse()
    mgmt = next(v for v in p.vrfs if v.name == "MGMT")
    assert mgmt.rd is None
    assert mgmt.route_target_import == []


IOSXR_VRF_RT_IN_VRF_BLOCK = """
vrf TENANT_X
 address-family ipv4 unicast
  import route-target
   65010:11
  !
  export route-target
   65010:22
  !
 !
!
router bgp 65010
 vrf TENANT_X
  rd 65010:77
  neighbor 198.51.100.2
   remote-as 65020
"""


def test_the_vrf_block_wins_and_the_bgp_block_only_fills_what_it_left_blank():
    """IOS-XR splits the two: RD under BGP, route-targets under the VRF.

    The shared back-fill must take the RD from BGP without touching the
    route-targets the VRF block already answered.
    """
    p = IOSXRParser(IOSXR_VRF_RT_IN_VRF_BLOCK).parse()
    vrf = next(v for v in p.vrfs if v.name == "TENANT_X")
    assert vrf.rd == "65010:77"                      # back-filled from `router bgp`
    assert vrf.route_target_import == ["65010:11"]   # kept from the VRF block
    assert vrf.route_target_export == ["65010:22"]


# ---------------------------------------------------------------------------
# 3 — interface PIM mode: EOS says `pim ipv4 sparse-mode`. (Capture line 77.)
# ---------------------------------------------------------------------------

EOS_PIM_INTERFACE = """
interface Ethernet1
   description UPLINK-TO-CORE
   no switchport
   ip address 172.16.1.1/30
   pim ipv4 sparse-mode
"""

# `pim ipv4 bidirectional` and `pim ipv4 border-router` are NOT alternative modes:
# pushed to the live cEOS they are accepted and emitted ALONGSIDE `pim ipv4
# sparse-mode`, all three on the same interface. `pim ipv4 dense-mode` is rejected
# ("% Invalid input") — EOS has no dense mode.
EOS_PIM_INTERFACE_WITH_FLAGS = """
interface Ethernet1
   no switchport
   ip address 172.16.1.1/30
   pim ipv4 sparse-mode
   pim ipv4 bidirectional
   pim ipv4 border-router
"""


def test_eos_interface_pim_mode():
    p = EOSParser(EOS_PIM_INTERFACE).parse()
    e1 = next(i for i in p.interfaces if i.name == "Ethernet1")
    assert e1.pim_mode == "sparse-mode"


def test_eos_pim_flags_are_not_mistaken_for_the_mode():
    p = EOSParser(EOS_PIM_INTERFACE_WITH_FLAGS).parse()
    e1 = next(i for i in p.interfaces if i.name == "Ethernet1")
    assert e1.pim_mode == "sparse-mode"   # not "bidirectional", not "border-router"


def test_cisco_interface_pim_mode_still_reads_its_own_spelling():
    """`ip pim sparse-mode` — the Cisco-family spelling, from `_work/nxos_full.cfg`."""
    p = NXOSParser("""
interface Ethernet1/1
  ip address 10.0.0.1/24
  ip pim sparse-mode
""").parse()
    e1 = next(i for i in p.interfaces if i.name == "Ethernet1/1")
    assert e1.pim_mode == "sparse-mode"


# ---------------------------------------------------------------------------
# 4 — `aggregate-address 10.0.0.0/8 as-set summary-only`: EOS prints it at the
#     PROCESS level, and in the opposite keyword order. (Capture line 213.)
# ---------------------------------------------------------------------------

EOS_BGP_AGGREGATE = """
router bgp 65000
   router-id 1.1.1.1
   maximum-paths 8 ecmp 8
   aggregate-address 10.0.0.0/8 as-set summary-only
   !
   address-family ipv4
      network 10.0.0.0/16 route-map RM_REDIST
      redistribute connected route-map RM_REDIST
"""


def test_eos_process_level_aggregate_lands_in_the_ipv4_family():
    p = EOSParser(EOS_BGP_AGGREGATE).parse()
    bgp = next(b for b in p.bgp_instances if b.vrf is None)
    af = next(a for a in bgp.address_families if a.afi == "ipv4")

    assert len(af.aggregate_addresses) == 1
    agg = af.aggregate_addresses[0]
    assert str(agg.prefix) == "10.0.0.0/8"
    # BOTH flags. The device reorders what you type — you type `summary-only as-set`
    # and it prints `as-set summary-only` — and the old AF-level parser swallowed the
    # first keyword after a CIDR prefix into its mask group, so `as_set` read False.
    assert agg.summary_only is True
    assert agg.as_set is True

    # maximum-paths is emitted at the process level too, and still reaches the AF.
    assert af.maximum_paths == 8


def test_ios_dotted_mask_aggregate_is_unchanged():
    """The IOS spelling, in the IOS keyword order, inside an AF block.

    Lines as committed in `_work/ios_full.cfg`.
    """
    p = IOSParser("""
router bgp 65000
 address-family ipv4
  aggregate-address 10.0.0.0 255.0.0.0 summary-only as-set
  maximum-paths 8
 exit-address-family
""").parse()
    bgp = next(b for b in p.bgp_instances if b.vrf is None)
    af = next(a for a in bgp.address_families if a.afi == "ipv4")
    agg = af.aggregate_addresses[0]
    assert str(agg.prefix) == "10.0.0.0/8"
    assert agg.summary_only is True
    assert agg.as_set is True


# ---------------------------------------------------------------------------
# 5 — `logging vrf MGMT host 10.0.0.21`: EOS names the VRF BEFORE the host.
#     (Capture lines 13-15.)
# ---------------------------------------------------------------------------

EOS_SYSLOG = """
logging vrf MGMT host 10.0.0.21
logging host 10.0.0.20
logging source-interface Loopback0
"""


def test_eos_vrf_scoped_syslog_host_is_read():
    p = EOSParser(EOS_SYSLOG).parse()

    hosts = {str(h.address): h for h in p.syslog.hosts}
    assert sorted(hosts) == ["10.0.0.20", "10.0.0.21"]
    assert hosts["10.0.0.21"].vrf == "MGMT"   # not None, and not "MGMT host"
    assert hosts["10.0.0.20"].vrf is None
    assert p.syslog.source_interface == "Loopback0"


def test_ios_syslog_host_is_unchanged():
    """The IOS spellings, unaffected by EOS joining the pattern set.

    Deliberately NOT asserted here: `logging host 10.0.0.21 vrf MGMT`. That is the
    form an operator TYPES on IOS; no source establishes that an IOS device PRINTS
    it, and Cisco's own IPv4 `show running-config` transcript in the VRF-Aware System
    Message Logging chapter prints the VRF BEFORE the address —
    `logging host vrf vpn1 10.0.0.3`. Until a cisco-ios capture settles that, a test
    asserting either spelling would be asserting folklore. (See the follow-up filed
    with CCR-0059: on the vrf-first spelling confgraph today reads address="vrf".)
    """
    p = IOSParser("""
logging host 10.0.0.20
logging trap informational
logging source-interface Loopback0
""").parse()
    host = p.syslog.hosts[0]
    assert str(host.address) == "10.0.0.20"
    assert host.vrf is None
    assert p.syslog.trap_level == "informational"
    assert p.syslog.source_interface == "Loopback0"


# ---------------------------------------------------------------------------
# 6 — `dns domain example.com` + `ip name-server vrf default …`. (Capture 18-20.)
# ---------------------------------------------------------------------------

EOS_DNS = """
hostname R1-EOS-FULL
ip name-server vrf default 8.8.4.4
ip name-server vrf default 8.8.8.8
dns domain example.com
"""


def test_eos_dns_domain_and_name_servers():
    p = EOSParser(EOS_DNS).parse()
    assert p.dns.domain_name == "example.com"     # was None: EOS has no `ip domain-name`
    assert p.dns.name_servers == ["8.8.4.4", "8.8.8.8"]


def test_ios_domain_name_is_unchanged():
    """Lines as committed in `_work/ios_full.cfg`."""
    p = IOSParser("""
ip domain name example.com
ip name-server 8.8.8.8
""").parse()
    assert p.dns.domain_name == "example.com"
    assert p.dns.name_servers == ["8.8.8.8"]


# ---------------------------------------------------------------------------
# 7 — `isis passive` on the INTERFACE. EOS has no `passive-interface` under
#     `router isis` — the device rejects it. (Capture lines 90-93, 233-238.)
# ---------------------------------------------------------------------------

EOS_ISIS = """
interface Ethernet1
   no switchport
   ip address 172.16.1.1/30
   isis enable CORE
!
interface Loopback0
   ip address 1.1.1.1/32
   isis enable CORE
   isis passive
!
router isis CORE
   net 49.0001.0000.0000.0001.00
   is-type level-2
   log-adjacency-changes
   redistribute bgp route-map RM_REDIST
   advertise passive-only
"""


def test_eos_isis_passive_interface_declared_on_the_interface():
    p = EOSParser(EOS_ISIS).parse()
    isis = p.isis_instances[0]

    assert isis.tag == "CORE"
    assert isis.net == ["49.0001.0000.0000.0001.00"]
    assert isis.is_type == "level-2"
    # The passive interface, named from the interface end.
    assert isis.passive_interfaces == ["Loopback0"]
    # Membership comes from `isis enable CORE`, so BOTH interfaces are in the process,
    # and only one of them is passive.
    assert {i.name: i.passive for i in isis.interfaces} == {
        "Ethernet1": False,
        "Loopback0": True,
    }
    assert [r.protocol for r in isis.redistribute] == ["bgp"]
    assert isis.redistribute[0].route_map == "RM_REDIST"


def test_ios_process_level_passive_interface_is_unchanged():
    """Lines as committed in `_work/ios_full.cfg` (router isis CORE block)."""
    p = IOSParser("""
router isis CORE
 net 49.0001.0000.0000.0001.00
 is-type level-2-only
 metric-style wide
 redistribute bgp 65000 route-map RM_REDIST
 passive-interface Loopback0
""").parse()
    isis = p.isis_instances[0]
    assert isis.passive_interfaces == ["Loopback0"]
    assert isis.metric_style == "wide"


# ---------------------------------------------------------------------------
# 8 — multicast. EOS states it as BLOCKS: `router multicast` and
#     `router pim sparse-mode`, with the address family in between.
#     (Capture lines 240-264.)
# ---------------------------------------------------------------------------

EOS_MULTICAST = """
router multicast
   ipv4
      routing
!
router pim sparse-mode
   ipv4
      rp address 1.1.1.1 239.0.0.0/8
"""

# The other `rp address` renderings, each pushed to the live cEOS and read back from
# its running-config verbatim (2026-07-14).
EOS_MULTICAST_RP_FORMS = """
router pim sparse-mode
   ipv4
      rp address 2.2.2.2 access-list ACL_MGMT
      rp address 4.4.4.4 override
      rp address 5.5.5.5 239.1.0.0/16 priority 20
"""


def test_eos_multicast_blocks_are_read():
    p = EOSParser(EOS_MULTICAST).parse()

    assert p.multicast.multicast_routing_enabled is True
    assert len(p.multicast.pim_rp_addresses) == 1
    rp = p.multicast.pim_rp_addresses[0]
    assert str(rp.rp_address) == "1.1.1.1"
    # The groups this RP serves are named by PREFIX. That is not an ACL name, and
    # putting it in `acl` would dangle against ACLConfig (the CCR-0030 shape).
    assert rp.group_range == "239.0.0.0/8"
    assert rp.acl is None


def test_eos_rp_address_group_prefix_and_acl_are_different_fields():
    p = EOSParser(EOS_MULTICAST_RP_FORMS).parse()
    rps = {str(r.rp_address): r for r in p.multicast.pim_rp_addresses}
    assert sorted(rps) == ["2.2.2.2", "4.4.4.4", "5.5.5.5"]

    assert rps["2.2.2.2"].acl == "ACL_MGMT"
    assert rps["2.2.2.2"].group_range is None

    assert rps["4.4.4.4"].override is True
    assert rps["4.4.4.4"].acl is None

    assert rps["5.5.5.5"].group_range == "239.1.0.0/16"
    assert rps["5.5.5.5"].acl is None


def test_ios_flat_multicast_lines_are_unchanged():
    """Lines as committed in `_work/ios_full.cfg`.

    UPDATED by CCR-0085. The fixture line uses the `group-list` keyword, which is
    NX-OS-specific — classic IOS/IOS-XE has NO `group-list` keyword in
    `ip pim rp-address` (the ACL is a bare trailing token; Cisco IOS IP Multicast
    Command Reference, `ip pim rp-address`). CCR-0085 makes the shared parser
    keyword-aware: `group-list <token>` is a group selector and lands in
    `group_range` on every OS, so this (non-device-emitted) IOS line now reads
    `group_range='ACL_MGMT'`, not `acl`. The genuine IOS bare-acl form is asserted
    unchanged below. Follow-up: `_work/ios_full.cfg` should use the bare-acl form.
    """
    p = IOSParser("""
ip multicast-routing
ip pim rp-address 1.1.1.1 group-list ACL_MGMT
ip pim ssm default
""").parse()
    assert p.multicast.multicast_routing_enabled is True
    rp = p.multicast.pim_rp_addresses[0]
    assert str(rp.rp_address) == "1.1.1.1"
    # group-list keyword -> group_range (CCR-0085), even for this non-device IOS line.
    assert rp.group_range == "ACL_MGMT"
    assert rp.acl is None

    # The DEVICE-EMITTED IOS form is a BARE access-list token -> acl, unchanged:
    p2 = IOSParser("ip pim rp-address 2.2.2.2 SM_ACL\n").parse()
    rp2 = p2.multicast.pim_rp_addresses[0]
    assert rp2.acl == "SM_ACL"
    assert rp2.group_range is None
