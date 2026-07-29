"""CCR-0088 — NX-OS VRRP advertise timer dropped; VRRPv3 AF groups unmodeled.

Two device-verified defects on n9kv 10.5(5) (own containerlab, push+readback):

1. The classic ``vrrp <grp>`` block emits a child ``advertisement-interval <n>``,
   but the NX-OS collector passed it through untranslated so the shared VRRP
   applier (which only knows the IOS ``timers advertise <n>`` spelling) dropped
   it. ``VRRPGroup.timers_advertise`` was therefore never populated. The fix
   normalizes ``advertisement-interval`` -> ``timers advertise`` in the NX-OS
   ``_collect_vrrp_commands`` block loop, beside the existing ``address``->``ip``
   rewrite.

2. NX-OS VRRPv3 (``vrrpv3 <grp> address-family {ipv4|ipv6}``) was entirely
   unrecognized — parsing the emitted block yielded an empty ``vrrp_groups``.
   The fix models VRRPv3 additively on ``VRRPGroup`` (version/afi/addresses) and
   parses the block key-by-key (the device emits ``priority`` before
   ``address``) in ``NXOSParser._parse_vrrpv3_groups``, merged into the same
   ``vrrp_groups`` list.

Values assert exactly (handbook §7.5 — no presence-only checks). Emitted shapes
from ``syntax-corpus/nxos/vrrp.yaml`` (``vrrp-group`` and
``vrrpv3-address-family``, both verified-capture, n9kv 10.5(5)) and device_facts
``vrrp-advertisement-interval-dropped`` / ``vrrpv3-group-dropped``.
"""
from ipaddress import IPv4Address

from confgraph.parsers.nxos_parser import NXOSParser


def _iface(interfaces, name):
    return next(i for i in interfaces if i.name == name)


# ---- Part 1: VRRPv2 advertisement-interval -> timers_advertise ----
# Device-emitted classic VRRP block (n9kv 10.5(5)).
NXOS_VRRP_V2 = """feature vrrp
feature interface-vlan
interface Vlan210
  vrrp 5
    priority 120
    advertisement-interval 3
    address 10.199.210.1
"""


def test_vrrpv2_advertisement_interval_maps_to_timers_advertise():
    parsed = NXOSParser(NXOS_VRRP_V2).parse()
    grp = _iface(parsed.interfaces, "Vlan210").vrrp_groups[0]
    assert grp.group_number == 5
    assert grp.timers_advertise == 3
    # existing VRRPv2 fields still parse (no regression on the block form)
    assert grp.priority == 120
    assert grp.virtual_ip == IPv4Address("10.199.210.1")
    # v3 dimensions untouched on a classic group
    assert grp.version is None
    assert grp.afi is None
    assert grp.addresses == []


# ---- Part 2: VRRPv3 address-family group modeled ----
# Device-emitted VRRPv3 block; note the device emits priority BEFORE address.
NXOS_VRRPV3 = """feature vrrpv3
interface Vlan131
  no shutdown
  ip address 10.131.131.1/24
  vrrpv3 31 address-family ipv4
    priority 120
    address 10.131.131.254 primary
"""


def test_vrrpv3_address_family_group_modeled():
    parsed = NXOSParser(NXOS_VRRPV3).parse()
    groups = _iface(parsed.interfaces, "Vlan131").vrrp_groups
    assert len(groups) == 1
    grp = groups[0]
    assert grp.group_number == 31
    assert grp.version == 3
    assert grp.afi == "ipv4"
    assert grp.priority == 120
    # IPv4 primary mirrored into virtual_ip for VRRPv2 parity
    assert grp.virtual_ip == IPv4Address("10.131.131.254")
    # verbatim per-AF address (primary keyword preserved)
    assert grp.addresses == ["10.131.131.254 primary"]


# VRRPv3 with an IPv6 AF and a primary + secondary address — parsed by key;
# virtual_ip stays None for a v6 AF (only IPv4 primaries mirror to virtual_ip).
# The afi choice and the primary/secondary keywords are within the documented
# verified-capture form of `vrrpv3-address-family`. The advertise timer is
# deliberately absent here: NX-OS VRRPv3 emits it as `timers advertise <ms>`,
# whose emitted form is doc-only (not capture-verified) — out of scope.
NXOS_VRRPV3_IPV6 = """feature vrrpv3
interface Vlan140
  vrrpv3 40 address-family ipv6
    priority 200
    address fe80::1 primary
    address 2001:db8::1 secondary
"""


def test_vrrpv3_ipv6_af_group():
    parsed = NXOSParser(NXOS_VRRPV3_IPV6).parse()
    grp = _iface(parsed.interfaces, "Vlan140").vrrp_groups[0]
    assert grp.group_number == 40
    assert grp.version == 3
    assert grp.afi == "ipv6"
    assert grp.priority == 200
    assert grp.timers_advertise is None
    assert grp.virtual_ip is None
    assert grp.addresses == ["fe80::1 primary", "2001:db8::1 secondary"]


# ---- Part 3: classic VRRPv2 unchanged (regression guard) ----
# The CLEAN case from the CCR — must parse identically to before the fix.
NXOS_VRRP_CLEAN = """feature vrrp
feature interface-vlan
interface Vlan210
  vrrp 5
    priority 120
    authentication text VRKEY
    address 10.199.210.1
"""


def test_vrrpv2_clean_case_unchanged():
    parsed = NXOSParser(NXOS_VRRP_CLEAN).parse()
    grp = _iface(parsed.interfaces, "Vlan210").vrrp_groups[0]
    assert grp.group_number == 5
    assert grp.priority == 120
    assert grp.virtual_ip == IPv4Address("10.199.210.1")
    assert grp.authentication == "text VRKEY"
    # no VRRPv3 leakage onto a classic group
    assert grp.version is None
    assert grp.afi is None
