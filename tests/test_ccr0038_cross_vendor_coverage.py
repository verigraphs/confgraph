"""CCR-0038 — the same concept must parse on every OS, not just some.

Every assertion here is a VALUE assertion. A presence check (`bool(x)`,
`len(x) >= 1`) passes on a wrong value, and a wrong value is worse than a
missing one — which is the whole complaint the CCR is about.

Four themes:

  1. VRF `description`   — was missing on 5 of 6 OSes.
  2. OSPF per-interface settings written INSIDE the routing process (IOS-XR,
     JunOS, PAN-OS) must reach `InterfaceConfig`, which is where IOS/NX-OS/EOS
     already put them.
  3. BGP `graceful-restart` on JunOS and PAN-OS.
  4. `line` config on NX-OS (`line vty`) and IOS-XR (`line default`).

Config syntax used below is device-EMITTED form, per syntax-corpus and the
consultations recorded in the CCR — notably NX-OS `import map` (NOT
`import route-map`, which no Nexus emits) and the JunOS rule that
`routing-options { graceful-restart; }` is the only thing that ENABLES GR.
"""

import pytest

from confgraph.change_ir import simple_keyed_list_key
from confgraph.models.base import OSType
from confgraph.models.interface import InterfaceConfig, InterfaceType
from confgraph.models.line import LineType
from confgraph.models.ospf import OSPFArea, OSPFConfig, OSPFInterfaceConfig
from confgraph.models.parsed_config import ParsedConfig
from confgraph.parsers.eos_parser import EOSParser
from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.iosxr_parser import IOSXRParser
from confgraph.parsers.junos_parser import JunOSParser
from confgraph.parsers.nxos_parser import NXOSParser
from confgraph.parsers.panos_parser import PANOSParser


# ---------------------------------------------------------------------------
# Theme 1 — VRF description, on every OS that has a VRF
# ---------------------------------------------------------------------------

IOS_VRF = (
    "vrf definition TENANT_RED\n"
    " description Red tenant L3VPN\n"
    " rd 65001:11\n"
    "!\n"
)

EOS_VRF = (
    "vrf instance TENANT_RED\n"
    "   description Red tenant L3VPN\n"
    "   rd 65001:11\n"
    "!\n"
)

NXOS_VRF = (
    "vrf context TENANT_RED\n"
    "  description Red tenant L3VPN\n"
    "  rd 65001:11\n"
    "  address-family ipv4 unicast\n"
    "    route-target import 65001:11\n"
    "    import map RM_RED_IN\n"
    "    export map RM_RED_OUT\n"
    "!\n"
)

IOSXR_VRF = (
    "vrf TENANT_RED\n"
    " description Red tenant L3VPN\n"
    " address-family ipv4 unicast\n"
    "  import route-policy RP-RED-IN\n"
    "  export route-policy RP-RED-OUT\n"
    " !\n"
    "!\n"
)

JUNOS_VRF = (
    "routing-instances {\n"
    "    TENANT_RED {\n"
    "        instance-type vrf;\n"
    '        description "Red tenant L3VPN";\n'
    "        route-distinguisher 65001:11;\n"
    "    }\n"
    "}\n"
)


@pytest.mark.parametrize(
    "parser_cls, cfg",
    [
        (IOSParser, IOS_VRF),
        (EOSParser, EOS_VRF),
        (NXOSParser, NXOS_VRF),
        (IOSXRParser, IOSXR_VRF),
        (JunOSParser, JUNOS_VRF),
    ],
    ids=["ios", "eos", "nxos", "iosxr", "junos"],
)
def test_vrf_description_parses_on_every_os(parser_cls, cfg):
    """The single most widely-missing field in confgraph. Five parsers, one field."""
    vrfs = parser_cls(cfg).parse().vrfs
    vrf = next(v for v in vrfs if v.name == "TENANT_RED")
    assert vrf.description == "Red tenant L3VPN"


def test_nxos_vrf_route_map_import_export_uses_the_map_keyword():
    """NX-OS spells it `import map`, not `import route-map`.

    `import route-map` appears nowhere in the NX-OS command reference. Parsing it
    would make the parser correct against a line no Nexus prints.
    """
    vrf = next(v for v in NXOSParser(NXOS_VRF).parse().vrfs if v.name == "TENANT_RED")
    assert vrf.route_map_import == "RM_RED_IN"
    assert vrf.route_map_export == "RM_RED_OUT"


def test_nxos_vrf_import_route_map_is_not_invented():
    """The spelling the fixture used to carry must NOT parse — it is not a command."""
    cfg = (
        "vrf context TENANT_BLUE\n"
        "  address-family ipv4 unicast\n"
        "    import route-map RM_BOGUS\n"
        "!\n"
    )
    vrf = next(v for v in NXOSParser(cfg).parse().vrfs if v.name == "TENANT_BLUE")
    assert vrf.route_map_import is None


def test_iosxr_vrf_route_policy_dialect_still_parses():
    vrf = next(v for v in IOSXRParser(IOSXR_VRF).parse().vrfs if v.name == "TENANT_RED")
    assert vrf.route_map_import == "RP-RED-IN"
    assert vrf.route_map_export == "RP-RED-OUT"


def test_vrf_description_quoted_value_is_unquoted():
    """EOS renders a multi-word description both quoted and bare across its own
    transcripts, so both must yield the same value."""
    cfg = 'vrf instance TENANT_RED\n   description "Red tenant L3VPN"\n!\n'
    vrf = next(v for v in EOSParser(cfg).parse().vrfs if v.name == "TENANT_RED")
    assert vrf.description == "Red tenant L3VPN"


# ---------------------------------------------------------------------------
# Theme 2 — OSPF settings written inside the routing process reach the interface
# ---------------------------------------------------------------------------

IOSXR_OSPF = (
    "interface GigabitEthernet0/0/0/0\n"
    " ipv4 address 10.0.0.1 255.255.255.0\n"
    "!\n"
    "interface Loopback0\n"
    " ipv4 address 1.1.1.1 255.255.255.255\n"
    "!\n"
    "router ospf 7\n"
    " area 0\n"
    "  interface Loopback0\n"
    "   passive enable\n"
    "  !\n"
    "  interface GigabitEthernet0/0/0/0\n"
    "   cost 100\n"
    "   network point-to-point\n"
    "   priority 42\n"
    "   hello-interval 5\n"
    "   bfd fast-detect\n"
    "   bfd minimum-interval 250\n"
    "   bfd multiplier 3\n"
    "  !\n"
    " !\n"
    "!\n"
)


def test_iosxr_ospf_area_interface_settings_reach_the_interface():
    """`router ospf 7 > area 0 > interface Gi0/0/0/0 > cost 100` must land on the
    InterfaceConfig — which is where IOS/NX-OS/EOS already put `ip ospf cost`."""
    pc = IOSXRParser(IOSXR_OSPF).parse()
    gi = next(i for i in pc.interfaces if i.name == "GigabitEthernet0/0/0/0")

    assert gi.ospf_cost == 100
    assert gi.ospf_network_type == "point-to-point"
    assert gi.ospf_priority == 42
    assert gi.ospf_hello_interval == 5
    assert gi.ospf_area == "0"
    assert gi.ospf_process_id == 7
    assert gi.bfd_interval == 250
    assert gi.bfd_multiplier == 3

    lo = next(i for i in pc.interfaces if i.name == "Loopback0")
    assert lo.ospf_passive is True
    assert lo.ospf_cost is None  # no cost configured — and honestly None


def test_iosxr_bfd_fast_detect_disable_means_off_not_on():
    """`bfd fast-detect disable` is a REAL emitted line and it means BFD OFF.

    A pattern matching `bfd fast-detect*` would invert the operator's intent —
    the exact class of wrong value this CCR exists to stop.
    """
    cfg = (
        "interface GigabitEthernet0/0/0/1\n"
        " ipv4 address 10.0.1.1 255.255.255.0\n"
        "!\n"
        "router ospf 7\n"
        " area 0\n"
        "  interface GigabitEthernet0/0/0/1\n"
        "   bfd fast-detect disable\n"
        "  !\n"
        " !\n"
        "!\n"
    )
    pc = IOSXRParser(cfg).parse()
    area = pc.ospf_instances[0].areas[0]
    assert area.interface_settings["GigabitEthernet0/0/0/1"].bfd is False


JUNOS_OSPF = (
    "interfaces {\n"
    "    ge-0/0/0 {\n"
    "        unit 0 {\n"
    "            family inet {\n"
    "                address 10.0.0.1/30;\n"
    "            }\n"
    "        }\n"
    "    }\n"
    "}\n"
    "protocols {\n"
    "    ospf {\n"
    "        area 0.0.0.0 {\n"
    "            interface ge-0/0/0.0 {\n"
    "                metric 100;\n"
    "                interface-type p2p;\n"
    "                bfd-liveness-detection {\n"
    "                    minimum-interval 300;\n"
    "                    multiplier 3;\n"
    "                }\n"
    "            }\n"
    "        }\n"
    "    }\n"
    "}\n"
)


def test_junos_ospf_metric_is_the_cost_and_bfd_reaches_the_interface():
    """On JunOS `metric` IS the OSPF cost — there is no `cost` keyword — and
    `bfd-liveness-detection` is a block whose timers are the interface's."""
    pc = JunOSParser(JUNOS_OSPF).parse()
    ge = next(i for i in pc.interfaces if i.name == "ge-0/0/0.0")

    assert ge.ospf_cost == 100
    assert ge.ospf_network_type == "p2p"
    assert ge.ospf_area == "0.0.0.0"
    assert ge.bfd_interval == 300
    assert ge.bfd_multiplier == 3


PANOS_OSPF_VR = """<config>
  <devices>
    <entry name="localhost.localdomain">
      <network>
        <interface>
          <ethernet>
            <entry name="ethernet1/5">
              <layer3><ip><entry name="10.0.5.1/30"/></ip></layer3>
            </entry>
          </ethernet>
        </interface>
        <virtual-router>
          <entry name="default">
            <interface>
              <member>ethernet1/5</member>
            </interface>
            <protocol>
              <ospf>
                <enable>yes</enable>
                <router-id>5.5.5.5</router-id>
                <area>
                  <entry name="0.0.0.0">
                    <type><normal/></type>
                    <interface>
                      <entry name="ethernet1/5">
                        <enable>yes</enable>
                        <passive>no</passive>
                        <metric>100</metric>
                        <priority>42</priority>
                        <link-type><p2p/></link-type>
                      </entry>
                    </interface>
                  </entry>
                </area>
              </ospf>
              <bgp>
                <enable>yes</enable>
                <router-id>5.5.5.5</router-id>
                <local-as>65001</local-as>
                <routing-options>
                  <med>
                    <always-compare-med>yes</always-compare-med>
                  </med>
                  <graceful-restart>
                    <enable>yes</enable>
                    <stale-route-time>120</stale-route-time>
                  </graceful-restart>
                </routing-options>
              </bgp>
            </protocol>
          </entry>
        </virtual-router>
      </network>
    </entry>
  </devices>
</config>
"""


def test_panos_ospf_area_interface_settings_reach_the_interface():
    """PAN-OS has no `ip ospf cost` on the interface object: an interface joins
    OSPF by being an <entry> inside an area, and its cost is the <metric> there."""
    pc = PANOSParser(PANOS_OSPF_VR).parse()
    eth = next(i for i in pc.interfaces if i.name == "ethernet1/5")

    assert eth.ospf_cost == 100
    assert eth.ospf_priority == 42
    assert eth.ospf_network_type == "p2p"   # <link-type><p2p/></link-type>
    assert eth.ospf_area == "0.0.0.0"
    assert eth.ospf_passive is False        # <passive>no</passive>


def test_panos_does_not_assert_an_invented_ospf_process_id():
    """PAN-OS has no OSPF process concept. OSPFConfig.process_id == 1 is
    confgraph's placeholder; stamping it onto an interface would be a fabricated
    value (and would manufacture an unresolvable graph reference)."""
    pc = PANOSParser(PANOS_OSPF_VR).parse()
    eth = next(i for i in pc.interfaces if i.name == "ethernet1/5")
    assert eth.ospf_process_id is None


def test_backfill_never_clobbers_a_value_the_interface_block_set():
    """A parsed value must always beat a back-filled one.

    IOS configures OSPF ON the interface, so the interface block is authoritative
    and the shared back-fill must be a no-op there.
    """
    cfg = (
        "interface GigabitEthernet0/1\n"
        " ip address 10.0.0.1 255.255.255.0\n"
        " ip ospf cost 250\n"
        " ip ospf 1 area 0\n"
        "!\n"
        "router ospf 1\n"
        " network 10.0.0.0 0.0.0.255 area 0\n"
        "!\n"
    )
    pc = IOSParser(cfg).parse()
    gi = next(i for i in pc.interfaces if i.name == "GigabitEthernet0/1")
    assert gi.ospf_cost == 250


def test_interface_settings_is_empty_on_the_interface_configuring_oses():
    """IOS/NX-OS/EOS write OSPF on the interface, so nothing rides in the area —
    the shared back-fill has nothing to do and cannot regress them."""
    cfg = (
        "interface Ethernet1/1\n"
        "  ip address 10.0.0.1/24\n"
        "  ip ospf cost 100\n"
        "  ip router ospf 1 area 0.0.0.0\n"
        "router ospf 1\n"
        "!\n"
    )
    pc = NXOSParser(cfg).parse()
    eth = next(i for i in pc.interfaces if i.name == "Ethernet1/1")
    assert eth.ospf_cost == 100
    for ospf in pc.ospf_instances:
        for area in ospf.areas:
            assert area.interface_settings == {}


# ---------------------------------------------------------------------------
# Theme 3 — BGP graceful-restart
# ---------------------------------------------------------------------------

def _junos_bgp(routing_options_gr: str, bgp_gr: str) -> str:
    return (
        "routing-options {\n"
        "    autonomous-system 65000;\n"
        f"{routing_options_gr}"
        "}\n"
        "protocols {\n"
        "    bgp {\n"
        f"{bgp_gr}"
        "        group EXT {\n"
        "            type external;\n"
        "            peer-as 65001;\n"
        "            neighbor 203.0.113.2;\n"
        "        }\n"
        "    }\n"
        "}\n"
    )


def test_junos_graceful_restart_needs_the_global_enable():
    """`routing-options { graceful-restart; }` is the ONLY thing that enables GR."""
    cfg = _junos_bgp("    graceful-restart;\n", "")
    bgp = JunOSParser(cfg).parse().bgp_instances[0]
    assert bgp.graceful_restart is True


def test_junos_bgp_stanza_alone_does_not_enable_graceful_restart():
    """A `graceful-restart` stanza under `protocols bgp` can only MODIFY or DISABLE
    it — per the vendor, "you cannot enable graceful restart for specific protocols
    unless graceful restart is also enabled globally". Reporting True here would be
    a fabricated value, and the coverage fixture used to ask for exactly that."""
    cfg = _junos_bgp("", "        graceful-restart {\n            restart-time 400;\n        }\n")
    bgp = JunOSParser(cfg).parse().bgp_instances[0]
    assert bgp.graceful_restart is False


def test_junos_bgp_stanza_can_disable_and_can_tune():
    enabled = _junos_bgp(
        "    graceful-restart;\n",
        "        graceful-restart {\n            restart-time 400;\n        }\n",
    )
    bgp = JunOSParser(enabled).parse().bgp_instances[0]
    assert bgp.graceful_restart is True
    assert bgp.graceful_restart_restart_time == 400

    opted_out = _junos_bgp(
        "    graceful-restart;\n",
        "        graceful-restart {\n            disable;\n        }\n",
    )
    bgp = JunOSParser(opted_out).parse().bgp_instances[0]
    assert bgp.graceful_restart is False


def test_panos_graceful_restart_and_always_compare_med():
    bgp = PANOSParser(PANOS_OSPF_VR).parse().bgp_instances[0]
    assert bgp.graceful_restart is True
    assert bgp.graceful_restart_stalepath_time == 120
    assert bgp.bestpath_options.always_compare_med is True


def test_panos_graceful_restart_absent_is_false_not_true():
    cfg = PANOS_OSPF_VR.replace("<enable>yes</enable>\n                    <stale-route-time>120</stale-route-time>",
                                "<enable>no</enable>")
    bgp = PANOSParser(cfg).parse().bgp_instances[0]
    assert bgp.graceful_restart is False


# ---------------------------------------------------------------------------
# Theme 4 — line configuration
# ---------------------------------------------------------------------------

def test_nxos_line_vty_has_no_number():
    """NX-OS emits a bare `line vty` — no number, no range. The inherited IOS
    header demanded a digit, so `p.lines` came back empty on every Nexus."""
    cfg = (
        "line vty\n"
        "  exec-timeout 10\n"
        "  session-limit 5\n"
        "!\n"
    )
    lines = NXOSParser(cfg).parse().lines
    assert len(lines) == 1
    line = lines[0]
    assert line.line_type == LineType.VTY
    assert line.first_line is None       # NX-OS does not number lines
    assert line.exec_timeout_minutes == 10
    assert line.session_timeout is None  # session-LIMIT is not session-timeout


def test_iosxr_line_default_console_and_template():
    """IOS-XR has no numbered vty lines at all: `line default`, `line console` and
    named `line template <name>` blocks are the whole of its line config."""
    cfg = (
        "line default\n"
        " exec-timeout 10 0\n"
        " transport input ssh\n"
        "!\n"
        "line console\n"
        " exec-timeout 0 0\n"
        "!\n"
        "line template NETOPS\n"
        " exec-timeout 5 30\n"
        "!\n"
    )
    lines = IOSXRParser(cfg).parse().lines
    by_type = {l.line_type: l for l in lines}
    assert set(by_type) == {LineType.DEFAULT, LineType.CONSOLE, LineType.TEMPLATE}

    default = by_type[LineType.DEFAULT]
    assert default.first_line is None
    assert default.exec_timeout_minutes == 10
    assert default.exec_timeout_seconds == 0
    assert default.transport_input == ["ssh"]

    tmpl = by_type[LineType.TEMPLATE]
    assert tmpl.name == "NETOPS"
    assert tmpl.exec_timeout_minutes == 5
    assert tmpl.exec_timeout_seconds == 30


def test_ios_numbered_lines_still_parse_unchanged():
    """The IOS dialect keeps its numbers — Theme 4 touches a shared walk, and a
    move on IOS would be a regression, not a bonus."""
    cfg = (
        "line con 0\n"
        " exec-timeout 5 0\n"
        "!\n"
        "line vty 0 4\n"
        " exec-timeout 10 0\n"
        " transport input ssh\n"
        "!\n"
    )
    lines = IOSParser(cfg).parse().lines
    vty = next(l for l in lines if l.line_type == LineType.VTY)
    assert vty.first_line == 0
    assert vty.last_line == 4
    assert vty.transport_input == ["ssh"]

    con = next(l for l in lines if l.line_type == LineType.CONSOLE)
    assert con.first_line == 0
    assert con.exec_timeout_minutes == 5


def test_change_ir_identity_is_unique_per_line_block():
    """Widening `first_line` to Optional must not collapse the change-IR identity.

    `lines` is a `simple_keyed_list_key` (family-8d) collection, and the exact-path
    dedupe in `derive_ops` ASSUMES identity paths are unique. Keying on
    `first_line` alone was safe only while it was a required int: once IOS-XR's
    unnumbered `line template <name>` blocks became representable, every one of
    them hashed to ('template', 'None') — a silent collision no harness check and
    no unit test covered, which is exactly why it shipped green.
    """
    cfg = (
        "line template ALPHA-TPL\n"
        " exec-timeout 5 0\n"
        "!\n"
        "line template BRAVO-TPL\n"
        " exec-timeout 9 0\n"
        "!\n"
        "line default\n"
        " exec-timeout 10 0\n"
        "!\n"
        "line console\n"
        " exec-timeout 0 0\n"
        "!\n"
    )
    lines = IOSXRParser(cfg).parse().lines
    keys = [simple_keyed_list_key("lines", l) for l in lines]

    assert len(set(keys)) == len(lines) == 4, f"identity collision: {keys}"

    by_name = {l.name: l for l in lines if l.name}
    assert simple_keyed_list_key("lines", by_name["ALPHA-TPL"]) == ("template", "ALPHA-TPL")
    assert simple_keyed_list_key("lines", by_name["BRAVO-TPL"]) == ("template", "BRAVO-TPL")


def test_change_ir_identity_unchanged_for_numbered_ios_lines():
    """The number still keys exactly as it did — IOS identity paths must not move."""
    cfg = (
        "line con 0\n"
        " exec-timeout 5 0\n"
        "!\n"
        "line vty 0 4\n"
        " exec-timeout 10 0\n"
        "!\n"
        "line vty 5 15\n"
        " exec-timeout 10 0\n"
        "!\n"
    )
    lines = IOSParser(cfg).parse().lines
    keys = [simple_keyed_list_key("lines", l) for l in lines]
    assert set(keys) == {("console", "0"), ("vty", "0"), ("vty", "5")}
    assert len(set(keys)) == len(lines)


def test_nxos_unnumbered_line_has_a_stable_identity():
    cfg = "line vty\n  exec-timeout 10\n!\nline console\n  exec-timeout 5\n!\n"
    lines = NXOSParser(cfg).parse().lines
    keys = [simple_keyed_list_key("lines", l) for l in lines]
    assert set(keys) == {("vty", ""), ("console", "")}
    assert len(set(keys)) == len(lines)


def test_backfill_does_not_treat_a_parsed_zero_as_unset():
    """`0` is a real OSPF value, not "unset".

    In Python `0 == False`, so a `not in (None, False)` guard reads an explicitly
    parsed ZERO as absent and overwrites it. `ip ospf priority 0` means "never
    become DR" — promoting it to a back-filled 33 inverts the operator's intent.
    The docstring promises a parsed value never loses to a back-filled one.
    """
    parser = IOSParser("")
    intf = InterfaceConfig(
        object_id="i", source_os=OSType.IOS, name="GigabitEthernet0/0",
        interface_type=InterfaceType.PHYSICAL,
        ospf_priority=0,   # explicitly parsed: never become DR
        ospf_cost=0,
    )
    area = OSPFArea(
        area_id="0",
        interface_settings={
            "GigabitEthernet0/0": OSPFInterfaceConfig(
                name="GigabitEthernet0/0", priority=33, cost=100,
            )
        },
    )
    pc = ParsedConfig(
        source_os=OSType.IOS,
        interfaces=[intf],
        ospf_instances=[OSPFConfig(
            object_id="o", source_os=OSType.IOS, process_id=1, areas=[area],
        )],
    )
    parser._backfill_ospf_interface_settings(pc)

    assert pc.interfaces[0].ospf_priority == 0
    assert pc.interfaces[0].ospf_cost == 0


def test_iosxr_vty_pool_is_not_a_line_block():
    """`vty-pool default 0 4 line-template test` BINDS a template to a vty range.
    It is a single top-level line, not a line block — parsing it as one would
    invent a block the device does not have."""
    cfg = "vty-pool default 0 4 line-template NETOPS\n"
    assert IOSXRParser(cfg).parse().lines == []


# ---------------------------------------------------------------------------
# Single-parser residue
# ---------------------------------------------------------------------------

def test_ios_send_community_inside_an_address_family_block():
    """`send-community` is the same command whether it sits under `router bgp` or
    inside an `address-family` block. The AF walk was a SECOND transcription of the
    neighbor vocabulary and never learned it."""
    cfg = (
        "router bgp 65000\n"
        " neighbor 10.100.1.1 remote-as 65001\n"
        " address-family ipv4\n"
        "  neighbor 10.100.1.1 activate\n"
        "  neighbor 10.100.1.1 send-community both\n"
        "  neighbor 10.100.1.1 route-map RM_IN in\n"
        " exit-address-family\n"
        "!\n"
    )
    bgp = IOSParser(cfg).parse().bgp_instances[0]
    nbr = next(n for n in bgp.neighbors if str(n.peer_ip) == "10.100.1.1")
    af = nbr.address_families[0]
    assert af.send_community == "both"
    assert af.route_map_in == "RM_IN"      # the walk it already had, still working


def test_ios_send_community_extended_keyword_is_kept():
    cfg = (
        "router bgp 65000\n"
        " neighbor 10.100.1.1 remote-as 65001\n"
        " address-family ipv4\n"
        "  neighbor 10.100.1.1 send-community extended\n"
        " exit-address-family\n"
        "!\n"
    )
    bgp = IOSParser(cfg).parse().bgp_instances[0]
    nbr = next(n for n in bgp.neighbors if str(n.peer_ip) == "10.100.1.1")
    assert nbr.address_families[0].send_community == "extended"


def test_ios_ip_sla_source_interface():
    """`icmp-echo {dest} [source-ip {ip} | source-interface {name}]` — the two are
    ALTERNATIVES in the vendor grammar, so they get separate fields."""
    cfg = (
        "ip sla 1\n"
        " icmp-echo 10.0.0.1 source-interface GigabitEthernet0/0\n"
        " frequency 10\n"
        "!\n"
    )
    sla = IOSParser(cfg).parse().ip_sla_operations[0]
    assert sla.source_interface == "GigabitEthernet0/0"
    assert sla.source_ip is None
    assert sla.destination == "10.0.0.1"


def test_junos_ntp_and_syslog_source_is_an_address_not_an_interface():
    """JunOS names both sources by ADDRESS (`source-address 1.1.1.1`); there is no
    `ntp source-interface` on JunOS. Writing the address into `source_interface`
    would be the wrong-value defect CCR-0030 is about."""
    cfg = (
        "system {\n"
        "    ntp {\n"
        "        server 10.0.0.1;\n"
        "        source-address 192.0.2.9;\n"
        "    }\n"
        "    syslog {\n"
        "        host 10.0.0.20 {\n"
        "            any info;\n"
        "        }\n"
        "        source-address 192.0.2.9;\n"
        "    }\n"
        "}\n"
    )
    pc = JunOSParser(cfg).parse()
    assert pc.ntp.source_address == "192.0.2.9"
    assert pc.ntp.source_interface is None
    assert pc.syslog.source_address == "192.0.2.9"
    assert pc.syslog.source_interface is None


def test_panos_virtual_router_interface_member_list():
    """The interfaces ASSIGNED to a VR are a <member> list directly under the VR
    entry — not the entry-keyed <interface><entry name=…> lists that appear again
    under protocol/ospf/area."""
    vrf = next(v for v in PANOSParser(PANOS_OSPF_VR).parse().vrfs if v.name == "default")
    assert vrf.interfaces == ["ethernet1/5"]
