"""CCR-0034 — PAN-OS Panorama-pushed layout must parse, not come back empty.

Before the fix, ``PANOSParser`` only knew ``devices/entry/{network,vsys/entry}``.
A Panorama config — security rules under
``device-group/entry/{pre,post}-rulebase`` and network/vsys under
``template/entry/config/devices/entry`` — produced 0 ACLs, 0 zones and 0
interfaces *with no error*, which a consumer cannot tell apart from a firewall
that genuinely has no policy.

Element paths below are the emitted shapes (Palo Alto's own SDKs read exported
configs with them: pango ``DeviceGroupXpathPrefix``/``poli/security/pano.go``,
pan-os-php ``PanoramaConf.php``/``Template.php``); rule precedence is per the
Panorama admin guide, "Device Group Policies":

    shared pre → DG pre (ancestor→descendant) → [local] →
    DG post (descendant→ancestor) → shared post
"""

import pytest

from confgraph.parsers.base import ParseError
from confgraph.parsers.panos_parser import PANOSParser
from confgraph.parsers.panos_xml import (
    LAYOUT_LOCAL, LAYOUT_PANORAMA, detect_layout, parse_panos_xml,
)


def _rules(acl):
    """Rule names in evaluation order, read back out of the ACL remarks."""
    return [e.remark.split()[0].removeprefix("rule:") for e in acl.entries]


# ---------------------------------------------------------------------------
# Panorama: device-group policy + template network/vsys
# ---------------------------------------------------------------------------

PANORAMA = """\
<config version="10.1.0">
  <devices>
    <entry name="localhost.localdomain">
      <device-group>
        <entry name="EDGE-DG">
          <pre-rulebase>
            <security>
              <rules>
                <entry name="permit-dns">
                  <from><member>inside-z</member></from>
                  <to><member>outside-z</member></to>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                  <application><member>dns</member></application>
                  <action>allow</action>
                </entry>
              </rules>
            </security>
            <nat>
              <rules>
                <entry name="dnat-web">
                  <from><member>outside-z</member></from>
                  <to><member>outside-z</member></to>
                  <destination><member>198.51.100.9</member></destination>
                  <destination-translation>
                    <translated-address>172.31.7.9</translated-address>
                    <translated-port>8443</translated-port>
                  </destination-translation>
                </entry>
              </rules>
            </nat>
          </pre-rulebase>
          <post-rulebase>
            <security>
              <rules>
                <entry name="block-rest">
                  <from><member>any</member></from>
                  <to><member>any</member></to>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                  <application><member>any</member></application>
                  <action>deny</action>
                </entry>
              </rules>
            </security>
          </post-rulebase>
        </entry>
      </device-group>
      <template>
        <entry name="TPL-EDGE">
          <settings><default-vsys>vsys1</default-vsys></settings>
          <config>
            <devices>
              <entry name="localhost.localdomain">
                <deviceconfig>
                  <system><hostname>pa-edge-07</hostname></system>
                </deviceconfig>
                <network>
                  <interface>
                    <ethernet>
                      <entry name="ethernet1/7">
                        <layer3>
                          <ip><entry name="198.51.100.5/30"/></ip>
                        </layer3>
                      </entry>
                    </ethernet>
                  </interface>
                  <virtual-router>
                    <entry name="vr-edge">
                      <interface><member>ethernet1/7</member></interface>
                      <routing-table>
                        <ip>
                          <static-route>
                            <entry name="upstream">
                              <destination>0.0.0.0/0</destination>
                              <nexthop><ip-address>198.51.100.6</ip-address></nexthop>
                              <admin-dist>15</admin-dist>
                            </entry>
                          </static-route>
                        </ip>
                      </routing-table>
                    </entry>
                  </virtual-router>
                </network>
                <vsys>
                  <entry name="vsys1">
                    <zone>
                      <entry name="outside-z">
                        <network>
                          <layer3><member>ethernet1/7</member></layer3>
                        </network>
                      </entry>
                    </zone>
                  </entry>
                </vsys>
              </entry>
            </devices>
          </config>
        </entry>
      </template>
    </entry>
  </devices>
</config>
"""


@pytest.fixture(scope="module")
def panorama():
    return PANOSParser(PANORAMA).parse()


def test_panorama_layout_is_detected_not_assumed():
    assert detect_layout(parse_panos_xml(PANORAMA)).kind == LAYOUT_PANORAMA


def test_device_group_pre_and_post_security_rules_become_one_acl(panorama):
    # Was: 0 ACLs. The scope is the device-group, not a vsys.
    assert [a.name for a in panorama.acls] == ["security-policy-EDGE-DG"]
    acl = panorama.acls[0]
    assert _rules(acl) == ["permit-dns", "block-rest"]      # pre before post
    assert [e.action for e in acl.entries] == ["permit", "deny"]
    # ascending sequence carries the evaluation order
    assert [e.sequence for e in acl.entries] == sorted(e.sequence for e in acl.entries)


def test_template_interface_and_zone_and_virtual_router(panorama):
    # Was: 0 interfaces, 0 zones — the config lives one <config> level deeper.
    iface = next(i for i in panorama.interfaces if i.name == "ethernet1/7")
    assert str(iface.ip_address) == "198.51.100.5/30"
    assert iface.zone == "outside-z"           # zone membership crosses template→vsys
    assert iface.virtual_router == "vr-edge"

    zone = next(z for z in panorama.zones if z.name == "outside-z")
    assert zone.vsys == "vsys1"
    assert zone.interfaces == ["ethernet1/7"]

    assert [v.name for v in panorama.vrfs] == ["vr-edge"]
    assert panorama.hostname == "pa-edge-07"


def test_template_static_route_and_device_group_nat(panorama):
    route = next(r for r in panorama.static_routes if str(r.destination) == "0.0.0.0/0")
    assert str(r_nh := route.next_hop) == "198.51.100.6" and r_nh is not None
    assert route.distance == 15
    assert route.vrf == "vr-edge"

    # NAT rules live in the same device-group rulebases as the security rules.
    assert panorama.nat is not None
    entry = panorama.nat.static_entries[0]
    assert str(entry.local_ip) == "198.51.100.9"
    assert str(entry.global_ip) == "172.31.7.9"
    assert entry.local_port == 8443


# ---------------------------------------------------------------------------
# Precedence: shared rulebases and the device-group hierarchy
# ---------------------------------------------------------------------------

HIERARCHY = """\
<config version="10.1.0">
  <shared>
    <pre-rulebase>
      <security>
        <rules>
          <entry name="shared-pre-mgmt">
            <from><member>any</member></from>
            <to><member>any</member></to>
            <action>allow</action>
          </entry>
        </rules>
      </security>
    </pre-rulebase>
    <post-rulebase>
      <security>
        <rules>
          <entry name="shared-post-log">
            <from><member>any</member></from>
            <to><member>any</member></to>
            <action>deny</action>
          </entry>
        </rules>
      </security>
    </post-rulebase>
  </shared>
  <devices>
    <entry name="localhost.localdomain">
      <device-group>
        <entry name="BRANCH-DG">
          <pre-rulebase>
            <security>
              <rules>
                <entry name="branch-pre">
                  <from><member>any</member></from>
                  <to><member>any</member></to>
                  <action>allow</action>
                </entry>
              </rules>
            </security>
          </pre-rulebase>
          <post-rulebase>
            <security>
              <rules>
                <entry name="branch-post">
                  <from><member>any</member></from>
                  <to><member>any</member></to>
                  <action>deny</action>
                </entry>
              </rules>
            </security>
          </post-rulebase>
        </entry>
        <entry name="CORP-DG">
          <pre-rulebase>
            <security>
              <rules>
                <entry name="corp-pre">
                  <from><member>any</member></from>
                  <to><member>any</member></to>
                  <action>allow</action>
                </entry>
              </rules>
            </security>
          </pre-rulebase>
          <post-rulebase>
            <security>
              <rules>
                <entry name="corp-post">
                  <from><member>any</member></from>
                  <to><member>any</member></to>
                  <action>deny</action>
                </entry>
              </rules>
            </security>
          </post-rulebase>
        </entry>
      </device-group>
    </entry>
  </devices>
  <readonly>
    <devices>
      <entry name="localhost.localdomain">
        <device-group>
          <entry name="CORP-DG"><id>2</id></entry>
          <entry name="BRANCH-DG"><id>3</id><parent-dg>CORP-DG</parent-dg></entry>
        </device-group>
      </entry>
    </devices>
  </readonly>
</config>
"""


def test_effective_policy_follows_panorama_precedence_order():
    parsed = PANOSParser(HIERARCHY).parse()
    by_name = {a.name: a for a in parsed.acls}

    # BRANCH-DG inherits CORP-DG (its <parent-dg>) and shared:
    # shared pre → ancestor pre → own pre → own post → ancestor post → shared post
    assert _rules(by_name["security-policy-BRANCH-DG"]) == [
        "shared-pre-mgmt", "corp-pre", "branch-pre",
        "branch-post", "corp-post", "shared-post-log",
    ]
    # CORP-DG has no <parent-dg>, so it hangs off shared only — a child's rules
    # never leak upward into its parent's effective policy.
    assert _rules(by_name["security-policy-CORP-DG"]) == [
        "shared-pre-mgmt", "corp-pre", "corp-post", "shared-post-log",
    ]


# ---------------------------------------------------------------------------
# The local layout still parses (this fix is a behavior change)
# ---------------------------------------------------------------------------

LOCAL = """\
<config version="10.1.0">
  <devices>
    <entry name="localhost.localdomain">
      <deviceconfig><system><hostname>pa-branch-02</hostname></system></deviceconfig>
      <network>
        <interface>
          <ethernet>
            <entry name="ethernet1/4">
              <layer3><ip><entry name="203.0.113.33/29"/></ip></layer3>
            </entry>
          </ethernet>
        </interface>
      </network>
      <vsys>
        <entry name="vsys1">
          <zone>
            <entry name="dmz-z">
              <network><layer3><member>ethernet1/4</member></layer3></network>
            </entry>
          </zone>
          <rulebase>
            <security>
              <rules>
                <entry name="permit-ssh">
                  <from><member>dmz-z</member></from>
                  <to><member>dmz-z</member></to>
                  <action>allow</action>
                </entry>
              </rules>
            </security>
          </rulebase>
        </entry>
      </vsys>
    </entry>
  </devices>
</config>
"""


def test_local_vsys_layout_is_unchanged():
    assert detect_layout(parse_panos_xml(LOCAL)).kind == LAYOUT_LOCAL
    parsed = PANOSParser(LOCAL).parse()
    assert parsed.hostname == "pa-branch-02"
    assert [a.name for a in parsed.acls] == ["security-policy-vsys1"]
    assert _rules(parsed.acls[0]) == ["permit-ssh"]
    assert [z.name for z in parsed.zones] == ["dmz-z"]
    iface = next(i for i in parsed.interfaces if i.name == "ethernet1/4")
    assert iface.zone == "dmz-z"


# ---------------------------------------------------------------------------
# An unrecognized layout is loud, not empty
# ---------------------------------------------------------------------------

# A document whose <devices><entry> carries neither firewall config
# (deviceconfig/network/vsys) nor Panorama config (device-group/template):
# nothing this parser can read, so it must say so.
UNREADABLE = """\
<config version="10.1.0">
  <devices>
    <entry name="localhost.localdomain">
      <plugins><cloud_services><some-future-thing/></cloud_services></plugins>
    </entry>
  </devices>
</config>
"""

NOT_PANOS = "<rpc-reply><configuration><system/></configuration></rpc-reply>"

# A template-STACK carries no config of its own that we can resolve: a stack is
# assembled from its member templates by a priority no primary source states.
# It is therefore not read — and, crucially, not a recognition marker either.
# Recognizing this document and then reading nothing out of it would hand back a
# silent empty model, which is the defect CCR-0034 exists to end. It must raise.
TEMPLATE_STACK_ONLY = """\
<config version="10.1.0">
  <devices>
    <entry name="localhost.localdomain">
      <template-stack>
        <entry name="TS-EDGE">
          <templates>
            <member>TPL-EDGE</member>
          </templates>
          <devices><entry name="007051000099"/></devices>
        </entry>
      </template-stack>
    </entry>
  </devices>
</config>
"""


@pytest.mark.parametrize("bad", [UNREADABLE, NOT_PANOS, TEMPLATE_STACK_ONLY])
def test_unrecognized_layout_raises_rather_than_returning_an_empty_model(bad):
    with pytest.raises(ParseError) as exc:
        PANOSParser(bad).parse()
    assert exc.value.protocol == "layout"

    # and it is loud from any entry point, not only the full parse()
    with pytest.raises(ParseError):
        PANOSParser(bad).parse_acls()


def test_template_stack_alongside_templates_still_parses_the_templates():
    """A real Panorama export carries stacks *and* the templates they stack.

    Dropping template-stack as a marker must not make such a document
    unrecognized — it is recognized on its <template>/<device-group>, and only
    the stack's own overrides go unread.
    """
    stacked = PANORAMA.replace(
        "      <template>",
        "      <template-stack>\n"
        "        <entry name=\"TS-EDGE\">\n"
        "          <templates><member>TPL-EDGE</member></templates>\n"
        "        </entry>\n"
        "      </template-stack>\n"
        "      <template>",
        1,
    )
    parsed = PANOSParser(stacked).parse()
    assert parsed.hostname == "pa-edge-07"
    assert [i.name for i in parsed.interfaces] == ["ethernet1/7"]
    assert [z.name for z in parsed.zones] == ["outside-z"]
    assert [a.name for a in parsed.acls] == ["security-policy-EDGE-DG"]
