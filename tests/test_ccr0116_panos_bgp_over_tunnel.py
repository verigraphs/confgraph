"""CCR-0116 — PAN-OS BGP-over-IPSec-VPN dependency chain.

A PAN-OS site-to-site VPN runs BGP over an IPSec tunnel.  The dependency graph
must chain:

    bgp_instance -> interface(tunnel.N) -> interface(physical egress)

so that "underlay/tunnel down -> BGP down" is derivable.  The first hop
(BGP peer's ``local-address/interface`` -> ``tunnel.N``) already worked; this
locks it in and adds the downstream hops:

  * ``network/tunnel/ipsec/entry`` binds ``tunnel-interface`` (TEXT, the
    ``tunnel.N``) to an IKE gateway that is ENTRY-KEYED by ``@name`` under
    ``<auto-key><ike-gateway>``.  Manual-key / global-protect-satellite tunnels
    have no ``<auto-key>`` and therefore no IKE gateway.
  * ``network/ike/gateway/entry`` carries ``local-address/interface`` — the
    PHYSICAL egress the whole tunnel rides.

XML shapes are the PAN-OS emitted forms cited by the CCR (SDK/doc-grounded,
recorded under ``syntax-corpus/panos``).
"""

import pytest

from confgraph.analysis import DependencyResolver
from confgraph.graph import GraphBuilder
from confgraph.models.base import OSType
from confgraph.models.interface import InterfaceConfig, InterfaceType
from confgraph.models.parsed_config import ParsedConfig
from confgraph.parsers.panos_parser import PANOSParser


# Full minimal chain: BGP(OVERLAY/branch-1) -> tunnel.1 -> ipsec(vpn-to-branch)
# -> ike gw(gw-branch) -> ethernet1/1.
FULL_CHAIN = """\
<config version="10.1.0">
  <devices>
    <entry name="localhost.localdomain">
      <deviceconfig><system><hostname>pa-vpn-1</hostname></system></deviceconfig>
      <network>
        <interface>
          <ethernet>
            <entry name="ethernet1/1">
              <layer3><ip><entry name="203.0.113.1/30"/></ip></layer3>
            </entry>
          </ethernet>
          <tunnel>
            <units>
              <entry name="tunnel.1">
                <ip><entry name="10.255.0.1/30"/></ip>
              </entry>
            </units>
          </tunnel>
        </interface>
        <ike>
          <gateway>
            <entry name="gw-branch">
              <local-address><interface>ethernet1/1</interface></local-address>
              <peer-address><ip>203.0.113.9</ip></peer-address>
              <protocol>
                <version>ikev2</version>
                <ikev2><ike-crypto-profile>default</ike-crypto-profile></ikev2>
              </protocol>
            </entry>
          </gateway>
        </ike>
        <tunnel>
          <ipsec>
            <entry name="vpn-to-branch">
              <tunnel-interface>tunnel.1</tunnel-interface>
              <auto-key>
                <ike-gateway><entry name="gw-branch"/></ike-gateway>
                <ipsec-crypto-profile>default</ipsec-crypto-profile>
              </auto-key>
            </entry>
          </ipsec>
        </tunnel>
        <virtual-router>
          <entry name="default">
            <protocol>
              <bgp>
                <enable>yes</enable>
                <local-as>65001</local-as>
                <peer-group>
                  <entry name="OVERLAY">
                    <peer>
                      <entry name="branch-1">
                        <enable>yes</enable>
                        <peer-as>65010</peer-as>
                        <local-address><interface>tunnel.1</interface></local-address>
                        <peer-address><ip>10.255.0.2</ip></peer-address>
                      </entry>
                    </peer>
                  </entry>
                </peer-group>
              </bgp>
            </protocol>
          </entry>
        </virtual-router>
      </network>
    </entry>
  </devices>
</config>
"""


def _edge_fields(g, src, tgt):
    """Return the set of edge ``field`` labels src->tgt (empty if no edge)."""
    if not g.has_edge(src, tgt):
        return set()
    # DiGraph: at most one edge per pair; but be robust to attribute shape.
    return {g.edges[src, tgt].get("field")}


# ---------------------------------------------------------------------------
# Full connected chain
# ---------------------------------------------------------------------------

def test_full_chain_bgp_tunnel_egress_connected():
    parsed = PANOSParser(FULL_CHAIN).parse()
    g = GraphBuilder(parsed).build()

    bgp = "bgp_instance::65001"
    tun = "interface::tunnel.1"
    eth = "interface::ethernet1/1"

    for node in (bgp, tun, eth):
        assert node in g, f"missing node {node}"

    # Hop 1 (lock-in): BGP peer sources from tunnel.1
    assert g.has_edge(bgp, tun), "BGP -> tunnel.1 edge missing (regression)"
    assert g.edges[bgp, tun]["resolved"] is True
    assert g.edges[bgp, tun]["field"] == "update_source"

    # Hop 2 (new): tunnel.1 rides the physical egress ethernet1/1
    assert g.has_edge(tun, eth), "tunnel.1 -> ethernet1/1 underlay edge missing"
    assert g.edges[tun, eth]["resolved"] is True
    assert g.edges[tun, eth]["field"] == "tunnel_underlay"

    # The chain is genuinely connected end to end.
    import networkx as nx
    assert nx.has_path(g, bgp, eth)


def test_tunnel_binding_recorded_on_interface():
    parsed = PANOSParser(FULL_CHAIN).parse()
    tun = next(i for i in parsed.interfaces if i.name == "tunnel.1")

    assert tun.interface_type == InterfaceType.TUNNEL
    assert tun.tunnel_underlay_interface == "ethernet1/1"
    assert tun.tunnel_ike_gateway == "gw-branch"
    # ipsec-crypto-profile reuses the existing tunnel_protection_profile field.
    assert tun.tunnel_protection_profile == "default"
    assert tun.tunnel_ike_crypto_profile == "default"


def test_ipsec_ike_hop_surfaced_as_crypto_edge():
    parsed = PANOSParser(FULL_CHAIN).parse()
    g = GraphBuilder(parsed).build()

    tun = "interface::tunnel.1"
    crypto = "crypto::crypto"
    assert crypto in g, "crypto node missing"
    assert g.has_edge(tun, crypto), "tunnel.1 -> crypto IPSec/IKE hop missing"
    assert g.edges[tun, crypto]["resolved"] is True
    assert g.edges[tun, crypto]["field"] == "tunnel_ike_gateway"


# ---------------------------------------------------------------------------
# auto-key gating — manual-key yields NO ike-gateway/egress binding
# ---------------------------------------------------------------------------

MANUAL_KEY = """\
<config version="10.1.0">
  <devices>
    <entry name="localhost.localdomain">
      <network>
        <interface>
          <ethernet>
            <entry name="ethernet1/1">
              <layer3><ip><entry name="203.0.113.1/30"/></ip></layer3>
            </entry>
          </ethernet>
          <tunnel>
            <units><entry name="tunnel.7"><ip><entry name="10.255.7.1/30"/></ip></entry></units>
          </tunnel>
        </interface>
        <ike>
          <gateway>
            <entry name="gw-branch">
              <local-address><interface>ethernet1/1</interface></local-address>
              <peer-address><ip>203.0.113.9</ip></peer-address>
            </entry>
          </gateway>
        </ike>
        <tunnel>
          <ipsec>
            <entry name="vpn-manual">
              <tunnel-interface>tunnel.7</tunnel-interface>
              <manual-key>
                <local-spi>00001000</local-spi>
                <remote-spi>00001000</remote-spi>
              </manual-key>
            </entry>
          </ipsec>
        </tunnel>
      </network>
    </entry>
  </devices>
</config>
"""


def test_manual_key_ipsec_binds_nothing():
    parsed = PANOSParser(MANUAL_KEY).parse()
    tun = next(i for i in parsed.interfaces if i.name == "tunnel.7")
    assert tun.tunnel_ike_gateway is None
    assert tun.tunnel_underlay_interface is None

    g = GraphBuilder(parsed).build()
    # No invented tunnel -> egress or tunnel -> crypto edge.
    assert not g.has_edge("interface::tunnel.7", "interface::ethernet1/1")
    assert not g.has_edge("interface::tunnel.7", "crypto::crypto")


# ---------------------------------------------------------------------------
# Partial chain degrades gracefully (no crash, no invented egress edge)
# ---------------------------------------------------------------------------

MISSING_GATEWAY = """\
<config version="10.1.0">
  <devices>
    <entry name="localhost.localdomain">
      <network>
        <interface>
          <ethernet>
            <entry name="ethernet1/1">
              <layer3><ip><entry name="203.0.113.1/30"/></ip></layer3>
            </entry>
          </ethernet>
          <tunnel>
            <units><entry name="tunnel.9"><ip><entry name="10.255.9.1/30"/></ip></entry></units>
          </tunnel>
        </interface>
        <ike>
          <gateway>
            <entry name="gw-present">
              <local-address><interface>ethernet1/1</interface></local-address>
              <peer-address><ip>203.0.113.9</ip></peer-address>
            </entry>
          </gateway>
        </ike>
        <tunnel>
          <ipsec>
            <entry name="vpn-dangling">
              <tunnel-interface>tunnel.9</tunnel-interface>
              <auto-key>
                <ike-gateway><entry name="gw-absent"/></ike-gateway>
                <ipsec-crypto-profile>default</ipsec-crypto-profile>
              </auto-key>
            </entry>
          </ipsec>
        </tunnel>
      </network>
    </entry>
  </devices>
</config>
"""


def test_missing_ike_gateway_degrades():
    parsed = PANOSParser(MISSING_GATEWAY).parse()
    tun = next(i for i in parsed.interfaces if i.name == "tunnel.9")

    # Gateway name is recorded even though the gateway is absent; egress unknown.
    assert tun.tunnel_ike_gateway == "gw-absent"
    assert tun.tunnel_underlay_interface is None
    # The known IPSec profile is still captured.
    assert tun.tunnel_protection_profile == "default"

    g = GraphBuilder(parsed).build()  # must not crash
    # No tunnel -> egress edge (egress unresolvable).
    assert not g.has_edge("interface::tunnel.9", "interface::ethernet1/1")


GATEWAY_NO_EGRESS = FULL_CHAIN.replace(
    "<local-address><interface>ethernet1/1</interface></local-address>", ""
)


def test_gateway_without_egress_degrades():
    parsed = PANOSParser(GATEWAY_NO_EGRESS).parse()
    tun = next(i for i in parsed.interfaces if i.name == "tunnel.1")
    assert tun.tunnel_ike_gateway == "gw-branch"
    assert tun.tunnel_underlay_interface is None

    g = GraphBuilder(parsed).build()
    assert not g.has_edge("interface::tunnel.1", "interface::ethernet1/1")
    # BGP -> tunnel hop still intact.
    assert g.has_edge("bgp_instance::65001", "interface::tunnel.1")


# ---------------------------------------------------------------------------
# Non-PAN-OS regression: field-driven, so other OSes are untouched
# ---------------------------------------------------------------------------

def test_non_panos_tunnel_unaffected():
    # An IOS-style tunnel using the pre-existing tunnel_source field must NOT
    # gain any underlay/crypto edge — the new fields default None.
    iface = InterfaceConfig(
        object_id="iface_Tunnel0",
        source_os=OSType.IOS,
        name="Tunnel0",
        interface_type=InterfaceType.TUNNEL,
        tunnel_source="GigabitEthernet0/0",
        tunnel_protection_profile="MY-IPSEC-PROFILE",
    )
    assert iface.tunnel_underlay_interface is None
    assert iface.tunnel_ike_gateway is None
    assert iface.tunnel_ike_crypto_profile is None

    parsed = ParsedConfig(source_os=OSType.IOS, interfaces=[iface])
    links = DependencyResolver(parsed).resolve().links
    fields = {(l.source_field, l.ref_type) for l in links if l.source_id == "Tunnel0"}
    assert ("tunnel_underlay", "interface") not in fields
    assert ("tunnel_ike_gateway", "crypto") not in fields
