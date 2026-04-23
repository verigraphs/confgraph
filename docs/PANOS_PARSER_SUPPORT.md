# Palo Alto PAN-OS Parser Support Documentation

## Overview

The PAN-OS parser (`confgraph.parsers.panos_parser.PANOSParser`) parses Palo Alto Networks PAN-OS device configurations in XML format. Unlike all other parsers, it does **not** use `CiscoConfParse` — PAN-OS configurations are XML documents, not line-oriented text. Instead it uses a lightweight XML navigation helper (`confgraph.parsers.panos_xml`) built on Python's standard `xml.etree.ElementTree`.

**Class:** `confgraph.parsers.panos_parser.PANOSParser`
**Inherits from:** `BaseParser`
**XML helper:** `confgraph.parsers.panos_xml`
**OSType:** `OSType.PANOS` ("panos")

---

## Key Syntax Differences from IOS

| Feature | IOS | PAN-OS |
|---------|-----|--------|
| Config format | Line-by-line, indentation-based | XML document |
| VRF equivalent | `vrf definition NAME` | `<virtual-router>` under `<network>` |
| Interface IP | `ip address X MASK` on interface | `<layer3><ip><entry name="X/LEN"/>` |
| Subinterfaces | Named subinterfaces (`Gi0/0.100`) | Units under `<layer3><units><entry name="...">` |
| BGP | `router bgp ASN` | `<protocol><bgp>` inside a virtual-router |
| BGP peer-groups | `neighbor IP peer-group NAME` | `<peer-group>` containing `<peer>` entries |
| BGP update-source | `neighbor IP update-source INTF` | `<local-address><interface>` per peer |
| OSPF | `router ospf PROC` | `<protocol><ospf>` inside a virtual-router |
| Static routes | `ip route PREFIX MASK NEXTHOP` | `<routing-table><ip><static-route>` |
| ACLs | `ip access-list NAME` | `<rulebase><security><rules>` — zone-based rules |
| NAT | `ip nat inside source` | `<rulebase><nat><rules>` — source/destination translation |
| IPsec | `crypto map / crypto isakmp policy` | `<ike><gateway>` + `<tunnel><ipsec>` |
| Security zones | Not applicable | `<zone>` entries in vsys — fundamental segmentation unit |

---

## Configuration Syntax Support

### 1. Virtual Routers (VRF equivalent)

**XML structure:**
```xml
<network>
  <virtual-router>
    <entry name="default">
      <interface>
        <member>ethernet1/1</member>
        <member>loopback.1</member>
      </interface>
    </entry>
  </virtual-router>
</network>
```

**PAN-OS-Specific Differences:**
- Virtual routers are the routing domain boundary in PAN-OS (≈ VRF in IOS)
- Interface membership is declared inside the virtual-router, not on the interface
- Multiple virtual routers can exist; the default is named `"default"`

**Supported Attributes:**
- Virtual router name → `VRFConfig.name`
- Member interfaces (used for cross-referencing `virtual_router` on `InterfaceConfig`)

**Parsing Status:** ✅ Implemented — `parse_vrfs()` handles `<network><virtual-router>` entries

---

### 2. Interface Configuration

**XML structure:**
```xml
<interface>
  <ethernet>
    <entry name="ethernet1/1">
      <layer3>
        <ip><entry name="203.0.113.2/30"/></ip>
        <mtu>1500</mtu>
      </layer3>
      <comment>ISP Uplink</comment>
    </entry>
  </ethernet>
  <loopback>
    <units>
      <entry name="loopback.1">
        <ip><entry name="10.255.255.1/32"/></ip>
      </entry>
    </units>
  </loopback>
  <tunnel>
    <units>
      <entry name="tunnel.1">
        <ip><entry name="10.100.1.1/30"/></ip>
        <comment>IPsec tunnel to Branch-A</comment>
      </entry>
    </units>
  </tunnel>
</interface>
```

**PAN-OS-Specific Differences:**
- Ethernet, loopback, tunnel, and aggregate-ethernet interfaces have different XML paths
- Sub-interfaces (units) live under `<layer3><units><entry name="..."/>`
- Zone and virtual-router membership are resolved by cross-referencing `<zone>` and `<virtual-router>` blocks during parse
- `<link-state>down</link-state>` signals a disabled interface

**Supported Attributes:**
- Interface name, type classification
- IPv4 primary address (CIDR, from `<layer3><ip><entry name="X/LEN"/>`)
- IPv6 addresses
- Description (from `<comment>`)
- Enabled/disabled state
- MTU
- Zone assignment (`zone` field — cross-referenced from `<vsys><zone>`)
- Virtual router assignment (`virtual_router` field — cross-referenced from `<network><virtual-router>`)

**Interface type classification:**

| Name pattern | InterfaceType |
|--------------|---------------|
| `loopback.*`, `lo.*` | LOOPBACK |
| `tunnel.*` | TUNNEL |
| `ae*`, `bond*` | PORTCHANNEL |
| `vlan*`, `vl*` | VLAN |
| `mgmt*`, `management*` | MANAGEMENT |
| All others (`ethernet*`) | PHYSICAL |

**Parsing Status:** ✅ Implemented — `parse_interfaces()` handles ethernet, loopback, tunnel, and aggregate-ethernet interface types with zone/VR cross-referencing

---

### 3. BGP Configuration

**XML structure:**
```xml
<virtual-router>
  <entry name="default">
    <protocol>
      <bgp>
        <enable>yes</enable>
        <router-id>10.255.255.1</router-id>
        <local-as>65001</local-as>
        <peer-group>
          <entry name="UPSTREAM-ISP">
            <peer>
              <entry name="ISP-A-Peer">
                <enable>yes</enable>
                <peer-address><ip>203.0.113.1</ip></peer-address>
                <connection-options>
                  <remote-as>64512</remote-as>
                  <keep-alive-interval>30</keep-alive-interval>
                </connection-options>
                <local-address>
                  <ip>203.0.113.2</ip>
                  <interface>ethernet1/1</interface>
                </local-address>
              </entry>
            </peer>
          </entry>

          <!-- BGP over IPsec tunnel -->
          <entry name="BRANCH-VPN">
            <peer>
              <entry name="Branch-A">
                <peer-address><ip>10.100.1.2</ip></peer-address>
                <connection-options><remote-as>65101</remote-as></connection-options>
                <!-- update-source = tunnel interface (IPsec) -->
                <local-address>
                  <ip>10.100.1.1</ip>
                  <interface>tunnel.1</interface>
                </local-address>
              </entry>
            </peer>
          </entry>
        </peer-group>
      </bgp>
    </protocol>
  </entry>
</virtual-router>
```

**PAN-OS-Specific Differences:**
- BGP is scoped per virtual-router (not a global process)
- All neighbors belong to a named `<peer-group>` — no flat `neighbor IP remote-as N` syntax
- `<local-address><interface>` maps to `update_source` — enables BGP-over-tunnel graph edges
- No address-family blocks; IPv4 unicast is implicit
- Redistribution uses `<redistribution-rules>` with `<address-family-identifier>`

**Supported Attributes:**
- Local ASN, router-ID
- Peer groups with all their nested neighbors
- Per-neighbor: peer IP, remote AS, description, shutdown state, update-source interface
- Redistribution rules
- VRF context from virtual-router name

**BGP over IPsec tunnels:** When `<local-address><interface>` references a tunnel interface, the graph draws:
```
bgp:65001 ──[update_source]──► iface:tunnel.1 ──[zone]──► zone:vpn-tunnels
```
This makes the full BGP → tunnel → IPsec dependency chain visible.

**Parsing Status:** ✅ Implemented — `parse_bgp()` handles `<protocol><bgp>` per virtual-router with peer-group/peer hierarchy and `update_source` capture

---

### 4. OSPF Configuration

**XML structure:**
```xml
<protocol>
  <ospf>
    <enable>yes</enable>
    <router-id>10.255.255.1</router-id>
    <area>
      <entry name="0.0.0.0">
        <interface>
          <entry name="ethernet1/5">
            <enable>yes</enable>
            <passive>no</passive>
            <metric>10</metric>
          </entry>
          <entry name="loopback.1">
            <enable>yes</enable>
            <passive>yes</passive>
          </entry>
        </interface>
      </entry>
    </area>
    <export-rules>
      <entry name="connected"/>
      <entry name="static"/>
    </export-rules>
  </ospf>
</protocol>
```

**PAN-OS-Specific Differences:**
- OSPF is scoped per virtual-router
- No process-ID concept — parser uses `1` as a conventional placeholder
- Interface membership is declared inside the OSPF area block
- Redistribution uses `<export-rules>` entries

**Supported Attributes:**
- Router-ID
- Areas with interface membership lists
- Redistribution (export-rules)
- VRF context from virtual-router name

**Parsing Status:** ✅ Implemented — `parse_ospf()` handles `<protocol><ospf>` per virtual-router

---

### 5. Static Routes

**XML structure:**
```xml
<routing-table>
  <ip>
    <static-route>
      <entry name="default-route">
        <destination>0.0.0.0/0</destination>
        <nexthop><ip-address>203.0.113.1</ip-address></nexthop>
        <metric>10</metric>
      </entry>
      <entry name="tunnel1-remote">
        <destination>10.100.1.2/32</destination>
        <nexthop><ip-address>10.100.1.2</ip-address></nexthop>
        <interface>tunnel.1</interface>
        <metric>1</metric>
      </entry>
    </static-route>
  </ip>
</routing-table>
```

**Supported Attributes:**
- Destination prefix (CIDR)
- Next-hop IP or interface
- Administrative distance (metric)
- VRF context from virtual-router name

**Parsing Status:** ✅ Implemented — `parse_static_routes()` handles `<routing-table><ip><static-route>` per virtual-router

---

### 6. Security Policies → ACLConfig

**XML structure:**
```xml
<rulebase>
  <security>
    <rules>
      <entry name="trust-to-internet">
        <from><member>trust</member></from>
        <to><member>untrust</member></to>
        <source><member>10.10.0.0/24</member></source>
        <destination><member>any</member></destination>
        <application>
          <member>web-browsing</member>
          <member>ssl</member>
        </application>
        <action>allow</action>
      </entry>
      <entry name="deny-all">
        <from><member>any</member></from>
        <to><member>any</member></to>
        <source><member>any</member></source>
        <destination><member>any</member></destination>
        <application><member>any</member></application>
        <action>deny</action>
      </entry>
    </rules>
  </security>
</rulebase>
```

**PAN-OS-Specific Differences:**
- Security policies are zone-based (`from`/`to` reference zone names, not interfaces)
- Matching is by application identity (App-ID), not TCP/UDP port numbers
- Mapped to `ACLConfig` with `acl_type="extended"` and `name="security-policy-{vsys}"`
- Rule details (zone, source, destination, application) stored in `ACLEntry.remark`
- `allow` → `permit`; `deny` → `deny`

**Supported Attributes:**
- Rule name, action (permit/deny)
- From/to zones, source/destination addresses, applications (captured in remark)
- Per-vsys ACL object

**Parsing Status:** ✅ Implemented — `parse_acls()` maps `<rulebase><security><rules>` to `ACLConfig`

---

### 7. NAT Policies → NATConfig

**XML structure:**
```xml
<rulebase>
  <nat>
    <rules>
      <!-- Source NAT (PAT via interface) -->
      <entry name="trust-snat-to-internet">
        <source-translation>
          <dynamic-ip-and-port>
            <interface-address>
              <interface>ethernet1/1</interface>
            </interface-address>
          </dynamic-ip-and-port>
        </source-translation>
      </entry>

      <!-- Destination NAT (DNAT to web server) -->
      <entry name="dnat-web-server">
        <destination><member>203.0.113.2</member></destination>
        <destination-translation>
          <translated-address>172.16.10.10</translated-address>
          <translated-port>443</translated-port>
        </destination-translation>
      </entry>
    </rules>
  </nat>
</rulebase>
```

**PAN-OS-Specific Differences:**
- Source NAT (SNAT/PAT) and destination NAT (DNAT) are separate rule types in the same rulebase
- PAN-OS does not reference external ACL objects for NAT — source addresses are inline in the rule
- DNAT rules are captured as `NATStaticEntry`; SNAT rules are noted but not mapped to avoid false dangling references

**Supported Attributes:**
- Static DNAT: original IP (from destination member), translated IP and port
- Direction: `"outside"` for DNAT

**Parsing Status:** ✅ Implemented — `parse_nat()` captures `<destination-translation>` entries as `NATStaticEntry`

---

### 8. IPsec / IKE → CryptoConfig

**XML structure:**
```xml
<ike>
  <crypto-profiles>
    <ike-crypto-profiles>
      <entry name="IKEv2-AES256-SHA256-DH14">
        <encryption><member>aes-256-cbc</member></encryption>
        <hash><member>sha256</member></hash>
        <dh-group><member>group14</member></dh-group>
        <lifetime><hours>8</hours></lifetime>
      </entry>
    </ike-crypto-profiles>
    <ipsec-crypto-profiles>
      <entry name="IPSec-AES256-SHA256">
        <esp>
          <encryption><member>aes-256-cbc</member></encryption>
          <authentication><member>sha256</member></authentication>
        </esp>
      </entry>
    </ipsec-crypto-profiles>
  </crypto-profiles>

  <gateway>
    <entry name="GW-Branch-A">
      <peer-address><ip>198.51.100.10</ip></peer-address>
      <local-address>
        <interface>ethernet1/4</interface>
      </local-address>
      <ike-crypto-profile>IKEv2-AES256-SHA256-DH14</ike-crypto-profile>
    </entry>
  </gateway>
</ike>

<tunnel>
  <ipsec>
    <entry name="IPSEC-Branch-A">
      <auto-key>
        <ike-gateway><entry name="GW-Branch-A"/></ike-gateway>
        <ipsec-crypto-profile>IPSec-AES256-SHA256</ipsec-crypto-profile>
      </auto-key>
      <tunnel-interface>tunnel.1</tunnel-interface>
    </entry>
  </ipsec>
</tunnel>
```

**PAN-OS-Specific Differences:**
- IKE crypto profiles → `IKEv1Policy` (PAN-OS abstracts IKEv1/v2 similarly)
- IPsec crypto profiles → `IPSecTransformSet`
- IKE gateways → `CryptoMapEntry` (one entry per remote peer)
- All gateways are collected into a single `CryptoMap` named `"PANOS-IPSEC"`

**Supported Attributes:**
- IKE crypto profiles: encryption, hash, DH group, lifetime
- IPsec crypto profiles: ESP encryption + authentication algorithms
- IKE gateways: peer IP, local interface, crypto profile reference

**Parsing Status:** ✅ Implemented — `parse_crypto()` handles `<ike><crypto-profiles>`, `<ike><gateway>`, and `<tunnel><ipsec>` blocks

---

### 9. Security Zones → PANOSZoneConfig

**XML structure:**
```xml
<vsys>
  <entry name="vsys1">
    <zone>
      <entry name="untrust">
        <network>
          <layer3>
            <member>ethernet1/1</member>
            <member>ethernet1/4</member>
          </layer3>
          <zone-protection-profile>Zone-Protect-Strict</zone-protection-profile>
        </network>
        <log-setting>default</log-setting>
      </entry>
      <entry name="vpn-tunnels">
        <network>
          <tunnel>
            <member>tunnel.1</member>
            <member>tunnel.2</member>
          </tunnel>
        </network>
      </entry>
    </zone>
  </entry>
</vsys>
```

**PAN-OS-Specific Differences:**
- Security zones are the fundamental policy segmentation unit — interfaces are assigned to zones, not policies
- Zone types: `layer3`, `layer2`, `tap`, `virtual-wire`, `tunnel`
- Zones live inside `<vsys>` entries (multi-vsys environments have zones per vsys)
- Zone → interface membership generates graph edges: `zone ──► interface`

**Supported Attributes:**
- Zone name, vsys, zone type
- Member interfaces (drives `zone → interface` graph edges)
- Zone protection profile
- Log setting

**Parsing Status:** ✅ Implemented — `parse_zones()` handles all zone types across all vsys entries; zone membership also populates `InterfaceConfig.zone`

---

## Graph Visualization

PAN-OS configs produce a graph with the following node types:

| Node type | Color | Represents |
|-----------|-------|------------|
| `interface` | Blue | Ethernet, loopback, tunnel, AE interfaces |
| `vrf` | Blue | Virtual routers |
| `bgp_instance` | Green | BGP process per virtual-router |
| `ospf_instance` | Green | OSPF process per virtual-router |
| `static_route` | Green | Static routing entries |
| `acl` | Amber | Security policy rulebase (zone-based) |
| `nat` | Red | NAT policy (DNAT entries) |
| `crypto` | Red | IKE/IPsec configuration |
| `zone` | Red | Security zones |

**Key dependency chains visible in the graph:**

- **BGP over IPsec tunnel:**
  `bgp_instance ──► iface:tunnel.1 ──► zone:vpn-tunnels`
  The `update_source` edge from BGP neighbor to tunnel interface makes this chain explicit.

- **Zone → interface membership:**
  `zone:untrust ──► iface:ethernet1/1`
  Each zone shows which interfaces it contains.

- **Crypto → interface:**
  IKE gateways reference their local interface, connecting the crypto node to the interface graph.

**Sidebar clusters available:** BGP, OSPF, NAT, Crypto/VPN, Zones

---

## Parser Architecture

Unlike IOS-style parsers, PAN-OS uses a two-layer approach:

```
Config text (XML)
    │
    ▼
panos_xml.parse_panos_xml()       Strip namespace declarations, ElementTree.fromstring()
    ├── find_device()             <devices><entry>
    ├── find_all_vsys()           <vsys><entry>
    ├── entries(parent, path)     findall("{path}/entry")
    ├── text_val(el, path)        find(path).text.strip()
    └── members(el, path)         findall("{path}/member")
    │
    ▼
PANOSParser parse methods         Navigate XML tree, build model objects
    │
    ▼
ParsedConfig                      Standard model used by all OS types
```

---

## Implemented Methods Summary

| Method | What it handles |
|--------|-----------------|
| `_extract_hostname()` | `<deviceconfig><system><hostname>` |
| `_collect_unrecognized_blocks()` | Returns `[]` — CiscoConfParse not used |
| `parse_vrfs()` | `<network><virtual-router>` entries |
| `parse_interfaces()` | Ethernet, loopback, tunnel, AE interfaces with zone/VR cross-referencing |
| `parse_bgp()` | `<protocol><bgp>` per virtual-router with peer-group/peer hierarchy |
| `parse_ospf()` | `<protocol><ospf>` per virtual-router with area/interface blocks |
| `parse_static_routes()` | `<routing-table><ip><static-route>` per virtual-router |
| `parse_acls()` | `<rulebase><security><rules>` — zone-based security policies |
| `parse_nat()` | `<rulebase><nat><rules>` — static DNAT entries |
| `parse_crypto()` | IKE crypto profiles, IPsec profiles, IKE gateways |
| `parse_zones()` | `<vsys><zone>` entries across all virtual systems |

---

## Parser Limitations

1. **IPv6 routing protocols** — IPv6 static routes and OSPFv3 are not parsed.
2. **Multi-vsys policy** — Security and NAT policies are parsed per-vsys; inter-vsys policy is not modeled.
3. **Panorama device groups** — Only device-local config is supported; Panorama shared/device-group rules are not parsed.
4. **Application-ID (App-ID) semantics** — Security policy ACL entries capture application names as text in the remark field only; App-ID object definitions are not resolved.
5. **Address objects / address groups** — Named address objects and groups referenced in security/NAT rules are not resolved to IP addresses.
6. **Service objects** — Named service objects (port definitions) are not resolved.
7. **Source NAT (SNAT/PAT)** — SNAT rules are detected but not modeled as `NATDynamicEntry` to avoid false dangling references (PAN-OS does not reference external ACL objects for source selection).
8. **GlobalProtect VPN** — Not parsed.
9. **Decryption policies** — Not parsed.
10. **High Availability (HA)** — HA configuration is not parsed.

---

## Testing and Validation

**Sample Configuration:** `samples/panos_sample.xml`

**Validated output (`confgraph info samples/panos_sample.xml --os panos`):**
```
Hostname : pa-edge-fw01
OS       : panos

Interfaces         8
VRFs               1
BGP instances      1
OSPF instances     1
ACLs               1
Static routes      6
```

**Auto-detection signals** (used when `--os` is not provided):

| Signal | Example |
|--------|---------|
| `<config version=` | PAN-OS XML config header |
| `<devices>` | Top-level devices block |
| `<vsys>` | Virtual system block |
| `<rulebase>` | Security/NAT rulebase |
| `<virtual-router>` | Network virtual-router block |

---

## Quick Reference

```python
from confgraph.parsers.panos_parser import PANOSParser

parser = PANOSParser(config_text)
parsed = parser.parse()
# os_type = OSType.PANOS  # "panos"
```

```bash
confgraph info samples/panos_sample.xml --os panos
confgraph map  samples/panos_sample.xml --os panos --lint
```

---

**Last Updated:** 2026-04-22
**Parser Version:** 1.0.0
