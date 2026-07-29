# Palo Alto PAN-OS Parser Support Documentation

## Overview

The PAN-OS parser (`confgraph.parsers.panos_parser.PANOSParser`) parses Palo Alto Networks PAN-OS device configurations in XML format. Unlike all other parsers, it does **not** use `CiscoConfParse` — PAN-OS configurations are XML documents, not line-oriented text. Instead it uses a lightweight XML navigation helper (`confgraph.parsers.panos_xml`) built on Python's standard `xml.etree.ElementTree`.

Two document layouts are read (CCR-0034 / CCR-0041): a **local firewall** export (`devices/entry/{deviceconfig,network,vsys/entry}`) and a **Panorama** export (device-group `pre`/`post`-rulebase, `shared` rulebase, and network/vsys config nested inside `template` entries). Layout is decided exactly once by `panos_xml.detect_layout`, which hands every parse method a layout-neutral view (device / vsys / policy scopes) so no method ever asks "am I Panorama?". A document in neither known layout raises `ParseError` rather than returning an empty model — "this firewall has no rules" and "this firewall's rules are in a place we don't read" must not look the same.

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
- Member interfaces → `VRFConfig.interfaces` (the `<interface><member>` list that is a *direct* child of the VR entry — not the entry-keyed interface lists nested under `protocol/ospf/area`). This both populates the VRF↔interface edge and cross-references `virtual_router` on `InterfaceConfig`.

**Parsing Status:** ✅ Implemented — `parse_vrfs()` handles `<network><virtual-router>` entries across all device scopes

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
- IPv6 addresses (from `<ipv6><addresses><entry>`)
- Description (from `<comment>`)
- Enabled/disabled state (`<link-state>down</link-state>` → disabled)
- MTU (from `<layer3><mtu>` or `<mtu>`)
- Zone assignment (`zone` field — cross-referenced from `<vsys><zone>`)
- Virtual router assignment (`virtual_router` field — cross-referenced from `<network><virtual-router>`)
- OSPF per-interface settings (cost, priority, hello, network type, passive) — these live inside the OSPF `<area>`, not on the interface object, so `parse_ospf()` carries them out in `OSPFArea.interface_settings` and `BaseParser._backfill_ospf_interface_settings` attributes them onto the `InterfaceConfig` (the one shared backfill every OS uses)

**Tunnel underlay chain (CCR-0116):** A `tunnel.N` interface rides an IPSec tunnel (bound via `<tunnel-interface>`) whose IKE gateway's `local-address/interface` is the physical egress the tunnel actually depends on. `parse_interfaces()` resolves that chain onto the tunnel's `InterfaceConfig`:

| Field | Source |
|-------|--------|
| `tunnel_ike_gateway` | IKE gateway named under the IPSec tunnel's `<auto-key><ike-gateway><entry name="…"/>` |
| `tunnel_protection_profile` | `<auto-key><ipsec-crypto-profile>` (Phase-2 / IPSec profile) |
| `tunnel_underlay_interface` | the bound IKE gateway's `network/ike/gateway/.../local-address/interface` (physical egress) |
| `tunnel_ike_crypto_profile` | the bound IKE gateway's Phase-1 profile, read nested under `protocol/ikev{1,2}/ike-crypto-profile` |

Only `<auto-key>` IPSec tunnels bind a gateway; manual-key and GlobalProtect-satellite tunnels have no IKE gateway and are skipped so no egress edge is invented. Binding degrades gracefully: a tunnel referencing a missing gateway still records what is known and simply leaves `tunnel_underlay_interface` unset (no tunnel→egress edge emitted).

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
- Remote AS is `<peer-as>`, a **direct child of the peer entry** — it is not spelled `remote-as` and is not under `<connection-options>`
- Peer-group type is element-name-encoded (`<type><ebgp>…</ebgp></type>`); `type/{ebgp,ibgp}/export-nexthop` = `use-self` maps to `next_hop_self`
- `<local-address><interface>` maps to `update_source` — enables BGP-over-tunnel graph edges
- No address-family blocks; IPv4 unicast is implicit
- Neighbor authentication is a two-part relation: the peer's `connection-options/authentication` names an `<auth-profile>` under `<bgp>`; the secret lives in that profile (resolved to `password`)
- Redistribution rules (`<redist-rules>`) are keyed by the name of a `<redist-profile>`; the source protocols live in that profile's `<filter><type><member>` list. `address-family-identifier` on the rule is `ipv4|ipv6` (an address family), never the protocol.
- Import/export policy binds to peer-groups through each rule's `<used-by>` member list (see §3b)

**Supported Attributes:**
- Local ASN, router-ID
- Peer groups with all their nested neighbors; per peer-group `next_hop_self` and bound import/export route-maps
- Per-neighbor: peer IP, remote AS, description, shutdown state, update-source interface, timers (`keep-alive-interval`/`hold-time`), `ebgp_multihop` (from `<multihop>` TTL), `maximum_prefix` (`<max-prefixes>`), MD5 password (resolved from auth-profile), `next_hop_self`, import/export route-maps
- Redistribution rules resolved through redist-profiles (protocol + metric)
- Process-wide `<routing-options>`: graceful restart (`graceful-restart/enable`, `stale-route-time`) and `med/always-compare-med`
- VRF context from virtual-router name (`default` → global)

**BGP over IPsec tunnels:** When `<local-address><interface>` references a tunnel interface, the update-source edge plus the CCR-0116 tunnel-underlay binding chain the full path:
```
bgp:65001 ──[update_source]──► iface:tunnel.1 ──[tunnel_underlay]──► iface:ethernet1/4
                                     └──────────[tunnel_ike_gateway]──► crypto
```
This makes the full BGP → tunnel → physical egress → IPsec dependency chain visible.

**Parsing Status:** ✅ Implemented — `parse_bgp()` handles `<protocol><bgp>` per virtual-router with peer-group/peer hierarchy, `update_source` capture, auth-profile resolution, redist-profile resolution, and routing-options

---

### 3b. BGP Import/Export Policy → RouteMapConfig

**XML structure:**
```xml
<bgp>
  <policy>
    <import>
      <rules>
        <entry name="PREFER-BRANCH">
          <enable>yes</enable>
          <used-by><member>BRANCH-VPN</member></used-by>
          <match><address-prefix><entry name="10.100.0.0/16"/></address-prefix></match>
          <action><allow><update><local-preference>200</local-preference></update></allow></action>
        </entry>
      </rules>
    </import>
    <export> … </export>
  </policy>
</bgp>
```

**PAN-OS-Specific Differences:**
- PAN-OS has no `route-map NAME permit 10` object; a BGP import/export rule is normalized into a `RouteMapConfig` with a single sequence so a graph consumer cannot tell which vendor produced the policy node
- `<action>` is element-name-as-value (`<allow>…</allow>` or `<deny/>`) → `permit` / `deny`
- Match values are **inline**, not references to named objects: `match/address-prefix` (entry-keyed), `from-peer` (members), and regex/text matches (`as-path/regex`, `community/regex`, `extended-community/regex`, `med`, `route-table`). Inline patterns get a `-regex`-style `match_type` so the dependency resolver does not manufacture dangling references.
- Set clauses come from `action/allow/update`: `local-preference`, `med` (→ metric), `weight`, `nexthop`, `origin`, `as-path-limit`, plus element-name-encoded `as-path`/`community` operations
- Every named rule becomes a policy node (`parse_route_maps`), even a disabled one; only *enabled* rules bind to peer-groups via `<used-by>` (§3, `route_map_in`/`route_map_out`)

**Parsing Status:** ✅ Implemented — `parse_route_maps()` maps `<bgp><policy><import|export><rules>` to `RouteMapConfig`. (`parse_prefix_lists()` returns `[]` — PAN-OS has no named prefix-list object; policy prefixes are inline on the policy node.)

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
- No process-ID concept — parser uses `1` as a conventional placeholder (it is confgraph's own value and is deliberately never asserted onto an interface)
- Interface membership is declared inside the OSPF area block; each area interface entry carries the interface's own settings (`metric` = cost, `priority`, `hello-interval`, `link-type` = network type, `passive`) which are backfilled onto the `InterfaceConfig`
- Area type is element-name-encoded (`<type><stub/></type>`). PAN-OS has no `no-summary` keyword: a stub/NSSA area whose `<accept-summary>` is `no` **is** the totally-stubby / totally-NSSA case (STUB→TOTALLY_STUB, NSSA→TOTALLY_NSSA)
- Redistribution uses `<export-rules>`, keyed by redist-profile name (same resolution as BGP); `new-path-type` `ext-1`/`ext-2` → E1/E2 metric type

**Supported Attributes:**
- Router-ID
- Areas with type, interface membership lists, and per-interface settings; totally-stubby / totally-NSSA detection; ABR default-route cost (`type/{stub,nssa}/default-route/advertise/metric`)
- Redistribution (export-rules resolved through redist-profiles: protocol, metric, metric-type, tag)
- VRF context from virtual-router name

**Parsing Status:** ✅ Implemented — `parse_ospf()` handles `<protocol><ospf>` per virtual-router with area types, per-interface settings, and redist-profile resolution

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
- Next-hop IP or interface (`next_hop_interface` set when the route points out an interface)
- Administrative distance (`<admin-dist>`; defaults to PAN-OS's 10 when absent) and route metric (`<metric>`) — the two are **distinct** fields, not conflated (CCR-0030)
- VRF context from virtual-router name

**Parsing Status:** ✅ Implemented — `parse_static_routes()` handles `<routing-table><ip><static-route>` per virtual-router, separating `admin-dist` from `metric`

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
- Mapped to `ACLConfig` with `acl_type="extended"` and `name="security-policy-{scope}"` — one ACL per **policy scope** (a vsys locally, a device-group under Panorama)
- A scope's rulebases arrive already ordered by the layout: locally the single vsys rulebase; under Panorama the resolved `shared-pre → DG-pre → DG-post → shared-post` chain. Ascending ACL sequence numbers therefore carry the firewall's evaluation order.
- Rule details (rule name, zones, source, destination, application) stored in `ACLEntry.remark`
- `allow` → `permit`; `deny` → `deny`

**Supported Attributes:**
- Rule name, action (permit/deny)
- From/to zones, source/destination addresses, applications (captured in remark)
- One ACL object per policy scope, in evaluation order

**Source-NAT address sets:** Each source-NAT rule additionally materializes an ACL of its own (named `nat-source-{rule}`) holding the address set that rule translates, so `NATDynamicEntry.acl` (see §7) resolves instead of dangling — the same rulebase→ACLConfig mapping already applied to security rules (CCR-0035 #7).

**Parsing Status:** ✅ Implemented — `parse_acls()` maps `<rulebase><security><rules>` to `ACLConfig` per policy scope, plus one source-NAT ACL per source-translating NAT rule

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
- Source NAT and destination NAT (DNAT) are separate translations in the same rule/rulebase; both are now modeled
- `<source-translation>` has three mutually exclusive branches chosen by element name: `dynamic-ip-and-port` (PAT / overload), `dynamic-ip` (1:1 dynamic, no ports), and `static-ip`. `<translated-address>` is a **member list** under the two dynamic branches and a **text node** under `static-ip` — one element name, two shapes.
- PAN-OS does not reference external ACL objects for NAT; source addresses are inline on the rule. `parse_acls()` materializes those inline sets as `nat-source-{rule}` ACLs so `NATDynamicEntry.acl` resolves (§6, CCR-0035 #7).
- NAT rules are read per policy scope, so Panorama device-group NAT is covered

**Supported Attributes:**
- Destination NAT → `NATStaticEntry` (original IP from destination member, translated IP and port, direction `"outside"`)
- Source static NAT (`static-ip`) → `NATStaticEntry` (direction `"inside"`)
- Source dynamic NAT → `NATDynamicEntry` (direction `"inside"`, `acl` pointing at the materialized `nat-source-{rule}` set, egress `interface`, pool, and `overload=True` for `dynamic-ip-and-port` / `False` for `dynamic-ip`)

**Parsing Status:** ✅ Implemented — `parse_nat()` captures destination and static-source translations as `NATStaticEntry` and dynamic/PAT source translations as `NATDynamicEntry`

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
- IKE gateways: peer IP, and the Phase-1 crypto profile reference

**IKE crypto profile location (CCR-0116):** A device emits the gateway's Phase-1 profile **nested under the negotiated IKE version** — `protocol/ikev2/ike-crypto-profile` or `protocol/ikev1/ike-crypto-profile` — not as a flat child of the gateway. `parse_crypto()` reads the nested shape first (falling back to a flat `<ike-crypto-profile>` only as lenient back-compat for hand-written configs); the previous flat-only read returned nothing on a real export. This is the same reader `parse_interfaces()` uses for the tunnel underlay chain, so the crypto map and the tunnel binding never disagree.

**Parsing Status:** ✅ Implemented — `parse_crypto()` handles `<ike><crypto-profiles>`, `<ike><gateway>` (nested Phase-1 profile), and `<tunnel><ipsec>` blocks

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
| `route_map` | Green | BGP import/export policy rules (policy nodes) |
| `acl` | Amber | Security policy rulebase (zone-based) + source-NAT address sets |
| `nat` | Red | NAT policy (DNAT + source/PAT entries) |
| `crypto` | Red | IKE/IPsec configuration |
| `zone` | Red | Security zones |

**Key dependency chains visible in the graph:**

- **BGP over IPsec tunnel (CCR-0116):**
  `bgp_instance ──[update_source]──► iface:tunnel.1 ──[tunnel_underlay]──► iface:ethernet1/4`
  plus `iface:tunnel.1 ──[tunnel_ike_gateway]──► crypto`.
  The update-source edge reaches the tunnel; the resolved underlay binding then chains the tunnel to its physical egress interface and to the crypto node, so the full BGP → tunnel → egress → IPsec path is explicit. (The crypto edge is only drawn when crypto config was parsed, so no ghost node is invented.)

- **Zone → interface membership:**
  `zone:untrust ──► iface:ethernet1/1`
  Each zone shows which interfaces it contains.

- **NAT → ACL:**
  `nat ──► acl:nat-source-{rule}`
  A source-NAT dynamic entry points at the materialized address-set ACL, so the edge resolves instead of dangling.

- **BGP policy nodes:**
  Enabled import/export rules bind to their peer-group via `route_map_in`/`route_map_out`, surfacing each policy rule as a `route_map` node.

**Sidebar clusters available:** BGP, OSPF, NAT, Crypto/VPN, Zones

---

## Parser Architecture

Unlike IOS-style parsers, PAN-OS uses a layered approach:

```
Config text (XML)
    │
    ▼
panos_xml.parse_panos_xml()       Strip namespace declarations, ElementTree.fromstring()
    ├── entries(parent, path)     findall("{path}/entry")
    ├── text_val(el, path)        find(path).text.strip()
    ├── members(el, path)         findall("{path}/member")
    └── raw_xml(el)               indented tostring() for raw_config
    │
    ▼
panos_xml.detect_layout()         Classify the document EXACTLY ONCE:
    ├── local firewall  → devices/entry/{deviceconfig,network,vsys}
    ├── Panorama        → device-group pre/post-rulebase + shared + template/config
    └── neither         → raise UnrecognizedPANOSLayout → ParseError (no silent-empty model)
    │                     Returns a layout-neutral PANOSLayout view:
    │                       • device scopes  (own deviceconfig/network/vsys)
    │                       • vsys scopes    (own zone)
    │                       • policy scopes  (rulebase chains in evaluation order)
    ▼
PANOSParser parse methods         Consume the neutral scopes — never ask "am I Panorama?"
    │                             Panorama device-group hierarchy (parent-dg) resolved
    │                             from /config/readonly; template-stacks NOT read
    ▼
ParsedConfig                      Standard model used by all OS types
```

**Panorama specifics** (`_panorama_layout` / `_panorama_policies`): each device-group's effective rulebase chain is resolved to `shared-pre → ancestor-DG-pre → … → own-DG-pre → own-DG-post → … → shared-post`, using the parent-dg hierarchy emitted at `/config/readonly/...`. Template-stacks are deliberately **not** read (their config is assembled from member templates by an unstated priority); a template-stack-only document is an *unrecognized* layout and raises, rather than silently returning nothing.

---

## Implemented Methods Summary

| Method | What it handles |
|--------|-----------------|
| `_extract_hostname()` | `<deviceconfig><system><hostname>` across device scopes |
| `_collect_unrecognized_blocks()` | Returns `[]` — CiscoConfParse not used |
| `parse_vrfs()` | `<network><virtual-router>` entries + member interface list |
| `parse_interfaces()` | Ethernet, loopback, tunnel, AE interfaces with zone/VR cross-referencing and the CCR-0116 tunnel-underlay binding |
| `parse_bgp()` | `<protocol><bgp>` per virtual-router: peer-group/peer hierarchy, timers, multihop, auth-profile, redist-profiles, routing-options |
| `parse_route_maps()` | `<bgp><policy><import\|export><rules>` → `RouteMapConfig` policy nodes |
| `parse_prefix_lists()` | Returns `[]` — PAN-OS has no named prefix-list; policy prefixes are inline |
| `parse_ospf()` | `<protocol><ospf>` per virtual-router: area types, per-interface settings, redist-profiles |
| `parse_static_routes()` | `<routing-table><ip><static-route>` per virtual-router (admin-dist ≠ metric) |
| `parse_acls()` | `<rulebase><security><rules>` per policy scope + source-NAT address-set ACLs |
| `parse_nat()` | `<rulebase><nat><rules>` — DNAT + static/dynamic/PAT source NAT |
| `parse_crypto()` | IKE crypto profiles, IPsec profiles, IKE gateways (nested Phase-1 profile) |
| `parse_zones()` | `<vsys><zone>` entries across all virtual systems |

---

## Parser Limitations

1. **IPv6 routing protocols** — IPv6 static routes and OSPFv3 are not parsed. (BGP is IPv4-unicast; IPv6 redist-profiles are read for protocol names but there are no IPv6 BGP peerings.)
2. **Template-stacks** — Panorama `template` config is read, but `template-stack` entries are not: a stack assembles its config from member templates by an unstated priority, so it is not resolved. A template-stack-*only* document is treated as an unrecognized layout and raises (rather than silently returning an empty model).
3. **Application-ID (App-ID) semantics** — Security policy ACL entries capture application names as text in the remark field only; App-ID object definitions are not resolved.
4. **Address objects / address groups** — Named address objects and groups referenced in security/NAT rules are not resolved to IP addresses (they are kept verbatim in the remark / source-NAT ACL).
5. **Service objects** — Named service objects (port definitions) are not resolved.
6. **GlobalProtect VPN** — Not parsed (GlobalProtect-satellite IPSec tunnels are recognized only insofar as they are *skipped* by the tunnel-underlay binding).
7. **Decryption policies** — Not parsed.
8. **High Availability (HA)** — HA configuration is not parsed.

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
ACLs               2
Static routes      6
```

(ACLs = 2: the vsys `security-policy-vsys1` rulebase plus one materialized `nat-source-{rule}` address-set ACL for the sample's source-NAT rule.)

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

**Last Updated:** 2026-07-29
**Parser Version:** 1.0.0
