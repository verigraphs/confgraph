# Cisco IOS-XR Parser Support Documentation

## Overview

The IOS-XR parser (`confgraph.parsers.iosxr_parser.IOSXRParser`) parses Cisco IOS-XR device configurations. It inherits from `IOSParser` and overrides methods extensively where IOS-XR syntax diverges from IOS, including VRFs, interfaces, BGP, OSPF, ACLs, static routes, multicast, and all policy constructs.

**Class:** `confgraph.parsers.iosxr_parser.IOSXRParser`
**Inherits from:** `IOSParser`
**CiscoConfParse syntax:** `iosxr`
**OSType:** `OSType.IOS_XR` ("ios_xr")

---

## Key Syntax Differences from IOS

| Feature | IOS | IOS-XR |
|---------|-----|--------|
| VRF definition | `vrf definition NAME` | `vrf NAME` (no keyword) |
| VRF route-targets | inline children | multi-line under `import/export route-target` stanzas |
| Interface VRF | `vrf forwarding NAME` | `vrf NAME` (no keyword) |
| IP address | `ip address X MASK` | `ipv4 address X MASK` |
| Interface ACL | `ip access-group NAME in\|out` | `ipv4 access-group NAME ingress\|egress` |
| ACL definition | `ip access-list standard\|extended NAME` | `ipv4 access-list NAME` / `ipv6 access-list NAME` |
| Static routes | `ip route PREFIX MASK NEXTHOP` | `router static` block with nested `address-family` and optional `vrf` sub-blocks |
| BGP neighbor syntax | `neighbor X remote-as Y` (flat) | `neighbor X\n  remote-as Y` (block-style) |
| BGP peer templates | `neighbor X peer-group NAME` | `neighbor-group NAME` / `use neighbor-group NAME` |
| BGP neighbor policies | flat AF block per neighbor | `route-policy NAME in/out` inside neighbor's `address-family` sub-block |
| VRF BGP | `address-family ipv4 vrf NAME` | `vrf NAME` block under router bgp |
| Route-maps | `route-map NAME permit N` | `route-policy NAME` ... `end-policy` |
| Prefix-lists | `ip prefix-list NAME seq N` | `prefix-set NAME` ... `end-set` (comma-separated) |
| AS-path lists | `ip as-path access-list NAME` | `as-path-set NAME` ... `end-set` |
| Community lists | `ip community-list` | `community-set NAME` ... `end-set` |
| Extended communities | `ip extcommunity-list` | `extcommunity-set rt NAME` ... `end-set` |
| OSPF interface membership | `ip ospf PROC area AREA` on interface | nested under `area N` → `interface NAME` in OSPF block |
| Multicast RP / SSM | flat `ip pim rp-address` / `ip pim ssm` | `router pim` with nested `address-family ipv4` block; separate `multicast-routing` block |

---

## Configuration Syntax Support

### 1. VRF Configuration

**Syntax:**
```
vrf <name>
  description <text>
  address-family ipv4 unicast
    import route-target
      <rt-value>
    export route-target
      <rt-value>
    import route-policy <name>
    export route-policy <name>
```

**IOS-XR-Specific Differences:**
- VRF defined with `vrf NAME` (no `definition` keyword)
- Route-targets listed under `import route-target` / `export route-target` stanzas as children
- Import/export policies use `route-policy` instead of `route-map`

**Supported Attributes:**
- VRF name
- Route distinguisher (RD)
- Route-target import/export (nested stanza format)
- Import/export route-policies

**Parsing Status:** ✅ Overridden — `parse_vrfs()` handles `vrf NAME` with nested `import/export route-target` blocks and `import/export route-policy`

---

### 2. Interface Configuration

**Syntax:**
```
interface <type><number>
  description <text>
  vrf <vrf-name>
  ipv4 address <address> <mask>
  ipv6 address <address>/<prefix-length>
  ipv4 access-group <acl-name> ingress
  ipv4 access-group <acl-name> egress
  shutdown
```

**IOS-XR-Specific Differences:**
- **VRF:** `vrf NAME` (no `forwarding` keyword)
- **IP address:** `ipv4 address X MASK` instead of `ip address X MASK`
- **Interface ACL:** `ipv4 access-group NAME ingress|egress` instead of `ip access-group NAME in|out`
- OSPF interface membership is declared inside the OSPF block (not on the interface)

**Supported Attributes:**
- All standard interface attributes (name, description, shutdown)
- IPv4/IPv6 addresses
- VRF membership
- ACL in/out (`acl_in`, `acl_out` populated from `ipv4 access-group`)

**Parsing Status:** ✅ Overridden — `parse_interfaces()` handles `ipv4 address X MASK`, `vrf NAME`, and `ipv4 access-group NAME ingress|egress`

---

### 3. BGP Configuration

**Syntax:**
```
router bgp <asn>
  bgp router-id <router-id>
  neighbor-group <name>
    remote-as <asn>
    update-source <interface>
  neighbor <ip>
    remote-as <asn>
    description <text>
    use neighbor-group <name>
    address-family ipv4 unicast
      route-policy <name> in
      route-policy <name> out
  address-family ipv4 unicast
    network <prefix>/<length>
  vrf <vrf-name>
    rd <rd-value>
    neighbor <ip>
      remote-as <asn>
      address-family ipv4 unicast
        route-policy <name> in
        route-policy <name> out
```

**IOS-XR-Specific Differences:**

- Neighbor definitions use block syntax (`neighbor X\n  remote-as Y`) rather than flat `neighbor X remote-as Y`
- Peer templates use `neighbor-group NAME` / `use neighbor-group NAME`
- Route-policy assignments are inside each neighbor's `address-family` sub-block
- VRF BGP as `vrf NAME` block under `router bgp`

**Supported Attributes:**
- All standard BGP attributes
- Block-style neighbor parsing with per-neighbor AF policies
- Neighbor-groups (equivalent to IOS peer-groups)
- VRF BGP instances with route-policy in/out

**Parsing Status:**
- ✅ Overridden — `_parse_bgp_neighbors()` handles block-style neighbor syntax
- ✅ Overridden — `_apply_bgp_af_neighbor_policies()` reads `route-policy NAME in/out` from per-neighbor AF sub-blocks
- ✅ Overridden — `_parse_bgp_peer_groups()` handles `neighbor-group NAME` blocks
- ✅ Overridden — `_parse_bgp_vrf_instances()` handles `vrf NAME` blocks with block-style VRF neighbors

---

### 4. OSPF Configuration

**Syntax:**
```
router ospf <process-id>
  router-id <router-id>
  log adjacency changes detail
  redistribute bgp <asn> metric <m> metric-type <t> route-policy <name>
  area <area-id>
    interface <intf-name>
      cost <cost>
      network point-to-point
      passive enable
```

**IOS-XR-Specific Differences:**
- Interface membership is declared inside the OSPF block under `area N` → `interface NAME` stanzas
- Passive interfaces are indicated by `passive enable` inside the interface stanza
- Redistribution uses `route-policy` instead of `route-map`

**Supported Attributes:**
- Process ID, router-id
- Areas with nested interface assignments
- Area types (stub, NSSA)
- Passive interfaces (detected via `passive enable` within interface stanza)
- Redistribution with route-policy

**Parsing Status:** ✅ Overridden — `parse_ospf()` and `_parse_ospf_areas_iosxr()` handle area-nested interface blocks and `passive enable` detection

---

### 5. Route-Maps (Route-Policies)

**Syntax:**
```
route-policy <name>
  if destination in <prefix-set> then
    set local-preference <value>
    set community <community> additive
  else
    drop
  endif
end-policy
```

**IOS-XR-Specific Differences:**
- `route-policy NAME` / `end-policy` blocks replace IOS `route-map` sequences
- Policy body uses an if/then/else language
- `set` and `pass`/`drop` statements replace IOS set/permit/deny

**Supported Attributes:**
- Policy name
- Best-effort match extraction: `if destination in PREFIX_SET` → match clause
- Best-effort set extraction: `set` commands → set clauses
- Full policy body preserved in `raw_lines`

**Note:** IOS-XR route-policy bodies use an if/then/else language. The parser performs best-effort extraction sufficient for dependency graph analysis (identifying referenced prefix-sets and communities). The full policy body is preserved in `raw_lines`.

**Parsing Status:** ✅ Overridden — `parse_route_maps()` maps `route-policy`/`end-policy` blocks to `RouteMapConfig`

---

### 6. Prefix-Lists (Prefix-Sets)

**Syntax:**
```
prefix-set <name>
  10.0.0.0/8 le 32,
  192.168.0.0/16 ge 24 le 32,
  0.0.0.0/0
end-set
```

**IOS-XR-Specific Differences:**
- `prefix-set NAME` / `end-set` blocks replace IOS `ip prefix-list`
- Entries are comma-separated within the block
- No per-entry sequence numbers or permit/deny keywords; the set is referenced by route-policies

**Supported Attributes:**
- Set name
- Prefix entries (network/length, ge/le modifiers)

**Parsing Status:** ✅ Overridden — `parse_prefix_lists()` maps `prefix-set`/`end-set` comma-separated entries to `PrefixListConfig`

---

### 7. AS-Path Lists (AS-Path Sets)

**Syntax:**
```
as-path-set <name>
  ios-regex '^65000_',
  ios-regex '_65001_'
end-set
```

**IOS-XR-Specific Differences:**
- `as-path-set NAME` / `end-set` blocks replace IOS `ip as-path access-list`
- Entries use `ios-regex` keyword

**Parsing Status:** ✅ Overridden — `parse_as_path_lists()` maps `as-path-set`/`end-set` to `ASPathListConfig`

---

### 8. Community Lists (Community-Sets and Extcommunity-Sets)

**Syntax:**
```
community-set <name>
  65000:100,
  65000:200
end-set

extcommunity-set rt <name>
  65000:1,
  65000:2
end-set
```

**IOS-XR-Specific Differences:**
- `community-set NAME` / `end-set` blocks replace IOS `ip community-list`
- `extcommunity-set rt NAME` / `end-set` blocks capture extended communities used as route-targets; stored as `CommunityListConfig` with `list_type="extended"`

**Parsing Status:** ✅ Overridden — `parse_community_lists()` maps both `community-set`/`end-set` and `extcommunity-set rt`/`end-set` to `CommunityListConfig`

---

### 9. ACLs

**Syntax:**
```
ipv4 access-list INBOUND-ISP1
 10 deny ipv4 any host 10.0.0.1
 20 permit ipv4 any any
!
ipv6 access-list INBOUND-V6
 10 permit ipv6 any any
```

**IOS-XR-Specific Differences:**

- `ipv4 access-list NAME` and `ipv6 access-list NAME` replace IOS `ip access-list standard|extended NAME`
- Both IPv4 and IPv6 ACL blocks are parsed

**Parsing Status:** ✅ Overridden — `parse_acls()` handles `ipv4 access-list` and `ipv6 access-list` blocks

---

### 10. Static Routes

**Syntax:**
```
router static
 address-family ipv4 unicast
  0.0.0.0/0 192.168.1.1
  192.0.2.0/24 Null0 254
 !
 vrf CUST-A
  address-family ipv4 unicast
   0.0.0.0/0 10.0.0.2
```

**IOS-XR-Specific Differences:**

- All static routes are defined inside a `router static` block
- Routes are under `address-family ipv4 unicast` sub-blocks
- Per-VRF routes use a nested `vrf NAME` sub-block within `router static`

**Parsing Status:** ✅ Overridden — `parse_static_routes()` handles the `router static` block with nested `address-family` and `vrf` sub-blocks

---

### 11. Multicast

**Syntax:**
```
router pim
 address-family ipv4
  rp-address 10.0.0.1
  ssm range RFC1918
!
multicast-routing
 address-family ipv4
```

**IOS-XR-Specific Differences:**

- RP addresses and SSM config are nested under `router pim` → `address-family ipv4` blocks
- `multicast-routing` is a separate top-level block (IOS uses flat `ip pim` statements)

**Parsing Status:** ✅ Overridden — `parse_multicast()` handles `router pim` with nested `address-family ipv4` blocks and the separate `multicast-routing` block

---

### 12. Extended Protocol Support (Inherited from IOSParser)

The following protocols use IOS-identical syntax in IOS-XR:

| Protocol | Parsing Status |
|----------|---------------|
| NTP | ✅ Inherited from IOSParser |
| SNMP | ✅ Inherited from IOSParser |
| Syslog | ✅ Inherited from IOSParser |
| Banners | ✅ Inherited from IOSParser |
| Line configs (con/vty) | ✅ Inherited from IOSParser |
| QoS (class-map/policy-map) | ✅ Inherited from IOSParser |
| BFD | ✅ Inherited from IOSParser |
| IP SLA | ✅ Inherited from IOSParser |
| EEM Applets | ✅ Inherited from IOSParser |
| Object Tracking | ✅ Inherited from IOSParser |

See [IOS_PARSER_SUPPORT.md](IOS_PARSER_SUPPORT.md) for full syntax and attribute details.

---

## Overridden Methods Summary

| Method | Reason for Override |
|--------|---------------------|
| `parse_vrfs()` | Handles `vrf NAME` with nested `import/export route-target` blocks and `import/export route-policy` |
| `_extract_interface_vrf()` | Handles `vrf NAME` (no `forwarding` keyword) |
| `parse_interfaces()` | Handles `ipv4 address X MASK`, `vrf NAME`, and `ipv4 access-group NAME ingress\|egress` |
| `parse_acls()` | Handles `ipv4 access-list NAME` and `ipv6 access-list NAME` blocks |
| `parse_static_routes()` | Handles `router static` block with nested `address-family` and `vrf` sub-blocks |
| `_parse_bgp_neighbors()` | Handles block-style neighbor syntax (`neighbor X\n  remote-as Y`) |
| `_apply_bgp_af_neighbor_policies()` | Reads `route-policy NAME in/out` from per-neighbor `address-family` sub-blocks |
| `_parse_bgp_peer_groups()` | Handles `neighbor-group NAME` blocks |
| `_parse_bgp_vrf_instances()` | Handles `vrf NAME` blocks under router bgp with block-style VRF neighbor parsing |
| `parse_ospf()` | Consumes passive interface list from `_parse_ospf_areas_iosxr()` |
| `_parse_ospf_areas_iosxr()` | Handles area-nested interface blocks; detects `passive enable` |
| `parse_route_maps()` | Maps `route-policy`/`end-policy` blocks to `RouteMapConfig` |
| `parse_prefix_lists()` | Maps `prefix-set`/`end-set` comma-separated entries to `PrefixListConfig` |
| `parse_as_path_lists()` | Maps `as-path-set`/`end-set` to `ASPathListConfig` |
| `parse_community_lists()` | Maps `community-set`/`end-set` and `extcommunity-set rt`/`end-set` to `CommunityListConfig` |
| `parse_multicast()` | Handles `router pim` nested AF blocks and separate `multicast-routing` block |

---

## Parser Limitations

1. **Route-policy full semantics** — Complex if/then/else logic is best-effort; only `destination in PREFIX_SET` and `set` commands are extracted
2. **IPv6 routing** — Limited IPv6 routing protocol coverage
3. **IOS-XR-specific features** — Segment Routing, MPLS-TE, L2VPN not parsed

---

## Testing and Validation

**Sample Configuration:** `samples/iosxr_test.cfg`

**Validated output (`confgraph info samples/iosxr_test.cfg --os iosxr`):**
```
Hostname : XR-CORE-01
OS       : ios_xr
Interfaces         2
VRFs               1
BGP instances      2
OSPF instances     1
Route-maps         4
Prefix-lists       2
ACLs               3
Community-lists    2
AS-path-lists      1
Static routes      3
SNMP               1
```

---

## Quick Reference

```python
from confgraph.parsers.iosxr_parser import IOSXRParser
from confgraph.models.base import OSType

parser = IOSXRParser(config_text)
parsed = parser.parse()
# os_type = OSType.IOS_XR  # "ios_xr"
```

```bash
confgraph info samples/iosxr_test.cfg --os iosxr
```

---

**Last Updated:** 2026-04-13
**Parser Version:** 1.2.0
