# Cisco IOS-XR Parser Support Documentation

## Overview

The IOS-XR parser (`confgraph.parsers.iosxr_parser.IOSXRParser`) parses Cisco IOS-XR device configurations. It inherits from `IOSParser` and overrides methods extensively where IOS-XR syntax diverges from IOS, including VRFs, interfaces, BGP, OSPF, and all policy constructs.

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
| BGP peer templates | `neighbor X peer-group NAME` | `neighbor-group NAME` / `use neighbor-group NAME` |
| VRF BGP | `address-family ipv4 vrf NAME` | `vrf NAME` block under router bgp |
| Route-maps | `route-map NAME permit N` | `route-policy NAME` ... `end-policy` |
| Prefix-lists | `ip prefix-list NAME seq N` | `prefix-set NAME` ... `end-set` (comma-separated) |
| AS-path lists | `ip as-path access-list NAME` | `as-path-set NAME` ... `end-set` |
| Community lists | `ip community-list` | `community-set NAME` ... `end-set` |
| OSPF interface membership | `ip ospf PROC area AREA` on interface | nested under `area N` → `interface NAME` in OSPF block |

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
  shutdown
```

**IOS-XR-Specific Differences:**
- **VRF:** `vrf NAME` (no `forwarding` keyword)
- **IP address:** `ipv4 address X MASK` instead of `ip address X MASK`
- **IPv6:** `ipv6 address` (standard)
- OSPF interface membership is declared inside the OSPF block (not on the interface)

**Supported Attributes:**
- All standard interface attributes (name, description, shutdown)
- IPv4/IPv6 addresses
- VRF membership

**Parsing Status:** ✅ Overridden — `parse_interfaces()` handles `ipv4 address X MASK` and `vrf NAME`

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
    use neighbor-group <name>
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
- Peer templates use `neighbor-group NAME` / `use neighbor-group NAME`
- VRF BGP as `vrf NAME` block under `router bgp`
- Neighbor policies use `route-policy NAME in/out` instead of `route-map`

**Supported Attributes:**
- All standard BGP attributes
- Neighbor-groups (equivalent to IOS peer-groups)
- VRF BGP instances with route-policy in/out

**Parsing Status:**
- ✅ Core BGP: Inherited from IOSParser
- ✅ Overridden — `_parse_bgp_peer_groups()` handles `neighbor-group NAME` blocks
- ✅ Overridden — `_parse_bgp_vrf_instances()` handles `vrf NAME` blocks; `route-policy` for in/out

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
- Redistribution uses `route-policy` instead of `route-map`

**Supported Attributes:**
- Process ID, router-id
- Areas with nested interface assignments
- Area types (stub, NSSA)
- Passive interfaces (via `passive enable` within interface stanza)
- Redistribution with route-policy

**Parsing Status:** ✅ Overridden — complete override for area-nested interface blocks

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

**Note on parsing:** IOS-XR route-policy bodies use an if/then/else language. The parser performs best-effort extraction sufficient for dependency graph analysis (identifying referenced prefix-sets and communities). The full policy body is preserved in `raw_lines`.

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

### 8. Community Lists (Community-Sets)

**Syntax:**
```
community-set <name>
  65000:100,
  65000:200
end-set
```

**IOS-XR-Specific Differences:**
- `community-set NAME` / `end-set` blocks replace IOS `ip community-list`

**Parsing Status:** ✅ Overridden — `parse_community_lists()` maps `community-set`/`end-set` to `CommunityListConfig`

---

### 9. Extended Protocol Support (Inherited from IOSParser)

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
| Multicast (PIM/IGMP) | ✅ Inherited from IOSParser |
| Static Routes | ✅ Inherited from IOSParser |

See [IOS_PARSER_SUPPORT.md](IOS_PARSER_SUPPORT.md) for full syntax and attribute details.

---

## Overridden Methods Summary

| Method | Reason for Override |
|--------|---------------------|
| `parse_vrfs()` | Handles `vrf NAME` with nested `import/export route-target` blocks and `import/export route-policy` |
| `_extract_interface_vrf()` | Handles `vrf NAME` (no `forwarding` keyword) |
| `parse_interfaces()` | Handles `ipv4 address X MASK` |
| `_parse_bgp_peer_groups()` | Handles `neighbor-group NAME` blocks |
| `_parse_bgp_vrf_instances()` | Handles `vrf NAME` blocks under router bgp; `route-policy` for in/out |
| `parse_ospf()` | Complete override for area-nested interface blocks |
| `parse_route_maps()` | Maps `route-policy`/`end-policy` blocks to `RouteMapConfig` |
| `parse_prefix_lists()` | Maps `prefix-set`/`end-set` comma-separated entries to `PrefixListConfig` |
| `parse_as_path_lists()` | Maps `as-path-set`/`end-set` to `ASPathListConfig` |
| `parse_community_lists()` | Maps `community-set`/`end-set` to `CommunityListConfig` |

---

## Parser Limitations

1. **Route-policy full semantics** — Complex if/then/else logic is best-effort; only `destination in PREFIX_SET` and `set` commands are extracted
2. **IPv6 routing** — Limited IPv6 routing protocol coverage
3. **IOS-XR-specific features** — Segment Routing, MPLS-TE, L2VPN not parsed

---

## Testing and Validation

**Sample Configuration:** `samples/ios_xr.txt`

**Validated Counts:**
```
✅ Hostname: R1-IOSXR
✅ Interfaces: 12 parsed
✅ VRFs: 2 parsed
✅ BGP: 2 instances (global + VRF)
✅ OSPF: 1 process
✅ Route-maps (route-policies): 13 parsed
✅ Prefix-lists (prefix-sets): 4 parsed
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
uv run python test_iosxr_parser.py
```

---

**Last Updated:** 2026-03-28
**Parser Version:** 1.1.0
