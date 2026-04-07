# Cisco NX-OS Parser Support Documentation

## Overview

The NX-OS parser (`confgraph.parsers.nxos_parser.NXOSParser`) parses Cisco NX-OS device configurations. It inherits from `IOSParser` and overrides methods where NX-OS syntax diverges from IOS.

**Class:** `confgraph.parsers.nxos_parser.NXOSParser`
**Inherits from:** `IOSParser`
**CiscoConfParse syntax:** `nxos`
**OSType:** `OSType.NXOS` ("nxos")

---

## Key Syntax Differences from IOS

| Feature | IOS | NX-OS |
|---------|-----|-------|
| VRF definition | `vrf definition NAME` | `vrf context NAME` |
| Interface VRF | `vrf forwarding NAME` | `vrf member NAME` |
| IP address notation | `10.1.1.1 255.255.255.0` | `10.1.1.1/24` (CIDR) |
| BGP peer templates | `neighbor X peer-group NAME` | `template peer NAME` / `inherit peer NAME` |
| OSPF on interface | `ip ospf PROC area AREA` | `ip router ospf PROC area AREA` |
| VRF BGP | `address-family ipv4 vrf NAME` | `vrf NAME` block under router bgp |

---

## Configuration Syntax Support

### 1. VRF Configuration

**Syntax:**
```
vrf context <name>
  rd <rd-value>
  address-family ipv4 unicast
    route-target import <rt-value>
    route-target export <rt-value>
```

**NX-OS-Specific Differences:**
- Uses `vrf context` instead of IOS `vrf definition`
- Route-targets nested under `address-family` blocks within the VRF

**Supported Attributes:**
- VRF name
- Route distinguisher (RD)
- Route-target import/export (per address-family)
- Import/export route-maps

**Parsing Status:** ✅ Overridden — `parse_vrfs()` handles `vrf context NAME` and nested address-family RTs

---

### 2. Interface Configuration

**Syntax:**
```
interface <type><number>
  description <text>
  ip address <address>/<prefix-length>
  vrf member <vrf-name>
  ip router ospf <proc-id> area <area-id>
  no shutdown
```

**NX-OS-Specific Differences:**
- **CIDR Notation:** IP addresses use `/prefix` notation
- **VRF:** `vrf member NAME` instead of `vrf forwarding NAME`
- **OSPF membership:** `ip router ospf PROC area AREA` instead of `ip ospf PROC area AREA`

**Supported Attributes:**
- All standard interface attributes (name, description, IP, shutdown)
- VRF membership via `vrf member`
- OSPF area membership
- Channel-group, switchport, HSRP/VRRP, tunnel parameters

**Parsing Status:** ✅ Overridden — `parse_interfaces()` handles CIDR notation and `ip router ospf` for OSPF membership

---

### 3. BGP Configuration

**Syntax:**
```
router bgp <asn>
  router-id <router-id>
  template peer <name>
    remote-as <asn>
    update-source <interface>
  neighbor <ip> remote-as <asn>
  neighbor <ip> inherit peer <name>
  address-family ipv4 unicast
    network <prefix>/<length>
  vrf <vrf-name>
    neighbor <ip> remote-as <asn>
    address-family ipv4 unicast
      redistribute connected
```

**NX-OS-Specific Differences:**
- BGP peer templates use `template peer NAME` / `inherit peer NAME` instead of `peer-group`
- VRF BGP configured as `vrf NAME` block directly under `router bgp` (not `address-family ipv4 vrf NAME`)

**Supported Attributes:**
- All standard BGP attributes (ASN, router-id, neighbors, address-families)
- Peer templates (equivalent to IOS peer-groups)
- VRF BGP instances

**Parsing Status:**
- ✅ Core BGP: Inherited from IOSParser
- ✅ Overridden — `_parse_bgp_peer_groups()` handles `template peer NAME` blocks
- ✅ Overridden — `_parse_bgp_vrf_instances()` handles `vrf NAME` blocks under router bgp

---

### 4. OSPF Configuration

**Syntax:**
```
router ospf <process-id>
  router-id <router-id>
  log-adjacency-changes
  passive-interface default
  no passive-interface <interface>
  redistribute bgp <asn> subnets route-map <name>
```

**NX-OS-Specific Differences:**
- OSPF process syntax is standard (`router ospf PROC`)
- Interface membership is declared on the interface via `ip router ospf PROC area AREA` (handled in `parse_interfaces()`)

**Parsing Status:** ✅ Inherited from IOSParser (interface OSPF membership handled in overridden `parse_interfaces()`)

---

### 5. Route-Maps

**Syntax:** Identical to IOS (`route-map NAME permit/deny SEQ`)

**Parsing Status:** ✅ Inherited from IOSParser

---

### 6. Prefix-Lists

**Syntax:** Identical to IOS (`ip prefix-list NAME seq N permit/deny PREFIX/LEN`)

**Parsing Status:** ✅ Inherited from IOSParser

---

### 7. Community Lists

**Syntax:** Identical to IOS (`ip community-list`)

**Parsing Status:** ✅ Inherited from IOSParser

---

### 8. AS-Path Lists

**Syntax:** Identical to IOS (`ip as-path access-list`)

**Parsing Status:** ✅ Inherited from IOSParser

---

### 9. Extended Protocol Support (Inherited from IOSParser)

The following protocols use IOS-identical syntax in NX-OS:

| Protocol | Parsing Status |
|----------|---------------|
| NTP | ✅ Inherited from IOSParser |
| SNMP | ✅ Inherited from IOSParser |
| Syslog | ✅ Inherited from IOSParser |
| Banners | ✅ Inherited from IOSParser |
| Line configs (con/vty) | ✅ Inherited from IOSParser |
| QoS (class-map/policy-map) | ✅ Inherited from IOSParser |
| NAT | ✅ Inherited from IOSParser |
| Crypto/IPsec | ✅ Inherited from IOSParser |
| BFD | ✅ Inherited from IOSParser |
| IP SLA | ✅ Inherited from IOSParser |
| EEM Applets | ✅ Inherited from IOSParser |
| Object Tracking | ✅ Inherited from IOSParser |
| Multicast (PIM/IGMP) | ✅ Inherited from IOSParser |
| Static Routes | ✅ Inherited from IOSParser |
| ACLs | ✅ Inherited from IOSParser |

See [IOS_PARSER_SUPPORT.md](IOS_PARSER_SUPPORT.md) for full syntax and attribute details.

---

## Overridden Methods Summary

| Method | Reason for Override |
|--------|---------------------|
| `parse_vrfs()` | Handles `vrf context NAME`, nested address-family RTs |
| `_extract_interface_vrf()` | Handles `vrf member NAME` |
| `parse_interfaces()` | CIDR notation + `ip router ospf` for OSPF membership |
| `_parse_bgp_peer_groups()` | Handles `template peer NAME` blocks |
| `_parse_bgp_vrf_instances()` | Handles `vrf NAME` blocks under router bgp |

---

## Parser Limitations

1. **NX-OS Fabric features** — VPC, VXLAN/EVPN, FabricPath not parsed
2. **IPv6 routing** — Limited IPv6 routing protocol coverage
3. **NX-OS-specific features** — Port profiles, role-based access control not parsed

---

## Testing and Validation

**Sample Configuration:** `samples/nxos.txt`

**Validated Counts:**
```
✅ Hostname: R1-NXOS
✅ Interfaces: 14 parsed
✅ VRFs: 3 parsed
✅ BGP: 2 instances (global + VRF)
✅ OSPF: 1 process
✅ Route-maps: 13 parsed
✅ Prefix-lists: 4 parsed
```

---

## Quick Reference

```python
from confgraph.parsers.nxos_parser import NXOSParser
from confgraph.models.base import OSType

parser = NXOSParser(config_text)
parsed = parser.parse()
# os_type = OSType.NXOS  # "nxos"
```

```bash
uv run python test_nxos_parser.py
```

---

**Last Updated:** 2026-03-28
**Parser Version:** 1.1.0
