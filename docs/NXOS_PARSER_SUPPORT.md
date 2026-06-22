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

### 9. VXLAN Configuration

**Syntax:**
```
vlan <id>
  vn-segment <vni-id>

interface nve1
  source-interface loopback0
  host-reachability protocol bgp
  member vni <l2-vni>
    mcast-group <address>
    suppress-arp
  member vni <l3-vni> associate-vrf
```

**Supported Attributes:**

- VNI-to-VLAN mapping via `vn-segment` under VLAN blocks
- All NVE interfaces (not just first)
- Source interface
- Host reachability protocol
- Per-VNI multicast group
- Per-VNI ARP suppression
- L3 VNI (`associate-vrf`)

**Parsing Status:** ✅ Overridden — `parse_vxlan()` handles NVE interfaces and `vn-segment` VLAN mappings

---

### 10. VPC Configuration

**Syntax:**
```
vpc domain <id>
  role priority <value>
  system-priority <value>
  peer-keepalive destination <ip> source <ip> vrf <vrf>
  delay restore <seconds>
  auto-recovery

interface port-channel<N>
  vpc peer-link

interface port-channel<M>
  vpc <vpc-id>
```

**Supported Attributes:**

- VPC domain ID, role priority, system priority
- Peer-keepalive destination, source, and VRF
- Delay restore, auto-recovery
- Per-interface VPC membership (parsed via interface parser)

**Parsing Status:** ✅ Overridden — `parse_vpc()` handles `vpc domain` block; per-interface `vpc N` membership parsed in `parse_interfaces()`

---

### 11. MPLS/LDP Configuration

**Syntax:**
```
mpls ldp configuration
  router-id <interface>
  graceful-restart
  session protection
  password required
```

**Supported Attributes:**

- Router-ID interface
- Graceful restart
- Session protection
- Password enforcement

**Parsing Status:** ✅ Overridden — `parse_mpls()` handles `mpls ldp configuration` block

---

### 12. Extended Protocol Support

| Protocol | Parsing Status | NX-OS Notes |
| -------- | -------------- | ----------- |
| NTP | ✅ Overridden | Handles `use-vrf` keyword, `ntp source-interface` |
| Syslog | ✅ Overridden | Handles `logging server` with `use-vrf`, per-server severity, `logging off` / `no logging on` |
| LLDP | ✅ Overridden | NX-OS uses `feature lldp` to enable; defaults to disabled |
| CDP | ✅ Overridden | NX-OS uses `feature cdp` to enable; defaults to disabled |
| DNS | ✅ Overridden | Scans `vrf context` blocks for per-VRF name-servers |
| AAA | ✅ Overridden | Parses `aaa group server tacacs+/radius NAME` child `server` members |
| Static Routes | ✅ Overridden | Parses routes inside `vrf context` blocks |
| ACLs | ✅ Inherited | NX-OS keyword-less `ip access-list NAME` form accepted by IOS parser |
| SNMP | ✅ Inherited from IOSParser | |
| Banners | ✅ Inherited from IOSParser | |
| Line configs (con/vty) | ✅ Inherited from IOSParser | |
| QoS (class-map/policy-map) | ✅ Inherited from IOSParser | |
| NAT | ✅ Inherited from IOSParser | |
| Crypto/IPsec | ✅ Inherited from IOSParser | |
| BFD | ✅ Inherited from IOSParser | |
| IP SLA | ✅ Inherited from IOSParser | |
| EEM Applets | ✅ Inherited from IOSParser | |
| Object Tracking | ✅ Inherited from IOSParser | |
| Multicast (PIM/IGMP) | ✅ Inherited from IOSParser | |

See [IOS_PARSER_SUPPORT.md](IOS_PARSER_SUPPORT.md) for full syntax and attribute details on inherited protocols.

---

### 13. Deletion Commands

NX-OS inherits all IOS tombstone types and adds the following NX-OS-specific tombstones:

| Command | Tombstone Emitted |
|---------|-------------------|
| `no member vni <id>` | `field:vxlan:vni:<id>` |
| `no peer-keepalive` | `field:vpc:peer_keepalive_*` |

**Parsing Status:** ✅ Overridden — `parse_deletion_commands()` emits NX-OS-specific tombstones in addition to inherited IOS tombstones

---

## Overridden Methods Summary

| Method | Reason for Override |
|--------|---------------------|
| `parse_vrfs()` | Handles `vrf context NAME`, nested address-family RTs |
| `_extract_interface_vrf()` | Handles `vrf member NAME` |
| `parse_interfaces()` | CIDR notation, `ip router ospf`, VPC membership |
| `_parse_bgp_peer_groups()` | Handles `template peer NAME` blocks |
| `_parse_bgp_neighbors()` | Handles nested neighbor blocks + `inherit peer NAME` |
| `_parse_bgp_vrf_instances()` | Handles `vrf NAME` blocks under router bgp |
| `parse_bgp()` | Peer-group attribute inheritance after parse |
| `parse_ospf()` | Extracts VRF from `router ospf N vrf NAME` header |
| `parse_static_routes()` | Parses routes inside `vrf context` blocks |
| `parse_ntp()` | Handles `use-vrf`, `ntp source-interface` |
| `parse_syslog()` | Handles `logging server` with `use-vrf`, `logging off` |
| `parse_lldp()` | `feature lldp` as enable signal (NX-OS defaults disabled) |
| `parse_cdp()` | `feature cdp` as enable signal (NX-OS defaults disabled) |
| `parse_dns()` | Scans `vrf context` blocks for per-VRF DNS |
| `parse_aaa()` | Parses `aaa group server` child `server` members |
| `parse_vxlan()` | All NVE interfaces, `vn-segment`, mcast-group, suppress-arp |
| `parse_vpc()` | `vpc domain` block + peer-link detection |
| `parse_mpls()` | `mpls ldp configuration` block |
| `parse_deletion_commands()` | NX-OS-specific tombstones (VNI, VPC) |

---

## Parser Limitations

1. **FabricPath** — Not parsed
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

**Last Updated:** 2026-06-22
