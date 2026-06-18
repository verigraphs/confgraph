# Parser Support Matrix

## Overview

Comprehensive overview of parser support across all network operating systems in confgraph. Each parser inherits from either `BaseParser` (abstract base) or `IOSParser` (reference implementation). EOS, IOS-XR, and NX-OS extend IOSParser and inherit methods where syntax is compatible.

**Last Updated:** June 14, 2026

---

## OS Type Support Summary

| OS Type | Parser Class | Inherits From | Override Count | Status |
|---------|-------------|---------------|----------------|--------|
| **Cisco IOS / IOS-XE** | `IOSParser` | `BaseParser` | 39 methods | ✅ Reference implementation |
| **Arista EOS** | `EOSParser` | `IOSParser` | 11 overrides + 28 inherited | ✅ Complete |
| **Cisco IOS-XR** | `IOSXRParser` | `IOSParser` | 14 overrides + 25 inherited | ✅ Complete |
| **Cisco NX-OS** | `NXOSParser` | `IOSParser` | 10 overrides + 31 inherited | ✅ Complete |
| **Juniper JunOS** | `JunOSParser` | `BaseParser` | 13 methods | ✅ Core protocols |
| **Palo Alto PAN-OS** | `PANOSParser` | `BaseParser` | 9 methods | ✅ Security-focused |

**Legend for protocol tables below:**
- ✅ = Native override for this platform's syntax
- ✅ (inherited) = Uses IOSParser implementation (works for platforms with compatible flat syntax)
- ❌ = Not implemented (returns empty)

---

## Protocol Support by OS Type

### Core Routing Protocols

| Protocol | IOS/IOS-XE | EOS | IOS-XR | NX-OS | JunOS | PAN-OS |
|----------|------------|-----|--------|-------|-------|--------|
| **BGP** | ✅ | ✅ (inherited) | ✅ (inherited) | ✅ | ✅ | ✅ |
| **OSPF** | ✅ | ✅ (inherited) | ✅ | ✅ | ✅ | ✅ |
| **IS-IS** | ✅ | ✅ | ✅ | ✅ (inherited) | ❌ | ❌ |
| **EIGRP** | ✅ | ✅ (inherited) | ✅ (inherited) | ✅ (inherited) | ❌ | ❌ |
| **RIP** | ✅ | ✅ (inherited) | ✅ (inherited) | ✅ (inherited) | ❌ | ❌ |
| **Static Routes** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

Notes:
- NX-OS BGP override handles `template peer` / `inherit peer` syntax
- IOS-XR OSPF override handles hierarchical `router ospf` → `area` → `interface` nesting
- EOS IS-IS override handles address-family based configuration
- IOS-XR IS-IS override handles per-interface config nested under `router isis`

### Infrastructure

| Protocol | IOS/IOS-XE | EOS | IOS-XR | NX-OS | JunOS | PAN-OS |
|----------|------------|-----|--------|-------|-------|--------|
| **VRF** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Interfaces** | ✅ | ✅ (inherited) | ✅ | ✅ | ✅ | ✅ |
| **Route-Maps** | ✅ | ✅ (inherited) | ✅ | ✅ (inherited) | ✅ | ❌ |
| **Prefix-Lists** | ✅ | ✅ | ✅ | ✅ (inherited) | ✅ | ❌ |

Notes:
- EOS VRF uses `vrf instance` syntax; IOS-XR uses `vrf NAME`; NX-OS uses `vrf context`
- IOS-XR route-maps override handles `route-policy` → `RouteMapConfig`
- IOS-XR prefix-lists override handles `prefix-set` syntax

### Access Control & Filtering

| Protocol | IOS/IOS-XE | EOS | IOS-XR | NX-OS | JunOS | PAN-OS |
|----------|------------|-----|--------|-------|-------|--------|
| **ACLs** | ✅ | ✅ | ✅ | ✅ (inherited) | ✅ | ✅ |
| **Community Lists** | ✅ | ✅ | ✅ | ✅ (inherited) | ✅ | ❌ |
| **AS-Path Lists** | ✅ | ✅ | ✅ | ✅ (inherited) | ✅ | ❌ |

Notes:
- IOS-XR community-lists override handles `community-set` / `extcommunity-set` syntax
- IOS-XR AS-path lists override handles `as-path-set` syntax
- EOS ACL override handles optional `standard` keyword and CIDR notation

### Data Center / Overlay

| Protocol | IOS/IOS-XE | EOS | IOS-XR | NX-OS | JunOS | PAN-OS |
|----------|------------|-----|--------|-------|-------|--------|
| **VXLAN/EVPN** | ❌ | ✅ | ❌ | ✅ | ❌ | ❌ |
| **VPC / MLAG** | ❌ | ✅ (MLAG) | ❌ | ✅ (VPC) | ❌ | ❌ |
| **VLANs** | ✅ | ✅ (inherited) | ✅ (inherited) | ✅ (inherited) | ❌ | ❌ |
| **VTP** | ✅ | ✅ (inherited) | ✅ (inherited) | ✅ (inherited) | ❌ | ❌ |
| **STP** | ✅ | ✅ (inherited) | ✅ (inherited) | ✅ (inherited) | ❌ | ❌ |

Notes:
- EOS VXLAN parsed from `interface Vxlan1` block (source-interface, VNI mappings, flood VTEPs)
- NX-OS VXLAN parsed from `interface nve1` block
- EOS MLAG (`mlag configuration`) maps to `VPCConfig` (domain-id is string, not int)
- NX-OS VPC parsed from `vpc domain` block + `vpc peer-link` on interfaces

### MPLS / Label Switching

| Protocol | IOS/IOS-XE | EOS | IOS-XR | NX-OS | JunOS | PAN-OS |
|----------|------------|-----|--------|-------|-------|--------|
| **MPLS/LDP** | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ |

Notes:
- IOS uses flat syntax (`mpls ldp router-id Loopback0 force`)
- EOS override handles hierarchical `mpls ldp` block with `router-id interface Loopback0`
- IOS-XR override handles hierarchical `mpls ldp` block with `router-id <IP>`
- NX-OS override handles `mpls ldp configuration` block
- Per-interface `mpls ip` parsed on IOS/EOS/NX-OS interface blocks; IOS-XR lists interfaces under `mpls ldp` block instead

### Multicast

| Protocol | IOS/IOS-XE | EOS | IOS-XR | NX-OS | JunOS | PAN-OS |
|----------|------------|-----|--------|-------|-------|--------|
| **PIM** | ✅ | ✅ (inherited) | ✅ | ✅ (inherited) | ❌ | ❌ |

Notes:
- IOS parses `ip pim rp-address`, `ip pim ssm`, `ip multicast-routing`, per-interface `ip pim sparse-mode`, MSDP peers
- IOS-XR multicast override handles hierarchical `router pim` and `router msdp` blocks
- EOS/NX-OS inherit IOS flat-syntax multicast parsing via `_BASE_KNOWN_PATTERNS`

### Management & Monitoring

| Protocol | IOS/IOS-XE | EOS | IOS-XR | NX-OS | JunOS | PAN-OS |
|----------|------------|-----|--------|-------|-------|--------|
| **NTP** | ✅ | ✅ (inherited) | ✅ | ✅ | ✅ | ❌ |
| **SNMP** | ✅ | ✅ (inherited) | ✅ (inherited) | ✅ (inherited) | ✅ | ❌ |
| **Syslog** | ✅ | ✅ (inherited) | ✅ (inherited) | ✅ | ✅ | ❌ |
| **BFD** | ✅ | ✅ | ✅ | ✅ (inherited) | ❌ | ❌ |
| **NetFlow** | ✅ | ✅ (inherited) | ✅ (inherited) | ✅ (inherited) | ❌ | ❌ |
| **LLDP** | ✅ | ✅ (inherited) | ✅ (inherited) | ✅ (inherited) | ❌ | ❌ |
| **CDP** | ✅ | ✅ (inherited) | ✅ (inherited) | ✅ (inherited) | ❌ | ❌ |

Notes:
- IOS-XR NTP override handles hierarchical `ntp` block
- NX-OS NTP override handles flat `ntp server` with `use-vrf` keyword
- NX-OS syslog override handles `logging server` with VRF and facility
- EOS BFD override handles EOS-specific `bfd` block syntax

### Security & AAA

| Protocol | IOS/IOS-XE | EOS | IOS-XR | NX-OS | JunOS | PAN-OS |
|----------|------------|-----|--------|-------|-------|--------|
| **AAA** | ✅ | ✅ (inherited) | ✅ (inherited) | ✅ (inherited) | ❌ | ❌ |
| **NAT** | ✅ | ✅ (inherited) | ✅ (inherited) | ✅ (inherited) | ❌ | ✅ |
| **Crypto/IPsec** | ✅ | ✅ (inherited) | ✅ (inherited) | ✅ (inherited) | ❌ | ✅ |
| **Security Zones** | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |

Notes:
- AAA parses authentication/authorization/accounting method-lists, TACACS+/RADIUS servers
- PAN-OS zones parsed from XML `vsys` → `zone` elements

### Services

| Protocol | IOS/IOS-XE | EOS | IOS-XR | NX-OS | JunOS | PAN-OS |
|----------|------------|-----|--------|-------|-------|--------|
| **DNS** | ✅ | ✅ (inherited) | ✅ (inherited) | ✅ (inherited) | ❌ | ❌ |
| **DHCP** | ✅ | ✅ (inherited) | ✅ (inherited) | ✅ (inherited) | ❌ | ❌ |

### High Availability (Interface-Level)

| Protocol | IOS/IOS-XE | EOS | IOS-XR | NX-OS | JunOS | PAN-OS |
|----------|------------|-----|--------|-------|-------|--------|
| **HSRP** | ✅ | ✅ (inherited) | ✅ (inherited) | ✅ (inherited) | ❌ | ❌ |
| **VRRP** | ✅ | ✅ (inherited) | ✅ (inherited) | ✅ (inherited) | ❌ | ❌ |
| **LACP** | ✅ | ✅ (inherited) | ✅ (inherited) | ✅ (inherited) | ❌ | ❌ |

Notes:
- HSRP/VRRP parsed as part of interface config (InterfaceConfig fields)
- LACP system-priority parsed globally; per-interface channel-group and min-links on InterfaceConfig

### Operational / Automation

| Protocol | IOS/IOS-XE | EOS | IOS-XR | NX-OS | JunOS | PAN-OS |
|----------|------------|-----|--------|-------|-------|--------|
| **IP SLA** | ✅ | ✅ (inherited) | ✅ (inherited) | ✅ (inherited) | ❌ | ❌ |
| **EEM** | ✅ | ✅ (inherited) | ✅ (inherited) | ✅ (inherited) | ❌ | ❌ |
| **Object Tracking** | ✅ | ✅ (inherited) | ✅ (inherited) | ✅ (inherited) | ❌ | ❌ |
| **Banners** | ✅ | ✅ (inherited) | ✅ (inherited) | ✅ (inherited) | ❌ | ❌ |
| **Line Config** | ✅ | ✅ (inherited) | ✅ (inherited) | ✅ (inherited) | ❌ | ❌ |

### QoS

| Protocol | IOS/IOS-XE | EOS | IOS-XR | NX-OS | JunOS | PAN-OS |
|----------|------------|-----|--------|-------|-------|--------|
| **Class-Maps** | ✅ | ✅ (inherited) | ✅ (inherited) | ✅ (inherited) | ❌ | ❌ |
| **Policy-Maps** | ✅ | ✅ (inherited) | ✅ (inherited) | ✅ (inherited) | ❌ | ❌ |

---

## Data Model Coverage

All models live in `confgraph/models/` and use Pydantic.

| Model | File | Used By |
|-------|------|---------|
| `BaseConfigObject` | `base.py` | All parsers |
| `OSType` | `base.py` | All parsers |
| `ParsedConfig` | `parsed_config.py` | All parsers (39 data fields) |
| `VRFConfig` | `vrf.py` | IOS, EOS, IOS-XR, NX-OS, JunOS, PAN-OS |
| `InterfaceConfig` | `interface.py` | All parsers |
| `BGPConfig` | `bgp.py` | IOS, EOS, IOS-XR, NX-OS, JunOS, PAN-OS |
| `OSPFConfig` | `ospf.py` | IOS, EOS, IOS-XR, NX-OS, JunOS, PAN-OS |
| `ISISConfig` | `isis.py` | IOS, EOS, IOS-XR, NX-OS |
| `RouteMapConfig` | `route_map.py` | IOS, EOS, IOS-XR, NX-OS, JunOS |
| `PrefixListConfig` | `prefix_list.py` | IOS, EOS, IOS-XR, NX-OS, JunOS |
| `StaticRoute` | `static_route.py` | IOS, EOS, IOS-XR, NX-OS, JunOS, PAN-OS |
| `ACLConfig` | `acl.py` | IOS, EOS, IOS-XR, NX-OS, JunOS, PAN-OS |
| `CommunityListConfig` | `community_list.py` | IOS, EOS, IOS-XR, NX-OS, JunOS |
| `ASPathListConfig` | `community_list.py` | IOS, EOS, IOS-XR, NX-OS, JunOS |
| `MulticastConfig` | `multicast.py` | IOS, EOS, IOS-XR, NX-OS |
| `MPLSConfig` | `mpls.py` | IOS, EOS, IOS-XR, NX-OS |
| `VXLANConfig` | `vxlan.py` | EOS, NX-OS |
| `VPCConfig` | `vpc.py` | EOS (MLAG), NX-OS (VPC) |
| `AAAConfig` | `aaa.py` | IOS, EOS, IOS-XR, NX-OS |
| `NTPConfig` | `ntp.py` | IOS, EOS, IOS-XR, NX-OS, JunOS |
| `SNMPConfig` | `snmp.py` | IOS, EOS, IOS-XR, NX-OS, JunOS |
| `SyslogConfig` | `syslog.py` | IOS, EOS, IOS-XR, NX-OS, JunOS |
| `BFDConfig` | `bfd.py` | IOS, EOS, IOS-XR, NX-OS |
| `DNSConfig` | `dns.py` | IOS, EOS, IOS-XR, NX-OS |
| `DHCPConfig` | `dhcp.py` | IOS, EOS, IOS-XR, NX-OS |
| `LLDPConfig` | `lldp.py` | IOS, EOS, IOS-XR, NX-OS |
| `CDPConfig` | `cdp.py` | IOS, EOS, IOS-XR, NX-OS |
| `STPConfig` | `stp.py` | IOS, EOS, IOS-XR, NX-OS |
| `VTPConfig` | `vlan.py` | IOS, EOS, IOS-XR, NX-OS |
| `VLANEntry` | `vlan.py` | IOS, EOS, IOS-XR, NX-OS |
| `NetFlowConfig` | `netflow.py` | IOS, EOS, IOS-XR, NX-OS |
| `NATConfig` | `nat.py` | IOS, EOS, IOS-XR, NX-OS, PAN-OS |
| `CryptoConfig` | `crypto.py` | IOS, EOS, IOS-XR, NX-OS, PAN-OS |
| `PANOSZoneConfig` | `panos_zone.py` | PAN-OS |
| `IPSLAOperation` | `ip_sla.py` | IOS, EOS, IOS-XR, NX-OS |
| `EEMApplet` | `eem.py` | IOS, EOS, IOS-XR, NX-OS |
| `ObjectTrack` | `object_tracking.py` | IOS, EOS, IOS-XR, NX-OS |

---

## Simulation Coverage (confgraph-entrp)

The simulation engine in `confgraph-entrp` provides service-level impact assessment for configuration changes. Not all parsed protocols have simulation support.

| Protocol | Simulation | Assessment Type |
|----------|-----------|-----------------|
| **BGP** | ✅ | Neighbor changes, AF changes, route-map impact |
| **OSPF** | ✅ | Area changes, adjacency loss, redistribution |
| **IS-IS** | ✅ | Adjacency loss, metric changes |
| **PIM/Multicast** | ✅ | RP reachability (IGP-based), PIM interface removal |
| **MPLS/LDP** | ✅ | Router-ID state, LDP peer reachability |
| **VXLAN** | ✅ | VTEP source-interface state, VTEP reachability |
| **VPC/MLAG** | ✅ | Peer-link state, keepalive reachability (VRF-aware) |
| **VTP** | ✅ | Cross-device VLAN propagation (server→client) |
| **LACP** | ✅ | Port-channel min-links → forced down cascade |
| **STP** | ✅ | Blocked port computation |
| **L2/VLAN** | ✅ | SVI state derivation from VLAN database |
| **NTP** | ✅ | Server changes, source-interface changes |
| **SNMP** | ✅ | Community/server changes |
| **Syslog** | ✅ | Server changes |
| **AAA** | ✅ | Method-list changes, TACACS/RADIUS server removal |
| **DNS** | ✅ | Server changes |
| **DHCP** | ✅ | Pool/relay changes |
| **BFD** | ✅ | Timer changes |
| **Interfaces** | ✅ | Shutdown detection, IP changes, causal chain |

---

## Test Coverage

| Test File | Purpose | Status |
|-----------|---------|--------|
| `test_ios_parser.py` | IOS core parsing | ✅ Passing |
| `test_ios_parser_detailed.py` | IOS BGP detailed validation | ✅ Passing |
| `test_new_protocols.py` | IOS extended protocol support | ✅ Passing |
| `test_eos_parser.py` | EOS parsing | ✅ Passing |
| `test_bgp_parser_e2e.py` | BGP end-to-end across platforms | ✅ Passing |
| `test_iface_bfd_parser.py` | Interface BFD parsing | ✅ Passing |
| `test_service_parsers.py` | NTP/SNMP/Syslog/BFD on IOS-XR, EOS, NX-OS | ✅ Passing |
| `test_interface_normalize.py` | Interface name normalization | ✅ Passing |
| `test_parser_mpls_vpc_gaps.py` | MPLS (IOS-XR, EOS, NX-OS) + EOS MLAG | ✅ Passing |

**Total: 196 tests passing** (confgraph repo)

---

## Architecture

### Parser Inheritance

```
BaseParser (ABC) ─── 40 parse_* methods defined
├── IOSParser ─────── 39 implemented (reference parser)
│   ├── EOSParser ─── 11 overrides (VRF, prefix-lists, ACLs, IS-IS, BFD, VXLAN, MPLS, MLAG, ...)
│   ├── IOSXRParser ─ 14 overrides (VRF, interfaces, OSPF, route-maps, prefix-lists, ACLs, IS-IS, multicast, MPLS, NTP, BFD, ...)
│   └── NXOSParser ── 10 overrides (VRF, interfaces, BGP, OSPF, static-routes, NTP, syslog, VXLAN, VPC, MPLS)
├── JunOSParser ───── 13 methods (core routing + management)
└── PANOSParser ───── 9 methods (routing + security/NAT/zones)
```

### File Locations

```
confgraph/
├── models/                    # Pydantic data models (37 model classes)
│   ├── base.py               # OSType enum, BaseConfigObject
│   ├── parsed_config.py      # ParsedConfig (39 data fields)
│   ├── bgp.py                # BGP (config, neighbor, peer-group, AF)
│   ├── ospf.py               # OSPF (config, area, redistribute)
│   ├── isis.py               # IS-IS (config, interface, redistribute)
│   ├── interface.py          # InterfaceConfig (all interface types)
│   ├── vrf.py                # VRF
│   ├── route_map.py          # Route-map / route-policy
│   ├── prefix_list.py        # Prefix-list / prefix-set
│   ├── static_route.py       # Static routes
│   ├── acl.py                # ACLs
│   ├── community_list.py     # Community + AS-path lists
│   ├── multicast.py          # PIM/MSDP/multicast
│   ├── mpls.py               # MPLS/LDP
│   ├── vxlan.py              # VXLAN/EVPN
│   ├── vpc.py                # VPC/MLAG
│   ├── vlan.py               # VTP + VLAN entries
│   ├── aaa.py                # AAA
│   ├── ntp.py                # NTP
│   ├── snmp.py               # SNMP
│   ├── syslog.py             # Syslog
│   ├── bfd.py                # BFD
│   ├── dns.py                # DNS
│   ├── dhcp.py               # DHCP
│   ├── lldp.py               # LLDP
│   ├── cdp.py                # CDP
│   ├── stp.py                # Spanning-tree
│   ├── netflow.py            # NetFlow
│   ├── nat.py                # NAT
│   ├── crypto.py             # Crypto/IPsec
│   ├── panos_zone.py         # PAN-OS security zones
│   ├── ip_sla.py             # IP SLA
│   ├── eem.py                # EEM applets
│   └── object_tracking.py    # Object tracking
├── parsers/                   # Parser implementations
│   ├── base.py               # Abstract BaseParser (40 methods)
│   ├── ios_parser.py         # IOS/IOS-XE (reference, ~5500 lines)
│   ├── eos_parser.py         # Arista EOS
│   ├── iosxr_parser.py       # Cisco IOS-XR
│   ├── nxos_parser.py        # Cisco NX-OS
│   ├── junos_parser.py       # Juniper JunOS
│   └── panos_parser.py       # Palo Alto PAN-OS
└── utils/
    └── interface.py           # Interface name normalization
```
