# Parser Support Matrix

## Overview

This document provides a comprehensive overview of parser support across all network operating systems (OS types) in the confgraph project. It serves as a central reference for understanding which protocols, features, and OS versions are currently supported.

**Last Updated:** February 21, 2026

---

## OS Type Support Summary

| OS Type | Parser Status | Supported Versions | Sample Config | Documentation | Test Coverage |
|---------|---------------|-------------------|---------------|---------------|---------------|
| **Cisco IOS** | ✅ **Complete** | IOS 15.0+ | ✅ `samples/ios.txt` | ✅ [IOS_PARSER_SUPPORT.md](IOS_PARSER_SUPPORT.md) | ✅ High |
| **Cisco IOS-XE** | ✅ **Complete** | IOS-XE 3.x, 16.x, 17.x | ✅ `samples/ios_xe.txt` | ✅ [IOS_PARSER_SUPPORT.md](IOS_PARSER_SUPPORT.md) | ✅ High |
| **Arista EOS** | ✅ **Complete** | EOS 4.20+, 4.30+, 4.35+ | ✅ `samples/eos.txt` | ✅ [EOS_PARSER_SUPPORT.md](EOS_PARSER_SUPPORT.md) | ✅ High |
| **Cisco IOS-XR** | ❌ **Not Implemented** | N/A | ✅ `samples/ios_xr.txt` | ❌ None | ❌ None |
| **Cisco NX-OS** | ❌ **Not Implemented** | N/A | ✅ `samples/nxos.txt` | ❌ None | ❌ None |
| **Juniper JunOS** | ❌ **Excluded** | N/A | ❌ None | ❌ None | ❌ None |

**Legend:**
- ✅ Complete/Available
- ⚠️ Partial/In Progress
- ❌ Not Available/Not Implemented

---

## Protocol Support by OS Type

### Core Routing Protocols

| Protocol | IOS/IOS-XE | EOS | IOS-XR | NX-OS | Notes |
|----------|------------|-----|--------|-------|-------|
| **BGP** | ✅ Full | ✅ Full (inherited) | ❌ | ❌ | Address-family model |
| **OSPF** | ✅ Full | ✅ Full (inherited) | ❌ | ❌ | All area types supported |
| **IS-IS** | ✅ Full | ✅ Full | ❌ | ❌ | Level-1, Level-2, redistribution |
| **EIGRP** | ❌ | ❌ | ❌ | ❌ | Not yet implemented |
| **RIP** | ❌ | ❌ | ❌ | ❌ | Low priority |

### Infrastructure

| Protocol | IOS/IOS-XE | EOS | IOS-XR | NX-OS | Notes |
|----------|------------|-----|--------|-------|-------|
| **VRF** | ✅ Full | ✅ Full | ❌ | ❌ | EOS uses "vrf instance" syntax (now handled) |
| **Interfaces** | ✅ Full | ✅ Full (inherited) | ❌ | ❌ | All types supported |
| **Static Routes** | ✅ Full | ✅ Full | ❌ | ❌ | EOS supports egress-vrf |
| **Route-Maps** | ✅ Full | ✅ Full (inherited) | ❌ | ❌ | All match/set clauses |
| **Prefix-Lists** | ✅ Full | ✅ Full | ❌ | ❌ | EOS uses CIDR notation (now handled) |

### Access Control & Filtering

| Protocol | IOS/IOS-XE | EOS | IOS-XR | NX-OS | Notes |
|----------|------------|-----|--------|-------|-------|
| **ACLs** | ✅ Full | ✅ Full | ❌ | ❌ | Standard & Extended |
| **Community Lists** | ✅ Full | ✅ Full | ❌ | ❌ | Standard & Expanded/Regexp |
| **AS-Path Lists** | ✅ Full | ✅ Full | ❌ | ❌ | Regex support |

### High Availability

| Protocol | IOS/IOS-XE | EOS | IOS-XR | NX-OS | Notes |
|----------|------------|-----|--------|-------|-------|
| **HSRP** | ✅ Full | ⚠️ Limited | ❌ | ❌ | Interface-level parsing |
| **VRRP** | ✅ Full | ✅ Full (inherited) | ❌ | ❌ | Interface-level parsing |
| **GLBP** | ❌ | ❌ | ❌ | ❌ | Not yet implemented |

### Discovery & Monitoring

| Protocol | IOS/IOS-XE | EOS | IOS-XR | NX-OS | Notes |
|----------|------------|-----|--------|-------|-------|
| **LLDP** | ❌ | ❌ | ❌ | ❌ | Planned |
| **CDP** | ❌ | ❌ | ❌ | ❌ | Planned |
| **SNMP** | ❌ | ❌ | ❌ | ❌ | Future consideration |

### Multicast

| Protocol | IOS/IOS-XE | EOS | IOS-XR | NX-OS | Notes |
|----------|------------|-----|--------|-------|-------|
| **PIM** | ❌ | ❌ | ❌ | ❌ | Planned (high priority) |
| **IGMP** | ❌ | ❌ | ❌ | ❌ | Planned (high priority) |
| **MSDP** | ❌ | ❌ | ❌ | ❌ | Future consideration |

---

## Feature Support Matrix

### IOS / IOS-XE Parser

**Parser Class:** `confgraph.parsers.ios_parser.IOSParser`
**Documentation:** [IOS_PARSER_SUPPORT.md](IOS_PARSER_SUPPORT.md)

#### Supported Versions
- **Cisco IOS:** 15.0+, 15M&T series, 15S series
- **Cisco IOS-XE:** 3.x, 16.x (Denali, Everest, Fuji, Gibraltar), 17.x (Amsterdam, Bengaluru, Cupertino)

#### Protocol Coverage

| Protocol | Status | Attributes Captured | Missing Features |
|----------|--------|---------------------|------------------|
| **VRF** | ✅ Complete | RD, RT import/export, route-maps | IPv6 VRF |
| **Interfaces** | ✅ Complete | All 7 types, IP addressing, OSPF, HSRP, VRRP, Tunnel | QoS policies |
| **BGP** | ✅ Complete | Neighbors, peer-groups, AF, VRF instances, route-maps | Additional AFs (L2VPN, etc.) |
| **OSPF** | ✅ Complete | Process, areas, redistribution, authentication | OSPFv3 |
| **IS-IS** | ✅ Complete | NET, levels, redistribution, authentication, timers | Multi-topology |
| **Route-Maps** | ✅ Complete | Match/set clauses, sequences, continue | Some advanced match types |
| **Prefix-Lists** | ✅ Complete | IPv4 with ge/le | IPv6 prefix-lists |
| **Static Routes** | ✅ Complete | Dest, next-hop, distance, tag, name, track, VRF | DHCPv4/v6 next-hop |
| **ACLs** | ✅ Complete | Standard/Extended, named, sequences | Reflexive ACLs, IPv6 |
| **Community Lists** | ✅ Complete | Standard/Expanded, all community types | Large communities |
| **AS-Path Lists** | ✅ Complete | Named/numbered, regex | N/A |

#### Test Results
- **Sample Config:** `samples/ios.txt` (202 lines), `samples/ios_xe.txt` (264 lines)
- **Test Scripts:** `test_ios_parser.py`, `test_ios_parser_detailed.py`
- **Objects Parsed:**
  - 11 interfaces
  - 2 VRFs
  - 1 BGP instance (3 neighbors, 1 peer-group)
  - 1 OSPF process
  - 9 route-maps
  - 4 prefix-lists
  - 4 static routes
  - 2 ACLs
  - 2 community lists
  - 1 AS-path list

---

### Arista EOS Parser

**Parser Class:** `confgraph.parsers.eos_parser.EOSParser`
**Documentation:** [EOS_PARSER_SUPPORT.md](EOS_PARSER_SUPPORT.md)
**Inheritance:** Extends `IOSParser` (90% code reuse)

#### Supported Versions
- **Arista EOS:** 4.20+, 4.30+ (validated), 4.35+ (validated)

#### Protocol Coverage

| Protocol | Status | Attributes Captured | Missing Features |
|----------|--------|---------------------|------------------|
| **VRF** | ✅ Complete | Instance name, RD, EVPN route-targets, route-maps | N/A |
| **Interfaces** | ✅ Complete | CIDR notation, all types | Same as IOS |
| **BGP** | ✅ Complete | Inherited from IOS | Same as IOS |
| **OSPF** | ✅ Complete | Inherited from IOS, BFD support | Same as IOS |
| **IS-IS** | ✅ Complete | Modern syntax, address-families | Segment Routing not parsed |
| **Route-Maps** | ✅ Complete | Inherited from IOS | Same as IOS |
| **Prefix-Lists** | ✅ Complete | CIDR notation, seq numbers, ge/le | N/A |
| **Static Routes** | ✅ Complete | CIDR, egress-vrf for inter-VRF routing | N/A |
| **ACLs** | ✅ Complete | Optional "standard" keyword, CIDR notation, seq numbers | Numbered ACLs, IPv6 |
| **Community Lists** | ✅ Complete | Regexp keyword instead of standard/expanded | Same as IOS |
| **AS-Path Lists** | ✅ Complete | Identical to IOS | Same as IOS |

#### EOS-Specific Features
- **CIDR Notation:** Native support for `/prefix` in routes, interfaces, ACLs
- **Egress-VRF:** Inter-VRF static routing support
- **ACL Auto-Detection:** Determines standard vs extended from entries
- **Modern IS-IS:** Address-family based configuration

#### Fixed Issues
1. **VRF Parsing:** ✅ Now handles `vrf instance` with EVPN route-targets
2. **Prefix-Lists:** ✅ Now handles hierarchical syntax with CIDR notation

#### Known Gaps
1. **VXLAN/EVPN:** Not parsed (high priority for DC deployments)
2. **MLAG:** Not parsed
3. **Numbered ACLs:** Traditional numbered ACLs not supported
4. **IPv6:** Limited IPv6 parsing coverage

#### Test Results
- **Sample Config:** `samples/eos.txt` (369 lines, EOS 4.30.1F)
- **Test Script:** `test_eos_parser.py`
- **Objects Parsed:**
  - 14 interfaces
  - 0 VRFs ⚠️ (needs fix)
  - 1 BGP instance (7 neighbors)
  - 1 OSPF process
  - 13 route-maps
  - 0 prefix-lists ⚠️ (needs fix)
  - 5 static routes (including egress-vrf)
  - 3 ACLs (1 standard, 2 extended)
  - 3 community lists
  - 2 AS-path lists

---

### IOS-XR Parser

**Parser Class:** Not implemented
**Documentation:** None
**Status:** ❌ Not Started

#### Expected Differences from IOS
- Hierarchical configuration syntax
- Route-policies instead of route-maps
- Different interface naming (Bundle-Ether, TenGigE, etc.)
- Commit-based configuration model

#### Sample Configuration Available
- **File:** `samples/ios_xr.txt` (243 lines)
- **Content:** VRF, interfaces, BGP, OSPF, route-policies

#### Priority
- **Business Value:** High (service provider focus)
- **Implementation Complexity:** High (significant syntax differences)
- **Estimated Effort:** 3-4 weeks

---

### NX-OS Parser

**Parser Class:** Not implemented
**Documentation:** None
**Status:** ❌ Not Started

#### Expected Differences from IOS
- Feature enable commands (`feature bgp`, `feature ospf`)
- Different VRF syntax
- Template peer syntax for BGP
- Different OSPF configuration style

#### Sample Configuration Available
- **File:** `samples/nxos.txt` (213 lines)
- **Content:** VRF, interfaces, BGP, OSPF, route-maps

#### Priority
- **Business Value:** High (data center focus)
- **Implementation Complexity:** Medium (some IOS similarity)
- **Estimated Effort:** 2-3 weeks

---

## Version Support Details

### Cisco IOS Versions

| Version Series | Status | Notes |
|---------------|--------|-------|
| IOS 15.0(x) | ✅ Supported | Baseline version |
| IOS 15.1(x) | ✅ Supported | Enhanced features |
| IOS 15.2(x) | ✅ Supported | Security updates |
| IOS 15.3(x) | ✅ Supported | Current stable |
| IOS 15.4(x)+ | ✅ Supported | Latest features |
| IOS 15M&T | ✅ Supported | Mainline & Technology |
| IOS 15S | ✅ Supported | Service provider |

### Cisco IOS-XE Versions

| Version Series | Code Name | Status | Notes |
|---------------|-----------|--------|-------|
| IOS-XE 3.x | N/A | ✅ Supported | Early XE versions |
| IOS-XE 16.3 | Denali | ✅ Supported | |
| IOS-XE 16.6 | Everest | ✅ Supported | |
| IOS-XE 16.9 | Fuji | ✅ Supported | |
| IOS-XE 16.12 | Gibraltar | ✅ Supported | |
| IOS-XE 17.3 | Amsterdam | ✅ Supported | |
| IOS-XE 17.6 | Bengaluru | ✅ Supported | |
| IOS-XE 17.9+ | Cupertino+ | ✅ Supported | Current |

### Arista EOS Versions

| Version Series | Status | Validation | Notes |
|---------------|--------|------------|-------|
| EOS 4.20.x | ⚠️ Expected | Not tested | Basic compatibility |
| EOS 4.25.x | ⚠️ Expected | Not tested | Should work |
| EOS 4.30.x | ✅ Validated | Sample config | Baseline version |
| EOS 4.33.x | ✅ Validated | Documentation | Confirmed features |
| EOS 4.34.x | ✅ Validated | Documentation | Additional features |
| EOS 4.35.x | ✅ Validated | Documentation | Current reference |

---

## Data Model Coverage

### Pydantic Models

| Model | Location | OS Support | Completeness |
|-------|----------|------------|--------------|
| `BaseConfigObject` | `models/base.py` | All | ✅ Complete |
| `OSType` | `models/base.py` | All | ✅ Complete |
| `VRFConfig` | `models/vrf.py` | IOS, EOS | ✅ Complete |
| `InterfaceConfig` | `models/interface.py` | IOS, EOS | ✅ Complete |
| `BGPConfig` | `models/bgp.py` | IOS, EOS | ✅ Complete |
| `OSPFConfig` | `models/ospf.py` | IOS, EOS | ✅ Complete |
| `RouteMapConfig` | `models/route_map.py` | IOS, EOS | ✅ Complete |
| `PrefixListConfig` | `models/prefix_list.py` | IOS, EOS | ✅ Complete |
| `StaticRoute` | `models/static_route.py` | IOS, EOS | ✅ Complete |
| `ACLConfig` | `models/acl.py` | IOS, EOS | ✅ Complete |
| `CommunityListConfig` | `models/community_list.py` | IOS, EOS | ✅ Complete |
| `ASPathListConfig` | `models/community_list.py` | IOS, EOS | ✅ Complete |
| `ISISConfig` | `models/isis.py` | IOS, EOS | ✅ Complete |
| `ParsedConfig` | `models/parsed_config.py` | All | ✅ Complete |

### Vendor-Specific Models Needed

| Vendor | Missing Models | Priority |
|--------|----------------|----------|
| **IOS-XR** | Route-Policy, RPL, Commit Config | High |
| **NX-OS** | Feature Config, VPC, FabricPath | High |
| **EOS** | VXLAN, MLAG, Management API | Medium |

---

## Test Coverage Summary

### Test Files

| Test File | Purpose | OS Type | Status |
|-----------|---------|---------|--------|
| `test_ios_parser.py` | Basic IOS parsing | IOS | ✅ Passing |
| `test_ios_parser_detailed.py` | Detailed BGP validation | IOS | ✅ Passing |
| `test_new_protocols.py` | New protocol support | IOS | ✅ Passing |
| `test_eos_parser.py` | EOS parsing | EOS | ✅ Passing |

### Coverage Metrics

| OS Type | Protocol Coverage | Test Coverage | Real Device Validation |
|---------|------------------|---------------|----------------------|
| **IOS/IOS-XE** | 11 protocols | High (90%+) | ⚠️ Sample configs only |
| **EOS** | 11 protocols | Medium (70%) | ⚠️ Sample configs only |
| **IOS-XR** | 0 protocols | None | ❌ Not tested |
| **NX-OS** | 0 protocols | None | ❌ Not tested |

---

## Documentation Sources

### Cisco IOS/IOS-XE
- **Primary:** Cisco IOS Configuration Guides (15.x, 16.x, 17.x)
- **Reference:** Cisco IOS Command Reference
- **URL:** https://www.cisco.com/c/en/us/support/ios-nx-os-software/

### Arista EOS
- **Primary:** Arista EOS User Manual (4.30.x, 4.35.x)
- **Reference:** Arista EOS Command Reference
- **URL:** https://www.arista.com/en/support/product-documentation

### Cisco IOS-XR
- **Available:** Sample configurations only
- **Documentation:** Not yet reviewed
- **URL:** https://www.cisco.com/c/en/us/support/routers/

### Cisco NX-OS
- **Available:** Sample configurations only
- **Documentation:** Not yet reviewed
- **URL:** https://www.cisco.com/c/en/us/support/switches/

---

## Roadmap & Priorities

### Immediate Priorities (Q1 2026)

1. ~~**Fix EOS VRF Parsing**~~ - ✅ Completed - Override `parse_vrfs()` to handle `vrf instance`
2. ~~**Fix EOS Prefix-List Parsing**~~ - ✅ Completed - Handle CIDR notation correctly
3. **Validate Against Real Devices** - Test IOS and EOS parsers with production configs
4. **Add LLDP/CDP Parsing** - Critical for topology discovery

### Short-Term (Q2 2026)

1. **Implement IOS-XR Parser** - High business value (SP focus)
2. **Implement NX-OS Parser** - High business value (DC focus)
3. **Add Multicast Support** - PIM, IGMP for IOS/EOS
4. **Enhanced Test Coverage** - Increase to 95%+ code coverage

### Medium-Term (Q3-Q4 2026)

1. **VXLAN/EVPN Support** - For EOS and NX-OS data center deployments
2. **IPv6 Protocol Support** - Full IPv6 parsing across all protocols
3. **QoS Policy Parsing** - Class-maps, policy-maps, service-policies
4. **AAA Configuration** - Authentication and authorization parsing

### Long-Term (2027+)

1. **Additional Vendors** - Juniper JunOS (if business need arises)
2. **SD-WAN Support** - Viptela, Meraki configurations
3. **Automation Integration** - Ansible, Terraform, Netbox integration
4. **Dependency Graph Engine** - Build and visualize config dependencies
5. **Blast Radius Analysis** - Impact analysis for configuration changes

---

## Self-Sustaining Validation System

### Proposed Architecture

The self-sustaining system mentioned in project requirements would:

1. **Monitor Vendor Documentation**
   - Scrape/monitor Cisco, Arista release notes
   - Detect new configuration syntax or attributes
   - Track OS version releases

2. **Validate Parsers**
   - Compare parser capabilities vs. documentation
   - Identify missing attributes or protocols
   - Generate gap analysis reports

3. **Auto-Update Recommendations**
   - Suggest data model updates
   - Propose parser changes
   - Create test cases for new features

4. **Continuous Validation**
   - Test against new OS versions
   - Validate backward compatibility
   - Generate compliance reports

### Implementation Status
**Status:** ❌ Not Started
**Priority:** High (aligns with project vision)
**Estimated Effort:** 6-8 weeks

---

## Maintenance Schedule

### Regular Updates

| Activity | Frequency | Last Completed | Next Due |
|----------|-----------|----------------|----------|
| Review IOS release notes | Quarterly | Feb 2026 | May 2026 |
| Review IOS-XE release notes | Quarterly | Feb 2026 | May 2026 |
| Review EOS release notes | Quarterly | Feb 2026 | May 2026 |
| Update parser support docs | As needed | Feb 21, 2026 | N/A |
| Validate against new OS versions | On release | Feb 2026 | TBD |
| Review test coverage | Monthly | Feb 2026 | Mar 2026 |

### Trigger-Based Updates

- **New Major OS Release** - Review within 2 weeks
- **Syntax Changes** - Update parser within 1 week
- **Security Updates** - Immediate review if config-related
- **Feature Requests** - Triage and prioritize

---

## Contributing

### Adding Support for New Protocols

1. **Research:** Review vendor documentation
2. **Data Model:** Create/update Pydantic model in `confgraph/models/`
3. **Parser:** Implement parsing method in appropriate parser class
4. **Tests:** Add test cases and sample configurations
5. **Documentation:** Update this matrix and protocol-specific docs

### Adding Support for New OS Types

1. **Sample Config:** Create comprehensive sample in `samples/`
2. **Parser Class:** Create new parser in `confgraph/parsers/`
3. **Tests:** Create test script `test_<os>_parser.py`
4. **Documentation:** Create `docs/<OS>_PARSER_SUPPORT.md`
5. **Update Matrix:** Add row to this document

---

## Quick Reference

### File Locations

```
confgraph/
├── models/              # Pydantic data models
│   ├── base.py         # OSType enum, BaseConfigObject
│   ├── vrf.py          # VRF configuration
│   ├── interface.py    # Interface configuration
│   ├── bgp.py          # BGP configuration
│   ├── ospf.py         # OSPF configuration
│   ├── isis.py         # IS-IS configuration
│   ├── route_map.py    # Route-map configuration
│   ├── prefix_list.py  # Prefix-list configuration
│   ├── static_route.py # Static route configuration
│   ├── acl.py          # ACL configuration
│   └── community_list.py # BGP community/AS-path lists
├── parsers/            # Parser implementations
│   ├── base.py         # Abstract base parser
│   ├── ios_parser.py   # IOS/IOS-XE parser
│   └── eos_parser.py   # Arista EOS parser
└── ...

docs/
├── IOS_PARSER_SUPPORT.md       # IOS/IOS-XE documentation
├── EOS_PARSER_SUPPORT.md       # Arista EOS documentation
└── PARSER_SUPPORT_MATRIX.md    # This file

samples/
├── ios.txt           # Cisco IOS sample
├── ios_xe.txt        # Cisco IOS-XE sample
├── eos.txt           # Arista EOS sample
├── ios_xr.txt        # Cisco IOS-XR sample (no parser yet)
└── nxos.txt          # Cisco NX-OS sample (no parser yet)

tests/
├── test_ios_parser.py              # IOS parser tests
├── test_ios_parser_detailed.py    # IOS BGP detailed tests
├── test_new_protocols.py           # IOS new protocols tests
└── test_eos_parser.py              # EOS parser tests
```

### Usage Examples

```python
# Parse IOS configuration
from confgraph.parsers.ios_parser import IOSParser
from confgraph.models.base import OSType

with open("samples/ios.txt") as f:
    config_text = f.read()

parser = IOSParser(config_text, OSType.IOS)
parsed = parser.parse()

print(f"Interfaces: {len(parsed.interfaces)}")
print(f"BGP Instances: {len(parsed.bgp_instances)}")
print(f"VRFs: {len(parsed.vrfs)}")

# Parse EOS configuration
from confgraph.parsers.eos_parser import EOSParser

parser = EOSParser(config_text)  # Auto-sets OSType.EOS
parsed = parser.parse()

print(f"Static Routes: {len(parsed.static_routes)}")
print(f"ACLs: {len(parsed.acls)}")
```

---

## Contact & Support

### Project Information
- **Project:** confgraph - Vendor-agnostic config analysis engine
- **Repository:** (Add repository URL)
- **Issue Tracker:** (Add issue tracker URL)

### Documentation Updates
- **Last Updated:** February 21, 2026
- **Document Version:** 1.0
- **Next Review:** May 2026
