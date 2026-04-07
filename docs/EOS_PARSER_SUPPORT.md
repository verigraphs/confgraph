# Arista EOS Parser Support Documentation

## Overview

The Arista EOS parser (`confgraph.parsers.eos_parser.EOSParser`) provides comprehensive parsing support for Arista EOS network device configurations. The parser inherits from `IOSParser` since EOS uses IOS-style syntax for most configurations, with specific overrides for EOS-specific syntax variations.

## Supported Versions

### Validated Versions
- **EOS 4.30.1F** - Sample configuration validated
- **EOS 4.35.1F** - Documentation reference version
- **EOS 4.34.x** - Documentation validated
- **EOS 4.33.x** - Documentation validated

### Expected Compatibility
- **EOS 4.30.x+** - All features should work
- **EOS 4.20.x+** - Core features supported (BGP, OSPF, Interfaces)
- Earlier versions may have partial support depending on syntax changes

## Configuration Syntax Support

### 1. VRF Configuration

**Syntax:**
```
vrf instance <name>
   rd <rd-value>
   route-target import evpn <rt-value>
   route-target export evpn <rt-value>
```

**EOS-Specific Differences:**
- Uses `vrf instance` instead of IOS `vrf definition`
- Supports EVPN route-targets with `evpn` keyword
- CIDR notation not used in VRF context

**Supported Attributes:**
- VRF name
- Route distinguisher (RD)
- Route-target import/export (with EVPN support)
- Route-map import/export

**Parsing Status:** ✅ Overridden — `parse_vrfs()` handles `vrf instance` syntax and EVPN route-targets

**Documentation Source:** EOS 4.35.1F - VRF Configuration Guide

---

### 2. Interface Configuration

**Syntax:**
```
interface <type><number>
   description <text>
   ip address <address>/<prefix-length>
   vrf <vrf-name>
   ip ospf area <area-id>
```

**EOS-Specific Differences:**
- **CIDR Notation:** Uses `/prefix` instead of subnet mask (e.g., `10.1.1.1/30` vs `10.1.1.1 255.255.255.252`)
- Interface types: Ethernet, Port-Channel, Loopback, Vlan, Tunnel, Management
- Uses `vrf <name>` directly (no `ip vrf forwarding`)

**Supported Attributes:**
- Interface name and type
- Description
- IP address (IPv4/IPv6 with CIDR notation)
- VRF membership
- Administrative status (shutdown)
- OSPF attributes (area, cost, network type, priority, authentication)
- VRRP configuration
- Tunnel parameters

**Interface Types Supported:**
- Physical: Ethernet, Management
- Logical: Loopback, Vlan, Tunnel, Port-Channel

**Parsing Status:** ✅ Inherited from IOSParser with CIDR notation support

**Documentation Source:** EOS 4.35.1F - Interface Configuration Guide

---

### 3. BGP Configuration

**Syntax:**
```
router bgp <asn>
   router-id <router-id>
   neighbor <ip> remote-as <asn>
   neighbor <ip> peer group <name>
   !
   address-family ipv4
      neighbor <ip> activate
      network <prefix>/<length>
   !
   vrf <vrf-name>
      rd <rd-value>
      neighbor <ip> remote-as <asn>
```

**EOS-Specific Differences:**
- Similar to IOS-XE address-family syntax
- VRF BGP configured within `router bgp` block
- Supports modern BGP features (graceful-restart, route-reflector-client)

**Supported Attributes:**
- ASN, router-id
- Neighbors (iBGP/eBGP)
- Peer groups
- Address families (IPv4/IPv6)
- VRF instances
- Route-maps (in/out)
- Timers, authentication, route-reflector-client
- Maximum-paths, maximum-routes

**Parsing Status:** ✅ Inherited from IOSParser

**Documentation Source:** EOS 4.35.1F - Border Gateway Protocol (BGP)

---

### 4. OSPF Configuration

**Syntax:**
```
router ospf <process-id>
   router-id <router-id>
   passive-interface default
   no passive-interface <interface>
   area <area-id> range <prefix>/<length> cost <cost>
   area <area-id> nssa no-summary
   redistribute bgp route-map <name>
```

**EOS-Specific Differences:**
- Similar to IOS syntax
- Area ranges use CIDR notation
- Supports BFD (`bfd default`)
- Enhanced logging (`log-adjacency-changes detail`)

**Supported Attributes:**
- Process ID, router-id
- Areas (normal, stub, NSSA, totally-stub, totally-NSSA)
- Area ranges, authentication
- Passive interfaces
- Redistribution with route-maps
- BFD support
- Default information originate

**Parsing Status:** ✅ Inherited from IOSParser

**Documentation Source:** EOS 4.35.1F - OSPF Configuration Guide

---

### 5. Route-Maps

**Syntax:**
```
route-map <name> permit <sequence>
   description <text>
   match ip address prefix-list <name>
   set local-preference <value>
   set community <value> additive
```

**EOS-Specific Differences:**
- Identical to IOS syntax
- Full support for match/set clauses

**Supported Attributes:**
- Route-map name, action, sequence
- Description
- Match clauses: prefix-list, as-path, community, metric, tag
- Set clauses: local-preference, metric, community, as-path prepend, origin
- Continue statement

**Parsing Status:** ✅ Inherited from IOSParser

**Documentation Source:** EOS 4.35.1F - ACLs and Route Maps

---

### 6. Prefix-Lists

**Syntax:**
```
ip prefix-list <name>
   seq <number> permit <prefix>/<length> le <max-length>
   seq <number> deny <prefix>/<length> ge <min-length> le <max-length>
```

**EOS-Specific Differences:**
- Uses CIDR notation for prefixes
- Sequence numbers on all entries

**Supported Attributes:**
- Prefix-list name
- Sequence number
- Action (permit/deny)
- Prefix with CIDR notation
- ge/le modifiers

**Parsing Status:** ✅ Overridden — `parse_prefix_lists()` handles EOS hierarchical prefix-list syntax with CIDR notation

**Documentation Source:** EOS 4.35.1F - ACLs and Route Maps

---

### 7. Static Routes

**Syntax:**
```
ip route [vrf <vrf-name>] <prefix>/<length> [egress-vrf <vrf-name>] <next-hop> [<distance>] [tag <tag>] [name <name>]
```

**EOS-Specific Differences:**
- **CIDR Notation:** Mandatory use of `/prefix` instead of subnet mask
- **Inter-VRF Routing:** Supports `egress-vrf` keyword for routing between VRFs
- Optional parameters: distance, tag, name, track

**Supported Attributes:**
- Destination prefix (CIDR notation)
- Next-hop (IP address or interface)
- VRF (ingress VRF)
- Egress VRF (for inter-VRF routing)
- Administrative distance
- Tag
- Name/description
- Track object

**Example:**
```
ip route 0.0.0.0/0 10.100.1.1 name DEFAULT_TO_ISP
ip route vrf CUSTOMER_A 10.0.0.0/8 egress-vrf default 10.0.0.1
```

**Parsing Status:** ✅ EOS-specific implementation

**Documentation Source:** EOS 4.35.1F - IPv4 Static Inter-VRF Route

---

### 8. Access Control Lists (ACLs)

**Syntax:**
```
ip access-list [standard] <name>
   [<seq>] remark <text>
   [<seq>] permit <source> [log]
   [<seq>] deny ip <source> <destination> [log]
```

**EOS-Specific Differences:**
- **Optional "standard" keyword:** Both `ip access-list standard NAME` and `ip access-list NAME` are valid
- **Auto-detection:** ACL type auto-detected from entries if keyword omitted
- **CIDR Notation:** ACL entries can use CIDR notation
- **Sequence Numbers:** All entries have sequence numbers

**Supported Attributes:**
- ACL name
- ACL type (standard/extended)
- Sequence numbers
- Action (permit/deny/remark)
- Protocol (extended ACLs)
- Source/destination (IP, wildcard, or CIDR)
- Port operators (eq, range, gt, lt, neq)
- Flags (log, syn, ack, etc.)

**Example:**
```
ip access-list standard MGMT_HOSTS
   10 permit 192.168.10.0/24
   20 permit host 10.0.0.100

ip access-list ALLOW_WEB_TRAFFIC
   10 permit tcp any any eq 80
   20 permit tcp any any eq 443
```

**Parsing Status:** ✅ EOS-specific implementation with auto-detection

**Documentation Source:** EOS 4.35.1F - ACLs and Route Maps

---

### 9. BGP Community Lists

**Syntax:**
```
ip community-list [regexp] <name> permit|deny <communities>
```

**EOS-Specific Differences:**
- **No "standard/expanded" keywords:** Type determined by presence of `regexp` keyword
- Standard: `ip community-list NAME permit 65000:100`
- Expanded: `ip community-list regexp NAME permit _65[0-9]{3}:[0-9]+_`

**Supported Attributes:**
- Community-list name
- Type (standard/expanded based on regexp keyword)
- Action (permit/deny)
- Community values or regex

**Example:**
```
ip community-list ALLOWED_COMMUNITIES permit 65000:100
ip community-list regexp CUSTOMER_COMMUNITIES permit _65[0-9]{3}:[0-9]+_
```

**Parsing Status:** ✅ EOS-specific implementation

**Documentation Source:** EOS 4.35.1F - Border Gateway Protocol (BGP)

---

### 10. BGP AS-Path Access Lists

**Syntax:**
```
ip as-path access-list <name> permit|deny <regex>
```

**EOS-Specific Differences:**
- Identical to IOS syntax

**Supported Attributes:**
- AS-path list name (can be numeric or named)
- Action (permit/deny)
- Regular expression

**Example:**
```
ip as-path access-list ALLOW_OWN_AS permit ^65000_
ip as-path access-list BLOCK_PRIVATE_AS deny _64[5-9][0-9]{2}_
```

**Parsing Status:** ✅ EOS-specific implementation (identical to IOS)

**Documentation Source:** EOS 4.35.1F - Border Gateway Protocol (BGP)

---

### 11. IS-IS Configuration

**Syntax:**
```
router isis <instance-name>
   net <NET-address>
   is-type level-2
   address-family ipv4 unicast
      redistribute connected
```

**EOS-Specific Differences:**
- Modern IS-IS syntax with address-family support
- Instance-based (named IS-IS process)
- Supports Segment Routing (SR-MPLS)

**Supported Attributes:**
- Instance name/tag
- NET address
- IS-type (level-1, level-2, level-1-2)
- Metric style
- Passive interfaces
- Redistribution
- Authentication
- Timers (max-lsp-lifetime, lsp-refresh-interval, spf-interval)

**Parsing Status:** ✅ EOS-specific implementation

**Documentation Source:** EOS 4.35.1F - IS-IS Configuration Guide

---

### 12. Extended Protocol Support (Inherited from IOSParser)

The following protocols use IOS-identical syntax in EOS and are parsed via IOSParser inheritance without modification:

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
| EIGRP | ✅ Inherited from IOSParser |
| RIP | ✅ Inherited from IOSParser |

See [IOS_PARSER_SUPPORT.md](IOS_PARSER_SUPPORT.md) for full syntax and attribute details for each of these protocols.

---

## Version Compatibility Matrix

| Feature | EOS 4.20+ | EOS 4.25+ | EOS 4.30+ | EOS 4.35+ | Notes |
|---------|-----------|-----------|-----------|-----------|-------|
| VRF (vrf instance) | ✅ | ✅ | ✅ | ✅ | Core feature |
| Interfaces (CIDR) | ✅ | ✅ | ✅ | ✅ | CIDR notation standard |
| BGP Basic | ✅ | ✅ | ✅ | ✅ | Address-family model |
| BGP Graceful-Restart | ✅ | ✅ | ✅ | ✅ | Standard feature |
| OSPF BFD | ✅ | ✅ | ✅ | ✅ | BFD support |
| Static Routes (egress-vrf) | ⚠️ | ✅ | ✅ | ✅ | Inter-VRF routing |
| ACLs (CIDR notation) | ✅ | ✅ | ✅ | ✅ | Standard feature |
| Community Lists | ✅ | ✅ | ✅ | ✅ | Standard feature |
| AS-Path Lists | ✅ | ✅ | ✅ | ✅ | Standard feature |
| IS-IS (modern syntax) | ✅ | ✅ | ✅ | ✅ | Instance-based |
| IS-IS Segment Routing | ❌ | ⚠️ | ✅ | ✅ | EOS 4.26.1F+ |

**Legend:**
- ✅ Fully Supported
- ⚠️ Partial Support / May require version-specific handling
- ❌ Not Supported / Not Available

---

## Parser Implementation Details

### Inheritance Strategy

The EOS parser inherits from `IOSParser` because:
1. **90% syntax similarity** - Most configuration syntax is IOS-compatible
2. **Code reuse** - VRF, BGP, OSPF, Route-maps use same parsing logic
3. **Maintenance efficiency** - Only override EOS-specific differences

### Overridden Methods

1. **`parse_vrfs()`** - Handles `vrf instance` syntax and EVPN route-targets
2. **`parse_prefix_lists()`** - Handles EOS hierarchical prefix-list syntax with CIDR notation
3. **`parse_static_routes()`** - CIDR notation and egress-vrf support
4. **`parse_acls()`** - Optional "standard" keyword and auto-detection
5. **`parse_community_lists()`** - Regexp keyword instead of standard/expanded
6. **`parse_as_path_lists()`** - Identical to IOS (included for completeness)
7. **`parse_isis()`** - Modern instance-based IS-IS syntax

---

## Known Limitations

1. **Numbered ACLs** - Parser only handles named ACLs
   - **Impact:** Traditional numbered ACLs (1-99, 100-199) not supported
   - **Priority:** Low (EOS primarily uses named ACLs)

2. **IPv6 Support** - Limited IPv6 parsing coverage
   - **Impact:** IPv6 configurations may not be fully captured
   - **Priority:** Medium

3. **VXLAN/EVPN** - Not currently parsed
   - **Impact:** Data center fabric configurations not captured
   - **Priority:** High for DC deployments

### Future Enhancements

1. **Multi-Agent Routing Model** - Parse `service routing protocols model multi-agent`
2. **Management API** - Parse `management api http-commands`
3. **MLAG Configuration** - Parse MLAG peer and interface configs
4. **VXLAN/EVPN** - Full VXLAN and EVPN configuration support

---

## Testing and Validation

### Test Coverage

**Sample Configuration:** `samples/eos.txt` (369 lines)
- EOS 4.30.1F configuration
- 14 interfaces (Ethernet, Port-Channel, Loopback, Vlan, Management, Tunnel)
- 2 VRFs (CUSTOMER_A, CUSTOMER_B, MGMT)
- 1 BGP instance (AS 65000) with 7 neighbors
- 1 OSPF process with 3 areas
- 13 route-maps
- 4 prefix-lists
- 5 static routes
- 3 ACLs
- 3 community lists
- 2 AS-path lists

**Test Scripts:**
- `test_eos_parser.py` - Basic parsing test
- `test_eos_parser_detailed.py` - Detailed output with all parsed objects

**Validation Results:**
```
✅ VRFs: 3 parsed (CUSTOMER_A, CUSTOMER_B, MGMT with EVPN route-targets)
✅ Interfaces: 14 parsed correctly
✅ BGP: 1 instance with 7 neighbors
✅ OSPF: 1 process with 3 areas
✅ Route-maps: 13 parsed
✅ Prefix-lists: 4 parsed (ISP1_PREFIX_IN, ISP1_PREFIX_OUT, CONNECTED_LOOPBACKS, CUSTOMER_A_ALLOWED)
✅ Static Routes: 5 parsed (including VRF and egress-vrf)
✅ ACLs: 3 parsed (1 standard, 2 extended with sequence numbers)
✅ Community Lists: 3 parsed (2 standard, 1 regexp/expanded)
✅ AS-Path Lists: 2 parsed (6 total entries)
```

---

## Arista Documentation References

### Primary Documentation Sources

1. **EOS 4.35.1F User Manual** (January 2026)
   - https://www.arista.com/en/um-eos/

2. **Configuration Guides:**
   - IPv4 Configuration: https://www.arista.com/en/um-eos/eos-ipv4
   - BGP Configuration: https://www.arista.com/en/um-eos/eos-border-gateway-protocol-bgp
   - OSPF Configuration: https://www.arista.com/en/um-eos/eos-ospf
   - IS-IS Configuration: https://www.arista.com/en/um-eos/eos-is-is
   - ACLs and Route Maps: https://www.arista.com/en/um-eos/eos-acls-and-route-maps
   - Static Routes: https://www.arista.com/en/um-eos/eos-static-inter-vrf-route

3. **Command Reference:**
   - Section 24.7 - ACL, Route Map, and Prefix List Commands
   - Section 33.4 - BGP Commands

---

## Quick Reference

### Parser Class Location
```python
from confgraph.parsers.eos_parser import EOSParser

parser = EOSParser(config_text)
parsed = parser.parse()
```

### Supported OS Type
```python
from confgraph.models.base import OSType

os_type = OSType.EOS  # "eos"
```

### Sample Configuration
```bash
samples/eos.txt  # EOS 4.30.1F sample configuration
```

### Test Script
```bash
uv run python test_eos_parser.py
```

---

**Last Updated:** 2026-03-28
**Parser Version:** 1.1.0
**Documentation Version:** EOS 4.35.1F
