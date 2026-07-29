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
- Uses `vrf instance` instead of IOS `vrf definition` (both spellings accepted)
- On a real EOS switch the `vrf instance NAME` block carries only the name and description; RD and route-targets are printed inside `router bgp <asn>` → `vrf NAME` and are read from there, then attributed back onto the VRF
- CIDR notation not used in VRF context

**Supported Attributes:**
- VRF name
- Description
- Route distinguisher (RD) — read from the `router bgp` VRF block and back-filled onto the VRF
- Route-target import/export — read from the `router bgp` VRF block and back-filled onto the VRF
- Route-map import/export

**Parsing Status:** ✅ Inherited — `parse_vrfs()` is no longer overridden. The header spelling (`vrf instance` / `vrf definition`) is supplied as data via `_VRF_HEADER_PATTERNS`; the body vocabulary (description, rd, route-target, route-map import/export) uses the shared `IOSParser.parse_vrfs` walk. RD/RT are sourced from the shared `router bgp` VRF-block traversal and attributed onto the `VRFConfig` by `BaseParser._backfill_vrf_rd_rt`.

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
- IP address (IPv4/IPv6 with CIDR notation), including CIDR secondary addresses (`ip address X.X.X.X/Y secondary`)
- VRF membership (bare `vrf NAME`; the older `vrf forwarding` spelling is also accepted)
- Administrative status (shutdown)
- OSPF attributes (area via bare `ip ospf area <area>` with no process ID, cost, network type, priority, authentication)
- VARP virtual (anycast-gateway) addresses — `ip virtual-router address <ip>`, accumulated one per line into `varp_addresses`
- VRRP configuration
- Tunnel parameters

**Interface Types Supported:**
- Physical: Ethernet, Management
- Logical: Loopback, Vlan, Tunnel, Port-Channel

**Whole-list reset (CCR-0113):** bare negations that reset an entire `default_factory` interface list are grounded and honored, including `no ip virtual-router address` clearing `varp_addresses`. These use the shared `_IFACE_WHOLE_LIST_RESET_PATTERNS` registry and reset the field to its factory default at finalization.

**Parsing Status:** ✅ Overridden — `parse_interfaces()` extends the inherited walk with EOS CIDR primary/secondary IPv4, EOS `ip ospf area` (no process ID), and VARP virtual-router address accumulation. The interface VRF binding is supplied as data via `_IFACE_VRF_PATTERNS` (no method override).

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
- VRF BGP configured within `router bgp` block as a `vrf NAME` sub-block (same block form as NX-OS and IOS-XR, not the IOS-XE `address-family ipv4 vrf NAME` form)
- Neighbor verb aliases: EOS `peer group` (two words) maps to IOS `peer-group`; EOS `maximum-routes` maps to IOS `maximum-prefix`. These are two dictionary entries (`_BGP_CMD_ALIASES`) on the shared neighbor walk, not a forked walk
- Best-path tie-break: EOS spells the router-id tie-break `bgp bestpath tie-break router-id` (IOS spells it `bgp bestpath compare-routerid`); both map to `bestpath_options.compare_routerid`. EOS rejects the IOS spelling. Handled by extending one spelling tuple (`_BGP_BESTPATH_SPELLINGS`); the shared bestpath walk covers both positive and negated forms
- Process-level `maximum-paths [ecmp]` / `maximum-paths ibgp` and flat `aggregate-address` are emitted outside any `address-family` block and folded into the implicit IPv4-unicast family
- Supports modern BGP features (graceful-restart, route-reflector-client)

**Supported Attributes:**
- ASN, router-id
- Neighbors (iBGP/eBGP)
- Peer groups
- Address families (IPv4/IPv6)
- VRF instances (block form), including RD and route-targets
- Route-maps (in/out)
- Timers, authentication, route-reflector-client
- Best-path options including `tie-break router-id`
- Maximum-paths, maximum-routes
- Flat `network` and `aggregate-address` statements at both global and VRF scope

**VRF parity (CCR-0114):** VRF-scoped flat `network` and `aggregate-address` lines (direct children of `vrf NAME`) now reach parity with the global instance path — flat networks land on the VRF's BGPConfig, and a flat aggregate is folded into the VRF's IPv4-unicast address-family. AF-nested networks/aggregates are read separately with no double-count.

**VRF neighbor AF (CCR-0115):** the shared VRF-block walker fires the per-neighbor AF-policy hook, so VRF `address-family` block `neighbor X <policy>` lines are captured (previously dropped for EOS while the identical global block parsed).

**Parsing Status:** ✅ Mostly inherited; the previously-forked EOS BGP walk was unified into the shared `IOSParser` walk. EOS contributes only data (`_BGP_CMD_ALIASES`, `_BGP_BESTPATH_SPELLINGS`) plus thin overrides: `_parse_bgp_vrf_instances()` (delegates to the shared block-form VRF traversal) and `_parse_bgp_process_level_af_settings()` (EOS process-level `maximum-paths`).

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

**EOS-Specific Differences:**
- Interface IS-IS membership uses `isis enable <tag>` (IOS: `ip router isis <tag>`), supplied as data via `_ISIS_IFACE_ENABLE_PATTERNS`
- EOS has no process-level `passive-interface` under `router isis` (the device rejects it); an interface declares itself passive with `isis passive`, read by the shared interface walk into `ISISInterface.passive` and back-filled into `ISISConfig.passive_interfaces`

**Parsing Status:** ✅ Inherited — `parse_isis()` is no longer overridden. The instance body (net / is-type / redistribute / log-adjacency-changes / timers) is spelled identically to IOS; EOS's two dialects (interface membership spelling and where passive lives) are data on the shared `IOSParser.parse_isis` walk.

**Documentation Source:** EOS 4.35.1F - IS-IS Configuration Guide

---

### 12. DNS Configuration

**Syntax:**
```
ip name-server <ip> [<ip>...]
ip domain-name <domain>
ip domain list <domain>
no ip domain lookup

vrf instance <name>
   ip name-server [vrf <name>] <ip> [<ip>...]
   ip domain-name <domain>
   ip domain list <domain>
   no ip domain lookup
```

**EOS-Specific Differences:**

- Per-VRF DNS entries are nested under `vrf instance NAME` blocks; IOS places them at global scope only.
- `parse_dns()` is overridden to scan all `vrf instance` stanzas and merge the discovered entries (name-servers, domain-name, domain-list, no domain lookup) with the global DNS config returned by the parent `IOSParser`.

**Supported Attributes:**

- Name servers
- Domain name
- Domain list
- Lookup enabled/disabled

**Parsing Status:** ✅ Overridden — `parse_dns()` merges VRF-scoped DNS entries from `vrf instance` blocks with global DNS config

**Documentation Source:** EOS 4.35.1F - DNS Configuration

---

### 13. VXLAN Configuration

**Syntax:**
```
interface Vxlan1
   vxlan source-interface Loopback1
   vxlan udp-port 4789
   vxlan vlan 10 vni 10010
   vxlan vrf TENANT-A vni 50001
   vxlan flood vtep 10.0.0.2 10.0.0.3
   vxlan learn-restrict any
```

**Supported Attributes:**

- Source interface
- UDP port
- VLAN-to-VNI mappings
- VRF-to-VNI mappings
- Flood VTEP list
- Learn-restrict

`line_numbers` are populated for all parsed lines.

**Deletion tombstones:** `no vxlan vlan <id> vni <id>` and `no vxlan vrf <name> vni <id>` inside `interface Vxlan1` produce `field:vxlan:vni:<vni_id>` removals. Under the op-primary model (CCR-0110) these are native singleton-removal ChangeOps queued via `_queue_native_singleton_removal()`; the byte-exact legacy tombstone string is regenerated from the op rather than persisted in the deprecated `no_commands` channel.

**Parsing Status:** ✅ EOS-specific implementation — `parse_vxlan()` reads from `interface Vxlan1`

**Documentation Source:** EOS 4.35.1F - VXLAN Configuration Guide

---

### 14. MPLS/LDP Configuration

**Syntax:**
```
mpls ldp
   router-id interface Loopback0
   no shutdown
   transport-address interface Loopback0
   graceful-restart
   session protection
```

**EOS-Specific Differences:**

- LDP sub-commands are nested under a `mpls ldp` block (IOS uses flat `mpls ldp router-id` lines).
- `router-id interface <name>` uses the `interface` keyword; a raw IP form is also accepted.

**Supported Attributes:**

- LDP router-id (interface name or IP)
- LDP enabled
- Graceful-restart
- Session protection
- Password

`line_numbers` are populated for all parsed lines.

**Parsing Status:** ✅ EOS-specific implementation — `parse_mpls()` handles `mpls ldp` hierarchical block

**Documentation Source:** EOS 4.35.1F - MPLS Configuration Guide

---

### 15. MLAG (VPC) Configuration

**Syntax:**
```
mlag configuration
   domain-id MLAG_DOMAIN
   local-interface Vlan4094
   peer-address 10.0.0.2
   peer-link Port-Channel1
   reload-delay mlag 300
```

**EOS-Specific Differences:**

- EOS uses `mlag configuration` block; the model is stored as `VPCConfig` for cross-OS compatibility.
- `peer-address` maps to `peer_keepalive_destination`.

**Supported Attributes:**

- Domain ID
- Peer link interface
- Peer keepalive destination (peer-address)
- Reload delay

`line_numbers` are populated for all parsed lines.

**Deletion tombstones:** `no peer-address` inside `mlag configuration` produces a `field:vpc:peer_keepalive_destination` removal. As with VXLAN, this is a native singleton-removal ChangeOp (CCR-0110 op-primary); the legacy tombstone string is regenerated from the op, not persisted in `no_commands`.

**Parsing Status:** ✅ EOS-specific implementation — `parse_vpc()` reads from `mlag configuration` block

**Documentation Source:** EOS 4.35.1F - MLAG Configuration Guide

---

### 16. Extended Protocol Support (Inherited from IOSParser)

The following protocols use IOS-identical syntax in EOS and are parsed via IOSParser inheritance without modification:

| Protocol | Parsing Status |
|----------|---------------|
| NTP | ✅ Inherited from IOSParser |
| SNMP | ✅ Inherited from IOSParser |
| Syslog | ✅ Inherited from IOSParser |
| Banners | ✅ Inherited from IOSParser |
| Line / session configs | ✅ Shared line walk; EOS extends it (see note below) |
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

**EOS management-line config (2026-07-14):** EOS has no numbered `line vty` block. The same concept — idle admin-session lifetime and its transport — is spelled as top-level `management ssh | console | telnet` blocks with an `idle-timeout <minutes>` child. These join the shared `parse_lines` walk via four data extensions (`_LINE_HEADER_PATTERNS`, `_LINE_TYPES`, `_LINE_EXEC_TIMEOUT_PATTERNS`, `_LINE_TRANSPORT_KEYWORDS`): `console` maps to the CONSOLE line type, `ssh`/`telnet` to VTY, and the block keyword becomes the `transport input` value. The header is anchored so the sibling `management api http-commands | gnmi | netconf` blocks are not swallowed.

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

1. **`parse_interfaces()`** - Extends the inherited walk with EOS CIDR primary/secondary IPv4, EOS `ip ospf area` (no process ID), and VARP `ip virtual-router address` accumulation
2. **`parse_prefix_lists()`** - Handles EOS hierarchical prefix-list syntax with CIDR notation
3. **`parse_static_routes()`** - CIDR notation and egress-vrf support
4. **`parse_acls()`** - Optional "standard" keyword and auto-detection
5. **`parse_community_lists()`** - Regexp keyword instead of standard/expanded
6. **`parse_as_path_lists()`** - Identical to IOS (included for completeness)
7. **`parse_bfd()`** - EOS `router bfd` block form and flat `bfd slow-timer <ms>` (singular)
8. **`parse_dns()`** - Merges VRF-scoped DNS entries from `vrf instance` blocks with global DNS config
9. **`parse_multicast()`** - EOS block form (`router multicast` → `ipv4` → `routing`, `router pim sparse-mode` → `ipv4` → `rp address …`); merges any flat lines the inherited walk finds
10. **`parse_vxlan()`** - Reads VXLAN config from `interface Vxlan1`; populates `line_numbers`
11. **`parse_mpls()`** - Handles EOS `mpls ldp` hierarchical block; populates `line_numbers`
12. **`parse_vpc()`** - Maps `mlag configuration` to `VPCConfig`; populates `line_numbers`
13. **`parse_deletion_commands()`** - Adds EOS-specific VXLAN VNI and MLAG native singleton-removal ops (CCR-0110 op-primary)
14. **`_parse_bgp_vrf_instances()`** - Delegates to the shared block-form VRF traversal (`_parse_bgp_vrf_blocks`) so EOS `router bgp` → `vrf NAME` blocks parse (unlike the IOS-XE `address-family ipv4 vrf` form)
15. **`_parse_bgp_process_level_af_settings()`** - Reads EOS process-level `maximum-paths [ecmp]` / `maximum-paths ibgp`; folded into the IPv4-unicast family by the shared merge

**No longer overridden (now data-driven on the shared walk):**

- **`parse_vrfs()`** — header spelling is data (`_VRF_HEADER_PATTERNS`); RD/RT read from the `router bgp` VRF block and back-filled
- **`parse_isis()`** — interface membership spelling and passive-interface placement are data on the shared walk
- **`parse_bgp()` / BGP neighbor and peer-group walks** — EOS dialect is two aliases (`_BGP_CMD_ALIASES`) plus the bestpath spelling tuple (`_BGP_BESTPATH_SPELLINGS`)
- **`parse_lines()`** — EOS `management ssh|console|telnet` blocks join via four table extensions
- **`_extract_interface_vrf()`** — interface VRF binding is data (`_IFACE_VRF_PATTERNS`)

**Data-driven dialect extensions (pattern-sets / lookup tables, not method overrides):** interface VRF (`_IFACE_VRF_PATTERNS`), VRF header (`_VRF_HEADER_PATTERNS`), OSPF process-wide BFD (`_OSPF_BFD_ALL_PATTERNS`), BGP bestpath spellings (`_BGP_BESTPATH_SPELLINGS`), BGP neighbor aliases (`_BGP_CMD_ALIASES`), interface BFD timers (`_IFACE_BFD_PATTERNS`), interface PIM mode (`_IFACE_PIM_MODE_PATTERNS`), syslog host (`_SYSLOG_HOST_PATTERNS`), DNS domain (`_DNS_DOMAIN_PATTERNS`), IS-IS interface enable (`_ISIS_IFACE_ENABLE_PATTERNS`), line/session config (`_LINE_HEADER_PATTERNS`, `_LINE_TYPES`, `_LINE_EXEC_TIMEOUT_PATTERNS`, `_LINE_TRANSPORT_KEYWORDS`), banners (`_BANNER_PATTERNS`), and whole-list interface reset (`_IFACE_WHOLE_LIST_RESET_PATTERNS`, incl. `varp_addresses`).

---

## Known Limitations

1. **Numbered ACLs** - Parser only handles named ACLs
   - **Impact:** Traditional numbered ACLs (1-99, 100-199) not supported
   - **Priority:** Low (EOS primarily uses named ACLs)

2. **IPv6 Support** - Limited IPv6 parsing coverage
   - **Impact:** IPv6 configurations may not be fully captured
   - **Priority:** Medium

### Future Enhancements

1. **Multi-Agent Routing Model** - Parse `service routing protocols model multi-agent`
2. **Management API** - Parse `management api http-commands`

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

**Last Updated:** 2026-07-29
**Parser Version:** 1.1.0
**Documentation Version:** EOS 4.35.1F
