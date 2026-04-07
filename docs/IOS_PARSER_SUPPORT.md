# Cisco IOS/IOS-XE Configuration Parser - Supported Versions and Features

## Supported Versions

### Cisco IOS
- **IOS 15.0** and later
- **IOS 15M&T** series (15.0M&T through 15.9M&T)
- **IOS 15S** series (15.0S through 15.9S)

### Cisco IOS-XE
- **IOS-XE 3.x** (XE 3S, XE 3SE) - Catalyst 3850, ASR 1000 initial releases
- **IOS-XE 16.x** series:
  - **16.3** (Denali) - BGP dynamic neighbors, IPv6 VRF support
  - **16.6** (Everest)
  - **16.9** (Gibraltar)
  - **16.12** (Gibraltar) - Full L2/L3/Security/MPLS/VXLAN BGP EVPN support
- **IOS-XE 17.x** series:
  - **17.3** (Amsterdam)
  - **17.4** (Bengaluru)
  - **17.6** (Cupertino)
  - **17.9** - **17.14** (Latest supported)
  - Feature additions: L2VPN EVPN AF support (17.11.1+), expanded BGP dynamic peering

## Configuration Syntax Support

The parser handles the unified configuration syntax shared across IOS and IOS-XE. The hierarchical block-based (indent-based) structure is consistent across all versions.

### Key Syntax Notes
- **Address Family Model:** Introduced in IOS 12.2(33)SRB, standardized in IOS 15.x and all IOS-XE
- **VRF Definition:** Both `vrf definition <name>` (IOS-XE) and `ip vrf <name>` (legacy IOS) syntax supported
- **BGP Configuration:** Address-family based configuration for IPv4, IPv6, VPNv4, L2VPN
- **OSPF:** Traditional `router ospf <process-id>` syntax (IOS-style)

---

## Parsing Coverage by Protocol

### 1. VRF (Virtual Routing and Forwarding)

#### Supported Commands
```
vrf definition <name>
  rd <route-distinguisher>
  route-target export <rt-value>
  route-target import <rt-value>
  route-target both <rt-value>
  address-family ipv4
    route-map <name> import
    route-map <name> export
  exit-address-family
```

#### Parsed Attributes
- ✅ VRF name
- ✅ Route Distinguisher (RD)
- ✅ Route Targets (import/export/both)
- ✅ Import/Export route-maps
- ✅ IPv4/IPv6 address families
- ⚠️  **Not yet:** VPN ID (NX-OS specific)

---

### 2. Interfaces

#### Supported Interface Types
- ✅ Physical interfaces (GigabitEthernet, TenGigabitEthernet, etc.)
- ✅ Loopback interfaces
- ✅ Port-channel (EtherChannel) interfaces
- ✅ VLAN/SVI interfaces
- ✅ Tunnel interfaces (GRE, IPsec)
- ✅ Management interfaces

#### Parsed Attributes
**Layer 3:**
- ✅ IP address (primary + secondary)
- ✅ IPv6 addresses
- ✅ VRF assignment (`vrf forwarding`)
- ✅ IP unnumbered
- ✅ MTU, bandwidth
- ✅ DHCP helper addresses

**Layer 2:**
- ✅ Switchport mode (access/trunk)
- ✅ Access VLAN
- ✅ Trunk allowed VLANs
- ✅ Trunk native VLAN

**Port-channel:**
- ✅ Channel-group membership
- ✅ Channel-group mode (active/passive/on)

**OSPF (Interface-level):**
- ✅ OSPF process ID and area
- ✅ OSPF cost, priority
- ✅ OSPF hello/dead intervals
- ✅ OSPF network type
- ✅ OSPF authentication (simple/MD5)
- ✅ OSPF message-digest keys

**FHRP:**
- ✅ HSRP groups (priority, preempt, virtual IP, timers, authentication, tracking)
- ✅ VRRP groups (priority, preempt, virtual IP, timers)

**Tunnel:**
- ✅ Tunnel source/destination
- ✅ Tunnel mode (GRE IP, IPsec, etc.)

**CDP/LLDP:**
- ✅ CDP enable/disable
- ✅ LLDP transmit/receive

---

### 3. BGP (Border Gateway Protocol)

#### Global BGP Configuration
```
router bgp <as-number>
  bgp router-id <router-id>
  bgp log-neighbor-changes
  bgp bestpath as-path multipath-relax
  bgp bestpath compare-routerid
  bgp bestpath med missing-as-worst
  ...
```

#### Parsed Attributes (Global)
- ✅ AS number
- ✅ Router ID
- ✅ Log neighbor changes
- ✅ Best-path options:
  - AS-path ignore
  - AS-path multipath-relax
  - Compare router-id
  - MED options (confed, missing-as-worst, always-compare-med)

#### BGP Neighbors
```
neighbor <ip> remote-as <asn>
neighbor <ip> peer-group <group-name>
neighbor <ip> description <text>
neighbor <ip> update-source <interface>
neighbor <ip> ebgp-multihop <ttl>
neighbor <ip> password <password>
neighbor <ip> route-map <name> in
neighbor <ip> route-map <name> out
neighbor <ip> prefix-list <name> in
neighbor <ip> maximum-prefix <number>
```

#### Parsed Neighbor Attributes
- ✅ Peer IP (IPv4/IPv6)
- ✅ Remote AS
- ✅ Peer-group membership
- ✅ Description
- ✅ Update-source
- ✅ eBGP multihop
- ✅ Password (MD5)
- ✅ Route-map in/out
- ✅ Prefix-list in/out
- ✅ Filter-list in/out
- ✅ Maximum-prefix
- ✅ Timers (keepalive/holdtime)
- ⚠️  **Inheritance:** Neighbors inheriting from peer-groups show `remote_as: "inherited"`

#### BGP Peer-Groups
```
neighbor <group-name> peer-group
neighbor <group-name> remote-as <asn>
neighbor <group-name> update-source <interface>
neighbor <group-name> route-reflector-client
neighbor <group-name> send-community both
```

#### Parsed Peer-Group Attributes
- ✅ Peer-group name
- ✅ Remote AS
- ✅ Update-source
- ✅ Route-reflector client
- ✅ Send-community (standard/extended/both)
- ✅ Route-map/prefix-list/filter-list policies
- ✅ Timers
- ✅ Password

#### Address Families (Global)
```
address-family ipv4
  network <prefix> [mask <mask>]
  redistribute <protocol> [<process-id>] [route-map <name>]
  aggregate-address <prefix> [mask] [summary-only] [as-set]
  neighbor <ip> activate
  neighbor <ip> next-hop-self
  neighbor <ip> send-community
  maximum-paths <number>
  maximum-paths ibgp <number>
exit-address-family
```

#### Parsed Address-Family Attributes
- ✅ AFI/SAFI (ipv4/ipv6 unicast)
- ✅ Network statements (with mask conversion)
- ✅ Redistribution (protocol, process-id, route-map, metric)
- ✅ Aggregate addresses (summary-only, as-set)
- ✅ Maximum-paths (eBGP/iBGP)
- ⚠️  **Not yet:** Neighbor activation status, AF-specific neighbor policies

#### VRF-Specific BGP
```
address-family ipv4 vrf <vrf-name>
  neighbor <ip> remote-as <asn>
  neighbor <ip> activate
  neighbor <ip> as-override
  neighbor <ip> route-map <name> in
  redistribute connected
  redistribute static
exit-address-family
```

#### Parsed VRF BGP Attributes
- ✅ VRF name
- ✅ VRF-specific neighbors (IP, remote-AS, description, route-maps)
- ✅ Redistribution (connected, static, OSPF)
- ⚠️  **Separate instances:** VRF BGP creates a new `BGPConfig` object with `vrf` field set

---

### 4. OSPF (Open Shortest Path First)

#### Global OSPF Configuration
```
router ospf <process-id>
  router-id <router-id>
  log-adjacency-changes [detail]
  auto-cost reference-bandwidth <mbps>
  passive-interface default
  no passive-interface <interface>
  redistribute bgp <asn> subnets route-map <name>
  default-information originate [always] [metric <m>] [metric-type <t>]
```

#### Parsed OSPF Attributes
- ✅ Process ID
- ✅ Router ID
- ✅ Log adjacency changes (detail)
- ✅ Auto-cost reference bandwidth
- ✅ Passive interface default
- ✅ Passive interfaces list
- ✅ Non-passive interfaces (when default is set)
- ✅ Default-information originate
- ⚠️  **Not yet:** Max-LSA, distance, timers throttle SPF/LSA

#### OSPF Areas
```
area <area-id> stub [no-summary]
area <area-id> nssa [no-summary] [default-information-originate]
area <area-id> authentication [message-digest]
area <area-id> range <prefix> <mask> [advertise | not-advertise]
```

#### Parsed Area Attributes
- ✅ Area ID (decimal or dotted-decimal)
- ✅ Area type (normal, stub, nssa, totally-stub, totally-nssa)
- ✅ Stub/NSSA no-summary
- ✅ Authentication type
- ✅ Area ranges (with advertise/not-advertise)
- ⚠️  **Not yet:** Virtual-links, default-cost

#### OSPF Redistribution
```
redistribute <protocol> [<process-id>] [metric <m>] [metric-type <1|2>] [subnets] [route-map <name>]
```

#### Parsed Redistribution Attributes
- ✅ Protocol (bgp, connected, static, rip, eigrp, etc.)
- ✅ Process ID (for BGP/OSPF)
- ✅ Metric
- ✅ Metric-type (E1/E2)
- ✅ Subnets flag
- ✅ Route-map

---

### 5. Route-Maps

#### Configuration Syntax
```
route-map <name> permit|deny <sequence>
  description <text>
  match ip address prefix-list <name>
  match as-path <acl-number>
  match community <list>
  match metric <value>
  set local-preference <value>
  set metric <value>
  set community <community>
  set as-path prepend <asn> [<asn> ...]
  continue <sequence>
```

#### Parsed Route-Map Attributes
- ✅ Route-map name
- ✅ Sequences (permit/deny, sequence number)
- ✅ Match clauses:
  - IP address (ACL/prefix-list)
  - AS-path
  - Community
  - Metric
  - Tag
- ✅ Set clauses:
  - Local-preference
  - Metric
  - Metric-type
  - Community
  - AS-path prepend
  - Next-hop
  - Origin
  - Weight
  - Tag
- ✅ Continue statement
- ✅ Description (per-sequence)

---

### 6. Prefix-Lists

#### Configuration Syntax
```
ip prefix-list <name> [seq <number>] permit|deny <prefix>/<length> [ge <min-length>] [le <max-length>]
ip prefix-list <name> description <text>
```

#### Parsed Prefix-List Attributes
- ✅ Prefix-list name
- ✅ Address family (IPv4/IPv6)
- ✅ Sequences (permit/deny, sequence number)
- ✅ Prefix matching (network/length)
- ✅ ge (greater-or-equal) modifier
- ✅ le (less-or-equal) modifier
- ✅ Description (per-entry, IOS-XE/NX-OS)
- ⚠️  **IPv6:** `ipv6 prefix-list` not yet parsed

---

### 7. Static Routes

#### Configuration Syntax
```
ip route [vrf <vrf-name>] <prefix> <mask> <next-hop> [<distance>] [tag <tag>] [name <name>] [track <obj>]
```

#### Parsed Attributes
- ✅ Destination prefix + mask
- ✅ Next-hop (IP address or exit interface)
- ✅ VRF
- ✅ Administrative distance
- ✅ Tag
- ✅ Name/description
- ✅ Track object reference

---

### 8. Access Control Lists (ACLs)

#### Configuration Syntax
```
ip access-list standard <name>
  [<seq>] permit <source> [log]
  [<seq>] deny <source> [log]

ip access-list extended <name>
  [<seq>] permit <protocol> <source> <destination> [log]
  [<seq>] deny <protocol> <source> <destination> [log]
```

#### Parsed Attributes
- ✅ ACL name
- ✅ ACL type (standard/extended)
- ✅ Sequence numbers
- ✅ Action (permit/deny/remark)
- ✅ Protocol (extended ACLs)
- ✅ Source/destination (IP, wildcard)
- ✅ Port operators (eq, range, gt, lt, neq)

---

### 9. BGP Community Lists

#### Configuration Syntax
```
ip community-list standard <name> permit|deny <communities>
ip community-list expanded <name> permit|deny <regex>
```

#### Parsed Attributes
- ✅ Community-list name
- ✅ Type (standard/expanded)
- ✅ Action (permit/deny)
- ✅ Community values or regex

---

### 10. BGP AS-Path Access Lists

#### Configuration Syntax
```
ip as-path access-list <name> permit|deny <regex>
```

#### Parsed Attributes
- ✅ AS-path list name
- ✅ Action (permit/deny)
- ✅ Regular expression

---

### 11. IS-IS

#### Configuration Syntax
```
router isis [<tag>]
  net <NET-address>
  is-type level-1-2
  passive-interface default
  no passive-interface <interface>
  redistribute connected [route-map <name>]
```

#### Parsed Attributes
- ✅ Instance name/tag
- ✅ NET address
- ✅ IS-type (level-1, level-2, level-1-2)
- ✅ Passive interfaces
- ✅ Redistribution

---

### 12. EIGRP

#### Configuration Syntax
```
router eigrp <as-number>
  network <prefix> <wildcard>
  no auto-summary
  redistribute static [metric ...]
  passive-interface <interface>
```

#### Parsed Attributes
- ✅ AS number
- ✅ Network statements
- ✅ Auto-summary
- ✅ Passive interfaces
- ✅ Redistribution

---

### 13. RIP

#### Configuration Syntax
```
router rip
  version 2
  network <network>
  no auto-summary
  passive-interface <interface>
  redistribute static [metric <m>]
```

#### Parsed Attributes
- ✅ Version
- ✅ Network statements
- ✅ Auto-summary
- ✅ Passive interfaces
- ✅ Redistribution

---

### 14. NTP

#### Configuration Syntax
```
ntp server <ip> [prefer] [source <interface>] [key <key-id>] [vrf <vrf>]
ntp peer <ip>
ntp authenticate
ntp authentication-key <key-id> md5 <key>
ntp trusted-key <key-id>
ntp source <interface>
```

#### Parsed Attributes
- ✅ NTP servers (IP, prefer, source, key, VRF)
- ✅ NTP peers
- ✅ Authentication (enabled, keys, trusted keys)
- ✅ Source interface

---

### 15. SNMP

#### Configuration Syntax
```
snmp-server community <community> [RO|RW] [<acl>]
snmp-server host <ip> version <ver> <community> [<traps>]
snmp-server location <text>
snmp-server contact <text>
snmp-server enable traps
```

#### Parsed Attributes
- ✅ Communities (string, access level, ACL)
- ✅ Trap hosts (IP, version, community)
- ✅ Location, contact
- ✅ Trap types enabled

---

### 16. Syslog

#### Configuration Syntax
```
logging host <ip> [transport <proto>] [port <port>]
logging source-interface <interface>
logging buffered <size> [<level>]
logging trap <level>
logging facility <facility>
```

#### Parsed Attributes
- ✅ Log hosts (IP, transport, port)
- ✅ Source interface
- ✅ Buffered logging (size, level)
- ✅ Trap level
- ✅ Facility

---

### 17. Banners

#### Configuration Syntax
```
banner motd ^C
  <message text>
^C
banner login ^C ... ^C
banner exec ^C ... ^C
```

#### Parsed Attributes
- ✅ Banner type (motd/login/exec)
- ✅ Banner text content

---

### 18. Line Configs

#### Configuration Syntax
```
line con 0
  logging synchronous
  exec-timeout <min> <sec>
line vty 0 4
  access-class <acl> in
  transport input ssh
  login local
```

#### Parsed Attributes
- ✅ Line type and range (con/vty/aux)
- ✅ Exec-timeout
- ✅ Logging synchronous
- ✅ Access-class
- ✅ Transport input/output
- ✅ Login method

---

### 19. QoS (Class-Map / Policy-Map)

#### Configuration Syntax
```
class-map match-any <name>
  match dscp <value>
  match access-group name <acl>
  match protocol <protocol>

policy-map <name>
  class <class-name>
    bandwidth percent <pct>
    priority percent <pct>
    set dscp <value>
    police rate <bps>
```

#### Parsed Attributes
- ✅ Class-map name, match type (match-any/match-all)
- ✅ Match clauses (DSCP, ACL, protocol, IP precedence)
- ✅ Policy-map name
- ✅ Class entries (class name, bandwidth, priority, police, set actions)

---

### 20. NAT

#### Configuration Syntax
```
ip nat inside source list <acl> interface <intf> overload
ip nat inside source static <local-ip> <global-ip>
ip nat pool <name> <start-ip> <end-ip> netmask <mask>
interface <intf>
  ip nat inside
  ip nat outside
```

#### Parsed Attributes
- ✅ NAT translations (static, dynamic, overload)
- ✅ NAT pools
- ✅ Inside/outside interface role

---

### 21. Crypto / IPsec

#### Configuration Syntax
```
crypto isakmp policy <priority>
  encryption <alg>
  hash <alg>
  authentication pre-share
  group <dh-group>

crypto ipsec transform-set <name> <transform> [<transform>]

crypto map <name> <seq> ipsec-isakmp
  set peer <ip>
  set transform-set <name>
  match address <acl>
```

#### Parsed Attributes
- ✅ ISAKMP policies (priority, encryption, hash, auth, DH group)
- ✅ IPsec transform sets
- ✅ Crypto maps (peer, transform-set, ACL match)

---

### 22. BFD

#### Configuration Syntax
```
bfd slow-timers <ms>
interface <intf>
  bfd interval <min-tx> min_rx <min-rx> multiplier <mult>
```

#### Parsed Attributes
- ✅ BFD global slow-timers
- ✅ Interface BFD (interval, min_rx, multiplier)

---

### 23. IP SLA

#### Configuration Syntax
```
ip sla <operation-number>
  icmp-echo <dest-ip> [source-ip <src-ip>]
  frequency <seconds>
ip sla schedule <op> life forever start-time now
```

#### Parsed Attributes
- ✅ Operation number
- ✅ Type (icmp-echo, udp-jitter, etc.)
- ✅ Destination/source IP
- ✅ Frequency
- ✅ Schedule (life, start-time)

---

### 24. EEM Applets

#### Configuration Syntax
```
event manager applet <name>
  event syslog pattern "<pattern>"
  action 1.0 cli command "show ip route"
  action 2.0 syslog msg "<text>"
```

#### Parsed Attributes
- ✅ Applet name
- ✅ Event type and parameters
- ✅ Action entries (sequence, type, parameters)

---

### 25. Object Tracking

#### Configuration Syntax
```
track <object-id> interface <intf> line-protocol
track <object-id> ip route <prefix> <mask> reachability
track <object-id> ip sla <op> reachability
```

#### Parsed Attributes
- ✅ Track object ID
- ✅ Track type (interface, ip route, ip sla)
- ✅ Tracked resource and state condition

---

### 26. Multicast

#### Configuration Syntax
```
ip multicast-routing [distributed]
interface <intf>
  ip pim sparse-mode
  ip igmp version <ver>
  ip igmp join-group <group>
ip pim rp-address <ip> [<acl>]
ip pim bsr-candidate <intf>
```

#### Parsed Attributes
- ✅ Multicast routing enabled
- ✅ PIM mode per interface (sparse-mode, dense-mode, sparse-dense-mode)
- ✅ IGMP version and static joins
- ✅ RP address (static and BSR/auto-RP)

---

## Parser Limitations and Future Enhancements

### Current Limitations
1. **BGP Neighbor AF-specific attributes:** Neighbor activate/deactivate within address-families not captured
2. **Confederation:** BGP confederation ID and peers not parsed
3. **IPv6:** Limited IPv6 support (addresses parsed, but IPv6 prefix-lists, routing not fully tested)

### Planned Enhancements
- [ ] BGP confederation support
- [ ] BGP graceful-restart attributes
- [ ] OSPF virtual-links, sham-links
- [ ] OSPF timers (SPF, LSA throttle)
- [ ] IPv6 routing protocol support (OSPFv3, BGP IPv6)

---

## Version Compatibility Matrix

| Feature | IOS 15.0+ | IOS-XE 3.x | IOS-XE 16.x | IOS-XE 17.x |
|---------|-----------|------------|-------------|-------------|
| VRF Definition | ✅ | ✅ | ✅ | ✅ |
| BGP Address-Family | ✅ | ✅ | ✅ | ✅ |
| BGP Dynamic Neighbors | ⚠️ | ⚠️ | ✅ (16.3+) | ✅ |
| BGP VRF IPv6 | ⚠️ | ⚠️ | ✅ (16.3+) | ✅ |
| OSPF BFD | ✅ | ✅ | ✅ | ✅ |
| HSRP v2 | ✅ | ✅ | ✅ | ✅ |
| VRRP | ✅ | ✅ | ✅ | ✅ |
| Tunnel Interfaces | ✅ | ✅ | ✅ | ✅ |
| Port-channel/EtherChannel | ✅ | ✅ | ✅ | ✅ |
| Static Routes | ✅ | ✅ | ✅ | ✅ |
| ACLs | ✅ | ✅ | ✅ | ✅ |
| Community Lists | ✅ | ✅ | ✅ | ✅ |
| AS-Path Lists | ✅ | ✅ | ✅ | ✅ |
| IS-IS | ✅ | ✅ | ✅ | ✅ |
| EIGRP | ✅ | ✅ | ✅ | ✅ |
| RIP | ✅ | ✅ | ✅ | ✅ |
| NTP | ✅ | ✅ | ✅ | ✅ |
| SNMP | ✅ | ✅ | ✅ | ✅ |
| Syslog | ✅ | ✅ | ✅ | ✅ |
| Banners | ✅ | ✅ | ✅ | ✅ |
| Line Configs | ✅ | ✅ | ✅ | ✅ |
| QoS (class-map/policy-map) | ✅ | ✅ | ✅ | ✅ |
| NAT | ✅ | ✅ | ✅ | ✅ |
| Crypto/IPsec | ✅ | ✅ | ✅ | ✅ |
| BFD | ✅ | ✅ | ✅ | ✅ |
| IP SLA | ✅ | ✅ | ✅ | ✅ |
| EEM Applets | ✅ | ✅ | ✅ | ✅ |
| Object Tracking | ✅ | ✅ | ✅ | ✅ |
| Multicast (PIM/IGMP) | ✅ | ✅ | ✅ | ✅ |

Legend:
- ✅ Fully supported by parser
- ⚠️  Partially supported or not available in this version
- ❌ Not supported by parser

---

## Testing and Validation

### Sample Configurations
The parser has been tested with comprehensive sample configurations located in:
- `samples/ios.txt` - IOS 15.x configuration
- `samples/ios_xe.txt` - IOS-XE 17.x configuration

### Test Coverage
Run the test suite:
```bash
uv run python test_ios_parser.py
uv run python test_ios_parser_detailed.py
```

### Validation
- ✅ 11 interfaces parsed (Loopback, GigabitEthernet, Port-channel, Tunnel, VLAN)
- ✅ 2 VRFs parsed with RD/RT
- ✅ BGP: 3 neighbors (2 iBGP, 1 eBGP), 1 peer-group, 1 address-family
- ✅ BGP VRF: 1 neighbor in CUSTOMER_A
- ✅ OSPF: 1 process, 1 area (NSSA), redistribution
- ✅ 9 route-maps with match/set clauses
- ✅ 4 prefix-lists with ge/le modifiers

---

## References

### Cisco Documentation
- [IP Routing: BGP Configuration Guide, IOS 15M&T](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/iproute_bgp/configuration/15-mt/irg-15-mt-book.html)
- [IP Routing: BGP Configuration Guide, IOS-XE 16](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/iproute_bgp/configuration/xe-16/irg-xe-16-book.html)
- [IP Routing: BGP Configuration Guide, IOS-XE 17](https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/ip-routing/b-ip-routing.html)
- [Cisco IOS IP Routing: BGP Command Reference](https://www.cisco.com/c/en/us/td/docs/ios/iproute_bgp/command/reference/irg_book.html)

### Parser Implementation
- **Library:** ciscoconfparse2 0.9.16
- **Python:** 3.10+
- **Data Models:** Pydantic 2.x

---

**Last Updated:** 2026-03-28
**Parser Version:** 1.1.0
**Maintainer:** Configz Development Team
