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
  ip name-server <ip> [<ip> ...]
  ip domain-name <domain>
  ip domain-list <domain>
  address-family ipv4 unicast
    route-target import <rt-value>
    route-target export <rt-value>
    route-target both <rt-value>
    import map <route-map>
    export map <route-map>
```

**NX-OS-Specific Differences:**
- Uses `vrf context` instead of IOS `vrf definition`
- Route-targets nested under `address-family` blocks within the VRF
- Import/export route-maps use the bare `map` token (`import map NAME` / `export map NAME`), not `route-map`
- Split `vrf context` blocks (one with `rd`, another with `address-family`) for the same name are merged by name

**Supported Attributes:**
- VRF name
- Route distinguisher (RD)
- Route-target import / export / both (per address-family)
- Import/export route-maps (`import map` / `export map`)
- VRF-scoped DNS (CCR-0093): per-VRF `ip name-server` → `VRFConfig.name_servers`, `ip domain-name` → `VRFConfig.domain_name`, `ip domain-list` → `VRFConfig.domain_list` (attributed to the VRF, not flattened into global DNS)

**Parsing Status:** ✅ Overridden — `parse_vrfs()` handles `vrf context NAME`, nested address-family RTs (`import`/`export`/`both`), `import map`/`export map`, and VRF-scoped DNS

---

### 2. Interface Configuration

**Syntax:**
```
interface <type><number>
  description <text>
  ip address <address>/<prefix-length> [secondary]
  vrf member <vrf-name>
  ip router ospf <proc-id> area <area-id>
  spanning-tree port type edge [trunk]
  storm-control {broadcast|multicast|unicast} level [pps|bps] <threshold>
  ip dhcp relay address <ip>
  ip flow monitor <name> {input|output}
  no shutdown
```

**NX-OS-Specific Differences:**
- **CIDR Notation:** IP addresses use `/prefix` notation (primary and `secondary`)
- **VRF:** `vrf member NAME` instead of `vrf forwarding NAME` (bare `vrf NAME` also accepted as a fallback)
- **OSPF membership:** `ip router ospf PROC area AREA` instead of `ip ospf PROC area AREA`
- **STP portfast** (CCR-0076): `spanning-tree port type edge` is NX-OS's rename of IOS `spanning-tree portfast` → `InterfaceConfig.stp_portfast`; `... type normal` sets it False
- **Storm-control** (CCR-0092): `storm-control {broadcast|multicast|unicast} level <threshold>` → `InterfaceConfig.storm_control` (list of `StormControlLevel` with `traffic_type`, `level`, `unit` — percent by default, or `pps`/`bps` when the unit keyword precedes the value)
- **DHCP relay** (CCR-0090, re-homed by CCR-0129): per-interface `ip dhcp relay address <ip>` (the NX-OS analogue of IOS `ip helper-address`) → `InterfaceConfig.helper_addresses` (repeatable, config order) — the SHARED cross-OS field for this one fact, so NX-OS relay changes reach the same DHCP assessor and relay-loop check as the IOS spelling. The CCR-0090 `dhcp_relay_addresses` field was removed. Note the member NEGATION `no ip dhcp relay address <ip>` is still parse-blind (CCR-0135)
- **NetFlow binding** (CCR-0094): `ip flow monitor <name> {input|output}` → `InterfaceConfig.flow_monitors` (list of `InterfaceFlowMonitor` with `monitor` + `direction`; IPv4 `input` is corpus-verified, `output` parsed leniently)

**Supported Attributes:**
- All standard interface attributes (name, description, IP, secondary IPs, shutdown)
- VRF membership via `vrf member`
- OSPF area membership
- Channel-group, switchport, HSRP/VRRP, tunnel parameters
- STP portfast, storm-control, DHCP relay targets, interface flow-monitor bindings, VPC membership

**Parsing Status:** ✅ Overridden — `parse_interfaces()` handles CIDR notation, `ip router ospf`, `spanning-tree port type edge`, storm-control, `ip dhcp relay address`, `ip flow monitor`, and VPC membership

#### 2a. FHRP — HSRP / VRRP (block and flat forms)

NX-OS emits HSRP/VRRP as indented `hsrp <N>` / `vrrp <N>` sub-blocks (attribute lines like `address` / `priority` / `preempt`) rather than the flat IOS `standby N <cmd>` pairs. Both spellings are collected and fed to the same shared HSRP/VRRP applier.

**Supported (CCR-0088):**
- Block-form `hsrp <N>` groups (with interface-level `hsrp version N`) and `vrrp <N>` groups
- `advertisement-interval` inside a `vrrp <N>` block → `VRRPGroup.timers_advertise` (mapped onto the shared `timers advertise` vocabulary)
- **VRRPv3 address-family groups**: `vrrpv3 <grp> address-family {ipv4|ipv6}` → `VRRPGroup` with `version=3`, `afi`, and per-AF virtual `addresses` (parsed by key, not position; IPv4 primary mirrored into `virtual_ip` for VRRPv2 parity). VRRPv2 and VRRPv3 are mutually exclusive on an interface.

**Parsing Status:** ✅ Overridden — `_collect_hsrp_commands()`, `_collect_vrrp_commands()`, `_parse_vrrp_groups()` / `_parse_vrrpv3_groups()`

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
  neighbor <ip>
    inherit peer <name>
    address-family ipv4 unicast
      route-map <name> in
      default-originate [route-map <name>]
      no next-hop-self
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
- **Nested neighbor blocks**: NX-OS nests ALL per-neighbor policy under `neighbor <ip>` → `address-family <afi> <safi>`. Both the bare-block form (`neighbor <ip>` with children) and the inline form (`neighbor <ip> remote-as <asn>` with children) are handled.
- **Per-address-family descent** (CCR-0077): each `address-family <afi> <safi>` sub-block under a neighbor becomes a `BGPNeighborAF` (route-map/prefix-list in/out, next-hop-self, send-community, maximum-prefix, default-originate). Any afi/safi pair is descended (incl. `l2vpn evpn`, `vpnv4`), so a dual-stack neighbor's IPv6 policy no longer clobbers its IPv4 policy. Session scalars are back-filled from the `ipv4 unicast` AF only.

**Supported Attributes:**
- All standard BGP attributes (ASN, router-id, neighbors, address-families)
- Peer templates (equivalent to IOS peer-groups) with attribute inheritance to inheriting neighbors
- VRF BGP instances (nested-block VRF neighbors captured with their per-AF route-maps, CCR-0032/0112)
- Per-neighbor `inherit peer NAME`, `default-originate [route-map]` (CCR-0078), and per-AF policy via `BGPNeighborAF`

**Parsing Status:**
- ✅ Core BGP: Inherited from IOSParser
- ✅ Overridden — `_parse_bgp_peer_groups()` handles `template peer NAME` blocks (and IOS-style `neighbor NAME peer-group`)
- ✅ Overridden — `_parse_bgp_neighbors()` / `_parse_nxos_neighbor_children()` handle inline + nested neighbor blocks, `inherit peer`, and per-AF descent
- ✅ Overridden — `_parse_bgp_vrf_instances()` handles `vrf NAME` blocks under router bgp
- ✅ Overridden — `_emit_bgp_neighbor_submode_negations()` handles indented `no <attr>` negations inside `neighbor <ip>` / address-family sub-blocks (CCR-0112)
- ✅ Inherited — AF-scoped `no network <cidr>` origination withdrawal under the `address-family` block (CCR-0081), where NX-OS places network statements

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
    ingress-replication protocol bgp
  member vni <l3-vni> associate-vrf
```

**Supported Attributes:**

- VNI-to-VLAN mapping via `vn-segment` under VLAN blocks
- All NVE interfaces (not just first)
- Source interface
- Host reachability protocol
- Per-VNI multicast group
- Per-VNI ARP suppression
- Per-VNI ingress-replication mode (CCR-0087): `ingress-replication protocol bgp` → `VXLANVniMapping.ingress_replication`; static head-end `peer-ip <ip>` lines → `ingress_replication_peers` (doc-grounded, parsed defensively)
- L3 VNI (`associate-vrf`; the mapping is flagged `vrf == "(L3)"` and reused by `parse_evpn()`)

**Parsing Status:** ✅ Overridden — `parse_vxlan()` handles NVE interfaces, `vn-segment` VLAN mappings, and ingress-replication mode

> The MP-BGP EVPN **control-plane** (L2VNI/L3VNI RD + route-targets) is modeled separately — see [Section 10, EVPN Control-Plane](#10-evpn-control-plane).

---

### 10. EVPN Control-Plane

The MP-BGP EVPN control-plane binds L2VNIs (MAC-VRF) and L3VNIs (tenant-VRF VNIs) to their route distinguishers and route-targets. This is distinct from the VXLAN data-plane (VTEP / VNI mappings in [Section 9](#9-vxlan-configuration)).

**Syntax:**
```
evpn
  vni <l2-vni> l2
    rd { auto | <rd> }
    route-target import { auto | <rt> }
    route-target export { auto | <rt> }

vrf context <tenant>
  vni <l3-vni>
  rd <rd>
  address-family ipv4 unicast
    route-target both <rt> evpn
  address-family ipv6 unicast
    route-target both <rt> evpn

interface nve1
  member vni <l3-vni> associate-vrf
```

**NX-OS-Specific Behavior (CCR-0087, CCR-0118):**
- **L2VNI (MAC-VRF)** lives under the top-level `evpn` block as `vni <n> l2` → `EVPNConfig.l2vnis` (`EVPNL2VNI`: rd + route-target import/export). There is **no** `vni <n> l3` form under `evpn`.
- **L3VNI** control-plane lives under `vrf context`: the `vni <n>` declaration (SVI-less mode spells it `vni <n> L3`) ties the L3VNI to its tenant VRF; the shared `rd` and the **`evpn`-suffixed** per-AF route-targets (`route-target both <rt> evpn`) are its EVPN RD/RTs → `EVPNConfig.l3vnis` (`EVPNL3VNI`). Plain (non-`evpn`) route-targets are left entirely to `parse_vrfs`.
- The NVE `member vni <n> associate-vrf` binding (from `parse_vxlan`, mapping flagged `vrf == "(L3)"`) sets `EVPNL3VNI.associate_vrf`. L3VNIs are joined one-per-VNI across the `vrf context` source and the NVE signal.
- `route-target both <rt>` populates **both** import and export lists; literal `auto` is preserved.

**Doc-grounded caveat (CCR-0118):** the L2VNI form is device-verified (n9kv 10.5(5)); the L3VNI `vrf context` `rd` / `route-target ... evpn` block is grounded in the Cisco Nexus 9000 VXLAN Config Guide 10.5(x), not a device readback. All fields are optional so partial (e.g. vni-only) declarations still parse.

**Parsing Status:** ✅ Overridden — `parse_evpn()` builds `EVPNConfig` from the `evpn` block, `vrf context` L3VNI declarations, and the NVE associate-vrf signal

---

### 11. VPC Configuration

**Syntax:**
```
vpc domain <id>
  role priority <value>
  system-priority <value>
  peer-keepalive destination <ip> source <ip> vrf <vrf>
  peer-gateway
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
- Peer-gateway (CCR-0075): `peer-gateway` → `VPCConfig.peer_gateway` (default False; `no peer-gateway` sets it False)
- Delay restore, auto-recovery
- Per-interface VPC membership and peer-link detection (parsed via interface parser)

**Parsing Status:** ✅ Overridden — `parse_vpc()` handles `vpc domain` block; per-interface `vpc N` membership parsed in `parse_interfaces()`

---

### 12. MPLS/LDP Configuration

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

### 13. QoS / CoPP

**Syntax:**
```
class-map type control-plane match-any CM_CRITICAL
  match access-group name ACL_BGP
policy-map type control-plane PM_COPP
  class CM_CRITICAL
    police cir 50 pps bc 16 packets

control-plane
  service-policy input PM_COPP
```

**NX-OS-Specific Behavior (CCR-0089, CCR-0119):**
- **Typed class-map / policy-map** (inherited from IOSParser): `class-map type <qualifier> <NAME>` / `policy-map type <qualifier> <NAME>` capture the name correctly and record the qualifier in `ClassMapConfig.type` / `PolicyMapConfig.type` (e.g. `control-plane`, `qos`, `queuing`; `None` for the plain untyped form).
- **CoPP policer units**: `police cir <n> pps bc <n> packets` (and `kbps`/`mbps`/`gbps`/`bps`) → `PolicyMapPolice.rate` / `burst` with `rate_unit` / `burst_unit` populated (the legacy IOS bare `police <bps>` form leaves the units `None`).
- **Control-plane binding** (overridden): the `control-plane` block's `service-policy input <PM>` → `ParsedConfig.control_plane` (`ControlPlaneConfig.service_policy_input`). The policed traffic itself lives in the referenced `policy-map type control-plane`.

**Parsing Status:**
- ✅ Inherited — typed class-map/policy-map name capture and `police ... pps/bc packets` units
- ✅ Overridden — `parse_control_plane()` models the `control-plane` service-policy binding

---

### 14. NetFlow / Flexible NetFlow

**Syntax:**
```
flow record <name>
  match ipv4 source address
  collect counter bytes
flow exporter <name>
  destination <ip> [use-vrf <vrf>]
  source <interface>
  version 9
flow monitor <name>
  record <record>
  exporter <exporter>
```

**Supported Attributes (CCR-0094):**
- `flow record` — `match` (key) and `collect` (non-key) field sets → `NetFlowRecord`
- `flow exporter` — destination (+ `use-vrf`), source, version → `NetFlowExporter`
- `flow monitor` — bound record + exporter → `NetFlowMonitor`
- Interface binding `ip flow monitor <name> {input|output}` → `InterfaceFlowMonitor` (see [Section 2](#2-interface-configuration))
- Returns `None` when the device carries none of the three blocks

> **Doc-grounded, not device-captured:** syntax is verified from `syntax-corpus/nxos/netflow.yaml`; the emitted running-config form is not yet hardware-captured (the n9kv 10.5(5) probe rejected `feature netflow`).

**Parsing Status:** ✅ Overridden — `parse_netflow()` builds `NetFlowConfig` from the three top-level `flow record` / `flow exporter` / `flow monitor` blocks

---

### 15. ACLs & Object-Groups

**Syntax:**
```
object-group ip address OG_HOSTS
  10 host 10.199.1.1
  20 10.199.2.0/24
object-group ip port OG_PORTS
  10 eq 443

ip access-list ACL_V4
  10 remark allow web
  20 permit tcp addrgroup OG_HOSTS any portgroup OG_PORTS
ipv6 access-list ACL_V6
  10 permit ipv6 any any
mac access-list ACL_MAC
  10 permit any any
```

**Supported Attributes (CCR-0086):**
- **Multi-family ACLs**: `ip` / `ipv6` / `mac` access-lists — `ACLConfig.family` is `ipv4` / `ipv6` / `mac` (one header grammar, single pass). IPv6/MAC have no standard/extended split.
- **Object-groups**: `object-group ip|ipv6 address|port <NAME>` blocks with their member lines → `ParsedConfig.object_groups` (`ObjectGroup` with `group_type` + `members`). Inherited from the IOS-family `parse_object_groups()`.
- **Group references in ACEs**: `addrgroup <NAME>` / `portgroup <NAME>` in place of a literal address → `ACLEntry.source_group` / `destination_group`.
- **Standalone `remark` ACEs**: comment-only entries → `ACLEntry.remark`.

**Parsing Status:** ✅ Inherited — `parse_acls()` (IPv4/IPv6/MAC families, addrgroup/portgroup, remark) and `parse_object_groups()` are provided by IOSParser and consumed unchanged by NX-OS

---

### 16. Extended Protocol Support

| Protocol | Parsing Status | NX-OS Notes |
| -------- | -------------- | ----------- |
| NTP | ✅ Overridden | Handles `use-vrf` keyword, `ntp source-interface` |
| Syslog | ✅ Overridden | Handles `logging server` with `use-vrf`, per-server severity, `logging off` / `no logging on` |
| LLDP | ✅ Overridden | NX-OS uses `feature lldp` to enable; defaults to disabled |
| CDP | ✅ Overridden | NX-OS uses `feature cdp` to enable; defaults to disabled |
| DNS | ✅ Inherited (+ VRF-scoping in `parse_vrfs`) | Global `ip name-server` / `ip domain-name` / hyphenated `ip domain-list` handled by inherited `parse_dns` (CCR-0117); per-`vrf context` DNS attributed to the VRF in `parse_vrfs` (CCR-0093) |
| AAA | ✅ Overridden | Parses `aaa group server tacacs+/radius NAME` child `server` members |
| Static Routes | ✅ Overridden | Parses routes inside `vrf context` blocks |
| ACLs / Object-groups | ✅ Inherited | IPv4/IPv6/MAC access-lists + object-groups — see [Section 15](#15-acls--object-groups) (CCR-0086) |
| QoS / CoPP | ✅ Inherited + Overridden | Typed class-map/policy-map + `control-plane` binding — see [Section 13](#13-qos--copp) (CCR-0089/0119) |
| NetFlow | ✅ Overridden | Flexible NetFlow record/exporter/monitor — see [Section 14](#14-netflow--flexible-netflow) (CCR-0094) |
| SNMP | ✅ Inherited from IOSParser | |
| Banners | ✅ Inherited from IOSParser | |
| Line configs (con/vty) | ✅ Overridden | NX-OS bare `line vty` / `line console` header (no number) |
| NAT | ✅ Inherited from IOSParser | |
| Crypto/IPsec | ✅ Inherited from IOSParser | |
| BFD | ✅ Inherited from IOSParser | |
| IP SLA | ✅ Inherited from IOSParser | Operation `frequency` and trailing destination `port` populated (CCR-0091) |
| EEM Applets | ✅ Inherited from IOSParser | |
| Object Tracking | ✅ Inherited from IOSParser | |
| IS-IS / EIGRP | ✅ Inherited from IOSParser | AF-transparent nesting via `_nested_block` so instance-level attrs under `address-family ipv4 unicast` are read (CCR-0067) |
| Multicast (PIM/IGMP) | ✅ Inherited from IOSParser | NX-OS PIM `anycast-rp`, `spt-threshold`, and `rp-address ... group-list <prefix>` forms parsed (CCR-0085) |

See [IOS_PARSER_SUPPORT.md](IOS_PARSER_SUPPORT.md) for full syntax and attribute details on inherited protocols.

---

### 17. Deletion Commands

NX-OS inherits all IOS top-level tombstone types and adds the following NX-OS-specific nested-block deletions:

| Command | Scope | Tombstone Emitted |
|---------|-------|-------------------|
| `no member vni <id>` | `interface nve` | `field:vxlan:vni:<id>` |
| `no host-reachability protocol` | `interface nve` | `field:vxlan:host_reachability` |
| `no peer-keepalive` | `vpc domain` | `field:vpc:peer_keepalive_destination` / `_source` / `_vrf` (one line fans out to three) |
| `no ip route ...` | `vrf context NAME` | `static:NAME:<dest>[:<nh_spec>]` (CIDR and `DEST MASK` forms) |
| `no vrf context NAME` | top-level | `field:vrfs:NAME` |

**Native ChangeOps (CCR-0110):** these removals are queued as native `ChangeOp`s (OBJECT_DELETE / LIST_REMOVE / singleton UNSET) and the tombstone strings above are regenerated **from** those ops (single source, byte-exact). Op-primary parsers no longer persist the deprecated legacy `no_commands` string channel — it now comes back empty; the removals live in the native op stream instead.

**Parsing Status:** ✅ Overridden — `parse_deletion_commands()` queues NX-OS-specific native removal ops (and their regenerated tombstones) in addition to inherited IOS tombstones

---

## Overridden Methods Summary

| Method | Reason for Override |
|--------|---------------------|
| `parse_vrfs()` | Handles `vrf context NAME`, nested AF RTs (`import`/`export`/`both`), `import map`/`export map`, VRF-scoped DNS (name-servers / domain-name / domain-list) |
| `_extract_interface_vrf()` | Handles `vrf member NAME` (and bare `vrf NAME` fallback) |
| `parse_interfaces()` | CIDR notation, secondary IPs, `ip router ospf`, VPC membership, STP `port type edge`, storm-control, `ip dhcp relay address`, `ip flow monitor` |
| `_collect_hsrp_commands()` / `_collect_vrrp_commands()` | Block-form `hsrp N` / `vrrp N` sub-blocks + `advertisement-interval` |
| `_parse_vrrp_groups()` / `_parse_vrrpv3_groups()` | Adds VRRPv3 `vrrpv3 <grp> address-family {ipv4\|ipv6}` groups |
| `_parse_bgp_peer_groups()` | Handles `template peer NAME` blocks (and IOS-style `neighbor NAME peer-group`) |
| `_parse_bgp_neighbors()` / `_parse_nxos_neighbor_children()` | Nested neighbor blocks, `inherit peer NAME`, per-AF descent to `BGPNeighborAF`, `default-originate` |
| `_parse_bgp_vrf_instances()` | Handles `vrf NAME` blocks under router bgp |
| `_emit_bgp_neighbor_submode_negations()` | Indented `no <attr>` neighbor/AF negations (CCR-0112) |
| `parse_bgp()` | Peer-group attribute inheritance after parse |
| `parse_ospf()` | Extracts VRF from `router ospf N vrf NAME` header + nested `vrf NAME` blocks |
| `_nested_block()` | AF-transparent view for IS-IS/EIGRP instance attrs under `address-family ipv4 unicast` (CCR-0067) |
| `parse_static_routes()` | Parses routes inside `vrf context` blocks |
| `parse_ntp()` | Handles `use-vrf`, `ntp source-interface` |
| `parse_syslog()` | Handles `logging server` with `use-vrf`, `logging off` |
| `parse_lldp()` | `feature lldp` as enable signal (NX-OS defaults disabled) |
| `parse_cdp()` | `feature cdp` as enable signal (NX-OS defaults disabled) |
| `parse_aaa()` | Parses `aaa group server` child `server` members |
| `parse_vxlan()` | All NVE interfaces, `vn-segment`, mcast-group, suppress-arp, ingress-replication |
| `parse_evpn()` | EVPN control-plane: L2VNI (`evpn` block) + L3VNI (`vrf context` + NVE associate-vrf) |
| `parse_vpc()` | `vpc domain` block + peer-link detection + peer-gateway |
| `parse_control_plane()` | `control-plane` CoPP `service-policy input` binding |
| `parse_netflow()` | Flexible NetFlow `flow record` / `exporter` / `monitor` blocks |
| `parse_mpls()` | `mpls ldp configuration` block |
| `parse_deletion_commands()` | NX-OS-specific native removal ops + tombstones (VNI, host-reachability, VPC peer-keepalive, VRF static routes, whole VRF) |

> **Note:** DNS is **not** overridden on NX-OS — the inherited `parse_dns()` handles global resolvers (incl. hyphenated `ip domain-list`, CCR-0117); per-VRF DNS is attributed inside `parse_vrfs()`. Object-groups and multi-family ACLs come from the inherited `parse_object_groups()` / `parse_acls()`. The bare `line vty` / `line console` header and NX-OS VRF `import map`/`export map` vocabulary are supplied via overridden class-level patterns (`_LINE_HEADER_PATTERNS`, `_VRF_SCALAR_PATTERNS`).

---

## Parser Limitations

1. **FabricPath** — Not parsed
2. **IPv6 routing** — IPv6 ACLs (CCR-0086) and IPv6 BGP address-families (CCR-0077) are now parsed; dedicated IPv6 IGP (OSPFv3, etc.) coverage remains limited
3. **NX-OS-specific features** — Port profiles, role-based access control not parsed (`port-profile` is a recognized top-level block but not modeled)
4. **VRRPv3 advertise timer** — the VRRPv3 `timers advertise <ms>` line is intentionally not parsed (doc-only, not capture-verified)
5. **NetFlow / EVPN-L3VNI** — parsed but doc-grounded rather than device-captured (see Sections 14 and 10)

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

**Last Updated:** 2026-07-29
