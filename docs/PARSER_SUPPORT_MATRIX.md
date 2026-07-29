# Parser Support Matrix

## Overview

Comprehensive overview of parser support across all network operating systems in confgraph. Each parser inherits from either `BaseParser` (abstract base) or `IOSParser` (reference implementation). EOS, IOS-XR, and NX-OS extend IOSParser and inherit methods where syntax is compatible. As of the 2026-07 refactors, many cross-OS dialects that used to be method overrides are now **data-driven** on the shared `IOSParser` base (pattern-sets / lookup tables) rather than forked methods; see the per-OS docs (`{IOS,IOSXR,NXOS,EOS,JUNOS,PANOS}_PARSER_SUPPORT.md`) for details.

**Last Updated:** July 29, 2026

---

## OS Type Support Summary

Override counts below are `parse_*` interface methods natively defined on each
subclass (measured from source). Many dialects that used to be method overrides
on EOS/IOS-XR/NX-OS are now **data-driven** on the shared `IOSParser` base
(pattern-sets / lookup tables), so the raw override count understates how much
each OS actually customizes — see the per-parser docs for the data-driven
extensions.

| OS Type | Parser Class | Inherits From | `parse_*` Overrides | Status |
|---------|-------------|---------------|----------------|--------|
| **Cisco IOS / IOS-XE** | `IOSParser` | `BaseParser` | 40 implemented (reference) | ✅ Reference implementation |
| **Arista EOS** | `EOSParser` | `IOSParser` | 13 overrides (+ data-driven dialects) | ✅ Complete |
| **Cisco IOS-XR** | `IOSXRParser` | `IOSParser` | 16 overrides | ✅ Complete |
| **Cisco NX-OS** | `NXOSParser` | `IOSParser` | 17 overrides | ✅ Complete |
| **Juniper JunOS** | `JunOSParser` | `BaseParser` | 13 methods | ✅ Core protocols |
| **Palo Alto PAN-OS** | `PANOSParser` | `BaseParser` | 11 methods | ✅ Security + routing surface |

**Legend for protocol tables below:**
- ✅ = Native override for this platform's syntax
- ✅ (inherited) = Uses IOSParser implementation (works for platforms with compatible flat syntax)
- ⚠️ = Partial / indirect support (see the adjacent note)
- ❌ = Not implemented (returns empty)

---

## Protocol Support by OS Type

### Core Routing Protocols

| Protocol | IOS/IOS-XE | EOS | IOS-XR | NX-OS | JunOS | PAN-OS |
|----------|------------|-----|--------|-------|-------|--------|
| **BGP** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **OSPF** | ✅ | ✅ (inherited) | ✅ | ✅ | ✅ | ✅ |
| **IS-IS** | ✅ | ✅ | ✅ | ✅ (inherited) | ❌ | ❌ |
| **EIGRP** | ✅ | ✅ (inherited) | ✅ (inherited) | ✅ (inherited) | ❌ | ❌ |
| **RIP** | ✅ | ✅ (inherited) | ✅ (inherited) | ✅ (inherited) | ❌ | ❌ |
| **Static Routes** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

Notes:
- NX-OS BGP override handles `template peer` / `inherit peer` syntax
- **Per-address-family neighbor descent:** NX-OS (CCR-0077) and IOS-XR now build a `BGPNeighborAF` per `address-family <afi> <safi>` sub-block under a neighbor (route-map/prefix-list in/out, next-hop-self, send-community, maximum-prefix, default-originate). A dual-stack neighbor's IPv6 policy no longer clobbers its IPv4 policy; any afi/safi (incl. `l2vpn evpn`, `vpnv4`) is descended.
- **VRF-scoped BGP neighbor AF policy:** IOS-XR (CCR-0115) and EOS (CCR-0115) now fire the same per-neighbor AF-policy hook inside `vrf NAME` blocks that the global instance uses, so VRF `address-family` neighbor policies are captured (previously dropped while the identical global block parsed).
- **EOS VRF flat parity (CCR-0114):** VRF-scoped flat `network` / `aggregate-address` lines reach parity with the global instance path.
- **`neighbor default-originate` (CCR-0078)** parsed on NX-OS (per-AF) and across the Cisco family.
- IOS-XR BGP is a native override (block-style `neighbor X` / `remote-as Y`, `neighbor-group` / `use neighbor-group`, `route-policy` per-AF); EOS BGP is mostly the shared `IOSParser` walk plus data (`peer group` / `maximum-routes` aliases, `bestpath tie-break router-id`) and two thin overrides.
- IOS-XR OSPF override handles hierarchical `router ospf` → `area` → `interface` nesting
- EOS IS-IS is now data-driven on the shared walk (`isis enable <tag>` membership, `isis passive`); IOS-XR IS-IS override handles per-interface config nested under `router isis` (AF-transparent descent)
- **JunOS BGP:** unified brace/set parsing (both device-emitted forms fold to one canonical tree), three-level `bgp`→`group`→`neighbor` attribute inheritance, and `groups` / `apply-groups` expansion during parse
- **PAN-OS routing surface:** BGP peer-groups / redistribution (via redist-profiles) / OSPF / source-NAT, plus the BGP-over-IPSec-tunnel dependency chain (update-source → tunnel → physical egress → IKE gateway, CCR-0116)

### Infrastructure

| Protocol | IOS/IOS-XE | EOS | IOS-XR | NX-OS | JunOS | PAN-OS |
|----------|------------|-----|--------|-------|-------|--------|
| **VRF** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Interfaces** | ✅ | ✅ (inherited) | ✅ | ✅ | ✅ | ✅ |
| **Route-Maps** | ✅ | ✅ (inherited) | ✅ | ✅ (inherited) | ✅ | ✅ |
| **Prefix-Lists** | ✅ | ✅ | ✅ | ✅ (inherited) | ✅ | ❌ |

Notes:
- EOS VRF uses `vrf instance` syntax (now parsed via shared walk; RD/RT back-filled from the `router bgp` VRF block); IOS-XR uses `vrf NAME`; NX-OS uses `vrf context`; JunOS uses `routing-instances`; PAN-OS uses `<virtual-router>`
- IOS-XR route-maps override handles `route-policy` → `RouteMapConfig`; JunOS maps `policy-statement`/`term`; PAN-OS normalizes each `<bgp><policy><import|export>` rule into a single-sequence `RouteMapConfig` (policy node)
- IOS-XR prefix-lists override handles `prefix-set` syntax; JunOS handles `policy-options prefix-list`; PAN-OS has no named prefix-list object (`parse_prefix_lists()` returns `[]` — policy prefixes are inline)

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
- **NX-OS ACLs (CCR-0086):** the shared-base `parse_acls()` now reads IPv4 / IPv6 / MAC access-lists (`ACLConfig.family`), `object-group` blocks (`parse_object_groups()` → `ParsedConfig.object_groups`), `addrgroup` / `portgroup` references in ACEs (`ACLEntry.source_group` / `destination_group`), and standalone `remark` entries — all inherited by NX-OS unchanged. NX-OS ACLs are therefore still `✅ (inherited)`, but now with multi-family + object-group coverage.
- **JunOS ACLs:** improved firewall-filter parsing — `firewall { filter … }` and `firewall { family F { filter … } }`, per-term action and address/protocol/port match conditions
- **Object-groups** are a distinct construct (no dedicated matrix row): parsed by the shared `parse_object_groups()` for the IOS family (IOS / EOS / IOS-XR / NX-OS)

### Data Center / Overlay

| Protocol | IOS/IOS-XE | EOS | IOS-XR | NX-OS | JunOS | PAN-OS |
|----------|------------|-----|--------|-------|-------|--------|
| **VXLAN (data-plane)** | ❌ | ✅ | ❌ | ✅ | ❌ | ❌ |
| **EVPN control-plane (L2VNI/L3VNI RD+RT)** | ❌ | ⚠️ (RT via BGP-VRF) | ❌ | ✅ | ❌ | ❌ |
| **VPC / MLAG** | ❌ | ✅ (MLAG) | ❌ | ✅ (VPC) | ❌ | ❌ |
| **VLANs** | ✅ | ✅ (inherited) | ✅ (inherited) | ✅ (inherited) | ❌ | ❌ |
| **VTP** | ✅ | ✅ (inherited) | ✅ (inherited) | ✅ (inherited) | ❌ | ❌ |
| **STP** | ✅ | ✅ (inherited) | ✅ (inherited) | ✅ (inherited) | ❌ | ❌ |

Notes:
- EOS VXLAN parsed from `interface Vxlan1` block (source-interface, VNI mappings, flood VTEPs)
- **NX-OS VXLAN** parsed from `interface nve1` block, now including per-VNI **ingress-replication mode** (`ingress-replication protocol bgp` → `VXLANVniMapping.ingress_replication`, plus static head-end `peer-ip` peers) and L3VNI `associate-vrf` (CCR-0087)
- **NX-OS EVPN control-plane (CCR-0087 / CCR-0118)** is modeled separately from the VXLAN data-plane, in a dedicated `EVPNConfig`: **L2VNI** (`evpn` block → `vni <n> l2` with rd + route-target import/export) and **L3VNI** (`vrf context` rd + `route-target … evpn` per-AF + the NVE `member vni … associate-vrf` binding). The L2VNI form is device-verified; the L3VNI `vrf context` form is doc-grounded (Nexus 9000 VXLAN Config Guide 10.5(x)).
- EOS carries EVPN route-targets on the VRF (read from `router bgp` → `vrf` and back-filled) but has **no** dedicated EVPN control-plane model — hence `⚠️`.
- EOS MLAG (`mlag configuration`) maps to `VPCConfig` (domain-id is string, not int)
- NX-OS VPC parsed from `vpc domain` block + `vpc peer-link` on interfaces (incl. `peer-gateway`, CCR-0075)

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
- EOS/NX-OS inherit IOS flat-syntax multicast parsing via `_BASE_KNOWN_PATTERNS` (EOS also has a block-form override merged with flat lines)
- **NX-OS PIM (CCR-0085):** the inherited walk now parses `ip pim anycast-rp`, `spt-threshold`, and `rp-address … group-list <prefix>` forms

### Management & Monitoring

| Protocol | IOS/IOS-XE | EOS | IOS-XR | NX-OS | JunOS | PAN-OS |
|----------|------------|-----|--------|-------|-------|--------|
| **NTP** | ✅ | ✅ (inherited) | ✅ | ✅ | ✅ | ❌ |
| **SNMP** | ✅ | ✅ (inherited) | ✅ (inherited) | ✅ (inherited) | ✅ | ❌ |
| **Syslog** | ✅ | ✅ (inherited) | ✅ (inherited) | ✅ | ✅ | ❌ |
| **BFD** | ✅ | ✅ | ✅ | ✅ (inherited) | ❌ | ❌ |
| **NetFlow** | ✅ | ✅ (inherited) | ✅ (inherited) | ✅ | ❌ | ❌ |
| **LLDP** | ✅ | ✅ (inherited) | ✅ (inherited) | ✅ | ❌ | ❌ |
| **CDP** | ✅ | ✅ (inherited) | ✅ (inherited) | ✅ | ❌ | ❌ |

Notes:
- IOS-XR NTP override handles hierarchical `ntp` block
- NX-OS NTP override handles flat `ntp server` with `use-vrf` keyword
- NX-OS syslog override handles `logging server` with VRF and facility
- EOS BFD override handles EOS-specific `bfd` block syntax
- **NX-OS NetFlow (CCR-0094)** is now a native override — Flexible NetFlow `flow record` / `flow exporter` / `flow monitor` blocks → `NetFlowConfig`, plus per-interface `ip flow monitor` bindings. Doc-grounded (syntax-corpus), not yet hardware-captured.
- **NX-OS IP SLA (CCR-0091):** operation `frequency` and trailing destination `port` now populated (still inherited, see Operational section)
- **EOS management-line config:** `management ssh | console | telnet` blocks with `idle-timeout` join the shared line walk (console→CONSOLE, ssh/telnet→VTY) — see Operational / Line Config

### Security & AAA

| Protocol | IOS/IOS-XE | EOS | IOS-XR | NX-OS | JunOS | PAN-OS |
|----------|------------|-----|--------|-------|-------|--------|
| **AAA** | ✅ | ✅ (inherited) | ✅ (inherited) | ✅ | ❌ | ❌ |
| **NAT** | ✅ | ✅ (inherited) | ✅ (inherited) | ✅ (inherited) | ❌ | ✅ |
| **Crypto/IPsec** | ✅ | ✅ (inherited) | ✅ (inherited) | ✅ (inherited) | ❌ | ✅ |
| **Security Zones** | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |

Notes:
- AAA parses authentication/authorization/accounting method-lists, TACACS+/RADIUS servers (NX-OS override parses `aaa group server` child `server` members)
- PAN-OS zones parsed from XML `vsys` → `zone` elements
- **PAN-OS NAT** models both destination-NAT (`NATStaticEntry`) and source NAT — static, dynamic, and PAT (`NATDynamicEntry`), with the source address set materialized as a `nat-source-{rule}` ACL so the reference resolves.
- **PAN-OS crypto** models IKE crypto profiles, IPsec profiles, and IKE gateways (Phase-1 profile read from the nested `protocol/ikev{1,2}/ike-crypto-profile` shape, CCR-0116), feeding the BGP-over-IPSec tunnel-underlay chain.

### Services

| Protocol | IOS/IOS-XE | EOS | IOS-XR | NX-OS | JunOS | PAN-OS |
|----------|------------|-----|--------|-------|-------|--------|
| **DNS** | ✅ | ✅ | ✅ (inherited) | ✅ | ❌ | ❌ |
| **DHCP** | ✅ | ✅ (inherited) | ✅ | ✅ (inherited) | ❌ | ❌ |

Notes:
- **EOS DNS override** merges per-`vrf instance` DNS entries with global DNS.
- **NX-OS DNS** is *not* overridden — the inherited `parse_dns()` handles global resolvers incl. the hyphenated `ip domain-list` (CCR-0117); per-`vrf context` DNS (name-servers / domain-name / domain-list) is attributed onto the VRF inside `parse_vrfs()` (CCR-0093), not flattened into global DNS.
- **NX-OS DHCP** pools stay inherited; per-interface `ip dhcp relay address <ip>` (the NX-OS analogue of `ip helper-address`) is parsed onto `InterfaceConfig.dhcp_relay_addresses` (CCR-0090) — an interface field, see High Availability / Interface-Level.

### High Availability (Interface-Level)

| Protocol | IOS/IOS-XE | EOS | IOS-XR | NX-OS | JunOS | PAN-OS |
|----------|------------|-----|--------|-------|-------|--------|
| **HSRP** | ✅ | ✅ (inherited) | ✅ (inherited) | ✅ | ❌ | ❌ |
| **VRRP** | ✅ | ✅ (inherited) | ✅ (inherited) | ✅ | ❌ | ❌ |
| **LACP** | ✅ | ✅ (inherited) | ✅ (inherited) | ✅ (inherited) | ❌ | ❌ |

Notes:
- HSRP/VRRP parsed as part of interface config (InterfaceConfig fields)
- LACP system-priority parsed globally; per-interface channel-group and min-links on InterfaceConfig
- **NX-OS HSRP/VRRP (CCR-0088)** are native overrides: NX-OS emits indented `hsrp <N>` / `vrrp <N>` sub-blocks (collected alongside the flat IOS `standby`/`vrrp` forms), plus **VRRPv3 address-family groups** (`vrrpv3 <grp> address-family {ipv4|ipv6}` → `VRRPGroup` version 3) and `advertisement-interval`.
- **NX-OS storm-control (CCR-0092):** `storm-control {broadcast|multicast|unicast} level [pps|bps] <threshold>` → `InterfaceConfig.storm_control`.
- **NX-OS per-interface DHCP relay (CCR-0090):** `ip dhcp relay address <ip>` → `InterfaceConfig.dhcp_relay_addresses`.
- EOS VARP anycast-gateway (`ip virtual-router address`) → `InterfaceConfig.varp_addresses`.
- JunOS and PAN-OS do not model FHRP (HSRP/VRRP).

### Operational / Automation

| Protocol | IOS/IOS-XE | EOS | IOS-XR | NX-OS | JunOS | PAN-OS |
|----------|------------|-----|--------|-------|-------|--------|
| **IP SLA** | ✅ | ✅ (inherited) | ✅ (inherited) | ✅ (inherited) | ❌ | ❌ |
| **EEM** | ✅ | ✅ (inherited) | ✅ (inherited) | ✅ (inherited) | ❌ | ❌ |
| **Object Tracking** | ✅ | ✅ (inherited) | ✅ (inherited) | ✅ (inherited) | ❌ | ❌ |
| **Banners** | ✅ | ✅ (inherited) | ✅ (inherited) | ✅ (inherited) | ❌ | ❌ |
| **Line Config** | ✅ | ✅ (see note) | ✅ (see note) | ✅ | ❌ | ❌ |
| **Change-IR / deletions (op-primary)** | ✅ | ✅ | derived-string | ✅ | n/a | n/a |

Notes:
- IP SLA `frequency` and destination `port` are populated on NX-OS (CCR-0091) via the inherited walk.
- **Line Config** is a single shared line walk keyed off `_LINE_HEADER_PATTERNS`. IOS-XR adds `line default` / `line console` / `line template NAME` headers; EOS has no numbered `line vty` — its `management ssh | console | telnet` blocks (`idle-timeout` child) join the same walk (console→CONSOLE line, ssh/telnet→VTY); NX-OS adds the bare `line vty` / `line console` header.
- **Op-primary vs derived (CCR-0110):** IOS, NX-OS, and EOS are **op-primary** — every removal/negation is a native `ChangeOp` on `ParsedConfig.change_ops`, and their legacy `no_commands` string channels are now empty (except three residual derived-only `ParsedConfig` tombstones: the whole-process `no router bgp` and the two OSPF area-type resets). IOS-XR, JunOS, and PAN-OS are **not** op-primary: IOS-XR still emits **derived tombstone strings** for its section/singleton removals (comms singletons `singleton:ntp` / `singleton:dns` stay string-only), while JunOS and PAN-OS do not process deletion/`no` semantics at all.

### QoS

| Protocol | IOS/IOS-XE | EOS | IOS-XR | NX-OS | JunOS | PAN-OS |
|----------|------------|-----|--------|-------|-------|--------|
| **Class-Maps** | ✅ | ✅ (inherited) | ✅ (inherited) | ✅ (inherited) | ❌ | ❌ |
| **Policy-Maps** | ✅ | ✅ (inherited) | ✅ (inherited) | ✅ (inherited) | ❌ | ❌ |
| **CoPP (control-plane binding)** | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ |

Notes:
- **Typed maps + police units are a shared-base change (CCR-0089 / CCR-0119):** `class-map type <qualifier> <NAME>` / `policy-map type <qualifier> <NAME>` now capture the real name (qualifier retained on `ClassMapConfig.type` / `PolicyMapConfig.type`), and `police cir <n> {pps|kbps|mbps|gbps|bps} [bc <n> [packets|bytes|ms]]` is parsed with `rate_unit` / `burst_unit`. Because this lives in the base, IOS and EOS benefit for typed maps / police units too; the legacy bare `police <bps>` form is unchanged.
- **NX-OS CoPP (native override):** the `control-plane` block's `service-policy input <PM>` → `ParsedConfig.control_plane` (`ControlPlaneConfig.service_policy_input`), via `parse_control_plane()`. The policed traffic lives in the referenced `policy-map type control-plane`.

---

## Data Model Coverage

All models live in `confgraph/models/` and use Pydantic.

| Model | File | Used By |
|-------|------|---------|
| `BaseConfigObject` | `base.py` | All parsers |
| `OSType` | `base.py` | All parsers |
| `ParsedConfig` | `parsed_config.py` | All parsers (now incl. `object_groups`, `control_plane`, `evpn`, and the native `change_ops` op stream) |
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
| `EVPNConfig` | `evpn.py` | NX-OS (L2VNI + L3VNI RD/RT) |
| `VPCConfig` | `vpc.py` | EOS (MLAG), NX-OS (VPC) |
| `AAAConfig` | `aaa.py` | IOS, EOS, IOS-XR, NX-OS |
| `NTPConfig` | `ntp.py` | IOS, EOS, IOS-XR, NX-OS, JunOS |
| `SNMPConfig` | `snmp.py` | IOS, EOS, IOS-XR, NX-OS, JunOS |
| `SyslogConfig` | `logging_config.py` | IOS, EOS, IOS-XR, NX-OS, JunOS |
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
| `IPSLAOperation` | `ipsla.py` | IOS, EOS, IOS-XR, NX-OS |
| `EEMApplet` | `eem.py` | IOS, EOS, IOS-XR, NX-OS |
| `ObjectTrack` | `object_tracking.py` | IOS, EOS, IOS-XR, NX-OS |
| `ObjectGroup` | `object_group.py` | IOS, EOS, IOS-XR, NX-OS |
| `ClassMapConfig` / `PolicyMapConfig` | `qos.py` | IOS, EOS, IOS-XR, NX-OS |
| `ControlPlaneConfig` | `qos.py` | NX-OS (CoPP service-policy binding) |

---

## Simulation Coverage (confgraph-entrp)

The simulation engine in `confgraph-entrp` provides service-level impact assessment for configuration changes. Not all parsed protocols have simulation support.

> ⚠️ This table references the separate `confgraph-entrp` repo and was not re-verified in this update; it may be out of date — verify separately.

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

> ⚠️ The specific test-file list and the total count below were not re-verified in this update (the suite has grown substantially with the 2026-07 parser work); treat the count as a lower bound and verify separately.

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

**Total: 429 tests passing** (confgraph repo)

---

## Architecture

### Parser Inheritance

```
BaseParser (ABC) ─── abstract parse_* interface
├── IOSParser ─────── 40 parse_* implemented (reference parser; owns shared VRF/OSPF/line
│   │                 walks, cross-version dialects, typed class/policy-map + CoPP police units,
│   │                 object-groups, multi-family ACLs)
│   ├── EOSParser ─── 13 parse_* overrides (interfaces, prefix-lists, static-routes, ACLs,
│   │                 community-lists, BFD, DNS, multicast, VXLAN, MPLS, MLAG, deletion-commands,
│   │                 + thin BGP-VRF hooks). VRF / IS-IS / BGP-neighbor / lines now data-driven.
│   ├── IOSXRParser ─ 16 parse_* overrides (VRF, interfaces, OSPF, route-maps/policies,
│   │                 prefix-sets, ACLs, community-sets, IS-IS, static-routes, multicast, MPLS,
│   │                 NTP, BFD, DHCP, BGP, deletion-commands). No parse() override — back-fills shared.
│   └── NXOSParser ── 17 parse_* overrides (VRF, interfaces, BGP, OSPF, static-routes, NTP,
│                     syslog, VXLAN, EVPN, VPC, control-plane/CoPP, NetFlow, MPLS, LLDP, CDP, AAA,
│                     deletion-commands). DNS/ACLs/object-groups/QoS-maps inherited.
├── JunOSParser ───── 13 parse_* methods (custom brace/set tokenizer + apply-groups expansion;
│                     core routing + management; no CiscoConfParse)
└── PANOSParser ───── 11 parse_* methods (XML; routing + BGP policy/route-maps + NAT +
                      security/zones/crypto; local-firewall & Panorama layouts)
```

### File Locations

```
confgraph/
├── models/                    # Pydantic data models
│   ├── base.py               # OSType enum, BaseConfigObject
│   ├── parsed_config.py      # ParsedConfig (data fields + native change_ops stream)
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
│   ├── vxlan.py              # VXLAN data-plane (VTEP / VNI mappings)
│   ├── evpn.py               # MP-BGP EVPN control-plane (L2VNI/L3VNI RD+RT) — NX-OS
│   ├── vpc.py                # VPC/MLAG
│   ├── vlan.py               # VTP + VLAN entries
│   ├── aaa.py                # AAA
│   ├── ntp.py                # NTP
│   ├── snmp.py               # SNMP
│   ├── logging_config.py     # Syslog (SyslogConfig)
│   ├── bfd.py                # BFD
│   ├── dns.py                # DNS
│   ├── dhcp.py               # DHCP
│   ├── lldp.py               # LLDP
│   ├── cdp.py                # CDP
│   ├── stp.py                # Spanning-tree
│   ├── netflow.py            # NetFlow (record/exporter/monitor)
│   ├── nat.py                # NAT
│   ├── crypto.py             # Crypto/IPsec
│   ├── qos.py                # Class-map / policy-map / CoPP ControlPlaneConfig
│   ├── object_group.py       # Object-groups (addr/port)
│   ├── rip.py                # RIP
│   ├── eigrp.py              # EIGRP
│   ├── line.py               # Line / session config
│   ├── panos_zone.py         # PAN-OS security zones
│   ├── ipsla.py              # IP SLA
│   ├── eem.py                # EEM applets
│   ├── object_tracking.py    # Object tracking
│   └── topology.py           # Cross-device topology
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
