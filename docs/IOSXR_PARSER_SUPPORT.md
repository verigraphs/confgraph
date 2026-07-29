# Cisco IOS-XR Parser Support Documentation

## Overview

The IOS-XR parser (`confgraph.parsers.iosxr_parser.IOSXRParser`) parses Cisco IOS-XR device configurations. It inherits from `IOSParser` and overrides methods extensively where IOS-XR syntax diverges from IOS, including VRFs, interfaces, BGP, OSPF, IS-IS, ACLs, static routes, multicast, MPLS/LDP, NTP, BFD, DHCP, and all policy constructs.

**Class:** `confgraph.parsers.iosxr_parser.IOSXRParser`
**Inherits from:** `IOSParser`
**CiscoConfParse syntax:** `iosxr`
**OSType:** `OSType.IOS_XR` ("ios_xr")

---

## Key Syntax Differences from IOS

| Feature | IOS | IOS-XR |
| ------- | --- | ------ |
| VRF definition | `vrf definition NAME` | `vrf NAME` (no keyword) |
| VRF route-targets | inline children | multi-line under `import/export route-target` stanzas |
| Interface VRF | `vrf forwarding NAME` | `vrf NAME` (no keyword) |
| IP address | `ip address X MASK` | `ipv4 address X MASK` |
| Interface ACL | `ip access-group NAME in\|out` | `ipv4 access-group NAME ingress\|egress` |
| ACL definition | `ip access-list standard\|extended NAME` | `ipv4 access-list NAME` / `ipv6 access-list NAME` |
| Static routes | `ip route PREFIX MASK NEXTHOP` | `router static` block with nested `address-family` and optional `vrf` sub-blocks |
| BGP neighbor syntax | `neighbor X remote-as Y` (flat) | `neighbor X\n  remote-as Y` (block-style) |
| BGP peer templates | `neighbor X peer-group NAME` | `neighbor-group NAME` / `use neighbor-group NAME` |
| BGP neighbor policies | flat AF block per neighbor | `route-policy NAME in/out` inside neighbor's `address-family` sub-block |
| VRF BGP | `address-family ipv4 vrf NAME` | `vrf NAME` block under router bgp |
| Route-maps | `route-map NAME permit N` | `route-policy NAME` ... `end-policy` |
| Prefix-lists | `ip prefix-list NAME seq N` | `prefix-set NAME` ... `end-set` (comma-separated) |
| AS-path lists | `ip as-path access-list NAME` | `as-path-set NAME` ... `end-set` |
| Community lists | `ip community-list` | `community-set NAME` ... `end-set` |
| Extended communities | `ip extcommunity-list` | `extcommunity-set rt NAME` ... `end-set` |
| OSPF interface membership | `ip ospf PROC area AREA` on interface | nested under `area N` → `interface NAME` in OSPF block |
| Multicast RP / SSM | flat `ip pim rp-address` / `ip pim ssm` | `router pim` with nested `address-family ipv4` block; separate `multicast-routing` block |
| IS-IS interface | `ip router isis` on interface | `interface NAME` nested under `router isis`; metric inside `address-family ipv4 unicast` sub-block |
| MPLS / LDP | flat `mpls ip` + `mpls ldp` | hierarchical `mpls ldp` block with interfaces as children |
| NTP | flat `ntp server …` | hierarchical `ntp` block (server/peer/auth nested) |

---

## Configuration Syntax Support

### 1. VRF Configuration

**Syntax:**

```text
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

**Note:** IOS-XR commonly declares RD (and route-targets) under `router bgp / vrf NAME`, not in the `vrf NAME` definition — so `parse_vrfs()` sets `VRFConfig.rd = None`. The RD and route-targets are read onto `BGPConfig` by `_parse_bgp_vrf_blocks()` and then attributed onto the matching `VRFConfig` by the **shared** `BaseParser._backfill_vrf_rd_rt()` walk (CCR-0059), which runs during `BaseParser.parse()`. There is **no** IOS-XR `parse()` override anymore — the former per-OS RD back-fill (old "X6") was removed in favor of that one shared, model-driven walk.

**Parsing Status:** ✅ Overridden — `parse_vrfs()` handles `vrf NAME` with nested `import/export route-target` blocks and `import/export route-policy`; RD/RT back-fill from BGP VRF blocks is the shared `BaseParser._backfill_vrf_rd_rt()`

---

### 2. Interface Configuration

**Syntax:**

```text
interface <type><number>
  description <text>
  vrf <vrf-name>
  ipv4 address <address> <mask>
  ipv6 address <address>/<prefix-length>
  ipv4 access-group <acl-name> ingress
  ipv4 access-group <acl-name> egress
  shutdown
```

**IOS-XR-Specific Differences:**

- **VRF:** `vrf NAME` (no `forwarding` keyword)
- **IP address:** `ipv4 address X MASK` instead of `ip address X MASK`
- **Interface ACL:** `ipv4 access-group NAME ingress|egress` instead of `ip access-group NAME in|out`
- OSPF interface membership is declared inside the OSPF block (not on the interface)

**Supported Attributes:**

- All standard interface attributes (name, description, shutdown)
- IPv4/IPv6 addresses
- VRF membership
- ACL in/out (`acl_in`, `acl_out` populated from `ipv4 access-group`)

**Parsing Status:** ✅ Overridden — `parse_interfaces()` handles `ipv4 address X MASK`, `vrf NAME`, and `ipv4 access-group NAME ingress|egress`

---

### 3. BGP Configuration

**Syntax:**

```text
router bgp <asn>
  bgp router-id <router-id>
  neighbor-group <name>
    remote-as <asn>
    update-source <interface>
  neighbor <ip>
    remote-as <asn>
    description <text>
    use neighbor-group <name>
    address-family ipv4 unicast
      route-policy <name> in
      route-policy <name> out
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

- Neighbor definitions use block syntax (`neighbor X\n  remote-as Y`) rather than flat `neighbor X remote-as Y`
- Peer templates use `neighbor-group NAME` / `use neighbor-group NAME`
- Route-policy assignments are inside each neighbor's `address-family` sub-block
- VRF BGP as `vrf NAME` block under `router bgp`

**Supported Attributes:**

- Block-style neighbor parsing (`_parse_iosxr_neighbor_block`, the single source of truth for both global and VRF neighbors). Neighbor-level fields: `remote-as`, `description`, `update-source`, `ebgp-multihop`, `password`, `shutdown`, `fall-over bfd`, `local-as` (+ `no-prepend` / `replace-as`), `timers`, `use neighbor-group`, and neighbor-level `route-policy … in/out`, `prefix-set … in/out`, `next-hop-self`, `route-reflector-client`, `send-community[-ebgp/both/extended]`
- Per-neighbor address-family policies → `BGPNeighborAF` (`_parse_iosxr_neighbor_af_block`): `route-policy in/out`, `prefix-set in/out`, `next-hop-self`, `route-reflector-client`, `send-community`, `default-originate` (+ conditional `route-policy`), `maximum-prefix` (limit / threshold / `warning-only`)
- Global address-families (`_parse_bgp_address_families`) descend into the `address-family <afi> unicast` block for `network`, `redistribute`, and `aggregate-address` statements (IOS-XR spells these with `route-policy`), plus `maximum-paths ebgp N` / `maximum-paths ibgp N`
- Neighbor-groups (equivalent to IOS peer-groups)
- VRF BGP instances: block-style VRF neighbors with **field-identical** per-AF policies to the global path, plus VRF RD, route-targets, redistribute, and network statements read from the `vrf NAME` block

**Note (CCR-0115):** A VRF neighbor's `address-family <afi> <safi>` sub-block now populates `BGPNeighbor.address_families` exactly as the global path does. Both paths call the same `_apply_bgp_af_neighbor_policies()` hook (fired for the VRF block by the shared `_parse_bgp_vrf_blocks()`); previously the VRF path re-implemented neighbor parsing and dropped the entire per-AF policy while the identical global block parsed correctly.

**Note:** `_parse_iosxr_neighbor_block` uses `.children` (direct children only) when collecting neighbor-level assignments so AF-level attributes don't flatten onto the neighbor; per-AF policies are handled separately by `_apply_bgp_af_neighbor_policies` (which reads each AF sub-block, scoped to that block, preventing cross-AF last-wins flattening).

**Parsing Status:**

- ✅ Overridden — `_parse_bgp_neighbors()` handles block-style neighbor syntax (delegates to `_parse_iosxr_neighbor_block`)
- ✅ Overridden — `_apply_bgp_af_neighbor_policies()` builds `BGPNeighborAF` entries from per-neighbor AF sub-blocks; fired for **both** the global instance and each VRF block
- ✅ Overridden — `_parse_bgp_peer_groups()` handles `neighbor-group NAME` blocks
- ✅ Overridden — `_parse_bgp_address_families()` handles `address-family <afi> unicast` descent + `maximum-paths ebgp/ibgp N`
- ✅ Overridden — `_parse_bgp_vrf_instances()` delegates to the shared `_parse_bgp_vrf_blocks()` (CCR-0032/0112/0115)

---

### 4. OSPF Configuration

**Syntax:**

```text
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
- Passive interfaces are indicated by `passive enable` inside the interface stanza
- Redistribution uses `route-policy` instead of `route-map`

**Supported Attributes:**

- Process ID, router-id
- Areas with nested interface assignments
- Area types (stub, NSSA)
- Passive interfaces (detected via `passive enable` within interface stanza)
- Redistribution with route-policy

**Note:** Because IOS-XR declares interface→area membership (and its per-interface cost, network type, BFD, etc.) inside the OSPF block, `_parse_ospf_areas_iosxr()` records each `area N > interface NAME` body onto `OSPFArea.interface_settings` (`OSPFInterfaceConfig`). Those settings are attributed back onto the interfaces by the **shared** `BaseParser._backfill_ospf_interface_settings()` walk (CCR-0038 Theme 2), which runs during `BaseParser.parse()`. There is **no** IOS-XR `parse()` override anymore — the former per-OS membership-only back-fill (old "X4") was removed because it carried only area membership and never the deeper interface settings; all OSes now run through the one shared walk.

**Parsing Status:** ✅ Overridden — `parse_ospf()` and `_parse_ospf_areas_iosxr()` handle area-nested interface blocks, `passive enable` detection, and populate `OSPFArea.interface_settings`; interface attribution is the shared `BaseParser._backfill_ospf_interface_settings()`

---

### 5. Route-Maps (Route-Policies)

**Syntax:**

```text
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

**Note:** IOS-XR route-policy bodies use an if/then/else language. The parser performs best-effort extraction sufficient for dependency graph analysis (identifying referenced prefix-sets and communities). The full policy body is preserved in `raw_lines`.

**Parsing Status:** ✅ Overridden — `parse_route_maps()` maps `route-policy`/`end-policy` blocks to `RouteMapConfig`

---

### 6. Prefix-Lists (Prefix-Sets)

**Syntax:**

```text
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

```text
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

### 8. Community Lists (Community-Sets and Extcommunity-Sets)

**Syntax:**

```text
community-set <name>
  65000:100,
  65000:200
end-set

extcommunity-set rt <name>
  65000:1,
  65000:2
end-set
```

**IOS-XR-Specific Differences:**

- `community-set NAME` / `end-set` blocks replace IOS `ip community-list`
- `extcommunity-set rt NAME` / `end-set` blocks capture extended communities used as route-targets; stored as `CommunityListConfig` with `list_type="extended"`

**Parsing Status:** ✅ Overridden — `parse_community_lists()` maps both `community-set`/`end-set` and `extcommunity-set rt`/`end-set` to `CommunityListConfig`

---

### 9. ACLs

**Syntax:**

```text
ipv4 access-list INBOUND-ISP1
 10 deny ipv4 any host 10.0.0.1
 20 permit ipv4 any any
!
ipv6 access-list INBOUND-V6
 10 permit ipv6 any any
```

**IOS-XR-Specific Differences:**

- `ipv4 access-list NAME` and `ipv6 access-list NAME` replace IOS `ip access-list standard|extended NAME`
- Both IPv4 and IPv6 ACL blocks are parsed

**Parsing Status:** ✅ Overridden — `parse_acls()` handles `ipv4 access-list` and `ipv6 access-list` blocks

---

### 10. Static Routes

**Syntax:**

```text
router static
 address-family ipv4 unicast
  0.0.0.0/0 192.168.1.1
  192.0.2.0/24 Null0 254
 !
 vrf CUST-A
  address-family ipv4 unicast
   0.0.0.0/0 10.0.0.2
```

**IOS-XR-Specific Differences:**

- All static routes are defined inside a `router static` block
- Routes are under `address-family ipv4 unicast` sub-blocks
- Per-VRF routes use a nested `vrf NAME` sub-block within `router static`

**Parsing Status:** ✅ Overridden — `parse_static_routes()` handles the `router static` block with nested `address-family` and `vrf` sub-blocks

---

### 11. Multicast

**Syntax:**

```text
router pim
 address-family ipv4
  rp-address 10.0.0.1
  ssm range RFC1918
!
multicast-routing
 address-family ipv4
```

**IOS-XR-Specific Differences:**

- RP addresses and SSM config are nested under `router pim` → `address-family ipv4` blocks
- `multicast-routing` is a separate top-level block (IOS uses flat `ip pim` statements)

**Parsing Status:** ✅ Overridden — `parse_multicast()` handles `router pim` with nested `address-family ipv4` blocks and the separate `multicast-routing` block

---

### 12. DHCP

**Syntax:**

```text
dhcp ipv4
  profile GUEST-POOL server
   pool
    network 192.168.100.0/24
    default-router 192.168.100.1
   helper-address vrf default 10.0.0.10
```

**IOS-XR-Specific Differences:**

- DHCP is configured under a `dhcp ipv4` block with named `profile` sub-blocks, not as `ip dhcp pool` (IOS)
- Helper-address entries are nested within profile blocks

**Supported Attributes:**

- Pool name (from profile block name)
- Helper addresses (extracted from `helper-address` lines within profile blocks)

**Parsing Status:** ✅ Overridden — `parse_dhcp()` handles `dhcp ipv4` profile blocks; the IOS `ip dhcp pool` path is not used

---

### 13. Deletion Commands

IOS-XR uses a different `no`-command vocabulary from IOS. `parse_deletion_commands()` is fully overridden and does **not** call `super()` — no IOS tombstone form is inherited. It emits **derived tombstone strings** into `BGPConfig.no_commands` / the parser's deletion channel (IOS-XR is deliberately kept on the derived string channel for its section/singleton removals; see the note below).

**IOS-XR tombstone forms (exactly what the code emits):**

| Command | Tombstone emitted |
| ------- | ----------------- |
| `no router ospf PROC` | `process:ospf:PROC` |
| `no router bgp ASN` | `process:bgp:ASN` |
| `no router isis [TAG]` | `process:isis:TAG` (empty tag → `process:isis:`) |
| `no router static` | `singleton:static_routes` |
| `no PREFIX NEXTHOP` inside `router static` → `address-family` (global) | `static::PREFIX` |
| `no PREFIX NEXTHOP` inside `router static` → `vrf NAME` → `address-family` | `static:NAME:PREFIX` |
| `no vrf NAME` | `vrf:NAME` (skips `definition`/`context`) |
| `no ipv4 access-list NAME` | `acl:NAME` |
| `no route-policy NAME` | `route-map:NAME` |
| `no prefix-set NAME` | `prefix-list:NAME` |
| `no router pim` | `singleton:multicast` |
| `no ntp` | `singleton:ntp` |
| `no domain name-server X` | `field:dns:name_server:X` |
| `no domain list X` | `field:dns:domain:X` |
| `no domain lookup` | `singleton:dns` |

**Interface field negations (native ChangeOps, not strings):** `no ipv4 access-group NAME ingress\|egress` is handled by `_detect_interface_field_negation_ops()`, which emits a native `UNSET` `ChangeOp` on `("field", "interface", NAME, "acl_in"|"acl_out")`. The caller regenerates the legacy tombstone from that op via `encode_legacy`. `service_policy` / NAT are not modeled on XR, so no negation is detected for them.

**Note:** IOS-XR is the one parser whose comms-singleton removals (`singleton:ntp` / `singleton:dns`) stay **derived** — `_singleton_section_gated()` returns `True` only for `ios_xr`, keeping those null-outs on the string channel with no native twin (CCR-0110 Phase 5). Community-set / extcommunity-set / as-path-set / SNMP / logging / BFD / flow / EIGRP / RIP removals are **not** emitted as tombstones by this parser.

**Parsing Status:** ✅ Overridden — `parse_deletion_commands()` maps the IOS-XR `no` forms above to tombstones; IOS tombstone logic is not called

---

### 14. IS-IS

**Syntax:**

```text
router isis CORE
 is-type level-2-only
 net 49.0001.0000.0000.0001.00
 address-family ipv4 unicast
  metric-style wide
 interface GigabitEthernet0/0/0/1
  address-family ipv4 unicast
   metric 20
  circuit-type level-2-only
 interface Loopback0
  passive
```

**IOS-XR-Specific Differences:**

- Per-interface IS-IS config is nested under the `router isis` block (not on the interface)
- Instance-level `metric-style` and per-interface `metric` are emitted one level deeper, inside an `address-family ipv4 unicast` sub-block
- `passive` is a bare keyword directly under the interface stanza

**Note (AF-transparent descent, CCR-0046):** IOS-XR nests an object's own attributes inside an `address-family ipv4 unicast` sub-block, one level deeper than the rest of the Cisco family. `_AFTransparentBlock` / `_nested_block()` provide a read-through view that hoists **only** the `ipv4 unicast` AF's children alongside the block's direct children, so the direct-child extractors (`metric_style`, per-interface `metric`) see through it. Only IPv4 unicast is spliced (the model's IS-IS fields carry no address-family dimension); an IPv6-only value is left `None` rather than mis-attributed. The view is deliberately **not** applied to BGP neighbor AF blocks, where the AF is a real `BGPNeighborAF` object.

**Parsing Status:** ✅ Overridden — `parse_isis()` reads instance config via `super().parse_isis()` and per-interface config via the AF-transparent view

---

### 15. MPLS / LDP

**Syntax:**

```text
mpls ldp
 router-id 10.0.0.1
 graceful-restart
 session protection
 interface GigabitEthernet0/0/0/0
```

**IOS-XR-Specific Differences:**

- LDP sub-commands are nested under a hierarchical `mpls ldp` block
- Interfaces are listed as children of `mpls ldp`; there is no per-interface `mpls ip` knob, so per-interface MPLS enablement is not extracted

**Supported Attributes:** LDP `router-id` (+ `force`), `graceful-restart`, `session protection`, `password`. `ldp_enabled` is `True` when a router-id is present.

**Parsing Status:** ✅ Overridden — `parse_mpls()` reads the hierarchical `mpls ldp` block. Segment Routing, MPLS-TE, and L2VPN are not parsed.

---

### 16. Extended Protocol Support

**IOS-XR-specific overrides** (syntax diverges from IOS):

| Protocol | Parsing Status |
| -------- | -------------- |
| NTP | ✅ Overridden — `parse_ntp()` reads the hierarchical `ntp` block (server/peer/`vrf`/auth-key/trusted-key/source/access-group/master/update-calendar); falls back to `super().parse_ntp()` for flat `ntp server …` configs |
| BFD | ✅ Overridden — `parse_bfd()` captures global `slow-timers` (hierarchical `bfd` block or flat `bfd slow-timers N`); per-interface BFD via `_parse_iface_bfd()` (`bfd fast-detect` / `minimum-interval` / `multiplier`; no `bfd-template` on XR) |
| DHCP | ✅ Overridden — see section 12 (`dhcp ipv4` profile blocks) |

**Inherited from IOSParser** (IOS-identical syntax in IOS-XR):

| Protocol | Parsing Status |
| -------- | -------------- |
| SNMP | ✅ Inherited from IOSParser |
| Syslog | ✅ Inherited from IOSParser |
| Banners | ✅ Inherited from IOSParser |
| Line configs (default/console/template) | ✅ Inherited body walk — XR-specific line headers added (`line default`, `line console`, `line template NAME`) |
| QoS (class-map/policy-map) | ✅ Inherited from IOSParser |
| IP SLA | ✅ Inherited from IOSParser |
| EEM Applets | ✅ Inherited from IOSParser |
| Object Tracking | ✅ Inherited from IOSParser |

See [IOS_PARSER_SUPPORT.md](IOS_PARSER_SUPPORT.md) for full syntax and attribute details.

---

## Overridden Methods Summary

> **No `parse()` override.** RD/RT and OSPF interface-setting back-fills run in the shared `BaseParser.parse()` via `_backfill_vrf_rd_rt()` (CCR-0059) and `_backfill_ospf_interface_settings()` (CCR-0038 Theme 2); the former per-OS back-fills were removed.

| Method | Reason for Override |
| ------ | ------------------- |
| `_nested_block()` / `_AFTransparentBlock` | AF-transparent read-through view — hoists `address-family ipv4 unicast` children so direct-child extractors see through XR's extra nesting level (CCR-0046) |
| `parse_vrfs()` | Handles `vrf NAME` with nested `import/export route-target` blocks and `import/export route-policy` |
| `_extract_interface_vrf()` | Handles `vrf NAME` (no `forwarding` keyword) |
| `parse_interfaces()` | Handles `ipv4 address X MASK` (+ secondary), `ipv6 address`, and `ipv4 access-group NAME ingress\|egress` |
| `_detect_interface_field_negation_ops()` | Emits native `UNSET` ChangeOps for `no ipv4 access-group … ingress\|egress` |
| `parse_acls()` | Handles `ipv4 access-list NAME` and `ipv6 access-list NAME` blocks |
| `parse_static_routes()` | Handles `router static` block with nested `address-family` and `vrf` sub-blocks (line grammar via `_parse_iosxr_static_route_line`) |
| `parse_dhcp()` | Handles `dhcp ipv4` profile blocks; does not use IOS `ip dhcp pool` path |
| `parse_deletion_commands()` | IOS-XR-specific tombstone forms; does not inherit IOS tombstone logic (no `super()`) |
| `_parse_bgp_neighbors()` | Block-style neighbor syntax; delegates to `_parse_iosxr_neighbor_block` |
| `_parse_iosxr_neighbor_block()` / `_parse_iosxr_neighbor_af_block()` | Single source of truth for XR neighbor and neighbor-AF field parsing |
| `_apply_bgp_af_neighbor_policies()` | Builds `BGPNeighborAF` from per-neighbor AF sub-blocks; fired for both global and VRF blocks (CCR-0115) |
| `_parse_bgp_peer_groups()` | Handles `neighbor-group NAME` blocks |
| `_parse_bgp_address_families()` | `address-family <afi> unicast` descent for network/redistribute/aggregate + `maximum-paths ebgp/ibgp N` |
| `_parse_bgp_vrf_instances()` | Delegates to shared `_parse_bgp_vrf_blocks()` (`vrf NAME` blocks, block-style neighbors) |
| `parse_ospf()` | Nested `area N > interface NAME` blocks; consumes passive-interface list from `_parse_ospf_areas_iosxr()`; also parses OSPF-VRF |
| `_parse_ospf_areas_iosxr()` | Area-nested interface blocks; `passive enable`; populates `OSPFArea.interface_settings` |
| `parse_route_maps()` | Maps `route-policy`/`end-policy` blocks (best-effort if/then/else) to `RouteMapConfig` |
| `parse_prefix_lists()` | Maps `prefix-set`/`end-set` comma-separated entries to `PrefixListConfig` |
| `parse_as_path_lists()` | Maps `as-path-set`/`end-set` to `ASPathListConfig` |
| `parse_community_lists()` | Maps `community-set`/`end-set` and `extcommunity-set rt`/`end-set` to `CommunityListConfig` (one entry per member) |
| `parse_multicast()` | Handles `router pim` nested AF blocks and separate `multicast-routing` block |
| `parse_isis()` | Per-interface IS-IS via the AF-transparent view |
| `parse_mpls()` | Hierarchical `mpls ldp` block |
| `parse_ntp()` | Hierarchical `ntp` block (falls back to flat IOS style) |
| `parse_bfd()` / `_parse_iface_bfd()` | Global `slow-timers`; per-interface `bfd fast-detect`/`minimum-interval`/`multiplier` |

---

## Parser Limitations

1. **Route-policy full semantics** — Complex if/then/else logic is best-effort; only `destination in PREFIX_SET` / `community matches-any` matches and `set` / `prepend as-path` clauses are extracted (full body preserved in `raw_lines`)
2. **IPv6 routing** — Limited IPv6 routing protocol coverage
3. **IOS-XR-specific features** — Segment Routing, MPLS-TE, and L2VPN are not parsed (`mpls ldp` is parsed; see section 15)
4. **IS-IS address-family** — Only IPv4-unicast IS-IS values are attributed; an IPv6-only `metric-style`/`metric` is left `None` rather than mis-attributed (the model carries no AF dimension for these fields)

---

## Testing and Validation

**Sample Configuration:** `samples/iosxr_test.cfg`

**Validated output (`confgraph info samples/iosxr_test.cfg --os iosxr`):**

```text
Hostname : XR-CORE-01
OS       : ios_xr
Interfaces         2
VRFs               1
BGP instances      2
OSPF instances     1
Route-maps         4
Prefix-lists       2
ACLs               3
Community-lists    2
AS-path-lists      1
Static routes      3
NTP                1
SNMP               1
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
confgraph info samples/iosxr_test.cfg --os iosxr
```

---

**Last Updated:** 2026-07-29
**Parser Version:** 1.3.0
