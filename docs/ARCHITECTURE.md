# confgraph — Architecture

## Overview

`confgraph` is a Python library that parses vendor network device CLI configurations (plain text) into typed, validated Pydantic data models.

---

## High-Level Flow

```
Raw CLI Text (show running-config)
            │
            ▼
    ┌───────────────┐
    │  OS Parser    │  IOSParser / EOSParser
    │               │
    │  1. Segments config via ciscoconfparse2
    │  2. Calls parse_*() per protocol      │
    │  3. Captures unrecognized blocks      │
    └───────┬───────┘
            │
            ▼
    ┌───────────────────────────────────────┐
    │           ParsedConfig                │
    │  (top-level container, Pydantic)      │
    │                                       │
    │  vrfs, interfaces, bgp_instances,     │
    │  ospf_instances, isis_instances,      │
    │  route_maps, prefix_lists,            │
    │  static_routes, acls,                 │
    │  community_lists, as_path_lists,      │
    │  unrecognized_blocks                  │
    └───────────────────────────────────────┘
```

---

## Class Hierarchy

```
BaseParser  (abc)
    │   _KNOWN_TOP_LEVEL_PATTERNS  ← class-level, overrideable
    │   _BEST_GUESS_KEYWORDS       ← class-level, overrideable
    │   _collect_unrecognized_blocks()
    │   parse()  → ParsedConfig
    │
    ├── IOSParser
    │       parse_vrfs()           → list[VRFConfig]
    │       parse_interfaces()     → list[InterfaceConfig]
    │       parse_bgp()            → list[BGPConfig]
    │       parse_ospf()           → list[OSPFConfig]
    │       parse_route_maps()     → list[RouteMapConfig]
    │       parse_prefix_lists()   → list[PrefixListConfig]
    │       parse_static_routes()  → list[StaticRoute]
    │       parse_acls()           → list[ACLConfig]
    │       parse_community_lists()→ list[CommunityListConfig]
    │       parse_as_path_lists()  → list[ASPathListConfig]
    │       parse_isis()           → list[ISISConfig]
    │
    └── EOSParser  (extends IOSParser)
            Overrides _KNOWN_TOP_LEVEL_PATTERNS
                - swaps "vrf definition" → "vrf instance"
                - adds EOS: management api, daemon, event-handler, policy-map
            Overrides _BEST_GUESS_KEYWORDS (adds EOS-specific labels)
            Overrides parse_vrfs()           EOS: "vrf instance NAME"
            Overrides parse_prefix_lists()   EOS: CIDR notation
            Overrides parse_static_routes()  EOS: CIDR notation
            Overrides parse_acls()           EOS: ACL syntax differences
            Overrides parse_community_lists()
            Overrides parse_as_path_lists()
            Overrides parse_isis()
            Overrides parse_bgp()            EOS: "peer group" (space, not hyphen)
```

---

## Data Models

```
confgraph/models/
│
├── base.py
│     OSType            enum: IOS | IOS_XE | IOS_XR | NXOS | EOS
│     BaseConfigObject  base Pydantic class (object_id, raw_lines, source_os, line_numbers)
│     UnrecognizedBlock block_header, raw_lines, best_guess
│
├── parsed_config.py
│     ParsedConfig      top-level container — holds all protocol lists + unrecognized_blocks
│
├── bgp.py
│     BGPNeighborBase   shared neighbor fields (remote_as, route_map_in/out, timers, ...)
│     BGPNeighbor       per-neighbor config (extends BGPNeighborBase)
│     BGPPeerGroup      peer-group config (extends BGPNeighborBase)
│     BGPAddressFamily  address-family config
│     BGPConfig         top-level BGP instance (asn, router_id, neighbors, peer_groups, ...)
│
├── ospf.py
│     OSPFArea          area config (area_id, networks, virtual_links, ...)
│     OSPFRedistribute  redistribution config
│     OSPFConfig        top-level OSPF instance (process_id, vrf, areas, ...)
│
├── isis.py
│     ISISInterface     per-interface IS-IS config
│     ISISRedistribute  redistribution config
│     ISISConfig        top-level IS-IS instance
│
├── interface.py
│     InterfaceType     enum: PHYSICAL | LOOPBACK | SVI | PORTCHANNEL | TUNNEL | MANAGEMENT | VLAN | NULL
│     HSRPGroup         HSRP group (priority, virtual_ip, timers, track_objects)
│     VRRPGroup         VRRP group (priority, virtual_ip, timers)
│     InterfaceConfig   full interface model (L2, L3, OSPF embedded, FHRP, tunnel, CDP/LLDP)
│
├── vrf.py
│     VRFConfig         name, rd, route_targets, description
│
├── route_map.py
│     RouteMapEntry     sequence, action, match/set clauses
│     RouteMapConfig    name + list[RouteMapEntry]
│
├── prefix_list.py
│     PrefixListEntry   sequence, action, prefix (IPv4Network | IPv6Network), le/ge
│     PrefixListConfig  name + list[PrefixListEntry]
│
├── acl.py
│     ACLEntry          sequence, action, protocol, src/dst, ports
│     ACLConfig         name, acl_type + list[ACLEntry]
│
├── static_route.py
│     StaticRoute       prefix, next_hop, vrf, distance, tag, name
│
└── community_list.py
      CommunityListEntry  sequence, action, communities
      CommunityListConfig name + list[CommunityListEntry]
      ASPathListEntry     sequence, action, regex
      ASPathListConfig    name + list[ASPathListEntry]
```

---

## Unrecognized Block Capture

Any top-level config block not matched by a `parse_*` method is preserved in `ParsedConfig.unrecognized_blocks` instead of being silently dropped.

```
Config text
    │
    ├── router bgp 65000   ← claimed by parse_bgp()
    ├── interface Eth1     ← claimed by parse_interfaces()
    ├── ntp server 1.1.1.1 ← NOT claimed → UnrecognizedBlock(best_guess="ntp")
    ├── aaa new-model      ← NOT claimed → UnrecognizedBlock(best_guess="aaa")
    └── snmp-server ...    ← NOT claimed → UnrecognizedBlock(best_guess="snmp")
```

**Pattern matching is OS-aware:**

| Parser | `vrf` pattern |
|---|---|
| `IOSParser` | `^vrf definition` |
| `EOSParser` | `^vrf instance` (overrides base) |

Subclasses extend or replace `_KNOWN_TOP_LEVEL_PATTERNS` and `_BEST_GUESS_KEYWORDS` at the class level — no runtime cost.

---

## Cross-References (current state)

Protocol objects reference each other by **name strings only** — links are not resolved into object pointers.

```
BGPNeighbor.route_map_in  = "RM-PEER-IN"   ← string, not RouteMapConfig
BGPNeighbor.prefix_list_in = "PL-ALLOWED"  ← string, not PrefixListConfig
InterfaceConfig.vrf        = "MGMT"         ← string, not VRFConfig
BGPConfig.vrf              = "MGMT"         ← string, not VRFConfig
```

`ParsedConfig` provides lookup helpers:

```python
parsed.get_route_map_by_name("RM-PEER-IN")    → RouteMapConfig | None
parsed.get_prefix_list_by_name("PL-ALLOWED")  → PrefixListConfig | None
parsed.get_vrf_by_name("MGMT")                → VRFConfig | None
parsed.get_interface_by_name("Ethernet1")     → InterfaceConfig | None
parsed.get_bgp_by_asn(65000)                  → BGPConfig | None
parsed.get_ospf_by_process_id(1)              → OSPFConfig | None
```

Full dependency resolution (resolving strings → objects, detecting dangling refs) is not yet implemented.

---

## Directory Structure

```
confgraph/
├── confgraph/
│   ├── models/
│   │   ├── base.py           OSType, BaseConfigObject, UnrecognizedBlock
│   │   ├── parsed_config.py  ParsedConfig (top-level container)
│   │   ├── bgp.py
│   │   ├── ospf.py
│   │   ├── isis.py
│   │   ├── interface.py
│   │   ├── vrf.py
│   │   ├── route_map.py
│   │   ├── prefix_list.py
│   │   ├── acl.py
│   │   ├── static_route.py
│   │   └── community_list.py
│   └── parsers/
│       ├── base.py           BaseParser (abstract)
│       ├── ios_parser.py     IOSParser  (2,244 lines)
│       └── eos_parser.py     EOSParser  (inherits IOSParser, ~841 lines)
└── docs/
    ├── ARCHITECTURE.md       (this file)
    ├── PARSER_SUPPORT_MATRIX.md
    ├── IOS_PARSER_SUPPORT.md
    └── EOS_PARSER_SUPPORT.md
```
