# confgraph — Architecture

## Overview

confgraph parses vendor network device configurations into typed Pydantic models, resolves cross-references between protocol objects, builds a directed dependency graph, and exports a self-contained interactive HTML file.

---

## High-Level Flow

```text
Config file (text / XML)
        │
        ▼
   OS Parser                  IOSParser / EOSParser / IOSXRParser /
   (BaseParser subclass)      NXOSParser / JunOSParser / PANOSParser
        │
        │  parse_vrfs(), parse_interfaces(), parse_bgp(), ...
        ▼
   ParsedConfig               Pydantic container: all protocol objects
        │
        ├──► DependencyResolver   resolves string cross-refs → DependencyReport
        │                         (dangling refs, orphaned objects, edge list)
        │
        ├──► GraphBuilder         ParsedConfig + DependencyReport → nx.DiGraph
        │
        └──► Exporter
               ├── HTMLExporter   self-contained interactive HTML (Cytoscape.js)
               └── JSONExporter   graph as JSON
```

---

## Parser Patterns

There are three parsing approaches, chosen by config format:

| Pattern | Used by | Underlying engine |
| --- | --- | --- |
| IOS-style (extend `IOSParser`) | EOS, NX-OS | `CiscoConfParse` |
| Custom tokenizer (extend `BaseParser`) | JunOS | `junos_hierarchy.parse_junos_config()` |
| XML (extend `BaseParser`) | PAN-OS | `xml.etree.ElementTree` via `panos_xml` |

---

## Class Hierarchy

```text
BaseParser  (abc)
│   _KNOWN_TOP_LEVEL_PATTERNS  ← class-level, overrideable
│   _BEST_GUESS_KEYWORDS       ← class-level, overrideable
│   _PARSE_STEPS               ← ordered list of (field, method) pairs
│   _collect_unrecognized_blocks()
│   parse()  → ParsedConfig
│
├── IOSParser                  CiscoConfParse, IOS/IOS-XE syntax
│     parse_vrfs()  parse_interfaces()  parse_bgp()  parse_ospf()
│     parse_isis()  parse_eigrp()  parse_rip()  parse_route_maps()
│     parse_prefix_lists()  parse_static_routes()  parse_acls()
│     parse_community_lists()  parse_as_path_lists()
│     parse_ntp()  parse_snmp()  parse_syslog()  parse_banners()
│     parse_lines()  parse_class_maps()  parse_policy_maps()
│     parse_nat()  parse_crypto()  parse_bfd()  parse_ip_sla()
│     parse_eem()  parse_object_tracks()  parse_multicast()
│
│   ├── EOSParser              Extends IOSParser — overrides EOS syntax differences
│   │     Overrides: parse_vrfs, parse_prefix_lists, parse_static_routes,
│   │                parse_acls, parse_community_lists, parse_as_path_lists,
│   │                parse_bgp, parse_isis
│   │
│   ├── NXOSParser             Extends IOSParser — NX-OS feature/vrf syntax
│   │
│   └── IOSXRParser            Extends IOSParser — IOS-XR hierarchical syntax,
│                              route-policies, prefix-sets, neighbor-groups
│
├── JunOSParser                Custom tokenizer, no CiscoConfParse
│     _extract_hostname()      system { host-name X; }
│     _collect_unrecognized_blocks() → []
│     All parse_*() navigate nested dict from junos_hierarchy tokenizer
│
└── PANOSParser                XML, no CiscoConfParse
      _extract_hostname()      <deviceconfig><system><hostname>
      _collect_unrecognized_blocks() → []
      All parse_*() navigate ElementTree via panos_xml helpers
```

---

## Data Models

```text
confgraph/models/
│
├── base.py
│     OSType            IOS | IOS_XE | IOS_XR | NXOS | EOS | JUNOS | PANOS
│     BaseConfigObject  object_id, raw_lines, source_os, line_numbers
│     UnrecognizedBlock block_header, raw_lines, best_guess
│
├── parsed_config.py
│     ParsedConfig      top-level container — all protocol lists
│
├── interface.py        InterfaceConfig (L2, L3, OSPF, FHRP, tunnel, QoS, NAT,
│                       crypto, PIM, IGMP, CDP/LLDP, zone, virtual_router)
│
├── vrf.py              VRFConfig (name, rd, route-targets)
├── bgp.py              BGPConfig, BGPNeighbor, BGPPeerGroup, BGPAddressFamily
├── ospf.py             OSPFConfig, OSPFArea, OSPFRedistribute
├── isis.py             ISISConfig
├── eigrp.py            EIGRPConfig
├── rip.py              RIPConfig
├── route_map.py        RouteMapConfig, RouteMapSequence, RouteMapMatch, RouteMapSet
├── prefix_list.py      PrefixListConfig, PrefixListEntry
├── acl.py              ACLConfig, ACLEntry
├── static_route.py     StaticRoute
├── community_list.py   CommunityListConfig, ASPathListConfig
├── nat.py              NATConfig, NATStaticEntry, NATDynamicEntry, NATPool
├── crypto.py           CryptoConfig, IKEv1Policy, IKEv2Proposal, IPSecTransformSet, CryptoMap
├── qos.py              ClassMapConfig, PolicyMapConfig
├── ntp.py              NTPConfig, NTPServer
├── snmp.py             SNMPConfig, SNMPCommunity
├── logging_config.py   SyslogConfig, LoggingHost
├── banner.py           BannerConfig
├── line.py             LineConfig
├── bfd.py              BFDConfig
├── ipsla.py            IPSLAOperation
├── eem.py              EEMApplet
├── object_tracking.py  ObjectTrack
├── multicast.py        MulticastConfig
└── panos_zone.py       PANOSZoneConfig  (PAN-OS only)
```

---

## Dependency Resolution

`DependencyResolver` walks every parsed object and emits `DependencyLink` records for every string cross-reference (e.g., `BGPNeighbor.route_map_in = "RM-IN"`). It tracks which named objects are referenced to identify orphans.

```python
report = DependencyResolver(parsed).resolve()
report.links          # all edges (resolved + dangling)
report.dangling_refs  # references with no matching target
report.orphaned       # defined objects never referenced by anything
```

All references remain strings in the data models — resolution happens exclusively in `DependencyResolver`, keeping models simple.

---

## Graph Builder

`GraphBuilder` converts `ParsedConfig` + `DependencyReport` into a `networkx.DiGraph`.

- **Nodes** — one per parsed object; attributes include `type`, `label`, `color`, `fill`, `status` (`ok` / `orphan` / `missing`), `raw_config`
- **Edges** — one per `DependencyLink`; ghost nodes are added for dangling targets
- **Node styles** — defined in `NODE_STYLE` dict in `builder.py` (shape, color, fill, group); shared by all exporters

Node groups: `infrastructure` · `routing` · `policy` · `qos` · `management` · `security` · `missing`

---

## HTML Exporter

The HTML exporter (`confgraph/graph/exporters/html.py`) renders the graph client-side using **Cytoscape.js** embedded in a single self-contained HTML file with no external dependencies.

Key frontend features:

- **Protocol clusters** — sidebar toggles that highlight all nodes reachable from a protocol root (BGP, OSPF, NAT, Crypto/VPN, Zones, etc.) via BFS; interface nodes are traversal stops, not transit points
- **Node isolation** — clicking a node dims everything not directly connected
- **Raw config panel** — sidebar shows original config lines for the selected node
- **Layout options** — Dagre (hierarchical), Cose-Bilkent (force-directed), Breadthfirst, Concentric
- **Collapsible/resizable sidebar** — drag handle + collapse toggle

---

## Directory Structure

```text
confgraph/
├── confgraph/
│   ├── models/              Pydantic data models (one file per protocol)
│   ├── parsers/
│   │   ├── base.py          BaseParser (abstract), ParseError
│   │   ├── ios_parser.py    IOSParser  (~4,200 lines)
│   │   ├── eos_parser.py    EOSParser  (~900 lines, extends IOSParser)
│   │   ├── nxos_parser.py   NXOSParser (~560 lines, extends IOSParser)
│   │   ├── iosxr_parser.py  IOSXRParser (~1,240 lines, extends IOSParser)
│   │   ├── junos_parser.py  JunOSParser (~1,190 lines, custom tokenizer)
│   │   ├── junos_hierarchy.py  JunOS brace-style tokenizer
│   │   ├── panos_parser.py  PANOSParser (~680 lines, XML)
│   │   └── panos_xml.py     PAN-OS XML navigation helpers
│   ├── graph/
│   │   ├── builder.py       GraphBuilder → nx.DiGraph
│   │   └── exporters/
│   │       ├── html.py      HTMLExporter (Cytoscape.js)
│   │       └── json.py      JSONExporter
│   ├── analysis/
│   │   └── dependency_resolver.py  DependencyResolver → DependencyReport
│   └── cli.py               Click CLI (map + info commands)
├── samples/                 Sample configs + pre-generated HTML per OS
└── docs/                    Architecture, parser support docs, CLI usage
```

---

## Adding a New Parser

See [ADDING_NEW_OS_SUPPORT.md](ADDING_NEW_OS_SUPPORT.md) for a step-by-step guide and file checklist.

---

**Last Updated:** 2026-04-22
