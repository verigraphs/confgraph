# Juniper JunOS Parser Support Documentation

## Overview

The JunOS parser (`confgraph.parsers.junos_parser.JunOSParser`) parses Juniper JunOS device configurations. Unlike all other parsers, it does **not** use `CiscoConfParse` — JunOS uses a brace-delimited hierarchical config format that is fundamentally incompatible with indentation-based parsing. Instead it uses a custom recursive tokenizer (`confgraph.parsers.junos_hierarchy`) to convert the config into a **single canonical tree** (a nested dict in which every node is a dict) that the parser navigates.

Both **brace-style** (hierarchical) and **set-style** config formats exist in JunOS, and both are device-emitted (`show configuration` and `show configuration | display set`). As of the unified brace/set rewrite (2026-07-12), **both forms are parsed** — they are two renderings of one configuration database, so the tokenizer folds them into exactly the same canonical tree. The input form is auto-detected (`_is_set_style`); no manual conversion is required.

Configuration-group inheritance (`groups` / `apply-groups` / `apply-groups-except`) is **expanded during parse** (2026-07-12, `confgraph.parsers.junos_groups.expand_apply_groups`), so every extractor downstream sees the **effective** configuration rather than the unexpanded form `show configuration` prints.

**Class:** `confgraph.parsers.junos_parser.JunOSParser`
**Inherits from:** `BaseParser`
**Tokenizer:** `confgraph.parsers.junos_hierarchy.parse_junos_config`
**Group expansion:** `confgraph.parsers.junos_groups.expand_apply_groups`
**OSType:** `OSType.JUNOS` ("junos")

---

## Key Syntax Differences from IOS

| Feature | IOS | JunOS |
|---------|-----|-------|
| Config format | Line-by-line, indentation-based | Brace-delimited hierarchy |
| VRF definition | `vrf definition NAME` | `routing-instances NAME { instance-type vrf; }` |
| VRF membership | `vrf forwarding NAME` on interface | `interface NAME;` inside `routing-instances NAME` |
| Interface IP | `ip address X MASK` | `family inet { address X/LEN; }` inside `unit N` |
| Interface ACL | `ip access-group NAME in\|out` | `family inet { filter { input\|output NAME; } }` |
| Subinterfaces | Named subinterfaces (`Gi0/0.100`) | Units (`ge-0/0/0 { unit 100 { } }`) |
| Route-maps | `route-map NAME permit N` | `policy-statement NAME { term T { } }` |
| Prefix-lists | `ip prefix-list NAME seq N permit PREFIX` | `prefix-list NAME { PREFIX; }` (no permit/deny) |
| AS-path lists | `ip as-path access-list NAME permit REGEX` | `as-path NAME "REGEX";` (flat statement) |
| Community lists | `ip community-list NAME permit VALUE` | `community NAME members VALUE;` (flat statement) |
| BGP neighbors | Flat: `neighbor IP remote-as N` | Group-centric: `group NAME { neighbor IP { } }` |
| BGP peer templates | `neighbor IP peer-group NAME` | `group NAME { }` (groups ARE the templates) |
| BGP import/export | `neighbor IP route-map NAME in\|out` | `neighbor IP { import NAME; export NAME; }` |
| ACLs | `ip access-list NAME` | `firewall { filter NAME { term T { } } }` |
| Static routes | `ip route PREFIX MASK NEXTHOP` | `routing-options { static { route P/L next-hop N; } }` |
| OSPF interface | `ip ospf PROC area AREA` on interface | `area A { interface NAME; }` inside OSPF block |
| ASN | `router bgp ASN` | `routing-options { autonomous-system ASN; }` |
| Router-ID | `router-id X` inside router bgp | `routing-options { router-id X; }` |

---

## Configuration Syntax Support

### 1. VRF Configuration (routing-instances)

**Syntax:**
```
routing-instances {
    CUST-A {
        instance-type vrf;
        interface ge-0/0/2.0;
        route-distinguisher 65000:100;
        vrf-target target:65000:100;
        vrf-table-label;
    }
}
```

**JunOS-Specific Differences:**
- VRFs are `routing-instances` (not `vrf definition`)
- Interface membership is declared inside the routing-instance (not on the interface)
- Route-targets use `vrf-target target:X:Y` (both import and export). `vrf-target` may instead be split into `import`/`export` sub-statements (set-style), which is handled.
- `vrf-import`/`vrf-export` name **policy-statements**, not route-targets. They are stored in the policy-reference fields (`route_map_import` / `route_map_export`), NOT in `route_target_*` (CCR-0030).

**Supported Attributes:**
- VRF name
- Description (`description`)
- Route distinguisher (`route-distinguisher`)
- Route-target import/export (`vrf-target`, including the `target:` prefix stripped) → `route_target_both` / `route_target_import` / `route_target_export`
- Import/export **policy** references (`vrf-import`, `vrf-export`) → `route_map_import` / `route_map_export`
- Member interfaces (`interface NAME;`)

**Cross-referencing:** Interface `vrf` field is populated by cross-referencing routing-instance `interface` members during `parse_vrfs()`, which runs before `parse_interfaces()`.

**Parsing Status:** ✅ Implemented — `parse_vrfs()` handles `routing-instances`, distinguishes route-target statements (`vrf-target`) from policy statements (`vrf-import`/`vrf-export`), and populates `_vrf_of_intf` for interface cross-referencing

---

### 2. Interface Configuration

**Syntax:**
```
interfaces {
    ge-0/0/0 {
        description "Uplink to ISP";
        unit 0 {
            family inet {
                address 203.0.113.1/30;
                filter {
                    input INBOUND-FILTER;
                    output OUTBOUND-FILTER;
                }
            }
            family inet6 {
                address 2001:db8::1/64;
            }
        }
    }
    lo0 {
        unit 0 {
            family inet {
                address 192.0.2.1/32;
            }
        }
    }
}
```

**JunOS-Specific Differences:**
- Interfaces are split into physical interface + logical unit (`ge-0/0/0 { unit 0 { } }`)
- Canonical name is `INTF.UNIT` (e.g., `ge-0/0/0.0`)
- IP address is under `family inet { address X/LEN; }` (CIDR, not dotted mask)
- ACL filters are under `family inet { filter { input NAME; output NAME; } }`
- VRF membership is NOT on the interface — it is declared in `routing-instances`

**Supported Attributes:**
- Interface name (in `INTF.UNIT` format)
- Interface type classification (physical, loopback, management, portchannel, SVI, tunnel)
- Description (from unit or parent interface)
- IPv4 primary and secondary addresses (first `address` under `family inet` is primary, the rest are secondary; a trailing `primary` keyword is tolerated)
- IPv6 addresses (`family inet6 { address X/LEN; }`)
- Inbound/outbound ACL filter (`acl_in`, `acl_out`)
- IP unnumbered source (`family inet { unnumbered-address lo0.0; }` → `unnumbered_source`)
- VRF assignment (cross-referenced from routing-instances)
- Admin state (`enabled=False` when `disable;` is present on the unit or parent interface; a unit-level `disable` also disables that unit)
- MTU (from `mtu N;` on the parent interface, applied to all its units)

**Interface type classification:**

| Prefix | InterfaceType |
|--------|---------------|
| `lo` | LOOPBACK |
| `fxp`, `em`, `me`, `re` | MANAGEMENT |
| `ae` | PORTCHANNEL |
| `irb`, `vlan` | SVI |
| `gr-`, `ip-`, `st0`, `lt-`, `mt-` | TUNNEL |
| All others (`ge-`, `xe-`, `et-`, `fe-`) | PHYSICAL |

**Parsing Status:** ✅ Implemented — `parse_interfaces()` handles brace-style unit blocks with `family inet`/`inet6`, `filter { input/output }`, `disable;`, and `mtu`

---

### 3. BGP Configuration

**Syntax:**
```
routing-options {
    autonomous-system 65000;
    router-id 192.0.2.1;
}

protocols {
    bgp {
        group IBGP-PEERS {
            type internal;
            local-address 192.0.2.1;
            neighbor 192.0.2.2 {
                description "CORE-02 iBGP";
                import IBGP-IMPORT;
                export IBGP-EXPORT;
            }
        }
        group EBGP-ISP {
            type external;
            peer-as 64512;
            neighbor 203.0.113.2 {
                description "ISP Uplink";
                import ISP-IMPORT;
                export ISP-EXPORT;
            }
        }
    }
}
```

**VRF BGP (inside routing-instance):**
```
routing-instances {
    CUST-A {
        protocols {
            bgp {
                group CUST-A-CE {
                    type external;
                    peer-as 65001;
                    neighbor 10.10.10.2 {
                        import CUST-A-IMPORT;
                        export CUST-A-EXPORT;
                    }
                }
            }
        }
    }
}
```

**JunOS-Specific Differences:**
- ASN and router-id are in `routing-options`, not inside `router bgp`
- BGP is group-centric: all neighbors belong to a named group (≈ peer-group)
- `import`/`export` reference policy-statements (≈ route-maps), not prefix-lists
- `local-address` is resolved to an interface name for `update_source` (parser-side, using interface IP reverse lookup, done in the `parse()` override; an unresolvable address is left unset)
- VRF BGP lives inside `routing-instances NAME { protocols { bgp { } } }`
- No flat `neighbor IP remote-as N` syntax — always block-style within a group
- iBGP neighbors (`type internal`) with no explicit `peer-as` inherit `remote_as` from the device ASN, with `remote_as_source: "internal"` recording the peer-type provenance (CCR-0170)
- **Three-level attribute inheritance:** session attributes are legal at `bgp` (instance), `group`, and `neighbor` levels; a peer inherits whatever it does not override. A single table-driven extractor (`_bgp_attrs` + `_bgp_inherit`) flattens instance → group → neighbor, last level winning. A `description` is the exception — it describes the object it is written on and is NOT inherited.

**Supported Attributes:**
- ASN (from `routing-options autonomous-system`)
- Router-ID (from `routing-options router-id`)
- Groups → `BGPPeerGroup` (name, remote-as, and any inheritable session attributes configured at group/instance level)
- Neighbors → `BGPNeighbor` with peer-group reference and the effective (inherited) attributes:
  - `import`/`export` → `route_map_in`/`route_map_out` (also on the neighbor address-family)
  - `authentication-key` → `password`
  - `local-address` → `update_source` (address reverse-resolved to interface)
  - `hold-time` → `BGPTimers` (keepalive derived as holdtime/3, min 1 — JunOS configures only the hold time)
  - `multihop` → `ebgp_multihop` (TTL from `multihop N`, `multihop { ttl N; }`, or `multihop ttl N`; bare `multihop` defaults to TTL 64)
  - `family <af> { <safi> { prefix-limit { maximum N; } } }` → `maximum_prefix` (path-walked; `accepted-prefix-limit` and the `drop-excess`/`hide-excess`/`teardown` siblings are deliberately NOT read as a hard limit)
- IPv4 and IPv6 neighbor addresses (per-neighbor `peer-as` override supported)
- **Graceful restart:** enabled only when `routing-options { graceful-restart; }` is present (the global enable); `protocols bgp { graceful-restart { … } }` can only tune (`restart-time`) or opt out (`disable`), never enable. Per-VRF enable may come from the instance's own `routing-options`.
- **Multipath / ECMP:** `multipath;` at instance or group level emits a `BGPAddressFamily` with `maximum_paths=64` (a high-water marker — JunOS carries no explicit path count)
- VRF BGP instances with their own groups and neighbors

**Parsing Status:**
- ✅ Implemented — `parse_bgp()` handles global `protocols bgp` and per-VRF BGP; reads ASN/router-id from `routing-options`
- ✅ Implemented — `_parse_bgp_block()` extracts groups (peer-groups) and neighbors (IPv4 + IPv6) with three-level attribute inheritance, graceful-restart state, and multipath
- ✅ Implemented — `parse()` override reverse-resolves `local-address` IPs to interface names for `update_source`

---

### 4. OSPF Configuration

**Syntax:**
```
protocols {
    ospf {
        area 0.0.0.0 {
            interface lo0.0 {
                passive;
            }
            interface ge-0/0/1.0 {
                interface-type p2p;
                metric 10;
                hello-interval 5;
                dead-interval 20;
                priority 0;
                authentication {
                    simple-password "secret";
                }
            }
        }
        area 0.0.0.1 {
            stub no-summaries;
        }
        area 0.0.0.2 {
            nssa;
        }
    }
}
```

**JunOS-Specific Differences:**
- Interface membership is declared inside the OSPF block under `area N { interface NAME; }`
- `passive;` is declared inside the interface sub-block (not as `passive-interface` at process level)
- No process ID concept — JunOS OSPF uses process ID 1 by convention
- Area type (`stub`, `stub no-summaries`, `nssa`, `nssa no-summaries`) sets `OSPFArea.area_type`; default is NORMAL
- `router-id` extracted from `protocols { ospf { router-id X; } }` (the OSPF block itself, not `routing-options`)
- Interface OSPF fields (`ospf_area`, `ospf_process_id`, `ospf_cost`, etc.) are back-filled on `InterfaceConfig` in the `parse()` override

**Supported Attributes:**
- Router-ID (from `ospf { router-id X; }`)
- Areas with interface membership lists
- Area type: `NORMAL`, `STUB`, `TOTALLY_STUB` (`stub no-summaries`), `NSSA`, `TOTALLY_NSSA` (`nssa no-summaries`); `stub`/`nssa` inline options are read from the flattened token list, so `default-metric N` → `default_cost` and NSSA `default-lsa` → `nssa_default_information_originate` are captured
- Per-interface sub-attributes (carried on `OSPFArea.interface_settings`, back-filled onto `InterfaceConfig` by the shared `BaseParser._backfill_ospf_interface_settings`): `metric` → OSPF cost (JunOS has no `cost` keyword), `hello-interval`, `dead-interval`, `interface-type` → network type, `priority`, `passive`
- Per-interface **BFD** (`bfd-liveness-detection { minimum-interval / minimum-receive-interval / multiplier }`) → `bfd`, `bfd_interval`, `bfd_min_rx`, `bfd_multiplier`
- Per-interface **authentication** (`md5` → message-digest; `simple-password` → simple, key captured)
- `passive_interfaces` list on `OSPFConfig`
- **Reference bandwidth** (`reference-bandwidth`, with `k`/`m`/`g` suffixes expanded) → `auto_cost_reference_bandwidth`
- **Graceful restart** (`graceful-restart`; `helper-disable` toggles the helper) → `graceful_restart`, `graceful_restart_helper`
- **BFD for all interfaces** (`bfd-liveness-detection` at the OSPF level) → `bfd_all_interfaces`
- **Overload** (`overload`) → `max_metric_router_lsa`
- **Redistribution via export policy:** JunOS has no `redistribute` keyword — `export [ POLICY … ];` injects routes into OSPF, so each export policy becomes an `OSPFRedistribute(protocol="policy", route_map=POLICY)` (the source protocol lives inside the policy's own `from protocol` terms and is not resolved here)

**Note:** OSPF uses a fixed `process_id=1` (JunOS has no process-ID concept).

**Parsing Status:** ✅ Implemented — `parse_ospf()` handles area-nested interface blocks with area-type detection, full interface sub-attribute extraction (including BFD and authentication), reference-bandwidth, graceful-restart, overload, and export-policy redistribution

---

### 5. Route-Maps (Policy-Statements)

**Syntax:**
```
policy-options {
    policy-statement ISP-IMPORT {
        term REJECT-DEFAULT {
            from {
                prefix-list DEFAULT-ROUTE;
            }
            then reject;
        }
        term ACCEPT-REST {
            then accept;
        }
    }
}
```

**JunOS-Specific Differences:**
- `policy-statement NAME` / `term T` replaces IOS `route-map NAME permit N`
- `from { }` block = match clauses; `then { }` block = action + set clauses
- `then accept` = permit; `then reject` = deny
- References use `prefix-list NAME`, `community NAME`, `as-path NAME` (not ACL numbers)
- `set community` uses additive/delete sub-keywords

**Supported Attributes:**
- Policy name → `RouteMapConfig.name`
- Terms → `RouteMapSequence` (numbered 10, 20, … in order of appearance)
- Match clauses (from the `from` block, resolved recursively so set-style `from family inet prefix-list …` is also found): `prefix-list`, `community`, `as-path` references
- Set clauses (from the `then` block): `local-preference`, `metric`, and community operations `community add|set|delete NAME` (set_type carries the operation, e.g. `community add`)
- Actions: `accept` → permit, `reject` → deny (a `reject` anywhere in `then` marks the term deny)

**Note:** JunOS policy-statement language is more expressive than IOS route-maps. The parser performs best-effort extraction sufficient for dependency graph analysis (identifying referenced prefix-lists, communities, AS-paths). Full policy semantics are not evaluated.

**Parsing Status:** ✅ Implemented — `parse_route_maps()` maps `policy-statement`/`term` blocks to `RouteMapConfig`

---

### 6. Prefix-Lists (prefix-list in policy-options)

**Syntax:**
```
policy-options {
    prefix-list DEFAULT-ROUTE {
        0.0.0.0/0;
    }
    prefix-list RFC1918 {
        10.0.0.0/8;
        172.16.0.0/12;
        192.168.0.0/16;
    }
}
```

**JunOS-Specific Differences:**
- Defined under `policy-options { prefix-list NAME { } }` (not top-level `ip prefix-list`)
- Entries are plain CIDR prefixes terminated with `;` — no sequence numbers or permit/deny keywords
- `upto /LEN` modifier ≈ IOS `le LEN`; `orlonger` ≈ `le 32`

**Supported Attributes:**
- List name
- CIDR prefix entries (auto-numbered as sequences 10, 20, …)
- `upto` and `orlonger` modifiers mapped to `le`

**Parsing Status:** ✅ Implemented — `parse_prefix_lists()` handles `policy-options { prefix-list NAME { PREFIX [upto /LEN | orlonger]; } }`, auto-numbering entries and mapping `upto`/`orlonger` to `le` (`description`/`apply-groups` keys are skipped)

---

### 7. AS-Path Lists (as-path in policy-options)

**Syntax:**
```
policy-options {
    as-path CUSTOMER-AS "^65001$";
    as-path UPSTREAM-AS "^64512_";
}
```

**JunOS-Specific Differences:**
- Flat statement form: `as-path NAME "regex";`
- In the canonical tree this is `{as-path: {NAME: {regex: {}}}}`; the parser reads the regex as the first child key of the name
- No permit/deny per entry — the set is referenced by policy-statements

**Parsing Status:** ✅ Implemented — `parse_as_path_lists()` reads each `as-path NAME` and its regex value

---

### 8. Community Lists (community in policy-options)

**Syntax:**
```
policy-options {
    community NO-EXPORT members no-export;
    community LOCAL-PREF-100 members 65000:100;
}
```

**JunOS-Specific Differences:**
- Flat statement form: `community NAME members VALUE;` — equivalently `community NAME members [ V1 V2 ];` or the block form; all converge on `{community: {NAME: {members: {V1: {}, …}}}}` in the canonical tree
- All `members` values are read (in configured order) via `_str_vals`
- `members` value can be a well-known community name (`no-export`, `no-advertise`) or AS:VAL

**Parsing Status:** ✅ Implemented — `parse_community_lists()` reads `community NAME { members … }`, capturing all member values

---

### 9. ACLs (firewall filters)

**Syntax:**
```
firewall {
    filter INBOUND-FILTER {
        term BLOCK-RFC1918 {
            from {
                source-prefix-list RFC1918;
            }
            then {
                discard;
            }
        }
        term ALLOW-ESTABLISHED {
            from {
                tcp-established;
            }
            then accept;
        }
        term DEFAULT-DENY {
            then {
                discard;
            }
        }
    }
}
```

**JunOS-Specific Differences:**
- ACLs are `firewall { filter NAME { term T { } } }` (not `ip access-list`)
- The filter body may hang from `firewall { filter NAME { … } }` (implicit IPv4) OR `firewall { family <inet|inet6> { filter NAME { … } } }` — both paths are walked (`_iter_filters`); an `inet6` family filter is tagged `afi="ipv6"`
- Stateless — no established/reflexive concepts (use `tcp-established` match instead)
- Actions: `accept`, `discard`, `reject` (no permit keyword; `discard`/`reject` → deny)
- Each term is named, not numbered — sequences are assigned 10, 20, … in order
- Applied to interfaces via `family inet { filter { input/output NAME; } }` (not `ip access-group`)

**Supported Attributes:**
- Filter name → `ACLConfig.name`
- Terms → `ACLEntry` with sequence (auto-assigned), action (permit/deny), term name stored as `remark`
- Match conditions from the `from` block: `protocol`, `source-address`/`destination-address` prefixes, `source-prefix-list`/`destination-prefix-list`, `source-port`/`destination-port`
- A term matching multiple source and/or destination prefixes is expanded to one `ACLEntry` per (source, destination) pair — all sharing the term's sequence/name/action — because `ACLEntry.source`/`.destination` are single strings (recover the term by grouping on `sequence`/`remark`)
- Per-prefix `except` exclusions are NOT emitted (the entry over-matches rather than inverting meaning — CCR-0036 model limitation)

**Parsing Status:** ✅ Implemented — `parse_acls()` handles both `firewall { filter … }` and `firewall { family F { filter … } }`, extracting per-term action and address/protocol/port match conditions

---

### 10. Static Routes

**Syntax:**
```
routing-options {
    static {
        route 0.0.0.0/0 next-hop 203.0.113.2;
        route 192.168.0.0/16 discard;
    }
}

routing-instances {
    CUST-A {
        routing-options {
            static {
                route 0.0.0.0/0 next-hop 10.0.0.1;
            }
        }
    }
}
```

**JunOS-Specific Differences:**
- Global static routes under `routing-options { static { route PREFIX next-hop NH; } }`
- Per-VRF routes under `routing-instances NAME { routing-options { static { } } }`
- Both the flat form (`route P next-hop NH;`) and the block form (`route P { next-hop NH; preference N; tag N; }`) are handled — a single block-form route no longer erases its flat siblings (CCR-0032)
- `discard` / `reject` / `blackhole` replaces IOS `Null0`
- CIDR notation for destination prefix (no separate mask argument)

**Supported Attributes:**
- Destination prefix (CIDR)
- Next-hop IP, an interface name, or discard/reject/blackhole keywords (which yield a null next-hop)
- `preference` → administrative distance (`distance`, default 1)
- `tag` → route tag
- VRF context from routing-instance

**Parsing Status:** ✅ Implemented — `parse_static_routes()` handles global and per-VRF `routing-options static` blocks in both flat and block form, including `preference` and `tag`

---

### 11. Management Protocols

NTP and syslog live under the top-level `system { }` block. **SNMP is its own top-level stanza** (`[edit snmp]`), a sibling of `protocols` and `firewall` — NOT a child of `system`.

**NTP:**
```
system {
    ntp {
        server 10.0.0.10;
        server 10.0.0.11 prefer key 5 version 4;
        source-address 192.0.2.1;
    }
}
```
Each `server` is a named block keyed by address; per-server options `prefer`, `key <id>`, `version <n>` are read from the option tokens. `source-address` is stored in `NTPConfig.source_address` (JunOS has no `ntp source-interface` — the source is named by address, not interface — CCR-0030).
**Parsing Status:** ✅ Implemented — `parse_ntp()` handles `system.ntp.server` (with per-server options) and `source-address`

**SNMP:**
```
snmp {
    community public {
        authorization read-only;
    }
    location "Rack 4";
    contact "netops@example.com";
}
```
`authorization read-only` → access `ro`, otherwise `rw`. `location` and `contact` are captured. Because SNMP is read from the **top-level** `snmp` stanza, a config that (incorrectly) nests `snmp` under `system { }` yields no SNMP output.
**Parsing Status:** ✅ Implemented — `parse_snmp()` handles top-level `snmp.community` with `authorization`, plus `location` and `contact`

**Syslog:**
```
system {
    syslog {
        host 10.0.0.20 {
            any any;
        }
        source-address 192.0.2.1;
    }
}
```
`source-address` (a sibling of the `host` stanzas, applied to all hosts) → `SyslogConfig.source_address`.
**Parsing Status:** ✅ Implemented — `parse_syslog()` handles `system.syslog.host` entries and `source-address`

---

## Tokenizer Architecture

Unlike IOS-style parsers that rely on `CiscoConfParse`, the JunOS parser converts the config into a **single canonical tree** in which *every node is a dict* — there are no `str` or `list` values. A statement's trailing tokens become its nested keys, so the brace form and the `set` form of the same statement fold into exactly the same tree:

```
Config text (brace-style OR set-style — auto-detected)
    │
    ▼
junos_hierarchy.parse_junos_config()
    ├── brace: _tokenize() → _parse_block()   Recursive descent
    └── set:   _parse_set_style()             Each "set A B C" is the path A → B → C
    │
    ▼
junos_groups.expand_apply_groups()            Expand groups / apply-groups inheritance
    │
    ▼
dict[str, dict]  (canonical tree)             Navigated by JunOSParser parse methods
    │
    ▼
ParsedConfig                                  Standard model used by all OS types
```

**Canonical-tree mapping (identical for both input forms):**

| Input | Stored as |
|-------|-----------|
| `keyword;` | `{keyword: {}}` |
| `keyword a;` | `{keyword: {a: {}}}` |
| `keyword a b;` | `{keyword: {a: {b: {}}}}` |
| `keyword name { child x; }` | `{keyword: {name: {child: {x: {}}}}}` |
| `keyword [ a b ];` | `{keyword: {a: {}, b: {}}}` |
| `set … keyword a b` | `{keyword: {a: {b: {}}}}` (identical to the brace leaf) |
| Duplicate statements | Merged into sibling keys (never degrade to a `list`) |
| `/* … */` and `#`/`##` comments | Stripped before tokenizing |

**Consequences the parser layer relies on:**
- Every value is a dict, so extractors need no per-statement shape branch. Helper readers give a uniform view: `_str_val()` (first child key as scalar), `_str_vals()` (all child keys), `_stmt_tokens()` (DFS-flattened inline option tokens — so `stub default-metric 10 no-summaries;` and its two equivalent `set` lines both flatten to the same token list), `_token_arg()` (token following a keyword), `_as_named_block()` (normalise a bare leaf to a named block).
- Because a statement's value is its *first* child key and every reader takes the first key, an explicit local value (inserted at parse time) wins over an inherited one — this is what makes `apply-groups` precedence work.

---

## Implemented Methods Summary

| Method | What it handles |
|--------|-----------------|
| `parse()` (override) | Runs `BaseParser.parse()`, then reverse-resolves BGP `local-address` IPs → `update_source` interface names |
| `_extract_hostname()` | `system { host-name X; }` |
| `_collect_unrecognized_blocks()` | Returns `[]` — CiscoConfParse not used |
| `parse_vrfs()` | `routing-instances NAME { instance-type vrf; … }` with interface cross-reference; splits `vrf-target` (RT) from `vrf-import`/`vrf-export` (policy) |
| `parse_interfaces()` | `interfaces { NAME { unit N { family inet/inet6 { } } } }` incl. `disable`, `mtu`, `unnumbered-address` |
| `_make_interface()` | Constructs `InterfaceConfig` from parsed unit data |
| `_junos_interface_type()` | Classifies interface name → `InterfaceType` (delegates to shared `infer_interface_type`) |
| `parse_bgp()` | `protocols bgp { group G { neighbor IP { } } }` + VRF BGP; ASN/router-id from `routing-options` |
| `_parse_bgp_block()` / `_bgp_attrs()` / `_bgp_inherit()` | Shared group/neighbor parser with three-level (instance→group→neighbor) attribute inheritance, graceful-restart, multipath |
| `parse_ospf()` | `protocols ospf { area A { interface I { } } }` incl. area types, per-interface BFD/auth, reference-bw, graceful-restart, overload, export redistribution |
| `parse_route_maps()` | `policy-options policy-statement NAME { term T { from/then } }` incl. metric and community add/set/delete set-clauses |
| `parse_prefix_lists()` | `policy-options prefix-list NAME { PREFIX [upto/orlonger]; }` |
| `parse_community_lists()` | `policy-options community NAME members VALUE;` (flat and block form) |
| `parse_as_path_lists()` | `policy-options as-path NAME "regex";` |
| `parse_acls()` | `firewall [family F] filter NAME { term T { from/then } }` incl. address/protocol/port matches |
| `parse_static_routes()` | `routing-options static { route P … ; }` (global + VRF), flat and block form, `preference`/`tag` |
| `parse_ntp()` | `system ntp { server IP <opts>; source-address … }` |
| `parse_snmp()` | top-level `snmp { community NAME { authorization ro/rw; } location; contact; }` |
| `parse_syslog()` | `system syslog { host IP { } source-address … }` |

---

## Parser Limitations

1. **IS-IS** — Not implemented (`ISISConfig` is imported but no `parse_isis` method exists).
2. **MPLS / LDP / RSVP / Segment Routing / VXLAN / Multicast** — Not parsed (`MulticastConfig` is imported but there is no `parse_multicast` method).
3. **EVPN / L2 / Switching** — Not parsed.
4. **VRRP** — Not parsed.
5. **LLDP** — Not parsed. **BFD** — parsed only in the OSPF context (per-interface `bfd-liveness-detection` and the OSPF-level `bfd_all_interfaces` flag); there is no standalone BFD model.
6. **AAA / DNS / DHCP** — Not parsed.
7. **Policy-statement full semantics** — Complex if/then/else constructs and `apply-path` are best-effort; from the `from` block only `prefix-list`, `community`, `as-path` references are extracted, and from `then` only `local-preference`, `metric`, and `community add/set/delete`.
8. **Firewall filter — `except` exclusions** — a per-prefix `except` modifier is dropped rather than emitted (the entry over-matches instead of inverting meaning — CCR-0036). A multi-prefix term is expanded to the cross product of (source, destination) prefixes because `ACLEntry` holds a single source/destination each.

---

## Testing and Validation

**Sample Configuration:** `samples/junos_test.cfg`

**Validated output (`confgraph info samples/junos_test.cfg --os junos`):**
```
Hostname : JUNOS-CORE-01
OS       : junos
Interfaces         3
VRFs               1
BGP instances      2
OSPF instances     1
Route-maps         6
Prefix-lists       2
ACLs               2
Community-lists    2
AS-path-lists      2
Static routes      3
NTP                1
```

(No SNMP line: `samples/junos_test.cfg` nests its `snmp` stanza under `system { }`, but the parser now reads SNMP from the **top-level** `snmp` stanza, so this sample yields no SNMP output.)

**Auto-detection signals** (used when `--os` is not provided):

| Signal | Example |
|--------|---------|
| `system {` | Top-level system block |
| `interfaces {` | Top-level interfaces block |
| `protocols {` | Top-level protocols block |
| `routing-options {` | Top-level routing-options block |
| `set system host-name` | Set-style prefix (set-style is auto-detected and **now fully parsed**) |

---

## Quick Reference

```python
from confgraph.parsers.junos_parser import JunOSParser

parser = JunOSParser(config_text)
parsed = parser.parse()
# os_type = OSType.JUNOS  # "junos"
```

```bash
confgraph info samples/junos_test.cfg --os junos
confgraph map  samples/junos_test.cfg --os junos --lint
```

---

**Last Updated:** 2026-07-29
**Parser Version:** 1.0.0
