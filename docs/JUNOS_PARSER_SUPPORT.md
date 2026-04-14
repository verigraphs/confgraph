# Juniper JunOS Parser Support Documentation

## Overview

The JunOS parser (`confgraph.parsers.junos_parser.JunOSParser`) parses Juniper JunOS device configurations. Unlike all other parsers, it does **not** use `CiscoConfParse` — JunOS uses a brace-delimited hierarchical config format that is fundamentally incompatible with indentation-based parsing. Instead it uses a custom recursive tokenizer (`confgraph.parsers.junos_hierarchy`) to convert the config into a nested dict that the parser navigates.

Both **brace-style** (hierarchical) and **set-style** config formats exist in JunOS. This parser handles **brace-style only**. Set-style output (lines beginning with `set`) can be converted to brace-style using `show configuration | display set` vs `show configuration` on the device.

**Class:** `confgraph.parsers.junos_parser.JunOSParser`
**Inherits from:** `BaseParser`
**Tokenizer:** `confgraph.parsers.junos_hierarchy.parse_junos_config`
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
- Route-targets use `vrf-target target:X:Y` for both import and export, or `vrf-import`/`vrf-export` separately

**Supported Attributes:**
- VRF name
- Route distinguisher (`route-distinguisher`)
- Route-target import/export (`vrf-target`, `vrf-import`, `vrf-export`)
- Member interfaces (`interface NAME;`)

**Cross-referencing:** Interface `vrf` field is populated by cross-referencing routing-instance `interface` members during `parse_vrfs()`, which runs before `parse_interfaces()`.

**Parsing Status:** ✅ Implemented — `parse_vrfs()` handles `routing-instances` with `vrf-target`/`vrf-import`/`vrf-export` and populates `_vrf_of_intf` for interface cross-referencing

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
- IPv4 primary and secondary addresses
- IPv6 addresses
- Inbound/outbound ACL filter (`acl_in`, `acl_out`)
- VRF assignment (cross-referenced from routing-instances)

**Interface type classification:**

| Prefix | InterfaceType |
|--------|---------------|
| `lo` | LOOPBACK |
| `fxp`, `em`, `me`, `re` | MANAGEMENT |
| `ae` | PORTCHANNEL |
| `irb`, `vlan` | SVI |
| `gr-`, `ip-`, `st0`, `lt-`, `mt-` | TUNNEL |
| All others (`ge-`, `xe-`, `et-`, `fe-`) | PHYSICAL |

**Parsing Status:** ✅ Implemented — `parse_interfaces()` handles brace-style unit blocks with `family inet`/`inet6` and `filter { input/output }`

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
- `local-address` is an IP, not an interface name (not mapped to `update_source`)
- VRF BGP lives inside `routing-instances NAME { protocols { bgp { } } }`
- No flat `neighbor IP remote-as N` syntax — always block-style within a group

**Supported Attributes:**
- ASN (from `routing-options autonomous-system`)
- Router-ID (from `routing-options router-id`)
- Groups → `BGPPeerGroup` (name, remote-as, import/export policies)
- Neighbors → `BGPNeighbor` with peer-group reference, import/export policies mapped to `route_map_in`/`route_map_out`
- VRF BGP instances with their own groups and neighbors

**Parsing Status:**
- ✅ Implemented — `parse_bgp()` handles global `protocols bgp` and per-VRF BGP
- ✅ Implemented — `_parse_bgp_block()` extracts groups (peer-groups) and their neighbors

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
            }
        }
    }
}
```

**JunOS-Specific Differences:**
- Interface membership is declared inside the OSPF block under `area N { interface NAME; }`
- `passive;` is declared inside the interface sub-block (not as `passive-interface` at process level)
- No process ID concept — JunOS OSPF uses process ID 1 by convention

**Supported Attributes:**
- Areas with interface membership lists
- Passive interface detection (via `passive;` within the interface sub-block)

**Parsing Status:** ✅ Implemented — `parse_ospf()` handles area-nested interface blocks

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
- Match clauses: `prefix-list`, `community`, `as-path` references
- Set clauses: `community`, `local-preference`
- Actions: `accept` → permit, `reject`/`discard` → deny

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

**Parsing Status:** ✅ Implemented — `parse_prefix_lists()` handles `prefix-list`/`end-set` style entries

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
- Flat statement form: `as-path NAME "regex";` (not a block)
- The tokenizer stores these as a list of `"NAME regex"` strings
- No permit/deny per entry — the set is referenced by policy-statements

**Parsing Status:** ✅ Implemented — `parse_as_path_lists()` parses both flat-statement and block forms

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
- Flat statement form: `community NAME members VALUE;` (not a block)
- The tokenizer stores these as a list of `"NAME members VALUE"` strings
- `members` value can be a well-known community name (`no-export`, `no-advertise`) or AS:VAL

**Parsing Status:** ✅ Implemented — `parse_community_lists()` parses both flat-statement and block forms

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
- Stateless — no established/reflexive concepts (use `tcp-established` match instead)
- Actions: `accept`, `discard`, `reject` (no permit keyword)
- Each term is named, not numbered — sequences are assigned 10, 20, … in order
- Applied to interfaces via `family inet { filter { input/output NAME; } }` (not `ip access-group`)

**Supported Attributes:**
- Filter name → `ACLConfig.name`
- Terms → `ACLEntry` with sequence (auto-assigned), action (permit/deny), term name stored as `remark`

**Parsing Status:** ✅ Implemented — `parse_acls()` handles `firewall { filter NAME { term T { } } }`

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
- `discard` / `reject` replaces IOS `Null0`
- CIDR notation for destination prefix (no separate mask argument)

**Supported Attributes:**
- Destination prefix (CIDR)
- Next-hop IP or discard/reject keywords
- VRF context from routing-instance

**Parsing Status:** ✅ Implemented — `parse_static_routes()` handles global and per-VRF `routing-options static` blocks

---

### 11. Management Protocols (Inherited from system block)

JunOS management configuration lives under the top-level `system { }` block rather than at the global config level.

**NTP:**
```
system {
    ntp {
        server 10.0.0.10;
        server 10.0.0.11;
    }
}
```
**Parsing Status:** ✅ Implemented — `parse_ntp()` handles `system.ntp.server`

**SNMP:**
```
system {
    snmp {
        community public {
            authorization read-only;
        }
    }
}
```
**Parsing Status:** ✅ Implemented — `parse_snmp()` handles `system.snmp.community` with `authorization`

**Syslog:**
```
system {
    syslog {
        host 10.0.0.20 {
            any any;
        }
    }
}
```
**Parsing Status:** ✅ Implemented — `parse_syslog()` handles `system.syslog.host` entries

---

## Tokenizer Architecture

Unlike IOS-style parsers that rely on `CiscoConfParse`, the JunOS parser uses a two-layer approach:

```
Config text
    │
    ▼
junos_hierarchy.parse_junos_config()
    ├── _tokenize()         Strip comments, emit tokens ({, }, ;, [, ], words, quoted strings)
    └── _parse_block()      Recursive descent → nested dict
    │
    ▼
dict[str, Any]              Navigated by JunOSParser parse methods
    │
    ▼
ParsedConfig                Standard model used by all OS types
```

**Key tokenizer behaviors:**

| Input | Stored as |
|-------|-----------|
| `keyword value;` | `{keyword: "value"}` |
| `keyword name { … }` | `{keyword: {name: {…}}}` |
| `keyword { … }` | `{keyword: {…}}` |
| `keyword [ a b c ];` | `{keyword: "a b c"}` |
| Duplicate keys | First block merged; leaves become list |
| `/* … */` and `# …` | Stripped before tokenizing |

---

## Implemented Methods Summary

| Method | What it handles |
|--------|-----------------|
| `_extract_hostname()` | `system { host-name X; }` |
| `_collect_unrecognized_blocks()` | Returns `[]` — CiscoConfParse not used |
| `parse_vrfs()` | `routing-instances NAME { instance-type vrf; … }` with interface cross-reference |
| `parse_interfaces()` | `interfaces { NAME { unit N { family inet { } } } }` |
| `_make_interface()` | Constructs `InterfaceConfig` from parsed unit data |
| `_junos_interface_type()` | Classifies interface name → `InterfaceType` |
| `parse_bgp()` | `protocols bgp { group G { neighbor IP { } } }` + VRF BGP |
| `_parse_bgp_block()` | Shared group/neighbor parser for global and VRF BGP |
| `parse_ospf()` | `protocols ospf { area A { interface I { } } }` |
| `parse_route_maps()` | `policy-options policy-statement NAME { term T { from/then } }` |
| `parse_prefix_lists()` | `policy-options prefix-list NAME { PREFIX; }` |
| `parse_community_lists()` | `policy-options community NAME members VALUE;` |
| `parse_as_path_lists()` | `policy-options as-path NAME "regex";` |
| `parse_acls()` | `firewall filter NAME { term T { from/then } }` |
| `parse_static_routes()` | `routing-options static { route P next-hop N; }` (global + VRF) |
| `parse_ntp()` | `system ntp { server IP; }` |
| `parse_snmp()` | `system snmp { community NAME { authorization ro/rw; } }` |
| `parse_syslog()` | `system syslog { host IP { } }` |

---

## Parser Limitations

1. **Set-style config not supported** — Only brace-style (hierarchical) config is parsed. Convert with `show configuration` (not `show configuration | display set`) before using confgraph.
2. **IS-IS** — Detected in `protocols isis` block but parsed as a stub (no IS-IS model populated).
3. **MPLS / LDP / RSVP / Segment Routing** — Not parsed.
4. **EVPN / VXLAN** — Not parsed.
5. **Policy-statement full semantics** — Complex if/then/else constructs and `apply-path` are best-effort; only `prefix-list`, `community`, `as-path` references in `from` blocks are extracted.
6. **Firewall filter match conditions** — Only the action (accept/discard) is captured; source/destination address match conditions in filter terms are not parsed into ACLEntry fields.
7. **IPv6 routing protocols** — Limited coverage.
8. **Multi-chassis / Virtual Chassis** — Not parsed.

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
SNMP               1
```

**Auto-detection signals** (used when `--os` is not provided):

| Signal | Example |
|--------|---------|
| `system {` | Top-level system block |
| `interfaces {` | Top-level interfaces block |
| `protocols {` | Top-level protocols block |
| `routing-options {` | Top-level routing-options block |
| `set system host-name` | Set-style prefix (detected but not parsed) |

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

**Last Updated:** 2026-04-14
**Parser Version:** 1.0.0
