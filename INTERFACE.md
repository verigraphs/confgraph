# confgraph — Public Interface Contract

This file documents the interface that external tools (e.g. configz-validator) depend on.
**Update this file whenever any of the below changes.**

---

## Package root

```
confgraph/
```

## Parsers

| Class | Module |
|---|---|
| `BaseParser` | `confgraph.parsers.base` |
| `ParseError` | `confgraph.parsers.base` |
| `IOSParser` | `confgraph.parsers.ios_parser` |
| `EOSParser` | `confgraph.parsers.eos_parser` |
| `NXOSParser` | `confgraph.parsers.nxos_parser` |
| `IOSXRParser` | `confgraph.parsers.iosxr_parser` |

All parsers expose a single entry point:
```python
parsed: ParsedConfig = ParserClass(config_text: str).parse()
```

## Models root

```
confgraph/models/
```

## ParsedConfig fields

| Field | Type |
|---|---|
| `source_os` | `OSType` |
| `hostname` | `str \| None` |
| `vrfs` | `list[VRFConfig]` |
| `interfaces` | `list[InterfaceConfig]` |
| `bgp_instances` | `list[BGPConfig]` |
| `ospf_instances` | `list[OSPFConfig]` |
| `isis_instances` | `list[ISISConfig]` |
| `eigrp_instances` | `list[EIGRPConfig]` |
| `rip_instances` | `list[RIPConfig]` |
| `route_maps` | `list[RouteMapConfig]` |
| `prefix_lists` | `list[PrefixListConfig]` |
| `static_routes` | `list[StaticRoute]` |
| `acls` | `list[ACLConfig]` |
| `community_lists` | `list[CommunityListConfig]` |
| `as_path_lists` | `list[ASPathListConfig]` |
| `class_maps` | `list[ClassMapConfig]` |
| `policy_maps` | `list[PolicyMapConfig]` |
| `lines` | `list[LineConfig]` |
| `ip_sla_operations` | `list[IPSLAOperation]` |
| `eem_applets` | `list[EEMApplet]` |
| `object_tracks` | `list[ObjectTrack]` |
| `ntp` | `NTPConfig \| None` |
| `snmp` | `SNMPConfig \| None` |
| `syslog` | `SyslogConfig \| None` |
| `banners` | `BannerConfig \| None` |
| `nat` | `NATConfig \| None` |
| `crypto` | `CryptoConfig \| None` |
| `bfd` | `BFDConfig \| None` |
| `multicast` | `MulticastConfig \| None` |
| `raw_config` | `str` |
| `unrecognized_blocks` | `list[UnrecognizedBlock]` |

## OSType enum

```python
from confgraph.models.base import OSType
# Values: OSType.IOS, OSType.IOS_XE, OSType.IOS_XR, OSType.NXOS, OSType.EOS
```

## BaseConfigObject

All model objects (VRFConfig, BGPConfig, etc.) inherit from `BaseConfigObject` which provides:
- `object_id: str`
- `raw_lines: list[str]`
- `line_numbers: list[int]`
- `source_os: OSType`
