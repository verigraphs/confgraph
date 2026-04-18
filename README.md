# confgraph

Parse network device configs and visualize how everything connects — BGP neighbors, OSPF areas, route-maps, prefix-lists, VRFs — as an interactive dependency graph.

```bash
uvx confgraph map router.txt
uvx confgraph map router.txt --lint
```

## What it does

Point it at a config file. It parses every protocol, builds a dependency graph, and exports an interactive HTML diagram you can open in any browser. `--lint` flags dangling references and orphaned objects.

## Supported platforms

| OS | Parser |
| --- | --- |
| Cisco IOS / IOS-XE | `IOSParser` |
| Cisco IOS-XR | `IOSXRParser` |
| Cisco NX-OS | `NXOSParser` |
| Arista EOS | `EOSParser` |
| Juniper JunOS | `JunOSParser` |

## Try it instantly

Pre-generated maps for all supported platforms — open any in your browser, no install needed:

| Platform | Sample config | Interactive map |
| --- | --- | --- |
| Cisco IOS | [samples/ios.txt](samples/ios.txt) | [samples/ios.html](samples/ios.html) |
| Cisco IOS-XE | [samples/ios_xe.txt](samples/ios_xe.txt) | [samples/ios_xe.html](samples/ios_xe.html) |
| Cisco IOS-XR | [samples/ios_xr.txt](samples/ios_xr.txt) | [samples/ios_xr.html](samples/ios_xr.html) |
| Cisco NX-OS | [samples/nxos.txt](samples/nxos.txt) | [samples/nxos.html](samples/nxos.html) |
| Arista EOS | [samples/eos.txt](samples/eos.txt) | [samples/eos.html](samples/eos.html) |
| Juniper JunOS | [samples/junos_test.cfg](samples/junos_test.cfg) | [samples/junos_test.html](samples/junos_test.html) |

Or run against your own config:

```bash
uvx confgraph map your-router.txt --output-dir .
open your-router.html
```

## Install

```bash
pip install confgraph
```

Or run without installing:

```bash
uvx confgraph map router.txt
```

## Use as a library

```python
from confgraph.parsers.ios_parser import IOSParser

parsed = IOSParser(open("router.txt").read()).parse()
print(parsed.bgp_instances)
print(parsed.ospf_instances)
```

```python
from confgraph.parsers.junos_parser import JunOSParser

parsed = JunOSParser(open("router.conf").read()).parse()
print(parsed.vrfs)          # routing-instances
print(parsed.route_maps)    # policy-statements
```

## Protocols parsed

VRF · BGP · OSPF · IS-IS · EIGRP · RIP · Route-maps · Prefix-lists · ACLs · Community lists · AS-path lists · Static routes · NTP · SNMP · Syslog · Banners · QoS · NAT · Crypto/IPsec · BFD · IP SLA · EEM · Object tracking · Multicast

## Security & Privacy

**Local-first by design.** confgraph never sends your config files anywhere. All parsing, graph generation, and analysis run entirely on your machine. The HTML output is a self-contained file with no external requests — no CDN, no analytics, no telemetry of any kind.

## Contributing

Contributions welcome — new parsers, bug fixes, additional protocol coverage. See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) to get started.

## License

Apache 2.0
