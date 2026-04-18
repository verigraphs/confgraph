# confgraph

Network configs are text files. The dependencies between them are a graph. confgraph makes that graph visible.

```bash
uvx confgraph map router.txt
```

![confgraph default view](docs/default_view.png)

## Why this matters

**The grep problem.** Most engineers navigate configs with grep. Want to change a prefix-list? Grep for the name, find the route-map, grep for the route-map, find the BGP neighbor. That's a 5-step mental join query. confgraph turns it into a single glance.

**The "Oh no" moment.** An engineer deletes an ACL that looks unused. Ten minutes later they realize it was the only thing protecting the management plane on a different VRF. In a graph, that ACL is visibly connected — you can see what you're about to break before you break it.

**Ghost configuration.** Large enterprise configs accumulate ghost objects: prefix-lists nobody calls, route-maps that reference non-existent ACLs. In a CLI they look like valid config. In a graph they appear as disconnected nodes. confgraph makes technical debt visible.

**Blast radius.** "What happens if I touch this community list?" usually gets the answer "I think it affects these three neighbors." With confgraph the answer is "I can see it affects these three neighbors" — with the directional flow from low-level object to high-level protocol laid out in front of you.

## What it does

Point it at a config file. It parses every protocol, builds a dependency graph, and exports an interactive HTML diagram you can open in any browser — no server, no account, no internet connection required.

```bash
uvx confgraph map router.txt --output-dir .
open router.html
```

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

## Install

Requires [pip](https://packaging.python.org/en/latest/tutorials/installing-packages/):

```bash
pip install confgraph
```

Or run without installing via [uv](https://docs.astral.sh/uv/getting-started/installation/#homebrew):

```bash
uvx confgraph map router.txt
```

## Protocols parsed

VRF · BGP · OSPF · IS-IS · EIGRP · RIP · Route-maps · Prefix-lists · ACLs · Community lists · AS-path lists · Static routes · NTP · SNMP · Syslog · Banners · QoS · NAT · Crypto/IPsec · BFD · IP SLA · EEM · Object tracking · Multicast

## Use as a library

```python
from confgraph.parsers.ios_parser import IOSParser

parsed = IOSParser(open("router.txt").read()).parse()
print(parsed.bgp_instances)
print(parsed.route_maps)
```

## Security & Privacy

**Local-first by design.** confgraph never sends your config files anywhere. All parsing, graph generation, and analysis run entirely on your machine. The HTML output is a self-contained file with no external requests — no CDN, no analytics, no telemetry of any kind.

## Contributing

Contributions welcome — new parsers, bug fixes, additional protocol coverage. See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) to get started.

## License

Apache 2.0
