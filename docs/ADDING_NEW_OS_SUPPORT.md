# Adding a New OS Parser

This guide walks through every file you need to touch to add full support for a new network OS. Follow the steps in order — each step depends on the previous ones.

---

## Step 0: Choose a parser pattern

There are three patterns in this codebase. Pick the one that matches the config format:

| Config format | Pattern | Example |
|---|---|---|
| IOS-style indented text | Extend `IOSParser` | EOS, NX-OS |
| Non-IOS indented text (brace/hierarchical) | Extend `BaseParser`, write custom tokenizer | JunOS |
| XML document | Extend `BaseParser`, use `xml.etree.ElementTree` | PAN-OS |

If the syntax is close enough to IOS that 80%+ of `parse_*` methods work unchanged, extend `IOSParser` and only override the methods that differ (see `EOSParser`). Otherwise extend `BaseParser` directly.

---

## Step 1: Add the OS type

**File:** `confgraph/models/base.py`

Add a value to the `OSType` enum:

```python
class OSType(str, Enum):
    ...
    MYOS = "myos"
```

---

## Step 2: Create the parser class

**File:** `confgraph/parsers/myos_parser.py`

Extend `BaseParser` (or `IOSParser`). You must implement these four abstract methods at minimum — the rest have default stubs that return empty lists:

```python
from confgraph.parsers.base import BaseParser
from confgraph.models.base import OSType

class MyOSParser(BaseParser):
    def __init__(self, config_text: str) -> None:
        super().__init__(config_text, OSType.MYOS, syntax="ios")

    def parse_vrfs(self) -> list[VRFConfig]: ...
    def parse_interfaces(self) -> list[InterfaceConfig]: ...
    def parse_bgp(self) -> list[BGPConfig]: ...
    def parse_ospf(self) -> list[OSPFConfig]: ...
    def parse_route_maps(self) -> list[RouteMapConfig]: ...
    def parse_prefix_lists(self) -> list[PrefixListConfig]: ...
```

All `parse_*` methods are wired into `BaseParser.parse()` automatically via `_PARSE_STEPS`. You do not need to call them yourself.

**If using CiscoConfParse** (IOS-style), call `self._get_parse_obj()` to get the lazy-loaded parse object.

**If NOT using CiscoConfParse** (XML, custom tokenizer), override:
- `_extract_hostname()` — return hostname from your format
- `_collect_unrecognized_blocks()` — return `[]`

---

## Step 3: Export from the parsers package

**File:** `confgraph/parsers/__init__.py`

```python
from confgraph.parsers.myos_parser import MyOSParser

__all__ = [..., "MyOSParser"]
```

---

## Step 4: Wire into the CLI

**File:** `confgraph/cli.py`

Two changes:

```python
# 1. Add alias mapping
_OS_ALIAS = {..., "myos": "myos"}

# 2. Add detection heuristic
def _detect_os(text: str) -> OSType:
    for sig in ("MyOS-specific-string",):
        if sig in text:
            return OSType.MYOS
    ...

# 3. Add dispatch
if detected == OSType.MYOS:
    from confgraph.parsers.myos_parser import MyOSParser
    parsed = MyOSParser(text).parse()

# 4. Add to --os option choices
@click.option("--os", type=click.Choice([..., "myos"]))
```

---

## Step 5: Add node styles to the graph builder

**File:** `confgraph/graph/builder.py`

If your OS introduces new node types (e.g., PAN-OS added `zone`), add entries to `NODE_STYLE` and `NODE_LABEL_PREFIX`, and add a node-creation block in `_add_defined_nodes()`.

If your OS reuses existing node types (interfaces, bgp_instance, etc.), no changes needed here.

---

## Step 6: Add dependency edges

**File:** `confgraph/analysis/dependency_resolver.py`

If your OS introduces new cross-reference relationships (e.g., zone → interface), add a `_resolve_myos_thing()` method and call it from `resolve()`:

```python
def resolve(self) -> DependencyReport:
    links = [...]
    links.extend(self._resolve_myos_thing())
    ...

def _resolve_myos_thing(self) -> list[DependencyLink]:
    links = []
    for zone in self._config.zones:
        for iface in zone.interfaces:
            links.append(self._link("zone", zone.name, "interface", "interface", iface))
    return links
```

---

## Step 7: Update the HTML exporter (optional)

**File:** `confgraph/graph/exporters/html.py`

If your OS adds new node types that should appear as sidebar clusters, add an entry to `CLUSTER_DEFS` and to the `LARGE_TYPES` set and layout roots arrays:

```javascript
const CLUSTER_DEFS = [
  ...
  { id: 'mytype', label: 'My Type', rootType: 'mytype', color: '#...' },
];
```

---

## Step 8: Create a sample config

**File:** `samples/myos_sample.<ext>`

Create a realistic sample that exercises all implemented parse methods. Then generate its HTML:

```bash
uv run confgraph map samples/myos_sample.cfg --os myos --output-dir samples/
```

Verify with:

```bash
uv run confgraph info samples/myos_sample.cfg --os myos
uv run confgraph map  samples/myos_sample.cfg --os myos --lint
```

---

## Step 9: Write documentation

Create `docs/MYOS_PARSER_SUPPORT.md` following the structure of any existing OS doc (e.g., [PANOS_PARSER_SUPPORT.md](PANOS_PARSER_SUPPORT.md)):

- Key syntax differences from IOS
- One section per supported protocol — syntax example, differences, supported attributes, parsing status
- Implemented methods summary table
- Known limitations
- Validated `confgraph info` output
- Auto-detection signals

Then add a row to [PARSER_SUPPORT_MATRIX.md](PARSER_SUPPORT_MATRIX.md) and update [README.md](../README.md).

---

## Checklist

```
[ ] models/base.py          — OSType enum value
[ ] parsers/myos_parser.py  — Parser class implementing parse_* methods
[ ] parsers/__init__.py     — Export MyOSParser
[ ] cli.py                  — Alias, detection, dispatch, --os choice
[ ] graph/builder.py        — Node styles + _add_defined_nodes (if new node types)
[ ] analysis/dependency_resolver.py — New edge resolvers (if new relationships)
[ ] graph/exporters/html.py — CLUSTER_DEFS (if new sidebar clusters)
[ ] samples/               — Sample config + generated HTML
[ ] docs/MYOS_PARSER_SUPPORT.md
[ ] docs/PARSER_SUPPORT_MATRIX.md
[ ] README.md
```
