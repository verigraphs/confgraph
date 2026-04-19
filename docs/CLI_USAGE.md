# confgraph CLI Usage

`confgraph` parses network device configs and generates interactive dependency graphs or object summaries.

---

## Commands

### `confgraph map`

Generates an interactive HTML dependency graph (and optionally JSON) from a config file.

```
confgraph map CONFIG_FILE [OPTIONS]
```

| Option | Values | Default | Description |
|---|---|---|---|
| `--os` | `eos`, `ios`, `nxos`, `iosxr`, `junos` | auto-detected | OS type of the config file |
| `--out` | `html`, `json`, `both` | `html` | Output format |
| `--output-dir` | path | current dir | Directory to write output files |
| `--lint` | — | off | Surface orphaned objects and dangling references |
| `--lint-severity` | `error`, `warn`, `all` | `all` | Filter lint issues by severity |

### `confgraph info`

Prints a summary of parsed objects (interfaces, ACLs, route-maps, etc.) from a config file.

```
confgraph info CONFIG_FILE [OPTIONS]
```

| Option | Values | Default | Description |
|---|---|---|---|
| `--os` | `eos`, `ios`, `nxos`, `iosxr`, `junos` | auto-detected | OS type of the config file |

---

## Examples

**Basic graph from a config file:**
```bash
confgraph map router1.cfg
```

**Specify OS type explicitly:**
```bash
confgraph map router1.cfg --os iosxr
```

**Save output to a specific directory:**
```bash
confgraph map router1.cfg --output-dir /tmp/graphs
```

**Generate both HTML and JSON output:**
```bash
confgraph map router1.cfg --out both
```

**Run lint to find orphaned objects and dangling references:**
```bash
confgraph map router1.cfg --lint
```

**Run lint and show only errors:**
```bash
confgraph map router1.cfg --lint --lint-severity error
```

**Print a parsed object summary:**
```bash
confgraph info router1.cfg --os nxos
```

---

## CONFGRAPH_INVENTORY

Set `CONFGRAPH_INVENTORY` to the path of a CSV file to auto-resolve OS type by hostname instead of relying on auto-detection.

```bash
export CONFGRAPH_INVENTORY=/path/to/inventory.csv
confgraph map router1.cfg
```

When `--os` is not provided, confgraph matches the config filename against the device name column in the CSV and reads the OS type from there.

**Supported device name column names:** `device_name`, `device`, `devicename`, `hostname`, `host_name`

**Supported OS type column names:** `os_type`, `ostype`, `os-type`

**Supported OS type values:** `ios`, `iosxr`, `nxos`, `eos`, `junos`

**Example CSV:**
```csv
hostname,os_type
router1,iosxr
switch1,nxos
core-fw,eos
```
