"""HTMLExporter — exports a graph as a single self-contained HTML file.

No internet connection required at render time: Cytoscape.js is inlined
from the bundled asset at ``configz/graph/assets/cytoscape.min.js``.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import networkx as nx

from confgraph.graph.exporters.base import BaseExporter
from confgraph.graph.exporters.json import JSONExporter

# Path to the bundled Cytoscape.js asset (resolved relative to this file)
_ASSETS_DIR = Path(__file__).parent.parent / "assets"
_CYTOSCAPE_JS = _ASSETS_DIR / "cytoscape.min.js"
_DAGRE_JS = _ASSETS_DIR / "dagre.min.js"
_CYTOSCAPE_DAGRE_JS = _ASSETS_DIR / "cytoscape-dagre.min.js"


def _load_cytoscape() -> str:
    """Return the inlined Cytoscape.js source."""
    return _CYTOSCAPE_JS.read_text(encoding="utf-8")


def _load_dagre() -> str:
    """Return inlined dagre + cytoscape-dagre sources."""
    return (
        _DAGRE_JS.read_text(encoding="utf-8") + "\n" +
        _CYTOSCAPE_DAGRE_JS.read_text(encoding="utf-8")
    )


class HTMLExporter(BaseExporter):
    """Generate a fully self-contained, offline-capable HTML visualisation.

    Features
    --------
    * Interactive pan/zoom Cytoscape.js canvas
    * All round (ellipse) nodes
    * Click a node → isolate view to that node + direct neighbors
    * Node detail panel: attributes + raw config shown in sidebar
    * Group filter checkboxes
    * Orphan highlight toggle
    * Live search
    * Layout selector
    """

    def export(self, graph: nx.DiGraph) -> str:
        graph_json = json.loads(JSONExporter().export(graph))
        hostname = graph.graph.get("hostname", "unknown")
        os_type = graph.graph.get("os", "unknown")
        generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        node_count = graph.number_of_nodes()
        edge_count = graph.number_of_edges()

        cytoscape_js = _load_cytoscape()
        dagre_js = _load_dagre()
        elements_json = json.dumps(graph_json["elements"])

        type_styles: dict[str, dict] = {}
        for _, attrs in graph.nodes(data=True):
            t = attrs.get("type", "unknown")
            if t not in type_styles:
                type_styles[t] = {
                    "color": attrs.get("color", "#AAB7B8"),
                    "shape": attrs.get("shape", "ellipse"),
                    "group": attrs.get("group", "other"),
                }

        legend_items_js = json.dumps(type_styles)
        status_style_rules_js = json.dumps([
            {"selector": "node[status = 'missing']",
             "style": {"border-style": "dashed", "border-opacity": 0.7, "opacity": 0.45}},
            {"selector": "node[status = 'orphan']",
             "style": {"border-width": 4, "border-color": "#D97706", "border-opacity": 1}},
        ])

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>confgraph — {hostname}</title>
<script>{cytoscape_js}</script>
<script>{dagre_js}</script>
<style>
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    display: flex;
    height: 100vh;
    overflow: hidden;
    background-color: #f8fafc;
    background-image: radial-gradient(#e2e8f0 1px, transparent 1px);
    background-size: 20px 20px;
    color: #1e293b;
}}

/* ── Sidebar ─────────────────────────────────────────────────────── */
#sidebar {{
    width: 300px;
    min-width: 220px;
    max-width: 400px;
    background: rgba(255, 255, 255, 0.82);
    backdrop-filter: blur(10px);
    -webkit-backdrop-filter: blur(10px);
    border-right: 1px solid #e2e8f0;
    display: flex;
    flex-direction: column;
    overflow: hidden;
    flex-shrink: 0;
    box-shadow: 2px 0 16px rgba(0,0,0,0.07);
}}
#sidebar-header {{
    padding: 14px 16px 10px;
    border-bottom: 1px solid #e2e8f0;
    background: #1e40af;
}}
#sidebar-header h1 {{
    font-size: 15px;
    font-weight: 700;
    color: #ffffff;
    letter-spacing: .5px;
}}
#sidebar-header .meta {{
    font-size: 11px;
    color: #bfdbfe;
    margin-top: 3px;
    line-height: 1.5;
}}
#sidebar-body {{
    flex: 1;
    overflow-y: auto;
    padding: 12px;
}}
#sidebar-body::-webkit-scrollbar {{ width: 5px; }}
#sidebar-body::-webkit-scrollbar-track {{ background: #f8fafc; }}
#sidebar-body::-webkit-scrollbar-thumb {{ background: #cbd5e1; border-radius: 3px; }}

/* ── Sections ────────────────────────────────────────────────────── */
.section {{ margin-bottom: 16px; }}
.section-title {{
    font-size: 10px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: #94a3b8;
    margin-bottom: 8px;
    padding-bottom: 4px;
    border-bottom: 1px solid #e2e8f0;
}}

/* ── Search ─────────────────────────────────────────────────────── */
#search {{
    width: 100%;
    padding: 7px 10px;
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-radius: 4px;
    color: #1e293b;
    font-size: 13px;
    outline: none;
}}
#search:focus {{ border-color: #1e40af; box-shadow: 0 0 0 2px #bfdbfe; }}
#search-count {{
    font-size: 11px;
    color: #94a3b8;
    margin-top: 4px;
    min-height: 16px;
}}

/* ── Filters ─────────────────────────────────────────────────────── */
.filter-row {{
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 6px;
    cursor: pointer;
    user-select: none;
}}
.filter-label {{ font-size: 12px; color: #334155; flex: 1; }}
.dot {{
    width: 10px; height: 10px;
    border-radius: 3px;
    flex-shrink: 0;
}}

/* ── Toggle switch ───────────────────────────────────────────────── */
.toggle {{
    position: relative;
    display: inline-block;
    width: 30px;
    height: 17px;
    flex-shrink: 0;
}}
.toggle input {{ opacity: 0; width: 0; height: 0; position: absolute; }}
.toggle-track {{
    position: absolute;
    inset: 0;
    background: #cbd5e1;
    border-radius: 9px;
    cursor: pointer;
    transition: background 0.2s;
}}
.toggle-track::before {{
    content: '';
    position: absolute;
    width: 11px; height: 11px;
    left: 3px; top: 3px;
    background: #fff;
    border-radius: 50%;
    transition: transform 0.2s;
    box-shadow: 0 1px 3px rgba(0,0,0,0.2);
}}
.toggle input:checked + .toggle-track {{ background: #1e40af; }}
.toggle input:checked + .toggle-track::before {{ transform: translateX(13px); }}

/* ── Orphan toggle ───────────────────────────────────────────────── */
#orphan-toggle {{
    display: flex;
    align-items: center;
    gap: 8px;
    cursor: pointer;
    user-select: none;
}}
#orphan-toggle label {{ font-size: 12px; color: #334155; cursor: pointer; }}

/* ── Hover tooltip ───────────────────────────────────────────────── */
#tooltip {{
    position: fixed;
    display: none;
    pointer-events: none;
    background: #1e293b;
    color: #f1f5f9;
    padding: 7px 11px;
    border-radius: 6px;
    font-size: 11px;
    line-height: 1.6;
    box-shadow: 0 4px 14px rgba(0,0,0,0.3);
    z-index: 9999;
    max-width: 260px;
}}
#tooltip .tip-meta {{
    font-size: 10px;
    color: #94a3b8;
}}
#tooltip .tip-name {{
    font-weight: 700;
    word-break: break-all;
}}

/* ── Layout selector ─────────────────────────────────────────────── */
#layout-select {{
    width: 100%;
    padding: 6px 8px;
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-radius: 4px;
    color: #1e293b;
    font-size: 12px;
    outline: none;
    cursor: pointer;
}}
#layout-select:focus {{ border-color: #1e40af; }}

/* ── Legend ──────────────────────────────────────────────────────── */
.legend-item {{
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 4px;
}}
.legend-swatch {{
    width: 12px; height: 12px;
    border-radius: 3px;
    border: 2px solid transparent;
    flex-shrink: 0;
}}
.legend-label {{ font-size: 11px; color: #475569; }}
.legend-edge {{
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 5px;
}}
.edge-line {{
    width: 28px; height: 2px;
    border-radius: 1px;
}}
.edge-dashed {{
    width: 28px; height: 0;
    border-top: 2px dashed #DC2626;
}}

/* ── Detail panel ────────────────────────────────────────────────── */
#detail-panel {{
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-radius: 6px;
    padding: 10px 12px;
    min-height: 60px;
    display: none;
}}
#detail-panel.visible {{ display: block; }}
#detail-title {{
    font-size: 13px;
    font-weight: 700;
    color: #1e40af;
    margin-bottom: 8px;
    word-break: break-all;
}}
.detail-row {{
    display: flex;
    gap: 6px;
    margin-bottom: 3px;
    font-size: 11px;
    line-height: 1.4;
}}
.detail-key {{ color: #94a3b8; min-width: 80px; flex-shrink: 0; }}
.detail-val {{ color: #1e293b; word-break: break-all; }}
.raw-config-label {{
    font-size: 10px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: #94a3b8;
    margin: 10px 0 6px;
    padding-top: 8px;
    border-top: 1px solid #e2e8f0;
}}
#detail-raw-wrapper {{
    position: relative;
}}
#detail-raw {{
    background: #0f172a;
    border-radius: 4px;
    padding: 8px 10px;
    max-height: 220px;
    overflow-y: auto;
    font-family: "SF Mono", "Fira Code", "Cascadia Code", monospace;
    font-size: 10px;
    line-height: 1.6;
    color: #86efac;
    white-space: pre;
    word-break: normal;
}}
#detail-raw::-webkit-scrollbar {{ width: 4px; }}
#detail-raw::-webkit-scrollbar-thumb {{ background: #334155; border-radius: 2px; }}
#copy-raw-btn {{
    position: absolute;
    top: 5px;
    right: 5px;
    background: rgba(255,255,255,0.08);
    border: 1px solid rgba(255,255,255,0.15);
    border-radius: 4px;
    color: #94a3b8;
    font-size: 10px;
    padding: 2px 7px;
    cursor: pointer;
    line-height: 1.6;
    transition: background 0.15s, color 0.15s;
}}
#copy-raw-btn:hover {{ background: rgba(255,255,255,0.16); color: #e2e8f0; }}
#copy-raw-btn.copied {{ color: #86efac; border-color: #86efac; }}

/* ── Canvas wrapper ──────────────────────────────────────────────── */
#canvas-wrapper {{
    flex: 1;
    position: relative;
}}

/* ── Cytoscape canvas ────────────────────────────────────────────── */
#cy {{
    width: 100%;
    height: 100%;
    background: transparent;
}}

/* ── Back button (floating on canvas) ───────────────────────────── */
#back-btn {{
    display: none;
    position: absolute;
    top: 14px;
    right: 14px;
    z-index: 100;
    padding: 8px 16px;
    background: #1e40af;
    color: #fff;
    border: none;
    border-radius: 6px;
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
    box-shadow: 0 2px 8px rgba(0,0,0,0.2);
}}
#back-btn:hover {{ background: #1e3a8a; }}

/* ── Buttons ─────────────────────────────────────────────────────── */
.btn {{
    width: 100%;
    padding: 7px;
    background: #ffffff;
    border: 1px solid #1e40af;
    border-radius: 4px;
    color: #1e40af;
    font-size: 12px;
    font-weight: 500;
    cursor: pointer;
    text-align: center;
    margin-top: 4px;
}}
.btn:hover {{ background: #1e40af; color: #ffffff; }}
</style>
</head>
<body>

<div id="sidebar">
  <div id="sidebar-header">
    <h1>confgraph</h1>
    <div class="meta">
      <strong>{hostname}</strong> &nbsp;·&nbsp; {os_type.upper()}<br>
      {node_count} nodes &nbsp;·&nbsp; {edge_count} edges<br>
      {generated_at}
    </div>
  </div>

  <div id="sidebar-body">

    <!-- Search -->
    <div class="section">
      <div class="section-title">Search</div>
      <input id="search" type="text" placeholder="Filter nodes by name…">
      <div id="search-count"></div>
      <div style="margin-top:8px;display:flex;align-items:center;gap:8px;user-select:none;">
        <label class="toggle"><input type="checkbox" id="chk-isolates"><span class="toggle-track"></span></label>
        <label for="chk-isolates" style="font-size:12px;color:#334155;cursor:pointer;">Show unconnected nodes</label>
      </div>
    </div>

    <!-- Detail panel -->
    <div class="section">
      <div class="section-title">Selected Node</div>
      <div id="detail-panel">
        <div id="detail-title"></div>
        <div id="detail-attrs"></div>
        <div class="raw-config-label">Raw Config</div>
        <div id="detail-raw-wrapper">
          <button id="copy-raw-btn">Copy</button>
          <div id="detail-raw"></div>
        </div>
      </div>
    </div>

    <!-- Protocol Clusters -->
    <div class="section">
      <div class="section-title">Protocol Clusters</div>
      <div id="cluster-filters"></div>
      <div id="cluster-none" style="font-size:11px;color:#94a3b8;margin-top:4px;display:none;">No protocol clusters found</div>
    </div>

    <!-- Filters -->
    <div class="section">
      <div class="section-title">Groups</div>
      <div id="group-filters"></div>
    </div>

    <!-- Orphan toggle -->
    <div class="section">
      <div class="section-title">Highlighting</div>
      <div id="orphan-toggle">
        <label class="toggle"><input type="checkbox" id="chk-orphan"><span class="toggle-track"></span></label>
        <label for="chk-orphan">Highlight orphaned nodes</label>
      </div>
    </div>

    <!-- Layout -->
    <div class="section">
      <div class="section-title">Layout</div>
      <select id="layout-select">
        <option value="cose">Force-directed (Cose)</option>
        <option value="dagre" selected>Hierarchical (Dagre)</option>
        <option value="directed">Directed top-down</option>
        <option value="concentric-group">Concentric by group</option>
        <option value="breadthfirst">Breadth-first</option>
        <option value="circle">Circle</option>
        <option value="concentric">Concentric</option>
        <option value="grid">Grid</option>
      </select>
      <button class="btn" id="btn-fit" style="margin-top:6px">Fit to screen</button>
    </div>


    <!-- Legend -->
    <div class="section">
      <div class="section-title">Legend</div>
      <div id="legend-nodes"></div>
      <div style="margin-top:8px">
        <div class="legend-edge">
          <div class="edge-line" style="background:#94a3b8"></div>
          <span class="legend-label">Resolved reference</span>
        </div>
        <div class="legend-edge">
          <div class="edge-dashed"></div>
          <span class="legend-label">Dangling reference</span>
        </div>
        <div class="legend-edge">
          <div class="dot" style="background:#F9FAFB;border:2px dashed #9CA3AF"></div>
          <span class="legend-label">Missing object (ghost)</span>
        </div>
      </div>
    </div>

  </div><!-- /sidebar-body -->
</div><!-- /sidebar -->

<div id="canvas-wrapper">
  <button id="back-btn">← Back to full graph</button>
  <div id="cy"></div>
  <div id="tooltip"></div>
</div>

<script>
(function() {{
  // ── Graph data ──────────────────────────────────────────────────────────────
  const elements = {elements_json};
  const legendStyles = {legend_items_js};

  // ── Pre-compute degree per node (used for isolate detection) ────────────────
  const degreeMap = {{}};
  elements.edges.forEach(e => {{
    degreeMap[e.data.source] = (degreeMap[e.data.source] || 0) + 1;
    degreeMap[e.data.target] = (degreeMap[e.data.target] || 0) + 1;
  }});
  elements.nodes.forEach(n => {{
    n.data.degree = degreeMap[n.data.id] || 0;
  }});
  const statusStyleRules = {status_style_rules_js};

  // ── Cytoscape style sheet ───────────────────────────────────────────────────
  const baseStyles = [
    {{
      selector: 'node',
      style: {{
        'label': 'data(display_label)',
        'background-color': 'data(fill)',
        'shape': 'round-rectangle',
        'corner-radius': 8,
        'width': 'label',
        'height': 'label',
        'padding': '12px',
        'border-width': 1.5,
        'border-color': 'data(color)',
        'border-opacity': 1,
        'font-size': '10px',
        'font-weight': '600',
        'color': '#1e293b',
        'text-valign': 'center',
        'text-halign': 'center',
        'text-wrap': 'wrap',
        'text-max-width': '80px',
        'min-width': '50px',
        'min-height': '36px',
        'shadow-blur': 6,
        'shadow-color': 'data(color)',
        'shadow-opacity': 0.10,
        'shadow-offset-x': 0,
        'shadow-offset-y': 2,
        'transition-property': 'opacity, background-color, border-color',
        'transition-duration': '0.15s',
      }}
    }},
    {{
      selector: 'node[status = "missing"]',
      style: {{
        'border-style': 'dashed',
        'border-width': 1,
        'border-opacity': 0.6,
        'background-color': '#f8fafc',
        'font-size': '9px',
        'color': '#94a3b8',
        'padding': '10px',
      }}
    }},
    {{
      selector: 'edge',
      style: {{
        'width': 1.5,
        'line-color': '#94a3b8',
        'target-arrow-color': '#94a3b8',
        'target-arrow-shape': 'triangle-tee',
        'curve-style': 'bezier',
        'opacity': 0.55,
        'transition-property': 'opacity, line-color',
        'transition-duration': '0.15s',
      }}
    }},
    {{
      selector: 'edge[resolved = 0]',
      style: {{
        'line-color': '#DC2626',
        'target-arrow-color': '#DC2626',
        'line-style': 'dashed',
        'opacity': 0.75,
      }}
    }},
    {{
      selector: '.selected-node',
      style: {{
        'border-width': 3,
        'z-index': 9999,
        'shadow-blur': 20,
        'shadow-color': 'data(color)',
        'shadow-opacity': 0.5,
        'shadow-offset-x': 0,
        'shadow-offset-y': 0,
      }}
    }},
    {{
      selector: '.neighbor-node',
      style: {{
        'border-width': 2.5,
        'z-index': 999,
      }}
    }},
    {{
      selector: '.faded',
      style: {{ 'opacity': 0.1 }}
    }},
    {{
      selector: '.orphan-highlighted',
      style: {{
        'border-width': 2,
        'border-color': '#D97706',
        'border-style': 'dashed',
        'border-opacity': 1,
      }}
    }},
    {{
      selector: 'edge.active-edge',
      style: {{
        'line-color': '#6366f1',
        'target-arrow-color': '#6366f1',
        'opacity': 0.6,
        'width': 1,
        'z-index': 9999,
      }}
    }},
  ].concat(statusStyleRules);

  // ── Layout configs ───────────────────────────────────────────────────────────
  // Initial: hierarchical top-to-bottom via Dagre
  const initialLayout = {{
    name: 'dagre',
    animate: false,
    rankDir: 'TB',
    ranker: 'network-simplex',
    nodeSep: 60,
    rankSep: 80,
    edgeSep: 20,
    padding: 60,
    fit: true,
  }};

  const cy = cytoscape({{
    container: document.getElementById('cy'),
    elements: elements,
    style: baseStyles,
    layout: initialLayout,
    wheelSensitivity: 0.3,
  }});

  // ── Type-based sizing: protocol/service nodes are slightly larger ─────────────
  // These are "anchor" objects that other config objects reference into.
  const LARGE_TYPES = new Set([
    'bgp_instance', 'ospf_instance', 'eigrp_instance', 'rip_instance', 'isis_instance',
    'policy_map', 'snmp', 'ntp', 'syslog', 'crypto', 'nat', 'multicast',
  ]);
  cy.nodes().forEach(function(n) {{
    if (n.data('status') === 'missing') return;
    if (LARGE_TYPES.has(n.data('type'))) {{
      n.style('padding', 20);
      n.style('font-size', '12px');
    }}
  }});

  // ── Drag tracking: prevent tap firing after a drag ─────────────────────────
  let wasDragged = false;
  cy.on('drag', 'node', function() {{ wasDragged = true; }});

  // ── State ───────────────────────────────────────────────────────────────────
  let isolated = false;

  function updateStats() {{}}  // no-op: statistics section removed

  // ── Legend ──────────────────────────────────────────────────────────────────
  const legendEl = document.getElementById('legend-nodes');
  Object.entries(legendStyles).forEach(([type, style]) => {{
    const row = document.createElement('div');
    row.className = 'legend-item';
    const fill = style.fill || '#ffffff';
    row.innerHTML = `<div class="legend-swatch" style="background:${{fill}};border-color:${{style.color}}"></div>
                     <span class="legend-label">${{type}}</span>`;
    legendEl.appendChild(row);
  }});

  // ── Protocol Clusters ────────────────────────────────────────────────────────
  // Each cluster is defined by a root node type. Membership is computed at
  // runtime by bidirectional graph traversal from all roots of that type.
  const CLUSTER_DEFS = [
    {{ id: 'bgp',    label: 'BGP',    rootType: 'bgp_instance',   color: '#1B5E20' }},
    {{ id: 'ospf',   label: 'OSPF',   rootType: 'ospf_instance',  color: '#166534' }},
    {{ id: 'eigrp',  label: 'EIGRP',  rootType: 'eigrp_instance', color: '#14532D' }},
    {{ id: 'isis',   label: 'IS-IS',  rootType: 'isis_instance',  color: '#15803D' }},
    {{ id: 'rip',    label: 'RIP',    rootType: 'rip_instance',   color: '#16a34a' }},
    {{ id: 'nat',    label: 'NAT',    rootType: 'nat',            color: '#7F1D1D' }},
    {{ id: 'crypto', label: 'Crypto / VPN', rootType: 'crypto',  color: '#991B1B' }},
    {{ id: 'qos',    label: 'QoS',    rootType: 'policy_map',     color: '#134E4A' }},
  ];

  // Build cluster node-id sets via BFS from all root nodes of each type
  function buildCluster(rootType) {{
    const roots = cy.nodes(`[type = "${{rootType}}"]`);
    if (roots.length === 0) return null;
    const visited = new Set();
    const queue = [];
    roots.forEach(r => {{ visited.add(r.id()); queue.push(r); }});
    while (queue.length > 0) {{
      const n = queue.shift();
      n.neighborhood('node').forEach(nb => {{
        if (!visited.has(nb.id())) {{
          visited.add(nb.id());
          queue.push(nb);
        }}
      }});
    }}
    return visited;  // Set of node IDs
  }}

  // Pre-compute clusters at startup
  const clusterMap = {{}};   // id → Set<nodeId>
  const activeClusters = new Set();  // currently selected cluster ids

  const clusterFiltersEl = document.getElementById('cluster-filters');
  let clusterCount = 0;

  CLUSTER_DEFS.forEach(def => {{
    const nodeSet = buildCluster(def.rootType);
    if (!nodeSet) return;  // protocol not present in config
    clusterMap[def.id] = nodeSet;
    clusterCount++;

    const row = document.createElement('label');
    row.className = 'filter-row';
    const toggleLabel = document.createElement('label');
    toggleLabel.className = 'toggle';
    const chk = document.createElement('input');
    chk.type = 'checkbox';
    chk.checked = false;
    chk.dataset.cluster = def.id;
    chk.addEventListener('change', applyClusterFilters);
    const track = document.createElement('span');
    track.className = 'toggle-track';
    toggleLabel.appendChild(chk);
    toggleLabel.appendChild(track);
    const dot = document.createElement('div');
    dot.className = 'dot';
    dot.style.background = def.color;
    const lbl = document.createElement('span');
    lbl.className = 'filter-label';
    lbl.textContent = `${{def.label}} (${{nodeSet.size}})`;
    row.appendChild(toggleLabel);
    row.appendChild(dot);
    row.appendChild(lbl);
    clusterFiltersEl.appendChild(row);
  }});

  if (clusterCount === 0) {{
    document.getElementById('cluster-none').style.display = 'block';
  }}

  function applyClusterFilters() {{
    activeClusters.clear();
    document.querySelectorAll('#cluster-filters input[type=checkbox]').forEach(chk => {{
      if (chk.checked) activeClusters.add(chk.dataset.cluster);
    }});

    if (activeClusters.size === 0) {{
      // No cluster selected → restore normal group filter view
      restoreFullGraph();
      return;
    }}

    // Union of all node IDs across selected clusters
    const visibleIds = new Set();
    activeClusters.forEach(cid => {{
      if (clusterMap[cid]) clusterMap[cid].forEach(id => visibleIds.add(id));
    }});

    // Save positions if not already saved
    if (Object.keys(savedPositions).length === 0) {{
      cy.nodes().forEach(n => {{ savedPositions[n.id()] = {{ ...n.position() }}; }});
    }}

    cy.elements().removeClass('selected-node neighbor-node active-edge faded');
    cy.nodes().forEach(n => {{
      if (visibleIds.has(n.id())) {{ n.show(); }}
      else {{ n.hide(); n.connectedEdges().hide(); }}
    }});
    cy.edges().forEach(e => {{
      if (e.source().visible() && e.target().visible()) e.show();
      else e.hide();
    }});

    backBtn.style.display = 'block';
    isolated = true;

    const visibleEles = cy.elements(':visible');
    visibleEles.layout({{
      name: 'dagre',
      animate: true,
      animationDuration: 400,
      rankDir: 'TB',
      ranker: 'network-simplex',
      nodeSep: 60,
      rankSep: 80,
      fit: true,
      padding: 60,
    }}).run();

    updateStats();
  }}

  // ── Group filters ─────────────────────────────────────────────────────────
  const groups = [...new Set(elements.nodes.map(n => n.data.group).filter(Boolean))].sort();
  const groupColors = {{
    infrastructure: '#3b82f6', routing: '#10b981', policy: '#f59e0b',
    qos: '#14b8a6', security: '#ef4444', management: '#64748b',
    missing: '#94a3b8', other: '#64748b',
  }};
  const filtersEl = document.getElementById('group-filters');
  groups.forEach(group => {{
    const row = document.createElement('label');
    row.className = 'filter-row';
    const toggleLabel = document.createElement('label');
    toggleLabel.className = 'toggle';
    const chk = document.createElement('input');
    chk.type = 'checkbox';
    chk.checked = true;
    chk.dataset.group = group;
    chk.addEventListener('change', applyGroupFilters);
    const track = document.createElement('span');
    track.className = 'toggle-track';
    toggleLabel.appendChild(chk);
    toggleLabel.appendChild(track);
    const dot = document.createElement('div');
    dot.className = 'dot';
    dot.style.background = groupColors[group] || '#94a3b8';
    const lbl = document.createElement('span');
    lbl.className = 'filter-label';
    lbl.textContent = group;
    row.appendChild(toggleLabel);
    row.appendChild(dot);
    row.appendChild(lbl);
    filtersEl.appendChild(row);
  }});

  function getHiddenGroups() {{
    const hidden = new Set();
    document.querySelectorAll('#group-filters input[type=checkbox]').forEach(chk => {{
      if (!chk.checked) hidden.add(chk.dataset.group);
    }});
    return hidden;
  }}

  function applyGroupFilters() {{
    if (isolated) return;  // don't interfere with isolated view
    const hidden = getHiddenGroups();
    const showIsolates = document.getElementById('chk-isolates').checked;
    cy.nodes().forEach(n => {{
      const isIsolate = (n.data('degree') || 0) === 0;
      if (hidden.has(n.data('group')) || (isIsolate && !showIsolates)) {{
        n.hide(); n.connectedEdges().hide();
      }} else {{
        n.show();
      }}
    }});
    cy.edges().forEach(e => {{
      if (e.source().visible() && e.target().visible()) e.show();
      else e.hide();
    }});
    updateStats();
  }}

  // ── Hide unconnected nodes on load; toggle via checkbox ──────────────────────
  document.getElementById('chk-isolates').addEventListener('change', applyGroupFilters);
  applyGroupFilters();

  // ── Orphan highlight ─────────────────────────────────────────────────────────
  document.getElementById('chk-orphan').addEventListener('change', function() {{
    if (this.checked) {{
      cy.nodes('[status = "orphan"]').addClass('orphan-highlighted');
    }} else {{
      cy.nodes().removeClass('orphan-highlighted');
    }}
  }});

  // ── Search ───────────────────────────────────────────────────────────────────
  const searchInput = document.getElementById('search');
  const searchCount = document.getElementById('search-count');
  searchInput.addEventListener('input', function() {{
    const q = this.value.trim().toLowerCase();
    cy.elements().removeClass('faded');
    if (!q) {{ searchCount.textContent = ''; return; }}
    const matched = cy.nodes().filter(n => n.data('label').toLowerCase().includes(q));
    cy.nodes().not(matched).addClass('faded');
    searchCount.textContent = matched.length + ' match' + (matched.length !== 1 ? 'es' : '');
  }});

  // ── Detail panel ─────────────────────────────────────────────────────────────
  const detailPanel = document.getElementById('detail-panel');
  const detailTitle = document.getElementById('detail-title');
  const detailAttrs = document.getElementById('detail-attrs');
  const detailRaw   = document.getElementById('detail-raw');
  const copyRawBtn  = document.getElementById('copy-raw-btn');
  const SKIP_KEYS = new Set(['id', 'label', 'display_label', 'color', 'fill', 'shape', 'raw_config']);

  copyRawBtn.addEventListener('click', function() {{
    const text = detailRaw.textContent;
    if (!text || text === '(no raw config available)') return;
    navigator.clipboard.writeText(text).then(() => {{
      copyRawBtn.textContent = 'Copied!';
      copyRawBtn.classList.add('copied');
      setTimeout(() => {{
        copyRawBtn.textContent = 'Copy';
        copyRawBtn.classList.remove('copied');
      }}, 1800);
    }});
  }});

  function showDetail(node) {{
    const d = node.data();
    detailTitle.textContent = d.label || d.id;
    detailAttrs.innerHTML = '';
    Object.entries(d).forEach(([k, v]) => {{
      if (SKIP_KEYS.has(k)) return;
      const row = document.createElement('div');
      row.className = 'detail-row';
      row.innerHTML = `<span class="detail-key">${{k}}</span><span class="detail-val">${{String(v)}}</span>`;
      detailAttrs.appendChild(row);
    }});
    detailRaw.textContent = d.raw_config || '(no raw config available)';
    detailPanel.classList.add('visible');
  }}

  function hideDetail() {{
    detailPanel.classList.remove('visible');
  }}

  // ── Isolation: show only clicked node + neighbors ─────────────────────────
  const backBtn = document.getElementById('back-btn');
  let savedPositions = {{}};

  function isolateNode(node) {{
    // Save all positions so we can restore them when going back
    savedPositions = {{}};
    cy.nodes().forEach(n => {{ savedPositions[n.id()] = {{ ...n.position() }}; }});

    const hood = node.closedNeighborhood();
    cy.elements().not(hood).hide();
    hood.show();
    cy.elements().removeClass('selected-node neighbor-node active-edge faded');
    node.addClass('selected-node');
    hood.nodes().not(node).addClass('neighbor-node');
    hood.edges().addClass('active-edge');

    // Concentric layout: selected node at center, neighbors equally spaced in a ring
    hood.layout({{
      name: 'concentric',
      animate: true,
      animationDuration: 400,
      animationEasing: 'ease-out-cubic',
      padding: 100,
      concentric: function(n) {{ return n.same(node) ? 2 : 1; }},
      levelWidth: function() {{ return 1; }},
      minNodeSpacing: 80,
      fit: true,
    }}).run();

    setTimeout(function() {{
      if (cy.zoom() > 1.2) cy.zoom({{ level: 1.2, renderedPosition: {{ x: cy.width() / 2, y: cy.height() / 2 }} }});
    }}, 420);

    backBtn.style.display = 'block';
    isolated = true;
    showDetail(node);
    updateStats();
  }}

  function restoreFullGraph() {{
    // Clear any active cluster selections
    document.querySelectorAll('#cluster-filters input[type=checkbox]').forEach(chk => {{
      chk.checked = false;
    }});
    activeClusters.clear();

    cy.elements().show();
    cy.elements().removeClass('selected-node neighbor-node active-edge faded');
    // Restore original positions from before isolation
    if (Object.keys(savedPositions).length > 0) {{
      cy.nodes().forEach(n => {{
        if (savedPositions[n.id()]) n.position(savedPositions[n.id()]);
      }});
      savedPositions = {{}};
    }}
    backBtn.style.display = 'none';
    isolated = false;
    hideDetail();
    applyGroupFilters();
    cy.fit(undefined, 80);
    searchInput.value = '';
    searchCount.textContent = '';
    updateStats();
  }}

  backBtn.addEventListener('click', restoreFullGraph);

  cy.on('tap', 'node', function(evt) {{
    if (wasDragged) {{ wasDragged = false; return; }}
    isolateNode(evt.target);
  }});

  cy.on('tap', function(evt) {{
    if (evt.target === cy) {{
      restoreFullGraph();
    }}
  }});

  // ── Hover tooltip ────────────────────────────────────────────────────────────
  const tooltip = document.getElementById('tooltip');

  function placeTooltip(clientX, clientY) {{
    const pad = 14;
    const tw = tooltip.offsetWidth;
    const th = tooltip.offsetHeight;
    const left = clientX + pad + tw > window.innerWidth  ? clientX - tw - pad : clientX + pad;
    const top  = clientY + pad + th > window.innerHeight ? clientY - th - pad : clientY + pad;
    tooltip.style.left = left + 'px';
    tooltip.style.top  = top  + 'px';
  }}

  cy.on('mouseover', 'node', function(evt) {{
    if (!isolated) {{
      const sel = evt.target;
      cy.elements().addClass('faded');
      sel.neighborhood().add(sel).removeClass('faded');
    }}
    const d = evt.target.data();
    const name = (d.label || d.id).split(':').slice(1).join(':') || d.label || d.id;
    const deg  = evt.target.degree();
    tooltip.innerHTML =
      `<div class="tip-meta">${{d.type || ''}} &nbsp;·&nbsp; ${{deg}} connection${{deg !== 1 ? 's' : ''}}</div>` +
      `<div class="tip-name">${{name}}</div>`;
    tooltip.style.display = 'block';
    placeTooltip(evt.originalEvent.clientX, evt.originalEvent.clientY);
  }});
  cy.on('mousemove', 'node', function(evt) {{
    placeTooltip(evt.originalEvent.clientX, evt.originalEvent.clientY);
  }});
  cy.on('mouseout', 'node', function() {{
    if (!isolated) cy.elements().removeClass('faded');
    tooltip.style.display = 'none';
  }});

  cy.on('mouseover', 'edge', function(evt) {{
    const d = evt.target.data();
    const resolved = d.resolved !== 0 && d.resolved !== false;
    tooltip.innerHTML =
      `<div class="tip-meta">${{resolved ? 'resolved ref' : '⚠ dangling ref'}}</div>` +
      `<div class="tip-name">${{d.field || ''}}</div>`;
    tooltip.style.display = 'block';
    placeTooltip(evt.originalEvent.clientX, evt.originalEvent.clientY);
  }});
  cy.on('mousemove', 'edge', function(evt) {{
    placeTooltip(evt.originalEvent.clientX, evt.originalEvent.clientY);
  }});
  cy.on('mouseout', 'edge', function() {{
    tooltip.style.display = 'none';
  }});

  // ── Layout selector ───────────────────────────────────────────────────────────
  // ── Layout configs per option ─────────────────────────────────────────────────
  const layoutConfigs = {{
    'dagre': {{
      name: 'dagre', animate: true, animationDuration: 500,
      rankDir: 'TB',       // top-to-bottom
      ranker: 'network-simplex',
      nodeSep: 60,         // horizontal spacing between nodes in same rank
      rankSep: 80,         // vertical spacing between ranks
      edgeSep: 20,
      padding: 60, fit: true,
    }},
    'cose': {{
      name: 'cose', animate: true, animationDuration: 500,
      randomize: true, padding: 80,
      nodeRepulsion: function() {{ return 80000; }},
      idealEdgeLength: function() {{ return 220; }},
      edgeElasticity: function() {{ return 60; }},
      gravity: 0.05, numIter: 2000, fit: true,
    }},
    'directed': {{
      name: 'breadthfirst', animate: true, animationDuration: 500,
      directed: true, spacingFactor: 0.9, padding: 60, fit: true,
      // Routing/protocol nodes as roots so they appear at the top
      roots: cy.nodes().filter(n => ['bgp_instance','ospf_instance','eigrp_instance',
        'rip_instance','isis_instance','policy_map','snmp','ntp','syslog',
        'crypto','nat','multicast'].includes(n.data('type'))),
    }},
    'concentric-group': {{
      name: 'concentric', animate: true, animationDuration: 500,
      padding: 60, fit: true, minNodeSpacing: 20,
      // Protocol/service nodes in centre, policy next, infra outer
      concentric: function(n) {{
        const t = n.data('type');
        if (['bgp_instance','ospf_instance','eigrp_instance','rip_instance',
             'isis_instance','policy_map','snmp','ntp','syslog','crypto',
             'nat','multicast'].includes(t)) return 4;
        if (['route_map','prefix_list','acl','community_list','as_path_list',
             'class_map'].includes(t)) return 3;
        if (['interface','vrf','static_route'].includes(t)) return 2;
        return 1;
      }},
      levelWidth: function() {{ return 1; }},
    }},
    'breadthfirst': {{
      name: 'breadthfirst', animate: true, animationDuration: 500,
      spacingFactor: 1.6, padding: 80, fit: true,
    }},
    'circle': {{
      name: 'circle', animate: true, animationDuration: 500,
      padding: 80, fit: true,
    }},
    'concentric': {{
      name: 'concentric', animate: true, animationDuration: 500,
      padding: 80, fit: true, minNodeSpacing: 30,
    }},
    'grid': {{
      name: 'grid', animate: true, animationDuration: 500,
      padding: 80, fit: true,
    }},
  }};

  document.getElementById('layout-select').addEventListener('change', function() {{
    const cfg = layoutConfigs[this.value];
    if (cfg) cy.layout(cfg).run();
  }});

  // ── Fit to screen ─────────────────────────────────────────────────────────────
  document.getElementById('btn-fit').addEventListener('click', function() {{
    cy.fit(undefined, 40);
  }});

}})();
</script>
</body>
</html>"""
        return html
