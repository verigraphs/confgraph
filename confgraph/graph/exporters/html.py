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


def _load_cytoscape() -> str:
    """Return the inlined Cytoscape.js source."""
    return _CYTOSCAPE_JS.read_text(encoding="utf-8")


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
             "style": {"border-style": "dashed", "border-opacity": 0.6}},
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
<style>
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    display: flex;
    height: 100vh;
    overflow: hidden;
    background: #f1f5f9;
    color: #1e293b;
}}

/* ── Sidebar ─────────────────────────────────────────────────────── */
#sidebar {{
    width: 300px;
    min-width: 220px;
    max-width: 400px;
    background: #ffffff;
    border-right: 1px solid #e2e8f0;
    display: flex;
    flex-direction: column;
    overflow: hidden;
    flex-shrink: 0;
    box-shadow: 2px 0 8px rgba(0,0,0,0.06);
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
    margin-bottom: 5px;
    cursor: pointer;
    user-select: none;
}}
.filter-row input[type=checkbox] {{ accent-color: #1e40af; cursor: pointer; }}
.filter-label {{ font-size: 12px; color: #334155; }}
.dot {{
    width: 10px; height: 10px;
    border-radius: 50%;
    flex-shrink: 0;
}}

/* ── Orphan toggle ───────────────────────────────────────────────── */
#orphan-toggle {{
    display: flex;
    align-items: center;
    gap: 8px;
    cursor: pointer;
    user-select: none;
}}
#orphan-toggle input {{ accent-color: #1e40af; cursor: pointer; }}
#orphan-toggle label {{ font-size: 12px; color: #334155; cursor: pointer; }}

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

/* ── Stats ────────────────────────────────────────────────────────── */
.stat-row {{
    display: flex;
    justify-content: space-between;
    font-size: 12px;
    padding: 3px 0;
    color: #64748b;
}}
.stat-row span:last-child {{ color: #1e293b; font-weight: 600; }}

/* ── Legend ──────────────────────────────────────────────────────── */
.legend-item {{
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 4px;
}}
.legend-swatch {{
    width: 12px; height: 12px;
    border-radius: 50%;
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

/* ── Canvas wrapper ──────────────────────────────────────────────── */
#canvas-wrapper {{
    flex: 1;
    position: relative;
}}

/* ── Cytoscape canvas ────────────────────────────────────────────── */
#cy {{
    width: 100%;
    height: 100%;
    background: #f8fafc;
    background-image:
        linear-gradient(rgba(148,163,184,0.15) 1px, transparent 1px),
        linear-gradient(90deg, rgba(148,163,184,0.15) 1px, transparent 1px);
    background-size: 24px 24px;  /* updated dynamically via JS on zoom/pan */
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
    </div>

    <!-- Detail panel -->
    <div class="section">
      <div class="section-title">Selected Node</div>
      <div id="detail-panel">
        <div id="detail-title"></div>
        <div id="detail-attrs"></div>
        <div class="raw-config-label">Raw Config</div>
        <div id="detail-raw"></div>
      </div>
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
        <input type="checkbox" id="chk-orphan">
        <label for="chk-orphan">Highlight orphaned nodes</label>
      </div>
    </div>

    <!-- Layout -->
    <div class="section">
      <div class="section-title">Layout</div>
      <select id="layout-select">
        <option value="cose">Cose (default)</option>
        <option value="breadthfirst">Breadth-first</option>
        <option value="circle">Circle</option>
        <option value="concentric">Concentric</option>
        <option value="grid">Grid</option>
      </select>
      <button class="btn" id="btn-fit" style="margin-top:6px">Fit to screen</button>
    </div>

    <!-- Stats -->
    <div class="section">
      <div class="section-title">Statistics</div>
      <div class="stat-row"><span>Total nodes</span><span id="stat-total">{node_count}</span></div>
      <div class="stat-row"><span>Visible</span><span id="stat-visible">—</span></div>
      <div class="stat-row"><span>Orphaned</span><span id="stat-orphan">—</span></div>
      <div class="stat-row"><span>Missing refs</span><span id="stat-missing">—</span></div>
      <div class="stat-row"><span>Total edges</span><span id="stat-edges">{edge_count}</span></div>
      <div class="stat-row"><span>Dangling edges</span><span id="stat-dangling">—</span></div>
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
</div>

<script>
(function() {{
  // ── Graph data ──────────────────────────────────────────────────────────────
  const elements = {elements_json};
  const legendStyles = {legend_items_js};
  const statusStyleRules = {status_style_rules_js};

  // ── Cytoscape style sheet ───────────────────────────────────────────────────
  const baseStyles = [
    {{
      selector: 'node',
      style: {{
        'label': 'data(label)',
        'background-color': 'data(fill)',
        'shape': 'ellipse',
        'width': 'label',
        'height': 'label',
        'padding': '14px',
        'border-width': 1.5,
        'border-color': 'data(color)',
        'border-opacity': 1,
        'font-size': '10px',
        'font-weight': '600',
        'color': '#1e293b',
        'text-valign': 'center',
        'text-halign': 'center',
        'text-wrap': 'wrap',
        'text-max-width': '100px',
        'min-width': '50px',
        'min-height': '50px',
      }}
    }},
    {{
      selector: 'node[status = "missing"]',
      style: {{
        'border-style': 'dashed',
        'border-width': 1,
        'border-opacity': 0.6,
        'background-color': '#F9FAFB',
        'font-size': '9px',
        'color': '#9CA3AF',
        'padding': '10px',
      }}
    }},
    {{
      selector: 'edge',
      style: {{
        'width': 1,
        'line-color': '#94a3b8',
        'target-arrow-color': '#94a3b8',
        'target-arrow-shape': 'triangle',
        'curve-style': 'bezier',
        'opacity': 0.6,
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
  // Initial: randomized start, high repulsion, low gravity → spread nodes out
  const initialLayout = {{
    name: 'cose',
    animate: false,
    randomize: true,
    padding: 80,
    nodeRepulsion: function() {{ return 80000; }},
    idealEdgeLength: function() {{ return 220; }},
    edgeElasticity: function() {{ return 60; }},
    gravity: 0.05,
    numIter: 3000,
    initialTemp: 400,
    coolingFactor: 0.98,
    minTemp: 1.0,
    fit: true,
  }};

  // Drag-settle: no randomize so nodes don't jump; lighter pass
  const settleLayout = {{
    name: 'cose',
    animate: true,
    animationDuration: 500,
    animationEasing: 'ease-out-cubic',
    randomize: false,
    padding: 80,
    nodeRepulsion: function() {{ return 80000; }},
    idealEdgeLength: function() {{ return 220; }},
    edgeElasticity: function() {{ return 60; }},
    gravity: 0.05,
    numIter: 400,
    initialTemp: 80,
    coolingFactor: 0.95,
    minTemp: 1.0,
    fit: false,
  }};

  const cy = cytoscape({{
    container: document.getElementById('cy'),
    elements: elements,
    style: baseStyles,
    layout: initialLayout,
    wheelSensitivity: 0.3,
  }});

  // ── Live physics: re-settle after dragging a node ──────────────────────────
  let settleTimer = null;
  cy.on('dragfree', 'node', function() {{
    clearTimeout(settleTimer);
    settleTimer = setTimeout(function() {{
      cy.layout(settleLayout).run();
    }}, 80);
  }});

  // ── State ───────────────────────────────────────────────────────────────────
  let isolated = false;

  // ── Stats ───────────────────────────────────────────────────────────────────
  function updateStats() {{
    const visible = cy.nodes(':visible').length;
    const orphans = cy.nodes('[status = "orphan"]').length;
    const missing = cy.nodes('[status = "missing"]').length;
    const dangling = cy.edges('[resolved = false]').length;
    document.getElementById('stat-visible').textContent = visible;
    document.getElementById('stat-orphan').textContent = orphans;
    document.getElementById('stat-missing').textContent = missing;
    document.getElementById('stat-dangling').textContent = dangling;
  }}
  cy.ready(updateStats);

  // ── Dynamic grid: scales and pans with the canvas ──────────────────────────
  const cyEl = document.getElementById('cy');
  const BASE_GRID = 24;
  function updateGrid() {{
    const zoom = cy.zoom();
    const pan  = cy.pan();
    const size = BASE_GRID * zoom;
    cyEl.style.backgroundSize = `${{size}}px ${{size}}px`;
    cyEl.style.backgroundPosition = `${{pan.x % size}}px ${{pan.y % size}}px`;
  }}
  cy.on('zoom pan', updateGrid);
  cy.ready(updateGrid);

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

  // ── Group filters ─────────────────────────────────────────────────────────
  const groups = [...new Set(elements.nodes.map(n => n.data.group).filter(Boolean))].sort();
  const groupColors = {{
    infrastructure: '#1565C0', routing: '#1B5E20', policy: '#7C2D12',
    qos: '#134E4A', security: '#7F1D1D', management: '#374151',
    missing: '#9CA3AF', other: '#6B7280',
  }};
  const filtersEl = document.getElementById('group-filters');
  groups.forEach(group => {{
    const row = document.createElement('label');
    row.className = 'filter-row';
    const chk = document.createElement('input');
    chk.type = 'checkbox';
    chk.checked = true;
    chk.dataset.group = group;
    chk.addEventListener('change', applyGroupFilters);
    const dot = document.createElement('div');
    dot.className = 'dot';
    dot.style.background = groupColors[group] || '#AAB7B8';
    const lbl = document.createElement('span');
    lbl.className = 'filter-label';
    lbl.textContent = group;
    row.appendChild(chk);
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
    cy.nodes().forEach(n => {{
      if (hidden.has(n.data('group'))) {{
        n.hide(); n.connectedEdges().hide();
      }} else {{
        n.show();
        // only show edges whose both endpoints are visible
      }}
    }});
    cy.edges().forEach(e => {{
      if (e.source().visible() && e.target().visible()) e.show();
      else e.hide();
    }});
    updateStats();
  }}

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
  const SKIP_KEYS = new Set(['id', 'label', 'color', 'fill', 'shape', 'raw_config']);

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
    isolateNode(evt.target);
  }});

  cy.on('tap', function(evt) {{
    if (evt.target === cy) {{
      restoreFullGraph();
    }}
  }});

  // ── Layout selector ───────────────────────────────────────────────────────────
  document.getElementById('layout-select').addEventListener('change', function() {{
    cy.layout({{ name: this.value, animate: true, animationDuration: 400, padding: 40 }}).run();
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
