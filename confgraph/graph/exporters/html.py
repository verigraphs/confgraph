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
    * Node detail panel on click (all attributes)
    * Color/shape legend per node type; edge legend (resolved vs dangling)
    * Group filter checkboxes (routing/policy/management/qos/security/infrastructure)
    * Orphan highlight toggle
    * Live search (highlights matching nodes)
    * Layout selector (cose, breadthfirst, circle, grid, concentric)
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

        # Collect unique node types for the legend (color/shape come from node data attributes)
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
        # Status overlay rules (data selectors — safe with :: in node IDs)
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
    border-radius: 2px;
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
    width: 14px; height: 10px;
    border-radius: 2px;
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
.detail-tabs {{
    display: flex;
    gap: 4px;
    margin-bottom: 8px;
}}
.detail-tab {{
    padding: 3px 10px;
    font-size: 11px;
    border-radius: 3px;
    cursor: pointer;
    border: 1px solid #cbd5e1;
    background: #ffffff;
    color: #64748b;
    user-select: none;
}}
.detail-tab.active {{
    background: #1e40af;
    border-color: #1e40af;
    color: #fff;
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
#detail-raw {{
    display: none;
    background: #0f172a;
    border-radius: 4px;
    padding: 8px 10px;
    max-height: 280px;
    overflow-y: auto;
    font-family: "SF Mono", "Fira Code", "Cascadia Code", monospace;
    font-size: 11px;
    line-height: 1.6;
    color: #86efac;
    white-space: pre;
    word-break: normal;
}}
#detail-raw::-webkit-scrollbar {{ width: 4px; }}
#detail-raw::-webkit-scrollbar-thumb {{ background: #334155; border-radius: 2px; }}
#detail-attrs {{ display: block; }}

/* ── Cytoscape canvas ────────────────────────────────────────────── */
#cy {{
    flex: 1;
    background: #f8fafc;
    background-image:
        linear-gradient(rgba(148,163,184,0.15) 1px, transparent 1px),
        linear-gradient(90deg, rgba(148,163,184,0.15) 1px, transparent 1px);
    background-size: 24px 24px;
}}

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
        <div class="detail-tabs">
          <div class="detail-tab active" id="tab-attrs">Attributes</div>
          <div class="detail-tab" id="tab-raw">Raw Config</div>
        </div>
        <div id="detail-attrs"></div>
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
          <div class="dot" style="background:#F9FAFB;border:2px dashed #9CA3AF;border-radius:50%"></div>
          <span class="legend-label">Missing object (ghost)</span>
        </div>
      </div>
    </div>

  </div><!-- /sidebar-body -->
</div><!-- /sidebar -->

<div id="cy"></div>

<script>
(function() {{
  // ── Graph data ──────────────────────────────────────────────────────────────
  const elements = {elements_json};
  const legendStyles = {legend_items_js};
  const statusStyleRules = {status_style_rules_js};

  // ── Cytoscape style sheet ───────────────────────────────────────────────────
  // Network-diagram theme: white/light fill, colored border, dark label
  const baseStyles = [
    {{
      selector: 'node',
      style: {{
        'label': 'data(label)',
        'background-color': 'data(fill)',
        'shape': 'data(shape)',
        'font-size': '10px',
        'font-weight': '600',
        'color': '#1e293b',
        'text-valign': 'center',
        'text-halign': 'center',
        'text-wrap': 'wrap',
        'text-max-width': '90px',
        'width': 'label',
        'height': 'label',
        'padding': '8px',
        'border-width': 2.5,
        'border-color': 'data(color)',
        'border-opacity': 1,
      }}
    }},
    {{
      selector: 'edge',
      style: {{
        'width': 1.5,
        'line-color': '#94a3b8',
        'target-arrow-color': '#94a3b8',
        'target-arrow-shape': 'triangle',
        'curve-style': 'bezier',
        'opacity': 0.85,
      }}
    }},
    {{
      selector: 'edge[resolved = 0]',
      style: {{
        'line-color': '#DC2626',
        'target-arrow-color': '#DC2626',
        'line-style': 'dashed',
        'opacity': 0.9,
      }}
    }},
    {{
      selector: '.highlighted',
      style: {{
        'border-width': 4,
        'border-color': '#1d4ed8',
        'border-opacity': 1,
        'background-color': '#dbeafe',
        'z-index': 9999,
      }}
    }},
    {{
      selector: '.faded',
      style: {{ 'opacity': 0.18 }}
    }},
    {{
      selector: '.orphan-highlighted',
      style: {{
        'border-width': 4,
        'border-color': '#D97706',
        'border-style': 'dashed',
        'border-opacity': 1,
      }}
    }},
    {{
      selector: 'edge.highlighted',
      style: {{
        'line-color': '#1d4ed8',
        'target-arrow-color': '#1d4ed8',
        'opacity': 1,
        'width': 2.5,
        'z-index': 9999,
      }}
    }},
    {{
      selector: 'node[?isCompound]',
      style: {{
        'background-color': '#f8fafc',
        'background-opacity': 0.45,
        'border-width': 1,
        'border-color': '#cbd5e1',
        'border-style': 'dashed',
        'label': 'data(label)',
        'font-size': '10px',
        'font-weight': '700',
        'text-valign': 'top',
        'text-halign': 'center',
        'color': '#94a3b8',
        'padding': '20px',
        'shape': 'roundrectangle',
      }}
    }},
  ].concat(statusStyleRules);

  // ── Compound parent nodes (one container per group) ─────────────────────────
  const groupLabels = {{
    routing: 'Routing', policy: 'Policy', infrastructure: 'Infrastructure',
    qos: 'QoS', security: 'Security', management: 'Management',
    missing: 'Missing refs', other: 'Other',
  }};
  const groupsPresent = [...new Set(elements.nodes.map(n => n.data.group).filter(Boolean))];
  const compoundNodes = groupsPresent.map(g => ({{
    data: {{ id: `__grp_${{g}}`, label: groupLabels[g] || g, isCompound: true, group: g }}
  }}));
  const augmentedElements = {{
    nodes: compoundNodes.concat(elements.nodes.map(n => ({{
      ...n,
      data: {{ ...n.data, parent: `__grp_${{n.data.group || 'other'}}` }},
    }}))),
    edges: elements.edges,
  }};

  const cy = cytoscape({{
    container: document.getElementById('cy'),
    elements: augmentedElements,
    style: baseStyles,
    layout: {{ name: 'cose', animate: false, randomize: true, padding: 40 }},
    wheelSensitivity: 0.3,
  }});

  // ── Stats ───────────────────────────────────────────────────────────────────
  function updateStats() {{
    const visible = cy.nodes('[!isCompound]:visible').length;
    const orphans = cy.nodes('[!isCompound][status = "orphan"]').length;
    const missing = cy.nodes('[!isCompound][status = "missing"]').length;
    const dangling = cy.edges('[resolved = false]').length;
    document.getElementById('stat-visible').textContent = visible;
    document.getElementById('stat-orphan').textContent = orphans;
    document.getElementById('stat-missing').textContent = missing;
    document.getElementById('stat-dangling').textContent = dangling;
  }}
  cy.ready(updateStats);

  // ── Legend ──────────────────────────────────────────────────────────────────
  const legendEl = document.getElementById('legend-nodes');
  Object.entries(legendStyles).forEach(([type, style]) => {{
    const row = document.createElement('div');
    row.className = 'legend-item';
    const radius = style.shape === 'ellipse' ? '50%' : '3px';
    const fill = style.fill || '#ffffff';
    row.innerHTML = `<div class="legend-swatch" style="background:${{fill}};border:2px solid ${{style.color}};border-radius:${{radius}}"></div>
                     <span class="legend-label">${{type}}</span>`;
    legendEl.appendChild(row);
  }});

  // ── Group filters ────────────────────────────────────────────────────────────
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

  function applyGroupFilters() {{
    const hidden = new Set();
    document.querySelectorAll('#group-filters input[type=checkbox]').forEach(chk => {{
      if (!chk.checked) hidden.add(chk.dataset.group);
    }});
    cy.nodes('[!isCompound]').forEach(n => {{
      if (hidden.has(n.data('group'))) {{
        n.hide(); n.connectedEdges().hide();
      }} else {{
        n.show();
      }}
    }});
    // Show/hide compound containers based on whether any children are visible
    cy.nodes('[?isCompound]').forEach(compound => {{
      if (compound.children(':visible').length > 0) compound.show();
      else compound.hide();
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
    cy.elements().removeClass('highlighted faded');
    if (!q) {{ searchCount.textContent = ''; return; }}
    const matched = cy.nodes('[!isCompound]').filter(n => n.data('label').toLowerCase().includes(q));
    cy.nodes('[!isCompound]').not(matched).addClass('faded');
    matched.addClass('highlighted');
    searchCount.textContent = matched.length + ' match' + (matched.length !== 1 ? 'es' : '');
  }});

  // ── Detail panel ─────────────────────────────────────────────────────────────
  const detailPanel = document.getElementById('detail-panel');
  const detailTitle = document.getElementById('detail-title');
  const detailAttrs = document.getElementById('detail-attrs');
  const detailRaw   = document.getElementById('detail-raw');
  const SKIP_KEYS = new Set(['id', 'label', 'color', 'shape', 'raw_config']);

  function switchTab(tab) {{
    document.getElementById('tab-attrs').classList.toggle('active', tab === 'attrs');
    document.getElementById('tab-raw').classList.toggle('active', tab === 'raw');
    detailAttrs.style.display = tab === 'attrs' ? 'block' : 'none';
    detailRaw.style.display   = tab === 'raw'   ? 'block' : 'none';
  }}

  // Wire tab clicks via JS (not inline onclick — switchTab is inside IIFE)
  document.getElementById('tab-attrs').addEventListener('click', function() {{ switchTab('attrs'); }});
  document.getElementById('tab-raw').addEventListener('click', function() {{ switchTab('raw'); }});

  cy.on('tap', 'node', function(evt) {{
    const node = evt.target;
    if (node.data('isCompound')) return;  // ignore compound container clicks
    const d = node.data();

    // ── Neighbourhood highlight ───────────────────────────────────────────────
    cy.elements().removeClass('highlighted faded');
    const hood = node.closedNeighborhood().not('[?isCompound]');
    cy.elements('[!isCompound]').not(hood).addClass('faded');
    hood.addClass('highlighted');
    // Keep edges inside neighbourhood vivid
    hood.connectedEdges().removeClass('faded').addClass('highlighted');

    // ── Detail panel ──────────────────────────────────────────────────────────
    detailTitle.textContent = d.label || d.id;
    detailAttrs.innerHTML = '';
    Object.entries(d).forEach(([k, v]) => {{
      if (SKIP_KEYS.has(k)) return;
      const row = document.createElement('div');
      row.className = 'detail-row';
      row.innerHTML = `<span class="detail-key">${{k}}</span><span class="detail-val">${{String(v)}}</span>`;
      detailAttrs.appendChild(row);
    }});
    const raw = d.raw_config || '';
    detailRaw.textContent = raw || '(no raw config available)';
    detailPanel.classList.add('visible');
    switchTab('attrs');
  }});

  cy.on('tap', function(evt) {{
    if (evt.target === cy) {{
      detailPanel.classList.remove('visible');
      cy.elements().removeClass('highlighted faded');
      document.getElementById('search').value = '';
      searchCount.textContent = '';
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
