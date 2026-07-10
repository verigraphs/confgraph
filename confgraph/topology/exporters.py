"""Topology graph exporters — JSON and static HTML.

Both exporters consume the nx.MultiGraph produced by TopologyGraphBuilder.

JSON
----
Machine-readable format consumed by the enterprise simulator (TOPO-3).
Schema:
  {
    "devices": { hostname: { os, asn, router_id } },
    "links": [
      { "type": "physical"|"bgp"|"igp",
        "device_a": ..., "device_b": ...,
        <type-specific fields> }
    ]
  }

HTML
----
Static self-contained file using Cytoscape.js (same library as the existing
per-device map command). Opens directly in a browser, no server required.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import networkx as nx

from confgraph.utils.escaping import json_for_script

# Reuse the bundled Cytoscape.js assets from the existing graph exporter
_ASSETS_DIR = Path(__file__).parent.parent / "graph" / "assets"
_CYTOSCAPE_JS = _ASSETS_DIR / "cytoscape.min.js"
_DAGRE_JS = _ASSETS_DIR / "dagre.min.js"
_CYTOSCAPE_DAGRE_JS = _ASSETS_DIR / "cytoscape-dagre.min.js"


# ---------------------------------------------------------------------------
# JSON exporter
# ---------------------------------------------------------------------------

def export_topology_json(g: nx.MultiGraph) -> str:
    """Serialize the topology graph to JSON."""
    devices: dict = {}
    for node, attrs in g.nodes(data=True):
        devices[node] = {
            "os": attrs.get("os", ""),
            "asn": attrs.get("asn"),
            "router_id": attrs.get("router_id"),
            "color": attrs.get("color", ""),
        }

    links: list[dict] = []
    for u, v, attrs in g.edges(data=True):
        edge: dict = {"device_a": u, "device_b": v}
        edge.update({k: v2 for k, v2 in attrs.items() if k != "color"})
        links.append(edge)

    return json.dumps({"devices": devices, "links": links}, indent=2, default=str)


# ---------------------------------------------------------------------------
# HTML exporter
# ---------------------------------------------------------------------------

def export_topology_html(g: nx.MultiGraph, title: str = "Network Topology") -> str:
    """Render the topology graph as a static self-contained HTML file.

    Matches the look-and-feel of the per-device ``confgraph map`` output:
    collapsible/resizable sidebar, dotted grid background, hover tooltips,
    layout switcher, animated node isolation on click, and a detail panel.
    """
    cytoscape_js = _CYTOSCAPE_JS.read_text(encoding="utf-8")
    dagre_js = (
        _DAGRE_JS.read_text(encoding="utf-8") + "\n" +
        _CYTOSCAPE_DAGRE_JS.read_text(encoding="utf-8")
    )

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    device_count = g.number_of_nodes()
    edge_count = g.number_of_edges()

    # Build Cytoscape elements in {nodes, edges} format
    nodes = []
    for node, attrs in g.nodes(data=True):
        os_str = attrs.get("os", "")
        asn = attrs.get("asn")
        label_parts = [node]
        if asn:
            label_parts.append(str(asn))

        nodes.append({
            "data": {
                "id": node,
                "label": node,
                "display_label": "\n".join(label_parts),
                "os": os_str,
                "asn": str(asn) if asn else "",
                "router_id": attrs.get("router_id") or "",
                "color": attrs.get("color", "#374151"),
            }
        })

    edges = []
    for i, (u, v, attrs) in enumerate(g.edges(data=True)):
        edge_type = attrs.get("edge_type", "unknown")
        line_style = attrs.get("style", "solid")
        color = attrs.get("color", "#9ca3af")
        edges.append({
            "data": {
                "id": f"e{i}",
                "source": u,
                "target": v,
                "label": attrs.get("label", ""),
                "edge_type": edge_type,
                "color": color,
                "line_style": line_style,
                # Extra attrs for detail panel
                "description": attrs.get("description", ""),
                "session_type": attrs.get("session_type", ""),
                "route_map_out_a": attrs.get("route_map_out_a", ""),
                "route_map_in_a": attrs.get("route_map_in_a", ""),
                "route_map_out_b": attrs.get("route_map_out_b", ""),
                "route_map_in_b": attrs.get("route_map_in_b", ""),
                "protocol": attrs.get("protocol", ""),
                "area": attrs.get("area", ""),
                "cost": str(attrs.get("cost", "")) if attrs.get("cost") is not None else "",
                "port_a": attrs.get("port_a", ""),
                "port_b": attrs.get("port_b", ""),
                "member_count": str(attrs.get("member_count", "")),
            }
        })

    elements_json = json_for_script({"nodes": nodes, "edges": edges})

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title>
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
    max-width: 480px;
    background: rgba(255, 255, 255, 0.82);
    backdrop-filter: blur(10px);
    -webkit-backdrop-filter: blur(10px);
    border-right: 1px solid #e2e8f0;
    display: flex;
    flex-direction: column;
    overflow: hidden;
    flex-shrink: 0;
    box-shadow: 2px 0 16px rgba(0,0,0,0.07);
    transition: width 0.25s ease, min-width 0.25s ease;
    position: relative;
}}
#sidebar.collapsed {{
    width: 0 !important;
    min-width: 0 !important;
    border-right: none;
}}
#sidebar-resize {{
    position: absolute;
    top: 0; right: 0;
    width: 5px;
    height: 100%;
    cursor: col-resize;
    z-index: 10;
    background: transparent;
}}
#sidebar-resize:hover {{ background: rgba(59,130,246,0.2); }}
#sidebar-toggle {{
    position: fixed;
    top: 50%;
    left: 300px;
    transform: translateY(-50%);
    z-index: 100;
    width: 18px;
    height: 48px;
    background: rgba(255,255,255,0.92);
    border: 1px solid #e2e8f0;
    border-left: none;
    border-radius: 0 6px 6px 0;
    box-shadow: 2px 0 8px rgba(0,0,0,0.08);
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    color: #64748b;
    font-size: 11px;
    transition: left 0.25s ease, background 0.15s;
    user-select: none;
    padding: 0;
    line-height: 1;
}}
#sidebar-toggle:hover {{ background: #f1f5f9; color: #1e40af; }}
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

/* ── Toggle switch ───────────────────────────────────────────────── */
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
    max-width: 280px;
}}
#tooltip .tip-meta {{ font-size: 10px; color: #94a3b8; }}
#tooltip .tip-name {{ font-weight: 700; word-break: break-all; }}

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
.legend-edge {{
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 5px;
}}
.edge-line {{
    width: 28px; height: 2px;
    border-radius: 1px;
    flex-shrink: 0;
}}
.edge-dashed {{
    width: 28px; height: 0;
    border-top: 2px dashed currentColor;
    flex-shrink: 0;
}}
.edge-dotted {{
    width: 28px; height: 0;
    border-top: 2px dotted currentColor;
    flex-shrink: 0;
}}
.legend-label {{ font-size: 11px; color: #475569; }}

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

/* ── Canvas wrapper ──────────────────────────────────────────────── */
#canvas-wrapper {{
    flex: 1;
    position: relative;
}}
#cy {{
    width: 100%;
    height: 100%;
    background: transparent;
}}

/* ── Back button ─────────────────────────────────────────────────── */
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

<button id="sidebar-toggle" title="Toggle sidebar">‹</button>

<div id="sidebar">
  <div id="sidebar-resize"></div>
  <div id="sidebar-header">
    <h1>&#128279; {title}</h1>
    <div class="meta">
      {device_count} devices &nbsp;·&nbsp; {edge_count} connections<br>
      {generated_at}
    </div>
  </div>

  <div id="sidebar-body">

    <!-- Search -->
    <div class="section">
      <div class="section-title">Search</div>
      <input id="search" type="text" placeholder="Filter devices by name…">
      <div id="search-count"></div>
    </div>

    <!-- Detail panel -->
    <div class="section">
      <div class="section-title">Selected</div>
      <div id="detail-panel">
        <div id="detail-title"></div>
        <div id="detail-attrs"></div>
      </div>
    </div>

    <!-- Edge type filters -->
    <div class="section">
      <div class="section-title">Edge Types</div>
      <div id="edge-filters"></div>
    </div>

    <!-- Layout -->
    <div class="section">
      <div class="section-title">Layout</div>
      <select id="layout-select">
        <option value="dagre" selected>Hierarchical (Dagre)</option>
        <option value="cose">Force-directed (Cose)</option>
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
      <div class="legend-edge">
        <div class="edge-line" style="background:#9ca3af"></div>
        <span class="legend-label">Physical link</span>
      </div>
      <div class="legend-edge">
        <div class="edge-dashed" style="color:#3b82f6"></div>
        <span class="legend-label">BGP iBGP</span>
      </div>
      <div class="legend-edge">
        <div class="edge-dashed" style="color:#f59e0b"></div>
        <span class="legend-label">BGP eBGP</span>
      </div>
      <div class="legend-edge">
        <div class="edge-dotted" style="color:#10b981"></div>
        <span class="legend-label">IGP (OSPF / IS-IS)</span>
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
  const elements = {elements_json};

  // ── Pre-compute degree per node ──────────────────────────────────────────
  const degreeMap = {{}};
  elements.edges.forEach(e => {{
    degreeMap[e.data.source] = (degreeMap[e.data.source] || 0) + 1;
    degreeMap[e.data.target] = (degreeMap[e.data.target] || 0) + 1;
  }});
  elements.nodes.forEach(n => {{
    n.data.degree = degreeMap[n.data.id] || 0;
  }});

  // ── Cytoscape style ──────────────────────────────────────────────────────
  const baseStyles = [
    {{
      selector: 'node',
      style: {{
        'label': 'data(display_label)',
        'background-color': 'data(color)',
        'shape': 'round-rectangle',
        'corner-radius': 8,
        'width': 'label',
        'height': 'label',
        'padding': '14px',
        'border-width': 2,
        'border-color': '#1e293b',
        'border-opacity': 0.3,
        'font-size': '11px',
        'font-weight': '600',
        'color': '#ffffff',
        'text-valign': 'center',
        'text-halign': 'center',
        'text-wrap': 'wrap',
        'text-max-width': '100px',
        'min-width': '70px',
        'min-height': '44px',
        'text-outline-color': 'data(color)',
        'text-outline-width': 1,
        'shadow-blur': 6,
        'shadow-color': 'data(color)',
        'shadow-opacity': 0.15,
        'shadow-offset-x': 0,
        'shadow-offset-y': 2,
        'transition-property': 'opacity, border-color, border-width',
        'transition-duration': '0.15s',
      }}
    }},
    {{
      selector: '.selected-node',
      style: {{
        'border-width': 3,
        'border-color': '#f59e0b',
        'border-opacity': 1,
        'shadow-blur': 20,
        'shadow-color': '#f59e0b',
        'shadow-opacity': 0.5,
        'z-index': 9999,
      }}
    }},
    {{
      selector: '.neighbor-node',
      style: {{
        'border-width': 2.5,
        'border-color': '#f59e0b',
        'border-opacity': 0.6,
        'z-index': 999,
      }}
    }},
    {{
      selector: '.faded',
      style: {{ 'opacity': 0.1 }}
    }},
    {{
      selector: 'edge',
      style: {{
        'label': 'data(label)',
        'font-size': '9px',
        'color': '#475569',
        'text-background-color': '#ffffff',
        'text-background-opacity': 0.85,
        'text-background-padding': '2px',
        'width': 1.5,
        'line-color': 'data(color)',
        'line-style': 'data(line_style)',
        'curve-style': 'bezier',
        'text-wrap': 'wrap',
        'text-max-width': 200,
        'opacity': 0.7,
        'transition-property': 'opacity, width',
        'transition-duration': '0.15s',
      }}
    }},
    {{
      selector: 'edge[edge_type = "physical"]',
      style: {{ 'width': 3, 'opacity': 0.85 }}
    }},
    {{
      selector: 'edge.active-edge',
      style: {{
        'opacity': 1,
        'width': 2.5,
        'z-index': 9999,
      }}
    }},
    {{
      selector: 'edge:selected',
      style: {{
        'line-color': '#f59e0b',
        'opacity': 1,
        'width': 2.5,
      }}
    }},
  ];

  const cy = cytoscape({{
    container: document.getElementById('cy'),
    elements: elements,
    style: baseStyles,
    layout: {{
      name: 'dagre',
      animate: false,
      rankDir: 'TB',
      ranker: 'network-simplex',
      nodeSep: 80,
      rankSep: 120,
      padding: 60,
      fit: true,
    }},
    wheelSensitivity: 0.3,
  }});

  setTimeout(function() {{
    cy.fit(undefined, 100);
    cy.zoom(cy.zoom() * 0.85);
    cy.center();
  }}, 0);

  // ── Layout configs ────────────────────────────────────────────────────────
  const layoutConfigs = {{
    'dagre': {{
      name: 'dagre', animate: true, animationDuration: 500,
      rankDir: 'TB', ranker: 'network-simplex',
      nodeSep: 80, rankSep: 120, padding: 60, fit: true,
    }},
    'cose': {{
      name: 'cose', animate: true, animationDuration: 500,
      randomize: true, padding: 80,
      nodeRepulsion: function() {{ return 120000; }},
      idealEdgeLength: function() {{ return 200; }},
      edgeElasticity: function() {{ return 60; }},
      gravity: 0.05, numIter: 2000, fit: true,
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
      padding: 80, fit: true, minNodeSpacing: 50,
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

  document.getElementById('btn-fit').addEventListener('click', function() {{
    cy.fit(undefined, 100);
    cy.zoom(cy.zoom() * 0.85);
    cy.center();
  }});

  // ── Edge type filters ─────────────────────────────────────────────────────
  const EDGE_TYPES = [
    {{ type: 'physical', label: 'Physical', color: '#9ca3af' }},
    {{ type: 'bgp',      label: 'BGP',      color: '#3b82f6' }},
    {{ type: 'igp',      label: 'IGP',      color: '#10b981' }},
  ];
  const hiddenTypes = new Set();
  const filtersEl = document.getElementById('edge-filters');

  // Only render filter rows for types that actually exist in the graph
  const presentTypes = new Set(elements.edges.map(e => e.data.edge_type));

  EDGE_TYPES.forEach(def => {{
    if (!presentTypes.has(def.type)) return;
    const row = document.createElement('label');
    row.className = 'filter-row';
    const toggleLabel = document.createElement('label');
    toggleLabel.className = 'toggle';
    const chk = document.createElement('input');
    chk.type = 'checkbox';
    chk.checked = true;
    chk.dataset.edgetype = def.type;
    chk.addEventListener('change', function() {{
      if (this.checked) {{ hiddenTypes.delete(def.type); }}
      else {{ hiddenTypes.add(def.type); }}
      applyEdgeFilter();
    }});
    const track = document.createElement('span');
    track.className = 'toggle-track';
    toggleLabel.appendChild(chk);
    toggleLabel.appendChild(track);
    const dot = document.createElement('div');
    dot.className = 'dot';
    dot.style.background = def.color;
    const lbl = document.createElement('span');
    lbl.className = 'filter-label';
    lbl.textContent = def.label;
    row.appendChild(toggleLabel);
    row.appendChild(dot);
    row.appendChild(lbl);
    filtersEl.appendChild(row);
  }});

  function applyEdgeFilter() {{
    cy.edges().forEach(e => {{
      if (hiddenTypes.has(e.data('edge_type'))) e.hide();
      else e.show();
    }});
  }}

  // ── Detail panel ──────────────────────────────────────────────────────────
  const detailPanel = document.getElementById('detail-panel');
  const detailTitle = document.getElementById('detail-title');
  const detailAttrs = document.getElementById('detail-attrs');

  function showNodeDetail(node) {{
    const d = node.data();
    detailTitle.textContent = d.label || d.id;
    detailAttrs.innerHTML = '';
    const fields = [
      ['OS', d.os],
      ['ASN', d.asn],
      ['Router-ID', d.router_id],
      ['Connections', String(d.degree || 0)],
    ];
    fields.forEach(([k, v]) => {{
      if (!v) return;
      const row = document.createElement('div');
      row.className = 'detail-row';
      row.innerHTML = `<span class="detail-key">${{k}}</span><span class="detail-val">${{v}}</span>`;
      detailAttrs.appendChild(row);
    }});
    detailPanel.classList.add('visible');
  }}

  function showEdgeDetail(edge) {{
    const d = edge.data();
    detailTitle.textContent = d.edge_type.toUpperCase() + ': ' + d.source + ' ↔ ' + d.target;
    detailAttrs.innerHTML = '';
    const fields = [
      ['Label', d.label],
      ['Session', d.session_type],
      ['Description', d.description],
      ['Protocol', d.protocol],
      ['Area', d.area],
      ['Cost', d.cost],
      ['Port A', d.port_a],
      ['Port B', d.port_b],
      ['Members', d.member_count !== '1' && d.member_count ? d.member_count : ''],
      ['Out→ A', d.route_map_out_a],
      ['In← A', d.route_map_in_a],
      ['Out→ B', d.route_map_out_b],
      ['In← B', d.route_map_in_b],
    ];
    fields.forEach(([k, v]) => {{
      if (!v) return;
      const row = document.createElement('div');
      row.className = 'detail-row';
      row.innerHTML = `<span class="detail-key">${{k}}</span><span class="detail-val">${{v}}</span>`;
      detailAttrs.appendChild(row);
    }});
    detailPanel.classList.add('visible');
  }}

  function hideDetail() {{
    detailPanel.classList.remove('visible');
  }}

  // ── Drag tracking ─────────────────────────────────────────────────────────
  let wasDragged = false;
  cy.on('drag', 'node', function() {{ wasDragged = true; }});

  // ── Node isolation ────────────────────────────────────────────────────────
  const backBtn = document.getElementById('back-btn');
  let isolated = false;
  let savedPositions = {{}};

  function isolateNode(node) {{
    savedPositions = {{}};
    cy.nodes().forEach(n => {{ savedPositions[n.id()] = {{ ...n.position() }}; }});

    const hood = node.closedNeighborhood();
    cy.elements().not(hood).hide();
    hood.show();
    cy.elements().removeClass('selected-node neighbor-node active-edge faded');
    node.addClass('selected-node');
    hood.nodes().not(node).addClass('neighbor-node');
    hood.edges().addClass('active-edge');

    hood.layout({{
      name: 'concentric',
      animate: true,
      animationDuration: 400,
      animationEasing: 'ease-out-cubic',
      padding: 100,
      concentric: function(n) {{ return n.same(node) ? 2 : 1; }},
      levelWidth: function() {{ return 1; }},
      minNodeSpacing: 100,
      fit: true,
    }}).run();

    setTimeout(function() {{
      if (cy.zoom() > 1.2) cy.zoom({{ level: 1.2, renderedPosition: {{ x: cy.width() / 2, y: cy.height() / 2 }} }});
    }}, 420);

    backBtn.style.display = 'block';
    isolated = true;
    showNodeDetail(node);
  }}

  function restoreFullGraph() {{
    cy.elements().show();
    cy.elements().removeClass('selected-node neighbor-node active-edge faded');
    if (Object.keys(savedPositions).length > 0) {{
      cy.nodes().forEach(n => {{
        if (savedPositions[n.id()]) n.position(savedPositions[n.id()]);
      }});
      savedPositions = {{}};
    }}
    applyEdgeFilter();
    backBtn.style.display = 'none';
    isolated = false;
    hideDetail();
    cy.fit(undefined, 80);
  }}

  backBtn.addEventListener('click', restoreFullGraph);

  cy.on('tap', 'node', function(evt) {{
    if (wasDragged) {{ wasDragged = false; return; }}
    isolateNode(evt.target);
  }});

  cy.on('tap', 'edge', function(evt) {{
    if (wasDragged) {{ wasDragged = false; return; }}
    cy.elements().removeClass('selected-node neighbor-node active-edge faded');
    showEdgeDetail(evt.target);
  }});

  cy.on('tap', function(evt) {{
    if (evt.target === cy) restoreFullGraph();
  }});

  // ── Hover tooltip ─────────────────────────────────────────────────────────
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
      cy.elements().addClass('faded');
      evt.target.neighborhood().add(evt.target).removeClass('faded');
    }}
    const d = evt.target.data();
    const deg = evt.target.degree();
    const meta = [d.os, d.asn ? 'AS' + d.asn : ''].filter(Boolean).join(' · ');
    tooltip.innerHTML =
      `<div class="tip-meta">${{meta || 'device'}} &nbsp;·&nbsp; ${{deg}} connection${{deg !== 1 ? 's' : ''}}</div>` +
      `<div class="tip-name">${{d.label}}</div>`;
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
    const typeLabel = d.session_type || d.protocol || d.edge_type;
    tooltip.innerHTML =
      `<div class="tip-meta">${{typeLabel}}</div>` +
      `<div class="tip-name">${{d.source}} ↔ ${{d.target}}</div>`;
    tooltip.style.display = 'block';
    placeTooltip(evt.originalEvent.clientX, evt.originalEvent.clientY);
  }});
  cy.on('mousemove', 'edge', function(evt) {{
    placeTooltip(evt.originalEvent.clientX, evt.originalEvent.clientY);
  }});
  cy.on('mouseout', 'edge', function() {{
    tooltip.style.display = 'none';
  }});

  // ── Search ────────────────────────────────────────────────────────────────
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

  // ── Sidebar collapse / resize ─────────────────────────────────────────────
  const sidebar = document.getElementById('sidebar');
  const toggleBtn = document.getElementById('sidebar-toggle');
  let sidebarWidth = 300;

  function updateTogglePos() {{
    const w = sidebar.classList.contains('collapsed') ? 0 : sidebar.offsetWidth;
    toggleBtn.style.left = w + 'px';
    toggleBtn.textContent = sidebar.classList.contains('collapsed') ? '›' : '‹';
  }}

  toggleBtn.addEventListener('click', function() {{
    if (sidebar.classList.contains('collapsed')) {{
      sidebar.classList.remove('collapsed');
      sidebar.style.width = sidebarWidth + 'px';
    }} else {{
      sidebarWidth = sidebar.offsetWidth;
      sidebar.classList.add('collapsed');
    }}
    setTimeout(function() {{ updateTogglePos(); cy.resize(); }}, 260);
  }});

  const resizeHandle = document.getElementById('sidebar-resize');
  let isResizing = false, startX, startWidth;

  resizeHandle.addEventListener('mousedown', function(e) {{
    isResizing = true;
    startX = e.clientX;
    startWidth = sidebar.offsetWidth;
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
  }});
  document.addEventListener('mousemove', function(e) {{
    if (!isResizing) return;
    const newWidth = Math.min(480, Math.max(220, startWidth + e.clientX - startX));
    sidebar.style.width = newWidth + 'px';
    sidebarWidth = newWidth;
    updateTogglePos();
  }});
  document.addEventListener('mouseup', function() {{
    if (!isResizing) return;
    isResizing = false;
    document.body.style.cursor = '';
    document.body.style.userSelect = '';
    cy.resize();
  }});

}})();
</script>
</body>
</html>"""
