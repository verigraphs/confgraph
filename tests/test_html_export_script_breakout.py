"""Regression tests for CCR-0029 — `</script>` breakout in HTML exporters.

Device-controlled text (hostname, interface description, raw_config) is
embedded into an inline ``<script>`` block via JSON, and into the map's
``<title>`` / sidebar as HTML text.  A literal ``</script>`` in any of those
values must not be able to close the script element early (JS sink) nor break
out of the HTML element (HTML sink).

Two sinks, two rules:
  * ``json_for_script`` — JSON destined for an inline ``<script>``.
  * ``escape_html``      — device text destined for an HTML element/attribute.
"""

from __future__ import annotations

import networkx as nx

from confgraph.graph.exporters.html import HTMLExporter
from confgraph.topology.exporters import export_topology_html
from confgraph.utils.escaping import escape_html, json_for_script

# A payload that closes the script element and injects live DOM if unescaped.
PAYLOAD = "</script><img src=x onerror=alert(1)>"


def _elements_block(html: str) -> str:
    """Return the inline ``<script>`` block that carries ``const elements``.

    Slice runs from the opening ``<script>`` of that block through its intended
    closing ``</script>`` (just before ``</body>``).
    """
    open_idx = html.rindex("<script>", 0, html.index("const elements ="))
    body_idx = html.index("</body>", open_idx)
    return html[open_idx:body_idx]


def _render_map() -> str:
    g = nx.DiGraph()
    g.graph["hostname"] = f"edge-sw01{PAYLOAD}"
    g.graph["os"] = "ios"
    g.add_node(
        "interface:GigabitEthernet0/0",
        label="GigabitEthernet0/0",
        display_label="Gi0/0",
        type="interface",
        group="infrastructure",
        status="ok",
        color="#3b82f6",
        fill="#eff6ff",
        shape="ellipse",
        description=PAYLOAD,
        raw_config=f"interface GigabitEthernet0/0\n description {PAYLOAD}\n",
    )
    return HTMLExporter().export(g)


def _render_topology() -> str:
    g = nx.MultiGraph()
    g.add_node(f"rtr-a{PAYLOAD}", os="ios", asn=65001, router_id="10.0.0.1", color="#374151")
    g.add_node("rtr-b", os="ios", asn=65002, router_id="10.0.0.2", color="#374151")
    g.add_edge(
        f"rtr-a{PAYLOAD}",
        "rtr-b",
        edge_type="bgp",
        label=PAYLOAD,
        description=PAYLOAD,
    )
    return export_topology_html(g)


# ── JS sink: data → <script> boundary ──────────────────────────────────────

def test_map_elements_block_has_no_script_breakout():
    """No `</script>` between the opening <script> of the elements block and
    its intended close, even though hostname/description/raw_config all carry
    the payload."""
    block = _elements_block(_render_map())
    inner = block[len("<script>"): block.rindex("</script>")]
    assert "</script>" not in inner
    # The data survived — neutralized, not dropped.
    assert "\\u003c/script\\u003e" in block


def test_topology_elements_block_has_no_script_breakout():
    """Same guarantee for the topology exporter's elements block."""
    block = _elements_block(_render_topology())
    inner = block[len("<script>"): block.rindex("</script>")]
    assert "</script>" not in inner
    assert "\\u003c/script\\u003e" in block


# ── HTML sink: device text → HTML element (map template only) ──────────────

def test_map_hostname_escaped_in_title():
    """The hostname payload in <title> is HTML-escaped, so `</script>` cannot
    appear inside the title text."""
    html = _render_map()
    title = html[html.index("<title>"): html.index("</title>")]
    assert "</script>" not in title
    assert "&lt;/script&gt;" in title


def test_map_hostname_escaped_in_sidebar():
    """The sidebar <strong>{hostname}</strong> payload is HTML-escaped."""
    html = _render_map()
    header = html[html.index('<div id="sidebar-header">'): html.index('<div id="sidebar-body">')]
    assert "</script>" not in header
    assert "&lt;/script&gt;" in header


# ── Unit coverage of the shared encoders ───────────────────────────────────

def test_json_for_script_neutralizes_close_tag():
    out = json_for_script({"v": PAYLOAD})
    assert "</script>" not in out
    assert "</" not in out
    assert "\\u003c/script\\u003e" in out


def test_escape_html_neutralizes_angle_brackets():
    assert escape_html(PAYLOAD) == "&lt;/script&gt;&lt;img src=x onerror=alert(1)&gt;"
