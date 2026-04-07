"""JSONExporter — exports a graph as Cytoscape.js elements JSON."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import networkx as nx

from confgraph.graph.exporters.base import BaseExporter


class JSONExporter(BaseExporter):
    """Serialize a NetworkX DiGraph to Cytoscape.js-compatible JSON.

    Output structure::

        {
          "elements": {
            "nodes": [{"data": {...}}, ...],
            "edges": [{"data": {...}}, ...]
          },
          "meta": {"hostname": "...", "os": "...", "generated_at": "..."}
        }
    """

    def export(self, graph: nx.DiGraph) -> str:
        nodes = []
        for node_id, attrs in graph.nodes(data=True):
            nodes.append({"data": {"id": node_id, **attrs}})

        edges = []
        for src, tgt, attrs in graph.edges(data=True):
            edges.append({
                "data": {
                    "source": src,
                    "target": tgt,
                    **attrs,
                }
            })

        payload = {
            "elements": {
                "nodes": nodes,
                "edges": edges,
            },
            "meta": {
                "hostname": graph.graph.get("hostname", "unknown"),
                "os": graph.graph.get("os", "unknown"),
                "generated_at": datetime.now(timezone.utc).isoformat(),
            },
        }
        return json.dumps(payload, indent=2, default=str)
