"""BaseExporter — abstract base class for all graph exporters."""

from __future__ import annotations

from abc import ABC, abstractmethod

import networkx as nx


class BaseExporter(ABC):
    """Convert a NetworkX DiGraph to a string representation.

    Subclasses implement :meth:`export` and return whatever string format
    they target (JSON, HTML, GML, etc.).  The graph contract:

    * ``g.graph["hostname"]`` — device hostname
    * ``g.graph["os"]``       — OS type string
    * Node attributes: ``label``, ``type``, ``group``, ``status``,
      ``shape``, ``color``, ``hostname``, plus optional type-specific extras
    * Edge attributes: ``id``, ``field``, ``resolved``
    """

    @abstractmethod
    def export(self, graph: nx.DiGraph) -> str:
        """Convert *graph* to an output string."""
