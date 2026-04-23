"""GraphBuilder — converts ParsedConfig + DependencyReport into a NetworkX directed graph.

This module has no visualization dependency. The resulting nx.DiGraph can be
passed to any exporter (JSON, HTML, GML, etc.) without modification.
"""

from __future__ import annotations

import networkx as nx

from confgraph.models.parsed_config import ParsedConfig
from confgraph.analysis.dependency_resolver import DependencyReport, DependencyResolver


# ---------------------------------------------------------------------------
# Visual metadata — shapes and colors per node type.
# Defined here (not in exporters) so every exporter shares the same semantics.
# ---------------------------------------------------------------------------

# Network-diagram theme: all rectangles, muted group colors, light fills.
# color  = border/accent color  (shown as node border)
# fill   = background fill      (light tint of the group color)
NODE_STYLE: dict[str, dict[str, str]] = {
    # ── Infrastructure ───────────────────────────────────────────────────────
    "interface":      {"shape": "round-rectangle", "color": "#3b82f6", "fill": "#eff6ff", "group": "infrastructure"},
    "vrf":            {"shape": "round-rectangle", "color": "#3b82f6", "fill": "#eff6ff", "group": "infrastructure"},
    "bfd":            {"shape": "round-rectangle", "color": "#3b82f6", "fill": "#eff6ff", "group": "infrastructure"},
    "ip_sla":         {"shape": "round-rectangle", "color": "#3b82f6", "fill": "#eff6ff", "group": "infrastructure"},
    "object_track":   {"shape": "round-rectangle", "color": "#3b82f6", "fill": "#eff6ff", "group": "infrastructure"},
    "eem_applet":     {"shape": "round-rectangle", "color": "#3b82f6", "fill": "#eff6ff", "group": "infrastructure"},
    # ── Routing ──────────────────────────────────────────────────────────────
    "bgp_instance":   {"shape": "round-rectangle", "color": "#10b981", "fill": "#ecfdf5", "group": "routing"},
    "ospf_instance":  {"shape": "round-rectangle", "color": "#10b981", "fill": "#ecfdf5", "group": "routing"},
    "eigrp_instance": {"shape": "round-rectangle", "color": "#10b981", "fill": "#ecfdf5", "group": "routing"},
    "rip_instance":   {"shape": "round-rectangle", "color": "#10b981", "fill": "#ecfdf5", "group": "routing"},
    "isis_instance":  {"shape": "round-rectangle", "color": "#10b981", "fill": "#ecfdf5", "group": "routing"},
    "static_route":   {"shape": "round-rectangle", "color": "#10b981", "fill": "#ecfdf5", "group": "routing"},
    "multicast":      {"shape": "round-rectangle", "color": "#10b981", "fill": "#ecfdf5", "group": "routing"},
    # ── Policy ───────────────────────────────────────────────────────────────
    "route_map":      {"shape": "round-rectangle", "color": "#f59e0b", "fill": "#fffbeb", "group": "policy"},
    "prefix_list":    {"shape": "round-rectangle", "color": "#f59e0b", "fill": "#fffbeb", "group": "policy"},
    "acl":            {"shape": "round-rectangle", "color": "#f59e0b", "fill": "#fffbeb", "group": "policy"},
    "community_list": {"shape": "round-rectangle", "color": "#f59e0b", "fill": "#fffbeb", "group": "policy"},
    "as_path_list":   {"shape": "round-rectangle", "color": "#f59e0b", "fill": "#fffbeb", "group": "policy"},
    # ── QoS ──────────────────────────────────────────────────────────────────
    "class_map":      {"shape": "round-rectangle", "color": "#14b8a6", "fill": "#f0fdfa", "group": "qos"},
    "policy_map":     {"shape": "round-rectangle", "color": "#14b8a6", "fill": "#f0fdfa", "group": "qos"},
    # ── Management ───────────────────────────────────────────────────────────
    "ntp":            {"shape": "round-rectangle", "color": "#64748b", "fill": "#f8fafc", "group": "management"},
    "snmp":           {"shape": "round-rectangle", "color": "#64748b", "fill": "#f8fafc", "group": "management"},
    "syslog":         {"shape": "round-rectangle", "color": "#64748b", "fill": "#f8fafc", "group": "management"},
    "banners":        {"shape": "round-rectangle", "color": "#64748b", "fill": "#f8fafc", "group": "management"},
    "lines":          {"shape": "round-rectangle", "color": "#64748b", "fill": "#f8fafc", "group": "management"},
    # ── Security ─────────────────────────────────────────────────────────────
    "crypto":         {"shape": "round-rectangle", "color": "#ef4444", "fill": "#fef2f2", "group": "security"},
    "nat":            {"shape": "round-rectangle", "color": "#ef4444", "fill": "#fef2f2", "group": "security"},
    "zone":           {"shape": "round-rectangle", "color": "#ef4444", "fill": "#fef2f2", "group": "security"},
    # ── Ghost (missing/dangling) ─────────────────────────────────────────────
    "missing":        {"shape": "round-rectangle", "color": "#94a3b8", "fill": "#f8fafc", "group": "missing"},
}

# Fallback for unknown types
_DEFAULT_STYLE = {"shape": "round-rectangle", "color": "#64748b", "fill": "#f8fafc", "group": "other"}

# Short prefix shown on node labels: "rm:ISP1_IN", "bgp:65000", etc.
NODE_LABEL_PREFIX: dict[str, str] = {
    "interface":      "iface",
    "vrf":            "vrf",
    "bgp_instance":   "bgp",
    "ospf_instance":  "ospf",
    "eigrp_instance": "eigrp",
    "rip_instance":   "rip",
    "isis_instance":  "isis",
    "static_route":   "route",
    "multicast":      "mcast",
    "route_map":      "rm",
    "prefix_list":    "pl",
    "acl":            "acl",
    "community_list": "cl",
    "as_path_list":   "aspath",
    "class_map":      "cmap",
    "policy_map":     "pmap",
    "ntp":            "ntp",
    "snmp":           "snmp",
    "syslog":         "syslog",
    "banners":        "banner",
    "lines":          "lines",
    "crypto":         "crypto",
    "nat":            "nat",
    "bfd":            "bfd",
    "ip_sla":         "sla",
    "object_track":   "track",
    "eem_applet":     "eem",
    "missing":        "?",
    "zone":           "zone",
}


def _node_id(node_type: str, name: str) -> str:
    """Deterministic, collision-free node ID."""
    return f"{node_type}::{name}"


def _style_for(node_type: str) -> dict[str, str]:
    return NODE_STYLE.get(node_type, _DEFAULT_STYLE)


class GraphBuilder:
    """Builds a NetworkX DiGraph from a ParsedConfig and its DependencyReport.

    Usage::

        g = GraphBuilder(parsed).build()
        # or, if you already have a report:
        g = GraphBuilder(parsed, report).build()
    """

    def __init__(
        self,
        parsed: ParsedConfig,
        report: DependencyReport | None = None,
    ) -> None:
        self._parsed = parsed
        self._report = report or DependencyResolver(parsed).resolve()

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def build(self) -> nx.DiGraph:
        """Convert ParsedConfig + DependencyReport into a directed graph."""
        g = nx.DiGraph()
        g.graph["hostname"] = self._parsed.hostname or "unknown"
        g.graph["os"] = str(self._parsed.source_os)

        # Collect orphaned object names for fast lookup
        orphan_keys: set[tuple[str, str]] = {
            (o.object_type, o.name) for o in self._report.orphaned
        }

        # 1. Add nodes for every defined object
        self._add_defined_nodes(g, orphan_keys)

        # 2. Add edges + ghost nodes for dangling targets
        edge_counter = 0
        seen_ghost: set[str] = set()
        for link in self._report.links:
            src_id = _node_id(link.source_type, link.source_id)
            tgt_id = _node_id(link.ref_type, link.ref_name)

            # Add ghost node for missing targets (once per unique id)
            if not link.resolved and tgt_id not in seen_ghost:
                if tgt_id not in g:
                    style = _style_for("missing")
                    g.add_node(tgt_id, **{
                        "label": f"?:{link.ref_name}",
                        "display_label": f"?\n{link.ref_name}",
                        "type": "missing",
                        "group": "missing",
                        "status": "missing",
                        "shape": style["shape"],
                        "color": style["color"],
                        "fill": style.get("fill", "#F9FAFB"),
                        "hostname": g.graph["hostname"],
                    })
                seen_ghost.add(tgt_id)

            # Only add edge if source node exists
            if src_id in g:
                g.add_edge(src_id, tgt_id, **{
                    "id": f"e{edge_counter}",
                    "field": link.source_field,
                    "resolved": link.resolved,
                })
                edge_counter += 1

        return g

    # ------------------------------------------------------------------
    # Private helpers — one method per object category
    # ------------------------------------------------------------------

    def _add_defined_nodes(
        self, g: nx.DiGraph, orphan_keys: set[tuple[str, str]]
    ) -> None:
        p = self._parsed
        hostname = p.hostname or "unknown"

        def _raw(obj) -> str:
            """Join raw_lines from a parsed object into a single string."""
            lines = getattr(obj, "raw_lines", None) or []
            return "\n".join(lines)

        def _raw_multi(*objs) -> str:
            """Join raw_lines from multiple objects (e.g. all lines configs)."""
            parts = []
            for obj in objs:
                lines = getattr(obj, "raw_lines", None) or []
                if lines:
                    parts.extend(lines)
            return "\n".join(parts)

        def _add(node_type: str, name: str, extra: dict | None = None, obj=None):
            status = "orphan" if (node_type, name) in orphan_keys else "ok"
            style = _style_for(node_type)
            prefix = NODE_LABEL_PREFIX.get(node_type, node_type)
            attrs = {
                "label": f"{prefix}:{name}",
                "display_label": f"{prefix}\n{name}",
                "type": node_type,
                "group": style["group"],
                "status": status,
                "shape": style["shape"],
                "color": style["color"],
                "fill": style.get("fill", "#FFFFFF"),
                "hostname": hostname,
                "raw_config": _raw(obj) if obj is not None else "",
            }
            if extra:
                attrs.update(extra)
            g.add_node(_node_id(node_type, name), **attrs)

        # Infrastructure
        for iface in p.interfaces:
            _add("interface", iface.name, {
                "vrf": iface.vrf or "",
                "ip_address": str(iface.ip_address) if iface.ip_address else "",
                "enabled": iface.enabled,
            }, obj=iface)
        for vrf in p.vrfs:
            _add("vrf", vrf.name, {"rd": vrf.rd or ""}, obj=vrf)

        # Routing protocols
        for bgp in p.bgp_instances:
            name = f"{bgp.asn}" + (f" vrf {bgp.vrf}" if bgp.vrf else "")
            _add("bgp_instance", name, {"asn": bgp.asn, "vrf": bgp.vrf or ""}, obj=bgp)
        for ospf in p.ospf_instances:
            name = f"{ospf.process_id}" + (f" vrf {ospf.vrf}" if ospf.vrf else "")
            _add("ospf_instance", name, {"process_id": ospf.process_id, "vrf": ospf.vrf or ""}, obj=ospf)
        for eigrp in p.eigrp_instances:
            _add("eigrp_instance", str(eigrp.as_number), {"as_number": eigrp.as_number}, obj=eigrp)
        for rip in p.rip_instances:
            _add("rip_instance", "rip", {"version": rip.version}, obj=rip)
        for isis in p.isis_instances:
            _add("isis_instance", isis.tag, {"tag": isis.tag}, obj=isis)
        for sr in p.static_routes:
            _add("static_route", str(sr.destination), {"vrf": sr.vrf or ""}, obj=sr)
        if p.multicast:
            _add("multicast", "multicast", {
                "routing_enabled": p.multicast.multicast_routing_enabled
            }, obj=p.multicast)

        # Policy objects
        for rm in p.route_maps:
            _add("route_map", rm.name, obj=rm)
        for pl in p.prefix_lists:
            _add("prefix_list", pl.name, obj=pl)
        for acl in p.acls:
            _add("acl", acl.name, {"acl_type": acl.acl_type}, obj=acl)
        for cl in p.community_lists:
            _add("community_list", cl.name, obj=cl)
        for ap in p.as_path_lists:
            _add("as_path_list", ap.name, obj=ap)

        # QoS
        for cm in p.class_maps:
            _add("class_map", cm.name, obj=cm)
        for pm in p.policy_maps:
            _add("policy_map", pm.name, obj=pm)

        # Management (singletons — one node each if present)
        if p.ntp:
            _add("ntp", "ntp", {"servers": len(p.ntp.servers)}, obj=p.ntp)
        if p.snmp:
            _add("snmp", "snmp", {"communities": len(p.snmp.communities)}, obj=p.snmp)
        if p.syslog:
            _add("syslog", "syslog", {"hosts": len(p.syslog.hosts)}, obj=p.syslog)
        if p.banners:
            _add("banners", "banners", obj=p.banners)
        if p.lines:
            raw_lines_text = _raw_multi(*p.lines)
            _add("lines", "lines", {"count": len(p.lines)})
            # patch raw_config after add since _raw_multi handles multiple objects
            g.nodes[_node_id("lines", "lines")]["raw_config"] = raw_lines_text

        # Security
        if p.crypto:
            _add("crypto", "crypto", {
                "isakmp_policies": len(p.crypto.isakmp_policies),
                "crypto_maps": len(p.crypto.crypto_maps),
            }, obj=p.crypto)
        if p.nat:
            _add("nat", "nat", {
                "static": len(p.nat.static_entries),
                "dynamic": len(p.nat.dynamic_entries),
            }, obj=p.nat)

        # Infrastructure singletons / collections
        if p.bfd:
            _add("bfd", "bfd", {"templates": len(p.bfd.templates)}, obj=p.bfd)
        for op in p.ip_sla_operations:
            _add("ip_sla", str(op.sla_id), {
                "operation_type": op.operation_type,
                "destination": op.destination,
            }, obj=op)
        for track in p.object_tracks:
            _add("object_track", str(track.track_id), {"track_type": track.track_type}, obj=track)
        for applet in p.eem_applets:
            _add("eem_applet", applet.name, obj=applet)

        # PAN-OS security zones
        for zone in p.zones:
            _add("zone", zone.name, {
                "vsys": zone.vsys,
                "zone_type": zone.zone_type,
                "interfaces": ",".join(zone.interfaces),
            }, obj=zone)
