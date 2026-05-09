"""TopologyGraphBuilder — builds a multi-device topology graph.

Produces a NetworkX graph where:
  - Nodes  = devices (one per hostname)
  - Edges  = physical links, BGP sessions, IGP adjacencies

This graph is separate from the per-device dependency graph produced by
confgraph.graph.builder. It operates across multiple parsed configs and an
optional PhysicalTopology from TOPO-1 ingest.

The graph is consumed by:
  - TopologyHTMLExporter  → static HTML file (TOPO-2)
  - TopologyJSONExporter  → JSON file consumed by the enterprise simulator (TOPO-3)
"""

from __future__ import annotations

import json
from ipaddress import IPv4Network
from typing import TYPE_CHECKING

import networkx as nx

from confgraph.utils.interface import canonical_to_display

if TYPE_CHECKING:
    from confgraph.models.parsed_config import ParsedConfig
    from confgraph.models.topology import PhysicalTopology

# ---------------------------------------------------------------------------
# OS-type → display color
# ---------------------------------------------------------------------------

_OS_COLORS: dict[str, str] = {
    "ios":    "#1d4ed8",   # blue
    "ios_xe": "#1d4ed8",
    "ios_xr": "#7c3aed",  # violet
    "eos":    "#047857",   # green (Arista)
    "nxos":   "#b45309",   # amber (NX-OS)
    "junos":  "#b91c1c",   # red (Juniper)
    "panos":  "#0369a1",   # sky (Palo Alto)
}
_DEFAULT_COLOR = "#374151"


# ---------------------------------------------------------------------------
# resolve_neighbor import (reused from enterprise if available, else inline)
# ---------------------------------------------------------------------------

def _get_effective_policy(neighbor, bgp, direction: str) -> str | None:
    """Return the effective route-map for *direction* ('in' or 'out').

    Applies the full IOS inheritance chain:
      neighbor-level → peer-group → address-family

    This ensures the graph shows the policy that is actually active,
    not a shadowed or overridden value.
    """
    # Try to import resolve_neighbor from enterprise package; fall back to
    # a local minimal implementation so OSS has no enterprise dependency.
    try:
        from confgraph_entrp.simulation.topology import resolve_neighbor
        resolved = resolve_neighbor(neighbor, bgp)
    except ImportError:
        resolved = neighbor

    if direction == "in":
        # Neighbor-level
        if resolved.route_map_in:
            return resolved.route_map_in
        # Address-family level
        for af in resolved.address_families:
            if af.route_map_in:
                return af.route_map_in
    else:
        if resolved.route_map_out:
            return resolved.route_map_out
        for af in resolved.address_families:
            if af.route_map_out:
                return af.route_map_out
    return None


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------

class TopologyGraphBuilder:
    """Build a multi-device topology graph.

    Parameters
    ----------
    devices:
        hostname → ParsedConfig mapping for all devices in the topology.
    physical_topology:
        Optional physical adjacency from TOPO-1 ingest. When provided,
        physical links are added as edges. When absent, only logical
        (BGP/IGP) edges are added.
    """

    def __init__(
        self,
        devices: dict[str, "ParsedConfig"],
        physical_topology: "PhysicalTopology | None" = None,
    ) -> None:
        self._devices = devices
        self._physical = physical_topology or []

    def build(self) -> nx.MultiGraph:
        """Return the topology graph.

        Uses MultiGraph to allow multiple edges between the same pair of
        devices (physical link + BGP session + IGP adjacency can all coexist).
        """
        g: nx.MultiGraph = nx.MultiGraph()

        # 1. Add one node per device
        for hostname, parsed in self._devices.items():
            g.add_node(hostname, **self._device_attrs(hostname, parsed))

        # 2. Physical link edges
        for link in self._physical:
            if link.device_a not in g or link.device_b not in g:
                continue
            label_a = canonical_to_display(link.port_a)
            label_b = canonical_to_display(link.port_b)
            count_suffix = f" (×{link.member_count})" if link.member_count > 1 else ""
            g.add_edge(
                link.device_a,
                link.device_b,
                edge_type="physical",
                label=f"{label_a} ↔ {label_b}{count_suffix}",
                port_a=link.port_a,
                port_b=link.port_b,
                member_count=link.member_count,
                source=link.source,
                color="#9ca3af",    # grey
                style="solid",
            )

        # 3. BGP session edges
        self._add_bgp_edges(g)

        # 4. IGP adjacency edges
        self._add_igp_edges(g)

        return g

    # ------------------------------------------------------------------
    # Device node attributes
    # ------------------------------------------------------------------

    def _device_attrs(self, hostname: str, parsed: "ParsedConfig") -> dict:
        os_str = str(parsed.source_os) if parsed.source_os else "unknown"
        asn: int | None = None
        router_id: str | None = None
        for bgp in parsed.bgp_instances:
            if bgp.vrf is None:
                asn = bgp.asn
                router_id = str(bgp.router_id) if bgp.router_id else None
                break

        return {
            "label": hostname,
            "os": os_str,
            "asn": asn,
            "router_id": router_id,
            "color": _OS_COLORS.get(os_str, _DEFAULT_COLOR),
            "node_type": "device",
        }

    # ------------------------------------------------------------------
    # BGP session edges
    # ------------------------------------------------------------------

    def _add_bgp_edges(self, g: nx.MultiGraph) -> None:
        """Add one edge per BGP session between known devices.

        Uses the same IP-based peer resolution as the enterprise simulator:
        match each neighbor's peer_ip against interface IPs of other devices.
        Deduplicates so each session appears once regardless of which side
        we encounter first.
        """
        from ipaddress import IPv4Address

        # Build ip → hostname lookup
        ip_to_host: dict[IPv4Address, str] = {}
        for hostname, parsed in self._devices.items():
            for iface in parsed.interfaces:
                if iface.ip_address:
                    ip_to_host[iface.ip_address.ip] = hostname

        seen: set[frozenset] = set()

        for hostname_a, parsed_a in self._devices.items():
            for bgp in parsed_a.bgp_instances:
                if bgp.vrf is not None:
                    continue  # global table only
                asn_a = bgp.asn

                for neighbor in bgp.neighbors:
                    peer_ip = neighbor.peer_ip
                    if not isinstance(peer_ip, IPv4Address):
                        continue
                    hostname_b = ip_to_host.get(peer_ip)
                    if hostname_b is None or hostname_b == hostname_a:
                        continue

                    session_key = frozenset([hostname_a, hostname_b])
                    if session_key in seen:
                        continue
                    seen.add(session_key)

                    parsed_b = self._devices[hostname_b]
                    asn_b: int | None = None
                    for bgp_b in parsed_b.bgp_instances:
                        if bgp_b.vrf is None:
                            asn_b = bgp_b.asn
                            break

                    session_type = "iBGP" if asn_a == asn_b else "eBGP"
                    color = "#3b82f6" if session_type == "iBGP" else "#f59e0b"

                    # Effective policies — capture all four directions
                    rm_out_a = _get_effective_policy(neighbor, bgp, "out")
                    rm_in_a = _get_effective_policy(neighbor, bgp, "in")

                    # Find the corresponding neighbor on B's side
                    rm_out_b: str | None = None
                    rm_in_b: str | None = None
                    ips_a = {
                        iface.ip_address.ip
                        for iface in parsed_a.interfaces
                        if iface.ip_address
                    }
                    for bgp_b in parsed_b.bgp_instances:
                        if bgp_b.vrf is not None:
                            continue
                        for nbr_b in bgp_b.neighbors:
                            if nbr_b.peer_ip and nbr_b.peer_ip in ips_a:
                                rm_in_b = _get_effective_policy(nbr_b, bgp_b, "in")
                                rm_out_b = _get_effective_policy(nbr_b, bgp_b, "out")
                                break

                    # Build label: show policies for both directions
                    policy_parts = []
                    # A→B: A's outbound and B's inbound
                    if rm_out_a:
                        policy_parts.append(f"{hostname_a}→out:{rm_out_a}")
                    if rm_in_b:
                        policy_parts.append(f"{hostname_b}←in:{rm_in_b}")
                    # B→A: B's outbound and A's inbound
                    if rm_out_b:
                        policy_parts.append(f"{hostname_b}→out:{rm_out_b}")
                    if rm_in_a:
                        policy_parts.append(f"{hostname_a}←in:{rm_in_a}")
                    policy_str = ", ".join(policy_parts)

                    label = session_type
                    if neighbor.description:
                        label += f" — {neighbor.description}"
                    if policy_str:
                        label += f" [{policy_str}]"

                    g.add_edge(
                        hostname_a,
                        hostname_b,
                        edge_type="bgp",
                        session_type=session_type,
                        label=label,
                        description=neighbor.description or "",
                        route_map_out_a=rm_out_a or "",
                        route_map_in_a=rm_in_a or "",
                        route_map_out_b=rm_out_b or "",
                        route_map_in_b=rm_in_b or "",
                        color=color,
                        style="dashed",
                    )

    # ------------------------------------------------------------------
    # IGP adjacency edges
    # ------------------------------------------------------------------

    def _add_igp_edges(self, g: nx.MultiGraph) -> None:
        """Add IGP adjacency edges derived from shared subnets + IGP config.

        Only adds an edge when both sides have IGP enabled on the shared
        subnet interface — same logic as igp.build_igp_adjacency().
        """
        from ipaddress import IPv4Network

        # Build subnet → [(hostname, iface)] map
        subnet_map: dict[IPv4Network, list[tuple[str, object]]] = {}
        for hostname, parsed in self._devices.items():
            for iface in parsed.interfaces:
                if not iface.enabled or iface.ip_address is None:
                    continue
                if iface.interface_type == "loopback":
                    continue
                net = iface.ip_address.network
                subnet_map.setdefault(net, []).append((hostname, iface))

        seen: set[frozenset] = set()

        for net, members in subnet_map.items():
            if len(members) < 2:
                continue
            for i, (h_a, iface_a) in enumerate(members):
                parsed_a = self._devices[h_a]
                for h_b, iface_b in members[i + 1:]:
                    parsed_b = self._devices[h_b]
                    key = frozenset([h_a, h_b, str(net)])
                    if key in seen:
                        continue

                    # Determine IGP protocol and cost
                    protocol, cost, area = self._igp_info(iface_a, parsed_a, iface_b, parsed_b)
                    if protocol is None:
                        continue

                    seen.add(key)
                    label_parts = [protocol]
                    if area:
                        label_parts.append(f"area {area}")
                    if cost is not None:
                        label_parts.append(f"cost {cost}")

                    g.add_edge(
                        h_a,
                        h_b,
                        edge_type="igp",
                        protocol=protocol,
                        label=" / ".join(label_parts),
                        area=area or "",
                        cost=cost,
                        subnet=str(net),
                        color="#10b981",   # green
                        style="dotted",
                    )

    def _igp_info(
        self,
        iface_a, parsed_a: "ParsedConfig",
        iface_b, parsed_b: "ParsedConfig",
    ) -> tuple[str | None, int | None, str | None]:
        """Return (protocol, cost, area) for the IGP adjacency on this link.

        Returns (None, None, None) when neither side has IGP enabled on
        the shared subnet interface.
        """
        # Check OSPF on A's side
        for ospf in parsed_a.ospf_instances:
            if ospf.shutdown:
                continue
            for net, area in ospf.network_statements:
                if iface_a.ip_address and iface_a.ip_address.network.overlaps(net):
                    cost = iface_a.ospf_cost
                    return "OSPF", cost, str(area)
            if iface_a.ospf_process_id is not None:
                return "OSPF", iface_a.ospf_cost, None

        # Check IS-IS on A's side
        for isis in parsed_a.isis_instances:
            passive = (
                iface_a.name in isis.passive_interfaces
                or (isis.passive_interface_default and iface_a.name not in isis.non_passive_interfaces)
            )
            if not passive:
                return "IS-IS", None, isis.tag or None

        # Check B's side symmetrically
        for ospf in parsed_b.ospf_instances:
            if ospf.shutdown:
                continue
            for net, area in ospf.network_statements:
                if iface_b.ip_address and iface_b.ip_address.network.overlaps(net):
                    return "OSPF", iface_b.ospf_cost, str(area)
            if iface_b.ospf_process_id is not None:
                return "OSPF", iface_b.ospf_cost, None

        for isis in parsed_b.isis_instances:
            passive = (
                iface_b.name in isis.passive_interfaces
                or (isis.passive_interface_default and iface_b.name not in isis.non_passive_interfaces)
            )
            if not passive:
                return "IS-IS", None, isis.tag or None

        return None, None, None
