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
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network
from typing import TYPE_CHECKING, Any

import networkx as nx

from confgraph.utils.interface import canonical_to_display, normalize_interface_name

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
# BGP session endpoints
# ---------------------------------------------------------------------------

@dataclass
class _BGPEndpoint:
    """One side of one BGP session: a single ``neighbor`` statement.

    A session has two endpoints when both devices configure each other, and one
    when only a single side does. ``local_ip`` is the address this device sources
    the session from — it is what makes two sessions between the same pair of
    devices distinguishable, and what lets the two endpoints of one session find
    each other (A's ``local_ip`` is B's ``peer_ip`` and vice versa).
    """

    host: str
    peer_host: str
    peer_ip: IPv4Address
    local_ip: IPv4Address | None
    bgp: Any        # BGPInstance
    neighbor: Any   # BGPNeighbor


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
        # Ambiguities found while building (e.g. one IP claimed by two devices).
        # The CLI prints these to stderr; nothing here is resolved silently.
        self.warnings: list[str] = []

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

    @staticmethod
    def _global_interfaces(parsed: "ParsedConfig") -> list[Any]:
        """The device's interfaces in the **global** routing table.

        A VRF-bound interface's address does not live in the global table, and
        `_bgp_endpoints` only walks global-table BGP instances. Mixing the two is
        how an address that is unique per routing table looks like a duplicate:
        10.0.0.1 in VRF CUST-A and 10.0.0.1 in the global table are different
        addresses, and only the latter can be a global-table BGP peer.
        """
        return [iface for iface in parsed.interfaces if iface.vrf is None]

    def _device_ips(self, hostname: str) -> set[IPv4Address]:
        """Every global-table IPv4 address configured on *hostname*."""
        ips: set[IPv4Address] = set()
        parsed = self._devices.get(hostname)
        if parsed is None:
            return ips
        for iface in self._global_interfaces(parsed):
            for addr in (iface.ip_address, *iface.secondary_ips):
                if addr is not None:
                    ips.add(addr.ip)
        return ips

    def _ip_owners(self) -> dict[IPv4Address, list[str]]:
        """global-table address → every device that configures it.

        A list, not a single hostname: two devices claiming one global-table
        address is a broken estate, and quietly picking a winner is how a session
        ends up attached to the wrong device. See ``_resolve_peer_host``.
        """
        owners: dict[IPv4Address, list[str]] = {}
        for hostname in self._devices:
            for ip in sorted(self._device_ips(hostname)):
                hosts = owners.setdefault(ip, [])
                if hostname not in hosts:
                    hosts.append(hostname)
        return owners

    def _global_asn(self, hostname: str) -> int | None:
        """The device's ASN in the global routing table (VRF instances ignored)."""
        parsed = self._devices.get(hostname)
        if parsed is None:
            return None
        for bgp in parsed.bgp_instances:
            if bgp.vrf is None:
                return bgp.asn
        return None

    def _resolve_peer_host(
        self,
        owners: dict[IPv4Address, list[str]],
        peer_ip: IPv4Address,
        self_host: str,
        remote_as: Any,
    ) -> str | None:
        """Return the device that owns *peer_ip*, or None if that is not knowable.

        Overlapping addressing across pods/tenants is routine, so one address can
        have several owners. The neighbor's ``remote-as`` is then **evidence**, not
        a tiebreak: a BGP peer's local ASN must equal the remote-as configured for
        it, so when exactly one candidate's ASN matches, the config has identified
        the peer and there is nothing ambiguous to report.

        When the ASN does *not* single out one candidate — every device sharing one
        ASN (the ordinary iBGP estate), or a peer-group member whose ``remote_as``
        is the string ``'inherited'`` — the config alone cannot say which device is
        meant. The session is then **declined and reported**, never guessed. An
        earlier revision fell back to ``sorted(candidates)[0]``; that hands the
        session to whichever hostname sorts first, which is not evidence at all.

        None therefore means: no device owns the address (an outside peer), or the
        owner is genuinely unidentifiable — and the latter is always warned about.
        """
        candidates = [h for h in owners.get(peer_ip, []) if h != self_host]
        if not candidates:
            return None
        if len(candidates) == 1:
            return candidates[0]

        # `remote_as` is an int only when the neighbor states one; it is 'inherited'
        # for a peer-group member and can be 'internal'/'external' elsewhere. A
        # string can never equal a parsed ASN, and must never appear to.
        if isinstance(remote_as, int) and not isinstance(remote_as, bool):
            matching = [h for h in candidates if self._global_asn(h) == remote_as]
            if len(matching) == 1:
                return matching[0]

        message = (
            f"Address {peer_ip} is configured in the global table of more than one "
            f"device ({', '.join(sorted(candidates))}) — the BGP peer it names is "
            f"ambiguous, so '{self_host}'s session to it is omitted from the graph."
        )
        if message not in self.warnings:
            self.warnings.append(message)
        return None

    def _resolve_local_ip(
        self,
        parsed: "ParsedConfig",
        neighbor: Any,
    ) -> IPv4Address | None:
        """The address this device sources the session from.

        1. the ``update-source`` interface's address, when configured;
        2. otherwise the address of the interface directly connected to the peer.

        Global-table interfaces only — a global-table session cannot be sourced
        from a VRF-bound address. Returns None when neither applies (the session
        then cannot be paired with its far side by address, and is keyed
        directionally instead).
        """
        interfaces = self._global_interfaces(parsed)

        if neighbor.update_source:
            want = normalize_interface_name(neighbor.update_source)
            for iface in interfaces:
                if normalize_interface_name(iface.name) == want and iface.ip_address:
                    return iface.ip_address.ip

        for iface in interfaces:
            for addr in (iface.ip_address, *iface.secondary_ips):
                if addr is not None and neighbor.peer_ip in addr.network:
                    return addr.ip
        return None

    def _bgp_endpoints(self) -> list[_BGPEndpoint]:
        """Every configured BGP neighbor statement that points at a known device."""
        owners = self._ip_owners()
        endpoints: list[_BGPEndpoint] = []

        for hostname, parsed in self._devices.items():
            for bgp in parsed.bgp_instances:
                if bgp.vrf is not None:
                    continue  # global table only
                for neighbor in bgp.neighbors:
                    peer_ip = neighbor.peer_ip
                    if not isinstance(peer_ip, IPv4Address):
                        continue
                    peer_host = self._resolve_peer_host(
                        owners, peer_ip, hostname, neighbor.remote_as
                    )
                    if peer_host is None:
                        continue
                    endpoints.append(_BGPEndpoint(
                        host=hostname,
                        peer_host=peer_host,
                        peer_ip=peer_ip,
                        local_ip=self._resolve_local_ip(parsed, neighbor),
                        bgp=bgp,
                        neighbor=neighbor,
                    ))
        return endpoints

    @staticmethod
    def _session_key(ep: _BGPEndpoint) -> Any:
        """The identity of the session this endpoint belongs to.

        Both the unordered **device** pair and the unordered **address** pair: an
        address pair alone is not unique across an estate (two pods numbered
        10.0.0.1 ↔ 10.0.0.2 are two sessions, not one), and a device pair alone is
        exactly the coarse key this CCR exists to remove. Both halves are
        symmetric, so the two sides of one session derive the same key.
        """
        return (
            frozenset({ep.host, ep.peer_host}),
            frozenset({ep.local_ip, ep.peer_ip}),
        )

    def _group_sessions(
        self, endpoints: list[_BGPEndpoint]
    ) -> list[list[_BGPEndpoint]]:
        """Group endpoints into sessions — one group per session, 1 or 2 endpoints.

        Two sessions between the same two devices (different source interfaces)
        are two distinct groups; the same session seen from both ends is one.
        """
        sessions: dict[Any, list[_BGPEndpoint]] = {}
        deferred: list[_BGPEndpoint] = []

        for ep in endpoints:
            if ep.local_ip is None:
                deferred.append(ep)
                continue
            sessions.setdefault(self._session_key(ep), []).append(ep)

        # Endpoints whose local address could not be determined: pair them with a
        # far-side endpoint that points back at this device from the address we
        # point at. Failing that, they stand alone as a one-sided session.
        for ep in deferred:
            local_ips = self._device_ips(ep.host)
            paired_key = None
            for key, members in sessions.items():
                if len(members) != 1:
                    continue
                other = members[0]
                if other.host != ep.peer_host or other.peer_ip not in local_ips:
                    continue
                # Same session if the far side sources it from the address we
                # point at — or, when its local address is unknown too, if the
                # address we point at is one of its own.
                if other.local_ip == ep.peer_ip or (
                    other.local_ip is None
                    and ep.peer_ip in self._device_ips(other.host)
                ):
                    paired_key = key
                    break
            if paired_key is not None:
                sessions[paired_key].append(ep)
            else:
                sessions.setdefault(
                    ("unpaired", ep.host, ep.peer_host, ep.peer_ip), []
                ).append(ep)

        return list(sessions.values())

    def _add_bgp_edges(self, g: nx.MultiGraph) -> None:
        """Add one edge per BGP **session** between known devices.

        Peers are resolved by matching each neighbor's ``peer_ip`` against the
        interface addresses of the other devices. Parallel sessions between the
        same pair of devices (e.g. a loopback-sourced iBGP session alongside a
        directly-connected one) are distinct sessions and become distinct edges,
        each carrying its own addresses, description and route-maps — which is
        what the MultiGraph is for.
        """
        for members in self._group_sessions(self._bgp_endpoints()):
            ep_a = members[0]
            ep_b = next((m for m in members[1:] if m.host != ep_a.host), None)

            host_a = ep_a.host
            host_b = ep_b.host if ep_b is not None else ep_a.peer_host
            if host_a not in g or host_b not in g:
                continue

            asn_a = ep_a.bgp.asn
            asn_b = ep_b.bgp.asn if ep_b is not None else self._global_asn(host_b)
            session_type = "iBGP" if asn_a == asn_b else "eBGP"
            color = "#3b82f6" if session_type == "iBGP" else "#f59e0b"

            # Effective policies — each side's own neighbor statement for THIS
            # session, not the first neighbor that happens to point at the device.
            rm_out_a = _get_effective_policy(ep_a.neighbor, ep_a.bgp, "out")
            rm_in_a = _get_effective_policy(ep_a.neighbor, ep_a.bgp, "in")
            rm_out_b = (
                _get_effective_policy(ep_b.neighbor, ep_b.bgp, "out") if ep_b else None
            )
            rm_in_b = (
                _get_effective_policy(ep_b.neighbor, ep_b.bgp, "in") if ep_b else None
            )

            # Session endpoint addresses. B's local address is known even when B
            # does not configure the session back: it is what A points at.
            local_ip_a = ep_a.local_ip
            local_ip_b = ep_b.local_ip if ep_b is not None else None
            if local_ip_b is None:
                local_ip_b = ep_a.peer_ip
            if local_ip_a is None and ep_b is not None:
                local_ip_a = ep_b.peer_ip

            description = ep_a.neighbor.description or (
                ep_b.neighbor.description if ep_b is not None else None
            )

            policy_parts = []
            if rm_out_a:
                policy_parts.append(f"{host_a}→out:{rm_out_a}")
            if rm_in_b:
                policy_parts.append(f"{host_b}←in:{rm_in_b}")
            if rm_out_b:
                policy_parts.append(f"{host_b}→out:{rm_out_b}")
            if rm_in_a:
                policy_parts.append(f"{host_a}←in:{rm_in_a}")

            addr_pair = (
                f"{local_ip_a} ↔ {local_ip_b}" if local_ip_a else f"→ {local_ip_b}"
            )
            label = f"{session_type} {addr_pair}"
            if description:
                label += f" — {description}"
            if policy_parts:
                label += f" [{', '.join(policy_parts)}]"

            g.add_edge(
                host_a,
                host_b,
                edge_type="bgp",
                session_type=session_type,
                label=label,
                description=description or "",
                local_ip_a=str(local_ip_a) if local_ip_a else "",
                local_ip_b=str(local_ip_b) if local_ip_b else "",
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
