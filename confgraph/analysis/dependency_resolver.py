"""Dependency resolution for parsed network configurations.

Resolves all string-based cross-references between parsed objects
(e.g. BGP neighbor → RouteMapConfig) and identifies:

  - Dangling references: a name is referenced but no matching object exists
  - Orphaned objects:    an object is defined but never referenced by anything

Usage::

    from confgraph.analysis import DependencyResolver

    report = DependencyResolver(parsed_config).resolve()
    report.dangling_refs   # list[DependencyLink] where resolved=False
    report.orphaned        # list[OrphanedObject]
    report.has_issues      # bool
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from confgraph.models.parsed_config import ParsedConfig


# ---------------------------------------------------------------------------
# Output models
# ---------------------------------------------------------------------------

class DependencyLink(BaseModel):
    """A single cross-reference between two config objects."""

    source_type: str = Field(description="Kind of object that holds the reference")
    source_id: str = Field(description="Identifier of the source object")
    source_field: str = Field(description="Field name that holds the reference")
    ref_type: str = Field(description="Kind of object being referenced")
    ref_name: str = Field(description="Name of the referenced object")
    resolved: bool = Field(description="True if the target exists in ParsedConfig")


class OrphanedObject(BaseModel):
    """An object that is defined but never referenced by any other object."""

    object_type: str = Field(description="Kind of object (e.g. 'route_map', 'prefix_list')")
    name: str = Field(description="Name of the orphaned object")


class DependencyReport(BaseModel):
    """Full dependency analysis result for a ParsedConfig."""

    links: list[DependencyLink] = Field(default_factory=list)
    orphaned: list[OrphanedObject] = Field(default_factory=list)

    @property
    def dangling_refs(self) -> list[DependencyLink]:
        """References that point to objects not found in ParsedConfig."""
        return [l for l in self.links if not l.resolved]

    @property
    def has_issues(self) -> bool:
        return bool(self.dangling_refs or self.orphaned)

    def summary(self) -> str:
        total = len(self.links)
        resolved = sum(1 for l in self.links if l.resolved)
        return (
            f"Links: {total} total, {resolved} resolved, {len(self.dangling_refs)} dangling | "
            f"Orphans: {len(self.orphaned)}"
        )


# ---------------------------------------------------------------------------
# Resolver
# ---------------------------------------------------------------------------

class DependencyResolver:
    """Resolves all cross-references in a ParsedConfig.

    Builds name indexes on construction, then walks every object to emit
    DependencyLinks. Tracks which named objects are referenced for orphan
    detection.
    """

    def __init__(self, config: ParsedConfig) -> None:
        self._config = config

        # Name indexes for O(1) resolution
        self._route_maps = {rm.name: rm for rm in config.route_maps}
        self._prefix_lists = {pl.name: pl for pl in config.prefix_lists}
        self._community_lists = {cl.name: cl for cl in config.community_lists}
        self._as_path_lists = {ap.name: ap for ap in config.as_path_lists}
        self._acls = {acl.name: acl for acl in config.acls}
        self._vrfs = {vrf.name: vrf for vrf in config.vrfs}
        self._interfaces = {iface.name: iface for iface in config.interfaces}
        self._class_maps = {cm.name: cm for cm in config.class_maps}
        self._policy_maps = {pm.name: pm for pm in config.policy_maps}
        self._ip_sla_ops = {op.sla_id: op for op in config.ip_sla_operations}

        # Track which named objects have been referenced (for orphan detection)
        self._referenced: dict[str, set[str]] = {
            "route_map":      set(),
            "prefix_list":    set(),
            "community_list": set(),
            "as_path_list":   set(),
            "acl":            set(),
            "class_map":      set(),
            "policy_map":     set(),
        }

        # BGP peer group orphans collected during BGP resolution
        self._pg_orphans: list[OrphanedObject] = []

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def resolve(self) -> DependencyReport:
        links: list[DependencyLink] = []
        links.extend(self._resolve_bgp())
        links.extend(self._resolve_ospf())
        links.extend(self._resolve_eigrp())
        links.extend(self._resolve_rip())
        links.extend(self._resolve_interfaces())
        links.extend(self._resolve_route_maps())
        links.extend(self._resolve_static_routes())
        links.extend(self._resolve_ntp())
        links.extend(self._resolve_snmp())
        links.extend(self._resolve_lines())
        links.extend(self._resolve_qos())
        links.extend(self._resolve_nat())
        links.extend(self._resolve_crypto())
        links.extend(self._resolve_ipsla())
        links.extend(self._resolve_object_tracking())
        links.extend(self._resolve_multicast())

        orphaned = self._find_orphans()
        return DependencyReport(links=links, orphaned=orphaned)

    # ------------------------------------------------------------------
    # BGP
    # ------------------------------------------------------------------

    def _resolve_bgp(self) -> list[DependencyLink]:
        links: list[DependencyLink] = []

        for bgp in self._config.bgp_instances:
            # Node ID must match GraphBuilder's naming: "{asn}" or "{asn} vrf {vrf}"
            bgp_node_id = f"{bgp.asn}" + (f" vrf {bgp.vrf}" if bgp.vrf else "")

            # BGP instance VRF
            if bgp.vrf:
                links.append(self._link("bgp_instance", bgp_node_id, "vrf", "vrf", bgp.vrf))

            # Global network statements → collapse to bgp_instance
            for net in bgp.networks:
                if net.route_map:
                    links.append(self._link(
                        "bgp_instance", bgp_node_id, "network_route_map", "route_map", net.route_map,
                    ))

            # Global redistribute → collapse to bgp_instance
            for redist in bgp.redistribute:
                if redist.route_map:
                    links.append(self._link(
                        "bgp_instance", bgp_node_id,
                        f"redistribute_{redist.protocol}_route_map", "route_map", redist.route_map,
                    ))

            # Peer groups → collapse to bgp_instance
            pg_names_defined = {pg.name for pg in bgp.peer_groups}
            pg_names_referenced: set[str] = set()

            for pg in bgp.peer_groups:
                links.extend(self._resolve_policy_holder("bgp_instance", bgp_node_id, pg))

            # Neighbors → collapse to bgp_instance
            for nb in bgp.neighbors:
                if nb.peer_group:
                    pg_names_referenced.add(nb.peer_group)

                links.extend(self._resolve_policy_holder("bgp_instance", bgp_node_id, nb))

            # Address families → collapse to bgp_instance
            for af in bgp.address_families:
                if af.vrf:
                    links.append(self._link("bgp_instance", bgp_node_id, "vrf", "vrf", af.vrf))

                for net in af.networks:
                    if net.route_map:
                        links.append(self._link(
                            "bgp_instance", bgp_node_id, "network_route_map", "route_map", net.route_map,
                        ))

                for redist in af.redistribute:
                    if redist.route_map:
                        links.append(self._link(
                            "bgp_instance", bgp_node_id,
                            f"redistribute_{redist.protocol}_route_map", "route_map", redist.route_map,
                        ))

                for agg in af.aggregate_addresses:
                    for field in ("attribute_map", "advertise_map", "suppress_map"):
                        val = getattr(agg, field)
                        if val:
                            links.append(self._link(
                                "bgp_instance", bgp_node_id, field, "route_map", val,
                            ))

            # Peer group orphan detection (scoped to this BGP instance)
            for pg_name in pg_names_defined:
                if pg_name not in pg_names_referenced:
                    self._pg_orphans.append(OrphanedObject(
                        object_type="bgp_peer_group", name=f"{bgp_node_id}:{pg_name}",
                    ))

        return links

    def _resolve_policy_holder(
        self, source_type: str, source_id: str, obj: object,
    ) -> list[DependencyLink]:
        """Resolve route-map / prefix-list / filter-list / update-source refs
        from a BGPNeighbor or BGPPeerGroup, including per-AF fields.
        All links are emitted from source_type/source_id (the parent node)."""
        links: list[DependencyLink] = []

        _DIRECT_FIELDS: list[tuple[str, str]] = [
            ("route_map_in",  "route_map"),
            ("route_map_out", "route_map"),
            ("prefix_list_in",  "prefix_list"),
            ("prefix_list_out", "prefix_list"),
            ("filter_list_in",  "as_path_list"),
            ("filter_list_out", "as_path_list"),
        ]
        for field, ref_type in _DIRECT_FIELDS:
            val = getattr(obj, field, None)
            if val:
                links.append(self._link(source_type, source_id, field, ref_type, val))

        if hasattr(obj, "update_source") and obj.update_source:
            links.append(self._link(
                source_type, source_id, "update_source", "interface", obj.update_source,
            ))

        # Per address-family — collapse to same parent node
        _AF_FIELDS: list[tuple[str, str]] = [
            ("route_map_in",  "route_map"),
            ("route_map_out", "route_map"),
            ("prefix_list_in",  "prefix_list"),
            ("prefix_list_out", "prefix_list"),
            ("filter_list_in",  "as_path_list"),
            ("filter_list_out", "as_path_list"),
            ("default_originate_route_map", "route_map"),
        ]
        for af in getattr(obj, "address_families", []):
            for field, ref_type in _AF_FIELDS:
                val = getattr(af, field, None)
                if val:
                    links.append(self._link(source_type, source_id, field, ref_type, val))

        return links

    # ------------------------------------------------------------------
    # OSPF
    # ------------------------------------------------------------------

    def _resolve_ospf(self) -> list[DependencyLink]:
        links: list[DependencyLink] = []

        for ospf in self._config.ospf_instances:
            # Node ID must match GraphBuilder's naming: "{process_id}" or "{process_id} vrf {vrf}"
            ospf_node_id = f"{ospf.process_id}" + (f" vrf {ospf.vrf}" if ospf.vrf else "")

            if ospf.vrf:
                links.append(self._link("ospf_instance", ospf_node_id, "vrf", "vrf", ospf.vrf))

            for redist in ospf.redistribute:
                if redist.route_map:
                    links.append(self._link(
                        "ospf_instance", ospf_node_id,
                        f"redistribute_{redist.protocol}_route_map", "route_map", redist.route_map,
                    ))

            if ospf.default_information_originate_route_map:
                links.append(self._link(
                    "ospf_instance", ospf_node_id,
                    "default_information_originate_route_map",
                    "route_map", ospf.default_information_originate_route_map,
                ))

        return links

    # ------------------------------------------------------------------
    # Interfaces
    # ------------------------------------------------------------------

    def _resolve_interfaces(self) -> list[DependencyLink]:
        links: list[DependencyLink] = []
        for iface in self._config.interfaces:
            if iface.vrf:
                links.append(self._link("interface", iface.name, "vrf", "vrf", iface.vrf))
            if iface.unnumbered_source:
                links.append(self._link(
                    "interface", iface.name, "unnumbered_source", "interface", iface.unnumbered_source,
                ))
            if iface.acl_in:
                links.append(self._link("interface", iface.name, "acl_in", "acl", iface.acl_in))
            if iface.acl_out:
                links.append(self._link("interface", iface.name, "acl_out", "acl", iface.acl_out))
        return links

    # ------------------------------------------------------------------
    # Route-maps (match clause references)
    # ------------------------------------------------------------------

    def _resolve_route_maps(self) -> list[DependencyLink]:
        links: list[DependencyLink] = []
        for rm in self._config.route_maps:
            for seq in rm.sequences:
                for match in seq.match_clauses:
                    ref_type = self._infer_match_ref_type(match.match_type)
                    if ref_type is None:
                        continue
                    for val in match.values:
                        links.append(self._link(
                            "route_map",
                            rm.name,
                            match.match_type,
                            ref_type,
                            val,
                        ))
        return links

    @staticmethod
    def _infer_match_ref_type(match_type: str) -> str | None:
        """Map a route-map match_type string to its referenced object type."""
        mt = match_type.lower()
        if "prefix-list" in mt:
            return "prefix_list"
        if "as-path" in mt:
            return "as_path_list"
        if "community" in mt and "extcommunity" not in mt:
            return "community_list"
        if any(kw in mt for kw in ("ip address", "ip next-hop", "ip route-source")):
            return "acl"
        return None

    # ------------------------------------------------------------------
    # Static routes
    # ------------------------------------------------------------------

    def _resolve_static_routes(self) -> list[DependencyLink]:
        links: list[DependencyLink] = []
        for sr in self._config.static_routes:
            if sr.vrf:
                links.append(self._link(
                    "static_route", str(sr.destination), "vrf", "vrf", sr.vrf,
                ))
            if sr.next_hop_interface:
                links.append(self._link(
                    "static_route", str(sr.destination),
                    "next_hop_interface", "interface", sr.next_hop_interface,
                ))
        return links

    # ------------------------------------------------------------------
    # Orphan detection
    # ------------------------------------------------------------------

    def _find_orphans(self) -> list[OrphanedObject]:
        orphaned: list[OrphanedObject] = list(self._pg_orphans)

        _INDEXES: list[tuple[str, dict]] = [
            ("route_map",      self._route_maps),
            ("prefix_list",    self._prefix_lists),
            ("community_list", self._community_lists),
            ("as_path_list",   self._as_path_lists),
            ("acl",            self._acls),
            ("class_map",      self._class_maps),
            ("policy_map",     self._policy_maps),
        ]
        for ref_type, index in _INDEXES:
            referenced = self._referenced[ref_type]
            for name in index:
                if name not in referenced:
                    orphaned.append(OrphanedObject(object_type=ref_type, name=name))

        return orphaned

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _link(
        self,
        source_type: str,
        source_id: str,
        source_field: str,
        ref_type: str,
        ref_name: str,
    ) -> DependencyLink:
        """Create a DependencyLink and update orphan-tracking state."""
        # Mark as referenced for orphan tracking (even if dangling)
        if ref_type in self._referenced:
            self._referenced[ref_type].add(ref_name)

        resolved = self._is_resolved(ref_type, ref_name)
        return DependencyLink(
            source_type=source_type,
            source_id=source_id,
            source_field=source_field,
            ref_type=ref_type,
            ref_name=ref_name,
            resolved=resolved,
        )

    def _is_resolved(self, ref_type: str, ref_name: str) -> bool:
        index: dict = {
            "route_map":      self._route_maps,
            "prefix_list":    self._prefix_lists,
            "community_list": self._community_lists,
            "as_path_list":   self._as_path_lists,
            "acl":            self._acls,
            "vrf":            self._vrfs,
            "interface":      self._interfaces,
            "class_map":      self._class_maps,
            "policy_map":     self._policy_maps,
        }.get(ref_type, {})
        return ref_name in index

    # ------------------------------------------------------------------
    # EIGRP
    # ------------------------------------------------------------------

    def _resolve_eigrp(self) -> list[DependencyLink]:
        links: list[DependencyLink] = []
        for eigrp in self._config.eigrp_instances:
            # Node ID must match GraphBuilder's naming: str(as_number)
            eigrp_node_id = str(eigrp.as_number)
            if eigrp.vrf:
                links.append(self._link("eigrp_instance", eigrp_node_id, "vrf", "vrf", eigrp.vrf))
            for redist in eigrp.redistribute:
                if redist.route_map:
                    links.append(self._link(
                        "eigrp_instance", eigrp_node_id,
                        f"redistribute_{redist.protocol}_route_map", "route_map", redist.route_map,
                    ))
        return links

    # ------------------------------------------------------------------
    # RIP
    # ------------------------------------------------------------------

    def _resolve_rip(self) -> list[DependencyLink]:
        links: list[DependencyLink] = []
        for rip in self._config.rip_instances:
            rip_id = "rip"
            if rip.vrf:
                links.append(self._link("rip_instance", rip_id, "vrf", "vrf", rip.vrf))
            for redist in rip.redistribute:
                if redist.route_map:
                    links.append(self._link(
                        "rip_instance", rip_id,
                        f"redistribute_{redist.protocol}_route_map", "route_map", redist.route_map,
                    ))
        return links

    # ------------------------------------------------------------------
    # NTP
    # ------------------------------------------------------------------

    def _resolve_ntp(self) -> list[DependencyLink]:
        links: list[DependencyLink] = []
        ntp = self._config.ntp
        if not ntp:
            return links
        for server in ntp.servers + ntp.peers:
            if server.vrf:
                links.append(self._link("ntp", "ntp", "server_vrf", "vrf", server.vrf))
            if server.source:
                links.append(self._link("ntp", "ntp", "server_source", "interface", server.source))
        if ntp.source_interface:
            links.append(self._link("ntp", "ntp", "source_interface", "interface", ntp.source_interface))
        for ag in filter(None, [ntp.access_group_query_only, ntp.access_group_serve_only,
                                  ntp.access_group_serve, ntp.access_group_peer]):
            links.append(self._link("ntp", "ntp", "access_group", "acl", ag))
        return links

    # ------------------------------------------------------------------
    # SNMP
    # ------------------------------------------------------------------

    def _resolve_snmp(self) -> list[DependencyLink]:
        links: list[DependencyLink] = []
        snmp = self._config.snmp
        if not snmp:
            return links
        for host in snmp.hosts:
            if host.vrf:
                links.append(self._link("snmp", "snmp", "host_vrf", "vrf", host.vrf))
        if snmp.source_interface:
            links.append(self._link("snmp", "snmp", "source_interface", "interface", snmp.source_interface))
        if snmp.trap_source:
            links.append(self._link("snmp", "snmp", "trap_source", "interface", snmp.trap_source))
        return links

    # ------------------------------------------------------------------
    # Lines
    # ------------------------------------------------------------------

    def _resolve_lines(self) -> list[DependencyLink]:
        links: list[DependencyLink] = []
        for line in self._config.lines:
            if line.access_class_in:
                links.append(self._link("lines", "lines", "access_class_in", "acl", line.access_class_in))
            if line.access_class_out:
                links.append(self._link("lines", "lines", "access_class_out", "acl", line.access_class_out))
        return links

    # ------------------------------------------------------------------
    # QoS
    # ------------------------------------------------------------------

    def _resolve_qos(self) -> list[DependencyLink]:
        links: list[DependencyLink] = []
        for cm in self._config.class_maps:
            for match in cm.matches:
                if "access-group" in match.match_type and match.values:
                    # "match access-group name <acl>" has "name" as a keyword, not an ACL name
                    acl_values = match.values[1:] if match.values[0] == "name" else match.values
                    for acl_name in acl_values:
                        links.append(self._link("class_map", cm.name, "match_acl", "acl", acl_name))
        for pm in self._config.policy_maps:
            for cls in pm.classes:
                if cls.class_name != "class-default":
                    links.append(self._link("policy_map", pm.name, "class", "class_map", cls.class_name))
                if cls.service_policy:
                    links.append(self._link(
                        "policy_map", pm.name,
                        "service_policy", "policy_map", cls.service_policy,
                    ))
        for iface in self._config.interfaces:
            if iface.service_policy_input:
                links.append(self._link(
                    "interface", iface.name, "service_policy_input",
                    "policy_map", iface.service_policy_input,
                ))
            if iface.service_policy_output:
                links.append(self._link(
                    "interface", iface.name, "service_policy_output",
                    "policy_map", iface.service_policy_output,
                ))
        return links

    # ------------------------------------------------------------------
    # NAT
    # ------------------------------------------------------------------

    def _resolve_nat(self) -> list[DependencyLink]:
        links: list[DependencyLink] = []
        nat = self._config.nat
        if not nat:
            return links
        for de in nat.dynamic_entries:
            links.append(self._link("nat", "nat", "acl", "acl", de.acl))
            if de.interface:
                links.append(self._link("nat", "nat", "interface", "interface", de.interface))
            if de.vrf:
                links.append(self._link("nat", "nat", "vrf", "vrf", de.vrf))
        for se in nat.static_entries:
            if se.vrf:
                links.append(self._link("nat", "nat", "vrf", "vrf", se.vrf))
        return links

    # ------------------------------------------------------------------
    # Crypto
    # ------------------------------------------------------------------

    def _resolve_crypto(self) -> list[DependencyLink]:
        links: list[DependencyLink] = []
        crypto = self._config.crypto
        if not crypto:
            return links
        for cmap in crypto.crypto_maps:
            for entry in cmap.entries:
                if entry.acl:
                    links.append(self._link(
                        "crypto", "crypto",
                        "match_acl", "acl", entry.acl,
                    ))
        return links

    # ------------------------------------------------------------------
    # IP SLA
    # ------------------------------------------------------------------

    def _resolve_ipsla(self) -> list[DependencyLink]:
        links: list[DependencyLink] = []
        for op in self._config.ip_sla_operations:
            sla_id_str = str(op.sla_id)
            if op.vrf:
                links.append(self._link("ip_sla", sla_id_str, "vrf", "vrf", op.vrf))
            if op.source_interface:
                links.append(self._link("ip_sla", sla_id_str, "source_interface", "interface", op.source_interface))
        return links

    # ------------------------------------------------------------------
    # Object tracking
    # ------------------------------------------------------------------

    def _resolve_object_tracking(self) -> list[DependencyLink]:
        links: list[DependencyLink] = []
        for track in self._config.object_tracks:
            track_id_str = str(track.track_id)
            if track.tracked_interface:
                links.append(self._link(
                    "object_track", track_id_str,
                    "tracked_interface", "interface", track.tracked_interface,
                ))
            if track.tracked_sla_id is not None:
                resolved = track.tracked_sla_id in self._ip_sla_ops
                links.append(DependencyLink(
                    source_type="object_track",
                    source_id=track_id_str,
                    source_field="tracked_sla_id",
                    ref_type="ip_sla",
                    ref_name=str(track.tracked_sla_id),
                    resolved=resolved,
                ))
        return links

    # ------------------------------------------------------------------
    # Multicast
    # ------------------------------------------------------------------

    def _resolve_multicast(self) -> list[DependencyLink]:
        links: list[DependencyLink] = []
        mc = self._config.multicast
        if not mc:
            return links
        for rp in mc.pim_rp_addresses:
            if rp.acl:
                links.append(self._link("multicast", "multicast", "pim_rp_acl", "acl", rp.acl))
        if mc.pim_ssm_range:
            links.append(self._link("multicast", "multicast", "pim_ssm_range", "acl", mc.pim_ssm_range))
        for peer in mc.msdp_peers:
            if peer.connect_source:
                links.append(self._link(
                    "multicast", "multicast",
                    "msdp_connect_source", "interface", peer.connect_source,
                ))
            if peer.sa_filter_in:
                links.append(self._link(
                    "multicast", "multicast", "msdp_sa_filter_in", "acl", peer.sa_filter_in,
                ))
            if peer.sa_filter_out:
                links.append(self._link(
                    "multicast", "multicast", "msdp_sa_filter_out", "acl", peer.sa_filter_out,
                ))
        if mc.vrf:
            links.append(self._link("multicast", "multicast", "vrf", "vrf", mc.vrf))
        return links
