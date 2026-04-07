"""BGP configuration models."""

from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from pydantic import BaseModel, Field
from confgraph.models.base import BaseConfigObject


class BGPTimers(BaseModel):
    """BGP keepalive and holdtime timers."""

    keepalive: int = Field(..., description="Keepalive interval (seconds)")
    holdtime: int = Field(..., description="Holdtime (seconds)")


class BGPBestpathOptions(BaseModel):
    """BGP best-path selection options."""

    as_path_ignore: bool = Field(
        default=False, description="Ignore AS-path length in best-path"
    )
    as_path_multipath_relax: bool = Field(
        default=False, description="Allow multiple paths with different AS paths"
    )
    compare_routerid: bool = Field(
        default=False, description="Compare router-id for identical EBGP paths"
    )
    med_confed: bool = Field(
        default=False, description="Compare MED among confederation paths"
    )
    med_missing_as_worst: bool = Field(
        default=False, description="Treat missing MED as highest value"
    )
    always_compare_med: bool = Field(
        default=False, description="Compare MED from different neighbors"
    )


class BGPNetwork(BaseModel):
    """BGP network statement."""

    prefix: IPv4Network | IPv6Network = Field(..., description="Network prefix")
    route_map: str | None = Field(
        default=None, description="Route-map to apply (references RouteMapConfig)"
    )
    backdoor: bool = Field(default=False, description="Network is a backdoor route")


class BGPRedistribute(BaseModel):
    """BGP redistribution configuration."""

    protocol: str = Field(
        ..., description="Protocol to redistribute (e.g., 'ospf', 'connected', 'static')"
    )
    process_id: int | str | None = Field(
        default=None, description="Process ID for IGP protocols"
    )
    route_map: str | None = Field(
        default=None, description="Route-map to apply (references RouteMapConfig)"
    )
    metric: int | None = Field(default=None, description="Metric value")


class BGPAggregate(BaseModel):
    """BGP aggregate-address configuration."""

    prefix: IPv4Network | IPv6Network = Field(..., description="Aggregate prefix")
    summary_only: bool = Field(
        default=False, description="Suppress more specific routes"
    )
    as_set: bool = Field(
        default=False, description="Generate AS-SET path information"
    )
    attribute_map: str | None = Field(
        default=None, description="Attribute-map to apply (references RouteMapConfig)"
    )
    advertise_map: str | None = Field(
        default=None, description="Advertise-map to apply (references RouteMapConfig)"
    )
    suppress_map: str | None = Field(
        default=None, description="Suppress-map to apply (references RouteMapConfig)"
    )


class BGPNeighborAF(BaseModel):
    """BGP neighbor address-family specific configuration."""

    afi: str = Field(..., description="Address family identifier (e.g., 'ipv4', 'ipv6')")
    safi: str = Field(
        ..., description="Sub-address family identifier (e.g., 'unicast', 'multicast')"
    )
    activate: bool = Field(default=True, description="Activate this address family")
    send_community: bool | str = Field(
        default=False,
        description="Send community attribute (True/False/'extended'/'both')",
    )
    next_hop_self: bool = Field(
        default=False, description="Set next-hop to self for EBGP peers"
    )
    route_reflector_client: bool = Field(
        default=False, description="Configure as route-reflector client"
    )
    route_map_in: str | None = Field(
        default=None, description="Inbound route-map (references RouteMapConfig)"
    )
    route_map_out: str | None = Field(
        default=None, description="Outbound route-map (references RouteMapConfig)"
    )
    prefix_list_in: str | None = Field(
        default=None, description="Inbound prefix-list (references PrefixListConfig)"
    )
    prefix_list_out: str | None = Field(
        default=None, description="Outbound prefix-list (references PrefixListConfig)"
    )
    filter_list_in: str | None = Field(
        default=None, description="Inbound AS-path filter-list"
    )
    filter_list_out: str | None = Field(
        default=None, description="Outbound AS-path filter-list"
    )
    maximum_prefix: int | None = Field(
        default=None, description="Maximum number of prefixes accepted"
    )
    maximum_prefix_threshold: int | None = Field(
        default=None, description="Threshold percentage for warning"
    )
    default_originate: bool = Field(
        default=False, description="Originate default route to this neighbor"
    )
    default_originate_route_map: str | None = Field(
        default=None,
        description="Route-map for default-originate (references RouteMapConfig)",
    )
    allowas_in: int | None = Field(
        default=None, description="Allow AS in AS-path (number of occurrences)"
    )
    soft_reconfiguration_inbound: bool = Field(
        default=False, description="Enable soft reconfiguration for inbound updates"
    )


class BGPNeighbor(BaseModel):
    """BGP neighbor configuration."""

    peer_ip: IPv4Address | IPv6Address = Field(..., description="Neighbor IP address")
    remote_as: int | str = Field(
        ..., description="Remote AS number (or 'internal'/'external')"
    )
    peer_group: str | None = Field(
        default=None, description="Peer-group name (references BGPPeerGroup)"
    )
    description: str | None = Field(default=None, description="Neighbor description")
    update_source: str | None = Field(
        default=None,
        description="Update source interface (references InterfaceConfig name)",
    )
    ebgp_multihop: int | None = Field(
        default=None, description="EBGP multihop TTL value"
    )
    next_hop_self: bool = Field(
        default=False, description="Set next-hop to self (global, not AF-specific)"
    )
    send_community: bool | str = Field(
        default=False,
        description="Send community attribute (True/False/'extended'/'both')",
    )
    route_reflector_client: bool = Field(
        default=False, description="Configure as route-reflector client"
    )
    password: str | None = Field(default=None, description="MD5 password")
    shutdown: bool = Field(default=False, description="Administratively shut down")
    timers: BGPTimers | None = Field(default=None, description="BGP timers")
    route_map_in: str | None = Field(
        default=None, description="Inbound route-map (references RouteMapConfig)"
    )
    route_map_out: str | None = Field(
        default=None, description="Outbound route-map (references RouteMapConfig)"
    )
    prefix_list_in: str | None = Field(
        default=None, description="Inbound prefix-list (references PrefixListConfig)"
    )
    prefix_list_out: str | None = Field(
        default=None, description="Outbound prefix-list (references PrefixListConfig)"
    )
    filter_list_in: str | None = Field(
        default=None, description="Inbound AS-path filter-list"
    )
    filter_list_out: str | None = Field(
        default=None, description="Outbound AS-path filter-list"
    )
    maximum_prefix: int | None = Field(
        default=None, description="Maximum number of prefixes accepted"
    )
    maximum_prefix_threshold: int | None = Field(
        default=None, description="Threshold percentage for warning"
    )
    fall_over_bfd: bool = Field(
        default=False, description="BFD fall-over detection enabled"
    )
    disable_connected_check: bool = Field(
        default=False, description="Disable connected check for EBGP"
    )
    address_families: list[BGPNeighborAF] = Field(
        default_factory=list,
        description="Address-family specific configurations",
    )
    local_as: int | None = Field(
        default=None, description="Local AS override for this neighbor"
    )
    local_as_no_prepend: bool = Field(
        default=False, description="Do not prepend local AS to AS-path"
    )
    local_as_replace_as: bool = Field(
        default=False, description="Replace AS with local AS"
    )


class BGPPeerGroup(BaseModel):
    """BGP peer-group configuration.

    Peer groups allow common configuration to be applied to multiple neighbors.
    """

    name: str = Field(..., description="Peer-group name")
    remote_as: int | str | None = Field(
        default=None, description="Remote AS number (or 'internal'/'external')"
    )
    description: str | None = Field(default=None, description="Peer-group description")
    update_source: str | None = Field(
        default=None,
        description="Update source interface (references InterfaceConfig name)",
    )
    ebgp_multihop: int | None = Field(
        default=None, description="EBGP multihop TTL value"
    )
    next_hop_self: bool = Field(default=False, description="Set next-hop to self")
    send_community: bool | str = Field(
        default=False, description="Send community attribute"
    )
    route_reflector_client: bool = Field(
        default=False, description="Configure as route-reflector client"
    )
    password: str | None = Field(default=None, description="MD5 password")
    timers: BGPTimers | None = Field(default=None, description="BGP timers")
    route_map_in: str | None = Field(
        default=None, description="Inbound route-map (references RouteMapConfig)"
    )
    route_map_out: str | None = Field(
        default=None, description="Outbound route-map (references RouteMapConfig)"
    )
    prefix_list_in: str | None = Field(
        default=None, description="Inbound prefix-list (references PrefixListConfig)"
    )
    prefix_list_out: str | None = Field(
        default=None, description="Outbound prefix-list (references PrefixListConfig)"
    )
    filter_list_in: str | None = Field(
        default=None, description="Inbound AS-path filter-list"
    )
    filter_list_out: str | None = Field(
        default=None, description="Outbound AS-path filter-list"
    )
    maximum_prefix: int | None = Field(
        default=None, description="Maximum number of prefixes accepted"
    )
    fall_over_bfd: bool = Field(
        default=False, description="BFD fall-over detection enabled"
    )
    disable_connected_check: bool = Field(
        default=False, description="Disable connected check for EBGP"
    )
    address_families: list[BGPNeighborAF] = Field(
        default_factory=list,
        description="Address-family specific configurations",
    )


class BGPAddressFamily(BaseModel):
    """BGP global address-family configuration."""

    afi: str = Field(..., description="Address family identifier (e.g., 'ipv4', 'ipv6')")
    safi: str = Field(
        ..., description="Sub-address family identifier (e.g., 'unicast', 'multicast')"
    )
    vrf: str | None = Field(
        default=None, description="VRF name (references VRFConfig)"
    )
    networks: list[BGPNetwork] = Field(
        default_factory=list, description="Network statements"
    )
    redistribute: list[BGPRedistribute] = Field(
        default_factory=list, description="Redistribution configurations"
    )
    aggregate_addresses: list[BGPAggregate] = Field(
        default_factory=list, description="Aggregate address configurations"
    )
    maximum_paths: int | None = Field(
        default=None, description="Maximum paths for ECMP"
    )
    maximum_paths_ibgp: int | None = Field(
        default=None, description="Maximum paths for IBGP ECMP"
    )
    default_information_originate: bool = Field(
        default=False, description="Originate default route"
    )
    auto_summary: bool = Field(
        default=False, description="Enable automatic network summarization"
    )
    synchronization: bool = Field(
        default=False, description="Enable BGP synchronization"
    )


class BGPConfig(BaseConfigObject):
    """BGP (Border Gateway Protocol) configuration.

    Covers global BGP process and all related configurations including
    neighbors, peer groups, address families, and policies.
    """

    asn: int = Field(..., description="BGP autonomous system number")
    router_id: IPv4Address | None = Field(
        default=None, description="BGP router ID"
    )
    vrf: str | None = Field(
        default=None,
        description="VRF context (None = global, otherwise references VRFConfig)",
    )
    log_neighbor_changes: bool = Field(
        default=True, description="Log neighbor state changes"
    )
    bestpath_options: BGPBestpathOptions = Field(
        default_factory=BGPBestpathOptions,
        description="Best-path selection options",
    )
    neighbors: list[BGPNeighbor] = Field(
        default_factory=list, description="BGP neighbors"
    )
    peer_groups: list[BGPPeerGroup] = Field(
        default_factory=list, description="BGP peer groups"
    )
    address_families: list[BGPAddressFamily] = Field(
        default_factory=list, description="Address family configurations"
    )
    networks: list[BGPNetwork] = Field(
        default_factory=list, description="Network statements (global)"
    )
    redistribute: list[BGPRedistribute] = Field(
        default_factory=list, description="Redistribution configurations (global)"
    )
    confederation_id: int | None = Field(
        default=None, description="BGP confederation identifier"
    )
    confederation_peers: list[int] = Field(
        default_factory=list, description="BGP confederation peer AS numbers"
    )
    cluster_id: int | IPv4Address | None = Field(
        default=None, description="Route reflector cluster ID"
    )
    graceful_restart: bool = Field(
        default=False, description="Graceful restart enabled"
    )
    graceful_restart_restart_time: int | None = Field(
        default=None, description="Graceful restart restart time (seconds)"
    )
    graceful_restart_stalepath_time: int | None = Field(
        default=None, description="Graceful restart stale-path time (seconds)"
    )
    enforce_first_as: bool = Field(
        default=True, description="Enforce first AS in AS-path for EBGP"
    )
    fast_external_fallover: bool = Field(
        default=True, description="Reset EBGP sessions immediately on link failure"
    )
    deterministic_med: bool = Field(
        default=False, description="Enable deterministic MED comparison"
    )
    dampening: bool = Field(
        default=False, description="Enable BGP route dampening"
    )
    default_local_preference: int = Field(
        default=100, description="Default local preference value"
    )
    default_metric: int | None = Field(
        default=None, description="Default MED metric"
    )
