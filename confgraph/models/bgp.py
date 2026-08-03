"""BGP configuration models."""

import re
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from confgraph.models.base import BaseConfigObject

# asdot AS-number spelling (RFC 5396): "A.B" with both halves 16-bit.
_ASDOT = re.compile(r"^(\d{1,5})\.(\d{1,5})$")


def normalize_remote_as(v):
    """Shared remote_as normalizer (CCR-0170) — the single seam that makes
    the field FAIL-CLOSED.

    ints pass through; strings either normalize to an int (decimal
    spellings, asdot per RFC 5396) or RAISE.  The legacy string arms —
    "inherited" provenance and "internal"/"external" peer types — are
    REJECTED here by design: they live on ``remote_as_source`` now, and a
    parser passing them through is a bug that must fail at parse time,
    not silently exempt the neighbor from every AS-agreement check (the
    pre-CCR ``int | str`` union let ANY non-int spelling — asdot was the
    measured case — form sessions with no AS validation at all).
    """
    if v is None or isinstance(v, int):
        return v
    if isinstance(v, str):
        s = v.strip()
        if s.isdigit():
            return int(s)
        m = _ASDOT.match(s)
        if m is not None:
            high, low = int(m.group(1)), int(m.group(2))
            if high <= 65535 and low <= 65535:
                return high * 65536 + low
    raise ValueError(
        f"remote_as must be an AS number (int, decimal string, or asdot "
        f"'A.B'); got {v!r}.  Provenance/peer-type spellings "
        f"('inherited'/'internal'/'external') belong on remote_as_source."
    )


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
    route_map: str | None = Field(
        default=None, description="Route-map applied to aggregate (references RouteMapConfig)"
    )


class BGPNeighborAF(BaseModel):
    """BGP neighbor address-family specific configuration."""

    afi: str = Field(..., description="Address family identifier (e.g., 'ipv4', 'ipv6')")
    safi: str = Field(
        ..., description="Sub-address family identifier (e.g., 'unicast', 'multicast')"
    )
    activate: bool | None = Field(
        default=None,
        description=(
            "Activate this address family. TRI-STATE (CCR-0165): True = "
            "explicitly activated (or the OS convention where the AF block's "
            "presence activates — NX-OS/IOS-XR/JunOS parsers assert True "
            "themselves); None = NOT STATED in the parsed text (an EOS "
            "policy-only AF line in a partial snippet) — a merge must never "
            "let None overwrite a stated baseline value; False = explicitly "
            "deactivated. Consumers read activation as bool(activate), so an "
            "unstated entry in a FULL config reads not-activated (the EOS "
            "multi-agent device truth)."
        ),
    )
    send_community: bool | str | None = Field(
        default=None,
        description="Send community attribute (True/False/'extended'/'both'/None=not configured)",
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
    maximum_prefix_warning_only: bool = Field(
        default=False,
        description="maximum-prefix warning-only — log but do not tear down session",
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
    advertise_map: str | None = Field(
        default=None,
        description=(
            "Route-map naming the prefixes to conditionally advertise "
            "(used with exist_map for conditional advertisement)"
        ),
    )
    exist_map: str | None = Field(
        default=None,
        description=(
            "Route-map whose condition must match a prefix in the local RIB "
            "for advertise_map prefixes to be sent; if the condition is FALSE "
            "all matching prefixes are suppressed"
        ),
    )


class BGPNeighbor(BaseModel):
    """BGP neighbor configuration."""

    peer_ip: IPv4Address | IPv6Address = Field(..., description="Neighbor IP address")
    # REQUIRED-BUT-NULLABLE (CCR-0170): required-ness is load-bearing —
    # the entrp merger's proposal-always-wins branch and _reset_field's
    # required-field no-op both key on the field having NO default.
    remote_as: int | None = Field(
        ..., description="Remote AS number (int; None when not stated — see remote_as_source)"
    )
    remote_as_source: Literal["declared", "inherited", "internal", "external"] | None = Field(
        default=None,
        description=(
            "Parse-time provenance of remote_as: 'declared' = stated as a "
            "number; 'inherited' = not stated (may resolve via peer-group/"
            "template); 'internal'/'external' = stated as a peer TYPE, not "
            "a number.  Inheritance fills the VALUE only; source keeps the "
            "parse-time fact."
        ),
    )

    _validate_remote_as = field_validator("remote_as", mode="before")(
        normalize_remote_as
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
    send_community: bool | str | None = Field(
        default=None,
        description="Send community attribute (True/False/'extended'/'both'/None=not configured)",
    )
    route_reflector_client: bool = Field(
        default=False, description="Configure as route-reflector client"
    )
    password: str | None = Field(default=None, description="MD5 password")
    password_encryption_type: str | None = Field(
        default=None,
        description="Encryption/hash type token preceding the MD5 key (e.g. '7', '3')",
    )
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
    default_originate: bool = Field(
        default=False, description="Originate default route to this neighbor"
    )
    default_originate_route_map: str | None = Field(
        default=None,
        description="Route-map for default-originate (references RouteMapConfig)",
    )
    address_families: list[BGPNeighborAF] = Field(
        default_factory=list,
        description="Address-family specific configurations",
    )
    default_originate: bool = Field(
        default=False,
        description=(
            "Originate a default route to this neighbor. On NX-OS this is a back-compat "
            "scalar hoisted from the ipv4-unicast neighbor address-family (where NX-OS "
            "nests it); address_families[].default_originate is the per-AF source of truth. "
            "IOS-XR neighbors carry it per-AF only and leave this scalar False."
        ),
    )
    default_originate_route_map: str | None = Field(
        default=None,
        description=(
            "Route-map gating default-originate (references RouteMapConfig). Back-compat "
            "scalar hoisted from the ipv4-unicast neighbor address-family."
        ),
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
    remote_as: int | None = Field(
        default=None, description="Remote AS number (int; see remote_as_source)"
    )
    remote_as_source: Literal["declared", "inherited", "internal", "external"] | None = Field(
        default=None,
        description="Parse-time provenance of remote_as (see BGPNeighbor).",
    )

    _validate_remote_as = field_validator("remote_as", mode="before")(
        normalize_remote_as
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
    send_community: bool | str | None = Field(
        default=None, description="Send community attribute (None=not configured)"
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
    default_originate: bool = Field(
        default=False, description="Originate default route to peers in this group"
    )
    default_originate_route_map: str | None = Field(
        default=None,
        description="Route-map for default-originate (references RouteMapConfig)",
    )
    local_as: int | None = Field(
        default=None, description="Local AS number for this peer-group"
    )
    local_as_no_prepend: bool = Field(
        default=False, description="Do not prepend local-as to updates from peer"
    )
    local_as_replace_as: bool = Field(
        default=False, description="Replace real AS with local-as in updates to peer"
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
    prefix_validate_allow_invalid: bool | None = Field(
        default=None,
        description=(
            "RPKI prefix validation mode: True = allow-invalid (permissive); "
            "False = strict enforcement (invalid ROA routes dropped); "
            "None = not mentioned in this config block (merger: no override)."
        ),
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
    rd: str | None = Field(
        default=None,
        description="Route-distinguisher declared inside the BGP VRF sub-block",
    )
    # Route-targets declared inside the BGP VRF sub-block (`router bgp N > vrf X >
    # route-target import|export …`). On EOS that is the ONLY place a device prints
    # them — the `vrf instance` block carries just name/description — so these are
    # not a duplicate of VRFConfig.route_target_*: they are where the L3VPN policy
    # is *declared*, and BaseParser._backfill_vrf_rd_rt attributes them onto the
    # VRFConfig so a consumer never has to know which vendor wrote the config.
    route_target_import: list[str] = Field(
        default_factory=list,
        description="Route-target import values declared inside the BGP VRF sub-block",
    )
    route_target_export: list[str] = Field(
        default_factory=list,
        description="Route-target export values declared inside the BGP VRF sub-block",
    )
    route_target_both: list[str] = Field(
        default_factory=list,
        description="Route-target import+export values declared inside the BGP VRF sub-block",
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
    default_ipv4_unicast: bool = Field(
        default=True,
        description=(
            "IOS/IOS-XE: the IPv4-unicast address family is auto-activated for "
            "every `neighbor remote-as` (command default = enabled). Set False by "
            "`no bgp default ipv4-unicast`, after which each neighbor's IPv4 AF "
            "activation is explicit (NX-OS-style). Absence of the line == the "
            "default (True): the affirmative `bgp default ipv4-unicast` never "
            "renders in running-config, so only the `no` form is ever seen. "
            "SCOPE GUARD for consumers: this field is meaningful ONLY for "
            "IOS-family configs — on NX-OS/IOS-XR activation is always "
            "explicit and this default-True carries no operational meaning; "
            "read it only under an IOS/IOS-XE source_os branch (an unguarded "
            "read would recreate the ipv4-default-on false positive on NX-OS)."
        ),
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
    rpki_server: str | None = Field(
        default=None,
        description=(
            "RPKI cache server address — format '<ip>:<port>' "
            "(e.g. '10.100.0.100:3323'). None = not configured."
        ),
    )
