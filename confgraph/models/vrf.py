"""VRF configuration models."""

from pydantic import Field
from confgraph.models.base import BaseConfigObject


class VRFConfig(BaseConfigObject):
    """VRF (Virtual Routing and Forwarding) configuration.

    VRF is a top-level config object that can be referenced by:
    - Interfaces (vrf member/vrf forwarding)
    - BGP (address-family vrf)
    - OSPF (vrf context)

    COPY-INVARIANT (CCR-0145 N1): on NX-OS, an ``evpn``-suffixed
    ``route-target ... evpn`` / ``rd`` line under ``vrf context`` also feeds
    :class:`~confgraph.models.evpn.EVPNL3VNI` — :meth:`NXOSParser.parse_vrfs`
    captures the value here (ignoring the trailing ``evpn`` token) while
    :meth:`NXOSParser.parse_evpn` captures it there (keyed by ``vni``). The
    ``EVPNL3VNI`` copy is AUTHORITATIVE for EVPN engine reads; the values held
    here are a parse-consistency shadow of those RTs (and must agree). Plain
    (non-``evpn``) RTs are L3VPN and live ONLY here. Removals honour the split:
    an ``evpn``-suffixed ``no`` clears both copies (dual-tombstone); a plain
    ``no route-target`` clears only this copy.
    """

    name: str = Field(
        ...,
        description="VRF name",
    )
    rd: str | None = Field(
        default=None,
        description="Route distinguisher (e.g., '65000:1')",
    )
    route_target_import: list[str] = Field(
        default_factory=list,
        description="Route target import values (e.g., ['65000:1', '65000:2'])",
    )
    route_target_export: list[str] = Field(
        default_factory=list,
        description="Route target export values",
    )
    route_target_both: list[str] = Field(
        default_factory=list,
        description="Route target values applied to both import and export",
    )
    description: str | None = Field(
        default=None,
        description="VRF description",
    )
    route_map_import: str | None = Field(
        default=None,
        description="Route-map applied on import (references RouteMapConfig)",
    )
    route_map_export: str | None = Field(
        default=None,
        description="Route-map applied on export (references RouteMapConfig)",
    )
    interfaces: list[str] = Field(
        default_factory=list,
        description="List of interface names assigned to this VRF",
    )
    vpnid: str | None = Field(
        default=None,
        description="VPN ID (NX-OS specific)",
    )
    domain_name: str | None = Field(
        default=None,
        description=(
            "VRF-scoped DNS domain name ('ip domain-name' under 'vrf context "
            "NAME'); distinct from the global DNSConfig.domain_name (NX-OS)"
        ),
    )
    domain_list: list[str] = Field(
        default_factory=list,
        description="VRF-scoped DNS search domains ('ip domain-list' under 'vrf context NAME')",
    )
    name_servers: list[str] = Field(
        default_factory=list,
        description=(
            "VRF-scoped DNS resolvers ('ip name-server' under 'vrf context NAME'); "
            "the management VRF's resolver set, kept separate from global DNS (NX-OS)"
        ),
    )
