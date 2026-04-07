"""VRF configuration models."""

from pydantic import Field
from confgraph.models.base import BaseConfigObject


class VRFConfig(BaseConfigObject):
    """VRF (Virtual Routing and Forwarding) configuration.

    VRF is a top-level config object that can be referenced by:
    - Interfaces (vrf member/vrf forwarding)
    - BGP (address-family vrf)
    - OSPF (vrf context)
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
