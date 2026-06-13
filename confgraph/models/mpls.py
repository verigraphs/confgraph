"""MPLS / LDP configuration models."""

from ipaddress import IPv4Address
from pydantic import Field
from confgraph.models.base import BaseConfigObject


class MPLSConfig(BaseConfigObject):
    """MPLS and LDP configuration (singleton per device).

    Covers global MPLS label switching and LDP session parameters.
    Per-interface ``mpls ip`` enablement is on InterfaceConfig.mpls_ip.
    """

    ldp_router_id: str | None = Field(
        default=None,
        description="LDP router-ID interface (e.g. 'Loopback0')",
    )
    ldp_router_id_force: bool = Field(
        default=False,
        description="Force LDP router-ID even if interface is down",
    )
    label_range_min: int | None = Field(
        default=None,
        description="Minimum label value in the local label space",
    )
    label_range_max: int | None = Field(
        default=None,
        description="Maximum label value in the local label space",
    )
    ldp_enabled: bool = Field(
        default=False,
        description="LDP is globally enabled (at least one interface has mpls ip or mpls ldp configured)",
    )
    ldp_graceful_restart: bool = Field(
        default=False,
        description="LDP graceful restart enabled",
    )
    ldp_session_protection: bool = Field(
        default=False,
        description="LDP session protection (targeted hello) enabled",
    )
    ldp_password: str | None = Field(
        default=None,
        description="LDP neighbor password (MD5 authentication)",
    )
