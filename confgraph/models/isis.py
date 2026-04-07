"""IS-IS configuration models."""

from ipaddress import IPv4Address
from pydantic import BaseModel, Field
from confgraph.models.base import BaseConfigObject


class ISISRedistribute(BaseModel):
    """IS-IS redistribution configuration."""

    protocol: str = Field(
        ...,
        description="Protocol to redistribute (bgp, ospf, connected, static, etc.)",
    )
    process_id: int | str | None = Field(
        default=None,
        description="Process ID for BGP/OSPF",
    )
    route_map: str | None = Field(
        default=None,
        description="Route-map to apply (references RouteMapConfig)",
    )
    metric: int | None = Field(
        default=None,
        description="Metric value",
    )
    metric_type: str | None = Field(
        default=None,
        description="Metric type (internal/external)",
    )
    level: str | None = Field(
        default=None,
        description="Level (level-1, level-2, level-1-2)",
    )


class ISISInterface(BaseModel):
    """IS-IS interface configuration."""

    name: str = Field(
        ...,
        description="Interface name",
    )
    circuit_type: str | None = Field(
        default=None,
        description="Circuit type (level-1, level-2, level-1-2)",
    )
    metric: int | None = Field(
        default=None,
        description="IS-IS metric",
    )
    level_1_metric: int | None = Field(
        default=None,
        description="Level-1 specific metric",
    )
    level_2_metric: int | None = Field(
        default=None,
        description="Level-2 specific metric",
    )
    priority: int | None = Field(
        default=None,
        description="DIS priority",
    )
    passive: bool = Field(
        default=False,
        description="Passive interface",
    )
    hello_interval: int | None = Field(
        default=None,
        description="Hello interval (seconds)",
    )
    hello_multiplier: int | None = Field(
        default=None,
        description="Hello multiplier",
    )


class ISISConfig(BaseConfigObject):
    """IS-IS (Intermediate System to Intermediate System) configuration.

    Covers IS-IS routing process configuration including NET addresses,
    authentication, and redistribution.
    """

    tag: str | None = Field(
        default=None,
        description="IS-IS process tag/name",
    )
    net: list[str] = Field(
        default_factory=list,
        description="Network Entity Title (NET) addresses",
    )
    is_type: str | None = Field(
        default=None,
        description="IS type (level-1, level-2, level-1-2)",
    )
    metric_style: str | None = Field(
        default=None,
        description="Metric style (narrow, wide, transition)",
    )
    log_adjacency_changes: bool = Field(
        default=False,
        description="Log adjacency state changes",
    )
    passive_interface_default: bool = Field(
        default=False,
        description="Set all interfaces passive by default",
    )
    passive_interfaces: list[str] = Field(
        default_factory=list,
        description="Passive interface names",
    )
    non_passive_interfaces: list[str] = Field(
        default_factory=list,
        description="Non-passive interfaces (when default is passive)",
    )
    redistribute: list[ISISRedistribute] = Field(
        default_factory=list,
        description="Redistribution configurations",
    )
    authentication_mode: str | None = Field(
        default=None,
        description="Authentication mode (md5, text)",
    )
    authentication_key: str | None = Field(
        default=None,
        description="Authentication key",
    )
    max_lsp_lifetime: int | None = Field(
        default=None,
        description="Maximum LSP lifetime (seconds)",
    )
    lsp_refresh_interval: int | None = Field(
        default=None,
        description="LSP refresh interval (seconds)",
    )
    spf_interval: int | None = Field(
        default=None,
        description="SPF calculation interval (seconds)",
    )
