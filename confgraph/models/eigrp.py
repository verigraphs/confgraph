"""EIGRP configuration models."""

from ipaddress import IPv4Address, IPv4Network
from pydantic import BaseModel, Field
from confgraph.models.base import BaseConfigObject


class EIGRPMetric(BaseModel):
    """EIGRP metric components."""

    bandwidth: int | None = Field(default=None, description="Bandwidth (Kbps)")
    delay: int | None = Field(default=None, description="Delay (tens of microseconds)")
    reliability: int | None = Field(default=None, description="Reliability (1-255)")
    load: int | None = Field(default=None, description="Load (1-255)")
    mtu: int | None = Field(default=None, description="MTU (bytes)")


class EIGRPNetwork(BaseModel):
    """EIGRP network statement."""

    network: IPv4Network = Field(..., description="Network address")
    wildcard: str | None = Field(default=None, description="Wildcard mask")


class EIGRPRedistribute(BaseModel):
    """EIGRP redistribution entry."""

    protocol: str = Field(..., description="Protocol to redistribute")
    process_id: int | str | None = Field(default=None, description="Process ID")
    metric: EIGRPMetric | None = Field(default=None, description="Metric values")
    route_map: str | None = Field(default=None, description="Route-map name")
    tag: int | None = Field(default=None, description="Tag value")


class EIGRPConfig(BaseConfigObject):
    """EIGRP process configuration."""

    as_number: int | str = Field(..., description="EIGRP autonomous system number")
    router_id: IPv4Address | None = Field(default=None, description="EIGRP router ID")
    networks: list[EIGRPNetwork] = Field(default_factory=list, description="Network statements")
    passive_interface_default: bool = Field(default=False, description="All interfaces passive by default")
    passive_interfaces: list[str] = Field(default_factory=list, description="Explicitly passive interfaces")
    non_passive_interfaces: list[str] = Field(default_factory=list, description="Non-passive interfaces (when default passive)")
    redistribute: list[EIGRPRedistribute] = Field(default_factory=list, description="Redistribution configurations")
    auto_summary: bool = Field(default=False, description="Auto-summary enabled")
    variance: int | None = Field(default=None, description="Variance for unequal-cost load balancing")
    maximum_paths: int | None = Field(default=None, description="Maximum equal-cost paths")
    distance_internal: int | None = Field(default=None, description="AD for internal routes")
    distance_external: int | None = Field(default=None, description="AD for external routes")
    default_metric: EIGRPMetric | None = Field(default=None, description="Default metric for redistribution")
    log_neighbor_changes: bool = Field(default=False, description="Log neighbor state changes")
    vrf: str | None = Field(default=None, description="VRF context")
    stub: str | None = Field(default=None, description="Stub configuration (e.g., 'connected summary')")

    class Config:
        use_enum_values = True
