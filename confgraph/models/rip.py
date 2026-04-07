"""RIP configuration models."""

from ipaddress import IPv4Network
from pydantic import BaseModel, Field
from confgraph.models.base import BaseConfigObject


class RIPTimers(BaseModel):
    """RIP timer configuration."""

    update: int = Field(..., description="Update timer (seconds)")
    invalid: int = Field(..., description="Invalid timer (seconds)")
    holddown: int = Field(..., description="Holddown timer (seconds)")
    flush: int = Field(..., description="Flush timer (seconds)")


class RIPRedistribute(BaseModel):
    """RIP redistribution entry."""

    protocol: str = Field(..., description="Protocol to redistribute")
    process_id: int | str | None = Field(default=None, description="Process ID")
    metric: int | None = Field(default=None, description="Metric value")
    route_map: str | None = Field(default=None, description="Route-map name")


class RIPConfig(BaseConfigObject):
    """RIP process configuration."""

    version: int = Field(default=2, description="RIP version (1 or 2)")
    networks: list[IPv4Network] = Field(default_factory=list, description="Network statements")
    passive_interface_default: bool = Field(default=False, description="All interfaces passive by default")
    passive_interfaces: list[str] = Field(default_factory=list, description="Explicitly passive interfaces")
    non_passive_interfaces: list[str] = Field(default_factory=list, description="Non-passive interfaces (when default passive)")
    redistribute: list[RIPRedistribute] = Field(default_factory=list, description="Redistribution configurations")
    auto_summary: bool = Field(default=False, description="Auto-summary enabled")
    timers: RIPTimers | None = Field(default=None, description="RIP timer configuration")
    default_information_originate: bool = Field(default=False, description="Originate default route")
    maximum_paths: int | None = Field(default=None, description="Maximum equal-cost paths")
    distance: int | None = Field(default=None, description="Administrative distance")
    vrf: str | None = Field(default=None, description="VRF context")

    class Config:
        use_enum_values = True
