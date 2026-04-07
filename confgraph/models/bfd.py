"""BFD (Bidirectional Forwarding Detection) configuration models."""

from pydantic import BaseModel, Field
from confgraph.models.base import BaseConfigObject


class BFDInterval(BaseModel):
    """BFD timer intervals."""

    min_tx: int = Field(..., description="Minimum transmit interval (ms)")
    min_rx: int = Field(..., description="Minimum receive interval (ms)")
    multiplier: int = Field(..., description="Detection multiplier")


class BFDTemplate(BaseModel):
    """BFD template configuration."""

    name: str = Field(..., description="Template name")
    type: str = Field(default="single-hop", description="Template type (single-hop, multi-hop)")
    interval: BFDInterval | None = Field(default=None, description="Timer intervals")
    echo: bool = Field(default=True, description="Echo mode enabled")
    authentication: str | None = Field(default=None, description="Authentication method")


class BFDMap(BaseModel):
    """BFD map entry (for multi-hop)."""

    afi: str = Field(..., description="Address family (ipv4, ipv6)")
    destination: str = Field(..., description="Destination address")
    source: str = Field(..., description="Source address")
    template: str = Field(..., description="Template name")


class BFDConfig(BaseConfigObject):
    """BFD global configuration (singleton per device)."""

    templates: list[BFDTemplate] = Field(default_factory=list, description="BFD templates")
    maps: list[BFDMap] = Field(default_factory=list, description="BFD maps")
    slow_timers: int | None = Field(default=None, description="Slow timer interval (ms)")

    class Config:
        use_enum_values = True
