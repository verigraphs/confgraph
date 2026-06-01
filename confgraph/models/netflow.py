"""NetFlow configuration models."""

from ipaddress import IPv4Address
from pydantic import BaseModel, Field
from confgraph.models.base import BaseConfigObject


class NetFlowDestination(BaseModel):
    """A single NetFlow export destination (collector)."""

    address: IPv4Address = Field(..., description="Collector IP address")
    port: int = Field(..., description="UDP port")


class NetFlowConfig(BaseConfigObject):
    """NetFlow export configuration (singleton per device).

    Covers classic IOS NetFlow ('ip flow-export') commands.
    """

    source_interface: str | None = Field(
        default=None,
        description="Interface used as source IP for flow export packets",
    )
    destinations: list[NetFlowDestination] = Field(
        default_factory=list,
        description="Flow export destinations (collector IP + UDP port)",
    )
    version: int | None = Field(
        default=None,
        description="NetFlow export version (5, 9, etc.)",
    )

    class Config:
        use_enum_values = True
