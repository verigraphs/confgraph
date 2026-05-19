"""Spanning Tree Protocol (STP / RSTP / MSTP) configuration models."""

from pydantic import BaseModel, Field
from confgraph.models.base import BaseConfigObject


class STPVlanConfig(BaseModel):
    """Per-VLAN STP parameters."""

    vlan_id: str = Field(..., description="VLAN ID or range (e.g. '1', '10-20', '1,5,10')")
    priority: int | None = Field(default=None, description="Bridge priority (multiples of 4096)")
    hello_time: int | None = Field(default=None, description="Hello time in seconds")
    forward_time: int | None = Field(default=None, description="Forward delay in seconds")
    max_age: int | None = Field(default=None, description="Max age in seconds")


class STPConfig(BaseConfigObject):
    """Spanning Tree global configuration (singleton per device)."""

    mode: str | None = Field(
        default=None,
        description="STP mode: pvst, rapid-pvst, mst (IOS) / mstp, rstp (EOS) / rapid-pvst (NX-OS)",
    )
    vlan_configs: list[STPVlanConfig] = Field(
        default_factory=list,
        description="Per-VLAN STP parameters",
    )
    portfast_default: bool = Field(
        default=False,
        description="Portfast enabled by default on all access ports",
    )
    bpduguard_default: bool = Field(
        default=False,
        description="BPDU guard enabled by default on portfast ports",
    )
    bpdufilter_default: bool = Field(
        default=False,
        description="BPDU filter enabled by default on portfast ports",
    )
    loopguard_default: bool = Field(
        default=False,
        description="Loopguard enabled globally",
    )

    class Config:
        use_enum_values = True
