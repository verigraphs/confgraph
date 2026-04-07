"""IP SLA configuration models."""

from ipaddress import IPv4Address
from pydantic import BaseModel, Field
from confgraph.models.base import BaseConfigObject


class IPSLASchedule(BaseModel):
    """IP SLA schedule configuration."""

    sla_id: int = Field(..., description="SLA operation ID")
    life: str = Field(default="forever", description="Schedule life (forever or seconds)")
    start_time: str = Field(default="now", description="Start time")
    recurring: bool = Field(default=False, description="Recurring schedule")
    ageout: int | None = Field(default=None, description="Ageout time (seconds)")


class IPSLAReaction(BaseModel):
    """IP SLA reaction configuration."""

    sla_id: int = Field(..., description="SLA operation ID")
    react_element: str = Field(..., description="React element (rtt, packetLoss, etc.)")
    threshold_type: str = Field(default="never", description="Threshold type")
    threshold_value_upper: int | None = Field(default=None, description="Upper threshold value")
    threshold_value_lower: int | None = Field(default=None, description="Lower threshold value")
    action_type: str = Field(default="none", description="Action type (trapOnly, triggerOnly, trapAndTrigger)")


class IPSLAOperation(BaseConfigObject):
    """IP SLA operation configuration."""

    sla_id: int = Field(..., description="SLA operation ID")
    operation_type: str = Field(..., description="Operation type (icmp-echo, udp-jitter, tcp-connect, etc.)")
    destination: str = Field(..., description="Destination address or hostname")
    source_interface: str | None = Field(default=None, description="Source interface")
    source_ip: IPv4Address | None = Field(default=None, description="Source IP address")
    port: int | None = Field(default=None, description="Destination port")
    frequency: int | None = Field(default=None, description="Probe frequency (seconds)")
    threshold: int | None = Field(default=None, description="Threshold (ms)")
    timeout: int | None = Field(default=None, description="Operation timeout (ms)")
    vrf: str | None = Field(default=None, description="VRF context")
    tag: str | None = Field(default=None, description="Operation tag")
    schedule: IPSLASchedule | None = Field(default=None, description="Schedule configuration")
    reactions: list[IPSLAReaction] = Field(default_factory=list, description="Reaction configurations")

    class Config:
        use_enum_values = True
