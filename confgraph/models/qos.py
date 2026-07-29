"""QoS (Quality of Service) configuration models — class-map and policy-map."""

from pydantic import BaseModel, Field
from confgraph.models.base import BaseConfigObject


class ClassMapMatch(BaseModel):
    """A single match criterion inside a class-map."""

    match_type: str = Field(..., description="Match type (e.g., 'dscp', 'access-group', 'protocol', 'ip precedence')")
    values: list[str] = Field(default_factory=list, description="Match values")


class ClassMapConfig(BaseConfigObject):
    """Class-map configuration."""

    name: str = Field(..., description="Class-map name")
    type: str | None = Field(
        default=None,
        description="Type qualifier from 'class-map type <X> ...' (e.g. 'control-plane', 'qos', 'queuing'); None for the plain untyped form",
    )
    match_type: str = Field(default="match-all", description="Match logic: match-all or match-any")
    matches: list[ClassMapMatch] = Field(default_factory=list, description="Match criteria")

    class Config:
        use_enum_values = True


class PoliceAction(BaseModel):
    """Action taken by a policer for a specific color."""

    action_type: str = Field(..., description="conform/exceed/violate")
    action: str = Field(..., description="Action (transmit, drop, set-dscp-transmit, etc.)")


class PolicyMapPolice(BaseModel):
    """Police statement within a policy-map class."""

    rate: int | None = Field(default=None, description="Rate in bps")
    burst: int | None = Field(default=None, description="Normal burst (bytes)")
    excess_burst: int | None = Field(default=None, description="Excess burst (bytes)")
    rate_unit: str | None = Field(default=None, description="Rate unit (bps, kbps, mbps, gbps, percent)")
    conform_actions: list[PoliceAction] = Field(default_factory=list)
    exceed_actions: list[PoliceAction] = Field(default_factory=list)
    violate_actions: list[PoliceAction] = Field(default_factory=list)


class PolicyMapShape(BaseModel):
    """Traffic shaping statement."""

    type: str = Field(..., description="Shape type (average, peak)")
    rate: int = Field(..., description="Rate in bps")


class PolicyMapSet(BaseModel):
    """Set action within a policy-map class."""

    set_type: str = Field(..., description="Set type (dscp, precedence, cos, qos-group, etc.)")
    value: str = Field(..., description="Set value")


class PolicyMapClass(BaseModel):
    """A class entry inside a policy-map."""

    class_name: str = Field(..., description="Class-map name reference")
    bandwidth: int | None = Field(default=None, description="Guaranteed bandwidth (Kbps)")
    bandwidth_percent: int | None = Field(default=None, description="Guaranteed bandwidth (%)")
    priority: int | None = Field(default=None, description="LLQ priority bandwidth (Kbps)")
    priority_percent: int | None = Field(default=None, description="LLQ priority bandwidth (%)")
    police: PolicyMapPolice | None = Field(default=None, description="Police configuration")
    shape: PolicyMapShape | None = Field(default=None, description="Shape configuration")
    queue_limit: int | None = Field(default=None, description="Queue limit (packets)")
    random_detect: bool = Field(default=False, description="WRED enabled")
    set_actions: list[PolicyMapSet] = Field(default_factory=list, description="Set actions")
    service_policy: str | None = Field(default=None, description="Child policy-map name (hierarchical)")


class PolicyMapConfig(BaseConfigObject):
    """Policy-map configuration."""

    name: str = Field(..., description="Policy-map name")
    type: str | None = Field(
        default=None,
        description="Type qualifier from 'policy-map type <X> ...' (e.g. 'control-plane', 'qos', 'queuing'); None for the plain untyped form",
    )
    classes: list[PolicyMapClass] = Field(default_factory=list, description="Class entries")

    class Config:
        use_enum_values = True


class ControlPlaneConfig(BaseModel):
    """Control-plane (CoPP) binding — the 'control-plane' block.

    Models the service-policy that attaches a control-plane policing (CoPP)
    policy-map to the control plane, e.g. NX-OS::

        control-plane
          service-policy input PM_COPP
    """

    service_policy_input: str | None = Field(
        default=None,
        description="Name of the policy-map attached via 'service-policy input <PM>'",
    )
