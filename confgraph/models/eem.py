"""EEM (Embedded Event Manager) configuration models."""

from pydantic import BaseModel, Field
from confgraph.models.base import BaseConfigObject


class EEMEvent(BaseModel):
    """EEM event specification."""

    event_type: str = Field(..., description="Event type (syslog, timer, interface, snmp, etc.)")
    parameters: dict[str, str] = Field(default_factory=dict, description="Event parameters as key-value pairs")
    raw: str = Field(..., description="Raw event line text")


class EEMAction(BaseModel):
    """EEM action entry."""

    label: str = Field(..., description="Action label (e.g., '1.0', '001')")
    action_type: str = Field(..., description="Action type (cli, syslog, snmp-trap, mail, set, etc.)")
    parameters: str = Field(default="", description="Action parameters (rest of the action line)")


class EEMApplet(BaseConfigObject):
    """EEM applet configuration."""

    name: str = Field(..., description="Applet name")
    event: EEMEvent | None = Field(default=None, description="Event that triggers the applet")
    actions: list[EEMAction] = Field(default_factory=list, description="Actions to execute")
    description: str | None = Field(default=None, description="Applet description")
    maximum_run_time: int | None = Field(default=None, description="Maximum run time (seconds)")

    class Config:
        use_enum_values = True
