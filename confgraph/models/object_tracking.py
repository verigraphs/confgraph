"""Object tracking configuration models."""

from pydantic import BaseModel, Field
from confgraph.models.base import BaseConfigObject


class TrackListObject(BaseModel):
    """Object reference within a tracking list."""

    object_id: int = Field(..., description="Tracked object ID")
    negate: bool = Field(default=False, description="Negate the state of this object")


class ObjectTrack(BaseConfigObject):
    """Object tracking configuration."""

    track_id: int = Field(..., description="Track object ID")
    track_type: str = Field(..., description="Track type (interface, ip sla, list, ip route, etc.)")
    tracked_interface: str | None = Field(default=None, description="Interface being tracked")
    tracked_interface_param: str | None = Field(default=None, description="Interface parameter (line-protocol, ip routing)")
    tracked_sla_id: int | None = Field(default=None, description="IP SLA operation ID being tracked")
    tracked_sla_param: str | None = Field(default=None, description="IP SLA parameter (reachability, state)")
    tracked_route: str | None = Field(default=None, description="IP route being tracked (prefix/len)")
    tracked_route_vrf: str | None = Field(default=None, description="VRF for tracked route")
    list_type: str | None = Field(default=None, description="List tracking type (boolean-and, boolean-or, threshold)")
    list_objects: list[TrackListObject] = Field(default_factory=list, description="Objects in the tracking list")
    delay_up: int | None = Field(default=None, description="Delay before transitioning to up (seconds)")
    delay_down: int | None = Field(default=None, description="Delay before transitioning to down (seconds)")

    class Config:
        use_enum_values = True
