"""VLAN database models."""

from pydantic import BaseModel, Field


class VLANEntry(BaseModel):
    """A single VLAN in the device VLAN database."""

    vlan_id: int = Field(..., description="VLAN ID (1–4094)")
    name: str | None = Field(default=None, description="VLAN name")
    state: str = Field(default="active", description="'active' or 'suspend'")
