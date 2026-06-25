"""VLAN database and VTP models."""

from pydantic import BaseModel, Field

from confgraph.models.base import BaseConfigObject


class VLANEntry(BaseModel):
    """A single VLAN in the device VLAN database."""

    vlan_id: int = Field(..., description="VLAN ID (1–4094)")
    name: str | None = Field(default=None, description="VLAN name")
    state: str = Field(default="active", description="'active' or 'suspend'")
    vn_segment: int | None = Field(
        default=None,
        description="VXLAN VNI mapped to this VLAN (NX-OS 'vn-segment')",
    )


class VTPConfig(BaseConfigObject):
    """VLAN Trunking Protocol configuration."""

    domain: str | None = Field(default=None, description="VTP domain name")
    mode: str | None = Field(
        default=None,
        description="VTP mode: 'server', 'client', 'transparent', or 'off'",
    )
    version: int | None = Field(default=None, description="VTP version (1, 2, or 3)")

    class Config:
        use_enum_values = True
