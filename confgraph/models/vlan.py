"""VLAN database and VTP models."""

from pydantic import BaseModel, Field

from confgraph.models.base import BaseConfigObject


class VLANEntry(BaseModel):
    """A single VLAN in the device VLAN database."""

    vlan_id: int = Field(..., description="VLAN ID (1–4094)")
    name: str | None = Field(default=None, description="VLAN name")
    state: str | None = Field(
        default=None,
        description="'active' or 'suspend'; None when the config does not state it",
    )
    vn_segment: int | None = Field(
        default=None,
        description="VXLAN VNI mapped to this VLAN (NX-OS 'vn-segment')",
    )


def vlan_is_active(entry: VLANEntry) -> bool:
    """A VLAN with no stated ``state`` is active on the device.

    ``state`` is None when the config never said ``state active|suspend``
    (CCR-0211: a fabricated "active" is indistinguishable from an explicit
    restate under field-level merge).  Every active-VLAN test reads through
    here so the unstated case cannot drift between call sites.
    """
    return entry.state != "suspend"


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
