"""LLDP (Link Layer Discovery Protocol) configuration models."""

from pydantic import Field
from confgraph.models.base import BaseConfigObject


class LLDPConfig(BaseConfigObject):
    """LLDP global configuration (singleton per device)."""

    enabled: bool = Field(
        default=True,
        description="LLDP globally enabled ('lldp run' / 'no lldp run')",
    )
    timer: int | None = Field(
        default=None,
        description="LLDP advertisement interval in seconds ('lldp timer N')",
    )
    holdtime: int | None = Field(
        default=None,
        description="LLDP holdtime in seconds ('lldp holdtime N')",
    )
    reinit: int | None = Field(
        default=None,
        description="LLDP reinit delay in seconds ('lldp reinit N')",
    )
    tlv_select: list[str] = Field(
        default_factory=list,
        description="TLV types explicitly enabled via 'lldp tlv-select'",
    )

    class Config:
        use_enum_values = True
