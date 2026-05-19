"""CDP (Cisco Discovery Protocol) configuration models."""

from pydantic import Field
from confgraph.models.base import BaseConfigObject


class CDPConfig(BaseConfigObject):
    """CDP global configuration (singleton per device)."""

    enabled: bool = Field(
        default=True,
        description="CDP globally enabled ('cdp run' / 'no cdp run')",
    )
    timer: int | None = Field(
        default=None,
        description="CDP advertisement interval in seconds ('cdp timer N')",
    )
    holdtime: int | None = Field(
        default=None,
        description="CDP holdtime in seconds ('cdp holdtime N')",
    )
    advertise_v2: bool = Field(
        default=True,
        description="CDPv2 advertisements enabled ('cdp advertise-v2')",
    )

    class Config:
        use_enum_values = True
