"""Base models for all network configuration objects."""

from enum import Enum
from pydantic import BaseModel, Field


class UnrecognizedBlock(BaseModel):
    """A top-level config block not handled by any parser method.

    Captures config sections for unsupported protocols/services so
    that no configuration is silently dropped.
    """

    block_header: str = Field(
        ...,
        description="First line of the block (e.g. 'ntp server 10.0.0.1')",
    )
    raw_lines: list[str] = Field(
        ...,
        description="All lines of the block including children",
    )
    best_guess: str | None = Field(
        default=None,
        description="Inferred protocol/service keyword (e.g. 'ntp', 'aaa')",
    )


class OSType(str, Enum):
    """Supported network operating systems."""

    IOS = "ios"
    IOS_XE = "ios_xe"
    IOS_XR = "ios_xr"
    NXOS = "nxos"
    EOS = "eos"


class BaseConfigObject(BaseModel):
    """Base class for all configuration objects.

    All protocol-specific config models inherit from this to maintain:
    - Original raw config lines
    - Source OS type
    - Unique identifier
    - Line number references
    """

    object_id: str = Field(
        ...,
        description="Unique identifier for this config object (e.g., 'bgp_65000', 'interface_Loopback0')",
    )
    raw_lines: list[str] = Field(
        default_factory=list,
        description="Original configuration lines from the device",
    )
    source_os: OSType = Field(
        ...,
        description="Source operating system type",
    )
    line_numbers: list[int] = Field(
        default_factory=list,
        description="Line numbers in the original configuration file",
    )

    class Config:
        """Pydantic model configuration."""
        use_enum_values = True
