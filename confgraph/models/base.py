"""Base models for all network configuration objects."""

from enum import Enum
from pydantic import BaseModel, Field


class UnrecognizedBlock(BaseModel):
    """Config not handled by any parser method.

    Captures config sections for unsupported protocols/services so that no
    configuration is silently dropped. Two granularities share this model:
    a whole top-level block no parse method claims, and a single child line
    inside a claimed block that its parse method does not consume (the
    header then reads '<block header> > <child line>').
    """

    block_header: str = Field(
        ...,
        description=(
            "First line of an unclaimed block (e.g. 'ntp server 10.0.0.1'), or "
            "'<block header> > <child line>' for an unrecognized child line "
            "inside a claimed block (e.g. 'router ospf 1 > distribute-list "
            "prefix BLOCK-ALL in')"
        ),
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
    JUNOS = "junos"
    PANOS = "panos"


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
    no_commands: list[str] = Field(
        default_factory=list,
        description=(
            "Scoped deletion tombstones set by the parser when 'no' commands appear "
            "within this object's config block (e.g. 'neighbor:10.1.1.1' on BGPConfig, "
            "'seq:30' on ACLConfig, 'description' on InterfaceConfig)."
        ),
    )

    class Config:
        """Pydantic model configuration."""
        use_enum_values = True
