"""Syslog/logging configuration models.

Named logging_config to avoid collision with the stdlib logging module.
"""

from ipaddress import IPv4Address, IPv6Address
from pydantic import BaseModel, Field
from confgraph.models.base import BaseConfigObject


class LoggingHost(BaseModel):
    """Syslog server host."""

    address: IPv4Address | IPv6Address | str = Field(..., description="Syslog server address")
    transport: str | None = Field(default=None, description="Transport (udp, tcp, tls)")
    port: int | None = Field(default=None, description="Port number")
    vrf: str | None = Field(default=None, description="VRF context")
    level: str | None = Field(default=None, description="Severity level filter")


class SyslogConfig(BaseConfigObject):
    """Syslog/logging configuration (singleton per device)."""

    enabled: bool = Field(default=True, description="Logging enabled")
    hosts: list[LoggingHost] = Field(default_factory=list, description="Syslog servers")
    buffered_size: int | None = Field(default=None, description="Log buffer size (bytes)")
    buffered_level: str | None = Field(default=None, description="Minimum level for buffer logging")
    console_level: str | None = Field(default=None, description="Minimum level for console logging")
    monitor_level: str | None = Field(default=None, description="Minimum level for monitor (terminal) logging")
    trap_level: str | None = Field(default=None, description="Minimum level for syslog trap")
    facility: str | None = Field(default=None, description="Syslog facility (e.g., local7)")
    source_interface: str | None = Field(default=None, description="Source interface for syslog packets")
    origin_id: str | None = Field(default=None, description="Origin ID added to messages")
    timestamps_log: str | None = Field(default=None, description="Timestamp format for log messages")
    timestamps_debug: str | None = Field(default=None, description="Timestamp format for debug messages")

    class Config:
        use_enum_values = True
