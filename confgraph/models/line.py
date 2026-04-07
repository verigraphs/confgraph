"""Line (console, VTY, aux, TTY) configuration models."""

from enum import Enum
from pydantic import Field
from confgraph.models.base import BaseConfigObject


class LineType(str, Enum):
    """Line type classification."""

    CONSOLE = "console"
    VTY = "vty"
    AUX = "aux"
    TTY = "tty"


class LineConfig(BaseConfigObject):
    """Configuration for a console, VTY, AUX, or TTY line."""

    line_type: LineType = Field(..., description="Line type")
    first_line: int = Field(..., description="First line number")
    last_line: int | None = Field(default=None, description="Last line number (for ranges like vty 0 4)")
    exec_timeout_minutes: int | None = Field(default=None, description="Exec timeout minutes")
    exec_timeout_seconds: int | None = Field(default=None, description="Exec timeout seconds")
    logging_synchronous: bool = Field(default=False, description="Synchronize log messages")
    transport_input: list[str] = Field(default_factory=list, description="Allowed input transports (ssh, telnet, none, all)")
    transport_output: list[str] = Field(default_factory=list, description="Allowed output transports")
    access_class_in: str | None = Field(default=None, description="Inbound access class (ACL name)")
    access_class_out: str | None = Field(default=None, description="Outbound access class (ACL name)")
    ipv6_access_class_in: str | None = Field(default=None, description="IPv6 inbound access class")
    privilege_level: int | None = Field(default=None, description="Default privilege level")
    password: str | None = Field(default=None, description="Line password")
    login: str | None = Field(default=None, description="Login authentication (local, tacacs, etc.)")
    length: int | None = Field(default=None, description="Screen length (lines)")
    width: int | None = Field(default=None, description="Screen width (columns)")
    session_timeout: int | None = Field(default=None, description="Session timeout (minutes)")
    history_size: int | None = Field(default=None, description="History buffer size")
    no_exec: bool = Field(default=False, description="No exec shell on this line")
    stopbits: int | None = Field(default=None, description="Stop bits (for serial lines)")
    speed: int | None = Field(default=None, description="Line speed (baud rate)")
    flowcontrol: str | None = Field(default=None, description="Flow control (hardware, software, none)")

    class Config:
        use_enum_values = True
