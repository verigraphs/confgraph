"""AAA (Authentication, Authorization, Accounting) configuration models."""

from pydantic import BaseModel, Field
from confgraph.models.base import BaseConfigObject


class AAAAuthList(BaseModel):
    """AAA authentication method list."""

    name: str = Field(..., description="Method list name (e.g., 'default', 'CONSOLE')")
    service: str = Field(..., description="Service type: login, enable, dot1x, ppp")
    methods: list[str] = Field(default_factory=list, description="Ordered method list (local, tacacs+, radius, none, ...)")


class AAAAuthorList(BaseModel):
    """AAA authorization method list."""

    name: str = Field(..., description="Method list name")
    service: str = Field(..., description="Service type: exec, commands, network, ...")
    privilege_level: int | None = Field(default=None, description="Privilege level (for 'commands N' type)")
    methods: list[str] = Field(default_factory=list, description="Ordered method list")


class AAAAcctList(BaseModel):
    """AAA accounting method list."""

    name: str = Field(..., description="Method list name")
    service: str = Field(..., description="Service type: exec, commands, network, ...")
    privilege_level: int | None = Field(default=None, description="Privilege level (for 'commands N' type)")
    trigger: str = Field(default="start-stop", description="Accounting trigger: start-stop, stop-only, none")
    methods: list[str] = Field(default_factory=list, description="Ordered method list")


class TacacsServer(BaseModel):
    """TACACS+ server definition."""

    name: str | None = Field(default=None, description="Named server block name (IOS-XE 'tacacs server T1')")
    address: str = Field(..., description="Server IP or hostname")
    port: int | None = Field(default=None, description="TCP port (default 49)")
    timeout: int | None = Field(default=None, description="Timeout in seconds")
    key: str | None = Field(default=None, description="Shared secret key (may be encrypted)")
    vrf: str | None = Field(default=None, description="VRF for management plane access")


class RadiusServer(BaseModel):
    """RADIUS server definition."""

    name: str | None = Field(default=None, description="Named server block name (IOS-XE 'radius server R1')")
    address: str = Field(..., description="Server IP or hostname")
    auth_port: int | None = Field(default=None, description="Auth port (default 1812/1645)")
    acct_port: int | None = Field(default=None, description="Accounting port (default 1813/1646)")
    timeout: int | None = Field(default=None, description="Timeout in seconds")
    key: str | None = Field(default=None, description="Shared secret key (may be encrypted)")
    vrf: str | None = Field(default=None, description="VRF for management plane access")


class AAAConfig(BaseConfigObject):
    """AAA configuration (singleton per device)."""

    new_model: bool = Field(default=False, description="'aaa new-model' is present")
    authentication_lists: list[AAAAuthList] = Field(
        default_factory=list, description="Authentication method lists"
    )
    authorization_lists: list[AAAAuthorList] = Field(
        default_factory=list, description="Authorization method lists"
    )
    accounting_lists: list[AAAAcctList] = Field(
        default_factory=list, description="Accounting method lists"
    )
    tacacs_servers: list[TacacsServer] = Field(
        default_factory=list, description="TACACS+ server definitions"
    )
    radius_servers: list[RadiusServer] = Field(
        default_factory=list, description="RADIUS server definitions"
    )
    tacacs_source_interface: str | None = Field(
        default=None,
        description="Source interface for TACACS+ packets (ip tacacs source-interface)",
    )
    radius_source_interface: str | None = Field(
        default=None,
        description="Source interface for RADIUS packets (ip radius source-interface)",
    )
    local_auth_enabled: bool = Field(
        default=False,
        description="At least one authentication list uses 'local' as a method",
    )

    class Config:
        use_enum_values = True
