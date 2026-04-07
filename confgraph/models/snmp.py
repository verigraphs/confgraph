"""SNMP configuration models."""

from ipaddress import IPv4Address, IPv6Address
from pydantic import BaseModel, Field
from confgraph.models.base import BaseConfigObject


class SNMPCommunity(BaseModel):
    """SNMP community string configuration."""

    community_string: str = Field(..., description="Community string")
    access: str = Field(..., description="Access type: ro or rw")
    acl: str | None = Field(default=None, description="IPv4 ACL name")
    ipv6_acl: str | None = Field(default=None, description="IPv6 ACL name")
    view: str | None = Field(default=None, description="MIB view name")


class SNMPHost(BaseModel):
    """SNMP trap/inform host."""

    address: IPv4Address | IPv6Address | str = Field(..., description="Host address")
    version: str = Field(..., description="SNMP version (1, 2c, 3)")
    community_or_user: str = Field(..., description="Community string or username")
    traps: bool = Field(default=True, description="Send traps (False = informs)")
    udp_port: int | None = Field(default=None, description="UDP port")
    vrf: str | None = Field(default=None, description="VRF context")


class SNMPView(BaseModel):
    """SNMP MIB view."""

    name: str = Field(..., description="View name")
    oid_tree: str = Field(..., description="OID tree")
    included: bool = Field(default=True, description="Included (True) or excluded (False)")


class SNMPGroup(BaseModel):
    """SNMP v3 group."""

    name: str = Field(..., description="Group name")
    version: str = Field(..., description="SNMP version")
    security_level: str | None = Field(default=None, description="Security level (noauth, auth, priv)")
    read_view: str | None = Field(default=None, description="Read view")
    write_view: str | None = Field(default=None, description="Write view")
    notify_view: str | None = Field(default=None, description="Notify view")
    acl: str | None = Field(default=None, description="Access list")


class SNMPUser(BaseModel):
    """SNMP v3 user."""

    username: str = Field(..., description="Username")
    group: str = Field(..., description="Group name")
    version: str = Field(..., description="SNMP version")
    auth_algorithm: str | None = Field(default=None, description="Auth algorithm (md5, sha)")
    auth_password: str | None = Field(default=None, description="Auth password")
    priv_algorithm: str | None = Field(default=None, description="Privacy algorithm (des, aes)")
    priv_key_size: int | None = Field(default=None, description="Privacy key size (128, 192, 256)")
    priv_password: str | None = Field(default=None, description="Privacy password")


class SNMPConfig(BaseConfigObject):
    """SNMP configuration (singleton per device)."""

    communities: list[SNMPCommunity] = Field(default_factory=list, description="Community strings")
    hosts: list[SNMPHost] = Field(default_factory=list, description="Trap/inform hosts")
    location: str | None = Field(default=None, description="System location")
    contact: str | None = Field(default=None, description="System contact")
    chassis_id: str | None = Field(default=None, description="Chassis ID")
    source_interface: str | None = Field(default=None, description="Source interface")
    trap_source: str | None = Field(default=None, description="Trap source interface")
    enable_traps: list[str] = Field(default_factory=list, description="Enabled trap types")
    views: list[SNMPView] = Field(default_factory=list, description="MIB views")
    groups: list[SNMPGroup] = Field(default_factory=list, description="SNMP v3 groups")
    users: list[SNMPUser] = Field(default_factory=list, description="SNMP v3 users")
    if_index_persist: bool = Field(default=False, description="Persist ifIndex values across reloads")

    class Config:
        use_enum_values = True
