"""NTP configuration models."""

from ipaddress import IPv4Address, IPv6Address
from pydantic import BaseModel, Field
from confgraph.models.base import BaseConfigObject


class NTPAuthKey(BaseModel):
    """NTP authentication key."""

    key_id: int = Field(..., description="Key ID")
    algorithm: str = Field(..., description="Algorithm (md5, sha1, etc.)")
    key_string: str = Field(..., description="Key string (may be encrypted)")


class NTPServer(BaseModel):
    """NTP server or peer entry."""

    address: IPv4Address | IPv6Address | str = Field(..., description="Server/peer address")
    prefer: bool = Field(default=False, description="Preferred server")
    key_id: int | None = Field(default=None, description="Authentication key ID")
    version: int | None = Field(default=None, description="NTP version")
    vrf: str | None = Field(default=None, description="VRF context")
    source: str | None = Field(default=None, description="Source interface")


class NTPConfig(BaseConfigObject):
    """NTP configuration (singleton per device)."""

    master: bool = Field(default=False, description="Device is NTP master")
    master_stratum: int | None = Field(default=None, description="Stratum level when master")
    servers: list[NTPServer] = Field(default_factory=list, description="NTP servers")
    peers: list[NTPServer] = Field(default_factory=list, description="NTP peers")
    source_interface: str | None = Field(default=None, description="Source interface for NTP packets")
    authenticate: bool = Field(default=False, description="NTP authentication enabled")
    authentication_keys: list[NTPAuthKey] = Field(default_factory=list, description="Authentication keys")
    trusted_keys: list[int] = Field(default_factory=list, description="Trusted key IDs")
    access_group_query_only: str | None = Field(default=None, description="ACL for query-only access")
    access_group_serve_only: str | None = Field(default=None, description="ACL for serve-only access")
    access_group_serve: str | None = Field(default=None, description="ACL for serve access")
    access_group_peer: str | None = Field(default=None, description="ACL for peer access")
    update_calendar: bool = Field(default=False, description="Update hardware calendar")
    logging: bool = Field(default=False, description="Log NTP events")

    class Config:
        use_enum_values = True
