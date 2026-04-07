"""NAT (Network Address Translation) configuration models."""

from ipaddress import IPv4Address
from pydantic import BaseModel, Field
from confgraph.models.base import BaseConfigObject


class NATPool(BaseModel):
    """NAT address pool."""

    name: str = Field(..., description="Pool name")
    start_address: IPv4Address = Field(..., description="Start IP address")
    end_address: IPv4Address = Field(..., description="End IP address")
    netmask: str | None = Field(default=None, description="Netmask")
    prefix_length: int | None = Field(default=None, description="Prefix length")
    type: str | None = Field(default=None, description="Pool type (rotary, match-host)")


class NATStaticEntry(BaseModel):
    """Static NAT translation entry."""

    direction: str = Field(default="inside", description="Translation direction (inside/outside)")
    protocol: str | None = Field(default=None, description="Protocol (tcp, udp) for port NAT")
    local_ip: IPv4Address = Field(..., description="Local IP address")
    local_port: int | None = Field(default=None, description="Local port (for port NAT)")
    global_ip: IPv4Address = Field(..., description="Global IP address")
    global_port: int | None = Field(default=None, description="Global port (for port NAT)")
    vrf: str | None = Field(default=None, description="VRF context")
    extendable: bool = Field(default=False, description="Extendable entry")


class NATDynamicEntry(BaseModel):
    """Dynamic NAT/PAT entry."""

    direction: str = Field(default="inside", description="Translation direction (inside/outside)")
    acl: str = Field(..., description="ACL name defining which addresses to translate")
    pool: str | None = Field(default=None, description="NAT pool name")
    interface: str | None = Field(default=None, description="Interface for PAT (overload on interface)")
    overload: bool = Field(default=False, description="PAT/overload enabled")
    vrf: str | None = Field(default=None, description="VRF context")


class NATTimeouts(BaseModel):
    """NAT translation timeout values."""

    default: int | None = Field(default=None, description="Default timeout (seconds)")
    tcp: int | None = Field(default=None, description="TCP timeout (seconds)")
    udp: int | None = Field(default=None, description="UDP timeout (seconds)")
    dns: int | None = Field(default=None, description="DNS timeout (seconds)")
    finrst: int | None = Field(default=None, description="TCP FIN/RST timeout (seconds)")
    icmp: int | None = Field(default=None, description="ICMP timeout (seconds)")
    syn: int | None = Field(default=None, description="TCP SYN timeout (seconds)")


class NATConfig(BaseConfigObject):
    """NAT configuration (singleton per device)."""

    pools: list[NATPool] = Field(default_factory=list, description="NAT address pools")
    static_entries: list[NATStaticEntry] = Field(default_factory=list, description="Static NAT translations")
    dynamic_entries: list[NATDynamicEntry] = Field(default_factory=list, description="Dynamic NAT/PAT entries")
    timeouts: NATTimeouts = Field(default_factory=NATTimeouts, description="NAT translation timeouts")
    translation_max_entries: int | None = Field(default=None, description="Maximum translation table entries")
    log_translations: bool = Field(default=False, description="Log translation events")

    class Config:
        use_enum_values = True
