"""DHCP server / relay / snooping configuration models."""

from pydantic import BaseModel, Field
from confgraph.models.base import BaseConfigObject


class DHCPExcludedRange(BaseModel):
    """DHCP excluded address range ('ip dhcp excluded-address')."""

    low: str = Field(..., description="First excluded IP address")
    high: str | None = Field(default=None, description="Last excluded IP address (None = single address)")


class DHCPPool(BaseModel):
    """DHCP address pool ('ip dhcp pool NAME')."""

    name: str = Field(..., description="Pool name")
    network: str | None = Field(default=None, description="Subnet (e.g. '192.168.1.0 255.255.255.0')")
    default_router: list[str] = Field(default_factory=list, description="Default gateway IPs")
    dns_servers: list[str] = Field(default_factory=list, description="DNS server IPs")
    domain_name: str | None = Field(default=None, description="Domain name pushed to clients")
    lease_days: int | None = Field(default=None, description="Lease duration in days")
    lease_hours: int | None = Field(default=None, description="Lease duration hours component")
    lease_minutes: int | None = Field(default=None, description="Lease duration minutes component")
    lease_infinite: bool = Field(default=False, description="Lease is infinite")


class DHCPConfig(BaseConfigObject):
    """DHCP server / relay / snooping configuration (singleton per device)."""

    excluded_ranges: list[DHCPExcludedRange] = Field(
        default_factory=list, description="Excluded address ranges"
    )
    pools: list[DHCPPool] = Field(
        default_factory=list, description="DHCP address pools"
    )
    snooping_enabled: bool = Field(
        default=False,
        description="DHCP snooping globally enabled ('ip dhcp snooping')",
    )
    snooping_vlans: list[str] = Field(
        default_factory=list,
        description="VLANs with snooping enabled ('ip dhcp snooping vlan ...')",
    )
    relay_information_option: bool = Field(
        default=True,
        description="Option 82 insertion enabled (default on IOS; 'no ip dhcp relay information option' disables)",
    )

    class Config:
        use_enum_values = True
