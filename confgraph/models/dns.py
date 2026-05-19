"""DNS / name resolution configuration models."""

from pydantic import Field
from confgraph.models.base import BaseConfigObject


class DNSConfig(BaseConfigObject):
    """DNS / name-resolution configuration (singleton per device)."""

    lookup_enabled: bool = Field(
        default=True,
        description="IP DNS lookup is enabled ('no ip domain lookup' sets this False)",
    )
    domain_name: str | None = Field(
        default=None,
        description="Primary domain name ('ip domain name DOMAIN' / 'ip domain-name DOMAIN')",
    )
    domain_list: list[str] = Field(
        default_factory=list,
        description="Additional search domains ('ip domain list DOMAIN')",
    )
    name_servers: list[str] = Field(
        default_factory=list,
        description="Ordered list of name-server IPs ('ip name-server ...')",
    )
    vrf: str | None = Field(
        default=None,
        description="VRF used for DNS queries (NX-OS: 'ip domain-lookup source-interface')",
    )

    class Config:
        use_enum_values = True
