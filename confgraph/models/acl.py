"""Access Control List (ACL) configuration models."""

from ipaddress import IPv4Address, IPv4Network
from pydantic import BaseModel, Field, computed_field
from confgraph.models.base import BaseConfigObject


def _parse_acl_addr(addr: str | None, wildcard: str | None) -> IPv4Network | None:
    """Convert an ACL address + wildcard mask into an IPv4Network.

    Handles the four forms that appear in IOS/EOS/NX-OS/IOS-XR ACLs:

    * ``any``               → 0.0.0.0/0
    * ``host 10.0.0.1``     → 10.0.0.1/32
    * ``10.0.0.0 0.0.0.255``  (addr + wildcard)  → 10.0.0.0/24
    * ``10.0.0.0/24``       (CIDR, EOS style)    → 10.0.0.0/24

    Returns ``None`` if the address cannot be parsed (e.g. named object-groups).
    """
    if not addr:
        return None

    addr = addr.strip()

    if addr == "any":
        return IPv4Network("0.0.0.0/0")

    if addr.startswith("host "):
        host_str = addr[5:].strip()
        try:
            return IPv4Network(f"{host_str}/32")
        except ValueError:
            return None

    if "/" in addr:
        try:
            return IPv4Network(addr, strict=False)
        except ValueError:
            return None

    # Plain IP — pair with wildcard mask if available
    if wildcard:
        try:
            # Wildcard is the bitwise inverse of a subnet mask.
            # IPv4Network accepts hostmask notation directly.
            return IPv4Network(f"{addr}/{wildcard}", strict=False)
        except ValueError:
            pass

    # Plain IP with no wildcard — treat as /32
    try:
        return IPv4Network(f"{addr}/32")
    except ValueError:
        return None


class ACLEntry(BaseModel):
    """ACL entry (ACE - Access Control Entry)."""

    sequence: int | None = Field(
        default=None,
        description="Sequence number (for named ACLs)",
    )
    action: str = Field(
        ...,
        description="Action ('permit' or 'deny')",
    )
    protocol: str | None = Field(
        default=None,
        description="Protocol (ip, tcp, udp, icmp, eigrp, ospf, etc.)",
    )
    source: str | None = Field(
        default=None,
        description="Source address or 'any' or 'host X.X.X.X'",
    )
    source_wildcard: str | None = Field(
        default=None,
        description="Source wildcard mask",
    )
    destination: str | None = Field(
        default=None,
        description="Destination address or 'any' or 'host X.X.X.X'",
    )
    destination_wildcard: str | None = Field(
        default=None,
        description="Destination wildcard mask",
    )
    source_port: str | None = Field(
        default=None,
        description="Source port or port range (e.g., 'eq 80', 'range 1024 65535')",
    )
    destination_port: str | None = Field(
        default=None,
        description="Destination port or port range",
    )
    flags: list[str] = Field(
        default_factory=list,
        description="Additional flags (established, log, etc.)",
    )
    remark: str | None = Field(
        default=None,
        description="Comment/remark for this entry",
    )

    @computed_field
    @property
    def source_network(self) -> IPv4Network | None:
        """Source address as IPv4Network (None if unparseable).

        Enables programmatic analysis such as overlap detection::

            if entry_a.source_network.overlaps(entry_b.source_network): ...
        """
        return _parse_acl_addr(self.source, self.source_wildcard)

    @computed_field
    @property
    def destination_network(self) -> IPv4Network | None:
        """Destination address as IPv4Network (None if unparseable)."""
        return _parse_acl_addr(self.destination, self.destination_wildcard)


class ACLConfig(BaseConfigObject):
    """Access Control List configuration.

    Supports standard ACLs (1-99, 1300-1999), extended ACLs (100-199, 2000-2699),
    and named ACLs (standard/extended).
    """

    name: str = Field(
        ...,
        description="ACL name or number",
    )
    acl_type: str = Field(
        ...,
        description="ACL type ('standard', 'extended', 'ipv6')",
    )
    entries: list[ACLEntry] = Field(
        default_factory=list,
        description="ACL entries",
    )
