"""Crypto (IPsec/IKE) configuration models."""

from ipaddress import IPv4Address
from pydantic import BaseModel, Field
from confgraph.models.base import BaseConfigObject


class IKEv1Policy(BaseModel):
    """IKEv1 (ISAKMP) policy."""

    priority: int = Field(..., description="Policy priority (lower = preferred)")
    encryption: str | None = Field(default=None, description="Encryption algorithm (des, 3des, aes-128, etc.)")
    hash: str | None = Field(default=None, description="Hash algorithm (md5, sha, sha256)")
    authentication: str | None = Field(default=None, description="Authentication method (pre-share, rsa-sig)")
    group: int | None = Field(default=None, description="DH group number")
    lifetime: int | None = Field(default=None, description="SA lifetime (seconds)")


class IKEv1Key(BaseModel):
    """IKEv1 pre-shared key."""

    key_string: str = Field(..., description="Pre-shared key string")
    peer_address: IPv4Address | None = Field(default=None, description="Peer address")
    peer_wildcard: str | None = Field(default=None, description="Peer wildcard (0.0.0.0 for any)")
    vrf: str | None = Field(default=None, description="VRF context")


class IKEv2Proposal(BaseModel):
    """IKEv2 proposal."""

    name: str = Field(..., description="Proposal name")
    encryption: list[str] = Field(default_factory=list, description="Encryption algorithms")
    integrity: list[str] = Field(default_factory=list, description="Integrity algorithms")
    group: list[int] = Field(default_factory=list, description="DH groups")


class IKEv2Policy(BaseModel):
    """IKEv2 policy."""

    name: str = Field(..., description="Policy name")
    proposals: list[str] = Field(default_factory=list, description="Proposal names")
    match_fvrf: str | None = Field(default=None, description="Match front-door VRF")
    match_address_local: IPv4Address | None = Field(default=None, description="Match local address")


class IPSecTransformSet(BaseModel):
    """IPsec transform set."""

    name: str = Field(..., description="Transform set name")
    transforms: list[str] = Field(default_factory=list, description="Transforms (esp-aes, esp-sha-hmac, etc.)")
    mode: str = Field(default="tunnel", description="Mode (tunnel or transport)")


class CryptoMapEntry(BaseModel):
    """Single entry in a crypto map."""

    sequence: int = Field(..., description="Sequence number")
    map_type: str = Field(default="ipsec-isakmp", description="Map type")
    peer: IPv4Address | None = Field(default=None, description="Remote peer address")
    transform_sets: list[str] = Field(default_factory=list, description="Transform set names")
    acl: str | None = Field(default=None, description="Match ACL name")
    pfs_group: int | None = Field(default=None, description="PFS DH group")
    sa_lifetime_seconds: int | None = Field(default=None, description="SA lifetime (seconds)")
    sa_lifetime_kilobytes: int | None = Field(default=None, description="SA lifetime (kilobytes)")
    isakmp_profile: str | None = Field(default=None, description="ISAKMP profile name")
    ikev2_profile: str | None = Field(default=None, description="IKEv2 profile name")


class CryptoMap(BaseModel):
    """Crypto map (collection of entries)."""

    name: str = Field(..., description="Crypto map name")
    entries: list[CryptoMapEntry] = Field(default_factory=list, description="Crypto map entries")


class IPSecProfile(BaseModel):
    """IPsec profile (for tunnel interfaces)."""

    name: str = Field(..., description="Profile name")
    transform_sets: list[str] = Field(default_factory=list, description="Transform set names")
    pfs_group: int | None = Field(default=None, description="PFS DH group")
    sa_lifetime_seconds: int | None = Field(default=None, description="SA lifetime (seconds)")
    ikev2_profile: str | None = Field(default=None, description="IKEv2 profile name")


class CryptoConfig(BaseConfigObject):
    """Crypto/IPsec configuration (singleton per device)."""

    isakmp_policies: list[IKEv1Policy] = Field(default_factory=list, description="IKEv1 ISAKMP policies")
    isakmp_keys: list[IKEv1Key] = Field(default_factory=list, description="IKEv1 pre-shared keys")
    ikev2_proposals: list[IKEv2Proposal] = Field(default_factory=list, description="IKEv2 proposals")
    ikev2_policies: list[IKEv2Policy] = Field(default_factory=list, description="IKEv2 policies")
    transform_sets: list[IPSecTransformSet] = Field(default_factory=list, description="IPsec transform sets")
    crypto_maps: list[CryptoMap] = Field(default_factory=list, description="Crypto maps")
    ipsec_profiles: list[IPSecProfile] = Field(default_factory=list, description="IPsec profiles")

    class Config:
        use_enum_values = True
