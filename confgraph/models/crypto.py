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


class IKECryptoProfile(BaseModel):
    """A NAMED IKE (Phase-1) crypto profile — PAN-OS
    ``network/ike/crypto-profiles/ike-crypto-profiles/entry`` (CCR-0139).

    The SAME device object also lands, nameless, in
    :attr:`CryptoConfig.isakmp_policies` as an :class:`IKEv1Policy` (that
    flattening predates this model and stays for its existing consumers).  Both
    are populated from ONE walk in ``PANOSParser.parse_crypto`` so they cannot
    disagree.

    This object exists because the NAME is the thing an IKE gateway references:
    without it, deleting a profile object a gateway still points at is
    invisible (CCR-0130's edge 1 has nothing to resolve against).

    Two fields ``IKEv1Policy`` carries are deliberately absent: ``priority``
    (PAN-OS has no policy priority — the flattened form synthesizes 10/20/30…
    from walk order, and a named object must not carry a fabricated ordinal as
    if the device emitted it) and ``authentication`` (nothing in the PAN-OS
    walk reads it).
    """

    name: str = Field(..., description="IKE crypto profile name")
    encryption: str | None = Field(default=None, description="Encryption algorithm (first member as emitted)")
    hash: str | None = Field(default=None, description="Hash algorithm (first member as emitted)")
    group: int | None = Field(default=None, description="DH group number (from 'groupN')")
    lifetime: int | None = Field(default=None, description="IKE SA lifetime (seconds)")


class IKEGateway(BaseModel):
    """A NAMED IKE gateway — PAN-OS ``network/ike/gateway/entry`` (CCR-0139).

    The middle link of the tunnel dependency chain
    ``tunnel.N -> IPSec tunnel -> IKE gateway -> physical egress`` (CCR-0116):
    an IPSec tunnel's ``auto-key/ike-gateway/entry@name`` resolves to one of
    these, and the gateway in turn names the physical egress interface every
    tunnel riding it depends on.

    The same device object also lands, anonymously, in
    :attr:`CryptoConfig.crypto_maps` as a :class:`CryptoMapEntry` (sequence
    numbers synthesized from walk order).  Both are populated from ONE walk in
    ``PANOSParser.parse_crypto``; the anonymous form is unchanged and keeps its
    consumers.

    COPY INVARIANT (CCR-0130 design review S4): a tunnel ``InterfaceConfig``
    bound to this gateway carries parse-time COPIES of two fields below —
    ``InterfaceConfig.tunnel_underlay_interface`` copies
    :attr:`egress_interface` and ``InterfaceConfig.tunnel_ike_crypto_profile``
    copies :attr:`ike_crypto_profile`.  Both come from this object via
    ``PANOSParser._bind_tunnel_underlay``, so the gateway OWNS those facts and
    the interface fields are a convenience view of them.
    """

    name: str = Field(..., description="IKE gateway name")
    egress_interface: str | None = Field(
        default=None,
        description=(
            "Physical egress interface the gateway (and every tunnel riding it) "
            "depends on (PAN-OS local-address/interface)"
        ),
    )
    # ``str``, not IPv4Address: this keeps the emitted text verbatim instead of
    # coercing it.  Only the <ip> child is read today, so an fqdn or dynamic
    # peer (both device-valid — syntax-corpus panos/ipsec.yaml
    # ike-gateway-peer-address) leaves this None; that is the flattened form's
    # existing gap carried over, not a new one, and the type leaves room to
    # close it without a model change.
    peer_address: str | None = Field(
        default=None,
        description="Peer endpoint as emitted (peer-address/ip; None for fqdn/dynamic peers)",
    )
    ike_version: str | None = Field(
        default=None,
        description="Negotiated IKE version (protocol/version: ikev1, ikev2, ikev2-preferred)",
    )
    ike_crypto_profile: str | None = Field(
        default=None,
        description="Referenced IKE (Phase-1) crypto profile name",
    )


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
    # CCR-0139 — the tunnel chain's middle links, BY NAME.  Additive and
    # PAN-OS-only: the IOS family has no named IKE gateways or IKE crypto
    # profiles (its ISAKMP policies are keyed by priority), so its parsers
    # leave both lists empty.  Each object also appears in its pre-existing
    # anonymous form above (isakmp_policies / crypto_maps), populated from the
    # same walk — see IKEGateway / IKECryptoProfile.
    ike_crypto_profiles: list[IKECryptoProfile] = Field(
        default_factory=list, description="Named IKE (Phase-1) crypto profiles (PAN-OS)"
    )
    ike_gateways: list[IKEGateway] = Field(
        default_factory=list, description="Named IKE gateways (PAN-OS)"
    )

    class Config:
        use_enum_values = True
