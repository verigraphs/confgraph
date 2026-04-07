"""Interface configuration models."""

from enum import Enum
from ipaddress import IPv4Address, IPv4Interface, IPv6Interface
from pydantic import BaseModel, Field
from confgraph.models.base import BaseConfigObject


class InterfaceType(str, Enum):
    """Interface type classification."""

    PHYSICAL = "physical"
    LOOPBACK = "loopback"
    SVI = "svi"
    PORTCHANNEL = "portchannel"
    TUNNEL = "tunnel"
    MANAGEMENT = "management"
    VLAN = "vlan"
    NULL = "null"


class HSRPGroup(BaseModel):
    """HSRP (Hot Standby Router Protocol) group configuration."""

    group_number: int = Field(..., description="HSRP group number")
    priority: int | None = Field(default=None, description="HSRP priority (0-255)")
    preempt: bool = Field(default=False, description="Preempt enabled")
    virtual_ip: IPv4Address | None = Field(
        default=None, description="Virtual IP address"
    )
    timers_hello: int | None = Field(default=None, description="Hello timer (seconds)")
    timers_hold: int | None = Field(default=None, description="Hold timer (seconds)")
    authentication: str | None = Field(
        default=None, description="Authentication string"
    )
    track_objects: list[int] = Field(
        default_factory=list, description="Tracked object numbers"
    )


class VRRPGroup(BaseModel):
    """VRRP (Virtual Router Redundancy Protocol) group configuration."""

    group_number: int = Field(..., description="VRRP group number")
    priority: int | None = Field(default=None, description="VRRP priority (1-254)")
    preempt: bool = Field(default=False, description="Preempt enabled")
    virtual_ip: IPv4Address | None = Field(
        default=None, description="Virtual IP address"
    )
    timers_advertise: int | None = Field(
        default=None, description="Advertisement timer (seconds)"
    )
    authentication: str | None = Field(
        default=None, description="Authentication string"
    )
    track_objects: list[int] = Field(
        default_factory=list, description="Tracked object numbers"
    )


class InterfaceConfig(BaseConfigObject):
    """Interface configuration for all interface types.

    Covers physical, loopback, SVI, port-channel, tunnel interfaces
    across all vendor OS types.
    """

    name: str = Field(
        ...,
        description="Interface name (e.g., 'GigabitEthernet0/0/1', 'Loopback0')",
    )
    interface_type: InterfaceType = Field(
        ...,
        description="Interface type classification",
    )
    description: str | None = Field(
        default=None,
        description="Interface description",
    )
    enabled: bool = Field(
        default=True,
        description="Interface enabled (no shutdown = True, shutdown = False)",
    )
    vrf: str | None = Field(
        default=None,
        description="VRF assignment (references VRFConfig name)",
    )

    # Layer 3 addressing
    ip_address: IPv4Interface | None = Field(
        default=None,
        description="Primary IPv4 address with prefix length (e.g., '10.0.0.1/24')",
    )
    ipv6_addresses: list[IPv6Interface] = Field(
        default_factory=list,
        description="IPv6 addresses assigned to this interface",
    )
    secondary_ips: list[IPv4Interface] = Field(
        default_factory=list,
        description="Secondary IPv4 addresses",
    )
    unnumbered_source: str | None = Field(
        default=None,
        description="Source interface for IP unnumbered (references another interface)",
    )

    # Physical attributes
    mtu: int | None = Field(
        default=None,
        description="Maximum transmission unit (bytes)",
    )
    speed: str | None = Field(
        default=None,
        description="Interface speed (e.g., '1000', 'auto')",
    )
    duplex: str | None = Field(
        default=None,
        description="Duplex mode ('full', 'half', 'auto')",
    )
    bandwidth: int | None = Field(
        default=None,
        description="Configured bandwidth in Kbps (for OSPF cost calculation)",
    )

    # Layer 2 attributes
    switchport_mode: str | None = Field(
        default=None,
        description="Switchport mode ('access', 'trunk', 'routed')",
    )
    access_vlan: int | None = Field(
        default=None,
        description="Access VLAN ID",
    )
    trunk_allowed_vlans: list[int] = Field(
        default_factory=list,
        description="Allowed VLANs on trunk (empty list = all)",
    )
    trunk_native_vlan: int | None = Field(
        default=None,
        description="Native VLAN for trunk",
    )

    # Port-channel
    channel_group: int | None = Field(
        default=None,
        description="Port-channel number this interface belongs to",
    )
    channel_group_mode: str | None = Field(
        default=None,
        description="Channel-group mode ('active', 'passive', 'on', 'desirable', 'auto')",
    )

    # FHRP (First Hop Redundancy Protocols)
    hsrp_groups: list[HSRPGroup] = Field(
        default_factory=list,
        description="HSRP groups configured on this interface",
    )
    vrrp_groups: list[VRRPGroup] = Field(
        default_factory=list,
        description="VRRP groups configured on this interface",
    )

    # OSPF (embedded per-interface config)
    ospf_process_id: int | str | None = Field(
        default=None,
        description="OSPF process ID (if OSPF enabled on this interface)",
    )
    ospf_area: str | None = Field(
        default=None,
        description="OSPF area ID",
    )
    ospf_cost: int | None = Field(
        default=None,
        description="OSPF cost override",
    )
    ospf_priority: int | None = Field(
        default=None,
        description="OSPF priority for DR/BDR election",
    )
    ospf_hello_interval: int | None = Field(
        default=None,
        description="OSPF hello interval (seconds)",
    )
    ospf_dead_interval: int | None = Field(
        default=None,
        description="OSPF dead interval (seconds)",
    )
    ospf_network_type: str | None = Field(
        default=None,
        description="OSPF network type ('point-to-point', 'broadcast', etc.)",
    )
    ospf_passive: bool = Field(
        default=False,
        description="OSPF passive interface",
    )
    ospf_authentication: str | None = Field(
        default=None,
        description="OSPF authentication type ('message-digest', 'null')",
    )
    ospf_authentication_key: str | None = Field(
        default=None,
        description="OSPF authentication key",
    )
    ospf_message_digest_keys: dict[int, str] = Field(
        default_factory=dict,
        description="OSPF message-digest keys (key-id -> key-string)",
    )

    # Helper addresses
    helper_addresses: list[IPv4Address] = Field(
        default_factory=list,
        description="DHCP relay / IP helper addresses",
    )

    # Tunnel attributes
    tunnel_source: str | None = Field(
        default=None,
        description="Tunnel source (interface name or IP address)",
    )
    tunnel_destination: IPv4Address | None = Field(
        default=None,
        description="Tunnel destination IP address",
    )
    tunnel_mode: str | None = Field(
        default=None,
        description="Tunnel mode (e.g., 'gre ip', 'ipsec ipv4')",
    )

    # CDP/LLDP
    cdp_enabled: bool = Field(
        default=True,
        description="CDP enabled on this interface",
    )
    lldp_transmit: bool = Field(
        default=True,
        description="LLDP transmit enabled",
    )
    lldp_receive: bool = Field(
        default=True,
        description="LLDP receive enabled",
    )

    # PIM per-interface
    pim_mode: str | None = Field(default=None, description="PIM mode (sparse-mode, dense-mode, sparse-dense-mode)")
    pim_dr_priority: int | None = Field(default=None, description="PIM DR priority")
    pim_query_interval: int | None = Field(default=None, description="PIM query interval (seconds)")
    pim_bfd: bool = Field(default=False, description="BFD enabled for PIM on this interface")

    # IGMP per-interface
    igmp_version: int | None = Field(default=None, description="IGMP version (1, 2, 3)")
    igmp_query_interval: int | None = Field(default=None, description="IGMP query interval (seconds)")
    igmp_query_max_response_time: int | None = Field(default=None, description="IGMP query max response time (seconds)")
    igmp_access_group: str | None = Field(default=None, description="IGMP access group ACL")
    igmp_join_groups: list[str] = Field(default_factory=list, description="IGMP join-group addresses")
    igmp_static_groups: list[str] = Field(default_factory=list, description="IGMP static-group addresses")

    # QoS service-policy
    service_policy_input: str | None = Field(default=None, description="Input service-policy name")
    service_policy_output: str | None = Field(default=None, description="Output service-policy name")

    # NAT
    nat_direction: str | None = Field(default=None, description="NAT direction (inside or outside)")

    # Crypto
    crypto_map: str | None = Field(default=None, description="Crypto map applied to this interface")

    class Config:
        """Pydantic model configuration."""
        use_enum_values = True
