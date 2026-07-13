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
    version: int | None = Field(default=None, description="HSRP version (1 or 2)")
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


class GLBPGroup(BaseModel):
    """GLBP (Gateway Load Balancing Protocol) group configuration."""

    group_number: int = Field(..., description="GLBP group number")
    priority: int | None = Field(default=None, description="GLBP priority (1-255)")
    preempt: bool = Field(default=False, description="Preempt enabled")
    virtual_ip: IPv4Address | None = Field(
        default=None, description="Virtual IP address"
    )
    weighting: int | None = Field(
        default=None, description="GLBP weighting value"
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
    acl_in: str | None = Field(
        default=None,
        description="Inbound ACL applied via 'ip access-group <name> in'",
    )
    acl_out: str | None = Field(
        default=None,
        description="Outbound ACL applied via 'ip access-group <name> out'",
    )

    # Physical attributes
    mtu: int | None = Field(
        default=None,
        description="L2/system maximum transmission unit (bytes) — the 'mtu' command",
    )
    ip_mtu: int | None = Field(
        default=None,
        description="IP-layer MTU override ('ip mtu') — when set, OSPF uses this instead of mtu",
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
    delay: int | None = Field(
        default=None,
        description="Configured delay in tens of microseconds (for EIGRP metric calculation)",
    )
    eigrp_authentication_mode: str | None = Field(
        default=None,
        description="EIGRP authentication mode (md5, hmac-sha-256)",
    )
    eigrp_authentication_key_chain: str | None = Field(
        default=None,
        description="EIGRP authentication key-chain name",
    )
    eigrp_hello_interval: int | None = Field(
        default=None,
        description="EIGRP hello interval in seconds (ip hello-interval eigrp <AS> <sec>); default 5",
    )
    eigrp_hold_time: int | None = Field(
        default=None,
        description="EIGRP hold time in seconds (ip hold-time eigrp <AS> <sec>); default 15",
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
    min_links: int | None = Field(
        default=None,
        description="Minimum number of active member links required to keep port-channel up (port-channel min-links N)",
    )

    # LACP per-interface
    lacp_port_priority: int | None = Field(
        default=None,
        description="LACP port priority (lacp port-priority N). Default 32768.",
    )
    lacp_rate: str | None = Field(
        default=None,
        description="LACP rate: 'fast' (1 s) or 'normal' (30 s). None=default (normal).",
    )

    # VPC per-interface
    vpc_id: int | None = Field(
        default=None,
        description="VPC ID assigned to this port-channel (NX-OS: vpc <id>)",
    )

    # STP per-interface
    stp_portfast: bool | None = Field(
        default=None,
        description="STP portfast enabled on this interface (spanning-tree portfast). None=inherit global default.",
    )
    stp_bpduguard: bool | None = Field(
        default=None,
        description="STP BPDU guard on this interface (spanning-tree bpduguard enable/disable). None=inherit global default.",
    )
    stp_bpdufilter: bool | None = Field(
        default=None,
        description="STP BPDU filter on this interface (spanning-tree bpdufilter enable/disable). None=inherit global default.",
    )
    stp_cost: int | None = Field(
        default=None,
        description="STP path cost override (spanning-tree cost X). None=auto.",
    )
    stp_port_priority: int | None = Field(
        default=None,
        description="STP port priority (spanning-tree port-priority X). None=default (128).",
    )
    stp_root_guard: bool = Field(
        default=False,
        description="STP root guard enabled on this interface (spanning-tree guard root)",
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
    glbp_groups: list[GLBPGroup] = Field(
        default_factory=list,
        description="GLBP groups configured on this interface",
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
    ospf_mtu_ignore: bool = Field(
        default=False,
        description="Suppress OSPF MTU mismatch check on this interface (ip ospf mtu-ignore)",
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
    tunnel_protection_profile: str | None = Field(
        default=None,
        description="IPsec profile name applied via 'tunnel protection ipsec profile <name>'",
    )
    tunnel_key: int | None = Field(
        default=None,
        description="GRE tunnel key",
    )
    nhrp_network_id: int | None = Field(
        default=None,
        description="NHRP network-id (DMVPN domain identifier)",
    )
    nhrp_authentication: str | None = Field(
        default=None,
        description="NHRP authentication key",
    )
    nhrp_nhs: list[IPv4Address] = Field(
        default_factory=list,
        description="NHRP NHS (hub) IP addresses configured on this spoke",
    )
    nhrp_map: list[str] = Field(
        default_factory=list,
        description="Static NHRP map entries in 'proto-addr nbma-addr' format",
    )

    # Port-Security
    port_security_enabled: bool = Field(
        default=False,
        description="Switchport port-security globally enabled on this interface",
    )
    port_security_max_mac: int | None = Field(
        default=None,
        description="Maximum allowed MAC addresses (switchport port-security maximum N)",
    )
    port_security_violation: str | None = Field(
        default=None,
        description="Violation mode: 'shutdown', 'restrict', or 'protect'",
    )
    port_security_sticky: bool = Field(
        default=False,
        description="Sticky MAC learning enabled (switchport port-security mac-address sticky)",
    )

    # 802.1X
    dot1x_port_control: str | None = Field(
        default=None,
        description="802.1X port-control mode: 'auto', 'force-authorized', 'force-unauthorized'",
    )
    dot1x_host_mode: str | None = Field(
        default=None,
        description="802.1X host mode: 'single-host', 'multi-host', 'multi-auth', 'multi-domain'",
    )
    dot1x_mab: bool = Field(
        default=False,
        description="MAC Authentication Bypass (MAB) enabled on this interface",
    )
    dot1x_guest_vlan: int | None = Field(
        default=None,
        description="Guest VLAN assigned when no 802.1X supplicant responds",
    )
    dot1x_auth_fail_vlan: int | None = Field(
        default=None,
        description="Auth-fail VLAN assigned when 802.1X authentication fails",
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

    # MPLS per-interface
    mpls_ip: bool = Field(default=False, description="MPLS IP forwarding enabled on this interface (mpls ip)")

    # PIM per-interface
    pim_mode: str | None = Field(default=None, description="PIM mode (sparse-mode, dense-mode, sparse-dense-mode)")
    pim_dr_priority: int | None = Field(default=None, description="PIM DR priority")
    pim_query_interval: int | None = Field(default=None, description="PIM query interval (seconds)")
    pim_bfd: bool = Field(default=False, description="BFD enabled for PIM on this interface")

    # BFD per-interface
    bfd_interval: int | None = Field(default=None, description="BFD min transmit interval (ms)")
    bfd_min_rx: int | None = Field(default=None, description="BFD min receive interval (ms)")
    bfd_multiplier: int | None = Field(default=None, description="BFD detection multiplier")
    bfd_template: str | None = Field(default=None, description="BFD template name applied to this interface")

    # VARP (Arista) — the virtual gateway address(es) shared by an SVI across
    # MLAG peers; EOS's alternative to HSRP/VRRP, so it is neither of those and
    # is NOT the PAN-OS `virtual_router` field below (a routing-instance name).
    # A device emits one `ip virtual-router address <ip>` line PER address, so
    # this is a list (syntax-corpus/eos/interfaces.yaml: ip-virtual-router-address).
    varp_addresses: list[IPv4Address] = Field(
        default_factory=list,
        description="Arista VARP virtual gateway addresses (ip virtual-router address)",
    )

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

    # uRPF (unicast Reverse Path Forwarding)
    ip_verify_unicast: str | None = Field(
        default=None,
        description="uRPF mode: 'rx' (strict — source must be reachable via same interface), 'any' (loose), or None",
    )

    # PBR (Policy-Based Routing)
    ip_policy_route_map: str | None = Field(
        default=None,
        description="Route-map applied for PBR on this interface ('ip policy route-map <name>')",
    )

    # Crypto
    crypto_map: str | None = Field(default=None, description="Crypto map applied to this interface")

    # PAN-OS specific
    zone: str | None = Field(default=None, description="PAN-OS security zone this interface belongs to")
    virtual_router: str | None = Field(default=None, description="PAN-OS virtual router this interface is assigned to")

    class Config:
        """Pydantic model configuration."""
        use_enum_values = True
