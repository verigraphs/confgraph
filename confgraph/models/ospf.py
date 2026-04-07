"""OSPF configuration models."""

from enum import Enum
from ipaddress import IPv4Address, IPv4Network
from pydantic import BaseModel, Field
from confgraph.models.base import BaseConfigObject


class OSPFAreaType(str, Enum):
    """OSPF area types."""

    NORMAL = "normal"
    STUB = "stub"
    NSSA = "nssa"
    TOTALLY_STUB = "totally_stub"
    TOTALLY_NSSA = "totally_nssa"


class OSPFMDKey(BaseModel):
    """OSPF message-digest authentication key."""

    key_id: int = Field(..., description="Key ID (1-255)")
    key_string: str = Field(..., description="MD5 key string")
    encryption_type: int | None = Field(
        default=None, description="Encryption type (0=clear, 7=encrypted)"
    )


class OSPFRange(BaseModel):
    """OSPF area range configuration."""

    prefix: IPv4Network = Field(..., description="Summary prefix")
    advertise: bool = Field(
        default=True, description="Advertise this range (False = not-advertise)"
    )
    cost: int | None = Field(default=None, description="Cost for this range")


class OSPFRedistribute(BaseModel):
    """OSPF redistribution configuration."""

    protocol: str = Field(
        ...,
        description="Protocol to redistribute (e.g., 'bgp', 'connected', 'static')",
    )
    process_id: int | str | None = Field(
        default=None, description="Process ID for BGP or other OSPF process"
    )
    route_map: str | None = Field(
        default=None, description="Route-map to apply (references RouteMapConfig)"
    )
    metric: int | None = Field(default=None, description="Metric value")
    metric_type: int | None = Field(
        default=None, description="Metric type (1=E1, 2=E2)"
    )
    subnets: bool = Field(
        default=False, description="Include subnets in redistribution"
    )
    tag: int | None = Field(default=None, description="Tag value")


class OSPFArea(BaseModel):
    """OSPF area configuration."""

    area_id: str = Field(
        ..., description="Area ID (e.g., '0', '0.0.0.1', '10')"
    )
    area_type: OSPFAreaType = Field(
        default=OSPFAreaType.NORMAL, description="Area type"
    )
    stub_no_summary: bool = Field(
        default=False, description="Stub area with no summary LSAs"
    )
    nssa_no_summary: bool = Field(
        default=False, description="NSSA area with no summary LSAs"
    )
    nssa_default_information_originate: bool = Field(
        default=False, description="Originate default route in NSSA"
    )
    nssa_translate: str | None = Field(
        default=None, description="NSSA translation option ('always', 'candidate')"
    )
    default_cost: int | None = Field(
        default=None, description="Default cost for stub/NSSA areas"
    )
    authentication: str | None = Field(
        default=None, description="Area authentication type ('message-digest', 'null')"
    )
    ranges: list[OSPFRange] = Field(
        default_factory=list, description="Area range configurations"
    )
    interfaces: list[str] = Field(
        default_factory=list,
        description="Interface names in this area (references InterfaceConfig)",
    )
    virtual_links: list[str] = Field(
        default_factory=list, description="Virtual link configurations"
    )

    class Config:
        """Pydantic model configuration."""
        use_enum_values = True


class OSPFInterfaceConfig(BaseModel):
    """OSPF interface-level configuration.

    This is embedded within InterfaceConfig but also defined here
    for reference and potential standalone use.
    """

    process_id: int | str = Field(..., description="OSPF process ID")
    area_id: str = Field(..., description="OSPF area ID")
    cost: int | None = Field(default=None, description="Interface cost override")
    priority: int | None = Field(
        default=None, description="Router priority for DR/BDR election"
    )
    hello_interval: int | None = Field(
        default=None, description="Hello interval (seconds)"
    )
    dead_interval: int | None = Field(
        default=None, description="Dead interval (seconds)"
    )
    retransmit_interval: int | None = Field(
        default=None, description="Retransmit interval (seconds)"
    )
    transmit_delay: int | None = Field(
        default=None, description="Transmit delay (seconds)"
    )
    network_type: str | None = Field(
        default=None,
        description="Network type ('point-to-point', 'broadcast', 'non-broadcast', 'point-to-multipoint')",
    )
    passive: bool = Field(default=False, description="Passive interface")
    authentication: str | None = Field(
        default=None, description="Authentication type ('message-digest', 'null')"
    )
    authentication_key: str | None = Field(
        default=None, description="Authentication key (plain or simple)"
    )
    message_digest_keys: list[OSPFMDKey] = Field(
        default_factory=list, description="Message-digest keys"
    )
    mtu_ignore: bool = Field(
        default=False, description="Ignore MTU mismatch in DBD packets"
    )
    bfd: bool = Field(default=False, description="BFD enabled on this interface")


class OSPFConfig(BaseConfigObject):
    """OSPF (Open Shortest Path First) configuration.

    Covers OSPF process configuration including areas, redistribution,
    and global settings.
    """

    process_id: int | str = Field(
        ...,
        description="OSPF process ID (int for IOS, can be string for IOS-XR/NX-OS)",
    )
    vrf: str | None = Field(
        default=None,
        description="VRF context (None = global, otherwise references VRFConfig)",
    )
    router_id: IPv4Address | None = Field(
        default=None, description="OSPF router ID"
    )
    log_adjacency_changes: bool = Field(
        default=True, description="Log adjacency state changes"
    )
    log_adjacency_changes_detail: bool = Field(
        default=False, description="Log adjacency state changes with detail"
    )
    auto_cost_reference_bandwidth: int | None = Field(
        default=None,
        description="Reference bandwidth for cost calculation (Mbps)",
    )
    passive_interface_default: bool = Field(
        default=False, description="Set all interfaces as passive by default"
    )
    passive_interfaces: list[str] = Field(
        default_factory=list,
        description="Explicitly passive interfaces (references InterfaceConfig names)",
    )
    non_passive_interfaces: list[str] = Field(
        default_factory=list,
        description="Non-passive interfaces (when passive-interface default is set)",
    )
    areas: list[OSPFArea] = Field(
        default_factory=list, description="OSPF area configurations"
    )
    redistribute: list[OSPFRedistribute] = Field(
        default_factory=list, description="Redistribution configurations"
    )
    default_information_originate: bool = Field(
        default=False, description="Originate default route"
    )
    default_information_originate_always: bool = Field(
        default=False,
        description="Always advertise default route (even if not in routing table)",
    )
    default_information_originate_metric: int | None = Field(
        default=None, description="Metric for default route"
    )
    default_information_originate_metric_type: int | None = Field(
        default=None, description="Metric type for default route (1=E1, 2=E2)"
    )
    default_information_originate_route_map: str | None = Field(
        default=None,
        description="Route-map for default-originate (references RouteMapConfig)",
    )
    default_metric: int | None = Field(
        default=None, description="Default metric for redistributed routes"
    )
    distance: int | None = Field(
        default=None, description="Administrative distance for OSPF routes"
    )
    distance_intra_area: int | None = Field(
        default=None, description="Distance for intra-area routes"
    )
    distance_inter_area: int | None = Field(
        default=None, description="Distance for inter-area routes"
    )
    distance_external: int | None = Field(
        default=None, description="Distance for external routes"
    )
    max_lsa: int | None = Field(
        default=None, description="Maximum number of LSAs"
    )
    max_metric_router_lsa: bool = Field(
        default=False, description="Advertise maximum metric in router LSA"
    )
    max_metric_router_lsa_on_startup: int | None = Field(
        default=None,
        description="Advertise max metric on startup (seconds)",
    )
    timers_throttle_spf_initial: int | None = Field(
        default=None, description="SPF throttle initial delay (milliseconds)"
    )
    timers_throttle_spf_min: int | None = Field(
        default=None, description="SPF throttle minimum hold time (milliseconds)"
    )
    timers_throttle_spf_max: int | None = Field(
        default=None, description="SPF throttle maximum wait time (milliseconds)"
    )
    timers_throttle_lsa_all: int | None = Field(
        default=None, description="LSA throttle for all LSA types (milliseconds)"
    )
    network_statements: list[tuple[IPv4Network, str]] = Field(
        default_factory=list,
        description="Network statements (network, wildcard, area) - IOS style",
    )
    shutdown: bool = Field(
        default=False, description="OSPF process shutdown"
    )
    graceful_restart: bool = Field(
        default=False, description="Graceful restart enabled"
    )
    graceful_restart_helper: bool = Field(
        default=False, description="Graceful restart helper mode"
    )
    bfd_all_interfaces: bool = Field(
        default=False, description="BFD enabled on all OSPF interfaces"
    )

    class Config:
        """Pydantic model configuration."""
        use_enum_values = True
