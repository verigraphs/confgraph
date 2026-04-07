"""Network configuration data models."""

from confgraph.models.base import BaseConfigObject, OSType
from confgraph.models.vrf import VRFConfig
from confgraph.models.interface import (
    InterfaceConfig,
    InterfaceType,
    HSRPGroup,
    VRRPGroup,
)
from confgraph.models.bgp import (
    BGPConfig,
    BGPNeighbor,
    BGPPeerGroup,
    BGPAddressFamily,
    BGPNeighborAF,
    BGPNetwork,
    BGPRedistribute,
    BGPAggregate,
    BGPBestpathOptions,
    BGPTimers,
)
from confgraph.models.ospf import (
    OSPFConfig,
    OSPFArea,
    OSPFInterfaceConfig,
    OSPFAreaType,
    OSPFRange,
    OSPFRedistribute,
    OSPFMDKey,
)
from confgraph.models.route_map import (
    RouteMapConfig,
    RouteMapSequence,
    RouteMapMatch,
    RouteMapSet,
)
from confgraph.models.prefix_list import (
    PrefixListConfig,
    PrefixListEntry,
)
from confgraph.models.parsed_config import ParsedConfig

__all__ = [
    "BaseConfigObject",
    "OSType",
    "VRFConfig",
    "InterfaceConfig",
    "InterfaceType",
    "HSRPGroup",
    "VRRPGroup",
    "BGPConfig",
    "BGPNeighbor",
    "BGPPeerGroup",
    "BGPAddressFamily",
    "BGPNeighborAF",
    "BGPNetwork",
    "BGPRedistribute",
    "BGPAggregate",
    "BGPBestpathOptions",
    "BGPTimers",
    "OSPFConfig",
    "OSPFArea",
    "OSPFInterfaceConfig",
    "OSPFAreaType",
    "OSPFRange",
    "OSPFRedistribute",
    "OSPFMDKey",
    "RouteMapConfig",
    "RouteMapSequence",
    "RouteMapMatch",
    "RouteMapSet",
    "PrefixListConfig",
    "PrefixListEntry",
    "ParsedConfig",
]
