"""Physical topology models.

Represents the physical underlay — which device ports are cabled together —
independently of any logical (BGP/IGP) configuration.  This separation allows
the simulator to detect mis-peerings and correctly model shared-VLAN fabrics
where subnet-based inference would produce false adjacencies.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class PhysicalLink:
    """A single physical (or LAG-resolved logical) link between two devices.

    After LAG resolution, *port_a* and *port_b* always refer to the logical
    interface (e.g. Port-channel1) rather than a member port (e.g.
    GigabitEthernet0/1).  For non-LAG links, they are the physical interface
    name in canonical long form.

    *member_count* is 1 for non-LAG links and N for LAG links where N member
    ports were observed in the discovery data.  This is informational only —
    used for graph edge labelling (e.g. "Po1 ↔ Po1 (×8)").

    *source* records where the adjacency was learned:
      "cdp"             — from CDP neighbor data
      "lldp"            — from LLDP neighbor data
      "mac-arp"         — validated via MAC-ARP correlation (supplementary only)
    """

    device_a: str
    port_a: str           # canonical long-form logical interface on device_a
    device_b: str
    port_b: str           # canonical long-form logical interface on device_b
    source: str           # "cdp" | "lldp" | "mac-arp"
    member_count: int = 1


# A physical topology is simply an ordered list of links.
# Two devices may have multiple links between them (parallel paths or separate
# LAGs); each is a separate PhysicalLink entry.
PhysicalTopology = list[PhysicalLink]
