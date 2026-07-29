"""EVPN (MP-BGP EVPN) control-plane configuration models.

Distinct from the VXLAN data-plane (VTEP / VNI mappings in
``confgraph.models.vxlan``): this models the top-level ``evpn`` block that
binds an L2VNI (MAC-VRF) and an L3VNI (routing / tenant-VRF VNI) to their route
distinguishers and route-targets — the control-plane that stitches VNIs across a
VXLAN-EVPN fabric.
"""

from pydantic import BaseModel, Field
from confgraph.models.base import BaseConfigObject


class EVPNL2VNI(BaseModel):
    """Per-L2VNI MAC-VRF binding under the top-level ``evpn`` block.

    Models::

        evpn
          vni <n> l2
            rd { auto | <rd> }
            route-target import { auto | <rt> }
            route-target export { auto | <rt> }

    Device-emitted notes (n9kv 10.5(5), CCR-0087):
    - ``route-target both <rt>`` is a typed convenience that renders as
      separate ``import`` and ``export`` lines, so it populates BOTH lists.
    - ``auto`` DOES nvgen; it is kept as the literal ``'auto'`` token rather
      than resolved or dropped. An operator override emits the literal
      ``<rd>`` / ``<rt>`` value instead.
    """

    vni: int = Field(..., description="L2 VXLAN Network Identifier (MAC-VRF)")
    rd: str | None = Field(
        default=None,
        description="Route distinguisher: 'auto' or an explicit value (ASN2:NN, ASN4:NN, IPV4:NN)",
    )
    route_target_import: list[str] = Field(
        default_factory=list,
        description="Import route-targets ('auto' or explicit); 'route-target both' also populates this list",
    )
    route_target_export: list[str] = Field(
        default_factory=list,
        description="Export route-targets ('auto' or explicit); 'route-target both' also populates this list",
    )


class EVPNL3VNI(BaseModel):
    """Per-L3VNI (routing / tenant-VRF VNI) EVPN control-plane binding.

    The NX-OS L3VNI control-plane lives under ``vrf context`` (NOT under the
    top-level ``evpn`` block, which carries L2VNIs only)::

        vrf context <name>
          vni <n>                                # traditional; new mode: `vni <n> L3`
          rd { auto | <rd> }
          address-family ipv4 unicast
            route-target { both | import | export } { auto | <rt> } evpn
          address-family ipv6 unicast
            route-target { both | import | export } { auto | <rt> } evpn

    ``NXOSParser.parse_evpn`` JOINS this ``vrf context`` declaration with the NVE
    ``member vni <n> associate-vrf`` signal into ONE entry per VNI. ``vrf`` carries
    the tenant VRF from the ``vrf context`` declaration; ``rd`` and the
    ``evpn``-suffixed route-targets are its EVPN RD/RTs (``route-target both`` →
    both lists, literal ``auto`` preserved); ``associate_vrf`` records the NVE
    binding. Field shapes mirror :class:`EVPNL2VNI`.

    DOC-GROUNDED CAVEAT (CCR-0118): unlike the L2VNI form (device-verified on
    n9kv 10.5(5), CCR-0087), the L3VNI's ``vrf context`` emitted ``rd`` /
    ``route-target ... evpn`` block was NOT captured on the 9000v. It is grounded
    in the Cisco Nexus 9000 VXLAN Config Guide 10.5(x), not a device readback —
    promotable to verified-capture once captured. Fields are all optional so a
    partial (e.g. vni-only) declaration still parses.
    """

    vni: int = Field(..., description="L3 VXLAN Network Identifier (routing / tenant-VRF VNI)")
    rd: str | None = Field(
        default=None,
        description="Route distinguisher: 'auto' or an explicit value (ASN2:NN, ASN4:NN, IPV4:NN)",
    )
    route_target_import: list[str] = Field(
        default_factory=list,
        description="Import route-targets ('auto' or explicit); 'route-target both' also populates this list",
    )
    route_target_export: list[str] = Field(
        default_factory=list,
        description="Export route-targets ('auto' or explicit); 'route-target both' also populates this list",
    )
    vrf: str | None = Field(
        default=None,
        description="Associated tenant VRF (from the `vrf context <name> / vni <n>` L3VNI declaration)",
    )
    associate_vrf: bool = Field(
        default=False,
        description="True when the NVE binds this L3VNI to the fabric via `member vni <n> associate-vrf`",
    )


class EVPNConfig(BaseConfigObject):
    """Top-level ``evpn`` MP-BGP EVPN control-plane block (singleton per device)."""

    l2vnis: list[EVPNL2VNI] = Field(
        default_factory=list,
        description="Per-VNI L2VNI (MAC-VRF) RD / route-target bindings",
    )
    l3vnis: list[EVPNL3VNI] = Field(
        default_factory=list,
        description="Per-VNI L3VNI (routing / tenant-VRF VNI) RD / route-target bindings",
    )
