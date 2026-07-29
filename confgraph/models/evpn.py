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
    """Per-L3VNI (routing / tenant-VRF VNI) binding under the top-level ``evpn`` block.

    Models the L3VNI counterpart of :class:`EVPNL2VNI`::

        evpn
          vni <n> l3
            rd { auto | <rd> }
            route-target import { auto | <rt> }
            route-target export { auto | <rt> }

    The ``l3`` keyword (vs ``l2``) is the only structural discriminator: the
    ``rd`` / ``route-target`` grammar and the ``route-target both``-expansion /
    literal-``auto`` conventions are identical to the L2VNI form, so this reuses
    the exact same field shapes.

    The canonical NX-OS L3VNI control-plane actually lives under
    ``vrf context <name>`` (``vni <n>`` declaration, ``rd``, and per-address-family
    ``route-target ... evpn``); ``NXOSParser.parse_evpn`` JOINS that with the
    ``evpn / vni <n> l3`` block (if any) and the NVE ``member vni <n>
    associate-vrf`` signal into ONE entry per VNI. ``vrf`` carries the tenant VRF
    from the ``vrf context`` declaration; ``associate_vrf`` records the NVE
    binding.

    DOC-GROUNDED CAVEAT (CCR-0118): unlike the L2VNI form (device-verified on
    n9kv 10.5(5), CCR-0087), the L3VNI's emitted ``rd`` / ``route-target`` block
    (both the ``evpn / vni l3`` and the ``vrf context`` shapes) was NOT captured
    on the 9000v. It is grounded in the Cisco Nexus 9000 VXLAN Config Guide
    10.5(x) + the L2VNI analogy, not a device readback — promotable to
    verified-capture once captured. Fields are therefore all optional so a bare
    ``vni <n> l3`` declaration (or a vrf-context-only L3VNI) also parses.
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
