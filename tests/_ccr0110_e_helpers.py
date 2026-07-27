"""CCR-0110 Phase E — shared test helpers for the tombstone-emission migration.

Op-primary parsers (IOS/NX-OS/EOS) no longer populate ``no_commands`` /
``interface_no_commands`` / ``bgp_no_commands``: every deletion is carried by a
native ``ChangeOp`` and the legacy string vocabulary is *reconstructed* from the
composed ChangeSet by :func:`confgraph.change_ir.encode_legacy_shim` — the
golden-pinned inverse codec (byte-exact vs the frozen goldens in
``test_change_ir_shim_phase4``, including the ``_readded_later`` service-entity
suppression).

The family / parity suites use these helpers to assert that reconstructed
vocabulary (arm A of the migration) while their op-emission assertions keep
reading ``native_change_ops`` / ``derive_ops`` directly (arm B).  None of the
readers mutate the parsed config, so op assertions on the same object stay clean.
"""

from __future__ import annotations

import re

from confgraph.change_ir import derive_ops, encode_legacy_shim


def legacy_artifacts(pc):
    """The legacy ``LegacyArtifacts`` reconstructed from *pc*'s composed
    ChangeSet via the golden-pinned shim codec."""
    return encode_legacy_shim(derive_ops(pc))


def iface_nc(pc, name):
    """Reconstructed ``interface_no_commands`` for interface *name* ([] if none)."""
    return legacy_artifacts(pc).interface_no_commands.get(name, [])


def bgp_nc(pc, asn, vrf=""):
    """Reconstructed ``bgp_no_commands`` for the ``(asn, vrf)`` instance."""
    return legacy_artifacts(pc).bgp_no_commands.get((str(asn), vrf), [])


def reconstruct_tombstones(pc):
    """Repopulate *pc*'s deprecated string containers from its composed
    ChangeSet, so the natives-less ``derive_ops`` fallback path — which
    op-primary parsers no longer feed, but a JunOS/pre-Phase-3 parse would — can
    be exercised.  Call BEFORE nulling ``native_change_ops``."""
    art = legacy_artifacts(pc)
    pc.no_commands = list(art.no_commands)
    for iface in pc.interfaces:
        iface.no_commands = art.interface_no_commands.get(iface.name, [])
    for bgp in pc.bgp_instances:
        bgp.no_commands = art.bgp_no_commands.get((str(bgp.asn), bgp.vrf or ""), [])
    return pc


# ---------------------------------------------------------------------------
# Hoisted-multiset predicate (moved here from test_change_ir; the shim suite is
# its only remaining consumer).  Tombstones whose emitting family became native
# in Phase 3 are hoisted to the front of the composed ChangeSet and compared as
# an order-inert multiset; everything else is compared order-exact.
# ---------------------------------------------------------------------------

_FAMILY3_TOMBSTONE_PREFIXES = (
    "field:ip_sla_operations:",
    "field:object_tracks:",
    "field:eem_applets:",
    "field:banners:",
)

# WI-DB2 (CCR Appendix AD): the four OSPF withdrawal-twin shapes + the EIGRP
# redistribute twin — vrf-scoped (segment 3 is the vrf, "" for global), which
# keeps them disjoint from the derived VRF-blind stub/nssa area resets.
_DB2_IGP_TWIN_RE = re.compile(
    r"^field:(?:"
    r"(?:ospf|eigrp):[^:]+:[^:]*:redistribute:"
    r"|ospf:[^:]+:[^:]*:default_information_originate$"
    r"|ospf:[^:]+:[^:]*:area:[^:]+:virtual_link:"
    r"|ospf:[^:]+:[^:]*:area:[^:]+:filter_list_(?:in|out)$"
    r")"
)


def _is_reordered_native_tombstone(t: str) -> bool:
    """Tombstones whose emitting family is native since Phase 3 and therefore
    hoisted to the front of the composed ChangeSet (multiset, not sequence).

    Family 3 (service entities) + family 4 (``static:`` route removals) + family
    6a/6b/6c (whole-process removals) + family 7a (``field:vrfs:`` RT/rd removals
    and whole-VRF deletes) + families 8a/8b/8c (singleton entry removals /
    scalar resets / null-outs, ``field:lldp:tlv:`` TLV removals, ``vlan:``
    deletes) — each encodes byte-exactly but no longer at its legacy walk-group
    position in ``no_commands``.  Non-weakening: order among these and other
    families is semantically inert — each dispatches to an independent handler
    over disjoint fields.  (``process:bgp:`` stays derived until 5a-retirement;
    the IOS-XR ``singleton:ntp`` / ``singleton:dns`` stay DERIVED and keep their
    exact sequence position; the IOS-XR DERIVED ``singleton:multicast`` shares
    its string with the now-native IOS one, so it joins the order-exempt
    multiset.)
    """
    return (
        t.startswith(_FAMILY3_TOMBSTONE_PREFIXES)
        or t.startswith("static:")
        or t.startswith("process:isis:")
        or t.startswith("process:eigrp:")
        or t.startswith("process:ospf:")
        or t.startswith("field:vrfs:")
        or t.startswith(
            ("field:ntp:", "field:snmp:", "field:syslog:", "field:dns:", "field:aaa:")
        )
        or t.startswith(
            (
                "field:dhcp:",
                "field:netflow:",
                "field:multicast:",
                "field:bfd:",
                "field:vxlan:",
                "field:vpc:",
                "field:mpls:",
            )
        )
        or t.startswith(("field:lldp:", "vlan:"))
        or _DB2_IGP_TWIN_RE.match(t) is not None
        or t.startswith(("field:interface:", "interface:"))
        or t in ("singleton:snmp", "singleton:aaa", "singleton:netflow", "singleton:multicast")
    )
