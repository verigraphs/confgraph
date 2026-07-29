"""CCR-0089 — NX-OS CoPP: typed class-map/policy-map name + control-plane binding.

Two defects, one shared root cause plus one NX-OS modeling gap:

1. `class-map type <X> ... <NAME>` and `policy-map type <X> <NAME>` were parsed
   with the qualifier token `type` mis-read as the map NAME (yielding
   `class_maps == [('type', None)]`). The shared IOS-family `parse_class_maps` /
   `parse_policy_maps` (ios_parser.py) now skip an optional `type <qualifier>`,
   capture the real NAME, and carry the qualifier on
   `ClassMapConfig.type` / `PolicyMapConfig.type`. This is the same defect the
   corpus records for `type qos` (CCR-0064), fixed generically for any qualifier.

2. The `control-plane` block with `service-policy input <PM>` was unmodeled —
   `ParsedConfig` had no place for the binding that ATTACHES the CoPP policy.
   A new `ControlPlaneConfig` (models/qos.py) is populated by the NX-OS
   `parse_control_plane` override.

Because the type-token fix lives in the shared IOS-family code that IOS / EOS /
IOS-XR inherit, `test_ios_plain_class_map_policy_map_unchanged` is the
make-or-break regression guard: the common untyped form must keep parsing the
NAME exactly as before, with `type is None`.

Fixture lines are device-emitted, corpus-backed:
  - `class-map type control-plane` / `policy-map type control-plane` /
    `control-plane` / `service-policy input` — syntax-corpus/nxos/copp.yaml
    (verified-capture, n9kv 10.5(5)).
  - `class-map type qos match-all <NAME>` — syntax-corpus/nxos/qos.yaml
    (verified-capture; the emitted form always carries the match-{all|any} token).
  - plain `class-map match-any <NAME>` / `policy-map <NAME>` — the committed
    IOS coverage fixture (_work/ios_full.cfg).
"""
from confgraph.parsers.nxos_parser import NXOSParser
from confgraph.parsers.ios_parser import IOSParser


# Device-emitted CoPP config (n9kv 10.5(5)), verbatim from the CCR repro.
NXOS_COPP = """class-map type control-plane match-any CM_COPP
  match access-group name COPP_ACL
policy-map type control-plane PM_COPP
  class CM_COPP
    police cir 50 pps bc 16 packets conform transmit violate drop
control-plane
  service-policy input PM_COPP
"""


def test_class_map_type_control_plane_name_and_type():
    """(a) NAME is CM_COPP (not 'type'); qualifier carried on .type."""
    p = NXOSParser(NXOS_COPP).parse()
    cm = next(c for c in p.class_maps if c.name == "CM_COPP")
    assert cm.name == "CM_COPP"
    assert cm.type == "control-plane"
    assert cm.match_type == "match-any"
    # the pre-fix bug: the map would have been named the literal token 'type'
    assert not any(c.name == "type" for c in p.class_maps)


def test_policy_map_type_control_plane_name_and_type():
    """(b) NAME is PM_COPP (not 'type'); qualifier carried on .type."""
    p = NXOSParser(NXOS_COPP).parse()
    pm = next(m for m in p.policy_maps if m.name == "PM_COPP")
    assert pm.name == "PM_COPP"
    assert pm.type == "control-plane"
    assert not any(m.name == "type" for m in p.policy_maps)


def test_control_plane_binding_modeled():
    """(c) control-plane / service-policy input PM_COPP is recoverable."""
    p = NXOSParser(NXOS_COPP).parse()
    assert p.control_plane is not None
    assert p.control_plane.service_policy_input == "PM_COPP"


def test_class_map_type_qos_name():
    """(e) CCR-0064 case handled generically: type qos NAME captured."""
    cfg = "class-map type qos match-all QOS-CLASS\n  match dscp 46\n"
    p = NXOSParser(cfg).parse()
    cm = next(c for c in p.class_maps if c.name == "QOS-CLASS")
    assert cm.name == "QOS-CLASS"
    assert cm.type == "qos"
    assert cm.match_type == "match-all"


# --- REGRESSION GUARD (make-or-break): plain untyped IOS form is unchanged ----

IOS_PLAIN_QOS = """class-map match-any FOO
  match dscp ef
policy-map BAR
  class FOO
    priority percent 20
"""


def test_ios_plain_class_map_policy_map_unchanged():
    """(d) The common untyped form still captures the NAME exactly, type is None.

    This is the shared-code regression guard: IOS / EOS / IOS-XR inherit the
    same parse_class_maps / parse_policy_maps.
    """
    p = IOSParser(IOS_PLAIN_QOS).parse()

    cm = next(c for c in p.class_maps if c.name == "FOO")
    assert cm.name == "FOO"
    assert cm.type is None
    assert cm.match_type == "match-any"

    pm = next(m for m in p.policy_maps if m.name == "BAR")
    assert pm.name == "BAR"
    assert pm.type is None

    # An untyped IOS config never grows a control-plane binding.
    assert p.control_plane is None


def test_nxos_plain_untyped_maps_still_work():
    """Untyped maps on NX-OS (no `type`) keep parsing the NAME, type is None."""
    cfg = "class-map match-all PLAIN_CM\n  match dscp 10\npolicy-map PLAIN_PM\n  class PLAIN_CM\n"
    p = NXOSParser(cfg).parse()
    assert next(c for c in p.class_maps if c.name == "PLAIN_CM").type is None
    assert next(m for m in p.policy_maps if m.name == "PLAIN_PM").type is None
