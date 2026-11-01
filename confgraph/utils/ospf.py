"""OSPF value normalization shared by the models and every consumer.

CCR-0227: an OSPF area ID is a 32-bit number that vendors print two ways.
NX-OS and JunOS spell the backbone ``0.0.0.0``; IOS and IOS-XR spell it ``0``.
On hardware they are the same area and the adjacency forms. Stored as raw
strings they are two different keys, so the model partitions one real area in
two across a mixed-vendor estate: the adjacency gate refuses the neighbor,
and every area-KEYED structure (ABR detection, inter-area filtering) computes
against half the area.

Canonical form is the DECIMAL spelling — chosen over dotted-quad because it
leaves existing tombstone and golden keys (``ospf:1:area:0:stub_reset``)
byte-identical.
"""

import re

# Exactly four dotted octets. [0-9] not \d — \d is Unicode-aware, and a
# Devanagari digit is not an area ID.
_DOTTED_QUAD = re.compile(r"^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$")


def canonical_area_id(value):
    """Return *value*'s canonical OSPF area ID — the single normalizer.

    ``"0.0.0.0"`` -> ``"0"``; any dotted quad -> the decimal spelling of its
    32-bit value (``"0.0.0.51"`` -> ``"51"``). Everything else — decimal
    strings, None, non-strings — passes through UNCHANGED: this normalizes a
    spelling, it never rejects or invents one. Deliberately not a parser of
    out-of-range quads either (``"0.0.0.999"`` is not an area ID in any
    spelling, so it passes through for the caller to see as written).
    """
    if not isinstance(value, str):
        return value
    match = _DOTTED_QUAD.match(value.strip())
    if match is None:
        return value
    octets = [int(group) for group in match.groups()]
    if any(octet > 255 for octet in octets):
        return value
    return str(
        (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
    )


def canonical_process_id(value):
    """Return *value*'s canonical OSPF process identity — digit or verbatim.

    An OSPF process identifier is a NUMBER on IOS/IOS-XE and a WORD — an
    "instance tag" — on NX-OS, IOS-XR and EOS (``router ospf UNDERLAY``), so
    both the process and the interface model it as ``int | str``. Every
    producer must therefore agree on WHICH spelling it stores, because the
    consumers decide membership by EQUALITY: the parser's own passive-default
    walk (``BaseParser.parse``) and the engine's ``_ospf_member`` both ask
    ``ospf.process_id == iface.ospf_process_id``. A producer storing ``"1"``
    where another stores ``1`` partitions one process in two exactly as the
    area-id drift above did (CCR-0239).

    The rule: a digit string becomes its ``int``, anything else — a tag,
    ``None``, a non-string — is returned unchanged. This normalizes a
    spelling; it never rejects or invents one.

    Deliberately ``str.isdigit()`` and not ``[0-9]``, unlike
    :func:`canonical_area_id` above: this mirrors the existing producers
    byte-for-byte so the helper can never disagree with one. Those producers
    still carry the rule inline (``ios_parser.parse_ospf``,
    ``EOSParser.parse_ospf``, ``IOSXRParser.parse_ospf``); migrating them onto
    this helper edits the shared IOS base class and is a follow-up, not part
    of CCR-0239.
    """
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return value
