"""PAN-OS XML configuration parser utilities.

Provides lightweight helpers for navigating PAN-OS running-config XML
without requiring lxml or CiscoConfParse.

Two document layouts exist and both are read (CCR-0034).  ``detect_layout``
below is the *single* place that knows which one a document is; every parse
method in ``panos_parser`` consumes the neutral :class:`PANOSLayout` view
(device scopes / vsys scopes / policy scopes) and never asks "am I Panorama?".
Adding a third layout is one new branch in ``detect_layout`` plus one builder
function — no change to any parse method.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from xml.etree import ElementTree
from xml.etree.ElementTree import Element


def parse_panos_xml(text: str) -> Element:
    """Parse PAN-OS XML config text and return the root <config> element."""
    # Strip XML namespace declarations that can confuse ElementTree
    text = re.sub(r'\s+xmlns[^=]*="[^"]*"', '', text)
    return ElementTree.fromstring(text)


def find_device(root: Element) -> Element | None:
    """Return the first <devices><entry> element (the local firewall)."""
    return root.find("./devices/entry")


def find_vsys(device: Element, vsys_name: str = "vsys1") -> Element | None:
    """Return the vsys <entry> matching vsys_name."""
    return device.find(f"./vsys/entry[@name='{vsys_name}']")


def find_all_vsys(device: Element) -> list[Element]:
    """Return all vsys <entry> elements."""
    return device.findall("./vsys/entry") or []


def entries(parent: Element | None, path: str) -> list[Element]:
    """Return all <entry> children at path relative to parent."""
    if parent is None:
        return []
    return parent.findall(f"{path}/entry") or []


def text_val(element: Element | None, path: str) -> str | None:
    """Return stripped text at path relative to element, or None."""
    if element is None:
        return None
    el = element.find(path)
    if el is not None and el.text:
        return el.text.strip()
    return None


def members(element: Element | None, path: str) -> list[str]:
    """Return all <member> text values at path relative to element."""
    if element is None:
        return []
    return [m.text.strip() for m in element.findall(f"{path}/member") if m.text]


def raw_xml(element: Element) -> str:
    """Return indented XML string for an element (used as raw_config)."""
    ElementTree.indent(element, space="  ")
    return ElementTree.tostring(element, encoding="unicode")


# ---------------------------------------------------------------------------
# Document layout — local firewall (vsys) vs Panorama (device-group + template)
# ---------------------------------------------------------------------------
#
# Element paths below are the ones a device/Panorama *emits* (verified against
# Palo Alto's own SDKs, which read exported configs: pango `util.util.go`
# DeviceGroupXpathPrefix + `poli/security/pano.go`, pan-os-python `panorama.py`
# / `policies.py`, pan-os-php `PanoramaConf.php` / `Template.php`; ordering per
# the Panorama 10.2 admin guide, "Device Group Policies").
#
#   local firewall :  /config/devices/entry/{deviceconfig,network,vsys/entry}
#   Panorama       :  /config/devices/entry/device-group/entry/{pre,post}-rulebase
#                     /config/devices/entry/template/entry/config/devices/entry/...
#                     /config/shared/{pre,post}-rulebase
#                     /config/readonly/devices/entry/device-group/entry/parent-dg
#
# Deliberately NOT read (unestablished emitted shape — do not guess):
#   * a bare <rulebase> under a *named* device-group: pango rejects it
#     (`ValidateRulebase`: rulebase requires the "shared" device group), and the
#     device-group entry schema carries only pre-/post-rulebase.
#   * /config/panorama/... (policy pushed *onto* a managed firewall) — only the
#     pre-rulebase path is documented; the rest of that subtree is not.
#   * template-stack (/config/devices/entry/template-stack/entry) — NOT read at
#     all, and therefore NOT a recognition marker: a stack's config is assembled
#     from its member templates by a priority no primary source states, so
#     resolving it would be a guess.  A template-stack-only document is an
#     *unrecognized* layout and raises — recognizing it and then reading nothing
#     out of it would rebuild the silent-empty model CCR-0034 exists to end.
#     (A normal Panorama export also carries <template> entries, so it is still
#     recognized; only the stack's own overrides are absent.)

LAYOUT_LOCAL = "local-vsys"
LAYOUT_PANORAMA = "panorama"

#: Panorama's top-level policy scope; also the implicit parent of a device-group
#: whose <parent-dg> is absent.
SHARED = "shared"


class UnrecognizedPANOSLayout(ValueError):
    """The document is not a PAN-OS layout this parser knows how to read.

    Raised instead of returning an empty model: "this firewall has no rules" and
    "this firewall's rules are somewhere we don't look" must not be the same
    answer (CCR-0034).
    """


@dataclass(frozen=True)
class DeviceScope:
    """An element owning one device's ``deviceconfig`` / ``network`` / ``vsys``.

    Local layout: the ``devices/entry`` itself.  Panorama: each template's
    inner ``config/devices/entry`` (a template wraps a whole firewall config).
    ``name`` is the template name under Panorama, the device entry name locally.
    """

    name: str
    element: Element


@dataclass(frozen=True)
class VsysScope:
    """A vsys ``entry`` — owns ``zone`` (and, locally, ``rulebase``)."""

    name: str
    element: Element


@dataclass(frozen=True)
class PolicyScope:
    """The rule containers that apply to one policy scope, in evaluation order.

    ``rulebases`` is an ordered tuple of rulebase-shaped elements (each having
    ``security/rules`` and/or ``nat/rules``): locally the vsys ``rulebase``;
    under Panorama the resolved chain

        shared pre → ancestor DG pre → … → own DG pre →
        own DG post → … → ancestor DG post → shared post

    which is the firewall's documented evaluation order with the local-rule slot
    (absent from a Panorama export) elided.
    """

    name: str
    rulebases: tuple[Element, ...]


@dataclass(frozen=True)
class PANOSLayout:
    """A layout-neutral view of a PAN-OS document."""

    kind: str
    devices: tuple[DeviceScope, ...]
    vsys: tuple[VsysScope, ...]
    policies: tuple[PolicyScope, ...]


#: A marker may only name an element some scope builder below actually *reads*.
#: Recognizing a document on an element nothing walks turns the ParseError off
#: and hands back an empty model — the very failure this module exists to end.
#: (`template-stack` is therefore absent: see the "NOT read" note above.)
_LOCAL_MARKERS = ("deviceconfig", "network", "vsys")
_PANORAMA_MARKERS = ("device-group", "template")


def detect_layout(root: Element) -> PANOSLayout:
    """Classify a PAN-OS document and return its layout-neutral view.

    Raises:
        UnrecognizedPANOSLayout: the document matches no known layout.
    """
    if root.tag != "config":
        raise UnrecognizedPANOSLayout(
            f"expected a PAN-OS <config> document root, got <{root.tag}>"
        )

    device_entries = root.findall("./devices/entry")

    panorama_owners = [
        e for e in device_entries
        if any(e.find(m) is not None for m in _PANORAMA_MARKERS)
    ]
    if panorama_owners:
        return _panorama_layout(root, panorama_owners)

    local_entries = [
        e for e in device_entries
        if any(e.find(m) is not None for m in _LOCAL_MARKERS)
    ]
    if local_entries:
        return _local_layout(local_entries)

    raise UnrecognizedPANOSLayout(
        "no PAN-OS layout recognized: expected a local firewall config "
        "(devices/entry with deviceconfig|network|vsys) or a Panorama config "
        "(devices/entry with device-group|template); "
        f"found {len(device_entries)} devices/entry with neither "
        "(note: template-stack alone is not readable — its config is assembled "
        "from member templates by an unstated priority, so it is not supported)"
    )


def _local_layout(device_entries: list[Element]) -> PANOSLayout:
    devices = tuple(DeviceScope(e.get("name", ""), e) for e in device_entries)
    vsys: list[VsysScope] = []
    policies: list[PolicyScope] = []
    for dev in devices:
        for vs in find_all_vsys(dev.element):
            name = vs.get("name", "vsys1")
            vsys.append(VsysScope(name, vs))
            rulebase = vs.find("rulebase")
            if rulebase is not None:
                policies.append(PolicyScope(name, (rulebase,)))
    return PANOSLayout(
        kind=LAYOUT_LOCAL,
        devices=devices,
        vsys=tuple(vsys),
        policies=tuple(policies),
    )


def _panorama_layout(root: Element, owners: list[Element]) -> PANOSLayout:
    devices: list[DeviceScope] = []
    vsys: list[VsysScope] = []
    for owner in owners:
        for tmpl in owner.findall("./template/entry"):
            tmpl_name = tmpl.get("name", "")
            # A template wraps a complete firewall <config> document.
            for dev_el in tmpl.findall("./config/devices/entry"):
                devices.append(DeviceScope(tmpl_name, dev_el))
                for vs in find_all_vsys(dev_el):
                    vsys.append(VsysScope(vs.get("name", "vsys1"), vs))
    return PANOSLayout(
        kind=LAYOUT_PANORAMA,
        devices=tuple(devices),
        vsys=tuple(vsys),
        policies=_panorama_policies(root, owners),
    )


def _panorama_policies(root: Element, owners: list[Element]) -> tuple[PolicyScope, ...]:
    """Resolve each device-group's effective rulebase chain, in evaluation order."""
    device_groups: dict[str, Element] = {}
    for owner in owners:
        for dg in owner.findall("./device-group/entry"):
            name = dg.get("name", "")
            if name:
                device_groups.setdefault(name, dg)

    parents = _device_group_parents(root)
    shared_pre = root.find("./shared/pre-rulebase")
    shared_post = root.find("./shared/post-rulebase")

    scopes: list[PolicyScope] = []
    for name, dg in device_groups.items():
        chain = _device_group_chain(name, parents, device_groups)
        ordered = (
            [shared_pre]
            + [d.find("pre-rulebase") for d in chain]
            + [d.find("post-rulebase") for d in reversed(chain)]
            + [shared_post]
        )
        rulebases = tuple(el for el in ordered if el is not None)
        if rulebases:
            scopes.append(PolicyScope(name, rulebases))

    if not scopes:
        # Shared-only Panorama (no device-groups) still carries policy.
        rulebases = tuple(el for el in (shared_pre, shared_post) if el is not None)
        if rulebases:
            scopes.append(PolicyScope(SHARED, rulebases))

    return tuple(scopes)


def _device_group_parents(root: Element) -> dict[str, str]:
    """device-group name → parent name, from the emitted ``readonly`` meta tree.

    PAN-OS 8.0+ records the device-group hierarchy at
    ``/config/readonly/devices/entry/device-group/entry/parent-dg`` — not inside
    the device-group's own subtree.  A device-group with no ``parent-dg`` hangs
    off ``shared``.
    """
    parents: dict[str, str] = {}
    for entry in root.findall("./readonly/devices/entry/device-group/entry"):
        name = entry.get("name", "")
        if name:
            parents[name] = text_val(entry, "parent-dg") or SHARED
    return parents


def _device_group_chain(
    name: str,
    parents: dict[str, str],
    device_groups: dict[str, Element],
) -> list[Element]:
    """Ancestors highest-level-first, ending with the device-group itself."""
    chain: list[Element] = []
    seen: set[str] = set()
    current: str | None = name
    while current and current != SHARED and current not in seen:
        seen.add(current)
        dg = device_groups.get(current)
        if dg is None:  # parent named but not present in this document
            break
        chain.append(dg)
        current = parents.get(current)
    chain.reverse()
    return chain
