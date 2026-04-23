"""PAN-OS XML configuration parser utilities.

Provides lightweight helpers for navigating PAN-OS running-config XML
without requiring lxml or CiscoConfParse.
"""

from __future__ import annotations

import re
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
