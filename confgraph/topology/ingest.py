"""Physical topology ingest — CDP, LLDP, and MAC-ARP CSV parsers.

Reads discovery data from CSV files and produces a normalized
``PhysicalTopology`` (list of ``PhysicalLink``).

Processing pipeline
-------------------
1. Parse CSV rows into raw adjacency records.
2. Normalize device hostnames (strip domain suffixes, match against inventory).
3. Normalize interface names to canonical long form via
   ``confgraph.utils.interface.normalize_interface_name``.
4. Resolve LAG member ports to their parent Port-channel using the parsed
   device configs (``channel_group`` field on ``InterfaceConfig``).
5. De-duplicate: collapse multiple rows for the same logical link
   (e.g. all 8 member ports of a LAG) into a single ``PhysicalLink``
   with ``member_count`` set accordingly.

MAC-ARP role
------------
MAC-ARP data is NOT used for adjacency inference (too noisy on shared VLANs).
``load_mac_arp()`` is provided for future use as a supplementary validation
layer — callers can use it to confirm IP→MAC→port mappings when CDP/LLDP data
is ambiguous.

CSV column names are case-insensitive and leading/trailing whitespace is
stripped from all values.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from confgraph.models.topology import PhysicalLink, PhysicalTopology
from confgraph.utils.interface import normalize_interface_name

if TYPE_CHECKING:
    from confgraph.models.parsed_config import ParsedConfig


# ---------------------------------------------------------------------------
# Hostname normalization
# ---------------------------------------------------------------------------

def _normalize_hostname(raw: str, inventory: set[str]) -> str:
    """Strip domain suffix from *raw* and match against *inventory*.

    CDP/LLDP often reports the full FQDN (e.g. ``spine-01.dc1.example.com``).
    We strip everything after the first ``.`` and try to match the short name
    against the inventory.  If no match is found, the stripped name is
    returned as-is so the caller can decide how to handle unknown peers.
    """
    raw = raw.strip()
    short = raw.split(".")[0]
    if short in inventory:
        return short
    if raw in inventory:
        return raw
    return short


# ---------------------------------------------------------------------------
# LAG membership map
# ---------------------------------------------------------------------------

def build_lag_map(
    devices: dict[str, "ParsedConfig"],
) -> dict[str, dict[str, str]]:
    """Build a per-device LAG membership map from parsed interface configs.

    Returns:
        ``{hostname: {member_port_canonical: lag_interface_canonical}}``

    Example:
        ``{"spine-01": {"GigabitEthernet0/1": "Port-channel1",
                        "GigabitEthernet0/2": "Port-channel1"}}``

    Port-channel name is constructed as ``"Port-channel{channel_group}"``
    using the ``channel_group`` field already parsed by the IOS/EOS parsers.
    IOS-XR uses ``Bundle-Ether``; both normalize to ``Port-channel`` via
    ``normalize_interface_name``.
    """
    lag_map: dict[str, dict[str, str]] = {}
    for hostname, parsed in devices.items():
        membership: dict[str, str] = {}
        for iface in parsed.interfaces:
            if iface.channel_group is not None:
                member_canonical = normalize_interface_name(iface.name)
                lag_canonical = f"Port-channel{iface.channel_group}"
                membership[member_canonical] = lag_canonical
        lag_map[hostname] = membership
    return lag_map


def _resolve_lag(
    hostname: str,
    port_canonical: str,
    lag_map: dict[str, dict[str, str]],
) -> str:
    """Return the LAG interface name if *port_canonical* is a member port.

    Returns *port_canonical* unchanged if it is not a member port.
    """
    return lag_map.get(hostname, {}).get(port_canonical, port_canonical)


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

@dataclass
class _LinkKey:
    """Canonical key for deduplicating physical links.

    A link between (device_a, port_a) ↔ (device_b, port_b) is the same
    regardless of which side is "a" and which is "b".
    """
    pair: frozenset  # frozenset of two (device, port) tuples


def _make_key(device_a: str, port_a: str, device_b: str, port_b: str) -> frozenset:
    return frozenset([(device_a, port_a), (device_b, port_b)])


# ---------------------------------------------------------------------------
# CDP ingest
# ---------------------------------------------------------------------------

def load_cdp(
    csv_path: str | Path,
    inventory: set[str],
    devices: dict[str, "ParsedConfig"],
    lag_map: dict[str, dict[str, str]] | None = None,
) -> PhysicalTopology:
    """Parse a CDP neighbors CSV and return a ``PhysicalTopology``.

    Expected columns (case-insensitive):
        local_device, local_port, remote_device, remote_port

    Optional columns (ignored if absent):
        platform, software_version, capabilities

    Rows where either device is not in *inventory* are silently skipped —
    we only model links between devices we have configs for.
    """
    if lag_map is None:
        lag_map = build_lag_map(devices)

    seen: dict[frozenset, PhysicalLink] = {}

    with open(csv_path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        # Normalize header keys to lowercase
        for raw_row in reader:
            row = {k.strip().lower(): v.strip() for k, v in raw_row.items()}

            local_dev = _normalize_hostname(row.get("local_device", ""), inventory)
            remote_dev = _normalize_hostname(row.get("remote_device", ""), inventory)
            local_port_raw = row.get("local_port", "")
            remote_port_raw = row.get("remote_port", "")

            if not all([local_dev, remote_dev, local_port_raw, remote_port_raw]):
                continue
            if local_dev not in inventory or remote_dev not in inventory:
                continue

            local_port = _resolve_lag(
                local_dev,
                normalize_interface_name(local_port_raw),
                lag_map,
            )
            remote_port = _resolve_lag(
                remote_dev,
                normalize_interface_name(remote_port_raw),
                lag_map,
            )

            key = _make_key(local_dev, local_port, remote_dev, remote_port)
            if key in seen:
                seen[key].member_count += 1
            else:
                seen[key] = PhysicalLink(
                    device_a=local_dev,
                    port_a=local_port,
                    device_b=remote_dev,
                    port_b=remote_port,
                    source="cdp",
                    member_count=1,
                )

    return list(seen.values())


# ---------------------------------------------------------------------------
# LLDP ingest
# ---------------------------------------------------------------------------

def load_lldp(
    csv_path: str | Path,
    inventory: set[str],
    devices: dict[str, "ParsedConfig"],
    lag_map: dict[str, dict[str, str]] | None = None,
) -> PhysicalTopology:
    """Parse an LLDP neighbors CSV and return a ``PhysicalTopology``.

    Expected columns (case-insensitive):
        local_device, local_port, remote_device, remote_port

    Optional columns (ignored if absent):
        system_description, port_description, chassis_id
    """
    if lag_map is None:
        lag_map = build_lag_map(devices)

    seen: dict[frozenset, PhysicalLink] = {}

    with open(csv_path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for raw_row in reader:
            row = {k.strip().lower(): v.strip() for k, v in raw_row.items()}

            local_dev = _normalize_hostname(row.get("local_device", ""), inventory)
            remote_dev = _normalize_hostname(row.get("remote_device", ""), inventory)
            local_port_raw = row.get("local_port", "")
            remote_port_raw = row.get("remote_port", "")

            if not all([local_dev, remote_dev, local_port_raw, remote_port_raw]):
                continue
            if local_dev not in inventory or remote_dev not in inventory:
                continue

            local_port = _resolve_lag(
                local_dev,
                normalize_interface_name(local_port_raw),
                lag_map,
            )
            remote_port = _resolve_lag(
                remote_dev,
                normalize_interface_name(remote_port_raw),
                lag_map,
            )

            key = _make_key(local_dev, local_port, remote_dev, remote_port)
            if key in seen:
                seen[key].member_count += 1
            else:
                seen[key] = PhysicalLink(
                    device_a=local_dev,
                    port_a=local_port,
                    device_b=remote_dev,
                    port_b=remote_port,
                    source="lldp",
                    member_count=1,
                )

    return list(seen.values())


# ---------------------------------------------------------------------------
# MAC-ARP ingest (supplementary validation only)
# ---------------------------------------------------------------------------

@dataclass
class MACARPEntry:
    """A single MAC-ARP table entry."""
    device: str
    interface: str       # canonical interface name
    mac_address: str
    ip_address: str


def load_mac_arp(
    csv_path: str | Path,
    inventory: set[str],
    devices: dict[str, "ParsedConfig"],
) -> list[MACARPEntry]:
    """Parse a MAC-ARP CSV and return normalized entries.

    Expected columns (case-insensitive):
        device, interface, mac_address, ip_address

    This data is NOT used to infer adjacency edges directly.  It is returned
    as a list of ``MACARPEntry`` objects for callers that want to use it as a
    supplementary validation layer (e.g. confirm an IP→MAC→port mapping when
    CDP/LLDP data is ambiguous or incomplete).
    """
    entries: list[MACARPEntry] = []

    with open(csv_path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for raw_row in reader:
            row = {k.strip().lower(): v.strip() for k, v in raw_row.items()}

            device = _normalize_hostname(row.get("device", ""), inventory)
            iface_raw = row.get("interface", "")
            mac = row.get("mac_address", "").lower()
            ip = row.get("ip_address", "")

            if not all([device, iface_raw, mac, ip]):
                continue
            if device not in inventory:
                continue

            entries.append(MACARPEntry(
                device=device,
                interface=normalize_interface_name(iface_raw),
                mac_address=mac,
                ip_address=ip,
            ))

    return entries


# ---------------------------------------------------------------------------
# Combined ingest
# ---------------------------------------------------------------------------

def load_physical_topology(
    inventory: set[str],
    devices: dict[str, "ParsedConfig"],
    cdp_path: str | Path | None = None,
    lldp_path: str | Path | None = None,
) -> PhysicalTopology:
    """Load and merge physical topology from CDP and/or LLDP CSV files.

    At least one of *cdp_path* or *lldp_path* must be provided.

    When both are provided, CDP takes precedence: links already present from
    CDP are not duplicated from LLDP (matched by the same canonical
    device+port key).  LLDP contributes only links not already seen in CDP.

    Returns a deduplicated ``PhysicalTopology``.
    """
    if cdp_path is None and lldp_path is None:
        raise ValueError("At least one of cdp_path or lldp_path must be provided.")

    lag_map = build_lag_map(devices)
    seen: dict[frozenset, PhysicalLink] = {}

    if cdp_path is not None:
        for link in load_cdp(cdp_path, inventory, devices, lag_map):
            key = _make_key(link.device_a, link.port_a, link.device_b, link.port_b)
            if key in seen:
                seen[key].member_count += link.member_count
            else:
                seen[key] = link

    if lldp_path is not None:
        for link in load_lldp(lldp_path, inventory, devices, lag_map):
            key = _make_key(link.device_a, link.port_a, link.device_b, link.port_b)
            if key not in seen:  # CDP already takes precedence
                seen[key] = link

    return list(seen.values())
