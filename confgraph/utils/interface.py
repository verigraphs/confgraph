"""Interface name normalization utilities.

Converts vendor-specific and abbreviated interface names to a canonical long
form so that names from device configs, CDP/LLDP discovery data, and routing
protocol outputs can be reliably compared across OS types.

Canonical form
--------------
IOS / IOS-XR / EOS / NX-OS interfaces are normalized to the full IOS long form:
  GigabitEthernet0/1, TenGigabitEthernet1/0/1, Port-channel1, Loopback0, etc.

JunOS interfaces use a structurally different naming convention (xe-0/0/1,
et-0/0/1, ae0, fxp0) that is already unambiguous. JunOS names are returned
unchanged — only whitespace is stripped and the first character is lowercased
to match JunOS convention.

Display form
------------
canonical_to_display() produces a short label suitable for graph edges:
  GigabitEthernet0/1  →  Gi0/1
  TenGigabitEthernet1/0/1  →  Te1/0/1
  Port-channel1  →  Po1

Usage
-----
    from confgraph.utils.interface import normalize_interface_name, canonical_to_display

    normalize_interface_name("Gi0/1")          # → "GigabitEthernet0/1"
    normalize_interface_name("xe-0/0/1")       # → "xe-0/0/1"  (JunOS — unchanged)
    canonical_to_display("GigabitEthernet0/1") # → "Gi0/1"
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Prefix → canonical long form
# Order matters: longer/more-specific prefixes must come before shorter ones
# to avoid e.g. "Te" matching before "TenGig".
# ---------------------------------------------------------------------------

_PREFIX_MAP: list[tuple[str, str]] = [
    # 100GE variants
    ("HundredGigabitEthernet",  "HundredGigabitEthernet"),
    ("HundredGig",              "HundredGigabitEthernet"),
    ("HundredGE",               "HundredGigabitEthernet"),
    ("Hun",                     "HundredGigabitEthernet"),
    ("Hu",                      "HundredGigabitEthernet"),

    # 400GE variants
    ("FourHundredGigabitEthernet", "FourHundredGigabitEthernet"),
    ("FourHundredGig",             "FourHundredGigabitEthernet"),
    ("FourHundredGE",              "FourHundredGigabitEthernet"),
    ("Foh",                        "FourHundredGigabitEthernet"),

    # 40GE variants
    ("FortyGigabitEthernet",    "FortyGigabitEthernet"),
    ("FortyGig",                "FortyGigabitEthernet"),
    ("FortyGE",                 "FortyGigabitEthernet"),
    ("Fo",                      "FortyGigabitEthernet"),

    # 25GE variants
    ("TwentyFiveGigE",          "TwentyFiveGigE"),
    ("TwentyFiveGig",           "TwentyFiveGigE"),
    ("TwentyFiveGigabitEthernet", "TwentyFiveGigE"),
    ("Twe",                     "TwentyFiveGigE"),

    # 10GE variants
    ("TenGigabitEthernet",      "TenGigabitEthernet"),
    ("TenGigE",                 "TenGigabitEthernet"),
    ("TenGig",                  "TenGigabitEthernet"),
    ("TenGE",                   "TenGigabitEthernet"),
    ("Ten",                     "TenGigabitEthernet"),
    ("Te",                      "TenGigabitEthernet"),

    # 1GE variants
    ("GigabitEthernet",         "GigabitEthernet"),
    ("GigabitEth",              "GigabitEthernet"),
    ("Gigabit",                 "GigabitEthernet"),
    ("GigEth",                  "GigabitEthernet"),
    ("GigE",                    "GigabitEthernet"),
    ("Gig",                     "GigabitEthernet"),
    ("Gi",                      "GigabitEthernet"),
    ("GE",                      "GigabitEthernet"),

    # FastEthernet
    ("FastEthernet",            "FastEthernet"),
    ("FastEth",                 "FastEthernet"),
    ("Fast",                    "FastEthernet"),
    ("Fa",                      "FastEthernet"),

    # Ethernet (EOS / NX-OS bare "Ethernet" or "Eth")
    ("Ethernet",                "Ethernet"),
    ("Eth",                     "Ethernet"),

    # Port-channel / LAG
    ("Port-channel",            "Port-channel"),
    ("Port-Channel",            "Port-channel"),
    ("portchannel",             "Port-channel"),
    ("PortChannel",             "Port-channel"),
    ("Bundle-Ether",            "Port-channel"),   # IOS-XR LAG
    ("Bundle-ether",            "Port-channel"),
    ("Po",                      "Port-channel"),

    # Loopback
    ("Loopback",                "Loopback"),
    ("loopback",                "Loopback"),
    ("Lo",                      "Loopback"),

    # Management
    ("Management",              "Management"),
    ("management",              "Management"),
    ("Mgmt",                    "Management"),
    ("mgmt",                    "Management"),
    ("Ma",                      "Management"),
    ("MgmtEth",                 "Management"),     # IOS-XR

    # Vlan / SVI / IRB
    ("Vlan",                    "Vlan"),
    ("vlan",                    "Vlan"),
    ("Vl",                      "Vlan"),
    ("BVI",                     "Vlan"),           # IOS-XR BVI
    ("irb",                     "Vlan"),           # JunOS IRB — treated as Vlan

    # Tunnel
    ("Tunnel",                  "Tunnel"),
    ("tunnel",                  "Tunnel"),
    ("Tu",                      "Tunnel"),

    # Serial
    ("Serial",                  "Serial"),
    ("serial",                  "Serial"),
    ("Se",                      "Serial"),

    # Null
    ("Null",                    "Null"),
    ("null",                    "Null"),

    # Subinterface shorthand (no type prefix — just a number, rare)
]

# Build a sorted match list: longest prefix first to avoid partial matches
_SORTED_PREFIX_MAP: list[tuple[str, str]] = sorted(
    _PREFIX_MAP, key=lambda x: len(x[0]), reverse=True
)

# JunOS interface prefixes — left unchanged
_JUNOS_PREFIXES: tuple[str, ...] = (
    "xe-", "et-", "ge-", "fe-",   # physical (10G, 100G, 1G, FE) — hyphenated, unambiguous
    "ae",                           # aggregated ethernet (LAG) — e.g. ae0, ae1
    "lo0",                          # loopback — JunOS always lo0 (not Lo which is IOS)
    "fxp",                          # management (fxp0)
    "irb",                          # integrated routing and bridging
    "vlan.",                        # VLAN subinterface (dot-notation)
    "reth",                         # redundant ethernet (SRX)
    "st0",                          # secure tunnel (SRX)
    "em",                           # management on vMX
    "esi",                          # ESI interface
    "si",                           # service interface
)


def _is_junos(name: str) -> bool:
    """Return True if *name* looks like a JunOS interface name.

    JunOS names are always lowercase (xe-0/0/1, ae0, lo0, fxp0).
    IOS abbreviations like Lo0 or Lo1 start with an uppercase letter, so
    the check is case-sensitive — only lowercase-prefixed names match.
    """
    return any(name.startswith(p) for p in _JUNOS_PREFIXES)


def normalize_interface_name(name: str) -> str:
    """Return the canonical long-form interface name.

    - JunOS names (xe-*, et-*, ae*, lo*, fxp*, etc.) are returned unchanged
      (stripped of surrounding whitespace only).
    - All other names: the abbreviated prefix is expanded to the IOS long form
      and reassembled with the port/slot suffix unchanged.
    - If the prefix is not recognized, the name is returned as-is (stripped).

    Examples
    --------
    >>> normalize_interface_name("Gi0/1")
    'GigabitEthernet0/1'
    >>> normalize_interface_name("  Te1/0/1  ")
    'TenGigabitEthernet1/0/1'
    >>> normalize_interface_name("Po1")
    'Port-channel1'
    >>> normalize_interface_name("xe-0/0/1")
    'xe-0/0/1'
    >>> normalize_interface_name("Bundle-Ether12")
    'Port-channel12'
    """
    name = name.strip()
    if not name:
        return name

    # JunOS — return unchanged
    if _is_junos(name):
        return name

    # Match against the prefix map using longest-prefix-first strategy.
    # We do NOT split on the first digit because some suffixes contain letters
    # (e.g. MgmtEth0/RP0/CPU0/0 — suffix starts with a digit but path
    # components contain letters).  Instead, try each known prefix in
    # longest-first order and take the first that matches the start of *name*.
    for abbrev, canonical in _SORTED_PREFIX_MAP:
        if name.lower().startswith(abbrev.lower()):
            suffix = name[len(abbrev):]
            return canonical + suffix

    # No prefix matched — return as-is
    return name


# ---------------------------------------------------------------------------
# Display (short) form
# ---------------------------------------------------------------------------

_CANONICAL_TO_SHORT: dict[str, str] = {
    "GigabitEthernet":          "Gi",
    "TenGigabitEthernet":       "Te",
    "TwentyFiveGigE":           "Twe",
    "FortyGigabitEthernet":     "Fo",
    "HundredGigabitEthernet":   "Hu",
    "FourHundredGigabitEthernet": "Foh",
    "FastEthernet":             "Fa",
    "Ethernet":                 "Eth",
    "Port-channel":             "Po",
    "Loopback":                 "Lo",
    "Management":               "Ma",
    "Vlan":                     "Vl",
    "Tunnel":                   "Tu",
    "Serial":                   "Se",
    "Null":                     "Null",
}


def canonical_to_display(canonical_name: str) -> str:
    """Return a short display label for a canonical interface name.

    Used for graph edge labels where space is limited.

    Examples
    --------
    >>> canonical_to_display("GigabitEthernet0/1")
    'Gi0/1'
    >>> canonical_to_display("Port-channel1")
    'Po1'
    >>> canonical_to_display("xe-0/0/1")
    'xe-0/0/1'   # JunOS — unchanged
    """
    canonical_name = canonical_name.strip()
    if _is_junos(canonical_name):
        return canonical_name

    for full, short in _CANONICAL_TO_SHORT.items():
        if canonical_name.startswith(full):
            suffix = canonical_name[len(full):]
            return short + suffix

    return canonical_name
