"""Network configuration parsers.

``PARSER_BEHAVIOR_VERSION`` is a monotonic integer that identifies the observable
behavior of the parsers as a whole. Consumers key parse caches and input digests on
it (the platform parse cache folds it into its cache key as ``::pbv=<n>``; CCR-0082's
gate digest keys carry it as their parser-version input) so that a behavior-only
change — one that alters parse output for some OS but leaves the ``ParsedConfig``
JSON schema, the package version, and the pydantic version all unchanged — still
invalidates stale hits. Those three signals are already caught by the existing key
components; this constant closes the remaining hole.

Maintenance rule (review-checklist discipline, mirroring confgraph-entrp's
``STATE_SCHEMA_VERSION`` practice): bump ``PARSER_BEHAVIOR_VERSION``
in the same commit as the behavior change. A behavior change is ANY change that can alter parse
output for ANY OS without a corresponding ``ParsedConfig`` JSON-schema change —
parser bug fixes, new syntax support, normalization changes, and model-semantic
changes that are invisible to the schema all count. It is one shared integer across
all OS parsers by design; per-OS granularity was explicitly rejected in CCR-0097.
A missed bump means consumers serve stale cache hits, i.e. a wrong parse — so the
bump is not optional for a qualifying change.
"""

from confgraph.parsers.base import BaseParser, ParseError
from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.eos_parser import EOSParser
from confgraph.parsers.nxos_parser import NXOSParser
from confgraph.parsers.iosxr_parser import IOSXRParser
from confgraph.parsers.junos_parser import JunOSParser
from confgraph.parsers.panos_parser import PANOSParser

# 2 (CCR-0129): NX-OS ``ip dhcp relay address`` re-homed from the retired
# ``InterfaceConfig.dhcp_relay_addresses`` onto ``helper_addresses``.  A bump is not
# strictly REQUIRED by the rule above (the field removal also moves the ParsedConfig
# JSON schema, which the platform parse cache keys on independently), but
# confgraph-entrp's gate ``digest_key()`` carries pbv with NO schema component, so this
# is the only signal that moves there — and over-keying is the documented posture.
# 3 (CCR-0146): IOS/IOS-XE ``no bgp default ipv4-unicast`` now parses onto the new
# ``BGPConfig.default_ipv4_unicast`` field — observable parse output moves (a config
# that disables the default now yields False instead of the silent old True).  Same
# posture as the CCR-0129 bump: the new field also moves the ParsedConfig JSON schema
# (so the platform parse cache invalidates independently and a bump is not strictly
# required), but entrp's schema-less ``digest_key()`` only moves on pbv, so we bump.
# 4 (CCR-0165): ``BGPNeighborAF.activate`` is tri-state — EOS policy-only AF
# entries now parse activate=None (unstated) instead of False, and the
# block-presence OSes assert True explicitly. Schema also moves (bool -> bool|None),
# but entrp's schema-less ``digest_key()`` only moves on pbv — same posture as 2/3.
# Also under 4: the shared IOS/EOS AF walk no longer emits an EMPTY BGPNeighborAF
# for a peer whose only AF-block lines are vocabulary-invisible (13 such commands
# measured) — deliberate; a real config's ``activate`` line keeps the entry.
PARSER_BEHAVIOR_VERSION: int = 4

__all__ = [
    "BaseParser",
    "ParseError",
    "IOSParser",
    "EOSParser",
    "NXOSParser",
    "IOSXRParser",
    "JunOSParser",
    "PANOSParser",
    "PARSER_BEHAVIOR_VERSION",
]
