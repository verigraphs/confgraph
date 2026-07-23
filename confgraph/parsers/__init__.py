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

PARSER_BEHAVIOR_VERSION: int = 1

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
