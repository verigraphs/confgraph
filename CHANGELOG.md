# Changelog

All notable changes to `confgraph` are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.5] - 2026-07-26

### Deprecated

- **`ParsedConfig.no_commands`, `InterfaceConfig.no_commands`, and
  `BGPConfig.no_commands` are deprecated** (CCR-0025 Phase 4 / CCR-0110). These
  tombstone fields record `no ...` negation lines in the legacy string
  vocabulary. They are superseded by the Change-IR operation model
  (`ParsedConfig.change_ops`), which represents the same intent as structured
  `ChangeOp`s with real provenance.

  The `CONFGRAPH_CHANGE_IR` default flipped to `ops` (2026-07-19). This release
  starts the deprecation window: the fields stay **populated but deprecated for
  one release cycle** (revised from two — CCR-0025 §8.2, owner decision
  2026-07-25) — during the window they continue to carry what the parsers emit;
  when parser tombstone emission retires (CCR-0110 Phase E) they are refilled by
  the ops-to-legacy shim (`confgraph.change_ir.encode_legacy_shim`),
  byte-identical, continuously verified by the shim's in-suite identity sweep.
  In the release after this window the fields are emptied; they are removed
  from the model only at the next **major** version, preserving schema
  compatibility until then. `confgraph`'s own platform and engine consumers
  already stopped reading the fields at the default flip.

  **Migration:** read change intent from `ParsedConfig.change_ops` (Change-IR)
  instead of the `no_commands` string containers.
