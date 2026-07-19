# Changelog

All notable changes to `confgraph` are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Deprecated

- **`ParsedConfig.no_commands`, `InterfaceConfig.no_commands`, and
  `BGPConfig.no_commands` are deprecated** (CCR-0025 Phase 4). These tombstone
  fields record `no ...` negation lines in the legacy string vocabulary. They are
  superseded by the Change-IR operation model (`ParsedConfig.change_ops`), which
  represents the same intent as structured `ChangeOp`s with real provenance.

  When the `CONFGRAPH_CHANGE_IR` default flips to `ops`, the parsers stop emitting
  these tombstones natively. To give downstream consumers a courtesy migration
  window, the fields stay **populated but deprecated for two minor releases** after
  the flip: they are refilled from the composed change set by the ops-to-legacy
  shim (`confgraph.change_ir.encode_legacy_shim`) at near-zero cost, byte-identical
  to what the parsers emitted before. After that window the fields are emptied, and
  they are removed from the model only at the next **major** version, preserving
  schema compatibility until then. `confgraph`'s own platform and engine consumers
  stop reading the fields at the default flip.

  **Migration:** read change intent from `ParsedConfig.change_ops` (Change-IR)
  instead of the `no_commands` string containers.
