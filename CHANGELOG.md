# Changelog

All notable changes to `confgraph` are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.6] - 2026-07-27

### Changed

- **Op-primary parsers (IOS, NX-OS, EOS) no longer emit legacy tombstone
  strings** into `ParsedConfig.no_commands`, `InterfaceConfig.no_commands`, or
  `BGPConfig.no_commands` (CCR-0110 Phase E). This closes the one-release
  deprecation window opened in 0.3.5: those fields are now **empty** on
  op-primary parses. The Change-IR operation model (`ParsedConfig.change_ops`)
  is unaffected — every removal that previously produced a tombstone string is
  still emitted as a native `ChangeOp` with real provenance, so the composed
  ChangeSet is byte-identical to 0.3.5.

  **IOS-XR is excepted** (pending Phase 5): its deletion capability is carried
  by derived tombstone strings (no native op sits behind them), so IOS-XR
  continues to populate `no_commands` for its top-level and interface
  deletions. **Three residual derived-only strings also survive on all OSes**
  (each has no native op behind it — the string carries the deletion):
  the whole-process `no router bgp <asn>` delete (`process:bgp:<asn>`) and the
  OSPF area type resets (`field:ospf:<pid>:area:<n>:stub_reset` and
  `...:nssa_reset`). All other OSPF-area deletion variants are op-backed and
  emit no string.

  The ops-to-legacy shim (`confgraph.change_ir.encode_legacy_shim`) is **not**
  wired to refill the deprecated fields (owner-confirmed zero external
  consumers, zero remaining engine readers). It survives as a **codec
  artifact** — the inverse deriver that reconstructs the byte-exact legacy
  string vocabulary from the composed ChangeSet — pinned against frozen
  pre-removal goldens by the shim identity suite.

  **Migration:** read change intent from `ParsedConfig.change_ops` (Change-IR)
  instead of the `no_commands` string containers. The fields remain on the
  model (empty) until removed at the next major version.

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
