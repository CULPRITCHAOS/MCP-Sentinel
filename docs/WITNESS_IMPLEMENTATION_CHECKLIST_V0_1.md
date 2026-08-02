# WITNESS Boundary Contracts — Immediate Implementation Checklist

## Freeze before coding

- [x] Create branch `experiment/witness-boundary-contracts-v0`.
- [x] Add the frozen experiment specification.
- [x] Add the YAML contracts and JSON scenario matrix.
- [ ] Record SHA-256 digests of all three files.
- [ ] Add a claims matrix with every C1-C6 marked `planned`.
- [ ] Record current MCP Sentinel commit SHA.

## Phase 1 tasks

- [ ] Define `BoundaryContract`.
- [ ] Strictly parse YAML and reject unknown keys.
- [ ] Define `SourceRecord`.
- [ ] Define deterministic transformation lineage.
- [ ] Implement argument-role/source authorization.
- [ ] Normalize effect event types.
- [ ] Implement verdict precedence: `INCOMPLETE` > `FAIL` > `DENY` > `PASS`.
- [ ] Build fixed-plan runner.
- [ ] Implement all twelve pairs.
- [ ] Add receipt modification test.
- [ ] Add replay under changed contract/tool digest test.
- [ ] Remove scalar trust score from experiment output.

## Phase 2 hardening prerequisites

- [ ] Remove host-network fallback.
- [ ] Use a dedicated trusted sink/observer image.
- [ ] Fail if isolated network cannot be created.
- [ ] Capture all outbound destinations.
- [ ] Capture process spawning.
- [ ] Capture writes across all experiment-writable locations.
- [ ] Record observer heartbeat and capture window.
- [ ] Return `INCOMPLETE` on observer loss.
- [ ] Freeze two agent planners and exact versions.
- [ ] Implement baseline manifest.

## Analysis

- [ ] Compute UASR, UEMR, BTC, FBR, utility delta, drift detection, evidence completeness, and overhead.
- [ ] Compare B7 with strongest single-layer baseline.
- [ ] Apply thresholds without modifying them.
- [ ] Publish raw and normalized failures.
- [ ] Update claims matrix.
- [ ] Decide `continue`, `narrow`, or `stop`.

## Do not build yet

- [ ] No dashboard.
- [ ] No marketplace.
- [ ] No automated contract synthesis.
- [ ] No generalized framework adapters.
- [ ] No certification language.
- [ ] No cryptographic transparency log.
- [ ] No new repository before Phase 2 differentiation.
