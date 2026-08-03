# WITNESS Boundary Contracts — Immediate Implementation Checklist v0.2

## DEV-WIT-001 revision gate

- [x] Record that the evidence-coverage defect was found before Phase 1 results.
- [x] Preserve every v0.1 artifact and its Git history unchanged.
- [x] Keep scenario meaning, claims, thresholds, baselines, kill criteria, and matched-pair content unchanged.
- [x] Require explicit evidence for every enforced effect domain.
- [x] Record the non-negotiable privacy boundary in the v0.2 specification and deviation record.
- [ ] Obtain independent review and merge of the v0.2 checkpoint before resuming WIT-7.

## Freeze before coding

- [x] Create branch `experiment/witness-boundary-contracts-v0.2`.
- [x] Add the frozen experiment specification.
- [x] Add the YAML contracts and JSON scenario matrix.
- [ ] Record Git-blob SHA-256 digests of the exact v0.2 artifact set.
- [ ] Add a claims matrix with every C1-C6 marked `planned`.
- [ ] Record current MCP Sentinel commit SHA.

## Phase 1 tasks

- [ ] Define `BoundaryContract`.
- [ ] Strictly parse YAML and reject unknown keys.
- [ ] Cross-validate every effect domain against required telemetry.
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

## Non-negotiable privacy checks

- [x] No real email credentials, inbox, contacts, or live email delivery.
- [x] No real API keys or production secrets.
- [x] No personal files outside disposable fixtures.
- [x] `send_email` uses only a local mock receiver and reserved `.test` identities.
- [x] Email, attachment, credential, and canary data are synthetic.
