# DEV-WIT-001 — Require Explicit Per-Domain Effect Evidence

**Status:** Frozen deviation candidate; authoritative only after independent review and merge
**Experiment revision:** `witness-boundary-contracts-v0.2`
**Prior authoritative checkpoint:** `903d4d3910f887a389ef40a4ca90be6ea0168d34`
**Discovery source:** Independent P1 security review of WIT-7 draft PR #5

## Classification

The defect was discovered before Phase 1 execution results. This correction is
not post-result tuning. v0.1 artifacts and Git history remain unchanged. v0.1
must not be executed as the authoritative experiment version, and no v0.1
result may support H3, H5, C2, C3, or C4.

## Confirmed defect

v0.1 declares effect domains fail-closed but does not require telemetry for
every enforced domain. `observer_health` alone cannot distinguish "the effect
did not occur" from "the relevant stream was never required or captured."

The exact gaps are:

| Tool | Missing v0.1 evidence |
|---|---|
| `send_email` | `dns_events`, `filesystem_events`, `process_events` |
| `write_file` | `dns_events`, `network_events`, `process_events`, `durable_state_diff` |
| `fetch_url` | `filesystem_events`, `process_events`, `durable_state_diff` |

The defect prevents valid evaluation of H3/C2, H5/C4, undeclared-effect miss
rate, observer false-pass count, P12, and therefore C3.

## Approved correction represented by this candidate

- Every tool requires `observer_health`.
- Network enforcement requires `network_events`.
- Hostname, DNS, redirect, or IP-class policy requires `dns_events`.
- Filesystem enforcement requires `filesystem_events`.
- Process enforcement requires `process_events`.
- Durable-state enforcement requires `durable_state_diff`.
- A credentials section requires `credential_scan`.
- All three current tools require `dns_events` and `network_events`.
- Required evidence must prove each stream was enabled and its capture window
  covered execution.
- An empty stream is valid only when required, active, healthy, and linked to
  that execution.
- Missing or degraded required telemetry yields `INCOMPLETE`, never `PASS`.

No scenario meaning, claim, threshold, baseline, kill criterion, or matched-pair
content changes. Scenario v0.2 differs only in its experiment-version reference.

## Non-negotiable privacy boundary

WITNESS v0.x must never request, access, store, or use real email credentials,
a real inbox, real contacts, live email delivery, real API keys or production
secrets, or personal files outside disposable fixtures.

`send_email` remains a synthetic test tool using only:

- a local mock receiver;
- reserved identities such as `user@example.test`, `manager@example.test`, and
  `attacker@example.test`;
- synthetic email and attachment fixtures;
- synthetic canary credentials;
- disposable temporary directories and local mock services.

## Workflow consequences

1. Preserve v0.1 artifacts, manifest, verifier, tests, and Git history.
2. Freeze the exact v0.2 artifact set through a separately versioned manifest
   and verifier anchored by Git review plus the Linear WIT-13 checkpoint.
3. Keep PR #5 draft and unchanged until this checkpoint is independently
   approved and merged.
4. After merge, update PR #5 onto the approved v0.2 base, add deterministic
   effect-to-evidence cross-validation and tests, and stop for review again.
5. Keep WIT-7 In Progress and blocked by WIT-13. Keep WIT-8 and WIT-9 in
   Backlog. WIT-12 remains the next gate after WIT-7 approval.
