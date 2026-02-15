# MCP Sentinel — Project Roadmap

> Derived from Implementation Specification v0.3

## Overview

MCP Sentinel is a CLI tool that tests MCP (Model Context Protocol) servers for behavioral correctness and security. It answers one question: **"Does this MCP server do what it claims and nothing else?"**

---

## Milestones

### Phase 1: Core Data Models & Schema Analysis (Steps 1-3) -- COMPLETE

**Goal:** Establish the foundation — data models, test case generation, and CLI skeleton.

- [x] **Step 1 — `models.py`** (17 unit tests passing)
  - Implement all Pydantic data models (`Finding`, `ToolTestResult`, `TelemetryRecord`, `SentinelReport`, etc.)
  - Write validation tests for each model
  - Verify serialization/deserialization round-trips

- [x] **Step 2 — `schema_analyzer.py`** (20 unit tests passing)
  - Tool discovery via MCP `ClientSession.list_tools()`
  - Test case generation from JSON schemas (valid, edge, malformed, injection)
  - Fixture oracle rules (`FIXTURE_ORACLE_RULES`) for deterministic testing
  - Unit tests with mock schemas and oracle rule matching

- [x] **Step 3 — `cli.py` skeleton** (verified: --help, --version, arg validation)
  - Click CLI group with `test` command
  - `--mode`, `--command`, `--image`, `--tests-per-tool`, `--timeout`, `--export-telemetry`, `--format`, `--output`
  - Argument validation: schema mode requires `--command`, sandbox requires `--image`
  - `--help` output and version flag

---

### Phase 2: Schema Mode End-to-End (Steps 4-7) -- COMPLETE

**Goal:** Fully working schema mode with both test fixtures passing.

- [x] **Step 4 — `test_runner.py` (schema mode)**
  - Wire `SchemaAnalyzer` into the test execution loop
  - MCP stdio client connection via `mcp.client.stdio.stdio_client`
  - Timing: `datetime.now(utc)` for wall clock, `time.monotonic()` for duration
  - Oracle rule checking during test execution
  - Trust score calculation

- [x] **Step 5 — Test fixtures**
  - `tests/fixtures/good_server/server.py` — clean MCP server (add_numbers, echo, reverse_string)
  - `tests/fixtures/evil_server/server.py` — malicious server (read_file exfils, calculate evals, greet drops backdoor)
  - Verify both run standalone via `python server.py`

- [x] **Step 6 — Integration: schema mode vs good_server** -- MUST PASS #1 VERIFIED
  - **MUST PASS #1:** trust >= 0.9, zero critical/high findings

- [x] **Step 7 — Integration: schema mode vs evil_server** -- MUST PASS #2, #6 VERIFIED
  - **MUST PASS #2:** Tests run, report generated (no crash)
  - **MUST PASS #6:** `calculate` tool flagged for accepting `__import__('os').system('id')` via fixture oracle rules → `category=unsafe_input_accepted`

---

### Phase 3: Exfiltration Sink & Sandbox Infrastructure (Steps 8-10) -- COMPLETE

**Goal:** Build the Docker sandbox components.

- [x] **Step 8 — `exfil_sink.py`** (10 unit tests passing)
  - Dumb HTTP server code (runs inside container, logs JSON to stdout)
  - `parse_sink_logs()` — host-side canary detection
  - Unit tests with fabricated log data and canary values

- [x] **Step 9 — `sandbox.py`**
  - Docker network creation (`internal=True`, no internet)
  - Exfil sink container startup
  - Observer sidecar (tcpdump — pcap collected, parsing deferred)
  - MCP server launch via `asyncio.create_subprocess_exec("docker", "run", "-i", ...)`
  - Hardened container: `CAP_DROP ALL`, read-only root, tmpfs `/tmp`, no-new-privileges, memory/CPU/PID limits
  - Canary env var injection, trapped domain `/etc/hosts` mapping
  - Teardown and cleanup

- [x] **Step 10 — `sandbox._scan_tmp()`**
  - Filesystem scanning via `docker exec find + stat + sha256sum` (NOT docker diff — can't see tmpfs)
  - `is_executable` from `stat()` permissions: `(int(perm, 8) & 0o111) != 0`
  - Content hash and preview extraction
  - Test with a container that writes to `/tmp`

---

### Phase 4: Sandbox Mode End-to-End (Steps 11-13) -- CODE COMPLETE, NEEDS DOCKER

**Goal:** Full behavioral monitoring with Docker sandbox passing all integration tests.

- [x] **Step 11 — `test_runner.py` (sandbox mode)** (code complete)
  - Wire sandbox orchestrator into test runner
  - MCP SDK stream adapter for subprocess stdio (hardest integration point)
  - Post-run telemetry analysis: filesystem entries, exfil captures, resource snapshots
  - **Known challenge:** `mcp` SDK's `stdio_client` manages its own subprocess; sandbox mode needs a custom adapter for `ClientSession`

- [ ] **Step 12 — Dockerfiles for fixtures**
  - Evil server Dockerfile (needs Python + urllib)
  - Good server Dockerfile
  - Build and tag images for sandbox testing

- [ ] **Step 13 — Integration: sandbox mode vs evil_server** (requires Docker runtime)
  - **MUST PASS #3:** Exfil detected — sink logs contain POST to `/collect` and `/keys`, `category=data_exfiltration`
  - **MUST PASS #4:** Canary leaked — `parse_sink_logs()` finds canary values in capture bodies, `category=canary_leaked`, `matched_canary_keys` populated
  - **MUST PASS #5:** `/tmp` write detected — `_scan_tmp()` finds `/tmp/.backdoor.sh` with `is_executable=True`, `severity=critical`

---

### Phase 5: Telemetry, Polish & Ship (Steps 14-16) -- PARTIALLY COMPLETE

**Goal:** Complete telemetry export, exit codes, mode labeling. All MUST PASS green.

- [x] **Step 14 — Telemetry export** -- MUST PASS #7 VERIFIED
  - JSONL export: every line is valid JSON and validates as `TelemetryRecord`
  - **MUST PASS #7:** Telemetry JSONL valid

- [x] **Step 15 — Exit codes & mode labels** -- MUST PASS #8, #9 VERIFIED
  - Exit code 0 = clean, 1 = high findings, 2 = critical findings
  - Schema report: sandbox fields are `null`
  - Sandbox report: sandbox fields populated
  - CLI banner matches active mode
  - **MUST PASS #8:** Correct exit codes
  - **MUST PASS #9:** Mode labeling consistent

- [ ] **Step 16 — Full checklist green**
  - Run all 9 MUST PASS items end-to-end
  - Fix any regressions
  - Ship

---

## MUST PASS Acceptance Criteria

| # | Test | Pass Condition | Status |
|---|------|---------------|--------|
| 1 | Good server schema mode | trust >= 0.9, zero critical/high | **PASS** |
| 2 | Evil server schema mode | Tests run, report generated | **PASS** |
| 3 | Evil server sandbox: exfil detected | Sink logs contain captures, `category=data_exfiltration` | Needs Docker |
| 4 | Evil server sandbox: canary leaked | Canary values found in captures, `matched_canary_keys` populated | Needs Docker |
| 5 | Evil server sandbox: /tmp write | `/tmp/.backdoor.sh` found via docker exec, `is_executable=True` | Needs Docker |
| 6 | Evil server: unsafe eval | Oracle rule matches `__import__` pattern, `category=unsafe_input_accepted` | **PASS** |
| 7 | Telemetry JSONL valid | Every line parses as valid `TelemetryRecord` | **PASS** |
| 8 | Exit codes | 0=clean, 1=high, 2=critical | **PASS** |
| 9 | Mode labeling | Schema has null sandbox fields, sandbox has them populated | **PASS** (schema verified) |

**Summary: 6/9 MUST PASS verified. Remaining 3 require Docker runtime for sandbox integration tests.**

---

## Test Suite Summary

| Suite | Tests | Status |
|-------|-------|--------|
| Unit: models | 17 | All passing |
| Unit: schema_analyzer | 20 | All passing |
| Unit: exfil_sink | 10 | All passing |
| Integration: schema mode | 4 | All passing |
| **Total** | **51** | **All passing** |

---

## Architecture Summary

```
Schema Mode:
  CLI → SchemaAnalyzer → TestRunner → MCP Server (stdio process)

Sandbox Mode:
  CLI → TestRunner → SandboxOrchestrator
    → Docker Network (internal, no internet)
      → Exfil Sink (dumb HTTP logger)
      → Observer Sidecar (tcpdump/pcap)
      → MCP Server (hardened container, subprocess stdio)
    → Host-side analysis (canary detection, filesystem scan, telemetry)
```

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Python 3.11+ |
| MCP Client | `mcp` SDK (`pip install mcp`) |
| CLI | `click` + `rich` |
| Sandboxing | Docker (bridge network, hardened containers) |
| Data Models | `pydantic` v2 |
| Reporting | JSON + HTML (`jinja2`) + JSONL telemetry |
| Network Capture | tcpdump in sidecar (pcap — Phase 2 parsing) |
| FS Detection | `docker exec` (find + stat + sha256sum) |

---

## Non-Negotiable Design Decisions

1. **Sandbox stdio = subprocess.** `asyncio.create_subprocess_exec("docker", "run", "-i", ...)` — not Docker SDK sockets.
2. **Filesystem detection = docker exec scan.** NOT docker diff (can't see tmpfs).
3. **`is_executable` = stat() permissions.** `(int(perm, 8) & 0o111) != 0`.
4. **Canary detection = host-side.** Sink is dumb. `parse_sink_logs()` does all analysis.
5. **Timestamps:** `datetime.now(utc)` for wall clock, `time.monotonic()` for duration.
6. **pcap parsing is deferred.** Collect the pcap. Don't parse it. Sink captures are primary evidence.

---

## Known Limitations

1. Schema mode cannot detect side effects (explicitly labeled in reports)
2. Sandbox cannot detect in-memory-only behavior
3. Stdio transport only (no SSE/HTTP)
4. No semantic correctness checking (garbage output matching schema type passes)
5. Single-call testing only (stateful attacks not caught)
6. FS scan is post-hoc (files created then deleted mid-run are invisible)
7. pcap not parsed (network evidence from sink captures only)
8. Oracle rules are fixture-specific (real-world policy file is Phase 2)

---

## Future Work (Post-v0.3)

- **Phase 2:** pcap parsing with scapy, real-world policy files, SSE/HTTP transport
- **Phase 2:** Stateful multi-call test sequences
- **Phase 2:** Semantic correctness oracles beyond fixture-specific rules
- **Phase 2:** HTML report generation with jinja2 templates
