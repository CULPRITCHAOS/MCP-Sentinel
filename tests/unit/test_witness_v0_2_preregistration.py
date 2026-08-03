"""Focused tests for the DEV-WIT-001 v0.2 preregistration revision."""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
CONTRACT = ROOT / "contracts" / "boundary-contracts-v0.2.yaml"
SCENARIO_V01 = ROOT / "fixtures" / "witness" / "scenarios-v0.1.json"
SCENARIO_V02 = ROOT / "fixtures" / "witness" / "scenarios-v0.2.json"
SPEC = ROOT / "docs" / "WITNESS_BOUNDARY_CONTRACTS_EXPERIMENT_V0_2.md"
CLAIMS = ROOT / "docs" / "WITNESS_CLAIMS_MATRIX_V0_2.md"
DEVIATION = ROOT / "docs" / "WITNESS_DEVIATION_DEV_WIT_001.md"

BASE_EFFECT_EVIDENCE = {
    "dns_events",
    "network_events",
    "filesystem_events",
    "process_events",
    "durable_state_diff",
    "observer_health",
}


def _tool_blocks() -> dict[str, str]:
    text = CONTRACT.read_text(encoding="utf-8")
    blocks: dict[str, str] = {}
    for block in text.split("\n  - tool:\n")[1:]:
        match = re.search(r"^      name: ([a-z_]+)$", block, re.MULTILINE)
        assert match is not None
        blocks[match.group(1)] = block
    return blocks


def _required_evidence(block: str) -> set[str]:
    match = re.search(
        r"^      required: \[([^\]]+)\]$",
        block,
        re.MULTILINE,
    )
    assert match is not None
    return {item.strip() for item in match.group(1).split(",")}


def _strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def test_contract_declares_v0_2_and_all_three_tools() -> None:
    text = CONTRACT.read_text(encoding="utf-8")

    assert text.startswith("contract_version: witness-boundary-v0.2\n")
    assert set(_tool_blocks()) == {"send_email", "write_file", "fetch_url"}


def test_every_enforced_domain_has_explicit_evidence() -> None:
    for name, block in _tool_blocks().items():
        required = _required_evidence(block)
        assert BASE_EFFECT_EVIDENCE <= required, name
        if "\n      credentials:\n" in block:
            assert "credential_scan" in required, name
        assert "external_to_executor: true" in block
        assert "failure_verdict: INCOMPLETE" in block


def test_exact_v0_1_gaps_are_closed() -> None:
    required = {
        name: _required_evidence(block) for name, block in _tool_blocks().items()
    }

    assert {"dns_events", "filesystem_events", "process_events"} <= required[
        "send_email"
    ]
    assert {
        "dns_events",
        "network_events",
        "process_events",
        "durable_state_diff",
    } <= required["write_file"]
    assert {
        "filesystem_events",
        "process_events",
        "durable_state_diff",
    } <= required["fetch_url"]


def test_scenario_meaning_is_unchanged_except_version_reference() -> None:
    v01 = json.loads(SCENARIO_V01.read_text(encoding="utf-8"))
    v02 = json.loads(SCENARIO_V02.read_text(encoding="utf-8"))

    assert v01.pop("experiment") == "witness-boundary-contracts-v0.1"
    assert v02.pop("experiment") == "witness-boundary-contracts-v0.2"
    assert v02 == v01


def test_claims_c1_through_c6_are_reset_to_planned() -> None:
    text = CLAIMS.read_text(encoding="utf-8")

    for claim in range(1, 7):
        row = next(
            line
            for line in text.splitlines()
            if line.startswith(f"| C{claim} |")
        )
        assert row.endswith("| `planned` |")


def test_deviation_records_timing_gaps_and_claim_impact() -> None:
    text = DEVIATION.read_text(encoding="utf-8")
    normalized = " ".join(text.split())

    assert "before Phase 1 execution results" in normalized
    assert "not post-result tuning" in normalized
    assert "v0.1 artifacts and Git history remain unchanged" in normalized
    assert "no v0.1 result may support H3, H5, C2, C3, or C4" in normalized
    assert "`send_email` | `dns_events`, `filesystem_events`, `process_events`" in text
    assert (
        "`write_file` | `dns_events`, `network_events`, `process_events`, "
        "`durable_state_diff`" in text
    )
    assert (
        "`fetch_url` | `filesystem_events`, `process_events`, "
        "`durable_state_diff`" in text
    )


def test_privacy_boundary_is_explicit_and_synthetic() -> None:
    combined = SPEC.read_text(encoding="utf-8") + DEVIATION.read_text(
        encoding="utf-8"
    )
    normalized = " ".join(combined.split())
    for prohibited in (
        "real email credentials",
        "real inbox",
        "real contacts",
        "live email delivery",
        "production secrets",
        "personal files outside disposable fixtures",
    ):
        assert prohibited in normalized

    scenario = json.loads(SCENARIO_V02.read_text(encoding="utf-8"))
    addresses = {value for value in _strings(scenario) if "@" in value}
    assert addresses
    assert all(address.endswith("@example.test") for address in addresses)

    contract = CONTRACT.read_text(encoding="utf-8")
    hosts = set(re.findall(r"^            host: ([a-z0-9-]+)$", contract, re.MULTILINE))
    assert hosts == {"mock-mail", "docs-a", "docs-b"}
