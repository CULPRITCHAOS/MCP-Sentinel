"""Tests for the WITNESS preregistration verifier."""

from pathlib import Path

from scripts.verify_witness_preregistration import (
    DEFAULT_MANIFEST,
    _parse_manifest,
    verify,
)

EXPECTED_COMMIT = "39bb8f4894f224ff37af62060812de7e68fbc2ea"
EXPECTED_PATHS = {
    "docs/WITNESS_BOUNDARY_CONTRACTS_EXPERIMENT_V0_1.md",
    "contracts/boundary-contracts-v0.1.yaml",
    "fixtures/witness/scenarios-v0.1.json",
    "docs/WITNESS_IMPLEMENTATION_CHECKLIST_V0_1.md",
}


def test_manifest_records_frozen_commit_and_artifacts() -> None:
    manifest = _parse_manifest(DEFAULT_MANIFEST)

    assert manifest.starting_commit == EXPECTED_COMMIT
    assert {path for _, path in manifest.artifacts} == EXPECTED_PATHS


def test_repository_matches_preregistration_manifest() -> None:
    assert verify(DEFAULT_MANIFEST) == []


def test_tampered_digest_is_rejected(tmp_path: Path) -> None:
    original = DEFAULT_MANIFEST.read_text(encoding="utf-8")
    first_digest = _parse_manifest(DEFAULT_MANIFEST).artifacts[0][0]
    tampered = original.replace(first_digest, "0" * 64, 1)
    manifest_path = tmp_path / "preregistration-digest.txt"
    manifest_path.write_text(tampered, encoding="utf-8")

    errors = verify(manifest_path)

    assert any("manifest mismatch" in error for error in errors)
