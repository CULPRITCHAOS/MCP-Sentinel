"""Tests for the WITNESS preregistration verifier."""

from pathlib import Path

import pytest

from scripts.verify_witness_preregistration import (
    DEFAULT_MANIFEST,
    EXPECTED_ARTIFACT_PATHS,
    EXPECTED_MANIFEST_SHA256,
    EXPECTED_METADATA,
    _parse_manifest,
    _parse_manifest_content,
    verify,
)

EXPECTED_COMMIT = "39bb8f4894f224ff37af62060812de7e68fbc2ea"
EXPECTED_REPOSITORY = "CULPRITCHAOS/MCP-Sentinel"
EXPECTED_BRANCH = "experiment/witness-boundary-contracts-v0"
EXPECTED_PATHS = {
    "docs/WITNESS_BOUNDARY_CONTRACTS_EXPERIMENT_V0_1.md",
    "contracts/boundary-contracts-v0.1.yaml",
    "fixtures/witness/scenarios-v0.1.json",
    "docs/WITNESS_IMPLEMENTATION_CHECKLIST_V0_1.md",
}


def _manifest_text() -> str:
    return DEFAULT_MANIFEST.read_text(encoding="utf-8")


def _write_manifest(tmp_path: Path, content: str) -> Path:
    manifest_path = tmp_path / "preregistration-digest.txt"
    manifest_path.write_text(content, encoding="utf-8")
    return manifest_path


def test_manifest_records_frozen_commit_and_artifacts() -> None:
    manifest = _parse_manifest(DEFAULT_MANIFEST)

    assert manifest.starting_commit == EXPECTED_COMMIT
    assert {path for _, path in manifest.artifacts} == EXPECTED_PATHS
    assert EXPECTED_ARTIFACT_PATHS == EXPECTED_PATHS
    assert EXPECTED_METADATA["starting_commit"] == EXPECTED_COMMIT
    assert EXPECTED_METADATA["repository"] == EXPECTED_REPOSITORY
    assert EXPECTED_METADATA["branch"] == EXPECTED_BRANCH
    assert len(EXPECTED_MANIFEST_SHA256) == 64


def test_repository_matches_preregistration_manifest() -> None:
    assert verify(DEFAULT_MANIFEST) == []


def test_artifact_removal_is_rejected() -> None:
    lines = _manifest_text().splitlines()
    artifact_lines = [line for line in lines if line.startswith("artifact ")]
    reduced = [line for line in lines if not line.startswith("artifact ")]
    reduced.extend(artifact_lines[:-1])

    with pytest.raises(ValueError, match="artifact path set mismatch"):
        _parse_manifest_content("\n".join(reduced))


def test_artifact_substitution_is_rejected() -> None:
    substituted = _manifest_text().replace(
        "docs/WITNESS_IMPLEMENTATION_CHECKLIST_V0_1.md",
        "docs/SUBSTITUTED.md",
    )

    with pytest.raises(ValueError, match="artifact path set mismatch"):
        _parse_manifest_content(substituted)


def test_artifact_addition_is_rejected() -> None:
    added = _manifest_text() + f"\nartifact {'0' * 64}  docs/EXTRA.md\n"

    with pytest.raises(ValueError, match="artifact path set mismatch"):
        _parse_manifest_content(added)


def test_duplicate_artifact_path_is_rejected() -> None:
    artifact_line = next(
        line for line in _manifest_text().splitlines() if line.startswith("artifact ")
    )
    duplicated = _manifest_text() + f"\n{artifact_line}\n"

    with pytest.raises(ValueError, match="duplicate artifact path"):
        _parse_manifest_content(duplicated)


def test_starting_commit_change_is_rejected() -> None:
    changed = _manifest_text().replace(EXPECTED_COMMIT, "0" * 40)

    with pytest.raises(ValueError, match="metadata starting_commit mismatch"):
        _parse_manifest_content(changed)


@pytest.mark.parametrize(
    ("key", "replacement"),
    [
        ("repository", "attacker/other-repository"),
        ("branch", "attacker/other-branch"),
    ],
)
def test_repository_or_branch_change_is_rejected(
    key: str,
    replacement: str,
) -> None:
    expected = EXPECTED_METADATA[key]
    changed = _manifest_text().replace(f"{key}={expected}", f"{key}={replacement}")

    with pytest.raises(ValueError, match=f"metadata {key} mismatch"):
        _parse_manifest_content(changed)


def test_manifest_byte_change_is_rejected(tmp_path: Path) -> None:
    manifest_path = _write_manifest(tmp_path, _manifest_text() + "\n# changed\n")

    errors = verify(manifest_path)

    assert any("manifest checkpoint mismatch" in error for error in errors)


def test_duplicate_metadata_key_is_rejected() -> None:
    duplicated = _manifest_text() + "\nrepository=CULPRITCHAOS/MCP-Sentinel\n"

    with pytest.raises(ValueError, match="duplicate metadata key"):
        _parse_manifest_content(duplicated)


def test_unknown_metadata_key_is_rejected() -> None:
    changed = _manifest_text() + "\nunknown_key=value\n"

    with pytest.raises(ValueError, match="unknown metadata key"):
        _parse_manifest_content(changed)


def test_tampered_digest_is_rejected(tmp_path: Path) -> None:
    original = _manifest_text()
    first_digest = _parse_manifest(DEFAULT_MANIFEST).artifacts[0][0]
    tampered = original.replace(first_digest, "0" * 64, 1)
    manifest_path = _write_manifest(tmp_path, tampered)

    errors = verify(manifest_path)

    assert any("manifest checkpoint mismatch" in error for error in errors)
