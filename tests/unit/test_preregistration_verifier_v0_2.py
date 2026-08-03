"""Tests for the WITNESS v0.2 preregistration verifier."""

import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

import scripts.verify_witness_preregistration_v0_2 as verifier
from scripts.verify_witness_preregistration_v0_2 import (
    DEFAULT_MANIFEST,
    EXPECTED_ARTIFACT_PATHS,
    EXPECTED_MANIFEST_SHA256,
    EXPECTED_METADATA,
    MANIFEST_PATH,
    _parse_manifest,
    _parse_manifest_content,
    verify,
)

EXPECTED_COMMIT = "68dc76682bc7716207645b0fb3fa7702a384b3f6"
EXPECTED_SOURCE_BASE = "903d4d3910f887a389ef40a4ca90be6ea0168d34"
EXPECTED_REPOSITORY = "CULPRITCHAOS/MCP-Sentinel"
EXPECTED_BRANCH = "experiment/witness-boundary-contracts-v0.2"
EXPECTED_PATHS = {
    "docs/WITNESS_BOUNDARY_CONTRACTS_EXPERIMENT_V0_2.md",
    "contracts/boundary-contracts-v0.2.yaml",
    "fixtures/witness/scenarios-v0.2.json",
    "docs/WITNESS_IMPLEMENTATION_CHECKLIST_V0_2.md",
    "docs/WITNESS_CLAIMS_MATRIX_V0_2.md",
    "docs/WITNESS_DEVIATION_DEV_WIT_001.md",
}


def _manifest_text() -> str:
    return DEFAULT_MANIFEST.read_text(encoding="utf-8")


def _write_manifest(tmp_path: Path, content: str) -> Path:
    manifest_path = tmp_path / "preregistration-digest.txt"
    manifest_path.write_text(content, encoding="utf-8")
    return manifest_path


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
    )


def _append_drift(repo: Path, relative_path: str) -> None:
    path = repo / relative_path
    path.write_bytes(path.read_bytes() + b"\nWITNESS isolated drift test\n")


@pytest.fixture
def isolated_git_repo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[Path]:
    source_root = verifier.ROOT
    repo = tmp_path / "isolated-repo"
    subprocess.run(
        [
            "git",
            "-c",
            "core.autocrlf=false",
            "clone",
            "--no-local",
            "--quiet",
            str(source_root),
            str(repo),
        ],
        check=True,
        capture_output=True,
    )
    _git(repo, "config", "user.name", "WITNESS Test")
    _git(repo, "config", "user.email", "witness-test@example.invalid")
    _git(repo, "config", "core.autocrlf", "false")
    monkeypatch.setattr(verifier, "ROOT", repo)
    yield repo


def _external_manifest_copy(tmp_path: Path, repo: Path) -> Path:
    destination = tmp_path / "pristine-preregistration-digest.txt"
    shutil.copyfile(repo / MANIFEST_PATH, destination)
    return destination


def test_manifest_records_frozen_commit_and_artifacts() -> None:
    manifest = _parse_manifest(DEFAULT_MANIFEST)

    assert manifest.starting_commit == EXPECTED_COMMIT
    assert {path for _, path in manifest.artifacts} == EXPECTED_PATHS
    assert EXPECTED_ARTIFACT_PATHS == EXPECTED_PATHS
    assert EXPECTED_METADATA["starting_commit"] == EXPECTED_COMMIT
    assert EXPECTED_METADATA["repository"] == EXPECTED_REPOSITORY
    assert EXPECTED_METADATA["branch"] == EXPECTED_BRANCH
    assert EXPECTED_METADATA["source_base_commit"] == EXPECTED_SOURCE_BASE
    assert EXPECTED_METADATA["deviation_id"] == "DEV-WIT-001"
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
        "docs/WITNESS_IMPLEMENTATION_CHECKLIST_V0_2.md",
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
        ("source_base_commit", "0" * 40),
        ("deviation_id", "DEV-WIT-999"),
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


@pytest.mark.parametrize("artifact_path", sorted(EXPECTED_PATHS))
def test_committed_drift_is_detected_for_each_frozen_artifact(
    isolated_git_repo: Path,
    artifact_path: str,
) -> None:
    _append_drift(isolated_git_repo, artifact_path)
    _git(isolated_git_repo, "add", "--", artifact_path)
    _git(isolated_git_repo, "commit", "-m", f"drift {artifact_path}")

    errors = verifier.verify(isolated_git_repo / MANIFEST_PATH)

    assert any(f"committed drift for {artifact_path}" in error for error in errors)


def test_staged_frozen_artifact_drift_is_detected(isolated_git_repo: Path) -> None:
    artifact_path = "contracts/boundary-contracts-v0.2.yaml"
    _append_drift(isolated_git_repo, artifact_path)
    _git(isolated_git_repo, "add", "--", artifact_path)

    errors = verifier.verify(isolated_git_repo / MANIFEST_PATH)

    assert "staged changes exist in frozen artifacts" in errors


def test_unstaged_frozen_artifact_drift_is_detected(isolated_git_repo: Path) -> None:
    artifact_path = "fixtures/witness/scenarios-v0.2.json"
    _append_drift(isolated_git_repo, artifact_path)

    errors = verifier.verify(isolated_git_repo / MANIFEST_PATH)

    assert "unstaged changes exist in frozen artifacts" in errors


@pytest.mark.parametrize(
    ("mode", "expected_error"),
    [
        ("delete", "manifest missing at HEAD"),
        ("modify", "committed manifest drift"),
    ],
)
def test_committed_manifest_deletion_or_drift_is_detected(
    tmp_path: Path,
    isolated_git_repo: Path,
    mode: str,
    expected_error: str,
) -> None:
    pristine_manifest = _external_manifest_copy(tmp_path, isolated_git_repo)
    manifest = isolated_git_repo / MANIFEST_PATH
    if mode == "delete":
        manifest.unlink()
        _git(isolated_git_repo, "add", "-u", "--", MANIFEST_PATH)
    else:
        _append_drift(isolated_git_repo, MANIFEST_PATH)
        _git(isolated_git_repo, "add", "--", MANIFEST_PATH)
    _git(isolated_git_repo, "commit", "-m", f"{mode} manifest")

    errors = verifier.verify(pristine_manifest)

    assert any(expected_error in error for error in errors)


def test_staged_manifest_drift_is_detected(
    tmp_path: Path,
    isolated_git_repo: Path,
) -> None:
    pristine_manifest = _external_manifest_copy(tmp_path, isolated_git_repo)
    _append_drift(isolated_git_repo, MANIFEST_PATH)
    _git(isolated_git_repo, "add", "--", MANIFEST_PATH)

    errors = verifier.verify(pristine_manifest)

    assert "staged changes exist in frozen artifacts" in errors


def test_unstaged_manifest_drift_is_detected(
    tmp_path: Path,
    isolated_git_repo: Path,
) -> None:
    pristine_manifest = _external_manifest_copy(tmp_path, isolated_git_repo)
    _append_drift(isolated_git_repo, MANIFEST_PATH)

    errors = verifier.verify(pristine_manifest)

    assert "unstaged changes exist in frozen artifacts" in errors
