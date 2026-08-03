"""Verify the frozen WITNESS v0.2 preregistration revision artifacts.

The manifest hashes Git blob bytes at the recorded starting commit. This avoids
platform-specific line-ending changes while still detecting later committed,
staged, or unstaged changes to any frozen artifact.

The code-pinned manifest digest is an internal consistency check, not an
independently external trust anchor. Git review of the exact verifier commit and
the Linear-recorded checkpoint anchor changes to the verifier and its pins.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = "results/witness-v0.2/preregistration-digest.txt"
DEFAULT_MANIFEST = ROOT / MANIFEST_PATH
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
EXPECTED_MANIFEST_SHA256 = (
    "fbe5e7263104a33fae1908c2c8bea478acf0f21de8b6c5874e1984c8276f8894"
)
EXPECTED_METADATA = {
    "manifest_version": "witness-preregistration-v0.2",
    "deviation_id": "DEV-WIT-001",
    "repository": "CULPRITCHAOS/MCP-Sentinel",
    "branch": "experiment/witness-boundary-contracts-v0.2",
    "source_base_commit": "903d4d3910f887a389ef40a4ca90be6ea0168d34",
    "starting_commit": "68dc76682bc7716207645b0fb3fa7702a384b3f6",
    "hash_algorithm": "sha256",
    "hash_domain": "git_blob_bytes_at_starting_commit",
}
EXPECTED_ARTIFACT_PATHS = frozenset(
    {
        "docs/WITNESS_BOUNDARY_CONTRACTS_EXPERIMENT_V0_2.md",
        "contracts/boundary-contracts-v0.2.yaml",
        "fixtures/witness/scenarios-v0.2.json",
        "docs/WITNESS_IMPLEMENTATION_CHECKLIST_V0_2.md",
        "docs/WITNESS_CLAIMS_MATRIX_V0_2.md",
        "docs/WITNESS_DEVIATION_DEV_WIT_001.md",
    }
)


@dataclass(frozen=True)
class Manifest:
    starting_commit: str
    artifacts: tuple[tuple[str, str], ...]


def _git(*args: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", *args],
        cwd=ROOT,
        check=check,
        capture_output=True,
    )


def _parse_manifest_content(content: str) -> Manifest:
    fields: dict[str, str] = {}
    artifacts: list[tuple[str, str]] = []
    artifact_paths: set[str] = set()

    for line_number, raw_line in enumerate(content.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("artifact "):
            parts = line.split(maxsplit=2)
            if len(parts) != 3:
                raise ValueError(f"invalid artifact line {line_number}")
            digest, artifact_path = parts[1], parts[2]
            if not SHA256_RE.fullmatch(digest):
                raise ValueError(f"invalid SHA-256 on line {line_number}")
            is_absolute = artifact_path.startswith(("/", "\\"))
            if is_absolute or ".." in Path(artifact_path).parts:
                raise ValueError(f"unsafe artifact path on line {line_number}")
            if artifact_path in artifact_paths:
                raise ValueError(f"duplicate artifact path on line {line_number}")
            artifacts.append((digest, artifact_path))
            artifact_paths.add(artifact_path)
            continue
        if "=" not in line:
            raise ValueError(f"invalid manifest line {line_number}")
        key, value = line.split("=", 1)
        if key not in EXPECTED_METADATA:
            raise ValueError(f"unknown metadata key on line {line_number}: {key}")
        if key in fields:
            raise ValueError(f"duplicate metadata key on line {line_number}: {key}")
        fields[key] = value

    missing_keys = EXPECTED_METADATA.keys() - fields.keys()
    if missing_keys:
        missing = ", ".join(sorted(missing_keys))
        raise ValueError(f"missing metadata keys: {missing}")

    for key, expected in EXPECTED_METADATA.items():
        actual = fields[key]
        if actual != expected:
            raise ValueError(
                f"metadata {key} mismatch: expected {expected}, got {actual}"
            )

    commit = fields["starting_commit"]
    if not COMMIT_RE.fullmatch(commit):
        raise ValueError("starting_commit must be a full lowercase Git SHA-1")

    if artifact_paths != EXPECTED_ARTIFACT_PATHS:
        missing_paths = sorted(EXPECTED_ARTIFACT_PATHS - artifact_paths)
        extra_paths = sorted(artifact_paths - EXPECTED_ARTIFACT_PATHS)
        raise ValueError(
            "artifact path set mismatch: "
            f"missing={missing_paths}, extra={extra_paths}"
        )

    return Manifest(commit, tuple(artifacts))


def _canonical_manifest_bytes(path: Path) -> bytes:
    raw = path.read_bytes()
    canonical = raw.replace(b"\r\n", b"\n")
    if b"\r" in canonical:
        raise ValueError("manifest contains unsupported carriage returns")
    return canonical


def _parse_manifest(path: Path) -> Manifest:
    canonical = _canonical_manifest_bytes(path)
    actual_digest = _sha256(canonical)
    if actual_digest != EXPECTED_MANIFEST_SHA256:
        raise ValueError(
            "manifest checkpoint mismatch: "
            f"expected {EXPECTED_MANIFEST_SHA256}, got {actual_digest}"
        )
    return _parse_manifest_content(canonical.decode("utf-8"))


def _blob(commit: str, path: str) -> bytes:
    result = _git("show", f"{commit}:{path}")
    return result.stdout


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _ensure_clean(paths: tuple[str, ...]) -> list[str]:
    errors: list[str] = []
    for label, args in (
        ("unstaged", ("diff", "--quiet", "--", *paths)),
        ("staged", ("diff", "--cached", "--quiet", "--", *paths)),
    ):
        result = _git(*args, check=False)
        if result.returncode == 1:
            errors.append(f"{label} changes exist in frozen artifacts")
        elif result.returncode != 0:
            detail = result.stderr.decode("utf-8", errors="replace").strip()
            errors.append(f"could not inspect {label} changes: {detail}")
    return errors


def verify(manifest_path: Path) -> list[str]:
    try:
        manifest = _parse_manifest(manifest_path)
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        return [f"invalid manifest: {exc}"]
    errors: list[str] = []

    commit_check = _git(
        "cat-file",
        "-e",
        f"{manifest.starting_commit}^{{commit}}",
        check=False,
    )
    if commit_check.returncode != 0:
        return [f"starting commit is unavailable: {manifest.starting_commit}"]

    head = _git("rev-parse", "HEAD").stdout.decode("ascii").strip()
    paths = tuple(path for _, path in manifest.artifacts) + (MANIFEST_PATH,)

    try:
        head_manifest_digest = _sha256(_blob(head, MANIFEST_PATH))
    except subprocess.CalledProcessError:
        errors.append(f"manifest missing at HEAD: {MANIFEST_PATH}")
    else:
        if head_manifest_digest != EXPECTED_MANIFEST_SHA256:
            errors.append(
                "committed manifest drift: "
                f"expected {EXPECTED_MANIFEST_SHA256}, got {head_manifest_digest}"
            )

    for expected, path in manifest.artifacts:
        try:
            frozen_digest = _sha256(_blob(manifest.starting_commit, path))
        except subprocess.CalledProcessError:
            errors.append(f"artifact missing at starting commit: {path}")
            continue
        if frozen_digest != expected:
            message = (
                f"manifest mismatch for {path}: "
                f"expected {expected}, got {frozen_digest}"
            )
            errors.append(message)
            continue

        try:
            head_digest = _sha256(_blob(head, path))
        except subprocess.CalledProcessError:
            errors.append(f"artifact missing at HEAD: {path}")
            continue
        if head_digest != expected:
            errors.append(
                f"committed drift for {path}: frozen {expected}, HEAD {head_digest}"
            )

    errors.extend(_ensure_clean(paths))
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=DEFAULT_MANIFEST,
        help="path to preregistration-digest.txt",
    )
    args = parser.parse_args()

    try:
        errors = verify(args.manifest.resolve())
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if errors:
        for error in errors:
            print(f"FAIL: {error}", file=sys.stderr)
        return 1

    print("PASS: WITNESS v0.2 preregistration artifacts match the frozen manifest")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
