"""Verify the frozen WITNESS v0.1 preregistration artifacts.

The manifest hashes Git blob bytes at the recorded starting commit. This avoids
platform-specific line-ending changes while still detecting later committed,
staged, or unstaged changes to any frozen artifact.
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
DEFAULT_MANIFEST = ROOT / "results" / "witness-v0.1" / "preregistration-digest.txt"
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


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


def _parse_manifest(path: Path) -> Manifest:
    fields: dict[str, str] = {}
    artifacts: list[tuple[str, str]] = []

    lines = path.read_text(encoding="utf-8").splitlines()
    for line_number, raw_line in enumerate(lines, 1):
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
            artifacts.append((digest, artifact_path))
            continue
        if "=" not in line:
            raise ValueError(f"invalid manifest line {line_number}")
        key, value = line.split("=", 1)
        fields[key] = value

    commit = fields.get("starting_commit", "")
    if not COMMIT_RE.fullmatch(commit):
        raise ValueError("starting_commit must be a full lowercase Git SHA-1")
    if fields.get("hash_algorithm") != "sha256":
        raise ValueError("hash_algorithm must be sha256")
    if fields.get("hash_domain") != "git_blob_bytes_at_starting_commit":
        raise ValueError("unexpected hash_domain")
    if not artifacts:
        raise ValueError("manifest contains no artifacts")
    if len({path for _, path in artifacts}) != len(artifacts):
        raise ValueError("manifest contains duplicate artifact paths")

    return Manifest(commit, tuple(artifacts))


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
    manifest = _parse_manifest(manifest_path)
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
    paths = tuple(path for _, path in manifest.artifacts)

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

    print("PASS: WITNESS v0.1 preregistration artifacts match the frozen manifest")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
