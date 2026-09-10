#!/usr/bin/env python3
"""Create and verify the immutable SDK release artifact digest manifest."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
ARGUMENT_COUNT = 7
NATIVE_PLATFORMS = (
    "linux-amd64",
    "linux-arm64",
    "darwin-amd64",
    "darwin-arm64",
)
PYTHON_WHEEL_TAGS = (
    "cp39-abi3-manylinux_2_28_x86_64",
    "cp39-abi3-manylinux_2_28_aarch64",
    "cp39-abi3-macosx_11_0_x86_64",
    "cp39-abi3-macosx_11_0_arm64",
)


class ManifestError(ValueError):
    """Release identity or artifact bytes do not match the manifest."""


def _require(condition: bool, message: str) -> None:  # noqa: FBT001
    if not condition:
        raise ManifestError(message)


def _digest(path: Path) -> dict[str, Any]:
    hasher = hashlib.sha256()
    with path.open("rb") as artifact:
        for block in iter(lambda: artifact.read(1024 * 1024), b""):
            hasher.update(block)
    return {"sha256": hasher.hexdigest(), "size": path.stat().st_size}


def _expected_artifact_names(version: str) -> set[str]:
    native = {f"cleverbase-ffi-v{version}-{platform}.tar.gz" for platform in NATIVE_PLATFORMS}
    return (
        native
        | {f"{name}.sha256" for name in native}
        | {f"alkemio_cleverbase_sdk-{version}-{tag}.whl" for tag in PYTHON_WHEEL_TAGS}
        | {
            f"alkemio_cleverbase_sdk-{version}.tar.gz",
            f"alkemio-cleverbase-sdk-{version}.tgz",
        }
    )


def _artifacts(
    directory: Path,
    manifest: Path,
    version: str,
) -> dict[str, dict[str, Any]]:
    _require(directory.is_dir(), f"artifact directory not found: {directory}")
    entries = sorted(directory.iterdir(), key=lambda path: path.name)
    other_entries = [entry for entry in entries if entry.resolve() != manifest.resolve()]
    _require(
        all(entry.is_file() and not entry.is_symlink() for entry in other_entries),
        "release artifacts must be top-level regular files",
    )
    actual = {entry.name for entry in other_entries}
    expected = _expected_artifact_names(version)
    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)
    _require(
        not missing and not unexpected,
        f"artifact set mismatch: missing={missing}, unexpected={unexpected}",
    )
    return {entry.name: _digest(entry) for entry in other_entries}


def create_manifest(
    directory: Path,
    manifest: Path,
    version: str,
    tag: str,
    commit: str,
) -> None:
    """Hash a complete top-level artifact set and bind it to one tag and commit."""
    _require(SEMVER.fullmatch(version) is not None, "invalid SDK version")
    _require(tag == f"bindings/go/v{version}", "tag does not match SDK version")
    _require(COMMIT.fullmatch(commit) is not None, "invalid commit SHA")
    payload = {
        "schema_version": 1,
        "version": version,
        "tag": tag,
        "commit": commit,
        "artifacts": _artifacts(directory, manifest, version),
    }
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(
        json.dumps(payload, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )


def verify_manifest(
    directory: Path,
    manifest: Path,
    expected_version: str,
    tag: str,
    commit: str,
) -> None:
    """Fail unless release identity and every artifact byte match exactly."""
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    _require(payload.get("schema_version") == 1, "manifest schema mismatch")
    _require(payload.get("tag") == tag, "manifest tag mismatch")
    _require(payload.get("commit") == commit, "manifest commit mismatch")
    version = payload.get("version")
    _require(version == expected_version, "manifest version mismatch")
    _require(tag == f"bindings/go/v{expected_version}", "manifest version mismatch")
    recorded = payload.get("artifacts")
    _require(isinstance(recorded, dict), "manifest artifact set is invalid")
    current = _artifacts(directory, manifest, expected_version)
    _require(set(recorded) == set(current), "manifest artifact set mismatch")
    for name, expected in recorded.items():
        _require(expected == current[name], f"artifact digest mismatch: {name}")


def main(argv: list[str]) -> int:
    """Run create or verify from CI."""
    if len(argv) != ARGUMENT_COUNT or argv[1] not in {"create", "verify"}:
        sys.stderr.write(
            "usage: sdk_artifact_manifest.py <create|verify> "
            "<artifact-dir> <manifest> <version> <tag> <commit>\n"
        )
        return 2
    command, directory, manifest, version, tag, commit = argv[1:]
    try:
        if command == "create":
            create_manifest(Path(directory), Path(manifest), version, tag, commit)
        else:
            verify_manifest(Path(directory), Path(manifest), version, tag, commit)
    except (ManifestError, OSError, json.JSONDecodeError, KeyError) as error:
        sys.stderr.write(f"SDK artifact manifest failed: {error}\n")
        return 1
    sys.stdout.write(f"SDK artifact manifest {command}: ok\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
