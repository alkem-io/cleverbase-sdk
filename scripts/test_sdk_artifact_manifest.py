"""Contract tests for the release artifact digest manifest."""

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING

import pytest

from sdk_artifact_manifest import ManifestError, create_manifest, verify_manifest

if TYPE_CHECKING:
    from pathlib import Path

VERSION = "0.3.3"
TAG = f"bindings/go/v{VERSION}"
COMMIT = "a" * 40


def expected_artifact_names(version: str = VERSION) -> set[str]:
    """Return the fixed public artifacts assembled for one SDK release."""
    native = {
        f"cleverbase-ffi-v{version}-{platform}.tar.gz"
        for platform in (
            "linux-amd64",
            "linux-arm64",
            "darwin-amd64",
            "darwin-arm64",
        )
    }
    return (
        native
        | {f"{name}.sha256" for name in native}
        | {
            f"alkemio_cleverbase_sdk-{version}-cp39-abi3-manylinux_2_28_x86_64.whl",
            f"alkemio_cleverbase_sdk-{version}-cp39-abi3-manylinux_2_28_aarch64.whl",
            f"alkemio_cleverbase_sdk-{version}-cp39-abi3-macosx_11_0_x86_64.whl",
            f"alkemio_cleverbase_sdk-{version}-cp39-abi3-macosx_11_0_arm64.whl",
            f"alkemio_cleverbase_sdk-{version}.tar.gz",
            f"alkemio-cleverbase-sdk-{version}.tgz",
        }
    )


def write_release_artifacts(directory: Path) -> None:
    """Create a complete deterministic release inventory for manifest tests."""
    directory.mkdir()
    for name in expected_artifact_names():
        (directory / name).write_bytes(name.encode())


def test_manifest_binds_tag_commit_and_artifact_bytes(tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    write_release_artifacts(artifacts)
    manifest = tmp_path / "sdk-artifacts.json"

    create_manifest(artifacts, manifest, VERSION, TAG, COMMIT)

    parsed = json.loads(manifest.read_text(encoding="utf-8"))
    assert parsed["schema_version"] == 1
    assert parsed["version"] == VERSION
    assert parsed["tag"] == TAG
    assert parsed["commit"] == COMMIT
    assert set(parsed["artifacts"]) == expected_artifact_names()
    verify_manifest(artifacts, manifest, VERSION, TAG, COMMIT)


def test_manifest_rejects_tampering_or_wrong_release_identity(tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    write_release_artifacts(artifacts)
    manifest = tmp_path / "sdk-artifacts.json"
    create_manifest(artifacts, manifest, VERSION, TAG, COMMIT)

    artifact = artifacts / f"alkemio_cleverbase_sdk-{VERSION}.tar.gz"
    original = artifact.read_bytes()
    artifact.write_bytes(b"tampered")
    with pytest.raises(ManifestError, match="digest mismatch"):
        verify_manifest(artifacts, manifest, VERSION, TAG, COMMIT)

    artifact.write_bytes(original)
    with pytest.raises(ManifestError, match="tag mismatch"):
        verify_manifest(artifacts, manifest, VERSION, "bindings/go/v0.3.4", COMMIT)
    with pytest.raises(ManifestError, match="commit mismatch"):
        verify_manifest(artifacts, manifest, VERSION, TAG, "c" * 40)
    with pytest.raises(ManifestError, match="version mismatch"):
        verify_manifest(artifacts, manifest, "0.3.4", TAG, COMMIT)


@pytest.mark.parametrize("change", ["missing", "extra"])
def test_manifest_create_rejects_incomplete_or_extra_inventory(
    tmp_path: Path,
    change: str,
) -> None:
    artifacts = tmp_path / "artifacts"
    write_release_artifacts(artifacts)
    if change == "missing":
        (artifacts / sorted(expected_artifact_names())[0]).unlink()
    else:
        (artifacts / "unexpected-private.txt").write_bytes(b"private")

    with pytest.raises(ManifestError, match="artifact set mismatch"):
        create_manifest(artifacts, tmp_path / "sdk-artifacts.json", VERSION, TAG, COMMIT)


@pytest.mark.parametrize("change", ["missing", "extra"])
def test_manifest_verify_rejects_self_consistent_poisoned_inventory(
    tmp_path: Path,
    change: str,
) -> None:
    artifacts = tmp_path / "artifacts"
    write_release_artifacts(artifacts)
    manifest = tmp_path / "sdk-artifacts.json"
    create_manifest(artifacts, manifest, VERSION, TAG, COMMIT)
    payload = json.loads(manifest.read_text(encoding="utf-8"))

    if change == "missing":
        name = sorted(expected_artifact_names())[0]
        (artifacts / name).unlink()
        del payload["artifacts"][name]
    else:
        name = "unexpected-private.txt"
        content = b"private"
        (artifacts / name).write_bytes(content)
        payload["artifacts"][name] = {
            "sha256": hashlib.sha256(content).hexdigest(),
            "size": len(content),
        }
    manifest.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ManifestError, match="artifact set mismatch"):
        verify_manifest(artifacts, manifest, VERSION, TAG, COMMIT)


def test_manifest_rejects_nested_or_empty_artifact_sets(tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    manifest = tmp_path / "sdk-artifacts.json"
    with pytest.raises(ManifestError, match="artifact set mismatch"):
        create_manifest(artifacts, manifest, "0.3.3", "bindings/go/v0.3.3", "d" * 40)

    nested = artifacts / "nested"
    nested.mkdir()
    (nested / "secret").write_bytes(b"secret")
    with pytest.raises(ManifestError, match="top-level regular files"):
        create_manifest(artifacts, manifest, "0.3.3", "bindings/go/v0.3.3", "d" * 40)
