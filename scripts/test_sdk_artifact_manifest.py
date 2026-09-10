"""Contract tests for the release artifact digest manifest."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sdk_artifact_manifest import ManifestError, create_manifest, verify_manifest


def test_manifest_binds_tag_commit_and_artifact_bytes(tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "a.whl").write_bytes(b"python")
    (artifacts / "b.tgz").write_bytes(b"node")
    manifest = tmp_path / "sdk-artifacts.json"

    create_manifest(
        artifacts,
        manifest,
        "0.3.3",
        "bindings/go/v0.3.3",
        "a" * 40,
    )

    parsed = json.loads(manifest.read_text(encoding="utf-8"))
    assert parsed["schema_version"] == 1
    assert parsed["version"] == "0.3.3"
    assert parsed["tag"] == "bindings/go/v0.3.3"
    assert parsed["commit"] == "a" * 40
    assert list(parsed["artifacts"]) == ["a.whl", "b.tgz"]
    verify_manifest(artifacts, manifest, "bindings/go/v0.3.3", "a" * 40)


def test_manifest_rejects_tampering_or_wrong_release_identity(tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "sdk.whl").write_bytes(b"original")
    manifest = tmp_path / "sdk-artifacts.json"
    create_manifest(artifacts, manifest, "0.3.3", "bindings/go/v0.3.3", "b" * 40)

    (artifacts / "sdk.whl").write_bytes(b"tampered")
    with pytest.raises(ManifestError, match="digest mismatch"):
        verify_manifest(artifacts, manifest, "bindings/go/v0.3.3", "b" * 40)

    (artifacts / "sdk.whl").write_bytes(b"original")
    with pytest.raises(ManifestError, match="tag mismatch"):
        verify_manifest(artifacts, manifest, "bindings/go/v0.3.4", "b" * 40)
    with pytest.raises(ManifestError, match="commit mismatch"):
        verify_manifest(artifacts, manifest, "bindings/go/v0.3.3", "c" * 40)


def test_manifest_rejects_nested_or_empty_artifact_sets(tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    manifest = tmp_path / "sdk-artifacts.json"
    with pytest.raises(ManifestError, match="no release artifacts"):
        create_manifest(artifacts, manifest, "0.3.3", "bindings/go/v0.3.3", "d" * 40)

    nested = artifacts / "nested"
    nested.mkdir()
    (nested / "secret").write_bytes(b"secret")
    with pytest.raises(ManifestError, match="top-level regular files"):
        create_manifest(artifacts, manifest, "0.3.3", "bindings/go/v0.3.3", "d" * 40)
