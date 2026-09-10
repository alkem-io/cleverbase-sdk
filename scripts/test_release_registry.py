"""Tests for fail-closed PyPI and npm release reconciliation."""

from __future__ import annotations

import base64
import hashlib
import time
from typing import TYPE_CHECKING

import pytest

import release_registry
from release_registry import RegistryError, npm_status, pypi_provenance_valid, pypi_status

if TYPE_CHECKING:
    from pathlib import Path


def test_pypi_allows_only_missing_or_digest_identical_files(tmp_path: Path) -> None:
    wheel = tmp_path / "alkemio_cleverbase_sdk-0.3.3-cp39-abi3-manylinux_2_28_x86_64.whl"
    sdist = tmp_path / "alkemio_cleverbase_sdk-0.3.3.tar.gz"
    wheel.write_bytes(b"wheel")
    sdist.write_bytes(b"sdist")

    missing = pypi_status(tmp_path, "0.3.3", None)
    assert missing == "missing"

    payload = {
        "info": {"name": "alkemio-cleverbase-sdk", "version": "0.3.3"},
        "urls": [
            {"filename": wheel.name, "digests": {"sha256": hashlib.sha256(b"wheel").hexdigest()}},
            {"filename": sdist.name, "digests": {"sha256": hashlib.sha256(b"sdist").hexdigest()}},
        ],
    }
    assert pypi_status(tmp_path, "0.3.3", payload) == "present"

    payload["urls"][0]["digests"]["sha256"] = "0" * 64
    with pytest.raises(RegistryError, match="PyPI digest mismatch"):
        pypi_status(tmp_path, "0.3.3", payload)


def test_pypi_partial_release_is_safe_but_extra_file_is_not(tmp_path: Path) -> None:
    wheel = tmp_path / "alkemio_cleverbase_sdk-0.3.3-cp39-abi3-manylinux_2_28_x86_64.whl"
    sdist = tmp_path / "alkemio_cleverbase_sdk-0.3.3.tar.gz"
    wheel.write_bytes(b"wheel")
    sdist.write_bytes(b"sdist")
    partial = {
        "info": {"name": "alkemio-cleverbase-sdk", "version": "0.3.3"},
        "urls": [
            {"filename": wheel.name, "digests": {"sha256": hashlib.sha256(b"wheel").hexdigest()}},
        ],
    }
    assert pypi_status(tmp_path, "0.3.3", partial) == "missing"

    partial["urls"].append(
        {"filename": "unexpected.whl", "digests": {"sha256": "0" * 64}},
    )
    with pytest.raises(RegistryError, match="unexpected PyPI files"):
        pypi_status(tmp_path, "0.3.3", partial)


def test_npm_requires_exact_tarball_identity_and_provenance(tmp_path: Path) -> None:
    tarball = tmp_path / "alkemio-cleverbase-sdk-0.3.3.tgz"
    tarball.write_bytes(b"node")
    digest = base64.b64encode(hashlib.sha512(b"node").digest()).decode()
    payload = {
        "name": "@alkemio/cleverbase-sdk",
        "version": "0.3.3",
        "dist": {
            "integrity": f"sha512-{digest}",
            "attestations": {
                "url": "https://registry.npmjs.org/-/npm/v1/attestations/example",
                "provenance": {"predicateType": "https://slsa.dev/provenance/v1"},
            },
        },
    }

    assert npm_status(tarball, "0.3.3", None, require_provenance=False) == "missing"
    assert npm_status(tarball, "0.3.3", payload, require_provenance=True) == "present"

    payload["dist"]["integrity"] = "sha512-invalid"
    with pytest.raises(RegistryError, match="npm digest mismatch"):
        npm_status(tarball, "0.3.3", payload, require_provenance=False)

    payload["dist"]["integrity"] = f"sha512-{digest}"
    payload["dist"].pop("attestations")
    with pytest.raises(RegistryError, match="npm provenance"):
        npm_status(tarball, "0.3.3", payload, require_provenance=True)


def test_pypi_provenance_matches_the_integrity_api_shape() -> None:
    assert pypi_provenance_valid({"attestation_bundles": [{"attestations": [{}]}]})
    assert not pypi_provenance_valid({"attestation_bundles": []})
    assert not pypi_provenance_valid({"version": 1})


def test_verify_retries_transient_registry_visibility_with_fixed_backoff(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wheel = tmp_path / "alkemio_cleverbase_sdk-0.3.3-cp39-abi3-manylinux_2_28_x86_64.whl"
    sdist = tmp_path / "alkemio_cleverbase_sdk-0.3.3.tar.gz"
    wheel.write_bytes(b"wheel")
    sdist.write_bytes(b"sdist")
    payload = {
        "info": {"name": "alkemio-cleverbase-sdk", "version": "0.3.3"},
        "urls": [
            {"filename": wheel.name, "digests": {"sha256": hashlib.sha256(b"wheel").hexdigest()}},
            {"filename": sdist.name, "digests": {"sha256": hashlib.sha256(b"sdist").hexdigest()}},
        ],
    }
    responses = iter([None, None, None, payload])
    sleeps: list[int] = []
    monkeypatch.setattr(release_registry, "_pypi_metadata", lambda _version: next(responses))
    monkeypatch.setattr(release_registry, "_verify_pypi_provenance", lambda *_args: None)
    monkeypatch.setattr(time, "sleep", sleeps.append)

    result = release_registry.main(
        ["release_registry.py", "pypi", "verify", str(tmp_path), "0.3.3"],
    )

    assert result == 0
    assert sleeps == [2, 5, 10]
