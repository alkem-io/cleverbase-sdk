"""Tests for fail-closed PyPI and npm release reconciliation."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import time
import urllib.error
from typing import TYPE_CHECKING

import pytest

import release_registry
from release_registry import (
    RegistryError,
    RegistryVisibilityPendingError,
    npm_status,
    pypi_provenance_valid,
    pypi_status,
)

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
    responses = iter(
        [
            RegistryVisibilityPendingError("HTTP 404"),
            RegistryVisibilityPendingError("HTTP 429"),
            RegistryVisibilityPendingError("HTTP 503"),
            payload,
        ],
    )
    sleeps: list[int] = []

    def metadata(_version: str, *, allow_missing: bool) -> dict[str, object] | None:
        assert not allow_missing
        response = next(responses)
        if isinstance(response, Exception):
            raise response
        return response

    monkeypatch.setattr(release_registry, "_pypi_metadata", metadata)
    monkeypatch.setattr(release_registry, "_verify_pypi_provenance", lambda *_args: None)
    monkeypatch.setattr(time, "sleep", sleeps.append)

    result = release_registry.main(
        ["release_registry.py", "pypi", "verify", str(tmp_path), "0.3.3"],
    )

    assert result == 0
    assert sleeps == [2, 5, 10]


def test_verify_exhausts_exactly_four_transient_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wheel = tmp_path / "alkemio_cleverbase_sdk-0.3.3-cp39-abi3-manylinux_2_28_x86_64.whl"
    sdist = tmp_path / "alkemio_cleverbase_sdk-0.3.3.tar.gz"
    wheel.write_bytes(b"wheel")
    sdist.write_bytes(b"sdist")
    calls = 0
    sleeps: list[int] = []

    def pending(_version: str, *, allow_missing: bool) -> None:
        nonlocal calls
        assert not allow_missing
        calls += 1
        message = "HTTP 503"
        raise RegistryVisibilityPendingError(message)

    monkeypatch.setattr(release_registry, "_pypi_metadata", pending)
    monkeypatch.setattr(time, "sleep", sleeps.append)

    result = release_registry.main(
        ["release_registry.py", "pypi", "verify", str(tmp_path), "0.3.3"],
    )

    assert result == 1
    assert calls == 4
    assert sleeps == [2, 5, 10]


def test_preflight_and_semantic_failures_are_never_retried(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wheel = tmp_path / "alkemio_cleverbase_sdk-0.3.3-cp39-abi3-manylinux_2_28_x86_64.whl"
    sdist = tmp_path / "alkemio_cleverbase_sdk-0.3.3.tar.gz"
    wheel.write_bytes(b"wheel")
    sdist.write_bytes(b"sdist")
    calls = 0
    sleeps: list[int] = []

    def missing(_version: str, *, allow_missing: bool) -> None:
        nonlocal calls
        assert allow_missing
        calls += 1

    monkeypatch.setattr(release_registry, "_pypi_metadata", missing)
    monkeypatch.setattr(time, "sleep", sleeps.append)
    assert (
        release_registry.main(
            ["release_registry.py", "pypi", "preflight", str(tmp_path), "0.3.3"],
        )
        == 0
    )
    assert calls == 1
    assert sleeps == []

    def permanent(_version: str, *, allow_missing: bool) -> None:
        nonlocal calls
        assert not allow_missing
        calls += 1
        message = "digest mismatch"
        raise RegistryError(message)

    monkeypatch.setattr(release_registry, "_pypi_metadata", permanent)
    assert (
        release_registry.main(
            ["release_registry.py", "pypi", "verify", str(tmp_path), "0.3.3"],
        )
        == 1
    )
    assert calls == 2
    assert sleeps == []


@pytest.mark.parametrize("status", [404, 429, 500, 503])
def test_http_boundary_classifies_only_transient_statuses(
    status: int,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    error = urllib.error.HTTPError("https://pypi.org/test", status, "pending", None, None)

    def fail(*_args: object, **_kwargs: object) -> None:
        raise error

    monkeypatch.setattr(release_registry.urllib.request, "urlopen", fail)

    with pytest.raises(RegistryVisibilityPendingError):
        release_registry._http_json("https://pypi.org/test")  # noqa: SLF001


@pytest.mark.parametrize(
    "error",
    [TimeoutError("direct timeout"), urllib.error.URLError(TimeoutError("wrapped timeout"))],
    ids=["direct", "url-error"],
)
def test_http_boundary_classifies_only_actual_timeouts_as_transient(
    error: Exception,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(*_args: object, **_kwargs: object) -> None:
        raise error

    monkeypatch.setattr(release_registry.urllib.request, "urlopen", fail)

    with pytest.raises(RegistryVisibilityPendingError):
        release_registry._http_json("https://pypi.org/test")  # noqa: SLF001


@pytest.mark.parametrize(
    "error",
    [
        urllib.error.HTTPError("https://pypi.org/test", 400, "bad request", None, None),
        urllib.error.URLError(OSError("certificate failure")),
    ],
    ids=["http-400", "url-error"],
)
def test_http_boundary_keeps_permanent_failures_non_retryable(
    error: Exception,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(*_args: object, **_kwargs: object) -> None:
        raise error

    monkeypatch.setattr(release_registry.urllib.request, "urlopen", fail)

    with pytest.raises(RegistryError) as caught:
        release_registry._http_json("https://pypi.org/test")  # noqa: SLF001
    assert not isinstance(caught.value, RegistryVisibilityPendingError)


def test_http_boundary_keeps_malformed_json_non_retryable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        release_registry.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: io.BytesIO(b"{"),
    )

    with pytest.raises(RegistryError) as caught:
        release_registry._http_json("https://pypi.org/test")  # noqa: SLF001
    assert not isinstance(caught.value, RegistryVisibilityPendingError)
    assert isinstance(caught.value.__cause__, json.JSONDecodeError)


def test_verify_does_not_retry_digest_or_provenance_mismatch(
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
            {"filename": wheel.name, "digests": {"sha256": "0" * 64}},
            {"filename": sdist.name, "digests": {"sha256": hashlib.sha256(b"sdist").hexdigest()}},
        ],
    }
    metadata_calls = 0
    sleeps: list[int] = []

    def metadata(_version: str, *, allow_missing: bool) -> dict[str, object]:
        nonlocal metadata_calls
        assert not allow_missing
        metadata_calls += 1
        return payload

    monkeypatch.setattr(release_registry, "_pypi_metadata", metadata)
    monkeypatch.setattr(time, "sleep", sleeps.append)
    assert (
        release_registry.main(
            ["release_registry.py", "pypi", "verify", str(tmp_path), "0.3.3"],
        )
        == 1
    )
    assert metadata_calls == 1
    assert sleeps == []

    payload["urls"][0]["digests"]["sha256"] = hashlib.sha256(b"wheel").hexdigest()
    provenance_calls = 0

    def invalid_provenance(*_args: object) -> None:
        nonlocal provenance_calls
        provenance_calls += 1
        message = "PyPI provenance is missing"
        raise RegistryError(message)

    monkeypatch.setattr(release_registry, "_verify_pypi_provenance", invalid_provenance)
    assert (
        release_registry.main(
            ["release_registry.py", "pypi", "verify", str(tmp_path), "0.3.3"],
        )
        == 1
    )
    assert metadata_calls == 2
    assert provenance_calls == 1
    assert sleeps == []
