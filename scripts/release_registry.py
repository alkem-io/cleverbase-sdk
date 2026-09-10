#!/usr/bin/env python3
"""Reconcile exact SDK artifacts with PyPI and npm without overwriting bytes."""

from __future__ import annotations

import base64
import hashlib
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


PYPI_PACKAGE = "alkemio-cleverbase-sdk"
NPM_PACKAGE = "@alkemio/cleverbase-sdk"
SLSA_PROVENANCE = "https://slsa.dev/provenance/v1"


class RegistryError(ValueError):
    """Published bytes or provenance differ from the intended release."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RegistryError(message)


def _digest(path: Path, algorithm: str) -> bytes:
    hasher = hashlib.new(algorithm)
    with path.open("rb") as artifact:
        for block in iter(lambda: artifact.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.digest()


def _python_artifacts(directory: Path, version: str) -> dict[str, Path]:
    prefix = f"alkemio_cleverbase_sdk-{version}"
    artifacts = {
        path.name: path
        for path in directory.iterdir()
        if path.is_file()
        and not path.is_symlink()
        and path.name.startswith(prefix)
        and (path.suffix == ".whl" or path.name == f"{prefix}.tar.gz")
    }
    _require(len(artifacts) >= 2, "Python release must contain wheels and an sdist")
    _require(any(name.endswith(".whl") for name in artifacts), "Python release has no wheels")
    _require(f"{prefix}.tar.gz" in artifacts, "Python release has no sdist")
    return artifacts


def pypi_status(directory: Path, version: str, payload: dict[str, Any] | None) -> str:
    """Return missing/present or reject any non-identical partial PyPI release."""
    local = _python_artifacts(directory, version)
    if payload is None:
        return "missing"

    info = payload.get("info")
    _require(isinstance(info, dict), "PyPI metadata is invalid")
    _require(info.get("name") == PYPI_PACKAGE, "PyPI package name mismatch")
    _require(info.get("version") == version, "PyPI package version mismatch")
    urls = payload.get("urls")
    _require(isinstance(urls, list), "PyPI file metadata is invalid")
    remote: dict[str, str] = {}
    for entry in urls:
        _require(isinstance(entry, dict), "PyPI file metadata is invalid")
        filename = entry.get("filename")
        digests = entry.get("digests")
        _require(
            isinstance(filename, str)
            and isinstance(digests, dict)
            and isinstance(digests.get("sha256"), str),
            "PyPI file digest metadata is invalid",
        )
        remote[filename] = digests["sha256"]

    unexpected = sorted(set(remote) - set(local))
    _require(not unexpected, f"unexpected PyPI files: {', '.join(unexpected)}")
    for filename, remote_digest in remote.items():
        local_digest = _digest(local[filename], "sha256").hex()
        _require(local_digest == remote_digest, f"PyPI digest mismatch: {filename}")
    return "present" if set(remote) == set(local) else "missing"


def npm_status(
    tarball: Path,
    version: str,
    payload: dict[str, Any] | None,
    *,
    require_provenance: bool,
) -> str:
    """Return missing/present or reject a non-identical npm package version."""
    _require(tarball.is_file() and not tarball.is_symlink(), "npm tarball is missing")
    expected_name = f"alkemio-cleverbase-sdk-{version}.tgz"
    _require(tarball.name == expected_name, f"npm tarball filename must be {expected_name}")
    if payload is None:
        _require(not require_provenance, "npm release is missing")
        return "missing"

    _require(payload.get("name") == NPM_PACKAGE, "npm package name mismatch")
    _require(payload.get("version") == version, "npm package version mismatch")
    distribution = payload.get("dist")
    _require(isinstance(distribution, dict), "npm distribution metadata is invalid")
    local_integrity = "sha512-" + base64.b64encode(_digest(tarball, "sha512")).decode("ascii")
    _require(distribution.get("integrity") == local_integrity, "npm digest mismatch")

    if require_provenance:
        attestations = distribution.get("attestations")
        _require(isinstance(attestations, dict), "npm provenance is missing")
        provenance = attestations.get("provenance")
        _require(
            isinstance(provenance, dict)
            and provenance.get("predicateType") == SLSA_PROVENANCE
            and isinstance(attestations.get("url"), str)
            and attestations["url"].startswith("https://registry.npmjs.org/"),
            "npm provenance is invalid",
        )
    return "present"


def _http_json(url: str, *, allow_missing: bool = False, accept: str | None = None) -> Any:
    headers = {"User-Agent": "alkemio-cleverbase-sdk-release/1"}
    if accept is not None:
        headers["Accept"] = accept
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        if allow_missing and error.code == 404:
            return None
        raise RegistryError(f"registry request failed with HTTP {error.code}: {url}") from error
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
        raise RegistryError(f"registry request failed: {url}: {error}") from error


def _pypi_metadata(version: str) -> dict[str, Any] | None:
    return _http_json(
        f"https://pypi.org/pypi/{PYPI_PACKAGE}/{version}/json",
        allow_missing=True,
    )


def _npm_metadata(version: str) -> dict[str, Any] | None:
    package = urllib.parse.quote(NPM_PACKAGE, safe="@")
    return _http_json(
        f"https://registry.npmjs.org/{package}/{version}",
        allow_missing=True,
        accept="application/vnd.npm.install-v1+json",
    )


def pypi_provenance_valid(provenance: Any) -> bool:
    """Recognize the current PyPI integrity API's non-empty bundle shape."""
    if not isinstance(provenance, dict):
        return False
    bundles = provenance.get("attestation_bundles")
    return isinstance(bundles, list) and bool(bundles)


def _verify_pypi_provenance(payload: dict[str, Any], version: str) -> None:
    for entry in payload["urls"]:
        filename = urllib.parse.quote(entry["filename"], safe="")
        provenance = _http_json(
            f"https://pypi.org/integrity/{PYPI_PACKAGE}/{version}/{filename}/provenance",
            accept="application/vnd.pypi.integrity.v1+json",
        )
        _require(
            pypi_provenance_valid(provenance),
            f"PyPI provenance is missing: {entry['filename']}",
        )


def main(argv: list[str]) -> int:
    """Run one preflight or post-publication registry check."""
    if len(argv) != 5 or argv[1] not in {"pypi", "npm"} or argv[2] not in {
        "preflight",
        "verify",
    }:
        print(
            "usage: release_registry.py <pypi|npm> <preflight|verify> "
            "<artifact-dir-or-tarball> <version>",
            file=sys.stderr,
        )
        return 2

    registry, operation, artifact, version = argv[1:]
    try:
        if registry == "pypi":
            payload = _pypi_metadata(version)
            status = pypi_status(Path(artifact), version, payload)
            if operation == "verify":
                _require(status == "present" and payload is not None, "PyPI release is incomplete")
                _verify_pypi_provenance(payload, version)
        else:
            payload = _npm_metadata(version)
            status = npm_status(
                Path(artifact),
                version,
                payload,
                require_provenance=operation == "verify",
            )
            if operation == "verify":
                attestations = payload["dist"]["attestations"]
                response = _http_json(attestations["url"])
                _require(isinstance(response, dict) and bool(response), "npm attestation is empty")
    except (RegistryError, OSError, KeyError, TypeError) as error:
        print(f"SDK registry reconciliation failed: {error}", file=sys.stderr)
        return 1
    print(status)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
