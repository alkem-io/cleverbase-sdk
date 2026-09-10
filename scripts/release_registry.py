#!/usr/bin/env python3
"""Reconcile exact SDK artifacts with PyPI and npm without overwriting bytes."""

from __future__ import annotations

import base64
import hashlib
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, cast

PYPI_PACKAGE = "alkemio-cleverbase-sdk"
NPM_PACKAGE = "@alkemio/cleverbase-sdk"
SLSA_PROVENANCE = "https://slsa.dev/provenance/v1"
HTTP_NOT_FOUND = 404
HTTP_TOO_MANY_REQUESTS = 429
HTTP_SERVER_ERROR_MIN = 500
HTTP_SERVER_ERROR_MAX = 600
MINIMUM_PYTHON_ARTIFACTS = 2
ARGUMENT_COUNT = 5
ALLOWED_REGISTRY_HOSTS = {"pypi.org", "registry.npmjs.org"}
VERIFY_BACKOFF_SECONDS = (0, 2, 5, 10)


class RegistryError(ValueError):
    """Published bytes or provenance differ from the intended release."""


class RegistryVisibilityPendingError(RegistryError):
    """A registry has not made a just-published HTTP resource visible yet."""


def _require(condition: bool, message: str) -> None:  # noqa: FBT001
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
    _require(
        len(artifacts) >= MINIMUM_PYTHON_ARTIFACTS,
        "Python release must contain wheels and an sdist",
    )
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


def _http_json(url: str, *, allow_missing: bool = False, accept: str | None = None) -> object:
    parsed = urllib.parse.urlsplit(url)
    _require(
        parsed.scheme == "https" and parsed.hostname in ALLOWED_REGISTRY_HOSTS,
        "registry URL is not an approved HTTPS origin",
    )
    headers = {"User-Agent": "alkemio-cleverbase-sdk-release/1"}
    if accept is not None:
        headers["Accept"] = accept
    request = urllib.request.Request(url, headers=headers)  # noqa: S310 -- origin checked above
    try:
        with urllib.request.urlopen(  # noqa: S310 -- request origin checked above
            request,
            timeout=30,
        ) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        if allow_missing and error.code == HTTP_NOT_FOUND:
            return None
        msg = f"registry request failed with HTTP {error.code}: {url}"
        if (
            error.code in {HTTP_NOT_FOUND, HTTP_TOO_MANY_REQUESTS}
            or HTTP_SERVER_ERROR_MIN <= error.code < HTTP_SERVER_ERROR_MAX
        ):
            raise RegistryVisibilityPendingError(msg) from error
        raise RegistryError(msg) from error
    except TimeoutError as error:
        msg = f"registry request timed out: {url}"
        raise RegistryVisibilityPendingError(msg) from error
    except urllib.error.URLError as error:
        msg = f"registry request failed: {url}: {error}"
        if isinstance(error.reason, TimeoutError):
            raise RegistryVisibilityPendingError(msg) from error
        raise RegistryError(msg) from error
    except json.JSONDecodeError as error:
        msg = f"registry request failed: {url}: {error}"
        raise RegistryError(msg) from error


def _pypi_metadata(version: str, *, allow_missing: bool) -> dict[str, Any] | None:
    payload = _http_json(
        f"https://pypi.org/pypi/{PYPI_PACKAGE}/{version}/json",
        allow_missing=allow_missing,
    )
    return cast("dict[str, Any] | None", payload)


def _npm_metadata(version: str, *, allow_missing: bool) -> dict[str, Any] | None:
    package = urllib.parse.quote(NPM_PACKAGE, safe="@")
    payload = _http_json(
        f"https://registry.npmjs.org/{package}/{version}",
        allow_missing=allow_missing,
        accept="application/vnd.npm.install-v1+json",
    )
    return cast("dict[str, Any] | None", payload)


def pypi_provenance_valid(provenance: object) -> bool:
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


def _reconcile_once(registry: str, operation: str, artifact: str, version: str) -> str:
    if registry == "pypi":
        payload = _pypi_metadata(version, allow_missing=operation == "preflight")
        status = pypi_status(Path(artifact), version, payload)
        if operation == "verify":
            _require(status == "present" and payload is not None, "PyPI release is incomplete")
            _verify_pypi_provenance(payload, version)
        return status

    payload = _npm_metadata(version, allow_missing=operation == "preflight")
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
    return status


def _reconcile(registry: str, operation: str, artifact: str, version: str) -> str:
    if operation != "verify":
        return _reconcile_once(registry, operation, artifact, version)

    last_error = RegistryVisibilityPendingError("registry verification did not run")
    # Registries can briefly return a transient HTTP status after accepting a publication. This
    # fixed verify-only allowance never retries publication, rebuilds, or semantic mismatches.
    for delay in VERIFY_BACKOFF_SECONDS:
        if delay:
            time.sleep(delay)
        try:
            return _reconcile_once(registry, operation, artifact, version)
        except RegistryVisibilityPendingError as error:
            last_error = error
    raise last_error


def main(argv: list[str]) -> int:
    """Run one preflight or post-publication registry check."""
    if (
        len(argv) != ARGUMENT_COUNT
        or argv[1] not in {"pypi", "npm"}
        or argv[2]
        not in {
            "preflight",
            "verify",
        }
    ):
        sys.stderr.write(
            "usage: release_registry.py <pypi|npm> <preflight|verify> "
            "<artifact-dir-or-tarball> <version>\n"
        )
        return 2

    registry, operation, artifact, version = argv[1:]
    try:
        status = _reconcile(registry, operation, artifact, version)
    except (RegistryError, OSError, KeyError, TypeError) as error:
        sys.stderr.write(f"SDK registry reconciliation failed: {error}\n")
        return 1
    sys.stdout.write(f"{status}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
