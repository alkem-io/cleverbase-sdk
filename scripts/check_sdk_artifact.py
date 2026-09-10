#!/usr/bin/env python3
"""Fail-closed inspection of final Python and npm SDK distributions."""

from __future__ import annotations

import json
import sys
import tarfile
import zipfile
from contextlib import contextmanager
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from typing import Iterable, Iterator


NODE_PACKAGE = "@alkemio/cleverbase-sdk"
PYTHON_PACKAGE = "alkemio-cleverbase-sdk"
PYTHON_DIST = "alkemio_cleverbase_sdk"
NODE_NATIVE_FILES = {
    "cleverbase.darwin-arm64.node",
    "cleverbase.darwin-x64.node",
    "cleverbase.linux-arm64-gnu.node",
    "cleverbase.linux-x64-gnu.node",
}
NODE_MEMBERS = {
    "package/LICENSE",
    "package/README.md",
    "package/index.d.ts",
    "package/index.js",
    "package/package.json",
    *(f"package/{name}" for name in NODE_NATIVE_FILES),
}


class ArtifactError(ValueError):
    """A release artifact violates the public distribution contract."""


def _safe_members(names: Iterable[str]) -> set[str]:
    members = set(names)
    for name in members:
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts or not path.parts:
            raise ArtifactError(f"unsafe archive path: {name}")
    return members


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ArtifactError(message)


@contextmanager
def _checked_tar(path: Path) -> Iterator[tuple[tarfile.TarFile, set[str]]]:
    with tarfile.open(path, "r:gz") as archive:
        members = archive.getmembers()
        _require(
            all(member.isfile() for member in members),
            "archives may contain regular files only",
        )
        yield archive, _safe_members(member.name for member in members)


def check_node_tarball(path: Path, version: str) -> None:
    """Validate the exact one-tarball npm distribution contract."""
    expected_name = f"alkemio-cleverbase-sdk-{version}.tgz"
    _require(path.name == expected_name, f"npm artifact filename must be {expected_name}")
    with _checked_tar(path) as (archive, members):
        _require(members == NODE_MEMBERS, "npm tarball has unexpected members")
        package_file = archive.extractfile("package/package.json")
        loader_file = archive.extractfile("package/index.js")
        _require(package_file is not None and loader_file is not None, "npm metadata is unreadable")
        package = json.loads(package_file.read())
        loader = loader_file.read().decode("utf-8")

    _require(package.get("name") == NODE_PACKAGE, "npm package name mismatch")
    _require(package.get("version") == version, "npm package version mismatch")
    _require(package.get("publishConfig") == {"access": "public"}, "npm publish access mismatch")
    _require(
        f"{NODE_PACKAGE}-" not in loader,
        "npm loader contains a platform-package fallback",
    )
    for native_file in NODE_NATIVE_FILES:
        _require(native_file in loader, f"npm loader omits {native_file}")


def check_python_wheel(path: Path, version: str, expected_tag: str) -> None:
    """Validate one platform wheel's identity, tag, and typed public surface."""
    expected_name = f"{PYTHON_DIST}-{version}-{expected_tag}.whl"
    _require(path.name == expected_name, f"wheel filename must be {expected_name}")
    dist_info = f"{PYTHON_DIST}-{version}.dist-info"
    expected_members = {
        f"{dist_info}/METADATA",
        f"{dist_info}/WHEEL",
        f"{dist_info}/RECORD",
        "cleverbase.pyi",
        "cleverbase/__init__.py",
        "cleverbase/__init__.pyi",
        "cleverbase/py.typed",
        "cleverbase/cleverbase.abi3.so",
    }
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        members = _safe_members(info.filename for info in infos)
        _require(
            all(((info.external_attr >> 16) & 0o170000) != 0o120000 for info in infos),
            "wheel may not contain symlinks",
        )
        _require(members == expected_members, "wheel has unexpected members or typing surface")
        metadata = BytesParser().parsebytes(archive.read(f"{dist_info}/METADATA"))
        wheel = BytesParser().parsebytes(archive.read(f"{dist_info}/WHEEL"))

    _require(metadata.get("Name") == PYTHON_PACKAGE, "wheel package name mismatch")
    _require(metadata.get("Version") == version, "wheel package version mismatch")
    _require(metadata.get("License-Expression") == "EUPL-1.2", "wheel license mismatch")
    project_urls = set(metadata.get_all("Project-URL", []))
    _require(
        "Repository, https://github.com/alkem-io/cleverbase-sdk" in project_urls,
        "wheel repository metadata mismatch",
    )
    _require(
        "Issues, https://github.com/alkem-io/cleverbase-sdk/issues" in project_urls,
        "wheel issue tracker mismatch",
    )
    _require(wheel.get("Tag") == expected_tag, "wheel compatibility tag mismatch")


def check_python_sdist(path: Path, version: str) -> None:
    """Validate that the Python sdist is self-contained and omits build residue."""
    expected_name = f"{PYTHON_DIST}-{version}.tar.gz"
    _require(path.name == expected_name, f"sdist filename must be {expected_name}")
    root = f"{PYTHON_DIST}-{version}"
    required = {
        f"{root}/PKG-INFO",
        f"{root}/pyproject.toml",
        f"{root}/README.md",
        f"{root}/Cargo.toml",
        f"{root}/bindings/python/Cargo.toml",
        f"{root}/bindings/python/Cargo.lock",
        f"{root}/bindings/python/cleverbase.pyi",
        f"{root}/bindings/python/src/lib.rs",
        f"{root}/crates/cleverbase-core/Cargo.toml",
        f"{root}/crates/cleverbase-core/src/lib.rs",
        f"{root}/crates/cleverbase-attestation/Cargo.toml",
        f"{root}/crates/cleverbase-attestation/src/lib.rs",
    }
    with _checked_tar(path) as (_, members):
        _require(required <= members, "sdist is missing required build inputs")
        _require(all(name.startswith(f"{root}/") for name in members), "sdist has multiple roots")
        forbidden_parts = {".git", "target", "node_modules", "__pycache__"}
        for name in members:
            parts = set(PurePosixPath(name).parts)
            if parts & forbidden_parts or name.endswith((".env", ".pyc")):
                raise ArtifactError(f"sdist contains forbidden member: {name}")


def main(argv: list[str]) -> int:
    """Dispatch one artifact contract from the release workflow."""
    if len(argv) not in {4, 5}:
        print(
            "usage: check_sdk_artifact.py "
            "<node|python-wheel|python-sdist> <artifact> <version> [wheel-tag]",
            file=sys.stderr,
        )
        return 2
    kind, artifact, version = argv[1:4]
    try:
        if kind == "node" and len(argv) == 4:
            check_node_tarball(Path(artifact), version)
        elif kind == "python-wheel" and len(argv) == 5:
            check_python_wheel(Path(artifact), version, argv[4])
        elif kind == "python-sdist" and len(argv) == 4:
            check_python_sdist(Path(artifact), version)
        else:
            raise ArtifactError("invalid artifact contract arguments")
    except (ArtifactError, OSError, tarfile.TarError, zipfile.BadZipFile, json.JSONDecodeError) as error:
        print(f"SDK artifact contract failed: {error}", file=sys.stderr)
        return 1
    print(f"SDK {kind} artifact contract: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
