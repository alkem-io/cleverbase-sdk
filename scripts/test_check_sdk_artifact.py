"""Contract tests for final public SDK distribution inspection."""

from __future__ import annotations

import io
import json
import tarfile
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from check_sdk_artifact import (
    ArtifactError,
    check_node_tarball,
    check_python_sdist,
    check_python_wheel,
)

if TYPE_CHECKING:
    pass

VERSION = "0.3.3"
ROOT_LICENSE = (Path(__file__).resolve().parents[1] / "LICENSE").read_bytes()
NODE_FILES = {
    "package/LICENSE": ROOT_LICENSE,
    "package/README.md": b"readme",
    "package/index.d.ts": b"export declare function verifyPdf(): void\n",
    "package/index.js": (
        b"require('./cleverbase.darwin-arm64.node')\n"
        b"require('./cleverbase.darwin-x64.node')\n"
        b"require('./cleverbase.linux-arm64-gnu.node')\n"
        b"require('./cleverbase.linux-x64-gnu.node')\n"
    ),
    "package/package.json": (
        b'{"name":"@alkemio/cleverbase-sdk","version":"0.3.3","publishConfig":{"access":"public"}}'
    ),
    "package/cleverbase.darwin-arm64.node": b"darwin-arm64",
    "package/cleverbase.darwin-x64.node": b"darwin-x64",
    "package/cleverbase.linux-arm64-gnu.node": b"linux-arm64",
    "package/cleverbase.linux-x64-gnu.node": b"linux-x64",
}


def write_tgz(path: Path, files: dict[str, bytes]) -> None:
    """Write a minimal gzip-compressed tar fixture."""
    with tarfile.open(path, "w:gz") as archive:
        for name, content in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))


def write_zip(path: Path, files: dict[str, bytes]) -> None:
    """Write a minimal ZIP fixture."""
    with zipfile.ZipFile(path, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)


def wheel_files(tag: str) -> dict[str, bytes]:
    """Return the required wheel members for one platform tag."""
    dist_info = f"alkemio_cleverbase_sdk-{VERSION}.dist-info"
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {
            "component": {
                "type": "library",
                "name": "cleverbase-py",
                "version": VERSION,
            }
        },
    }
    return {
        f"{dist_info}/METADATA": (
            b"Metadata-Version: 2.4\n"
            b"Name: alkemio-cleverbase-sdk\n"
            b"Version: 0.3.3\n"
            b"License-Expression: EUPL-1.2\n"
            b"License-File: LICENSE\n"
            b"Project-URL: Repository, https://github.com/alkem-io/cleverbase-sdk\n"
            b"Project-URL: Issues, https://github.com/alkem-io/cleverbase-sdk/issues\n\n"
            b"readme\n"
        ),
        f"{dist_info}/WHEEL": f"Wheel-Version: 1.0\nTag: {tag}\n".encode(),
        f"{dist_info}/RECORD": b"record\n",
        f"{dist_info}/sboms/cleverbase-py.cyclonedx.json": json.dumps(sbom).encode(),
        f"{dist_info}/licenses/LICENSE": ROOT_LICENSE,
        "cleverbase/__init__.py": b"from .cleverbase import *\n",
        "cleverbase/__init__.pyi": b"def verify_pdf(document: bytes): ...\n",
        "cleverbase/py.typed": b"",
        "cleverbase/cleverbase.abi3.so": b"native",
    }


def sdist_files() -> dict[str, bytes]:
    """Return the minimum independently buildable sdist layout."""
    root = f"alkemio_cleverbase_sdk-{VERSION}"
    return {
        f"{root}/PKG-INFO": b"Name: alkemio-cleverbase-sdk\nVersion: 0.3.3\n",
        f"{root}/pyproject.toml": b"[build-system]\n",
        f"{root}/README.md": b"readme\n",
        f"{root}/LICENSE": ROOT_LICENSE,
        f"{root}/Cargo.toml": b"[workspace]\n",
        f"{root}/bindings/python/Cargo.toml": b"[package]\n",
        f"{root}/bindings/python/Cargo.lock": b"version = 4\n",
        f"{root}/bindings/python/cleverbase.pyi": b"def verify_pdf(): ...\n",
        f"{root}/bindings/python/src/lib.rs": b"pub fn binding() {}\n",
        f"{root}/crates/cleverbase-core/Cargo.toml": b"[package]\n",
        f"{root}/crates/cleverbase-core/src/lib.rs": b"pub fn core() {}\n",
        f"{root}/crates/cleverbase-attestation/Cargo.toml": b"[package]\n",
        f"{root}/crates/cleverbase-attestation/src/lib.rs": b"pub fn attestation() {}\n",
    }


def test_node_tarball_has_exact_allow_list(tmp_path: Path) -> None:
    package = tmp_path / "alkemio-cleverbase-sdk-0.3.3.tgz"
    write_tgz(package, NODE_FILES)
    check_node_tarball(package, VERSION)

    files = dict(NODE_FILES)
    files["package/src/lib.rs"] = b"secret source"
    write_tgz(package, files)
    with pytest.raises(ArtifactError, match="unexpected members"):
        check_node_tarball(package, VERSION)


def test_node_tarball_rejects_platform_package_fallbacks(tmp_path: Path) -> None:
    package = tmp_path / "alkemio-cleverbase-sdk-0.3.3.tgz"
    files = dict(NODE_FILES)
    files["package/index.js"] += b"require('@alkemio/cleverbase-sdk-linux-x64-gnu')\n"
    write_tgz(package, files)
    with pytest.raises(ArtifactError, match="platform-package fallback"):
        check_node_tarball(package, VERSION)


def test_node_tarball_carries_the_authoritative_license(tmp_path: Path) -> None:
    package = tmp_path / "alkemio-cleverbase-sdk-0.3.3.tgz"
    files = dict(NODE_FILES)
    files["package/LICENSE"] = b"stale license copy"
    write_tgz(package, files)
    with pytest.raises(ArtifactError, match="license content mismatch"):
        check_node_tarball(package, VERSION)


def test_python_wheel_pins_tag_and_typing_surface(tmp_path: Path) -> None:
    tag = "cp39-abi3-macosx_11_0_arm64"
    wheel = tmp_path / f"alkemio_cleverbase_sdk-{VERSION}-{tag}.whl"
    files = wheel_files(tag)
    write_zip(wheel, files)
    check_python_wheel(wheel, VERSION, tag)

    files.pop("cleverbase/py.typed")
    write_zip(wheel, files)
    with pytest.raises(ArtifactError, match="typing surface"):
        check_python_wheel(wheel, VERSION, tag)


def test_python_wheel_pins_generated_sbom_identity(tmp_path: Path) -> None:
    tag = "cp39-abi3-manylinux_2_28_x86_64"
    wheel = tmp_path / f"alkemio_cleverbase_sdk-{VERSION}-{tag}.whl"
    files = wheel_files(tag)
    dist_info = f"alkemio_cleverbase_sdk-{VERSION}.dist-info"
    sbom_name = f"{dist_info}/sboms/cleverbase-py.cyclonedx.json"
    sbom = json.loads(files[sbom_name])
    sbom["metadata"]["component"]["version"] = "9.9.9"
    files[sbom_name] = json.dumps(sbom).encode()
    write_zip(wheel, files)
    with pytest.raises(ArtifactError, match="SBOM identity"):
        check_python_wheel(wheel, VERSION, tag)


def test_python_wheel_carries_the_authoritative_license(tmp_path: Path) -> None:
    tag = "cp39-abi3-manylinux_2_28_x86_64"
    wheel = tmp_path / f"alkemio_cleverbase_sdk-{VERSION}-{tag}.whl"
    files = wheel_files(tag)
    dist_info = f"alkemio_cleverbase_sdk-{VERSION}.dist-info"
    files[f"{dist_info}/licenses/LICENSE"] = b"stale license copy"
    write_zip(wheel, files)
    with pytest.raises(ArtifactError, match="license content mismatch"):
        check_python_wheel(wheel, VERSION, tag)


def test_python_wheel_rejects_unsafe_member(tmp_path: Path) -> None:
    tag = "cp39-abi3-manylinux_2_28_x86_64"
    wheel = tmp_path / f"alkemio_cleverbase_sdk-{VERSION}-{tag}.whl"
    files = wheel_files(tag)
    files["../credential.env"] = b"secret"
    write_zip(wheel, files)
    with pytest.raises(ArtifactError, match="unsafe archive path"):
        check_python_wheel(wheel, VERSION, tag)


def test_python_wheel_rejects_unexpected_non_sbom_member(tmp_path: Path) -> None:
    tag = "cp39-abi3-manylinux_2_28_x86_64"
    wheel = tmp_path / f"alkemio_cleverbase_sdk-{VERSION}-{tag}.whl"
    files = wheel_files(tag)
    files["cleverbase/private.rs"] = b"source"
    write_zip(wheel, files)
    with pytest.raises(ArtifactError, match="unexpected non-SBOM"):
        check_python_wheel(wheel, VERSION, tag)


def test_python_sdist_is_self_contained_and_clean(tmp_path: Path) -> None:
    sdist = tmp_path / f"alkemio_cleverbase_sdk-{VERSION}.tar.gz"
    files = sdist_files()
    write_tgz(sdist, files)
    check_python_sdist(sdist, VERSION)

    root = f"alkemio_cleverbase_sdk-{VERSION}"
    files[f"{root}/target/release/private-key"] = b"secret"
    write_tgz(sdist, files)
    with pytest.raises(ArtifactError, match="forbidden member"):
        check_python_sdist(sdist, VERSION)

    files = sdist_files()
    files.pop(f"{root}/LICENSE")
    write_tgz(sdist, files)
    with pytest.raises(ArtifactError, match="license"):
        check_python_sdist(sdist, VERSION)
