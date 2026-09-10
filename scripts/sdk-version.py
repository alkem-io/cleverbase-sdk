#!/usr/bin/env python3
"""Check or synchronize the public SDK binding version copies."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VERSION_FILE = ROOT / "SDK_VERSION"
SEMVER = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?")
PUBLIC_PACKAGES = (
    (ROOT / "crates/cleverbase-ffi/Cargo.toml", "cleverbase-ffi"),
    (ROOT / "bindings/python/Cargo.toml", "cleverbase-py"),
    (ROOT / "bindings/node/Cargo.toml", "cleverbase-node"),
)
LOCK_PACKAGES = (
    (ROOT / "Cargo.lock", "cleverbase-ffi"),
    (ROOT / "bindings/python/Cargo.lock", "cleverbase-py"),
    (ROOT / "bindings/node/Cargo.lock", "cleverbase-node"),
)


def sdk_version() -> str:
    """Read and validate the one authoritative SDK version."""
    version = VERSION_FILE.read_text(encoding="utf-8").strip()
    if SEMVER.fullmatch(version) is None:
        msg = f"SDK_VERSION is not semantic version: {version!r}"
        raise ValueError(msg)
    return version


def toml_string(table: str, key: str) -> str | None:
    """Read one quoted string from a controlled TOML table."""
    match = re.search(rf'(?m)^{re.escape(key)}\s*=\s*"([^"]+)"\s*$', table)
    return match.group(1) if match is not None else None


def toml_package(path: Path, package_name: str) -> dict[str, object]:
    """Return one named Cargo.lock or Cargo.toml package table."""
    text = path.read_text(encoding="utf-8")
    if path.name == "Cargo.lock":
        tables = re.findall(r"(?ms)^\[\[package\]\]\s*$.*?(?=^\[\[package\]\]|\Z)", text)
    else:
        match = re.search(r"(?ms)^\[package\]\s*$.*?(?=^\[|\Z)", text)
        tables = [] if match is None else [match.group(0)]
    for table in tables:
        if toml_string(table, "name") == package_name:
            return {"name": package_name, "version": toml_string(table, "version")}
    msg = f"{path.relative_to(ROOT)}: package {package_name!r} not found"
    raise ValueError(msg)


def expected_values(version: str, release_tag: str | None) -> list[tuple[str, object, object]]:
    """Collect every independently serialized public version/name value."""
    values: list[tuple[str, object, object]] = []
    for path, package_name in PUBLIC_PACKAGES + LOCK_PACKAGES:
        package = toml_package(path, package_name)
        values.append(
            (f"{path.relative_to(ROOT)}:{package_name}.version", package.get("version"), version)
        )

    pyproject_text = (ROOT / "bindings/python/pyproject.toml").read_text(encoding="utf-8")
    project_match = re.search(r"(?ms)^\[project\]\s*$.*?(?=^\[|\Z)", pyproject_text)
    if project_match is None:
        msg = "bindings/python/pyproject.toml: [project] not found"
        raise ValueError(msg)
    project = project_match.group(0)
    values.extend(
        (
            (
                "bindings/python/pyproject.toml:project.name",
                toml_string(project, "name"),
                "alkemio-cleverbase-sdk",
            ),
            (
                "bindings/python/pyproject.toml:project.version",
                toml_string(project, "version"),
                version,
            ),
        )
    )

    package_json = json.loads((ROOT / "bindings/node/package.json").read_text(encoding="utf-8"))
    package_lock = json.loads(
        (ROOT / "bindings/node/package-lock.json").read_text(encoding="utf-8")
    )
    values.extend(
        (
            (
                "bindings/node/package.json:name",
                package_json.get("name"),
                "@alkemio/cleverbase-sdk",
            ),
            ("bindings/node/package.json:version", package_json.get("version"), version),
            (
                "bindings/node/package-lock.json:name",
                package_lock.get("name"),
                "@alkemio/cleverbase-sdk",
            ),
            ("bindings/node/package-lock.json:version", package_lock.get("version"), version),
            (
                "bindings/node/package-lock.json:packages[''].name",
                package_lock.get("packages", {}).get("", {}).get("name"),
                "@alkemio/cleverbase-sdk",
            ),
            (
                "bindings/node/package-lock.json:packages[''].version",
                package_lock.get("packages", {}).get("", {}).get("version"),
                version,
            ),
        )
    )
    if release_tag is not None:
        values.append(("release tag", release_tag, f"bindings/go/v{version}"))
    return values


def check(release_tag: str | None) -> int:
    """Fail closed when any public version or package identity has drifted."""
    version = sdk_version()
    mismatches = [
        f"{label}: got {actual!r}, want {expected!r}"
        for label, actual, expected in expected_values(version, release_tag)
        if actual != expected
    ]
    if mismatches:
        sys.stderr.write("SDK version/package metadata is out of sync:\n")
        sys.stderr.writelines(f"- {mismatch}\n" for mismatch in mismatches)
        return 1
    sys.stdout.write(f"SDK version/package metadata: {version} (ok)\n")
    return 0


def required_tool(name: str) -> str:
    """Resolve a controlled package-manager executable to an absolute path."""
    executable = shutil.which(name)
    if executable is None:
        msg = f"required executable not found: {name}"
        raise RuntimeError(msg)
    return executable


def replace_package_version(path: Path, package_name: str, version: str) -> None:
    """Replace the version in one Cargo manifest's named package table."""
    text = path.read_text(encoding="utf-8")
    pattern = re.compile(
        rf"(\[package\](?:(?!\n\[).)*?\nname\s*=\s*\"{re.escape(package_name)}\""
        rf"(?:(?!\n\[).)*?\nversion\s*=\s*)\"[^\"]+\"",
        re.DOTALL,
    )
    updated, count = pattern.subn(rf'\g<1>"{version}"', text, count=1)
    if count != 1:
        msg = f"{path.relative_to(ROOT)}: could not replace {package_name} version"
        raise ValueError(msg)
    path.write_text(updated, encoding="utf-8")


def synchronize() -> None:
    """Update manifests, then let their native package managers regenerate locks."""
    version = sdk_version()
    for path, package_name in PUBLIC_PACKAGES:
        replace_package_version(path, package_name, version)

    pyproject_path = ROOT / "bindings/python/pyproject.toml"
    pyproject = pyproject_path.read_text(encoding="utf-8")
    pyproject = re.sub(
        r'(?m)^name = "[^"]+"$', 'name = "alkemio-cleverbase-sdk"', pyproject, count=1
    )
    pyproject = re.sub(r'(?m)^version = "[^"]+"$', f'version = "{version}"', pyproject, count=1)
    pyproject_path.write_text(pyproject, encoding="utf-8")

    npm = required_tool("npm")
    cargo = required_tool("cargo")
    subprocess.run(  # noqa: S603 -- executable resolved from the operator's PATH
        [npm, "version", version, "--no-git-tag-version", "--allow-same-version"],
        cwd=ROOT / "bindings/node",
        check=True,
    )
    package_path = ROOT / "bindings/node/package.json"
    package = json.loads(package_path.read_text(encoding="utf-8"))
    package["name"] = "@alkemio/cleverbase-sdk"
    package_path.write_text(
        json.dumps(package, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    subprocess.run(  # noqa: S603 -- executable resolved from the operator's PATH
        [npm, "install", "--package-lock-only", "--ignore-scripts"],
        cwd=ROOT / "bindings/node",
        check=True,
    )

    for manifest in (
        ROOT / "Cargo.toml",
        ROOT / "bindings/python/Cargo.toml",
        ROOT / "bindings/node/Cargo.toml",
    ):
        subprocess.run(  # noqa: S603 -- executable resolved from the operator's PATH
            [cargo, "metadata", "--format-version", "1", "--manifest-path", str(manifest)],
            cwd=ROOT,
            check=True,
            stdout=subprocess.DEVNULL,
        )


def main() -> int:
    """Run the requested version operation."""
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    check_parser = subparsers.add_parser("check")
    check_parser.add_argument("--tag")
    subparsers.add_parser("sync")
    args = parser.parse_args()
    if args.command == "sync":
        synchronize()
        return check(None)
    return check(args.tag)


if __name__ == "__main__":
    raise SystemExit(main())
