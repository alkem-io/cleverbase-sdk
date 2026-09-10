"""Tests for fail-closed SDK version synchronization tooling."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from types import ModuleType


def load_sdk_version() -> ModuleType:
    """Load the hyphenated release helper as an ordinary Python module."""
    path = Path(__file__).with_name("sdk-version.py")
    spec = importlib.util.spec_from_file_location("sdk_version", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_required_tool_fails_when_the_package_manager_is_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_sdk_version()
    monkeypatch.setattr(module.shutil, "which", lambda _name: None)

    with pytest.raises(RuntimeError, match="required executable not found: cargo"):
        module.required_tool("cargo")


@pytest.mark.parametrize("missing_tool", ["npm", "cargo"])
def test_sync_does_not_write_when_a_required_tool_is_absent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    missing_tool: str,
) -> None:
    module = load_sdk_version()
    version_file = tmp_path / "SDK_VERSION"
    version_file.write_text("0.3.3\n", encoding="utf-8")
    public_packages = []
    for relative, package_name in (
        ("crates/cleverbase-ffi/Cargo.toml", "cleverbase-ffi"),
        ("bindings/python/Cargo.toml", "cleverbase-py"),
        ("bindings/node/Cargo.toml", "cleverbase-node"),
    ):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            f'[package]\nname = "{package_name}"\nversion = "0.0.0"\n',
            encoding="utf-8",
        )
        public_packages.append((path, package_name))
    pyproject = tmp_path / "bindings/python/pyproject.toml"
    pyproject.write_text(
        '[project]\nname = "old-name"\nversion = "0.0.0"\n',
        encoding="utf-8",
    )
    managed = [path for path, _name in public_packages] + [pyproject]
    before = {path: path.read_bytes() for path in managed}

    monkeypatch.setattr(module, "ROOT", tmp_path)
    monkeypatch.setattr(module, "VERSION_FILE", version_file)
    monkeypatch.setattr(module, "PUBLIC_PACKAGES", tuple(public_packages))
    monkeypatch.setattr(
        module.shutil,
        "which",
        lambda name: None if name == missing_tool else f"/usr/bin/{name}",
    )

    with pytest.raises(RuntimeError, match=f"required executable not found: {missing_tool}"):
        module.synchronize()

    assert {path: path.read_bytes() for path in managed} == before
