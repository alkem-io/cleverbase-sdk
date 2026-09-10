"""Tests for fail-closed SDK version synchronization tooling."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest


def load_sdk_version() -> ModuleType:
    """Load the hyphenated release helper as an ordinary Python module."""
    path = Path(__file__).with_name("sdk-version.py")
    spec = importlib.util.spec_from_file_location("sdk_version", path)
    assert spec is not None and spec.loader is not None
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
