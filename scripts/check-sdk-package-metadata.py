#!/usr/bin/env python3
"""Fail closed when public Python/npm package metadata drifts."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
NODE_FILES = [
    "index.js",
    "index.d.ts",
    "cleverbase.darwin-arm64.node",
    "cleverbase.darwin-x64.node",
    "cleverbase.linux-arm64-gnu.node",
    "cleverbase.linux-x64-gnu.node",
    "README.md",
    "LICENSE",
]


def require(errors: list[str], condition: bool, message: str) -> None:
    """Append one actionable contract failure."""
    if not condition:
        errors.append(message)


def main() -> int:
    """Check static metadata before any artifact build is allowed to publish."""
    errors: list[str] = []
    version = (ROOT / "SDK_VERSION").read_text(encoding="utf-8").strip()

    node_path = ROOT / "bindings/node/package.json"
    node = json.loads(node_path.read_text(encoding="utf-8"))
    require(errors, node.get("name") == "@alkemio/cleverbase-sdk", "npm package name")
    require(errors, node.get("version") == version, "npm package version")
    require(errors, node.get("license") == "EUPL-1.2", "npm license")
    require(
        errors,
        node.get("repository")
        == {
            "type": "git",
            "url": "git+https://github.com/alkem-io/cleverbase-sdk.git",
            "directory": "bindings/node",
        },
        "npm repository metadata",
    )
    require(
        errors,
        node.get("homepage") == "https://github.com/alkem-io/cleverbase-sdk#readme",
        "npm homepage",
    )
    require(
        errors,
        node.get("bugs") == {"url": "https://github.com/alkem-io/cleverbase-sdk/issues"},
        "npm issue tracker",
    )
    require(errors, node.get("files") == NODE_FILES, "npm exact files allow-list")
    require(errors, node.get("publishConfig") == {"access": "public"}, "npm public publish config")
    require(
        errors,
        node.get("napi")
        == {
            "name": "cleverbase",
            "triples": {
                "defaults": False,
                "additional": [
                    "x86_64-unknown-linux-gnu",
                    "aarch64-unknown-linux-gnu",
                    "x86_64-apple-darwin",
                    "aarch64-apple-darwin",
                ],
            },
        },
        "npm advertised native target allow-list",
    )

    loader = (ROOT / "bindings/node/index.js").read_text(encoding="utf-8")
    require(errors, "@cleverbase/" not in loader, "generated Node loader has legacy @cleverbase fallbacks")
    require(
        errors,
        "@alkemio/cleverbase-sdk-" not in loader,
        "Node loader must not reference unpublished platform packages",
    )

    pyproject = (ROOT / "bindings/python/pyproject.toml").read_text(encoding="utf-8")
    python_patterns = {
        "Python distribution name": r'(?m)^name = "alkemio-cleverbase-sdk"$',
        "Python package version": rf'(?m)^version = "{re.escape(version)}"$',
        "Python README metadata": r'(?m)^readme = "README.md"$',
        "Python license metadata": r'(?m)^license = "EUPL-1\.2"$',
        "Python repository URL": (
            r'(?ms)^\[project\.urls\]\s*$.*?^Repository = '
            r'"https://github.com/alkem-io/cleverbase-sdk"$'
        ),
        "Python issue tracker": (
            r'(?ms)^\[project\.urls\]\s*$.*?^Issues = '
            r'"https://github.com/alkem-io/cleverbase-sdk/issues"$'
        ),
        "Python wheel typing include": r'(?m)^include = \["cleverbase\.pyi"\]$',
    }
    for label, pattern in python_patterns.items():
        require(errors, re.search(pattern, pyproject) is not None, label)
    require(
        errors,
        (ROOT / "bindings/python/cleverbase.pyi").is_file(),
        "Python typing surface cleverbase.pyi",
    )
    require(
        errors,
        (ROOT / "bindings/python/README.md").is_file(),
        "Python package README",
    )
    python_cargo = (ROOT / "bindings/python/Cargo.toml").read_text(encoding="utf-8")
    require(
        errors,
        re.search(r'(?m)^readme = "README.md"$', python_cargo) is not None,
        "Python crate README metadata",
    )

    if errors:
        print("SDK package metadata contract failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print("SDK package metadata contract: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
