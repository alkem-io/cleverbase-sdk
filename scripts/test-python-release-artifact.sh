#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 <wheel-or-sdist>" >&2
  exit 2
}

if [ "$#" -ne 1 ]; then
  usage
fi

artifact="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
if [ ! -f "$artifact" ]; then
  echo "Python artifact not found: $artifact" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python_bin="${PYTHON_BIN:-python3}"
work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

"$python_bin" -m venv "$work_dir/venv"
venv_python="$work_dir/venv/bin/python"
version="$(tr -d '[:space:]' < "$repo_root/SDK_VERSION")"
"$venv_python" -m pip install \
  --disable-pip-version-check \
  "$artifact" \
  pytest==8.4.2 \
  cbor2==5.6.5 >/dev/null

SDK_VERSION="$version" "$venv_python" - <<'PY'
import importlib.metadata
import os
from pathlib import Path

import cleverbase

assert importlib.metadata.version("alkemio-cleverbase-sdk") == os.environ["SDK_VERSION"]
assert "site-packages" in Path(cleverbase.__file__).as_posix()
PY

"$venv_python" -m pytest -q "$repo_root/bindings/python/tests"
