#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <native-archive>" >&2
  exit 2
fi

archive="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
checksum="$archive.sha256"
if [ ! -s "$archive" ] || [ ! -s "$checksum" ]; then
  echo "native archive and checksum are required" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

if command -v sha256sum >/dev/null 2>&1; then
  (cd "$(dirname "$archive")" && sha256sum -c "$(basename "$checksum")")
else
  expected="$(awk '{print $1}' "$checksum")"
  actual="$(shasum -a 256 "$archive" | awk '{print $1}')"
  [ "$actual" = "$expected" ] || { echo "native archive checksum mismatch" >&2; exit 1; }
fi

tar -xzf "$archive" -C "$work_dir"
[ -s "$work_dir/lib/libcleverbase_ffi.a" ] || {
  echo "native archive is missing lib/libcleverbase_ffi.a" >&2
  exit 1
}
[ -s "$work_dir/LICENSE" ] || {
  echo "native archive is missing LICENSE" >&2
  exit 1
}

(
  cd "$repo_root/bindings/go"
  CGO_ENABLED=1 CGO_LDFLAGS="-L$work_dir/lib" go test ./...
)
