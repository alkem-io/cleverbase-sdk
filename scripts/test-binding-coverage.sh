#!/usr/bin/env bash
# Build each published language binding exactly as its public tests consume it and enforce the
# constitution's per-binding >=95% line-coverage floor. CI and the release dry-run share this entry
# point so coverage cannot drift between ordinary development and publication.
set -euo pipefail

cd "$(dirname "$0")/.."
repo_root="$(pwd)"
minimum=95

rust_channel="$(awk -F '"' '/^[[:space:]]*channel[[:space:]]*=/ { print $2; exit }' rust-toolchain.toml)"
if [[ -z "$rust_channel" ]]; then
  echo "rust-toolchain.toml: missing toolchain channel" >&2
  exit 1
fi
rust_sysroot="$(rustup run "$rust_channel" rustc --print sysroot)"
export PATH="$rust_sysroot/bin:$PATH"

rust_cargo() {
  rustup run "$rust_channel" cargo "$@"
}

coverage_environment() {
  local manifest="$1"
  rust_cargo llvm-cov show-env --manifest-path "$manifest" --sh
}

python_coverage() {
  local venv="${VIRTUAL_ENV:-$repo_root/.venv}"
  local maturin="$venv/bin/maturin"
  local pytest="$venv/bin/pytest"
  [[ -x "$maturin" ]] || { echo "maturin not found at $maturin" >&2; exit 1; }
  [[ -x "$pytest" ]] || { echo "pytest not found at $pytest" >&2; exit 1; }

  rust_cargo llvm-cov clean --manifest-path bindings/python/Cargo.toml
  eval "$(coverage_environment bindings/python/Cargo.toml)"
  (
    cd bindings/python
    "$maturin" develop
    "$pytest" tests
  )
  rust_cargo llvm-cov report \
    --manifest-path bindings/python/Cargo.toml \
    --package cleverbase-py \
    --fail-under-lines "$minimum" \
    --show-missing-lines
}

node_coverage() {
  rust_cargo llvm-cov clean --manifest-path bindings/node/Cargo.toml
  eval "$(coverage_environment bindings/node/Cargo.toml)"
  (
    cd bindings/node
    npm run build
    npm test
  )
  rust_cargo llvm-cov report \
    --manifest-path bindings/node/Cargo.toml \
    --package cleverbase-node \
    --fail-under-lines "$minimum" \
    --show-missing-lines
}

go_coverage() {
  rust_cargo build -p cleverbase-ffi
  export CGO_LDFLAGS="-L$repo_root/target/debug"
  export LD_LIBRARY_PATH="$repo_root/target/debug${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
  export DYLD_LIBRARY_PATH="$repo_root/target/debug${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"
  (
    cd bindings/go
    go test -coverprofile=cover.out ./...

    test_binary="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/cleverbase-go.test"
    go test -c -o "$test_binary" .
    if command -v readelf >/dev/null; then
      loader_metadata="$(readelf -d "$test_binary")"
      checkout_path="$(printf '%s\n' "$loader_metadata" \
        | grep -E '\((RPATH|RUNPATH)\)' \
        | grep -F 'target/debug' || true)"
    elif command -v otool >/dev/null; then
      loader_metadata="$(otool -l "$test_binary")"
      checkout_path="$(printf '%s\n' "$loader_metadata" \
        | awk '/cmd LC_RPATH/ { in_rpath=1; next } in_rpath && /path / { print; in_rpath=0 }' \
        | grep -F 'target/debug' || true)"
    else
      echo "readelf or otool is required for the runtime-path check" >&2
      exit 1
    fi
    [[ -n "$loader_metadata" ]] || {
      echo "the runtime-path inspector returned no output" >&2
      exit 1
    }
    if [[ -n "$checkout_path" ]]; then
      printf '%s\n' "$checkout_path"
      echo "Go binding embeds a checkout-local target/debug RUNPATH" >&2
      exit 1
    fi

    total="$(go tool cover -func=cover.out | awk '/^total:/ {print $3}' | tr -d '%')"
    echo "Go binding statement coverage: ${total}%"
    awk "BEGIN { exit !(${total} >= ${minimum}) }" || {
      echo "Go coverage ${total}% < ${minimum}%" >&2
      exit 1
    }
  )
}

case "${1:-}" in
  python) python_coverage ;;
  node) node_coverage ;;
  go) go_coverage ;;
  *)
    echo "usage: $0 {python|node|go}" >&2
    exit 2
    ;;
esac
