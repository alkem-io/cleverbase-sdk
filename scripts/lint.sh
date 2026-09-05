#!/usr/bin/env bash
# Run the SAME lint / format / type-check gate CI runs (.github/workflows/lint.yml), locally.
#
# Why this exists: the test gate (`cargo test`, `go test`, `npm test`, `pytest`) checks that the code
# WORKS, but the CI lint jobs additionally enforce ruff+mypy (Python), eslint+prettier+tsc (Web), and
# gofmt+golangci-lint (Go) + cargo fmt/clippy (Rust). `go vet` alone does NOT read .golangci.yml, so a
# goconst/revive violation passes `go test` yet fails CI. This script closes that gap — run it (or the
# pre-push hook that calls it) before pushing.
#
# Behavior: runs each language's checks if its tool is installed; a MISSING tool is a loud WARNING
# (not a hard failure) so a dev without all four toolchains can still push — but CI remains the
# authoritative gate. Any check that actually RUNS and fails makes this script exit non-zero.
# Set CLEVERBASE_LINT_STRICT=1 to also fail on a missing tool (full CI parity).
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1
ROOT="$(pwd)"
FAILED=()
WARNED=()
strict="${CLEVERBASE_LINT_STRICT:-0}"

have() { command -v "$1" >/dev/null 2>&1; }
section() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }
# run <label> <cmd...>: run a check, record failure. The label is stripped before executing the cmd.
run() { local label="$1"; shift; echo "+ $*"; if "$@"; then echo "  ok: $label"; else FAILED+=("$label: $*"); echo "  FAIL: $*"; fi; }
# need <tool> <install-hint>: gate a tool; returns 1 (skip) if missing, recording a warn/fail.
need() {
  if have "$1"; then return 0; fi
  WARNED+=("$1 not installed — $2")
  if [ "$strict" = "1" ]; then FAILED+=("$1 missing (strict): $2"); fi
  return 1
}

section "Rust (cargo fmt + clippy)"
if need rustup "install Rust via rustup (the pinned rust-toolchain.toml channel is required)"; then
  rust_channel="$(awk -F '"' '/^[[:space:]]*channel[[:space:]]*=/ { print $2; exit }' rust-toolchain.toml)"
  if [ -z "$rust_channel" ]; then
    FAILED+=("rust-toolchain.toml: missing toolchain channel")
  else
    rust_sysroot="$(rustup run "$rust_channel" rustc --print sysroot 2>/dev/null)"
    if [ -z "$rust_sysroot" ] || [ ! -x "$rust_sysroot/bin/cargo-clippy" ]; then
      FAILED+=("rustup toolchain $rust_channel: missing cargo-clippy")
    else
      # Do not call whichever `cargo`/`cargo-clippy` happens to be first on PATH: Homebrew's
      # binaries ignore rust-toolchain.toml and can enforce a different lint set than CI.
      # The edge is inherent to a mixed package-manager/rustup install, so one toolchain PATH
      # removes it for every Rust command rather than guarding each invocation separately.
      export PATH="$rust_sysroot/bin:$PATH"
      clippy_expected="clippy 0.1.$(printf '%s' "$rust_channel" | awk -F. '{print $2}')"
      clippy_version="$(rustup run "$rust_channel" cargo clippy --version)"
      if [[ "$clippy_version" != "$clippy_expected"* ]]; then
        FAILED+=("clippy: got $clippy_version, want $clippy_expected from $rust_channel")
      else
        run cargo rustup run "$rust_channel" cargo fmt --all --check
        run clippy rustup run "$rust_channel" cargo clippy --workspace --all-targets --all-features -- -D warnings
        run clippy-python env PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1 rustup run "$rust_channel" cargo clippy --manifest-path bindings/python/Cargo.toml --all-targets -- -D warnings
        run clippy-node rustup run "$rust_channel" cargo clippy --manifest-path bindings/node/Cargo.toml --all-targets -- -D warnings
      fi
    fi
  fi
fi

section "Python (ruff + mypy)"
if need ruff "pip install ruff==0.15.19"; then
  run ruff-check ruff check .
  run ruff-format ruff format --check .
fi
if need mypy "pip install mypy==2.1.0"; then
  ( cd bindings/python && echo "+ mypy ." && mypy . ) || FAILED+=("mypy: bindings/python")
fi

section "Web (eslint + prettier)"
# tsc (frontend/helper-ts + examples/reference-integration/web) needs npm installs; CI runs it. It is
# skipped here for speed — run it manually in those dirs if you touch TypeScript. eslint + prettier are
# the fast checks that catch the common formatting/lint failures.
if need npx "install Node.js 20+"; then
  run eslint npx eslint .
  run prettier npx prettier --check .
fi

section "Go (gofmt + vet + golangci-lint)"
if need go "install Go 1.22+"; then
  # golangci-lint on the cgo binding needs the C ABI built + linkable.
  run ffi-build cargo build -p cleverbase-ffi
  export CGO_LDFLAGS="-L${ROOT}/target/debug"
  export LD_LIBRARY_PATH="${ROOT}/target/debug${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
  export DYLD_LIBRARY_PATH="${ROOT}/target/debug${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"
  unformatted="$(gofmt -l bindings/go examples/go_demo examples/reference-integration 2>/dev/null || true)"
  if [ -n "$unformatted" ]; then FAILED+=("gofmt: $unformatted"); echo "  FAIL gofmt: $unformatted"; else echo "  ok: gofmt"; fi
  ( cd bindings/go && go vet ./... ) || FAILED+=("go vet: bindings/go")
  if need golangci-lint "https://golangci-lint.run/usage/install (pin v2.12.2)"; then
    ( cd bindings/go && golangci-lint run ./... ) || FAILED+=("golangci-lint: bindings/go")
    ( cd examples/go_demo && golangci-lint run ./... ) || FAILED+=("golangci-lint: examples/go_demo")
  fi
fi

section "Summary"
for w in "${WARNED[@]:-}"; do [ -n "$w" ] && printf '\033[33mSKIPPED\033[0m %s\n' "$w"; done
if [ "${#FAILED[@]}" -gt 0 ]; then
  for f in "${FAILED[@]}"; do printf '\033[31mFAILED\033[0m  %s\n' "$f"; done
  echo ""
  echo "Lint gate FAILED. Fix the above (this is what CI's lint jobs enforce)."
  exit 1
fi
printf '\033[32mAll ran lint checks passed.\033[0m\n'
[ "${#WARNED[@]}" -gt 0 ] && echo "(some linters were skipped — install them, or set CLEVERBASE_LINT_STRICT=1, for full CI parity)"
exit 0
