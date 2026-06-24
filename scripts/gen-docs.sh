#!/usr/bin/env bash
# Generate the multi-language API documentation as Markdown into docs/api/.
#
# The generated Markdown is COMMITTED to the repo so the reference docs are browseable directly on
# GitHub (GitHub renders .md in its file viewer). This is the single authoritative recipe — the
# `docs` GitHub Actions workflow (.github/workflows/docs.yml) runs the very same commands and then
# fails if the committed output is stale, so contributors must re-run `make docs` after changing a
# public API (Constitution Principle III: one source of truth for the recipe).
#
# Every generator consumes the in-source doc comments the lint gate already enforces; this script
# does NOT touch any SDK source or lint config.
#
#   Rust   rustdoc JSON -> Markdown  -> docs/api/rust/   (cargo rustdoc --output-format json,
#                                                          converted by scripts/rustdoc_json_to_markdown.py)
#   Go     gomarkdoc                 -> docs/api/go.md    (godoc of the public binding package)
#   Python pydoc-markdown            -> docs/api/python.md(the cleverbase.pyi public stub)
#   TS     typedoc + markdown plugin -> docs/api/ts/      (TSDoc of the frontend helper)
#
# Tool prerequisites (versions pinned in the manifests that own them — see docs/README.md):
#   - Rust toolchain pinned by rust-toolchain.toml (1.92.0); rustup picks it up automatically.
#     rustdoc JSON is unstable, enabled on stable via RUSTC_BOOTSTRAP=1.
#   - gomarkdoc: pinned to $GOMARKDOC_VERSION below (auto-installed into $(go env GOPATH)/bin if missing).
#   - pydoc-markdown: pinned to $PYDOC_MARKDOWN_VERSION below; installed into the repo venv (.venv),
#       auto-installed if missing. .github/workflows/docs.yml pins the SAME version (single source for
#       the recipe), so the generated Markdown is byte-deterministic in CI and on a dev machine —
#       a floating version would re-render docs and falsely trip the workflow's stale-doc diff check.
#   - typedoc + typedoc-plugin-markdown: devDependencies of frontend/helper-ts; `npm install` provides them.
set -euo pipefail

# Single source for the doc-generator tool versions. Pinned to EXACT releases so the generated
# Markdown is deterministic (Constitution Principle III: one authoritative recipe). docs.yml's
# pydoc-markdown install MUST stay in lockstep with PYDOC_MARKDOWN_VERSION.
PYDOC_MARKDOWN_VERSION="4.8.2"
GOMARKDOC_VERSION="v1.1.0"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

OUT="$REPO_ROOT/docs/api"
LIB_DIR="$REPO_ROOT/target/debug"
PY="$REPO_ROOT/.venv/bin/python"
PIP="$REPO_ROOT/.venv/bin/pip"

echo "==> Cleaning previous output ($OUT)"
rm -rf "$OUT"
mkdir -p "$OUT/rust" "$OUT/ts"

# ---------------------------------------------------------------------------
# 1. RUST — rustdoc is HTML-native, so we emit rustdoc's machine-readable JSON
#    and convert it to Markdown with our own format-version-pinned, unit-tested
#    converter (scripts/rustdoc_json_to_markdown.py). missing_docs is `deny`,
#    and we fail on ANY rustdoc warning, so a missing/broken doc breaks the build.
#    RUSTC_BOOTSTRAP=1 unlocks the unstable `--output-format json` on the pinned
#    stable toolchain (1.94.x -> format_version 57; see rust-toolchain.toml).
# ---------------------------------------------------------------------------
echo "==> [1/5] Rust: cargo rustdoc --output-format json -> Markdown"
for crate in cleverbase-core cleverbase-ffi; do
  json="${crate//-/_}.json"
  RUSTDOCFLAGS="-D warnings" RUSTC_BOOTSTRAP=1 \
    cargo rustdoc -p "$crate" -- -Z unstable-options --output-format json
  "$PY" "$REPO_ROOT/scripts/rustdoc_json_to_markdown.py" \
    "$REPO_ROOT/target/doc/$json" "$OUT/rust/${crate//-/_}.md"
done
cat > "$OUT/rust/README.md" <<'MD'
# Rust API

Generated from the in-source rustdoc comments of the Rust workspace (rustdoc JSON → Markdown).

- [`cleverbase_core`](cleverbase_core.md) — the sans-IO protocol/crypto core (the state machine,
  PAdES/CMS assembly, RFC 3161 timestamping, the session handle).
- [`cleverbase_ffi`](cleverbase_ffi.md) — the stable C ABI over the core.
MD

# ---------------------------------------------------------------------------
# 2. GO — gomarkdoc renders the public binding package's godoc to Markdown.
#    cgo needs the cleverbase-ffi library on the link path, so build it first.
# ---------------------------------------------------------------------------
echo "==> [2/5] Go: build cleverbase-ffi + gomarkdoc"
cargo build -p cleverbase-ffi
GOBIN="$(go env GOPATH)/bin"
GOMARKDOC="$GOBIN/gomarkdoc"
if [ ! -x "$GOMARKDOC" ]; then
  echo "    gomarkdoc not found — installing ${GOMARKDOC_VERSION}"
  go install "github.com/princjef/gomarkdoc/cmd/gomarkdoc@${GOMARKDOC_VERSION}"
fi
(
  cd "$REPO_ROOT/bindings/go"
  CGO_LDFLAGS="-L$LIB_DIR" \
  LD_LIBRARY_PATH="$LIB_DIR" \
  DYLD_LIBRARY_PATH="$LIB_DIR" \
    "$GOMARKDOC" --output "$OUT/go.md" ./...
)

# ---------------------------------------------------------------------------
# 3. PYTHON — pydoc-markdown renders the public surface to Markdown. The runtime
#    module is a compiled PyO3 extension whose functions carry no __doc__, and
#    PEP 484 stubs (ruff PYI021) carry no docstrings either — but cleverbase.pyi
#    carries the full, mypy-strict-enforced TYPE SIGNATURES for the 4 public
#    functions + SCHEMA_VERSION, the durable documented contract. pydoc-markdown's
#    bundled loader resolves modules by import name and only finds `.py`, so we
#    drive it through scripts/pyi_to_markdown.py, which parses the `.pyi` with the
#    same docspec-python parser and renders Markdown (no build/import needed).
# ---------------------------------------------------------------------------
echo "==> [3/5] Python: pydoc-markdown on bindings/python/cleverbase.pyi"
if ! "$PY" -c "import pydoc_markdown" 2>/dev/null; then
  echo "    pydoc-markdown not found in .venv — installing ${PYDOC_MARKDOWN_VERSION}"
  "$PIP" install "pydoc-markdown==${PYDOC_MARKDOWN_VERSION}"
fi
"$PY" "$REPO_ROOT/scripts/pyi_to_markdown.py" \
  "$REPO_ROOT/bindings/python/cleverbase.pyi" "$OUT/python.md"

# ---------------------------------------------------------------------------
# 4. TYPESCRIPT (frontend) — typedoc + typedoc-plugin-markdown render the TSDoc
#    of the no-crypto frontend helper to Markdown (config in frontend/helper-ts/typedoc.json).
# ---------------------------------------------------------------------------
echo "==> [4/5] TypeScript (frontend helper): typedoc (markdown) on frontend/helper-ts/src/index.ts"
(
  cd "$REPO_ROOT/frontend/helper-ts"
  if [ ! -x node_modules/.bin/typedoc ] || [ ! -d node_modules/typedoc-plugin-markdown ]; then
    echo "    typedoc/plugin not found — npm install"
    npm install
  fi
  npx typedoc --out "$OUT/ts"
)

# ---------------------------------------------------------------------------
# 5. NODE BINDING (backend) — the napi binding that backend Node/TS services use.
#    Its public API is the napi-generated index.d.ts; napi propagates the Rust `///`
#    doc comments into it as JSDoc, which typedoc renders to Markdown
#    (config in bindings/node/typedoc.json). Regenerate index.d.ts with `napi build`
#    if the binding's Rust signatures/docs change.
# ---------------------------------------------------------------------------
echo "==> [5/5] TypeScript (Node backend binding): typedoc (markdown) on bindings/node/index.d.ts"
(
  cd "$REPO_ROOT/bindings/node"
  if [ ! -x node_modules/.bin/typedoc ] || [ ! -d node_modules/typedoc-plugin-markdown ]; then
    echo "    typedoc/plugin not found — npm install"
    npm install
  fi
  npx typedoc
)

# ---------------------------------------------------------------------------
# Landing index — links every language section. Plain Markdown so it renders on
# GitHub directly.
# ---------------------------------------------------------------------------
echo "==> Writing landing index ($OUT/README.md)"
cat > "$OUT/README.md" <<'MD'
# Cleverbase SDK — API documentation

Reference documentation for every language surface, generated as Markdown from the in-source doc
comments and committed to the repo so it is browseable directly on GitHub. Regenerate with
`make docs` (see [`docs/README.md`](../README.md)).

| Surface                    | Source                                               | Section |
| -------------------------- | ---------------------------------------------------- | ------- |
| Rust core + C ABI          | `crates/cleverbase-core` + `crates/cleverbase-ffi`   | [`rust/`](rust/README.md) |
| Go binding (backend)       | `bindings/go` (the public binding package)           | [`go.md`](go.md) |
| Python binding (backend)   | `bindings/python/cleverbase.pyi` (the public stub)   | [`python.md`](python.md) |
| Node binding (backend)     | `bindings/node/index.d.ts` (the napi binding)        | [`node/`](node/README.md) |
| TypeScript frontend helper | `frontend/helper-ts/src/index.ts` (no-crypto)        | [`ts/`](ts/README.md) |
MD

echo ""
echo "==> Done. Markdown docs under: $OUT"
echo "    Open: $OUT/README.md"
