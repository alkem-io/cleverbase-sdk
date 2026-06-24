#!/usr/bin/env bash
# Generate the multi-language API documentation site into docs/api/.
#
# Runs all four language generators and aggregates them under a single directory with a landing
# index.html that links each language section. This is the single authoritative recipe — the
# `docs` GitHub Actions workflow (.github/workflows/docs.yml) runs the very same commands so local
# and CI output match (Constitution Principle III: one source of truth for the recipe).
#
# Generators (each consumes the doc-comments the lint gate already enforces — this script does NOT
# touch any SDK source):
#   Rust   rustdoc (`cargo doc`)   -> docs/api/rust/   (missing_docs is deny; built with -D warnings)
#   Go     gomarkdoc               -> docs/api/go.md   (renders godoc of the public binding package)
#   Python pdoc                    -> docs/api/python/ (renders the cleverbase.pyi public stub)
#   TS     typedoc                 -> docs/api/ts/     (renders the TSDoc of the frontend helper)
#
# Tool prerequisites (versions pinned in the manifests that own them — see docs/README.md):
#   - Rust toolchain pinned by rust-toolchain.toml (1.92.0); rustup picks it up automatically.
#   - gomarkdoc: `go install github.com/princjef/gomarkdoc/cmd/gomarkdoc@latest`
#       (auto-installed below into $(go env GOPATH)/bin if missing).
#   - pdoc: installed into the repo venv (.venv); auto-installed below if missing.
#   - typedoc: a devDependency of frontend/helper-ts (package.json); `npm install` provides it.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

OUT="$REPO_ROOT/docs/api"
LIB_DIR="$REPO_ROOT/target/debug"

echo "==> Cleaning previous output ($OUT)"
rm -rf "$OUT"
mkdir -p "$OUT"

# ---------------------------------------------------------------------------
# 1. RUST — rustdoc for the workspace (core + C ABI). missing_docs is `deny`,
#    and we additionally fail the build on ANY rustdoc warning so a doc-link
#    typo or a missing doc cannot slip through.
# ---------------------------------------------------------------------------
echo "==> [1/4] Rust: cargo doc --no-deps --workspace"
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
rm -rf "$OUT/rust"
cp -R "$REPO_ROOT/target/doc" "$OUT/rust"
# Drop rustdoc's zero-byte build lock — it's not part of the docs and its 0700 perms upset some
# artifact packers.
rm -f "$OUT/rust/.lock"
# Land on the core crate's index when the section is opened directly.
cat > "$OUT/rust/index.html" <<'HTML'
<!doctype html><meta charset="utf-8">
<title>Cleverbase SDK — Rust API</title>
<meta http-equiv="refresh" content="0; url=cleverbase_core/index.html">
<a href="cleverbase_core/index.html">cleverbase_core</a>
HTML

# ---------------------------------------------------------------------------
# 2. GO — gomarkdoc renders the public binding package's godoc to markdown.
#    cgo needs the cleverbase-ffi library on the link path, so build it first.
# ---------------------------------------------------------------------------
echo "==> [2/4] Go: build cleverbase-ffi + gomarkdoc"
cargo build -p cleverbase-ffi
GOBIN="$(go env GOPATH)/bin"
GOMARKDOC="$GOBIN/gomarkdoc"
if [ ! -x "$GOMARKDOC" ]; then
  echo "    gomarkdoc not found — installing"
  go install github.com/princjef/gomarkdoc/cmd/gomarkdoc@latest
fi
(
  cd "$REPO_ROOT/bindings/go"
  CGO_LDFLAGS="-L$LIB_DIR" \
  LD_LIBRARY_PATH="$LIB_DIR" \
  DYLD_LIBRARY_PATH="$LIB_DIR" \
    "$GOMARKDOC" --output "$OUT/go.md" ./...
)

# ---------------------------------------------------------------------------
# 3. PYTHON — pdoc renders the public surface. The runtime module is a compiled
#    PyO3 extension whose functions carry no __doc__, and PEP 484 stubs (ruff
#    PYI021) carry no docstrings either — but the cleverbase.pyi stub carries
#    the full, mypy-strict-enforced TYPE SIGNATURES for the 4 public functions
#    + SCHEMA_VERSION, which is the durable documented contract. So we point
#    pdoc straight at the stub (no build/import needed).
# ---------------------------------------------------------------------------
echo "==> [3/4] Python: pdoc on bindings/python/cleverbase.pyi"
PDOC="$REPO_ROOT/.venv/bin/pdoc"
PIP="$REPO_ROOT/.venv/bin/pip"
if [ ! -x "$PDOC" ]; then
  echo "    pdoc not found in .venv — installing"
  "$PIP" install pdoc
fi
"$PDOC" -o "$OUT/python" "$REPO_ROOT/bindings/python/cleverbase.pyi"

# ---------------------------------------------------------------------------
# 4. TYPESCRIPT — typedoc renders the TSDoc of the no-crypto frontend helper.
# ---------------------------------------------------------------------------
echo "==> [4/4] TypeScript: typedoc on frontend/helper-ts/src/index.ts"
(
  cd "$REPO_ROOT/frontend/helper-ts"
  if [ ! -x node_modules/.bin/typedoc ]; then
    echo "    typedoc not found — npm install"
    npm install
  fi
  npx typedoc --out "$OUT/ts" src/index.ts
)

# ---------------------------------------------------------------------------
# Landing index — links every section. Kept as a single static file (no build
# step) so the aggregated site is self-contained.
# ---------------------------------------------------------------------------
echo "==> Writing landing index ($OUT/index.html)"
cat > "$OUT/index.html" <<'HTML'
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Cleverbase SDK — API documentation</title>
  <style>
    :root { color-scheme: light dark; }
    body { font: 16px/1.5 system-ui, sans-serif; max-width: 52rem; margin: 3rem auto; padding: 0 1.25rem; }
    h1 { margin-bottom: .25rem; }
    p.lead { color: #666; margin-top: 0; }
    ul { list-style: none; padding: 0; }
    li { margin: .75rem 0; padding: 1rem 1.25rem; border: 1px solid #8884; border-radius: .5rem; }
    li a { font-size: 1.1rem; font-weight: 600; text-decoration: none; }
    li span { display: block; color: #777; font-size: .9rem; margin-top: .25rem; }
    code { background: #8882; padding: .1rem .35rem; border-radius: .25rem; }
  </style>
</head>
<body>
  <h1>Cleverbase SDK — API documentation</h1>
  <p class="lead">Generated from the in-source doc comments of each language surface.</p>
  <ul>
    <li>
      <a href="rust/cleverbase_core/index.html">Rust &mdash; <code>cleverbase-core</code> + <code>cleverbase-ffi</code></a>
      <span>rustdoc for the protocol/crypto core and the stable C ABI.
      See also <a href="rust/cleverbase_ffi/index.html"><code>cleverbase_ffi</code></a>.</span>
    </li>
    <li>
      <a href="go.md">Go &mdash; <code>bindings/go</code></a>
      <span>godoc of the typed Go binding, rendered to Markdown by gomarkdoc.</span>
    </li>
    <li>
      <a href="python/cleverbase.html">Python &mdash; <code>cleverbase</code></a>
      <span>The public PyO3 surface (4 functions + <code>SCHEMA_VERSION</code>), from the typed <code>cleverbase.pyi</code> stub.</span>
    </li>
    <li>
      <a href="ts/index.html">TypeScript &mdash; <code>@cleverbase/frontend-helper</code></a>
      <span>TSDoc for the no-crypto frontend signing helper.</span>
    </li>
  </ul>
</body>
</html>
HTML

echo ""
echo "==> Done. Site at: $OUT"
echo "    Open: $OUT/index.html"
