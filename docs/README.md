# API documentation

The public API of every language surface is documented in-source with doc comments, and that is
enforced by the lint gate (`.github/workflows/lint.yml`): Rust `missing_docs` (deny), Go `revive`
exported-symbol rule, Python `pydocstyle`/ruff, and TypeScript `tsdoc`/`jsdoc`. This directory's
tooling **generates** browsable reference docs from those comments — it never edits source.

The generated docs are **Markdown, committed to the repo** under [`docs/api/`](api/README.md), so
they are browseable directly on GitHub (GitHub renders `.md` in its file viewer — no Pages site to
visit, no build to run). When you change a public API you **must** regenerate and commit the docs;
CI fails otherwise (see [Staleness check](#staleness-check)).

## What gets generated

| Language   | Source                                               | Generator                          | Output             |
| ---------- | ---------------------------------------------------- | ---------------------------------- | ------------------ |
| Rust       | `crates/cleverbase-core` + `crates/cleverbase-ffi`   | rustdoc JSON → Markdown (own conv.) | `docs/api/rust/`   |
| Go         | `bindings/go` (the public binding package)           | `gomarkdoc`                        | `docs/api/go.md`   |
| Python     | `bindings/python/cleverbase.pyi` (the public stub)   | `pydoc-markdown`                   | `docs/api/python.md` |
| TypeScript | `frontend/helper-ts/src/index.ts` (no-crypto helper) | `typedoc` + `typedoc-plugin-markdown` | `docs/api/ts/`     |

A landing index, [`docs/api/README.md`](api/README.md), links all four sections.

## Generate locally

```sh
make docs            # or: ./scripts/gen-docs.sh
git add docs/api && git commit   # commit the regenerated Markdown
```

`scripts/gen-docs.sh` is the single authoritative recipe; the CI workflow runs the same commands.
It auto-installs any missing generator (`gomarkdoc` into `$(go env GOPATH)/bin`, `pydoc-markdown`
into the repo `.venv`) and `npm install`s the TypeScript dev-dependencies. To remove the output:
`make docs-clean`.

### Tool prerequisites and version pins

- **rustdoc** — ships with the Rust toolchain, pinned to **1.92.0** by `rust-toolchain.toml`
  (rustup selects it automatically). The build runs with `RUSTDOCFLAGS=-D warnings`, so
  `missing_docs` and any broken doc-link fail the build.
- **gomarkdoc** — `go install github.com/princjef/gomarkdoc/cmd/gomarkdoc@latest`. It renders the
  package through cgo, so `cargo build -p cleverbase-ffi` must run first and
  `CGO_LDFLAGS`/`LD_LIBRARY_PATH` must point at `target/debug` (the script sets these).
- **pydoc-markdown `4.8.x`** — installed into the repo virtualenv
  (`.venv/bin/pip install pydoc-markdown`).
- **typedoc `^0.28` + typedoc-plugin-markdown `^4`** — `devDependencies` of `frontend/helper-ts`
  (`package.json`); pulled in by `npm install`. The plugin + Markdown output are configured in
  `frontend/helper-ts/typedoc.json`.

### Rust: rustdoc JSON → Markdown

rustdoc is HTML-native, so to commit Markdown we consume rustdoc's machine-readable JSON instead:

```sh
RUSTC_BOOTSTRAP=1 cargo rustdoc -p cleverbase-core -- -Z unstable-options --output-format json
```

`RUSTC_BOOTSTRAP=1` unlocks the unstable `--output-format json` on the pinned **stable** 1.92.0
(producing `target/doc/cleverbase_core.json`, schema `format_version` 57). The off-the-shelf
JSON→Markdown converters on crates.io/npm lag the rustdoc format version (e.g. `rustdoc-md` targets
v42), so a stale one would silently drop or mis-render items. We therefore convert with our own
small, **unit-tested** walker, [`scripts/rustdoc_json_to_markdown.py`](../scripts/rustdoc_json_to_markdown.py)
(tests: `scripts/test_rustdoc_json_to_markdown.py`), which pins the supported `format_version` and
fails loudly if a toolchain bump changes it. It walks the crate's modules and emits Markdown grouped
by kind — modules, structs (fields + inherent methods), enums (variants + inherent methods), traits,
functions, constants, type aliases — each with its rustdoc comment and a Rust-rendered signature,
following `pub use` re-exports without duplicating items. The crate-level `//!` overview heads the
page. Output: `docs/api/rust/cleverbase_core.md` and `cleverbase_ffi.md`, indexed by
`docs/api/rust/README.md`.

### Why the Python generator targets the `.pyi` stub (not the compiled module)

The Python runtime module is a compiled PyO3 extension. Its functions expose no `__doc__`
(`#[pyfunction]` definitions carry no `///` comment that PyO3 would surface), and PEP 484 stubs are
type-only by rule (ruff `PYI021`). The `cleverbase.pyi` stub is therefore the best documentation
source: it carries the full, mypy-strict-enforced **type signatures** for the four public functions
(`begin_signing`, `resume_redirect`, `resume_redirect_error`, `resume_http`) plus `SCHEMA_VERSION`,
which is the durable documented contract. `pydoc-markdown`'s bundled loader resolves modules by
import name and only finds `.py` files, so we drive it through
[`scripts/pyi_to_markdown.py`](../scripts/pyi_to_markdown.py): it parses the `.pyi` with the same
`docspec-python` parser pydoc-markdown uses and renders Markdown directly (no build/import step).

## Staleness check

`.github/workflows/docs.yml` runs on pushes to `develop`/`main`, on pull requests, and on manual
`workflow_dispatch`. It does **not** publish anything — it sets up the four toolchains, runs the
same `make docs` recipe, then `git diff --exit-status -- docs/api` (plus an untracked-files check
for newly documented APIs). If the committed Markdown differs from a fresh regeneration the job
fails, so a public-API change that wasn't followed by `make docs` is caught in CI. Permissions are
least-privilege `contents: read`; all third-party actions are pinned to a commit SHA with a version
comment, matching the repo's other workflows.
