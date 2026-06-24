# API documentation

The public API of every language surface is documented in-source with doc comments, and that is
enforced by the lint gate (`.github/workflows/lint.yml`): Rust `missing_docs` (deny), Go `revive`
exported-symbol rule, Python `pydocstyle`/ruff, and TypeScript `tsdoc`/`jsdoc`. This directory's
tooling **generates** browsable reference docs from those comments — it never edits source.

## What gets generated

| Language   | Source                                              | Generator   | Output             |
| ---------- | --------------------------------------------------- | ----------- | ------------------ |
| Rust       | `crates/cleverbase-core` + `crates/cleverbase-ffi`  | `rustdoc`   | `docs/api/rust/`   |
| Go         | `bindings/go` (the public binding package)          | `gomarkdoc` | `docs/api/go.md`   |
| Python     | `bindings/python/cleverbase.pyi` (the public stub)  | `pdoc`      | `docs/api/python/` |
| TypeScript | `frontend/helper-ts/src/index.ts` (no-crypto helper) | `typedoc`   | `docs/api/ts/`     |

A landing `docs/api/index.html` links all four sections.

> The generated tree under `docs/api/` is **not** committed (it is git-ignored). Only the
> hand-written `.md` files in `docs/` are tracked.

## Generate locally

```sh
make docs            # or: ./scripts/gen-docs.sh
open docs/api/index.html
```

`scripts/gen-docs.sh` is the single authoritative recipe; the CI workflow runs the same commands.
It auto-installs any missing generator (`gomarkdoc`, `pdoc`) and `npm install`s the TypeScript
dev-dependencies. To remove the output: `make docs-clean`.

### Tool prerequisites and version pins

- **rustdoc** — ships with the Rust toolchain, which is pinned to **1.92.0** by
  `rust-toolchain.toml` (rustup selects it automatically). The build runs with
  `RUSTDOCFLAGS=-D warnings`, so `missing_docs` and any broken doc-link fail the build.
- **gomarkdoc `v1.1.0`** — `go install github.com/princjef/gomarkdoc/cmd/gomarkdoc@latest`. It
  renders the package through cgo, so `cargo build -p cleverbase-ffi` must run first and
  `CGO_LDFLAGS`/`LD_LIBRARY_PATH` must point at `target/debug` (the script sets these).
- **pdoc `16.x`** — installed into the repo virtualenv (`.venv/bin/pip install pdoc`).
- **typedoc `^0.28.19`** — a `devDependency` of `frontend/helper-ts` (`package.json`); pulled in by
  `npm install`.

### Why pdoc targets the `.pyi` stub (not the compiled module)

The Python runtime module is a compiled PyO3 extension. Its functions expose no `__doc__`
(`#[pyfunction]` definitions carry no `///` comment that PyO3 would surface), and PEP 484 stubs are
type-only by rule (ruff `PYI021`). The `cleverbase.pyi` stub is therefore the best documentation
source: it carries the full, mypy-strict-enforced **type signatures** for the four public functions
(`begin_signing`, `resume_redirect`, `resume_redirect_error`, `resume_http`) plus `SCHEMA_VERSION`,
which is the durable documented contract. pdoc renders it directly, with no build/import step.

## Publish (GitHub Pages)

`.github/workflows/docs.yml` runs on push to `develop`/`main` and on manual `workflow_dispatch`.
Four per-language jobs build their section (each with its own pinned toolchain) and upload it as an
artifact; a `publish` job downloads all four, writes the landing index, and deploys the aggregated
site to GitHub Pages via `actions/upload-pages-artifact` + `actions/deploy-pages`
(`permissions: pages: write, id-token: write`). All third-party actions are pinned to a commit SHA
with a version comment, matching the repo's other workflows.

> One-time repo setting: **Settings → Pages → Build and deployment → Source = "GitHub Actions"**.
