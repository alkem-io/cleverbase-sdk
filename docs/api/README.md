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
