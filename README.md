# Cleverbase SDK

A production-grade, polyglot SDK for two capabilities built on
[Cleverbase](https://cleverbase.com) (a Dutch Qualified Trust Service Provider):

- **Remote Qualified Electronic Signing (QES)** of PDFs — via the Cloud Signature Consortium (CSC)
  API + OpenID Connect.
- **EUDI attestation** — issuance (OpenID4VCI) and verification (OpenID4VP) of **SD-JWT VC** and
  **ISO 18013-5 mdoc** credentials, with the EU trust model (trust lists, revocation/status, and the
  opt-in eIDAS qualified gate).

Built for the [Alkemio](https://github.com/alkem-io) platform, designed to stand alone. Cleverbase
publishes no official SDK and signs only a *hash* — so this SDK owns the whole AdES stack (container
assembly, timestamping, validation) and, for attestations, the full verification bar.

## Architecture

**Sans-IO Rust cores** hold all protocol + cryptography and perform **no I/O**:
[`crates/cleverbase-core`](crates/cleverbase-core) (signing) is a pure, serializable state machine
that *emits effects* (HTTP requests to perform, browser redirects to issue) which the host executes
and feeds back; [`crates/cleverbase-attestation`](crates/cleverbase-attestation) (EUDI attestation)
takes host-supplied bytes — trust lists, status documents, presentations — and authenticates +
evaluates them. This keeps the cores deterministic, auditable, and testable against recorded
exchanges, and lets every language binding stay thin.

```text
crates/cleverbase-core         sans-IO signing state machine, CSC/OIDC client, CAdES/PAdES CMS, RFC 3161
crates/cleverbase-attestation  sans-IO EUDI verify (SD-JWT VC + mdoc), OpenID4VP/DCQL, status, OpenID4VCI issuance
crates/cleverbase-ffi          stable C ABI (CBOR in / result out) — consumed by Go
bindings/python                PyO3 + maturin            → import cleverbase
bindings/node                  napi-rs                   → @cleverbase/sdk
bindings/go                    cgo over the C ABI        → typed Go API
frontend/helper-ts             thin TS redirect/status helper (no crypto, no secrets)
```

## Status (Phase 1: signing)

Implemented and tested (Rust unit + integration; independently validated with **OpenSSL**):

- ✅ Remote QES over CSC (OAuth2 Authorization-Code, two-round: service + credential scopes).
- ✅ **PAdES B-B** and **B-T** (RFC 3161 timestamp from an external qualified TSA).
- ✅ **RSA** (CSC v1, OpenSSL-validated end-to-end) and **ECDSA P-256** (CSC v2, validated at the
  CMS layer — assembly + in-crate verification; a full ECDSA OpenSSL/DSS pass is on the roadmap,
  see `docs/limitations.md`); CAdES signed attributes incl. `signing-certificate-v2`; detached CMS
  with an **external** signature (the Cleverbase model).
- ✅ Signer-identity binding/verification (FR-014), per-operation evidence records (FR-015),
  optional **visible appearance** with rendered text (FR-016), stateless resumable session handle
  (FR-013), WYSIWYS hash-bound authorization.
- ✅ Python, Node, and Go bindings + the TS frontend helper, all with passing tests.

See [`specs/001-remote-qes-signing`](specs/001-remote-qes-signing) for the spec, plan, and tasks,
and [`docs/limitations.md`](docs/limitations.md) for known limitations and remaining work.

## Status (EUDI attestation & verification)

Implemented and tested (Rust unit + integration; offline and sans-IO — the host supplies trust
lists, status documents, and presentations as bytes):

- ✅ **Always-on verification bar** — issuer signature → issuer trust (RFC 5280 chain-to-anchor,
  key-purpose, name constraints) → validity window → revocation/status → holder binding →
  selective-disclosure integrity, for **SD-JWT VC** (RFC 9901) and **ISO 18013-5 mdoc** (CBOR/COSE).
  Any failed check ⇒ INVALID with a specific reason (no false-accept).
- ✅ **OpenID4VP 1.0** presentation verify (nonce/audience/replay, KB-JWT, mdoc handover transcript)
  + in-core **DCQL** including set-level `credential_sets` / `multiple` cardinality.
- ✅ **Token Status List** authentication (draft-ietf-oauth-status-list) — the core verifies the
  signed JWT/CWT status token itself and reads the revocation bit.
- ✅ Opt-in **eIDAS qualified-status gate** (ETSI TS 119 615) — off by default, fail-closed.
- ✅ **Issuance** (OpenID4VCI) via a sans-IO obtain/present state machine + a holder signer-hook
  (the SDK never holds the private key).
- ✅ Python, Node, and Go bindings for the attestation surface.

See [`specs/004-attestation-and-verification`](specs/004-attestation-and-verification) for the spec,
plan, and standards-conformance record, and [`docs/attestation.md`](docs/attestation.md) for usage.

## Build & test

```bash
# Rust core + C ABI (+ independent OpenSSL/TSA validation; needs `openssl`)
cargo test --workspace

# Python binding
python3 -m venv .venv && .venv/bin/pip install maturin cbor2 pytest
( cd bindings/python && PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1 ../../.venv/bin/maturin develop )
.venv/bin/pytest bindings/python/tests

# Node binding
( cd bindings/node && npm install && npm run build && npm test )

# Go binding (links the C ABI dylib)
cargo build -p cleverbase-ffi
( cd bindings/go && DYLD_LIBRARY_PATH=$PWD/../../target/debug go test )

# Frontend helper
( cd frontend/helper-ts && npm install && npm run build && npm test )
```

### Lint gate (match CI locally)

CI runs a lint/format/type-check gate (`.github/workflows/lint.yml`) — `cargo fmt`+`clippy`,
`ruff`+`mypy`, `eslint`+`prettier`+`tsc`, `gofmt`+`golangci-lint` — that the test commands above do
**not** cover (`go test` passes code that `golangci-lint` rejects). Run the lint/format subset of
that gate locally:

```bash
./scripts/lint.sh            # runs every lint tool that is installed; warns on any that are missing
CLEVERBASE_LINT_STRICT=1 ./scripts/lint.sh   # also fail on a missing tool
```

`scripts/lint.sh` covers everything CI's lint job runs **except** the TypeScript `tsc --noEmit`
type-check (it needs `npm install` in `frontend/helper-ts` + `examples/reference-integration/web`);
run that in those dirs if you touch TypeScript. CI remains the authoritative gate.

To run it automatically before every push, enable the committed pre-push hook once per clone:

```bash
git config core.hooksPath .githooks   # then `git push` runs scripts/lint.sh first (bypass: --no-verify)
```

## API documentation

Generated API reference (Markdown, browseable on GitHub) lives under [`docs/api/`](docs/api/):

- Rust: [core (`cleverbase-core`)](docs/api/rust/cleverbase_core.md) · [attestation (`cleverbase-attestation`)](docs/api/rust/cleverbase_attestation.md) · [C ABI (`cleverbase-ffi`)](docs/api/rust/cleverbase_ffi.md)
- Backend bindings: [Go](docs/api/go.md) · [Python](docs/api/python.md) · [Node/TypeScript](docs/api/node/)
- Frontend: [TypeScript helper (no-crypto)](docs/api/ts/)

Regenerate after any public-API change with `make docs` (CI fails if `docs/api/` is stale). See
[`docs/README.md`](docs/README.md) for the generation flow.

## Security model (Constitution Principle IV)

Secrets (`client_secret`, SAD, tokens, keys) are **server-side only**. The frontend helper performs
no cryptography and carries no secrets — only redirect URLs, an opaque correlation id, and the
OAuth `code`/`state`. The session handle may carry short-lived authorization material and **must be
stored encrypted server-side**.

## License

Licensed under the **European Union Public Licence v. 1.2 (EUPL-1.2)**. See [LICENSE](LICENSE).
