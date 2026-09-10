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
bindings/node                  napi-rs                   → @alkemio/cleverbase-sdk
bindings/go                    cgo over the C ABI        → typed Go API
frontend/helper-ts             thin TS redirect/status helper (no crypto, no secrets)
```

## Status (Phase 1: signing)

Implemented and tested (Rust unit + integration; independently validated with **OpenSSL**):

- ✅ Remote QES over CSC (OAuth2 Authorization-Code, two-round: service + credential scopes).
- ✅ **PAdES B-B** and **B-T** (required PDF `/M`, certificate-CN `/Name` when available, no CMS
  `signing-time` attribute, complete `/Contents` exclusion, and an RFC 3161 timestamp for B-T).
- ✅ **RSA** (CSC v1, OpenSSL-validated end-to-end) and **ECDSA P-256** (CSC v2, validated at the
  CMS layer — assembly + in-crate verification; a full ECDSA OpenSSL/DSS pass is on the roadmap,
  see `docs/limitations.md`); CAdES signed attributes incl. `signing-certificate-v2`; detached CMS
  with an **external** signature (the Cleverbase model).
- ✅ Signer-identity binding/verification (FR-014), per-operation evidence records (FR-015),
  optional **visible appearance** with rendered text (FR-016), stateless resumable session handle
  (FR-013), WYSIWYS hash-bound authorization.
- ✅ Stateless integrity verification of a singly-signed PAdES B-B/B-T PDF using the SHA-256 CMS
  profile emitted by this SDK (`rsaEncryption`/PKCS #1 v1.5 or P-256 ECDSA with SHA-256, with the
  SDK's minimal `ESSCertIDv2` form): strict complete-`/Contents` ByteRange/CMS binding,
  embedded-leaf signature and
  digest checks, profile and signer identity. Other valid CMS profiles may return an unsupported
  or malformed verdict. B-T additionally requires a timestamp token bound to the signature value,
  with a matching CMS content digest and a signature verified by a certificate embedded in that
  token. This operation does not establish signer or TSA certificate trust, trusted-list or
  revocation status, signer authorization, or TSA policy, and is not qualified validation.
- ✅ Python, Node, and Go bindings + the TS frontend helper, all with passing tests.

See [`specs/001-remote-qes-signing`](specs/001-remote-qes-signing) for the spec, plan, and tasks,
[`docs/proof-matrix.md`](docs/proof-matrix.md) for the current evidence, and
[`docs/limitations.md`](docs/limitations.md) for known limitations and remaining work. The
[acceptance certificate provenance record](docs/acceptance-ca-provenance.md) documents the
published test chain without treating it as an operator trust decision.

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

# Go binding (builds and links the debug C ABI library explicitly)
make go-test

# Frontend helper
( cd frontend/helper-ts && npm install && npm run build && npm test )
```

### Consume released bindings

One shared SDK version identifies the native archives and all three language bindings. Python keeps
the import name `cleverbase`; the distribution names are Alkemio-owned:

```bash
pip install alkemio-cleverbase-sdk==0.3.3
npm install @alkemio/cleverbase-sdk@0.3.3
```

The Go binding is a nested module. Its releases use tags such as `bindings/go/v0.3.3`, while Go
consumers pin the module version normally:

```bash
go get github.com/alkem-io/cleverbase-sdk/bindings/go@v0.3.3
```

The same GitHub Release contains `cleverbase-ffi-v0.3.3-<os>-<arch>.tar.gz` and a matching
`.sha256` file for Linux and Darwin, on amd64 and arm64. Download the pair for the build host, verify
the checksum before extraction, and point `CGO_LDFLAGS` at the extracted `lib` directory. For
example:

```bash
gh release download bindings/go/v0.3.3 \
  --repo alkem-io/cleverbase-sdk \
  --pattern 'cleverbase-ffi-v0.3.3-linux-amd64*' --dir .cleverbase
( cd .cleverbase && sha256sum -c cleverbase-ffi-v0.3.3-linux-amd64.tar.gz.sha256 )
tar -xzf .cleverbase/cleverbase-ffi-v0.3.3-linux-amd64.tar.gz -C .cleverbase
CGO_LDFLAGS="-L$PWD/.cleverbase/lib" go build ./...
```

`SDK_VERSION` is the authoritative public version. To publish, synchronize its manifest and lockfile
copies, then push the matching annotated tag, for example `bindings/go/v0.3.3`. The tag workflow
builds once from that commit, tests the assembled native archives, Python wheels/sdist, and one
four-platform npm tarball, and binds their digests to the tag and commit. It stages a draft GitHub
release and publishes in deterministic GitHub → PyPI → npm order. A rerun may fill a missing
destination only when every already-published byte matches; any mismatch stops the release. The
GitHub release becomes public only after all registries, provenance records, and clean installs
verify. Running the native packaging contract locally on macOS requires GNU tar
(`brew install gnu-tar`).

#### v0.3.3 release notes

- Makes the Python and Node bindings first-class published packages alongside Go and the native
  libraries, with one synchronized SDK version and one coordinated release.
- Adds `verify_pdf` parity to Python and Node. All three bindings expose the same integrity, profile,
  signer and snake-case reason contract, including strict `malformed_byte_range` results.
- Documents and tests the host-context boundary in every binding: callers provide fresh entropy of
  at least 16 bytes, and `now_unix` must resolve to a UTC year in `0000..=9999`.
- Gates the public bindings at Python 97.51%, Go 97.3%, and the user-approved Node 93.47% measured
  boundary. Node's generated napi-rs registration/conversion locations execute outside the profiler;
  no source exclusions or remapping are used.
- Publishes four Linux/macOS amd64/arm64 native archives, four Python `abi3` wheels plus an sdist,
  and one npm tarball carrying the four native modules. The Linux artifacts target glibc 2.28 and
  macOS artifacts target 11.0.
- Attests GitHub assets with GitHub build provenance, publishes PyPI registry attestations through
  trusted publishing, and publishes npm provenance through GitHub OIDC. The npm bootstrap token is
  used only for the first publication and is then revoked after the trusted publisher is configured.

#### v0.3.2 release notes

- This is a Go/native release. The Python and Node bindings compile and pass their suites against
  the same core, but this tag does not publish either language package.
- Adds a positive RFC 3161 nonce to every timestamp request, derived from host entropy with the
  `rfc3161-nonce` domain label. The nonce persists only while the timestamp effect is pending and
  the response must echo it exactly before the message imprint is accepted.
- Extends the shared configuration validator to reject malformed TSA URLs before a session starts;
  the request-dependent B-T-requires-TSA rule remains in `Begin`.
- Emits the PAdES baseline signature dictionary with `/M` fixed from the host clock and `/Name` from
  the non-empty embedded leaf-certificate common name, while omitting the forbidden CMS signing-time
  signed attribute. Host times outside the four-digit PDF year range are rejected before signing.
- Makes ByteRange exclude the complete `<...>` Contents string and keeps verification strict to that
  ETSI EN 319 142-1 V1.2.1 (2024-01) layout.
- Fails closed across the upgrade boundary: timestamp-pending sessions created before nonce
  persistence must restart, and PDFs emitted with the earlier raw-hex ByteRange convention return
  `integrity=false` with `malformed_byte_range` and must be re-signed. There is no compatibility path.
- Poppler `pdfsig` and pyHanko independently validate RSA and P-256 B-T fixtures as cryptographically
  sound and covering the complete document; the opt-in profile job retains EU DSS for the explicit
  PAdES baseline-level assertion and binds pdfsig validity and coverage within one signature block.
- The low-level Rust `pades::container::prepare` and `crypto::cms::build_signed_attrs` helper
  signatures change with the consolidated metadata path. The FFI wire contract and Go, Python, and
  Node binding APIs are unchanged.

#### v0.3.1 release notes

- Adds `Config.Validate()` to the Go binding so long-running hosts can reject invalid SDK
  configuration before listening or creating a signing session.
- Uses the Rust core's existing configuration validator through the versioned CBOR ABI; `Begin`
  retains the same validation as defense in depth, and Go shares one configuration encoder across
  both calls.
- The config-only operation cannot enforce the request-dependent B-T-requires-TSA rule and does not
  yet validate TSA URL syntax; that validation boundary is tracked in [#36](https://github.com/alkem-io/cleverbase-sdk/issues/36).

#### v0.3.0 release notes

- Adds generic, stateless `verify_pdf` support to the Rust core and C ABI, exposed as `VerifyPDF`
  by the Go binding. Invalid documents return typed verdicts rather than call errors.
- Verifies strict single-signature PAdES B-B/B-T ByteRange and CMS integrity for RSA and P-256
  ECDSA. B-T additionally verifies the timestamp token's internal content digest, binding to the
  document signature value, and signature against the token's embedded signer certificate.
- Successful verdicts expose the profile and embedded signer certificate's canonical serial and
  common name. The verifier does not establish certificate-chain or TSA trust, revocation status,
  TSA policy, signer authorization, or qualified status; multiple signatures remain unsupported.

#### v0.2.1 release notes

- Includes the OAuth token-exchange wire fix: both service and credential token grants send the
  required form `client_id` as well as HTTP Basic authentication.
- The reference signing service forwards `REFSVC_UPSTREAM_BASE_URL` once to the generic SDK config,
  keeping the SDK endpoint separate from the fixture-only `REFSVC_BASE_URL` rewrite.

#### v0.2.0 release notes

- Adds an optional upstream base-URL override for documented developer services; `base_url()` now
  returns `&str`, and `TrustServiceConfiguration` has the additive `upstream_base_url` field.
- Rejects unknown fields in trust-service and TSA configuration rather than silently falling back
  to a default endpoint.
- Sends CSC RSA `signAlgo` as `rsaEncryption` (`1.2.840.113549.1.1.1`), with SHA-256 carried by
  `hashAlgo`.
- Derives signer identity from the signing leaf certificate when CSC does not supply a complete
  direct identity pair, and canonicalizes certificate serials as uppercase hexadecimal without
  separators or a DER sign pad.

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
Local Rust linting requires [rustup](https://rustup.rs/): the script invokes the exact channel
pinned in `rust-toolchain.toml` rather than an arbitrary package-manager Cargo.

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
