# Phase 0 Research: Reference Integration Services & Container Delivery

All Technical-Context unknowns were resolved during two `/speckit-clarify` rounds; this records the
resulting technical decisions, their rationale, and the alternatives rejected.

## 1. Backend embeds the SDK via the existing Go binding (cgo, statically linked)

**Decision**: The signing service is a Go program that imports the existing `bindings/go` package
(cgo over `cleverbase-ffi`). It runs the SDK's `begin`/`resume` loop and performs the emitted HTTP
effects with `net/http`. For containers it **statically links** the crate's `staticlib`
(`libcleverbase_ffi.a`) with `CGO_ENABLED=1`, producing one self-contained binary.

**Rationale**: Reuses the single Rust core (Constitution III) — no protocol/crypto is re-implemented
in Go; the service only does I/O + session orchestration. Static linking removes any runtime
`LD_LIBRARY_PATH`/`.so` shipping, which is what makes "deploy as a sidecar" trivial.

**Alternatives rejected**: (a) Run the sans-IO core as a separate socket sidecar the Go service calls
per step — more round-trips, and the Go binding already exists; (b) dynamic-link the `cdylib` — needs
a shared lib + loader config in the image.

**libc note**: The Rust `staticlib` pulls the platform C runtime, so the final image uses a base that
ships glibc + libgcc (`gcr.io/distroless/cc-debian12`), not `:static`. Building the Rust and Go
stages on the same `debian:bookworm` toolchain avoids ABI mismatch. Native per-arch runners build
natively, so no cross-compilation is required.

## 2. Multi-arch images on NATIVE GitHub runners → GHCR (no QEMU)

**Decision**: A build matrix over **`ubuntu-24.04`** (amd64) and **`ubuntu-24.04-arm`** (arm64
GitHub-hosted runners). Each runner builds and pushes its image **by digest** to GHCR natively; a
final job assembles a **manifest list** (`docker buildx imagetools create`) referencing both digests.
Login via the workflow `GITHUB_TOKEN` with `packages: write`.

**Rationale**: Native runners satisfy FR-019 ("native, not emulation") and are faster + correct for
arm64 than QEMU. The per-digest + manifest-list pattern is the standard way to publish multi-arch from
separate native builders.

**Alternatives rejected**: `buildx` with QEMU emulation (slow; the request explicitly wants native
runners); a single emulated multi-platform build.

**Tags** (FR-020): default-branch push → `sha-<short>` and the branch name; tagged release → the
semver tag + `latest`, with the multi-arch manifest carrying those tags.

## 3. Image signing + SBOM (supply-chain hardening)

**Decision**: **cosign keyless** (Sigstore, GitHub OIDC) signs each published image digest; an **SBOM**
(SPDX) is generated with **Syft** and attached as a cosign attestation; **build provenance** (SLSA) is
emitted by the build step. Bases are minimal/distroless and run as **non-root**.

**Rationale**: Keyless avoids private-key custody and binds signatures to the workflow identity; fits
the eIDAS/QES posture and the supply-chain hardening already applied to the SDK's CI (FR-023, SC-009).

**Alternatives rejected**: cosign key-pairs (key management burden); no signing/SBOM (rejected in
clarification).

## 4. Credential-free fixtures = a mock upstream HTTP server

**Decision**: A small **Go HTTP stub** implements the exact CSC/OIDC + RFC 3161 TSA endpoints the SDK
drives (`/oauth2/authorize`, `/oauth2/token`, `/csc/v{1,2}/credentials/list`, `/credentials/info`,
`/signatures/signHash`, and a TSA `/tsr`). The signing service points its **base URL** at the mock in
fixtures mode and runs the **same effect-performing HTTP path** as live. The mock signs `signHash`
requests with the SDK's **synthetic fixture key** and issues timestamps from a local TSA, so the
produced CMS validates with **OpenSSL** exactly as in the SDK's `independent_validation` test. The
mock's `/oauth2/authorize` immediately 302-redirects back with a canned `code`+`state`, so the flow is
fully automatable without a human.

**Rationale**: Identical HTTP path ⇒ fixtures↔live is a base-URL + credentials change only (FR-014);
the response shapes derive from the SDK's authoritative recorded fixtures + synthetic PKI (FR-015,
DRY). It exercises the real serialization/parse boundary, not an in-process shortcut.

**Alternatives rejected**: in-process canned responses (diverges from the live code path); a
record/replay proxy (needs recorded live traffic we do not yet have).

## 5. Session store

**Decision**: An in-memory `map[correlationID]Session` behind a `SessionStore` interface, with TTL
eviction; the OAuth `state` is indexed to its correlation id. A shared/persistent implementation
(e.g. Redis) is a documented extension point, not built.

**Rationale**: Single-replica reference default (FR-005); the interface keeps it swappable without
touching the loop.

## 6. Backend REST API + authentication

**Decision**: Go stdlib `net/http` with a tiny router; endpoints `POST /v1/sign/start`,
`POST /v1/sign/complete`, `GET /v1/sign/status`, `GET /v1/sign/result`, plus `GET /healthz` /
`GET /readyz`. A **bearer API-key** middleware (env `REFSVC_API_KEY`) is **on by default**; it is
disabled only when explicitly configured for local fixtures runs. Missing/invalid key → `401` before
any signing work (FR-025).

**Rationale**: Implements the frontend-helper contract (start/complete/status) + result retrieval
(FR-002), and prevents a deployed image from being an open signing-initiation endpoint.

## 7. Web frontend

**Decision**: A minimal vanilla-TypeScript page built on the existing `frontend/helper-ts` package
(no framework), bundled to static assets and served by a small static-file image. It hosts the
registered **redirect-return route** that parses `code`+`state` (or `error`+`state`) and forwards them
to the backend via the helper's `complete`/`reportRedirectError`.

**Rationale**: Thin, no-crypto reference UI (FR-010/011/012) reusing the helper; minimal surface keeps
it illustrative and auditable (Constitution IV).

## 8. Backend coverage gate (≥95%)

**Decision**: `go test -coverprofile` over the signing-service logic packages with a CI gate failing
below **95%** line coverage; tests are written test-first. The mock-upstream is test scaffolding and is
covered by use in the E2E; the thin frontend and `main`/wiring are exempt from the unit floor.

**Rationale**: The service carries real logic (effect loop, session lifecycle, mapping, auth) and is
deployable, so it is a first-class package under Constitution VI (FR-024, SC-008).

## 9. CI structure

**Decision**: Extend the repo's existing `Lint`/`Tests` workflows with Go-service jobs
(golangci-lint + `go test` ≥95%) and a **credential-free E2E** job (compose up the mock + service,
drive the **backend HTTP API**, validate the signed PDF with OpenSSL). Add a separate **`images`**
workflow (the native multi-arch → GHCR + cosign + SBOM pipeline) triggered on default-branch pushes
and tags.

**Rationale**: Keeps the merge-gating tests (lint, unit ≥95%, E2E) in the always-on workflows
(FR-021), and isolates the heavier image publish in its own workflow (FR-019/020).

## 10. Standards & versions targeted (Constitution II)

The integration drives the SDK's standards-conformant flow: **OAuth 2.0 (RFC 6749)** + **OIDC Core
1.0**, **CSC v1 (RSA)** and **CSC v2 (ECDSA P-256)**, **PAdES (ETSI EN 319 142)** B-B/B-T via the core,
and **RFC 3161** timestamping. The mock upstream implements the CSC/OIDC + TSA subset already
documented in `specs/001-remote-qes-signing/contracts/external-dependencies.md` (single source — the
mock does not re-specify the contract). No proprietary protocol divergence is introduced.
