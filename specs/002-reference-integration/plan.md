# Implementation Plan: Reference Integration Services & Container Delivery

**Branch**: `feature/reference-integration` | **Date**: 2026-06-24 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `specs/002-reference-integration/spec.md`

## Summary

Build a runnable, deployable **reference integration** for the Cleverbase SDK: a Go **signing
service** that embeds the SDK via the existing Go binding and performs the sans-IO core's I/O, a thin
no-crypto **web frontend** on `frontend/helper-ts` — **extended** to surface the second
(credential-scope/SCAL2) authorization redirect (`complete()` → `{ status, redirectUrl? }`, a
`0.1.0→0.2.0` change; see T012/T017) — and a **mock upstream** that serves the SDK's recorded fixtures
so the entire signing journey runs **without Cleverbase credentials** and is gated in CI. Package both services as **cosign-signed, SBOM-attested, multi-arch (amd64+arm64)** GHCR images
built on **native GitHub runners**, deployable via Docker Compose and Kubernetes (Kustomize).
Switching to live Cleverbase acceptance is a configuration change only. Full technical decisions are
in [research.md](./research.md).

## Technical Context

**Language/Version**: Go ≥ 1.22 (signing service + mock upstream, cgo over `cleverbase-ffi`);
TypeScript ≥ 5 (web frontend, on the existing `frontend/helper-ts`); Rust per the workspace
`rust-toolchain.toml` (the SDK staticlib, already built).

**Primary Dependencies**: existing `bindings/go` (Go binding) + `cleverbase-ffi` staticlib;
`fxamacker/cbor` (already a binding dep); `frontend/helper-ts`; Docker buildx; cosign (keyless),
Syft (SBOM); Kustomize. No web framework (vanilla TS); Go stdlib `net/http`.

**Storage**: in-memory session store behind a `SessionStore` interface (TTL eviction); no external
database. Pluggable persistent store documented, not built.

**Testing**: `go test` with a **≥95% line-coverage gate** on the signing service; `golangci-lint`;
a credential-free **backend-API E2E** (compose up mock + service, drive the REST API, validate the
signed PDF with OpenSSL); image start/health smoke on each architecture.

**Target Platform**: Linux containers, `linux/amd64` + `linux/arm64`; Docker and Kubernetes.

**Project Type**: multi-service (web frontend + backend service + mock) — reference integration.

**Performance Goals**: not latency-critical (human-paced signing flow). SC-001: full credential-free
run achievable in < 10 minutes from a clean checkout. Image builds use native runners (no QEMU).

**Constraints**: secrets (client secret, tokens, SDK handle) stay server-side and never reach the
frontend; the PDF stays in the backend (hash-only upstream); fixtures↔live is a base-URL+credentials
config change only; published images non-root, distroless, signed, SBOM-attested.

**Scale/Scope**: single-replica reference; only in-flight sessions are stateful; single-tenant. HA,
durable storage, and multi-tenant routing are out of scope.

## Constitution Check

*GATE: re-checked after Phase 1 design — PASS with the obligations noted.*

| Principle | Assessment |
|-----------|------------|
| I. Production-Grade Completeness | **PASS** — the deliverable (credential-free runnable stack + multi-arch signed images + live-by-config) is complete, not a stub. Live signing is gated on external credentials (US2) — that is *phasing of WHAT ships*, not a half-feature; the architecture supports it with config only. |
| II. Standards-First Conformance | **PASS** — drives the SDK's conformant OAuth2/OIDC/CSC/PAdES/RFC-3161 flow; the mock implements the CSC/OIDC+TSA subset already specified in `specs/001-remote-qes-signing/contracts/external-dependencies.md` (no re-spec, no proprietary divergence). |
| III. Single Rust Core, Idiomatic Bindings | **PASS** — the Go service uses the **existing** Go binding and re-implements **no** protocol/crypto; it only performs I/O + session orchestration. |
| IV. Security & Cryptographic Rigor | **PASS** — secrets server-side; frontend is the no-crypto helper; backend API-key auth on by default; PDF stays in backend. |
| V. Own the Full AdES Stack | **PASS (no new logic)** — all AdES work stays in the SDK; the integration only drives it. |
| VI. Test-First & Contract-Tested (≥95%) | **PASS w/ obligation** — signing service ≥95% unit coverage, test-first; the credential-free E2E against the mock is the documented-stub contract test; live contract tests are US2 (external-credential-gated). |
| VII. Versioning & ABI Stability | **PASS** — the service declares the SDK core + Go-binding version it wraps; image tags follow SemVer on release. |
| VIII. DRY / RCA / No opportunistic | **PASS** — fixtures reuse the SDK's authoritative recorded shapes + synthetic PKI (single source); no parallel copy; scope limited to this feature. |

No violations → **Complexity Tracking is empty**.

## Project Structure

### Documentation (this feature)

```text
specs/002-reference-integration/
├── plan.md              # This file
├── research.md          # Phase 0 decisions
├── data-model.md        # Entities + session lifecycle
├── quickstart.md        # Run/validation scenarios
├── contracts/
│   └── reference-service-api.md   # Backend REST API contract
└── tasks.md             # Phase 2 (/speckit-tasks — not created here)
```

### Source Code (repository root)

```text
examples/reference-integration/
├── signing-service/                 # Go backend (embeds the SDK via bindings/go, cgo)
│   ├── cmd/refsvc/main.go           # wiring + config load + HTTP server
│   ├── internal/
│   │   ├── config/                  # RunProfile from env; fail-fast validation
│   │   ├── session/                 # SessionStore (in-memory, TTL) + status mapping
│   │   ├── flow/                    # begin/resume loop, performs HTTP effects
│   │   ├── httpapi/                 # start/complete/status/result/health + API-key auth
│   │   └── upstream/                # net/http client for the emitted effects
│   ├── Dockerfile                   # multi-stage: rust staticlib → cgo Go build → distroless/cc
│   └── *_test.go                    # ≥95% unit coverage (test-first)
├── mock-upstream/                   # Go stub: CSC/OIDC + RFC 3161 TSA serving SDK fixtures
│   ├── cmd/mockupstream/main.go
│   ├── internal/…                   # authorize/token/list/info/signHash + TSA, synthetic PKI
│   └── Dockerfile
├── web/                             # thin no-crypto TS UI on frontend/helper-ts
│   ├── src/                         # start/return pages; wires helper start/complete/status
│   ├── Dockerfile                   # static bundle served by a minimal static image
│   └── package.json
├── deploy/
│   ├── compose.yml                  # local full stack (fixtures)
│   └── k8s/
│       ├── base/                    # plain manifests for the 3 services
│       └── overlays/{fixtures,live}/# Kustomize overlays (mode + secrets)
└── README.md

.github/workflows/
├── lint.yml   (extend)              # + golangci-lint for the Go service/mock
├── test.yml   (extend)              # + go test ≥95% gate + credential-free backend-API E2E
└── images.yml (new)                 # native amd64+arm64 → GHCR + cosign + SBOM
```

**Structure Decision**: the reference integration lives under `examples/reference-integration/`
(grouped with the SDK's usage examples per Constitution I's "demos are examples" framing), but the
`signing-service` is treated as a first-class package under the ≥95% coverage gate (FR-024). Fixtures
are sourced from the SDK's existing `tests/fixtures/pki/` and recorded shapes (DRY); CI work extends
the repo's existing `lint`/`test` workflows and adds a dedicated `images` workflow.

## Complexity Tracking

No Constitution violations — table intentionally empty.
