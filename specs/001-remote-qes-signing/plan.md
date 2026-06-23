# Implementation Plan: Remote Qualified Signing (PAdES B-B / B-T)

**Branch**: `001-remote-qes-signing` (spec dir; no git branch — git hook not installed) | **Date**: 2026-06-22 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `specs/001-remote-qes-signing/spec.md`

## Summary

Deliver the first slice of the Cleverbase SDK: obtain a **Qualified Electronic Signature (QES)**
on a PDF, where a human signer authorizes in their Cleverbase wallet, producing a signed PDF at
PAdES conformance **B-B** and **B-T**. Because Cleverbase signs only a hash (no container,
timestamp, or validation — verified against its live CSC service), the SDK owns the whole AdES
stack.

Technical approach: a single **memory-safe Rust core** implemented **sans-IO** — it is a pure,
serializable state machine that performs all cryptography (hashing, CMS/PKCS#7 assembly, PAdES
container construction, RFC 3161 timestamp request/embedding) and *emits effects* (HTTP requests
to perform, browser redirect URLs to issue) which the host executes. Network I/O, persistence, and
clock live in the host; the core stays pure, deterministic, WASM-able, and trivially
contract-testable against recorded HTTP fixtures. Thin idiomatic bindings — **Python (PyO3)**,
**TypeScript/Node (napi-rs)** and **Go (cgo over a C ABI)** — expose the same operations. The
browser frontend helper shipped in this phase is **pure TypeScript** (redirect orchestration +
status polling, no crypto); a WASM build of the core for the browser is a later enhancement (the
core is kept WASM-able for it). The signing pipeline is a staged augmentation flow
(Sign → +Timestamp → … → Validate) with all seams present from day 1; this slice wires B-B and B-T.

## Technical Context

**Language/Version**: Rust (stable, edition 2021, MSRV 1.83 — the workspace `rust-version`) for the core. Bindings:
Python ≥ 3.9 (PyO3 + maturin), Node ≥ 18 / TypeScript ≥ 5 (napi-rs), Go ≥ 1.22 (cgo over the C ABI).
The browser helper is pure TypeScript in this phase; a `wasm32-unknown-unknown` (wasm-bindgen)
build of the core is deferred to a later enhancement.

**Primary Dependencies** (Rust core, all pure / no network):

- PDF: `lopdf` (low-level read + incremental-update writing; ByteRange + signature placeholder).
- AdES/CMS: RustCrypto `cms`, `x509-cert`, `der`, `spki`, `const-oid`.
- Crypto: RustCrypto `sha2`, `rsa`, `p256` + `ecdsa` + `signature` (handles **RSA** for CSC v1 and
  **ECDSA P-256** for CSC v2), `rand_core` (salts/nonces via host-provided entropy).
- Timestamp: RFC 3161 `TimeStampReq`/`TimeStampToken` built/parsed with `cms` + `der`.
- Tokens/JOSE: `jsonwebtoken` (validate OIDC `id_token` RS256) — deferred along with OIDC `sub`
  matching and the HS256 multi-tenant `account_token` (see docs/limitations.md); not used in Phase 1.
- FFI/WASM wire format: `ciborium` (CBOR) for the C ABI and WASM boundary; `serde` throughout.
- NO `tokio`, NO `reqwest` — the core is sans-IO.

Binding/tooling: PyO3 + maturin; napi-rs; wasm-bindgen; cgo + a `cdylib`/`staticlib` C-ABI shim.

**Storage**: None in the SDK. The SDK is stateless; the integrator persists the opaque, serializable
**Signing Session Handle** between the authorization round-trip and finalization. The handle may
carry short-lived authorization material and MUST be stored securely server-side.

**Testing**: `cargo test` + `proptest` (core); `pytest`, `vitest` (or jest), `go test` (bindings);
**contract tests** replay recorded Cleverbase CSC/OIDC HTTP fixtures into the sans-IO core and also
run against the Cleverbase **acceptance** environment + public stub credentials; **independent
validation** of every produced CMS in CI via **OpenSSL** (an independent implementation).
**EU DSS** (PAdES/QES + timestamp) and **veraPDF** (PDF/A) are recommended for integrator-side
acceptance and are not run by this repo's CI (see `docs/limitations.md`). Coverage via
`cargo-llvm-cov` gates the Rust crates at ≥ 95%; bindings are gated by their full test suites.

**Target Platform**: Linux x86_64/aarch64 (glibc + musl), macOS arm64/x64, Windows x64; plus
`wasm32` for the browser helper. Prebuilt artifacts shipped per platform (wheels, napi prebuilds,
cdylib releases).

**Project Type**: Multi-language SDK (library) — Rust core workspace + 3 language bindings + TS
frontend helper + runnable demos.

**Performance Goals** (SDK overhead only; end-to-end latency is dominated by human authorization):
container assembly + signature embedding **< 200 ms** for a typical (≤ 5 MB) PDF; signature/PDF
verification in tests **< 100 ms**; the sans-IO core adds no blocking I/O of its own.

**Constraints**: sans-IO core (no network, no ambient clock — time + entropy injected as inputs);
secrets server-side only; thin TS frontend helper performs no crypto and handles no secrets; stable
C-ABI within a major version; ≥ 95% unit coverage; SHA-256 only (the sole hash Cleverbase's CSC
service advertises).

**Scale/Scope**: Phase 1 = QES signing at PAdES B-B + B-T, across Go/TS/Python + the FE helper +
demos. Stateless ⇒ horizontally scalable; concurrent signing sessions are unbounded by the SDK
(bounded only by the host). Out of scope (architected-for, later phases): B-LT/B-LTA + LTV, the
runtime eIDAS validation sidecar, non-PDF formats (CAdES/XAdES/JAdES), identification/auth/
attestation, batch/multi-document authorization.

## Constitution Check

*GATE: must pass before Phase 0 and re-checked after Phase 1 design.*

| # | Principle | How this plan satisfies it | Status |
|---|-----------|----------------------------|--------|
| I | Production-grade completeness | Ships complete B-B **and** B-T, all 3 bindings + FE helper; no stubs. Higher AdES levels are deferred *phases*, not partial features. | PASS |
| II | Standards-first conformance | CSC API v1 (RSA) + v2 (ECDSA-P256), OAuth 2.0 / OIDC, PAdES (ETSI EN 319 142), RFC 3161, PDF/A (ISO 19005). Targeted versions recorded in research.md. | PASS |
| III | Single Rust core, idiomatic bindings | One sans-IO core holds all protocol+crypto logic; PyO3/napi/cgo/WASM are thin mappers. No logic duplicated per language. | PASS |
| IV | Security & cryptographic rigor | Memory-safe core; vetted RustCrypto libs (no hand-rolled crypto); secrets + session handle server-side; FE helper no crypto/secrets. | PASS |
| V | Own the full AdES stack | Staged augmentation pipeline with all seams (timestamp/revocation/archive/validate) present; this slice wires B-B + B-T; no offload assumed. | PASS |
| VI | Test-first & contract-tested (≥95%) | TDD; contract tests vs Cleverbase (fixtures + acceptance); DSS + veraPDF validation of output; coverage gate ≥ 95% in CI. | PASS |
| VII | Versioning & ABI stability | SemVer; stable C-ABI; versioned CBOR wire schema; bindings declare core version. | PASS |
| VIII | Engineering discipline | DRY (single core, shared fixtures); RCA recorded per fix; changes scoped (no opportunistic edits). | PASS |

**Result: PASS, no violations.** The multi-package polyglot structure is *required* by Principle III
(not excess complexity), so Complexity Tracking is empty. The eIDAS validation sidecar is **not** a
Phase 1 runtime dependency — DSS/veraPDF are used only as independent test validators here.

## Project Structure

### Documentation (this feature)

```text
specs/001-remote-qes-signing/
├── plan.md              # This file
├── research.md          # Phase 0 — decisions & rationale
├── data-model.md        # Phase 1 — entities & state machine
├── quickstart.md        # Phase 1 — runnable validation guide
├── contracts/           # Phase 1 — public API & dependency contracts
│   ├── sdk-api.md
│   ├── frontend-helper.md
│   └── external-dependencies.md
└── checklists/
    └── requirements.md
```

### Source Code (repository root)

```text
crates/
├── cleverbase-core/         # The sans-IO Rust core: state machine, crypto, PAdES pipeline
│   ├── src/
│   │   ├── signing/         # CSC/OIDC orchestration state machine (emits effects)
│   │   ├── pades/           # container assembly, ByteRange, incremental update, appearance, PDF/A
│   │   ├── timestamp/       # RFC 3161 request build + token embed (B-T)
│   │   ├── crypto/          # hashing, CMS, RSA + ECDSA-P256, cert/identity handling
│   │   ├── effects.rs       # HttpEffect / RedirectEffect contract types
│   │   ├── session.rs       # serializable Signing Session Handle
│   │   ├── evidence.rs      # Signing Evidence Record
│   │   └── lib.rs           # typed Rust API (single source of truth)
│   └── tests/               # unit + proptest + fixture-replay contract tests
├── cleverbase-ffi/          # C-ABI shim (cdylib/staticlib): CBOR-in/result-out (Go consumes this)
└── cleverbase-wasm/         # wasm-bindgen surface (frontend helper engine)

bindings/
├── python/                  # PyO3 + maturin → `cleverbase`
├── node/                    # napi-rs → `@cleverbase/sdk` (+ bundled WASM)
└── go/                      # cgo over cleverbase-ffi → `cleverbase`

frontend/
└── helper-ts/               # thin TS helper: start/redirect/return/poll-status (no crypto)

examples/                    # demos per language (usage examples of the finished SDK)
tests/
├── contract/                # shared recorded Cleverbase CSC/OIDC fixtures
└── validation/              # DSS + veraPDF harness over produced signatures
```

**Structure Decision**: A Cargo workspace (`crates/`) holds the core + C-ABI + WASM surfaces;
`bindings/` holds the three thin language packages; `frontend/helper-ts` the browser helper;
`examples/` the demos. This is the canonical shape mandated by Principle III (single core + thin
bindings).

## Complexity Tracking

> No Constitution Check violations — nothing to justify. The polyglot multi-package layout is
> required by Principle III, and the absence of an HTTP client / async runtime in the core is a
> simplification (sans-IO), not added complexity.
