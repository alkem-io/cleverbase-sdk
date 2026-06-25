# Implementation Plan: EUDI attestation — verification now, issuance forward-looking

**Branch**: `feature/004-attestation-and-verification` | **Date**: 2026-06-25 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `specs/004-attestation-and-verification/spec.md`

## Summary

Add **EUDI attestation** to the SDK: a complete, standards-based **verifier** now (verify presented
SD-JWT VC **and** ISO/IEC 18013-5 mdoc credentials — issuer signature, EU-trust-list membership, validity,
revocation/status, holder binding, selective-disclosure integrity, and replay/audience binding via a full
OpenID4VP request+verify), plus an **opt-in eIDAS qualified-status determination** (ETSI TS 119 615 cl.
4.12), and a **forward-looking, gated issuance/holding/presentation** path (OpenID4VCI/OpenID4VP) whose
issuer is a configurable backend and whose live path is skipped until a real issuer API (Cleverbase's, when
it ships) exists.

Research (`research.md`) settles the approach: **verification is buildable now with no hand-rolled crypto**
(EUDI's ES256/P-256/SHA-256 baseline is a strict subset of the crates the SDK already owns); the work is to
build the **format verifiers** (SD-JWT VC on `sd-jwt-payload` + in-house issuer-JWS; mdoc on
`ciborium`+`coset` + in-house digest/validity checks), a **native Rust EU trust-list engine** (no Rust
tooling exists — the biggest build), the OpenID4VP **binding** layer (DCQL), and reuse the **spec-001
signer-hook** for holder key custody (the SDK is not a wallet). Cleverbase has **no EUDI issuer API today**,
so live issuance is gated like spec-003's live-signing path.

## Technical Context

**Language/Version**: Rust 1.94.1 (the single core — a new `cleverbase-attestation` crate + new
`cleverbase-ffi` C-ABI functions); the existing Go/Python/Node bindings extend over the same C-ABI. A
no-crypto TS frontend helper only if a redirect/presentation orchestration step needs it (no secrets).

**Primary Dependencies**: reuse (already vendored) `p256 0.13`, `ecdsa 0.16`, `rsa 0.9`, `sha2 0.10`,
`ciborium 0.2`, `der`/`spki`/`x509-cert`/`cms` (the AdES X.509 stack), `quick-xml` (trust-list XML). **New,
vetted, permissive**: `coset` (Google, Apache-2.0 — COSE_Sign1/Mac0 codec for mdoc) and `sd-jwt-payload`
(IOTA, Apache-2.0 — SD-JWT/disclosure/KB-JWT format layer; crypto delegated to the existing RustCrypto).
`ed25519-dalek` only if a Member-State profile needs EdDSA (deferrable — outside the EUDI mandatory
baseline). **Reference/oracle only (NOT runtime deps)**: SpruceID `isomdl` + `openid4vp` (conformance
oracles), EU DSS (trust-list/qualification parity oracle, Java sidecar in tests), EU `eudi-srv-pid-issuer`
(gated issuance double), a Kotlin/TS EU reference verifier (independent cross-check for Principle VI).

**Storage**: N/A in the core (sans-IO). Credential custody + holder-binding keys are the **integrator's**
(HSM/KMS) — the SDK orchestrates and never holds them.

**Testing**: `cargo test` (format verifiers, trust-list engine, OpenID4VP binding, negative paths) against
**conformant offline test vectors** (vendored IETF arf-pid SD-JWT VC + multipaz ISO 18013-5 Annex-D mdoc +
a self-signed test PKI; Tier A traceability + Tier B generated negatives); cross-checked against an
**independent (Kotlin/TS) reference verifier** (VI); gated issuance against `eudi-srv-pid-issuer`; the live
Cleverbase issuer path skipped when absent.

**Target Platform**: Linux + macOS CI; the core stays WASM-able (pure-Rust, no JVM/OpenSSL-FFI in the
shipped core — DSS is a test-only sidecar).

**Project Type**: Polyglot SDK monorepo — adds an attestation domain to the single Rust core + C-ABI +
bindings.

**Performance Goals**: N/A (verification is request-scoped, not a hot path); trust-list fetch/refresh is
cached, not per-verification.

**Constraints**: no hand-rolled crypto (IV); the core stays sans-IO + pure-Rust (III); not a wallet, no
holder key/secret in the SDK or a browser (IV); ≥95% per-crate coverage (VI); standards version-**pinned**
(SD-JWT VC draft-16/RFC 9901, OpenID4VP/VCI 1.0 + DCQL, TS 119 612 v2.4.1/TLv6, TS 119 615 v1.4.1 cl.4.12 —
several are pre-operational, mark experimental); produced/obtained artifacts cross-checked against an
**independent, different-language** reference verifier (VI).

**Scale/Scope**: 2 credential formats (SD-JWT VC, ISO mdoc) × the full verifier path; 1 native trust-list
engine; 1 opt-in qualified-status determination; 1 gated issuance/holding/presentation path with a
signer-hook. Large — phased (below).

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Assessment | Status |
|-----------|-----------|--------|
| I. Production-Grade Completeness | Verification ships **complete** (both formats, always-on bar, full verifier). The opt-in qualified gate and gated issuance are **complete capabilities delivered in phases** (not half-features); the *live* Cleverbase issuance is gated like 003 because the upstream API doesn't exist yet — a phasing-of-WHEN, not HOW-complete. | ✅ PASS |
| II. Standards-First | Cites + version-pins SD-JWT VC (RFC 9901 + draft-16), ISO/IEC 18013-5 mdoc, OpenID4VP 1.0 (DCQL), OpenID4VCI 1.0, ETSI TS 119 612/602 (trust lists), TS 119 615 cl.4.12 (qualified determination), eIDAS (EU 2024/1183). | ✅ PASS |
| III. Single Rust Core, Idiomatic Bindings | All logic in one Rust core (new `cleverbase-attestation` crate, same workspace + C-ABI); thin bindings; no per-language crypto/protocol. Core stays pure-Rust/WASM-able (DSS is test-only). | ✅ PASS |
| IV. Security & Cryptographic Rigor | No hand-rolled crypto (reuse RustCrypto + `coset`); **not a wallet** — holder keys stay in the integrator's HSM via the spec-001 **signer-hook**; no secret in a browser. | ✅ PASS |
| V. Own the Full AdES/Trust Stack | The SDK **owns** the verification stack (native trust-list + qualified-status engine — no reference engine exists for QEAA); DSS/Kotlin references are **test parity/cross-check oracles**, never a hosted dependency that sees private data. | ✅ PASS |
| VI. Test-First & Contract-Tested (≥95%) | Test-first against conformant offline vectors; **independent different-language reference verifier** cross-check; gated issuance against the EU reference issuer; live Cleverbase contract gated/skipped. Coverage floor held. | ✅ PASS |
| VII. Versioning & ABI Stability | Additive C-ABI + binding surface (SemVer minor). Experimental/pre-operational standards + pre-1.0 reference crates are **pinned**; reference crates are oracles, not shipped deps. | ✅ PASS |
| VIII. DRY · RCA · No Opportunistic Edits | Reuse the signer-hook (DRY with signing) and one trust-list primitive shared by the always-on bar + the opt-in qualified gate. Scope held to attestation; no drive-by edits to signing. | ✅ PASS |

**Result**: No violations. Significant **build risks** (not violations) are tracked in Complexity Tracking.

## Project Structure

### Documentation (this feature)

```text
specs/004-attestation-and-verification/
├── plan.md, research.md, data-model.md, quickstart.md
├── contracts/
│   ├── verifier.md              # verify(presentation, policy) -> verdict; always-on bar
│   ├── openid4vp-verifier.md    # build request (DCQL + nonce + audience) + verify bound response
│   ├── qualified-status-gate.md # opt-in ETSI TS 119 615 cl.4.12 determination
│   ├── trust-anchor-source.md   # pluggable EU LOTL / Trusted List / IACA / per-role anchors
│   └── holder-signer-hook.md    # gated issuance/holding/presentation; integrator-owned key custody
└── checklists/requirements.md   # spec-quality checklist (16/16 items pass)
```

### Source code (repository root) — new + touched

```text
crates/
├── cleverbase-attestation/      # NEW crate (the single Rust core's attestation domain)
│   ├── src/sdjwtvc/             # SD-JWT VC verify: disclosures+KB (sd-jwt-payload) + in-house issuer-JWS + vct
│   ├── src/mdoc/                # ISO 18013-5 verify: ciborium+coset + in-house valueDigests + MSO validityInfo
│   ├── src/openid4vp/           # verifier: DCQL request build + vp_token binding (nonce/audience) verify
│   ├── src/trust/               # native EU trust-list engine (TS 119 612/602 LOTL/LoTE; IACA; per-role anchors)
│   ├── src/qualified/           # opt-in TS 119 615 cl.4.12 qualified-status determination (reuses trust/)
│   ├── src/issuance/            # forward-looking OpenID4VCI + holder presentation, gated; signer-hook seam
│   └── tests/                   # conformance vectors + negatives + independent-verifier cross-check
└── cleverbase-ffi/              # extend the C-ABI with attestation verify/issue functions (CBOR in/out)

bindings/{go,python,node}/       # thin idiomatic shims over the new C-ABI functions
tests/fixtures/attestation/      # NEW: vendored (arf-pid SD-JWT VC, Annex-D mdoc, test PKI) + a gen recipe
.github/workflows/               # attestation verify suite (always-on, offline) + opt-in cross-check/issuance jobs
```

**Structure Decision**: Add a **new `cleverbase-attestation` crate** in the existing workspace (attestation
is a distinct domain from signing), surfaced through the **existing `cleverbase-ffi` C-ABI** + the existing
bindings — still "one Rust core, one C-ABI, thin bindings" (Principle III). The trust-list engine and the
signer-hook are the two load-bearing new abstractions; the latter is a direct reuse of the spec-001 signing
pattern.

## Complexity Tracking

> No Constitution violations. These are **build risks** surfaced by research, recorded so planning/tasks
> account for them (not justifications for violations).

| Risk | Why it exists | Mitigation |
|------|---------------|------------|
| **No Rust tooling for EU trust lists (TS 119 612/602/LOTL)** — biggest build | The ecosystem has only Java (EU DSS) / Kotlin libs | Build a native Rust trust-list engine (`quick-xml` + the existing X.509 stack); use EU DSS as a **test-only** cross-language parity oracle. Keeps the core pure-Rust/WASM-able (III/IV rationale). |
| **Rust mdoc verification is immature** (`isomdl` omits valueDigests-match + MSO validity) | No safe drop-in verifier exists | Build the security-critical mdoc checks in-house on `ciborium`+`coset`+existing crypto; use `isomdl` as a data-model donor + test oracle only. |
| **TS 119 615 cl.4.12 QEAA qualification is pre-operational; OID4VP/VCI + SD-JWT VC drafts in flux; reference crates pre-1.0** | Standards/ecosystem mid-rollout (EUDI ~end-2026) | Make qualified-status **opt-in** + version-pinned + honest `Indeterminate` where TL data is absent; pin all standards/oracle versions; keep references as oracles, not shipped deps. |
| **Independent cross-check must cross languages** (Principle VI) | Rust-vs-Rust is not independent | Cross-check the Rust verifier against a Kotlin/TS EU reference verifier in CI (opt-in job). |

## Phasing within the feature (delivery order)

Each phase is a complete, independently testable increment (Principle I):

1. **P1 — Verification MVP (US1)**: the native trust-list engine (always-on bar) → SD-JWT VC verify → mdoc
   verify → the OpenID4VP full-verifier binding (DCQL request + nonce/audience-bound verify) → negative
   paths (FR-005). Both formats, **zero external dependency** (offline vectors), cross-checked against an
   independent reference verifier. Ships first.
2. **Opt-in qualified-status gate (FR-014)**: TS 119 615 cl.4.12 determination over the trust-list
   primitives; off by default, version-pinned, honest `Indeterminate`.
3. **P2 — Issuance/holding/presentation (US2), gated**: OpenID4VCI issuance + holder OpenID4VP presentation
   via the **signer-hook**; issuer as a configurable backend; exercised against the EU reference issuer and
   **skipped** when no issuer API is configured (the spec-003 live-signing gating pattern); a future
   Cleverbase issuer drops in by configuration.

Test-first throughout; no hand-rolled crypto; the core stays sans-IO + pure-Rust.
</content>
