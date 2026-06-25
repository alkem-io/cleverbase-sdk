# Implementation Plan: ECDSA P-256 validation parity + live Cleverbase-account signing

**Branch**: `feature/003-ecdsa-and-live-signing` | **Date**: 2026-06-24 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `specs/003-ecdsa-and-live-signing/spec.md`

## Summary

The Rust core **already produces and self-verifies a correct ECDSA P-256 signature end-to-end** — the
gap is purely **independent-validation coverage**: the mock upstream signs RSA-only, the credential-free
E2E runs `v1_rsa` only, and `independent_validation.rs` is RSA-hardcoded, so ECDSA has never been driven
through a full begin→authorize→sign→assemble→independently-verify flow. This feature closes that gap by
making **signature algorithm a parameter** of the test/fixture/reference layer (RSA + ECDSA P-256 share
one DRY path), adds an **opt-in PAdES/eIDAS profile-conformance gate** over produced signatures, and adds
a **gated live contract path** that signs against the real Cleverbase service through a **pluggable
authorizer** (interactive default + opt-in headless) and independently verifies the result against the
real Cleverbase trust chain.

The technical approach is settled by research (see `research.md`): **no `cleverbase-core` changes** (it is
already algorithm-parametric and DRY); all work is in `tests/fixtures/`, the mock upstream, the E2E
harness, `independent_validation.rs`, and new opt-in CI tooling.

## Technical Context

**Language/Version**: Rust 1.94.1 (core + `independent_validation.rs`); Go 1.22+ (reference integration,
E2E, the live harness + Authorizer); Python 3.11+ (opt-in pyHanko profile gate); Java 17 via container
(opt-in EU DSS baseline-level assertion). TypeScript/frontend surfaces are **unaffected**.

**Primary Dependencies**: existing — `p256`, `rsa`, `der` crates (core, already present); the `openssl`
CLI (always-on independent validation, already used). **New, opt-in only**: `pyhanko-cli` (MIT, pip) and
the EU DSS container — neither is linked into the shipped SDK (Constitution Principle V: pluggable
validation backend).

**Storage**: N/A (no persistence introduced).

**Testing**: `cargo test` (`independent_validation.rs` gains an ECDSA arm + a B-T ECDSA arm); `go test`
(credential-free E2E becomes an algorithm table `{v1_rsa, v2_ecdsa}` × `{B-B, B-T}`; `live_test.go`
becomes a full gated live contract path); `openssl cms -verify` (always-on, algorithm-agnostic);
`pyhanko adesverify` + EU DSS (opt-in profile gate).

**Target Platform**: Linux + macOS CI runners (matches existing jobs).

**Project Type**: Polyglot SDK monorepo (Rust core + C-ABI + Go/Python/Node bindings + reference
integration). This feature touches the **core's test crate**, **fixtures**, the **reference
integration**, and **CI** — not the shipped SDK API.

**Performance Goals**: N/A — this is a validation/coverage + contract-test feature; no hot paths.

**Constraints**: unit-test coverage stays **≥95% per crate/package** (Principle VI); the credential-free
pipeline stays **fully runnable with zero external dependencies** and green; the live path is **opt-in,
skipped when credentials are absent**, and **never commits/logs secrets** (Principle IV / FR-010);
**no `cleverbase-core` source change** (the core already supports ECDSA — changing it would be
out-of-scope, Principle VIII).

**Scale/Scope**: 2 algorithms (RSA-2048, ECDSA P-256) × 2 conformance levels (B-B, B-T), one new Go
`Authorizer` abstraction (2 impls), one reproducible PKI generation script, two opt-in CI validation
jobs (profile-conformance, live).

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Assessment | Status |
|-----------|-----------|--------|
| I. Production-Grade Completeness | Ships ECDSA parity + the live contract path complete; no stubs (the existing `live_test.go` smoke stub is replaced by a full gated path). | ✅ PASS |
| II. Standards-First Conformance | Cites ETSI EN 319 142 (PAdES B-B/B-T profile gate), CSC v1/v2, RFC 3161, ecdsa-with-SHA256 (`1.2.840.10045.4.3.2`). | ✅ PASS |
| III. Single Rust Core, Idiomatic Bindings | **Zero core/binding changes**; no crypto/protocol logic added or duplicated. Algorithm dispatch already lives once in the core. | ✅ PASS |
| IV. Security & Cryptographic Rigor | Real credentials only via secure external config, never committed/logged (FR-010); no hand-rolled crypto (reuse `p256`/`rsa`/openssl/pyHanko/DSS). | ✅ PASS |
| V. Own the Full AdES Stack | The opt-in profile gate uses the **pluggable validation backend** the constitution names (pyHanko / EU DSS), self-hosted, never an external hosted service. | ✅ PASS |
| VI. Test-First & Contract-Tested (≥95%) | The feature *is* test coverage: write the failing ECDSA E2E + `independent_validation` arms first; contract-test against the real Cleverbase surface (live path); independent-validator checks on produced signatures. Coverage floor preserved. | ✅ PASS |
| VII. Versioning & ABI Stability | No ABI/API surface change. | ✅ PASS |
| VIII. DRY · RCA · No Opportunistic Edits | DRY is the central mandate (FR-004): one algorithm-parametrized fixture/sign/validate path, no RSA/ECDSA copy-paste. Scope is held to the ECDSA gap + live path; the PKI `gen.sh` is in-scope (it makes the algorithm-parametrized fixtures reproducible — a stated research gap, not a drive-by). | ✅ PASS |

**Result**: No violations. Complexity Tracking is empty.

## Project Structure

### Documentation (this feature)

```text
specs/003-ecdsa-and-live-signing/
├── plan.md              # This file
├── research.md          # Phase 0 — decisions (grounded in the codebase research)
├── data-model.md        # Phase 1 — entities (Signer fixture, Authorizer, Profile-gate result, …)
├── quickstart.md        # Phase 1 — runnable validation scenarios
├── contracts/           # Phase 1 — interface contracts
│   ├── authorizer.md            # the Go Authorizer interface (interactive | headless)
│   ├── algorithm-fixtures.md    # mock multi-signer + credentials_info variants + PKI gen recipe
│   ├── live-contract-path.md    # live flow, config env vars, gating/skip semantics
│   └── profile-conformance-gate.md  # opt-in pyHanko/DSS gate contract
└── checklists/requirements.md   # spec quality checklist (already 16/16)
```

### Source code (repository root) — files this feature touches

```text
tests/fixtures/
├── pki/gen.sh                       # NEW — reproducible PKI recipe (ca, signer-rsa, signer-ec, tsa)
└── upstream/                        # credentials_info: generalize to per-algorithm (RSA + ECDSA) variants

crates/cleverbase-core/
└── tests/independent_validation.rs  # parametrize over KeyAlgo: add ECDSA B-B + B-T arms (NO src change)

examples/reference-integration/
├── mock-upstream/mock/
│   ├── server.go                    # multi-signer: hold RSA+EC keys, select per routed CSC base (v1→RSA, v2→EC)
│   └── server_test.go               # assert the route's expected algorithm (not hardcoded RSA)
└── signing-service/
    ├── e2e/credfree_test.go         # table: {v1_rsa, v2_ecdsa} × {B-B, B-T}; reuse validateCMS unchanged
    ├── e2e/live_test.go             # full gated live contract path (start→authorize→complete×2→result→verify)
    ├── e2e/authorizer.go            # NEW — Authorizer interface + Interactive (default) & Headless impls
    └── internal/config/config.go    # live knobs: authorizer mode + real trust-anchor (CA bundle)

scripts/
└── validate-pades.sh                # NEW — opt-in profile-conformance gate (pyHanko adesverify; DSS baseline-level)

.github/workflows/
├── test.yml                         # add the ECDSA E2E arm to the credential-free job (still no external deps)
├── profile-conformance.yml          # NEW — opt-in gate (off by default), runs validate-pades.sh
└── live.yml                         # NEW — opt-in live job, gated on real-credential secrets, skip-when-absent
```

**Structure Decision**: **Extend the existing monorepo in place** — no new top-level project. The feature
is a test/fixture/reference-integration + CI change layered on the unchanged core. The one new
abstraction is the Go `Authorizer` interface (research confirms the SDK/flow need no change — the
authorizer seam is purely in the E2E harness, replacing the mock's auto-follow). The one new fixture
asset is the reproducible PKI `gen.sh`. Everything else parametrizes existing RSA-hardcoded code by
algorithm.

## Complexity Tracking

> No Constitution violations — this section is intentionally empty.

## Phasing within the feature (delivery order)

Aligned to the spec's user-story priorities (P1 ships first, independently):

1. **P1 — ECDSA credential-free parity** (US1): PKI `gen.sh` → mock multi-signer → `credentials_info`
   per-algorithm → E2E algorithm table → `independent_validation.rs` ECDSA B-B/B-T arms. Delivers the
   headline gap closure with **zero external dependencies**.
2. **Opt-in profile-conformance gate** (FR-014): `scripts/validate-pades.sh` + the off-by-default CI job,
   exercised over the credential-free B-B/B-T PDFs for both algorithms.
3. **P2 — live contract path** (US2): `Authorizer` interface (interactive default) → full `live_test.go`
   flow + live verification against the real trust anchor → opt-in `live.yml` gated on secrets; headless
   authorizer is a drop-in added when an automatable Cleverbase test approval exists.

Test-first throughout (Principle VI): each parametrized test/arm is written to fail before the
fixture/mock change makes it pass.
</content>
