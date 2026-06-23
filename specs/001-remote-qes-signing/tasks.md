---
description: "Task list for Remote Qualified Signing (PAdES B-B / B-T)"
---

# Tasks: Remote Qualified Signing (PAdES B-B / B-T)

**Input**: Design documents from `specs/001-remote-qes-signing/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/, quickstart.md

**Tests**: REQUIRED. Constitution Principle VI (Test-First & Contract-Tested, NON-NEGOTIABLE)
mandates tests authored and approved before implementation, failing first, with ≥95% unit coverage
and independent reference-validator (EU DSS / veraPDF) checks on produced output.

**Organization**: by user story (spec.md): US1 = sign PDF B-B (P1, MVP), US2 = trusted timestamp
B-T (P2), US3 = frontend helper (P3). Cross-cutting FRs attach to the story that produces them.

**Post-analysis remediation (2026-06-22)**: closes `/speckit-analyze` findings — C1 (FR-009
production-config) → T060; C2 (FR-006 RSA+ECDSA-P256 dual-algo) → T031, T048; C3 (FR-007
negative paths) → T032; A1 (FR-016 signature metadata) → T033 + T038; A2 (SC-007 timing) → T064.
Spec↔data-model drift (I1, I2, I3) reconciled directly in spec.md and data-model.md.

## Format: `[ID] [P?] [Story?] Description`

- **[P]**: parallelizable (different files, no incomplete dependencies)
- **[Story]**: US1/US2/US3 for user-story phases only (Setup/Foundational/Polish carry none)

## Path Conventions

Cargo workspace per plan.md: `crates/cleverbase-core` (sans-IO core), `crates/cleverbase-ffi`
(C-ABI); `bindings/{python,node,go}`; `frontend/helper-ts`; `examples/`; shared
`tests/contract`, `tests/validation`, `tests/fixtures`. (A `cleverbase-wasm` crate is deferred —
see T020 / docs/limitations.md — the frontend helper needs no in-browser core.)

---

## Phase 1: Setup (Shared Infrastructure)

- [X] T001 Create Cargo workspace + crate skeletons (`cleverbase-core`, `cleverbase-ffi`) in `Cargo.toml` and `crates/` (`cleverbase-wasm` deferred — see T020)
- [X] T002 [P] Scaffold binding projects in `bindings/python/` (maturin/PyO3), `bindings/node/` (napi-rs), `bindings/go/` (cgo)
- [ ] T003 [P] Scaffold `frontend/helper-ts/` and `examples/` directories
- [ ] T004 [P] Configure lint/format (rustfmt+clippy, ruff/black, eslint/prettier, gofmt/golangci-lint) in repo config files
- [ ] T005 [P] Configure coverage tooling with ≥95% gate (cargo-llvm-cov, pytest-cov, vitest/c8, `go test -cover`) in `tests/coverage.config`
- [X] T006 Set up CI matrix (Linux glibc/musl, macOS arm64/x64, Windows) building core + ffi + 3 bindings in `.github/workflows/ci.yml`
- [ ] T007 [P] Stand up validation harness containers (EU DSS, veraPDF) in `tests/validation/harness/`
- [ ] T008 [P] Add sample inputs (plain PDF, PDF/A) in `tests/fixtures/`

---

## Phase 2: Foundational (Blocking Prerequisites)

**No user story can start until this completes.**

**Tests first (must fail before implementation):**

- [X] T009 [P] CBOR wire-schema round-trip + version tests in `crates/cleverbase-core/tests/wire.rs`
- [X] T010 [P] Session-handle serialize/deserialize/version tests in `crates/cleverbase-core/tests/session.rs`

**Implementation:**

- [X] T011 [P] Define `Effect` (HttpEffect/RedirectEffect) + `Step` union in `crates/cleverbase-core/src/effects.rs`
- [X] T012 [P] Define versioned, serializable `SigningSessionHandle` in `crates/cleverbase-core/src/session.rs`
- [X] T013 [P] Define `SigningEvidenceRecord` + `SigningOutcome` enum in `crates/cleverbase-core/src/evidence.rs`
- [X] T014 [P] Define request/config types (SigningRequest incl. `appearance`/`signature_meta`/`expected_signer`, TrustServiceConfiguration, TsaConfiguration, ExpectedSignerIdentity, SignatureAppearance) in `crates/cleverbase-core/src/types.rs`
- [X] T015 Implement `begin`/`resume` operation shell + `SigningPhase` state enum (no behavior) in `crates/cleverbase-core/src/signing/mod.rs`
- [X] T016 [P] Implement crypto primitives (SHA-256, CMS SignedData builder, **RSA + ECDSA-P256** encoding) in `crates/cleverbase-core/src/crypto/mod.rs`
- [X] T017 [P] Implement PDF primitives (parse, incremental-update writer, AcroForm sig field, ByteRange + `/Contents` placeholder) in `crates/cleverbase-core/src/pades/container.rs`
- [X] T018 [P] Implement OAuth2/OIDC + CSC (v1 + v2) request builders & response parsers (pure effect builders) in `crates/cleverbase-core/src/signing/csc.rs`
- [X] T019 Implement C-ABI shim (`cleverbase_process`/`cleverbase_free`, CBOR) in `crates/cleverbase-ffi/src/lib.rs`
- [~] T020 WASM surface — NOT REQUIRED for US3: the frontend helper performs no crypto (Principle IV), so it needs no in-browser core. Deferred unless a future in-browser non-secret use arises.
- [X] T021 [P] Wire PyO3 binding to core `begin`/`resume` (typed) in `bindings/python/src/lib.rs`
- [X] T022 [P] Wire napi-rs binding to core `begin`/`resume` (typed) in `bindings/node/src/lib.rs`
- [X] T023 [P] Wire Go binding over C-ABI (typed wrapper, CBOR) in `bindings/go/cleverbase.go`
- [ ] T024 Build fixture-replay test harness (feed recorded HTTP into begin/resume) in `tests/contract/harness.rs`

**Checkpoint**: core surface callable from all bindings; primitives + harness ready.

---

## Phase 3: User Story 1 - Sign a PDF (PAdES B-B) (Priority: P1) 🎯 MVP

**Goal**: produce a valid QES on a PDF at PAdES B-B; signer authorizes in wallet; document never leaves integrator infra (hash-only).

**Independent Test**: sign a sample PDF; EU DSS recognizes a valid qualified signature at PAdES B-B; assert no document bytes in any HttpEffect.

**Tests (write first, must fail):**

- [X] T025 [P] [US1] Contract test: full B-B flow over fixtures (service→credential→signHash→embed) in `crates/cleverbase-core/tests/sign_bb.rs`
- [X] T026 [P] [US1] Contract test: hash-bound credential authorization (WYSIWYS) in `crates/cleverbase-core/tests/wysiwys.rs`
- [X] T027 [P] [US1] Contract test: identity binding match + mismatch→`IdentityMismatch` in `crates/cleverbase-core/tests/identity.rs`
- [X] T028 [P] [US1] Contract test: evidence record emitted on success AND failure in `crates/cleverbase-core/tests/evidence_bb.rs`
- [X] T029 [P] [US1] Contract test: stateless resume (persist handle, drop, reload, finalize) in `crates/cleverbase-core/tests/resume.rs`
- [ ] T030 [P] [US1] Contract test: signing an already-signed PDF preserves prior signatures in `crates/cleverbase-core/tests/multi_sig.rs`
- [ ] T031 [P] [US1] Contract+validation test: B-B with **RSA (CSC v1)** AND **ECDSA-P256 (CSC v2)** credentials both produce DSS-valid QES in `crates/cleverbase-core/tests/algo_matrix_bb.rs` (FR-006, closes C2)
- [X] T032 [P] [US1] Negative-path contract tests: **decline vs timeout/expiry** distinction, **CredentialUnavailable**, **document changed between init and sign**, **transient network failure mid-flow recovery**, **AppearancePlacementError** in `crates/cleverbase-core/tests/negative_paths.rs` (FR-007, closes C3)
- [ ] T033 [P] [US1] Contract test: signature metadata (`reason`, `location`) emitted into the PAdES signature dictionary in `crates/cleverbase-core/tests/signature_meta.rs` (FR-016, closes A1)
- [X] T034 [P] [US1] Independent validation test: produced B-B verified by **OpenSSL `cms -verify`** (detached signature, message-digest over ByteRange, chain to CA) in `crates/cleverbase-core/tests/independent_validation.rs`. Deeper **EU DSS** PAdES-conformance gate tracked as follow-up.

**Implementation:**

- [X] T035 [US1] Implement B-B signing state machine (ServiceAuth→CredentialDiscovery→CredentialAuth[hash-bound]→Signing→Completed), incl. the negative terminal outcomes in `crates/cleverbase-core/src/signing/mod.rs`
- [X] T036 [US1] Implement signer-identity verification (cert subject serialNumber / `sub`) in `crates/cleverbase-core/src/crypto/identity.rs` (FR-014)
- [X] T037 [US1] Implement evidence-record emission on all terminal states in `crates/cleverbase-core/src/evidence.rs` (FR-015)
- [X] T038 [US1] Implement CMS embed → B-B PAdES output **including `signature_meta` (reason/location) in the signature dictionary** (splice into `/Contents`) in `crates/cleverbase-core/src/pades/sign.rs` (FR-004, FR-016)
- [X] T039 [P] [US1] Implement optional visible appearance renderer (widget, embedded fonts) in `crates/cleverbase-core/src/pades/appearance.rs` (FR-016)
- [ ] T040 [P] [US1] Implement PDF/A-preserving incremental update + veraPDF validation test in `crates/cleverbase-core/src/pades/pdfa.rs` and `tests/validation/verapdf.rs` (FR-017)
- [ ] T041 [P] [US1] Python B-B sign test + idiomatic wrapper in `bindings/python/tests/test_sign_bb.py`
- [ ] T042 [P] [US1] Node B-B sign test + idiomatic wrapper in `bindings/node/test/sign_bb.test.ts`
- [ ] T043 [P] [US1] Go B-B sign test + idiomatic wrapper in `bindings/go/sign_bb_test.go`
- [ ] T044 [US1] Cross-language parity test (same fixture → DSS-equivalent output, both algos) in `tests/validation/parity.rs` (FR-012, SC-004)
- [X] T045 [P] [US1] Demo: sign a PDF (B-B) in each language in `examples/`

**Checkpoint**: MVP — invisible & visible B-B QES (RSA + ECDSA-P256), PDF/A-safe, DSS-validated, callable from Go/TS/Python, negative paths covered.

---

## Phase 4: User Story 2 - Trusted timestamp (PAdES B-T) (Priority: P2)

**Goal**: embed a qualified RFC 3161 timestamp so signing time is provable (PAdES B-T).

**Independent Test**: request B-T with a configured TSA; EU DSS reports a valid signature timestamp at B-T; TSA failure yields `TimestampFailed` with no downgrade.

**Tests (write first, must fail):**

- [X] T046 [P] [US2] Contract test: B-T augmentation embeds `signature-time-stamp` in `crates/cleverbase-core/tests/sign_bt.rs`
- [ ] T047 [P] [US2] Contract test: TSA failure → `TimestampFailed`, no downgrade in `crates/cleverbase-core/tests/tsa_fail.rs`
- [ ] T048 [P] [US2] Contract+validation test: B-T with **RSA and ECDSA-P256** credentials both validate at B-T via EU DSS in `crates/cleverbase-core/tests/algo_matrix_bt.rs` (FR-006, closes C2 for B-T)
- [X] T049 [P] [US2] Validation test: B-T (signature timestamp) validates via EU DSS in `tests/validation/dss_bt.rs`

**Implementation:**

- [X] T050 [US2] Implement RFC 3161 TimeStampReq builder + TimeStampToken parse/embed in `crates/cleverbase-core/src/timestamp/mod.rs`
- [X] T051 [US2] Wire `Augmenting` phase into state machine (level=B_T) with no-downgrade guard in `crates/cleverbase-core/src/signing/mod.rs`
- [X] T052 [P] [US2] Extend evidence record with timestamp fields in `crates/cleverbase-core/src/evidence.rs`
- [ ] T053 [P] [US2] Per-binding B-T smoke tests in `bindings/python/tests/test_sign_bt.py`, `bindings/node/test/sign_bt.test.ts`, `bindings/go/sign_bt_test.go`
- [ ] T054 [P] [US2] Demo: sign with B-T in each language in `examples/`

**Checkpoint**: complete B-T (Phase 1 signing commitment met).

---

## Phase 5: User Story 3 - Frontend redirect/consent helper (Priority: P3)

**Goal**: a thin TS helper drives the signer through wallet authorization with no secrets/crypto in the browser.

**Independent Test**: drive a demo web app through the helper; verify no secret/handle/private key in browser traffic and no crypto performed client-side.

**Tests (write first, must fail):**

- [X] T055 [P] [US3] Test: helper carries no secrets/handle and performs no crypto (traffic assertion) in `frontend/helper-ts/test/no-secrets.test.ts`
- [X] T056 [P] [US3] Test: start→redirect→return→status flow in `frontend/helper-ts/test/flow.test.ts`

**Implementation:**

- [X] T057 [US3] Implement TS helper (start/redirect/return/poll-status) talking to the integrator backend — no WASM, performs no crypto — in `frontend/helper-ts/src/index.ts`
- [ ] T058 [P] [US3] Demo web app wiring backend SDK + FE helper in `examples/web/`

**Checkpoint**: FE helper complete.

---

## Phase 6: Polish & Cross-Cutting Concerns

- [ ] T059 [P] Enforce ≥95% coverage gate in CI across core + bindings in `.github/workflows/ci.yml`
- [X] T060 [P] Conformance test: environment switch **acceptance ↔ production** is **config-only** (no code change), exercising both code paths via config in `tests/contract/environment_switch.rs` (FR-009, closes C1)
- [ ] T061 [P] Live acceptance smoke tests vs `connect.acc.cleverbase.com` (stub creds) in `tests/contract/acceptance.rs`
- [ ] T062 [P] Package + publish prebuilt artifacts (wheels, napi prebuilds, cdylib releases) per platform in `.github/workflows/release.yml`
- [X] T063 [P] Author API docs/READMEs for core + each binding + FE helper in `docs/` and package READMEs
- [ ] T064 Timed gate: first qualified signature against acceptance via the provided example completes within **30 minutes** in `tests/validation/first_signature_timing.rs` (SC-007, closes A2)
- [ ] T065 Run quickstart.md scenarios S1–S7 end-to-end as a release gate (tracked in `tests/validation/quickstart_gate.rs`)
- [X] T066 Security review pass (secret handling, no FE crypto, memory safety, and an explicit "no embedded wallet / no PIN or wallet-credential handling in the core" item) per Constitution IV, recorded in `docs/security-review.md`
- [ ] T067 [P] Performance benchmarks (assembly <200 ms / verify <100 ms) against a stated baseline — the standard CI Linux x86_64 runner, a ≤5 MB input PDF, release build — recorded in `crates/cleverbase-core/benches/signing.rs`

---

## Dependencies & Execution Order

### Phase dependencies

- **Setup (P1)**: no dependencies.
- **Foundational (P2)**: depends on Setup — **BLOCKS all user stories**.
- **US1 (P3)**: depends on Foundational. The MVP.
- **US2 (P4)**: depends on Foundational + US1's signing state machine (T035) and PAdES output (T038).
- **US3 (P5)**: depends on Foundational (operation shell T015); needs no WASM (T020 deferred — the helper performs no crypto); independent of US1/US2 behavior.
- **Polish (P6)**: depends on all targeted stories.

### Key within-story ordering

- Tests (T025–T034, T046–T049, T055–T056) authored and failing BEFORE their implementation.
- Core types (T011–T014) → operation shell (T015) → primitives (T016–T018) → C-ABI/WASM/bindings (T019–T023).
- T035 before T036/T037/T038; T038 emits `signature_meta` (covers T033); T050 before T051.
- T031/T048 (dual-algo) depend on the algo encoders in T016 and the relevant signing path (T035 / T051).

### Parallel opportunities

- Setup: T002–T005, T007, T008 in parallel.
- Foundational: T009/T010 parallel; T011–T014 parallel; T016/T017/T018 parallel; T021/T022 parallel (T023 after T019).
- US1: all test tasks T025–T034 in parallel; T039/T040 parallel; binding tests T041/T042/T043 parallel (then T044 parity).
- US2: T046/T047/T048/T049 parallel; T053/T054 parallel.
- Polish: T059, T060, T061, T062, T063, T067 in parallel.

---

## Implementation Strategy

### MVP first (US1 only)

1. Phase 1 Setup → Phase 2 Foundational (CRITICAL — blocks everything).
2. Phase 3 US1 → **stop and validate**: B-B QES (RSA + ECDSA-P256) validated by EU DSS, PDF/A
   preserved, signature metadata + optional appearance, negative paths covered, callable from all
   three languages.
3. A complete, demonstrable signing capability.

### Incremental delivery

US1 (B-B) → US2 (B-T) completes the Phase 1 signing commitment → US3 (FE helper) → Polish (release
packaging, env-switch + acceptance + timing gates, coverage gate, security review).

### Notes

- [P] = different files, no incomplete dependency. Story labels map tasks to user stories.
- Tests fail before implementation; every produced signature is checked against EU DSS / veraPDF.
- Commit per task or logical group; record an RCA in the PR for any bug fix (Constitution VIII).
- Out of scope here (architected-for, later phases): B-LT/B-LTA + LTV, runtime eIDAS validation
  sidecar, non-PDF formats, identification/auth/attestation, batch authorization, the `name_and_dob`
  identity-match mode (deferred — see data-model.md).
