---
description: "Task list for EUDI attestation — verification now, issuance forward-looking"
---

# Tasks: EUDI attestation — verification now, issuance forward-looking

**Input**: Design documents from `specs/004-attestation-and-verification/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/ (all present)

**Tests**: REQUIRED (Constitution Principle VI — Test-First). Every implementation task is preceded by a
test that MUST fail first; produced/obtained artifacts are cross-checked against an **independent,
different-language** reference verifier.

**Branch**: `feature/004-attestation-and-verification`

## Key constraints (from plan.md / research.md)

- **No hand-rolled crypto** (IV): reuse the SDK's `p256`/`ecdsa`/`rsa`/`sha2`/`ciborium` + X.509/CMS stack;
  add only `coset` (COSE codec) + `sd-jwt-payload` (format layer) + `quick-xml` (trust lists).
- **One Rust core** (III): all logic in a new `crates/cleverbase-attestation` crate over the existing
  `cleverbase-ffi` C-ABI + bindings; core stays **sans-IO + pure-Rust/WASM-able** (no JVM/OpenSSL-FFI).
- **Not a wallet** (IV): holder keys via the spec-001 **signer-hook**; the SDK never holds them.
- **Biggest build = the native EU trust-list engine** (no Rust tooling exists); EU DSS is a **test-only**
  parity oracle. The opt-in qualified gate (TS 119 615 cl.4.12) is **experimental, version-pinned**.
- Verification ships **complete + offline-testable**; issuance is **gated** (Cleverbase has no issuer API).

## Phase 1: Setup

- [X] T001 Scaffold the `crates/cleverbase-attestation` crate in the workspace (Cargo.toml with **pinned** `coset`, `sd-jwt-payload`, `quick-xml` + reuse of the workspace crypto/X.509 deps; `src/lib.rs` + module dirs `sdjwtvc/ mdoc/ openid4vp/ trust/ qualified/ issuance/`); register it in the root workspace and as a dependency of `crates/cleverbase-ffi`.
- [ ] T002 [P] Vendor **Tier A** conformance fixtures into `tests/fixtures/attestation/vectors/` — the IETF arf-pid SD-JWT VC example, the OWF multipaz ISO 18013-5 **Annex-D** mdoc vector, and the `isomdl`/EUDI test IACA PKI (incl. a deliberate wrong-signer cert) — with a `NOTICE` attribution file (research D9).
- [ ] T003 [P] Add the **Tier B** generator + test PKI under `tests/fixtures/attestation/gen/` — a self-signed test IACA root/intermediate/DS + an SD-JWT VC issuer EC key + a recipe that mints SD-JWT VCs (with KB-JWTs) and mdocs and the negative variants (expired/revoked/tampered/wrong-issuer/wrong-audience). Offline, reproducible.

**Checkpoint**: crate builds; offline fixtures + generator present.

## Phase 2: Foundational (blocking prerequisites)

- [X] T004 [P] Define the shared domain types in `crates/cleverbase-attestation/src/types.rs` — `Format{SdJwtVc,Mdoc}`, `Attestation`, `Issuer{role,trustStatus,qualifiedStatus?}`, `VerificationPolicy`, `VerificationResult{valid,disclosedAttributes,trustStatus,qualifiedStatus?,reasons[]}`, and a closed **reason-code** enum (data-model.md).
- [X] T005 Define the `TrustAnchorSource` trait + a **configured test-anchor** impl in `crates/cleverbase-attestation/src/trust/mod.rs` (resolve(role,format,issuerCert)->TrustDecision; the full EU-LOTL engine is T013). The offline suite uses the test anchor (contracts/trust-anchor-source.md).
- [X] T006 Add the attestation **C-ABI seam** to `crates/cleverbase-ffi` (CBOR-in/out `verify` + later `issue/present` functions, initially returning a not-implemented status) and the thin shim stubs in `bindings/{go,python,node}` so everything links before logic lands.

**Checkpoint**: shared types + trust trait + C-ABI seam compile across the core + bindings.

## Phase 3: User Story 1 — Verify a presented EUDI attestation (Priority: P1) 🎯 MVP

**Goal**: complete, standards-based verification of presented SD-JWT VC **and** mdoc credentials — always-on
bar + full OpenID4VP verifier — offline-testable, cross-checked against an independent reference verifier.

**Independent test**: `cargo test -p cleverbase-attestation --test verify` + `--test openid4vp_binding`
pass for both formats (VALID + every negative path); zero external dependency.

### Tests for US1 (write first — MUST fail)

- [X] T007 [P] [US1] SD-JWT VC verification tests in `crates/cleverbase-attestation/src/sdjwtvc/` — VALID (disclosed attributes returned) + INVALID for tamper, expired, revoked, wrong-issuer, untrusted, broken-KB, unsupported, each asserting the **specific reason** (no false-accept).
- [X] T008 [P] [US1] mdoc verification tests in `crates/cleverbase-attestation/src/mdoc/` — VALID + INVALID incl. **valueDigests mismatch** (selective-disclosure integrity) and **MSO validityInfo expired** (the checks `isomdl` omits), each with a specific reason.
- [X] T009 [P] [US1] Trust-list engine tests in `crates/cleverbase-attestation/src/trust/` — issuer present / absent / expired-or-withdrawn **entry** / list-signature-authentication / **unreachable**→fail-closed / **stale list** (the list itself expired-but-reachable, e.g. past its `NextUpdate`)→fail-closed, against trust-list fixtures. (U1: stale-list is distinct from an unreachable list and from an expired entry.)
- [X] T010 [P] [US1] OpenID4VP binding tests in `crates/cleverbase-attestation/src/openid4vp/` — a presentation bound to an SDK-issued request → VALID; the same **replayed** or built for a **different audience** → INVALID (`replay`/`wrong_audience`). Both formats.

### Implementation for US1

- [X] T011 [US1] SD-JWT VC verifier in `src/sdjwtvc/` — `sd-jwt-payload` for disclosures + KB-JWT structure; **in-house compact-JWS** issuer-signature verify via existing RustCrypto; `vct` type-metadata (draft-16). Makes T007 pass.
- [X] T012 [US1] mdoc verifier in `src/mdoc/` — `ciborium`+`coset` IssuerAuth (COSE_Sign1) verify; **in-house** recompute+match `valueDigests` and enforce MSO `validityInfo`; DeviceAuth (DeviceSignature) holder binding. Makes T008 pass.
- [X] T013 [US1] **Native EU trust-list engine** in `src/trust/` (the biggest build — research D5) — fetch/parse (`quick-xml`) + **authenticate** the LOTL + national Trusted Lists (TS 119 612 v2.4.1/TLv6) + per-role anchors (PID Art.5a(18), PuB-EAA Art.45f(3)) + IACA roots + cache; host-driven `refresh()`, sans-IO `resolve()`. **(U1)** The `resolve()`/`refresh()` contract MUST surface the trust-list **reachability/stale policy** (data-model `TrustAnchorSource.reachability`): an **unreachable** or **stale** (past its `NextUpdate`) LOTL/national list is **fail-closed** by default — distinct from the per-credential status endpoint (T014) and from an expired issuer entry (T009). Makes T009 pass. (EU DSS = test parity oracle, not a runtime dep.)
- [X] T014 [US1] Revocation/status check (status list / CRL) + the **fail-closed** reachability policy in `crates/cleverbase-attestation/src/status/`; wired into the always-on bar (`verify`).
- [X] T015 [US1] OpenID4VP **full verifier** in `src/openid4vp/` — build the request (DCQL + fresh nonce + audience) and verify the `vp_token` is bound to it (nonce echo + audience), per both formats' binding mechanisms. Makes T010 pass.
- [X] T016 [US1] Assemble the always-on `verify(presentation, policy, anchors, request?)` entry point (contracts/verifier.md) wiring T011–T015; expose it through the `cleverbase-ffi` C-ABI + the `bindings/{go,python,node}` shims (replace the T006 stub).
- [X] T017 [US1] Independent **cross-check** harness `scripts/crosscheck-attestation.sh` — verify the shared vectors with a different-language EU reference verifier (Kotlin `eudi-lib-jvm-sdjwt-kt` / TS `mdoc-ts`) and assert verdict agreement (Principle VI); self-skips if the reference isn't available. **(C1)** The harness MUST take an arbitrary artifact path so it also accepts **SDK-produced** artifacts (US2: an obtained credential + a holder `vp_token`) and assert the independent verifier agrees — fully demonstrating FR-013's "produced/obtained … checked against an independent reference verifier", not just the US1 verifier.

**Checkpoint**: US1 independently shippable — both formats verified offline with no false-accept, full
OpenID4VP binding, cross-checked against an independent verifier.

## Phase 4: Opt-in qualified-status gate (FR-014 — cross-cutting)

**Goal**: opt-in eIDAS qualified-status determination over the always-on bar; off by default, experimental,
version-pinned.

- [X] T018 [P] Qualified-gate tests in `src/qualified/` — qualified issuer (granted at the relevant time) → `Qualified`; trusted-but-non-qualified → VALID-but-`NotQualified` (no false "qualified"); missing TL data → `Indeterminate`; **gate disabled → the always-on verdict is unchanged** (SC-007). Self-skips if TL fixtures absent.
- [X] T019 Qualified-status determination (TS 119 615 v1.4.1 **cl. 4.12**) in `src/qualified/`, reusing the T013 trust primitives (service type `…/EAA/Q`, status-at-relevant-time); **opt-in**, version-pinned. **(A1)** Outcome conditions, pinned: `Qualified` = the issuer's `EAA/Q` service entry is `granted` at the relevant time; `NotQualified` = the entry is found but not granted (or withdrawn/suspended) at that time; `Indeterminate` = the trust-list data is absent / ambiguous / unreachable (never assume qualified). Makes T018 pass. (contracts/qualified-status-gate.md)
- [X] T020 Surface the opt-in gate via `VerificationPolicy.qualifiedGate` + the C-ABI + bindings.

**Checkpoint**: enabling/disabling the gate never changes the always-on bar; no false "qualified".

## Phase 5: User Story 2 — Obtain/hold/present an attestation (Priority: P2, gated)

**Goal**: drive OpenID4VCI issuance + OpenID4VP holder presentation via the signer-hook; issuer as a
configurable backend; live path gated/skipped when no issuer API is configured.

**Independent test**: against the EU reference issuer, `--test issuance`/`--test presentation` round-trip
and verify under US1; with no issuer configured, the issuance test **skips** and US1 still passes.

### Tests for US2 (write first — MUST fail / gated)

- [X] T021 [P] [US2] Signer-hook tests in `src/issuance/` — the SDK builds the exact PoP-JWT / KB-JWT / DeviceAuth **signingInput**, a stub HSM signs it, the SDK **never accesses a private key**, and `aud`/`nonce` are exposed for host inspection (FR-009).
- [X] T022 [P] [US2] Issuance gating tests in `src/issuance/` — `IssuerBackend.kind=None` → **skip** (reported skipped, never failed); `kind=Reference` → `obtain` yields a conformant attestation that verifies under US1 **and is cross-checked against the independent reference verifier** (T017 harness, C1/FR-013) (gated on the reference issuer).
- [X] T023 [P] [US2] Holder presentation tests in `src/issuance/` — `present` with a disclosed subset produces a `vp_token` that the US1 verifier accepts (round-trip), bound to the verifier's request, **and that the independent reference verifier (T017) also accepts** (C1/FR-013).

### Implementation for US2

- [X] T024 [US2] Signer-hook + `HolderContext` in `src/issuance/` (integrator-supplied public key + async `sign(handle,alg,signingInput)`; build PoP-JWT/KB-JWT/DeviceSignature inputs deterministically) — reuse the spec-001 pattern (DRY). Makes T021 pass.
- [X] T025 [US2] OpenID4VCI `obtain` with a configurable `IssuerBackend` (None/Reference/Cleverbase) + the **skip-when-None** gating in `src/issuance/`. Makes T022 pass.
- [X] T026 [US2] Holder OpenID4VP `present` (selective disclosure, bound to the request) in `src/issuance/`. Makes T023 pass.
- [X] T027 [US2] Wire the EU `eudi-srv-pid-issuer` **reference-issuer double** (docker-compose) + an **opt-in** `.github/workflows/attestation-live-issuance.yml` job, gated on the reference issuer being available.
- [X] T028 [US2] Surface `issue`/`present` through the C-ABI + bindings.

**Checkpoint**: US2 round-trips against the reference issuer; skips cleanly without one; a future Cleverbase
issuer drops in by configuration (SC-005).

## Phase 6: Polish & cross-cutting concerns

- [X] T029 [P] CI: add the always-on attestation **verify** suite (offline, zero external deps) to `.github/workflows/test.yml`, with a **≥95% coverage gate** for `cleverbase-attestation`. (Done: `test.yml` `rust` job runs `cargo test --workspace` — which builds+tests `cleverbase-attestation` offline — and a new `Coverage gate — cleverbase-attestation` step mirrors the core/ffi `cargo llvm-cov --fail-under-lines 95`; attestation line coverage is **97.72%**. `scripts/gen-docs.sh`'s rustdoc loop now includes `cleverbase-attestation` (clean `RUSTDOCFLAGS=-D warnings` after the intra-doc-link fix).)
- [X] T030 [P] CI: opt-in jobs (off by default) for the independent cross-check (T017 — over **both** the US1 vectors **and** the US2-produced artifacts, C1), the gated issuance (T027), and the qualified gate — SHA-pinned actions, secret-gated where needed, skip-when-absent. (Done: new `.github/workflows/attestation-crosscheck.yml` (`workflow_dispatch`, SHA-pinned `actions/checkout`) with a `crosscheck` job — exports SDK-produced VALID artifacts via the new `tests/export_artifacts.rs` (`required-features = ["test-vectors"]`, reusing the in-crate minters — DRY) and runs `scripts/crosscheck-attestation.sh` per format (self-skips without the Kotlin/TS reference) — plus a `qualified-gate` job (experimental TS 119 615 cl. 4.12, self-skips without the TL fixture). The live-issuance job `attestation-live-issuance.yml` already exists (T027).)
- [X] T031 [P] DRY review (Principle VIII): confirm the signer-hook is shared with signing (no twin), and one trust-list primitive backs both the always-on bar and the qualified gate — no duplication. (Done, recorded in `standards-conformance.md` §3: (1) the signer-hook reuses the spec-001 build-input/host-signs-off-box/splice **pattern** — neither crate holds a key, and the mechanisms differ by domain (core's CSC `signHash` HTTP effect vs. attestation's local `Signer` callback), so there is nothing to extract; (2) `trust::chain::verify_chain` is the single X.509 primitive backing the always-on bar (`trust::engine`/`trust::xml`) **and** the qualified gate (`qualified` anchors the TL signer through it), and `qualified` reuses `trust::manifest::parse_rfc3339_utc_pub`; (3) the parallel `begin`/`resume`+effect state machines in `issuance::obtain` vs `cleverbase-core::effects` are a **justified** parallel — attestation does not depend on core (standalone sans-IO core), and the `Step` enums share no terminal variants — so no extraction, tracked as a deliberate parallel.)
- [X] T032 [P] **Standards conformance + version-pinning audit (Principle II/VII; FR-010).** Produce a traceability matrix mapping each governing standard → the task/test that demonstrates conformance, AND record the targeted versions: **eIDAS — Regulation (EU) 910/2014 as amended by (EU) 2024/1183** (the qualified/EAA framing → T013/T019), SD-JWT VC draft-16/RFC 9901 (→T011), OpenID4VP/VCI 1.0 (DCQL) (→T015/T025), ISO/IEC 18013-5 (→T012), ETSI TS 119 612 v2.4.1/TLv6 + **TS 119 602** LoTE (→T013), TS 119 615 v1.4.1 cl.4.12 (→T019), and the crate pins `coset`/`sd-jwt-payload`/`quick-xml`. (C1: closes the "version-pinning ≠ conformance citation" gap by giving FR-010 an explicit traceability home.) (Done: `specs/004-attestation-and-verification/standards-conformance.md` §1 (the standard→version→task→module→tests matrix) + §2 (the `coset =0.4.2` / `sd-jwt-payload =0.5.1` / `quick-xml =0.40.1` pins + the reused crypto stack).)
- [X] T033 [P] Docs: the attestation API surface (README + `docs/api`) and the **honest Cleverbase-reality** note (FR-011/SC-006) — no EUDI issuer API today (OIDC attributes + roadmap); the issuer backend is the future-Cleverbase seam. (C2: the honest-reality note is a **hard, non-deferrable requirement** (FR-011/SC-006), not optional polish — it MUST ship; it sits in this phase only because it documents the whole feature, but it cannot be dropped.) (Done: new `docs/attestation.md` documents the API surface (verify/openid4vp/trust/status/qualified/issuance/signer-hook + the `cleverbase_attestation_verify`/`_issuance` C-ABI) and ships the honest note — Cleverbase exposes no EUDI issuer API today (only OIDC attributes incl. `com.cleverbase.proof` + roadmap); verification is standards-based + Cleverbase-independent; the `Cleverbase` `IssuerBackend` is the future seam, default `None` skips. `make docs` regenerated the committed Rust API docs — `docs/api/rust/cleverbase_attestation.md` added, `cleverbase_ffi.md`/rust README updated; `git diff docs/api` is only the intended attestation additions.)
- [X] T034 Run `quickstart.md` scenarios 1–5 (offline) end-to-end and confirm green; record the result + the experimental-standards caveats. (Done, recorded in `standards-conformance.md` §4: scenarios 1–5 all green — S1 verify both formats (23 sdjwtvc + 40 mdoc), S2 replay/audience (11 openid4vp), S3 qualified gate (18), S4 cross-check self-skips cleanly, S5 full 230-test suite + **97.72%** coverage; S6 live issuance self-skips on unset `ATT_ISSUER`. Quickstart names the suites as `--test` targets but they are delivered as in-crate `#[cfg(test)]` modules, so they run via test-name filters (equivalent form). Caveats recorded: the qualified gate (TS 119 615 cl. 4.12) is experimental/pre-operational + opt-in; the cross-check needs an external reference verifier.)

## Dependencies & execution order

- **Setup (P1)** → everything. T001 then T002/T003 [P].
- **Foundational (P2)** → after Setup. T004 [P]; T005, T006.
- **US1 (P3)** → after Foundational. Tests T007–T010 [P] first; impl T011/T012 [P] (different modules), T013 (big build, blocks T016), T014, T015; T016 after T011–T015; T017 after T016. **MVP delivered here.**
- **Qualified gate (P4)** → after T013 (reuses the trust engine). T018 first; T019; T020.
- **US2 (P5)** → after US1 (round-trips through the verifier). Tests T021–T023 [P]; T024→T025→T026, T027 [P], T028.
- **Polish (P6)** → after the phases it covers.

## Parallel execution examples

- **Setup**: T002 + T003 together.
- **US1 tests**: T007 + T008 + T009 + T010 together, then implement (T011 + T012 in parallel).
- **US2 tests**: T021 + T022 + T023 together.
- **Polish**: T029 + T030 + T031 + T032 + T033 together.

## Implementation strategy

- **MVP = User Story 1 (Phase 3)**: complete EUDI **verification** (both formats, always-on bar, full
  OpenID4VP verifier), offline-testable, independently cross-checked — standalone value (verifies any
  conformant attestation, incl. future Cleverbase ones), zero external dependency.
- **Increment 2 = the opt-in qualified gate (Phase 4)**.
- **Increment 3 = User Story 2 (Phase 5)**: gated issuance/holding/presentation; a future Cleverbase issuer
  enabled by configuration.
- Test-first throughout; no hand-rolled crypto; the core stays sans-IO + pure-Rust. The **native trust-list
  engine (T013)** is the largest single task — size it accordingly and cross-check against EU DSS.

## Analysis remediation

### Round 1 (`/speckit-analyze` — C1/C2/A1/I1/U1/D1; I2 was a false alarm)

| Finding | Severity | Closed by |
|---------|----------|-----------|
| C1 — FR-010 conformance had no explicit home (only version-pinning) | MEDIUM | **T032** expanded into a standards **conformance-traceability** matrix (standard → demonstrating task), eIDAS cited |
| C2 — FR-011/SC-006 honest-reality doc framed as deferrable polish | MEDIUM | **T033** marked a **hard, non-deferrable** requirement (must ship, not optional polish) |
| A1 — T014 had a literal `src/...` placeholder path | LOW | **T014** pinned to `crates/cleverbase-attestation/src/status/` |
| I1 — TS 119 602 (+ TS 119 615) missing from the spec's FR-010 list | LOW | **spec.md FR-010** adds ETSI TS 119 602 + TS 119 615 + a conformance-traceability mapping |
| U1 — "stale" trust list (vs unreachable) not exercised | LOW | **T009** adds a stale-list (expired-but-reachable, past `NextUpdate`)→fail-closed case |
| D1 — Assumptions restated the Clarifications verbatim | LOW | **spec.md Assumptions** condensed the 3 clarify-derived bullets into a back-reference |
| I2 — spec branch vs git branch mismatch | LOW | **False alarm** — actual branch IS `feature/004-attestation-and-verification` (the analyzer's `BRANCH` field was empty); no change |

### Round 2 (re-`/speckit-analyze` — C1/I1/U1/A1, all LOW; distinct from Round 1's same-letter findings)

| Finding | Severity | Closed by |
|---------|----------|-----------|
| C1(r2) — independent reference cross-check covered only the US1 verifier, not US2-produced artifacts (FR-013/VI) | LOW | **T017** harness broadened to accept SDK-produced artifacts; **T022/T023** cross-check the obtained credential + holder `vp_token`; **T030** job runs over both |
| I1(r2) — plan's `16/16` checklist shorthand undocumented | LOW | **plan.md** spelled out: "spec-quality checklist (16/16 items pass)" |
| U1(r2) — T013 didn't explicitly bind the trust-list reachability/stale policy | LOW | **T013** names the `TrustAnchorSource.reachability` fail-closed policy for unreachable/stale (past `NextUpdate`) lists, distinct from status (T014) + expired entry (T009) |
| A1(r2) — Indeterminate-vs-NotQualified conditions only in T018's test | LOW | **T019** pins the outcome conditions (granted→Qualified; found-but-not-granted/withdrawn→NotQualified; absent/ambiguous/unreachable→Indeterminate) |
</content>
