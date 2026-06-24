---
description: "Task list for ECDSA P-256 validation parity + live Cleverbase-account signing"
---

# Tasks: ECDSA P-256 validation parity + live Cleverbase-account signing

**Input**: Design documents from `specs/003-ecdsa-and-live-signing/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/ (all present)

**Tests**: REQUIRED (Constitution Principle VI — Test-First & Contract-Tested). Every implementation task is
preceded by a test that MUST fail first.

**Branch**: `feature/003-ecdsa-and-live-signing`

> **Analysis remediation**: this list incorporates the `/speckit-analyze` findings F1–F7 (negative-path
> and edge-case coverage + two ambiguities). See the **Analysis remediation (F1–F7)** section at the end
> for the finding→task mapping.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: may run in parallel (different files, no dependency on an incomplete task)
- **[Story]**: US1 / US2 for user-story phases; Setup / cross-cutting / Polish phases carry no story label
- Exact repo-relative file paths are given in each task.

## Key constraint (from plan.md / research.md)

**Do NOT modify `crates/cleverbase-core/src/`** — the core already produces and self-verifies correct
ECDSA P-256, and already rejects unsupported keys / normalizes raw `r‖s`. All work is in fixtures, the mock
upstream, the E2E harness, the core's *test* crate (`crates/cleverbase-core/tests/`), and CI. The
negative-path tasks (T007–T009) assert the core's **existing** reject behaviour end-to-end; they add no
`src/` change. Every change is algorithm-parametrized (no RSA/ECDSA copy-paste — FR-004).

---

## Phase 1: Setup (shared test-fixture infrastructure)

- [X] T001 [P] Create the reproducible PKI generation script `tests/fixtures/pki/gen.sh` that regenerates `ca.*`, `signer-rsa.*`, `signer-ec.*`, `tsa.*` with the EXACT existing filenames (Go `os.ReadFile` + Rust `include_bytes!` depend on them) per `contracts/algorithm-fixtures.md` §3; both signer certs MUST `openssl verify -CAfile ca.cert.der` OK. Recipe only — it does NOT replace the already-committed fixtures (avoids churning `include_bytes!` consumers). **(A1)** Scope the recipe to the `ca/signer-rsa/signer-ec/tsa` key+cert material; `tsa.cnf` is a committed openssl `ts` **input config** the recipe consumes, and `ca.cert.srl`/`tsa_serial.txt` are **transient openssl serial byproducts** the recipe need not reproduce.
- [X] T002 [P] **(N1 — single template, not two copies)** Extend the existing `tests/fixtures/upstream/credentials_info.json` into **one** template with a per-algorithm substitution (the signer's cert + `algo` OID) — RSA (`1.2.840.113549.1.1.1` + `signer-rsa`) and ECDSA (`1.2.840.10045.2.1` + `signer-ec`) — filled at serve-time from the selected signer. Do **NOT** add two committed JSON copies (contracts/algorithm-fixtures.md §2).
- [X] T003 Verify the EC fixtures chain + load: `openssl verify -CAfile tests/fixtures/pki/ca.cert.der tests/fixtures/pki/signer-ec.cert.der` is OK and the `key.pk8` parses as P-256 (manual one-time check; `gen.sh` documents the recipe).

**Checkpoint**: fixtures + the per-algorithm `credentials/info` variants exist and validate.

---

## Phase 2: Foundational (blocking prerequisites)

No additional foundational *code* is required: the independent validator (`validateCMS` /
`assertTimestampToken` in `e2e/credfree_test.go`, and the OpenSSL paths in `independent_validation.rs`) is
already **algorithm-agnostic**, and the core already signs ECDSA and rejects unsupported keys. US1 and US2
are otherwise independent (US1 uses the synthetic mock; US2 uses real Cleverbase). Proceed to the user
stories.

---

## Phase 3: User Story 1 — ECDSA P-256 credential-free, independently verified (Priority: P1) 🎯 MVP

**Goal**: A full credential-free B-B and B-T flow signed with ECDSA P-256, accepted by the independent
OpenSSL validator — at parity with RSA, sharing one DRY path, with the no-false-accept and reject-bad-input
guarantees explicitly tested. No external dependencies.

**Independent test**: `cargo test -p cleverbase-core --test independent_validation` and
`go test ./e2e/ -run CredentialFree` pass for `{v1_rsa, v2_ecdsa} × {B-B, B-T}`, including the negative
cases; RSA unchanged.

### Tests for US1 (write first — MUST fail)

- [X] T004 [P] [US1] In `examples/reference-integration/mock-upstream/mock/server_test.go`, add a failing test asserting a `/csc/v2` `signHash` response is an ECDSA P-256 signature verifiable against `signer-ec` (fails today — the mock is RSA-only).
- [X] T005 [P] [US1] In `examples/reference-integration/signing-service/e2e/credfree_test.go`, convert `TestCredentialFree{BB,BT}` into a table over `{v1_rsa, v2_ecdsa}` (the `v2_ecdsa` cases fail until the mock signs ECDSA).
- [X] T006 [P] [US1] In `crates/cleverbase-core/tests/independent_validation.rs`, add ECDSA `B-B` and `B-T` cases by parametrizing `produce_signed_pdf` / `drive_bt_to_timestamp` / `upstream_fixture` over `KeyAlgo` (fails until the EC producer is wired).
- [X] T007 [P] [US1] **(F1 — no-false-accept on the always-on bar)** Add a negative test for the ECDSA arm: tamper the produced ECDSA CMS (flip a signature byte / swap in a wrong-algorithm signature) and assert the always-on validator **rejects** it — in `crates/cleverbase-core/tests/independent_validation.rs` (assert `openssl cms -verify` fails) AND in `examples/reference-integration/signing-service/e2e/credfree_test.go` (assert `validateCMS` returns an error). Backs FR-012 / SC-006 (no false-accept).
- [X] T008 [P] [US1] **(F2 — unsupported/ambiguous key OID)** Add a fixture variant under `tests/fixtures/upstream/` whose `credentials/info` advertises an unsupported/ambiguous key OID (neither RSA nor P-256), and a test in `crates/cleverbase-core/tests/independent_validation.rs` asserting the flow terminates with a **specific** credential-unavailable error and produces **no** signature (never guesses an algorithm). Backs US1 Acceptance Scenario 3 + Edge Case. (Exercises the core's existing `Other`-key rejection — no `src/` change.)
- [X] T009 [P] [US1] **(F3 — malformed raw r‖s; A1 — pinned injection point)** Add a test in `crates/cleverbase-core/tests/independent_validation.rs` that drives **its own `signHash` simulator** (the Rust arm — where the core-reject assertion lives) to return an ECDSA signature of **unexpected raw length** (e.g. 63/65 bytes, not 64 and not valid DER), and assert the core **rejects** it rather than mis-encoding a malformed CMS. Backs the Edge Case. (Exercises `ecdsa_signature_to_der`'s reject path end-to-end — no `src/` change; if it reveals the core does NOT reject, stop and raise an RCA rather than patching around it.)

### Implementation for US1

- [X] T010 [US1] In `examples/reference-integration/mock-upstream/mock/server.go`, replace the single `rsaKey` with a per-CSC-route `signer` (loaded key + cert + `algo` OID + `sign(tbs)`): RSA `SignPKCS1v15` on `/csc/v1`, P-256 → raw `r‖s` on `/csc/v2`; `handleSignHash` dispatches on the route's signer. Makes T004 pass. (contracts/algorithm-fixtures.md §1) (The malformed-length reject test T009 lives in the Rust simulator per A1, so the mock needs no malformed-output hook.)
- [X] T011 [US1] In `examples/reference-integration/mock-upstream/mock/server.go`, serve the `credentials/info` **template substituted with the route's signer cert + `algo` OID** (one template, no second committed copy — N1), so the core detects `KeyAlgo::EcdsaP256` on v2; the cert + OID come from the same selected `signer` as the signature (no drift).
- [X] T012 [P] [US1] In `crates/cleverbase-core/tests/independent_validation.rs`, implement the EC producer (simulate `signHash` with `p256::ecdsa::SigningKey` returning raw `r‖s`; inject `signer-ec` cert + ECDSA OID via the parametrized `upstream_fixture`); reuse the existing `openssl cms -verify` + `openssl_timestamp` paths unchanged. Makes T006, T007 (core arm), T008, T009 pass.
- [X] T013 [US1] Run `go test ./e2e/ -run CredentialFree` and confirm both algorithms pass with `validateCMS` / `assertTimestampToken` reused **unchanged**, including the T007 e2e negative case. Makes T005 + T007 (e2e arm) pass.
- [X] T014 [US1] In `examples/reference-integration/mock-upstream/mock/server_test.go`, update the existing RSA-hardcoded assertions to assert the **route's** expected algorithm (v1→RSA, v2→ECDSA).

**Checkpoint**: US1 is independently shippable — credential-free ECDSA B-B/B-T verified by OpenSSL, bad
signatures/keys/inputs explicitly rejected (no false-accept), RSA unchanged (FR-005), one parametrized
path (FR-004).

---

## Phase 4: PAdES/eIDAS profile-conformance gate (FR-014 — cross-cutting, opt-in)

**Goal**: An opt-in gate that asserts produced B-B/B-T PDFs meet the ETSI EN 319 142 baseline profile, in
addition to (never instead of) the always-on OpenSSL bar. Validates US1 outputs first; reused for US2.

### Test (write first — MUST fail / self-skip if toolchain absent)

- [X] T015 [P] **(F5 — concrete artifact path)** Add `scripts/test-validate-pades.sh` asserting: a known-good B-B PDF passes `--expect-level B-B`; the same asserted as `--expect-level B-T` fails; a tampered PDF fails AdES validation. Self-skips (exit 0 with a SKIP message) when `pyhanko`/the DSS container are absent, mirroring the `openssl`-absent skip.

### Implementation

- [X] T016 Implement `scripts/validate-pades.sh --expect-level {B-B|B-T} --trust <pem> <pdf>...` driving pyHanko `adesverify` (AdES validation, RSA + ECDSA) and EU DSS (structural `PAdES-BASELINE-B/-T` level assertion); non-zero on AdES failure or level mismatch. **(N2 — pin the toolchain)** Pin `pyhanko-cli` to an exact version and the **EU DSS container to a digest-pinned image (or a fixed DSS release tag) declared ONCE in this script** (single source — Constitution III), so the gate is reproducible across CI and dev. (contracts/profile-conformance-gate.md)
- [X] T017 [P] Add `.github/workflows/profile-conformance.yml` — **off by default** (`workflow_dispatch`/label gate), installs the **pinned** `pyhanko-cli` into a throwaway venv + runs the **digest-pinned** DSS container (the same pins declared in `scripts/validate-pades.sh`, N2), over the credential-free B-B/B-T PDFs for both algorithms.

**Checkpoint**: enabling/disabling the gate does not affect the always-on OpenSSL bar (SC-007); a
crypto-valid-but-non-conformant signature fails loudly. **(C1)** SC-007's "every produced B-B/B-T
signature" is scoped to **when the gate is enabled** — consistent with FR-014's opt-in nature; when the
opt-in job runs (T017), it MUST cover **every** produced PDF for **both** algorithms (no sampling/skips),
so "every … when enabled" holds.

---

## Phase 5: User Story 2 — live contract path against real Cleverbase (Priority: P2)

**Goal**: A gated test that signs against the real Cleverbase service through a pluggable authorizer and
independently verifies the result against the real trust chain. Skipped cleanly without credentials.

**Independent test**: with real creds set, `go test ./e2e/ -run Live` drives start→complete×2→result→verify
against the real chain (B-B; B-T when a TSA is set); without creds it is **skipped** and US1 still passes.

### Tests for US2 (write first — MUST fail / be gated)

- [X] T018 [P] [US2] In `examples/reference-integration/signing-service/e2e/authorizer_test.go`, add a harness test with a stub `Authorizer` asserting `runFlow` calls `Authorize` exactly twice and feeds the returned `(code,state)` into `/v1/sign/complete` unchanged (contracts/authorizer.md).
- [X] T019 [P] [US2] In `examples/reference-integration/signing-service/e2e/live_test.go`, add a gated full-flow test (against a real-service double or recorded acceptance responses) for start→complete×2→result→verify, plus an explicit assertion that the path **skips** (not fails) when the required `REFSVC_*` live env is absent (FR-009). **(N3 — trust-chain mismatch fails loudly)** Also assert that a **wrong/rotated `REFSVC_LIVE_CA_BUNDLE`** (one that does not match the signer's issuer) makes verification **fail loudly**, naming the untrusted/missing issuer (FR-008/FR-011) — exercise this credential-free by verifying a known-good produced PDF against a deliberately-wrong CA, so it runs without real credentials.
- [X] T020 [P] [US2] **(F4 — authorization timeout/decline)** In `examples/reference-integration/signing-service/e2e/authorizer_test.go`, assert that an `Authorizer.Authorize` which times out (human did not approve within the window) or returns `access_denied` surfaces a clear, specific error ("authorization not completed" / "declined") and that `runFlow` **does not hang** — backs the Edge Case + FR-011 (distinguish a dependency/authorization problem from an SDK defect).

### Implementation for US2

- [X] T021 [US2] Add `examples/reference-integration/signing-service/e2e/authorizer.go`: the `Authorizer` interface + `mockAutoApprove` (refactor the existing `followRedirect`) + `Interactive` impl (with a configurable timeout that returns a clear error, not a hang); make `runFlow` authorizer-agnostic. Makes T018 + T020 pass; credential-free runs keep working via `mockAutoApprove`. (contracts/authorizer.md)
- [X] T022 [US2] In `examples/reference-integration/signing-service/internal/config/config.go`, add the live knobs `REFSVC_LIVE_AUTHORIZER` (`interactive` default | `headless`) and `REFSVC_LIVE_CA_BUNDLE` (real issuer-chain PEM), validated in `validateLive`.
- [X] T023 [US2] Implement the full live path in `examples/reference-integration/signing-service/e2e/live_test.go`: drive both redirects via the configured `Authorizer`, complete, GET `/v1/sign/result`, verify against `REFSVC_LIVE_CA_BUNDLE` (reusing `validateCMS`); B-B required, B-T when `REFSVC_TSA_URL` set (FR-015). **(F6 — algorithm selection)** the test signs with the algorithm of the configured `REFSVC_CSC_API`; covering **both** RSA and ECDSA is realized by running the live job (T025) as a **matrix over `{v1_rsa, v2_ecdsa}`**, each leg **skipping** when that algorithm's credential is unavailable — the live suite passes if **at least one** leg verified (FR-007/008). **(I1)** A single local `go test -run Live` therefore covers exactly the **one** algorithm of the configured `REFSVC_CSC_API`; "both algorithms" is a **CI-matrix** property (T025), not a single-invocation one — the live test MUST NOT claim to cover both in one run. Makes T019 pass.
- [X] T024 [US2] **(U1 — scoped to the interface drop-in)** Add the opt-in `Headless` `Authorizer` impl in `examples/reference-integration/signing-service/e2e/authorizer.go` (selected by `REFSVC_LIVE_AUTHORIZER=headless`), satisfying the `Authorizer` interface and selectable by config without changing `runFlow` (FR-013). **Scope**: the interface drop-in + wiring only; the actual automatable-approval mechanism is a **pending external dependency** (an automatable Cleverbase test credential the project will supply later — see spec Dependencies / Clarifications). Implement it against that mechanism if available; otherwise land the type with a clearly-marked, documented "pending automatable approval" gap (e.g. returns a specific "headless approval not configured" error). **(U1-r4)** Include a test asserting that selecting `REFSVC_LIVE_AUTHORIZER=headless` **without** the mechanism configured returns that specific "not configured" error (not a hang/panic) — covers the shipped drop-in branch and keeps it inside T027's ≥95% floor. This task **MUST NOT block** US2's interactive path (T021/T023).
- [X] T025 [P] [US2] Add `.github/workflows/live.yml` — opt-in job gated on real-credential secrets, **matrix over `{v1_rsa, v2_ecdsa}`** with each leg skip-when-absent (F6), never logging secrets (FR-010).

**Checkpoint**: US2 runs the real-surface contract test with credentials and is cleanly skipped without
them; an authorization timeout/decline fails fast with a clear error; failures distinguish a
service/credential problem from an SDK defect (FR-011).

---

## Phase 6: Polish & cross-cutting concerns

- [X] T026 [P] In `.github/workflows/test.yml`, add the ECDSA arm to the always-on credential-free E2E job (still zero external dependencies; keeps the pipeline green).
- [X] T027 [P] **(F7 — coverage scope)** Verify unit-test coverage stays **≥95% per package** after the changes (Principle VI / SC-004), explicitly **including the new Go harness/config code** — `e2e/authorizer.go` (Interactive/mockAutoApprove non-gated branches), the `config.go` live-knob validation, and any new branch logic — not just the unchanged core. Add targeted tests for any new package/branch that dipped below the floor.
- [X] T028 [P] DRY review (FR-004 / SC-003): confirm a single `signer` type, one `credentials/info` template, and one algorithm-parametrized producer per harness — no RSA/ECDSA twin code anywhere.
- [X] T029 [P] Update docs: `examples/reference-integration/README.md` (+ any doc asserting RSA-only validation) to state ECDSA parity, the opt-in profile gate, and the live-path env vars (`REFSVC_LIVE_AUTHORIZER`, `REFSVC_LIVE_CA_BUNDLE`); regenerate API docs if any public surface text changed (none expected).
- [X] T030 Run `quickstart.md` scenarios 1–4 (credential-free) end-to-end and confirm green; record the RCA-style note that the gap was validation-coverage-only (core unchanged).

---

## Dependencies & execution order

- **Setup (Phase 1)** → everything. T001/T002 are [P]; T003 follows.
- **Foundational (Phase 2)**: none (empty by design).
- **US1 (Phase 3)**: depends on Setup. Tests T004–T009 [P] first; then T010→T011 (same file, sequential), T012 [P]; T013 after T010/T011/T012; T014 after T010. The negative tests T007/T008/T009 go green as part of T012/T013. **MVP delivered here.**
- **Profile gate (Phase 4)**: depends on US1 producing PDFs. T015 first; T016; T017 [P].
- **US2 (Phase 5)**: independent of US1 except the shared harness; tests T018/T019/T020 [P] first; T021→T023 (T023 needs T021+T022), T024 after T021, T025 [P] after T023.
- **Polish (Phase 6)**: after the stories it covers (T026 after US1; T027/T028 after US1+US2; T029/T030 last).

## Parallel execution examples

- **Setup**: T001 + T002 together.
- **US1 tests**: T004 + T005 + T006 + T007 + T008 + T009 together (different files/cases), then implement.
- **US2 tests**: T018 + T019 + T020 together, then implement.
- **Polish**: T026 + T027 + T028 + T029 together.

## Implementation strategy

- **MVP = User Story 1 (Phase 3)**: ships the headline ECDSA validation-parity gap closure with zero
  external dependencies — independently testable and releasable, with the trust-critical no-false-accept /
  reject-bad-input guarantees explicitly covered.
- **Increment 2 = Profile gate (Phase 4)**: adds the opt-in eIDAS profile-conformance assurance.
- **Increment 3 = User Story 2 (Phase 5)**: adds the real-surface live contract test (interactive now,
  headless drop-in later).
- Test-first throughout; the core is never modified (RCA: the gap is coverage, not capability).

## Analysis remediation

### Round 1 (`/speckit-analyze` — F1–F7)

| Finding | Severity | Closed by |
|---------|----------|-----------|
| F1 — no-false-accept on the **always-on** bar untested for ECDSA (FR-012/SC-006) | MEDIUM | **T007** (tamper → reject, in both `independent_validation.rs` and `validateCMS`) |
| F2 — unsupported/ambiguous key OID rejection untested (US1 AS#3 / Edge) | MEDIUM | **T008** (bad-OID `credentials/info` variant → specific error, no signature) |
| F3 — malformed raw r‖s length rejection untested (Edge) | MEDIUM | **T009** (wrong-length sig → reject, not mis-encode) |
| F4 — authorization timeout/decline → clear error, not hang (Edge / FR-011) | LOW | **T020** (+ T021 Interactive timeout returns a clear error) |
| F5 — old ambiguous test-artifact path | LOW | **T015** pinned to `scripts/test-validate-pades.sh` |
| F6 — live "both algorithms, require one" selection mechanism unstated (FR-007) | LOW | **T023 + T025** (matrix over `{v1_rsa, v2_ecdsa}`, each skip-when-absent, pass on ≥1) |
| F7 — coverage scope must include new Go harness/config code (SC-004) | LOW | **T027** (explicitly counts `authorizer.go` / `config.go` branches) |

### Round 2 (re-`/speckit-analyze` — I1/U1/A1/C1)

| Finding | Severity | Closed by |
|---------|----------|-----------|
| I1 — "both algorithms live" reads as a single-run property; it is a CI-matrix one | LOW | **T023** + spec.md US2 Independent Test (one local run = configured algorithm; both = matrix per T025) |
| U1 — headless authorizer approval mechanism is a pending external dependency | LOW | **T024** scoped to the interface drop-in + a documented "pending automatable approval" gap; never blocks the interactive path |
| A1 — T009 malformed-r‖s injection point was an either/or | LOW | **T009** pinned to the Rust `independent_validation.rs` simulator arm; **T010** mock hook dropped |
| C1 — SC-007 "every produced signature" vs opt-in gate | LOW | Phase 4 checkpoint note: SC-007 is scoped to "when the gate is enabled"; the opt-in run (T017) covers every PDF for both algorithms (consistent, made explicit) |

### Round 3 (re-`/speckit-analyze` — N1/N2/N3/N4)

| Finding | Severity | Closed by |
|---------|----------|-----------|
| N1 — `credentials/info`: two committed variant files vs one template not pinned | LOW | **T002 + T011** pinned to **one template** substituted at serve-time (no two copies); **data-model.md** reconciled |
| N2 — EU DSS container image/version not provisioned/pinned | LOW | **T016 + T017** require a digest-pinned DSS image + exact pyHanko version declared once in `scripts/validate-pades.sh`; **contracts/profile-conformance-gate.md** updated |
| N3 — wrong/rotated trust-chain "fail loudly" edge untested for the live arm | LOW | **T019** asserts a wrong `REFSVC_LIVE_CA_BUNDLE` → loud named "untrusted/missing issuer" failure (exercised credential-free) |
| N4 — FR-013 reads as unconditional MUST while the headless mechanism is deferred | LOW | **spec.md FR-013** sentence: the MUST is the pluggable **seam**; the headless approval **mechanism** ships when an automatable credential exists |

### Round 4 (full re-`/speckit-analyze` — D1/A1/I1/U1; C1 already closed)

| Finding | Severity | Closed by |
|---------|----------|-----------|
| D1 — `credentials/info` "template" vs "variant" phrasing differs across docs | LOW | **contracts/algorithm-fixtures.md §2** unified to "single template, per-route substitution" (matching data-model.md / research.md) |
| A1 — `gen.sh` vs committed openssl side-files (`*.srl`, `tsa_serial.txt`, `tsa.cnf`) | LOW | **T001 + contracts/algorithm-fixtures.md §3**: `tsa.cnf` is a committed input config; `*.srl`/`tsa_serial.txt` are transient byproducts not reproduced |
| I1 — `REFSVC_MODE` master switch missing from the config tables | LOW | **data-model.md LiveRunConfig + contracts/live-contract-path.md** add `REFSVC_MODE` (`fixtures`/`live`) |
| U1(r4) — headless "not configured" error branch untested | LOW | **T024** adds a test that selecting `headless` without the mechanism returns the specific "not configured" error (covers the drop-in branch for T027) |
| C1 — profile gate "every… when enabled" | LOW | already closed in Round 2 (Phase 4 checkpoint note); re-confirmed consistent |
</content>
