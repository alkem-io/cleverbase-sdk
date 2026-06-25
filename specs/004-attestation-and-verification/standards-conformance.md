# Standards conformance + version-pinning audit (T032, FR-010)

This is the conformance-traceability home FR-010 requires (Constitution Principle II/VII): for every
governing standard it records the **targeted version** and the **demonstrating module/test** in the
`cleverbase-attestation` crate. It also pins the third-party crate versions the format/trust layers
build on, and (as the Polish-phase record) carries the T031 DRY review and the T034 quickstart
results.

The crate is intentionally a **standalone, sans-IO core** (it does not depend on `cleverbase-core`):
verification is standards-based and Cleverbase-independent. See `docs/limitations.md` and
`examples/reference-integration/README.md` for the honest Cleverbase-reality note (FR-011/SC-006).

## 1. Standards traceability matrix (FR-010)

Each row maps a governing standard → its targeted version → the task that implements it → the
module/tests that demonstrate conformance. "Module" paths are under `crates/cleverbase-attestation/`.
Test names are the in-crate `#[cfg(test)]` cases (run with `cargo test -p cleverbase-attestation`).

| Standard | Targeted version | Task | Demonstrating module | Representative tests |
|----------|------------------|------|----------------------|----------------------|
| **eIDAS** — Regulation (EU) 910/2014 **as amended by (EU) 2024/1183** (the qualified/(Q)EAA + per-role trust framing: PID Art. 5a(18), PuB-EAA Art. 45f(3)) | Consolidated 2024/1183 | T013, T019 | `src/trust/`, `src/qualified/` | `qualified::tests::qualified_issuer_granted_at_the_relevant_time_is_qualified`, `qualified::tests::trusted_but_non_qualified_issuer_is_not_qualified` |
| **SD-JWT VC** — `draft-ietf-oauth-sd-jwt-vc` + **SD-JWT** RFC 9901 | draft-16 / RFC 9901 | T011 | `src/sdjwtvc/` | `sdjwtvc::tests::valid_credential_from_trusted_issuer_is_accepted_with_disclosed_attributes`, `selective_disclosure_reveals_only_the_presented_subset`, `tampered_issuer_signature_is_rejected_as_tamper` |
| **ISO/IEC 18013-5** — mdoc (`DeviceResponse`, MSO `valueDigests`/`validityInfo`, `DeviceAuth`) | 18013-5:2021 | T012 | `src/mdoc/` | `mdoc::tests::valid_mdoc_verifies_and_returns_disclosed_attributes`, `value_digest_mismatch_is_rejected_as_disclosure_integrity`, `expired_validity_info_is_rejected_as_expired` |
| **OpenID4VP** — request build (DCQL + fresh nonce + audience) + `vp_token` binding verify | 1.0 (DCQL) | T015 | `src/openid4vp/` | `openid4vp::tests::build_request_draws_a_fresh_nonce_each_call`, `sd_jwt_bound_to_the_issued_request_is_valid`, `sd_jwt_replayed_with_a_stale_nonce_is_replay` |
| **OpenID4VCI** — pre-authorized-code `obtain` (sans-IO state machine + signer-hook PoP) | 1.0 | T025 | `src/issuance/obtain.rs`, `src/issuance/signer.rs` | `issuance::obtain::tests::*` (skip-when-`None`, reference round-trip), `issuance::signer::tests::*` |
| **ETSI TS 119 612** — Trusted Lists (LOTL / national TL, TLv6) | v2.4.1 / TLv6 | T013 | `src/trust/xml.rs`, `src/trust/engine.rs`, `src/trust/chain.rs` | `trust::engine::tests::*` (present/absent/expired-entry/unreachable→fail-closed/stale→fail-closed), `trust::xml::tests::*`, `trust::chain::tests::*` |
| **ETSI TS 119 602** — Lists of Trusted Entities (LoTE) data model the TL reader follows | v1.x | T013 | `src/trust/xml.rs`, `src/trust/manifest.rs` | `trust::xml::tests::*`, `trust::manifest::tests::*` |
| **ETSI TS 119 615** — qualified-status determination, **cl. 4.12** | v1.4.1 (`qualified::TS_119_615_VERSION = "1.4.1"`) | T019 | `src/qualified/` | `qualified::tests::the_implementation_is_pinned_to_ts_119_615_v1_4_1`, `issuer_absent_from_the_trust_list_is_indeterminate`, `withdrawn_eaa_q_is_qualified_before_and_not_qualified_after_the_withdrawal` |

Notes:

- The **qualified gate (TS 119 615 cl. 4.12)** is **opt-in, experimental, version-pinned** (cl. 4.12
  is pre-operational): off by default via `VerifyContext::qualified_gate`; enabling/disabling it never
  changes the always-on verdict (SC-007). The pinned constant is asserted by
  `the_implementation_is_pinned_to_ts_119_615_v1_4_1` so a silent version drift fails the suite.
- **ES256** (ECDSA / P-256 / SHA-256) is the EUDI mandatory baseline (HAIP 1.0 §7); both the
  SD-JWT VC issuer/KB-JWT JOSE signatures and the mdoc COSE signatures are verified over it.
- **EU DSS** is a **test-only** parity oracle for the trust-list engine, never a runtime/build dep.

## 2. Crate version pins (the format/trust + crypto layers)

The format/trust layers added for this feature are pinned to EXACT versions (`=x.y.z`) in the root
`Cargo.toml` `[workspace.dependencies]` so the conformance target is reproducible (Principle VII):

| Crate | Pin | Role |
|-------|-----|------|
| `coset` | `=0.4.2` | COSE codec for ISO 18013-5 mdoc (`IssuerAuth` / `DeviceAuth` `COSE_Sign1`). Codec only — crypto stays in the RustCrypto stack. |
| `sd-jwt-payload` | `=0.5.1` (`default-features = false`) | SD-JWT VC format layer (disclosures + KB-JWT structure); signature verification is in-house RustCrypto (no second crypto stack). |
| `quick-xml` | `=0.40.1` | TS 119 612 trust-list XML reader. |

The crypto / X.509 / CMS stack is **reused** from the signing core's pinned set (one authoritative
crypto stack — Principle III/IV; no hand-rolled crypto — Principle IV), at the workspace pins:
`ciborium 0.2`, `sha2 0.10`, `der 0.7`, `const-oid 0.9`, `spki 0.7`, `x509-cert 0.2`, `cms 0.2`,
`rsa 0.9`, `p256 0.13`, `ecdsa 0.16`, `signature 2`, `base64ct 1`.

## 3. DRY review (T031, Constitution Principle VIII)

Two reuse claims were verified against the source; no genuine copy-paste duplication was found, so no
extraction was performed (and none was warranted — see the justification for the parallel state
machines below).

### 3.1 Signer-hook is the spec-001 pattern, not a re-implementation

The holder signer-hook (`src/issuance/signer.rs`) reuses the **pattern** of the spec-001 remote-signing
flow (SDK builds the exact, deterministic signing input; the host signs out-of-process; the SDK
splices the signature back), explicitly documented in the module header. It is **not** a copy of any
signing logic, and there is no shared private-key handling to extract because **neither crate ever
holds a key**:

- `cleverbase-core` signs via the CSC **`signHash` HTTP effect** — the remote Cleverbase signer signs
  over the network (a `Step::PerformHttp`); there is no `Signer` trait.
- `cleverbase-attestation` signs the holder proof via a local **`Signer` callback trait**
  (`Signer::sign(handle, &SigningInput)`) — the integrator's wallet/HSM signs the holder key
  out-of-process.

The mechanisms differ **by domain** (a remote QES signing service vs. the integrator's local holder
HSM); only the sans-IO boundary and the build-input/splice-result shape are shared, which is the
intended reuse.

### 3.2 One trust-list primitive backs both the always-on bar and the qualified gate

`src/trust/chain.rs::verify_chain` is the **single** X.509 chain-validation primitive. It backs:

- the **always-on bar** — `src/trust/engine.rs` (`resolve`, line ~277) and `src/trust/xml.rs`
  (LOTL/national-TL signer authentication, line ~215); and
- the **qualified gate** — `src/qualified/mod.rs` anchors the national TL's signer certificate through
  the same `verify_chain` (its module header states this is "the same X.509 primitive the always-on
  bar uses — DRY").

The qualified module defines **no** parallel chain validator and also reuses
`src/trust/manifest.rs::parse_rfc3339_utc_pub` for the RFC 3339 status-time parsing — one authoritative
trust/time primitive set.

### 3.3 The parallel `begin`/`resume` + effect state machines are justified (not duplication)

`src/issuance/obtain.rs` defines its own `HttpEffect` / `HttpMethod` / `ObtainStep`, mirroring
`cleverbase-core::effects::{HttpEffect, HttpMethod, Step}`. This is a **justified parallel**, not
extractable copy-paste:

- `cleverbase-attestation` **does not depend on** `cleverbase-core` (sibling crates under
  `cleverbase-ffi`); the attestation core is deliberately standalone (one self-contained sans-IO
  attestation core). Sharing the type would force a cross-crate dependency (pulling the unrelated
  PAdES/CMS/timestamp stack into the attestation core) or a new shared crate — an architectural change
  far outside this task's scope (no opportunistic refactor — Principle VIII).
- The domains genuinely diverge: the `Step` enums share **no** terminal variants
  (`Step::{Redirect, Done{signed, evidence}}` vs. `ObtainStep::{Sign(SigningInput), Skipped,
  Obtained(HeldAttestation)}`), and the `HttpEffect.body` semantics differ
  (`Option<Vec<u8>>` skip-if-none vs. always-present `Vec<u8>`).

Recorded as a deliberate parallel; tracked here rather than refactored.

## 4. Quickstart results (T034)

`quickstart.md` scenarios 1–5 (the offline ones) were run end-to-end and confirmed green. The
quickstart names the suites as separate integration-test targets (`--test verify`,
`--test openid4vp_binding`, `--test qualified_gate`, `--test issuance`); in the delivered crate these
suites are **in-crate `#[cfg(test)]` modules** (the only integration-test targets are `live_issuance`
and the opt-in `export_artifacts`), so they are exercised via test-name filters, which is the
equivalent runnable form. Results:

| Scenario | Validates | Runnable command (as delivered) | Result |
|----------|-----------|---------------------------------|--------|
| 1 — verify both formats | US1, FR-001/002/003/005, SC-001/002 | `cargo test -p cleverbase-attestation sdjwtvc:: mdoc::` | green |
| 2 — replay / audience binding | FR-015, SC-008 | `cargo test -p cleverbase-attestation openid4vp::` | green |
| 3 — opt-in qualified gate | FR-014, SC-007 | `cargo test -p cleverbase-attestation qualified::` | green (fixture present; self-skips when absent) |
| 4 — independent cross-check | FR-013, Principle VI | `scripts/crosscheck-attestation.sh --expect valid <artifact>` | self-skips cleanly (no EU reference verifier on PATH); exit 0 |
| 5 — coverage + no-external-deps | FR-013, SC-003 | `cargo test -p cleverbase-attestation` + per-crate coverage | green; 230 tests; line coverage **97.72% ≥ 95%** |
| 6 — gated live issuance | US2, FR-006/007/008/009, SC-004/005 | `cargo test -p cleverbase-attestation --test live_issuance` | self-skips when `ATT_ISSUER` unset (opt-in workflow only) |

**Experimental-standards caveat (recorded per T034):** Scenario 3's qualified-status gate implements
**TS 119 615 v1.4.1 cl. 4.12**, which is **pre-operational** — it is opt-in, off by default, and
version-pinned; enabling it never changes the always-on verdict (SC-007), and missing/ambiguous TL
data yields `Indeterminate` (never a false "qualified"). Scenario 4's independent cross-check is the
FR-013 signal but requires an external different-language reference verifier (Kotlin
`eudi-lib-jvm-sdjwt-kt` / TS `mdoc-ts`), which is not packaged with the SDK; the harness self-skips
when it is absent (the opt-in `attestation-crosscheck.yml` workflow wires it).
