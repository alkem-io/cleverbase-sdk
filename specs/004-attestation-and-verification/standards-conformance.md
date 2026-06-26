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

### 1.1 Leaf key-purpose policy (X.509 path validation — `src/trust/chain.rs`)

`verify_chain` enforces the role/format-appropriate **leaf key purpose** on the credential's signing
certificate (the `LeafPurpose` parameter), so a genuinely-chained-but-WRONG-PURPOSE leaf is rejected
(closing the "right chain, wrong purpose" false-accept — e.g. a TLS `serverAuth` cert issued under the
same trusted root, or an mdoc-DS cert presented as the SD-JWT VC issuer leaf). The purpose is threaded
from the credential's `Format` by `resolve_chain`; the trust-list-signer authentication paths
(`trust::xml`, `qualified`) pass `TrustListSigner`, which imposes no credential-leaf purpose (a TL
signer is governed by a separate ETSI profile).

| Leaf role/format | Enforced leaf-purpose rule | Standard (verified online) |
|------------------|----------------------------|----------------------------|
| **mdoc Document Signer** (`Format::Mdoc`) | `extendedKeyUsage` MUST be present and contain `id-mso-mdl-DS` = **`1.0.18013.5.1.2`**. Absent EKU, or an EKU not listing the OID (e.g. only `serverAuth`), is rejected (`WrongLeafPurpose`). Criticality is **not** required: ISO marks the EKU row mandatory-but-not-critical (field type `m`, not `mc`), and RFC 5280 §4.2.1.12 leaves EKU criticality at the issuer's option. | **ISO/IEC 18013-5:2021 Annex B, Table B.3** (mDL document signer certificate). OID cross-checked at the OID registry. Criticality per **RFC 5280 §4.2.1.12**. |
| **SD-JWT VC issuer** (`Format::SdJwtVc`) | **No EKU is mandated by any governing spec.** Enforced floor: the leaf **MUST NOT be a CA** (`basicConstraints cA=TRUE` ⇒ rejected — a CA cert must not double as an end-entity signer); and **if** `keyUsage` is present it MUST assert a signing bit (`digitalSignature` or `nonRepudiation`/content-commitment — ETSI EN 319 412-2 issuer Types A/B/C). Absent `keyUsage` is permitted. No EKU is required (an EKU, if present, is not rejected). | IETF **`draft-ietf-oauth-sd-jwt-vc`** §2.5 + **RFC 9901** (silent on EKU/keyUsage); **OpenID4VC HAIP 1.0** §6.1.1 (chain-to-anchor only, no EKU); **EUDI ARF** / Commission IRs (issuer distinguished by **QcStatement** OIDs `0.4.0.194126.1.x`, **not** an EKU); **ETSI TS 119 412-6** / **EN 319 412-2** (keyUsage Types A/B/C/F mandated; §4.3.10 forbids marking EKU critical and assigns no EKU). |
| **Trust-list signer** (`TrustListSigner`) | No credential-leaf key-purpose constraint (the signer is authenticated solely by chaining to a configured scheme-operator anchor). | n/a — TL signer governed by a separate ETSI profile, not the credential-leaf profiles above. |

Fail-closed throughout: a malformed or duplicate `extendedKeyUsage` / `keyUsage` / `basicConstraints`
extension is rejected (a leaf whose purpose cannot be decoded is not trusted to act in that role), using
`x509-cert`'s typed `ExtendedKeyUsage` / `KeyUsage` / `BasicConstraints` decoders (no hand-rolled ASN.1).

Source URLs: ISO 18013-5 DS profile (Table B.3) — https://www.iso.org/standard/69084.html (DS EKU
`1.0.18013.5.1.2`, https://oid-base.com/get/1.0.18013.5.1.2); RFC 5280 §4.2.1.9 (pathLenConstraint
"non-self-issued"), §4.2.1.12 (EKU criticality), §6.1 (self-issued = subject DN == issuer DN), §6.1.4
(l) (self-issued not counted toward path length) — https://www.rfc-editor.org/rfc/rfc5280; SD-JWT VC
§2.5 — https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-16.html; HAIP 1.0 §6.1.1 —
https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html; ETSI TS 119 412-6
/ EN 319 412-2 — https://www.etsi.org/deliver/etsi_ts/119400_119499/11941206/.

### 1.2 Certification-path validation hardening (RFC 5280 §6.1 — `src/trust/chain.rs`)

`verify_chain` walks the supplied `x5c`/`x5chain` to a configured anchor as a **bounded, backtracking
depth-first search**: when several supplied intermediates name-match (and validly issue) the current
certificate — a cross-certificate or an alternate sub-CA — each is tried in turn and a dead-end branch
is unwound so an alternate is explored. A conformant credential that reaches a configured anchor via
**some** valid path is therefore accepted (no false-reject from a greedy first-match commit). Two path
counters are threaded distinctly per **RFC 5280**: `pathLenConstraint` counts only **non-self-issued**
intermediates (§4.2.1.9 / §6.1.4 (l): a self-issued — subject DN == issuer DN — key-rollover cert "is
not counted when evaluating path length"), while the `MAX_PATH_LEN` denial-of-service cap counts every
hop (so a self-issued-cert flood cannot evade it). Source: https://www.rfc-editor.org/rfc/rfc5280
§4.2.1.9, §6.1, §6.1.4.

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
