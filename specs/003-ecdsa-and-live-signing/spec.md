# Feature Specification: ECDSA P-256 validation parity + live Cleverbase-account signing

**Feature Branch**: `feature/003-ecdsa-and-live-signing`

**Created**: 2026-06-24

**Status**: Draft

**Input**: User description: "yes, close this gap regarding ECDSA. Remember about DRY principle, unify code paths where it is possible. Also, expand our FE testing fixture to be able to sign with an actual cleverbase account (we will get OIDC registration and the rest). And for verification of such signature."

## Context

The SDK already *implements* both signature algorithms the Cleverbase remote-QES surface offers —
RSA (CSC `v1_rsa`, sha256WithRSAEncryption) and ECDSA P-256 (CSC `v2_ecdsa`, ecdsa-with-SHA256) — and
both have unit coverage (credential-algorithm detection, signature-algorithm OIDs, ECDSA r‖s→DER
encoding). However only **RSA** is proven correct end-to-end: the credential-free reference stack signs
with an RSA key, the B-B/B-T end-to-end test runs `v1_rsa`, and the independent OpenSSL validation
verifies only the RSA-produced CMS. **ECDSA P-256 has never been driven through a full
begin→authorize→sign→assemble→independently-verify flow**, so an integrator relying on it could ship a
silently wrong signature. (Synthetic EC signer fixtures already exist but are not wired into the test
upstream.) Separately, no test has ever produced a signature against the **real** Cleverbase service —
all proof to date is against a stand-in mock.

This feature closes both gaps: it brings ECDSA P-256 to full validation parity with RSA (credential-
free, independently verified, with the two algorithms sharing one DRY code/test path), and it adds a
gated contract path that signs with a **real Cleverbase account** and independently verifies the
resulting signature against the real Cleverbase-issued trust chain.

## Clarifications

### Session 2026-06-24

- Q: How is the Cleverbase user-authorization step (OIDC/SCAL2 approval — the signer's sole-control
  moment) completed during a live signing run? → A: Design for both via a **pluggable authorizer**: an
  interactive human-in-the-loop mode (default, works today — a human completes the Cleverbase approval and
  the flow resumes) plus a headless mode (opt-in, activated when a Cleverbase test credential with
  automatable approval is available, enabling unattended/CI runs). The live path selects the mode by
  configuration and must support adding the headless mode without a rewrite.
- Q: What depth of validation must the independent verification assert (credential-free and live)? → A:
  **Both.** The cryptographic + structural OpenSSL check (CMS signature, certificate chain, RFC 3161
  timestamp for B-T, and the PAdES ByteRange/Contents structure) is the **always-on** bar — extended to
  ECDSA at parity with RSA. In addition, a **PAdES/eIDAS baseline-profile conformance** validation (ETSI
  EN 319 142 PAdES B-B/B-T: signed-attribute set, signing-certificate-v2 reference, timestamp) is provided
  as an **opt-in** gate over produced signatures.
- Q: Which signature algorithms must the live contract path cover? → A: **Both, opportunistically;
  require one.** Exercise whichever real credential the supplied account has; cover both RSA (v1) and
  ECDSA (v2) live when credentials for both are available, but require only one algorithm to sign + verify
  for the live path to pass (the credential-free suite already proves both algorithms end-to-end).
- Q: Which PAdES conformance levels must the live contract path cover? → A: **B-B required, B-T when a TSA
  is available.** The live path MUST produce + verify a B-B signature; it additionally covers B-T when an
  RFC 3161 timestamp authority is configured for the run, but B-B alone is sufficient to pass (B-T
  timestamping is already proven credential-free, and a live TSA may not always be wired) — mirroring the
  "require minimum, cover more opportunistically" pattern used for algorithms.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - ECDSA P-256 signatures are independently verified end-to-end, at parity with RSA (Priority: P1)

An integrator (or a maintainer guaranteeing the SDK's advertised capabilities) needs the same level of
proof for ECDSA P-256 that already exists for RSA: that a signature the SDK assembles for an ECDSA
credential is structurally and cryptographically correct — accepted by an *independent* validator, not
just by the SDK's own code. Today that proof exists only for RSA.

**Why this priority**: The SDK publicly advertises "RSA and ECDSA P-256," but ECDSA is unproven beyond
unit tests. This is the headline correctness gap the user asked to close, and it is achievable entirely
with the existing credential-free infrastructure (no external dependency), so it can ship first and
independently.

**Independent Test**: Run the credential-free reference stack configured for an ECDSA P-256 credential
and complete a B-B and a B-T signing flow; assert the produced PDF's PAdES/CMS verifies with an
independent validator (OpenSSL) against the synthetic EC certificate chain — exactly as the RSA case is
verified today. No real Cleverbase credentials required.

**Acceptance Scenarios**:

1. **Given** the reference stack in credential-free mode presenting an ECDSA P-256 credential, **When** a
   B-B signing flow completes, **Then** the produced PDF carries a PAdES CMS whose signature-algorithm
   is `ecdsa-with-SHA256` and which an independent validator accepts against the synthetic EC issuer
   chain.
2. **Given** the same configuration with conformance B-T, **When** the flow completes, **Then** the
   signature additionally carries a valid RFC 3161 timestamp that the independent validator accepts.
3. **Given** a credential whose key is neither RSA nor ECDSA P-256 (e.g. an unsupported curve), **When**
   signing is attempted, **Then** the flow terminates with a clear, specific error and produces no
   signature (no silent fallback to a wrong algorithm).
4. **Given** the RSA path that exists today, **When** the ECDSA path is added, **Then** RSA behaviour and
   its existing validation are unchanged (no regression).

---

### User Story 2 - Signatures produced against a real Cleverbase account are independently verified (Priority: P2)

A maintainer needs to prove the SDK works against the **actual** Cleverbase service — its real OIDC
authentication, its real CSC signing API, and the real PKI — not only against the credential-free mock.
A gated contract path runs a complete signing journey against the Cleverbase acceptance environment
using a supplied real account/credential, and independently verifies that the resulting signature is
valid against the real Cleverbase-issued signer certificate and its issuer chain.

**Why this priority**: The mock proves the SDK's behaviour against a faithful stand-in, but only a live
run proves the SDK matches the real Cleverbase API and produces signatures the real trust chain accepts.
It is P2 (not P1) because it depends on real credentials and a human-authenticated authorization step
that the project will supply later ("we will get OIDC registration and the rest"), so it must be
*opt-in* and must not block the credential-free pipeline.

**Independent Test**: With real Cleverbase credentials and an account configured, run the live contract
path for a full signing flow; assert it produces a signed PDF that an independent validator accepts
against the real Cleverbase-issued signer certificate + issuer chain. A single run exercises the algorithm
of the configured credential; covering **both** RSA and ECDSA live is a CI-matrix property (one matrix leg
per algorithm), not a single-run one. With no real credentials configured, the path is **skipped**
(reported as skipped, never failed), leaving the credential-free suite unaffected.

**Acceptance Scenarios**:

1. **Given** valid real Cleverbase credentials and account are configured, **When** the live contract
   path runs a full signing flow for the account's credential type, **Then** it produces a signed PDF
   that an independent validator accepts against the **real** Cleverbase signer certificate and its
   issuer chain.
2. **Given** the supplied account has an ECDSA P-256 credential, **When** the live flow runs, **Then** it
   exercises and verifies the real ECDSA path (and likewise for an RSA credential), so live coverage
   mirrors the algorithm parity proven credential-free in User Story 1.
3. **Given** no real credentials are configured (the default CI state), **When** the test suite runs,
   **Then** the live contract path is skipped and the credential-free suite runs and passes unchanged.
4. **Given** a real-service authentication or authorization failure (expired/invalid credential, declined
   approval), **When** the live flow runs, **Then** the failure is surfaced as a clear, actionable error
   distinguishing a service/credential problem from an SDK defect.
5. **Given** the interactive authorization mode, **When** the live flow reaches the Cleverbase approval
   step, **Then** a human can complete the approval and the flow resumes to produce a verified signature;
   **and** when a headless (automatable test-account) mode is configured instead, the same flow runs
   unattended — selected purely by configuration, with no change to the rest of the live path.
6. **Given** a live run with no timestamp authority configured, **When** the live flow runs, **Then** it
   produces + verifies a **B-B** signature and passes (not blocked by the missing TSA); **and** when an
   RFC 3161 timestamp authority *is* configured, **Then** it additionally produces + verifies a **B-T**
   signature.

---

### Edge Cases

- A credential whose certificate chain advertises an unexpected or ambiguous key OID → resolved to a
  single supported algorithm or rejected with a specific error; never guessed.
- An ECDSA signature returned by the signing service in raw r‖s form of unexpected length → rejected,
  not mis-encoded into a malformed DER signature.
- A live flow where the human authorization (OIDC/SCAL2 approval) is not completed within the allotted
  window → the test fails fast with a clear "authorization not completed" message, not a hang.
- The real Cleverbase issuer/trust chain rotates or differs from what the verifier expects → verification
  fails loudly with which certificate/chain was missing, rather than passing on an unverified chain.
- Running the live path without one or more required real-credential settings → skipped (not a partial,
  misleading run).
- A signature that passes the cryptographic + structural check but fails PAdES/eIDAS profile conformance
  (when that opt-in gate is enabled) → the gate fails loudly, naming the non-conformant element, rather
  than passing a non-conformant-but-cryptographically-valid signature.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The credential-free reference stack MUST be able to present and sign with an **ECDSA P-256**
  credential (in addition to the existing RSA credential), selectable per signing flow.
- **FR-002**: The system MUST complete full **B-B and B-T** signing flows using an ECDSA P-256 credential
  and produce a PAdES/CMS signature whose signature algorithm is `ecdsa-with-SHA256`.
- **FR-003**: An **independent validator** (not the SDK's own code) MUST verify the ECDSA-signed output —
  the CMS signature, the certificate chain, the PAdES ByteRange/Contents structure, and (for B-T) the RFC
  3161 timestamp — for both B-B and B-T, mirroring the existing RSA validation. This cryptographic +
  structural check is the **always-on** validation bar.
- **FR-004**: The RSA and ECDSA signing/verification paths MUST share a single, **algorithm-parametrized
  code path** wherever the logic is common (credential generation/fixtures, the test upstream's signing,
  the end-to-end harness, and the independent-validation harness). Algorithm-specific behaviour MUST be
  isolated to the minimum necessary points, with **no copy-pasted RSA/ECDSA duplication** (Constitution
  Principle III/VIII — DRY).
- **FR-005**: Adding ECDSA coverage MUST NOT regress any existing RSA behaviour, test, or validation.
- **FR-006**: Unit-test line coverage MUST remain ≥95% per crate/package after the change (Constitution
  Principle VI); the new credential-free ECDSA flow MUST be covered by tests that fail before the
  implementation exists (test-first).
- **FR-007**: The system MUST provide a **live contract path** that performs a complete signing journey
  against the **real Cleverbase environment** using externally supplied real credentials/account. It MUST
  exercise **both RSA (v1) and ECDSA (v2)** when real credentials for both are available, and MUST pass
  when **at least one** algorithm signs and is independently verified (the credential-free suite already
  proves both algorithms end-to-end).
- **FR-008**: The live contract path MUST **independently verify** the signature it produces against the
  **real Cleverbase-issued signer certificate and its issuer chain** (not a synthetic chain).
- **FR-009**: The live contract path MUST be **opt-in and gated on the presence of real credentials**: when
  the required real-credential configuration is absent, it MUST be reported as **skipped** (never failed),
  and the credential-free pipeline MUST run and pass unchanged.
- **FR-010**: The live contract path MUST NEVER commit, log, or otherwise expose real secrets
  (credentials, tokens, keys); real credentials are provided only via secure external configuration
  (Constitution Principle IV).
- **FR-011**: Failures in the live path MUST clearly distinguish a **service/credential/authorization
  problem** (the dependency) from an **SDK defect**, so a red live run is actionable.
- **FR-012**: The independent verification (both synthetic and live) MUST reject — not silently accept — a
  signature whose algorithm, chain, digest, or timestamp does not validate.
- **FR-013**: The live contract path MUST drive the Cleverbase user-authorization step through a
  **pluggable authorizer** with two interchangeable modes selected by configuration: an **interactive**
  mode (default, available immediately — surfaces the authorization to a human and resumes once approved)
  and a **headless** mode (opt-in — drives an automatable Cleverbase test-credential approval for
  unattended runs). Enabling the headless mode MUST NOT require reworking the live path. The MUST is on the
  pluggable **seam** (both modes selectable by configuration); the headless **approval mechanism** is
  delivered when an automatable Cleverbase test credential becomes available (a pending external dependency
  — see Dependencies), and until then the headless mode ships as a configured, documented drop-in.
- **FR-014**: An **opt-in PAdES/eIDAS baseline-profile conformance** validation MUST be available over
  produced signatures (credential-free and live), asserting the output meets the ETSI EN 319 142 PAdES
  **B-B / B-T** profile (the required signed-attribute set, the signing-certificate-v2 reference, and the
  RFC 3161 timestamp for B-T). It runs in addition to — never instead of — the always-on cryptographic +
  structural check (FR-003 / FR-012) and MUST be independently enable-able.
- **FR-015**: The live contract path MUST produce + independently verify a **B-B** signature (required),
  and MUST **additionally** produce + verify a **B-T** signature when an RFC 3161 timestamp authority is
  available to the run. **B-B alone is sufficient** for the live path to pass — a live run MUST NOT be
  blocked by the absence of a timestamp authority (B-T timestamping is already proven by the
  credential-free suite).

### Key Entities

- **Signing credential**: a signer key + certificate of a given algorithm (RSA-2048 or ECDSA P-256),
  identified by its certificate's key/signature OIDs; drives which signature algorithm the flow uses.
- **Synthetic signer fixture**: a credential-free, committed test credential (one per algorithm) used by
  the reference stack to produce verifiable signatures without contacting Cleverbase.
- **Real Cleverbase account/credential**: an externally supplied registration (OIDC client + account +
  credential) used only by the gated live contract path; never committed.
- **Produced signature artifact**: the signed PDF and its embedded PAdES/CMS (signature algorithm,
  certificate chain, optional RFC 3161 timestamp) — the thing the independent validator checks.
- **Independent validator**: a verifier external to the SDK's signing code that confirms a produced
  signature is correct against a given trust chain (synthetic for credential-free, real for live).

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Both signature algorithms the SDK advertises (RSA and ECDSA P-256) are proven end-to-end:
  100% of the conformance levels validated for RSA (B-B and B-T) are also validated for ECDSA P-256 by an
  independent validator.
- **SC-002**: The credential-free pipeline produces and independently verifies an ECDSA P-256 signature
  for B-B and B-T with **zero** real credentials required, and continues to do so for RSA (no regression).
- **SC-003**: There is **one** algorithm-parametrized signing/verification path, not two parallel copies:
  adding or changing an algorithm touches a single place, and a reviewer can confirm no RSA/ECDSA logic is
  duplicated.
- **SC-004**: Unit-test line coverage stays ≥95% per crate/package, and the credential-free test suite
  (including the new ECDSA flows) passes with no external dependency.
- **SC-005**: When real Cleverbase credentials are supplied, a maintainer can produce a signature with a
  real account and have it independently verified against the real Cleverbase trust chain in a single,
  repeatable run — covering both RSA and ECDSA when credentials for both are supplied, and passing on at
  least one verified algorithm; when credentials are absent, that run is cleanly skipped and the rest of
  the suite is green.
- **SC-006**: A deliberately broken signature (wrong algorithm, tampered chain, bad timestamp) is rejected
  by the independent validator in 100% of cases — the verification has no false-accept.
- **SC-007**: With the PAdES/eIDAS profile-conformance gate enabled, every produced B-B and B-T signature
  (RSA and ECDSA) is confirmed to meet the ETSI EN 319 142 baseline profile, while the always-on
  cryptographic + structural verification runs unconditionally regardless of whether that gate is enabled.

## Assumptions

- **ECDSA parity reuses the existing credential-free infrastructure**: the reference mock upstream, the
  shared fixtures, and the OpenSSL-based independent validation are extended (parametrized by algorithm),
  not replaced. The synthetic EC signer fixtures already in the repository are the starting point.
- **Independent verification means an external validator** (OpenSSL for the CMS/chain/timestamp, plus the
  existing structural PAdES checks), consistent with how RSA is validated today, as the **always-on** bar —
  for both the synthetic and live paths (live uses the real Cleverbase issuer chain as the trust anchor).
  A **PAdES/eIDAS baseline-profile conformance** validation (ETSI EN 319 142) is provided as an additional
  **opt-in** gate (FR-014), not a replacement for the cryptographic bar.
- **The live path targets the Cleverbase acceptance environment** by default, using externally supplied
  credentials (the project will provide the OIDC registration, account, and credential). It is a
  maintainer-run / opt-in contract check, not part of the always-on credential-free CI.
- **The real-service user-authorization step uses a pluggable authorizer** (resolved — see
  Clarifications): an interactive human-in-the-loop mode is the default and works as soon as real
  credentials are supplied; a headless mode is added for unattended runs when Cleverbase provides an
  automatable test-credential approval. The real OIDC registration, account, and credential are supplied
  by the project ("we will get OIDC registration and the rest").
- **No new signature algorithms are in scope** — only bringing the already-implemented ECDSA P-256 to
  validation parity with RSA, and proving the real surface. RSA and ECDSA P-256 remain the full set.
- **Real credentials are never committed**; they enter only via secure external configuration and are
  excluded from logs/artifacts (Constitution Principle IV).

## Dependencies

- A real Cleverbase OIDC client registration, account, and signing credential (RSA and/or ECDSA P-256),
  plus the real issuer/trust chain — supplied externally by the project for User Story 2.
- The existing credential-free reference integration (spec 002) and the Rust signing core (spec 001),
  which this feature extends.
