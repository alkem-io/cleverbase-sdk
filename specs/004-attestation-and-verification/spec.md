# Feature Specification: EUDI attestation — verification now, issuance forward-looking

**Feature Branch**: `feature/004-attestation-and-verification`

**Created**: 2026-06-25

**Status**: Draft

**Input**: User description: "so, we need now to add attestation. cleverbase MUST have something regarding it in the docs or elsewhere" + clarifications: "we are talking about the EUDI verifiable-credential sense" and "in addition to attestation we need also verification in SDK".

## Context

This feature adds **EUDI attestation** (electronic attestation of attributes — verifiable credentials in
the EU Digital Identity sense, NOT device/remote attestation) to the SDK, which today does remote QES
signing (specs 001–003). It covers two halves: **verifying** a presented attestation (the verifier /
relying-party side) and **obtaining/holding** an attestation (the issuance / holder side).

A pre-feature feasibility check of what **Cleverbase actually offers** (the user's explicit gate —
"Cleverbase MUST have something regarding it in the docs or elsewhere") found, with sources:

- **No integratable EUDI attestation API exists at Cleverbase today.** Their developer portal documents
  only Client Registration, the OIDC **Identification API**, **Data Sharing DM (Beta)**, the **CSC Signing
  API** (+ v2 Beta), and a **Storage API (Beta)** — none for EUDI wallet, (Q)EAA, PID, OpenID4VCI/VP,
  SD-JWT VC, or mdoc.
- The Identification API returns identity **attributes as OIDC claims** (including a `com.cleverbase.proof`
  claim) — these are *not* independently-verifiable EUDI credentials.
- Cleverbase's EUDI work is **roadmap / closed government pilots** (e.g. a VNG hackathon, Dec 2025 / Jan
  2026) and **research repositories explicitly marked "not a supported Cleverbase product"** — consistent
  with the EU EUDI Wallet timeline (wallets due end-2026).

This finding **forks the feature by footing**:

- **Verification** (verify a presented SD-JWT VC or ISO mdoc against the issuer signature, the EU Trusted
  Lists, validity, revocation/status, and holder binding) is **buildable now against open EUDI standards,
  independent of any Cleverbase API** — exactly as the SDK already *owns* the AdES validation stack for
  signatures (Constitution Principle V).
- **Issuance / holding** (obtaining a (Q)EAA or PID *from an issuer* via OpenID4VCI) **depends on an issuer
  API; Cleverbase has none today.** It is therefore specified **forward-looking against the EUDI standards
  + Cleverbase's roadmap, with the Cleverbase-/issuer-dependent steps gated and skipped until a real issuer
  API exists** — mirroring how spec 003 gates the live-signing contract path on real credentials.

## Clarifications

### Session 2026-06-25

- Q: "Attestation" in which sense? → A: The **EUDI verifiable-credential** sense (electronic attestation of
  attributes — (Q)EAA / PID), NOT device/remote/TEE attestation.
- Q: Given Cleverbase has no integratable EUDI attestation issuance API today, how is this feature scoped?
  → A: **Verify now + issuance forward-looking (gated).** Build the EUDI attestation **verification** stack
  now (standards-based, no Cleverbase API needed); **also** specify issuance/holding against the EUDI
  standards + Cleverbase's roadmap, with the Cleverbase-/issuer-dependent parts **gated/skipped until that
  API ships** (the spec-003 live-signing gating pattern).
- Q: Phase the two credential formats, or deliver both? → A: **Both together** — SD-JWT VC **and** ISO/IEC
  18013-5 mdoc verification are delivered in this feature (no format phasing).
- Q: How deep should the eIDAS trust determination go on verification? → A: **Always-on crypto + trust;
  qualified status opt-in.** The always-on bar is cryptographic validity + issuer-present-on-the-configured-
  trust-list (trusted). Full eIDAS **qualified-status determination** (ETSI TS 119 615 — Qualified EAA? from
  a qualified issuer? granted at the relevant time?) is an **opt-in additional gate**, mirroring the spec-003
  always-on-bar + opt-in-profile-gate pattern.
- Q: On the verifier side, build the request or only verify? → A: **Full verifier** — the SDK builds the
  OpenID4VP presentation request (attribute query + nonce + audience binding) **and** verifies the response
  is bound to that request (replay/audience-binding correct by construction).

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Verify a presented EUDI attestation (Priority: P1)

A relying-party integrator receives an EUDI verifiable credential presented by a holder (an SD-JWT VC or an
ISO/IEC 18013-5 mdoc) and needs a trustworthy **valid / invalid verdict with reasons** — without becoming a
PKI/standards expert. The SDK verifies the issuer's signature, anchors trust to the EU Trusted Lists,
checks validity period and revocation/status, confirms holder binding, and confirms selective-disclosure
integrity.

**Why this priority**: This is the half that is **fully buildable today** against open standards with no
dependency on a Cleverbase (or any) issuer API, it is the natural extension of the SDK's "own the
validation stack" mandate (Principle V), and it delivers standalone value (any EUDI-conformant attestation,
including future Cleverbase ones, can be verified). It is the MVP and ships first.

**Independent Test**: Present conformant EUDI test credentials (SD-JWT VC and mdoc) issued under a test
trust anchor; assert the SDK returns VALID with the expected disclosed attributes; present tampered,
expired, revoked, wrong-issuer, and broken-holder-binding variants and assert each returns INVALID with the
specific reason. No real Cleverbase API or live network required.

**Acceptance Scenarios**:

1. **Given** a well-formed, in-validity SD-JWT VC presentation from an issuer in the configured trust list,
   **When** it is verified, **Then** the result is VALID and exposes the disclosed attributes and the
   resolved issuer/trust status.
2. **Given** the same for an ISO mdoc presentation, **When** it is verified, **Then** the result is VALID
   with the disclosed attributes.
3. **Given** a credential whose issuer signature is tampered, is expired, is revoked/suspended per its
   status mechanism, is from an issuer not in the trust list, or whose holder binding does not verify,
   **When** it is verified, **Then** the result is INVALID with a **specific** machine-readable reason (no
   false-accept).
4. **Given** a selective-disclosure presentation revealing only a subset of attributes, **When** it is
   verified, **Then** only the disclosed attributes are returned and their integrity against the issuer
   signature is confirmed (undisclosed attributes are neither revealed nor required).
5. **Given** the SDK issued an OpenID4VP request with a fresh nonce + audience, **When** a presentation that
   is **not** bound to that nonce/audience (replayed, or addressed to a different verifier) is verified,
   **Then** the result is INVALID with a replay/audience-binding reason; **and** a presentation correctly
   bound to the issued request verifies.
6. **Given** the opt-in qualified-status gate is enabled, **When** an attestation from a **qualified** issuer
   (granted at the relevant time) is verified, **Then** the verdict reports QUALIFIED; **and** an otherwise-
   valid attestation from a non-qualified (but trusted) issuer reports VALID-but-NOT-QUALIFIED, never a
   false "qualified".

---

### User Story 2 - Obtain, hold, and present an EUDI attestation (Priority: P2, issuance gated on the issuer API)

An integrator drives a holder through **obtaining** an attestation from an issuer (OpenID4VCI) and later
**presenting** it (with selective disclosure) to a verifier (OpenID4VP). The SDK orchestrates these flows
sans-IO and hands the resulting artifacts to the integrator; it is **not** a wallet and never holds
sole-control secrets in a browser (Principle IV).

**Why this priority**: It completes the issuer→holder→verifier triangle, but the issuance side depends on a
real issuer API and **Cleverbase has none today** (roadmap/pilot). It is therefore P2 and its
Cleverbase-/issuer-dependent steps are **opt-in and skipped until a real issuer API exists**, exactly like
the spec-003 live-signing contract path. The standards-level flow and the holder→verifier presentation are
specified now; the live issuance is exercised when an issuer API becomes available.

**Independent Test**: Against an **EUDI-conformant issuer test double / reference issuer** (not a real
Cleverbase API), run the OpenID4VCI issuance flow and assert a conformant credential is obtained; run the
OpenID4VP presentation flow and assert the produced presentation verifies under User Story 1. When **no
issuer API is configured**, the issuance path is **skipped** (reported skipped, never failed), and the
verification suite (US1) still runs and passes.

**Acceptance Scenarios**:

1. **Given** an EUDI-conformant issuer (reference/test) and a configured holder context, **When** the
   issuance (OpenID4VCI) flow runs, **Then** a conformant attestation (SD-JWT VC or mdoc) is obtained and
   verifies under User Story 1.
2. **Given** a held attestation, **When** the holder presents it (OpenID4VP) disclosing a chosen subset of
   attributes, **Then** the verifier (US1) accepts it and sees only the disclosed attributes.
3. **Given** no issuer API is configured (the default state), **When** the test suite runs, **Then** the
   issuance path is **skipped** and the verification suite runs and passes unchanged.
4. **Given** a real Cleverbase issuer API becomes available, **When** it is configured, **Then** the same
   issuance flow obtains a Cleverbase-issued attestation that verifies under User Story 1 — **without
   reworking** the flow (the issuer is a configured backend, like the TSA/CSC backends in signing).
5. **Given** issuance/holding involves holder-binding key material, **When** the flow runs, **Then** no
   sole-control secret or holder key is handled in a browser/frontend, and credential custody follows the
   integrator-owns-storage model (the SDK is not an embedded wallet).

---

### Edge Cases

- An issuer present in the trust list but with an **expired or revoked trust-list entry** → INVALID with a
  trust-status reason (not merely "issuer unknown").
- A credential whose **status/revocation endpoint is unreachable** → a defined, configurable outcome
  (fail-closed by default), never a silent VALID.
- A presentation whose **format is recognized but malformed** (bad SD-JWT disclosure digest, bad mdoc
  COSE/CBOR) → INVALID with a specific parse/cryptographic reason, never a crash or a guess.
- A presentation in an **unsupported format/profile** → a clear "unsupported format" error, not a
  misverification.
- The **EU LOTL / national Trusted List** is unreachable or stale → a defined outcome (configurable;
  fail-closed by default for qualified verification), surfaced explicitly.
- Issuance attempted with **no issuer API configured** → skipped, not a partial/misleading run.
- A real Cleverbase attestation API that, when it ships, **diverges from the assumed EUDI profile** → the
  issuer-backend seam absorbs it without reworking verification or the holder flow.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The SDK MUST **verify a presented EUDI attestation** and return a clear VALID/INVALID verdict
  with machine-readable reasons, for credentials presented to a relying party.
- **FR-002**: Verification MUST cover **both** EUDI credential formats — **SD-JWT VC** and **ISO/IEC
  18013-5 mdoc** — **delivered together in this feature** (no format phasing).
- **FR-003**: The **always-on** verification bar MUST check, at minimum: the **issuer signature**, issuer
  **membership in the configured trust list** (EU LOTL / national Trusted Lists, ETSI TS 119 612) via a
  **pluggable trust-anchor source**, the **validity period**, **revocation/status**, **holder binding**, and
  **selective-disclosure integrity**.
- **FR-004**: Verification MUST be performable **without any Cleverbase API and without live issuance** —
  using configured trust anchors and the presented credential alone (offline-capable where the standards
  allow).
- **FR-005**: A verification MUST **never false-accept**: a tampered, expired, revoked, wrong-issuer,
  untrusted, or holder-binding-broken credential MUST return INVALID with a specific reason.
- **FR-006**: The SDK MUST **drive the issuance flow (OpenID4VCI)** to obtain an attestation from an
  **EUDI-conformant issuer**, exposing the issuer as a **configurable backend** (so Cleverbase's issuer API,
  when it ships, drops in without reworking the flow).
- **FR-007**: The SDK MUST **drive the presentation flow (OpenID4VP)** so a holder can present a held
  attestation with **selective disclosure** to a verifier, and the produced presentation MUST verify under
  FR-001.
- **FR-008**: The issuance/holding capability MUST be **opt-in and gated**: when no issuer API is
  configured it MUST be **skipped** (reported skipped, never failed), and the verification capability
  (FR-001) MUST remain fully usable and tested without it.
- **FR-009**: The SDK MUST **not be an embedded wallet** and MUST NOT handle sole-control secrets or holder
  private keys in a frontend/browser; credential custody follows the integrator-owns-storage model
  (Principle IV). Holder-binding key handling MUST stay server-side / out of the browser.
- **FR-010**: The SDK MUST cite and conform to the governing standards (Principle II): **OpenID4VCI**,
  **OpenID4VP**, **SD-JWT VC**, **ISO/IEC 18013-5 mdoc**, **ETSI TS 119 612** and **ETSI TS 119 602**
  (Trusted Lists / Lists of Trusted Entities), **ETSI TS 119 615** (qualified-status determination), eIDAS
  (Regulation (EU) 910/2014 as amended by (EU) 2024/1183), and MUST record the targeted versions **and a
  conformance-traceability mapping** (standard → demonstrating task/test).
- **FR-011**: The feature MUST **document the Cleverbase reality** honestly: that Cleverbase exposes no EUDI
  attestation API today (only OIDC identity attributes incl. `com.cleverbase.proof`, and roadmap/pilots),
  and that the issuer backend is the seam through which a future Cleverbase API is integrated.
- **FR-012**: Crypto/protocol logic MUST live in the single Rust core and be exposed through the existing
  binding model (Principle III); no per-language re-implementation. Verification MUST reuse a **pluggable
  validation backend** approach consistent with the AdES stack (Principle V) rather than bespoke trust
  logic where a reference engine suffices.
- **FR-013**: Unit-test coverage MUST remain ≥95% per crate/package (Principle VI); the verification paths
  MUST be covered by tests (incl. the negative paths of FR-005) written test-first against conformant test
  credentials, with produced/obtained attestations checked against an independent reference verifier.
- **FR-014**: An **opt-in eIDAS qualified-status determination** (ETSI TS 119 615) MUST be available in
  addition to the always-on bar (FR-003), determining whether the attestation is a **Qualified** EAA from a
  qualified issuer with the relevant service granted at the relevant time, and reporting that qualification
  status in the verdict. It runs **in addition to — never instead of** — the always-on crypto + trust-list
  bar, and MUST be independently enable-able (the spec-003 always-on-bar + opt-in-gate pattern).
- **FR-015**: As a verifier, the SDK MUST be able to **build the OpenID4VP presentation request** (the
  attribute query + a fresh **nonce** + the **audience** binding) and MUST **verify that the received
  presentation is cryptographically bound to that request** (nonce + audience), so a replayed or
  wrong-audience presentation is rejected (FR-005). Owning both halves makes replay/audience binding correct
  by construction.

### Key Entities

- **Attestation (verifiable credential)**: an issuer-signed set of attributes about a subject, in a
  format (SD-JWT VC or ISO mdoc), with validity, status, and holder-binding metadata.
- **Issuer**: the authority that signs an attestation; trust is anchored via the EU Trusted Lists. A
  **configurable backend** (a future Cleverbase issuer API drops in here).
- **Holder context**: the party that obtains and presents an attestation, with a holder-binding key —
  owned/stored by the integrator, never by an embedded SDK wallet.
- **Verifier / relying party**: consumes a presentation and obtains a VALID/INVALID verdict + disclosed
  attributes.
- **Presentation**: a (possibly selectively-disclosed) submission of a held attestation to a verifier
  (OpenID4VP).
- **Trust-anchor source**: the EU LOTL / national Trusted Lists (or a configured test anchor) used to
  decide issuer trust/qualification status.
- **Verification result**: VALID/INVALID + disclosed attributes + machine-readable reasons + resolved
  trust/qualification status.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A relying-party integrator can verify a presented EUDI attestation (SD-JWT VC and mdoc) and
  get a VALID/INVALID verdict with reasons, using **zero** Cleverbase API calls and **zero** live issuance.
- **SC-002**: **100%** of the negative cases (tampered, expired, revoked, wrong-issuer, untrusted,
  broken-holder-binding, unreachable-status fail-closed) return INVALID with a specific reason — no
  false-accept.
- **SC-003**: The verification suite runs and passes with **no external dependency** (conformant test
  credentials + configured test trust anchors); per-crate/package coverage stays ≥95%.
- **SC-004**: With an EUDI-conformant issuer (reference/test) configured, an integrator can obtain an
  attestation and produce a presentation that the SDK's own verifier accepts; with **no** issuer configured,
  that path is cleanly **skipped** and the verification suite still passes.
- **SC-005**: When a real Cleverbase (or other) issuer API becomes available, enabling it requires
  **only configuration** — no rework of the verification or presentation logic (the issuer-backend seam
  proven by the reference issuer).
- **SC-006**: The feature's documentation states the Cleverbase attestation reality accurately (no EUDI
  issuance API today; OIDC attributes + roadmap), with no overclaim that Cleverbase issues EUDI credentials
  today.
- **SC-007**: With the opt-in qualified-status gate enabled, the verdict correctly distinguishes
  **QUALIFIED** (Q)EAAs (qualified issuer, granted at the relevant time per ETSI TS 119 615) from
  valid-but-not-qualified attestations — **no false "qualified"**; with the gate disabled, the always-on
  crypto + trust-list bar runs unchanged.
- **SC-008**: A replayed or wrong-audience presentation (not bound to the SDK-issued OpenID4VP request's
  nonce + audience) is rejected in **100%** of cases; a correctly-bound presentation verifies.

## Assumptions

- **Verification is Cleverbase-independent and standards-based** — it anchors trust in the EU LOTL /
  national Trusted Lists and verifies any EUDI-conformant issuer's attestation, consistent with the SDK's
  "own the validation stack" mandate (Principle V) and its pluggable validation-backend approach.
- **Issuance is forward-looking and gated** — built against the EUDI standards + Cleverbase's roadmap, with
  the issuer exposed as a configurable backend and the Cleverbase-/issuer-dependent steps skipped when no
  issuer API is configured (the spec-003 live-signing gating pattern). Cleverbase publishing a real EUDI
  attestation API is an **external dependency** for the live issuance path.
- **The three resolved scope decisions** — both formats together (no phasing), the always-on crypto +
  trust-list bar with an opt-in eIDAS qualified-status gate, and the full-verifier (build-request + bound-
  verify) model — are authoritatively recorded in **Clarifications** and carried by FR-002 / FR-003+FR-014 /
  FR-015 respectively; not restated here (D1).
- **The SDK is not a wallet** — it orchestrates issuance/presentation sans-IO and verifies; the integrator
  owns credential storage and the holder-binding key custody; no sole-control secret or holder key is
  handled in the frontend (Principle IV).
- **Today's Cleverbase reality** is identity **attributes** via the OIDC Identification API (incl.
  `com.cleverbase.proof`) — explicitly **not** EUDI verifiable credentials; this feature does not relabel
  those as (Q)EAAs.
- **Trust-list / status reachability** is fail-closed by default for qualified verification (configurable),
  surfaced explicitly rather than silently degraded.

## Dependencies

- The open EUDI standards (OpenID4VCI, OpenID4VP, SD-JWT VC, ISO/IEC 18013-5 mdoc, ETSI TS 119 612, eIDAS
  2024/1183) and conformant **test credentials + test trust anchors** for the verification suite.
- The EU LOTL / national Trusted Lists for production trust anchoring.
- **A real EUDI attestation issuer API** (Cleverbase's, when it ships in the 2026 EUDI rollout window, or
  another conformant issuer) for the **live issuance** path — absent today; the live issuance path is
  gated/skipped until it exists.
- The existing SDK (specs 001–003): the Rust core + binding model + the validation-backend approach this
  feature extends.
</content>
