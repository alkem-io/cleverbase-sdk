# Feature Specification: Remote Qualified Signing (PAdES B-B / B-T)

**Feature Branch**: `001-remote-qes-signing`
<!-- Spec directory is independent of git branch; the git branch hook is not installed, so no branch was created. -->

**Created**: 2026-06-22

**Status**: Draft

**Input**: User description: "for the Phase 1 signing slice"

This is the first delivered slice of the Cleverbase SDK: enabling an application to obtain a
**Qualified Electronic Signature (QES)** on a PDF document, where a human signer authorizes the
signature from their Cleverbase wallet, and the resulting signed PDF reaches PAdES conformance
**B-B** and **B-T** (timestamped). Higher conformance levels (B-LT, B-LTA), non-PDF signature
formats, identification/authentication, and attestation are explicitly out of scope for this
feature (see Assumptions).

## Clarifications

### Session 2026-06-22

- Q: Who owns in-flight signing-session state across the authorization round-trip? → A: Stateless
  SDK — it returns a serializable session handle the integrator persists and supplies to finalize;
  the SDK stores no session state.
- Q: Should the SDK bind a request to an expected signer and verify the authorizing person matches?
  → A: Yes — verify the authorizing signer's qualified certificate against an expected identity
  before signing; on by default, relaxable per request; a mismatch fails the operation.
- Q: Should the SDK emit a structured per-operation evidence/audit record? → A: Yes — return a
  signing-evidence record (document hash, signer identity, conformance level, signing time,
  outcome) on success and failure; the SDK does not store it.
- Q: Visible signature appearance + metadata in Phase 1, or invisible only? → A: Optional —
  invisible by default; the integrator may request, per signature, a visible signature block
  (page/position, reason, location, signer name, signing time).
- Q: Preserve PDF/A conformance when the input is PDF/A? → A: Yes — when the input is PDF/A, the
  signed output remains PDF/A-valid (including embedded fonts for any visible appearance);
  non-PDF/A inputs produce a standard signed PDF. (Phase 1 status: PDF/A is detected and reported
  best-effort for invisible signatures; embedded-font visible appearances and veraPDF verification
  are deferred — see `docs/limitations.md`.)

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Sign a PDF with a qualified signature (Priority: P1) 🎯 MVP

An integrating application has a PDF that a specific person must sign with legal effect. Through
the SDK, the application initiates a signing request for that document; the signer is prompted to
authorize the signature in their Cleverbase wallet (scanning a code and approving with their PIN);
once the signer approves exactly the content being signed, the application receives the same PDF
with a valid qualified electronic signature embedded (PAdES B-B). The original document never
leaves the application's own infrastructure — only a cryptographic hash is shared with the trust
service.

**Why this priority**: This is the core value of the entire SDK and a complete, demonstrable
unit on its own. Without it, nothing else in the signing domain has value.

**Independent Test**: Submit a sample PDF and a signer reference; complete the signer
authorization against the trust service's test environment; confirm the returned PDF embeds a
signature that an independent reference validator recognizes as a valid qualified electronic
signature at PAdES level B-B.

**Acceptance Scenarios**:

1. **Given** a valid PDF and an enrolled signer, **When** the application requests a signature and
   the signer authorizes it in their wallet, **Then** the application receives a signed PDF whose
   signature validates as a qualified electronic signature (PAdES B-B).
2. **Given** a signing request, **When** the signer is asked to authorize, **Then** what the signer
   approves is cryptographically bound to the exact content that will be signed (the signer cannot
   be tricked into approving different content).
3. **Given** a signing request, **When** the signature is produced, **Then** the document content
   itself was never transmitted to the trust service (only its hash).
4. **Given** a signer who declines or lets the authorization expire, **When** the application polls
   or awaits the result, **Then** the application receives a clear, non-secret outcome indicating
   the signature was not completed and why.

---

### User Story 2 - Trusted timestamp on the signature (Priority: P2)

The integrating application needs the signing time to be independently provable, so the signature
must carry a trusted timestamp from a qualified Time-Stamping Authority. Building on User Story 1,
the application requests conformance level B-T; the produced signed PDF additionally embeds a
trusted timestamp token, establishing when the signature existed even after the fact.

**Why this priority**: Required to complete the Phase 1 commitment (B-B + B-T) and a prerequisite
for later long-term-validation levels, but it layers on top of the working B-B signature, so it is
sequenced after the MVP.

**Independent Test**: Produce a B-T signature; confirm an independent reference validator reports a
valid signature timestamp and a provable signing time at PAdES level B-T.

**Acceptance Scenarios**:

1. **Given** a configured qualified Time-Stamping Authority, **When** the application requests a B-T
   signature, **Then** the resulting signed PDF embeds a valid trusted timestamp and validates at
   PAdES level B-T.
2. **Given** the timestamp authority is unreachable or rejects the request, **When** a B-T signature
   is requested, **Then** the operation fails with a clear outcome and does NOT silently downgrade to
   B-B (the requested conformance level is honored or the request fails).

---

### User Story 3 - Drive the signer through authorization from a web app (Priority: P3)

An integrating web application wants to move the signer through the wallet-authorization step
without its frontend ever touching secrets or cryptography. Using a thin frontend helper, the web
app starts the signing flow on its backend, sends the signer's browser to the trust service's
authorization step, and reflects progress/status back to the user — while all secrets and signing
operations remain on the backend.

**Why this priority**: It improves integration ergonomics (and powers the demos), but the signing
capability is fully usable without it via the backend alone, so it is the lowest priority of the
three.

**Independent Test**: Using the frontend helper in a sample web app, a signer is taken from "start
signing" through wallet authorization and back to a completed/failed status, with verification that
the frontend transmitted no secrets and performed no cryptographic operations.

**Acceptance Scenarios**:

1. **Given** a backend-initiated signing request, **When** the frontend helper orchestrates the
   redirect to authorization and the return, **Then** the signer reaches the wallet authorization
   step and the application reflects the final status.
2. **Given** any frontend interaction, **When** network traffic is inspected, **Then** no client
   secret, signing token, or private key is present and no signing/cryptography happens in the
   browser.

---

### Edge Cases

- **Signer declines** in the wallet, or never responds → the request resolves to a clear "not
  signed" outcome that distinguishes decline from timeout.
- **Authorization expires** (the time-limited consent lapses) before signing completes → clear,
  retryable failure; no partial/invalid signature is produced.
- **Signer has no active signing credential** (no usable qualified certificate) → clear outcome
  surfaced to the integrator before signing is attempted.
- **Document changes** between initiation and signing → the content-bound authorization no longer
  matches and signing is refused (integrity protected).
- **Timestamp authority unavailable** during a B-T request → fail clearly without downgrading the
  requested conformance level.
- **Transient network/session failures** mid-flow → recoverable with clear status; never emit a
  malformed or partially-signed PDF.
- **Signer credential type varies** (different signing-credential generations exist) → signing
  succeeds regardless of the signer's credential type, producing an equivalently valid signature.
- **Already-signed PDF** is submitted for an additional signature → the new signature is added
  without invalidating existing valid signatures. (Phase 1 status: an already-signed input is
  rejected with `InvalidDocument`; multi-signature via incremental update — FR-010 — is deferred,
  see `docs/limitations.md`. This avoids ever corrupting an existing signature.)
- **Authorizing signer ≠ expected signer** (when identity binding is enabled) → the operation is
  refused with a distinct identity-mismatch outcome and no signature is produced.
- **Backend restarts after authorization** but before finalization → the signature is completed
  from the persisted session handle without re-prompting the signer, provided the authorization has
  not expired.
- **Visible appearance requested at an invalid page/position** → the operation fails with a clear
  placement error and produces no malformed PDF.
- **PDF/A input** → the signed output is verified to remain PDF/A-conformant; if the requested
  signature or appearance cannot be applied without breaking PDF/A conformance, the operation fails
  clearly rather than emitting a non-conformant file.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The system MUST allow an integrating application to request a qualified electronic
  signature over a PDF document the application supplies.
- **FR-002**: The system MUST keep the document content within the integrator's infrastructure,
  transmitting only a cryptographic hash of the to-be-signed content to the trust service.
- **FR-003**: The system MUST route the signer to authorize the signature in their Cleverbase
  wallet and MUST bind that authorization to the exact content being signed.
- **FR-004**: On successful authorization, the system MUST embed the resulting signature into the
  PDF and produce a signed PDF that validates as a qualified electronic signature at PAdES
  conformance level **B-B**.
- **FR-005**: The system MUST support producing PAdES conformance level **B-T** by incorporating a
  trusted timestamp from a configurable qualified Time-Stamping Authority, and MUST NOT silently
  downgrade a requested level.
- **FR-006**: The system MUST produce signatures correctly regardless of which signing-credential
  generation the signer holds (it MUST handle the differing signature algorithms in use).
- **FR-007**: The system MUST present clear, actionable, secret-free outcomes for all failure
  conditions, distinguishing at least: signer decline, authorization timeout/expiry, no active
  signing credential, and timestamp-authority failure.
- **FR-008**: The system MUST keep all credentials and signing-authorization secrets server-side;
  the optional frontend helper MUST handle no secrets and perform no cryptographic operations.
- **FR-009**: The system MUST be operable against both the trust service's test/acceptance
  environment and its production environment via configuration, without code changes.
- **FR-010**: The system MUST add a new signature to a PDF without invalidating pre-existing valid
  signatures in that PDF.
- **FR-011**: Signatures produced by the system MUST be verifiable by independent reference
  validators (this is a delivery condition, exercised by the test suite).
- **FR-012**: The signing capability MUST be available to integrating applications in **Go**,
  **TypeScript/Node**, and **Python**, exposed idiomatically in each, and MUST produce
  equivalently valid signed output across all three. **All three bindings are delivered within
  this feature (Phase 1)**, each complete; the build order may prove the core plus one reference
  binding end-to-end before fanning out, but the shipped feature includes all three.
- **FR-013**: The SDK MUST be stateless for in-flight signing sessions: it MUST return
  a serializable session handle that the integrator persists and supplies to finalize the
  signature, and MUST NOT itself persist signing-session state. A signature MUST be completable
  after a backend restart using only the persisted handle and without re-prompting the signer,
  while the signer's authorization remains valid.
- **FR-014**: The SDK MUST support binding a signing request to an expected signer identity and
  MUST verify the authorizing signer's qualified certificate against it before producing the
  signature. Verification MUST be enabled by default and relaxable per request; a mismatch MUST
  fail the operation with a distinct outcome and MUST NOT produce a signature.
- **FR-015**: The SDK MUST return a structured signing-evidence record for every signing attempt —
  on both success and failure — containing at least the document hash, the signer identity, the
  requested conformance level, the signing time, and the outcome. The SDK MUST NOT persist this
  record itself.
- **FR-016**: The SDK MUST produce an invisible signature by default and MUST allow the integrator
  to request, per signature, a visible signature appearance plus signature metadata (page and
  position, reason, location, signer name, signing time). When requested, the visible appearance
  MUST be embedded in the signed PDF without invalidating the signature.
- **FR-017**: When the input document is PDF/A-conformant, the signed output MUST remain PDF/A-valid
  (the signature and any visible appearance MUST NOT break PDF/A conformance, including embedding
  required fonts); for non-PDF/A inputs the SDK produces a standard signed PDF.
- **FR-018**: The SDK MUST expose a stateless integrity-only verifier for an arbitrary singly-signed
  PDF. It MUST strictly bind `/ByteRange` to `/Contents`, verify the detached CMS signature and
  signed message digest with the embedded signer certificate, report B-B/B-T structure and signer
  identity, and return invalid input as a typed verdict. It MUST NOT claim certificate-chain trust,
  revocation status, or RFC 3161 token validity when those checks were not performed.

### Key Entities

- **Signing Request**: An application's intent to sign a specific document for a specific signer at
  a requested conformance level (B-B or B-T), with optional **expected signer identity**, optional
  **visible appearance**, and optional **signature metadata** (reason, location).
- **Signer**: The natural person who authorizes the signature; holds a qualified signing credential
  accessed through their Cleverbase wallet.
- **Signing Credential**: The signer's qualified certificate/key used to create the signature.
- **Signature Authorization**: The signer's content-bound, time-limited consent that activates the
  signature.
- **Signed Document**: The resulting PDF with an embedded signature at a specific PAdES conformance
  level.
- **Trusted Timestamp**: A timestamp token from a qualified Time-Stamping Authority, required for
  conformance level B-T.
- **Trust Service Configuration** (canonical name `TrustServiceConfiguration`): The environment and
  client identity the integrator uses to reach the trust service (acceptance vs production).
- **Signing Session Handle**: A serializable representation of an in-flight signing session,
  persisted by the integrator and supplied to finalize the signature; the SDK holds no server-side
  session state.
- **Expected Signer Identity**: The identity an integrator optionally binds a request to; the SDK
  verifies the authorizing signer's certificate against it (on by default), matched on the
  certificate subject **serial number** by default (a stable Cleverbase subject identifier is an
  alternative).
- **Signing Evidence Record**: A structured per-operation record (document hash, signer identity,
  conformance level, signing time, outcome) returned for both success and failure; stored by the
  integrator.
- **Signature Appearance**: Optional per-request visual signature block and metadata (page and
  position, reason, location, signer name, signing time) rendered into the signed PDF; omitted for
  invisible signatures.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: An integrating application can take a PDF from signing request to a signed PDF in a
  single signer authorization session.
- **SC-002**: 100% of B-B signatures produced by the SDK are recognized as valid qualified
  electronic signatures by an independent reference validator.
- **SC-003**: 100% of B-T signatures produced by the SDK additionally show a valid trusted
  timestamp and a provable signing time in an independent reference validator.
- **SC-004**: The signing capability yields equivalently valid signed output when invoked from each
  supported language, verified by the same reference validator.
- **SC-005**: In 100% of signing operations, the document content is never transmitted off the
  integrator's infrastructure (only its hash is), verifiable by inspecting outbound traffic.
- **SC-006**: Every defined failure condition (decline, expiry/timeout, no credential, timestamp
  failure) yields a distinct, actionable outcome with no secret material exposed.
- **SC-007**: A developer can obtain their first qualified signature against the test environment
  using the provided example within 30 minutes of starting.
- **SC-008**: When signer-identity binding is enabled, signatures are produced only when the
  authorizing signer's certificate matches the expected identity; 100% of mismatches are refused
  with no signature produced.
- **SC-009**: A signing operation interrupted by a backend restart after authorization can be
  completed from persisted state without re-prompting the signer, while the authorization is valid.
- **SC-010**: Every signing attempt (success or failure) yields an evidence record containing the
  document hash, signer identity, conformance level, signing time, and outcome.
- **SC-011**: When a visible appearance is requested, the signed PDF shows the requested signature
  block and metadata at the specified page/position and still validates at the requested
  conformance level; when not requested, the signature is invisible and equally valid.
- **SC-012**: 100% of PDF/A inputs produce signed output that still validates as PDF/A-conformant in
  an independent checker; non-PDF/A inputs produce a standard signed PDF.

## Assumptions

- Integrators have, or will separately obtain, a Cleverbase client registration (onboarding is
  sales-led and out of scope), and signers have an enrolled Cleverbase wallet.
- A qualified Time-Stamping Authority will be contracted and configured for B-T; the trust service
  itself does not provide timestamping, so this is an external delivery dependency.
- Phase 1 targets **PDF documents (PAdES)** only. Other signature formats (CAdES/XAdES/JAdES) are
  out of scope for this feature.
- Conformance levels **above B-T** (B-LT, B-LTA / long-term validation) are out of scope for this
  feature and are planned as a later phase; the design must not preclude them.
- **Identification**, **authentication**, and **attestation/EUDI** are separate features, not part
  of this slice.
- A runtime signature-**validation** service is out of scope for Phase 1; independent validation is
  used only to verify the SDK's output during testing.
- Signing is a backend capability; the signer authorizes in Cleverbase's own wallet app, and the
  SDK does not embed a wallet.
- Single-document signing is the Phase 1 default; batch/multi-document signing in one authorization
  is out of scope for this feature.
