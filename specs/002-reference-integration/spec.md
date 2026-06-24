# Feature Specification: Reference Integration Services & Container Delivery

**Feature Branch**: `feature/reference-integration` (spec dir: `specs/002-reference-integration/`)

**Created**: 2026-06-23

**Status**: Implemented

**Input**: User description: "specify development of those services, assuming they will run in k8s or in docker. So far in this repo, setup also CI for building images (to ghcr, amd64 and arm64 with native GH runners). Include cred-free fixtures, so it is CI-able/runnable"

## Overview

A runnable **reference integration** for the Cleverbase SDK: a server-side **signing service** that
embeds the backend SDK and a thin **web frontend** that drives a signer through the authorization
redirects. Together they demonstrate — and continuously test — the complete remote-QES signing
journey end to end, packaged as container images deployable to Docker or Kubernetes.

Because real signing depends on Cleverbase credentials obtained through external onboarding, the
integration ships a **credential-free fixtures mode** that completes the entire flow against recorded
upstream response shapes (the same ones the SDK's tests use). This makes the whole stack runnable and
testable in CI today, with a switch to live Cleverbase acceptance requiring **configuration only**.

This feature is developer/integrator-facing: the "users" are the integrating engineer, the CI
pipeline, the signer who completes the browser flow, and a host application that delegates signing.

## Clarifications

### Session 2026-06-24

- Q: How should the credential-free end-to-end signing test (the CI merge gate) drive the flow? → A:
  Drive the backend HTTP API directly (start/complete/status/result), simulating the redirect
  returns — no browser, fast and deterministic.
- Q: Does the ≥95% unit-coverage gate (Constitution Principle VI) apply to the reference-integration
  Go signing service? → A: Yes — the backend signing service is a first-class package held to ≥95%
  unit coverage in CI; the thin web frontend and deployment glue are illustrative and exempt.
- Q: What supply-chain hardening should the published GHCR images carry? → A: A minimal/distroless,
  non-root base, plus cosign signing and an SBOM/provenance attestation.
- Q: How should the credential-free fixtures mode supply the upstream (CSC/OIDC + TSA) responses? → A:
  A mock upstream HTTP server the backend targets via its base-URL config; the backend runs the same
  effect-performing HTTP code as live, so fixtures↔live is a base-URL + credentials change only.
- Q: What form should the Kubernetes deployment artifacts take? → A: Plain, readable manifests with a
  Kustomize overlay selecting fixtures vs live + secrets.
- Q: Should the reference backend's REST API require authentication when deployed? → A: Yes — a
  configurable API key, enabled by default (disable-able for local fixtures runs).

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Complete a signing flow with no credentials (Priority: P1)

An engineer with no Cleverbase access starts the stack and completes a full PAdES B-B signing journey
in the browser — initiate → authorization redirect(s) → signed document — entirely against recorded
fixtures, ending with a signed PDF that an independent validator accepts. No client secret, token, or
real signer is required.

**Why this priority**: This is the MVP. It unblocks development, demos, and CI immediately — before
Cleverbase onboarding completes — and proves the integration wiring (frontend ↔ backend ↔ SDK loop)
that the live mode reuses unchanged. It delivers standalone value: a working, inspectable reference an
integrator can read and run.

**Independent Test**: Bring up the services with the fixtures profile and no credentials configured.
For a manual check, drive the flow from the web UI; for the automated CI gate, drive the **backend
HTTP API directly** (start/complete/status/result, simulating the redirect returns — no browser).
Confirm a signed PDF is produced and passes independent validation, and that no document bytes or
secrets left the backend.

**Acceptance Scenarios**:

1. **Given** the stack running in fixtures mode with no Cleverbase credentials set, **When** a user
   starts a signing session for a PDF and follows the flow to completion, **Then** the backend returns
   a `completed` status and a signed PDF that the independent validator accepts at PAdES B-B.
2. **Given** fixtures mode, **When** the signer "declines" at the authorization step, **Then** the
   session resolves to a `declined` terminal status (distinct from failure), surfaced in the UI.
3. **Given** any run, **When** every outbound request to the (mock) upstream is inspected, **Then**
   only a document hash — never the document bytes, the client secret, a token, or the session handle
   — is present.

---

### User Story 2 - Sign live against Cleverbase acceptance via configuration (Priority: P2)

An integrator supplies Cleverbase acceptance credentials and endpoint configuration (and, for B-T, a
qualified timestamp authority) and the *same* services drive a real signer through the OAuth login and
per-signature (SCAL2) authorization, producing a real signed PDF.

**Why this priority**: This is the end goal, but it is gated on an external dependency (Cleverbase
client registration + a test signer) outside this repository's control. The architecture must make the
transition from fixtures to live a configuration change, never a code change.

**Independent Test**: With acceptance credentials and a registered redirect URI configured, complete a
signing session with a real test signer and obtain a signed PDF; repeat with B-T configured against a
qualified TSA and confirm the timestamp is present and valid.

**Acceptance Scenarios**:

1. **Given** live mode with valid acceptance credentials and a registered redirect URI, **When** a
   test signer completes login and authorizes the hash, **Then** a signed PDF and an evidence record
   are produced and the signer's certificate is reported.
2. **Given** live mode with a qualified TSA configured and conformance level B-T, **When** signing
   completes, **Then** the signed PDF carries a valid timestamp bound to the signature.
3. **Given** the deployment is switched from fixtures to live, **When** the change is applied, **Then**
   only configuration/secrets differ — the service and frontend artifacts are identical.

---

### User Story 3 - Build and publish deployable multi-architecture images (Priority: P3)

On changes to the default branch and on tagged releases, the CI pipeline builds container images for
the signing service and the web frontend for both `linux/amd64` and `linux/arm64`, and publishes them
to the GitHub Container Registry (GHCR), so they can be deployed to Docker or Kubernetes on either
architecture.

**Why this priority**: Packaging and publishing enables real deployment, but it is downstream of having
runnable, tested services (US1). It is independently valuable to platform/ops consumers.

**Independent Test**: Trigger the image workflow; confirm amd64 and arm64 images for both services are
pushed to GHCR with the expected tags, and that each image starts and passes a health check on its
native architecture.

**Acceptance Scenarios**:

1. **Given** a push to the default branch, **When** the image workflow runs, **Then** multi-arch
   (amd64 + arm64) images for both services are published to GHCR, tagged by commit and branch.
2. **Given** a tagged release, **When** the image workflow runs, **Then** images are additionally
   tagged with the release version and a multi-arch manifest list is published.
3. **Given** a published image, **When** it is run on amd64 and on arm64, **Then** it starts and its
   readiness/health endpoint reports healthy on each architecture.

---

### Edge Cases

- **Signer declines or authorization expires** → the session reaches a distinct terminal status
  (`declined` vs expired/`failed`), surfaced to the UI and never reported as `completed`.
- **Expected signer ≠ authorizing signer** (when identity binding is enabled) → the session fails with
  an identity-mismatch outcome and no signature is produced.
- **Browser returns to the redirect URI with an OAuth error instead of a code** → it is forwarded to
  the backend and resolved to the correct terminal status.
- **A session is abandoned mid-flow** → its server-side state expires and is reclaimed without leaking
  secrets; a stale correlation id reports a terminal/expired status, not a hang.
- **The backend restarts mid-session** → behavior is defined by the chosen session store (the in-memory
  default loses in-flight sessions; acceptable for the reference default and documented).
- **An already-signed PDF is submitted** → rejected with a clear invalid-document outcome (Phase-1 SDK
  behavior), surfaced in the UI.
- **Live mode selected but required configuration missing** → the service fails fast at startup with a
  clear error rather than starting half-configured.
- **Image build for one architecture fails** → no partial/misleading multi-arch manifest is published;
  the failure is visible and blocks the affected tag.
- **A backend API request arrives without a valid API key** (when auth is enabled) → it is rejected
  with 401 before any signing work, and no session is created.

## Requirements *(mandatory)*

### Functional Requirements

**Signing service (backend)**

- **FR-001**: The system MUST provide a backend signing service that uses the Cleverbase backend SDK to
  run the sans-IO `begin`/`resume` state machine and performs, on the SDK's behalf, the HTTP requests
  and browser-redirect issuance the SDK emits as effects.
- **FR-002**: The backend MUST expose the integration contract the frontend helper expects: start a
  session (returns an authorization redirect URL + a correlation id), complete a returned redirect
  (accepting either an authorization code or an OAuth error), and report session status by correlation
  id; and MUST additionally make the finished signed document retrievable by correlation id.
- **FR-003**: The backend MUST keep all secrets and sensitive material — client secret, tokens, and the
  session handle — server-side, and MUST NEVER expose them to the frontend or any client-bound response.
- **FR-004**: The document to be signed MUST remain within the integration's own infrastructure; only a
  document hash may be sent upstream to the trust service.
- **FR-005**: The backend MUST maintain per-session state keyed by a correlation id (and map the OAuth
  `state` value to it) for the duration of a multi-redirect flow, with a default store that requires no
  external dependency and a documented option to plug in a shared/persistent store. Sessions MUST
  expire after a configurable TTL (**default 15 minutes**); an expired session resolves to a terminal
  status and is reclaimed.
- **FR-006**: The backend MUST be configured entirely through environment/configuration (trust-service
  environment, API generation, client credentials, redirect URI, optional TSA, and run mode), with no
  secrets baked into images or source.
- **FR-007**: The backend MUST expose liveness and readiness endpoints suitable for container
  orchestration.
- **FR-008**: The backend MUST emit structured logs of the effect loop (each upstream request/result and
  each state transition) with secrets redacted, sufficient to diff fixtures-mode behavior against live.
- **FR-009**: The backend MUST surface terminal outcomes distinctly — matching the SDK's
  `SigningOutcome` set: `completed`, `declined`, and the seven failure reasons (snake_case, as the
  Rust core serializes them) `authorization_expired`, `credential_unavailable`, `identity_mismatch`,
  `invalid_document`, `timestamp_failed`, `appearance_placement_error`, `signature_invalid` — so the
  frontend can reflect them accurately. The complete authoritative `failed` `reason` set (these seven
  SDK codes plus the service-operational codes `upstream_error`, `resume_error`, `session_expired`,
  and the defensive catch-all `unknown`) is defined in
  `contracts/reference-service-api.md`, the authoritative API definition.
- **FR-025**: The backend REST API MUST support a **configurable API key** (env-supplied bearer/key),
  **enabled by default** so a deployed image is not an open signing-initiation endpoint; it MAY be
  disabled for local fixtures runs. Requests without a valid key MUST be rejected (401) before any
  signing work begins.

**Web frontend**

- **FR-010**: The system MUST provide a web frontend that uses the no-crypto frontend helper to start a
  session, send the signer through the authorization redirect(s), reflect status, and deliver the
  completed signed document for download.
- **FR-011**: The frontend MUST perform no cryptography and MUST handle no secrets, tokens, private keys,
  or session handles — only opaque correlation ids, redirect URLs, and the OAuth `code`/`state`.
- **FR-012**: The registered redirect-return location MUST be served by the frontend, which forwards the
  returned `code`+`state` (or OAuth `error`+`state`) to the backend to advance the flow.

**Credential-free fixtures mode**

- **FR-013**: The system MUST provide a credential-free "fixtures" run mode that completes the entire
  signing journey using recorded upstream response shapes served by a **mock upstream HTTP server** the
  backend targets via base-URL configuration, producing a signed document that passes independent
  validation, with no Cleverbase credentials and no real signer required.
- **FR-014**: In fixtures mode the backend MUST run the **same effect-performing HTTP path** (against
  the mock upstream) and the same `begin`/`resume` loop and frontend flow as live mode, so switching to
  live is a **base-URL + credentials configuration change only** (no code change). Selecting fixtures vs
  live MUST be a single configuration choice.
- **FR-015**: The fixtures data MUST derive from a single authoritative source — language-neutral
  upstream response shapes under `tests/fixtures/upstream/` (extracted once from the SDK's tests so the
  Rust tests and the Go mock both read the same file) plus the synthetic PKI under `tests/fixtures/pki/`.
  The Go mock MUST NOT hand-author a parallel/divergent copy of the upstream shapes (Constitution VIII).

**Containerization & deployment**

- **FR-016**: Both services MUST be runnable as container images that start from configuration alone (no
  interactive setup), suitable for Docker and Kubernetes.
- **FR-017**: The repository MUST provide a local one-command bring-up (e.g. a compose definition) that
  runs the full stack in fixtures mode, including any mock upstream and a timestamp authority needed to
  exercise B-T locally.
- **FR-018**: The repository MUST provide **plain, readable Kubernetes manifests with a Kustomize
  overlay** that selects the fixtures vs live configuration and supplies secrets, for both services.

**Continuous integration**

- **FR-019**: CI MUST build container images for both services for `linux/amd64` and `linux/arm64`,
  using native GitHub-hosted runners per architecture (not emulation), and publish them to GHCR.
- **FR-020**: Published images MUST be tagged by commit SHA and branch on default-branch pushes, and
  additionally by release version with a combined multi-architecture manifest on tagged releases.
- **FR-021**: CI MUST run the credential-free end-to-end signing flow as an automated test that produces
  and independently validates a signed document, and this test MUST gate merges (it runs without any
  Cleverbase credentials or secrets). The automated test drives the **backend HTTP API directly**
  (simulating the redirect returns); it MUST NOT require a browser.
- **FR-022**: Image build/publish steps MUST use least-privilege registry credentials and MUST NOT
  require or expose any Cleverbase or signing secrets.
- **FR-023**: Published images MUST be built from a **minimal/distroless, non-root** base, be
  cryptographically **signed** (e.g. cosign), and carry a retrievable **SBOM/provenance attestation**.

**Quality gate**

- **FR-024**: The reference-integration **backend signing service** MUST carry unit tests with **≥95%
  line coverage**, enforced in CI per Constitution Principle VI. The thin web frontend and deployment
  glue are illustrative and exempt from the unit-coverage floor (they are covered by the end-to-end
  test); this exemption MUST NOT reduce the service's own coverage obligation.

### Key Entities *(include if feature involves data)*

- **Signing service**: the backend that owns the SDK loop, secrets, upstream I/O, and session state.
- **Web frontend**: the no-crypto browser app that orchestrates redirects and reflects status.
- **Run mode / profile**: the configuration selecting fixtures vs live behavior plus endpoint/credential settings.
- **Fixtures dataset**: the recorded upstream (CSC/OIDC + timestamp) response shapes driving credential-free runs, sourced from the SDK's authoritative fixtures.
- **Signing session**: server-side state for one signing journey, addressed by a correlation id, carrying status and (on success) the signed document.
- **Signed document result**: the produced signed PDF plus its evidence record.
- **Container image**: a published, runnable artifact for a service, per architecture, in GHCR.
- **Mock upstream service**: the stub HTTP service that serves the fixtures dataset in credential-free
  mode, standing in for Cleverbase CSC/OIDC and the TSA at a configurable base URL.
- **Deployment artifact**: the Docker Compose definition (local/CI) and the Kubernetes manifests +
  Kustomize overlays that run the services.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A developer with no Cleverbase credentials can bring up the full stack with a single
  command and complete a signing flow yielding an independently-validated signed PDF in under 10
  minutes of **warm run time** (after the first cold build of the Rust staticlib + images, which is
  not counted toward the 10 minutes).
- **SC-002**: The credential-free end-to-end flow runs in CI on every change and must pass for a change
  to merge (0 credentials required).
- **SC-003**: Switching a running deployment from fixtures to live signing requires only configuration
  and secret changes — zero changes to service or frontend artifacts.
- **SC-004**: No secret, token, private key, or session handle ever appears in any frontend-bound or
  browser-observable payload, verified by an automated check over all outbound frontend traffic.
- **SC-005**: On every default-branch change, runnable images for the signing service, the web frontend,
  and the fixtures mock upstream are published to GHCR for both amd64 and arm64, and each image passes a
  start-and-health check on its native architecture.
- **SC-006**: A tagged release publishes version-tagged images with a single multi-architecture manifest
  that resolves correctly on amd64 and arm64 hosts.
- **SC-007**: The only blocker to performing a *live* signature is the externally-provided Cleverbase
  credentials/test-signer (and, for B-T, a qualified TSA) — no additional engineering is required in this
  repository.
- **SC-008**: The reference backend service sustains **≥95% unit-test line coverage**, enforced as a CI
  gate; a change dropping it below 95% does not merge.
- **SC-009**: Every published image is **signed** and carries a retrievable **SBOM/provenance**
  attestation; an independent consumer can verify the signature and read the SBOM.

## Assumptions

- **In-repo deliverable**: these services live in this SDK repository (a reference-integration area), not
  a separate repository — per the request to set this up "in this repo".
- **Backend language/binding**: the signing service is implemented in **Go**, embedding the SDK via the
  existing Go binding (preferred per the request); an explicit input, not an open choice.
- **Registry & runners**: images are published to **GHCR** under this repository's organization, with
  multi-arch builds on **native GitHub-hosted amd64 and arm64 runners** (explicit inputs).
- **Frontend scope**: the web frontend is a thin reference UI built on the existing no-crypto frontend
  helper; illustrative, not a production end-user product, and may be minimal.
- **Deployment targets**: both Docker Compose (local/CI) and Kubernetes manifests are provided; a service
  mesh, ingress controller, and cluster provisioning are out of scope (manifests assume a generic cluster).
- **Session store default**: an in-memory per-instance store is the default (single-replica reference
  deployment); a shared/persistent store is a documented extension point, not built here.
- **Fixtures source**: credential-free fixtures reuse the SDK's existing recorded upstream response shapes
  and synthetic test PKI; the local timestamp authority for B-T reuses the SDK tests' approach.
- **Independent validation**: signed output is validated with the independent validator already wired in
  the SDK (OpenSSL); deeper conformance (EU DSS / veraPDF) remains the SDK's documented later layer and is
  not required for this feature's CI gate.
- **External dependency for live mode**: Cleverbase acceptance client registration, a test signer +
  authorizer, and a qualified TSA for B-T are provided externally and are prerequisites for US2 only; US1
  and US3 do not depend on them.
- **No multi-tenancy / durability guarantees**: the reference service is single-tenant and stateless
  beyond in-flight sessions; durable storage, multi-tenant routing, and HA are out of scope.
