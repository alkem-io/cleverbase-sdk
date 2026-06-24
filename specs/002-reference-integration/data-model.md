# Phase 1 Data Model: Reference Integration Services

Language-neutral data shapes for the reference integration. The cryptographic/protocol state is
owned by the SDK's opaque **session handle**; the service holds only the orchestration envelope
around it. Nothing here re-models the SDK's internal types.

## Entities

### SigningSession (backend, in-memory)

The service-side envelope for one signing journey, addressed by `correlation_id`.

| Field | Type | Notes |
|-------|------|-------|
| `correlation_id` | string (opaque) | Public id returned to the frontend; primary key. Wire/JSON field name is `correlationId` (camelCase) — same identifier. |
| `oauth_state` | string | Current pending OAuth `state` (CSRF); secondary index → `correlation_id`. Re-written on each of the **two sequential** redirects (service-auth, then credential-auth/SCAL2); only one pending state exists at a time, and the index MUST be updated when the second redirect is issued. |
| `sdk_handle` | bytes (opaque CBOR) | The SDK session handle. **Sensitive** — never leaves the backend. |
| `status` | `SessionStatus` | Frontend-facing status (see enum). |
| `outcome` | `SigningOutcome` \| null | Terminal SDK outcome once reached. |
| `conformance_level` | `"B-B"` \| `"B-T"` | From the start request. |
| `result_pdf` | bytes \| null | Signed PDF, present only on success. **Sensitive** (the document). |
| `evidence` | object \| null | The SDK evidence record on terminal. |
| `created_at` / `expires_at` | timestamp | TTL eviction; `expires_at` enforces session lifetime. |

**Validation / rules**:
- `sdk_handle`, `result_pdf`, and any token/secret MUST NOT be serialized into any client-bound
  response (only `correlation_id`, `status`, and — on `result` fetch — the signed PDF bytes).
- A session is created only after the API key check passes (when auth is enabled).
- On any terminal status the SDK handle is already scrubbed by the core; the service additionally
  drops `sdk_handle` and retains only `result_pdf`/`evidence` until the result is fetched or TTL.

### SessionStatus (frontend-facing enum)

Mirrors the frontend helper's `SignStatus` so the UI maps 1:1.

`pending` · `authorizing` · `completed` · `declined` · `failed`

Mapping from SDK `Step`/`SigningOutcome` → `SessionStatus`:

| SDK signal | SessionStatus |
|------------|---------------|
| `Redirect` emitted (service or credential auth) | `authorizing` |
| `PerformHttp` in progress (token/list/info/signHash/TSA) | `pending` |
| `Done` / outcome `Signed` | `completed` |
| outcome `Declined` | `declined` |
| outcome `AuthorizationExpired` | `failed` + `reason: authorization_expired` |
| outcome `IdentityMismatch` | `failed` + `reason: identity_mismatch` |
| outcome `InvalidDocument` | `failed` + `reason: invalid_document` |
| outcome `TimestampFailed` | `failed` + `reason: timestamp_failed` |
| outcome `SignatureInvalid` | `failed` + `reason: signature_invalid` |
| outcome `CredentialUnavailable` | `failed` + `reason: credential_unavailable` |
| outcome `AppearancePlacementError` | `failed` + `reason: appearance_placement_error` |

Each `failed` session carries a `reason` code (the snake_case SDK outcome name above), so all **nine**
SDK terminal outcomes (`completed`, `declined`, and the **seven** `failed` reasons) remain
distinguishable to the frontend, mirroring the SDK's `SigningOutcome` set (single source). `reason` is
emitted **only** for `failed` (never for `declined`/`completed`/in-progress statuses).

Beyond the SDK outcomes, the service maps its own operational failures to three additional `failed`
reason codes — `upstream_error` (an upstream call failed), `resume_error` (the SDK could not advance),
and `session_expired` (the TTL elapsed before completion). The `status`/`complete` endpoints and the
API contract enumerate exactly this set (seven SDK + three operational).

### RunProfile (configuration)

Selects fixtures vs live and carries endpoint/credential settings (12-factor env).

| Field | Env | Notes |
|-------|-----|-------|
| `mode` | `REFSVC_MODE` | `fixtures` \| `live`. |
| `base_url` | `REFSVC_BASE_URL` | Upstream base (mock URL in fixtures; Cleverbase host in live). |
| `environment` / `csc_api` | `REFSVC_ENV` / `REFSVC_CSC_API` | `acceptance`/`production`; `v1_rsa`/`v2_ecdsa`. |
| `default_conformance` | `REFSVC_DEFAULT_CONFORMANCE` | Default PAdES level (`B-B`) used when a `start` request omits `conformanceLevel`; the **per-request** `conformanceLevel` (API contract) overrides it. |
| `client_id` / `client_secret` | `REFSVC_CLIENT_ID` / `REFSVC_CLIENT_SECRET` | **Secret**; required in live, unused in fixtures. |
| `redirect_uri` | `REFSVC_REDIRECT_URI` | Registered frontend return URL. |
| `tsa_url` / `tsa_auth` / `tsa_policy` | `REFSVC_TSA_*` | Required for B-T live; mock TSA in fixtures. |
| `api_key` | `REFSVC_API_KEY` | Backend API key; auth on unless explicitly disabled for local. |
| `session_ttl` | `REFSVC_SESSION_TTL` | Session lifetime (**default 15m**); an expired session resolves to a terminal status and is reclaimed. |

**Rules**: in `live` mode, missing `client_id`/`client_secret`/`redirect_uri` (or `tsa_*` when B-T) →
**fail fast at startup**. In `fixtures` mode no Cleverbase secret is required.

### MockUpstream fixtures (credential-free)

The recorded upstream response shapes the mock serves, sourced from the SDK's authoritative fixtures.

| Item | Source |
|------|--------|
| Synthetic CA / signer cert + key (RSA, EC) | `tests/fixtures/pki/` (the SDK's). |
| OAuth `token`, `credentials/list`, `credentials/info` response **shapes** | `tests/fixtures/upstream/*.json` — language-neutral fixtures **extracted from** the SDK's `independent_validation`/signing tests so Rust + the Go mock read one source (FR-015). |
| `signHash` signing | Computed live by the mock using the synthetic fixture private key (so output validates). |
| TSA token | Issued by a local RFC 3161 TSA (OpenSSL-based, as in the SDK tests). |

### Published image (delivery)

| Field | Notes |
|-------|-------|
| `repository` | `ghcr.io/<org>/cleverbase-refsvc`, `…/cleverbase-refweb`, and `…/cleverbase-refmock`. |
| `platforms` | `linux/amd64`, `linux/arm64` (manifest list). |
| `tags` | `sha-<short>` + branch on main; semver + `latest` on release. |
| `signature` | cosign keyless (OIDC) over each digest. |
| `sbom` | SPDX attestation attached via cosign. |

## SigningSession lifecycle (state transitions)

```text
                 start(API key ok)
   (none) ───────────────────────────▶ authorizing  (service-auth redirect issued)
                                            │ complete(code,state)
                                            ▼
                                         pending      (token → list → info HTTP effects)
                                            │ credential-auth redirect issued
                                            ▼
                                         authorizing  (SCAL2 hash authorization)
                                            │ complete(code,state)
                                            ▼
                                         pending      (SAD → signHash → CMS → [B-T: TSA])
                                            ▼
                 ┌───────────────────────────┼───────────────────────────┐
                 ▼                            ▼                           ▼
             completed                    declined                    failed
        (result_pdf ready)        (signer access_denied)     (expired/mismatch/invalid/…)

  Any state ── TTL expiry ──▶ failed (expired), session reclaimed, secrets dropped.
  complete(error,state) at an authorizing state ──▶ declined | failed (per OAuth error).
```

- Transitions are driven entirely by SDK `resume(...)` results; the service never decides protocol
  outcomes, only maps them to `SessionStatus` and performs the emitted I/O.
- `complete` is rejected (409/400) if the session is already terminal or the `state` does not match a
  pending session (CSRF) — the SDK also enforces `state`, this is defense-in-depth at the edge.
