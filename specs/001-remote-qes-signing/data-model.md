# Data Model: Remote Qualified Signing (PAdES B-B / B-T)

Conceptual model for the sans-IO core. Field types are language-neutral; bindings map them to native
types (and CBOR over the C-ABI/WASM boundary). Nothing here is persisted by the SDK — the integrator
persists only the **Signing Session Handle**.

## Entities

### SigningRequest (input)
The integrator's intent to sign.
- `document`: bytes — the PDF to sign (stays in the integrator's infra; only its hash leaves).
- `conformance_level`: enum `{ B_B, B_T }` — requested PAdES level (default `B_B`).
- `expected_signer`: ExpectedSignerIdentity? — optional; when present, verification is on.
- `appearance`: SignatureAppearance? — optional; absent ⇒ invisible signature.
- `signature_meta`: { reason?, location? } — optional PAdES signature dictionary metadata.
- Validation: `document` MUST be a readable PDF; if PDF/A, output MUST remain PDF/A (FR-017);
  `conformance_level=B_T` REQUIRES a configured TSA.

### ExpectedSignerIdentity
What a request may be bound to (FR-014).
- `match_on`: enum `{ certificate_serial_number (default), cleverbase_subject }` for **Phase 1**.
  `name_and_dob` is **deferred to a later phase** (not implemented in Phase 1 — we do not ship an
  untested match mode, per Constitution Principle I).
- `value`: string — the expected identifier. For `certificate_serial_number` it is the credential
  certificate's serial number from CSC `credentials/info` (`cert.serialNumber`) or, when that
  optional convenience field is absent, its leaf certificate. It is canonical uppercase hex with
  no separators or DER `00` sign padding; for `cleverbase_subject` it is the
  subject DN's `serialNumber` RDN (the stable natural-person identifier, e.g. `PNONL-…`). Both
  are matched from the authorizing certificate.
  When either direct identity field is missing, both identity values come from the leaf certificate
  and the partial direct value is deliberately discarded.
  (OIDC `sub` matching is deferred — Phase 1 has no ID-token fetch, so it is not a match source yet.)
- Rule: mismatch against the authorizing signer's certificate ⇒ terminal `IdentityMismatch`,
  no signature produced.

### SignatureAppearance
Optional visible block (FR-016).
- `page`: uint (1-based), `rect`: { x, y, w, h } (PDF points).
- `show`: { signer_name?, reason?, location?, signing_time? }. (A logo/`image` is roadmap — see
  docs/limitations.md.)
- Rule: out-of-bounds page/rect ⇒ terminal placement error, no malformed PDF.

### TrustServiceConfiguration (input)
- `environment`: enum `{ acceptance, production }`.
- `csc_api`: enum `{ v1_rsa, v2_ecdsa }` (required — no default).
- `client_id`: string; `client_secret`: secret; `redirect_uri`: string.
- `upstream_base_url?`: alternate absolute Cleverbase origin for a documented developer service.
  It replaces the selected environment host for both OAuth and CSC endpoints; it must use HTTPS,
  except `http` on a loopback host, and may carry a base path but no credentials, query, or fragment.
- `tsa`: TsaConfiguration? — required when `conformance_level=B_T`.
- Rule: secrets are inputs the host supplies per call; the SDK never stores them.

### TsaConfiguration
- `url`: string (RFC 3161 endpoint of an external **qualified** TSA); `auth?`: secret (e.g. a Bearer
  header value); `policy_oid?`: string (requested TSA policy). The imprint hash is always SHA-256
  (hard-coded in the request builder, not a config field).

### SigningCredential (discovered)
From `credentials/list` + `credentials/info`.
- `credential_id`: string; `key_algo`: enum `{ RSA, ECDSA_P256 }`; `cert_chain`: X.509[] (DER);
  `subject`: SignerSubject; `scal`: `{ "1" | "2" }`.

### SignerSubject / SignerIdentity
- `serial_number`: string; `common_name`: string; `given_name?`, `surname?`; `raw_subject`: string
  (full DN). Used for identity matching (§7 of research) and the evidence record.

### Credential authorization (conceptual — not a persisted struct)
SCAL2 per-signature authorization is not modeled as a stored object. The service Bearer is carried
on the handle (`service_token`); the SAD is obtained at the credential-token step and used
immediately for `signHash` (atomic — never persisted). WYSIWYS holds structurally: the base64url
`hash` bound into the credential-scope authorize URL is exactly the hash sent to `signHash` (both
derived from the same `signed_attrs`). Authorization expiry surfaces as `AuthorizationExpired` from
the credential-token HTTP status; there is no host-clock `expires_at` check.

### SigningSessionHandle (persisted by integrator)
Opaque, **serializable, versioned** snapshot of in-flight state (FR-013). The host re-derives the
next effect from `phase`; effects are not stored on the handle.
- Always: `schema_version`: uint; `phase`: SigningPhase; `request_digest`: string (lowercase-hex
  SHA-256); `conformance_level`: enum; `correlation_id`: string.
- Carried as the flow advances (all optional): `state` (OAuth CSRF); `service_token` (Bearer,
  secret); `credential_id`; `cert_chain`; `key_algo`; `signed_attrs_der`; `staged_pdf` (PDF with
  ByteRange + placeholder, pre-signature); `contents_span`; `cms_der`; `signing_time_unix`;
  `signer`; `pdf_a`; `request` (**carries the document**); `config` (**carries `client_secret`**).
- Rules: contains the document and short-lived secrets ⇒ **store securely server-side, encrypted at
  rest**; the flow resumes statelessly from the handle alone.

### SignedDocument (output)
- `pdf`: bytes (signed, incremental-update appended); `conformance_level`: enum;
  `pdf_a`: bool (preserved if input was PDF/A).

### PdfVerification (output)
- `integrity`: bool — true only when one signature dictionary is structurally bound to its raw-hex
  `/Contents` gap, the embedded CMS signature verifies with the certificate selected by SignerInfo,
  and the signed `message-digest` equals SHA-256 of the two `/ByteRange` segments.
- `profile?`: enum `{ B_B, B_T }`, present only when `integrity=true`. B-T means the CMS contains a
  signature-time-stamp attribute; its token is not validated by this integrity-only operation.
- `signer?`: `{ serial_number, common_name }`, derived from the embedded signer certificate and
  present only when `integrity=true`.
- `reasons`: closed machine-readable failure list documented by the SDK API contract. Invalid input
  returns a verdict rather than an exception. It is empty if and only if `integrity=true`.
- Supported CMS profile: SHA-256 with `rsaEncryption`/PKCS #1 v1.5 or `ecdsa-with-SHA256`, plus
  `ESSCertIDv2` with its default SHA-256 algorithm and no `issuerSerial`, matching SDK output.
  Other valid CMS profiles may return an unsupported or malformed verdict.
- Explicitly out of scope: certificate path building/trust, revocation, trusted-list status, signer
  authorization, and RFC 3161 token validation. `integrity=true` is not qualified validation.
  Phase 1 rejects multiple signatures; co-signing later lifts that limit.

### TimestampInfo (B-T evidence summary)
- `tsa`: string (the TSA URL); `gen_time`: i64 (the TSA token's own genTime, Unix seconds);
  `policy_oid?`: string. The raw RFC 3161 `TimeStampToken` is embedded into the CMS as the
  signature-time-stamp attribute; it is not surfaced as a separate field.

### SigningEvidenceRecord (output, success AND failure — FR-015)
- `request_digest`: string (lowercase-hex SHA-256 of the input document); `outcome`: SigningOutcome;
- `signer`: SignerIdentity?; `conformance_level`: enum; `signing_time?`: instant;
- `timestamp?`: TimestampInfo { tsa, gen_time, policy_oid? }; `failure_reason?`: string (free text,
  secret-free); `correlation_id`: string.
- Rule: returned on every attempt; the SDK does not persist it.

### Effect (sans-IO output)
What the host must do next.
- `HttpEffect`: { method, url, headers, body } — retry-safety depends on the operation (idempotent
  reads may be retried; a token exchange or `signHash` must be retried only on a pure transport
  failure, never after a server reply, since they consume a one-time SAD / produce a signature).
- `RedirectEffect`: { url, state } — send the signer's browser here; resume with the returned `code`.

## Enumerations

- `SigningPhase`: `ServiceAuthPending → ServiceTokenPending → ListPending → InfoPending →
  CredentialAuthPending → CredentialTokenPending → SignPending → (TimestampPending for B-T) →
  Completed | Failed`.
- `SigningOutcome`: `Signed | Declined | AuthorizationExpired | CredentialUnavailable |
  IdentityMismatch | TimestampFailed | InvalidDocument | AppearancePlacementError |
  SignatureInvalid`. `SignatureInvalid` ⇒ the trust service returned a signature that failed the
  core's verification against the signer certificate (never reported as `Signed`).

## State machine (signing lifecycle)

```text
Created
  │ begin(request, config)               → emits RedirectEffect (scope=service)
  ▼
ServiceAuthPending
  │ resume(code)                         → emits HttpEffect token; then credentials/list+info
  ▼
CredentialDiscovery
  │ (credential resolved; cert subject checked vs ExpectedSignerIdentity)
  │   mismatch ───────────────────────────────────────────► Failed(IdentityMismatch)
  │ prepare PDF (ByteRange + placeholder); compute bound_hash
  │                                       → emits RedirectEffect (scope=credential, hash-bound)
  ▼
CredentialAuthPending
  │ resume(code)                         → emits HttpEffect token → SAD
  │   declined/expired ───────────────────────────────────► Failed(Declined|AuthorizationExpired)
  ▼
Signing
  │                                       → emits HttpEffect signatures/signHash
  │ embed raw signature into CMS → splice into /Contents  (= B-B)
  ▼
Augmenting   (only when level=B_T)
  │                                       → emits HttpEffect TimeStampReq to TSA
  │   tsa failure ─────────────────────────────────────────► Failed(TimestampFailed)   [no downgrade]
  │ embed TimeStampToken (signature-time-stamp attribute)
  ▼
Completed  → returns SignedDocument + SigningEvidenceRecord
```

Every transition is driven by `resume(handle, effect_result)`; the core never performs I/O. All
`Failed(*)` states also return a SigningEvidenceRecord (FR-015). In Phase 1 an **already-signed**
input PDF is **rejected** up front with `InvalidDocument` (re-saving it would invalidate the prior
signature); adding a further signature without invalidating existing ones requires incremental-
update multi-signature (FR-010), which is deferred — see docs/limitations.md.
