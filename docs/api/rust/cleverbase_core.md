# Crate `cleverbase_core`

# cleverbase-core

The sans-IO core of the Cleverbase SDK: a pure, serializable state machine for obtaining a
Qualified Electronic Signature (QES) on a PDF (PAdES B-B / B-T). It performs all cryptography
and PDF work in-process and **emits effects** (HTTP requests, browser redirects) that the host
executes — it never performs I/O itself. This keeps the core deterministic, WASM-able, and
contract-testable by replaying recorded HTTP fixtures.

See `specs/001-remote-qes-signing/` for the spec, plan, and contracts.

## Status

Phase 1 (signing) is implemented and tested: the full CSC/OIDC flow (service auth → credential
discovery → identity check → PDF prepare → hash-bound credential auth → `signHash` → CMS
assembly → embed), PAdES **B-B** and **B-T** (RFC 3161), **RSA** and **ECDSA P-256**, optional
visible appearance, and the stateless session handle. See `docs/limitations.md` for the
later-phase roadmap (B-LT/B-LTA, full PDF/A, EUDI attestation).

## Module `crypto`

Cryptographic primitives. Only vetted RustCrypto implementations are used — no hand-rolled
crypto (Constitution Principle IV). SHA-256 lives here; CMS / RSA / ECDSA-P256 assembly and the
ESS structures are in `cms`/`ess`, and RFC 3161 timestamping in `crate::timestamp`.

### Module `cms`

CAdES/PAdES-B CMS (PKCS#7) SignedData assembly with an **external** signature.

This mirrors how Cleverbase signs: we build the signed attributes, the host obtains a signature
over `sha256(DER(signedAttrs))` (Cleverbase `signHash`), and we assemble a detached
`SignedData`. No private key ever lives in the core. Built only on vetted RustCrypto crates
(Constitution Principle IV).

#### Enums

##### enum `CmsError`

```rust
enum CmsError
```

Errors from CMS assembly/verification.

###### Variants

- `Der(Error)`
  - A DER encode/decode error.
- `UnsupportedAlgo`
  - The key algorithm is not supported for CMS assembly.
- `EmptyChain`
  - The certificate chain was empty.
- `Verify(String)`
  - Signature verification failed.

#### Functions

##### fn `assemble_signed_data`

```rust
fn assemble_signed_data(cert_chain_der: &[Vec<u8>], signed_attrs_der: &[u8], signature: &[u8], key_algo: KeyAlgo) -> Result<Vec<u8>, CmsError>
```

Assemble a detached CMS `SignedData` (wrapped in a `ContentInfo`) from the signer's certificate
chain (DER, leaf first), the signed-attributes DER, and the raw signature value from the signer.

##### fn `build_signed_attrs`

```rust
fn build_signed_attrs(content_hash: &[u8], leaf_cert_der: &[u8], now_unix: i64) -> Result<Vec<u8>, CmsError>
```

Build the DER of the signed attributes as a `SET OF` (tag `0x31`) — the bytes whose SHA-256 the
signer authorizes and signs (`signHash`). `content_hash` is sha256 of the PDF ByteRange bytes.

##### fn `embed_timestamp`

```rust
fn embed_timestamp(content_info_der: &[u8], token_der: &[u8]) -> Result<Vec<u8>, CmsError>
```

Embed an RFC 3161 timestamp token as the `signature-time-stamp` unsigned attribute (PAdES B-T).

##### fn `has_signature_timestamp`

```rust
fn has_signature_timestamp(content_info_der: &[u8]) -> Result<bool, CmsError>
```

True if the CMS SignerInfo carries a `signature-time-stamp` unsigned attribute (B-T).

##### fn `reparse_for_verify`

```rust
fn reparse_for_verify(content_info_der: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<Vec<u8>>), CmsError>
```

Re-parse an assembled CMS, returning `(signed_attrs_der, message_digest, signature, cert_chain)`
— the SET OF re-encoding is exactly what was signed.

##### fn `signer_signature`

```rust
fn signer_signature(content_info_der: &[u8]) -> Result<Vec<u8>, CmsError>
```

Return the SignerInfo signature value of an assembled CMS (the bytes a B-T timestamp covers).

##### fn `tbs_hash`

```rust
fn tbs_hash(signed_attrs_der: &[u8]) -> [u8; 32]
```

SHA-256 of the signed-attributes DER — the hash sent to the signing service.

##### fn `verify_signed_data`

```rust
fn verify_signed_data(cms_der: &[u8], key_algo: KeyAlgo) -> Result<Vec<u8>, CmsError>
```

Verify the assembled CMS signature against the signer's leaf certificate (defense-in-depth: the
core must never report `Signed` for a signature it cannot itself verify). On success returns the
`message-digest` signed attribute so the caller can bind it to the document without re-parsing.

### Module `ess`

Minimal ESS structures for the `signing-certificate-v2` signed attribute (RFC 5035), required
by CAdES-B / PAdES-B.

#### Structs

##### struct `EssCertIdV2`

```rust
struct EssCertIdV2
```

`ESSCertIDv2` with the default SHA-256 hash algorithm (hashAlgorithm omitted ⇒ sha256) and no
issuerSerial. `cert_hash` is `sha256(DER(signer certificate))`.

###### Fields

- `cert_hash: OctetString`
  - `sha256(DER(signer certificate))`.

##### struct `SigningCertificateV2`

```rust
struct SigningCertificateV2
```

`SigningCertificateV2 ::= SEQUENCE { certs SEQUENCE OF ESSCertIDv2 }` (policies omitted).

###### Fields

- `certs: Vec<EssCertIdV2>`
  - The `ESSCertIDv2` entries (the signer leaf certificate).

### Functions

#### fn `sha256`

```rust
fn sha256(data: &[u8]) -> [u8; 32]
```

SHA-256 digest of `data`. (SHA-256 is the only hash Cleverbase's CSC service advertises.)

### Constants

#### const `SHA256_OID`

```rust
const SHA256_OID: ObjectIdentifier = _
```

The SHA-256 algorithm OID, parsed form of [`SHA256_OID_STR`].

#### const `SHA256_OID_STR`

```rust
const SHA256_OID_STR: &str = "2.16.840.1.101.3.4.2.1"
```

The SHA-256 algorithm OID — the single source for the string and parsed forms, shared by the
`signHash` request, the CMS digest algorithm, and the RFC 3161 message imprint (Principle VIII).
SHA-256 is the only hash Cleverbase's CSC service advertises.

## Module `effects`

Sans-IO effect types: what the host must do next (contracts/sdk-api.md).

The core never performs I/O. It returns a [`Step`]; the host performs the described effect and
calls `resume` with the result.

### Structs

#### struct `HttpEffect`

```rust
struct HttpEffect
```

An HTTP request the host must perform on the core's behalf. The core does not advance until it
receives a result. Retry-safety is NOT blanket-guaranteed — it depends on the operation:
idempotent reads (`credentials/list`, `credentials/info`) may be retried freely, but a token
exchange or `signHash` can consume a one-time authorization (SAD) or produce a signature, so
retry those only on a pure transport failure (no response received), never after a server reply.

##### Fields

- `method: HttpMethod`
  - HTTP method to use.
- `url: String`
  - Absolute request URL.
- `headers: Vec<(String, String)>`
  - Request headers as `(name, value)` pairs.
- `body: Option<Vec<u8>>`
  - Optional request body bytes.

#### struct `RedirectEffect`

```rust
struct RedirectEffect
```

A browser redirect the host must issue to the signer; on return, resume with the `code`+`state`.

##### Fields

- `url: String`
  - URL to send the signer's browser to.
- `state: String`
  - OAuth `state` (CSRF token); echoed back on return and validated by `resume`.

### Enums

#### enum `HttpMethod`

```rust
enum HttpMethod
```

HTTP method for an [`HttpEffect`].

##### Variants

- `Get`
  - HTTP GET.
- `Post`
  - HTTP POST.

#### enum `Step`

```rust
enum Step
```

The result of one `begin`/`resume` call: exactly one next action or a terminal outcome.

##### Variants

- `PerformHttp(HttpEffect)`
  - Perform this HTTP request, then `resume` with the response.
- `Redirect(RedirectEffect)`
  - Send the signer's browser here, then `resume` with the returned code+state.
- `Done { signed: SignedDocument, evidence: SigningEvidenceRecord }`
  - Terminal success.
- `Failed { evidence: SigningEvidenceRecord }`
  - Terminal failure; `evidence.outcome` is never `Signed`.

##### Methods

```rust
fn is_terminal(&self) -> bool
```

`true` for terminal steps ([`Step::Done`] / [`Step::Failed`]); the flow does not resume past them.

## Module `evidence`

Per-operation signing evidence record, returned on success AND failure (FR-015).

### Structs

#### struct `SignerIdentity`

```rust
struct SignerIdentity
```

The signer's identity, derived from their qualified certificate subject.

##### Fields

- `serial_number: String`
  - Certificate serial number from CSC `credentials/info` or its leaf certificate, canonicalized
as uppercase hexadecimal without separators or DER `00` sign padding.
- `common_name: String`
  - Subject common name (`CN`), or empty if absent.
- `given_name: Option<String>`
  - Subject given name (`GN`/`givenName`), if present.
- `surname: Option<String>`
  - Subject surname (`SN`/`surname`), if present.
- `raw_subject: String`
  - The raw subject distinguished name (RFC 4514).

#### struct `SigningEvidenceRecord`

```rust
struct SigningEvidenceRecord
```

Structured evidence emitted for every signing attempt (FR-015). Not persisted by the SDK.

##### Fields

- `request_digest: String`
  - SHA-256 of the to-be-signed content (hex).
- `outcome: SigningOutcome`
  - Terminal outcome of the attempt.
- `conformance_level: ConformanceLevel`
  - Conformance level that was requested / produced.
- `signer: Option<SignerIdentity>`
  - The derived signer identity, when known.
- `signing_time: Option<i64>`
  - Signing time (Unix seconds), present on success.
- `timestamp: Option<TimestampInfo>`
  - Trusted-timestamp summary (B-T success only).
- `failure_reason: Option<String>`
  - Human-readable failure reason, present on failure.
- `correlation_id: String`
  - Correlation id for this attempt (derived from request entropy).

#### struct `TimestampInfo`

```rust
struct TimestampInfo
```

Trusted-timestamp summary recorded in the evidence (B-T).

##### Fields

- `tsa: String`
  - The TSA endpoint URL used.
- `gen_time: i64`
  - The TSA's own `genTime` from the timestamp token (Unix seconds).
- `policy_oid: Option<String>`
  - The TSA policy OID, when the caller requested a specific one.

### Enums

#### enum `SigningOutcome`

```rust
enum SigningOutcome
```

Terminal outcome of a signing attempt (data-model: SigningOutcome).

##### Variants

- `Signed`
  - The document was signed successfully (the only success outcome).
- `Declined`
  - The signer declined in the wallet (OAuth `access_denied`).
- `AuthorizationExpired`
  - Authorization was not completed in time / expired.
- `CredentialUnavailable`
  - No usable signing credential was available (or the trust service rejected the request).
- `IdentityMismatch`
  - The authorizing signer did not match the expected identity (FR-014).
- `TimestampFailed`
  - The B-T timestamp could not be obtained or did not bind to the signature.
- `InvalidDocument`
  - The input was not a signable PDF (non-PDF, no pages, or already signed).
- `AppearancePlacementError`
  - The requested visible-appearance placement was invalid (e.g. page out of range).
- `SignatureInvalid`
  - The signature returned by the trust service failed verification against the signer's
certificate — the core refuses to report `Signed` for a signature it cannot verify.

##### Methods

```rust
fn is_success(&self) -> bool
```

`true` only for [`SigningOutcome::Signed`].

## Module `pades`

PAdES container assembly: prepare a PDF for signing (signature dictionary, `/ByteRange`,
`/Contents` placeholder) and embed the CMS. See contracts + data-model.

### Module `container`

PAdES (PDF) signature container: incremental signature dictionary + `/ByteRange` + `/Contents`
placeholder, hash over the ByteRange, CMS embedding, and an optional visible appearance.

Cleverbase signs only a hash; we own the container (Constitution Principle V). The to-be-signed
digest is `sha256` over the whole PDF except the `/Contents` value (the standard PAdES
ByteRange). After the signer's signature is wrapped into a detached CMS (see
[`crate::crypto::cms`]), the CMS DER is written into the `/Contents` placeholder.

#### Structs

##### struct `PreparedSignature`

```rust
struct PreparedSignature
```

A PDF staged for signing.

###### Fields

- `staged_pdf: Vec<u8>`
  - The PDF bytes with `/ByteRange` finalized and a zeroed `/Contents` placeholder.
- `content_hash: [u8; 32]`
  - SHA-256 over the ByteRange (the CMS `message-digest`).
- `contents_span: (usize, usize)`
  - Byte span (start, end) of the hex digits inside `/Contents` (exclusive of `< >`).

##### struct `VisibleAppearance`

```rust
struct VisibleAppearance
```

A resolved visible signature appearance: where to draw and the text lines to render (FR-016).

###### Fields

- `page: u32`
  - 1-based page number.
- `rect: (f64, f64, f64, f64)`
  - (x, y, width, height) in PDF points.
- `lines: Vec<String>`
  - Text lines, top to bottom.

#### Enums

##### enum `PadesError`

```rust
enum PadesError
```

Errors from PAdES container operations.

###### Variants

- `Pdf(Error)`
  - An error from the underlying PDF library.
- `Io(Error)`
  - An I/O error while (re-)serializing the PDF.
- `NoPages`
  - The document has no pages to attach a signature to.
- `InvalidPlacement`
  - The requested visible-appearance placement was invalid (page or rectangle).
- `Placeholder(&'static str)`
  - A required placeholder (named) could not be located in the serialized PDF.
- `CmsTooLarge(usize, usize)`
  - The assembled CMS does not fit the `/Contents` placeholder (`actual` > `capacity` bytes).
- `AlreadySigned`
  - The input document already carries a signature (multi-signature is a later phase).

#### Functions

##### fn `byte_range_digest`

```rust
fn byte_range_digest(staged: &[u8], span: (usize, usize)) -> Option<[u8; 32]>
```

SHA-256 over the signed byte range of a staged PDF: everything except the `/Contents` hex value
between `span.0` and `span.1`. This is the value the CMS `message-digest` attribute must equal,
binding the signature to exactly this document (WYSIWYS). Returns `None` if `span` is out of
bounds (e.g. a corrupted/tampered handle).

##### fn `embed_cms`

```rust
fn embed_cms(staged_pdf: &mut [u8], contents_span: (usize, usize), cms_der: &[u8]) -> Result<(), PadesError>
```

Write the detached CMS (DER) into the `/Contents` placeholder as hex. Remaining placeholder
bytes stay zero (excluded from the ByteRange, so they do not affect the signature).

##### fn `is_already_signed`

```rust
fn is_already_signed(pdf: &[u8]) -> bool
```

True if the PDF already carries a signature — detected by `/ByteRange`, which appears only in
signature dictionaries. Phase 1 signs only previously-unsigned documents; adding a signature to
an already-signed PDF (multi-signature via incremental update, FR-010) is a later phase, so such
input is rejected up front rather than risk corrupting the existing signature.

##### fn `is_pdf_a`

```rust
fn is_pdf_a(pdf: &[u8]) -> bool
```

Heuristic PDF/A detection: PDF/A documents carry XMP metadata in the `pdfaid` namespace.

##### fn `prepare`

```rust
fn prepare(original_pdf: &[u8], reason: Option<&str>, location: Option<&str>, appearance: Option<&VisibleAppearance>) -> Result<PreparedSignature, PadesError>
```

Prepare a PDF for signing. Adds a signature field + dictionary (invisible, or visible when an
appearance is given) and returns the staged bytes, the ByteRange digest, and the `/Contents`
span to embed into.

## Module `session`

The serializable, versioned signing session handle (FR-013, data-model).

The integrator persists this between the authorization round-trip and finalization. It carries
short-lived authorization material and the request/config, so it MUST be stored securely
server-side (encrypted at rest).

### Structs

#### struct `SigningSessionHandle`

```rust
struct SigningSessionHandle
```

Opaque-to-the-integrator, serializable session state.

##### Fields

- `schema_version: u32`
  - Wire schema version this handle was produced at ([`crate::SCHEMA_VERSION`]).
- `phase: SigningPhase`
  - Current phase of the signing state machine.
- `request_digest: String`
  - SHA-256 of the document bytes (hex), for correlation.
- `conformance_level: ConformanceLevel`
  - Conformance level requested for this session.
- `correlation_id: String`
  - Correlation id for this session (derived from the begin-call entropy).
- `state: Option<String>`
  - OAuth `state` for the currently pending redirect, if any.
- `credential_id: Option<String>`
  - The selected CSC credential id, once discovered.
- `service_token: Option<Secret>`
  - Service-scope Bearer token (sensitive).
- `cert_chain: Option<Vec<Vec<u8>>>`
  - Signer certificate chain (DER, leaf first).
- `key_algo: Option<KeyAlgo>`
  - Signing key algorithm family, from `credentials/info`.
- `signed_attrs_der: Option<Vec<u8>>`
  - DER of the CMS signed attributes (the bytes whose hash is signed).
- `staged_pdf: Option<Vec<u8>>`
  - The staged PDF (with ByteRange + `/Contents` placeholder) awaiting CMS embedding.
- `contents_span: Option<(usize, usize)>`
  - Byte span (start, end) of the `/Contents` hex placeholder in `staged_pdf`.
- `cms_der: Option<Vec<u8>>`
  - Assembled CMS (without timestamp), carried from signing to the B-T timestamp step.
- `signing_time_unix: Option<i64>`
  - Signing time (Unix seconds) recorded at the prepare step.
- `signer: Option<SignerIdentity>`
  - The derived signer identity, once known.
- `pdf_a: Option<bool>`
  - Best-effort PDF/A indicator for the staged output.
- `request: Option<SigningRequest>`
  - Carried so the flow can resume statelessly. Contains the document; treat as sensitive.
- `config: Option<TrustServiceConfiguration>`
  - Carried so the flow can resume statelessly. Contains secrets; encrypt at rest.

##### Methods

```rust
fn terminal(phase: SigningPhase, request_digest: String, conformance_level: ConformanceLevel, correlation_id: String) -> Self
```

Build a terminal (Completed/Failed) handle that carries no further state.

### Enums

#### enum `SigningPhase`

```rust
enum SigningPhase
```

Phase of the signing state machine. Each `*Pending` phase awaits a specific `ResumeInput`.

##### Variants

- `ServiceAuthPending`
  - Awaiting the service-scope authorization redirect return.
- `ServiceTokenPending`
  - Awaiting the service-scope token-exchange HTTP response.
- `ListPending`
  - Awaiting the credentials/list HTTP response.
- `InfoPending`
  - Awaiting the credentials/info HTTP response.
- `CredentialAuthPending`
  - Awaiting the credential-scope authorization redirect return.
- `CredentialTokenPending`
  - Awaiting the credential-scope token (SAD) HTTP response.
- `SignPending`
  - Awaiting the signatures/signHash HTTP response.
- `TimestampPending`
  - Awaiting the timestamp-authority HTTP response (B-T only).
- `Completed`
  - Terminal: the flow completed successfully.
- `Failed`
  - Terminal: the flow failed (see the evidence record's outcome).

## Module `signing`

The sans-IO signing state machine (contracts/sdk-api.md, data-model.md).

`begin` starts a signing flow; `resume` advances it given the result of the last effect. The
core performs no I/O — it returns a [`Step`] describing what the host must do next. The full
CSC/OIDC flow is wired here: service authorization → credential discovery → identity check →
PDF preparation → hash-bound credential authorization → `signHash` → CMS assembly → embed.
PAdES B-B and B-T are both implemented.

### Module `csc`

CSC / OAuth response parsers and signer-identity derivation (FR-014).

Cleverbase responses are JSON. These are pure parse functions over the response bytes the host
feeds back via `ResumeInput::HttpResult`. Identity matching uses the subject DN and serial
number in `credentials/info` when both are present, otherwise the leaf certificate that CSC
returns in the same response.

#### Structs

##### struct `CredentialInfo`

```rust
struct CredentialInfo
```

Flattened, useful view of `credentials/info`.

###### Fields

- `certificates: Vec<String>`
  - Certificate chain, base64-encoded DER (leaf first).
- `subject_dn: String`
  - The subject distinguished name (RFC 4514).
- `serial_number: String`
  - The certificate serial number reported by the service.
- `scal: String`
  - The advertised SCAL level (`"2"` for per-signature sole control).
- `key_algo: KeyAlgo`
  - The detected signing key algorithm family.

##### struct `CredentialList`

```rust
struct CredentialList
```

`credentials/list` response.

###### Fields

- `credential_ids: Vec<String>`
  - The credential ids available to this service token.

##### struct `SignaturesResponse`

```rust
struct SignaturesResponse
```

`signatures/signHash` response (raw signature values, base64).

###### Fields

- `signatures: Vec<String>`
  - Raw signature values (base64), one per requested hash.

##### struct `TokenResponse`

```rust
struct TokenResponse
```

OAuth2 token response (service-scope Bearer, or credential-scope SAD).

###### Fields

- `access_token: String`
  - The access token (service-scope Bearer, or credential-scope SAD).
- `token_type: String`
  - The token type (e.g. `Bearer` or `SAD`).
- `expires_in: Option<i64>`
  - Token lifetime in seconds, when reported.

#### Enums

##### enum `KeyAlgo`

```rust
enum KeyAlgo
```

Signing key algorithm family, derived from the credential's advertised OIDs.

###### Variants

- `Rsa`
  - RSA (PKCS#1 v1.5 with SHA-256).
- `EcdsaP256`
  - ECDSA over the NIST P-256 curve with SHA-256.
- `Other`
  - Any other / unsupported algorithm.

###### Methods

```rust
fn sign_algo_oid(&self) -> &'static str
```

The `signAlgo` OID to request from CSC `signatures/signHash` (empty for [`KeyAlgo::Other`]).

#### Functions

##### fn `matches_expected`

```rust
fn matches_expected(expected: &ExpectedSignerIdentity, identity: &SignerIdentity) -> bool
```

Check the authorizing signer against an expected identity (FR-014). The default match key is the
certificate serial number; `cleverbase_subject` matches the stable subject identifier — the
subject DN's `serialNumber` RDN (e.g. `PNONL-…`), per data-model.md — not the whole DN.
`name_and_dob` is deferred (see data-model.md) and not a variant here.

##### fn `parse_credentials_info`

```rust
fn parse_credentials_info(body: &[u8]) -> Result<CredentialInfo, CoreError>
```

Parse a `credentials/info` response body into the flattened [`CredentialInfo`].

##### fn `parse_credentials_list`

```rust
fn parse_credentials_list(body: &[u8]) -> Result<CredentialList, CoreError>
```

Parse a `credentials/list` response body.

##### fn `parse_signatures`

```rust
fn parse_signatures(body: &[u8]) -> Result<SignaturesResponse, CoreError>
```

Parse a `signatures/signHash` response body.

##### fn `parse_token_response`

```rust
fn parse_token_response(body: &[u8]) -> Result<TokenResponse, CoreError>
```

Parse an OAuth2 token response body.

##### fn `signer_identity`

```rust
fn signer_identity(info: &CredentialInfo, leaf_certificate_der: &[u8]) -> Result<SignerIdentity, CoreError>
```

Derive the signer's identity from CSC `credentials/info`.

CSC providers may omit the non-standard `subjectDN` and `serialNumber` convenience fields.
In that case the authoritative leaf certificate (first `certificates` entry) supplies both
values, avoiding an empty identity and preserving expected-signer matching.

### Structs

#### struct `HostContext`

```rust
struct HostContext
```

Host-provided context for a single call (keeps the core deterministic).

##### Fields

- `now_unix: i64`
  - Current time, Unix seconds.
- `entropy: Vec<u8>`
  - Fresh random bytes (OAuth `state`, correlation id). Provide ≥ 16 bytes.

### Enums

#### enum `CoreError`

```rust
enum CoreError
```

Usage/programmer errors (not protocol outcomes, which are `Step::Failed`).

##### Variants

- `MissingTsaConfig`
  - B-T was requested but no TSA is configured.
- `InvalidConfig(String)`
  - A required configuration value was missing or invalid.
- `StateMismatch`
  - The returned OAuth `state` did not match the pending one (CSRF check failed).
- `BadHandle(String)`
  - The session handle was malformed, tampered, or carried an unsupported schema version.
- `UnexpectedInput`
  - The supplied [`ResumeInput`] did not match what the current phase expects.
- `ProtocolParse(String)`
  - A trust-service response could not be parsed.
- `Internal(String)`
  - An internal invariant failed while assembling the signature/container.

#### enum `ResumeInput`

```rust
enum ResumeInput
```

The result the host feeds back into `resume`.

##### Variants

- `HttpResult { status: u16, headers: Vec<(String, String)>, body: Vec<u8> }`
  - Response to a prior [`Step::PerformHttp`].
- `RedirectReturn { code: String, state: String }`
  - Code+state received at the integrator's `redirect_uri` after a [`Step::Redirect`].
- `RedirectError { error: String, state: String }`
  - An OAuth error received at the `redirect_uri` instead of a code (e.g. `access_denied` when
the signer declines in the wallet), with the `state` for CSRF validation.

### Functions

#### fn `begin`

```rust
fn begin(request: SigningRequest, config: TrustServiceConfiguration, ctx: HostContext) -> Result<(SigningSessionHandle, Step), CoreError>
```

Begin a signing flow. Returns the session handle plus the first [`Step`].

#### fn `resume`

```rust
fn resume(handle: SigningSessionHandle, input: ResumeInput, ctx: HostContext) -> Result<(SigningSessionHandle, Step), CoreError>
```

Advance a signing flow given the result of the last effect.

## Module `timestamp`

RFC 3161 timestamping for PAdES B-T.

Builds a `TimeStampReq` over `sha256(signature value)` and extracts the `TimeStampToken` from
the TSA's `TimeStampResp`. The token is embedded into the CMS as the `signature-time-stamp`
unsigned attribute (see [`crate::crypto::cms::embed_timestamp`]). Cleverbase's CSC signing API
exposes no timestamp endpoint, so the host points this at a configured RFC 3161 TSA.

### Enums

#### enum `TimestampError`

```rust
enum TimestampError
```

Errors from RFC 3161 handling.

##### Variants

- `Der(Error)`
  - A DER encode/decode error.
- `NotGranted`
  - The TSA did not grant a timestamp (non-granted status or no token in the response).
- `InvalidPolicyOid(String)`
  - The configured TSA policy OID was not a valid object identifier.

### Functions

#### fn `build_request`

```rust
fn build_request(signature_sha256: &[u8], policy_oid: Option<&str>) -> Result<Vec<u8>, TimestampError>
```

Build an RFC 3161 `TimeStampReq` over `sha256(signature value)` with `certReq = true`, optionally
constraining the TSA to a specific policy OID.

#### fn `parse_gen_time`

```rust
fn parse_gen_time(token_der: &[u8]) -> Option<i64>
```

Parse the TSA's `genTime` (Unix seconds) from a `TimeStampToken` (CMS `ContentInfo`, DER).
Returns `None` if the token cannot be parsed.

#### fn `parse_message_imprint`

```rust
fn parse_message_imprint(token_der: &[u8]) -> Option<Vec<u8>>
```

Parse the `messageImprint.hashedMessage` (the hash the TSA actually timestamped) from a
`TimeStampToken`, so the caller can confirm the token is bound to the value it submitted.
Returns `None` if the token cannot be parsed.

#### fn `parse_response`

```rust
fn parse_response(resp_der: &[u8]) -> Result<Vec<u8>, TimestampError>
```

Extract the `TimeStampToken` (a CMS `ContentInfo`, DER) from a `TimeStampResp`.

## Module `types`

Input/output value types for the signing API (see contracts/sdk-api.md, data-model.md).

### Structs

#### struct `AppearanceShow`

```rust
struct AppearanceShow
```

Which fields a visible appearance should render.

##### Fields

- `signer_name: bool`
  - Render the signer's name (common name, or the raw subject DN as fallback).
- `reason: bool`
  - Render the signing reason (from [`SignatureMeta::reason`]).
- `location: bool`
  - Render the signing location (from [`SignatureMeta::location`]).
- `signing_time: bool`
  - Render the signing time (UTC).

#### struct `ExpectedSignerIdentity`

```rust
struct ExpectedSignerIdentity
```

Optional binding of a request to a specific expected signer (FR-014).

##### Fields

- `match_on: MatchOn`
  - Which identity field the `value` is compared against.
- `value: String`
  - The expected value (e.g. a certificate serial number or a `PNONL-…` subject identifier).

#### struct `Rect`

```rust
struct Rect
```

A rectangle on a PDF page, in PDF points.

##### Fields

- `x: f64`
  - Lower-left x coordinate, in PDF points.
- `y: f64`
  - Lower-left y coordinate, in PDF points.
- `w: f64`
  - Width, in PDF points.
- `h: f64`
  - Height, in PDF points.

#### struct `RequestOptions`

```rust
struct RequestOptions
```

The optional parts of a [`SigningRequest`] that the language bindings accept as a single JSON
object (so a binding needs one `options_json` argument rather than one parameter per nested
field). All fields are optional; the JSON shape mirrors the serde representation of the types.

##### Fields

- `expected_signer: Option<ExpectedSignerIdentity>`
  - Optional expected-signer binding (FR-014).
- `appearance: Option<SignatureAppearance>`
  - Optional visible signature appearance (FR-016).
- `signature_meta: Option<SignatureMeta>`
  - Optional signature dictionary metadata.

##### Methods

```rust
fn from_json(s: &str) -> Result<Self, String>
```

Parse from a JSON object string. Empty/whitespace input yields all-none defaults.

#### struct `Secret`

```rust
struct Secret
```

A secret string whose contents never appear in `Debug` output (Constitution Principle IV).
It still (de)serializes its inner value so a session handle can round-trip authorization
material; the integrator is responsible for encrypting handles at rest.

##### Methods

```rust
fn expose(&self) -> &str
```

Reveal the secret. Call sites should keep the result on the server only.

```rust
fn new<impl Into<String>: Into<String>>(s: impl Into<String>) -> Self
```

Wrap a value as a redacted secret.

#### struct `SignatureAppearance`

```rust
struct SignatureAppearance
```

Optional visible signature appearance (FR-016). Absent ⇒ invisible signature.

##### Fields

- `page: u32`
  - 1-based page number.
- `rect: Rect`
  - Where to draw the appearance, in PDF points.
- `show: AppearanceShow`
  - Which fields to render inside the rectangle.

#### struct `SignatureMeta`

```rust
struct SignatureMeta
```

PAdES signature dictionary metadata (FR-016).

##### Fields

- `reason: Option<String>`
  - Optional signing reason (PDF signature dictionary `/Reason`).
- `location: Option<String>`
  - Optional signing location (PDF signature dictionary `/Location`).

#### struct `SignedDocument`

```rust
struct SignedDocument
```

The signed result returned on success (data-model: SignedDocument).

##### Fields

- `pdf: Vec<u8>`
  - The signed PDF bytes (signature embedded into the `/Contents` placeholder).
- `conformance_level: ConformanceLevel`
  - The conformance level actually produced.
- `pdf_a: bool`
  - Best-effort PDF/A indicator: true when the signed output still carries the PDF/A marker and
an invisible signature was used. Conformance is NOT independently validated in Phase 1 (no
veraPDF — see docs/limitations.md); do not treat this as a guarantee.

#### struct `SigningRequest`

```rust
struct SigningRequest
```

An application's intent to sign a document (data-model: SigningRequest).

##### Fields

- `document: Vec<u8>`
  - The PDF to sign. Stays in the integrator's infra; only its hash leaves (FR-002).
- `conformance_level: ConformanceLevel`
  - Requested PAdES conformance level (defaults to B-B).
- `expected_signer: Option<ExpectedSignerIdentity>`
  - Optional binding to a specific expected signer (FR-014).
- `appearance: Option<SignatureAppearance>`
  - Optional visible signature appearance; absent ⇒ invisible signature (FR-016).
- `signature_meta: Option<SignatureMeta>`
  - Optional signature dictionary metadata (`/Reason`, `/Location`).

#### struct `TrustServiceConfiguration`

```rust
struct TrustServiceConfiguration
```

How to reach the Cleverbase trust service (data-model: TrustServiceConfiguration).

##### Fields

- `environment: Environment`
  - Which Cleverbase environment to target.
- `csc_api: CscApi`
  - Which CSC API generation (selects host + signature algorithm).
- `client_id: String`
  - OAuth2 client id issued by Cleverbase.
- `client_secret: Secret`
  - OAuth2 client secret (redacted in `Debug`).
- `redirect_uri: String`
  - OAuth2 redirect URI registered for this client.
- `upstream_base_url: Option<String>`
  - Optional alternate Cleverbase origin for a documented developer/stub service. It replaces
the selected environment host for both OAuth and CSC endpoints.
- `tsa: Option<TsaConfiguration>`
  - TSA configuration; required when requesting B-T.

##### Methods

```rust
fn authorize_url(&self) -> String
```

The OAuth2 authorization endpoint for the selected API generation and environment.

```rust
fn base_url(&self) -> String
```

Base URL for the configured upstream, with a trailing slash removed.

Uses [`Self::upstream_base_url`] when present; otherwise selects the documented host from
[`Self::csc_api`] and [`Self::environment`]. A valid override is emitted in URL-normalized
form (canonical scheme/host, IDN, and path), never in the caller's raw spelling.

```rust
fn token_url(&self) -> String
```

The OAuth2 token endpoint for the selected API generation and environment.

```rust
fn validate(&self) -> Result<(), String>
```

Validate the optional alternate Cleverbase origin before a signing session starts.

Alternate origins are for documented developer environments only. They must be absolute,
omit credentials, query, and fragment, and use HTTPS except for an explicitly loopback
HTTP endpoint used in local development. A path is permitted as a service base path.

#### struct `TsaConfiguration`

```rust
struct TsaConfiguration
```

Configuration for reaching an external qualified Time-Stamping Authority (required for B-T).

##### Fields

- `url: String`
  - RFC 3161 TSA endpoint URL the host POSTs the timestamp query to.
- `auth: Option<Secret>`
  - Optional `Authorization` header value for the TSA (sent verbatim).
- `policy_oid: Option<String>`
  - Optional TSA policy OID to constrain the timestamp request to.

### Enums

#### enum `ConformanceLevel`

```rust
enum ConformanceLevel
```

PAdES conformance level requested for a signature.

##### Variants

- `BB`
  - PAdES-B-B (basic): signed attributes, signing certificate, no trusted timestamp.
- `BT`
  - PAdES-B-T: B-B plus an RFC 3161 signature timestamp from a qualified TSA.

##### Methods

```rust
fn from_wire(s: &str) -> Option<Self>
```

Parse the wire string (`"B-B"` / `"B-T"`) used by the language bindings. `None` if unknown.

#### enum `CscApi`

```rust
enum CscApi
```

Which CSC API generation (selects signature algorithm + host).

##### Variants

- `V1Rsa`
  - CSC v1 (production), RSA signatures.
- `V2Ecdsa`
  - CSC v2 (beta), ECDSA P-256 signatures.

##### Methods

```rust
fn from_wire(s: &str) -> Option<Self>
```

Parse the wire string (`"v1_rsa"` / `"v2_ecdsa"`). `None` if unknown.

#### enum `Environment`

```rust
enum Environment
```

Which Cleverbase environment to target.

##### Variants

- `Acceptance`
  - Cleverbase acceptance (test) environment.
- `Production`
  - Cleverbase production environment.

##### Methods

```rust
fn from_wire(s: &str) -> Option<Self>
```

Parse the wire string (`"acceptance"` / `"production"`). `None` if unknown.

#### enum `MatchOn`

```rust
enum MatchOn
```

How an expected signer identity is matched against the authorizing certificate.
`name_and_dob` is deferred to a later phase (see data-model.md) and intentionally absent.

##### Variants

- `CertificateSerialNumber`
  - The credential certificate's serial number from CSC `credentials/info` or its leaf
certificate when CSC omits `cert.serialNumber`, canonicalized as uppercase hexadecimal
without separators or DER `00` sign padding. Default.
- `CleverbaseSubject`
  - The subject DN's `serialNumber` RDN — the stable natural-person identifier (e.g. `PNONL-…`).

## Module `util`

Small dependency-free helpers: hex, standard base64, percent-encoding, and civil-date math.

Kept local (rather than pulling extra crates) so the sans-IO core stays lean and WASM-friendly.

### Functions

#### fn `base64_decode`

```rust
fn base64_decode(input: &str) -> Result<Vec<u8>, &'static str>
```

Decode standard base64 (tolerates padding and embedded whitespace).

#### fn `base64_std`

```rust
fn base64_std(input: &[u8]) -> String
```

Standard (padded) base64 encoding.

#### fn `base64url_nopad`

```rust
fn base64url_nopad(input: &[u8]) -> String
```

URL-safe base64 without padding (RFC 4648 §5) — used for the CSC credential-authorization hash.

#### fn `civil_from_days`

```rust
fn civil_from_days(days: i64) -> (i64, i64, i64)
```

Civil date `(year, month, day)` from days since the Unix epoch (Howard Hinnant's algorithm).
Single source for the proleptic-Gregorian conversion (visible-appearance date + TSA genTime).

#### fn `days_from_civil`

```rust
fn days_from_civil(y: i64, m: i64, d: i64) -> i64
```

Days since the Unix epoch for a proleptic-Gregorian date — the inverse of [`civil_from_days`].

#### fn `percent_encode`

```rust
fn percent_encode(s: &str) -> String
```

RFC 3986 unreserved-only percent-encoding (safe for query parameters).

#### fn `to_hex`

```rust
fn to_hex(bytes: &[u8]) -> String
```

Lowercase hex encoding.

## Module `wire`

Versioned CBOR wire envelope for the C-ABI (Go) and WASM boundaries (contracts/sdk-api.md).

Native bindings (PyO3, napi-rs) call the typed Rust API directly; Go and WASM exchange these
CBOR-encoded envelopes. The envelope carries a `schema_version` so a binding can refuse a
payload it cannot read (Constitution Principle VII).

### Structs

#### struct `WireRequest`

```rust
struct WireRequest
```

Versioned request envelope.

##### Fields

- `schema_version: u32`
  - Wire schema version of this envelope.
- `op: WireOp`
  - The operation to perform.

#### struct `WireResponse`

```rust
struct WireResponse
```

Versioned response envelope.

##### Fields

- `schema_version: u32`
  - Wire schema version of this envelope.
- `result: WireResult`
  - The operation result.

### Enums

#### enum `WireOp`

```rust
enum WireOp
```

A decoded operation request from a non-native binding.

##### Variants

- `Begin { request: SigningRequest, config: TrustServiceConfiguration, ctx: HostContext }`
  - Begin a new signing flow.
- `Resume { handle: SigningSessionHandle, input: ResumeInput, ctx: HostContext }`
  - Resume an existing signing flow.

#### enum `WireResult`

```rust
enum WireResult
```

The result of a wire operation: a `(handle, step)` pair on success, or an error message.

##### Variants

- `Ok { handle: SigningSessionHandle, step: Step }`
  - Success: the updated session handle plus the next step.
- `Err { message: String }`
  - A usage/protocol error, rendered as a message.

### Functions

#### fn `decode_handle`

```rust
fn decode_handle(bytes: &[u8]) -> Result<SigningSessionHandle, String>
```

Decode an opaque handle (from the binding envelope) back into a session handle.

#### fn `decode_request`

```rust
fn decode_request(bytes: &[u8]) -> Result<WireRequest, String>
```

Decode a CBOR request envelope, rejecting unknown schema versions.

#### fn `encode_handle_step`

```rust
fn encode_handle_step(handle: &SigningSessionHandle, step: &Step) -> Vec<u8>
```

Encode `(handle, step)` as the binding envelope CBOR.

#### fn `encode_response`

```rust
fn encode_response(result: WireResult) -> Vec<u8>
```

Encode a CBOR response envelope at the current schema version.

## Constants

### const `SCHEMA_VERSION`

```rust
const SCHEMA_VERSION: u32 = 1
```

Wire schema version for the CBOR FFI/WASM boundary and the session handle.
