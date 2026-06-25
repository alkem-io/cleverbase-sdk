# Crate `cleverbase_attestation`

# cleverbase-attestation

The sans-IO EUDI **attestation** core of the Cleverbase SDK. It verifies presented EUDI
credentials in both mandated formats — **SD-JWT VC** (RFC 9901 / draft-16) and **ISO/IEC 18013-5
mdoc** — against EU trust anchors, and (forward-looking, gated) drives OpenID4VCI issuance and
OpenID4VP holder presentation via the integrator's signer-hook. Like `cleverbase-core` it is
**sans-IO** (no network in the core; trust lists are fetched/cached by a host-driven step and
passed in as anchors) and **pure-Rust / WASM-able** (no JVM, no OpenSSL-FFI).

See `specs/004-attestation-and-verification/` for the spec, plan, data-model, and contracts.

## Design constraints (from the plan)

- **No hand-rolled crypto** (Principle IV): signatures and digests go through the SDK's existing
  RustCrypto stack (`p256`/`ecdsa`/`rsa`/`sha2`/`x509-cert`/`cms`) plus `coset` for COSE.
- **One Rust core** (Principle III): all attestation logic lives here, surfaced over the existing
  `cleverbase-ffi` C-ABI; the bindings stay thin.
- **Not a wallet** (Principle IV): holder keys are the integrator's, exercised via the spec-001
  signer-hook; the SDK never holds a private key.

## Status

User Story 1 (feature 004 — the MVP) is implemented: the global [`verify()`] entry point assembles
the always-on bar over both format verifiers ([`sdjwtvc`], [`mdoc`]), the native EU trust-list
engine ([`trust`]), the revocation/[`status`] check (fail-closed by default), and the
[`openid4vp`] request binding (nonce + audience), surfaced over the `cleverbase-ffi` C-ABI via
[`wire`]. The opt-in [`qualified`]-status gate (T019) and the gated [`issuance`] path (US2)
remain stubs filled in by later tasks; [`verify::VerifyContext::qualified_gate`] is the off-by-
default seam for the former.

## Module `issuance`

Forward-looking, **gated** issuance + holder presentation (OpenID4VCI / OpenID4VP) — US2.

Drives OpenID4VCI `obtain` and holder OpenID4VP `present` through the spec-001 **signer-hook**
(research D8): the integrator's HSM/KMS signs out-of-process; the SDK never holds the holder
private key (not a wallet — FR-009). The issuer is a configurable backend ([`IssuerBackend`]); the
live path is **skipped** when no issuer API is configured (`kind = None`), so a future Cleverbase
issuer drops in by configuration.

## Sans-IO, mirroring the signing core

Like `cleverbase_core::signing`, issuance is a **sans-IO state machine driven by host effects**.
[`begin_obtain`]/[`resume_obtain`] mirror the signing core's `begin`/`resume`: each call returns
an [`ObtainStep`] describing the next host effect (an HTTP request, or a holder **sign** via the
[`Signer`] hook) and the core advances only when the host feeds the result back. The holder key
never enters the core — the **sign** step is the exact analogue of the CSC `signHash` HTTP effect
(the host signs off-box and returns the bytes; the SDK splices them in).

## Modules

- [`signer`] — the [`HolderContext`] + [`Signer`] hook and the deterministic [`SigningInput`]
  builders for the PoP-JWT / KB-JWT ceremonies (the splice helpers live with each builder).
- [`device`] — the mdoc `DeviceAuth` `DeviceSignature` ceremony (a detached COSE_Sign1).
- [`obtain`] — the configurable-backend OpenID4VCI flow + the **skip-when-`None`** gating.
- [`present`](mod@present) — the holder OpenID4VP present (selective disclosure, bound to the
  request).

### Module `device`

mdoc `DeviceAuth` `DeviceSignature` ceremony for the holder signer-hook (US2 — task T024).

The mdoc holder-binding signature is a **detached** COSE_Sign1 over the ISO/IEC 18013-5 §9.1.3
`DeviceAuthentication` structure (`["DeviceAuthentication", SessionTranscript, docType,
DeviceNameSpacesBytes]`, wrapped `#6.24`). Unlike the JOSE ceremonies, the to-be-signed bytes are
a COSE `Sig_structure`, built here with `coset::sig_structure_data` (a pure encoder — no key), and
the spliced result is a reconstructed `CoseSign1` whose detached signature the verifier checks
with [`crate::mdoc`].

The `aud`/`nonce` the holder binds are folded into the session-transcript handover (the same
[`crate::openid4vp::oid4vp_handover_transcript`] the verifier reconstructs), so the
[`crate::issuance::signer::SigningInput`] surfaces them for host policy inspection even though the
signed COSE payload carries them only as a hash.

#### Structs

##### struct `DeviceSignatureBuild`

```rust
struct DeviceSignatureBuild
```

A built mdoc `DeviceSignature` input, plus the splice context (the protected header + payload) to
reconstruct the detached COSE_Sign1 once the host has signed the `Sig_structure`.

###### Fields

- `input: SigningInput`
  - The signing input the host must sign (exposes the verifier `aud`/`nonce`).
- `device_auth_payload: Vec<u8>`
  - The `#6.24(bstr .cbor DeviceAuthentication)` detached payload (kept so the verifier-side and a
caller assembling the `DeviceResponse` use the identical bytes).

###### Methods

```rust
fn assemble(&self, signature: &[u8]) -> Result<Vec<u8>, SignerError>
```

Splice the host-returned `r‖s` ES256 signature into a detached `DeviceSignature` COSE_Sign1,
returning its CBOR encoding (the `deviceAuth.deviceSignature` value).

# Errors

[`SignerError::BadSignatureLength`] if the signature is not the algorithm's expected length;
[`SignerError::Serialize`] on a (here impossible) COSE re-encode failure.

#### Functions

##### fn `build_device_signature`

```rust
fn build_device_signature(doc_type: &str, session_transcript: &[u8], audience: &str, nonce: &str) -> Result<DeviceSignatureBuild, SignerError>
```

Build the mdoc `DeviceSignature` signing input over the `DeviceAuthentication` for `doc_type`,
bound to a session-transcript handover that folds in `audience`/`nonce`.

`session_transcript` is the CBOR `SessionTranscript` the holder signs over (for OpenID4VP, the
[`crate::openid4vp::oid4vp_handover_transcript`] of `audience`+`nonce`); the empty
`DeviceNameSpaces` (`#6.24(bstr .cbor {})`) is used (the device discloses no extra namespaces).
The host signs [`DeviceSignatureBuild::input`]; [`DeviceSignatureBuild::assemble`] splices the
result.

# Errors

[`SignerError::Serialize`] on a (here impossible) CBOR-encode failure of an in-memory value.

### Module `obtain`

OpenID4VCI `obtain` — a sans-IO, host-effect-driven issuance state machine (US2 — task T025).

Mirrors the signing core's `begin`/`resume` + `Step`/effect shape (research D8, Principle III):
[`begin_obtain`] starts the OpenID4VCI ceremony and [`resume_obtain`] advances it given the result
of the last host effect. The core performs **no I/O**; it returns an [`ObtainStep`] describing what
the host must do next — an HTTP request, or a **holder sign** (the PoP proof, the exact analogue of
the CSC `signHash` effect: the host's HSM signs the SDK-built `signing_input` and feeds the bytes
back; the SDK splices them).

## Configurable backend + skip-when-`None` gating (FR-008)

The issuer is an [`IssuerBackend`] with a [`kind`](IssuerBackendKind): `None` (default) → the flow
is **skipped** ([`ObtainStep::Skipped`], a clear skipped outcome, **never a failure**); `Reference`
→ the EU `eudi-srv-pid-issuer` test double; `Cleverbase` → a future drop-in (enabled by
configuration only). The flow logic is identical across `Reference`/`Cleverbase` — only the
endpoints differ — so a future Cleverbase issuer needs no rework of the holder flow (SC-005).

## Flow (pre-authorized-code grant)

`credential offer (pre-authorized_code)` → POST token endpoint → `Sign` the OpenID4VCI proof-JWT
(PoP) via the signer-hook → POST credential endpoint with the proof → parse the issued SD-JWT VC /
mdoc into a [`HeldAttestation`]. The pre-authorized-code grant is the self-contained flow the
reference issuer supports without an interactive browser leg.

#### Structs

##### struct `CredentialOffer`

```rust
struct CredentialOffer
```

An OpenID4VCI credential offer (the pre-authorized-code path — the self-contained grant the
reference issuer supports). The `credential_configuration_id` selects which credential to request
(and its [`Format`]).

###### Fields

- `pre_authorized_code: String`
  - The OpenID4VCI `pre-authorized_code` from the offer's grant.
- `credential_configuration_id: String`
  - The credential configuration id to request (e.g. `eu.europa.ec.eudi.pid_vc_sd_jwt`).
- `format: Format`
  - The format of the credential this configuration issues (so the SDK parses the right shape).

##### struct `HttpEffect`

```rust
struct HttpEffect
```

An HTTP request the host must perform on the core's behalf (mirrors the signing core's
`HttpEffect`; the core stays sans-IO). The host performs it and feeds the response back via
[`resume_obtain`].

###### Fields

- `method: HttpMethod`
  - HTTP method.
- `url: String`
  - Absolute request URL.
- `headers: Vec<(String, String)>`
  - Request headers as `(name, value)` pairs.
- `body: Vec<u8>`
  - Request body bytes (form-encoded for the token endpoint; JSON for the credential endpoint).

##### struct `IssuerBackend`

```rust
struct IssuerBackend
```

The configured issuer backend: the [`kind`](IssuerBackendKind) plus the OpenID4VCI endpoints the
flow drives (ignored when `kind = None`).

###### Fields

- `kind: IssuerBackendKind`
  - Which issuer API this backend targets.
- `token_endpoint: String`
  - The OpenID4VCI **token** endpoint (the pre-authorized-code grant is exchanged here).
- `credential_endpoint: String`
  - The OpenID4VCI **credential** endpoint (the credential request — with the PoP proof — is POSTed
here).
- `credential_issuer: String`
  - The credential-issuer identifier the PoP-JWT `aud` must be addressed to.

###### Methods

```rust
fn none() -> Self
```

A `None` backend — issuance is skipped (the default; no endpoints needed).

##### struct `ObtainSession`

```rust
struct ObtainSession
```

An in-flight `obtain` session: the carried state between effects (the analogue of the signing
core's `SigningSessionHandle`). Holds **no** private key — only the holder public context, the
backend config, and the OpenID4VCI access token + the in-progress PoP material.

#### Enums

##### enum `HttpMethod`

```rust
enum HttpMethod
```

HTTP method for an [`HttpEffect`] (the issuance flow uses POST for both endpoints).

###### Variants

- `Get`
  - HTTP GET.
- `Post`
  - HTTP POST.

##### enum `IssuerBackendKind`

```rust
enum IssuerBackendKind
```

Which issuer API the flow targets (data-model.md `IssuerBackend.kind`).

###### Variants

- `None`
  - No issuer API configured — the issuance path is **skipped** (the default; Cleverbase ships no
EUDI issuer API today, so this is the honest default — FR-008/SC-006).
- `Reference`
  - The EU `eudi-srv-pid-issuer` reference test double (issues SD-JWT VC + mso_mdoc).
- `Cleverbase`
  - A future Cleverbase EUDI issuer API — a drop-in enabled by configuration only (SC-005).

##### enum `ObtainError`

```rust
enum ObtainError
```

A usage/protocol error from the `obtain` flow (distinct from the terminal [`ObtainStep::Failed`]
outcome, which carries this).

###### Variants

- `UnexpectedInput`
  - The [`ResumeObtain`] input did not match what the current phase expects.
- `AlreadyTerminal`
  - The session was resumed past a terminal phase.
- `TokenRequest(String)`
  - The token endpoint returned a non-success status or an unparseable body.
- `CredentialRequest(String)`
  - The credential endpoint returned a non-success status or an unparseable body.
- `Proof(String)`
  - The PoP-JWT signing input could not be built.

##### enum `ObtainStep`

```rust
enum ObtainStep
```

The next host effect (or terminal outcome) of an `obtain` step — mirrors the signing core's
`Step`. The core returns exactly one of these and advances only when the host feeds the result
back via [`resume_obtain`].

###### Variants

- `PerformHttp(HttpEffect)`
  - Perform this HTTP request, then [`resume_obtain`] with the response.
- `Sign(SigningInput)`
  - **Sign** this PoP-JWT signing input with the holder key (the signer-hook effect — the SDK
never holds the key), then [`resume_obtain`] with the raw `r‖s` ES256 signature. The
[`SigningInput`] exposes the issuer `aud`/`c_nonce` for host policy inspection.
- `Skipped`
  - Terminal: the issuance path is **skipped** because no issuer API is configured
(`kind = None`) — a clear skipped outcome, never a failure (FR-008).
- `Obtained(HeldAttestation)`
  - Terminal success: the issued, parsed [`HeldAttestation`] (verifiable under US1).
- `Failed(ObtainError)`
  - Terminal failure (a protocol error from the issuer, or a malformed response).

###### Methods

```rust
const fn is_terminal(&self) -> bool
```

Whether this step is terminal (the flow does not resume past [`Self::Skipped`] /
[`Self::Obtained`] / [`Self::Failed`]).

##### enum `ResumeObtain`

```rust
enum ResumeObtain
```

The result the host feeds back into [`resume_obtain`].

###### Variants

- `Http { status: u16, body: Vec<u8> }`
  - The response to a prior [`ObtainStep::PerformHttp`].
- `Signature(Vec<u8>)`
  - The raw `r‖s` ES256 signature for a prior [`ObtainStep::Sign`] (the holder PoP proof).

#### Functions

##### fn `begin_obtain`

```rust
fn begin_obtain(offer: CredentialOffer, backend: IssuerBackend, holder: HolderContext, now_unix: i64) -> (ObtainSession, ObtainStep)
```

Begin an OpenID4VCI `obtain` flow.

When `backend.kind == None`, returns [`ObtainStep::Skipped`] (the issuance path is skipped, never
failed — FR-008) and a session that is already terminal. Otherwise returns the first effect: the
token-endpoint POST (the pre-authorized-code grant).

##### fn `resume_obtain`

```rust
fn resume_obtain(session: ObtainSession, input: ResumeObtain) -> Result<(ObtainSession, ObtainStep), ObtainError>
```

Advance an `obtain` flow given the result of the last effect.

# Errors

Returns [`ObtainError`] for a usage error (a resume that does not match the current phase, or a
resume past a terminal step). A *protocol* failure (issuer error, malformed response) is the
terminal [`ObtainStep::Failed`] outcome, not an `Err`.

### Module `present`

Holder OpenID4VP `present` — build a selectively-disclosed presentation bound to the verifier's
request via the signer-hook (US2 — task T026).

[`present`] takes a [`HeldAttestation`] (an obtained SD-JWT VC / mdoc), the verifier's
[`PresentationRequest`], the [`HolderContext`] + [`Signer`] hook, and the subset of claims to
disclose, and produces a `vp_token` that **verifies under** [`crate::openid4vp::verify_response`]
(the round-trip oracle). Holder binding is built by the signer-hook — the SDK never holds the
private key (FR-009):

- **SD-JWT VC** — the SDK conceals the undisclosed claims, computes the KB-JWT signing input
  (`aud`/`nonce`/`sd_hash`) over the resulting presentation prefix, the host signs it, and the SDK
  splices the compact KB-JWT onto the presentation.
- **mdoc** — the SDK reconstructs the `DeviceAuthentication` over the request's OID4VP handover
  (`audience`+`nonce`), the host signs the COSE `Sig_structure`, and the SDK splices a fresh
  detached `DeviceSignature` into the held `DeviceResponse`.

#### Structs

##### struct `PreparedPresentation`

```rust
struct PreparedPresentation
```

A holder presentation prepared up to (but not including) the holder signature: it carries the
[`SigningInput`](super::signer::SigningInput) the host must sign and the splice context to
assemble the final [`HolderPresentation`].

This is the two-step seam that mirrors the signing core's begin/resume: [`prepare_present`] builds
it (returning the input to sign), then [`PreparedPresentation::finish`] splices the host signature
into the `vp_token`. The one-shot [`present`] (with an in-process [`Signer`]) is a thin wrapper
over the two — DRY, and the same code path backs the C-ABI's `BeginPresent`/`FinishPresent`.

###### Methods

```rust
fn finish(&self, signature: &[u8]) -> Result<HolderPresentation, PresentError>
```

Splice the host-returned `r‖s` ES256 signature into the final [`HolderPresentation`].

# Errors

[`PresentError`] when the signature does not splice (wrong length) or the envelope re-encode
fails.

```rust
fn signing_input(&self) -> &SigningInput
```

The signing input the host must sign with the holder key (exposes the verifier `aud`/`nonce`).

#### Enums

##### enum `HeldAttestation`

```rust
enum HeldAttestation
```

A held (obtained) attestation the holder can present (the output of [`super::obtain`], or any
credential the integrator already holds). Carries the encoded credential only — no key.

###### Variants

- `SdJwtVc { issued: String }`
  - An issued SD-JWT VC: the compact `<issuer-JWS>~<D.1>~…~<D.N>~` string (issuer JWS + **all**
the issued disclosures, no KB-JWT yet — the holder selects + binds at presentation time).
- `Mdoc { device_response: Vec<u8> }`
  - An issued mdoc: the CBOR `DeviceResponse` (the issuer-signed parts + a placeholder
`DeviceSignature` the holder replaces, bound to the verifier's request, at presentation time).

##### enum `HolderPresentation`

```rust
enum HolderPresentation
```

An owned holder OpenID4VP `vp_token`, the output of [`present`]. The caller borrows it as a
[`VpToken`] via [`HolderPresentation::as_vp_token`] to verify it under
[`crate::openid4vp::verify_response`] (the round-trip), or carries it on the wire.

Owning the bytes (rather than returning a borrowed [`VpToken`]) keeps `present` allocation-honest:
no leaked `'static` borrow, and the same value serializes onto the C-ABI.

###### Variants

- `SdJwtVc { vp_token: String }`
  - A compact SD-JWT VC presentation string (`<issuer-JWS>~<D>…~<KB-JWT>`).
- `Mdoc { audience: String, device_response: Vec<u8> }`
  - An mdoc `vp_token`: the rebuilt `DeviceResponse` plus the addressed audience.

###### Methods

```rust
fn as_vp_token(&self) -> VpToken<'_>
```

Borrow this presentation as a [`VpToken`] for [`crate::openid4vp::verify_response`].

##### enum `PresentError`

```rust
enum PresentError
```

An error building a holder presentation.

###### Variants

- `Malformed(String)`
  - The held credential could not be parsed.
- `UndisclosableClaim(String)`
  - A requested disclosed claim is not present in the held credential.
- `Signer(String)`
  - The signer-hook failed (the host's error rendered as a message).
- `Build(String)`
  - Building or splicing a ceremony envelope failed.

#### Functions

##### fn `prepare_present`

```rust
fn prepare_present(held: &HeldAttestation, request: &PresentationRequest, disclose: &BTreeSet<String>, iat: i64) -> Result<PreparedPresentation, PresentError>
```

Prepare a holder presentation for the held attestation, disclosing only `disclose`, bound to the
verifier's `request` — up to the holder signature (the two-call seam; the host signs
[`PreparedPresentation::signing_input`] and calls [`PreparedPresentation::finish`]).

# Errors

[`PresentError`] when the held credential is malformed, a requested claim is not disclosable, or
building the ceremony envelope fails.

##### fn `present`

```rust
fn present<S: Signer>(held: &HeldAttestation, request: &PresentationRequest, _holder: &HolderContext, disclose: &BTreeSet<String>, signer: &S, iat: i64) -> Result<HolderPresentation, PresentError> where <S>::Error: Display
```

Build an OpenID4VP `vp_token` for the held attestation, disclosing only `disclose`, bound to the
verifier's `request` via the holder signer-hook.

The produced [`HolderPresentation`] **verifies under** [`crate::openid4vp::verify_response`]
against the same `request` (the round-trip), revealing only the `disclose` subset. `iat` is the
holder's signing instant (the KB-JWT `iat`). A thin wrapper over [`prepare_present`] +
[`PreparedPresentation::finish`] with an in-process [`Signer`].

# Errors

[`PresentError`] when the held credential is malformed, a requested claim is not disclosable, or
the signer-hook / envelope build fails.

### Module `signer`

Holder signer-hook + `HolderContext` (US2 — task T024).

The SDK is **not a wallet** (FR-009): it never generates, imports, holds, or sees the holder
private key. This module is the **signer-hook** — a direct reuse of the spec-001 remote-signing
pattern (research D8, Principle III/VIII): the integrator supplies (1) the holder **public** key
and (2) a [`Signer`] callback that signs out-of-process (their HSM/KMS), exactly as the CSC
`signHash` flow signs the SDK-built CMS `SignedAttributes` digest off-box.

The SDK builds the **exact, deterministic** [`SigningInput`] for each EUDI ceremony —

- the **OpenID4VCI** proof-of-possession JWT (`typ: openid4vci-proof+jwt`),
- the **SD-JWT VC** holder Key-Binding JWT (`typ: kb+jwt`), and
- the **mdoc** `DeviceAuth` `DeviceSignature` (a detached COSE_Sign1 over `DeviceAuthentication`)

— and splices the host-returned signature back into the envelope (the compact JWS, or the
COSE_Sign1). Each [`SigningInput`] exposes the `aud`/`nonce` it binds ([`SigningInput::audience`]
/ [`SigningInput::nonce`]) so the host can apply policy before it blind-signs (the same
blind-signing trust boundary the CSC flow documents — RCA: a deterministic input + exposed
`aud`/`nonce` is what lets the host refuse a mis-scoped request).

## Sans-IO seam

[`Signer::sign`] is synchronous (the core is sans-IO and never blocks on I/O): a host with an
async HSM drives its future to completion behind this seam, exactly as the signing core's host
performs the `signHash` HTTP effect and feeds the bytes back. The signature is the raw fixed-width
`r‖s` ES256 form (64 bytes) — the encoding both the compact-JWS and COSE_Sign1 envelopes carry.

#### Structs

##### struct `HolderContext`

```rust
struct HolderContext
```

The integrator-supplied holder context (data-model.md `HolderContext`).

Carries the holder **public** key (a JWK, the issuer-bound `cnf` for SD-JWT VC / the source of the
mdoc `DeviceKey` COSE_Key) and an opaque `handle` the host's [`Signer`] uses to select the
matching private key in its HSM/KMS. **No private key** is present — the SDK never holds one
(FR-009).

###### Fields

- `holder_public_jwk: Value`
  - The holder's public key as a JWK (`kty=EC`, `crv=P-256`, base64url `x`/`y`). This is what the
issuer binds in the credential's `cnf` (SD-JWT VC) / MSO `deviceKey` (mdoc); the SDK reads the
public point from it but never a private component.
- `key_handle: String`
  - An opaque handle the host's [`Signer`] maps to the holder private key in its HSM/KMS (the SDK
passes it through to [`Signer::sign`] and never interprets it).

###### Methods

```rust
fn cnf(&self) -> Value
```

The holder public key as a `cnf` confirmation object (`{"jwk": <public JWK>}`, RFC 7800) — the
shape an SD-JWT VC issuer embeds so the verifier can check the KB-JWT against the bound key.

```rust
fn new<impl Into<String>: Into<String>>(holder_public_jwk: Value, key_handle: impl Into<String>) -> Self
```

Construct a holder context from a public JWK and a host key handle.

```rust
fn public_sec1(&self) -> Option<Vec<u8>>
```

The raw uncompressed SEC1 public point (`0x04 ‖ X ‖ Y`, 65 bytes) of the holder key, decoded
from its JWK `x`/`y`, or `None` when the JWK is not a P-256 EC public key. Used to derive the
mdoc `DeviceKey` COSE_Key.

##### struct `KbJwtBuild`

```rust
struct KbJwtBuild
```

A built SD-JWT VC Key-Binding JWT input, plus the splice context to assemble the compact KB-JWT
(`typ: kb+jwt`) and append it to the SD-JWT presentation prefix.

###### Fields

- `input: SigningInput`
  - The signing input the host must sign (exposes the verifier `aud`/`nonce`).

###### Methods

```rust
fn assemble(&self, signature: &[u8]) -> Result<String, SignerError>
```

Splice the host-returned `r‖s` ES256 signature into the compact KB-JWT.

# Errors

[`SignerError::BadSignatureLength`] if the signature is not the algorithm's expected length.

##### struct `PopJwtBuild`

```rust
struct PopJwtBuild
```

A built OpenID4VCI proof-of-possession JWT input, plus the splice context to assemble the compact
JWS once the host has signed it.

###### Fields

- `input: SigningInput`
  - The signing input the host must sign (exposes `aud`/`nonce`).

###### Methods

```rust
fn assemble(&self, signature: &[u8]) -> Result<String, SignerError>
```

Splice the host-returned `r‖s` ES256 signature into the compact PoP-JWT.

# Errors

[`SignerError::BadSignatureLength`] if the signature is not the algorithm's expected length.

##### struct `SigningInput`

```rust
struct SigningInput
```

The exact, deterministic bytes the host signs for one ceremony, plus the `aud`/`nonce` it binds
(exposed for host-side policy inspection — the blind-signing trust boundary, RCA-documented).

The SDK builds this; the host signs [`SigningInput::to_be_signed`] out-of-process and the SDK
splices the signature back via the matching builder. The struct **carries no private key** — it
is pure public material (the bytes to sign + the bound `aud`/`nonce`), so logging it leaks nothing
secret.

###### Methods

```rust
const fn algorithm(&self) -> SignatureAlgorithm
```

The algorithm the host must sign with.

```rust
fn audience(&self) -> &str
```

The `aud` this input binds (the issuer's identifier for a PoP-JWT; the verifier's `client_id`
for a KB-JWT / `DeviceSignature`) — exposed so the host can refuse a mis-scoped request before
it blind-signs.

```rust
const fn ceremony(&self) -> Ceremony
```

The ceremony this input belongs to.

```rust
fn nonce(&self) -> &str
```

The `nonce` this input binds (the issuer `c_nonce` for a PoP-JWT; the verifier's request nonce
for a KB-JWT / `DeviceSignature`) — exposed for the same host-policy reason as
[`Self::audience`].

```rust
fn to_be_signed(&self) -> &[u8]
```

The exact bytes to sign (the JOSE `header.payload` ASCII signing input, or the COSE `Sig_structure`
`to_be_signed`). The host signs **these bytes verbatim**; the SDK splices the result.

#### Enums

##### enum `Ceremony`

```rust
enum Ceremony
```

The ceremony a [`SigningInput`] belongs to (so a host policy can branch on it, and so the splice
helpers reject a mismatched signature). Each ceremony binds `aud`/`nonce` differently — exposed
uniformly via [`SigningInput::audience`] / [`SigningInput::nonce`].

###### Variants

- `Oid4vciProof`
  - The OpenID4VCI proof-of-possession JWT (`typ: openid4vci-proof+jwt`) — binds the issuer's
`aud` and the issuer-supplied `c_nonce`.
- `KeyBinding`
  - The SD-JWT VC holder Key-Binding JWT (`typ: kb+jwt`) — binds the verifier's `aud` and the
request `nonce`.
- `DeviceSignature`
  - The mdoc `DeviceAuth` `DeviceSignature` (detached COSE_Sign1 over `DeviceAuthentication`) —
binds the verifier's `aud` and `nonce` cryptographically inside the session-transcript
handover the signed payload covers (so they are surfaced here for host inspection even though
the COSE payload carries them as a hash, not as cleartext fields).

##### enum `SignatureAlgorithm`

```rust
enum SignatureAlgorithm
```

The signature algorithm the holder key signs with. The EUDI baseline mandates **ES256** (ECDSA /
P-256 / SHA-256 — HAIP 1.0 §7; research D1) for both the JOSE (PoP-JWT / KB-JWT) and the COSE
(`DeviceSignature`) ceremonies, so it is the only variant the signer-hook builds inputs for; any
other algorithm is a future extension (kept a closed enum so an unsupported `alg` is a type error,
never a guess).

###### Variants

- `Es256`
  - ECDSA over P-256 with SHA-256 (the EUDI mandatory baseline).

###### Methods

```rust
const fn jose_alg(self) -> &'static str
```

The JOSE `alg` header value (RFC 7518) for a compact JWS signed with this algorithm.

##### enum `SignerError`

```rust
enum SignerError
```

An error building a signing input or splicing a signature back into an envelope.

###### Variants

- `CeremonyMismatch`
  - The host returned a signature whose ceremony does not match the input it was built for.
- `BadSignatureLength(SignatureAlgorithm, usize)`
  - The host returned a signature of the wrong length for the algorithm (ES256 raw `r‖s` is 64
bytes).
- `Serialize(String)`
  - A JSON value could not be serialized while building the input (an impossible failure on plain
in-memory `serde_json::Value`s; surfaced rather than swallowed).

#### Traits

##### trait `Signer`

```rust
trait Signer
```

The holder key-custody seam (research D8). The integrator implements this over their HSM/KMS; the
SDK calls [`Signer::sign`] with a SDK-built [`SigningInput`] and never touches a private key.

Implementations sign [`SigningInput::to_be_signed`] and return the **raw fixed-width `r‖s`** ES256
signature (64 bytes for P-256) — the encoding both the compact JWS and the COSE_Sign1 envelopes
carry. The method is synchronous (sans-IO): a host with an async signer drives its future to
completion behind this call.

```rust
fn sign(&self, handle: &str, input: &SigningInput) -> Result<Vec<u8>, <Self>::Error>
```

Sign `input.to_be_signed()` with the holder key bound to `handle`, returning the raw `r‖s`
ES256 signature.

# Errors

Returns the host signer's error when the signature cannot be produced (key unavailable, policy
refusal after inspecting `input.audience()`/`input.nonce()`, transport failure, …).

#### Functions

##### fn `build_kb_jwt`

```rust
fn build_kb_jwt(audience: &str, nonce: &str, iat: i64, presentation_prefix: &str) -> Result<KbJwtBuild, SignerError>
```

Build the SD-JWT VC **Key-Binding JWT** signing input (`typ: kb+jwt`, RFC 9901 §4.3). Binds the
verifier's `audience` (`aud`) and request `nonce`, plus the `sd_hash` over the presentation prefix
(the issuer-JWS-plus-selected-disclosures, up to and including the final `~`).

`sd_hash` is computed as the base64url SHA-256 of `presentation_prefix` (the bytes the verifier
recomputes — see [`crate::sdjwtvc`]'s holder-binding check). The host signs [`KbJwtBuild::input`]
and [`KbJwtBuild::assemble`] produces the compact KB-JWT to append after the prefix.

# Errors

[`SignerError::Serialize`] on the (impossible) JSON-serialization failure of an in-memory value.

##### fn `build_pop_jwt`

```rust
fn build_pop_jwt(holder: &HolderContext, audience: &str, c_nonce: &str, iat: i64) -> Result<PopJwtBuild, SignerError>
```

Build the OpenID4VCI **proof-of-possession** JWT signing input (`typ: openid4vci-proof+jwt`,
draft OpenID4VCI 1.0 §8.2.1.1). Binds the credential-issuer `audience` and the issuer-supplied
`c_nonce`; the holder public key travels in the `jwk` header so the issuer binds it as the
credential's `cnf`.

The host signs [`PopJwtBuild::input`] and [`PopJwtBuild::assemble`] splices the result.

# Errors

[`SignerError::Serialize`] on the (impossible) JSON-serialization failure of an in-memory value.

### Module `wire`

Versioned CBOR wire envelope for the **issuance** C-ABI surface (US2 — task T028).

Mirrors the `verify` envelope (`crate::wire`) and `cleverbase_core::wire`: the C-ABI and the
non-native bindings exchange these CBOR-encoded envelopes; native callers use the typed Rust API
([`super::begin_obtain`] / [`super::resume_obtain`] / [`super::prepare_present`]) directly.

The issuance flow is **sans-IO + host-effect-driven** (mirroring the signing core's begin/resume),
so the wire carries the same shape: an [`IssuanceOp`] (one of `BeginObtain`, `ResumeObtain`,
`BeginPresent`, `FinishPresent`) in, and the next step ([`WireObtainStep`], or the `PreparePresent`
/ `Present` outcome) plus the opaque session/prepared **handle** out. The holder key never crosses
this boundary: a `Sign` effect surfaces the [`SigningInput`] the host signs out-of-process, and
the host feeds the raw `r‖s` signature back via a resume op.

This is a **separate, additive** envelope from the `verify` one (which stays at its own schema
version), surfaced by a new C-ABI function — so the verifier surface is untouched (Principle VII).

#### Structs

##### struct `IssuanceRequest`

```rust
struct IssuanceRequest
```

An issuance request envelope.

###### Fields

- `schema_version: u32`
  - Wire schema version.
- `op: IssuanceOp`
  - The issuance operation.

##### struct `IssuanceResponse`

```rust
struct IssuanceResponse
```

An issuance response envelope.

###### Fields

- `schema_version: u32`
  - Wire schema version.
- `outcome: IssuanceOutcome`
  - The operation outcome.

#### Enums

##### enum `IssuanceOp`

```rust
enum IssuanceOp
```

An issuance operation carried on the wire.

###### Variants

- `BeginObtain { offer: CredentialOffer, backend: IssuerBackend, holder: HolderContext, now_unix: i64 }`
  - Begin an OpenID4VCI `obtain` flow (the offer + the configured backend + the holder context).
- `ResumeObtain { session: ObtainSession, input: WireResumeObtain }`
  - Resume an `obtain` flow with the result of the last effect (an HTTP response, or the holder
PoP signature).
- `BeginPresent { held: HeldAttestation, request: PresentationRequest, disclose: Vec<String>, iat: i64 }`
  - Begin a holder OpenID4VP `present` flow — prepare the presentation up to the holder signature
(the returned `Sign` effect).
- `FinishPresent { prepared: PreparedPresentation, signature: Vec<u8> }`
  - Finish a `present` flow by splicing the holder signature into the `vp_token`.

##### enum `IssuanceOutcome`

```rust
enum IssuanceOutcome
```

The outcome of an issuance operation.

###### Variants

- `Obtain { step: WireObtainStep, session: Option<ObtainSession> }`
  - An `obtain` step: the next step + the (opaque) session handle to carry into the next resume.
- `PreparePresent { input: SigningInput, prepared: PreparedPresentation }`
  - A `BeginPresent` step: the `Sign` input + the opaque prepared handle to carry into
`FinishPresent`.
- `Present { presentation: HolderPresentation }`
  - A `FinishPresent` step: the produced `vp_token`.
- `Err { message: String }`
  - A decode/usage error rendered as a message.

##### enum `WireObtainStep`

```rust
enum WireObtainStep
```

The next step of an `obtain` flow, on the wire (the CBOR mirror of [`ObtainStep`]).

###### Variants

- `PerformHttp { effect: HttpEffect }`
  - Perform this HTTP request, then resume with the response.
- `Sign { input: SigningInput }`
  - Sign this PoP input with the holder key, then resume with the signature.
- `Skipped`
  - Terminal: the flow was skipped (no issuer API configured).
- `Obtained { held: HeldAttestation }`
  - Terminal: the obtained credential.
- `Failed { message: String }`
  - Terminal: a protocol failure (rendered as a message).

##### enum `WireResumeObtain`

```rust
enum WireResumeObtain
```

The resume input for an `obtain` flow, on the wire.

###### Variants

- `Http { status: u16, body: Vec<u8> }`
  - The response to a prior HTTP effect.
- `Signature { signature: Vec<u8> }`
  - The raw `r‖s` ES256 holder PoP signature for a prior `Sign` effect.

#### Functions

##### fn `decode_issuance_request`

```rust
fn decode_issuance_request(bytes: &[u8]) -> Result<IssuanceRequest, String>
```

Decode an issuance request envelope, rejecting unknown schema versions.

# Errors

Returns the decode error (or a schema-version mismatch message) as a `String`.

##### fn `encode_issuance_response`

```rust
fn encode_issuance_response(outcome: IssuanceOutcome) -> Vec<u8>
```

Encode an issuance response envelope at the current schema version.

##### fn `process_issuance_bytes`

```rust
fn process_issuance_bytes(input: &[u8]) -> Vec<u8>
```

Decode → dispatch → encode. Pure; shared by the C-ABI, language bindings, and tests (single source
of truth — Principle III).

#### Constants

##### const `ISSUANCE_SCHEMA_VERSION`

```rust
const ISSUANCE_SCHEMA_VERSION: u32 = 1
```

Wire schema version of the **issuance** envelope (independent of the `verify` envelope's
`ATTESTATION_SCHEMA_VERSION` and the signing core's `SCHEMA_VERSION`). Version 1 is the initial
`obtain`/`present` surface.

## Module `mdoc`

ISO/IEC 18013-5 mdoc verification.

Verifies a presented mdoc `DeviceResponse` against the always-on bar (contracts/verifier.md),
owning the security-critical checks the only Rust mdoc library omits (research D3):

1. **`IssuerAuth` signature** — the `COSE_Sign1` over the Mobile Security Object (MSO) is verified
   with the Document Signer (DS) certificate's public key (ES256, via the SDK's `p256`/`ecdsa`),
   and the DS certificate is resolved from the `x5chain` COSE header and checked for trust through
   the pluggable [`crate::trust::TrustAnchorSource`] (the IACA root).
2. **`valueDigests` integrity (in-house)** — each disclosed `IssuerSignedItem` is re-hashed (with
   the MSO `digestAlgorithm`) over its tagged-CBOR (`#6.24`) byte string and matched against the
   MSO `valueDigests`; any mismatch is rejected. This is the selective-disclosure-integrity check.
3. **MSO `validityInfo` (in-house)** — the `signed` / `validFrom` / `validUntil` bounds are
   enforced at the verification instant.
4. **`DeviceAuth` holder binding** — the `DeviceSignature` `COSE_Sign1` over the
   `DeviceAuthentication` structure (including the session transcript) is verified against the MSO
   `DeviceKey`. (The `DeviceMac` / ECDH variant is a documented follow-on — research D8.)

Every failure path yields a specific [`crate::types::ReasonCode`] and never a false-accept
(SC-002). The module is **sans-IO** — it works from the passed `DeviceResponse` bytes, the
configured anchors, and (optionally) the session transcript alone, with no network.

All crypto routes through the SDK's vetted RustCrypto stack plus `coset` (a COSE *codec*, not
crypto) and `ciborium` (CBOR) — no hand-rolled crypto (Principle IV).

### Structs

#### struct `MdocVerifyParams`

```rust
struct MdocVerifyParams<'a>
```

The verification instant and the optional session transcript needed to verify an mdoc.

`now_unix` is the time (Unix seconds) at which the MSO `validityInfo` window is enforced — passed
in (sans-IO) rather than read from the system clock so verification is deterministic and testable.
`session_transcript` is the CBOR-encoded `SessionTranscript` the holder's `DeviceSignature` is
computed over; it is supplied by the transport/OpenID4VP layer. When `None`, the verifier treats
the holder binding as bound to an empty transcript (the value the test issuer and a transport-less
presentation agree on).

##### Fields

- `now_unix: i64`
  - The verification instant, in Unix seconds, at which `validityInfo` is enforced.
- `session_transcript: Option<&'a [u8]>`
  - The CBOR-encoded ISO/IEC 18013-5 `SessionTranscript` the `DeviceSignature` is bound to.
- `role: IssuerRole`
  - The issuer role under which DS trust is resolved against the anchors (mdoc anchors to an IACA
root; the role selects the per-role/format anchor set).
- `status: StatusOutcome`
  - The revocation/status outcome (the T014 seam) — the canonical [`StatusOutcome`] the
[`verify()`](crate::verify()) entry point resolves through the host status source. Mirrors the SD-JWT VC
status seam so the always-on bar's revocation check covers both formats.

### Functions

#### fn `issuer_signing_cert_der`

```rust
fn issuer_signing_cert_der(device_response: &[u8]) -> Option<Vec<u8>>
```

Extract the Document Signer signing certificate (DER) a presented mdoc claims in its `IssuerAuth`
`x5chain`, without verifying anything (the opt-in [`crate::qualified`] gate matches this leaf
against the national Trusted List's `EAA/Q` service entries).

Returns `None` when the `DeviceResponse` does not parse or carries no `x5chain` leaf. The value is
*claimed* (its trust + signature are decided by the always-on bar in [`verify`]); this read is
only the gate's cert-matching input, never an acceptance.

#### fn `verify`

```rust
fn verify<A: TrustAnchorSource + ?Sized>(device_response: &[u8], anchors: &A, params: &MdocVerifyParams<'_>) -> VerificationResult
```

Verify a presented ISO/IEC 18013-5 mdoc `DeviceResponse`.

Runs the mdoc always-on bar — `IssuerAuth` signature + DS trust, in-house `valueDigests`
integrity, MSO `validityInfo`, and the `DeviceAuth` holder binding — over the first document in
the response. Returns a [`VerificationResult`]: `valid = true` with the disclosed attributes when
every check passes, or `valid = false` carrying a single specific [`ReasonCode`] on the first
failure (no false-accept — SC-002).

`anchors` is the configured trust-anchor source (the IACA root for mdoc); `params` carries the
verification instant, the session transcript for the holder binding, and the issuer role.

## Module `openid4vp`

OpenID4VP 1.0 verifier binding (DCQL request build + `vp_token` binding verify).

The SDK is a **full verifier** (contracts/openid4vp-verifier.md): it builds the OpenID4VP
presentation request (a DCQL query + a fresh `nonce` + the verifier's `audience`/`client_id`) AND
verifies that a returned `vp_token` is cryptographically **bound** to it. Owning both halves makes
replay / audience binding **correct by construction** — the verifier never accepts a presentation
it did not request.

## Operations

- [`build_request`] — `(dcql, audience) -> PresentationRequest { dcql, nonce (fresh), audience }`.
  The fresh `nonce` comes from the host RNG seam [`NonceSource`] (the core is sans-IO; entropy is
  host-provided exactly as the signing core takes it via `HostContext.entropy`).
- [`verify_response`] — `(vp_token, request, policy, anchors) -> VerificationResult`. Runs the
  per-format always-on bar ([`crate::sdjwtvc`] / [`crate::mdoc`]) **plus** the binding checks.

## Binding checks (FR-015 / SC-008)

- **Nonce**: the presentation echoes the request's fresh `nonce` — SD-JWT VC in the KB-JWT
  (`nonce`); mdoc in the `SessionTranscript` / OID4VPHandover the `DeviceAuth` signs over. A
  missing/mismatched nonce ⇒ INVALID [`ReasonCode::Replay`] (a replayed presentation cannot
  satisfy a fresh nonce).
- **Audience**: the presentation is addressed to this verifier's `client_id` — SD-JWT VC KB-JWT
  `aud`; mdoc the handover/`client_id`. Wrong audience ⇒ INVALID [`ReasonCode::WrongAudience`].

For mdoc the response is delivered to a verifier-controlled address, so the **audience** is an
observable cleartext field (compared directly → `WrongAudience`) while **freshness** is purely
cryptographic (the nonce is folded into the signed handover transcript → a mismatch surfaces as a
failed holder binding, attributed to `Replay`). For SD-JWT VC both `aud` and `nonce` are carried
in the (signed, but here pre-verification read) KB-JWT, so both are attributed precisely before
the full cryptographic bar runs.

### Structs

#### struct `Dcql`

```rust
struct Dcql
```

A DCQL (Digital Credentials Query Language — OpenID4VP 1.0) query.

OpenID4VP 1.0 removed Presentation-Exchange `presentation_definition`; the query is **DCQL**. The
binding verifier does not interpret the query's selection semantics (that is the holder/wallet's
job when building the presentation) — it carries the query opaquely as its canonical JSON so the
issued request is reproducible and auditable. Carrying it as a structured-but-opaque value keeps
the wire contract explicit without re-implementing DCQL evaluation in the verifier.

##### Fields

- `query_json: String`
  - The DCQL query as its canonical JSON text (what a wallet receives in the request).

##### Methods

```rust
fn from_json<impl Into<String>: Into<String>>(query_json: impl Into<String>) -> Self
```

Wrap a DCQL query given as JSON text.

#### struct `MdocVpToken`

```rust
struct MdocVpToken
```

An mdoc OpenID4VP `vp_token` envelope: the ISO 18013-5 `DeviceResponse` plus the audience the
response was addressed to.

In an OpenID4VP flow the mdoc response is delivered to a verifier-controlled `response_uri` for a
specific `client_id`, so the **audience** is an observable (cleartext, comparable) field, while
**freshness** is bound cryptographically inside the handover transcript the `DeviceAuth` signs
over. This envelope makes that explicit on the wire: `audience` is compared to the request
(→ [`ReasonCode::WrongAudience`]); the `device_response` is verified against the handover the
verifier reconstructs from the request `nonce` (a mismatch → [`ReasonCode::Replay`]).

##### Fields

- `audience: String`
  - The audience (`client_id`) the response was addressed to.
- `device_response: Vec<u8>`
  - The CBOR-encoded ISO 18013-5 `DeviceResponse`.

#### struct `PresentationRequest`

```rust
struct PresentationRequest
```

A verifier-built OpenID4VP presentation request (data-model.md `PresentationRequest`).

Built by [`build_request`] with a **fresh** `nonce` per request; the SDK tracks it to verify a
returned `vp_token` is bound to exactly this `nonce` + `audience`. Carries only verifier-side data
(no secret), so deriving `Debug` is safe.

##### Fields

- `dcql: Dcql`
  - The DCQL query of which attributes/credentials are requested.
- `nonce: Vec<u8>`
  - The fresh per-request nonce the presentation MUST echo (replay protection).
- `audience: String`
  - The verifier's `client_id` the presentation MUST be addressed to (audience binding).

##### Methods

```rust
fn nonce_b64(&self) -> String
```

The request `nonce` as a base64url-unpadded string (the form an SD-JWT VC KB-JWT echoes).

### Enums

#### enum `VpToken`

```rust
enum VpToken<'a>
```

The presented credential, in the format carried by an OpenID4VP `vp_token`.

OpenID4VP carries either a compact SD-JWT VC presentation string or an mdoc `DeviceResponse`
(wrapped here with its addressed audience — see [`MdocVpToken`]). Detected by the caller; the
verifier never guesses (an unrecognized shape would be [`ReasonCode::UnsupportedFormat`] at the
[`verify()`](crate::verify()) entry point).

##### Variants

- `SdJwtVc(&'a str)`
  - A compact SD-JWT VC presentation (`<issuer-JWS>~<D>…~<KB-JWT>`).
- `Mdoc(MdocVpToken)`
  - An mdoc `DeviceResponse` plus its addressed audience.

### Traits

#### trait `NonceSource`

```rust
trait NonceSource
```

A host-driven source of fresh entropy for the request `nonce` (keeps the core sans-IO — the
entropy is host-provided, mirroring `cleverbase_core::HostContext.entropy`).

[`build_request`] draws a fresh nonce per request; the host wires a CSPRNG in production and a
deterministic sequence in tests. The trait takes `&mut self` so a counter/CSPRNG can advance.

```rust
fn fresh_nonce(&mut self) -> Vec<u8>
```

Return fresh random bytes for a new request nonce (≥ 16 bytes recommended). Each call MUST
return a distinct, unpredictable value (no reuse — replay protection depends on it).

### Functions

#### fn `build_request`

```rust
fn build_request<N: NonceSource + ?Sized, impl Into<String>: Into<String>>(nonce_source: &mut N, dcql: Dcql, audience: impl Into<String>) -> PresentationRequest
```

Build an OpenID4VP presentation request: the DCQL query, a **fresh** nonce drawn from the host
[`NonceSource`], and the verifier's audience (`client_id`).

A fresh nonce per call is the replay-protection invariant (contracts/openid4vp-verifier.md): the
SDK keeps the returned [`PresentationRequest`] and only accepts a `vp_token` bound to it.

#### fn `oid4vp_handover_transcript`

```rust
fn oid4vp_handover_transcript(audience: &str, nonce: &[u8]) -> Vec<u8>
```

Build the OpenID4VP handover `SessionTranscript` bytes for an mdoc presentation from the
`audience` (`client_id`) and `nonce`.

Modelled as the ISO 18013-5 `SessionTranscript` shape `[null, null, OID4VPHandover]` where the
handover is `["OID4VPHandover", clientIdHash, nonceHash]` (SHA-256 over the audience and nonce) —
the holder folds the same handover into the `DeviceAuthentication` it signs, so reconstructing it
here binds the device signature to this exact request. Both the holder (test issuer) and the
verifier MUST build it identically.

#### fn `verify_response`

```rust
fn verify_response<A: TrustAnchorSource + ?Sized>(vp_token: &VpToken<'_>, request: &PresentationRequest, _policy: &VerificationPolicy, anchors: &A, now_unix: i64, role: IssuerRole, status: StatusOutcome) -> VerificationResult
```

Verify an OpenID4VP `vp_token` is cryptographically bound to an issued request, running the
per-format always-on bar **plus** the nonce/audience binding (contracts/openid4vp-verifier.md).

- SD-JWT VC: attributes the binding to [`ReasonCode::WrongAudience`] / [`ReasonCode::Replay`] from
  the KB-JWT `aud`/`nonce`, then runs the full bar with the request as the holder-binding
  challenge (so the binding is also cryptographically enforced — correct by construction).
- mdoc: compares the addressed audience (→ `WrongAudience`), then runs the bar against the
  handover transcript reconstructed from the request nonce/audience (a fresh-nonce mismatch
  surfaces as a failed holder binding, attributed to `Replay`).

`now_unix`/`role`/`status` are the remaining per-format-bar inputs the [`verify()`](crate::verify()) entry
point supplies (the validity instant, the trust-anchor role, and the resolved status outcome).

## Module `qualified`

Opt-in eIDAS qualified-status determination (ETSI TS 119 615 v1.4.1 cl. 4.12) — T019.

Over the always-on bar (which is never replaced by this), an **opt-in**, version-pinned
determination of whether an attestation issuer is a **qualified** EAA provider: authenticate the
LOTL → select the national Trusted List → match the issuer's signing certificate against a
trust-service entry of type [`EAA_Q_SERVICE_TYPE`] (`…/Svctype/EAA/Q`) → read the
`granted`/`withdrawn` service status **at the relevant time** (the credential's issuance/relevant
time, NOT "now"). The reusable trust-list primitives ([`crate::trust`]) anchor the same PKI (DRY).

## Outcome conditions (pinned — tasks T018/T019, analyze A1)

- [`QualifiedStatus::Qualified`] — the issuer's `EAA/Q` service entry is **`granted`** at the
  relevant time.
- [`QualifiedStatus::NotQualified`] — the entry is **found but not granted** (its status at the
  relevant time is withdrawn/suspended, the grant had not yet begun, or the issuer is on the TL
  only under a non-`EAA/Q` service type).
- [`QualifiedStatus::Indeterminate`] — the trust-list data needed to decide is **absent,
  ambiguous, or unreachable** (the issuer is on no service entry, or there is no TL at all). The
  gate **never assumes qualified** (no false "qualified" — SC-007).

## Experimental + version-pinned

cl. 4.12 (QEAA qualified-status determination) was newly standardized (TS 119 615 v1.3.1, Jan
2026) and is **pre-operational**: national Trusted Lists are only beginning to carry `EAA/Q`
entries (post CIR (EU) 2025/1569). This implementation is pinned to [`TS_119_615_VERSION`]
(`1.4.1`) and is **off by default** ([`crate::verify::VerifyContext::qualified_gate`]) — enabling
it is opt-in, and absent fixtures honestly yield `Indeterminate`.

## Trust-list authentication (scope)

The national TL is **authenticated** by chain-validating its embedded signer certificate against
a configured scheme-operator anchor, reusing [`crate::trust::chain::verify_chain`] (the same X.509
primitive the always-on bar uses — DRY). The full enveloped XML-DSig `SignatureValue`/C14N check
is the always-on engine's remaining production hardening ([`crate::trust::xml`]); the offline
JSON form here carries the signer cert so the gate exercises the same chain-authentication seam.

### Structs

#### struct `QualifiedTrustList`

```rust
struct QualifiedTrustList
```

A parsed national Trusted List for the qualified-status gate: the per-issuer-cert trust-service
entries (keyed by signing-cert DER, since a cert may appear under several services), the embedded
signer certificate (for chain-authentication), and the `nextUpdate` instant.

Carries only issuer-public certificate data (no secret), so deriving `Debug` is safe.

##### Methods

```rust
fn empty() -> Self
```

An empty national TL (no services, no signer) — the offline "no qualified data" case that
yields [`QualifiedStatus::Indeterminate`] for every issuer.

```rust
const fn next_update_unix(&self) -> i64
```

The list's `nextUpdate` instant (Unix seconds); at or after it the list is stale.

```rust
fn parse(bytes: &[u8]) -> Result<Self, QualifiedTrustListError>
```

Parse a qualified-status national Trusted List from its raw JSON bytes.

# Errors

Returns [`QualifiedTrustListError`] when the JSON is malformed, a certificate body is not
valid base64 DER, or a `nextUpdate` / status `startingTime` is not an RFC 3339 UTC timestamp.

```rust
fn signer_cert_der(&self) -> Option<&[u8]>
```

The list's own signing certificate (DER) from its enveloped signature, if present.

### Enums

#### enum `QualifiedTrustListError`

```rust
enum QualifiedTrustListError
```

An error parsing the qualified-status national Trusted List.

##### Variants

- `Json(Error)`
  - The bytes were not valid JSON of the expected national-TL shape.
- `Base64(String)`
  - A signing/signer certificate body was not valid base64 DER.
- `Time(String)`
  - A `nextUpdate` or status `startingTime` was not an RFC 3339 UTC timestamp.

### Functions

#### fn `qualified_status`

```rust
fn qualified_status(issuer_cert_der: &[u8], relevant_time_unix: i64, trust_list: &QualifiedTrustList) -> QualifiedStatus
```

Determine the eIDAS qualified status of an attestation issuer at a relevant time (TS 119 615
v1.4.1 cl. 4.12 — the opt-in gate, research D6).

Matches `issuer_cert_der` (the credential's signing certificate) against the national TL's
trust-service entries, then reads the effective service status **at `relevant_time_unix`** (the
credential's issuance/relevant time, NOT "now"):

- [`QualifiedStatus::Qualified`] — some matched [`EAA_Q_SERVICE_TYPE`] service is
  [`SERVICE_STATUS_GRANTED`] at the relevant time.
- [`QualifiedStatus::NotQualified`] — the issuer is **found** on the TL, but no `EAA/Q` service is
  granted at the relevant time (it is withdrawn/suspended, the grant had not begun, or the only
  matched service is non-`EAA/Q`).
- [`QualifiedStatus::Indeterminate`] — the issuer is on **no** service entry (the data needed to
  decide is absent). Never assumes qualified (no false "qualified" — SC-007).

### Constants

#### const `EAA_Q_SERVICE_TYPE`

```rust
const EAA_Q_SERVICE_TYPE: &str = "http://uri.etsi.org/TrstSvc/Svctype/EAA/Q"
```

The TS 119 612 trust-service **type** URI for a *qualified* electronic attestation of attributes
(QEAA) issuing service. Only a service of this exact type can make an issuer
[`QualifiedStatus::Qualified`] (a plain `…/Svctype/EAA` — non-qualified EAA — never does).

#### const `SERVICE_STATUS_GRANTED`

```rust
const SERVICE_STATUS_GRANTED: &str = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted"
```

The TS 119 612 trust-service **status** URI for a `granted` service (in force). An `EAA/Q` service
whose effective status at the relevant time is `granted` makes its issuer
[`QualifiedStatus::Qualified`].

#### const `TS_119_615_VERSION`

```rust
const TS_119_615_VERSION: &str = "1.4.1"
```

The pinned TS 119 615 version this determination implements (research D6 — experimental,
pre-operational). Surfaced so a consumer can record exactly which clause-4.12 revision produced a
verdict.

## Module `sdjwtvc`

SD-JWT VC (RFC 9901 / draft-ietf-oauth-sd-jwt-vc-16) verification.

Verifies a presented SD-JWT VC against the always-on bar (contracts/verifier.md): the
issuer-signed compact JWS, issuer trust (via the pluggable [`crate::trust::TrustAnchorSource`]),
the `nbf`/`exp` validity window, the holder Key-Binding JWT (`aud`/`nonce`/`sd_hash`), and
selective-disclosure integrity (each disclosed claim must match an issuer-signed digest). A
failed check yields `valid = false` with a specific [`ReasonCode`] — never a false-accept
(SC-002).

## Layering (research D2/D1)

- The **format layer** (issuer-JWS framing, disclosures, the optional KB-JWT) is parsed with
  [`sd_jwt_payload`].
- The **crypto** is the SDK's own RustCrypto stack: the issuer ES256 JWS and the holder ES256
  KB-JWT are both verified **in-house** over `p256`/`ecdsa`/`sha2` (the SDK has no JOSE crate, and
  `sd-jwt-payload` parses the KB-JWT but does **not** verify its signature — so the holder-binding
  signature check is built here). No new JOSE dependency, no hand-rolled crypto (Principle IV).
- **Selective-disclosure digests** are recomputed with `sha2` (the `_sd_alg`, `sha-256`) and
  matched against the issuer-signed `_sd` arrays.

## Status seam (T014)

The revocation/status check is owned by [`crate::status`]; this module takes its canonical
[`crate::status::StatusOutcome`] (re-exported here as [`StatusInput`]) so the always-on bar is
honoured without re-implementing the status fetch here — the single authoritative status type
(DRY). The always-on [`verify()`](crate::verify()) entry point resolves the credential's status
reference through the host [`crate::status::StatusSource`] seam and passes the outcome in.

### Structs

#### struct `KeyBindingChallenge`

```rust
struct KeyBindingChallenge<'a>
```

The holder-binding challenge a presented KB-JWT must satisfy (RFC 9901 §4.3).

##### Fields

- `audience: &'a str`
  - The expected `aud` — the verifier's `client_id`.
- `nonce: &'a str`
  - The expected fresh `nonce`.

#### struct `SdJwtVcInput`

```rust
struct SdJwtVcInput<'a, A: TrustAnchorSource + ?Sized>
```

The verifier inputs for an SD-JWT VC presentation (the per-format slice of the always-on
`verify` entry point that task T016 assembles).

Sans-IO: every input — the presentation, the trust anchors, the holder-binding challenge, and the
status outcome — is passed in; this performs no network I/O.

##### Fields

- `presentation: &'a str`
  - The compact SD-JWT VC presentation: `<issuer-JWS>~<D.1>~…~<D.N>~<optional KB-JWT>`.
- `anchors: &'a A`
  - The configured trust anchors; the issuer's signing certificate is resolved against these.
- `role: IssuerRole`
  - The issuer role under which to anchor trust (selects the trust list — research D5).
- `key_binding: Option<KeyBindingChallenge<'a>>`
  - The holder-binding challenge the KB-JWT must echo (`aud` = verifier `client_id`, `nonce`),
or `None` to accept a presentation without holder binding (e.g. an issuer-only credential).
- `now_unix: i64`
  - The current time (Unix seconds) the `nbf`/`exp` window is checked against.
- `status: StatusInput`
  - The revocation/status outcome (the T014 seam).

### Functions

#### fn `issuer_signing_cert_der`

```rust
fn issuer_signing_cert_der(presentation: &str) -> Option<Vec<u8>>
```

Extract the issuer signing certificate (DER) a presented SD-JWT VC claims in its JWS `x5c` header,
without verifying anything (the opt-in [`crate::qualified`] gate matches this leaf against the
national Trusted List's `EAA/Q` service entries).

Returns `None` when the presentation does not parse or carries no `x5c` leaf. The value is
*claimed* (its trust + signature are decided by the always-on bar in [`verify_sd_jwt_vc`]); this
read is only the gate's cert-matching input, never an acceptance.

#### fn `kb_jwt_aud_nonce`

```rust
fn kb_jwt_aud_nonce(presentation: &str) -> Option<(String, String)>
```

Extract the `aud` and `nonce` a presented SD-JWT VC's KB-JWT echoes, without verifying anything
(the [`crate::openid4vp`] layer uses this to attribute a request-binding failure to the specific
[`ReasonCode::Replay`] / [`ReasonCode::WrongAudience`] before delegating to the full bar).

Returns `None` when the presentation does not parse or carries no KB-JWT. The values are *claimed*
(their cryptographic verification is the always-on holder-binding check in [`verify_sd_jwt_vc`]);
this read is only for failure attribution, never for acceptance.

#### fn `verify_sd_jwt_vc`

```rust
fn verify_sd_jwt_vc<A: TrustAnchorSource + ?Sized>(input: &SdJwtVcInput<'_, A>) -> VerificationResult
```

Verify a presented SD-JWT VC against the always-on bar, returning a [`VerificationResult`].

On any failed check the result has `valid = false` and carries the single specific
[`ReasonCode`] for the **first** check that failed; only a credential that clears every check is
`valid = true`, with the disclosed (and only the disclosed) attributes returned.

## Module `status`

Revocation / status check (status list / CRL) with a fail-closed reachability policy (T014).

The always-on bar (FR-003) includes revocation: a credential whose status mechanism says it is
revoked → INVALID `revoked`; one whose status cannot be reached → fail-closed by default →
INVALID `status_unavailable` (never a silent VALID). This module evaluates that check.

## Sans-IO (host seam — like the trust engine)

The core performs no network I/O. A credential references its status mechanism (a Token Status
List pointer `uri`+`idx`, or a CRL the integrator names); the **host** fetches the referenced
status document and supplies its bytes through the [`StatusSource`] seam, exactly as the trust
engine takes fetched trust-list bytes through `TrustListFetcher`. The fetch (network, caching,
freshness of the *transport*) is the host's; the *evaluation* and the **fail-closed policy** are
the core's.

## Status mechanisms

- **Token Status List** (IETF `draft-ietf-oauth-status-list` — the EUDI/HAIP baseline): a
  credential carries a `status.status_list = { idx, uri }`; the referenced list is a packed
  bit-array (1 or 2 bits per entry). A non-zero status value at `idx` is revoked/suspended.
- **CRL** (X.509 Certificate Revocation List): a credential is identified by an issuer-assigned
  serial; the referenced CRL enumerates revoked serials. Modelled abstractly here (the integrator
  supplies the parsed revoked-serial set) so the same fail-closed policy covers both.

The decision maps to a single canonical [`StatusOutcome`] that the per-format verifiers consume
through their status seam (one authoritative status type — DRY).

### Enums

#### enum `StatusOutcome`

```rust
enum StatusOutcome
```

The canonical outcome of the revocation/status check, consumed by both per-format verifiers'
status seam (the single authoritative status type — DRY, Principle III).

The per-format `verify` paths translate this into their reject reason: [`Self::Revoked`] →
[`ReasonCode::Revoked`], [`Self::Unavailable`] → [`ReasonCode::StatusUnavailable`], and
[`Self::NoStatus`]/[`Self::Good`] continue the bar. Carried across the C-ABI as CBOR (the host
resolves it through [`check_status`] and passes the outcome in), hence the `serde` derives.

[`ReasonCode::Revoked`]: crate::types::ReasonCode::Revoked
[`ReasonCode::StatusUnavailable`]: crate::types::ReasonCode::StatusUnavailable

##### Variants

- `NoStatus`
  - The credential declares no status mechanism — nothing to check (continue the bar).
- `Good`
  - The status mechanism was reachable and says the credential is current.
- `Revoked`
  - The status mechanism says the credential is revoked or suspended.
- `Unavailable`
  - The status document was unreachable (or unparseable) and the policy is fail-closed — never a
silent VALID.

#### enum `StatusReference`

```rust
enum StatusReference
```

What a credential declares about its status mechanism (parsed from the credential), or the
absence of one.

This is the *reference* the host resolves: a Token Status List pointer (`uri`+`idx`), or a CRL
entry (a CRL location plus the credential's serial). The host fetches the referenced document and
supplies it via the [`StatusSource`] seam; the core then evaluates `idx`/serial against it.

##### Variants

- `None`
  - The credential declares no status mechanism.
- `StatusList { index: u64, uri: String }`
  - A Token Status List reference: the index of this credential's entry and the list URI the host
fetches.
- `Crl { serial: Vec<u8>, uri: String }`
  - A CRL reference: the credential's serial and the CRL location the host fetches.

### Traits

#### trait `StatusSource`

```rust
trait StatusSource
```

A host-driven source of fetched status documents (keeps the core sans-IO — Principle III).

Mirrors `crate::trust::engine::TrustListFetcher`: the core never performs network I/O; the host
fetches the referenced status document (network, transport caching) and returns its parsed form,
or `None` when it is unreachable. A `None` under [`StatusReachability::FailClosed`] is the
fail-closed reject; under [`StatusReachability::BestEffort`] it is tolerated.

```rust
fn fetch_status_list(&self, uri: &str) -> Option<Vec<u8>>
```

Fetch the packed Token Status List bytes for `uri`, or `None` if unreachable.

The bytes are the **unpacked** status array: one byte per entry holding that entry's status
value (`0` = valid; non-zero = revoked/suspended). The host is responsible for decompressing /
bit-unpacking the wire form (the CBOR/JWT-wrapped, optionally DEFLATE-compressed bitstring)
into this byte-per-entry view; the core does not pull a compression dependency into its
sans-IO surface.

```rust
fn fetch_crl_revoked_serials(&self, uri: &str) -> Option<Vec<Vec<u8>>>
```

Fetch the set of revoked serials for the CRL at `uri`, or `None` if unreachable.

Each entry is a revoked credential serial (big-endian bytes). The host parses the DER CRL (or
its cached form) into this set; the core checks membership.

### Functions

#### fn `check_status`

```rust
fn check_status<S: StatusSource + ?Sized>(reference: &StatusReference, source: &S, reachability: StatusReachability) -> StatusOutcome
```

Evaluate a credential's status against the host-supplied status documents, applying the
fail-closed reachability policy.

- [`StatusReference::None`] → [`StatusOutcome::NoStatus`].
- A reachable status list / CRL → [`StatusOutcome::Revoked`] if the entry is revoked, else
  [`StatusOutcome::Good`].
- An **unreachable** status document → [`StatusOutcome::Unavailable`] under
  [`StatusReachability::FailClosed`] (the secure default), or [`StatusOutcome::Good`] under
  [`StatusReachability::BestEffort`] (the credential is not failed on reachability alone).

Sans-IO: the status documents are supplied through `source`; this performs no network I/O.

## Module `trust`

Pluggable trust-anchor source for issuer trust (contracts/trust-anchor-source.md).

Verification anchors issuer trust **per role/format**: a QEAA issuer is found on the EU LOTL +
national Trusted Lists, a PID provider on the eIDAS Art. 5a(18) Commission list, a PuB-EAA
provider on the Art. 45f(3) list, and an mdoc issuer on an IACA root. This module defines the
pluggable seam — the [`TrustAnchorSource`] trait — plus the [`TrustDecision`] / [`TrustListEntry`]
types, the fail-closed [`Reachability`] policy, and a configured offline [`StaticTestAnchors`]
implementation for the offline test suite.

The **native EU trust-list engine** (fetch + authenticate the LOTL and national Trusted Lists via
`quick-xml` + the SDK's X.509 stack) is the largest single build and lands in task **T013**; this
module provides only the trait + the test anchor (task **T005**, preceded by **T009**).

## Sans-IO contract

[`TrustAnchorSource::resolve`] is **pure**: it works only against the already-fetched, cached,
in-memory anchors and performs no I/O. [`TrustAnchorSource::refresh`] is where the production
engine fetches/caches the signed trust-list XML/JSON; it is **host-driven** (not per-verification)
and is the point at which the [`Reachability`] policy applies.

### Module `chain`

X.509 chain validation against trusted anchors (research D5, no hand-rolled crypto).

Trust anchoring asks one question: does the credential's signing certificate (the mdoc
`IssuerAuth` x5chain leaf or the SD-JWT VC JWS `x5c` leaf) **chain to** a certificate that the
configured trust anchor lists for the credential's role/format? This module answers it by
reusing the SDK's vetted X.509 stack — `x509-cert` for parsing, `p256`/`ecdsa` + `rsa` for the
signature math, `sha2` for the digest — and never hand-rolls crypto (Principle IV / research D1).

The validation is intentionally a **direct-issuer** check sized for the EUDI trust model: an
issuer leaf is trusted iff it is signed by (or *is*) an anchor certificate, the leaf's `issuer`
name matches the anchor's `subject` name, and the leaf is within its validity window at the
relevant time. ISO 18013-5 IACA hierarchies and the eIDAS trusted lists are one-level (root →
document-signer / service); a configured anchor *is* the root, so a one-hop chain is the
production shape. The matcher also accepts an exact DER-equal leaf (a self-issued anchor that is
itself the listed entry), which covers a trusted-list entry that pins the leaf directly.

#### Enums

##### enum `ChainError`

```rust
enum ChainError
```

Why a candidate issuer certificate failed to chain to a trusted anchor.

Every rejection carries a specific reason so an untrusted verdict is never opaque (the engine
maps these onto [`crate::types::ReasonCode::UntrustedIssuer`] / `Expired`).

###### Variants

- `Malformed(String)`
  - A certificate (leaf or anchor) could not be parsed as DER X.509.
- `IssuerMismatch`
  - The leaf's issuer name does not match any candidate anchor's subject name.
- `SignatureInvalid`
  - The leaf's signature did not verify under any name-matching anchor's public key.
- `UnsupportedAlgorithm(String)`
  - The leaf carries a signature algorithm the SDK does not implement (outside the EUDI
baseline: ES256/384/512 + RSA-PKCS#1v1.5 over SHA-256/384/512).
- `LeafExpired`
  - The leaf is outside its own validity window at the relevant time.

#### Functions

##### fn `verify_chain`

```rust
fn verify_chain(leaf_cert_der: &[u8], anchor_certs_der: &[Vec<u8>], now_unix: i64) -> Result<(), ChainError>
```

Whether `leaf_cert_der` chains to **any** of the trusted `anchor_certs_der`, valid at
`now_unix`.

This is the trust-anchoring primitive: a leaf is trusted iff some anchor either (a) is DER-equal
to the leaf (the anchor pins the leaf directly), or (b) issued the leaf — the leaf's `issuer`
name equals the anchor's `subject` name **and** the leaf's signature verifies under the anchor's
public key — and in case (b) the leaf is within its own validity window at `now_unix`. Returns
the first specific [`ChainError`] when no anchor matches.

# Errors

Returns [`ChainError`] when the leaf is malformed, no anchor's subject matches the leaf's issuer,
the signature does not verify, the algorithm is unsupported, or the leaf is expired.

### Module `engine`

The native EU trust-list engine (research D5 — the biggest single build).

[`NativeTrustEngine`] is the production [`TrustAnchorSource`]: a host-driven
[`NativeTrustEngine::refresh`]
**fetches → parses → authenticates → caches** the signed trust lists (the offline JSON manifest
now; a TS 119 612 XML LOTL / national TL via [`super::xml`]), and a pure, sans-IO
[`NativeTrustEngine::resolve`] answers issuer-trust questions against the **cached** anchors by
chain-
validating the issuer's signing certificate ([`super::chain`]).

## Reachability / stale policy (U1, fail-closed by default)

[`refresh`](NativeTrustEngine::refresh) is where the [`Reachability`] policy applies. Three outcomes are kept
distinct (the contract's U1 requirement):

- **Unreachable** — the [`TrustListFetcher`] could not return bytes ([`TrustError::Unreachable`]).
- **Stale** — the fetched list parsed, but its `NextUpdate` is at/before the current clock
  ([`TrustError::Stale`]).
- **Authentication failure** — a fetched XML list's signing certificate did not chain to a
  configured scheme anchor ([`TrustError::Authentication`]).

Under [`Reachability::FailClosed`] (the default) any of these fails `refresh` **and** clears the
cached anchors, so a subsequent `resolve` cannot serve stale/empty trust (no silent VALID). Under
[`Reachability::BestEffort`] an unreachable/stale list keeps the last-known-good cache. All three
are distinct from an **expired/withdrawn entry** (a present-but-out-of-window issuer leaf →
`resolve` returns untrusted) and from the per-credential status endpoint
([`crate::types::StatusReachability`]).

#### Structs

##### struct `NativeTrustEngine`

```rust
struct NativeTrustEngine
```

The native EU trust-list engine ([`TrustAnchorSource`]).

Configure it with one or more trust lists, then [`refresh`](Self::refresh) (host-driven) to
fetch/authenticate/cache them; [`resolve`](Self::resolve) is pure and works on the cache.

Carries only issuer-public anchor data + a clock (no secret), so deriving `Debug` is safe.

###### Methods

```rust
fn new(reachability: Reachability, now_unix: i64) -> Self
```

Construct an engine with the given [`Reachability`] policy and a fixed clock (Unix seconds).

The clock is an explicit input (the seam) so validity/staleness are deterministic; the host
advances it via [`Self::set_now`] before each refresh in production.

```rust
const fn now_unix(&self) -> i64
```

The current engine clock (Unix seconds).

```rust
fn refresh_with(&mut self, fetcher: &mut dyn TrustListFetcher) -> Result<(), TrustError>
```

Host-driven refresh against a supplied [`TrustListFetcher`].

This is the production refresh entry point: the trait's [`TrustAnchorSource::refresh`] takes
no fetcher (it is the sans-IO seam), so the host calls this with its own fetcher.

# Errors

Returns [`TrustError::Unreachable`] / [`TrustError::Stale`] / [`TrustError::Authentication`]
per the reachability/stale policy. Under [`Reachability::FailClosed`] the cache is cleared on
any failure (no stale trust); under [`Reachability::BestEffort`] the last-known-good cache is
kept on an unreachable/stale list.

```rust
fn set_now(&mut self, now_unix: i64)
```

Set the engine clock (Unix seconds) — the deterministic clock seam (U1 staleness).

```rust
fn with_json_manifest<impl Into<String>: Into<String>>(self, name: impl Into<String>) -> Self
```

Configure the offline JSON manifest list under the given logical name (builder-style).

```rust
fn with_xml_list<impl Into<String>: Into<String>>(self, name: impl Into<String>, role: IssuerRole, format: Format, scheme_anchors_der: Vec<Vec<u8>>, chain_only: bool) -> Self
```

Configure a TS 119 612 XML trust list under the given logical name, mapping every service it
carries to `(role, format)` and authenticating its signing cert against `scheme_anchors_der`
(builder-style).

`chain_only` opts into authenticating on the signing-cert chain alone (the enveloped
XML-DSig `SignatureValue`/C14N check is the remaining production hardening — see
[`super::xml`]); with `false`, the list fails authentication closed by default.

#### Traits

##### trait `TrustListFetcher`

```rust
trait TrustListFetcher
```

A host-driven source of raw trust-list bytes (keeps the core sans-IO — research D5 / Principle
III).

The core never performs network I/O; the host supplies the fetched bytes (or signals
unreachable) so the engine can parse/authenticate/cache them. A fetcher returns the raw
trust-list document for a logical list name (e.g. a LOTL URL the host configured), or `None`
when that list is unreachable.

```rust
fn fetch(&mut self, list_name: &str) -> Option<Vec<u8>>
```

Fetch the raw bytes of the named trust list, or `None` if it is unreachable.

`list_name` is the engine-configured logical name of a list (the host maps it to a URL /
cache). The returned bytes are the JSON manifest or TS 119 612 XML the engine will
parse+authenticate.

### Module `manifest`

The offline JSON trust-list manifest (`tests/fixtures/attestation/trust-list.json`).

For the fully-offline test suite (research D9 / SC-003) the configured trust anchor is seeded
from a small JSON manifest: per `(role, format)` it lists the trusted anchor certificate(s) as
base64 DER, plus a `nextUpdate` timestamp so the **stale-list** policy (past `NextUpdate` →
fail-closed) has a value to exercise. This is the JSON counterpart of the production TS 119 612
XML path ([`super::xml`]); both feed the same in-memory anchor cache in
[`super::NativeTrustEngine`]. It is **not** a production trust source — there is no signature on
the JSON manifest (the offline suite trusts the bytes it ships); the *XML* path carries the
enveloped-signature authentication.

#### Structs

##### struct `TrustListManifest`

```rust
struct TrustListManifest
```

A parsed, in-memory trust-list manifest: the per-`(role, format)` anchor certificates plus the
`nextUpdate` instant after which the list is stale.

Carries only issuer-public anchor certificates (no secret), so deriving `Debug` is safe.

###### Methods

```rust
fn anchors_for(&self, role: IssuerRole, format: Format) -> &[Vec<u8>]
```

The anchor certificates (DER) trusted for a given `(role, format)`, or an empty slice if the
manifest lists none.

```rust
const fn next_update_unix(&self) -> i64
```

The `nextUpdate` instant (Unix seconds): at or after this time the list is **stale**.

```rust
fn parse(bytes: &[u8]) -> Result<Self, ManifestError>
```

Parse a JSON trust-list manifest from its raw bytes.

# Errors

Returns [`ManifestError`] when the JSON is malformed, an anchor certificate is not valid
base64, or `nextUpdate` is not a valid RFC 3339 UTC timestamp.

#### Enums

##### enum `ManifestError`

```rust
enum ManifestError
```

An error parsing the JSON trust-list manifest.

###### Variants

- `Json(Error)`
  - The manifest bytes were not valid JSON of the expected shape.
- `Base64(String)`
  - An anchor entry's `anchorCertDerB64` was not valid base64.
- `NextUpdate(String)`
  - The manifest's `nextUpdate` was not an RFC 3339 / ISO 8601 UTC timestamp.
- `UnknownRole(String)`
  - An anchor entry named a role the SDK does not recognise.
- `UnknownFormat(String)`
  - An anchor entry named a credential format the SDK does not recognise.

### Module `xml`

TS 119 612 trust-list XML parsing + signature-authentication path (`quick-xml`, research D5).

The production EU trust model is a **signed XML** LOTL / national Trusted List (ETSI TS 119 612
v2.4.1 / TLv6): a `<TrustServiceStatusList>` whose `<SchemeInformation>` carries a
`<NextUpdate>`, whose `<TrustServiceProviderList>` carries per-service
`<ServiceDigitalIdentity>` → `<X509Certificate>` anchor certificates, and which is sealed with an
enveloped XML-DSig `<ds:Signature>` whose `<X509Certificate>` is the trust-list operator's
signing certificate. This module parses that structure with `quick-xml` and exposes the per-list
anchor certificates + `NextUpdate` to the engine, and **authenticates** the list by chain-
validating its embedded signing certificate against a configured scheme-operator trust anchor
(the SDK's X.509 stack — [`super::chain`]).

## What is complete vs. remaining production hardening (honest scope — research D5 caveat)

- **Complete now**: the `quick-xml` parse path (anchor certs per service + `NextUpdate`), and the
  X.509 **chain** authentication of the list's embedded signing certificate against a configured
  scheme-operator anchor. A list whose signing certificate does not chain to a configured anchor
  is **rejected** (`SignerUntrusted`).
- **Remaining production hardening** (deliberately not yet done — and it **fails closed**): the
  full enveloped XML-DSig cryptographic check — exclusive C14N (XML-EXC-C14N), `<Reference>`
  digest recomputation over the canonicalised `SignedInfo`/document, and the RSA/ECDSA
  `SignatureValue` verification. Until that lands, [`XmlTrustList::authenticate`] requires the
  caller to opt in to "chain-only" authentication explicitly; the default path returns
  [`XmlTrustListError::SignatureUnverified`] so a real LOTL is **not silently trusted** on the
  chain alone. This matches the fail-closed default the contract mandates.

#### Structs

##### struct `XmlTrustList`

```rust
struct XmlTrustList
```

A parsed TS 119 612 trust list: per-`(role, format)` anchor certificates, the list's `NextUpdate`,
and (when present) the list's own signing certificate from the enveloped `<ds:Signature>`.

Carries only issuer-public anchor + signer certificates (no secret), so deriving `Debug` is safe.

###### Methods

```rust
fn anchors_for(&self, role: IssuerRole, format: Format) -> &[Vec<u8>]
```

The anchor certificates (DER) the parsed list carries for a `(role, format)`.

```rust
fn authenticate(&self, scheme_anchors_der: &[Vec<u8>], now_unix: i64, chain_only: bool) -> Result<(), XmlTrustListError>
```

Authenticate the trust list: chain-validate its embedded signing certificate against a
configured scheme-operator trust anchor.

`chain_only` is the explicit opt-in to authenticate on the signing-cert chain **alone**
(the enveloped XML-DSig `SignatureValue`/C14N digest check is the remaining production
hardening — see the module docs). When `chain_only` is `false`, this fails closed with
[`XmlTrustListError::SignatureUnverified`] so a real LOTL is never trusted on the chain
alone by default.

# Errors

Returns [`XmlTrustListError::Unsigned`] if the list carried no `<ds:Signature>`,
[`XmlTrustListError::SignerUntrusted`] if its signing certificate does not chain to a
configured scheme anchor, or [`XmlTrustListError::SignatureUnverified`] when `chain_only` is
`false`.

```rust
const fn next_update_unix(&self) -> i64
```

The list's `NextUpdate` instant (Unix seconds); at or after it the list is stale.

```rust
fn parse(bytes: &[u8], role: IssuerRole, format: Format) -> Result<Self, XmlTrustListError>
```

Parse a TS 119 612 trust-list XML from its raw bytes, with the role/format every service maps
to supplied by the caller (the production engine derives this from the service `ServiceType`
URIs — `…/Svctype/EAA/Q` etc.; the parse path collects every service anchor under the given
role/format so the engine can anchor against them).

# Errors

Returns [`XmlTrustListError`] when the XML is malformed, a certificate body is not valid
base64, or `<NextUpdate>` is missing/invalid.

```rust
fn signer_cert_der(&self) -> Option<&[u8]>
```

The list's own signing certificate (DER) from the enveloped `<ds:Signature>`, if signed.

#### Enums

##### enum `XmlTrustListError`

```rust
enum XmlTrustListError
```

An error parsing or authenticating a TS 119 612 trust-list XML.

###### Variants

- `Xml(String)`
  - The bytes were not well-formed XML.
- `Base64(String)`
  - A `<X509Certificate>` element body was not valid base64.
- `NextUpdate(String)`
  - The `<NextUpdate>` element was missing or not an RFC 3339 UTC timestamp.
- `Unsigned`
  - The trust list carried no `<ds:Signature>` to authenticate.
- `SignerUntrusted(ChainError)`
  - The trust-list signing certificate did not chain to a configured scheme-operator anchor.
- `SignatureUnverified`
  - The full enveloped XML-DSig cryptographic check is not yet implemented; authenticating on the
chain alone must be explicitly opted into (fail-closed default — see the module docs).

### Structs

#### struct `StaticTestAnchors`

```rust
struct StaticTestAnchors
```

A configured, offline trust anchor for the test suite (task T005).

Trusts exactly the set of issuer certificates it was configured with, keyed by `(role, format)` so
that per-role/format anchoring is exercised (an issuer trusted as a PID provider is not thereby
trusted as a QEAA). It performs no I/O — [`StaticTestAnchors::refresh`] is a no-op — so the
offline suite needs no network and no EU lists. It is **not** a production trust source.

Carries only issuer-public certificates (no secret), so deriving `Debug` is safe.

##### Methods

```rust
fn is_trusted(&self, role: IssuerRole, format: Format, issuer_cert_der: &[u8]) -> bool
```

Whether a given certificate is configured as trusted for the role/format (the matching rule:
exact DER equality against the configured set).

```rust
fn new() -> Self
```

Construct an empty test anchor set (trusts nothing until certificates are added).

```rust
fn trust(self, role: IssuerRole, format: Format, issuer_cert_der: &[u8]) -> Self
```

Trust the given DER-encoded issuer certificate for a specific role/format.

Returns `self` for builder-style configuration.

#### struct `TrustDecision`

```rust
struct TrustDecision
```

The outcome of resolving an issuer against the configured anchors
(contracts/trust-anchor-source.md).

`trusted` is the always-on-bar trust decision; `entry` carries the matched [`TrustListEntry`] when
`trusted` is `true` (it is `None` for an untrusted issuer).

##### Fields

- `trusted: bool`
  - Whether the issuer is on the configured trust anchor for its role/format.
- `entry: Option<TrustListEntry>`
  - The matched trust-list entry, present iff `trusted`.

##### Methods

```rust
const fn trusted(entry: TrustListEntry) -> Self
```

A trusted decision carrying its matched entry.

```rust
const fn untrusted() -> Self
```

An untrusted decision (no matched entry).

#### struct `TrustListEntry`

```rust
struct TrustListEntry
```

A matched entry on a trust list — the in-force record under which an issuer is trusted
(contracts/trust-anchor-source.md).

Carries only issuer-public trust-list data (no secret), so deriving `Debug` is safe.

##### Fields

- `role: IssuerRole`
  - The issuer role under which this entry was matched.
- `format: Format`
  - The credential format this anchor covers.
- `anchor_cert_der: Vec<u8>`
  - The DER-encoded issuer/anchor certificate that the credential's signer chained to.
- `service_name: Option<String>`
  - A human-readable label for the trust-list service (e.g. a national TL service name), if
known. The test anchor leaves this empty.

### Enums

#### enum `Reachability`

```rust
enum Reachability
```

The reachability policy for fetching/refreshing a trust list (contracts/trust-anchor-source.md).

The default is **fail-closed**: an unreachable or stale (past its `NextUpdate`) LOTL / national
Trusted List makes [`TrustAnchorSource::refresh`] fail rather than silently serve stale or empty
anchors that could let an untrusted issuer through. This is distinct from the per-credential
revocation/status reachability ([`crate::types::StatusReachability`]) and from an
expired/withdrawn issuer *entry* (which surfaces as [`TrustStatus::Untrusted`] at `resolve` time).

[`TrustStatus::Untrusted`]: crate::types::TrustStatus::Untrusted

##### Variants

- `FailClosed`
  - An unreachable or stale trust list fails the refresh (the secure default).
- `BestEffort`
  - An unreachable or stale trust list serves the last-known-good cached anchors (opt-in; for
environments that accept the weaker guarantee).

#### enum `TrustError`

```rust
enum TrustError
```

An error from refreshing the trust anchors.

The production engine fetches and authenticates signed trust-list XML/JSON in `refresh`; this
surfaces the fail-closed outcomes. The offline [`StaticTestAnchors`] never fails to refresh.

##### Variants

- `Unreachable(String)`
  - A trust list could not be fetched (the fail-closed reachability outcome).
- `Stale(String)`
  - A fetched trust list is stale (past its `NextUpdate`) and the policy is fail-closed.
- `Authentication(String)`
  - A fetched trust list failed signature authentication.

### Traits

#### trait `TrustAnchorSource`

```rust
trait TrustAnchorSource
```

The pluggable trust-anchor source (contracts/trust-anchor-source.md).

Implementations range from the offline [`StaticTestAnchors`] to the native EU trust-list engine
(task T013). `resolve` MUST be pure (sans-IO) — it works on cached, in-memory anchors only.

```rust
fn resolve(&self, role: IssuerRole, format: Format, issuer_cert_der: &[u8]) -> TrustDecision
```

Resolve whether an issuer is trusted for a given role/format, matching its DER-encoded signing
certificate against the configured anchors. **Pure / sans-IO** — never performs I/O.

`issuer_cert_der` is the credential's signing certificate (the mdoc `IssuerAuth` x5chain leaf,
or the SD-JWT VC JWS `x5c` leaf).

```rust
fn refresh(&mut self) -> Result<(), TrustError>
```

Fetch and cache the signed trust lists (host-driven, **not** per-verification). The native
engine applies the [`Reachability`] policy here; the offline anchors are infallible.

# Errors

Returns [`TrustError`] when a trust list is unreachable/stale (under [`Reachability::FailClosed`])
or fails signature authentication.

## Module `types`

Shared domain types for EUDI attestation verification (data-model.md).

These are the conceptual domain entities of the attestation core. They are **sans-IO** — the core
holds no persistence and no key custody — and are carried across the `cleverbase-ffi` C-ABI as
CBOR (hence the `serde` derives), so they form a versioned wire contract, not just an in-process
API. None of these types carries a private key or other sole-control secret (those stay in the
integrator's HSM via the signer-hook), so deriving `Debug` here exposes only issuer-public and
verifier-side data. `disclosedAttributes` does carry the holder-disclosed subject claims (PII by
nature); a host that logs a [`VerificationResult`] is logging exactly the data it asked the
subject to disclose — no *undisclosed* attribute is ever present.

### Structs

#### struct `Attestation`

```rust
struct Attestation
```

An issuer-signed set of attributes about a subject, in one of two formats (data-model.md).

For a *presentation*, `attributes` holds only the **disclosed** subset; undisclosed attributes are
neither revealed nor required. `raw` is the encoded credential as received (compact SD-JWT(+KB) or
CBOR `DeviceResponse`) — the verifier works from `raw`, and the structured fields are the parsed,
verified view.

##### Fields

- `format: Format`
  - The credential format.
- `issuer: Issuer`
  - The signing authority and its resolved trust posture.
- `attributes: BTreeMap<String, AttributeValue>`
  - The disclosed claims (for a presentation, only the disclosed subset).
- `validity: Validity`
  - The credential validity window.
- `raw: Vec<u8>`
  - The encoded credential as received.

#### struct `Issuer`

```rust
struct Issuer
```

The signing authority of an attestation, with its resolved trust posture (data-model.md).

`qualified_status` is `Some` only when the opt-in qualified gate ran; otherwise it is `None`
(never assume qualified).

##### Fields

- `role: IssuerRole`
  - The issuer role, which selects the trust anchor.
- `trust_status: TrustStatus`
  - Whether the issuer is on the configured trust anchor for its role/format.
- `qualified_status: Option<QualifiedStatus>`
  - The eIDAS qualified status, present only when the opt-in gate ran.

#### struct `Validity`

```rust
struct Validity
```

The validity window of an attestation (SD-JWT VC `nbf`/`exp`; mdoc MSO `validityInfo`), as Unix
seconds. Either bound may be absent if the format/credential omits it.

##### Fields

- `not_before: Option<i64>`
  - Not-valid-before (Unix seconds), if present.
- `not_after: Option<i64>`
  - Not-valid-after (Unix seconds), if present.

#### struct `VerificationPolicy`

```rust
struct VerificationPolicy
```

The verifier's policy input (data-model.md `VerificationPolicy`).

Defaults are the secure baseline: both formats accepted, the qualified gate **off**, and status
reachability **fail-closed**.

##### Fields

- `formats: Vec<Format>`
  - Which formats to accept. An empty set is treated as "both" (the default).
- `qualified_gate: bool`
  - Enable the opt-in TS 119 615 qualified-status determination (default off).
- `status_reachability: StatusReachability`
  - The fail-closed-vs-best-effort status-reachability policy (default fail-closed).

#### struct `VerificationResult`

```rust
struct VerificationResult
```

The verdict of a verification (data-model.md `VerificationResult`).

No **false-accept** (SC-002): any failed always-on check yields `valid = false` with at least one
specific [`ReasonCode`]. `qualified_status` is `Some` only when the opt-in gate ran.

##### Fields

- `valid: bool`
  - The always-on bar: signature + trust-list membership + validity + status + holder binding +
disclosure integrity + (when a request was supplied) request binding all passed.
- `disclosed_attributes: BTreeMap<String, AttributeValue>`
  - Only the disclosed subset of attributes; undisclosed attributes are neither revealed nor
required.
- `trust_status: TrustStatus`
  - The issuer trust status.
- `qualified_status: Option<QualifiedStatus>`
  - The eIDAS qualified status, present only when the opt-in gate ran.
- `reasons: Vec<ReasonCode>`
  - The machine-readable reasons for the verdict (especially for INVALID — FR-005); empty for a
clean VALID.

##### Methods

```rust
fn invalid(reason: ReasonCode) -> Self
```

Construct an INVALID verdict carrying a single specific reason, with no disclosed attributes
and an `Untrusted` issuer — the safe default for an early reject (e.g. an unsupported format
or a malformed credential), before the issuer or its disclosures are even established.

### Enums

#### enum `AttributeValue`

```rust
enum AttributeValue
```

A disclosed attribute value.

Credential claims are heterogeneous (strings, numbers, booleans, nested maps, byte strings — e.g.
an mdoc `portrait`). A closed, self-describing value type keeps the CBOR wire contract explicit
rather than leaning on an untyped `serde_json::Value`/`ciborium::Value` (which would also drag a
`Debug`-via-untyped-value foot-gun into the public API).

##### Variants

- `Text(String)`
  - A UTF-8 text claim.
- `Integer(i64)`
  - An integer claim.
- `Boolean(bool)`
  - A boolean claim.
- `Bytes(Vec<u8>)`
  - A byte-string claim (e.g. an mdoc portrait or a raw value).
- `Map(BTreeMap<String, Self>)`
  - A nested object claim.
- `Array(Vec<Self>)`
  - An array claim.
- `Null`
  - An explicitly null claim.

#### enum `Format`

```rust
enum Format
```

The credential format of an attestation. The format determines the encoding (JOSE vs CBOR/COSE)
and the selective-disclosure / holder-binding mechanism (data-model.md).

##### Variants

- `SdJwtVc`
  - SD-JWT VC (IETF RFC 9901 / draft-16) — compact JWS with selective-disclosure salts and a
holder Key-Binding JWT.
- `Mdoc`
  - ISO/IEC 18013-5 mdoc — a CBOR `DeviceResponse` with a COSE_Sign1 `IssuerAuth` and `DeviceAuth`
holder binding.

#### enum `IssuerRole`

```rust
enum IssuerRole
```

The issuer role, which selects the trust anchor for verification (research D5).

EUDI anchors trust **per role** — a qualified-EAA issuer is found on a different list than a PID
provider — so the role is an explicit input to [`crate::trust::TrustAnchorSource::resolve`].

##### Variants

- `Qeaa`
  - Qualified Electronic Attestation of Attributes issuer (EU LOTL + national Trusted Lists,
ETSI TS 119 612).
- `Pid`
  - Person Identification Data provider (Commission list under eIDAS Art. 5a(18)).
- `PubEaa`
  - Public-body EAA provider (Commission list under eIDAS Art. 45f(3)).
- `NonQualifiedEaa`
  - Non-qualified EAA issuer (trusted via a configured anchor, but not on a qualified list).

#### enum `QualifiedStatus`

```rust
enum QualifiedStatus
```

The eIDAS qualified status of the issuer, populated **only** by the opt-in TS 119 615 cl. 4.12
gate (otherwise absent — never assumed). See [`crate::qualified`].

Outcome conditions are pinned (tasks T018/T019): `Qualified` iff the issuer's `EAA/Q` service
entry was `granted` at the relevant time; `NotQualified` iff the entry is found but not granted
(withdrawn/suspended) at that time; `Indeterminate` iff the trust-list data is
absent/ambiguous/unreachable. There is no false "qualified" (SC-007).

##### Variants

- `Qualified`
  - The issuer's qualified-EAA service was `granted` at the relevant time.
- `NotQualified`
  - The issuer's entry was found but not granted (withdrawn/suspended) at the relevant time.
- `Indeterminate`
  - The trust-list data needed to decide was absent, ambiguous, or unreachable.

#### enum `ReasonCode`

```rust
enum ReasonCode
```

A machine-readable reason for a verification outcome (FR-005 / SC-002).

This is a **closed** enum: every failed always-on check maps to exactly one specific variant, so
an INVALID verdict always carries an actionable, stable reason (no opaque "verification failed").
New reasons are added by SemVer-minor as the verifier grows; consumers MUST treat an unknown
reason conservatively.

##### Variants

- `Tamper`
  - The issuer signature did not verify, or the credential was otherwise tampered with.
- `Expired`
  - The credential is outside its validity window at the relevant time (SD-JWT VC `nbf`/`exp`;
mdoc MSO `validityInfo`).
- `Revoked`
  - The credential is revoked per its status mechanism (status list / CRL).
- `UntrustedIssuer`
  - The issuer is not on the configured trust anchor for its role/format (absent, or an
expired/withdrawn trust-list entry).
- `StatusUnavailable`
  - The revocation/status endpoint (or trust list) was unreachable or stale and the policy is
fail-closed (never a silent VALID).
- `HolderBinding`
  - The holder binding did not verify (SD-JWT VC KB-JWT; mdoc DeviceAuth).
- `DisclosureIntegrity`
  - A disclosed attribute did not match an issuer-signed digest (SD-JWT disclosure digest; mdoc
`valueDigests`).
- `Replay`
  - The presentation was replayed — it did not echo the issued request's fresh `nonce`.
- `WrongAudience`
  - The presentation was addressed to a different audience than the verifier's `client_id`.
- `UnsupportedFormat`
  - The credential format is unrecognized or not enabled by the policy (never a guess).
- `MalformedCredential`
  - The credential or presentation was structurally malformed and could not be parsed.
- `MissingRequestBinding`
  - The request binding was required (an OpenID4VP request was supplied) but is missing from the
presentation.

#### enum `StatusReachability`

```rust
enum StatusReachability
```

The fail-closed-vs-best-effort policy for an unreachable revocation/status endpoint
(data-model.md `VerificationPolicy.statusReachability`).

##### Variants

- `FailClosed`
  - An unreachable status endpoint yields INVALID `status_unavailable` (the secure default).
- `BestEffort`
  - An unreachable status endpoint is tolerated (the credential is not failed on reachability
alone) — opt-in, for environments that accept the weaker guarantee.

#### enum `TrustStatus`

```rust
enum TrustStatus
```

The issuer's trust status under the always-on bar: present on the configured trust anchor for its
role/format, or not (data-model.md).

##### Variants

- `Trusted`
  - The issuer is present (and its trust-list entry is currently in-force) on the configured
anchor.
- `Untrusted`
  - The issuer is absent, or its entry is expired/withdrawn/revoked, on the configured anchor.

## Module `verify`

The always-on `verify` entry point (contracts/verifier.md) — T016.

The global verifier: detect the credential format (SD-JWT VC or ISO mdoc; unsupported →
[`ReasonCode::UnsupportedFormat`]), run the matching per-format always-on bar (issuer signature +
issuer **trust** via the [`TrustAnchorSource`], validity window, revocation/**status**, holder
binding, selective-disclosure integrity), and — when an OpenID4VP `request` is supplied — the
request **binding** (nonce echo + audience) via [`crate::openid4vp`]. Any failed check yields
`valid = false` with a specific [`ReasonCode`] (no false-accept — SC-002).

## Sans-IO

Like the rest of the core, this performs no network I/O: the trust anchors are passed in
(refreshed by a host-driven step beforehand), the validity instant is supplied, and the
revocation/**status** outcome is resolved by the host through [`crate::status`] and passed in as
a [`StatusOutcome`]. The format verifiers ([`crate::sdjwtvc`], [`crate::mdoc`]) own the crypto.

## Qualified-status gate (T019)

The opt-in eIDAS qualified-status determination ([`crate::qualified`]) is a separate, off-by-
default gate. [`VerifyContext::qualified_gate`] is the seam: it is **off by default**, in which
case the always-on bar runs and returns a complete verdict and `qualified_status` stays `None`.
When enabled (and a [`VerifyContext::qualified_trust_list`] is supplied), the gate populates
`VerificationResult.qualified_status` via [`crate::qualified::qualified_status`]; disabling it
leaves the always-on verdict **byte-identical** to a gate-off run (no false "qualified" — SC-007).

### Structs

#### struct `VerifyContext`

```rust
struct VerifyContext<'a>
```

The remaining per-format-bar inputs the host supplies to [`verify`] (the validity instant, the
trust-anchor role, the resolved status outcome, and the mdoc session transcript / qualified-gate
seam).

These are sans-IO inputs: `now_unix` is the verification instant; `role` selects the trust anchor
(research D5); `status` is the [`crate::status`] outcome the host already resolved; and
`session_transcript` is the mdoc `DeviceAuth` transport binding for a **non-OpenID4VP**
presentation (an OpenID4VP `request` overrides it with the reconstructed handover).

##### Fields

- `now_unix: i64`
  - The verification instant (Unix seconds) the validity window is checked against.
- `role: IssuerRole`
  - The issuer role under which trust is anchored.
- `status: StatusOutcome`
  - The revocation/status outcome resolved by the host (via [`crate::status::check_status`]).
- `session_transcript: Option<&'a [u8]>`
  - The mdoc `SessionTranscript` the `DeviceAuth` is bound to, for a presentation **without** an
OpenID4VP request (with a request, the handover is reconstructed from the request instead).
- `qualified_gate: bool`
  - **Off by default** seam for the opt-in eIDAS qualified-status gate (T019). When `false` (the
default) the always-on bar runs unchanged and `qualified_status` stays `None`. When `true`
**and** a [`Self::qualified_trust_list`] is supplied, the gate populates
`qualified_status`; the always-on verdict is byte-identical either way (SC-007).
- `qualified_trust_list: Option<&'a QualifiedTrustList>`
  - The national Trusted List the opt-in qualified gate reads (off-path unless `qualified_gate` is
set). `None` with the gate enabled yields an honest [`QualifiedStatus::Indeterminate`]
(unreachable data — never a false "qualified"). Host-supplied (the core stays sans-IO).

[`QualifiedStatus::Indeterminate`]: crate::types::QualifiedStatus::Indeterminate

### Enums

#### enum `Presentation`

```rust
enum Presentation<'a>
```

A presented credential, in one of the two mandated formats (the typed input the C-ABI wire maps
to; native callers build it directly).

SD-JWT VC is a compact text presentation; mdoc is a CBOR `DeviceResponse` paired with the audience
it was addressed to in an OpenID4VP flow (`None` for a bare offline presentation with no request
binding). Use [`detect_format`] to classify raw bytes before constructing this.

##### Variants

- `SdJwtVc(&'a str)`
  - A compact SD-JWT VC presentation (`<issuer-JWS>~<D>…~<optional KB-JWT>`).
- `Mdoc { device_response: &'a [u8], audience: Option<&'a str> }`
  - An ISO/IEC 18013-5 mdoc `DeviceResponse`, with the OpenID4VP addressed audience when one
applies (the verifier's `client_id`); `None` for a bare presentation verified without a
request binding.

##### Methods

```rust
const fn format(&self) -> Format
```

The credential format of this presentation.

### Functions

#### fn `detect_format`

```rust
fn detect_format(presentation: &[u8]) -> Option<Format>
```

Detect the credential format of raw presentation bytes, or `None` if neither format is
recognized (the caller maps `None` → [`ReasonCode::UnsupportedFormat`] — never a guess).

- **SD-JWT VC**: valid UTF-8 beginning with a compact JWS (`header.payload.signature`, base64url)
  followed by a `~` (the disclosure separator). The first segment must have exactly two `.`.
- **mdoc**: a CBOR map carrying a `documents` array (the ISO/IEC 18013-5 `DeviceResponse` shape).

#### fn `verify`

```rust
fn verify<A: TrustAnchorSource + ?Sized>(presentation: &Presentation<'_>, policy: &VerificationPolicy, anchors: &A, ctx: &VerifyContext<'_>, request: Option<&PresentationRequest>) -> VerificationResult
```

The always-on `verify` entry point (contracts/verifier.md).

Detects the format (rejecting an unsupported one, or one the `policy` does not enable, as
[`ReasonCode::UnsupportedFormat`]), runs the matching per-format always-on bar against the
configured `anchors`, and — when `request` is supplied — the OpenID4VP binding (nonce + audience).
Returns a [`VerificationResult`] that is `valid = true` only when every check passed, else
`valid = false` with a specific [`ReasonCode`] (no false-accept — SC-002).

## Module `wire`

Versioned CBOR wire envelope for the attestation C-ABI (and WASM) boundary.

Mirrors `cleverbase-core::wire`: the C-ABI and non-native bindings exchange these CBOR-encoded
envelopes; native bindings can call the typed Rust API ([`verify()`](crate::verify())) directly. The envelope
carries an [`ATTESTATION_SCHEMA_VERSION`] so a binding can refuse a payload it cannot read
(Principle VII).

Protocol logic lives **here, in the core** — the `cleverbase-ffi` C-ABI only wraps
[`process_verify_bytes`] in the pointer/length/free dance (Principle III: no protocol logic in
bindings). The `verify` operation is the always-on bar (contracts/verifier.md); this envelope
carries everything the sans-IO [`verify()`](crate::verify()) entry point needs: the presented credential, the
verifier policy, the configured **trust anchors** (resolved by the host-driven trust step and
passed in as `(role, format, cert)` entries — data-model.md `TrustAnchorSource`), the verification
**context** (instant, role, resolved revocation/status outcome, mdoc transcript, qualified-gate
seam), and the optional OpenID4VP **request** the presentation must be bound to.

## Schema version 3

Version 2 replaced the version-1 foundation seam (which carried only `presentation` + `policy` and
returned `NotImplemented`) with the full always-on verifier wiring. Version 3 (this) additively
carries the opt-in qualified-status gate's national Trusted List
([`WireContext::qualified_trust_list`]) alongside the existing `qualified_gate` flag (T020), so
the C-ABI gate has data. The CBOR shape changed (an additive field), so the schema version was
bumped (Principle VII); a binding speaking an older version is refused with a clear message rather
than mis-parsed.

### Structs

#### struct `VerifyRequest`

```rust
struct VerifyRequest
```

A `verify` request: the presented credential, the policy, the configured anchors, the
verification context, and (optionally) the OpenID4VP request the presentation must be bound to.

##### Fields

- `schema_version: u32`
  - Wire schema version of this envelope.
- `presentation: WirePresentation`
  - The presented credential.
- `policy: VerificationPolicy`
  - The verifier policy.
- `anchors: Vec<WireTrustAnchor>`
  - The configured trust anchors (resolved + passed in by the host's trust-refresh step).
- `context: WireContext`
  - The verification context (instant, role, status, transcript, gate seam).
- `request: Option<PresentationRequest>`
  - The OpenID4VP request the presentation must be bound to, when present.

#### struct `VerifyResponse`

```rust
struct VerifyResponse
```

A versioned `verify` response envelope.

##### Fields

- `schema_version: u32`
  - Wire schema version of this envelope.
- `outcome: VerifyOutcome`
  - The operation outcome.

#### struct `WireContext`

```rust
struct WireContext
```

The verification context carried on the wire (the CBOR mirror of [`VerifyContext`]).

##### Fields

- `now_unix: i64`
  - The verification instant (Unix seconds).
- `role: IssuerRole`
  - The issuer role under which trust is anchored.
- `status: StatusOutcome`
  - The host-resolved revocation/status outcome.
- `session_transcript: Option<Vec<u8>>`
  - The mdoc `SessionTranscript` for a non-OpenID4VP presentation (else `None`).
- `qualified_gate: bool`
  - The off-by-default opt-in qualified-status gate flag (T019/T020). When `true`, the gate runs
over [`Self::qualified_trust_list`] and populates `VerificationResult.qualified_status`; when
`false` (the default) the always-on verdict is byte-identical and `qualified_status` is absent
(SC-007).
- `qualified_trust_list: Option<Vec<u8>>`
  - The raw national Trusted List JSON the opt-in gate reads (the offline
`qualified-trust-list.json` form / a host-supplied national TL), carried additively on the
wire so the C-ABI gate has data. `None` (the default) with the gate enabled yields an honest
`Indeterminate` (unreachable data — never a false "qualified").

#### struct `WireTrustAnchor`

```rust
struct WireTrustAnchor
```

A single configured trust anchor passed across the wire: a trusted issuer/anchor certificate for
a `(role, format)` (the host resolved these from the EU LOTL / national TLs / IACA roots in its
trust-refresh step and passes them in — the core stays sans-IO).

##### Fields

- `role: IssuerRole`
  - The issuer role this anchor covers.
- `format: Format`
  - The credential format this anchor covers.
- `cert_der: Vec<u8>`
  - The DER-encoded trusted issuer/anchor certificate.

### Enums

#### enum `VerifyOutcome`

```rust
enum VerifyOutcome
```

The outcome of a `verify` operation.

##### Variants

- `Ok { result: VerificationResult }`
  - The verdict (the always-on bar — contracts/verifier.md).
- `Err { message: String }`
  - A decode/usage error rendered as a message (e.g. an unsupported schema version).

#### enum `WirePresentation`

```rust
enum WirePresentation
```

The presented credential as carried on the wire (the CBOR mirror of [`Presentation`]).

SD-JWT VC is the compact presentation string; mdoc is the `DeviceResponse` bytes plus the
OpenID4VP addressed audience (present only when verifying against a request).

##### Variants

- `SdJwtVc { presentation: String }`
  - A compact SD-JWT VC presentation string.
- `Mdoc { device_response: Vec<u8>, audience: Option<String> }`
  - An mdoc `DeviceResponse` plus its OpenID4VP addressed audience (when bound to a request).

### Functions

#### fn `decode_verify_request`

```rust
fn decode_verify_request(bytes: &[u8]) -> Result<VerifyRequest, String>
```

Decode a `verify` request envelope, rejecting unknown schema versions.

# Errors

Returns the decode error (or a schema-version mismatch message) as a `String`.

#### fn `encode_verify_response`

```rust
fn encode_verify_response(outcome: VerifyOutcome) -> Vec<u8>
```

Encode a `verify` response envelope at the current schema version.

#### fn `process_verify_bytes`

```rust
fn process_verify_bytes(input: &[u8]) -> Vec<u8>
```

Decode → verify → encode. Pure; shared by the C-ABI, language bindings, and tests (single source
of truth — Principle III). A well-formed request runs the always-on [`verify`] entry point and
returns the [`VerificationResult`]; a malformed one yields [`VerifyOutcome::Err`].

### Constants

#### const `ATTESTATION_SCHEMA_VERSION`

```rust
const ATTESTATION_SCHEMA_VERSION: u32 = 3
```

Wire schema version of the attestation envelope. Bumped on a breaking CBOR-shape change within a
SemVer major (independent of the signing core's `SCHEMA_VERSION`). Version 2 carries the full
verifier inputs (the always-on bar + OpenID4VP binding); version 1 was the foundation seam.
