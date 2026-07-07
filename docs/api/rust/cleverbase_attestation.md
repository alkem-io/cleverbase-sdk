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
  RustCrypto stack (`p256`/`ecdsa`/`rsa`/`sha2`/`x509-cert`) plus `coset` for COSE.
- **One Rust core** (Principle III): all attestation logic lives here, surfaced over the existing
  `cleverbase-ffi` C-ABI; the bindings stay thin.
- **Not a wallet** (Principle IV): holder keys are the integrator's, exercised via the spec-001
  signer-hook; the SDK never holds a private key.

## Status

User Story 1 (feature 004 — the MVP) is implemented: the global [`verify()`] entry point assembles
the always-on bar over both format verifiers ([`sdjwtvc`], [`mdoc`]), the native EU trust-list
engine ([`trust`]), the revocation/[`status`] check (fail-closed by default), and the
[`openid4vp`] request binding (nonce + audience), surfaced over the `cleverbase-ffi` C-ABI via
[`wire`]. The opt-in [`qualified`]-status gate (eIDAS qualified-status determination) is
implemented and off by default ([`verify::VerifyContext::qualified_gate`] is the seam); the gated
[`issuance`] path (US2 — OpenID4VCI `obtain` + OpenID4VP holder `present` via the signer-hook) is
implemented and skips when no issuer backend is configured.

## Module `crypto`

Shared crate-internal crypto helpers (DRY — Constitution Principle III): the **one** SHA-256
digest, the **one** P-256 JWK → SEC1 decode, the **one** cert-DER → P-256 verifying-key path, and
the IANA hash-algorithm name the verifier supports.

The JWK decode + digest were previously copy-pasted across [`crate::sdjwtvc`] (the SD-JWT VC
verifier), [`crate::issuance::signer`] (the holder context), and [`mod@crate::issuance::present`]
(the `_sd_alg` name) — three independent transcriptions of the same `kty=EC`/`crv=P-256` guard,
base64url `x`/`y` decode, 32-byte-length check, and `0x04 ‖ X ‖ Y` SEC1 assembly, plus two copies
of `sha256(&[u8]) -> [u8; 32]` and a stray `"sha-256"` literal. The cert-DER → verifying-key
`Certificate::from_der → subject_public_key_info.to_der() → from_public_key_der` sequence was
likewise transcribed in both issuer-signature verifiers ([`crate::sdjwtvc`]'s JWS `x5c` leaf and
[`crate::mdoc`]'s COSE_Sign1 `IssuerAuth` `x5chain` leaf). All are consolidated here so there is
one authoritative source.

No hand-rolled crypto (Principle IV): the digest is the SDK's vetted `sha2`, the public-point
decode ends in `p256::ecdsa::VerifyingKey::from_sec1_bytes`, and the cert path ends in
`from_public_key_der` — each crate's own on-curve check is preserved.

## Module `datetime`

One authoritative RFC 3339 / ISO 8601 **UTC** timestamp parser for the whole verifier (DRY —
Constitution Principle III).

Both the mdoc MSO `validityInfo` (`validFrom`/`validUntil`/`signed`) and the trust-list
timestamps (TS 119 612 `NextUpdate`, qualified-status effective `startingTime`) need the same
grammar: the `YYYY-MM-DDThh:mm:ssZ` UTC form, with optional fractional seconds. They previously
carried two independent copies, both of which validated the day only as `1..=31` for *every*
month — so `2023-02-31`, `2023-04-31`, and `2023-02-29` (non-leap) parsed to a **wrong instant**
(`civil_to_unix` silently rolls an over-long day forward into the next month). For a validity
window / stale-list boundary that is a security defect (a tampered or malformed instant is
accepted instead of failing closed).

This single parser is **correct** (day-of-month is validated against the month and leap year)
and **fails closed** (returns `None` on any deviation), so a malformed timestamp can never parse
to a wrong instant.

No date crate: the civil-date math is the public-domain `days_from_civil` algorithm (Howard
Hinnant) — the same self-contained algorithm `chrono`/`time` use — keeping the verifier
pure-Rust / WASM-able with no extra dependency.

## Module `dcql`

In-core OpenID4VP 1.0 **DCQL** (Digital Credentials Query Language) model + evaluator.

This module is the "did I get what I requested" gate the verifier was missing (conformance-audit
Theme 4 / T4.1): the always-on bar proves a presentation is cryptographically sound, trusted, and
request-bound, but it never checked that the credential **matches the DCQL request** — so a
trusted, freshly-bound credential of the **wrong** `vct`/`docType`, or one missing a requested
claim, used to pass as VALID (a false-trust). The DCQL is no longer carried opaquely: it is parsed
and evaluated **in-core** (the explicit product decision — full DCQL evaluation in-core, not
delegated to the wallet, per OpenID4VP 1.0 §"Security Checks on the Returned Credentials and
Presentations": *"the Verifier MUST NOT rely on the Wallet to enforce these constraints"*).

## Specification (verified online, not from training data)

OpenID4VP **1.0** — <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html>; source
`openid/OpenID4VP` `1.0/openid-4-verifiable-presentations-1_0.md`:

- **§6 Digital Credentials Query Language (DCQL)** — top-level `credentials` (REQUIRED, non-empty
  array of Credential Queries) + `credential_sets` (OPTIONAL); *"Implementations MUST ignore any
  unknown properties."*
- **§6.1 Credential Query** — `id` (REQUIRED), `format` (REQUIRED), `multiple` (default `false`),
  `meta` (REQUIRED; format-specific), `claims` (OPTIONAL), `claim_sets` (OPTIONAL),
  `require_cryptographic_holder_binding` (default `true`).
- **§6.2 Credential Set Query** — `options` (REQUIRED, array of arrays of credential `id`s),
  `required` (default `true`).
- **§6.3 Claims Query** — `id` (REQUIRED iff `claim_sets` present), `path` (REQUIRED, a Claims Path
  Pointer), `values` (OPTIONAL, non-empty array of strings/integers/booleans).
- **§"Claims Path Pointer"** — a non-empty array of strings (object key), non-negative integers
  (array index), and `null` (all array elements) for JSON-based credentials (SD-JWT VC); exactly two
  string components `[namespace, dataElementIdentifier]` for ISO mdoc credentials.
- **§"Selecting Claims"** — `claims` absent ⇒ no SD claims requested; `claims` present and
  `claim_sets` absent ⇒ all listed claims requested; both present ⇒ one `claim_sets` option (the
  first satisfiable); `claim_sets` MUST NOT be present if `claims` is absent.
- **§"Selecting Credentials"** — no `credential_sets` ⇒ all `credentials` requested; otherwise all
  `required` (or `required`-omitted) Credential Set Queries + optionally any non-required ones.
- **§"VP Token Validation"** — step 2.2: *"Validate that the returned Credential(s) meet all
  criteria defined in the query in the Authorization Request (e.g., Claims included in the
  presentation)."*; step 3: *"Check that the set of Presentations returned satisfies all
  requirements defined in the Verifier's request as described in [Selecting Claims and
  Credentials]."*
- Format meta — SD-JWT VC `vct_values` (§"Parameter in the `meta` parameter ... `vct_values`"); mdoc
  `doctype_value` (§"Parameter in the `meta` parameter ... `doctype_value`").

## What this module enforces (and what it deliberately does not)

It parses the DCQL query and, against a presentation the always-on bar already accepted, checks
(a) **format**, (b) **meta** (SD-JWT VC `vct` ∈ `vct_values`; mdoc `docType` == `doctype_value`),
(c) every requested **claim path** resolves in the **claims present in the verified presentation**
(honoring `claim_sets`), and (d) a claim's presented value ∈ its `values`. The set-level check
(§"VP Token Validation" step 3 + §"Selecting Credentials") is [`crate::openid4vp::verify_vp_token`].

Value matching follows §6.3: for an ISO mdoc the CBOR value is matched after conversion to JSON
(RFC 8949 §6.1) — the SDK's [`AttributeValue`] is already that decoded JSON-shaped value, so a
`Text`/`Integer`/`Boolean` is matched against a string/integer/boolean respectively.

Claim paths resolve against the **full set of claims present in the verified presentation** — the
claims the holder actually presented, whether **selectively disclosed** OR carried in the **clear**
(non-selectively-disclosable). Per OpenID4VP 1.0 §8.6 "VP Token Validation" step 2.2 a Verifier
validates the query against the "Claims included in the presentation", and §6.4 notes a presentation
legitimately carries non-selectively-disclosable claims — so a clear subject claim satisfies a query
exactly as a disclosed one does. For SD-JWT VC this is the clear issuer-signed payload claims MERGED
with the disclosed claims (the caller passes `crate::sdjwtvc::presented_claims`); for mdoc the
namespace-grouped `disclosed_attributes` is already the full presented set (the `IssuerSignedItems`).
This is broader than the privacy-minimal [`crate::types::VerificationResult::disclosed_attributes`]
the verifier reports to the host, which omits the clear claims.

`trusted_authorities` (§6.1.1) is not evaluated here (issuer trust is the always-on bar's per-role
anchoring); `require_cryptographic_holder_binding:false` is not honored (the SDK always requires
holder binding — a documented secure default).

### Structs

#### struct `ClaimsQuery`

```rust
struct ClaimsQuery
```

One OpenID4VP 1.0 Claims Query (§6.3).

##### Fields

- `id: Option<String>`
  - The claim `id` (REQUIRED iff the owning query has `claim_sets`; OPTIONAL otherwise).
- `path: Vec<PathComponent>`
  - The Claims Path Pointer to the claim (§"Claims Path Pointer"); always non-empty.
- `values: Option<Vec<ClaimValue>>`
  - The expected values (§6.3 `values`): a present, non-empty set the disclosed value must be in.

#### struct `CredentialQuery`

```rust
struct CredentialQuery
```

One OpenID4VP 1.0 Credential Query (§6.1): a request for a presentation of a matching credential.

##### Fields

- `id: String`
  - The `id` identifying this credential in the `vp_token` response and in `credential_sets`.
- `format: Format`
  - The requested credential format.
- `meta: CredentialMeta`
  - The format-specific `meta` constraint (SD-JWT VC `vct_values`; mdoc `doctype_value`).
- `claims: Vec<ClaimsQuery>`
  - The requested claims (§6.3); empty when the query lists no selectively-disclosable claims.
- `claim_sets: Vec<Vec<String>>`
  - The `claim_sets`: alternative combinations of claim `id`s, in Verifier preference order. Empty
when absent (then all of [`Self::claims`] are requested — §"Selecting Claims").
- `multiple: bool`
  - Whether more than one Presentation may be returned for this query (§6.1 `multiple`, default
`false`).

#### struct `CredentialSetQuery`

```rust
struct CredentialSetQuery
```

One OpenID4VP 1.0 Credential Set Query (§6.2).

##### Fields

- `options: Vec<Vec<String>>`
  - The `options`: each is a set of credential `id`s that satisfies this use case (§6.2). One option
is satisfied iff every credential `id` it lists is satisfied.
- `required: bool`
  - Whether this set is required to satisfy the request (§6.2 `required`, default `true`).

#### struct `DcqlQuery`

```rust
struct DcqlQuery
```

A parsed OpenID4VP 1.0 DCQL query (§6). Carries only the credential/claim/set constraints this SDK
evaluates; unknown top-level and per-object properties are ignored (§6 *"Implementations MUST ignore
any unknown properties"*).

[`parse`](Self::parse) is **lenient** about entries it cannot enforce, but only up to the point that
leniency stays fail-closed. A Credential Query whose `format` this SDK does not support (or that
lacks an `id`/`format`) is dropped from [`Self::credentials`] — it cannot be satisfied by either
supported format, so it imposes no enforceable in-core constraint on a presentation of a supported
format. But once the `format` IS supported, a structurally-malformed `claims`/`path`/`values`/
`claim_sets` does NOT drop the query: dropping it would collapse `credentials` toward empty and
silently disable the "did I get what I requested" gate (`evaluate_single` → `Inactive`) — a
fail-OPEN. Such a query is kept ALIVE but UNSATISFIABLE (via the never-resolving
[`PathComponent::Unrepresentable`] / [`ClaimValue::Unrepresentable`] sentinels and never-matching
`claim_sets` options), so the gate runs and returns `NotSatisfied` (fail closed). A single bad entry
thus never disables the gate for the rest. `parse` errors only on a non-JSON / non-object input or a
duplicate credential `id`.

##### Fields

- `credentials: Vec<CredentialQuery>`
  - The Credential Queries this SDK can evaluate (supported format + well-formed), in request order.
- `credential_sets: Vec<CredentialSetQuery>`
  - The Credential Set Queries (§6.2) constraining which combinations of credentials are required.

##### Methods

```rust
fn parse(json: &str) -> Result<Self, DcqlError>
```

Parse a DCQL query from its JSON text (§6).

Lenient by contract (see the type docs): unsupported-format or malformed Credential Queries /
Credential Set Queries are dropped rather than failing the whole parse, so one bad entry never
disables enforcement for the rest. Errors only on a non-JSON / non-object input.

# Errors

[`DcqlError::Json`] if the text is not JSON; [`DcqlError::NotAnObject`] if it is not a JSON
object.

### Enums

#### enum `ClaimValue`

```rust
enum ClaimValue
```

An expected claim value (§6.3 `values`: *"an array of strings, integers or boolean values"*).

##### Variants

- `Text(String)`
  - A string value.
- `Integer(i64)`
  - An integer value.
- `Boolean(bool)`
  - A boolean value.
- `Unrepresentable`
  - A numeric `values` entry that is NOT representable as the comparison type (`i64`) — a JSON
float, or an integer outside `i64` range. Such a value can never equal a disclosed
string/integer/boolean, so it is retained as an explicit NEVER-matching sentinel rather than
dropped: dropping it would collapse the whole Credential Query (via the lenient parse), leaving
`evaluate_single` `Inactive` and the "did I get what I requested" gate silently disabled — a
fail-OPEN. Keeping it as unmatchable keeps the query enforced (the claim simply never resolves →
`NotSatisfied`, fail-closed). Never produced from a spec-valid, representable value.

#### enum `CredentialMeta`

```rust
enum CredentialMeta
```

The format-specific `meta` constraint of a [`CredentialQuery`] (§6.1 `meta`). A `None` constraint
means the `meta` placed no type restriction (`meta` absent/empty — §6.1 *"If empty, no specific
constraints are placed on the metadata"*).

##### Variants

- `SdJwtVc { vct_values: Option<Vec<String>> }`
  - SD-JWT VC `meta.vct_values` (§"... `vct_values`"): the allowed `vct` values. `None` ⇒ no `vct`
constraint.
- `Mdoc { doctype_value: Option<String> }`
  - ISO mdoc `meta.doctype_value` (§"... `doctype_value`"): the allowed `docType`. `None` ⇒ no
`docType` constraint.

#### enum `DcqlError`

```rust
enum DcqlError
```

A failure parsing the DCQL JSON into a [`DcqlQuery`]. Only a truly unusable input (non-JSON, or a
JSON value that is not an object) errors; malformed/unsupported sub-entries are dropped leniently.

##### Variants

- `Json`
  - The query text is not valid JSON.
- `NotAnObject`
  - The query is valid JSON but not a JSON object (§6: a DCQL query is a JSON object).
- `DuplicateCredentialId`
  - Two Credential Queries share the same `id` (§6.1: credential `id`s MUST be unique). A duplicate
is rejected rather than silently last-wins — otherwise the set-level `by_id` lookup
([`crate::openid4vp::verify_vp_token`]) would evaluate a presentation against the WRONG query.

#### enum `PathComponent`

```rust
enum PathComponent
```

One component of a Claims Path Pointer (§"Claims Path Pointer").

##### Variants

- `Key(String)`
  - A string component: select the value at this object key.
- `Index(u64)`
  - A non-negative-integer component: select this 0-based index of an array.
- `AllElements`
  - A `null` component: select all elements of the currently selected array(s).
- `Unrepresentable`
  - A path component that is NOT a valid Claims Path Pointer element (§"Claims Path Pointer"
admits only strings, non-negative integers, and `null`) — a JSON float, a negative index, or a
nested object/array. Mirrors [`ClaimValue::Unrepresentable`]: it is retained as an explicit
NEVER-resolving sentinel rather than dropped, because dropping it would collapse the whole
Credential Query (via the lenient parse), leaving `evaluate_single` `Inactive` and the "did I
get what I requested" gate silently disabled — a fail-OPEN. Keeping it unresolvable keeps the
query enforced (the claim simply never resolves → `NotSatisfied`, fail closed). Never produced
from a spec-valid path component.

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
fn build_device_signature(doc_type: &str, session_transcript: &[u8], device_name_spaces_bytes: &[u8], audience: &str, nonce: &str) -> Result<DeviceSignatureBuild, SignerError>
```

Build the mdoc `DeviceSignature` signing input over the `DeviceAuthentication` for `doc_type`,
bound to a session-transcript handover that folds in `audience`/`nonce`.

`session_transcript` is the CBOR `SessionTranscript` the holder signs over (for OpenID4VP, the
[`crate::openid4vp::oid4vp_handover_transcript`] of `audience`+`nonce`). `device_name_spaces_bytes`
is the **exact** `DeviceNameSpacesBytes` (`#6.24(bstr .cbor DeviceNameSpaces)`) of the
`deviceSigned.nameSpaces` being presented — the verifier rebuilds `DeviceAuthentication` from the
document's *actual* `deviceSigned.nameSpaces` ([`crate::mdoc`]), so the signature MUST cover the
same bytes or a device-disclosed (non-empty) namespace map would be rejected. Use
[`empty_device_name_spaces_bytes`] for the empty-disclosure case.
The host signs [`DeviceSignatureBuild::input`]; [`DeviceSignatureBuild::assemble`] splices the
result.

# Errors

[`SignerError::Serialize`] on a (here impossible) CBOR-encode failure of an in-memory value, or a
malformed `session_transcript` / `device_name_spaces_bytes` (not decodable CBOR).

##### fn `empty_device_name_spaces_bytes`

```rust
fn empty_device_name_spaces_bytes() -> Vec<u8>
```

The `DeviceNameSpacesBytes` for an empty device-disclosed namespace map (`#6.24(bstr .cbor {})`)
— the bytes to sign over when the device discloses no extra namespaces. Infallible (the encode is
the crate's infallible `cbor_to_vec`).

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

`credential offer (pre-authorized_code)` → POST token endpoint → POST the **Nonce Endpoint** for a
fresh `c_nonce` (OpenID4VCI 1.0 §7 `#nonce-endpoint`) → `Sign` the OpenID4VCI proof-JWT (PoP) via
the signer-hook → POST credential endpoint with the `proofs` object → parse the issued SD-JWT VC /
mdoc out of the `credentials` array into a [`HeldAttestation`]. The pre-authorized-code grant is
the self-contained flow the reference issuer supports without an interactive browser leg.

## OpenID4VCI 1.0 wire shapes (verified online against the 1.0 final text)

This path tracks **OpenID4VCI 1.0 final**
(<https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html>; source
`openid/OpenID4VCI` `1.0/openid-4-verifiable-credential-issuance-1_0.md`), which made three
breaking changes over the early `~draft-13` shapes this code originally tracked:

1. **Credential Request** carries `proofs` — an object keyed by proof type whose value is a
   **non-empty array** (`{"proofs":{"jwt":[<jwt>]}}`), replacing the draft singular
   `proof`/`proof_type` (§8.2 `#credential-request`).
2. The one-time `c_nonce` is fetched from a dedicated **Nonce Endpoint** rather than read from the
   Token Response (§7 `#nonce-endpoint`; the Token Response no longer carries `c_nonce`).
3. **Credential Response** returns `credentials` — an array of objects, each with a `credential`
   member — replacing the draft top-level `credential` string (§8.3 `#credential-response`).

#### Structs

##### struct `CredentialOffer`

```rust
struct CredentialOffer
```

An OpenID4VCI credential offer (the pre-authorized-code path — the self-contained grant the
reference issuer supports). The `credential_configuration_id` selects which credential to request
(and its [`Format`]).

###### Fields

- `pre_authorized_code: Secret`
  - The OpenID4VCI `pre-authorized_code` from the offer's grant. It is a bearer grant (redeemable
for the credential), so it is held as a redacting [`Secret`] — it never appears in
`Debug`/log/panic output (FR-010, Constitution Principle IV), yet still (de)serializes
transparently so the offer round-trips on the wire and the redemption site percent-encodes the
live value (only the `Debug` exposure was the leak).
- `credential_configuration_id: String`
  - The credential configuration id to request (e.g. `eu.europa.ec.eudi.pid_vc_sd_jwt`).
- `format: Format`
  - The format of the credential this configuration issues (so the SDK parses the right shape).
- `tx_code: Option<Secret>`
  - The End-User-supplied **Transaction Code** value to send in the Token Request, present only
when the offer's pre-authorized-code grant carried a `tx_code` object (OpenID4VCI 1.0 §6.1 +
§Token-Request `#token-request`: "This value MUST be present if a `tx_code` object was present
in the Credential Offer"). It is a low-entropy one-time code (typically a PIN delivered out of
band), so it is held as a redacting [`Secret`] (never in `Debug`/log output — FR-010) yet
(de)serializes transparently so the offer round-trips and the token-request site percent-encodes
the live value. `None` when the offer carried no `tx_code` object (the default).

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
- `nonce_endpoint: String`
  - The OpenID4VCI **Nonce Endpoint** (`nonce_endpoint` Credential Issuer Metadata, OpenID4VCI 1.0
§7 `#nonce-endpoint`). 1.0 moved the one-time `c_nonce` out of the Token Response: the flow
POSTs here (unauthenticated, empty body) for a fresh `c_nonce` before building the PoP proof. A
Credential Issuer that requires `c_nonce` values in the proof MUST offer this endpoint
(`#nonce-endpoint`); the EUDI reference issuer does.
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
- `NonceRequest(String)`
  - The Nonce Endpoint (OpenID4VCI 1.0 §7 `#nonce-endpoint`) returned a non-success status or a
body without the REQUIRED `c_nonce`.
- `CredentialRequest(String)`
  - The credential endpoint returned a non-success status or an unparseable body.
- `Deferred(String)`
  - The issuer returned a **deferred** Credential Response (HTTP 202 + a `transaction_id`,
OpenID4VCI 1.0 §8.3 `#credential-response`). Deferred issuance — polling the Deferred Credential
Endpoint (§9 `#deferred-credential-issuance`) — is a documented scope cut (see
`standards-conformance.md`), so it is surfaced as a clear, distinct terminal failure rather than
a confusing "missing credentials" parse error.
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
- `MultiDocumentMdoc(usize)`
  - The held mdoc `DeviceResponse` carries more than one `Document`. The holder `present` seam
signs ONE `DeviceSignature` (one [`PreparedPresentation::signing_input`], one host signature),
so it can bind exactly one document; a multi-document held credential is rejected rather than
producing a token whose extra documents carry a signature over the FIRST document's data (which
the verifier — checking each document against its OWN docType + `deviceSigned.nameSpaces` —
would reject). A holder presents individual credentials; multi-document binding is a separate,
multi-signature seam (a documented follow-on), never a silently-invalid token.

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
fn present<S: Signer>(held: &HeldAttestation, request: &PresentationRequest, holder: &HolderContext, disclose: &BTreeSet<String>, signer: &S, iat: i64) -> Result<HolderPresentation, PresentError> where <S>::Error: Display
```

Build an OpenID4VP `vp_token` for the held attestation, disclosing only `disclose`, bound to the
verifier's `request` via the holder signer-hook.

The produced [`HolderPresentation`] **verifies under** [`crate::openid4vp::verify_response`]
against the same `request` (the round-trip), revealing only the `disclose` subset. `iat` is the
holder's signing instant (the KB-JWT `iat`). A thin wrapper over [`prepare_present`] +
[`PreparedPresentation::finish`] with an in-process [`Signer`].

A `disclose` entry is a `/`-delimited qualified string in BOTH formats: for an SD-JWT VC it is the
claim's JSON-pointer path (a top-level claim is its bare name, a nested claim is `parent/leaf`); for
an mdoc it is the namespace-qualified `"{namespace}/{elementIdentifier}"` (see `qualified_element_id`).
An entry matching no disclosable claim is rejected as [`PresentError::UndisclosableClaim`].

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
shape an SD-JWT VC issuer embeds so the verifier can check the KB-JWT against the bound key. The
embedded JWK is stripped of any private members via [`Self::public_jwk_only`] (FR-010).

```rust
fn new<impl Into<String>: Into<String>>(holder_public_jwk: Value, key_handle: impl Into<String>) -> Self
```

Construct a holder context from a public JWK and a host key handle.

```rust
fn public_jwk_only(&self) -> Value
```

The holder JWK with **every private/symmetric member stripped** (`d`, `p`, `q`, `dp`, `dq`,
`qi`, `k`, `oth`) so only the public key is ever emitted on the wire (FR-010, Constitution
Principle IV — the SDK MUST NEVER leak secrets).

A [`HolderContext`] is supposed to carry only the holder *public* JWK, but a common JWK-export
mistake leaves the private scalar `d` (or the RSA CRT params) attached. The SDK is the
documented last line of defense, so it strips them here rather than trusting the integrator to
have done so — used at **every** embed site (the PoP-JWT JOSE header and the `cnf`).

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

[`SignerError::BadSignatureLength`] if the signature is not the algorithm's expected length;
[`SignerError::Serialize`] if the to-be-signed buffer is not valid UTF-8 (impossible for an
SDK-built input — it is ASCII base64url `header.payload` — but checked rather than assumed).

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

[`SignerError::BadSignatureLength`] if the signature is not the algorithm's expected length;
[`SignerError::Serialize`] if the to-be-signed buffer is not valid UTF-8 (impossible for an
SDK-built input — it is ASCII base64url `header.payload` — but checked rather than assumed).

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

Build the OpenID4VCI **proof-of-possession** JWT signing input (the `jwt` proof type, OpenID4VCI
1.0 §F.1 `#jwt-proof-type`). The header carries `typ` (REQUIRED, `openid4vci-proof+jwt`), `alg`
(REQUIRED, ES256), and the holder public key in the `jwk` header (so the issuer binds it as the
credential's `cnf`); the body carries `aud` (REQUIRED, the Credential Issuer Identifier), `iat`
(REQUIRED), and `nonce` (the `c_nonce` from the Nonce Endpoint, §7 `#nonce-endpoint`). `iss` is
omitted: §F.1 requires it omitted "if the access token ... was obtained from a Pre-Authorized Code
Flow through anonymous access to the token endpoint", which is this path.

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
2. **`valueDigests` integrity (in-house)** — each disclosed `IssuerSignedItem` is hashed (with the
   MSO `digestAlgorithm`) over its **on-wire `IssuerSignedItemBytes`** — the `#6.24(bstr)` element
   exactly as received (ISO/IEC 18013-5 §9.2.2.5), never a re-encode — and matched against the MSO
   `valueDigests`; any mismatch is rejected. This is the selective-disclosure-integrity check.
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

#### struct `MdocVerifyMeta`

```rust
struct MdocVerifyMeta
```

Verify a presented ISO/IEC 18013-5 mdoc `DeviceResponse`.

Runs the mdoc always-on bar — `IssuerAuth` signature + DS trust, in-house `valueDigests`
integrity, MSO `validityInfo` (including the `signed` consistency check), and the `DeviceAuth`
holder binding — over **every** document in the response (and enforces the top-level
`DeviceResponse.status`). Returns a [`VerificationResult`]: `valid = true` with the disclosed
attributes only when every document clears every check, or `valid = false` carrying a single
specific [`ReasonCode`] on the first failure (no false-accept — SC-002). Verifying every document
is essential: a verdict that covered only `documents[0]` would let a forged second document ride
inside a VALID result unverified.

## Disclosed-attributes shape (mdoc: namespace-grouped)

[`VerificationResult::disclosed_attributes`] for an mdoc is GROUPED BY NAMESPACE: each top-level key
is an ISO/IEC 18013-5 namespace, and its value is an [`AttributeValue::Map`] of that namespace's
`{ elementIdentifier: elementValue }` — i.e. `{ "org.iso.18013.5.1": Map({ "given_name": … }), … }`.
`elementIdentifier`s are unique only WITHIN a namespace, so a presentation MAY legitimately carry the
SAME id (e.g. `given_name`) in two namespaces with different values; grouping by namespace keeps
those distinct (never a false `DisclosureIntegrity` reject) and preserves the namespace provenance a
consumer needs. Across multiple documents the namespaces merge, with a same-`(namespace, id)`
conflicting value rejected as `DisclosureIntegrity` (an identical re-disclosure merges cleanly).
The byproducts the single always-on-bar pass already computed about a `DeviceResponse`, surfaced
alongside the [`VerificationResult`] so the callers that would otherwise RE-DECODE the same response
(the OpenID4VP replay classifier and the opt-in qualified gate) read these cached results instead.

Every field is derived from the ONE `ciborium` decode + per-document parse [`verify_with_meta`]
already performs; nothing here changes the verdict (it is the same `VerificationResult`
[`verify_with_meta`] returns) — it only avoids the duplicate decodes those callers used to trigger
(an attacker-multipliable soft-DoS lever: documents × IssuerAuth/MSO size).

##### Fields

- `document_count: usize`
  - The `documents` array length (`0` when the response is too malformed to read it). The OpenID4VP
replay classifier bounds its `Replay` re-attribution to the single-document case via this count,
read from the bar's own decode (no separate `DeviceResponse` re-decode).
- `claimed_issuers: Vec<(Vec<u8>, i64, Option<String>)>`
  - Per-document **claimed** issuer `(ds_cert_der, issuance_time_unix, category)` — the Document
Signer leaf (DER) from `IssuerAuth.x5chain`, the MSO `validityInfo.signed`, and the ETSI TS
119 472-1 **`category`** data element (the qualified-EAA type indication in namespace
`org.etsi.01947201.010101`; `Some(urn)` when the document disclosed the element, else `None`) —
all collected during a VALID bar pass (and EMPTY on any INVALID verdict). The three are carried
as ONE tuple per document (no parallel index-aligned arrays to re-correlate — no drift risk). The
opt-in [`crate::qualified`] gate folds these directly (it runs only on a VALID credential),
reading EACH document's already-extracted cert, its issuance/relevant time, and its `category`
(the PRO-4.12.4-03 type indication for that document — `None` ⇒ the precondition is undecidable ⇒
fail closed, never a false "qualified") rather than re-decoding the response. On a VALID
credential `signed` is mandatory (the bar requires it), so this is the single source the gate
folds — the per-document `(leaf, signed, category)` triple the bar pass paired.
- `doc_types: Vec<String>`
  - Per-document verified `docType` (the signed MSO `docType`, one per document), collected during a
VALID bar pass (and EMPTY on any INVALID verdict). The in-core OpenID4VP DCQL gate
([`crate::dcql`]) matches these against the query's `meta.doctype_value` (mdoc `docType` ==
`doctype_value`), reading the bar's already-decoded `docType` rather than re-decoding the
response. On a VALID document the MSO `docType` equals the document `docType` (the bar enforces
it), so this is the authoritative type view for the "did I get what I requested" check.
- `binding_machinery: Option<DeviceBindingMachinery>`
  - The `DeviceAuth` holder-binding **machinery** soundness across every document — populated ONLY
when the verdict is an INVALID [`ReasonCode::HolderBinding`] AND the response is single-document
(`document_count == 1`), the one case the OpenID4VP replay classifier consults it; `None`
otherwise (including any multi-document `HolderBinding`, which is never re-attributed to
`Replay`). Computed from the bar's already-decoded `documents` (no second `DeviceResponse`
decode), and — when populated — identical to the standalone `device_binding_machinery`
(a test/`test-vectors`-gated helper).

#### struct `MdocVerifyParams`

```rust
struct MdocVerifyParams<'a>
```

The verification instant and the optional session transcript needed to verify an mdoc.

`now_unix` is the time (Unix seconds) at which the MSO `validityInfo` window is enforced — passed
in (sans-IO) rather than read from the system clock so verification is deterministic and testable.
`session_transcript` is the CBOR-encoded `SessionTranscript` the holder's `DeviceSignature` is
computed over; it is supplied by the transport/OpenID4VP layer. ISO/IEC 18013-5 §9.1.5
`DeviceAuthentication` is **always** computed over a real `SessionTranscript` (the device-retrieval
transcript, or the OpenID4VP handover), so when a document asserts holder binding (carries a
`DeviceSignature`) and `session_transcript` is `None`, the verifier CANNOT confirm that binding and
MUST NOT fabricate a transcript to "pass" it. The verifier therefore rejects such a document with
[`ReasonCode::MissingRequestBinding`] rather than silently no-op the binding — the caller must
supply the explicit `SessionTranscript` (or, for OpenID4VP, the reconstructed handover via
[`crate::openid4vp`]).

##### Fields

- `now_unix: i64`
  - The verification instant, in Unix seconds, at which `validityInfo` is enforced.
- `session_transcript: Option<&'a [u8]>`
  - The CBOR-encoded ISO/IEC 18013-5 `SessionTranscript` the `DeviceSignature` is bound to.
- `role: IssuerRole`
  - The issuer role under which DS trust is resolved against the anchors (mdoc anchors to an IACA
root; the role selects the per-role/format anchor set).
- `statuses: &'a [StatusOutcome]`
  - The revocation/status outcomes (the T014 seam) — one canonical [`StatusOutcome`] **per document**,
positional (index `i` is `documents[i]`'s status), resolved by the host through the status source.
A `DeviceResponse` MAY carry MORE THAN ONE document, each with its OWN status-list pointer, so a
single outcome cannot cover them (applying one to all would let a revoked second document ride
inside a VALID verdict — SC-002). A document whose index is not covered by `statuses` fails closed
to [`StatusOutcome::Unavailable`] (never a silent VALID). Mirrors the SD-JWT VC status seam (which
carries a single credential's single outcome).
- `status_tokens: &'a BTreeMap<String, Vec<u8>>`
  - The host-fetched **signed** Token Status List tokens, keyed by list URI → raw token bytes. When a
document's MSO `status` element declares a `status_list` reference AND a token is supplied here
for its `uri`, the bar AUTHENTICATES that token in-core (verifying its signature against a key
authorized by that document's DS trust anchor) and reads the revocation bit itself — overriding
that document's positional [`Self::statuses`] entry. Empty
([`crate::status::DEFAULT_STATUS_TOKENS`]) ⇒ the positional seam alone (pre-existing behavior).

### Enums

#### enum `DeviceBindingMachinery`

```rust
enum DeviceBindingMachinery
```

Whether a presented mdoc's `DeviceAuth` holder-binding **machinery** is structurally sound — used
to tell a fresh-nonce/transcript mismatch apart from a genuine holder-binding fault when a
[`verify_with_meta`] run returns [`ReasonCode::HolderBinding`].

A nonce/transcript mismatch (a replayed presentation) fails the `DeviceSignature` check **only**
because the verifier rebuilds `DeviceAuthentication` over a different transcript than the holder
signed — the binding machinery itself is intact: the `DeviceAuth` is a `DeviceSignature`, its alg
is ES256, the MSO `DeviceKey` parses, and the signature bytes form a well-formed ES256 signature.
A genuine fault (a corrupt/garbled signature, a non-ES256 alg, an unparseable `DeviceKey`, or a
`DeviceMac`-only `DeviceAuth`) is **transcript-independent** — it fails for ANY transcript — so it
is NOT a freshness mismatch and must keep [`ReasonCode::HolderBinding`].

[`crate::openid4vp`] uses this to attribute the failure precisely: `Sound` (every document's
binding machinery is intact) ⇒ the failure is the fresh-nonce mismatch ⇒ `Replay`; `Faulty` ⇒ a
real holder-binding fault ⇒ `HolderBinding` (never masked as `Replay`).

##### Variants

- `Sound`
  - Every document's `DeviceAuth` is a well-formed ES256 `DeviceSignature` over a parseable MSO
`DeviceKey` — so a failed binding is consistent with (only) a transcript/nonce mismatch.
- `Faulty`
  - At least one document's binding is structurally broken (corrupt signature, non-ES256 alg,
unparseable `DeviceKey`, or `DeviceMac`-only) — a transcript-INDEPENDENT holder-binding fault.

### Functions

#### fn `verify_with_meta`

```rust
fn verify_with_meta<A: TrustAnchorSource + ?Sized>(device_response: &[u8], anchors: &A, params: &MdocVerifyParams<'_>) -> (VerificationResult, MdocVerifyMeta)
```

Verify a presented mdoc `DeviceResponse` against the always-on bar (the IACA-rooted issuer chain,
the MSO `validityInfo` window, selective-disclosure integrity, and the `DeviceAuth` holder binding)
AND surface the [`MdocVerifyMeta`] the single bar pass already computed — the per-document claimed
issuer `(cert, issuance_time)`, the document count, and (on a `HolderBinding` failure) the
holder-binding-machinery soundness — so the OpenID4VP binding verifier and the qualified gate read
these cached results instead of re-decoding the response. This is the canonical mdoc entry point;
callers that do not need the meta simply take the [`VerificationResult`] (`.0`).

## Module `openid4vp`

OpenID4VP 1.0 verifier binding (DCQL request build + `vp_token` binding verify).

The SDK is a **full verifier** (contracts/openid4vp-verifier.md): it builds the OpenID4VP
presentation request (a DCQL query + a fresh `nonce` + the verifier's `audience`/`client_id`) AND
verifies that a returned `vp_token` is cryptographically **bound** to it. Owning both halves makes
replay / audience binding **correct by construction** — the verifier never accepts a presentation
it did not request.

## Operations

- [`build_request`] — `(dcql, audience, response_uri) -> PresentationRequest { dcql, nonce
  (fresh), audience, response_uri }`. The fresh `nonce` comes from the host RNG seam
  [`NonceSource`] (the core is sans-IO; entropy is host-provided exactly as the signing core takes
  it via `HostContext.entropy`). The `response_uri` is the verifier's response endpoint — a
  first-class request parameter the mdoc handover binds (OpenID4VP 1.0 §B.2.6).
- [`verify_response`] — `(vp_token, request, policy, anchors) -> VerificationResult`. Runs the
  per-format always-on bar ([`crate::sdjwtvc`] / [`crate::mdoc`]) **plus** the binding checks.

## Binding checks (FR-015 / SC-008)

- **Nonce**: the presentation echoes the request's fresh `nonce` — SD-JWT VC in the KB-JWT
  (`nonce`); mdoc in the `SessionTranscript` / `OpenID4VPHandover` (OpenID4VP 1.0 §B.2.6)
  the `DeviceAuth` signs over. A missing/mismatched nonce ⇒ INVALID
  [`ReasonCode::Replay`] (a replayed presentation cannot satisfy a fresh nonce).
- **Audience**: the presentation is addressed to this verifier's `client_id` — SD-JWT VC KB-JWT
  `aud`; mdoc the handover/`client_id`. Wrong audience ⇒ INVALID [`ReasonCode::WrongAudience`].

For mdoc the response is delivered to a verifier-controlled address, so the **audience** is an
observable cleartext field (compared directly → `WrongAudience`) while **freshness** is purely
cryptographic (the nonce is folded into the signed handover transcript → a mismatch surfaces as a
failed holder binding, attributed to `Replay`). For SD-JWT VC both `aud` and `nonce` are carried
in the (signed, but here pre-verification read) KB-JWT, so both are attributed precisely before
the full cryptographic bar runs.

### Structs

#### struct `CredentialVerification`

```rust
struct CredentialVerification
```

The per-credential outcome within a [`verify_vp_token`] evaluation.

`presentations` carries the [`VerificationResult`] of EACH Presentation returned under this
Credential Query `id` (in input order); `satisfied` is whether this Credential Query is fulfilled —
at least one returned Presentation both verified (always-on bar + binding) AND matched this query
(format + `meta` + claims), honoring the `multiple` cardinality (a `multiple:false` query MUST carry
at most one Presentation — OpenID4VP 1.0 §"Response Parameters").

Serializable so the set-level result crosses the C-ABI wire ([`crate::wire::WireVpTokenResponse`])
without a parallel re-implementation of the shape (DRY — Principle III): the per-credential
[`VerificationResult`]s serialize exactly as the single-presentation `verify` outcome does.

##### Fields

- `presentations: Vec<VerificationResult>`
  - The verification result of each Presentation returned under this Credential Query `id`.
- `satisfied: bool`
  - Whether this Credential Query is satisfied (≥1 verified-and-matching Presentation; cardinality
respected).

#### struct `Dcql`

```rust
struct Dcql
```

A DCQL (Digital Credentials Query Language — OpenID4VP 1.0 §6) query.

OpenID4VP 1.0 removed Presentation-Exchange `presentation_definition`; the query is **DCQL**. The
query is carried on the wire as its canonical JSON text (so the issued request stays reproducible
and auditable) AND is now **evaluated in-core** ([`parse`](Self::parse) → [`crate::dcql::DcqlQuery`]):
the verifier no longer treats it opaquely — after the always-on bar accepts a presentation it checks
the credential SATISFIES the query (correct `vct`/`docType`, requested claims present, values
matched) per OpenID4VP 1.0 §"VP Token Validation" step 2.2, closing the "did I get what I requested"
gap (conformance-audit T4.1). This was the explicit product decision — full DCQL evaluation in-core,
not delegated to the wallet (§"Security Checks on the Returned Credentials and Presentations":
*"the Verifier MUST NOT rely on the Wallet to enforce these constraints"*).

##### Fields

- `query_json: String`
  - The DCQL query as its canonical JSON text (what a wallet receives in the request).

##### Methods

```rust
fn from_json<impl Into<String>: Into<String>>(query_json: impl Into<String>) -> Self
```

Wrap a DCQL query given as JSON text.

```rust
fn parse(&self) -> Result<DcqlQuery, DcqlError>
```

Parse this query into the structured [`crate::dcql::DcqlQuery`] the in-core evaluator uses
(OpenID4VP 1.0 §6). See [`crate::dcql::DcqlQuery::parse`] for the (lenient) parsing contract.

# Errors

[`crate::dcql::DcqlError`] when the query text is not JSON or not a JSON object.

#### struct `MdocVpToken`

```rust
struct MdocVpToken<'a>
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

- `audience: &'a str`
  - The audience (`client_id`) the response was addressed to.
- `device_response: &'a [u8]`
  - The CBOR-encoded ISO 18013-5 `DeviceResponse` — borrowed (not owned), so a multi-KB attacker-
sized `DeviceResponse` is never cloned to build the token (the verifier only reads it).

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
- `response_uri: String`
  - The verifier's `response_uri` (or `redirect_uri`) request parameter — the endpoint the
presentation is returned to. This is the **4th element** of the mdoc `OpenID4VPHandoverInfo`
(OpenID4VP 1.0 §B.2.6), a distinct request parameter from the `client_id` (`audience`); the
holder folds it into the signed handover, so the verifier MUST reconstruct the handover with
the same value. A direct-`response_uri` deployment uses the absolute response endpoint; a
`redirect_uri` deployment its redirect target (the spec accepts either, by Response Mode).

##### Methods

```rust
fn nonce_b64(&self) -> String
```

The request `nonce` as a base64url-unpadded string (the form an SD-JWT VC KB-JWT echoes).

#### struct `VpTokenVerification`

```rust
struct VpTokenVerification
```

The outcome of evaluating a whole OpenID4VP `vp_token` against its DCQL query (OpenID4VP 1.0 §"VP
Token Validation" steps 2 + 3): the per-credential results plus the set-level verdict.

`satisfied` is the overall set-level decision (§"VP Token Validation" step 3 + §"Selecting
Credentials"): with no `credential_sets`, EVERY Credential Query in `credentials` must be satisfied;
otherwise EVERY **required** Credential Set Query must have at least one fully-satisfied `option`
(non-required sets are optional).

Serializable so it is the payload of [`crate::wire::WireVpTokenResponse`] over the C-ABI (DRY —
Principle III: the wire response carries this exact type, not a parallel mirror).

##### Fields

- `satisfied: bool`
  - Whether the returned set of Presentations satisfies the request's set-level requirements.
- `credentials: BTreeMap<String, CredentialVerification>`
  - The per-credential outcomes, keyed by the Credential Query `id` the Presentations were returned
under.

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
  - A compact SD-JWT VC presentation (`<issuer-JWS>…~<KB-JWT>`).
- `Mdoc(MdocVpToken<'a>)`
  - An mdoc `DeviceResponse` plus its addressed audience.

##### Methods

```rust
const fn format(&self) -> Format
```

The credential format this `vp_token` carries.

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
fn build_request<N: NonceSource + ?Sized, impl Into<String>: Into<String>, impl Into<String>: Into<String>>(nonce_source: &mut N, dcql: Dcql, audience: impl Into<String>, response_uri: impl Into<String>) -> PresentationRequest
```

Build an OpenID4VP presentation request: the DCQL query, a **fresh** nonce drawn from the host
[`NonceSource`], the verifier's audience (`client_id`), and the verifier's `response_uri`.

A fresh nonce per call is the replay-protection invariant (contracts/openid4vp-verifier.md): the
SDK keeps the returned [`PresentationRequest`] and only accepts a `vp_token` bound to it. The
`response_uri` is the verifier's response endpoint (or `redirect_uri`); it is the 4th element of
the mdoc handover (OpenID4VP 1.0 §B.2.6) and is therefore part of what the holder cryptographically
binds — distinct from the `audience`/`client_id`.

#### fn `oid4vp_handover_transcript`

```rust
fn oid4vp_handover_transcript(audience: &str, nonce: &[u8], response_uri: &str) -> Vec<u8>
```

Build the conformant OpenID4VP-1.0 / ISO 18013-7 mdoc `SessionTranscript` bytes for a
redirect-invoked presentation, from the verifier's `client_id` (`audience`), request `nonce`, and
`response_uri`.

This is the **`OpenID4VPHandover`** of OpenID4VP 1.0 §B.2.6 ("`Handover` and `SessionTranscript`
Definitions"), NOT a custom structure — a conformant EUDI wallet signs `DeviceAuth` over exactly
this `SessionTranscript`, so the verifier reconstructs it identically (CDDL reproduced verbatim):

```text
SessionTranscript = [null, null, OpenID4VPHandover]   ; ISO 18013-5 §9.1.5.1, with
                                                      ; DeviceEngagementBytes = EReaderKeyBytes = null
OpenID4VPHandover = ["OpenID4VPHandover", OpenID4VPHandoverInfoHash]
OpenID4VPHandoverInfoHash  = bstr            ; SHA-256 of OpenID4VPHandoverInfoBytes
OpenID4VPHandoverInfoBytes = bstr .cbor OpenID4VPHandoverInfo
OpenID4VPHandoverInfo = [clientId, nonce, jwkThumbprint, responseUri]
  clientId      = tstr   ; the `client_id` request parameter (the audience)
  nonce         = tstr   ; the `nonce` request parameter value
  jwkThumbprint = bstr / null  ; RFC 7638 thumbprint of the response-encryption key, else null
  responseUri   = tstr   ; the `response_uri` (or `redirect_uri`) request parameter
```

The handover folds **one** SHA-256 over the CBOR-encoded inner `OpenID4VPHandoverInfo` array
(not a per-field hash): every request parameter is therefore bound, and any tampered field
changes the single hash. The holder (here the test issuer) and the verifier MUST build the
transcript identically, so this one function is the single authoritative source for both halves.

Per OpenID4VP 1.0 §B.2.6 the four `OpenID4VPHandoverInfo` elements map to the SDK as:
- `clientId` — the `client_id` request parameter (the verifier's `audience`).
- `nonce` — the `nonce` request parameter is a text string; the SDK carries the nonce as bytes,
  so the conformant text value is its base64url-unpadded form (identical to the value an SD-JWT VC
  KB-JWT echoes), keeping the two formats' nonce-on-the-wire byte-identical.
- `jwkThumbprint` — `null`: this SDK does not negotiate response encryption (no `direct_post.jwt`),
  so there is no verifier encryption key to thumbprint; the spec mandates `null` in that case.
- `responseUri` — the **actual** `response_uri` (or `redirect_uri`) request parameter, a value
  distinct from `clientId`. The spec's §B.2.6 fourth element MUST be this real endpoint, NOT the
  `client_id`, so the SDK carries it as the first-class [`PresentationRequest::response_uri`].

#### fn `verify_response`

```rust
fn verify_response<A: TrustAnchorSource + ?Sized>(vp_token: &VpToken<'_>, request: &PresentationRequest, policy: &VerificationPolicy, anchors: &A, now_unix: i64, role: IssuerRole, statuses: &[StatusOutcome]) -> VerificationResult
```

Verify an OpenID4VP `vp_token` is cryptographically bound to an issued request, running the
per-format always-on bar **plus** the nonce/audience binding (contracts/openid4vp-verifier.md).

- SD-JWT VC: attributes the binding to [`ReasonCode::WrongAudience`] / [`ReasonCode::Replay`] from
  the KB-JWT `aud`/`nonce`, then runs the full bar with the request as the holder-binding
  challenge (so the binding is also cryptographically enforced — correct by construction).
- mdoc: compares the addressed audience (→ `WrongAudience`), then runs the bar against the
  handover transcript reconstructed from the request nonce/audience (a fresh-nonce mismatch
  surfaces as a failed holder binding, attributed to `Replay`).

`policy` carries the accepted-format restriction (`policy.formats`); a `vp_token` whose format the
policy excludes is rejected with [`ReasonCode::UnsupportedFormat`] BEFORE any bar runs, so this
public entry honors the gate even when a native caller invokes it directly (not only via the
[`verify()`](crate::verify()) wrapper). `now_unix`/`role`/`statuses` are the remaining
per-format-bar inputs (the validity instant, the trust-anchor role, and the per-document resolved
status outcomes — SD-JWT VC reads index 0; an mdoc `DeviceResponse` checks `documents[i]` against
`statuses[i]`).

**Qualified-status gate:** this entry NEVER populates `VerificationResult.qualified_status`,
regardless of `policy.qualified_gate`. The opt-in eIDAS qualified gate (TS 119 615 cl. 4.12) runs
ONLY via the [`crate::verify::verify()`] entry point, which carries the `qualified_trust_list` +
`qualified_scheme_anchors` inputs this function does not receive; `None` here is the honest value.

#### fn `verify_vp_token`

```rust
fn verify_vp_token<A: TrustAnchorSource + ?Sized>(request: &PresentationRequest, vp_token: &BTreeMap<String, Vec<VpToken<'_>>>, policy: &VerificationPolicy, anchors: &A, now_unix: i64, role: IssuerRole, statuses: &BTreeMap<String, Vec<Vec<StatusOutcome>>>, status_tokens: &BTreeMap<String, Vec<u8>>) -> VpTokenVerification
```

Evaluate a full OpenID4VP `vp_token` (the `{ credential_id: [presentations] }` shape — OpenID4VP 1.0
§"Response Parameters") against the DCQL query carried in `request`, enforcing the complete
§"VP Token Validation" + §6 DCQL semantics **in-core** (the explicit product decision — not delegated
to the wallet, §"Security Checks on the Returned Credentials and Presentations").

For EACH `(credential_id, presentations)` entry it runs, per Presentation, the always-on bar + the
request binding ([`verify_response`]) AND the per-query DCQL match (format + `meta` + claims/values),
then folds the per-credential satisfaction into the set-level verdict (the [`crate::dcql`] set fold):
step 3 — every required Credential Set Query has a fully-satisfied option (or, with no
`credential_sets`, every Credential Query is satisfied).

The per-credential trust-anchoring **role** is derived from the matching Credential Query's expected
type (`meta`) when it names a EUDI PID type (conformance-audit T4.3 — the verifier's own query states
the type it expects), falling back to the supplied `role` otherwise; the per-format bar then
validates the credential's ACTUAL claimed type against that role (rejecting a contradiction as
[`ReasonCode::RoleMismatch`]). `now_unix` is the shared per-bar instant. `statuses` carries the
host-resolved revocation outcomes keyed by credential id → per **token** (presentation) → per
**document** (positional), so EACH credential and EACH document is checked against its OWN outcome —
one outcome is never silently reused across credentials or documents (SC-002). A credential id /
token / document with no supplied outcome fails closed to [`StatusOutcome::Unavailable`].

`status_tokens` is the host-fetched **signed** Token Status List tokens (uri → raw token bytes),
shared across every presentation exactly as the single-presentation [`crate::verify::verify()`] path
takes them: when a presented credential declares a Token Status List reference AND a token is supplied
for its URI, the core AUTHENTICATES that token in-core (signature under a key authorized by the
credential's own trust anchor + `sub` binding + freshness + bit read) and that outcome OVERRIDES the
positional `statuses` entry — so the set-level path performs the SAME in-core status authentication as
the single-presentation path (the map is uri→bytes, resolved identically per credential referencing a
list). An empty map ⇒ the positional `statuses` seam alone (host pre-resolved), unchanged.

This is the ONLY entry that enforces the **set-level** DCQL semantics (`credential_sets` required
option-sets + `multiple` cardinality); the single-presentation [`verify_response`] / the C-ABI
`verify()` surface enforce only the per-presentation single-query match. Reachable over the C-ABI via
[`crate::wire::process_vp_token_bytes`] (the `{credential_id: [presentations]}` map + the signed
status tokens now cross the wire). Like [`verify_response`], it NEVER populates `qualified_status` —
the opt-in qualified gate runs only via [`crate::verify::verify()`].

## Module `qualified`

Opt-in eIDAS qualified-status determination (ETSI TS 119 615 v1.4.1 cl. 4.12) — T019.

Over the always-on bar (which is never replaced by this), an **opt-in**, version-pinned
determination of whether an attestation issuer is a **qualified** EAA provider: authenticate the
LOTL → select the national Trusted List → confirm the attestation self-declares the qualified-EAA
type ([`EAA_EU_QUALIFIED_TYPE`], TS 119 615 PRO-4.12.4-03) → match the issuer's signing certificate
against a trust-service entry of type [`EAA_Q_SERVICE_TYPE`] (`…/Svctype/EAA/Q`) → read the
`granted`/`withdrawn` service status **at the relevant time** (the credential's issuance/relevant
time, NOT "now"). The reusable trust-list primitives ([`crate::trust`]) anchor the same PKI (DRY).

## Outcome conditions (pinned — tasks T018/T019, analyze A1)

- [`QualifiedStatus::Qualified`] — the attestation self-declares the qualified-EAA type AND the
  issuer's `EAA/Q` service entry is **`granted`** at the relevant time.
- [`QualifiedStatus::NotQualified`] — the entry is **found but not granted** (its status at the
  relevant time is withdrawn/suspended, the grant had not yet begun, or the issuer is on the TL
  only under a non-`EAA/Q` service type), with the self-declaration present.
- [`QualifiedStatus::Indeterminate`] — the trust-list data needed to decide is **absent,
  ambiguous, or unreachable** (the issuer is on no service entry, or there is no TL at all), the
  TL fails authentication, **or the attestation does not self-declare the qualified-EAA type**
  (PRO-4.12.4-03). The gate **never assumes qualified** (no false "qualified" — SC-007).

## QEAA type-indication precondition (TS 119 615 v1.4.1 PRO-4.12.4-03 — the T5.2 false-trust fix)

Before the issuer's `EAA/Q` service status is read, the determination requires the **EAA content
to self-declare the qualified-EAA type**. PRO-4.12.4-03 (verified online against the v1.4.1 PDF)
mandates: *"check whether the URN `'urn:etsi:esi:eaa:eu:qualified'` is present within the content
of EAA and if this URN is not present"* → set the result to `Indeterminate`
(`ERROR_NO_ETSI_QEAA_TYPE_INDICATION_FOUND`) and **stop**. So an attestation whose declared type
does not carry [`EAA_EU_QUALIFIED_TYPE`] is `Indeterminate`, **never** `Qualified`, even if its
issuer is a granted `EAA/Q` QTSP. Per **ETSI TS 119 472-1** (the format profile, v1.2.1 — verified
online) the URN is carried in the issuer-signed **`category`** element, distinct from the
credential-TYPE identifier (`vct`/`docType`); the type indication is threaded from
[`verify`](crate::verify()) as `type_indication`, read from `category` for **both** formats:

- **SD-JWT VC** — the issuer-signed `category` claim (`crate::sdjwtvc::issuer_category`), NOT the
  `vct` (which is the credential type, e.g. `urn:eudi:pid:1`, and never the qualified URN).
- **ISO mdoc** — the `category` data element in namespace `org.etsi.01947201.010101` (TS 119 472-1
  cl. 6.2.2), surfaced per document by the always-on bar in the `MdocVerifyMeta.claimed_issuers`
  `(leaf, signed, category)` triple.

The precondition is **enforced for both formats**: an ABSENT `category` (an ordinary EAA, which TS
119 472-1 EAA-5.2.2.1-01 says MUST NOT carry `category`; or an mdoc document that did not disclose
the element → `None`) OR a present-but-non-URN value fails closed to `Indeterminate` (never a false
"qualified"). (This corrects an earlier model that read the SD-JWT `vct` and exempted mdoc entirely
— reading `vct` made the SD-JWT gate mechanically dead, since a real QEAA's `vct` is its credential
type, not the qualified URN.)

**Version note (the doc-nit reconciliation):** cl. 4.12 was introduced in TS 119 615 **v1.3.1**
(2026-01) and is retained in the pinned **v1.4.1** (2026-05). The QEAA self-declaration URN was
**renamed between the two**: v1.3.1 used `urn:etsi:eaa:eu:qualified`; v1.4.1 inserts an `esi:`
segment → `urn:etsi:esi:eaa:eu:qualified`. This implementation pins [`TS_119_615_VERSION`]
(`1.4.1`) and therefore uses the v1.4.1 URN (verified online against the v1.4.1 PDF —
not training data).

## Experimental + version-pinned

cl. 4.12 (QEAA qualified-status determination) is **pre-operational**: national Trusted Lists are
only beginning to carry `EAA/Q` entries (post CIR (EU) 2025/1569). This implementation is pinned to
[`TS_119_615_VERSION`] (`1.4.1`) and is **off by default** ([`crate::verify::VerifyContext::qualified_gate`])
— enabling it is opt-in, and absent fixtures honestly yield `Indeterminate`.

## Service-digital-identity matching (TS 119 612 V2.4.1 §5.5.3 — the T5.4 false-reject fix)

A credential's signing leaf is matched against a trust-service's digital identity (Sdi) by any of
(verified online against TS 119 612 V2.4.1 §5.5.3 + the EU DSS `DigitalIdentityListTypeConverter`):

1. **Exact X509Certificate DER** — the mandatory, machine-processable Sdi form (DSS matches on this
   alone);
2. **X509SKI** — the leaf shares the Sdi's `SubjectKeyIdentifier` (a renewed/re-encoded cert with
   the same key); §5.5.3 lists X509SKI as an optional machine-usable identifier;
3. **Issuing-CA** — the Sdi lists the **issuing CA** (the common national-TL shape — the Sdi is the
   CA, not the byte-identical leaf), matched by the leaf's `issuer` DN == the Sdi cert's `subject`
   DN, tightened by the leaf's AKI == the Sdi's SKI when both are present.

`X509SubjectName` (a bare Distinguished Name) is **deliberately not** machine-matched: §5.5.3 states
it *"should not be used by applications in machine processable way"*, and EU DSS does not consume it.
(The issuing-CA rule compares the leaf's `issuer` field to the Sdi **certificate's** subject — a
chain relationship — not a bare X509SubjectName element.) This closes the false-reject where a valid
QEAA whose Sdi lists the issuing CA / its SKI (not the exact leaf) was reported `Indeterminate`.

## Trust-list authentication (fail-closed — SC-007)

Before any status is read, the national TL is **authenticated** by
[`QualifiedTrustList::authenticate`]: it chain-validates the list's embedded signer certificate
([`QualifiedTrustList::signer_cert_der`]) against a host-configured **scheme-operator trust
anchor**, reusing [`crate::trust::chain::verify_chain`] (the same X.509 primitive the always-on
bar uses — DRY; no re-implemented crypto), and rejects a **stale** list (`now_unix` at/after its
`NextUpdate`). An unsigned list (no signer), a signer that does not chain to the scheme anchor,
and a stale list all **fail** authentication. [`qualified_status`] runs `authenticate` first and
returns [`QualifiedStatus::Indeterminate`] (NEVER [`QualifiedStatus::Qualified`]) on any failure
— fail-closed, consistent with the always-on engine's stale/auth policy ([`crate::trust::engine`])
and the spec-003 pattern. A forged / attacker-supplied / unsigned TL can therefore never make an
unchained issuer report `Qualified`.

Staleness in this cl. 4.12 determination is **fail-closed** (a stale snapshot → `Indeterminate`),
which is intentionally stricter than the general national-TL staleness handling (a non-fatal
warning, TS 119 615 PRO-4.2.4-10, applied in [`crate::trust::engine`]): the qualified-status
determination must never assert `Qualified` from a stale or expired-signer trust snapshot (the
now-vs-relevant-time SC-007 invariant below), so it does not relax staleness the way the always-on
membership engine does for a national TL.

The full enveloped XAdES `SignatureValue`/C14N check is a documented scope cut
([`crate::trust::xml`], `standards-conformance.md`); the offline JSON form here carries the signer
cert so the gate exercises the same chain-authentication seam against the same X.509 stack.

### Structs

#### struct `QualifiedTrustList`

```rust
struct QualifiedTrustList
```

A parsed national Trusted List for the qualified-status gate: the trust-service entries, the
embedded signer certificate (for chain-authentication), and the `nextUpdate` instant.

Carries only issuer-public certificate data (no secret), so deriving `Debug` is safe.

##### Methods

```rust
fn authenticate(&self, scheme_anchors: &[Vec<u8>], now_unix: i64) -> Result<(), QualifiedTrustError>
```

Authenticate the national Trusted List **before** any status is read (the fail-closed gate —
SC-007).

Authentication has two parts, both mandatory:

1. **Signer chain** — the list's embedded signer certificate
   ([`Self::signer_cert_der`]) must chain-validate to one of the host-configured
   `scheme_anchors` (the scheme-operator / national-TL-operator trust anchors), at `now_unix`,
   via [`crate::trust::chain::verify_chain`] (DRY — the same X.509 primitive the always-on bar
   uses; no re-implemented crypto). An **unsigned** list (no signer) or a signer that does not
   chain fails. When `scheme_anchors` is empty the list cannot be authenticated at all
   ([`QualifiedTrustError::NoSchemeAnchor`]).
2. **Freshness** — the list must not be **stale**: `now_unix` must be strictly before its
   `NextUpdate` (a list with an absent/zero `NextUpdate` is treated as stale). For this cl. 4.12
   determination staleness is **fail-closed** (stricter than the general national-TL warning of
   PRO-4.2.4-10 — see the module docs): a stale snapshot must never assert `Qualified`.

# Errors

Returns [`QualifiedTrustError`] when no scheme anchor is configured, the list is unsigned, the
signer does not chain to a scheme anchor, or the list is stale. Every variant is mapped to
[`QualifiedStatus::Indeterminate`] by [`qualified_status`] (never `Qualified`).

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

Returns [`QualifiedTrustListError`] when the JSON is malformed, a certificate/SKI body is not
valid base64, or a `nextUpdate` / status `startingTime` is not an RFC 3339 UTC timestamp.

```rust
fn signer_cert_der(&self) -> Option<&[u8]>
```

The list's own signing certificate (DER) from its enveloped signature, if present.

### Enums

#### enum `QualifiedTrustError`

```rust
enum QualifiedTrustError
```

Why authenticating a national Trusted List failed (before any status is read).

Every failure is fail-closed: [`qualified_status`] maps any of these onto
[`QualifiedStatus::Indeterminate`] (never [`QualifiedStatus::Qualified`] — SC-007). The variants
keep the rejection specific so a forged / unsigned / unchained / stale list is never opaque.

##### Variants

- `NoSchemeAnchor`
  - No scheme-operator trust anchor was configured, so the list's authenticity cannot be
established (can't authenticate ⇒ can't assert qualified).
- `Unsigned`
  - The list carries no embedded signer certificate (an unsigned list cannot be authenticated).
- `SignerNotTrusted(ChainError)`
  - The list's signer certificate did not chain-validate to any configured scheme-operator anchor.
- `Stale`
  - The list is stale: `now` is at or after its `NextUpdate` (or it carries no `NextUpdate`).

#### enum `QualifiedTrustListError`

```rust
enum QualifiedTrustListError
```

An error parsing the qualified-status national Trusted List.

##### Variants

- `Json(Error)`
  - The bytes were not valid JSON of the expected national-TL shape.
- `Base64(String)`
  - A signing/signer/SKI value was not valid base64.
- `Time(String)`
  - A `nextUpdate` or status `startingTime` was not an RFC 3339 UTC timestamp.

### Functions

#### fn `qualified_status`

```rust
fn qualified_status(issuer_cert_der: &[u8], now_unix: i64, relevant_time_unix: i64, trust_list: &QualifiedTrustList, scheme_anchors: &[Vec<u8>], type_indication: Option<&str>) -> QualifiedStatus
```

Determine the eIDAS qualified status of an attestation issuer at a relevant time (TS 119 615
v1.4.1 cl. 4.12 — the opt-in gate, research D6).

## Two distinct times — authenticate at `now`, read status at the relevant time

Trust-list **authentication** and the issuer **status read** are evaluated at *different* instants
(the load-bearing split — RCA below):

- **`now_unix`** — the verification instant ("real now"). Used to **authenticate the TL**
  ([`QualifiedTrustList::authenticate`]): the freshness check (`now >= NextUpdate ⇒ stale`) AND the
  TL-signer certificate's chain validity ([`crate::trust::chain::verify_chain`] `notBefore`/
  `notAfter`). Whether the LOTL/national-TL snapshot in hand is itself **currently** fresh and
  signed by a **currently** valid scheme operator is a *now* property — a stale or expired-signer TL
  must never be trusted just because the credential being checked is old.
- **`relevant_time_unix`** — the credential's issuance/relevant time. Used only to **read the
  issuer's granted/withdrawn `EAA/Q` status** (the effective status at that instant); per eIDAS the
  status read is "status at the relevant time" (an issuer not yet granted when it signed a
  credential, but granted later, is NOT `Qualified` for that earlier credential).

**RCA — why the split matters (the false-`Qualified` bug this fixes):** a prior fix correctly
derived the relevant time for the *status read* from the credential's issuance time, but then passed
that SAME old time into `authenticate`, so the TL freshness/signer-validity checks were evaluated at
the credential's issuance time instead of `now`. A TL whose `NextUpdate` is in the past relative to
real `now` (stale) but in the future relative to an old credential's issuance time was treated as
fresh, yielding a false `Qualified` from a stale/withdrawn-since trust snapshot. Authentication MUST
use `now_unix`; only the status read uses `relevant_time_unix`.

## QEAA type-indication precondition (PRO-4.12.4-03)

`type_indication` is the credential's issuer-signed **`category`** — the SD-JWT VC `category` claim
/ the mdoc `category` data element (ETSI TS 119 472-1), NOT the `vct`/`docType` (which is the
credential-TYPE identifier, e.g. `urn:eudi:pid:1`, and never the qualified URN); see the module
docs. Per PRO-4.12.4-03 the EAA must self-declare the qualified-EAA type
([`EAA_EU_QUALIFIED_TYPE`]) before a `Qualified` verdict, and this is enforced for **both** formats:
any `type_indication` that is not exactly that URN — INCLUDING an absent one (`None` — no /
undisclosed `category`) — yields [`QualifiedStatus::Indeterminate`]
(`ERROR_NO_ETSI_QEAA_TYPE_INDICATION_FOUND`) **before** any service status is read (never a false
"qualified"; fail-closed).

## Flow

**Authenticates the national TL first** (against `scheme_anchors` at `now_unix`): an unsigned /
forged / unchained / stale list yields [`QualifiedStatus::Indeterminate`] (fail-closed). Then it
enforces the type-indication precondition. Only then does it match `issuer_cert_der` against the
trust-service entries (§5.5.3 Sdi matching) and read the effective service status **at
`relevant_time_unix`**:

- [`QualifiedStatus::Qualified`] — some matched [`EAA_Q_SERVICE_TYPE`] service is
  [`SERVICE_STATUS_GRANTED`] at the relevant time.
- [`QualifiedStatus::NotQualified`] — the issuer is **found** on the TL, but no `EAA/Q` service is
  granted at the relevant time.
- [`QualifiedStatus::Indeterminate`] — the TL did not authenticate, the type indication is absent
  (PRO-4.12.4-03), **or** the issuer is on **no** matching service entry. Never assumes qualified
  (no false "qualified" — SC-007).

### Constants

#### const `EAA_EU_QUALIFIED_TYPE`

```rust
const EAA_EU_QUALIFIED_TYPE: &str = "urn:etsi:esi:eaa:eu:qualified"
```

The TS 119 615 **v1.4.1** PRO-4.12.4-03 QEAA self-declaration URN: the URN that MUST be present
within the EAA content for the attestation to be a *qualified* EAA. (v1.3.1 used the shorter
`urn:etsi:eaa:eu:qualified`; v1.4.1 — the pinned version — inserts the `esi:` segment. Verified
online against the v1.4.1 PDF.) When the credential's type indication is not this URN, the
determination is [`QualifiedStatus::Indeterminate`], never `Qualified`.

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
  - The revocation/status outcome (the T014 seam) — the host-pre-resolved positional outcome used as
the fallback when the credential declares no Token Status List reference, or declares one for
which no signed token is supplied in [`Self::status_tokens`].
- `status_tokens: &'a BTreeMap<String, Vec<u8>>`
  - The host-fetched **signed** Token Status List tokens, keyed by list URI → raw token bytes. When
this credential's issuer-signed `status` claim declares a `status_list` reference AND a token is
supplied here for its `uri`, the bar AUTHENTICATES that token in-core (verifying its signature
against a key authorized by this credential's own trust anchor) and reads the revocation bit
itself — overriding [`Self::status`] for this credential. Empty
([`crate::status::DEFAULT_STATUS_TOKENS`]) ⇒ the positional [`Self::status`] seam alone
(pre-existing behavior).

### Functions

#### fn `verify_sd_jwt_vc`

```rust
fn verify_sd_jwt_vc<A: TrustAnchorSource + ?Sized>(input: &SdJwtVcInput<'_, A>) -> VerificationResult
```

Verify a presented SD-JWT VC against the always-on bar, returning a [`VerificationResult`].

On any failed check the result has `valid = false` and carries the single specific
[`ReasonCode`] for the **first** check that failed; only a credential that clears every check is
`valid = true`, with the disclosed (and only the disclosed) attributes returned.

## Module `secret`

A minimal redacting secret newtype for the OAuth bearer token / one-time `c_nonce` the issuance
flow carries (`crate::issuance::obtain`).

This is a deliberate, self-contained copy of the ~20-line `Secret` newtype the signing core
(`cleverbase-core`) defines. It is *not* a DRY violation: pulling in `cleverbase-core` solely to
reuse this trivial leaf type dragged the whole signing stack — including `lopdf` (a PDF library) —
into this otherwise pure-Rust / WASM-able / minimal verifier (contradicting the `lib.rs` posture).
The correct trade-off for a trivial leaf type is a local definition rather than a heavy
cross-crate dependency; see the removed-dependency rationale in `Cargo.toml`.

Semantics match the core type exactly: the inner value never appears in `Debug` output
(Constitution Principle IV — never leak secrets via Debug/log/panic), yet it still
(de)serializes transparently so a CBOR-serialized `obtain` session can round-trip its
authorization material (the host owns the wire bytes by design in the sans-IO model — only the
`Debug` exposure was the leak).

### Structs

#### struct `Secret`

```rust
struct Secret
```

A secret string whose contents never appear in `Debug` output (Constitution Principle IV).

It still (de)serializes its inner value so a CBOR-serialized `obtain` session can round-trip its
bearer token / one-time nonce; the host is responsible for protecting serialized handles at rest.

`pub` because it appears in a public API field ([`crate::issuance::CredentialOffer`]'s bearer
`pre_authorized_code`), so the host can construct one from a received offer — the same surface the
signing core's `Secret` exposes.

##### Methods

```rust
fn new<impl Into<String>: Into<String>>(s: impl Into<String>) -> Self
```

Wrap a value as a redacted secret.

## Module `status`

Revocation / status check (status list / CRL) with a fail-closed reachability policy (T014).

The always-on bar (FR-003) includes revocation: a credential whose status mechanism says it is
revoked → INVALID `revoked`; one whose status cannot be reached → fail-closed by default →
INVALID `status_unavailable` (never a silent VALID). This module evaluates that check.

## Sans-IO (host seam — like the trust engine)

The core performs no network I/O. A credential references its status mechanism (a Token Status
List pointer `uri`+`idx`, or a CRL the integrator names); the **host** fetches the referenced
status document and supplies its bytes, exactly as the trust engine takes fetched trust-list
bytes through `TrustListFetcher`. The fetch (network, caching, freshness of the *transport*) is
the host's; the *evaluation* and the **fail-closed policy** are the core's.

Two host seams exist, at different trust levels:

- **Authenticated in-core (the authoritative path, [`verify_status_list_token`]).** The host
  fetches the *signed* Token Status List Token by URI and hands the RAW token bytes to the core,
  which then AUTHENTICATES it end-to-end — verifies the JWS/`COSE_Sign1` signature under a key the
  caller's trust closure authorizes, binds `sub` to the credential's list URI, checks `exp`/`ttl`,
  zlib-inflates the bitstring, and reads the status bit itself. The core no longer trusts a
  host-supplied *outcome*; it re-derives it from the signed artifact (fail-closed on any doubt).
  The always-on [`verify()`](crate::verify()) entry point uses this whenever a credential declares a
  Token Status List reference and the host supplied the matching token.
- **Host-pre-resolved ([`StatusSource`] / [`check_status`]).** The legacy seam where the host has
  already authenticated + unpacked the status document and supplies the byte-per-entry array; the
  core only reads the bit under the fail-closed policy. Retained for CRL (host-resolved) and as the
  positional fallback when no signed token is supplied for a given list URI.

## Status mechanisms

- **Token Status List** (IETF `draft-ietf-oauth-status-list` — the EUDI/HAIP baseline): a
  credential carries a `status.status_list = { idx, uri }`; the referenced list is a packed
  bit-array (1 or 2 bits per entry). A non-zero status value at `idx` is revoked/suspended.
- **CRL** (X.509 Certificate Revocation List): a credential is identified by an issuer-assigned
  serial; the referenced CRL enumerates revoked serials. Modelled abstractly here (the integrator
  supplies the parsed revoked-serial set) so the same fail-closed policy covers both.

The decision maps to a single canonical [`StatusOutcome`] that the per-format verifiers consume
through their status seam (one authoritative status type — DRY).

### Structs

#### struct `SignerKeyMaterial`

```rust
struct SignerKeyMaterial
```

The signer-identifying material a Status List Token embeds, handed to the caller's key-resolution
closure ([`verify_status_list_token`]'s `resolve_key`) so that `crate::trust` (layer 2) can
AUTHORIZE the signer WITHOUT this sans-IO module holding any trust anchors. The module extracts
this from the token header and performs the signature verification with whatever [`VerifyingKey`]
the closure returns; the trust/EKU policy is entirely the closure's.

##### Fields

- `x5chain: Vec<Vec<u8>>`
  - The signer's X.509 certificate chain (DER, **leaf-first**), from the token's `x5c` (JOSE, RFC
7515 §4.1.6 — base64 *standard*) or `x5chain` (COSE label 33, RFC 9360 — `bstr`/array of
`bstr`) header. Empty when the token carries no chain (a `kid`-only token — the closure then
resolves against the credential's own issuer key, or rejects).

A `kid` header is intentionally NOT surfaced: the reworked signer authorization
(`authorize_status_signer`) grants nothing off a `kid` — a chain-less token is authorized ONLY
to the credential's own issuer key (and then only if the signature verifies under it), so the
raw `kid` bytes carry no authorization weight and are not parsed.

### Enums

#### enum `StatusOutcome`

```rust
enum StatusOutcome
```

The canonical outcome of the revocation/status check, consumed by both per-format verifiers'
status seam (the single authoritative status type — DRY, Principle III).

The per-format `verify` paths translate this into their reject reason: [`Self::Revoked`] →
[`ReasonCode::Revoked`], [`Self::Unavailable`] → [`ReasonCode::StatusUnavailable`], [`Self::Untrusted`]
→ [`ReasonCode::StatusUntrusted`], and [`Self::NoStatus`]/[`Self::Good`] continue the bar. Carried
across the C-ABI as CBOR (the host resolves it through [`check_status`] and passes the outcome in),
hence the `serde` derives.

[`ReasonCode::Revoked`]: crate::types::ReasonCode::Revoked
[`ReasonCode::StatusUnavailable`]: crate::types::ReasonCode::StatusUnavailable
[`ReasonCode::StatusUntrusted`]: crate::types::ReasonCode::StatusUntrusted

##### Variants

- `NoStatus`
  - The credential declares no status mechanism — nothing to check (continue the bar).
- `Good`
  - The status mechanism was reachable and says the credential is current.
- `Revoked`
  - The status mechanism says the credential is revoked or suspended.
- `Unavailable`
  - The status document was genuinely absent / unreachable (no token supplied), or a SUPPLIED and
AUTHENTICATED token had a post-auth data problem the core could not read past (its `lst` would not
zlib-inflate, or the entry at this credential's `idx` is outside the list, or the status value is
not in the registry). Fail-closed — never a silent VALID. This is the *benign / transient* status
failure (distinct from [`Self::Untrusted`], the adversarial one).
- `Untrusted`
  - A SUPPLIED signed status-list token FAILED IN-CORE AUTHENTICATION — a stronger, likely-adversarial
signal than [`Self::Unavailable`]. Returned by [`verify_status_list_token`] when a token that WAS
supplied fails any authentication check: its JWS/`COSE_Sign1` signature did not verify under the
authorized key, a header gate (`typ`/`alg`/`crit`/`COSE_Mac0`) or structural/claims parse failed,
its `sub` did not byte-bind to the credential's list URI, it was expired/stale, or the signer was
not authorized. Also the mapping for a present-but-unusable status *reference*
([`StatusReference::Malformed`]): a declared mechanism the core cannot evaluate is closer to
"untrusted" than "unreachable". Identically fail-closed INVALID — this only refines the reason
(`ReasonCode::StatusUntrusted`) so a SOC can tell a probable revocation-path attack from a
transient outage; it never changes the accept/reject.

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
- `Malformed`
  - The credential declares a status mechanism (a `status_list` object IS present) but it is
**unusable**: an empty/absent `uri`, a non-integer/absent `idx`, or the wrong CBOR/JSON types.
This is DISTINCT from [`Self::None`] (no status claim at all): a present-but-malformed status
reference MUST fail closed ([`StatusOutcome::Unavailable`]) — never fall through to a
host-supplied positional `Good` — because the credential DID declare a revocation mechanism the
core cannot evaluate, so it cannot prove the credential is current (SC-002, fail-closed).
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

**Host obligation on THIS seam — authenticate the status document.** A Token Status List (or CRL)
is a *signed* artifact (draft-ietf-oauth-status-list: a JWT/CWT signed by the status provider). This
seam receives the ALREADY-AUTHENTICATED, unpacked status array — a host using it MUST verify the
status-list token's signature (and that its signer is the credential's authorized status provider)
BEFORE unpacking and returning the bytes, because [`check_status`] does not see the signed token.

**Prefer the in-core authenticated path.** For a Token Status List the authoritative surface is
[`verify_status_list_token`], which takes the RAW signed token and authenticates it end-to-end
inside the core (signature + `sub` binding + freshness + bit read) — so a host that returned an
unauthenticated (e.g. attacker-served) array here would NOT defeat revocation, because the
always-on verifier reads the bit from the signed token itself when one is supplied. This seam
remains for CRL (host-resolved) and as the positional fallback when no signed token is available.

```rust
fn fetch_status_list(&self, uri: &str) -> Option<Vec<u8>>
```

Fetch the packed Token Status List bytes for `uri`, or `None` if unreachable.

The bytes are the **unpacked** status array: one byte per entry holding that entry's status
value (`0` = valid; non-zero = revoked/suspended). The host is responsible for decompressing /
bit-unpacking the wire form (the CBOR/JWT-wrapped, optionally DEFLATE-compressed bitstring)
into this byte-per-entry view. (The in-core [`verify_status_list_token`] path instead
zlib-inflates the bitstring itself — this pre-unpacked seam is the host-pre-resolved fallback.)

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
- [`StatusReference::Malformed`] → [`StatusOutcome::Untrusted`] (a declared-but-uninterpretable
  status reference fails closed regardless of reachability — never a silent VALID; it named a
  mechanism the core cannot evaluate, closer to "untrusted" than "unreachable").
- A reachable status list / CRL → [`StatusOutcome::Revoked`] if the entry is revoked, else
  [`StatusOutcome::Good`].
- An **unreachable** status document → [`StatusOutcome::Unavailable`] under
  [`StatusReachability::FailClosed`] (the secure default), or [`StatusOutcome::Good`] under
  [`StatusReachability::BestEffort`] (the credential is not failed on reachability alone).

Sans-IO: the status documents are supplied through `source`; this performs no network I/O.

#### fn `status_reference_from_mdoc_status`

```rust
fn status_reference_from_mdoc_status(status_cbor: &Value) -> StatusReference
```

Parse the Token Status List reference an **mdoc** declares, from the already-parsed MSO `status`
element (draft-ietf-oauth-status-list-21 §8): a CBOR map `status_list → { idx (uint), uri (tstr) }`
with TEXT keys. As with the SD-JWT VC form the wire key is **`idx`**; it maps onto
[`StatusReference::StatusList`]'s `index`. Returns [`StatusReference::None`] when NO `status_list`
element is present at all, but [`StatusReference::Malformed`] when a `status_list` element IS present
yet unusable (empty/absent `uri`, absent/non-integer `idx`, or wrong types): a declared-but-
uninterpretable reference MUST fail closed, never fall through to a positional `Good`. Pure parser —
reaches into no other module (layer 2 threads the element in).

#### fn `status_reference_from_sd_jwt_claim`

```rust
fn status_reference_from_sd_jwt_claim(status_claim: &Value) -> StatusReference
```

Parse the Token Status List reference an **SD-JWT VC** declares, from its already-parsed `status`
claim value (draft-ietf-oauth-status-list-21 §8): `status → status_list → { idx, uri }`. Note the
wire key is **`idx`** (not `index`); it maps onto [`StatusReference::StatusList`]'s `index` field.
Returns [`StatusReference::None`] when NO `status_list` object is present at all (genuinely no Token
Status List mechanism — the caller applies its own policy to the absent reference), but
[`StatusReference::Malformed`] when a `status_list` object IS present yet unusable (empty/absent
`uri`, absent/non-integer `idx`, or wrong types): a declared-but-uninterpretable reference MUST fail
closed, never fall through to a positional `Good`. This is a pure parser — it reaches into no other
module (layer 2 threads the claim in).

#### fn `verify_status_list_token`

```rust
fn verify_status_list_token<F>(token: &[u8], expected_uri: &str, idx: u64, now_unix: i64, resolve_key: F) -> StatusOutcome where F: FnOnce(&SignerKeyMaterial) -> Result<VerifyingKey, ()>
```

Authenticate a *signed* Token Status List Token and read this credential's status bit from it,
returning the canonical [`StatusOutcome`] (draft-ietf-oauth-status-list-21). Both wire forms are
accepted and auto-detected: a compact JWS (`statuslist+jwt`, SD-JWT VC baseline — pure ASCII) or a
tagged `COSE_Sign1` CWT (`application/statuslist+cwt`, mdoc baseline — binary CBOR beginning with
the tag-18 byte `0xD2`). The host fetched `token` by URI (sans-IO — the network is the host's); this
verifies it in-core.

Fail-closed contract: EVERY check must hold, else the result is a fail-closed INVALID outcome, NEVER
[`StatusOutcome::Good`]. The FAILING outcome distinguishes an AUTHENTICATION failure of the supplied
token ([`StatusOutcome::Untrusted`] — the adversarial-leaning signal) from a post-auth DATA problem
of an authenticated token ([`StatusOutcome::Unavailable`] — benign). In order:
1. **Signature** — JWS ES256 / `COSE_Sign1` ES256 under the key `resolve_key` authorizes; a bad
   signature, non-ES256 `alg`, wrong `typ`, present `crit`, `COSE_Mac0` (tag 17), or a malformed
   structure/claims → `Untrusted` (authentication failed).
2. **Subject binding** — the token's `sub` MUST byte-exactly equal `expected_uri` (the credential's
   `status_list.uri`); a validly-signed list for a *different* URI → `Untrusted`.
3. **Freshness** — a present `exp` MUST be `> now_unix`; a present `ttl` requires `iat + ttl >=
   now_unix` (else the cached token is stale). `iat` is REQUIRED. Expired/stale → `Untrusted`.
4. **Bit** — the `lst` bitstring is zlib-inflated and the `bits`-wide, LSB-first entry at `idx` is
   read and mapped through the status registry (0=VALID→`Good`, 1=INVALID→`Revoked`,
   2=SUSPENDED→`Revoked`). This step runs only AFTER authentication (1–3) holds, so its failures are
   post-auth DATA problems → `Unavailable`, never `Good`: a `lst` that will not inflate, an
   out-of-range `idx`, or an unknown/reserved status value.

`resolve_key` receives the token's parsed [`SignerKeyMaterial`] and returns the [`VerifyingKey`] to
verify under (or `Err(())` to reject). The signing-key TRUST/EKU decision is the closure's — layer 2
implements it against `crate::trust`; this module only parses the hint and does the crypto.

### Constants

#### const `DEFAULT_STATUSES`

```rust
const DEFAULT_STATUSES: &[StatusOutcome] = _
```

The default per-document/per-credential status seam: a single [`StatusOutcome::NoStatus`] entry.

Used as the offline-suite / single-credential default for the positional `statuses` seam
([`crate::verify::VerifyContext::statuses`], [`crate::mdoc`]'s params). It covers exactly ONE
document: an mdoc `DeviceResponse` carrying MORE than one document needs one [`StatusOutcome`] per
document (the per-document revocation check is positional), so an under-supplied multi-document
response fails closed to [`StatusOutcome::Unavailable`] rather than reusing one outcome for all.

#### const `STATUS_SIGNING_EKU_OID_PLACEHOLDER`

```rust
const STATUS_SIGNING_EKU_OID_PLACEHOLDER: &str = "1.3.6.1.5.5.7.3.0"
```

The X.509 Extended Key Usage `KeyPurposeId` that authorizes a certificate to sign a Token Status
List — `id-kp-oauthStatusSigning` (draft-ietf-oauth-status-list-21 §13).

**PLACEHOLDER — `id-kp-oauthStatusSigning` is IANA-TBD.** The draft defines this as `{ id-kp TBD }`:
the PKIX `id-kp` arc (OID `1.3.6.1.5.5.7.3` = `iso(1) identified-organization(3) dod(6) internet(1)
security(5) mechanisms(5) pkix(7) kp(3)`) with a FINAL sub-arc that IANA has **not yet assigned**.
The real id-kp sub-arcs start at `.1` (serverAuth=`.1`, clientAuth=`.2`, …), so this placeholder uses
the **`.0`** terminal arc — a syntactically valid OID that matches **NO** real certificate
(fail-closed). It keeps the distinct status-signer authorization path wired + testable via an EXACT
OID match (never a prefix/arc match, which would unsoundly accept serverAuth/clientAuth as
status-signing). Replace this ONE constant with the assigned OID when IANA publishes — a single-line,
single-place update (DRY); the exact-match consumer needs no other change.

The EKU authorization DECISION is **not** made in this sans-IO module — it lives in `crate::trust`
(layer 2), whose `leaf_has_status_signing_eku` consumes this constant to check
whether a status-list signer's leaf certificate bears EXACTLY the status-signing purpose. It is
exposed here only so the value has one authoritative home.

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

X.509 certification-path validation against trusted anchors (RFC 5280 §6.1; research D5, no
hand-rolled crypto).

Trust anchoring asks one question: does the credential's signing certificate (the mdoc
`IssuerAuth` x5chain leaf or the SD-JWT VC JWS `x5c` leaf) **chain to** a certificate that the
configured trust anchor lists for the credential's role/format? This module answers it by
reusing the SDK's vetted X.509 stack — `x509-cert` for parsing, `p256`/`ecdsa` + `rsa` for the
signature math, `sha2` for the digest — and never hand-rolls crypto (Principle IV / research D1).

## Multi-tier path validation (RFC 5280 §6.1)

A credential carries its full signing chain leaf-first: `x5c` / `x5chain = [leaf, intermediate₁,
…]`. eIDAS QTSP / EUDI issuer PKIs commonly issue the leaf from an **intermediate sub-CA** that
itself chains to the trust-list-pinned root (RFC 5280 permits a path length > 1; ETSI EN 319
411), so a one-hop "anchor must directly issue the leaf" check would **false-reject** a conformant
credential. [`verify_chain`] therefore builds and validates a certification path
`leaf → intermediate₁ → … → a CONFIGURED ANCHOR` over the **supplied** chain plus the configured
anchors, enforcing the §6.1 rules at every hop:

- **name chaining (§6.1.3 (a)(4))** — each certificate's `issuer` equals the next-up certificate's
  `subject`;
- **signature (§6.1.3 (a)(1))** — each certificate's signature verifies under the next-up
  certificate's subject public key;
- **validity (§6.1.3 (a)(2))** — **every** certificate on the path (leaf, each intermediate, and
  the terminating anchor) is within its own `notBefore..notAfter` window at the relevant time;
- **CA constraints (§6.1.4 (k)/(n), §4.2.1.9, §4.2.1.3)** — every certificate that **issues** the
  next one down (each intermediate and the anchor) is a CA: `basicConstraints` present, **marked
  critical**, `cA=TRUE`, and (when `keyUsage` is present) the `keyCertSign` bit set;
- **path length (§6.1.4 (m), §4.2.1.9)** — an issuing CA's `pathLenConstraint`, when present,
  bounds the number of intermediates that may follow it toward the leaf.

The supplied intermediates are **attacker-controlled** path-building material: they are honoured
only as candidate issuers and the path is trusted **iff it terminates at a configured anchor**.
An attacker who supplies arbitrary intermediates that never reach a trusted anchor is rejected
([`ChainError::IssuerMismatch`] / `SignatureInvalid`), so an attacker cannot manufacture trust by
presenting their own chain. The path length is also capped ([`MAX_PATH_LEN`]) so an absurdly long
supplied chain cannot turn validation into a denial-of-service.

## Direct pin

The matcher also accepts an exact DER-equal certificate (a trusted-list entry that pins a specific
certificate — the leaf, or one of the supplied certs — directly). The direct-pin path still
enforces that pinned certificate's validity window (an expired pinned cert is rejected, never
trusted) but is deliberately **exempt from the CA constraint**: pinning a specific end-entity
certificate as trusted is an intentional, distinct trust model.

#### Enums

##### enum `ChainError`

```rust
enum ChainError
```

Why a candidate issuer certificate failed to chain to a trusted anchor.

Every rejection carries a specific reason so an untrusted verdict is never opaque. `resolve_chain`
folds these to a coarse-but-accurate [`crate::trust::TrustFailure`] on the [`crate::trust::TrustDecision`],
which the verifier maps to a [`crate::types::ReasonCode`]: [`Self::LeafExpired`]/[`Self::AnchorExpired`]
(a cert outside its validity window) → [`crate::types::ReasonCode::Expired`]; every other variant (no
path, bad signature, non-CA, wrong leaf purpose, unsupported algorithm, malformed, over-long) →
[`crate::types::ReasonCode::UntrustedIssuer`].

###### Variants

- `Malformed(String)`
  - A certificate (leaf, supplied intermediate, or anchor) could not be parsed as DER X.509.
- `IssuerMismatch`
  - No path could be built: at some hop the current certificate's `issuer` name matched no
candidate issuer's `subject` (neither a supplied intermediate nor a configured anchor), so the
path does not reach a trusted anchor. Also returned when the supplied chain is empty.
- `SignatureInvalid`
  - A certificate's signature did not verify under the name-matching candidate issuer's public key
at some hop on the path (a supplied intermediate or a configured anchor whose subject matched
but whose key did not produce the signature).
- `PathTooLong`
  - The supplied certification path is longer than [`MAX_PATH_LEN`] hops — rejected to bound the
validation work an attacker-supplied chain can demand (a denial-of-service guard).
- `UnsupportedAlgorithm(String)`
  - A certificate on the path carries a signature algorithm the SDK does not implement (outside the
EUDI baseline: ES256/384/512 + RSA-PKCS#1v1.5 over SHA-256/384/512).
- `LeafExpired`
  - The leaf is outside its own validity window at the relevant time.
- `AnchorExpired`
  - An issuing certificate on the path (an intermediate sub-CA or the terminating anchor) is itself
outside its own validity window at the relevant time. Per RFC 5280 §6.1.3 (a)(2) **every**
certificate in the path — each issuing CA included — must be valid at the validation time, so
an expired (or not-yet-valid) intermediate/anchor cannot vouch for an otherwise-in-window
certificate below it.
- `NotACa`
  - An issuing certificate on the path (an intermediate sub-CA or the terminating anchor) does not
assert the CA constraints required to issue certificates: per RFC 5280 §6.1.4 (k)/(n) and
§4.2.1.9 an issuer MUST carry `basicConstraints` **marked critical** with `cA=TRUE`, (when
`keyUsage` is present) the `keyCertSign` bit, and a `pathLenConstraint` (if present) wide enough
for the intermediates that follow it. This closes the "any cert is a CA" gap — a non-CA
(end-entity) certificate cannot act as a path intermediate or anchor. (The direct-pin path,
where the configured anchor *is* the pinned certificate, is exempt: pinning a specific
end-entity certificate as trusted is an intentional, distinct model.)
- `WrongLeafPurpose`
  - The leaf (the credential's signing certificate) does not carry the role/format-appropriate
**key purpose** required by [`LeafPurpose`], so it is genuinely chained to a trusted anchor but
**not fit for the purpose presented**:

- an **mdoc Document Signer** leaf lacking the mdlDS EKU (`1.0.18013.5.1.2`), carrying a foreign
  purpose (e.g. TLS `serverAuth`), lacking the `digitalSignature` keyUsage, or asserting
  `cA=TRUE` (ISO/IEC 18013-5:2021 Annex B Table B.3, the `mc` keyUsage / basicConstraints rows);
- an **SD-JWT VC issuer** leaf that is a CA, that has no (or a non-signing) `keyUsage` (ETSI EN
  319 412-2/-3 require keyUsage present asserting a signing bit), or that lacks the per-role
  eIDAS **QcStatement** its [`IssuerRole`] requires (PID → `id-etsi-qct-pid`; QEAA →
  `QcCompliance` + a qualified `QcType`; PuB-EAA → `QcPSB`) — the in-band guard that closes the
  chain-to-root false-trust where a plain eSeal/EAA cert sharing a QTSP root would be trusted as
  PID/QEAA (conformance-audit T1.3).

This closes the "right chain, wrong purpose" false-accept. Fail-closed on a malformed/duplicate
`extendedKeyUsage` / `keyUsage` / `basicConstraints` / `qcStatements` extension.
- `UnsupportedCriticalExtension(String)`
  - A certificate on the processed path (the leaf or an intermediate — never the trust anchor itself,
which RFC 5280 §6.1.1 treats as an input, not a path certificate) carries an extension marked
**critical** whose OID this validator does not recognize/process, so per RFC 5280 §6.1.4 (o) /
§6.1.5 (f) (and the §4.2 / §6 "MUST reject the certificate if it encounters a critical extension
it does not recognize") the path is rejected fail-closed. The recognized critical extensions are
`basicConstraints`, `keyUsage`, `extendedKeyUsage`, `nameConstraints`, and `subjectAltName`;
carries the offending OID for diagnostics.
- `NameConstraintViolation`
  - A certificate on the processed path violates the RFC 5280 §4.2.1.10 **name constraints** imposed
by a CA above it: its subject DN (or a `subjectAltName` entry) falls outside the accumulated
`permitted_subtrees`, or inside an `excluded_subtrees` (§6.1.3 (b)/(c), §6.1.4 (g)). Also returned
fail-closed when a CA imposes a name-constraint on a `GeneralName` type this validator does not
enforce (only `directoryName` and `dNSName` subtrees are processed; any other constraint type, or
a non-default `minimum`/`maximum` `BaseDistance`, is treated as unsupported → reject).
- `SignatureAlgorithmMismatch`
  - A certificate's outer `signatureAlgorithm` (RFC 5280 §4.1.1.2) does not equal the inner
`tbsCertificate.signature` algorithm identifier (§4.1.2.3) it is required to match — a malformed
or tampered certificate (the unsigned outer field was substituted), rejected fail-closed.

##### enum `LeafPurpose`

```rust
enum LeafPurpose
```

The role/format-appropriate **key purpose** the leaf (the credential's signing certificate) must
carry — enforced once, on the leaf, before the path walk, so a genuinely-chained-but-WRONG-PURPOSE
leaf is rejected (e.g. a TLS `serverAuth` cert issued under the same trusted root, or an mdoc DS
cert presented as the SD-JWT VC issuer leaf).

A chain that validates structurally (name/signature/CA/validity) is **not** sufficient: RFC 5280
and the format profiles constrain *what the leaf may be used for*. The verifier threads the
credential's format here (mdoc → [`Self::MdocDocumentSigner`], SD-JWT VC →
[`Self::SdJwtVcIssuer`]); the trust-list-signer-authentication call sites (the LOTL / national-TL
signer in `trust::xml` and `qualified`) pass [`Self::TrustListSigner`], which imposes no
credential-leaf purpose (a TL signer is governed by a different ETSI profile, not the credential
leaf profiles below).

###### Variants

- `MdocDocumentSigner`
  - **ISO/IEC 18013-5:2021 Annex B (Table B.3, mDL document signer certificate).** The Document
Signer leaf MUST satisfy the full Table B.3 leaf profile (verified online against the ISO DIS
Table B.3 text + the auth0-lab/mdl and spruceid/isomdl reference verifiers):

- `extendedKeyUsage` (Table B.3 row `m`, RFC 5280 §4.2.1.12) MUST include the mDL-DS key-purpose
  OID `id-mso-mdl-DS` = `1.0.18013.5.1.2` ([`OID_MDL_DS`]). ISO marks the EKU row `m` (not `mc`),
  and §4.2.1.12 leaves EKU criticality at the issuer's option, so criticality is not asserted —
  only the OID's presence;
- `keyUsage` (Table B.3 row **`mc`** = mandatory + critical) MUST assert `digitalSignature`. ISO
  fixes the DS keyUsage to `digitalSignature` only; this guard requires the `digitalSignature`
  bit (a `keyUsage` without it — present or absent — is rejected);
- `basicConstraints` (Table B.3 row **`mc`**, §4.2.1.9) MUST be `cA=FALSE`. A DS leaf that asserts
  `cA=TRUE` (so it could double as an issuing CA) is rejected even when it carries the mdlDS EKU.

A DS leaf lacking the mdlDS EKU (or carrying only a foreign purpose such as `serverAuth`),
lacking the `digitalSignature` keyUsage, or asserting `cA=TRUE`, is rejected
([`ChainError::WrongLeafPurpose`]). (No eIDAS QcStatement is required of an mdoc DS leaf — that is
an ETSI/eIDAS concept for the SD-JWT VC issuer cert, see [`Self::SdJwtVcIssuer`].)
- `SdJwtVcIssuer(IssuerRole)`
  - **SD-JWT VC issuer (PID / (Q)EAA) leaf**, keyed by the credential's [`IssuerRole`]. No governing
specification mandates a specific EKU for the SD-JWT VC issuer certificate referenced by the JWS
`x5c` (verified online: IETF `draft-ietf-oauth-sd-jwt-vc` §2.5 / RFC 9901 are silent on
EKU/keyUsage; OpenID4VC HAIP 1.0 §6.1.1 mandates only chain-to-anchor structure; the EUDI ARF /
Commission IRs distinguish issuer certs by **QcStatement** OIDs and `keyUsage`, never by an EKU;
ETSI EN 319 412-2 §4.3.10 even forbids marking EKU critical and assigns no EKU value). The
enforced policy is therefore two layered checks:

1. **The EN 319 412-2/-3 base-profile floor (every role).** The leaf **MUST NOT be a CA**
   (`basicConstraints cA=TRUE` is rejected — a CA certificate must not double as an end-entity
   signer), and a `keyUsage` extension **MUST be present** and assert a signing bit
   (`digitalSignature` or `nonRepudiation`/content-commitment). ETSI EN 319 412-2 §4.3.2
   (`NAT-4.3.2-1`) / EN 319 412-3 §4.3.1 (`LEG-4.3.1-2`, pulling in 412-2 §4.3.2 ¶1 + Table 1)
   make keyUsage **SHALL-present**, and a content/seal-signing certificate is limited to keyUsage
   Type A/B/F — each of which asserts a signing bit (verified online against the ETSI PDFs). So an
   **absent** keyUsage is now rejected (tightened from the prior "absent allowed"), as is a present
   keyUsage asserting only unrelated bits (e.g. `keyEncipherment` only). No EKU is required.
2. **The per-role eIDAS QcStatement check** (`leaf_has_required_qc_statements`). Under
   chain-to-root anchoring, a plain eSeal/EAA certificate sharing a QTSP root would otherwise be
   trusted as a PID/QEAA (conformance-audit T1.3); the in-band guard requires the role-appropriate
   ETSI `qcStatements` (RFC 3739 ext OID `1.3.6.1.5.5.7.1.3`): **PID** → the `QcType` statement
   carrying `id-etsi-qct-pid` (`0.4.0.194126.1.1`, ETSI TS 119 412-6 PID-4.5-01); **QEAA** →
   `QcCompliance` (`0.4.0.1862.1.1`) **and** a `QcType` carrying `id-etsi-qct-esign`/`-eseal`
   (`0.4.0.1862.1.6.{1,2}`, EN 319 412-5 §4.2 + TS 119 412-6 QEA-7.1); **PuB-EAA** → the `QcPSB`
   statement (`id-etsi-qcs-QcPSB`, TS 119 412-6 PSB-8.3-01); **NonQualifiedEAA** → no Qc
   requirement (EAA-6.x impose none). A leaf lacking the role's required statement is
   [`ChainError::WrongLeafPurpose`]. (mdoc DS leaves are NOT subject to this — they follow the ISO
   18013-5 Annex B profile, which assigns no QcStatement; see [`Self::MdocDocumentSigner`].)
- `TrustListSigner`
  - **Trust-list signer authentication** (the LOTL / national Trusted List signer, not a credential
leaf). Imposes no credential-leaf key-purpose constraint — the only requirement is that the
signer chains to a configured scheme-operator anchor (the structural §6.1 path). Used by
`trust::xml` and `qualified` when authenticating a signed trust list.

#### Functions

##### fn `verify_chain`

```rust
fn verify_chain<'a>(supplied_chain: &[&[u8]], anchor_certs_der: &'a [Vec<u8>], now_unix: i64, leaf_validity_time: Option<i64>, leaf_purpose: LeafPurpose) -> Result<&'a [u8], ChainError>
```

Whether the supplied certification path `supplied_chain` (leaf-first: `[leaf, intermediate₁, …]`)
builds a valid RFC 5280 §6.1 path to **any** of the trusted `anchor_certs_der`, with the leaf
carrying the `leaf_purpose`-appropriate key purpose.

## Two validation times — the DS-validity-at-signing-time seam (ISO/IEC 18013-5 §9.3.1)

`now_unix` is the verification instant the **chain authentication** is checked at (each intermediate
and the terminating anchor must be within its own validity window at `now_unix` — RFC 5280 §6.1.3
(a)(2)). `leaf_validity_time` is the (optional) instant the **leaf's own** validity window is checked
at:

- **`None`** — the leaf window is checked at `now_unix` (the SD-JWT VC issuer leaf, the trust-list
  signer: there is no distinct signing instant, so "now" is the right time);
- **`Some(t)`** — the leaf window is checked at `t` while the rest of the chain stays at `now_unix`.
  ISO/IEC 18013-5 §9.3.1 requires the mdoc **Document Signer** certificate window to contain the MSO
  `validityInfo.signed` time, not "now": DS certs rotate (~monthly) while mDLs live for years, so a
  conformant mDL would be **false-rejected** at `now` once its DS cert expired even though it was
  valid when it signed. The mdoc verifier passes `Some(mso.validityInfo.signed)` here (confirmed
  online against auth0-lab/mdl `Verifier.ts`, which checks the DS window against `validityInfo.signed`
  and the MSO's own `validFrom`/`validUntil` against the verification clock separately).

## What is enforced

A path is trusted iff, starting from the leaf (`supplied_chain[0]`), it can be walked up — through
zero or more of the supplied intermediates — to a certificate that **is** a configured anchor (a
direct DER-equal pin) or is **issued by** a configured anchor, enforcing:

- **leaf key purpose** — the leaf carries the role/format-appropriate purpose required by
  [`LeafPurpose`] (mdoc DS Table B.3 profile; SD-JWT VC issuer base floor + per-role QcStatement),
  else [`ChainError::WrongLeafPurpose`]. Checked once, on the leaf, before the walk;
- **direct pin** — a cert byte-equal to a configured anchor terminates the path as trusted, still
  subject to that cert's own validity window (an expired pinned cert is [`ChainError::LeafExpired`],
  never trusted), but exempt from the CA / key-purpose / name-constraint / critical-extension checks
  (pinning a specific certificate is a deliberate trust model, and a configured anchor is an RFC 5280
  §6.1.1 trust-anchor input, not a processed path certificate);
- **issued-by** — the child's `issuer` equals the issuer's `subject`, the child's outer/inner
  signature algorithms agree ([`ChainError::SignatureAlgorithmMismatch`]), the child's signature
  verifies under the issuer's subject public key, the issuer is a CA ([`ChainError::NotACa`]
  otherwise), and the issuer is within its validity window at `now_unix`
  ([`ChainError::AnchorExpired`] otherwise);
- **name constraints + critical extensions** (`enforce_path_constraints`) — once a path reaches an
  anchor, the processed certificates (leaf + intermediates, **not** the trust anchor) are walked
  top-down: each is rejected if it carries an unrecognized **critical** extension
  ([`ChainError::UnsupportedCriticalExtension`], RFC 5280 §6.1.4 (o) / §6.1.5 (f)), and each subject
  DN / SAN is checked against the `permitted`/`excluded` name-constraint subtrees imposed by the CAs
  above it ([`ChainError::NameConstraintViolation`], §4.2.1.10 / §6.1.3 (b)(c) / §6.1.4 (g)).

The walk is a **bounded depth-first search that backtracks** over candidate issuers: when several
supplied intermediates name-match the current certificate (e.g. a cross-certificate or an alternate
sub-CA), each is tried in turn, and a branch that dead-ends is unwound so an alternate is explored.
A conformant credential whose chain reaches a configured anchor via **some** valid path is therefore
accepted, even when a greedy first-match would have committed to a dead-end branch. Per RFC 5280
§6.1.4 (l) / §4.2.1.9 a **self-issued** intermediate (subject DN == issuer DN, e.g. a key-rollover
cert) does not consume path-length budget, so it is not counted toward a CA's `pathLenConstraint`.

The supplied intermediates are **attacker-controlled**: they are honoured only as candidate
issuers, never as trust roots, so a path that never reaches a configured anchor is rejected. The
path length is capped at [`MAX_PATH_LEN`] ([`ChainError::PathTooLong`]) to bound the work an
attacker-supplied chain can demand. Returns the most specific [`ChainError`] when no path validates.

## Returns

On success, `Ok(anchor_der)` is a **borrow** (with the input `anchor_certs_der` lifetime) of the DER
of the **trust anchor the path terminated at** — for a chain-to-root path, the matched configured
root; for a direct DER-equal pin, that pinned certificate (which IS the anchor). Returning a borrow
keeps `verify_chain` allocation-free: a caller that must OWN the anchor DER clones at its own boundary
(`resolve_chain` does, storing it as [`crate::trust::TrustListEntry::anchor_cert_der`], consumed by
the in-core status-signer authorization), while the pass/fail-only callers clone nothing. Callers that
anchor a downstream trust decision to the credential's SAME specific root rely on this being the ROOT,
not the leaf.

# Errors

Returns [`ChainError`] when the supplied chain is empty or a certificate is malformed, the leaf has
the wrong key purpose ([`ChainError::WrongLeafPurpose`]), the path reaches no configured anchor
([`ChainError::IssuerMismatch`]), a signature does not verify or its algorithms disagree, an
algorithm is unsupported, an issuing certificate is not a CA or is outside its validity window, the
leaf is outside its validity window at `leaf_validity_time`, a processed certificate carries an
unrecognized critical extension or violates a name constraint, or the path exceeds [`MAX_PATH_LEN`].

#### Constants

##### const `MAX_PATH_LEN`

```rust
const MAX_PATH_LEN: usize = 8
```

The maximum certification-path length [`verify_chain`] will validate, expressed as the cap on the
per-branch `hops` counter: a branch may promote at most `MAX_PATH_LEN` = **8** intermediate
certificates between the leaf and the terminating anchor. The anchor is reached at the head of a
`walk` frame (the direct-pin / issued-by-anchor termination) and is **not** counted as a hop, so the
longest path this admits is `leaf → up to 8 intermediates → anchor`. RFC 5280 places no hard ceiling
on path length, but the EUDI / eIDAS PKIs in scope are shallow (root → at most a small handful of
sub-CAs → leaf), so this small cap rejects an absurdly long **attacker-supplied** chain — bounding
the validation work it can demand — without rejecting any conformant credential.

##### const `OID_MDL_DS`

```rust
const OID_MDL_DS: &str = "1.0.18013.5.1.2"
```

The ISO/IEC 18013-5 mDL Document Signer extended-key-usage OID `id-mso-mdl-DS`
(`{iso(1) standard(0) driving-licence(18013) part-5(5) kp(1) mdlDS(2)}`). A conformant mdoc DS leaf
MUST list this OID in its `extendedKeyUsage` (ISO/IEC 18013-5:2021 Annex B, Table B.3); it is the
purpose [`LeafPurpose::MdocDocumentSigner`] enforces.

### Module `engine`

The native EU trust-list engine (research D5 — the biggest single build).

[`NativeTrustEngine`] is the production [`TrustAnchorSource`]: a host-driven
[`NativeTrustEngine::refresh`]
**fetches → parses → authenticates → caches** the signed trust lists (the offline JSON manifest
now; a TS 119 612 XML LOTL / national TL via [`super::xml`]), and a pure, sans-IO
[`NativeTrustEngine::resolve`] answers issuer-trust questions against the **cached** anchors by
chain-
validating the issuer's signing certificate ([`super::chain`]).

## Reachability / stale policy (U1 — fail-closed for the LOTL; ETSI warning for a national TL)

[`refresh`](NativeTrustEngine::refresh) is where the [`Reachability`] policy applies. Outcomes are
kept distinct (the contract's U1 requirement):

- **Unreachable** — the [`TrustListFetcher`] could not return bytes ([`TrustError::Unreachable`]).
- **Authentication failure** — a fetched XML list's signing certificate did not authenticate
  ([`TrustError::Authentication`]). (Per the T5.3 scope cut the XML path fails closed by default —
  see [`super::xml`].)
- **Stale** — the fetched list parsed but its `NextUpdate` is at/before the current clock. **Staleness
  is fatal only for a LOTL** (`ListKind::Lotl`): ETSI TS 119 615 v1.4.1 PRO-4.1.4-13 voids the LOTL
  and **stops the process** when its `NextUpdate` has passed ([`TrustError::Stale`]). For a **national
  / member-state TL** (`ListKind::National`) a passed `NextUpdate` is a **non-fatal WARNING**
  (PRO-4.2.4-10/12, `WARNING_EUTL_NEXTUPDATE_PASSED`): the list still authenticates and remains usable,
  and the engine records a warning ([`NativeTrustEngine::warnings`]) rather than failing. This aligns
  with the EU DSS reference (`TLExpirationDetection` → a configurable, default-log **warning**).
  Verified online against TS 119 615 v1.4.1 PRO-4.1.4-13 / PRO-4.2.4-10/12 and esig/dss `master`.

Under [`Reachability::FailClosed`] (the default) an unreachable / authentication-failed / **LOTL**-stale
refresh fails **and** clears the cached anchors, so a subsequent `resolve` cannot serve stale/empty
trust (no silent VALID). Under [`Reachability::BestEffort`] an unreachable / LOTL-stale list keeps the
last-known-good cache. A national-TL staleness is never a hard failure under either policy. All of
these are distinct from an **expired/withdrawn entry** (a present-but-out-of-window issuer leaf, or a
withdrawn TS 119 612 service → `resolve` returns untrusted) and from the per-credential status endpoint
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
fn refresh_with(&mut self, fetcher: &mut dyn TrustListFetcher) -> Result<(), TrustError>
```

Host-driven refresh against a supplied [`TrustListFetcher`].

This is the production refresh entry point: the trait's [`TrustAnchorSource::refresh`] takes
no fetcher (it is the sans-IO seam), so the host calls this with its own fetcher.

# Errors

Returns [`TrustError::Unreachable`] / [`TrustError::Stale`] / [`TrustError::Authentication`]
per the reachability/stale policy. Under [`Reachability::FailClosed`] the cache is cleared on
any failure (no stale trust); under [`Reachability::BestEffort`] the last-known-good cache is
kept on an unreachable/LOTL-stale list. A national-TL staleness is never a failure (it is a
recorded warning — [`Self::warnings`]).

```rust
fn set_now(&mut self, now_unix: i64)
```

Set the engine clock (Unix seconds) — the deterministic clock seam (U1 staleness).

```rust
fn warnings(&self) -> &[String]
```

Non-fatal warnings recorded during the last successful refresh (e.g. a national TL past its
`NextUpdate`, `WARNING_EUTL_NEXTUPDATE_PASSED` — TS 119 615 PRO-4.2.4-10). Empty after a clean
refresh, and cleared when a fail-closed refresh drops the cache.

```rust
fn with_json_manifest<impl Into<String>: Into<String>>(self, name: impl Into<String>) -> Self
```

Configure the offline JSON manifest list under the given logical name, as the **LOTL** (a passed
`NextUpdate` is fatal — TS 119 615 PRO-4.1.4-13). Builder-style.

```rust
fn with_national_json_manifest<impl Into<String>: Into<String>>(self, name: impl Into<String>) -> Self
```

Configure the offline JSON manifest list under the given logical name, as a **national /
member-state TL** (a passed `NextUpdate` is a non-fatal WARNING — TS 119 615 PRO-4.2.4-10/12;
the list stays usable). Builder-style.

```rust
fn with_xml_list<impl Into<String>: Into<String>>(self, name: impl Into<String>, role: IssuerRole, format: Format, scheme_anchors_der: Vec<Vec<u8>>, expected_service_type: Option<String>) -> Self
```

Configure a TS 119 612 XML LOTL under the given logical name, mapping every **`granted`**
service it carries to `(role, format)` and authenticating its signing cert against
`scheme_anchors_der` (builder-style). `expected_service_type` optionally restricts ingestion to
`granted` services of one `<ServiceTypeIdentifier>` (§5.5.1; `None` = any granted service).

The enveloped XAdES `SignatureValue`/exclusive-C14N verification is a documented scope cut
(T5.3 — see [`super::xml`]), so an XML list configured this way **fails authentication closed**
in production: a real LOTL is never trusted on the signing-cert chain alone.

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
V2.4.1 / TLv6): a `<TrustServiceStatusList>` whose `<SchemeInformation>` carries a
`<NextUpdate>`, whose `<TrustServiceProviderList>` carries per-`<TSPService>`
`<ServiceInformation>` blocks — each with a `<ServiceTypeIdentifier>` (cl. 5.5.1), a
`<ServiceDigitalIdentity>` → `<X509Certificate>` anchor (cl. 5.5.3), and a `<ServiceStatus>`
(cl. 5.5.4) — and which is sealed with an enveloped XAdES `<ds:Signature>` whose
`<X509Certificate>` is the trust-list operator's signing certificate. This module parses that
structure with `quick-xml` and exposes the per-list anchor certificates + `NextUpdate` to the
engine.

## Service status + type gating (cl. 5.5.1 / 5.5.4 — the T5.1 false-trust fix)

A trust service's `<X509Certificate>` is ingested as a trust anchor **only when its
`<ServiceStatus>` is `…/Svcstatus/granted`** ([`SVCSTATUS_GRANTED`], TS 119 612 V2.4.1 §5.5.4
item i / Annex D.5) — a **withdrawn**/suspended/absent-status service MUST NOT anchor trust (a
withdrawn QTSP cert is no longer a trust root). When the engine configures a specific expected
service type (e.g. [`SVCTYPE_EAA_Q`], §5.5.1.1), only `granted` services **of that type** are
ingested. (Verified online against the TS 119 612 V2.4.1 PDF, §5.5.1.1 (k) / §5.5.4 / Annex D.5.)

## Trust-list signature authentication (the T5.3 scope cut — fail-closed)

TS 119 612 V2.4.1 §5.7.1 requires the list to be sealed with a **XAdES-B-B** enveloped signature
(EN 319 132-1), and Annex B.1.0 fixes its profile: a `<ds:Signature>` enveloped in
`<TrustServiceStatusList>` whose data-object `<ds:Reference>` carries an *enveloped-signature*
transform **then exclusive canonicalization** (`http://www.w3.org/2001/10/xml-exc-c14n#`), with
`<ds:CanonicalizationMethod>` over `<ds:SignedInfo>` also exclusive-C14N. A faithful verification
therefore needs full XML **exclusive canonicalization** + `<ds:Reference>` digest recomputation +
`SignatureValue` verification — there is **no shortcut** (Annex B.1.0). Implementing exclusive
C14N correctly is a large, security-critical undertaking that the in-tree `quick-xml` does not
provide, so it is a **documented scope cut** (see `standards-conformance.md` §1.5).

Until full XAdES verification lands, [`XmlTrustList::authenticate`] **fails closed**: it returns
[`XmlTrustListError::SignatureUnverified`] for every list, even one whose embedded signing
certificate chains to a configured scheme anchor. Accepting a list on the signing-cert **chain
alone** is unsound — the signing certificate is public and copyable, so there is no binding
between the (unverified) signature and the list body, and a forged body would be accepted. That
chain-only acceptance is therefore **not reachable in production**: it exists only behind a
`#[cfg(test)]` seam (`XmlTrustList::authenticate_chain_only`) so the parse/anchor wiring stays
exercised by tests, while the production engine path is always fail-closed.

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
fn authenticate(&self, scheme_anchors_der: &[Vec<u8>], now_unix: i64) -> Result<(), XmlTrustListError>
```

Authenticate the trust list. **Production: fail-closed.**

The full enveloped XAdES verification (exclusive C14N + `<ds:Reference>` digest recomputation +
`SignatureValue` check) required by TS 119 612 V2.4.1 §5.7 / Annex B.1.0 (EN 319 132-1) is a
documented scope cut (no XML-C14N is available in-tree, and there is no sound shortcut — Annex
B.1.0). This method therefore surfaces the specific [`XmlTrustListError::Unsigned`] /
[`XmlTrustListError::SignerUntrusted`] reason when applicable and then **always** returns
[`XmlTrustListError::SignatureUnverified`]: a list is **never** trusted on its signing-cert
chain alone (the signing cert is public and copyable; a forged body would otherwise be
accepted). See the module docs + `standards-conformance.md`.

# Errors

Returns [`XmlTrustListError::Unsigned`] if the list carried no `<ds:Signature>`,
[`XmlTrustListError::SignerUntrusted`] if its signing certificate does not chain to a
configured scheme anchor, otherwise [`XmlTrustListError::SignatureUnverified`] (fail-closed).

```rust
const fn next_update_unix(&self) -> i64
```

The list's `NextUpdate` instant (Unix seconds); at or after it the list is stale.

```rust
fn parse(bytes: &[u8], role: IssuerRole, format: Format, expected_service_type: Option<&str>) -> Result<Self, XmlTrustListError>
```

Parse a TS 119 612 trust-list XML from its raw bytes. Every service whose `<ServiceStatus>` is
[`SVCSTATUS_GRANTED`] (cl. 5.5.4) — and, when `expected_service_type` is `Some`, whose
`<ServiceTypeIdentifier>` (cl. 5.5.1) matches it — contributes its `<ServiceDigitalIdentity>`
certificate(s) as anchors for the caller-supplied `(role, format)`. A **withdrawn** / suspended
/ absent-status service is parsed but **never** anchors trust (the T5.1 false-trust fix).

`expected_service_type` is the optional service-type filter (e.g. [`SVCTYPE_EAA_Q`]); `None`
ingests every `granted` service regardless of type.

# Errors

Returns [`XmlTrustListError`] when the XML is malformed, a certificate body is not valid
base64, or `<NextUpdate>` is missing/invalid.

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
  - The full enveloped XAdES `SignatureValue` / exclusive-C14N / `<ds:Reference>`-digest check is
a documented scope cut (TS 119 612 V2.4.1 §5.7 / Annex B.1.0; EN 319 132-1), so the XML
trust-list path **fails closed**: a list is never trusted on its signing-cert chain alone (a
public signer cert + forged body would otherwise be accepted). See the module docs +
`standards-conformance.md`.

#### Constants

##### const `SVCSTATUS_GRANTED`

```rust
const SVCSTATUS_GRANTED: &str = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted"
```

TS 119 612 V2.4.1 §5.5.4 item i / Annex D.5 — the URI of a trust service whose current status is
**`granted`** (the qualified status is in force). Only a `granted` service anchors trust
(cl. 5.5.4); a `withdrawn` / suspended / absent status MUST NOT. Authoritative source for the
TS 119 612 status/type URIs across the crate (DRY — re-exported by [`crate::qualified`]).

##### const `SVCSTATUS_WITHDRAWN`

```rust
const SVCSTATUS_WITHDRAWN: &str = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn"
```

TS 119 612 V2.4.1 §5.5.4 item i / Annex D.5 — the URI of a **`withdrawn`** trust service (the
qualified status was never granted, or has been withdrawn). A withdrawn service MUST NOT anchor
trust (the T5.1 false-trust fix).

##### const `SVCTYPE_EAA_Q`

```rust
const SVCTYPE_EAA_Q: &str = "http://uri.etsi.org/TrstSvc/Svctype/EAA/Q"
```

TS 119 612 V2.4.1 §5.5.1.1 (k) — the trust-service **type** URI for a *qualified* electronic
attestation of attributes (QEAA) issuing service. The qualified-status gate ([`crate::qualified`])
re-exports this as `EAA_Q_SERVICE_TYPE`.

### Structs

#### struct `ChainValidatingAnchors`

```rust
struct ChainValidatingAnchors
```

The chain-validating trust source for the **C-ABI / binding** verify path (contracts/verifier.md
step 3; data-model.md `TrustAnchorSource`).

The host's trust-refresh step resolves the in-force anchors (EU LOTL / national Trusted Lists /
IACA roots) out-of-process and passes them in as `(role, format, cert)` wire entries; this source
treats each as a **trusted anchor/root** and, at `resolve` time, **chain-validates** the
credential's signing leaf against the anchors configured for its role/format via
[`crate::trust::chain::verify_chain`] (DRY — the same X.509 primitive the always-on bar and the
[`NativeTrustEngine`] use; no re-implemented crypto). The core stays **sans-IO**: it does not
fetch or refresh the trust list — it only chain-validates against the host-supplied anchors.

This is the production C-ABI trust semantics — distinct from [`StaticTestAnchors`] (exact DER
equality only, an offline test seam):

- A host passing an **issuing CA / IACA root** trusts every credential whose leaf chains to it
  (the EUDI chain-to-root model), where exact-leaf-match would reject every real credential.
- The leaf's **validity window** (and a directly-pinned anchor's) is enforced at the verification
  instant, so an expired/withdrawn pinned issuer leaf is rejected ([`crate::trust::chain::ChainError::LeafExpired`]),
  not silently accepted. An expiry-driven chain failure carries [`TrustFailure::Expired`] on the
  [`TrustDecision`] (so the verifier reports `Expired`, not `UntrustedIssuer`); every other path
  failure carries [`TrustFailure::NotTrusted`].

The verification instant `now_unix` (the relevant time the leaf-validity window is checked at) is
carried on the source because [`TrustAnchorSource::resolve`] is sans-clock; the C-ABI builds one
per verify call from the wire context.

Carries only issuer-public certificates (no secret), so deriving `Debug` is safe.

##### Methods

```rust
fn new(now_unix: i64) -> Self
```

Construct an empty source for the verification instant `now_unix` (trusts nothing until anchors
are added).

```rust
fn trust(self, role: IssuerRole, format: Format, anchor_cert_der: &[u8]) -> Self
```

Add a host-resolved trusted anchor/root certificate (DER) for a `(role, format)`. A credential
whose leaf chains to it (or is a valid direct pin) for that role/format is trusted. Returns
`self` for builder-style configuration.

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

**⚠ Not a production trust source.** Its [`resolve`](TrustAnchorSource::resolve) does **exact-DER
pinning ONLY** — NO certificate validity-window check, NO path building, and it ignores the supplied
intermediates and `leaf_validity_time`. It is therefore strictly WEAKER than the production
[`ChainValidatingAnchors`]/[`NativeTrustEngine`], which reject an expired/withdrawn pinned leaf for
the same `resolve` call. Wiring this into a production verifier would trust a pinned-but-expired
issuer certificate (a trust false-accept). Use it only for the offline test suite / conformance
vectors; a production integrator MUST use [`ChainValidatingAnchors`] or [`NativeTrustEngine`].

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
`trusted` is `true` (it is `None` for an untrusted issuer). `failure` carries the coarse-but-accurate
[`TrustFailure`] category when `trusted` is `false` (so the verifier attributes `Expired` vs
`UntrustedIssuer`); it is `None` for a trusted decision.

##### Fields

- `trusted: bool`
  - Whether the issuer is on the configured trust anchor for its role/format.
- `entry: Option<TrustListEntry>`
  - The matched trust-list entry, present iff `trusted`.
- `failure: Option<TrustFailure>`
  - The untrusted-failure category, present iff `!trusted` (so the reason is never opaque).

##### Methods

```rust
const fn trusted(entry: TrustListEntry) -> Self
```

A trusted decision carrying its matched entry.

```rust
const fn untrusted() -> Self
```

An untrusted decision with no specific category (the exact-DER-pin miss / fail-closed default):
the signer is simply not among the configured anchors → [`TrustFailure::not_trusted`] (no source
[`crate::trust::chain::ChainError`]).

```rust
const fn untrusted_because(failure: TrustFailure) -> Self
```

An untrusted decision (no matched entry), carrying the [`TrustFailure`] category so the verifier
can attribute a precise reason.

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
  - The DER-encoded **trust anchor** the credential's signer chained to: for a chain-validating
source ([`ChainValidatingAnchors`] / [`NativeTrustEngine`]) the matched ROOT the path terminated
at (or, for a direct DER-equal pin, that pinned certificate — which IS the anchor); for the
exact-pin [`StaticTestAnchors`] the pinned leaf certificate (the pin is the anchor). This is the
specific root a distinct in-core Token Status List signer must ALSO chain to (see
the [`mod@crate::verify`] status-signer authorization) — so it MUST be the anchor, not the leaf.

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

#### enum `TrustFailure`

```rust
enum TrustFailure
```

Why an issuer resolved as **untrusted** — a coarse-but-accurate category so the verifier attributes
a precise [`crate::types::ReasonCode`] (the verdict is identically INVALID either way).

A chain-validating source ([`ChainValidatingAnchors`] / [`NativeTrustEngine`]) gets a specific
[`crate::trust::chain::ChainError`] back from [`crate::trust::chain::verify_chain`]; collapsing it to
a bare `trusted: false` would mislabel an EXPIRED (but otherwise trusted) signing cert as
"untrusted issuer". This enum preserves the load-bearing distinction the verifier needs:

- [`TrustFailure::Expired`] — the path failed **only** because a certificate on it (the leaf, an
  intermediate, or the anchor) was outside its validity window at the verification instant
  ([`ChainError::LeafExpired`]/[`ChainError::AnchorExpired`]). The credential's signer would
  otherwise chain to a trusted anchor — it is an expiry, not an absence of trust → the verifier maps
  it to [`crate::types::ReasonCode::Expired`].
- [`TrustFailure::NotTrusted`] — every other reason the path does not reach a configured anchor (no
  matching issuer, bad signature, a non-CA on the path, an unsupported algorithm, a malformed cert,
  an over-long chain, an exact-pin miss, or a stale cache) → [`crate::types::ReasonCode::UntrustedIssuer`].
  It carries the **source** [`ChainError`] (`Some`) when a chain-validating source produced one, so a
  debugging integrator can drill into the precise no-trust cause (signature-invalid vs not-a-CA vs
  wrong-leaf-purpose vs issuer-mismatch vs …) WITHOUT changing the coarse verdict mapping — closing the
  asymmetry with the qualified gate, which already keeps the full [`ChainError`] on
  [`crate::qualified::QualifiedTrustError::SignerNotTrusted`]. It is `None` for a no-trust that is NOT a
  chain-validation failure: an exact-DER-pin miss ([`StaticTestAnchors`]), an empty/absent anchor set, or
  a stale-cache fail-closed default.

[`ChainError`]: crate::trust::chain::ChainError
[`ChainError::LeafExpired`]: crate::trust::chain::ChainError::LeafExpired
[`ChainError::AnchorExpired`]: crate::trust::chain::ChainError::AnchorExpired

##### Variants

- `Expired`
  - A certificate on the signing path is outside its validity window (expired / not-yet-valid),
distinct from an absence of trust — surfaced as [`crate::types::ReasonCode::Expired`].
- `NotTrusted(Option<ChainError>)`
  - The signer does not chain to any configured anchor for the role/format (or the cache is stale)
— surfaced as [`crate::types::ReasonCode::UntrustedIssuer`]. Carries the source
[`crate::trust::chain::ChainError`] (`Some`) when a chain-validating source produced one, so the
reason can be drilled into for diagnostics; `None` for a non-chain no-trust (exact-pin miss /
empty anchors / fail-closed default). The verdict mapping stays coarse either way.

##### Methods

```rust
const fn not_trusted() -> Self
```

A no-trust failure that is NOT a chain-validation result (an exact-DER-pin miss, an empty/absent
anchor set, or a fail-closed default): [`TrustFailure::NotTrusted`] with no source
[`crate::trust::chain::ChainError`]. The single authoritative constructor for the sourceless
no-trust case (DRY) — every fail-closed default routes through it.

```rust
const fn reason_code(&self) -> ReasonCode
```

The [`crate::types::ReasonCode`] this untrusted-failure category maps to — the **one**
authoritative mapping (DRY — Principle III), shared by both per-format bars so an expired
signing cert reports `Expired` and a genuine no-trust reports `UntrustedIssuer` identically.
The carried [`crate::trust::chain::ChainError`] on `NotTrusted` is diagnostic only — it never
changes the coarse `UntrustedIssuer` verdict.

### Traits

#### trait `TrustAnchorSource`

```rust
trait TrustAnchorSource
```

The pluggable trust-anchor source (contracts/trust-anchor-source.md).

Implementations range from the offline [`StaticTestAnchors`] to the native EU trust-list engine
(task T013). `resolve` MUST be pure (sans-IO) — it works on cached, in-memory anchors only.

```rust
fn resolve(&self, role: IssuerRole, format: Format, issuer_cert_der: &[u8], supplied_intermediates: &[Vec<u8>], leaf_validity_time: Option<i64>) -> TrustDecision
```

Resolve whether an issuer is trusted for a given role/format, validating the credential's
signing certification path against the configured anchors. **Pure / sans-IO** — never performs
I/O.

`issuer_cert_der` is the credential's signing leaf (the mdoc `IssuerAuth` x5chain leaf, or the
SD-JWT VC JWS `x5c` leaf) and `supplied_intermediates` are the remaining `x5c` / `x5chain`
certificates the credential carries (leaf-first order overall: leaf, then intermediate sub-CAs).
A chain-validating source builds the RFC 5280 §6.1 path `leaf → intermediate₁ → … → anchor`; the
supplied intermediates are untrusted path-building material, so the path is trusted only if it
reaches a configured anchor. An exact-match source ignores the intermediates (it pins the leaf).

`leaf_validity_time` is the instant the **leaf's own** validity window is checked at (the
chain-authentication validity stays at the source's verification clock). It is `None` for the
SD-JWT VC issuer and the trust-list signer (no distinct signing instant — the leaf is checked at
"now"); the mdoc verifier passes `Some(mso.validityInfo.signed)` so the Document Signer
certificate's window is checked against the MSO signing time per ISO/IEC 18013-5 §9.3.1 (DS certs
rotate while mDLs live for years — a conformant mDL must not be false-rejected once its DS cert
expires). An exact-match source ignores it.

```rust
fn resolve_status_signer(&self, role: IssuerRole, format: Format, signer_leaf_der: &[u8], supplied_intermediates: &[Vec<u8>]) -> TrustDecision
```

Authorize a Token Status List **signer** leaf that is DISTINCT from the credential's own issuer:
chain-validate the signer leaf (+ its supplied intermediates) to the SAME configured anchor set
the credential's issuer chains to for `(role, format)`, WITHOUT imposing the credential-leaf key
purpose. A status-list signer follows its own profile (draft-ietf-oauth-status-list §13), so the
credential-leaf QcStatement / mdlDS-EKU floor MUST NOT be applied here; the status-signing EKU is
enforced separately by the caller (the [`mod@crate::verify`] status-signer glue). **Pure / sans-IO.**

Used ONLY on the distinct-signer branch of the in-core Token Status List check: the primary path
(the issuer signs its own status list) resolves the key from the credential's already-verified
issuer leaf by byte-equality and never calls this. Returns a [`TrustDecision`]; `trusted` iff the
signer leaf chains to a configured anchor.

**Default: fail-closed** (`untrusted`). An exact-DER-pin source ([`StaticTestAnchors`]) cannot
chain-validate a signer that is not itself pinned, so it authorizes NO distinct status signer —
only the same-issuer key-reuse path applies there. The chain-validating production sources
([`ChainValidatingAnchors`] / [`NativeTrustEngine`]) override this.

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
- `request_bound: bool`
  - Whether **request binding** (the OpenID4VP nonce/audience/replay + KB-JWT freshness checks) was
evaluated — `true` iff a `request` was supplied to [`crate::verify::verify`]. A request-less
verification (offline / batch / stored re-verification) is a legitimate mode but provides NO
replay/audience protection, so a `valid = true` with `request_bound = false` means "the credential
is cryptographically sound + trusted + in-window, but NOT bound to any request". An integrator that
intended bound verification MUST assert this is `true` — it is the observable signal that a
silently-omitted `request` (an envelope-construction slip) did not downgrade the check.
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
- `StatusUntrusted`
  - A host-supplied **signed** status-list token failed IN-CORE AUTHENTICATION — a stronger,
likely-adversarial signal than [`Self::StatusUnavailable`]. Distinct from a benign unreachable
(no token supplied → [`Self::StatusUnavailable`]): here the host DID supply a Token Status List
token and the core could not authenticate it — its JWS/`COSE_Sign1` signature did not verify
under an authorized signer, its `sub` did not bind to the credential's list URI, it was
expired/stale, or its signer was untrusted / cross-issuer. Also carries a present-but-unusable
status *reference* (a declared `status_list` whose `idx`/`uri` the core cannot evaluate — it
named a mechanism that failed to resolve, closer to "untrusted" than "unreachable"). Identically
fail-closed INVALID (SC-002); this only refines the REASON so a SOC can tell a probable attack on
the revocation path from a transient outage, never the accept/reject.
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
  - The request binding was required but the presentation carries no material to bind it. This one
code intentionally covers **three** distinct "the binding cannot be evaluated" conditions
(deliberately NOT split into separate codes — the verdict is identically INVALID and an
integrator's response is the same: the holder must re-present with a request-bound token):

1. **mdoc under an OpenID4VP request, no addressed audience** — the `Presentation::Mdoc` carried
   `audience: None`, so there is no `client_id` to bind the response to and the OpenID4VP handover
   cannot be reconstructed ([`mod@crate::verify`]).
2. **mdoc without an OpenID4VP request, no `SessionTranscript`** — a `DeviceSignature` is always
   computed over a real `SessionTranscript` (ISO/IEC 18013-5 §9.1.5); with neither a request nor a
   supplied transcript the holder binding cannot be verified, and the verifier MUST NOT fabricate a
   `[null,null,null]` transcript and "pass" it ([`crate::mdoc`]).
3. **SD-JWT VC under an OpenID4VP request, no KB-JWT** — the presentation has no Key Binding JWT, so
   there is nothing carrying the request `aud`/`nonce` to verify ([`crate::openid4vp`]).

All three are "the binding material is absent" — distinct from [`Self::HolderBinding`] (binding
material is present but its signature did not verify) and [`Self::Replay`]/[`Self::WrongAudience`]
(binding present and valid, but bound to the wrong `nonce`/`audience`).
- `QueryNotSatisfied`
  - The presentation verified cryptographically (signature + trust + binding + disclosure integrity)
but does **not** satisfy the OpenID4VP 1.0 DCQL Credential Query it was requested under — the
verifier did **not** get what it asked for. This closes the "did I get what I requested" gap
(conformance-audit T4.1): a trusted, freshly-bound credential of the **wrong** `vct`/`docType`,
missing a requested claim, or carrying a claim value outside the query's `values`, is rejected
rather than waved through as VALID (OpenID4VP 1.0 §"VP Token Validation" step 2.2; §6 DCQL —
<https://openid.net/specs/openid-4-verifiable-presentations-1_0.html>). It is attributed AFTER
the always-on crypto/trust bar passes, so it is distinct from [`Self::Tamper`] /
[`Self::UntrustedIssuer`] / [`Self::HolderBinding`] (those are the credential being unsound) — the
credential is sound, it is simply not the one the DCQL query requested.
- `RoleMismatch`
  - The caller-supplied [`crate::types::IssuerRole`] is inconsistent with the credential's claimed
type — e.g. a credential whose `vct`/`docType` is a EUDI **PID** type presented under a non-PID
trust-anchoring role (conformance-audit T4.3: per-role trust anchoring is only as good as the
role input, so the role is derived from / validated against the credential's claimed type and a
contradiction is rejected rather than silently anchoring under the wrong per-role list). A type
with no standardized role mapping keeps the caller-supplied role (no mismatch).

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
`VerificationResult.qualified_status` via [`crate::qualified::qualified_status`], which first
**authenticates** the national TL (chain-validates its signer against
[`VerifyContext::qualified_scheme_anchors`] + checks `NextUpdate` staleness): a forged / unsigned /
unchained / stale TL — or no scheme anchor configured — yields `Indeterminate`, never `Qualified`
(fail-closed). Disabling the gate leaves the always-on verdict **byte-identical** to a gate-off run
(no false "qualified" — SC-007).

`qualified_status` is **only meaningful for a VALID credential** and is therefore only computed
when `valid == true`. The determination matches the credential's CLAIMED `x5c`/`x5chain` leaf
against the TL **without re-verifying its signature**; since X.509 certificates are public, an
attacker could embed a real qualified issuer's leaf and sign with their own key. Only a VALID
verdict means the always-on bar has signature-verified AND trust-anchored that exact leaf, so the
qualified status is trustworthy. On an INVALID credential `qualified_status` stays `None` (never a
`Qualified` read off an unverified claimed cert — SC-002/SC-007). The status is read **at the
credential's issuance/relevant time** (SD-JWT VC `iat`/`nbf`; mdoc MSO `signed`/`validFrom`), not
at the verification instant.

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
- `statuses: &'a [StatusOutcome]`
  - The revocation/status outcomes resolved by the host (via [`crate::status::check_status`]), one
**per presented document**, positional. SD-JWT VC carries a single credential (index `0`); an mdoc
`DeviceResponse` MAY carry more than one document, each with its own status pointer, so `statuses[i]`
is `documents[i]`'s outcome. A document with no covering entry fails closed to
[`StatusOutcome::Unavailable`] — one outcome is never silently reused across documents (SC-002). The
default [`crate::status::DEFAULT_STATUSES`] covers exactly one document.
- `status_tokens: &'a BTreeMap<String, Vec<u8>>`
  - The host-fetched **signed** Token Status List tokens, keyed by list URI (the credential's
`status.status_list.uri`) → the raw token bytes (a `statuslist+jwt` compact JWS or an
`application/statuslist+cwt` tagged `COSE_Sign1`). When a presented credential declares a Token
Status List reference AND a token is supplied here for its URI, the core AUTHENTICATES that token
in-core ([`crate::status::verify_status_list_token`]) — verifying its signature against a key
authorized by the credential's own trust anchor, binding `sub` to the URI, checking freshness,
and reading the revocation bit itself — and that outcome OVERRIDES the positional
[`Self::statuses`] entry for that credential/document. With no token supplied for a URI (or for a
CRL / no reference), the positional `statuses` outcome is used exactly as before. Host-supplied
(the core stays sans-IO: the host does the fetch; the core does the authentication). The default
[`crate::status::DEFAULT_STATUS_TOKENS`] is empty (⇒ the positional seam alone, unchanged).
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
- `qualified_scheme_anchors: &'a [Vec<u8>]`
  - The scheme-operator trust anchor(s) (DER) the opt-in gate authenticates the national TL
against (off-path unless `qualified_gate` is set). The gate chain-validates the TL's embedded
signer against these before reading status; an empty set (the default) with the gate enabled
means the TL cannot be authenticated → [`QualifiedStatus::Indeterminate`] (can't authenticate
⇒ can't assert qualified — never a false "qualified"). Host-supplied (the core stays sans-IO).

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

**DCQL scope (single presentation).** When `request` carries a DCQL query, this enforces it at the
single-Credential-Query level: `valid = true` means the presentation matched **at least one**
Credential Query of its format (format + `meta` + `claims`/`claim_sets`/`values`). It does NOT
assert the request's **set-level completeness** — `credential_sets` (required option-sets) and
`multiple` cardinality — which is the job of the native [`crate::openid4vp::verify_vp_token`] over a
multi-presentation `vp_token`. An integrator answering a `credential_sets` request across several
presentations MUST fold set-level completeness itself; a per-presentation `valid = true` does not
mean "the whole DCQL request is satisfied".

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

## Trust semantics over the C-ABI

The wire anchors are treated as **trusted anchors/roots** and the credential's signing leaf is
**chain-validated** against them (per role/format) via [`ChainValidatingAnchors`], reusing the
production [`crate::trust::chain::verify_chain`] primitive (DRY). This is the EUDI chain-to-root
model (contracts/verifier.md step 3): a host passing an issuing **CA / IACA root** trusts every
credential whose leaf chains to it, and the leaf's **validity window** is enforced at the
verification instant — an expired/withdrawn pinned issuer leaf is rejected
([`crate::trust::chain::ChainError::LeafExpired`]), never silently accepted. The core stays
**sans-IO**: the host fetches/refreshes the trust list and passes the resolved anchors in; the
core only chain-validates against them (it does not fetch).

## Schema version 5

Version 2 replaced the version-1 foundation seam (which carried only `presentation` + `policy` and
returned `NotImplemented`) with the full always-on verifier wiring. Version 3 additively carried
the opt-in qualified-status gate's national Trusted List ([`WireContext::qualified_trust_list`])
alongside the existing `qualified_gate` flag (T020). Version 4 additively carried the
gate's **scheme-operator trust anchors** ([`WireContext::qualified_scheme_anchors`]) — the X.509
anchor(s) the gate chain-authenticates the national TL's signer against before reading any status,
so a forged / unsigned / unchained / stale TL can never report `Qualified` (fail-closed, SC-007);
with the gate enabled but no scheme anchor the determination is `Indeterminate`. Version 5 (this)
adds the OpenID4VP request's first-class **`response_uri`**
([`crate::openid4vp::PresentationRequest::response_uri`]) — the 4th element of the mdoc
`OpenID4VPHandoverInfo` (OpenID4VP 1.0 §B.2.6), previously stubbed to the `client_id`. A
`PresentationRequest` carried in [`VerifyRequest::request`] now requires this field, so the CBOR
shape changed and the schema version was bumped (Principle VII); a binding speaking an older
version is refused with a clear message rather than mis-parsed.

Version 5 ALSO carries (additively, no further bump) the host-fetched **signed** Token Status List
tokens ([`WireContext::status_tokens`], uri → raw token bytes) that drive the in-core Token Status
List authentication: when a presented credential declares a Token Status List reference and a
matching token is supplied, the core verifies the token's signature (against a key authorized by the
credential's own trust anchor) and reads the revocation bit itself, rather than trusting a
host-supplied outcome. The field is `#[serde(default)]` (empty), so an older v5 payload without it
decodes to "no signed tokens ⇒ the positional `statuses` seam alone" — a decode-compatible addition.
Because this crate is pre-release (0.1.0, unmerged), the addition consolidates into v5 rather than
minting a v6 for an unreleased shape.

Version 5 further carries the revocation/status seam as the **plural, per-document** positional
`statuses` ([`WireContext::statuses`], one [`StatusOutcome`] per presented document — a
multi-document mdoc `DeviceResponse` checks `documents[i]` against `statuses[i]`, never a silent
reuse of one outcome across documents, SC-002) and hardens both wire structs with
`#[serde(deny_unknown_fields)]`, so a typo'd/unrecognized key is a hard decode error rather than a
silently-defaulted field (e.g. a misspelled `qualified_gate` can no longer leave the gate off).

Version 5 ALSO adds a NEW, SEPARATE **set-level** OpenID4VP envelope
([`WireVpTokenRequest`]/[`WireVpTokenResponse`], decoded by [`process_vp_token_bytes`]) that carries
the full multi-credential `vp_token` (`{credential_id: [presentations]}`) so the set-level DCQL
semantics ([`crate::openid4vp::verify_vp_token`] — `credential_sets` required option-sets +
`multiple` cardinality) AND in-core Token Status List authentication are reachable over the C-ABI
(previously native-Rust-only). It is a distinct entry point on the SAME schema version — the
single-presentation [`VerifyRequest`]/[`process_verify_bytes`] envelope is untouched — so this is an
additive addition, not a shape change to an existing envelope (no bump; this crate is pre-release).

### Structs

#### struct `VerifyRequest`

```rust
struct VerifyRequest
```

A `verify` request: the presented credential, the policy, the configured anchors, the
verification context, and (optionally) the OpenID4VP request the presentation must be bound to.

`deny_unknown_fields`: an unrecognized key is a hard decode error, NOT silently ignored. This closes
the request-binding footgun — a **misspelled** `request` key (e.g. `"reqeust"`) would otherwise be
dropped to the `#[serde(default)] None` and silently downgrade to the request-LESS path (no
replay/audience protection) while still reporting `valid = true`. Within a schema version the field
set is fixed; forward compatibility is the `schema_version` bump, not unknown-field tolerance.

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

`deny_unknown_fields`: a typo'd optional key (`statuses`, `status_tokens`, `session_transcript`,
`qualified_gate`, `qualified_trust_list`, `qualified_scheme_anchors`) is a hard decode error rather than a silent
default — a misspelled `qualified_gate` must not silently leave the gate off, nor a misspelled
`session_transcript` silently skip the mdoc binding. Same rationale as [`VerifyRequest`].

##### Fields

- `now_unix: i64`
  - The verification instant (Unix seconds).
- `role: IssuerRole`
  - The issuer role under which trust is anchored.
- `statuses: Vec<StatusOutcome>`
  - The host-resolved revocation/status outcomes, one **per presented document**, positional (SD-JWT
VC uses index `0`; a multi-document mdoc `DeviceResponse` needs one per document). A document with
no covering entry fails closed to [`StatusOutcome::Unavailable`] — never a silent reuse of one
outcome across documents (SC-002).
- `status_tokens: BTreeMap<String, ByteBuf>`
  - The host-fetched **signed** Token Status List tokens, keyed by list URI → raw token bytes (a
`statuslist+jwt` compact JWS, or an `application/statuslist+cwt` tagged `COSE_Sign1`). When a
presented credential declares a Token Status List reference AND a token is supplied here for its
URI, the core AUTHENTICATES that token in-core (signature against a key authorized by the
credential's own trust anchor + `sub` binding + freshness + bit read) and that outcome OVERRIDES
the positional [`Self::statuses`] entry. Absent (the default `#[serde(default)]` empty map) ⇒ the
positional `statuses` seam alone (host pre-resolved), preserving the pre-existing behavior. The
values are CBOR byte strings ([`serde_bytes::ByteBuf`]) so the raw token round-trips through
ciborium without a lossy text re-encode. Carried additively within schema version 5 (this crate
is pre-release / unmerged, so the field consolidates into v5 rather than forcing a bump; an older
v5 payload lacking it decodes to the empty default — a decode-compatible addition).
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
- `qualified_scheme_anchors: Vec<WireSchemeAnchor>`
  - The scheme-operator trust anchor certificate(s) (DER) the opt-in gate chain-authenticates the
national TL's signer against **before** reading any status, carried additively on the wire.
Empty (the default) with the gate enabled means the TL cannot be authenticated → an honest
`Indeterminate` (can't authenticate ⇒ can't assert qualified — never a false "qualified").

#### struct `WireSchemeAnchor`

```rust
struct WireSchemeAnchor
```

One scheme-operator (national-TL-operator) trust anchor carried across the wire: the DER-encoded
anchor certificate the opt-in qualified gate authenticates the national Trusted List's signer
against. Distinct from [`WireTrustAnchor`] (which is role/format-scoped issuer trust for the
always-on bar); a scheme anchor is only the TL-signing root, so it carries no role/format.

##### Fields

- `cert_der: Vec<u8>`
  - The DER-encoded scheme-operator anchor certificate.

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

#### struct `WireVpTokenRequest`

```rust
struct WireVpTokenRequest
```

A **set-level** `verify_vp_token` request: the OpenID4VP request the presentations must be bound to,
the whole multi-credential `vp_token` (`{credential_id: [presentations]}`), the policy, the
configured anchors, the verification instant/role, the host-resolved per-credential/-token/-document
positional `statuses`, and (additively) the host-fetched signed Token Status List `status_tokens`.

`deny_unknown_fields` for the same reason as [`VerifyRequest`]: a misspelled key is a hard decode
error, never a silent default (a typo'd `status_tokens` must not silently drop in-core status
authentication). Reuses [`WirePresentation`] per presentation and [`WireTrustAnchor`] per anchor.

##### Fields

- `schema_version: u32`
  - Wire schema version of this envelope.
- `request: PresentationRequest`
  - The OpenID4VP request (DCQL query + fresh nonce + audience + `response_uri`) the presentations
must be bound to — the SAME [`PresentationRequest`] carried by [`VerifyRequest::request`].
- `vp_token: BTreeMap<String, Vec<WirePresentation>>`
  - The returned `vp_token`: each Credential Query `id` → the Presentations returned under it
(OpenID4VP 1.0 §"Response Parameters"). Reuses [`WirePresentation`] per presentation.
- `policy: VerificationPolicy`
  - The verifier policy.
- `anchors: Vec<WireTrustAnchor>`
  - The configured trust anchors (resolved + passed in by the host's trust-refresh step).
- `now_unix: i64`
  - The verification instant (Unix seconds), shared across every presentation.
- `role: IssuerRole`
  - The default issuer role trust is anchored under (per-credential a query's expected PID type may
override it — see [`verify_vp_token`]).
- `statuses: BTreeMap<String, Vec<Vec<StatusOutcome>>>`
  - The host-resolved revocation/status outcomes, keyed by credential id → per **token**
(presentation) → per **document** (positional). A credential id / token / document with no
covering entry fails closed to [`StatusOutcome::Unavailable`] — never a silent reuse (SC-002).
- `status_tokens: BTreeMap<String, ByteBuf>`
  - The host-fetched **signed** Token Status List tokens, keyed by list URI → raw token bytes,
shared across every presentation. When a presented credential declares a Token Status List
reference AND a token is supplied for its URI, the core AUTHENTICATES that token in-core and its
outcome OVERRIDES the positional [`Self::statuses`] entry (identically to the single-presentation
[`WireContext::status_tokens`]). Absent (the `#[serde(default)]` empty map) ⇒ the positional
`statuses` seam alone. `ByteBuf` so the raw token round-trips through ciborium without a lossy
text re-encode.

#### struct `WireVpTokenResponse`

```rust
struct WireVpTokenResponse
```

A versioned set-level `verify_vp_token` response envelope (mirrors [`VerifyResponse`]).

##### Fields

- `schema_version: u32`
  - Wire schema version of this envelope.
- `outcome: WireVpTokenOutcome`
  - The operation outcome.

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

#### enum `WireVpTokenOutcome`

```rust
enum WireVpTokenOutcome
```

The outcome of a set-level `verify_vp_token` operation (mirrors [`VerifyOutcome`]).

##### Variants

- `Ok { result: VpTokenVerification }`
  - The set-level verdict: the overall `satisfied` decision + the per-credential outcomes (each
carrying its per-Presentation [`VerificationResult`]s + its own `satisfied` flag).
- `Err { message: String }`
  - A decode/usage error rendered as a message (e.g. an unsupported schema version).

### Functions

#### fn `decode_verify_request`

```rust
fn decode_verify_request(bytes: &[u8]) -> Result<VerifyRequest, String>
```

Decode a `verify` request envelope, rejecting unknown schema versions.

# Errors

Returns the decode error (or a schema-version mismatch message) as a `String`.

#### fn `decode_vp_token_request`

```rust
fn decode_vp_token_request(bytes: &[u8]) -> Result<WireVpTokenRequest, String>
```

Decode a set-level `verify_vp_token` request envelope, rejecting unknown schema versions.

# Errors

Returns the decode error (or a schema-version mismatch message) as a `String`.

#### fn `encode_verify_response`

```rust
fn encode_verify_response(outcome: VerifyOutcome) -> Vec<u8>
```

Encode a `verify` response envelope at the current schema version.

#### fn `encode_vp_token_response`

```rust
fn encode_vp_token_response(outcome: WireVpTokenOutcome) -> Vec<u8>
```

Encode a set-level `verify_vp_token` response envelope at the current schema version.

#### fn `process_verify_bytes`

```rust
fn process_verify_bytes(input: &[u8]) -> Vec<u8>
```

Decode → verify → encode. Pure; shared by the C-ABI, language bindings, and tests (single source
of truth — Principle III). A well-formed request runs the always-on [`verify`] entry point and
returns the [`VerificationResult`]; a malformed one yields [`VerifyOutcome::Err`].

#### fn `process_vp_token_bytes`

```rust
fn process_vp_token_bytes(input: &[u8]) -> Vec<u8>
```

Decode → [`verify_vp_token`] → encode for the set-level `vp_token` surface. Pure; shared by the
C-ABI, language bindings, and tests (single source of truth — Principle III). A well-formed request
folds the complete OpenID4VP set-level DCQL semantics (`credential_sets` + `multiple`) AND
authenticates any supplied signed Token Status List token in-core; a malformed one yields
[`WireVpTokenOutcome::Err`] (fail-closed, same discipline as [`process_verify_bytes`]).

### Constants

#### const `ATTESTATION_SCHEMA_VERSION`

```rust
const ATTESTATION_SCHEMA_VERSION: u32 = 5
```

Wire schema version of the attestation envelope. Bumped on a breaking CBOR-shape change within a
SemVer major (independent of the signing core's `SCHEMA_VERSION`). The current version (5) carries
the full verifier inputs — the always-on bar + the OpenID4VP binding + the opt-in qualified-status
gate's national Trusted List / scheme anchors + the mdoc handover `response_uri`. See the
`## Schema version 5` module section for the per-version history (v1 was the foundation seam).
