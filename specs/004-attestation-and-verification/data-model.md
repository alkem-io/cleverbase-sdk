# Data Model: EUDI attestation — verification now, issuance forward-looking

Domain entities for the attestation core. No persistence in the core (sans-IO); credential/key custody is
the integrator's. Types are conceptual (the C-ABI carries them as CBOR), not a wire schema.

## Attestation (verifiable credential)

An issuer-signed set of attributes about a subject, in one of two formats.

| Field | Type | Notes |
|-------|------|-------|
| `format` | enum | `SdJwtVc` \| `Mdoc` (ISO 18013-5) |
| `issuer` | ref → Issuer | the signing authority; trust resolved via the trust-anchor source |
| `attributes` | map | claims; for a presentation, only the **disclosed** subset is present |
| `validity` | {notBefore, notAfter} | SD-JWT VC `nbf`/`exp`; mdoc MSO `validityInfo` |
| `status` | status-ref? | revocation/status mechanism (status list / CRL); may be absent |
| `holderBinding` | {key, proof} | SD-JWT VC `cnf`+KB-JWT; mdoc DeviceKey+DeviceAuth |
| `raw` | bytes | the encoded credential (compact SD-JWT(+KB) or CBOR DeviceResponse) |

**Rules**: the format determines the encoding (JOSE vs CBOR/COSE) and the disclosure/holder-binding
mechanism; selective-disclosure integrity (disclosed attribute ↔ issuer-signed digest) MUST be checked
(FR-003); an unrecognized/unsupported format → a specific "unsupported format" error, never a guess.

## Issuer

| Field | Type | Notes |
|-------|------|-------|
| `signingCert`/`key` | cert/key | the credential's signing key (x5chain for mdoc IssuerAuth; JWS `x5c`/`kid` for SD-JWT VC) |
| `role` | enum | `QEAA` \| `PID` \| `PubEAA` \| `NonQualifiedEAA` — selects the trust anchor (research D5) |
| `trustStatus` | enum | `Trusted` \| `Untrusted` (always-on bar: present on the configured trust list) |
| `qualifiedStatus` | enum? | `Qualified` \| `NotQualified` \| `Indeterminate` — from the opt-in gate only (else null) |

**Rules**: trust is anchored **per role/format** (QEAA→EU LOTL/Trusted Lists; PID→Art.5a(18) list;
PuB-EAA→Art.45f(3) list; mdoc→IACA root/VICAL). `qualifiedStatus` is populated only when the opt-in
TS 119 615 gate runs; otherwise it is absent (never assumed Qualified).

## TrustAnchorSource (pluggable)

| Member | Type | Notes |
|--------|------|-------|
| `anchors(role/format)` | resolve | returns the trust anchors for a role/format (EU LOTL + national TLs / IACA roots / per-role lists), or a configured **test anchor** for the offline suite |
| `refresh()` | func | fetch/cache signed trust-list XML/JSON (TS 119 612 v2.4.1 / TS 119 602 LoTE); not per-verification |
| `reachability` | policy | fail-closed by default when a list/status is unreachable (FR-003 edge) |

**Rules**: the source is configured (production EU lists vs test anchors); verification (FR-004) runs with
the configured anchors + the presented credential alone, offline-capable where the standards allow.

## VerificationPolicy (verifier input)

| Field | Type | Notes |
|-------|------|-------|
| `formats` | set | which formats to accept (default: both) |
| `qualifiedGate` | bool | enable the opt-in TS 119 615 qualified-status determination (default off) |
| `statusReachability` | enum | fail-closed (default) \| best-effort |
| `request` | ref → PresentationRequest? | the SDK-issued OpenID4VP request this presentation must be bound to |

## PresentationRequest (verifier-built, OpenID4VP)

| Field | Type | Notes |
|-------|------|-------|
| `dcql` | query | which attributes/credentials are requested (DCQL — OID4VP 1.0) |
| `nonce` | bytes | fresh per request; the presentation MUST echo it (replay protection) |
| `audience` | string | the verifier's `client_id`; the presentation MUST be addressed to it |

**Rules**: the verdict MUST confirm the presentation is cryptographically **bound** to the issued
`nonce`+`audience` (FR-015); an unbound/replayed/wrong-audience presentation → INVALID (SC-008).

## VerificationResult (verdict)

| Field | Type | Notes |
|-------|------|-------|
| `valid` | bool | always-on bar: signature + trust-list membership + validity + status + holder binding + disclosure integrity + request binding |
| `disclosedAttributes` | map | only the disclosed subset; undisclosed neither revealed nor required |
| `trustStatus` | enum | issuer Trusted/Untrusted |
| `qualifiedStatus` | enum? | Qualified/NotQualified/Indeterminate (opt-in gate only) |
| `reasons` | list | machine-readable reason codes (esp. for INVALID — FR-005) |

**Rules**: no **false-accept** — any failing check yields `valid=false` with a specific reason (SC-002);
`qualifiedStatus=Qualified` requires the opt-in gate to have positively determined it (no false "qualified",
SC-007).

## HolderContext + SignerHook (issuance/presentation — gated)

| Member | Type | Notes |
|--------|------|-------|
| `holderPublicKey` | JWK / COSE_Key | supplied by the integrator; the SDK never holds the private key |
| `sign(handle, alg, signingInput)` | async callback | the integrator's HSM/KMS signs; the SDK splices the result into the proof-JWT / KB-JWT / DeviceAuth envelope (research D8) |

**Rules**: the SDK is **not a wallet** (FR-009) — no holder private key, no sole-control secret, no crypto
in a browser; `signingInput` is built deterministically and exposes `aud`/`nonce` for host policy inspection
(blind-signing trust boundary, RCA-documented).

## IssuerBackend (issuance — configurable, gated)

| Field | Type | Notes |
|-------|------|-------|
| `kind` | enum | `Reference` (EU `eudi-srv-pid-issuer` test double) \| `Cleverbase` (future, when its API ships) \| `None` |
| `oid4vciConfig` | config | OpenID4VCI endpoints/credential offer |

**Rules**: when `kind=None` (default), the issuance path is **skipped** (reported skipped, never failed —
FR-008); a future Cleverbase issuer drops in as another `kind` **by configuration**, with no rework of
verification or the holder flow (SC-005).
</content>
