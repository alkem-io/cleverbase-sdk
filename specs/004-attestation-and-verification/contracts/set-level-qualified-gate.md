# Draft (DEFERRED): set-level qualified-status gate over the multi-credential `vp_token` surface

**Status: DRAFT / NOT IMPLEMENTED.** This is a follow-up spec captured for later. As of the sixth-review
remediation (commit `285a477`), the set-level surface **fails loud** on a request that asks for the
qualified gate rather than silently ignoring it — see [Current behavior](#current-behavior). This document
specifies how to lift that restriction and run the opt-in eIDAS qualified determination **per credential**
on the multi-credential path, reachable from the C-ABI + go/python/node bindings, at parity with the
single-presentation surface.

Read alongside [`qualified-status-gate.md`](qualified-status-gate.md) (the always-on-bar + opt-in-gate
determination this reuses) and [`openid4vp-verifier.md`](openid4vp-verifier.md) (the set-level DCQL fold).

## Motivation

The single-presentation surface (`verify()` / the `verify` C-ABI + bindings) already runs the opt-in
qualified gate: `WireContext` carries `qualified_gate` + `qualified_trust_list` + `qualified_scheme_anchors`,
and `crate::verify::verify` calls `qualified_status_for` → `fold_qualified` to populate
`VerificationResult.qualified_status` (SC-007: additive, never gates the always-on verdict).

The set-level surface (`openid4vp::verify_vp_token` / the `verify_vp_token` C-ABI + bindings, commit
`7a67742`) does **not**: `verify_vp_token` never reads `policy.qualified_gate`, and `WireVpTokenRequest`
carries no qualified Trusted List / scheme anchors. A binding integrator answering a multi-credential
OpenID4VP request that requires **qualified** (QC) issuers therefore cannot get a per-credential
`qualified_status` from the set-level surface — the exact gap the sixth review flagged (Altitude / cross-file
/ wrapper angles).

## Current behavior (the guard this spec replaces)

`crate::wire::process_vp_token_bytes` rejects a set-level request whose `policy.qualified_gate == true`
with a `WireVpTokenOutcome::Err`:

> "the opt-in qualified-status gate is not supported on the set-level vp_token surface; verify each
> presentation via the single-presentation surface, or unset qualified_gate"

This is the correct *interim* behavior (no silent no-op), and it is the **single enablement point**: when
this feature lands, that guard is removed and replaced by the plumbing below.

## Goal

For a set-level `verify_vp_token` request with the gate enabled, populate a per-credential,
per-presentation `qualified_status` (`Qualified | NotQualified | Indeterminate`) using the *same*
determination as single-presentation — reused, not re-implemented (Constitution III/VIII). The set-level
`satisfied` / `credential_sets` / `multiple` verdict is **unchanged**: qualified status is additive
observability (SC-007), never a satisfaction gate. Uniform across native, C-ABI, and all three bindings.

## Design

### 1. Wire — `WireVpTokenRequest` gains the qualified seam

Add the three fields the single-presentation `WireContext` already carries (additive, `#[serde(default)]`,
schema v5 pre-release — no bump; keep `deny_unknown_fields`):

```rust
/// Off-by-default opt-in qualified gate (mirrors WireContext). When policy.qualified_gate (or a
/// per-request flag) is set AND qualified_trust_list is supplied, each per-credential presentation
/// result carries a qualified_status; the satisfied verdict is byte-identical either way (SC-007).
#[serde(default)] pub qualified_trust_list: Option<serde_bytes::ByteBuf>,   // the national TL (JSON), as WireContext
#[serde(default)] pub qualified_scheme_anchors: Vec<WireSchemeAnchor>,      // reuse the existing WireSchemeAnchor
```

The enable flag stays `policy.qualified_gate` (same as single-presentation; `VerificationPolicy` is already
carried). **Remove the fail-loud guard** in `process_vp_token_bytes` and instead parse the TL + scheme
anchors (reuse the exact block from `process_verify_bytes`, which already does this for `WireContext` — factor
a shared helper to avoid a third copy, cf. the `take_status_tokens` extraction) and thread them in.

### 2. Native — `verify_vp_token` runs the gate per credential

`verify_vp_token` (and `verify_vp_token_slots`) gain the qualified inputs — a parsed
`Option<&QualifiedTrustList>` + `&[Vec<u8>]` scheme anchors + the `qualified_gate` bool (or a small
`QualifiedContext` bundle to stay under the argument-count bar, cf. `StatusInputs`). For each VALID
presentation whose credential is queried, after the per-presentation bar runs, call the **existing**
`crate::verify::qualified_status_for` and set it on that presentation's `VerificationResult.qualified_status`
— identical to `verify.rs:346-347`.

Key reuse points (already exist — do NOT re-implement):
- `qualified_status_for(presentation, ctx-like inputs, mdoc_meta)` — authenticates the TL once at `now`,
  then per document reads status at the credential's own relevant time (SD-JWT `iat`/`nbf`; mdoc MSO
  `signed`) and folds via `fold_qualified`. The `qualified_status_for` signature currently takes a
  `VerifyContext`; refactor its qualified inputs into a small struct both `verify()` and `verify_vp_token`
  pass, so the determination has one authoritative caller-shape (DRY).
- The mdoc per-document fold + `MdocVerifyMeta.claimed_issuers` (cert, signed, category) and the SD-JWT
  `issuer_category` / `issuer_signing_cert_der` / `issuance_time_unix` the gate needs are already surfaced
  by the per-presentation bar (`verify_response_with_meta`), so the inputs are in hand — no second decode.

### 3. Result — carried by the existing serde-derived types

No new result type: `VerificationResult.qualified_status` already serializes, and `CredentialVerification`
carries `Vec<VerificationResult>`, so each presentation's qualified status rides the wire for free. No
`VpTokenVerification`/`CredentialVerification` shape change.

### 4. C-ABI + bindings

No new symbol — the existing `cleverbase_attestation_verify_vp_token` + go `AttestationVerifyVpToken` /
node+python `attestation_verify_vp_token` are CBOR-through, so the added `WireVpTokenRequest` fields flow
without touching the binding code. Remove the "does not run the qualified gate" sentence from their
doc-comments; update the wire doc + [`qualified-status-gate.md`](qualified-status-gate.md) to note the gate
now runs on both surfaces.

## Decisions / open questions

- **Per-presentation, not per-credential-folded.** A Credential Query may return multiple presentations
  (`multiple: true`). Each presentation is its own credential with its own issuer/relevant-time, so
  `qualified_status` belongs on each `VerificationResult` (the current shape), NOT a single per-credential
  fold. A consumer that wants a per-credential-set qualified verdict composes it from the per-presentation
  statuses (document the composition rule; do not bake a fold that could hide a NotQualified among
  Qualifieds — mirror the mdoc multi-document `fold_qualified` fail-closed intent: a set is "qualified" only
  if every contributing presentation is `Qualified`).
- **Role per credential.** The per-credential role reconciliation `verify_vp_token` already does (a query's
  expected PID type may override the default `role`) must feed the qualified determination's role, not the
  envelope default — thread the reconciled role into `qualified_status_for`.
- **Only for queried + satisfied-eligible presentations.** Consistent with the R6 DoS hardening, do NOT run
  the (TL-authenticating, cert-matching) qualified determination for unqueried credential_ids or
  over-cardinality presentations — they can't contribute to the verdict, and running it is wasted work on
  attacker-controlled input. Run it only where the always-on bar ran.
- **TL authentication cost.** `qualified_status_for` authenticates the national TL once per call (the R2
  hoist). Across many credentials sharing one TL, authenticate the TL **once per `verify_vp_token` call**
  and reuse — do not re-authenticate per credential (thread an already-authenticated handle, or memoize
  within the call). Bounded by the R6 skip (only queried credentials).
- **Provisional identifiers unchanged.** This reuses the same status/EKU machinery; the IANA-TBD
  `STATUS_SIGNING_EKU_OID_PLACEHOLDER` and CWT-label caveats in [`qualified-status-gate.md`](qualified-status-gate.md)
  / `standards-conformance.md` §4 apply identically. No new provisional surface.
- **Experimental status.** cl. 4.12 is pre-operational (national TLs barely carry `EAA/Q` entries), so this
  is opt-in and, absent fixtures, yields `Indeterminate` — same posture as single-presentation.

## Test plan (test-first)

- A set-level request with `policy.qualified_gate=true` + a national TL fixture where one credential's
  issuer is a granted `EAA/Q` QTSP and another is not → the first presentation's `qualified_status ==
  Qualified`, the second `NotQualified`/`Indeterminate`; **`satisfied` is byte-identical to the gate-off
  run** (SC-007 additivity).
- Gate on + no TL supplied → every `qualified_status == Indeterminate` (fail-closed data-unreachable), still
  `satisfied` unchanged.
- Gate on + a credential's `category` absent (ordinary EAA) → `Indeterminate` (PRO-4.12.4-03), per
  [`qualified-status-gate.md`](qualified-status-gate.md).
- The fail-loud guard is GONE: `qualified_gate=true` no longer returns `Err` (delete/replace that test).
- Unqueried / over-cardinality presentations are NOT qualified-evaluated (assert no TL authentication runs
  for them — the R6 skip still holds).
- Binding smoke (≥ Go): a `WireVpTokenRequest` with the qualified fields set round-trips a
  per-presentation `qualified_status` through `AttestationVerifyVpToken`.

## Effort estimate

Small–medium. The determination (`qualified_status_for` / `fold_qualified`), the TL parse/authenticate, the
per-document category/relevant-time inputs, and the serde result carriage **all already exist**; this is
plumbing (wire fields + threading the qualified inputs through `verify_vp_token` per credential + removing
the guard) plus tests. The main design care is the per-presentation-vs-folded decision and the
authenticate-TL-once reuse. No new crypto, no new wire schema version, no binding code change.
