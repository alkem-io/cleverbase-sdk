# Contract: OpenID4VP full verifier (request build + bound verify)

The SDK is a **full verifier** (resolved in Clarifications): it builds the OpenID4VP presentation request
AND verifies the response is cryptographically bound to it. OpenID4VP **1.0** — query is **DCQL** (the old
`presentation_definition`/Presentation-Exchange was removed; treat PE as optional legacy behind a flag).

## Operations

```
buildRequest(query: Dcql, audience: client_id) -> PresentationRequest { dcql, nonce (fresh), audience }
verifyResponse(vp_token: bytes, request: PresentationRequest, policy, anchors) -> VerificationResult
```

`verifyResponse` runs the always-on bar (`verifier.md`) PLUS the **binding** checks:

## Binding checks (FR-015 / SC-008)

- **Nonce**: the presentation echoes the request's fresh `nonce` — SD-JWT VC: in the KB-JWT (`nonce`);
  mdoc: in the `SessionTranscript` / OID4VPHandover that the DeviceAuth signs over. A missing/mismatched
  nonce ⇒ INVALID `replay` (a replayed presentation cannot satisfy a fresh nonce).
- **Audience**: the presentation is addressed to this verifier's `client_id` — SD-JWT VC KB-JWT `aud`;
  mdoc handover/client_id. Wrong audience ⇒ INVALID `wrong_audience`.

Owning both halves makes replay/audience binding **correct by construction** — the verifier never accepts a
presentation it didn't request.

## DCQL satisfaction — "did I get what I requested" (now enforced IN-CORE)

OpenID4VP **1.0 §6 (DCQL)** + **§"VP Token Validation" steps 2.2 + 3** (verified online:
<https://openid.net/specs/openid-4-verifiable-presentations-1_0.html>; source `openid/OpenID4VP`
`1.0/openid-4-verifiable-presentations-1_0.md`). The DCQL query is no longer carried opaquely: it is
parsed and evaluated **in-core** (`src/dcql.rs`) — the explicit product decision, per §"Security Checks
on the Returned Credentials and Presentations": *"the Verifier MUST NOT rely on the Wallet to enforce
these constraints."* This closes the conformance-audit **T4.1/T4.2** false-trust: a trusted,
freshly-bound credential of the **wrong `vct`/`docType`**, missing a requested claim, or carrying a
value outside the query's `values`, used to pass as VALID.

After the always-on bar accepts a presentation, the verifier checks it SATISFIES the matching DCQL
Credential Query (`verify_response`/`verify` apply it automatically when the request carries an
enforceable DCQL):

- **format** matches the Credential Query `format` (§6.1).
- **meta** matches (§6.1): SD-JWT VC `vct` ∈ `meta.vct_values`; mdoc every `docType` == `meta.doctype_value`.
- every requested **claim path** (§"Claims Path Pointer": JSON-nested for SD-JWT VC;
  `[namespace, elementIdentifier]` for mdoc) resolves in the verified **disclosed** attributes,
  honoring `claim_sets` (§"Selecting Claims": at least one listed option fully present).
- if a claim specifies **`values`** (§6.3), the disclosed value ∈ `values`.

A sound, trusted, request-bound credential that does **not** satisfy its query ⇒ INVALID with the new
`ReasonCode::QueryNotSatisfied` (distinct from `Tamper`/`UntrustedIssuer`/`HolderBinding` — the
credential is sound, it is simply not the one requested).

**Set-level / multiplicity** (§"VP Token Validation" step 3 + §"Selecting Credentials"):
`openid4vp::verify_vp_token(request, vp_token, …)` evaluates a whole `{ credential_id: [presentations] }`
`vp_token` in-core — each Presentation runs the bar + binding + per-query DCQL match, then the set fold
requires every **required** Credential Set Query to have a fully-satisfied `option` (or, with no
`credential_sets`, every Credential Query satisfied); a `multiple:false` query MUST carry at most one
Presentation.

### Role derivation/validation (T4.3)

`IssuerRole` is no longer "only as good as the host's input". The credential's claimed type derives /
validates the trust-anchoring role in-core (`dcql::reconcile_role`): a EUDI **PID** type
(`vct urn:eudi:pid:1`/`eu.europa.ec.eudi.pid.1`; mdoc `docType eu.europa.ec.eudi.pid.1`) MUST anchor
under `IssuerRole::Pid`, so a caller role that contradicts the claimed type is rejected
(`ReasonCode::RoleMismatch`) **before** the trust resolve — it can never anchor under the wrong per-role
list. A type with no standardized role mapping keeps the caller-supplied role. The reconciled role is
the one threaded into `TrustAnchorSource::resolve` (and the per-role QcStatement leaf-purpose floor).

### DCQL scope cuts (documented, not silently omitted)

- **`trusted_authorities`** (§6.1.1) is not evaluated by the DCQL layer — issuer trust is the always-on
  bar's per-role/format chain-to-anchor (the spec note: *"Verifiers must verify that the issuer … is
  trusted on their own"*; `trusted_authorities` is a wallet-side data-minimization hint).
- **`require_cryptographic_holder_binding:false`** is not honored — the SDK **always** requires holder
  binding (a documented secure default; see `verifier.md`).
- **Value matching** is enforced verifier-side here (the verifier sees the real returned value), even
  though §6.3 treats `values` as best-effort for the *Wallet*; for mdoc the CBOR value is matched as its
  JSON form (RFC 8949 §6.1), which the SDK's decoded `AttributeValue` already is.
- Claim paths resolve against the **verified disclosed** set (the privacy-minimal claims actually
  presented); a path targeting an always-visible non-disclosed scalar is treated as not-present.
- **Encrypted responses** (`direct_post.jwt`) and the **DC-API** handover remain out of scope (carried
  forward from `verifier.md` / the audit's documented cuts).

## Invariants

- A fresh `nonce` per `buildRequest` (no reuse); the SDK tracks the issued request to verify against it.
- `verifyResponse` requires the originating `request` — a presentation cannot be verified "bound" without
  the nonce/audience it must match.

## Accepted design decisions (non-bugs — do NOT "fix" without a spec change)

- **Single-document mdoc: a wrong-key `DeviceSignature` surfaces as `replay`, not `holder_binding`.**
  For a single-document mdoc, an attacker can supply a well-formed `DeviceSignature` over the detached
  `DeviceAuthentication` transcript that simply does not verify under the device key. Whether that failure
  is "wrong holder key" or "stale/replayed nonce in the transcript the signature commits to" is **not
  distinguishable** from a single well-formed signature over a detached transcript — both manifest as
  "this signature does not verify against the expected (key, transcript) pair". The verifier therefore
  attributes the request-bound failure as `replay` (the freshness/binding check the request drives). Both
  outcomes are `valid=false`, so the verdict is identical and secure; only the machine-readable reason is
  the coarser-but-honest `replay` rather than `holder_binding`. Do not "sharpen" this to `holder_binding`
  by assuming wrong-key — that assumption is unprovable here and would mislabel a genuine stale-nonce replay.

See `verifier.md` → "Accepted design decisions" for the related mandatory-mdoc-binding and
ECDSA-malleability decisions.

## Tests (must fail first)

- A presentation correctly bound to an issued request → VALID; the same presentation **replayed** (or built
  for a different `audience`) → INVALID with `replay`/`wrong_audience` (SC-008). Both formats.
</content>
