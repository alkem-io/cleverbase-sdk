# Function: attestationVerifyVpToken()

> **attestationVerifyVpToken**(`request`): `Buffer`

Defined in: [index.d.ts:46](https://github.com/alkem-io/cleverbase-sdk/blob/main/bindings/node/index.d.ts#L46)

Verify a set-level OpenID4VP `vp_token` (the multi-credential presentation).

CBOR-through: takes a CBOR-encoded `WireVpTokenRequest` (attestation wire schema v5 — the OpenID4VP
request, the whole `{credential_id: [presentations]}` `vp_token`, verifier policy, host-resolved
trust anchors, per-credential statuses, and any signed Token Status List tokens) and returns a
CBOR-encoded `WireVpTokenResponse` (schema v5) carrying the `outcome`. Unlike `attestation_verify`
(a single presentation), this folds the OpenID4VP set-level DCQL semantics (`credential_sets` +
`multiple` cardinality) AND authenticates supplied status tokens in-core across the set. The
set-level verdict (`satisfied` + per-credential results) and any decode/usage error ride *inside*
the response body, not through this call's error channel; a malformed request fails closed to an
`err` outcome rather than throwing. All protocol/crypto logic lives in `cleverbase-attestation`
(Constitution Principle III/VIII); this wrapper is bytes-in / bytes-out only.

The set-level surface does NOT run the opt-in eIDAS qualified-status gate: a request with
`policy.qualified_gate = true` yields an `err` outcome (verify each presentation via
`attestation_verify` if the qualified gate is required).

## Parameters

### request

`Buffer`

## Returns

`Buffer`
