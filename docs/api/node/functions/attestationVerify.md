# Function: attestationVerify()

> **attestationVerify**(`request`): `Buffer`

Defined in: [index.d.ts:27](https://github.com/alkem-io/cleverbase-sdk/blob/main/bindings/node/index.d.ts#L27)

Verify an EUDI attestation presentation.

CBOR-through: takes a CBOR-encoded `VerifyRequest` (attestation wire schema v5 — the presented
SD-JWT VC / mdoc, verifier policy, host-resolved trust anchors, and verification context) and
returns a CBOR-encoded `VerifyResponse` (schema v5) carrying the `outcome`. The always-on verdict
(`VerificationResult` — `valid` plus machine-readable reason codes) and any decode/usage error
ride *inside* the response body, not through this call's error channel; a malformed request
fails closed to an `err` outcome rather than throwing. The holder's private key never crosses
this boundary — the verifier only inspects the presentation the holder already produced. All
protocol/crypto logic lives in `cleverbase-attestation` (Constitution Principle III/VIII); this
wrapper is bytes-in / bytes-out only.

## Parameters

### request

`Buffer`

## Returns

`Buffer`
