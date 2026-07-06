# Function: attestationIssuance()

> **attestationIssuance**(`request`): `Buffer`

Defined in: [index.d.ts:40](https://github.com/alkem-io/cleverbase-sdk/blob/main/bindings/node/index.d.ts#L40)

Drive an EUDI attestation issuance / holder-presentation step.

CBOR-through: takes a CBOR-encoded `IssuanceRequest` (issuance wire schema v1 — one `obtain` /
`prepare-present` / `finish-present` operation plus its opaque carried session/prepared handle)
and returns a CBOR-encoded `IssuanceResponse` (schema v1) carrying the `outcome` (the next step,
the produced `vp_token`, or an `err`). As with `attestation_verify`, errors ride inside the
response — a malformed request fails closed to an `err` outcome — and the holder key never
crosses this boundary (the host signs the returned `SigningInput` out-of-band and hands the
signature back on the next step). All protocol/crypto logic lives in `cleverbase-attestation`
(Constitution Principle III/VIII); this wrapper is bytes-in / bytes-out only.

## Parameters

### request

`Buffer`

## Returns

`Buffer`
