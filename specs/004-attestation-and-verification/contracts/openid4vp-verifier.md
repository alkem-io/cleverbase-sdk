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
