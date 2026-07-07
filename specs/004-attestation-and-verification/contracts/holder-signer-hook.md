# Contract: holder signer-hook + gated issuance (US2, forward-looking)

The issuance/holding/presentation side. The SDK is **not a wallet** (FR-009): it orchestrates the EUDI
ceremonies sans-IO and **never holds the holder private key** — a direct reuse of the spec-001 remote-
signing signer-hook (DRY, research D8). The live issuance is **gated** on a real issuer API (Cleverbase has
none today — spec-003 gating pattern).

## Signer-hook (holder key custody)

```
HolderContext {
  holderPublicKey: JWK | COSE_Key,                     // integrator-supplied; SDK never sees the private key
  sign(handle, alg, signingInput) -> signature         // async; the integrator's HSM/KMS signs
}
```

The SDK builds the exact `signingInput` for each ceremony and splices the returned signature into the
envelope:
- **OpenID4VCI proof-of-possession** JWT (`typ: openid4vci-proof+jwt`).
- **SD-JWT VC Key-Binding JWT** (`typ: kb+jwt`, over `aud`/`nonce`/`iat`/`sd_hash`).
- **mdoc DeviceAuth** — `DeviceSignature` (COSE_Sign1) first; `DeviceMac` (ECDH key-agreement) is a
  follow-on hook variant (documented).

**Invariants**: no holder private key, no sole-control secret, no crypto in a browser (IV); `signingInput`
is deterministic and exposes `aud`/`nonce` for host-side policy inspection (a blind-signing trust boundary,
like the CSC flow — RCA-documented).

## Issuance (OpenID4VCI) — configurable issuer backend, gated

```
IssuerBackend.kind = Reference | Cleverbase | None
obtain(offer, holderCtx, issuerBackend) -> Attestation   // OpenID4VCI; uses the signer-hook for PoP
```

- `kind=None` (default) → the issuance path is **skipped** (reported skipped, never failed — FR-008); the
  verification suite (US1) runs unaffected.
- `kind=Reference` → the EU `eudi-srv-pid-issuer` test double (issues SD-JWT VC + mso_mdoc) — exercises the
  flow without any Cleverbase API.
- `kind=Cleverbase` → a future drop-in when Cleverbase ships an EUDI issuer API — enabled by **configuration
  only**, no rework of verification or the holder flow (SC-005).

## Presentation (OpenID4VP, holder side)

```
present(heldAttestation, request, holderCtx, disclose: subset) -> vp_token
```

Builds a selectively-disclosed presentation bound to the verifier's request (nonce/audience via the
signer-hook); the produced `vp_token` MUST verify under `openid4vp-verifier.md` (round-trip).

## Tests (must fail first / gated)

- Against the **reference issuer** (test double): `obtain` yields a conformant attestation that verifies
  under `verifier.md`; `present` produces a vp_token the verifier accepts. With `kind=None`: the issuance
  test **skips** cleanly and the verification suite still passes. The signer-hook: a stub HSM signs the
  built `signingInput`; assert the SDK never accesses a private key and exposes `aud`/`nonce`.
</content>
