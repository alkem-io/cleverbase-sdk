# Contract: attestation verifier (always-on bar)

The core verification entry point. Lives in `cleverbase-attestation` (Rust core), surfaced over the
`cleverbase-ffi` C-ABI (CBOR in/out) and the bindings. Sans-IO: all inputs (the presented credential, the
configured trust anchors, the issued request) are passed in; no network in the core (trust lists are
fetched/cached by a host-driven step, then passed as anchors).

## Operation

```
verify(presentation: bytes, policy: VerificationPolicy, anchors: TrustAnchors, request?: PresentationRequest)
  -> VerificationResult
```

## Always-on checks (FR-003, FR-005 — every one MUST pass for VALID)

1. **Format** detected (SD-JWT VC or ISO mdoc); unsupported → INVALID `unsupported_format`.
2. **Issuer signature** verifies (JOSE `ES256…` for SD-JWT VC; COSE_Sign1 IssuerAuth for mdoc) — via the
   SDK's existing RustCrypto (no hand-rolled crypto).
3. **Issuer trust** — the issuer is present on the configured trust anchor for its role/format (EU
   LOTL/Trusted List / IACA root / per-role list). Absent/expired/revoked TL entry → INVALID `untrusted_issuer`.
4. **Validity period** in range at the relevant time (SD-JWT VC `nbf`/`exp`; mdoc MSO `validityInfo`).
5. **Revocation/status** — checked per the credential's status mechanism; **unreachable → fail-closed by
   default** (policy-configurable) → INVALID `status_unavailable` (never silent VALID).
6. **Holder binding** verifies (SD-JWT VC KB-JWT over `aud`/`nonce`/`sd_hash`; mdoc DeviceAuth).
7. **Selective-disclosure integrity** — each disclosed attribute matches an issuer-signed digest
   (SD-JWT disclosure digest; mdoc `valueDigests`); undisclosed attributes neither revealed nor required.
8. **Request binding** (when `request` given) — see `openid4vp-verifier.md` (nonce + audience).

## Result

`VerificationResult { valid, disclosedAttributes, trustStatus, qualifiedStatus?, reasons[] }`. INVALID
always carries a **specific machine-readable reason** (FR-005/SC-002). `qualifiedStatus` is populated only
when the opt-in gate (`qualified-status-gate.md`) ran.

## Invariants

- **No false-accept** (SC-002): any failed check ⇒ `valid=false` + reason.
- **No hand-rolled crypto** (IV): signatures/hashes go through the existing vetted crates + `coset`.
- **Offline-capable** (FR-004): runs with the passed anchors + credential alone; no Cleverbase API.

## Tests (must fail first)

- Per format: a conformant VALID case (disclosed attributes returned); and INVALID cases for tamper,
  expired, revoked, wrong-issuer, untrusted, broken-holder-binding, status-unreachable (fail-closed),
  unsupported-format — each asserting the specific reason. Cross-checked against an independent
  (Kotlin/TS) reference verifier (Principle VI).
</content>
