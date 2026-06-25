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
3. **Issuer trust** — the issuer's signing leaf **chain-validates** to a configured trust anchor for its
   role/format (EU LOTL/Trusted List / IACA root / per-role list), at the relevant time. The anchor MAY be
   the issuing CA / IACA root (the EUDI chain-to-root model — a credential is trusted when its leaf chains
   to a passed root) or a directly-pinned leaf; in **both** cases the leaf's validity window is enforced, so
   an expired/withdrawn issuer leaf → INVALID `untrusted_issuer`. The C-ABI / binding path uses this same
   chain-validating rule (`trust::chain::verify_chain`) over the host-passed anchors — it does **not** do
   exact-leaf-equality (which would reject every credential under a CA/root and accept an expired pinned
   leaf). Absent/expired/revoked anchor → INVALID `untrusted_issuer`.
4. **Validity period** in range at the relevant time (SD-JWT VC `nbf`/`exp`; mdoc MSO `validityInfo`).
5. **Revocation/status** — checked per the credential's status mechanism; **unreachable → fail-closed by
   default** (policy-configurable) → INVALID `status_unavailable` (never silent VALID).
6. **Holder binding** verifies (SD-JWT VC KB-JWT over `aud`/`nonce`/`sd_hash`; mdoc DeviceAuth).
7. **Selective-disclosure integrity** — each disclosed attribute matches an issuer-signed digest
   (SD-JWT disclosure digest; mdoc `valueDigests`); undisclosed attributes neither revealed nor required.
8. **Request binding** (when `request` given) — see `openid4vp-verifier.md` (nonce + audience).

## Result

`VerificationResult { valid, disclosedAttributes, trustStatus, qualifiedStatus?, reasons[] }`. INVALID
always carries a **specific machine-readable reason** (FR-005/SC-002).

**`disclosedAttributes` shape (per format).** SD-JWT VC returns the disclosed claims at their position in
the credential structure (RFC 9901 §7.1 nesting). **mdoc returns disclosed attributes GROUPED BY
NAMESPACE**: each top-level key is an ISO/IEC 18013-5 namespace, its value a map of that namespace's
`{ elementIdentifier: elementValue }` — e.g. `{ "org.iso.18013.5.1": { "given_name": …, … }, … }`. mdoc
`elementIdentifier`s are unique only **within** a namespace, so a valid presentation MAY carry the same
identifier (e.g. `given_name`) in two namespaces (or two documents) with different values; namespace
grouping keeps those distinct (never a false `disclosure_integrity` reject) and preserves namespace
provenance. A genuine conflict — the **same `(namespace, elementIdentifier)`** disclosed twice with
**different** values (across namespaces within a document, or across documents) — is rejected as
`disclosure_integrity`; an identical re-disclosure merges cleanly. The CBOR/C-ABI wire shape is unchanged
(`disclosedAttributes` is still `{ string → AttributeValue }`, the namespace map carried as an
`AttributeValue::Map`), so no schema bump.

`qualifiedStatus` is populated only
when the opt-in gate (`qualified-status-gate.md`) ran **and the credential is VALID** — it is only
meaningful for a VALID credential (the gate matches the credential's *claimed* signing cert, which only a
VALID verdict has signature-verified + trust-anchored), so on an INVALID credential `qualifiedStatus` is
absent (never a `Qualified` read off an unverified claimed cert).

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
