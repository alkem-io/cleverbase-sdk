# EUDI attestation (`cleverbase-attestation`)

The `cleverbase-attestation` crate is the **sans-IO EUDI attestation core** of the SDK: it verifies
presented EUDI credentials in both mandated formats — **SD-JWT VC** (RFC 9901 / draft-16) and
**ISO/IEC 18013-5 mdoc** — against EU trust anchors, and (forward-looking, gated) drives OpenID4VCI
issuance and OpenID4VP holder presentation via the integrator's signer-hook. Like `cleverbase-core`
it is **pure-Rust / WASM-able** (no JVM, no OpenSSL-FFI) and performs **no network I/O** in the core
(trust lists and status are fetched by host-driven steps and passed in).

The generated Rust API reference is at [`api/rust/cleverbase_attestation.md`](api/rust/cleverbase_attestation.md);
the spec is under [`specs/004-attestation-and-verification/`](../specs/004-attestation-and-verification/),
and the standards-conformance / version-pinning audit is in
[`standards-conformance.md`](../specs/004-attestation-and-verification/standards-conformance.md).

## The honest Cleverbase reality (today)

**Cleverbase exposes no EUDI attestation issuer API today.** Its current production surface is
**OIDC identity attributes** (including `com.cleverbase.proof`), plus a roadmap / pilots for EUDI
wallet capabilities. So this feature does **not** claim Cleverbase issues EUDI credentials today, and
it does not depend on Cleverbase to do so:

- **Verification is the shipped, always-on capability** and is **standards-based and
  Cleverbase-independent**: it verifies any conformant SD-JWT VC or mdoc credential against configured
  EU trust anchors, with no Cleverbase API and no live issuance. It works for a future
  Cleverbase-issued credential exactly as for any other conformant one.
- **Issuance is gated and forward-looking.** The OpenID4VCI `obtain` flow is built behind a
  configurable `IssuerBackend` whose `kind` is `None` (the default — issuance is **skipped**, never
  failed), `Reference` (the EU `eudi-srv-pid-issuer` test double), or `Cleverbase` (a **future**
  issuer API). The `Cleverbase` backend is the **future-Cleverbase seam**: when/if Cleverbase ships an
  EUDI issuer API, it drops in by configuration alone (SC-005) — no SDK code change. Until then the
  default `None` backend is the honest behaviour: the issuance path skips cleanly.
- **The SDK is not a wallet** and never holds a holder private key. The holder proof is signed
  out-of-process via the integrator's signer-hook (their wallet/HSM/KMS); see below.

This is the deliberate seam: verification stands alone today; issuance is architected so a future
Cleverbase issuer is a configuration change, not a rewrite.

## API surface

### Verification (always-on, offline)

- **`verify(presentation, policy, anchors, ctx, request?) -> VerificationResult`** (`crate::verify`):
  the always-on entry point. Detects the format, runs the per-format bar (issuer signature + trust +
  validity + selective-disclosure integrity + holder binding) and, when a `request` is supplied, the
  OpenID4VP nonce/audience binding. Returns a `VerificationResult { valid, disclosed_attributes,
  trust_status, qualified_status?, reasons[] }`; a failure carries a specific `ReasonCode` (a closed
  enum — never a false-accept).
- **`openid4vp::build_request(nonce_source, dcql, audience, response_uri)`** and
  **`openid4vp::verify_response(vp_token, request, …)`**: the full OpenID4VP verifier — build a DCQL
  request with a fresh nonce + audience (`client_id`) + the verifier's `response_uri` (the 4th element
  of the mdoc handover, OpenID4VP 1.0 §B.2.6), and verify a returned `vp_token` is bound to it.
- **Trust** (`crate::trust`): the `TrustAnchorSource` trait (`resolve` / host-driven `refresh`) with
  the `NativeTrustEngine` production implementation (TS 119 612 LOTL / national TL parse +
  authenticate + cache; fail-closed on unreachable/stale lists by default) and a configured
  test-anchor for the offline suite. `trust::chain::verify_chain` is the single X.509 chain primitive.
- **Status** (`crate::status`): revocation / status-list / CRL check with the fail-closed reachability
  policy, resolved by the host and passed into `verify`.
- **Qualified gate** (`crate::qualified`, opt-in): `qualified_status(...)` determines eIDAS
  qualified-status (TS 119 615 v1.4.1 cl. 4.12) — **off by default** via
  `VerifyContext::qualified_gate`; enabling/disabling it never changes the always-on verdict (SC-007),
  and absent/ambiguous data yields `Indeterminate`, never a false "qualified". Experimental,
  version-pinned.

### Issuance / holding / presentation (gated, US2)

- **`issuance::begin_obtain(...)` / `resume_obtain(...)`**: the sans-IO OpenID4VCI `obtain` state
  machine (mirrors the signing core's `begin`/`resume` + effect shape). Returns an `ObtainStep`
  (`PerformHttp` / `Sign` / `Skipped` / `Obtained` / `Failed`); the host performs each effect and
  resumes. `kind = None` → `Skipped`.
- **`issuance::present(...)`**: holder OpenID4VP presentation (selective disclosure, bound to the
  verifier's request) producing a `vp_token` the always-on verifier accepts.
- **`issuance::signer::Signer`** (the signer-hook): the integrator supplies the holder **public** key
  and a `sign(handle, &SigningInput)` callback. The SDK builds the exact, deterministic `SigningInput`
  for each ceremony (OpenID4VCI PoP-JWT / SD-JWT VC KB-JWT / mdoc `DeviceSignature`), exposes its
  `aud`/`nonce` for host policy, and splices the host-returned signature back. The **SDK never sees a
  private key** (FR-009) — this directly reuses the spec-001 remote-signing pattern.

### C-ABI + bindings

The crate is surfaced over the existing `cleverbase-ffi` C-ABI with the same CBOR-in / CBOR-out +
`cleverbase_free` discipline as the signing core:

- `cleverbase_attestation_verify` — the always-on verifier seam.
- `cleverbase_attestation_issuance` — the gated `obtain` / `present` seam.

The `bindings/{go,python,node}` shims wrap these the same way they wrap the signing entry points
(thin shims; all protocol logic stays in the Rust core — Principle III).

## Testing it

Everything below is **offline with zero external dependencies** (the trust lists / status / issuer are
sans-IO host seams fed by in-crate fixtures). See
[`quickstart.md`](../specs/004-attestation-and-verification/quickstart.md) for the full scenarios.

```sh
cargo test -p cleverbase-attestation            # the always-on suite (both formats, all negatives)
cargo test -p cleverbase-attestation qualified::  # the opt-in qualified gate (self-skips w/o fixtures)
```

The independent cross-check (a different-language EU reference verifier) and the live issuance
(against the EU reference issuer) are **opt-in** workflows that **self-skip** when their external
dependency is absent:

- `.github/workflows/attestation-crosscheck.yml` — runs `scripts/crosscheck-attestation.sh` over
  SDK-produced artifacts (FR-013); self-skips without the Kotlin/TS reference verifier.
- `.github/workflows/attestation-live-issuance.yml` — runs the gated live-issuance test against the
  EU `eudi-srv-pid-issuer`; self-skips when `ATT_ISSUER` is unset.
