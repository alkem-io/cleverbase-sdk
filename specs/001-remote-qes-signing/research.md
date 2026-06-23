# Phase 0 Research & Decisions: Remote Qualified Signing (PAdES B-B / B-T)

All findings below are grounded in prior investigation of Cleverbase's live services and the
relevant standards (recorded in project memory: `cleverbase-signing-surface`,
`sdk-architecture-decisions`). Each item: **Decision / Rationale / Alternatives**.

## 1. Core architecture — sans-IO state machine

**Decision**: The Rust core is **sans-IO**: a pure, serializable state machine that performs all
crypto and PDF work in-process and *emits effects* — `HttpEffect` (a request the host must perform)
and `RedirectEffect` (a URL to send the signer's browser to) — then consumes the results to advance.
Network, persistence, clock, and entropy are host-provided inputs.

**Rationale**: Keeps the core free of an async runtime/HTTP client → it compiles cleanly to WASM,
is deterministic, and is **contract-testable by replaying recorded Cleverbase HTTP fixtures**
(Principle VI). Concurrency becomes the binding's native concern (asyncio / event-loop /
goroutines), so each binding stays idiomatic. Matches Cleverbase's own `scal3` "pure, stateless"
design and our stateless-SDK decision.

**Alternatives**: (a) Core owns HTTP via `reqwest` + injected transport trait — duplicates an async
story across native + WASM and drags a runtime into the core; rejected. (b) Per-language native
HTTP orchestration — violates "no duplicated protocol logic" (Principle III); rejected.

## 2. Binding mechanisms & the one logical API

**Decision**: One typed Rust API in `cleverbase-core` is the single source of truth. **PyO3** and
**napi-rs** wrap it directly into idiomatic Python/TS types. **Go** consumes a thin C-ABI shim
(`cleverbase-ffi`, `cdylib`/`staticlib`) using **CBOR**-encoded request/response of the same types.
The **WASM** build (`wasm-bindgen`) exposes the same CBOR surface for the frontend helper.

**Rationale**: Idiomatic types where the FFI permits (Python/Node), a stable coarse CBOR boundary
where it doesn't (Go C-ABI, WASM) — all mapping to the same core logic (Principle III, VII). Rust is
the donor because it emits a clean C-ABI with no managed runtime (vs Go `c-shared`).

**Alternatives**: Uniform CBOR for all four (simpler, but worse Python/Node DX) — rejected in favor
of idiomatic typing where free.

## 3. Cleverbase signing protocol (the effects the core drives)

**Decision**: Target **CSC API v1** (production, RSA) as the primary path and **CSC v2** (ECDSA
P-256) behind configuration; the core handles both signature algorithms. The flow is OAuth 2.0
Authorization Code with **two authorizations**: (1) `scope=service` → Bearer; discover credentials
(`credentials/list`, `credentials/info`); (2) `scope=credential` with the **document hash bound
into consent** → SAD; then `signatures/signHash` returns the raw signature value. Completion is
signalled by the **OAuth redirect back to the integrator's `redirect_uri`** — there is **no
webhook** (verified). SHA-256 only.

**Rationale**: This is the verified production surface; binding the hash into credential
authorization gives WYSIWYS sole-control. Redirect-return drives the `RedirectEffect`/handle model.

**Alternatives**: signDoc / server-side container — **does not exist** on Cleverbase (verified);
not an option.

## 4. PAdES B-B container assembly

**Decision**: Build the PAdES container in-core with `lopdf` (incremental update: add an
`/AcroForm` signature field + signature dictionary with a `/ByteRange` and a zero-filled
`/Contents` placeholder), compute the SHA-256 over the ByteRange, obtain the raw signature from
Cleverbase, wrap it as a CMS/PKCS#7 `SignedData` (detached, `signing-certificate-v2` attribute,
signer cert chain from `credentials/info`) using RustCrypto `cms`, and splice it into `/Contents`.
Adding a signature uses incremental update so **existing signatures stay valid** (FR-010).

**Rationale**: Matches PAdES (ETSI EN 319 142-1) baseline B-B; all required crates exist in Rust
and are pure. Cleverbase returns only raw signature bytes, so we own assembly (Principle V).

**Alternatives**: pyHanko/DSS for assembly — would force a non-Rust runtime into the *signing* path;
rejected for B-B/B-T (reserved only for later formal *validation*).

## 5. B-T timestamping — external qualified TSA

**Decision**: B-T embeds a **signature timestamp** (`signature-time-stamp` unsigned attribute) built
via **RFC 3161**: the core produces a `TimeStampReq` over the signature value as an `HttpEffect` to a
**configurable external qualified TSA**; the returned `TimeStampToken` is embedded into the CMS.
A requested level is never silently downgraded (FR-005).

**Rationale**: Cleverbase provides **no timestamp service and no qualified TSA on the EU Trusted
List** (verified) — so a third-party qualified TSA is a required, configurable dependency
(procurement lead-time, flagged in spec). RFC 3161 client logic is modest and stays sans-IO (emit
request as an effect).

**Alternatives**: Self-issued timestamp — not qualified, defeats B-T; rejected.

## 6. Visible appearance + PDF/A preservation

**Decision**: Invisible by default; an optional per-request **Signature Appearance** (page, rect,
reason, location, signer name, time) renders a signature widget in the incremental update. When the
input is **PDF/A**, preserve conformance: embed required fonts in any appearance, avoid
conformance-breaking constructs, and **verify output with veraPDF in CI**; if conformance cannot be
preserved, **fail rather than emit a non-conformant file** (FR-016, FR-017).

**Rationale**: Legal/archival documents are commonly PDF/A; a signature that breaks PDF/A is a real
defect. Incremental-update signing preserves PDF/A when done to spec.

**Alternatives**: Always-PDF/A (lossy conversion) / no-PDF/A-guarantee — both rejected per
clarification.

## 7. Signer-identity matching key (resolves deferred clarification)

**Decision**: The **Expected Signer Identity** is matched against the **subject of the signer's
qualified certificate** returned by `credentials/info` — primarily the subject `serialNumber`
(the stable natural-person identifier in the ETSI qualified-cert profile), with `commonName` as a
human-readable cross-check. Integrators that previously identified the signer via OIDC may instead
supply the stable Cleverbase subject (`sub`) to match. The **full subject** is recorded in the
Signing Evidence Record. Verification is on by default; a mismatch fails with a distinct outcome
(FR-014).

**Rationale**: In a pure signing flow the certificate subject is always available and is the
legally-binding signer identity; `serialNumber` is the stable per-person key in qualified certs.
Deferred from clarify precisely because it depends on the cert profile — now pinned.

**Alternatives**: name+DOB matching (not always present in the cert, brittle) — **deferred to a
later phase**, not shipped in Phase 1 (avoids an untested match mode).

## 8. Signing Session Handle (stateless resumability)

**Decision**: An opaque, **serializable** handle holds the in-flight state: phase, request id,
document hash, bound credential id, the pending effect, and any short-lived authorization material
(service Bearer / SAD). It is **versioned** (schema tag) and round-trips across the FFI as CBOR.
The integrator persists it; the SDK stores nothing. Finalization after a backend restart works from
the handle alone, provided the authorization has not expired (FR-013).

**Rationale**: Realizes the stateless-SDK decision and restart-resumability edge case. Because the
handle may carry short-lived secrets, the contract requires **secure server-side storage** (and the
handle should be encrypted at rest by the integrator).

**Alternatives**: SDK-managed store — rejected at clarification (hidden state, scaling concerns).

## 9. Retry / timeout / idempotency (resolves deferred clarification)

**Decision**: Because the core is sans-IO, **retries are host-driven**: every `HttpEffect` is safe
to re-attempt on transient transport failure (the core does not advance until it receives a
response). The core surfaces **terminal** states distinctly: `Declined`, `AuthorizationExpired`
(SAD/credential-auth window lapsed), `CredentialUnavailable`, `IdentityMismatch`, `TimestampFailed`.
Wall-clock timeouts for awaiting the signer are a host policy, not core logic.

**Rationale**: Keeps correctness in the deterministic core and operational policy in the host;
aligns with the edge cases in the spec.

## 10. Concurrency & performance (resolves deferred clarification)

**Decision**: The core is `Send`/thread-safe and holds no shared mutable state ⇒ **unbounded
concurrent sessions**, limited only by the host. SDK-overhead targets: container assembly + embed
**< 200 ms** for ≤ 5 MB PDFs; verification **< 100 ms** (test path). No latency target on the
human-authorization legs (out of our control).

**Rationale**: Statelessness makes horizontal scaling trivial; targets bound only what the SDK
controls (technology-agnostic SC-style overhead).

## 11. Why Rust is sufficient for B-B/B-T (and where it stops)

**Decision**: B-B and B-T are fully implementable in pure Rust (`lopdf` + RustCrypto `cms`/`x509` +
RFC 3161). **B-LT/B-LTA + formal eIDAS validation are explicitly later phases**; the pipeline
exposes `RevocationSource`, archive-timestamp, and `ValidationBackend` seams now but does not
implement them here. Formal validation, when added, delegates to a self-hosted **EU DSS** (or
pyHanko) sidecar — not reimplemented in Rust.

**Rationale**: Rust has no pyHanko/DSS-equivalent for LTV/validation; confining Phase 1 to B-B/B-T
keeps it all-Rust and complete while honoring the architecture's seams (Principle V).

## 12. Test & validation strategy

**Decision**: (a) **Fixture-replay contract tests** — record real Cleverbase CSC/OIDC HTTP exchanges
(acceptance env + public stub creds) and replay them into the sans-IO core; (b) **live acceptance**
smoke tests against `connect.acc.cleverbase.com`; (c) **independent validation** of every produced
signature with **EU DSS** (PAdES/QES + timestamp) and **veraPDF** (PDF/A) in CI; (d) `proptest` over
PDF/byte-range edge cases; (e) coverage gate **≥ 95%** across core + bindings.

**Rationale**: Sans-IO makes (a) deterministic and offline; (c) satisfies Principle VI's
"validate against independent reference tools."

---

## Resolved unknowns

All NEEDS-CLARIFICATION/deferred items are now resolved: identity-matching key (§7),
retry/timeout/idempotency (§9), concurrency/perf (§10), core IO model (§1), and the binding/wire
strategy (§2). No open unknowns remain for Phase 1.
