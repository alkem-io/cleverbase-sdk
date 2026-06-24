# Research: ECDSA P-256 validation parity + live Cleverbase-account signing

Phase 0 output. Each decision is grounded in a read of the actual codebase (file:line cited) — there were
no open `NEEDS CLARIFICATION` markers entering planning (the spec resolved all four via `/speckit-clarify`).

## D1 — The core needs no changes; the gap is test/validation coverage

**Decision**: Make **no change to `cleverbase-core`**. Close the ECDSA gap entirely in fixtures, the mock
upstream, the E2E harness, and `independent_validation.rs`.

**Rationale**: The core already produces and **self-verifies** a correct ECDSA P-256 signature end-to-end.
`KeyAlgo` (`csc.rs:36-44`) is detected once from the credential cert OIDs (`key_algo_from_oids`,
`csc.rs:136-148`), stored on the session (`session.rs:68`), and threaded as a parameter. `signAlgo` is set
to `ecdsa-with-SHA256` (`signing/mod.rs:674`); `assemble_signed_data` DER-encodes the raw r‖s and sets the
ECDSA signature-algorithm (`cms.rs:155-179`); the core then cryptographically verifies its own ECDSA
signature before reporting `Signed` (`cms.rs:337-366`, called at `signing/mod.rs:721`). ECDSA is asserted
with real signatures at the `cms.rs` unit level (`ecdsa_signed_data_assembles_and_verifies`,
`ecdsa_raw_signature_is_normalized_to_der`). The only thing missing is a **full-flow, independently
validated** ECDSA run. Touching the core would violate Principle VIII (out-of-scope).

**Alternatives considered**: Refactoring the core's `match key_algo` sites — **rejected**: there is no
copy-paste there; the two branch points (signature-algorithm OID at `cms.rs:169-173`; raw→DER at
`cms.rs:176-179`; verify primitive at `cms.rs:343-364`) are inherently per-algorithm (different
curves/schemes/crates) and already isolated to the minimum FR-004 permits.

## D2 — DRY seam: signer algorithm = a fixture profile keyed by the routed CSC base

**Decision**: Make the **mock upstream hold both signer keys** and select per **routed CSC base path**
(`/csc/v1` → RSA signer, `/csc/v2` → EC signer). Introduce one small `signer` value (loaded key + cert +
`algo` OID + a `sign(tbs) []byte` closure) and a per-route map. `handleSignHash` dispatches on the route's
signer instead of the hardcoded `s.rsaKey`.

**Rationale**: Today RSA is hardcoded in 9 places outside the (already-parametric) core — the single
`rsaKey` field and `rsa.SignPKCS1v15` call (`mock/server.go:43-51,58-69,200`), the `{{signer_rsa_cert_b64}}`
substitution and RSA `algo` OID in the shared `credentials_info.json`, the `CscAPI:"v1_rsa"` literal in the
E2E (`credfree_test.go:65`), and the RSA assertions in `server_test.go`. A per-route `signer` is the single
switch point — one new type, one map, **zero** copy-pasted sign logic — and keeps the algorithm advertised
in `credentials/info` and the bytes returned by `signHash` derived from **one** source so they cannot drift
(the exact DRY requirement of FR-004). The ECDSA signature is returned as raw `r‖s`, which the core's
`ecdsa_signature_to_der` (`cms.rs:134-151`) normalizes — so this exercises the real CSC-v2 wire form.

**Alternatives considered**: Decoding the `signAlgo` OID from each `signHash` body to pick the key —
**rejected** as more complex than the route-keyed map and not needed (v1/v2 already separate the flows);
duplicating the mock into an RSA mock + an EC mock — **rejected** (parallel re-implementation, violates DRY).

## D3 — credential-free E2E and `independent_validation.rs` become algorithm tables

**Decision**: Parametrize both independent validators by `KeyAlgo`/`CscAPI`:
- E2E (`credfree_test.go`): run `TestCredentialFree{BB,BT}` as a table over `{v1_rsa, v2_ecdsa}`; **reuse
  `validateCMS`/`assertTimestampToken` unchanged** (`openssl cms -verify` is algorithm-agnostic).
- Core (`independent_validation.rs`): parametrize `produce_signed_pdf` / `drive_bt_to_timestamp` /
  `upstream_fixture` over the algorithm — for ECDSA, simulate `signHash` with `p256::ecdsa::SigningKey`
  returning raw `r‖s`, inject the EC cert + ECDSA `algo` OID into the `credentials_info` variant, and reuse
  the existing `openssl cms -verify` + `openssl_timestamp` paths unchanged.

**Rationale**: The EC fixtures already exist and chain to the same CA (`signer-ec.*`, verified `openssl
verify` OK), so only the **producer + fixture** layers need the algorithm parameter; the verifier layers
are already algorithm-agnostic. A table avoids RSA→ECDSA copy-paste twins (FR-004).

**Alternatives considered**: A second EC-only test file — **rejected** (duplication).

## D4 — Reproducible PKI generation (`tests/fixtures/pki/gen.sh`)

**Decision**: Add `tests/fixtures/pki/gen.sh` that deterministically regenerates `ca.*`, `signer-rsa.*`,
`signer-ec.*`, `tsa.*` with the exact filenames the Go (`os.ReadFile`) and Rust (`include_bytes!`)
consumers already expect, plus the per-algorithm `credentials_info` variants.

**Rationale**: Research found **no generation script exists** — the PKI was committed ad-hoc in PR #1.
Wiring the EC-signing path and adding an EC `credentials_info` variant is the moment to make the fixtures
reproducible (Principle II/VIII; the constitution values reproducibility). Scoped to exactly the fixtures
this feature relies on — not a drive-by.

**Alternatives considered**: Continuing to hand-maintain committed fixtures — **rejected** (not
reproducible; can't rotate or extend the algorithm set cleanly).

## D5 — Pluggable `Authorizer` lives in the E2E harness, not the SDK/flow

**Decision**: Add a Go `Authorizer` interface to the E2E harness with one method that **takes the authorize
URL + state and returns `(code, state)`**, replacing the mock's auto-following `followRedirect`
(`credfree_test.go:113-127`). Two impls: **Interactive** (default — surface the authorize URL, capture the
redirect callback, resume) and **Headless** (opt-in — drive an automatable Cleverbase test-credential
approval). Selected by config (`REFSVC_LIVE_AUTHORIZER=interactive|headless`).

**Rationale**: The driving loop (`runFlow`) is already authorizer-agnostic — it only needs `code,state` to
call `/v1/sign/complete`. So the pluggable seam is purely at the test-harness level: **no core or
`flow.go`/service change** (Principle III, FR-013). The interactive mode works the day real credentials
arrive; headless drops in later without reworking the loop.

**Alternatives considered**: Automating the human approval inside the SDK — **rejected** (would breach the
QTSP sole-control model, Principle IV / Security & Compliance) and is unnecessary.

## D6 — Live gating, config, and trust anchor

**Decision**: Reuse the existing `os.Getenv("REFSVC_*")` + `t.Skip`-when-absent gate (already in
`live_test.go:26-31` and `config.validateLive`). Add two missing knobs: the **authorizer mode**
(`REFSVC_LIVE_AUTHORIZER`) and a **real trust anchor** (`REFSVC_LIVE_CA_BUNDLE`, the real Cleverbase issuer
chain PEM — or taken from the `/credentials/info` `certificates:"chain"` the core already requests). The
live verification reuses `validateCMS` with the **real** CA instead of the synthetic
`tests/fixtures/pki/ca.cert.der`. Live targets the **acceptance** environment by default
(`REFSVC_ENV=acceptance`); all secrets are CI-secret-only and never committed/logged (FR-010).

**Rationale**: Minimal new surface; the skip-when-absent pattern keeps the credential-free pipeline
green and the live job out of the default path (FR-009).

**Alternatives considered**: Hardcoding the real CA — **rejected** (chains rotate; FR-008 wants the real
issuer chain, configurable).

## D7 — Opt-in profile-conformance gate: pyHanko primary, EU DSS for the baseline-level assertion

**Decision**: Implement the opt-in PAdES/eIDAS profile gate (FR-014) as `scripts/validate-pades.sh` driving
**pyHanko (`pyhanko adesverify`)** as the primary AdES validator (signature + chain + timestamp, RSA and
ECDSA P-256), **plus EU DSS** specifically for the **structural baseline-level** assertion
(`SignatureFormat == PAdES-BASELINE-B / -T`). Run as an **off-by-default** CI job
(`profile-conformance.yml`), separate from the always-on `openssl` check; **never linked into the SDK**.

**Rationale**: pyHanko is MIT, pip-installable, CI-trivial, and the constitution's named "lighter
alternative" (Principle V) — but its CLI **explicitly does not** assert structural PAdES-profile-level
conformance. EU DSS **does** emit the `PAdES-BASELINE-B/-T` level in its validation report, which is exactly
FR-014's literal wording ("meets the ETSI EN 319 142 PAdES B-B/B-T profile"). Using pyHanko for the AdES
validation and DSS for the baseline-level check satisfies FR-014 fully while keeping the everyday gate
lightweight. LGPL-2.1 (DSS) is fine for a separately-invoked, unmodified CI tool.

**Alternatives considered**: pyHanko only — **rejected** (cannot assert the baseline *level*, FR-014's
literal requirement); EU DSS only — **rejected** as the everyday gate (JVM/Maven heavier; the constitution
prefers the lighter default); any **hosted** validation service — **rejected** (Principle IV/V: private
documents must never leave the operator's infrastructure).

## D8 — Independent verification stays OpenSSL as the always-on bar

**Decision**: Keep `openssl cms -verify` (+ the RFC 3161 timestamp grep + PAdES ByteRange/Contents
structural checks) as the **always-on** validation bar for both algorithms and both paths (synthetic +
live); the pyHanko/DSS profile gate (D7) is strictly additional and opt-in.

**Rationale**: This is the established RSA bar (`credfree_test.go:172-223`, `independent_validation.rs`),
algorithm-agnostic, zero-dependency, and already green — extending it to ECDSA is free. Matches the spec's
resolved "both: always-on crypto + opt-in profile gate" clarification.
</content>
