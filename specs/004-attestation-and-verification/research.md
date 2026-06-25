# Research: EUDI attestation — verification now, issuance forward-looking

Phase 0 output. Each decision is grounded in web/ecosystem/standards research (June 2026); the spec's
clarifications resolved scope (both formats; always-on bar + opt-in qualified; full verifier; gated
issuance). Sources cited inline.

## D1 — No hand-rolled crypto: EUDI's baseline is a subset of what the SDK already owns

**Decision**: Reuse the SDK's existing crates for all attestation crypto — `p256`/`ecdsa` (ES256/384/512),
`rsa` (RSA-PSS for issuer/trust-list certs), `sha2`, `ciborium` (CBOR), and the `der`/`spki`/`x509-cert`/
`cms` X.509 stack. Add only **`coset`** (Google, Apache-2.0 — COSE_Sign1/Mac0 *codec*, not crypto) and an
**in-house compact-JWS** verification path (the SDK has no JOSE crate; route the digest to existing
RustCrypto rather than pull `josekit`/OpenSSL-FFI). `ed25519-dalek` only if a Member-State profile needs
EdDSA — deferrable (outside the EUDI mandatory baseline).

**Rationale**: EUDI fixes the baseline to **ES256 (ECDSA/P-256/SHA-256)** for both SD-JWT VC (JOSE) and
mdoc (COSE), with ES384/512 + RSA-PSS allowed (HAIP 1.0 §7; ECCG Agreed Cryptographic Mechanisms v2; ARF
Annex 2). All of this maps onto crates already vendored — so Principle IV ("no hand-rolling where a vetted
library exists") is satisfied with near-zero new crypto surface.

**Alternatives**: `josekit` for JOSE — rejected (OpenSSL-FFI, breaks the pure-Rust/WASM posture).

## D2 — SD-JWT VC verification: `sd-jwt-payload` for format, in-house issuer-JWS + vct

**Decision**: Build SD-JWT VC verification on **`sd-jwt-payload` (IOTA, Apache-2.0)** for the disclosure /
KB-JWT *format* layer (bring-your-own-crypto, sans-IO), with the **issuer-JWS verification** and the
**`vct` type-metadata** layer built in-house against **RFC 9901 + draft-ietf-oauth-sd-jwt-vc-16**.

**Rationale**: No permissive crate covers all four required pieces (disclosure digests + KB-JWT holder
verify + issuer JWS + `vct`); `vct` type-metadata is greenfield everywhere. `sd-jwt-payload` is the
cleanest sans-IO, Apache-2.0, RFC-9901-aligned format library and lets crypto route through the SDK's
vetted crates.

**Alternatives**: `ssi-sd-jwt` (SpruceID, Apache-2.0) — strong fallback but pulls the large `ssi`/JSON-LD
graph; keep as fallback. `bh-sd-jwt` (TBTL) — **AGPL-3.0, blocked** for a redistributable SDK; semantics
reference only. `sd-jwt-rs` (OWF) — pre-RFC/stale on crates.io; useful only as a fixture generator.

## D3 — mdoc verification: build in-house on `ciborium`+`coset` (the immature area)

**Decision**: Build a thin sans-IO ISO/IEC 18013-5 mdoc verifier on **`ciborium`** (already a dep) +
**`coset`** for CBOR/COSE, routing signatures through existing `p256`/`ecdsa`/`sha2` + the X.509 stack.
**Own** the two security-critical checks that the only Rust mdoc lib omits: recompute each disclosed
`IssuerSignedItem` tagged-CBOR digest and match the MSO `valueDigests`, and enforce MSO `validityInfo`
time bounds. Use SpruceID **`isomdl`** only as a data-model donor + a test oracle (its issuance module's
digest algorithm is the exact one to mirror; it ships Annex-D-style vectors).

**Rationale**: Rust mdoc verification is immature — `isomdl` (v0.2, pre-1.0) verifies IssuerAuth/DeviceAuth
+ x5chain but does **not** match `valueDigests` (selective-disclosure integrity) nor enforce `validityInfo`
— both mandatory (18013-5 §9). Adopting it as-is would push those exact checks onto us while inheriting a
0.2 dep + NFC/BLE transport surface we don't need. `ciborium`/`coset` are the mature ecosystem standard
(`coset` is encoding, not crypto).

**Alternatives**: Procivis `one-core` (Rust mdoc verify) — not on crates.io, heavyweight full-stack, wrong
for a sans-IO core. EU reference impl — Swift/Kotlin only, no Rust.

## D4 — OpenID4VP verifier: build the DCQL request + binding verify in-core

**Decision**: Build the verifier orchestration in the core — construct the OpenID4VP request with a **DCQL**
query + a fresh **nonce** + the **audience/client_id**, and verify the returned `vp_token` is cryptographic-
ally **bound** to that request (nonce echoed in the KB-JWT for SD-JWT VC / the mdoc SessionTranscript-
OID4VPHandover; audience = client_id). Use **`spruceid/openid4vp`** (pinned git) as a conformance oracle,
not a shipped dependency.

**Rationale**: **OpenID4VP 1.0 is Final (2025-07)** and uses **DCQL as the sole query mechanism**
(`presentation_definition`/Presentation-Exchange was removed) — build to DCQL, treat PE as optional legacy.
No production-ready, crates.io-published, SemVer-stable Rust OID4VP verifier exists (credible impls ship a
2023-era 0.1 while real DCQL code lives on git `main`). The binding logic is small, security-critical, and
the part the format verifiers don't provide — owning it makes replay/audience binding correct by
construction (FR-015) and is DRY.

**Alternatives**: impierce `openid4vc` (secondary reference); Procivis `one-core` (heavyweight, not
sans-IO); walt.id / EU reference verifier (Kotlin/JVM — usable only as cross-check oracles, D7).

## D5 — Trust anchoring: native Rust EU trust-list engine (the biggest build), per role/format

**Decision**: Build a **native Rust trust-list engine** (`quick-xml` + the existing X.509 stack) that
anchors issuer trust **per attestation role/format**: **QEAA** via the EU LOTL / national Trusted Lists
(ETSI TS 119 612, now v2.4.1/TLv6, enforced 29 Apr 2026); **PID Providers** via the Commission list under
eIDAS Art. 5a(18); **PuB-EAA** via the Art. 45f(3) list; **mdoc** via an **IACA root** trust anchor
(optionally a VICAL); plus the new **ETSI TS 119 602 "LoTE"** JSON/XML model. The trust-anchor source is a
**pluggable input** (FR-003: a configured test anchor for the offline suite; the real lists in production).
Run **EU DSS (Java) as a test-only parity oracle**, never a runtime/hosted dependency.

**Rationale**: There is **no production Rust crate** for TS 119 612/602/LOTL — this is a "fetch-signed-XML/
JSON + validate-the-chain yourself" task and the **biggest build risk** (load-bearing for the always-on bar
*and* the qualified gate). A native engine keeps the core pure-Rust/WASM-able and avoids dragging a JVM into
the shipped product (the same rationale Principle III gives for a Rust core over a Go/JVM one). DSS is the
canonical reference, so it's the natural cross-language parity oracle in tests (Principle VI).

**Alternatives**: EU DSS as a runtime sidecar — rejected for the shipped core (JVM runtime dep); kept as a
test oracle. OpenID-Federation trust (some EWC pilots) — not the ARF-mandated mechanism; would diverge from
conformance.

## D6 — Qualified-status determination: own logic (TS 119 615 cl.4.12), opt-in, experimental

**Decision**: Implement the opt-in eIDAS **qualified-status determination** as **native Rust logic**
over the same trust-list primitives (D5) — authenticate LOTL → select national TL → match the issuer's
service entry (service type `…/Svctype/EAA/Q`) → read `granted`/`withdrawn` status **at the relevant time**
→ conclude **Qualified / Not_Qualified / Indeterminate**. It is **opt-in** (off by default), **version-
pinned** to TS 119 615 v1.4.1, and returns honest **`Indeterminate`** where trust-list data is absent.

**Rationale**: **No reference engine implements QEAA qualified-status determination today** — EU DSS does it
only for signatures/seals/timestamps; the EUDI `eudi-srv-trust-validator` checks anchor *presence*, not the
algorithm — so there is nothing to wrap; it must be built. TS 119 615 added **clause 4.12 for QEAA in
v1.3.1 (Jan 2026)** (independently re-verified), but it is **pre-operational** (national TLs are only
beginning to carry `EAA/Q` entries post CIR (EU) 2025/1569). Making it opt-in + experimental + honest about
`Indeterminate` matches the spec-003 always-on-bar + opt-in-gate pattern and avoids overclaiming.

**Alternatives**: presence-only (skip 119 615) — fine as the default mode but can't deliver the opt-in
qualified verdict; DSS sidecar — doesn't compute QEAA (revisit if DSS ships cl.4.12).

## D7 — Independent cross-check + gated issuance doubles (Principle VI)

**Decision**: For the **independent reference verifier** (VI), cross-check the Rust verifier against a
**different-language EU reference** (Kotlin `eudi-lib-jvm-sdjwt-kt` / `eudi-srv-verifier-endpoint`, or a TS
`mdoc-ts`) in an opt-in CI job — **Rust-vs-Rust does not count as independent**. For the **gated issuance**
double, use the EU official **`eudi-srv-pid-issuer`** (Kotlin, Apache-2.0; docker-compose with Keycloak, so
the OAuth gate is self-contained) — it issues both SD-JWT VC and mso_mdoc. The **OpenID Foundation
conformance suite** (Java, self-hostable) is the long-term gold-standard counterparty.

**Rationale**: Principle VI requires produced/obtained artifacts checked against an *independent* validator;
the only independent EUDI verifiers/issuers are JVM/TS. All are "initial development — not for production"
and the Rust building blocks are pre-1.0, so use **at least two** independent references and pin versions.

**Alternatives**: walt.id / Animo Credo-TS / Sphereon — heavier alternates.

## D8 — Holder key custody: reuse the spec-001 signer-hook (not a wallet)

**Decision**: Use a sans-IO **signer-hook** model identical to the SDK's remote-signing pattern: the
integrator supplies (1) the holder **public** key (JWK for SD-JWT VC/OpenID4VCI, COSE_Key for mdoc) and (2)
an async **`sign(handle, alg, signing_input) -> signature`** callback; the SDK computes the exact bytes for
the OpenID4VCI proof-JWT, the SD-JWT VC **KB-JWT**, and the mdoc **DeviceAuth**, and splices the returned
signature into the envelope. The SDK **never generates, imports, holds, or sees** the holder private key;
it stays in the integrator's HSM/KMS; no secret or crypto in a browser.

**Rationale**: This is the industry norm for non-wallet/server-side stacks (Sphereon, walt.id, Procivis,
SpruceID `Signer` traits) and a direct reuse of spec-001 (DRY, Principle VIII) — satisfying Principle IV
(not a wallet, no sole-control secret in the frontend) and ARF's WSCD/key-attestation expectation.

**Risks (RCA-documented)**: the hook is a blind-signing trust boundary (like the CSC flow) — the SDK must
build signing input deterministically and expose `aud`/`nonce` for host-side policy inspection. mdoc
`DeviceMac` is ECDH key-agreement (not a signature) — support a `DeviceSignature` path first and document
the `DeviceMac` variant as a follow-on hook capability.

## D9 — Test fixtures: vendored conformance vectors + self-generated negatives, fully offline

**Decision**: Two tiers. **Tier A (traceability)** — vendor redistributable upstream vectors: the **ISO
18013-5 Annex-D** worked example reproduced under Apache-2.0 in OWF **multipaz** (`TestVectors.kt`), the
**IETF arf-pid SD-JWT VC** examples (deterministically reproduced from the pinned inputs + `random_seed:0`),
and the **`isomdl` test IACA PKI** (incl. a deliberate wrong-signer cert) + EUDI "Utopia" test roots.
**Tier B (backbone)** — a self-signed test IACA/issuer PKI + a generator that mints SD-JWT VCs (with
KB-JWTs) and mdocs to cover expiry/revocation/tamper/wrong-issuer/wrong-audience negatives (FR-005,
SC-002). Keep a NOTICE/attribution file; commit generator recipes.

**Rationale**: Upstream IETF repos commit only YAML inputs (outputs are `.gitignore`d) and the OIDF suite is
a live harness, so Tier B (self-generated under a test anchor) is the dependable, fully-offline (SC-003)
backbone; Tier A gives the standards-conformance signal.
</content>
