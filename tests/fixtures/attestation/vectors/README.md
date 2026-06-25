# Tier A — vendored upstream conformance vectors

These are **independent, upstream** EUDI conformance vectors, vendored for traceability (research
**D9**, task **T002**). They complement — and are anchored by — the **Tier B** self-generated test
PKI in the parent directory (`../gen.sh`, task **T003**), which is the dependable, fully-offline
backbone the verifier/trust-list tests build on. Attribution is also recorded in `../NOTICE`.

All material here is **synthetic conformance/test data** from public standards work — no real keys,
no real secrets.

## What actually consumes each vector

| Vector | Consumed by | Always-on? |
|--------|-------------|------------|
| `mdoc/multipaz-TestVectors.kt` (ISO 18013-5 Annex-D) | `cleverbase-attestation` `src/conformance.rs` — slices the `const val` hex out of this file and runs the SDK's mdoc **issuer-side** verifier against it | **Yes** (default `cargo test`) |
| `sd-jwt-vc/*.yml` (IETF arf-pid) | the independent cross-check (`scripts/crosscheck-attestation.sh`, opt-in) — see the SD-JWT VC note below for why these are NOT consumed by an always-on in-crate test | No (opt-in cross-check) |

## mdoc — ISO/IEC 18013-5 Annex-D vector

| File | Upstream |
|------|----------|
| `mdoc/multipaz-TestVectors.kt` | [`openwallet-foundation/multipaz`](https://github.com/openwallet-foundation/multipaz) → `multipaz/src/commonTest/kotlin/org/multipaz/mdoc/TestVectors.kt` |

- **What it is**: the **ISO/IEC 18013-5 Annex-D** worked example reproduced as hex-encoded CBOR
  constants — `DeviceResponse`, `IssuerSigned`, the MSO (`MobileSecurityObject`), `DeviceEngagement`,
  the static device/eReader keys, the DS certificate, etc. — the canonical mdoc parse/verify
  conformance vector.
- **Form**: kept as the original Kotlin source so the hex constants are 1:1 with upstream and easy to
  re-diff; **the mdoc conformance test (`src/conformance.rs`) `include_str!`s this exact file and
  slices the `const val` hex strings out of it at test time** (no Kotlin toolchain needed — they are
  plain hex). Keeping the file verbatim preserves attribution + diffability and means the bytes the
  SDK verifies are byte-identical to the vendored upstream.
- **What the test proves (always-on, default `cargo test`)**: the SDK's mdoc **issuer-side** bar —
  the `IssuerAuth` `COSE_Sign1` ES256 signature, DS-certificate trust (anchored on the Annex-D
  `ISO_18013_5_ANNEX_D_DS_CERT`), MSO `digestAlgorithm` / `validityInfo` enforcement, and the in-house
  `valueDigests` recompute over every disclosed `IssuerSignedItem` — verifies a **real,
  externally-authored** ISO vector at a fixed instant inside the MSO validity window. This is genuine
  external conformance (not Rust-mint-then-Rust-verify): a real ISO worked example, parsed and verified
  by the production code path. The negative cases (after the validity window → `Expired`; no configured
  anchor → `UntrustedIssuer`) prove the bar enforces the real MSO window/trust, not a stubbed one.
- **Scope: issuer-auth, by design.** Annex-D's `DeviceAuth` is the ISO device-retrieval `DeviceMac`
  (an ECDH-derived HMAC over the ISO `SessionTranscript`), **not** the OpenID4VP `DeviceSignature`
  this SDK's holder-binding path verifies (research D8). The holder binding is therefore out of scope
  for this issuer-signature conformance check; the issuer-signed parts (signature + digests +
  validity) are exactly what a real external vector lets us prove byte-for-byte. The OpenID4VP
  `DeviceSignature` holder binding is covered (against SDK-minted material) in the `openid4vp` / `mdoc`
  test suites.
- **License**: **Apache License 2.0** (originally The Android Open Source Project). The Apache-2.0
  header is retained in the file.

## SD-JWT VC — IETF arf-pid example

| File | Upstream |
|------|----------|
| `sd-jwt-vc/arf-pid-specification.yml` | [`oauth-wg/oauth-sd-jwt-vc`](https://github.com/oauth-wg/oauth-sd-jwt-vc) → `examples/03-pid/specification.yml` |
| `sd-jwt-vc/ietf-examples-settings.yml` | same repo → `examples/settings.yml` (pinned issuer/holder keys, `random_seed: 0`, `iat`/`exp`) |

- **What it is**: the ARF-aligned PID SD-JWT VC worked-example **inputs** from the
  `draft-ietf-oauth-sd-jwt-vc` source repo (`vct: urn:example:eudi:pid:aendgard:1`,
  selectively-disclosable PID claims, KB-JWT enabled, `typ: dc+sd-jwt`).
- **Why the YAML inputs and not a rendered SD-JWT**: upstream commits **only** the YAML inputs
  (confirmed: the repo's `examples/03-pid/` holds just `specification.yml`); the rendered SD-JWT /
  disclosures are produced by the IETF `sd-jwt-generator` and are `.gitignore`d upstream. They are
  deterministically reproducible from these two files (the fixed issuer/holder keys + `random_seed: 0`
  in `ietf-examples-settings.yml`), but the generator is a Python tool that is **not available in the
  offline Rust test environment**, so the rendered credential cannot be produced inside `cargo test`.
- **Why these are NOT consumed by an always-on in-crate test (honest status).** The IETF example signs
  the issuer JWS with a **bare JWK keyed by `iss`** (no X.509 `x5c` header). The SDK's SD-JWT VC
  verifier deliberately implements only the **EUDI / HAIP `x5c` trust profile** — it requires
  `alg=ES256` **and** an `x5c` leaf certificate, anchored to the EU trust lists (HAIP 1.0 §7; research
  D1) — and does not resolve a bare `iss`-keyed JWK. So even rendered, the arf-pid example would be
  (correctly) rejected by our verifier as structurally outside the EUDI trust model — it cannot serve
  as an always-on *positive* external-conformance vector under our `x5c`-only bar without re-keying it
  (which would make it no longer "the IETF example"). This is an upstream profile mismatch, **not** a
  conformance bug in the SDK verifier.
- **How SD-JWT VC external conformance IS covered**: through the **independent, different-language**
  cross-check (`scripts/crosscheck-attestation.sh`, opt-in CI job — see its header). The cross-check
  feeds an SDK-produced, `x5c`-bearing VALID SD-JWT VC artifact (minted by the same test issuer the
  in-crate suite verifies, exported by `tests/export_artifacts.rs`) to the Kotlin
  `eudi-lib-jvm-sdjwt-kt` reference verifier and asserts the independent verdict agrees. That is the
  cross-language SD-JWT VC conformance signal (Principle VI); the always-on **external** vector signal
  is provided by the mdoc Annex-D test above.
- **License**: IETF Trust Legal Provisions (BCP 78 / BCP 79); code components are under the
  **Simplified BSD License** (TLP §4). See the upstream repo `LICENSE.md` / `CONTRIBUTING.md`.

### Reproducing the rendered SD-JWT (optional, not committed, requires the Python generator)

```sh
pipx run sd-jwt-generator generate \
  --settings-path ietf-examples-settings.yml \
  --specification-path arf-pid-specification.yml
# -> deterministic sd_jwt_issuance / sd_jwt_presentation (random_seed:0)
```

## T002 status

**Both Tier A sources were vendored** (offline-usable hereafter; fetched once from the public
upstreams above). The mdoc side is the full Annex-D vector verbatim and is verified by an **always-on**
in-crate conformance test (`src/conformance.rs`). The SD-JWT VC side is the **inputs** (the upstream's
own committed form — rendered outputs are generator-produced and not committed upstream); because the
IETF example is `iss`/JWK-keyed (outside the SDK's EUDI `x5c` trust profile) and the generator is not
available offline, SD-JWT VC external conformance runs through the opt-in cross-check rather than an
always-on in-crate test (see the SD-JWT VC note above).

The **`isomdl` / EUDI "Utopia" test IACA PKI** that T002 also lists is **not** vendored here: that
role (a trusted IACA root + a deliberate wrong-signer cert) is already covered, equivalently and
deterministically, by the Tier B `../gen.sh` PKI (`ca-iaca.*` + `wrong-issuer.*`), so vendoring a
second IACA PKI would duplicate it without adding conformance signal. If a future test needs to parse
an upstream-issued mdoc against an upstream IACA specifically, vendor
[`spruceid/isomdl`](https://github.com/spruceid/isomdl) `test/` IACA material (Apache-2.0) into
`mdoc/` and record it in `../NOTICE`.
