# Tier A — vendored upstream conformance vectors

These are **independent, upstream** EUDI conformance vectors, vendored for traceability (research
**D9**, task **T002**). They complement — and are anchored by — the **Tier B** self-generated test
PKI in the parent directory (`../gen.sh`, task **T003**), which is the dependable, fully-offline
backbone the verifier/trust-list tests build on. Attribution is also recorded in `../NOTICE`.

All material here is **synthetic conformance/test data** from public standards work — no real keys,
no real secrets.

## SD-JWT VC — IETF arf-pid example

| File | Upstream |
|------|----------|
| `sd-jwt-vc/arf-pid-specification.yml` | [`oauth-wg/oauth-sd-jwt-vc`](https://github.com/oauth-wg/oauth-sd-jwt-vc) → `examples/03-pid/specification.yml` |
| `sd-jwt-vc/ietf-examples-settings.yml` | same repo → `examples/settings.yml` (pinned issuer/holder keys, `random_seed: 0`, `iat`/`exp`) |

- **What it is**: the ARF-aligned PID SD-JWT VC worked example from the
  `draft-ietf-oauth-sd-jwt-vc` source repo (`vct: urn:example:eudi:pid:aendgard:1`,
  selectively-disclosable PID claims, KB-JWT enabled, `typ: dc+sd-jwt`).
- **Why the YAML inputs and not a rendered SD-JWT**: upstream commits **only** the YAML inputs; the
  rendered SD-JWT / disclosures are produced by the IETF `sd-jwt-generator` and are `.gitignore`d
  upstream. They are **deterministically reproducible** from these two files (the fixed issuer/holder
  keys + `random_seed: 0` in `ietf-examples-settings.yml`). Vendoring the inputs is the faithful,
  redistributable form; a test that needs the rendered credential regenerates it from these inputs.
- **License**: IETF Trust Legal Provisions (BCP 78 / BCP 79); code components are under the
  **Simplified BSD License** (TLP §4). See the upstream repo `LICENSE.md` / `CONTRIBUTING.md`.

### Reproducing the rendered SD-JWT (optional, not committed)

```sh
pipx run sd-jwt-generator generate \
  --settings-path ietf-examples-settings.yml \
  --specification-path arf-pid-specification.yml
# -> deterministic sd_jwt_issuance / sd_jwt_presentation (random_seed:0)
```

## mdoc — ISO/IEC 18013-5 Annex-D vector

| File | Upstream |
|------|----------|
| `mdoc/multipaz-TestVectors.kt` | [`openwallet-foundation/multipaz`](https://github.com/openwallet-foundation/multipaz) → `multipaz/src/commonTest/kotlin/org/multipaz/mdoc/TestVectors.kt` |

- **What it is**: the **ISO/IEC 18013-5 Annex-D** worked example reproduced as hex-encoded CBOR
  constants — `DeviceResponse`, `IssuerSigned`, the MSO (`MobileSecurityObject`), `DeviceEngagement`,
  the static device/eReader keys, etc. — the canonical mdoc parse/verify conformance vector.
- **Form**: kept as the original Kotlin source so the hex constants are 1:1 with upstream and easy to
  re-diff; the mdoc verifier tests slice the `const val` hex strings out of this file (no Kotlin
  toolchain needed — they are plain hex). Keeping the file verbatim preserves attribution + diffability.
- **License**: **Apache License 2.0** (originally The Android Open Source Project). The Apache-2.0
  header is retained in the file.

## T002 status

**Both Tier A sources were successfully vendored** (offline-usable hereafter; fetched once from the
public upstreams above). The SD-JWT VC side is the **inputs** (the upstream's own committed form —
rendered outputs are generator-produced and not committed upstream); the mdoc side is the full
Annex-D vector verbatim.

The **`isomdl` / EUDI "Utopia" test IACA PKI** that T002 also lists is **not** vendored here: that
role (a trusted IACA root + a deliberate wrong-signer cert) is already covered, equivalently and
deterministically, by the Tier B `../gen.sh` PKI (`ca-iaca.*` + `wrong-issuer.*`), so vendoring a
second IACA PKI would duplicate it without adding conformance signal. If a future test needs to parse
an upstream-issued mdoc against an upstream IACA specifically, vendor
[`spruceid/isomdl`](https://github.com/spruceid/isomdl) `test/` IACA material (Apache-2.0) into
`mdoc/` and record it in `../NOTICE`.
