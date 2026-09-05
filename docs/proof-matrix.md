# SDK proof matrix

This is the factual, maintained answer to “what has been proved?”  A green test is scoped to
the mechanism and validator named below; it does not imply an unlisted property. The most recent
default-pipeline evidence is the [`Tests` run on develop at 87e1c3e](https://github.com/alkem-io/cleverbase-sdk/actions/runs/33963363863).

| Claim | Mechanism that proves it | Independent validator | Latest green run | Not proven / not implemented |
| --- | --- | --- | --- | --- |
| Sign PAdES B-B with RSA | `TestCredentialFreeBB/v1_rsa` drives start, both OAuth legs, CSC `signHash`, CMS assembly and PDF embedding against the synthetic credential-free mock. | OpenSSL `cms -verify` over the PDF ByteRange and synthetic CA. | [Tests](https://github.com/alkem-io/cleverbase-sdk/actions/runs/33963363863) | Only the mock until the stub/acceptance rows below run in CI. |
| Sign PAdES B-T with RSA | `TestCredentialFreeBT/v1_rsa` performs the B-B journey plus the mock RFC 3161 TSA path. | OpenSSL CMS verification; timestamp token structure assertion. | [Tests](https://github.com/alkem-io/cleverbase-sdk/actions/runs/33963363863) | No qualified production TSA or acceptance signer run. |
| Public-stub B-T preparation | `TestCleverbaseHashSigningStub/B-T` supplies `tsa.invalid` and records the same two OAuth traversals and CSC effects as B-B. The core rejects the stub’s fake signature before a TSA effect can be emitted. | None. | [Live contract path](https://github.com/alkem-io/cleverbase-sdk/actions/runs/33966737046) | No timestamp request, B-T PDF, or cryptographic verification is proved by the stub. |
| Sign with ECDSA P-256 | `TestCredentialFreeBB/v2_ecdsa` and `TestCredentialFreeECDSATamperRejected` drive CSC v2 raw `r∥s` normalization and reject a tampered result. | OpenSSL CMS verification. | [Tests](https://github.com/alkem-io/cleverbase-sdk/actions/runs/33963363863) | No Cleverbase-stub or acceptance ECDSA/v2 contract run. |
| Verify a singly-signed PAdES PDF (integrity only) | `verify_pdf` / Go `VerifyPDF` strictly parse the PDF signature dictionary and raw-hex ByteRange gap; resolve the embedded signer by issuer+serial; verify RSA/ECDSA signed attributes; compare the CMS message-digest to the two signed PDF ranges; and report B-B/B-T plus canonical signer serial/CN. `produced_b_b_signature_verifies_with_openssl`, `produced_b_t_signature_has_timestamp_and_verifies`, `verifier_rejects_tampered_pdf_byte_range_content`, `verifier_rejects_cms_signed_by_a_key_other_than_its_embedded_certificate`, and `verifier_rejects_the_public_cleverbase_stub_fake_signature` cover the positive and negative vectors. | OpenSSL independently verifies the valid mock outputs. | [Tests](https://github.com/alkem-io/cleverbase-sdk/actions/runs/33985631745) | The SDK verifier does **not** build or trust a chain, check revocation/trusted-list status, or validate the B-T timestamp token. Multiple signatures are rejected. |
| CA-backed validation of SDK-produced CMS | The reference-integration `verifyCMSWithCA` helper independently extracts the detached CMS and PDF ByteRange, then validates it against the supplied synthetic CA. | OpenSSL `cms -verify`. | [Tests](https://github.com/alkem-io/cleverbase-sdk/actions/runs/33985631745) | This is harness evidence for the synthetic mock chain, not certificate-path building by `verify_pdf` and not a Cleverbase acceptance/production trust result. |
| Co-sign / append to an already signed PDF | Not implemented. `container::is_already_signed` rejects `/ByteRange` input before signing. | None. | N/A | Incremental-update co-signing that preserves prior signatures is deferred. |
| EUDI attestation verify | `conformance::iso_18013_5_annex_d_issuer_auth_verifies_under_the_sdk_verifier` verifies the vendored externally authored ISO/IEC 18013-5 Annex-D mdoc vector. | ISO/IEC 18013-5 Annex-D vector. | [Tests](https://github.com/alkem-io/cleverbase-sdk/actions/runs/33963363863) | This row does not prove a live Cleverbase issuer integration. |
| EUDI attestation issue / present / verify | Native issuance and wire tests under `issuance::{signer,present,wire}::tests` exercise SDK-issued material and its verifier. | None; these are SDK-controlled vectors. | [Tests](https://github.com/alkem-io/cleverbase-sdk/actions/runs/33963363863) | No independent live issuer proof in this row. |
| PAdES profile conformance | `.github/workflows/profile-conformance.yml` runs only when manually dispatched or a PR has the `profile-conformance` label. | pyHanko and EU DSS when their toolchain/image is available. | No successful workflow run found as of 2026-09-05. | The opt-in pyHanko/DSS job has not yet supplied evidence for this matrix. |

## Cleverbase hash-signing stub contract checklist

The following rows are synchronized with `stubContractChecklist` in
`examples/reference-integration/signing-service/e2e/stub_test.go`. That test fails if a checklist
identifier is added, removed, or renamed in only one place. “Limitation” means the beta stub
accepted an input its OpenAPI declares invalid; it is recorded as a non-proof, not accepted as SDK
behavior.

<!-- hash-signing-stub-checklist:start -->
| Check | Endpoint | What the suite asserts | Current status |
| --- | --- | --- | --- |
| `authorize-service` | `/oauth2/authorize` | Service-scope authorize request fields and immediate 302 with code/state. | [Verified in public-stub CI](https://github.com/alkem-io/cleverbase-sdk/actions/runs/33966737046). |
| `authorize-credential` | `/oauth2/authorize` | Credential-scope request includes credential ID, one signature, and SHA-256 consent hash; immediate 302. | [Verified in public-stub CI](https://github.com/alkem-io/cleverbase-sdk/actions/runs/33966737046). |
| `token-service` | `/oauth2/token` | Basic auth plus grant type, code, client ID, redirect URI; Bearer token response shape. | [Verified in public-stub CI](https://github.com/alkem-io/cleverbase-sdk/actions/runs/33966737046). |
| `credentials-list` | `/csc/v1/credentials/list` | Bearer JSON request and non-empty `credentialIDs` response. | [Verified in public-stub CI](https://github.com/alkem-io/cleverbase-sdk/actions/runs/33966737046). |
| `credentials-info` | `/csc/v1/credentials/info` | Selected ID, chain/certInfo request; SCAL 2, RSA-2048, auth mode, multisign and leaf identity response. | [Verified in public-stub CI](https://github.com/alkem-io/cleverbase-sdk/actions/runs/33966737046). |
| `token-credential-sad` | `/oauth2/token` | Credential authorization-code exchange has the same required form and returns SAD. | [Verified in public-stub CI](https://github.com/alkem-io/cleverbase-sdk/actions/runs/33966737046). |
| `sign-hash` | `/csc/v1/signatures/signHash` | Bearer request has ID, SAD, SHA-256 hash, `rsaEncryption` signAlgo, and one response signature. | [Verified in public-stub CI](https://github.com/alkem-io/cleverbase-sdk/actions/runs/33966737046). |
| `token-wrong-client` | `/oauth2/token` | Wrong HTTP Basic client credential is rejected (4xx). | [Verified in public-stub CI](https://github.com/alkem-io/cleverbase-sdk/actions/runs/33966737046). |
| `info-missing-credential` | `/csc/v1/credentials/info` | Missing credential ID is rejected (400). | [Verified in public-stub CI](https://github.com/alkem-io/cleverbase-sdk/actions/runs/33966737046). |
| `sign-hash-wrong-algorithm` | `/csc/v1/signatures/signHash` | `sha256WithRSAEncryption` is rejected (400); documented CSC `rsaEncryption` is the accepted value. | [Verified in public-stub CI](https://github.com/alkem-io/cleverbase-sdk/actions/runs/33966737046). |
| `sign-hash-invalid-sad` | `/csc/v1/signatures/signHash` | Invalid or expired SAD is rejected (400). | [Verified in public-stub CI](https://github.com/alkem-io/cleverbase-sdk/actions/runs/33966737046). |
| `sign-hash-empty-credential-limitation` | `/csc/v1/signatures/signHash` | Logs either a current 200 acceptance or a spec-correct 400 for an empty credential ID. | Observed stub behavior; not a contract proof. |
| `sign-hash-malformed-hash-limitation` | `/csc/v1/signatures/signHash` | Logs either a current 200 acceptance or a spec-correct 400 for a non-base64 hash. | Observed stub behavior; not a cryptographic proof. |
| `sign-hash-short-hash-limitation` | `/csc/v1/signatures/signHash` | Logs either a current 200 acceptance or a spec-correct 400 for a 31-byte hash. | Observed stub behavior; not a cryptographic proof. |
| `oauth-auth-not-used` | `/oauth2/auth` | The SDK does not call this sibling authorize endpoint. | Not exercised. |
| `oauth-revoke-not-used` | `/oauth2/revoke` | The SDK does not revoke OAuth tokens. | Not exercised. |
| `csc-info-not-used` | `/csc/v1/info` | The SDK does not call general CSC info. | Not exercised. |
| `csc-auth-revoke-not-used` | `/csc/v1/auth/revoke` | The SDK does not revoke CSC authorization. | Not exercised. |
| `ecdsa-v2-not-exposed` | `not exposed by hash-signing stub` | The public hash-signing stub exposes CSC v1 RSA only. | Not testable against this stub. |
<!-- hash-signing-stub-checklist:end -->

The stub returns a deliberately fake signature. The SDK’s own CMS verification rejects it before
PDF embedding, so this checklist proves protocol preparation and rejection of non-cryptographic
output. It does not prove a signed PDF, cryptographic validity, trust chain, or real signer identity;
those require the synthetic mock or a real acceptance/production run.
