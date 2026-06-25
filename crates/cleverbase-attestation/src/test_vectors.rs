//! Shared conformant test vectors (the `test-vectors` feature).
//!
//! Exposes ready-made, CBOR-encoded `verify` request envelopes a downstream crate can drive through
//! the C-ABI without re-implementing the issuer side — e.g. the `cleverbase-ffi` end-to-end VALID
//! smoke test. The vectors reuse the same test-issuer minters the in-crate tests use (DRY), so a
//! fixture change is reflected everywhere. **Not** part of the production verification surface
//! (gated behind the off-by-default `test-vectors` feature).
//!
//! Test-support code: the strict `restriction` lints are relaxed here exactly as in the test-issuer
//! modules (a panic on a broken fixed fixture is the intended signal).
#![allow(clippy::expect_used, clippy::missing_panics_doc)]

use crate::sdjwtvc::test_issuer::{
    mint_sd_jwt, mint_sd_jwt_with_validity, ISSUER_CERT_DER, ISSUER_KEY_PK8, NOW,
};
use crate::types::{Format, IssuerRole, VerificationPolicy};
use crate::wire::{
    VerifyRequest, WireContext, WirePresentation, WireTrustAnchor, ATTESTATION_SCHEMA_VERSION,
};

/// The issuing **IACA root** (`ca-iaca`) the test SD-JWT VC issuer leaf chains to — the C-ABI trust
/// path is chain-validating (chain-to-root), so the smoke-test request pins the CA, not the leaf.
const CA_IACA_CERT_DER: &[u8] =
    include_bytes!("../../../tests/fixtures/attestation/ca-iaca.cert.der");

/// The verification instant the C-ABI smoke test runs at: 2026-09-01, INSIDE the `sdjwt-issuer` leaf
/// (and `ca-iaca` root) validity window (2026-06-25 .. 2027-09-23). The chain-validating C-ABI trust
/// path enforces the leaf's validity window at this instant, so the request must run in-window.
const SMOKE_NOW: i64 = 1_788_220_800; // 2026-09-01.

/// Build a CBOR-encoded [`VerifyRequest`] envelope for a **VALID** SD-JWT VC verification: a
/// trusted-issuer credential, in its validity window, no status mechanism, no OpenID4VP request.
///
/// The credential is minted in-window and the anchor is the **issuing IACA root** (`ca-iaca`): the
/// C-ABI trust path chain-validates the leaf to the passed CA (the EUDI chain-to-root model — a host
/// configuring a CA/root trusts every credential whose leaf chains to it), so this exercises the
/// production chain-validating trust, not an exact-leaf pin.
///
/// Driving this through the C-ABI (`cleverbase_attestation_verify`) yields a `VerifyOutcome::Ok`
/// with `valid = true` and the disclosed attributes — a true end-to-end VALID path.
#[must_use]
pub fn valid_sd_jwt_verify_request_cbor() -> Vec<u8> {
    // Mint in-window (nbf 2026-08-01, exp well after SMOKE_NOW but within the leaf cert's window).
    let sd_jwt = mint_sd_jwt_with_validity(
        ISSUER_KEY_PK8,
        ISSUER_CERT_DER,
        serde_json::json!(1_785_542_400), // nbf = 2026-08-01
        serde_json::json!(1_790_000_000), // exp = 2026-09-21 (inside the leaf cert window)
    );
    let req = VerifyRequest {
        schema_version: ATTESTATION_SCHEMA_VERSION,
        presentation: WirePresentation::SdJwtVc {
            presentation: sd_jwt.presentation(),
        },
        policy: VerificationPolicy::default(),
        anchors: vec![WireTrustAnchor {
            role: IssuerRole::Pid,
            format: Format::SdJwtVc,
            // The issuing CA root: the leaf chains to it (chain-to-root), not an exact-leaf pin.
            cert_der: CA_IACA_CERT_DER.to_vec(),
        }],
        context: WireContext {
            now_unix: SMOKE_NOW,
            role: IssuerRole::Pid,
            status: crate::status::StatusOutcome::NoStatus,
            session_transcript: None,
            qualified_gate: false,
            qualified_trust_list: None,
            qualified_scheme_anchors: Vec::new(),
        },
        request: None,
    };
    let mut buf = Vec::new();
    ciborium::into_writer(&req, &mut buf).expect("CBOR encode of the test VerifyRequest");
    buf
}

/// Build a CBOR-encoded issuance request envelope that **skips** (a `None` issuer backend) — the
/// gated default. Driving it through the C-ABI (`cleverbase_attestation_issuance`) yields a
/// `WireObtainStep::Skipped` (a clear skipped outcome, never a failure — FR-008), exercising the
/// additive issuance surface end-to-end without requiring a live issuer.
#[must_use]
pub fn skipped_issuance_request_cbor() -> Vec<u8> {
    use crate::issuance::obtain::{CredentialOffer, IssuerBackend};
    use crate::issuance::signer::HolderContext;
    use crate::issuance::wire::{IssuanceOp, IssuanceRequest, ISSUANCE_SCHEMA_VERSION};
    use crate::sdjwtvc::test_issuer::HOLDER_JWK_JSON;

    let jwk: serde_json::Value =
        serde_json::from_slice(HOLDER_JWK_JSON).expect("holder JWK fixture parses");
    let req = IssuanceRequest {
        schema_version: ISSUANCE_SCHEMA_VERSION,
        op: IssuanceOp::BeginObtain {
            offer: CredentialOffer {
                pre_authorized_code: crate::secret::Secret::new("pre-auth"),
                credential_configuration_id: "eu.europa.ec.eudi.pid_vc_sd_jwt".to_owned(),
                format: Format::SdJwtVc,
            },
            backend: IssuerBackend::none(),
            holder: HolderContext::new(jwk, "holder-handle"),
            now_unix: NOW,
        },
    };
    let mut buf = Vec::new();
    ciborium::into_writer(&req, &mut buf).expect("CBOR encode of the test IssuanceRequest");
    buf
}

/// The **rendered** SD-JWT VC presentation string of a VALID, trusted-issuer credential — the raw
/// artifact an *independent* EU reference verifier consumes (the `scripts/crosscheck-attestation.sh`
/// `--format sd-jwt-vc` input, FR-013 / Principle VI).
///
/// This is the compact `<issuer-JWS>~<D.1>~…~<D.N>` produced by the same test issuer the in-crate
/// suite uses (DRY), so the SDK-produced artifact the cross-check feeds the reference verifier is the
/// exact credential the always-on bar accepts — no parallel minting.
#[must_use]
pub fn valid_sd_jwt_vc_artifact() -> String {
    let sd_jwt = mint_sd_jwt(ISSUER_KEY_PK8, ISSUER_CERT_DER);
    sd_jwt.presentation()
}

/// The **rendered** mdoc `DeviceResponse` (CBOR) of a VALID, conformant credential — the raw artifact
/// an *independent* EU reference verifier consumes (the `scripts/crosscheck-attestation.sh`
/// `--format mdoc` input, FR-013 / Principle VI).
///
/// Produced by the same ISO/IEC 18013-5 test issuer the in-crate suite verifies (DRY): together with
/// the SD-JWT VC artifact this lets the cross-check span both mandated formats against a
/// different-language reference verifier, not just the SDK's own Rust verifier.
#[must_use]
pub fn valid_mdoc_artifact() -> Vec<u8> {
    crate::mdoc::test_issuer::MdocBuilder::new().build()
}
