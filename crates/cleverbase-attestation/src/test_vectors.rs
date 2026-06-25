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

use crate::sdjwtvc::test_issuer::{mint_sd_jwt, ISSUER_CERT_DER, ISSUER_KEY_PK8, NOW};
use crate::types::{Format, IssuerRole, VerificationPolicy};
use crate::wire::{
    VerifyRequest, WireContext, WirePresentation, WireTrustAnchor, ATTESTATION_SCHEMA_VERSION,
};

/// Build a CBOR-encoded [`VerifyRequest`] envelope for a **VALID** SD-JWT VC verification: a
/// trusted-issuer credential, in its validity window, no status mechanism, no OpenID4VP request.
///
/// Driving this through the C-ABI (`cleverbase_attestation_verify`) yields a `VerifyOutcome::Ok`
/// with `valid = true` and the disclosed attributes — a true end-to-end VALID path.
#[must_use]
pub fn valid_sd_jwt_verify_request_cbor() -> Vec<u8> {
    let sd_jwt = mint_sd_jwt(ISSUER_KEY_PK8, ISSUER_CERT_DER);
    let req = VerifyRequest {
        schema_version: ATTESTATION_SCHEMA_VERSION,
        presentation: WirePresentation::SdJwtVc {
            presentation: sd_jwt.presentation(),
        },
        policy: VerificationPolicy::default(),
        anchors: vec![WireTrustAnchor {
            role: IssuerRole::Pid,
            format: Format::SdJwtVc,
            cert_der: ISSUER_CERT_DER.to_vec(),
        }],
        context: WireContext {
            now_unix: NOW,
            role: IssuerRole::Pid,
            status: crate::status::StatusOutcome::NoStatus,
            session_transcript: None,
            qualified_gate: false,
            qualified_trust_list: None,
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
                pre_authorized_code: "pre-auth".to_owned(),
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
