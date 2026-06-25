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
