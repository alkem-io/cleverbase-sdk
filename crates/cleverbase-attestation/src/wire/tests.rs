//! Tests for the attestation wire envelope (T016 — the real verifier wiring, schema v2).
//!
//! A well-formed request runs the always-on [`crate::verify`] bar and carries the verdict back; a
//! malformed request or a wrong schema version is rejected with a clear message.

use super::{
    decode_verify_request, encode_verify_response, process_verify_bytes, VerifyOutcome,
    VerifyRequest, VerifyResponse, WireContext, WirePresentation, WireTrustAnchor,
    ATTESTATION_SCHEMA_VERSION,
};
use crate::mdoc::test_issuer::{mdoc_ds_cert_der, MdocBuilder};
use crate::sdjwtvc::test_issuer::{mint_sd_jwt, ISSUER_CERT_DER, ISSUER_KEY_PK8, NOW};
use crate::status::StatusOutcome;
use crate::types::{Format, IssuerRole, VerificationPolicy};

fn encode(req: &VerifyRequest) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::into_writer(req, &mut buf).unwrap();
    buf
}

/// A well-formed SD-JWT VC verify request whose issuer is trusted (a VALID verdict end-to-end).
fn valid_sd_jwt_request() -> VerifyRequest {
    let sd_jwt = mint_sd_jwt(ISSUER_KEY_PK8, ISSUER_CERT_DER);
    VerifyRequest {
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
            status: StatusOutcome::NoStatus,
            session_transcript: None,
            qualified_gate: false,
        },
        request: None,
    }
}

#[test]
fn well_formed_sd_jwt_request_verifies_valid() {
    let out = process_verify_bytes(&encode(&valid_sd_jwt_request()));
    let resp: VerifyResponse = ciborium::from_reader(&out[..]).unwrap();
    assert_eq!(resp.schema_version, ATTESTATION_SCHEMA_VERSION);
    match resp.outcome {
        VerifyOutcome::Ok { result } => {
            assert!(result.valid, "reasons {:?}", result.reasons);
            assert!(result.disclosed_attributes.contains_key("given_name"));
        }
        VerifyOutcome::Err { message } => panic!("unexpected error: {message}"),
    }
}

#[test]
fn untrusted_issuer_request_verifies_invalid_with_reason() {
    // Same credential, but no anchors configured → UntrustedIssuer (a real INVALID verdict).
    let mut req = valid_sd_jwt_request();
    req.anchors.clear();
    let out = process_verify_bytes(&encode(&req));
    let resp: VerifyResponse = ciborium::from_reader(&out[..]).unwrap();
    match resp.outcome {
        VerifyOutcome::Ok { result } => {
            assert!(!result.valid);
            assert_eq!(
                result.reasons,
                vec![crate::types::ReasonCode::UntrustedIssuer]
            );
        }
        VerifyOutcome::Err { message } => panic!("unexpected error: {message}"),
    }
}

#[test]
fn well_formed_mdoc_request_verifies_valid() {
    let response = MdocBuilder::new().build();
    let req = VerifyRequest {
        schema_version: ATTESTATION_SCHEMA_VERSION,
        presentation: WirePresentation::Mdoc {
            device_response: response,
            audience: None,
        },
        policy: VerificationPolicy::default(),
        anchors: vec![WireTrustAnchor {
            role: IssuerRole::Pid,
            format: Format::Mdoc,
            cert_der: mdoc_ds_cert_der().to_vec(),
        }],
        context: WireContext {
            now_unix: 1_717_200_000,
            role: IssuerRole::Pid,
            status: StatusOutcome::NoStatus,
            session_transcript: None,
            qualified_gate: false,
        },
        request: None,
    };
    let out = process_verify_bytes(&encode(&req));
    let resp: VerifyResponse = ciborium::from_reader(&out[..]).unwrap();
    match resp.outcome {
        VerifyOutcome::Ok { result } => assert!(result.valid, "reasons {:?}", result.reasons),
        VerifyOutcome::Err { message } => panic!("unexpected error: {message}"),
    }
}

#[test]
fn garbage_input_yields_err_outcome() {
    let out = process_verify_bytes(&[0xff, 0x00, 0x13, 0x37]);
    let resp: VerifyResponse = ciborium::from_reader(&out[..]).unwrap();
    assert!(matches!(resp.outcome, VerifyOutcome::Err { .. }));
}

#[test]
fn wrong_schema_version_is_rejected() {
    let mut req = valid_sd_jwt_request();
    req.schema_version = ATTESTATION_SCHEMA_VERSION + 1;
    let err = decode_verify_request(&encode(&req)).unwrap_err();
    assert!(err.contains("unsupported attestation schema_version"));
}

#[test]
fn response_round_trips_through_cbor() {
    let bytes = encode_verify_response(VerifyOutcome::Err {
        message: "x".to_owned(),
    });
    let resp: VerifyResponse = ciborium::from_reader(&bytes[..]).unwrap();
    assert!(matches!(resp.outcome, VerifyOutcome::Err { .. }));
}
