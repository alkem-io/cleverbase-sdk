//! Tests for the attestation wire envelope (T016 — the real verifier wiring, schema v2).
//!
//! A well-formed request runs the always-on [`crate::verify`] bar and carries the verdict back; a
//! malformed request or a wrong schema version is rejected with a clear message.

use super::{
    decode_verify_request, encode_verify_response, process_verify_bytes, VerifyOutcome,
    VerifyRequest, VerifyResponse, WireContext, WirePresentation, WireSchemeAnchor,
    WireTrustAnchor, ATTESTATION_SCHEMA_VERSION,
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
            qualified_trust_list: None,
            qualified_scheme_anchors: Vec::new(),
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
            qualified_trust_list: None,
            qualified_scheme_anchors: Vec::new(),
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

/// The optional national-TL fixture the opt-in C-ABI gate reads (qualified EAA/Q services).
const QUALIFIED_TRUST_LIST_JSON: &[u8] =
    include_bytes!("../../../../tests/fixtures/attestation/qualified-trust-list.json");
/// The scheme-operator anchor (the IACA root) the C-ABI gate authenticates the national TL against.
const CA_IACA: &[u8] = include_bytes!("../../../../tests/fixtures/attestation/ca-iaca.cert.der");
/// A self-signed cert that does NOT chain to `ca-iaca` — a forged national-TL signer over the wire.
const WRONG_ISSUER: &[u8] =
    include_bytes!("../../../../tests/fixtures/attestation/wrong-issuer.cert.der");

#[test]
fn opt_in_gate_over_the_c_abi_populates_qualified_status_and_is_additive() {
    // T020: the wire envelope additively carries the gate flag, the national TL bytes, and the
    // scheme-operator anchor. Driving the SAME credential with the gate OFF vs ON yields an identical
    // always-on verdict; only ON carries the qualified_status (sdjwt-issuer is a granted EAA/Q issuer
    // at NOW, and the TL authenticates against the supplied scheme anchor → Qualified).
    let base = valid_sd_jwt_request();

    let gate_on = {
        let mut req = base.clone();
        req.context.qualified_gate = true;
        req.context.qualified_trust_list = Some(QUALIFIED_TRUST_LIST_JSON.to_vec());
        req.context.qualified_scheme_anchors = vec![WireSchemeAnchor {
            cert_der: CA_IACA.to_vec(),
        }];
        req
    };

    let decode = |bytes: &[u8]| -> crate::types::VerificationResult {
        let resp: VerifyResponse = ciborium::from_reader(bytes).unwrap();
        match resp.outcome {
            VerifyOutcome::Ok { result } => result,
            VerifyOutcome::Err { message } => panic!("unexpected error: {message}"),
        }
    };

    let off = decode(&process_verify_bytes(&encode(&base)));
    let on = decode(&process_verify_bytes(&encode(&gate_on)));

    // Always-on verdict identical; gate is purely additive (SC-007).
    assert!(off.valid && on.valid);
    assert_eq!(off.reasons, on.reasons);
    assert_eq!(off.disclosed_attributes, on.disclosed_attributes);
    assert!(off.qualified_status.is_none(), "gate off → absent");
    assert_eq!(
        on.qualified_status,
        Some(crate::types::QualifiedStatus::Qualified),
        "gate on over the C-ABI → Qualified for a granted EAA/Q issuer"
    );
}

#[test]
fn opt_in_gate_over_the_c_abi_with_malformed_trust_list_is_indeterminate_not_an_error() {
    // A malformed national-TL blob fails CLOSED inside the gate (Indeterminate), never failing the
    // always-on verdict nor erroring the whole verify — no false "qualified".
    let mut req = valid_sd_jwt_request();
    req.context.qualified_gate = true;
    req.context.qualified_trust_list = Some(b"{ not a trust list".to_vec());
    let resp: VerifyResponse =
        ciborium::from_reader(&process_verify_bytes(&encode(&req))[..]).expect("response decodes");
    match resp.outcome {
        VerifyOutcome::Ok { result } => {
            assert!(result.valid, "always-on bar unaffected by a bad TL");
            assert_eq!(
                result.qualified_status,
                Some(crate::types::QualifiedStatus::Indeterminate)
            );
        }
        VerifyOutcome::Err { message } => panic!("a bad TL must not error the verify: {message}"),
    }
}

#[test]
fn opt_in_gate_over_the_c_abi_with_a_forged_trust_list_signer_is_indeterminate() {
    // A genuine fixture TL but driven with a FORGED scheme anchor (wrong-issuer, which the fixture's
    // ca-iaca signer does not chain to) over the wire → the gate cannot authenticate the TL →
    // Indeterminate, never Qualified (the false-trust bug fix, end-to-end through the C-ABI envelope).
    let mut req = valid_sd_jwt_request();
    req.context.qualified_gate = true;
    req.context.qualified_trust_list = Some(QUALIFIED_TRUST_LIST_JSON.to_vec());
    req.context.qualified_scheme_anchors = vec![WireSchemeAnchor {
        cert_der: WRONG_ISSUER.to_vec(),
    }];
    let resp: VerifyResponse =
        ciborium::from_reader(&process_verify_bytes(&encode(&req))[..]).expect("response decodes");
    match resp.outcome {
        VerifyOutcome::Ok { result } => {
            assert!(result.valid, "always-on bar unaffected");
            assert_eq!(
                result.qualified_status,
                Some(crate::types::QualifiedStatus::Indeterminate),
                "an unauthenticated TL must never report Qualified over the C-ABI"
            );
        }
        VerifyOutcome::Err { message } => panic!("must not error: {message}"),
    }
}

#[test]
fn opt_in_gate_over_the_c_abi_without_a_scheme_anchor_is_indeterminate() {
    // The gate is on with a genuine fixture TL but NO scheme anchor supplied over the wire → the TL
    // cannot be authenticated → Indeterminate (can't authenticate ⇒ can't assert qualified).
    let mut req = valid_sd_jwt_request();
    req.context.qualified_gate = true;
    req.context.qualified_trust_list = Some(QUALIFIED_TRUST_LIST_JSON.to_vec());
    // qualified_scheme_anchors left empty (the default).
    let resp: VerifyResponse =
        ciborium::from_reader(&process_verify_bytes(&encode(&req))[..]).expect("response decodes");
    match resp.outcome {
        VerifyOutcome::Ok { result } => {
            assert!(result.valid);
            assert_eq!(
                result.qualified_status,
                Some(crate::types::QualifiedStatus::Indeterminate)
            );
        }
        VerifyOutcome::Err { message } => panic!("must not error: {message}"),
    }
}
