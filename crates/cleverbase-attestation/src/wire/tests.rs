//! Tests for the attestation wire envelope (T016 — the real verifier wiring, schema v2).
//!
//! A well-formed request runs the always-on [`crate::verify`] bar and carries the verdict back; a
//! malformed request or a wrong schema version is rejected with a clear message.

use super::{
    decode_verify_request, encode_verify_response, process_verify_bytes, VerifyOutcome,
    VerifyRequest, VerifyResponse, WireContext, WirePresentation, WireSchemeAnchor,
    WireTrustAnchor, ATTESTATION_SCHEMA_VERSION,
};
use crate::mdoc::test_issuer::{default_session_transcript, MdocBuilder};
use crate::sdjwtvc::test_issuer::{mint_sd_jwt_with_validity, ISSUER_CERT_DER, ISSUER_KEY_PK8};
use crate::status::StatusOutcome;
use crate::types::{Format, IssuerRole, VerificationPolicy};

/// The issuing IACA root (`ca-iaca`) the test issuer/DS leaves chain to. The C-ABI trust path is
/// chain-validating (chain-to-root), so the well-formed requests pin this CA, not the leaf.
const CA_IACA: &[u8] = include_bytes!("../../../../tests/fixtures/attestation/ca-iaca.cert.der");
/// A verification instant INSIDE the leaf + IACA-root validity windows (2026-06-25 .. 2027-09-23):
/// 2026-09-01. The chain-validating C-ABI trust path enforces the leaf's validity window at the
/// verification instant, so the well-formed requests must run in-window (the 2025 `NOW` is before the
/// leaf's notBefore and would now correctly fail chain validation).
const IN_WINDOW_NOW: i64 = 1_788_220_800; // 2026-09-01.

fn encode(req: &VerifyRequest) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::into_writer(req, &mut buf).unwrap();
    buf
}

/// A well-formed SD-JWT VC verify request whose issuer is trusted (a VALID verdict end-to-end).
///
/// The C-ABI trust path is chain-validating, so the credential is minted IN-WINDOW (nbf 2026-08-01,
/// at [`IN_WINDOW_NOW`]) and the anchor is the issuing **IACA root** (`ca-iaca`): the leaf chains to
/// the CA (chain-to-root), exercising the production trust rather than an exact-leaf pin.
fn valid_sd_jwt_request() -> VerifyRequest {
    let sd_jwt = mint_sd_jwt_with_validity(
        ISSUER_KEY_PK8,
        ISSUER_CERT_DER,
        serde_json::json!(1_785_542_400), // nbf = 2026-08-01 (in the leaf cert's window)
        serde_json::json!(1_790_000_000), // exp = 2026-09-21 (still in-window, after IN_WINDOW_NOW)
    );
    VerifyRequest {
        schema_version: ATTESTATION_SCHEMA_VERSION,
        presentation: WirePresentation::SdJwtVc {
            presentation: sd_jwt.presentation(),
        },
        policy: VerificationPolicy::default(),
        anchors: vec![WireTrustAnchor {
            role: IssuerRole::Pid,
            format: Format::SdJwtVc,
            // The issuing CA root: the leaf chains to it (chain-to-root), not an exact-leaf pin.
            cert_der: CA_IACA.to_vec(),
        }],
        context: WireContext {
            now_unix: IN_WINDOW_NOW,
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
    // The anchor is the issuing IACA root: the C-ABI trust path CHAIN-VALIDATES the leaf to the CA
    // (chain-to-root — the EUDI model), proving a host passing a CA/root trusts a chaining leaf.
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
fn expired_pinned_leaf_anchor_is_untrusted_over_the_c_abi() {
    // FALSE-ACCEPT FIX (C-ABI trust): a host pins the issuer LEAF directly as the anchor, but the
    // verification instant is PAST the leaf cert's notAfter. The chain-validating C-ABI trust path
    // enforces the leaf's validity window (reusing `verify_chain`), so the issuer is UntrustedIssuer
    // — NOT silently accepted as the old exact-DER-equality (`StaticTestAnchors`) path would.
    let mut req = valid_sd_jwt_request();
    // Pin the leaf itself as the anchor (a direct pin), and run far past its notAfter (≈2096).
    req.anchors = vec![WireTrustAnchor {
        role: IssuerRole::Pid,
        format: Format::SdJwtVc,
        cert_der: ISSUER_CERT_DER.to_vec(),
    }];
    req.context.now_unix = 4_000_000_000;
    let out = process_verify_bytes(&encode(&req));
    let resp: VerifyResponse = ciborium::from_reader(&out[..]).unwrap();
    match resp.outcome {
        VerifyOutcome::Ok { result } => {
            assert!(!result.valid, "an expired pinned leaf must NOT be accepted");
            assert_eq!(
                result.reasons,
                vec![crate::types::ReasonCode::UntrustedIssuer]
            );
        }
        VerifyOutcome::Err { message } => panic!("unexpected error: {message}"),
    }
}

#[test]
fn leaf_pinned_directly_within_validity_is_trusted_over_the_c_abi() {
    // The direct-pin path still works WITHIN the leaf's validity window: pinning the leaf at an
    // in-window instant is trusted (so the expired-pin rejection above is the validity gate firing,
    // not a blanket direct-pin failure).
    let mut req = valid_sd_jwt_request();
    req.anchors = vec![WireTrustAnchor {
        role: IssuerRole::Pid,
        format: Format::SdJwtVc,
        cert_der: ISSUER_CERT_DER.to_vec(),
    }];
    // now_unix already IN_WINDOW from the base request.
    let out = process_verify_bytes(&encode(&req));
    let resp: VerifyResponse = ciborium::from_reader(&out[..]).unwrap();
    match resp.outcome {
        VerifyOutcome::Ok { result } => assert!(result.valid, "reasons {:?}", result.reasons),
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
    // The C-ABI trust path chain-validates the DS leaf to the passed anchor and enforces the leaf
    // cert's validity window at `now`, so the credential is minted IN-WINDOW (MSO validityInfo inside
    // the mdoc-ds leaf cert window) and the anchor is the issuing IACA root (chain-to-root).
    let response = MdocBuilder::new()
        .signed("2026-08-01T00:00:00Z")
        .validity("2026-08-01T00:00:00Z", "2027-02-01T00:00:00Z")
        .build();
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
            // The issuing CA root: the DS leaf chains to it (chain-to-root), not an exact-leaf pin.
            cert_der: CA_IACA.to_vec(),
        }],
        context: WireContext {
            now_unix: IN_WINDOW_NOW,
            role: IssuerRole::Pid,
            status: StatusOutcome::NoStatus,
            // The mdoc `DeviceSignature` is signed over the builder's default transcript; a request-less
            // verify must be handed that same transcript (§9.1.5 — the verifier no longer fabricates
            // one) for the holder binding to verify.
            session_transcript: Some(default_session_transcript()),
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
/// A self-signed cert that does NOT chain to `ca-iaca` — a forged national-TL signer over the wire.
const WRONG_ISSUER: &[u8] =
    include_bytes!("../../../../tests/fixtures/attestation/wrong-issuer.cert.der");

/// The relevant/verification instant the qualified-gate wire test runs at — the shared in-window
/// instant (2026-09-01), inside both the credential leaf's and the national-TL signer's (`ca-iaca`)
/// validity windows. The gate authenticates the TL signer at the verification instant (enforced
/// against the signer cert's window), so the gate test mints an in-window credential and runs here.
const QUALIFIED_RELEVANT_GRANTED: i64 = IN_WINDOW_NOW; // 2026-09-01.

#[test]
fn opt_in_gate_over_the_c_abi_populates_qualified_status_and_is_additive() {
    // T020: the wire envelope additively carries the gate flag, the national TL bytes, and the
    // scheme-operator anchor. Driving the SAME credential with the gate OFF vs ON yields an identical
    // always-on verdict; only ON carries the qualified_status (sdjwt-issuer is a granted EAA/Q issuer
    // at the relevant time, and the TL authenticates against the supplied scheme anchor → Qualified).
    // The credential + verification instant are in-window for both the leaf and the TL signer certs.
    let base = {
        let mut req = valid_sd_jwt_request();
        let sd_jwt = mint_sd_jwt_with_validity(
            ISSUER_KEY_PK8,
            ISSUER_CERT_DER,
            serde_json::json!(QUALIFIED_RELEVANT_GRANTED - 1_000),
            serde_json::json!(QUALIFIED_RELEVANT_GRANTED + 1_000_000),
        );
        req.presentation = WirePresentation::SdJwtVc {
            presentation: sd_jwt.presentation(),
        };
        req.context.now_unix = QUALIFIED_RELEVANT_GRANTED;
        req
    };

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
