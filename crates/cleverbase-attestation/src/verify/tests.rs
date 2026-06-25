//! Tests for the always-on `verify` entry point (T016 — written test-first against the assembler).
//!
//! Exercises: format detection (SD-JWT VC / mdoc / unsupported); the per-format always-on bar via
//! the global `verify` (both formats VALID + a negative path each); the OpenID4VP binding through
//! `verify` (bound VALID, replay/wrong-audience INVALID, both formats); and the policy format gate.

use super::{detect_format, verify, Presentation, VerifyContext};
use crate::mdoc::test_issuer::{mdoc_ds_cert_der, MdocBuilder};
use crate::openid4vp::{oid4vp_handover_transcript, Dcql, PresentationRequest};
use crate::sdjwtvc::test_issuer::{
    attach_kb_jwt, mint_sd_jwt, HOLDER_KEY_PK8, ISSUER_CERT_DER, ISSUER_KEY_PK8, NOW,
};
use crate::status::StatusOutcome;
use crate::trust::StaticTestAnchors;
use crate::types::{Format, IssuerRole, ReasonCode, TrustStatus, VerificationPolicy};

const AUDIENCE: &str = "https://verifier.example/cb";
const WRONG_AUDIENCE: &str = "https://attacker.example/evil";
const MDOC_NOW: i64 = 1_717_200_000;

fn sd_jwt_anchors() -> StaticTestAnchors {
    StaticTestAnchors::new().trust(IssuerRole::Pid, Format::SdJwtVc, ISSUER_CERT_DER)
}

fn mdoc_anchors() -> StaticTestAnchors {
    StaticTestAnchors::new().trust(IssuerRole::Pid, Format::Mdoc, mdoc_ds_cert_der())
}

fn request_with(audience: &str, nonce: &[u8]) -> PresentationRequest {
    PresentationRequest {
        dcql: Dcql::from_json(r#"{"credentials":[]}"#),
        nonce: nonce.to_vec(),
        audience: audience.to_owned(),
    }
}

// =================================================================================================
// Format detection.
// =================================================================================================

#[test]
fn detects_sd_jwt_vc_from_compact_text() {
    let sd_jwt = mint_sd_jwt(ISSUER_KEY_PK8, ISSUER_CERT_DER);
    let presentation = sd_jwt.presentation();
    assert_eq!(
        detect_format(presentation.as_bytes()),
        Some(Format::SdJwtVc)
    );
}

#[test]
fn detects_mdoc_from_device_response_cbor() {
    let response = MdocBuilder::new().build();
    assert_eq!(detect_format(&response), Some(Format::Mdoc));
}

#[test]
fn unrecognized_bytes_have_no_format() {
    // Random bytes: not UTF-8 SD-JWT, not a DeviceResponse CBOR map.
    assert_eq!(detect_format(&[0xff, 0x00, 0x13, 0x37]), None);
    // A UTF-8 string with no `~` and not three JWS parts.
    assert_eq!(detect_format(b"hello world"), None);
    // A CBOR map without `documents`.
    let mut buf = Vec::new();
    ciborium::into_writer(&ciborium::value::Value::Map(vec![]), &mut buf).unwrap();
    assert_eq!(detect_format(&buf), None);
}

#[test]
fn presentation_format_accessor_matches_the_variant() {
    assert_eq!(Presentation::SdJwtVc("x~").format(), Format::SdJwtVc);
    assert_eq!(
        Presentation::Mdoc {
            device_response: &[],
            audience: None
        }
        .format(),
        Format::Mdoc
    );
}

// =================================================================================================
// Per-format always-on bar via the global verify (no request).
// =================================================================================================

#[test]
fn sd_jwt_vc_valid_through_verify() {
    let sd_jwt = mint_sd_jwt(ISSUER_KEY_PK8, ISSUER_CERT_DER);
    let presentation = sd_jwt.presentation();
    let anchors = sd_jwt_anchors();
    let ctx = VerifyContext {
        now_unix: NOW,
        role: IssuerRole::Pid,
        ..VerifyContext::default()
    };
    let result = verify(
        &Presentation::SdJwtVc(&presentation),
        &VerificationPolicy::default(),
        &anchors,
        &ctx,
        None,
    );
    assert!(result.valid, "reasons {:?}", result.reasons);
    assert_eq!(result.trust_status, TrustStatus::Trusted);
    assert!(result.disclosed_attributes.contains_key("given_name"));
}

#[test]
fn sd_jwt_vc_untrusted_issuer_through_verify() {
    let sd_jwt = mint_sd_jwt(ISSUER_KEY_PK8, ISSUER_CERT_DER);
    let presentation = sd_jwt.presentation();
    let empty = StaticTestAnchors::new(); // trusts nothing
    let ctx = VerifyContext {
        now_unix: NOW,
        ..VerifyContext::default()
    };
    let result = verify(
        &Presentation::SdJwtVc(&presentation),
        &VerificationPolicy::default(),
        &empty,
        &ctx,
        None,
    );
    assert!(!result.valid);
    assert_eq!(result.reasons, vec![ReasonCode::UntrustedIssuer]);
}

#[test]
fn sd_jwt_vc_revoked_status_through_verify() {
    let sd_jwt = mint_sd_jwt(ISSUER_KEY_PK8, ISSUER_CERT_DER);
    let presentation = sd_jwt.presentation();
    let anchors = sd_jwt_anchors();
    let ctx = VerifyContext {
        now_unix: NOW,
        status: StatusOutcome::Revoked,
        ..VerifyContext::default()
    };
    let result = verify(
        &Presentation::SdJwtVc(&presentation),
        &VerificationPolicy::default(),
        &anchors,
        &ctx,
        None,
    );
    assert!(!result.valid);
    assert_eq!(result.reasons, vec![ReasonCode::Revoked]);
}

#[test]
fn mdoc_valid_through_verify() {
    let response = MdocBuilder::new().build();
    let anchors = mdoc_anchors();
    let ctx = VerifyContext {
        now_unix: MDOC_NOW,
        role: IssuerRole::Pid,
        ..VerifyContext::default()
    };
    let result = verify(
        &Presentation::Mdoc {
            device_response: &response,
            audience: None,
        },
        &VerificationPolicy::default(),
        &anchors,
        &ctx,
        None,
    );
    assert!(result.valid, "reasons {:?}", result.reasons);
    assert!(result.disclosed_attributes.contains_key("family_name"));
}

#[test]
fn mdoc_unavailable_status_through_verify() {
    let response = MdocBuilder::new().build();
    let anchors = mdoc_anchors();
    let ctx = VerifyContext {
        now_unix: MDOC_NOW,
        status: StatusOutcome::Unavailable,
        ..VerifyContext::default()
    };
    let result = verify(
        &Presentation::Mdoc {
            device_response: &response,
            audience: None,
        },
        &VerificationPolicy::default(),
        &anchors,
        &ctx,
        None,
    );
    assert!(!result.valid);
    assert_eq!(result.reasons, vec![ReasonCode::StatusUnavailable]);
}

// =================================================================================================
// OpenID4VP binding through the global verify (request supplied).
// =================================================================================================

#[test]
fn sd_jwt_vc_bound_request_is_valid_through_verify() {
    let request = request_with(AUDIENCE, &[4u8; 16]);
    let sd_jwt = mint_sd_jwt(ISSUER_KEY_PK8, ISSUER_CERT_DER);
    let presentation = attach_kb_jwt(sd_jwt, HOLDER_KEY_PK8, AUDIENCE, &request.nonce_b64());
    let anchors = sd_jwt_anchors();
    let ctx = VerifyContext {
        now_unix: NOW,
        ..VerifyContext::default()
    };
    let result = verify(
        &Presentation::SdJwtVc(&presentation),
        &VerificationPolicy::default(),
        &anchors,
        &ctx,
        Some(&request),
    );
    assert!(result.valid, "reasons {:?}", result.reasons);
}

#[test]
fn sd_jwt_vc_replay_is_invalid_through_verify() {
    use base64ct::{Base64UrlUnpadded, Encoding as _};
    let stale = Base64UrlUnpadded::encode_string(&[0xAAu8; 16]);
    let sd_jwt = mint_sd_jwt(ISSUER_KEY_PK8, ISSUER_CERT_DER);
    let presentation = attach_kb_jwt(sd_jwt, HOLDER_KEY_PK8, AUDIENCE, &stale);
    let request = request_with(AUDIENCE, &[0xBBu8; 16]);
    let anchors = sd_jwt_anchors();
    let ctx = VerifyContext {
        now_unix: NOW,
        ..VerifyContext::default()
    };
    let result = verify(
        &Presentation::SdJwtVc(&presentation),
        &VerificationPolicy::default(),
        &anchors,
        &ctx,
        Some(&request),
    );
    assert!(!result.valid);
    assert_eq!(result.reasons, vec![ReasonCode::Replay]);
}

#[test]
fn mdoc_bound_request_is_valid_through_verify() {
    let request = request_with(AUDIENCE, &[6u8; 16]);
    let transcript = oid4vp_handover_transcript(AUDIENCE, &request.nonce);
    let response = MdocBuilder::new().session_transcript(transcript).build();
    let anchors = mdoc_anchors();
    let ctx = VerifyContext {
        now_unix: MDOC_NOW,
        ..VerifyContext::default()
    };
    let result = verify(
        &Presentation::Mdoc {
            device_response: &response,
            audience: Some(AUDIENCE),
        },
        &VerificationPolicy::default(),
        &anchors,
        &ctx,
        Some(&request),
    );
    assert!(result.valid, "reasons {:?}", result.reasons);
}

#[test]
fn mdoc_wrong_audience_is_invalid_through_verify() {
    let request = request_with(AUDIENCE, &[6u8; 16]);
    let transcript = oid4vp_handover_transcript(WRONG_AUDIENCE, &request.nonce);
    let response = MdocBuilder::new().session_transcript(transcript).build();
    let anchors = mdoc_anchors();
    let ctx = VerifyContext {
        now_unix: MDOC_NOW,
        ..VerifyContext::default()
    };
    let result = verify(
        &Presentation::Mdoc {
            device_response: &response,
            audience: Some(WRONG_AUDIENCE),
        },
        &VerificationPolicy::default(),
        &anchors,
        &ctx,
        Some(&request),
    );
    assert!(!result.valid);
    assert_eq!(result.reasons, vec![ReasonCode::WrongAudience]);
}

#[test]
fn mdoc_with_request_but_no_audience_is_missing_request_binding() {
    let request = request_with(AUDIENCE, &[6u8; 16]);
    let response = MdocBuilder::new().build();
    let anchors = mdoc_anchors();
    let ctx = VerifyContext {
        now_unix: MDOC_NOW,
        ..VerifyContext::default()
    };
    let result = verify(
        &Presentation::Mdoc {
            device_response: &response,
            audience: None, // a request is supplied but no addressed audience to bind
        },
        &VerificationPolicy::default(),
        &anchors,
        &ctx,
        Some(&request),
    );
    assert!(!result.valid);
    assert_eq!(result.reasons, vec![ReasonCode::MissingRequestBinding]);
}

// =================================================================================================
// Policy format gate + qualified-gate seam.
// =================================================================================================

#[test]
fn policy_that_excludes_a_format_rejects_it_as_unsupported() {
    // A policy that accepts only mdoc must reject an SD-JWT VC as unsupported (never verify it).
    let sd_jwt = mint_sd_jwt(ISSUER_KEY_PK8, ISSUER_CERT_DER);
    let presentation = sd_jwt.presentation();
    let anchors = sd_jwt_anchors();
    let policy = VerificationPolicy {
        formats: vec![Format::Mdoc],
        ..VerificationPolicy::default()
    };
    let ctx = VerifyContext {
        now_unix: NOW,
        ..VerifyContext::default()
    };
    let result = verify(
        &Presentation::SdJwtVc(&presentation),
        &policy,
        &anchors,
        &ctx,
        None,
    );
    assert!(!result.valid);
    assert_eq!(result.reasons, vec![ReasonCode::UnsupportedFormat]);
}

#[test]
fn qualified_gate_seam_is_off_by_default_and_a_no_op_when_enabled() {
    // The always-on bar must work without the gate, and enabling the seam (pending T019) must not
    // change the verdict nor fabricate a qualified status.
    let sd_jwt = mint_sd_jwt(ISSUER_KEY_PK8, ISSUER_CERT_DER);
    let presentation = sd_jwt.presentation();
    let anchors = sd_jwt_anchors();

    let off = VerifyContext {
        now_unix: NOW,
        qualified_gate: false,
        ..VerifyContext::default()
    };
    let on = VerifyContext {
        now_unix: NOW,
        qualified_gate: true,
        ..VerifyContext::default()
    };
    let r_off = verify(
        &Presentation::SdJwtVc(&presentation),
        &VerificationPolicy::default(),
        &anchors,
        &off,
        None,
    );
    let r_on = verify(
        &Presentation::SdJwtVc(&presentation),
        &VerificationPolicy::default(),
        &anchors,
        &on,
        None,
    );
    assert_eq!(r_off, r_on, "the gate seam is a no-op pending T019");
    assert!(r_on.qualified_status.is_none(), "never a false qualified");
}
