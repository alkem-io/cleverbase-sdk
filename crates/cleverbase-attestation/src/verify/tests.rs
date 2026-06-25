//! Tests for the always-on `verify` entry point (T016 — written test-first against the assembler).
//!
//! Exercises: format detection (SD-JWT VC / mdoc / unsupported); the per-format always-on bar via
//! the global `verify` (both formats VALID + a negative path each); the OpenID4VP binding through
//! `verify` (bound VALID, replay/wrong-audience INVALID, both formats); and the policy format gate.

use super::{detect_format, fold_qualified, verify, Presentation, VerifyContext};
use crate::mdoc::test_issuer::{mdoc_ds_cert_der, MdocBuilder};
use crate::openid4vp::{oid4vp_handover_transcript, Dcql, PresentationRequest};
use crate::qualified::QualifiedTrustList;
use crate::sdjwtvc::test_issuer::{
    attach_kb_jwt, mint_sd_jwt, HOLDER_KEY_PK8, ISSUER_CERT_DER, ISSUER_KEY_PK8, NOW,
};
use crate::status::StatusOutcome;
use crate::trust::StaticTestAnchors;
use crate::types::{
    Format, IssuerRole, QualifiedStatus, ReasonCode, TrustStatus, VerificationPolicy,
};

const AUDIENCE: &str = "https://verifier.example/cb";
const WRONG_AUDIENCE: &str = "https://attacker.example/evil";
/// The verifier's `response_uri` request parameter (OpenID4VP 1.0 §B.2.6 4th handover element) —
/// distinct from the `client_id` (`audience`).
const RESPONSE_URI: &str = "https://verifier.example/cb/response";
const MDOC_NOW: i64 = 1_717_200_000;

/// The scheme-operator anchor (the IACA root) the qualified-gate fixture's national TL is signed by.
const CA_IACA: &[u8] = include_bytes!("../../../../tests/fixtures/attestation/ca-iaca.cert.der");
/// The qualified-status national-TL fixture (`mdoc-ds` = granted EAA/Q at `RELEVANT_GRANTED`;
/// `wrong-issuer` = absent → Indeterminate).
const QUALIFIED_TRUST_LIST_JSON: &[u8] =
    include_bytes!("../../../../tests/fixtures/attestation/qualified-trust-list.json");
/// Relevant/verification instant inside the mdoc validity window AND the qualified-gate `granted`
/// window (2026-09-01): `mdoc-ds` is a granted EAA/Q issuer → Qualified, `wrong-issuer` is absent →
/// Indeterminate. (Mirrors `qualified::tests::RELEVANT_GRANTED`.)
const RELEVANT_GRANTED: i64 = 1_788_220_800;

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
        response_uri: RESPONSE_URI.to_owned(),
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
    let transcript = oid4vp_handover_transcript(AUDIENCE, &request.nonce, RESPONSE_URI);
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
    let transcript = oid4vp_handover_transcript(WRONG_AUDIENCE, &request.nonce, RESPONSE_URI);
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
fn qualified_gate_off_by_default_leaves_qualified_status_none_and_bar_unchanged() {
    // T019 landed: the gate is OFF by default. With it off, the always-on bar runs unchanged and
    // qualified_status stays None; enabling it with NO trust list never fabricates a qualified
    // status — it is the honest Indeterminate (SC-007), and the always-on `valid`/reasons are
    // identical to the gate-off run (the gate is additive, never altering the bar).
    let sd_jwt = mint_sd_jwt(ISSUER_KEY_PK8, ISSUER_CERT_DER);
    let presentation = sd_jwt.presentation();
    let anchors = sd_jwt_anchors();

    let off = VerifyContext {
        now_unix: NOW,
        qualified_gate: false,
        ..VerifyContext::default()
    };
    let on_no_list = VerifyContext {
        now_unix: NOW,
        qualified_gate: true, // enabled, but no qualified_trust_list supplied
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
        &on_no_list,
        None,
    );
    // Gate off → qualified_status absent.
    assert!(
        r_off.qualified_status.is_none(),
        "gate off → qualified_status absent (never assumed)"
    );
    // Enabling the gate is ADDITIVE: only qualified_status differs; the always-on verdict
    // (valid + reasons + disclosures + trust) is byte-identical (SC-007).
    assert_eq!(r_off.valid, r_on.valid);
    assert_eq!(r_off.reasons, r_on.reasons);
    assert_eq!(r_off.disclosed_attributes, r_on.disclosed_attributes);
    assert_eq!(r_off.trust_status, r_on.trust_status);
    assert_eq!(
        r_on.qualified_status,
        Some(QualifiedStatus::Indeterminate),
        "gate on with no trust list → Indeterminate, never a false qualified"
    );
}

// =================================================================================================
// Qualified-status multi-document provenance (the gate must cover EVERY document, not documents[0]).
// =================================================================================================

/// Load + parse the optional qualified-TL fixture, or `None` if it is absent/empty (self-skip seam,
/// mirroring `qualified::tests`).
fn qualified_trust_list_fixture() -> Option<QualifiedTrustList> {
    if QUALIFIED_TRUST_LIST_JSON.is_empty() {
        return None;
    }
    Some(QualifiedTrustList::parse(QUALIFIED_TRUST_LIST_JSON).expect("qualified TL fixture parses"))
}

#[test]
fn single_document_mdoc_qualified_issuer_reports_qualified() {
    // Baseline: a SINGLE-document mdoc from the granted EAA/Q `mdoc-ds` issuer → Qualified (so the
    // multi-document fix below is shown to be a genuine narrowing, not a blanket Indeterminate).
    let Some(tl) = qualified_trust_list_fixture() else {
        return; // self-skip: fixture absent
    };
    let response = MdocBuilder::new().build();
    let anchors = mdoc_anchors();
    let scheme = [CA_IACA.to_vec()];
    let ctx = VerifyContext {
        now_unix: RELEVANT_GRANTED,
        role: IssuerRole::Pid,
        qualified_gate: true,
        qualified_trust_list: Some(&tl),
        qualified_scheme_anchors: &scheme,
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
    assert!(
        result.valid,
        "single-doc mdoc must verify: {:?}",
        result.reasons
    );
    assert_eq!(
        result.qualified_status,
        Some(QualifiedStatus::Qualified),
        "a single granted-EAA/Q issuer → Qualified"
    );
}

#[test]
fn multi_document_mdoc_does_not_report_a_single_qualified_that_under_covers() {
    // PROVENANCE PROBE: `documents[0]` is the granted EAA/Q `mdoc-ds` issuer (→ Qualified on its own),
    // but a SECOND document carries a DIFFERENT issuer (`wrong-issuer`, absent from the TL →
    // Indeterminate). Reading only `documents[0]` would report Qualified over a result whose merged
    // attributes also cover the second, non-qualified issuer's document. The gate MUST decide over
    // EVERY document and fold so a `Qualified` never under-covers → Indeterminate here.
    let Some(tl) = qualified_trust_list_fixture() else {
        return; // self-skip: fixture absent
    };
    let response = MdocBuilder::new().append_second_issuer_document().build();
    let anchors = mdoc_anchors();
    let scheme = [CA_IACA.to_vec()];
    let ctx = VerifyContext {
        now_unix: RELEVANT_GRANTED,
        role: IssuerRole::Pid,
        qualified_gate: true,
        qualified_trust_list: Some(&tl),
        qualified_scheme_anchors: &scheme,
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
    // The gate runs independently of the always-on verdict (a multi-issuer response need not be
    // VALID); the determination MUST NOT be a single Qualified read from documents[0].
    assert_ne!(
        result.qualified_status,
        Some(QualifiedStatus::Qualified),
        "a multi-issuer mdoc must NOT report a Qualified that under-covers documents[1]"
    );
    assert_eq!(
        result.qualified_status,
        Some(QualifiedStatus::Indeterminate),
        "documents[1]'s issuer is undecidable → the folded status is Indeterminate (fail-closed)"
    );
}

#[test]
fn fold_qualified_requires_every_document_to_qualify() {
    // Unit-cover the fold: Qualified only if ALL qualify; else Indeterminate if any is undecidable;
    // else NotQualified; an empty set is Indeterminate (nothing to decide).
    use QualifiedStatus::{Indeterminate, NotQualified, Qualified};
    assert_eq!(fold_qualified([Qualified, Qualified]), Qualified);
    assert_eq!(fold_qualified([Qualified, Indeterminate]), Indeterminate);
    assert_eq!(fold_qualified([Qualified, NotQualified]), NotQualified);
    // Indeterminate dominates NotQualified (a definitive NotQualified-for-all cannot be asserted).
    assert_eq!(fold_qualified([NotQualified, Indeterminate]), Indeterminate);
    assert_eq!(fold_qualified([NotQualified, NotQualified]), NotQualified);
    assert_eq!(fold_qualified([Qualified]), Qualified);
    assert_eq!(fold_qualified(std::iter::empty()), Indeterminate);
}
