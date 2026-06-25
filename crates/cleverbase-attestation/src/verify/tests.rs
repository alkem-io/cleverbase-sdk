//! Tests for the always-on `verify` entry point (T016 — written test-first against the assembler).
//!
//! Exercises: format detection (SD-JWT VC / mdoc / unsupported); the per-format always-on bar via
//! the global `verify` (both formats VALID + a negative path each); the OpenID4VP binding through
//! `verify` (bound VALID, replay/wrong-audience INVALID, both formats); and the policy format gate.

use super::{detect_format, fold_qualified, verify, Presentation, VerifyContext};
use crate::mdoc::test_issuer::{
    default_session_transcript, mdoc_ds_cert_der, wrong_issuer_cert_der, MdocBuilder,
};
use crate::openid4vp::{oid4vp_handover_transcript, Dcql, PresentationRequest};
use crate::qualified::QualifiedTrustList;
use crate::sdjwtvc::test_issuer::{
    attach_kb_jwt, mint_sd_jwt, mint_sd_jwt_with_validity, HOLDER_KEY_PK8, ISSUER_CERT_DER,
    ISSUER_KEY_PK8, NOW, WRONG_ISSUER_KEY_PK8,
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
/// The MSO `signed`/`validFrom` instant the qualified-gate mdoc fixtures are minted at: 2026-08-01,
/// inside the `mdoc-ds` grant window (2026-07-01 .. withdrawn 2027-03-01) AND inside the IACA
/// signer + DS-leaf cert validity windows. After the relevant-time fix the gate reads each issuer's
/// status at the credential's OWN issuance time (the MSO `signed`), NOT at `RELEVANT_GRANTED`, so the
/// minted credential must itself be issued in-window for `mdoc-ds` to read as a granted EAA/Q issuer.
const MDOC_ISSUED_IN_GRANT: &str = "2026-08-01T00:00:00Z";
/// The validity upper bound paired with [`MDOC_ISSUED_IN_GRANT`] (well after `RELEVANT_GRANTED`).
const MDOC_VALID_UNTIL: &str = "2027-02-01T00:00:00Z";
/// Verification instant AFTER the `mdoc-ds` withdrawal (2027-03-01), inside the signer + leaf cert
/// windows (mirrors `qualified::tests::RELEVANT_AFTER_WITHDRAWN`). Used by the multi-document fold
/// probe so BOTH appended documents are within their validity windows at `now`.
const RELEVANT_AFTER_WITHDRAWN: i64 = 1_811_808_000; // 2027-06-01.
/// The MSO `signed`/`validFrom` of the second fold-probe document: 2027-04-01, AFTER the `mdoc-ds`
/// withdrawal (2027-03-01) but before `RELEVANT_AFTER_WITHDRAWN` — so it is valid-at-`now`, yet at its
/// OWN issuance time `mdoc-ds` is withdrawn → NotQualified (the per-document relevant-time narrowing).
const MDOC_ISSUED_AFTER_WITHDRAWN: &str = "2027-04-01T00:00:00Z";
/// The validity upper bound paired with [`MDOC_ISSUED_AFTER_WITHDRAWN`] (after `RELEVANT_AFTER_WITHDRAWN`).
const MDOC_AFTER_WITHDRAWN_VALID_UNTIL: &str = "2027-09-01T00:00:00Z";
/// An SD-JWT VC issuance/relevant time BEFORE the `sdjwt-issuer` EAA/Q grant began (the grant starts
/// 2026-07-01), yet AFTER the TL signer's notBefore (2026-06-25) so the TL still authenticates:
/// 2026-06-26. The false-qualified probe for the relevant-time fix.
const RELEVANT_BEFORE_GRANTED: i64 = 1_782_432_000; // 2026-06-26.

fn sd_jwt_anchors() -> StaticTestAnchors {
    StaticTestAnchors::new().trust(IssuerRole::Pid, Format::SdJwtVc, ISSUER_CERT_DER)
}

fn mdoc_anchors() -> StaticTestAnchors {
    StaticTestAnchors::new().trust(IssuerRole::Pid, Format::Mdoc, mdoc_ds_cert_der())
}

/// Always-on anchors that trust BOTH the IACA-chained `mdoc-ds` DS and the foreign, self-signed
/// `wrong-issuer` DS — so a multi-document response with a `wrong-issuer`-signed second document
/// passes the always-on bar (VALID) and the qualified gate runs. `wrong-issuer` is deliberately
/// absent from the qualified national TL, so the gate reads its per-document status as Indeterminate.
fn mdoc_anchors_with_wrong_issuer() -> StaticTestAnchors {
    StaticTestAnchors::new()
        .trust(IssuerRole::Pid, Format::Mdoc, mdoc_ds_cert_der())
        .trust(IssuerRole::Pid, Format::Mdoc, wrong_issuer_cert_der())
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
    // A request-less mdoc verify with a `DeviceSignature` requires the explicit `SessionTranscript` the
    // holder signed over (§9.1.5 — the verifier no longer fabricates one); supply the default
    // transcript the builder used.
    let transcript = default_session_transcript();
    let ctx = VerifyContext {
        now_unix: MDOC_NOW,
        role: IssuerRole::Pid,
        session_transcript: Some(&transcript),
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
    // mdoc disclosed attributes are GROUPED BY NAMESPACE (`{ ns: Map({ id: value }) }`); the builder's
    // default namespace is `org.iso.18013.5.1`, with `family_name` in its sub-map.
    assert!(
        matches!(
            result.disclosed_attributes.get("org.iso.18013.5.1"),
            Some(crate::types::AttributeValue::Map(ns)) if ns.contains_key("family_name")
        ),
        "family_name is disclosed under the org.iso.18013.5.1 namespace"
    );
}

#[test]
fn mdoc_request_less_without_a_session_transcript_is_missing_request_binding() {
    // A request-less mdoc verify with a `DeviceSignature` but NO `SessionTranscript` cannot confirm
    // holder binding; the verifier MUST reject it (§9.1.5 — never fabricate a transcript and silently
    // no-op the binding) rather than return VALID. This is the `verify`-entry-point view of the mdoc
    // fail-closed fix (the `ctx.session_transcript` default of `None`).
    let response = MdocBuilder::new().build();
    let anchors = mdoc_anchors();
    let ctx = VerifyContext {
        now_unix: MDOC_NOW,
        role: IssuerRole::Pid,
        ..VerifyContext::default() // session_transcript: None
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
        !result.valid,
        "a request-less mdoc with no SessionTranscript must NOT silently pass holder binding"
    );
    assert_eq!(result.reasons, vec![ReasonCode::MissingRequestBinding]);
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
    // Mint the credential ISSUED in the grant window: the gate reads `mdoc-ds`'s status at the MSO
    // `signed` (the credential's relevant time), not at `RELEVANT_GRANTED`.
    let response = MdocBuilder::new()
        .signed(MDOC_ISSUED_IN_GRANT)
        .validity(MDOC_ISSUED_IN_GRANT, MDOC_VALID_UNTIL)
        .build();
    let anchors = mdoc_anchors();
    let scheme = [CA_IACA.to_vec()];
    // Request-less verify of a `DeviceSignature`-bearing mdoc needs the explicit transcript (§9.1.5).
    let transcript = default_session_transcript();
    let ctx = VerifyContext {
        now_unix: RELEVANT_GRANTED,
        role: IssuerRole::Pid,
        session_transcript: Some(&transcript),
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
        "a single granted-EAA/Q issuer (issued in-window) → Qualified at the credential's relevant time"
    );
}

#[test]
fn multi_document_mdoc_does_not_report_a_single_qualified_that_under_covers() {
    // PROVENANCE + PER-DOCUMENT-RELEVANT-TIME PROBE: a VALID two-document response, BOTH signed by the
    // trusted `mdoc-ds` DS (so the always-on bar accepts it and the qualified gate runs). documents[0]
    // is issued IN the grant window (2026-08-01 → `mdoc-ds` is a granted EAA/Q issuer at that issuance
    // time → Qualified on its own); documents[1] is issued AFTER the issuer's withdrawal (2027-04-01 →
    // NotQualified at ITS issuance time). Both windows cover `now`, so the response is VALID. Reading
    // only documents[0], OR reading the status at "now" for both, would mis-report the verdict; the
    // gate MUST decide over EVERY document at EACH document's OWN relevant time and fold so a
    // `Qualified` never under-covers documents[1] → NotQualified here.
    let Some(tl) = qualified_trust_list_fixture() else {
        return; // self-skip: fixture absent
    };
    let response = MdocBuilder::new()
        // documents[0]: issued in-grant, valid window covers `now` (RELEVANT_AFTER_WITHDRAWN).
        .signed(MDOC_ISSUED_IN_GRANT)
        .validity(MDOC_ISSUED_IN_GRANT, MDOC_AFTER_WITHDRAWN_VALID_UNTIL)
        // documents[1]: same trusted DS, issued AFTER the withdrawal, valid window covers `now`.
        .append_valid_document_issued_at(
            MDOC_ISSUED_AFTER_WITHDRAWN,
            MDOC_AFTER_WITHDRAWN_VALID_UNTIL,
        )
        .build();
    let anchors = mdoc_anchors();
    let scheme = [CA_IACA.to_vec()];
    // Both documents are signed over the builder's default transcript; supply it so the request-less
    // verify confirms each holder binding (§9.1.5 — the verifier no longer fabricates one).
    let transcript = default_session_transcript();
    let ctx = VerifyContext {
        now_unix: RELEVANT_AFTER_WITHDRAWN,
        role: IssuerRole::Pid,
        session_transcript: Some(&transcript),
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
    // The response is VALID (both documents signed by the trusted DS), so the gate runs.
    assert!(
        result.valid,
        "both documents are signed by the trusted DS: {:?}",
        result.reasons
    );
    // The determination MUST NOT be a single Qualified read from documents[0].
    assert_ne!(
        result.qualified_status,
        Some(QualifiedStatus::Qualified),
        "a multi-document mdoc must NOT report a Qualified that under-covers documents[1]"
    );
    assert_eq!(
        result.qualified_status,
        Some(QualifiedStatus::NotQualified),
        "documents[1] is NotQualified at its own (post-withdrawal) relevant time → the fold is NotQualified"
    );
}

#[test]
fn multi_document_mdoc_with_a_foreign_issuer_document_is_indeterminate_end_to_end() {
    // PROVENANCE PROBE (end-to-end, the qualified-fold `Indeterminate`-via-foreign-issuer path): a
    // VALID two-document response whose documents[0] is signed by the IACA-chained, qualified `mdoc-ds`
    // (Qualified on its own at the credential's relevant time) and whose documents[1] is signed by a
    // FOREIGN/untrusted `wrong-issuer` DS that is NOT on the qualified national TL. The always-on bar
    // is configured to trust BOTH DS certs, so the whole response is VALID and the gate runs; but the
    // foreign issuer is absent from the qualified TL → its per-document status is `Indeterminate`, and
    // the fail-closed fold (Indeterminate dominates Qualified) MUST yield `Indeterminate` — NEVER a
    // single `Qualified` read off documents[0] that under-covers documents[1]'s foreign provenance
    // (SC-007). This exercises the fold end-to-end through `verify`, complementing the `fold_qualified`
    // UNIT test below.
    let Some(tl) = qualified_trust_list_fixture() else {
        return; // self-skip: fixture absent
    };
    let response = MdocBuilder::new()
        // documents[0]: trusted `mdoc-ds`, issued in-grant, valid window covers `now` (RELEVANT_GRANTED).
        .signed(MDOC_ISSUED_IN_GRANT)
        .validity(MDOC_ISSUED_IN_GRANT, MDOC_VALID_UNTIL)
        // documents[1]: FOREIGN `wrong-issuer` DS, issued in-window, valid window covers `now`.
        .append_wrong_issuer_document_issued_at(MDOC_ISSUED_IN_GRANT, MDOC_VALID_UNTIL)
        .build();
    // Trust BOTH the IACA-chained `mdoc-ds` AND the foreign `wrong-issuer` on the always-on bar, so the
    // whole response is VALID (otherwise documents[1] would fail the bar and the gate would never run).
    let anchors = mdoc_anchors_with_wrong_issuer();
    let scheme = [CA_IACA.to_vec()];
    // Both documents are signed over the builder's default transcript; supply it so the request-less
    // verify confirms each holder binding (§9.1.5 — the verifier no longer fabricates one).
    let transcript = default_session_transcript();
    let ctx = VerifyContext {
        now_unix: RELEVANT_GRANTED,
        role: IssuerRole::Pid,
        session_transcript: Some(&transcript),
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
    // The response is VALID (both DS certs are trusted on the always-on bar), so the gate runs.
    assert!(
        result.valid,
        "both documents are signed by always-on-trusted DS certs: {:?}",
        result.reasons
    );
    // documents[1]'s foreign issuer is absent from the qualified TL → Indeterminate; the fold is
    // Indeterminate (NOT a single Qualified that under-covers the foreign-issuer document).
    assert_ne!(
        result.qualified_status,
        Some(QualifiedStatus::Qualified),
        "a foreign-issuer second document must NOT report a Qualified that under-covers it"
    );
    assert_eq!(
        result.qualified_status,
        Some(QualifiedStatus::Indeterminate),
        "documents[1]'s issuer is on no qualified-TL service entry → its status is Indeterminate, and \
         the fail-closed fold (Indeterminate dominates) yields Indeterminate"
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

// =================================================================================================
// Qualified-status relevant-time + valid-gating (the FALSE-QUALIFIED fixes).
// =================================================================================================

#[test]
fn qualified_status_uses_the_credentials_issuance_time_not_now() {
    // FALSE-QUALIFIED FIX (relevant time): `sdjwt-issuer` is a granted EAA/Q issuer ONLY from
    // 2026-07-01. A credential it issued BEFORE the grant (here `nbf`/relevant time 2026-06-26) must
    // NOT be reported Qualified — even though the VERIFICATION instant (`now`) is well after the grant
    // (2026-09-01). The status MUST be read at the credential's issuance/relevant time, NOT "now"
    // (contracts/qualified-status-gate.md). Reading at "now" would falsely report Qualified.
    let Some(tl) = qualified_trust_list_fixture() else {
        return; // self-skip: fixture absent
    };
    // Minted with `nbf` BEFORE the grant; the always-on validity window still includes `now` so the
    // credential is VALID and the gate runs (the gate only computes status for a VALID credential).
    let sd_jwt = mint_sd_jwt_with_validity(
        ISSUER_KEY_PK8,
        ISSUER_CERT_DER,
        serde_json::json!(RELEVANT_BEFORE_GRANTED), // nbf = issuance/relevant time, before the grant
        serde_json::json!(RELEVANT_GRANTED + 1_000_000), // exp well after `now`
    );
    let presentation = sd_jwt.presentation();
    let anchors = sd_jwt_anchors();
    let scheme = [CA_IACA.to_vec()];
    let ctx = VerifyContext {
        now_unix: RELEVANT_GRANTED, // verification instant AFTER the grant — yet must not drive status
        role: IssuerRole::Pid,
        qualified_gate: true,
        qualified_trust_list: Some(&tl),
        qualified_scheme_anchors: &scheme,
        ..VerifyContext::default()
    };
    let result = verify(
        &Presentation::SdJwtVc(&presentation),
        &VerificationPolicy::default(),
        &anchors,
        &ctx,
        None,
    );
    assert!(
        result.valid,
        "credential is in-window at now: {:?}",
        result.reasons
    );
    // The issuer is on the TL but its grant had not yet begun at the credential's relevant time →
    // found-but-not-granted → NotQualified. Critically NOT Qualified (the false-qualified bug).
    assert_ne!(
        result.qualified_status,
        Some(QualifiedStatus::Qualified),
        "an issuer granted only AFTER issuance must NOT report Qualified for the earlier credential"
    );
    assert_eq!(
        result.qualified_status,
        Some(QualifiedStatus::NotQualified),
        "found on the TL but not granted at the credential's relevant time → NotQualified"
    );
}

#[test]
fn forged_credential_with_a_real_qualified_cert_reports_no_qualified_status() {
    // FALSE-QUALIFIED FIX (valid-gating): a forged SD-JWT VC whose `x5c` carries the REAL granted
    // EAA/Q `sdjwt-issuer` certificate (X.509 certs are public, so an attacker can embed one) but is
    // SIGNED WITH A DIFFERENT KEY (wrong-issuer). The always-on bar verifies the signature against the
    // embedded cert's public key → it fails → `valid = false` (Tamper). The qualified gate MUST NOT
    // report Qualified off that unverified claimed cert: `qualified_status` stays `None` because the
    // gate only runs for a VALID credential (SC-002/SC-007).
    let Some(tl) = qualified_trust_list_fixture() else {
        return; // self-skip: fixture absent
    };
    // Embed the real qualified `sdjwt-issuer` cert in `x5c`, but sign with the wrong-issuer key.
    let sd_jwt = mint_sd_jwt_with_validity(
        WRONG_ISSUER_KEY_PK8,
        ISSUER_CERT_DER, // the REAL granted EAA/Q issuer cert in x5c (a public cert)
        serde_json::json!(RELEVANT_GRANTED - 1_000),
        serde_json::json!(RELEVANT_GRANTED + 1_000_000),
    );
    let presentation = sd_jwt.presentation();
    // Trust the real issuer cert for the role/format (so trust is NOT what fails — the SIGNATURE is).
    let anchors = sd_jwt_anchors();
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
        &Presentation::SdJwtVc(&presentation),
        &VerificationPolicy::default(),
        &anchors,
        &ctx,
        None,
    );
    // The signature does not verify under the embedded (real) cert → INVALID (Tamper).
    assert!(!result.valid, "a forged signature must be INVALID");
    assert_eq!(result.reasons, vec![ReasonCode::Tamper]);
    // And the gate must NOT have reported the embedded qualified cert's status on an INVALID verdict.
    assert_eq!(
        result.qualified_status, None,
        "qualified status must be None for an INVALID credential (no Qualified off an unverified cert)"
    );
}

#[test]
fn credential_without_any_issuance_time_fails_closed_to_indeterminate() {
    // FALSE-QUALIFIED FIX (fail-closed): a VALID credential that carries NO issuance time at all (no
    // `iat`, no `nbf`) gives the gate no relevant time to read the status at. It MUST fail closed to
    // Indeterminate — never silently substitute "now" (which could falsely report Qualified). Even
    // though the issuer (sdjwt-issuer) IS a granted EAA/Q issuer at `now`, the absent issuance time
    // means the determination is undecidable.
    let Some(tl) = qualified_trust_list_fixture() else {
        return; // self-skip: fixture absent
    };
    // No `nbf` and no `exp` (both null = omitted) and no `iat` → the credential asserts no temporal
    // bound, so it is in-window/VALID, but it carries NO issuance time for the gate to read.
    let sd_jwt = mint_sd_jwt_with_validity(
        ISSUER_KEY_PK8,
        ISSUER_CERT_DER,
        serde_json::Value::Null, // nbf omitted
        serde_json::Value::Null, // exp omitted
    );
    let presentation = sd_jwt.presentation();
    let anchors = sd_jwt_anchors();
    let scheme = [CA_IACA.to_vec()];
    let ctx = VerifyContext {
        now_unix: RELEVANT_GRANTED, // the issuer IS granted at now — but now must NOT be used
        role: IssuerRole::Pid,
        qualified_gate: true,
        qualified_trust_list: Some(&tl),
        qualified_scheme_anchors: &scheme,
        ..VerifyContext::default()
    };
    let result = verify(
        &Presentation::SdJwtVc(&presentation),
        &VerificationPolicy::default(),
        &anchors,
        &ctx,
        None,
    );
    assert!(
        result.valid,
        "no temporal bound → in-window VALID: {:?}",
        result.reasons
    );
    assert_eq!(
        result.qualified_status,
        Some(QualifiedStatus::Indeterminate),
        "no issuance time → fail closed to Indeterminate, never read status at now"
    );
}
