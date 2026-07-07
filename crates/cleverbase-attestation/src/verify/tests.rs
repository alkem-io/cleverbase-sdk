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
use crate::qualified::{QualifiedTrustList, EAA_EU_QUALIFIED_TYPE};
use crate::sdjwtvc::test_issuer::{
    attach_kb_jwt, block_on, holder_cnf, mint_sd_jwt, mint_sd_jwt_with_validity, Es256Signer,
    Sha2Hasher, HOLDER_KEY_PK8, ISSUER_CERT_DER, ISSUER_KEY_PK8, NOW, WRONG_ISSUER_KEY_PK8,
};
use crate::status::StatusOutcome;
use crate::trust::{ChainValidatingAnchors, StaticTestAnchors};
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
        statuses: &[StatusOutcome::Revoked],
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
        statuses: &[StatusOutcome::Unavailable],
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

/// Mint an SD-JWT VC that self-declares the TS 119 615 v1.4.1 QEAA type indication via the
/// issuer-signed **`category`** claim ([`EAA_EU_QUALIFIED_TYPE`], PRO-4.12.4-03, per ETSI TS 119 472-1 —
/// NOT the `vct`, which is the credential-TYPE identifier), with caller-chosen `nbf`/`exp`. The
/// canonical `mint_sd_jwt_with_*` helpers fix either the `vct` or the validity window (never both, and
/// the `crate::sdjwtvc` test helpers must not be modified for this task), so the qualified-gate tests
/// that need BOTH a self-declared QEAA type AND a specific issuance window build the credential here
/// from the shared test-issuer primitives.
fn mint_qeaa_sd_jwt(nbf: i64, exp: i64) -> sd_jwt_payload::SdJwt {
    use base64ct::Encoding as _;
    use sd_jwt_payload::SdJwtBuilder;
    let cert_b64 = base64ct::Base64::encode_string(ISSUER_CERT_DER);
    let claims = serde_json::json!({
        "iss": "https://issuer.example/cb",
        "vct": "urn:eudi:pid:1",
        "category": EAA_EU_QUALIFIED_TYPE,
        "nbf": nbf,
        "exp": exp,
        "given_name": "Ada",
    });
    let signer = Es256Signer::from_pkcs8(ISSUER_KEY_PK8);
    block_on(
        SdJwtBuilder::new_with_hasher(claims, Sha2Hasher)
            .expect("builder")
            .header("x5c", serde_json::json!([cert_b64]))
            .header("typ", serde_json::json!("dc+sd-jwt"))
            .make_concealable("/given_name")
            .expect("concealable")
            .require_key_binding(holder_cnf())
            .finish(&signer, "ES256"),
    )
    .expect("issuer signing succeeds")
}

#[test]
fn single_document_mdoc_qualified_issuer_reports_qualified() {
    // Baseline: a SINGLE-document mdoc from the granted EAA/Q `mdoc-ds` issuer → Qualified (so the
    // multi-document fix below is shown to be a genuine narrowing, not a blanket Indeterminate).
    let Some(tl) = qualified_trust_list_fixture() else {
        return; // self-skip: fixture absent
    };
    // Mint the credential ISSUED in the grant window: the gate reads `mdoc-ds`'s status at the MSO
    // `signed` (the credential's relevant time), not at `RELEVANT_GRANTED`. The document self-declares
    // the ETSI TS 119 472-1 `category` type indication (the QEAA URN) so PRO-4.12.4-03 is satisfied.
    let response = MdocBuilder::new()
        .qeaa_category()
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
fn single_document_mdoc_without_the_category_element_is_indeterminate() {
    // PRO-4.12.4-03 precondition ENFORCED for mdoc (the mdoc analogue of the SD-JWT
    // `an_absent_type_indication_is_indeterminate`): the SAME granted EAA/Q `mdoc-ds` issuer, issued
    // in-window (so `read_status` would otherwise resolve Qualified), but the document does NOT disclose
    // the ETSI TS 119 472-1 `category` data element. Absent type indication → the gate fails closed to
    // `Indeterminate`, NEVER a false `Qualified` — even for a genuinely granted-at-issuance EAA/Q issuer.
    let Some(tl) = qualified_trust_list_fixture() else {
        return; // self-skip: fixture absent
    };
    // Identical to `single_document_mdoc_qualified_issuer_reports_qualified` MINUS `.qeaa_category()`.
    let response = MdocBuilder::new()
        .signed(MDOC_ISSUED_IN_GRANT)
        .validity(MDOC_ISSUED_IN_GRANT, MDOC_VALID_UNTIL)
        .build();
    let anchors = mdoc_anchors();
    let scheme = [CA_IACA.to_vec()];
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
        "the always-on bar still passes (the missing category is not a bar failure): {:?}",
        result.reasons
    );
    assert_ne!(
        result.qualified_status,
        Some(QualifiedStatus::Qualified),
        "an mdoc that does not disclose the ETSI `category` element must NOT be a false Qualified"
    );
    assert_eq!(
        result.qualified_status,
        Some(QualifiedStatus::Indeterminate),
        "an absent `category` type indication fails the PRO-4.12.4-03 precondition closed → Indeterminate"
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
        // documents[0]: issued in-grant, valid window covers `now` (RELEVANT_AFTER_WITHDRAWN). Carries
        // the ETSI `category` type indication so its PRO-4.12.4-03 precondition is satisfied → Qualified
        // on its own (the appended documents[1] also carries `category`, so the fold narrows on the
        // relevant-time STATUS, not on a missing precondition).
        .qeaa_category()
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
        // Two documents, neither declaring a status mechanism → one NoStatus per document (the single
        // default would fail documents[1] closed to Unavailable before the qualified fold runs).
        statuses: &[StatusOutcome::NoStatus, StatusOutcome::NoStatus],
        status_tokens: &crate::status::DEFAULT_STATUS_TOKENS,
        session_transcript: Some(&transcript),
        qualified_gate: true,
        qualified_trust_list: Some(&tl),
        qualified_scheme_anchors: &scheme,
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
        // Two documents, neither declaring a status mechanism -- one NoStatus per document (the single
        // default would fail documents[1] closed to Unavailable before the qualified fold runs).
        statuses: &[StatusOutcome::NoStatus, StatusOutcome::NoStatus],
        status_tokens: &crate::status::DEFAULT_STATUS_TOKENS,
        session_transcript: Some(&transcript),
        qualified_gate: true,
        qualified_trust_list: Some(&tl),
        qualified_scheme_anchors: &scheme,
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
    // credential is VALID and the gate runs (the gate only computes status for a VALID credential). The
    // credential self-declares the QEAA type (vct = the URN) so PRO-4.12.4-03 is satisfied and the
    // relevant-time read (not the URN precondition) is what decides NotQualified.
    let sd_jwt = mint_qeaa_sd_jwt(
        RELEVANT_BEFORE_GRANTED, // nbf = issuance/relevant time, before the grant
        RELEVANT_GRANTED + 1_000_000, // exp well after `now`
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

// =================================================================================================
// In-core Token Status List authentication through `verify()` (layer 2, draft-ietf-oauth-status-list).
//
// A presented credential DECLARES a Token Status List reference (SD-JWT VC `status.status_list` /
// mdoc MSO `status`); the host supplies the fetched SIGNED status-list token in `ctx.status_tokens`,
// keyed by list URI; the core AUTHENTICATES it in-core (signature under a key authorized by the
// credential's OWN issuer/anchor, `sub` binding, freshness, bit read) and the outcome OVERRIDES the
// positional `statuses` seam. These mint the credential + a REAL signed token with the issuer's own
// key (the same-issuer path) and assert `verify()` returns valid / `Revoked` per the bit. The
// negatives assert fail-closed: a token for the WRONG uri is not matched (falls back to positional),
// and a token signed by an UNTRUSTED key is REJECTED (`StatusUnavailable`), never accepted.
// =================================================================================================

use std::collections::BTreeMap;

use crate::sdjwtvc::test_issuer::{
    mint_sd_jwt_with_malformed_status, mint_sd_jwt_with_status, WRONG_ISSUER_CERT_DER,
};

/// The credential's Token Status List URI (its `status.status_list.uri` / MSO `status` uri).
const STATUS_LIST_URI: &str = "https://issuer.example/statuslists/verify-1";
/// The mdoc Document Signer private key (PKCS#8) — signs the same-issuer mdoc status-list CWT so the
/// token's `x5chain` leaf (`mdoc-ds` cert) equals the credential's verified DS leaf (same-issuer path).
const MDOC_DS_KEY_PK8: &[u8] =
    include_bytes!("../../../../tests/fixtures/attestation/mdoc-ds.key.pk8");

/// A single-entry `uri → signed-token` map for `ctx.status_tokens`.
fn tokens(uri: &str, token: Vec<u8>) -> BTreeMap<String, Vec<u8>> {
    let mut map = BTreeMap::new();
    map.insert(uri.to_owned(), token);
    map
}

/// zlib-compress (RFC 1950) a status bitstring, mirroring a status provider's `lst`.
fn zlib(bytes: &[u8]) -> Vec<u8> {
    miniz_oxide::deflate::compress_to_vec_zlib(bytes, 6)
}

/// The single-byte `bits=1` bitstring whose entry 0 is 0 (VALID) or 1 (INVALID/revoked) — the tests
/// reference `idx = 0`, so entry 0 is the LSB of byte 0.
fn one_bit_lst(revoked: bool) -> Vec<u8> {
    vec![u8::from(revoked)]
}

/// Mint a `statuslist+jwt` compact-JWS Status List Token signed by `signer_pk8`, carrying `leaf_der`
/// as its `x5c` leaf (base64 standard), `sub` bound to the credential's list URI, fresh `iat`/`exp`
/// around `now`, and entry 0 = 0/1 per `revoked`.
fn mint_status_jwt(
    signer_pk8: &[u8],
    leaf_der: &[u8],
    sub: &str,
    now: i64,
    revoked: bool,
) -> Vec<u8> {
    use base64ct::{Base64, Base64UrlUnpadded, Encoding as _};
    use p256::ecdsa::{signature::Signer as _, Signature, SigningKey};
    use pkcs8::DecodePrivateKey as _;

    let sk = SigningKey::from_pkcs8_der(signer_pk8).expect("valid PKCS#8 P-256 key");
    let header = serde_json::json!({
        "alg": "ES256",
        "typ": "statuslist+jwt",
        "x5c": [Base64::encode_string(leaf_der)],
    });
    let payload = serde_json::json!({
        "sub": sub,
        "iat": now - 100,
        "exp": now + 1_000,
        "status_list": {
            "bits": 1,
            "lst": Base64UrlUnpadded::encode_string(&zlib(&one_bit_lst(revoked))),
        },
    });
    let h = Base64UrlUnpadded::encode_string(&serde_json::to_vec(&header).unwrap());
    let p = Base64UrlUnpadded::encode_string(&serde_json::to_vec(&payload).unwrap());
    let signing_input = format!("{h}.{p}");
    let sig: Signature = sk.sign(signing_input.as_bytes());
    let s = Base64UrlUnpadded::encode_string(sig.to_bytes().as_slice());
    format!("{signing_input}.{s}").into_bytes()
}

/// Mint a tagged `COSE_Sign1` `application/statuslist+cwt` Status List Token signed by `signer_pk8`,
/// carrying `leaf_der` as its `x5chain` leaf (label 33), `sub` (key 2) bound to the list URI, fresh
/// `iat`/`exp`, and entry 0 = 0/1 per `revoked` (the mdoc baseline wire form).
fn mint_status_cwt(
    signer_pk8: &[u8],
    leaf_der: &[u8],
    sub: &str,
    now: i64,
    revoked: bool,
) -> Vec<u8> {
    use ciborium::value::Value as Cbor;
    use coset::{iana, CoseSign1Builder, HeaderBuilder, TaggedCborSerializable as _};
    use p256::ecdsa::{signature::Signer as _, Signature, SigningKey};
    use pkcs8::DecodePrivateKey as _;

    let sk = SigningKey::from_pkcs8_der(signer_pk8).expect("valid PKCS#8 P-256 key");
    let status_list = Cbor::Map(vec![
        (Cbor::Text("bits".to_owned()), Cbor::Integer(1.into())),
        (
            Cbor::Text("lst".to_owned()),
            Cbor::Bytes(zlib(&one_bit_lst(revoked))),
        ),
    ]);
    let claims = Cbor::Map(vec![
        (Cbor::Integer(2.into()), Cbor::Text(sub.to_owned())), // sub
        (Cbor::Integer(6.into()), Cbor::Integer((now - 100).into())), // iat
        (Cbor::Integer(4.into()), Cbor::Integer((now + 1_000).into())), // exp
        (Cbor::Integer(65_533.into()), status_list),           // status_list (provisional key)
    ]);
    let mut payload = Vec::new();
    ciborium::into_writer(&claims, &mut payload).unwrap();
    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::ES256)
        .value(16, Cbor::Text("application/statuslist+cwt".to_owned()))
        .build();
    let unprotected = HeaderBuilder::new()
        .value(33, Cbor::Bytes(leaf_der.to_vec()))
        .build();
    CoseSign1Builder::new()
        .protected(protected)
        .unprotected(unprotected)
        .payload(payload)
        .create_signature(&[], |tbs| {
            let sig: Signature = sk.sign(tbs);
            sig.to_bytes().as_slice().to_vec()
        })
        .build()
        .to_tagged_vec()
        .unwrap()
}

// --- SD-JWT VC -----------------------------------------------------------------------------------

#[test]
fn sd_jwt_status_list_valid_bit_verifies_in_core() {
    // The issuer signs its OWN status list (same-issuer path): the token's `x5c` leaf equals the
    // credential's `x5c` issuer leaf, so the key is resolved from that already-verified leaf. Entry 0
    // is VALID (bit 0) → the in-core outcome is `Good` → the credential is VALID.
    let sd_jwt = mint_sd_jwt_with_status(ISSUER_KEY_PK8, ISSUER_CERT_DER, 0, STATUS_LIST_URI);
    let presentation = sd_jwt.presentation();
    let token = mint_status_jwt(ISSUER_KEY_PK8, ISSUER_CERT_DER, STATUS_LIST_URI, NOW, false);
    let status_tokens = tokens(STATUS_LIST_URI, token);
    let ctx = VerifyContext {
        now_unix: NOW,
        status_tokens: &status_tokens,
        // The positional seam says Unavailable — the in-core authenticated token MUST override it.
        statuses: &[StatusOutcome::Unavailable],
        ..VerifyContext::default()
    };
    let result = verify(
        &Presentation::SdJwtVc(&presentation),
        &VerificationPolicy::default(),
        &sd_jwt_anchors(),
        &ctx,
        None,
    );
    assert!(
        result.valid,
        "a VALID (bit 0) in-core status list token must verify, overriding the positional Unavailable: {:?}",
        result.reasons
    );
}

#[test]
fn sd_jwt_status_list_revoked_bit_is_rejected_in_core() {
    // Entry 0 is INVALID (bit 1) in the signed token → the in-core outcome is `Revoked` → REJECTED,
    // even though the positional seam says the credential is current (Good). The authenticated token
    // is authoritative.
    let sd_jwt = mint_sd_jwt_with_status(ISSUER_KEY_PK8, ISSUER_CERT_DER, 0, STATUS_LIST_URI);
    let presentation = sd_jwt.presentation();
    let token = mint_status_jwt(ISSUER_KEY_PK8, ISSUER_CERT_DER, STATUS_LIST_URI, NOW, true);
    let status_tokens = tokens(STATUS_LIST_URI, token);
    let ctx = VerifyContext {
        now_unix: NOW,
        status_tokens: &status_tokens,
        statuses: &[StatusOutcome::Good],
        ..VerifyContext::default()
    };
    let result = verify(
        &Presentation::SdJwtVc(&presentation),
        &VerificationPolicy::default(),
        &sd_jwt_anchors(),
        &ctx,
        None,
    );
    assert!(!result.valid);
    assert_eq!(result.reasons, vec![ReasonCode::Revoked]);
}

#[test]
fn sd_jwt_status_token_for_wrong_uri_is_unresolved_and_fails_closed() {
    // A signed token is supplied, but under a DIFFERENT map key than the credential's declared list
    // URI, so the lookup by the credential's URI misses. The credential DECLARES a Token Status List
    // and the positional outcome is the default NoStatus (no host pre-resolution) — so the declared
    // list is UNRESOLVED → fail closed to StatusUnavailable (a declared-but-unresolved status must NOT
    // read as VALID). Contrast the pre-resolved-positional test below, where the host resolved it.
    let sd_jwt = mint_sd_jwt_with_status(ISSUER_KEY_PK8, ISSUER_CERT_DER, 0, STATUS_LIST_URI);
    let presentation = sd_jwt.presentation();
    let token = mint_status_jwt(ISSUER_KEY_PK8, ISSUER_CERT_DER, STATUS_LIST_URI, NOW, true);
    let status_tokens = tokens("https://issuer.example/statuslists/OTHER", token);
    let ctx = VerifyContext {
        now_unix: NOW,
        status_tokens: &status_tokens,
        // Default NoStatus positional outcome — the credential has no host-pre-resolved revocation.
        ..VerifyContext::default()
    };
    let result = verify(
        &Presentation::SdJwtVc(&presentation),
        &VerificationPolicy::default(),
        &sd_jwt_anchors(),
        &ctx,
        None,
    );
    assert!(
        !result.valid,
        "an unresolved declared status list must fail closed"
    );
    assert_eq!(result.reasons, vec![ReasonCode::StatusUnavailable]);
}

#[test]
fn sd_jwt_declared_status_with_a_host_pre_resolved_positional_outcome_is_honored() {
    // The credential declares a Token Status List but NO signed token is supplied for its URI; the host
    // instead PRE-RESOLVED the outcome positionally to Good (e.g. its own out-of-band check). A resolved
    // positional outcome (anything but the NoStatus default) is honored, so this verifies VALID — only
    // the NoStatus default means "declared but unresolved" and fails closed.
    let sd_jwt = mint_sd_jwt_with_status(ISSUER_KEY_PK8, ISSUER_CERT_DER, 0, STATUS_LIST_URI);
    let presentation = sd_jwt.presentation();
    let empty = BTreeMap::new();
    let ctx = VerifyContext {
        now_unix: NOW,
        status_tokens: &empty,
        statuses: &[StatusOutcome::Good],
        ..VerifyContext::default()
    };
    let result = verify(
        &Presentation::SdJwtVc(&presentation),
        &VerificationPolicy::default(),
        &sd_jwt_anchors(),
        &ctx,
        None,
    );
    assert!(
        result.valid,
        "a host-pre-resolved Good positional outcome is honored for a declared list with no token"
    );
}

#[test]
fn sd_jwt_malformed_status_list_fails_closed_over_a_positional_good() {
    // The issuer-signed `status.status_list` object IS present but malformed (a `uri`, no `idx`). A
    // present-but-uninterpretable status reference MUST NOT fall through to the host-supplied positional
    // `Good`: the credential declared a revocation mechanism the core cannot evaluate, so it fails closed
    // to StatusUntrusted (it named a mechanism that failed to resolve — the adversarial-leaning reason,
    // Group 2; SC-002). Contrast the well-formed-declared + positional-Good case above, which IS honored
    // — this proves the malformed case is treated distinctly (not as "no status").
    let sd_jwt =
        mint_sd_jwt_with_malformed_status(ISSUER_KEY_PK8, ISSUER_CERT_DER, STATUS_LIST_URI);
    let presentation = sd_jwt.presentation();
    let empty = BTreeMap::new();
    let ctx = VerifyContext {
        now_unix: NOW,
        status_tokens: &empty,
        // The host says the credential is current — but a malformed declared reference overrides it.
        statuses: &[StatusOutcome::Good],
        ..VerifyContext::default()
    };
    let result = verify(
        &Presentation::SdJwtVc(&presentation),
        &VerificationPolicy::default(),
        &sd_jwt_anchors(),
        &ctx,
        None,
    );
    assert!(
        !result.valid,
        "a present-but-malformed status_list must fail closed, not verify VALID off a positional Good"
    );
    assert_eq!(result.reasons, vec![ReasonCode::StatusUntrusted]);
}

#[test]
fn sd_jwt_status_token_signed_by_untrusted_key_is_rejected() {
    // The token is signed by an UNTRUSTED key (wrong-issuer), carrying the wrong-issuer cert as its
    // `x5c` leaf. Same-issuer key reuse fails (leaf ≠ the credential's issuer leaf); the distinct
    // status-signer path fails too (the exact-pin test anchors authorize no distinct signer). So the
    // signer is NOT authorized → the token fails in-core authentication → the credential is REJECTED
    // with `StatusUntrusted` (a supplied token that failed to authenticate — Group 2), NEVER accepted.
    let sd_jwt = mint_sd_jwt_with_status(ISSUER_KEY_PK8, ISSUER_CERT_DER, 0, STATUS_LIST_URI);
    let presentation = sd_jwt.presentation();
    let token = mint_status_jwt(
        WRONG_ISSUER_KEY_PK8,
        WRONG_ISSUER_CERT_DER,
        STATUS_LIST_URI,
        NOW,
        false, // even a "valid" bit must NOT rescue an unauthenticated token
    );
    let status_tokens = tokens(STATUS_LIST_URI, token);
    let ctx = VerifyContext {
        now_unix: NOW,
        status_tokens: &status_tokens,
        statuses: &[StatusOutcome::Good],
        ..VerifyContext::default()
    };
    let result = verify(
        &Presentation::SdJwtVc(&presentation),
        &VerificationPolicy::default(),
        &sd_jwt_anchors(),
        &ctx,
        None,
    );
    assert!(!result.valid);
    assert_eq!(result.reasons, vec![ReasonCode::StatusUntrusted]);
}

// --- Same-issuer authorization by KEY (B3): kid-only + rolled-over cert -----------------------------
//
// The same-issuer path is keyed on the issuer's PUBLIC KEY, not the token's cert-DER bytes. Two shapes
// a routine deployment produces — a `kid`-only token (no embedded chain) and a rolled-over issuer cert
// (a new certificate DER carrying the SAME key at renewal) — were both false-rejected by the previous
// cert-DER byte-equality (B3). These prove the key-based authorization accepts them (issuer-signed →
// VALID), while the untrusted-key negative above still rejects (the token must be signed by that key).

/// The rolled-over issuer certificate: a DIFFERENT DER than `sdjwt-issuer.cert.der` but carrying the
/// SAME P-256 public key (a renewal roll-over). Used to prove same-issuer authorization is by KEY.
const SDJWT_ISSUER_ROLLOVER_CERT_DER: &[u8] =
    include_bytes!("../../../../tests/fixtures/attestation/sdjwt-issuer-rollover.cert.der");

/// Mint a `statuslist+jwt` compact-JWS Status List Token signed by `signer_pk8` carrying only a `kid`
/// header (NO `x5c` chain), `sub` bound to the list URI, fresh `iat`/`exp`, entry 0 per `revoked`.
fn mint_status_jwt_kid_only(
    signer_pk8: &[u8],
    kid: &str,
    sub: &str,
    now: i64,
    revoked: bool,
) -> Vec<u8> {
    use base64ct::{Base64UrlUnpadded, Encoding as _};
    use p256::ecdsa::{signature::Signer as _, Signature, SigningKey};
    use pkcs8::DecodePrivateKey as _;

    let sk = SigningKey::from_pkcs8_der(signer_pk8).expect("valid PKCS#8 P-256 key");
    let header = serde_json::json!({ "alg": "ES256", "typ": "statuslist+jwt", "kid": kid });
    let payload = serde_json::json!({
        "sub": sub,
        "iat": now - 100,
        "exp": now + 1_000,
        "status_list": {
            "bits": 1,
            "lst": Base64UrlUnpadded::encode_string(&zlib(&one_bit_lst(revoked))),
        },
    });
    let h = Base64UrlUnpadded::encode_string(&serde_json::to_vec(&header).unwrap());
    let p = Base64UrlUnpadded::encode_string(&serde_json::to_vec(&payload).unwrap());
    let signing_input = format!("{h}.{p}");
    let sig: Signature = sk.sign(signing_input.as_bytes());
    let s = Base64UrlUnpadded::encode_string(sig.to_bytes().as_slice());
    format!("{signing_input}.{s}").into_bytes()
}

#[test]
fn sd_jwt_status_kid_only_token_from_the_issuer_key_verifies_in_core() {
    // B3 (kid-only): a status token with NO x5chain (a bare `kid`), signed by the credential's OWN
    // issuer key. Same-issuer authorization resolves the issuer key from the verified issuer leaf and
    // authorizes it for a chain-less token — which then verifies iff the issuer's key produced the
    // signature (the `kid` grants nothing on its own). Entry 0 is VALID → Good → VALID, overriding the
    // positional Unavailable. BEFORE the fix the empty-x5chain `split_first().ok_or(())?` rejected it
    // outright → StatusUnavailable → INVALID.
    let sd_jwt = mint_sd_jwt_with_status(ISSUER_KEY_PK8, ISSUER_CERT_DER, 0, STATUS_LIST_URI);
    let presentation = sd_jwt.presentation();
    let token =
        mint_status_jwt_kid_only(ISSUER_KEY_PK8, "issuer-key-1", STATUS_LIST_URI, NOW, false);
    let status_tokens = tokens(STATUS_LIST_URI, token);
    let ctx = VerifyContext {
        now_unix: NOW,
        status_tokens: &status_tokens,
        statuses: &[StatusOutcome::Unavailable],
        ..VerifyContext::default()
    };
    let result = verify(
        &Presentation::SdJwtVc(&presentation),
        &VerificationPolicy::default(),
        &sd_jwt_anchors(),
        &ctx,
        None,
    );
    assert!(
        result.valid,
        "a kid-only issuer-signed status token must verify (same-issuer by KEY): {:?}",
        result.reasons
    );
}

#[test]
fn sd_jwt_status_token_from_a_rolled_over_issuer_cert_verifies_in_core() {
    // B3 (roll-over): the token's x5chain leaf is a DIFFERENT certificate DER than the credential's
    // issuer leaf but carries the SAME public key (a routine renewal), and the token is signed by the
    // issuer key. Same-issuer authorization is by KEY, so the leaf-key == issuer-key match authorizes it
    // → Good → VALID. BEFORE the fix the cert-DER byte-equality missed (different DER) → distinct path →
    // the exact-pin test anchors authorize no distinct signer → StatusUnavailable → INVALID.
    let sd_jwt = mint_sd_jwt_with_status(ISSUER_KEY_PK8, ISSUER_CERT_DER, 0, STATUS_LIST_URI);
    let presentation = sd_jwt.presentation();
    // Signed by the ISSUER key, but the x5c leaf is the rolled-over cert (same key, different DER).
    let token = mint_status_jwt(
        ISSUER_KEY_PK8,
        SDJWT_ISSUER_ROLLOVER_CERT_DER,
        STATUS_LIST_URI,
        NOW,
        false,
    );
    let status_tokens = tokens(STATUS_LIST_URI, token);
    let ctx = VerifyContext {
        now_unix: NOW,
        status_tokens: &status_tokens,
        statuses: &[StatusOutcome::Unavailable],
        ..VerifyContext::default()
    };
    let result = verify(
        &Presentation::SdJwtVc(&presentation),
        &VerificationPolicy::default(),
        &sd_jwt_anchors(),
        &ctx,
        None,
    );
    assert!(
        result.valid,
        "a rolled-over-cert (same key, new DER) issuer-signed token must verify: {:?}",
        result.reasons
    );
}

// --- Distinct status-signer authorization (B1 root binding + B2 exact EKU) --------------------------
//
// A status signer whose key differs from the issuer's is authorized ONLY if it (a) chains to the
// credential's issuer's SAME SPECIFIC ROOT and (b) bears EXACTLY the placeholder status-signing EKU.
// These use a chain-validating source (the exact-pin test anchors authorize no distinct signer) and a
// 2026 instant inside the sdjwt-issuer + minted-signer validity windows (the shared test `NOW` predates
// the fixture PKI, which only the validity-skipping `StaticTestAnchors` tolerates).

/// A distinct status signer that chains to `ca-iaca` and bears EXACTLY the placeholder status-signing
/// EKU (`1.3.6.1.5.5.7.3.0`). (`CA_IACA` — the shared root — is defined at the top of this module.)
const STATUS_SIGNER_CERT_DER: &[u8] =
    include_bytes!("../../../../tests/fixtures/attestation/status-signer.cert.der");
const STATUS_SIGNER_KEY_PK8: &[u8] =
    include_bytes!("../../../../tests/fixtures/attestation/status-signer.key.pk8");
/// A distinct signer that chains to `ca-iaca` but bears the FOREIGN `serverAuth` EKU
/// (`1.3.6.1.5.5.7.3.1`) — the B2 exact-OID guard must reject it.
const STATUS_SIGNER_SERVERAUTH_CERT_DER: &[u8] =
    include_bytes!("../../../../tests/fixtures/attestation/status-signer-serverauth.cert.der");
const STATUS_SIGNER_SERVERAUTH_KEY_PK8: &[u8] =
    include_bytes!("../../../../tests/fixtures/attestation/status-signer-serverauth.key.pk8");
/// A distinct signer with the placeholder EKU that chains to a DIFFERENT root (`attacker-ca`) — the B1
/// same-root binding must reject it (no cross-issuer un-revocation).
const STATUS_SIGNER_OTHERROOT_CERT_DER: &[u8] =
    include_bytes!("../../../../tests/fixtures/attestation/status-signer-otherroot.cert.der");
const STATUS_SIGNER_OTHERROOT_KEY_PK8: &[u8] =
    include_bytes!("../../../../tests/fixtures/attestation/status-signer-otherroot.key.pk8");
/// The DIFFERENT root the other-root signer chains to (a real, CA-constrained root in the anchor set).
const ATTACKER_CA: &[u8] =
    include_bytes!("../../../../tests/fixtures/attestation/attacker-ca.cert.der");
/// A verification/issuance instant inside BOTH the `sdjwt-issuer` window (2026-06-30..2027-09-28) and
/// the minted status-signer windows: 2026-09-01. Required because a chain-validating source enforces
/// the leaf validity window (unlike `StaticTestAnchors`), and the shared `NOW` (2025) predates the PKI.
const STATUS_NOW_2026: i64 = 1_788_220_800;

/// Mint an SD-JWT VC signed by the trusted `sdjwt-issuer` (chains to `ca-iaca`) with a caller-chosen
/// validity window AND an issuer-signed Token Status List reference, so the distinct-signer tests can
/// verify it under a chain-validating source at a 2026 instant (the shared `mint_sd_jwt_with_status`
/// hard-codes the 2025 `NOW` window; the `crate::sdjwtvc` helpers must not be modified for this task).
fn mint_windowed_status_sd_jwt(nbf: i64, exp: i64, uri: &str) -> sd_jwt_payload::SdJwt {
    use base64ct::Encoding as _;
    use sd_jwt_payload::SdJwtBuilder;
    let cert_b64 = base64ct::Base64::encode_string(ISSUER_CERT_DER);
    let claims = serde_json::json!({
        "iss": "https://issuer.example/cb",
        "vct": "urn:eudi:pid:1",
        "given_name": "Ada",
        "family_name": "Lovelace",
        "nbf": nbf,
        "exp": exp,
        "status": { "status_list": { "idx": 0, "uri": uri } },
    });
    let signer = Es256Signer::from_pkcs8(ISSUER_KEY_PK8);
    block_on(
        SdJwtBuilder::new_with_hasher(claims, Sha2Hasher)
            .expect("builder")
            .header("x5c", serde_json::json!([cert_b64]))
            .header("typ", serde_json::json!("dc+sd-jwt"))
            .make_concealable("/family_name")
            .expect("concealable")
            .require_key_binding(holder_cnf())
            .finish(&signer, "ES256"),
    )
    .expect("issuer signing succeeds")
}

#[test]
fn sd_jwt_status_token_from_a_distinct_signer_chaining_to_the_issuer_root_verifies() {
    // B1 (distinct signer ACCEPT): a token signed by a DISTINCT cert (its own key ≠ the issuer key) that
    // (i) chains to the SAME ROOT (ca-iaca) as the credential's issuer AND (ii) bears EXACTLY the
    // placeholder status-signing EKU → authorized → Good → VALID (overriding the positional Unavailable).
    // BEFORE the fix the same-root check compared the signer leaf against the issuer LEAF (never the
    // root) in the distinct branch (only reached when they differ) → always false → StatusUnavailable →
    // INVALID (the distinct-signer feature was 100% inert).
    let sd_jwt = mint_windowed_status_sd_jwt(
        STATUS_NOW_2026 - 1_000_000,
        STATUS_NOW_2026 + 1_000_000,
        STATUS_LIST_URI,
    );
    let presentation = sd_jwt.presentation();
    let token = mint_status_jwt(
        STATUS_SIGNER_KEY_PK8,
        STATUS_SIGNER_CERT_DER,
        STATUS_LIST_URI,
        STATUS_NOW_2026,
        false,
    );
    let status_tokens = tokens(STATUS_LIST_URI, token);
    let anchors = ChainValidatingAnchors::new(STATUS_NOW_2026).trust(
        IssuerRole::Pid,
        Format::SdJwtVc,
        CA_IACA,
    );
    let ctx = VerifyContext {
        now_unix: STATUS_NOW_2026,
        role: IssuerRole::Pid,
        status_tokens: &status_tokens,
        statuses: &[StatusOutcome::Unavailable],
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
        "a distinct status signer chaining to the issuer's root with the placeholder EKU must verify: {:?}",
        result.reasons
    );
}

#[test]
fn sd_jwt_status_token_from_a_distinct_signer_with_a_foreign_eku_is_rejected() {
    // B2 guard: a distinct signer that chains to the SAME root (ca-iaca) but bears the FOREIGN
    // `serverAuth` EKU (1.3.6.1.5.5.7.3.1) instead of the placeholder status-signing OID. The exact-OID
    // EKU gate rejects the signer → the supplied token fails authentication → StatusUntrusted (Group 2).
    // The previous `starts_with("1.3.6.1.5.5.7.3.")` prefix
    // match (B2) would have ACCEPTED serverAuth once the root binding was fixed — this test proves that
    // hole is closed (never accepted off a TLS/other-purpose cert under a shared root).
    let sd_jwt = mint_windowed_status_sd_jwt(
        STATUS_NOW_2026 - 1_000_000,
        STATUS_NOW_2026 + 1_000_000,
        STATUS_LIST_URI,
    );
    let presentation = sd_jwt.presentation();
    let token = mint_status_jwt(
        STATUS_SIGNER_SERVERAUTH_KEY_PK8,
        STATUS_SIGNER_SERVERAUTH_CERT_DER,
        STATUS_LIST_URI,
        STATUS_NOW_2026,
        false, // even a "valid" bit must not rescue a signer with the wrong purpose
    );
    let status_tokens = tokens(STATUS_LIST_URI, token);
    let anchors = ChainValidatingAnchors::new(STATUS_NOW_2026).trust(
        IssuerRole::Pid,
        Format::SdJwtVc,
        CA_IACA,
    );
    let ctx = VerifyContext {
        now_unix: STATUS_NOW_2026,
        role: IssuerRole::Pid,
        status_tokens: &status_tokens,
        statuses: &[StatusOutcome::Good],
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
        !result.valid,
        "a distinct signer with a foreign (serverAuth) EKU must be rejected"
    );
    assert_eq!(result.reasons, vec![ReasonCode::StatusUntrusted]);
}

#[test]
fn sd_jwt_status_token_from_a_distinct_signer_chaining_to_a_different_root_is_rejected() {
    // B1 (root-binding proof): a distinct signer WITH the placeholder EKU that chains to a DIFFERENT
    // root (attacker-ca) than the credential's issuer (ca-iaca). Both roots are trusted for (Pid,
    // SdJwtVc), so the signer DOES chain (to attacker-ca) and carries the correct EKU — yet its matched
    // root ≠ the credential's root, so the same-root binding rejects it → StatusUntrusted (a supplied
    // token that failed signer authorization — Group 2). This is the
    // cross-issuer un-revocation the leaf/root confusion (B1) would have permitted once the branch was
    // reachable. The credential issuer still resolves to ca-iaca (its own issuing root).
    let sd_jwt = mint_windowed_status_sd_jwt(
        STATUS_NOW_2026 - 1_000_000,
        STATUS_NOW_2026 + 1_000_000,
        STATUS_LIST_URI,
    );
    let presentation = sd_jwt.presentation();
    let token = mint_status_jwt(
        STATUS_SIGNER_OTHERROOT_KEY_PK8,
        STATUS_SIGNER_OTHERROOT_CERT_DER,
        STATUS_LIST_URI,
        STATUS_NOW_2026,
        false,
    );
    let status_tokens = tokens(STATUS_LIST_URI, token);
    // Trust BOTH roots for (Pid, SdJwtVc): the signer chains (to attacker-ca), but to the WRONG root.
    let anchors = ChainValidatingAnchors::new(STATUS_NOW_2026)
        .trust(IssuerRole::Pid, Format::SdJwtVc, CA_IACA)
        .trust(IssuerRole::Pid, Format::SdJwtVc, ATTACKER_CA);
    let ctx = VerifyContext {
        now_unix: STATUS_NOW_2026,
        role: IssuerRole::Pid,
        status_tokens: &status_tokens,
        statuses: &[StatusOutcome::Good],
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
        !result.valid,
        "a distinct signer chaining to a DIFFERENT root than the issuer must be rejected"
    );
    assert_eq!(result.reasons, vec![ReasonCode::StatusUntrusted]);
}

// --- mdoc ----------------------------------------------------------------------------------------

#[test]
fn mdoc_status_list_valid_bit_verifies_in_core() {
    // The mdoc DS signs its own status list (same-issuer path): the CWT's `x5chain` leaf equals the
    // verified DS leaf. Entry 0 is VALID (bit 0) → `Good` → VALID, overriding the positional Unavailable.
    let response = MdocBuilder::new()
        .status_reference(0, STATUS_LIST_URI)
        .build();
    let transcript = default_session_transcript();
    let token = mint_status_cwt(
        MDOC_DS_KEY_PK8,
        mdoc_ds_cert_der(),
        STATUS_LIST_URI,
        MDOC_NOW,
        false,
    );
    let status_tokens = tokens(STATUS_LIST_URI, token);
    let ctx = VerifyContext {
        now_unix: MDOC_NOW,
        role: IssuerRole::Pid,
        session_transcript: Some(&transcript),
        status_tokens: &status_tokens,
        statuses: &[StatusOutcome::Unavailable],
        ..VerifyContext::default()
    };
    let result = verify(
        &Presentation::Mdoc {
            device_response: &response,
            audience: None,
        },
        &VerificationPolicy::default(),
        &mdoc_anchors(),
        &ctx,
        None,
    );
    assert!(
        result.valid,
        "a VALID (bit 0) in-core mdoc status list token must verify: {:?}",
        result.reasons
    );
}

#[test]
fn mdoc_status_list_revoked_bit_is_rejected_in_core() {
    // Entry 0 is INVALID (bit 1) in the signed CWT → `Revoked` → REJECTED, overriding a positional Good.
    let response = MdocBuilder::new()
        .status_reference(0, STATUS_LIST_URI)
        .build();
    let transcript = default_session_transcript();
    let token = mint_status_cwt(
        MDOC_DS_KEY_PK8,
        mdoc_ds_cert_der(),
        STATUS_LIST_URI,
        MDOC_NOW,
        true,
    );
    let status_tokens = tokens(STATUS_LIST_URI, token);
    let ctx = VerifyContext {
        now_unix: MDOC_NOW,
        role: IssuerRole::Pid,
        session_transcript: Some(&transcript),
        status_tokens: &status_tokens,
        statuses: &[StatusOutcome::Good],
        ..VerifyContext::default()
    };
    let result = verify(
        &Presentation::Mdoc {
            device_response: &response,
            audience: None,
        },
        &VerificationPolicy::default(),
        &mdoc_anchors(),
        &ctx,
        None,
    );
    assert!(!result.valid);
    assert_eq!(result.reasons, vec![ReasonCode::Revoked]);
}

#[test]
fn mdoc_two_documents_referencing_the_same_status_uri_verify() {
    // The "replay one credential twice" shape: two byte-identical valid documents BOTH referencing the
    // same status-list URI. The shared list authenticates for each document and the identical documents
    // merge cleanly, so the verdict is unchanged (VALID). Entry 0 is VALID (bit 0) in the same-issuer CWT.
    let response = MdocBuilder::new()
        .status_reference(0, STATUS_LIST_URI)
        .append_duplicate_document()
        .build();
    let transcript = default_session_transcript();
    let token = mint_status_cwt(
        MDOC_DS_KEY_PK8,
        mdoc_ds_cert_der(),
        STATUS_LIST_URI,
        MDOC_NOW,
        false,
    );
    let status_tokens = tokens(STATUS_LIST_URI, token);
    let ctx = VerifyContext {
        now_unix: MDOC_NOW,
        role: IssuerRole::Pid,
        session_transcript: Some(&transcript),
        status_tokens: &status_tokens,
        // One positional entry per document; both Unavailable, so the in-core authenticated token (shared
        // per URI) must override BOTH to Good.
        statuses: &[StatusOutcome::Unavailable, StatusOutcome::Unavailable],
        ..VerifyContext::default()
    };
    let result = verify(
        &Presentation::Mdoc {
            device_response: &response,
            audience: None,
        },
        &VerificationPolicy::default(),
        &mdoc_anchors(),
        &ctx,
        None,
    );
    assert!(
        result.valid,
        "a two-document response referencing one status URI must verify (clean merge): {:?}",
        result.reasons
    );
}

#[test]
fn mdoc_malformed_status_list_fails_closed_over_a_positional_good() {
    // The issuer-signed MSO `status.status_list` object IS present but malformed (an `idx`, no `uri`). A
    // present-but-uninterpretable reference MUST fail closed to StatusUntrusted (a declared mechanism the
    // core cannot evaluate — Group 2), never falling through to the host-supplied positional `Good`
    // (SC-002 — the mdoc mirror of the SD-JWT case).
    let response = MdocBuilder::new().malformed_status_reference().build();
    let transcript = default_session_transcript();
    let ctx = VerifyContext {
        now_unix: MDOC_NOW,
        role: IssuerRole::Pid,
        session_transcript: Some(&transcript),
        statuses: &[StatusOutcome::Good],
        ..VerifyContext::default()
    };
    let result = verify(
        &Presentation::Mdoc {
            device_response: &response,
            audience: None,
        },
        &VerificationPolicy::default(),
        &mdoc_anchors(),
        &ctx,
        None,
    );
    assert!(
        !result.valid,
        "a present-but-malformed mdoc status_list must fail closed, not verify off a positional Good"
    );
    assert_eq!(result.reasons, vec![ReasonCode::StatusUntrusted]);
}

#[test]
fn mdoc_status_token_signed_by_untrusted_key_is_rejected() {
    // The CWT is signed by the untrusted wrong-issuer key (its own cert as `x5chain` leaf), distinct
    // from the credential's DS leaf. Neither authorization path clears (same-issuer mismatch; the
    // exact-pin anchors authorize no distinct signer) → the supplied token fails authentication →
    // `StatusUntrusted` (Group 2), never accepted — even with a "valid" bit.
    let response = MdocBuilder::new()
        .status_reference(0, STATUS_LIST_URI)
        .build();
    let transcript = default_session_transcript();
    let token = mint_status_cwt(
        WRONG_ISSUER_KEY_PK8,
        wrong_issuer_cert_der(),
        STATUS_LIST_URI,
        MDOC_NOW,
        false,
    );
    let status_tokens = tokens(STATUS_LIST_URI, token);
    let ctx = VerifyContext {
        now_unix: MDOC_NOW,
        role: IssuerRole::Pid,
        session_transcript: Some(&transcript),
        status_tokens: &status_tokens,
        statuses: &[StatusOutcome::Good],
        ..VerifyContext::default()
    };
    let result = verify(
        &Presentation::Mdoc {
            device_response: &response,
            audience: None,
        },
        &VerificationPolicy::default(),
        &mdoc_anchors(),
        &ctx,
        None,
    );
    assert!(!result.valid);
    assert_eq!(result.reasons, vec![ReasonCode::StatusUntrusted]);
}
