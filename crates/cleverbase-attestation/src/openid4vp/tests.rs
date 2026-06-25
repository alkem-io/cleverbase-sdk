//! OpenID4VP binding tests (T010 — written test-first against the T015 verifier).
//!
//! A presentation correctly bound to an SDK-issued request verifies VALID; the same presentation
//! **replayed** (built for a stale/different nonce) or built for a **different audience** is INVALID
//! with the specific reason ([`ReasonCode::Replay`] / [`ReasonCode::WrongAudience`]) — for **both**
//! formats (SC-008). Also covers `build_request` freshness (a distinct nonce per call).

use base64ct::{Base64UrlUnpadded, Encoding as _};

use super::{
    build_request, oid4vp_handover_transcript, verify_response, Dcql, MdocVpToken, NonceSource,
    PresentationRequest, VpToken,
};
use crate::mdoc::test_issuer::MdocBuilder;
use crate::sdjwtvc::test_issuer::{
    attach_kb_jwt, mint_sd_jwt, HOLDER_KEY_PK8, ISSUER_CERT_DER, ISSUER_KEY_PK8, NOW,
};
use crate::status::StatusOutcome;
use crate::trust::StaticTestAnchors;
use crate::types::{Format, IssuerRole, ReasonCode, VerificationPolicy};

const AUDIENCE: &str = "https://verifier.example/cb";
const WRONG_AUDIENCE: &str = "https://attacker.example/evil";

/// A deterministic [`NonceSource`] for the tests: an incrementing counter, so each `build_request`
/// gets a distinct nonce (the freshness invariant) without a real CSPRNG in the offline suite.
#[derive(Default)]
struct CountingNonces {
    counter: u64,
}

impl NonceSource for CountingNonces {
    fn fresh_nonce(&mut self) -> Vec<u8> {
        self.counter += 1;
        // 16 bytes: the counter in the low 8, zero-padded — distinct + unpredictable enough for a
        // deterministic test (production wires a CSPRNG).
        let mut nonce = vec![0u8; 8];
        nonce.extend_from_slice(&self.counter.to_be_bytes());
        nonce
    }
}

/// A request fixed to a given audience + nonce (so the bound/replay/wrong-audience cases are
/// constructed deterministically against a known nonce).
fn request_with(audience: &str, nonce: &[u8]) -> PresentationRequest {
    PresentationRequest {
        dcql: Dcql::from_json(r#"{"credentials":[]}"#),
        nonce: nonce.to_vec(),
        audience: audience.to_owned(),
    }
}

fn anchors_sd_jwt() -> StaticTestAnchors {
    StaticTestAnchors::new().trust(IssuerRole::Pid, Format::SdJwtVc, ISSUER_CERT_DER)
}

fn anchors_mdoc() -> StaticTestAnchors {
    StaticTestAnchors::new().trust(
        IssuerRole::Pid,
        Format::Mdoc,
        crate::mdoc::test_issuer::mdoc_ds_cert_der(),
    )
}

const MDOC_NOW: i64 = 1_717_200_000; // inside the mdoc test issuer's default window.

// =================================================================================================
// build_request — fresh nonce per request.
// =================================================================================================

#[test]
fn build_request_draws_a_fresh_nonce_each_call() {
    let mut nonces = CountingNonces::default();
    let dcql = Dcql::from_json(r#"{"credentials":[{"id":"pid"}]}"#);
    let r1 = build_request(&mut nonces, dcql.clone(), AUDIENCE);
    let r2 = build_request(&mut nonces, dcql.clone(), AUDIENCE);
    assert_ne!(r1.nonce, r2.nonce, "each request MUST carry a fresh nonce");
    assert_eq!(r1.audience, AUDIENCE);
    assert_eq!(r1.dcql, dcql);
}

#[test]
fn nonce_b64_round_trips() {
    let req = request_with(AUDIENCE, &[1, 2, 3, 4]);
    assert_eq!(
        Base64UrlUnpadded::decode_vec(&req.nonce_b64()).unwrap(),
        vec![1, 2, 3, 4]
    );
}

// =================================================================================================
// SD-JWT VC binding.
// =================================================================================================

/// Mint an SD-JWT VC presentation whose KB-JWT is bound to `(aud, nonce_b64)`.
fn sd_jwt_presentation(aud: &str, nonce_b64: &str) -> String {
    let sd_jwt = mint_sd_jwt(ISSUER_KEY_PK8, ISSUER_CERT_DER);
    attach_kb_jwt(sd_jwt, HOLDER_KEY_PK8, aud, nonce_b64)
}

#[test]
fn sd_jwt_bound_to_the_issued_request_is_valid() {
    let request = request_with(AUDIENCE, &[9u8; 16]);
    let presentation = sd_jwt_presentation(AUDIENCE, &request.nonce_b64());
    let anchors = anchors_sd_jwt();
    let result = verify_response(
        &VpToken::SdJwtVc(&presentation),
        &request,
        &VerificationPolicy::default(),
        &anchors,
        NOW,
        IssuerRole::Pid,
        StatusOutcome::NoStatus,
    );
    assert!(
        result.valid,
        "bound presentation must be VALID: {:?}",
        result.reasons
    );
    assert!(result.disclosed_attributes.contains_key("given_name"));
}

#[test]
fn sd_jwt_replayed_with_a_stale_nonce_is_replay() {
    // The holder built the KB-JWT for an OLD nonce; the verifier issued a FRESH one.
    let stale = Base64UrlUnpadded::encode_string(&[0xAAu8; 16]);
    let presentation = sd_jwt_presentation(AUDIENCE, &stale);
    let request = request_with(AUDIENCE, &[0xBBu8; 16]); // fresh nonce ≠ stale
    let anchors = anchors_sd_jwt();
    let result = verify_response(
        &VpToken::SdJwtVc(&presentation),
        &request,
        &VerificationPolicy::default(),
        &anchors,
        NOW,
        IssuerRole::Pid,
        StatusOutcome::NoStatus,
    );
    assert!(!result.valid);
    assert_eq!(result.reasons, vec![ReasonCode::Replay]);
}

#[test]
fn sd_jwt_built_for_a_different_audience_is_wrong_audience() {
    let request = request_with(AUDIENCE, &[7u8; 16]);
    // The holder addressed the presentation to a DIFFERENT verifier.
    let presentation = sd_jwt_presentation(WRONG_AUDIENCE, &request.nonce_b64());
    let anchors = anchors_sd_jwt();
    let result = verify_response(
        &VpToken::SdJwtVc(&presentation),
        &request,
        &VerificationPolicy::default(),
        &anchors,
        NOW,
        IssuerRole::Pid,
        StatusOutcome::NoStatus,
    );
    assert!(!result.valid);
    assert_eq!(result.reasons, vec![ReasonCode::WrongAudience]);
}

#[test]
fn sd_jwt_without_a_kb_jwt_is_missing_request_binding() {
    // An issuer-only presentation (no KB-JWT) cannot be bound to a request.
    let sd_jwt = mint_sd_jwt(ISSUER_KEY_PK8, ISSUER_CERT_DER);
    let presentation = sd_jwt.presentation();
    let request = request_with(AUDIENCE, &[1u8; 16]);
    let anchors = anchors_sd_jwt();
    let result = verify_response(
        &VpToken::SdJwtVc(&presentation),
        &request,
        &VerificationPolicy::default(),
        &anchors,
        NOW,
        IssuerRole::Pid,
        StatusOutcome::NoStatus,
    );
    assert!(!result.valid);
    assert_eq!(result.reasons, vec![ReasonCode::MissingRequestBinding]);
}

// =================================================================================================
// mdoc binding.
// =================================================================================================

/// Mint an mdoc `vp_token` whose `DeviceAuth` is bound to the OID4VP handover for `(aud, nonce)` and
/// that declares it was addressed to `addressed_audience`.
fn mdoc_vp_token(addressed_audience: &str, handover_aud: &str, nonce: &[u8]) -> MdocVpToken {
    let transcript = oid4vp_handover_transcript(handover_aud, nonce);
    let device_response = MdocBuilder::new().session_transcript(transcript).build();
    MdocVpToken {
        audience: addressed_audience.to_owned(),
        device_response,
    }
}

#[test]
fn mdoc_bound_to_the_issued_request_is_valid() {
    let request = request_with(AUDIENCE, &[3u8; 16]);
    let token = mdoc_vp_token(AUDIENCE, AUDIENCE, &request.nonce);
    let anchors = anchors_mdoc();
    let result = verify_response(
        &VpToken::Mdoc(token),
        &request,
        &VerificationPolicy::default(),
        &anchors,
        MDOC_NOW,
        IssuerRole::Pid,
        StatusOutcome::NoStatus,
    );
    assert!(
        result.valid,
        "bound mdoc must be VALID: {:?}",
        result.reasons
    );
    assert!(result.disclosed_attributes.contains_key("given_name"));
}

#[test]
fn mdoc_replayed_with_a_stale_nonce_is_replay() {
    // The holder signed the handover over an OLD nonce; the verifier issued a FRESH one (same aud).
    let request = request_with(AUDIENCE, &[0x11u8; 16]);
    let token = mdoc_vp_token(AUDIENCE, AUDIENCE, &[0x22u8; 16]); // handover nonce ≠ request nonce
    let anchors = anchors_mdoc();
    let result = verify_response(
        &VpToken::Mdoc(token),
        &request,
        &VerificationPolicy::default(),
        &anchors,
        MDOC_NOW,
        IssuerRole::Pid,
        StatusOutcome::NoStatus,
    );
    assert!(!result.valid);
    assert_eq!(result.reasons, vec![ReasonCode::Replay]);
}

#[test]
fn mdoc_built_for_a_different_audience_is_wrong_audience() {
    // The response was addressed to a different verifier (observable cleartext audience).
    let request = request_with(AUDIENCE, &[5u8; 16]);
    let token = mdoc_vp_token(WRONG_AUDIENCE, WRONG_AUDIENCE, &request.nonce);
    let anchors = anchors_mdoc();
    let result = verify_response(
        &VpToken::Mdoc(token),
        &request,
        &VerificationPolicy::default(),
        &anchors,
        MDOC_NOW,
        IssuerRole::Pid,
        StatusOutcome::NoStatus,
    );
    assert!(!result.valid);
    assert_eq!(result.reasons, vec![ReasonCode::WrongAudience]);
}

#[test]
fn mdoc_binding_failure_other_than_holder_binding_passes_through() {
    // An untrusted DS (right audience + nonce) must surface UntrustedIssuer, NOT be masked as Replay
    // — only a holder-binding failure (the fresh-nonce mismatch) is attributed to Replay.
    let request = request_with(AUDIENCE, &[8u8; 16]);
    let transcript = oid4vp_handover_transcript(AUDIENCE, &request.nonce);
    let device_response = MdocBuilder::new()
        .use_wrong_issuer()
        .session_transcript(transcript)
        .build();
    let token = MdocVpToken {
        audience: AUDIENCE.to_owned(),
        device_response,
    };
    let anchors = anchors_mdoc(); // trusts the real DS, not the wrong issuer
    let result = verify_response(
        &VpToken::Mdoc(token),
        &request,
        &VerificationPolicy::default(),
        &anchors,
        MDOC_NOW,
        IssuerRole::Pid,
        StatusOutcome::NoStatus,
    );
    assert!(!result.valid);
    assert_eq!(result.reasons, vec![ReasonCode::UntrustedIssuer]);
}

#[test]
fn handover_transcript_is_deterministic_and_binds_both_inputs() {
    // The same (audience, nonce) yields identical bytes; varying either changes them (so a stale
    // nonce or wrong audience necessarily breaks the device-bound transcript).
    let a = oid4vp_handover_transcript(AUDIENCE, &[1, 2, 3]);
    let same = oid4vp_handover_transcript(AUDIENCE, &[1, 2, 3]);
    let diff_nonce = oid4vp_handover_transcript(AUDIENCE, &[1, 2, 4]);
    let diff_aud = oid4vp_handover_transcript(WRONG_AUDIENCE, &[1, 2, 3]);
    assert_eq!(a, same);
    assert_ne!(a, diff_nonce);
    assert_ne!(a, diff_aud);
}
