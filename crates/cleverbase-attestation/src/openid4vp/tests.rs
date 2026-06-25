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
/// The verifier's `response_uri` request parameter (OpenID4VP 1.0 §B.2.6 4th handover element) —
/// deliberately DISTINCT from the `client_id` (`audience`) so the handover-structure test can assert
/// the 4th element is the response_uri, not the client_id.
const RESPONSE_URI: &str = "https://verifier.example/cb/response";

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
        response_uri: RESPONSE_URI.to_owned(),
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
    let r1 = build_request(&mut nonces, dcql.clone(), AUDIENCE, RESPONSE_URI);
    let r2 = build_request(&mut nonces, dcql.clone(), AUDIENCE, RESPONSE_URI);
    assert_ne!(r1.nonce, r2.nonce, "each request MUST carry a fresh nonce");
    assert_eq!(r1.audience, AUDIENCE);
    assert_eq!(r1.response_uri, RESPONSE_URI);
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
    let transcript = oid4vp_handover_transcript(handover_aud, nonce, RESPONSE_URI);
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
    let transcript = oid4vp_handover_transcript(AUDIENCE, &request.nonce, RESPONSE_URI);
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
fn verify_response_rejects_a_format_the_policy_excludes() {
    // The public `verify_response` MUST honor the `policy.formats` gate it takes (a native caller can
    // invoke it directly, bypassing the `verify()` wrapper that previously applied the gate). A
    // presented format the policy excludes is rejected with UnsupportedFormat, before any bar runs.

    // mdoc presented, but the policy accepts SD-JWT VC only → UnsupportedFormat.
    let request = request_with(AUDIENCE, &[3u8; 16]);
    let token = mdoc_vp_token(AUDIENCE, AUDIENCE, &request.nonce);
    let sd_jwt_only = VerificationPolicy {
        formats: vec![Format::SdJwtVc],
        ..VerificationPolicy::default()
    };
    let result = verify_response(
        &VpToken::Mdoc(token),
        &request,
        &sd_jwt_only,
        &anchors_mdoc(),
        MDOC_NOW,
        IssuerRole::Pid,
        StatusOutcome::NoStatus,
    );
    assert!(!result.valid);
    assert_eq!(result.reasons, vec![ReasonCode::UnsupportedFormat]);

    // Symmetric: SD-JWT VC presented, but the policy accepts mdoc only → UnsupportedFormat.
    let sd_request = request_with(AUDIENCE, &[9u8; 16]);
    let presentation = sd_jwt_presentation(AUDIENCE, &sd_request.nonce_b64());
    let mdoc_only = VerificationPolicy {
        formats: vec![Format::Mdoc],
        ..VerificationPolicy::default()
    };
    let result = verify_response(
        &VpToken::SdJwtVc(&presentation),
        &sd_request,
        &mdoc_only,
        &anchors_sd_jwt(),
        NOW,
        IssuerRole::Pid,
        StatusOutcome::NoStatus,
    );
    assert!(!result.valid);
    assert_eq!(result.reasons, vec![ReasonCode::UnsupportedFormat]);

    // Control: the SAME mdoc under a policy that DOES accept mdoc verifies (so the rejection above is
    // the format gate, not some other failure).
    let ok_token = mdoc_vp_token(AUDIENCE, AUDIENCE, &request.nonce);
    let mdoc_ok = VerificationPolicy {
        formats: vec![Format::Mdoc],
        ..VerificationPolicy::default()
    };
    let ok = verify_response(
        &VpToken::Mdoc(ok_token),
        &request,
        &mdoc_ok,
        &anchors_mdoc(),
        MDOC_NOW,
        IssuerRole::Pid,
        StatusOutcome::NoStatus,
    );
    assert!(
        ok.valid,
        "an accepted-format mdoc verifies: {:?}",
        ok.reasons
    );
}

#[test]
fn mdoc_bound_presentation_with_a_corrupt_device_signature_is_holder_binding_not_replay() {
    // A presentation BOUND to the request (handover nonce == request nonce, so NOT a replay) whose
    // DeviceSignature is structurally CORRUPT (garbled/truncated bytes) is a genuine holder-binding
    // fault. The OID4VP layer must NOT mask it as Replay: before the fix it collapsed every
    // `[HolderBinding]` into `Replay`; the fix re-attributes only a fresh-nonce mismatch (sound
    // binding machinery) to Replay and KEEPS `HolderBinding` for a structurally-broken signature.
    let request = request_with(AUDIENCE, &[0x44u8; 16]);
    // Build over the SAME (request) handover so freshness is satisfied — the only fault is the corrupt
    // signature.
    let transcript = oid4vp_handover_transcript(AUDIENCE, &request.nonce, RESPONSE_URI);
    let device_response = MdocBuilder::new()
        .session_transcript(transcript)
        .mangle_device_signature()
        .build();
    let token = MdocVpToken {
        audience: AUDIENCE.to_owned(),
        device_response,
    };
    let result = verify_response(
        &VpToken::Mdoc(token),
        &request,
        &VerificationPolicy::default(),
        &anchors_mdoc(),
        MDOC_NOW,
        IssuerRole::Pid,
        StatusOutcome::NoStatus,
    );
    assert!(!result.valid);
    assert_eq!(
        result.reasons,
        vec![ReasonCode::HolderBinding],
        "a corrupt DeviceSignature on a bound presentation must stay HolderBinding, not be masked \
         as Replay"
    );
}

#[test]
fn handover_transcript_is_deterministic_and_binds_all_inputs() {
    // The same (audience, nonce, response_uri) yields identical bytes; varying any one changes them
    // (so a stale nonce, wrong audience, or tampered response_uri necessarily breaks the
    // device-bound transcript).
    let a = oid4vp_handover_transcript(AUDIENCE, &[1, 2, 3], RESPONSE_URI);
    let same = oid4vp_handover_transcript(AUDIENCE, &[1, 2, 3], RESPONSE_URI);
    let diff_nonce = oid4vp_handover_transcript(AUDIENCE, &[1, 2, 4], RESPONSE_URI);
    let diff_aud = oid4vp_handover_transcript(WRONG_AUDIENCE, &[1, 2, 3], RESPONSE_URI);
    let diff_response_uri =
        oid4vp_handover_transcript(AUDIENCE, &[1, 2, 3], "https://attacker.example/steal");
    assert_eq!(a, same);
    assert_ne!(a, diff_nonce);
    assert_ne!(a, diff_aud);
    assert_ne!(
        a, diff_response_uri,
        "the response_uri is folded into the handover hash, so changing it changes the transcript"
    );
}

#[test]
fn handover_transcript_is_the_conformant_openid4vp_1_0_structure() {
    // Pin the SessionTranscript to the OpenID4VP 1.0 / ISO 18013-7 `OpenID4VPHandover`
    // (§B.2.6) — NOT the old self-invented `["OID4VPHandover", clientIdHash, nonceHash]`.
    // SessionTranscript = [null, null, OpenID4VPHandover]
    // OpenID4VPHandover = ["OpenID4VPHandover", sha256(OpenID4VPHandoverInfoBytes)]
    // OpenID4VPHandoverInfo = [clientId, nonce, jwkThumbprint(null), responseUri]
    use base64ct::{Base64UrlUnpadded, Encoding as _};
    use ciborium::value::Value as CborValue;
    use sha2::{Digest as _, Sha256};

    let nonce = [1u8, 2, 3];
    let transcript_bytes = oid4vp_handover_transcript(AUDIENCE, &nonce, RESPONSE_URI);
    let transcript: CborValue = ciborium::from_reader(transcript_bytes.as_slice()).unwrap();

    // SessionTranscript = [null, null, OpenID4VPHandover].
    let CborValue::Array(st) = &transcript else {
        panic!("SessionTranscript is a 3-element array")
    };
    assert_eq!(st.len(), 3);
    assert_eq!(st[0], CborValue::Null, "DeviceEngagementBytes MUST be null");
    assert_eq!(st[1], CborValue::Null, "EReaderKeyBytes MUST be null");

    // OpenID4VPHandover = ["OpenID4VPHandover", OpenID4VPHandoverInfoHash].
    let CborValue::Array(handover) = &st[2] else {
        panic!("Handover is a 2-element array")
    };
    assert_eq!(handover.len(), 2);
    assert_eq!(
        handover[0],
        CborValue::Text("OpenID4VPHandover".to_owned()),
        "the fixed handover identifier is the spec string, not the old custom one"
    );

    // Recompute the expected single SHA-256 over the inner OpenID4VPHandoverInfo array and assert the
    // handover carries exactly that hash (so every request parameter is bound by one digest).
    // OpenID4VP 1.0 §B.2.6: OpenID4VPHandoverInfo = [clientId, nonce, jwkThumbprint, responseUri].
    let expected_info = CborValue::Array(vec![
        CborValue::Text(AUDIENCE.to_owned()),
        CborValue::Text(Base64UrlUnpadded::encode_string(&nonce)),
        CborValue::Null,
        CborValue::Text(RESPONSE_URI.to_owned()),
    ]);
    let mut info_bytes = Vec::new();
    ciborium::into_writer(&expected_info, &mut info_bytes).unwrap();
    let expected_hash = Sha256::digest(&info_bytes).to_vec();
    assert_eq!(
        handover[1],
        CborValue::Bytes(expected_hash),
        "the handover hash MUST be sha256(CBOR(OpenID4VPHandoverInfo))"
    );

    // The old custom structure had THREE handover elements (id + two per-field hashes); the
    // conformant one has exactly two — guard against a regression to the non-interoperable shape.
    assert_ne!(
        handover.len(),
        3,
        "must not regress to the self-invented 3-element handover"
    );

    // Directly assert the 4th OpenID4VPHandoverInfo element is the REAL response_uri (OpenID4VP 1.0
    // §B.2.6: "The fourth element MUST be either the redirect_uri or response_uri request
    // parameter"), NOT the client_id — this is the conformance bug fixed (the old code stubbed the
    // 4th element to the client_id/audience). Reconstruct the exact OpenID4VPHandoverInfoBytes the
    // handover hashes (the canonical CBOR encoding of the array we just verified) and decode it.
    let CborValue::Array(info) = &expected_info else {
        panic!("OpenID4VPHandoverInfo is an array")
    };
    assert_eq!(
        info.len(),
        4,
        "OpenID4VPHandoverInfo has exactly 4 elements"
    );
    assert_eq!(
        info[0],
        CborValue::Text(AUDIENCE.to_owned()),
        "1st element is the client_id (audience)"
    );
    assert_eq!(
        info[2],
        CborValue::Null,
        "3rd element (jwkThumbprint) is null (unencrypted flow)"
    );
    assert_eq!(
        info[3],
        CborValue::Text(RESPONSE_URI.to_owned()),
        "4th element MUST be the response_uri request parameter (§B.2.6), not the client_id"
    );
    assert_ne!(
        info[3], info[0],
        "the 4th element (response_uri) MUST be distinct from the 1st (client_id) — guarding the \
         fixed stub that previously set responseUri = client_id"
    );

    // And prove it end-to-end through the public function: a transcript whose 4th handover element
    // wrongly equalled the client_id (the old stub) would be byte-identical to building with
    // response_uri == AUDIENCE; assert the real transcript (response_uri = RESPONSE_URI) differs.
    let stubbed = oid4vp_handover_transcript(AUDIENCE, &nonce, AUDIENCE);
    assert_ne!(
        transcript_bytes, stubbed,
        "the real response_uri transcript MUST differ from the old responseUri = client_id stub"
    );
}
