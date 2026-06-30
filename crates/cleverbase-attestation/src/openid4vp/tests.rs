//! OpenID4VP binding tests (T010 — written test-first against the T015 verifier).
//!
//! A presentation correctly bound to an SDK-issued request verifies VALID; the same presentation
//! **replayed** (built for a stale/different nonce) or built for a **different audience** is INVALID
//! with the specific reason ([`ReasonCode::Replay`] / [`ReasonCode::WrongAudience`]) — for **both**
//! formats (SC-008). Also covers `build_request` freshness (a distinct nonce per call).

use base64ct::{Base64UrlUnpadded, Encoding as _};

use std::collections::BTreeMap;

use super::{
    build_request, oid4vp_handover_transcript, verify_response, verify_vp_token, Dcql, MdocVpToken,
    NonceSource, PresentationRequest, VpToken,
};
use crate::mdoc::test_issuer::MdocBuilder;
use crate::sdjwtvc::test_issuer::{
    attach_kb_jwt, mint_sd_jwt, mint_sd_jwt_with_clear_subject_claim, mint_sd_jwt_with_vct,
    HOLDER_KEY_PK8, ISSUER_CERT_DER, ISSUER_KEY_PK8, NOW,
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
    // mdoc disclosed attributes are GROUPED BY NAMESPACE (`{ ns: Map({ id: value }) }`); the builder's
    // default namespace is `org.iso.18013.5.1`, with `given_name` in its sub-map.
    assert!(
        matches!(
            result.disclosed_attributes.get("org.iso.18013.5.1"),
            Some(crate::types::AttributeValue::Map(ns)) if ns.contains_key("given_name")
        ),
        "given_name is disclosed under the org.iso.18013.5.1 namespace"
    );
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
fn multi_document_wrong_key_device_signature_is_holder_binding_not_replay() {
    // MULTI-DOCUMENT WRONG-KEY PROBE: a presentation BOUND to the request (handover nonce == request
    // nonce, so NOT a replay) carrying TWO documents — `documents[0]` correctly holder-bound (genuine
    // holder signature over the request handover transcript) and `documents[1]` whose `DeviceSignature`
    // is made by a WRONG (non-holder) key over the SAME transcript. The wrong-key signature is
    // structurally well-formed (ES256 + parseable DeviceKey), so the binding-machinery classifier reads
    // it as `Sound` — yet it is a GENUINE holder-binding fault, not a freshness replay. The OID4VP layer
    // MUST keep `HolderBinding`: it only re-attributes to `Replay` in the SINGLE-document case (where the
    // nonce is the only transcript-dependent variable); a multi-document binding fault is never laundered
    // into `Replay`.
    use ciborium::value::Value as CborValue;

    let request = request_with(AUDIENCE, &[0x55u8; 16]);
    let transcript = oid4vp_handover_transcript(AUDIENCE, &request.nonce, RESPONSE_URI);
    let device_response = MdocBuilder::new()
        .session_transcript(transcript)
        // documents[1]: same trusted DS, distinct disclosed element, signed over the SAME transcript
        // but with a WRONG (non-holder) key → a genuine wrong-key holder-binding fault.
        .append_wrong_key_document("nationality", CborValue::Text("NL".to_owned()))
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
        "a wrong-key DeviceSignature on documents[1] of a multi-document response must stay \
         HolderBinding, NEVER be laundered into Replay"
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

// =================================================================================================
// DCQL "did I get what I requested" gate (OpenID4VP 1.0 §"VP Token Validation" step 2.2 + §6 DCQL)
// — conformance-audit T4.1/T4.2. The always-on bar already proved the credential sound, trusted, and
// request-bound; these assert it must ALSO satisfy the DCQL Credential Query, and a sound credential of
// the WRONG vct/doctype or missing a requested claim is rejected as `QueryNotSatisfied` (the false-
// trust the gate closes). Role derivation/validation (T4.3) is covered at the bottom.
// =================================================================================================

/// The default `vct` the SD-JWT VC test issuer mints (a non-PID Collision-Resistant Name).
const SD_JWT_VCT: &str = "https://credentials.example/identity_credential";

/// A request bound to `(audience, nonce)` carrying an explicit DCQL query.
fn request_with_dcql(audience: &str, nonce: &[u8], dcql_json: &str) -> PresentationRequest {
    PresentationRequest {
        dcql: Dcql::from_json(dcql_json),
        nonce: nonce.to_vec(),
        audience: audience.to_owned(),
        response_uri: RESPONSE_URI.to_owned(),
    }
}

#[test]
fn sd_jwt_satisfying_the_dcql_query_is_valid() {
    // The credential's vct ∈ vct_values AND every requested claim is disclosed → VALID.
    let dcql = format!(
        r#"{{"credentials":[{{"id":"pid","format":"dc+sd-jwt","meta":{{"vct_values":["{SD_JWT_VCT}"]}},"claims":[{{"path":["given_name"]}},{{"path":["family_name"]}}]}}]}}"#
    );
    let request = request_with_dcql(AUDIENCE, &[9u8; 16], &dcql);
    let presentation = sd_jwt_presentation(AUDIENCE, &request.nonce_b64());
    let result = verify_response(
        &VpToken::SdJwtVc(&presentation),
        &request,
        &VerificationPolicy::default(),
        &anchors_sd_jwt(),
        NOW,
        IssuerRole::Pid,
        StatusOutcome::NoStatus,
    );
    assert!(
        result.valid,
        "a credential matching its DCQL query is VALID: {:?}",
        result.reasons
    );
}

#[test]
fn sd_jwt_of_the_wrong_vct_is_query_not_satisfied() {
    // The credential is sound, trusted, and request-bound — but its vct is NOT one the verifier asked
    // for. Before this gate it passed as VALID (the T4.1 false-trust); now it is rejected.
    let dcql = r#"{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:example:some-other-type"]}}]}"#;
    let request = request_with_dcql(AUDIENCE, &[9u8; 16], dcql);
    let presentation = sd_jwt_presentation(AUDIENCE, &request.nonce_b64());
    let result = verify_response(
        &VpToken::SdJwtVc(&presentation),
        &request,
        &VerificationPolicy::default(),
        &anchors_sd_jwt(),
        NOW,
        IssuerRole::Pid,
        StatusOutcome::NoStatus,
    );
    assert!(
        !result.valid,
        "a wrong-vct credential must NOT pass as VALID"
    );
    assert_eq!(result.reasons, vec![ReasonCode::QueryNotSatisfied]);
    assert!(
        result.disclosed_attributes.is_empty(),
        "a rejected verdict surfaces no disclosures"
    );
}

#[test]
fn sd_jwt_missing_a_requested_claim_is_query_not_satisfied() {
    // vct matches, but a requested claim was not disclosed → the verifier did not get what it asked for.
    let dcql = format!(
        r#"{{"credentials":[{{"id":"pid","format":"dc+sd-jwt","meta":{{"vct_values":["{SD_JWT_VCT}"]}},"claims":[{{"path":["email_address"]}}]}}]}}"#
    );
    let request = request_with_dcql(AUDIENCE, &[9u8; 16], &dcql);
    let presentation = sd_jwt_presentation(AUDIENCE, &request.nonce_b64());
    let result = verify_response(
        &VpToken::SdJwtVc(&presentation),
        &request,
        &VerificationPolicy::default(),
        &anchors_sd_jwt(),
        NOW,
        IssuerRole::Pid,
        StatusOutcome::NoStatus,
    );
    assert!(!result.valid);
    assert_eq!(result.reasons, vec![ReasonCode::QueryNotSatisfied]);
}

#[test]
fn sd_jwt_claim_value_match_and_mismatch() {
    // The test issuer mints family_name = "Lovelace".
    let matching = format!(
        r#"{{"credentials":[{{"id":"pid","format":"dc+sd-jwt","meta":{{"vct_values":["{SD_JWT_VCT}"]}},"claims":[{{"path":["family_name"],"values":["Lovelace"]}}]}}]}}"#
    );
    let request = request_with_dcql(AUDIENCE, &[9u8; 16], &matching);
    let presentation = sd_jwt_presentation(AUDIENCE, &request.nonce_b64());
    let result = verify_response(
        &VpToken::SdJwtVc(&presentation),
        &request,
        &VerificationPolicy::default(),
        &anchors_sd_jwt(),
        NOW,
        IssuerRole::Pid,
        StatusOutcome::NoStatus,
    );
    assert!(
        result.valid,
        "the disclosed family_name matches the requested value: {:?}",
        result.reasons
    );

    // A value the credential does not carry → not what was requested.
    let mismatch = format!(
        r#"{{"credentials":[{{"id":"pid","format":"dc+sd-jwt","meta":{{"vct_values":["{SD_JWT_VCT}"]}},"claims":[{{"path":["family_name"],"values":["Smith"]}}]}}]}}"#
    );
    let request = request_with_dcql(AUDIENCE, &[9u8; 16], &mismatch);
    let presentation = sd_jwt_presentation(AUDIENCE, &request.nonce_b64());
    let result = verify_response(
        &VpToken::SdJwtVc(&presentation),
        &request,
        &VerificationPolicy::default(),
        &anchors_sd_jwt(),
        NOW,
        IssuerRole::Pid,
        StatusOutcome::NoStatus,
    );
    assert!(!result.valid);
    assert_eq!(result.reasons, vec![ReasonCode::QueryNotSatisfied]);
}

/// Run the single-presentation gate over the clear-claim fixture (CLEAR `given_name` + DISCLOSED
/// `family_name`) with `dcql_json`.
fn verify_clear_claim_with_dcql(dcql_json: &str) -> crate::types::VerificationResult {
    let request = request_with_dcql(AUDIENCE, &[9u8; 16], dcql_json);
    let sd_jwt = mint_sd_jwt_with_clear_subject_claim(ISSUER_KEY_PK8, ISSUER_CERT_DER);
    let presentation = attach_kb_jwt(sd_jwt, HOLDER_KEY_PK8, AUDIENCE, &request.nonce_b64());
    verify_response(
        &VpToken::SdJwtVc(&presentation),
        &request,
        &VerificationPolicy::default(),
        &anchors_sd_jwt(),
        NOW,
        IssuerRole::Pid,
        StatusOutcome::NoStatus,
    )
}

#[test]
fn dcql_query_for_a_clear_sd_jwt_vc_claim_is_valid() {
    // REGRESSION (wave-3): `given_name` is carried in the issuer-signed CLEAR payload (not selectively
    // disclosed). OpenID4VP 1.0 §8.6 step 2.2 / §6.4: a claim PRESENT in the presentation satisfies the
    // request whether disclosed OR clear. Before the fix the gate resolved a claims `path` only against
    // the DISCLOSED set, so this same-credential query falsely rejected as QueryNotSatisfied.
    let dcql = format!(
        r#"{{"credentials":[{{"id":"pid","format":"dc+sd-jwt","meta":{{"vct_values":["{SD_JWT_VCT}"]}},"claims":[{{"path":["given_name"]}}]}}]}}"#
    );
    let result = verify_clear_claim_with_dcql(&dcql);
    assert!(
        result.valid,
        "a DCQL query for a CLEAR subject claim must be VALID: {:?}",
        result.reasons
    );

    // SAME-CREDENTIAL CONTROL: the identical credential with NO claims query (meta only) is VALID — so
    // the clear-claim `path` is the sole variable and must not flip a sound credential to invalid.
    let control = format!(
        r#"{{"credentials":[{{"id":"pid","format":"dc+sd-jwt","meta":{{"vct_values":["{SD_JWT_VCT}"]}}}}]}}"#
    );
    assert!(
        verify_clear_claim_with_dcql(&control).valid,
        "the same credential with no claims query is VALID"
    );
}

#[test]
fn dcql_query_for_a_disclosed_sd_jwt_vc_claim_is_still_valid() {
    // The disclosed `family_name` still resolves — the presented set is a SUPERSET of the disclosed set.
    let dcql = format!(
        r#"{{"credentials":[{{"id":"pid","format":"dc+sd-jwt","meta":{{"vct_values":["{SD_JWT_VCT}"]}},"claims":[{{"path":["family_name"]}}]}}]}}"#
    );
    assert!(
        verify_clear_claim_with_dcql(&dcql).valid,
        "a DCQL query for a DISCLOSED claim must still be VALID"
    );
}

#[test]
fn dcql_query_for_an_absent_sd_jwt_vc_claim_is_query_not_satisfied() {
    // A claim genuinely ABSENT from the presentation (neither clear nor disclosed) must still reject —
    // widening the resolution set to clear+disclosed does NOT make every path resolve (no weakening).
    let dcql = format!(
        r#"{{"credentials":[{{"id":"pid","format":"dc+sd-jwt","meta":{{"vct_values":["{SD_JWT_VCT}"]}},"claims":[{{"path":["email_address"]}}]}}]}}"#
    );
    let result = verify_clear_claim_with_dcql(&dcql);
    assert!(!result.valid);
    assert_eq!(result.reasons, vec![ReasonCode::QueryNotSatisfied]);
}

#[test]
fn dcql_value_match_on_a_clear_sd_jwt_vc_claim_works() {
    // A `values` restriction is evaluated against the CLEAR claim's value: "Ada" matches, "Bob" doesn't.
    let matching = format!(
        r#"{{"credentials":[{{"id":"pid","format":"dc+sd-jwt","meta":{{"vct_values":["{SD_JWT_VCT}"]}},"claims":[{{"path":["given_name"],"values":["Ada"]}}]}}]}}"#
    );
    assert!(
        verify_clear_claim_with_dcql(&matching).valid,
        "the clear given_name=Ada matches the requested value"
    );

    let mismatch = format!(
        r#"{{"credentials":[{{"id":"pid","format":"dc+sd-jwt","meta":{{"vct_values":["{SD_JWT_VCT}"]}},"claims":[{{"path":["given_name"],"values":["Bob"]}}]}}]}}"#
    );
    let result = verify_clear_claim_with_dcql(&mismatch);
    assert!(
        !result.valid,
        "a value mismatch on a clear claim must reject"
    );
    assert_eq!(result.reasons, vec![ReasonCode::QueryNotSatisfied]);
}

#[test]
fn mdoc_matching_doctype_is_valid_and_wrong_doctype_is_query_not_satisfied() {
    let request_match = {
        let dcql = r#"{"credentials":[{"id":"mdl","format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.mDL"},"claims":[{"path":["org.iso.18013.5.1","given_name"]}]}]}"#;
        request_with_dcql(AUDIENCE, &[3u8; 16], dcql)
    };
    let token = mdoc_vp_token(AUDIENCE, AUDIENCE, &request_match.nonce);
    let result = verify_response(
        &VpToken::Mdoc(token),
        &request_match,
        &VerificationPolicy::default(),
        &anchors_mdoc(),
        MDOC_NOW,
        IssuerRole::Pid,
        StatusOutcome::NoStatus,
    );
    assert!(
        result.valid,
        "an mdoc matching its DCQL doctype + claim is VALID: {:?}",
        result.reasons
    );

    // Wrong doctype_value → QueryNotSatisfied (a sound, trusted, bound mdoc of the wrong type).
    let dcql_wrong = r#"{"credentials":[{"id":"mdl","format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.other"}}]}"#;
    let request_wrong = request_with_dcql(AUDIENCE, &[3u8; 16], dcql_wrong);
    let token = mdoc_vp_token(AUDIENCE, AUDIENCE, &request_wrong.nonce);
    let result = verify_response(
        &VpToken::Mdoc(token),
        &request_wrong,
        &VerificationPolicy::default(),
        &anchors_mdoc(),
        MDOC_NOW,
        IssuerRole::Pid,
        StatusOutcome::NoStatus,
    );
    assert!(!result.valid);
    assert_eq!(result.reasons, vec![ReasonCode::QueryNotSatisfied]);
}

// ---- Role derivation/validation (conformance-audit T4.3) -----------------------------------------

#[test]
fn pid_typed_sd_jwt_under_the_pid_role_is_valid() {
    // A PID vct anchored under IssuerRole::Pid: role derivation derives Pid (matches the caller) and
    // anchors against the PID list, which trusts the issuer → VALID.
    let presentation = {
        let sd_jwt = mint_sd_jwt_with_vct(ISSUER_KEY_PK8, ISSUER_CERT_DER, "urn:eudi:pid:1");
        attach_kb_jwt(sd_jwt, HOLDER_KEY_PK8, AUDIENCE, &request().nonce_b64())
    };
    let result = verify_response(
        &VpToken::SdJwtVc(&presentation),
        &request(),
        &VerificationPolicy::default(),
        &anchors_sd_jwt(),
        NOW,
        IssuerRole::Pid,
        StatusOutcome::NoStatus,
    );
    assert!(
        result.valid,
        "a PID credential under the PID role is VALID: {:?}",
        result.reasons
    );
}

#[test]
fn pid_typed_sd_jwt_under_a_non_pid_role_is_role_mismatch() {
    // The credential's vct is a EUDI PID type, but the caller anchored it under QEAA — per-role trust
    // anchoring would otherwise be only as good as the (wrong) host input. The contradiction is
    // rejected BEFORE the trust resolve (T4.3), so it never anchors under the wrong per-role list.
    let presentation = {
        let sd_jwt = mint_sd_jwt_with_vct(ISSUER_KEY_PK8, ISSUER_CERT_DER, "urn:eudi:pid:1");
        attach_kb_jwt(sd_jwt, HOLDER_KEY_PK8, AUDIENCE, &request().nonce_b64())
    };
    let result = verify_response(
        &VpToken::SdJwtVc(&presentation),
        &request(),
        &VerificationPolicy::default(),
        &anchors_sd_jwt(),
        NOW,
        IssuerRole::Qeaa,
        StatusOutcome::NoStatus,
    );
    assert!(
        !result.valid,
        "a PID credential under a non-PID role must be rejected"
    );
    assert_eq!(result.reasons, vec![ReasonCode::RoleMismatch]);
}

#[test]
fn pid_typed_mdoc_under_a_non_pid_role_is_role_mismatch() {
    let request = request();
    let transcript = oid4vp_handover_transcript(AUDIENCE, &request.nonce, RESPONSE_URI);
    let device_response = MdocBuilder::new()
        .doc_type("eu.europa.ec.eudi.pid.1")
        .session_transcript(transcript)
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
        IssuerRole::Qeaa,
        StatusOutcome::NoStatus,
    );
    assert!(!result.valid);
    assert_eq!(result.reasons, vec![ReasonCode::RoleMismatch]);
}

/// A request fixed to `AUDIENCE` + a constant nonce with a non-constraining DCQL (the role-mismatch
/// tests fire before the gate, so the query is irrelevant).
fn request() -> PresentationRequest {
    request_with(AUDIENCE, &[9u8; 16])
}

// ---- verify_vp_token — set-level semantics (§"VP Token Validation" step 3 + §"Selecting Credentials")

/// Mint an SD-JWT VC of `vct` bound to `request`, ready to wrap in a [`VpToken::SdJwtVc`].
fn sd_jwt_of_vct(vct: &str, request: &PresentationRequest) -> String {
    let sd_jwt = mint_sd_jwt_with_vct(ISSUER_KEY_PK8, ISSUER_CERT_DER, vct);
    attach_kb_jwt(sd_jwt, HOLDER_KEY_PK8, AUDIENCE, &request.nonce_b64())
}

const VCT_A: &str = "https://credentials.example/type-a";
const VCT_B: &str = "https://credentials.example/type-b";

/// A two-SD-JWT-credential DCQL (`a` ⇒ VCT_A, `b` ⇒ VCT_B) plus the supplied `credential_sets` JSON.
fn two_credential_dcql(credential_sets: &str) -> String {
    format!(
        r#"{{"credentials":[
            {{"id":"a","format":"dc+sd-jwt","meta":{{"vct_values":["{VCT_A}"]}}}},
            {{"id":"b","format":"dc+sd-jwt","meta":{{"vct_values":["{VCT_B}"]}}}}
        ]{credential_sets}}}"#
    )
}

#[test]
fn verify_vp_token_required_set_satisfied_by_one_option() {
    let dcql =
        two_credential_dcql(r#","credential_sets":[{"options":[["a"],["b"]],"required":true}]"#);
    let request = request_with_dcql(AUDIENCE, &[9u8; 16], &dcql);
    let pres_a = sd_jwt_of_vct(VCT_A, &request);
    let mut vp_token = BTreeMap::new();
    vp_token.insert("a".to_owned(), vec![VpToken::SdJwtVc(&pres_a)]);
    let outcome = verify_vp_token(
        &request,
        &vp_token,
        &VerificationPolicy::default(),
        &anchors_sd_jwt(),
        NOW,
        IssuerRole::Pid,
        StatusOutcome::NoStatus,
    );
    assert!(
        outcome.satisfied,
        "option [a] of the required set is satisfied"
    );
    assert!(outcome.credentials.get("a").is_some_and(|c| c.satisfied));
}

#[test]
fn verify_vp_token_wrong_vct_under_an_id_is_unsatisfied() {
    // No credential_sets ⇒ every credential must be satisfied; here `a` carries a credential of a type
    // (`type-c`) that matches NEITHER query, so it both fails the per-credential match for `a` AND is
    // itself rejected as `QueryNotSatisfied` (it is not what ANY part of the request asked for).
    let dcql = two_credential_dcql("");
    let request = request_with_dcql(AUDIENCE, &[9u8; 16], &dcql);
    let pres_wrong = sd_jwt_of_vct("https://credentials.example/type-c", &request);
    let mut vp_token = BTreeMap::new();
    vp_token.insert("a".to_owned(), vec![VpToken::SdJwtVc(&pres_wrong)]);
    let outcome = verify_vp_token(
        &request,
        &vp_token,
        &VerificationPolicy::default(),
        &anchors_sd_jwt(),
        NOW,
        IssuerRole::Pid,
        StatusOutcome::NoStatus,
    );
    assert!(!outcome.satisfied);
    let credential = outcome.credentials.get("a").expect("entry for id a");
    assert!(!credential.satisfied);
    assert_eq!(
        credential.presentations.first().map(|r| r.reasons.clone()),
        Some(vec![ReasonCode::QueryNotSatisfied]),
        "the wrong-vct presentation is itself rejected as QueryNotSatisfied"
    );
}

#[test]
fn verify_vp_token_optional_set_absent_does_not_block() {
    let dcql = two_credential_dcql(
        r#","credential_sets":[{"options":[["a"]],"required":true},{"options":[["b"]],"required":false}]"#,
    );
    let request = request_with_dcql(AUDIENCE, &[9u8; 16], &dcql);
    let pres_a = sd_jwt_of_vct(VCT_A, &request);
    let mut vp_token = BTreeMap::new();
    vp_token.insert("a".to_owned(), vec![VpToken::SdJwtVc(&pres_a)]);
    let outcome = verify_vp_token(
        &request,
        &vp_token,
        &VerificationPolicy::default(),
        &anchors_sd_jwt(),
        NOW,
        IssuerRole::Pid,
        StatusOutcome::NoStatus,
    );
    assert!(
        outcome.satisfied,
        "required set [a] satisfied; optional set [b] may be absent"
    );
}

#[test]
fn verify_vp_token_required_optional_set_unsatisfied_when_required_missing() {
    let dcql = two_credential_dcql(
        r#","credential_sets":[{"options":[["a"]],"required":true},{"options":[["b"]],"required":false}]"#,
    );
    let request = request_with_dcql(AUDIENCE, &[9u8; 16], &dcql);
    // Only the OPTIONAL credential `b` is returned; the REQUIRED `a` is absent → overall unsatisfied.
    let pres_b = sd_jwt_of_vct(VCT_B, &request);
    let mut vp_token = BTreeMap::new();
    vp_token.insert("b".to_owned(), vec![VpToken::SdJwtVc(&pres_b)]);
    let outcome = verify_vp_token(
        &request,
        &vp_token,
        &VerificationPolicy::default(),
        &anchors_sd_jwt(),
        NOW,
        IssuerRole::Pid,
        StatusOutcome::NoStatus,
    );
    assert!(
        !outcome.satisfied,
        "the required set [a] is unsatisfied even though optional [b] is present"
    );
    assert!(outcome.credentials.get("b").is_some_and(|c| c.satisfied));
}

#[test]
fn verify_vp_token_multiple_false_rejects_two_presentations() {
    // `multiple` omitted ⇒ default false ⇒ at most one Presentation per Credential Query.
    let dcql = format!(
        r#"{{"credentials":[{{"id":"a","format":"dc+sd-jwt","meta":{{"vct_values":["{VCT_A}"]}}}}]}}"#
    );
    let request = request_with_dcql(AUDIENCE, &[9u8; 16], &dcql);
    let pres1 = sd_jwt_of_vct(VCT_A, &request);
    let pres2 = sd_jwt_of_vct(VCT_A, &request);
    let mut vp_token = BTreeMap::new();
    vp_token.insert(
        "a".to_owned(),
        vec![VpToken::SdJwtVc(&pres1), VpToken::SdJwtVc(&pres2)],
    );
    let outcome = verify_vp_token(
        &request,
        &vp_token,
        &VerificationPolicy::default(),
        &anchors_sd_jwt(),
        NOW,
        IssuerRole::Pid,
        StatusOutcome::NoStatus,
    );
    assert!(
        !outcome.satisfied,
        "two Presentations for a multiple:false query violate the cardinality"
    );
    assert!(outcome.credentials.get("a").is_some_and(|c| !c.satisfied));
}

#[test]
fn verify_vp_token_mdoc_credential_is_satisfied() {
    let dcql = r#"{"credentials":[{"id":"mdl","format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.mDL"}}]}"#;
    let request = request_with_dcql(AUDIENCE, &[3u8; 16], dcql);
    let token = mdoc_vp_token(AUDIENCE, AUDIENCE, &request.nonce);
    let mut vp_token = BTreeMap::new();
    vp_token.insert("mdl".to_owned(), vec![VpToken::Mdoc(token)]);
    let outcome = verify_vp_token(
        &request,
        &vp_token,
        &VerificationPolicy::default(),
        &anchors_mdoc(),
        MDOC_NOW,
        IssuerRole::Pid,
        StatusOutcome::NoStatus,
    );
    assert!(outcome.satisfied, "the mdoc matches its DCQL query");
    assert!(outcome.credentials.get("mdl").is_some_and(|c| c.satisfied));
}
