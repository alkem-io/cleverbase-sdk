//! Signer-hook tests (US2 — task T021, written test-first against T024).
//!
//! These assert the **holder key-custody invariant** (FR-009): the SDK builds the exact, deterministic
//! `signing_input` for each EUDI ceremony (PoP-JWT / KB-JWT / mdoc `DeviceSignature`), a **stub HSM**
//! (the only holder of a private key in the test) signs those bytes, and the SDK splices the result.
//! The produced KB-JWT / `DeviceSignature` then **verify under the US1 verifier** (the round-trip
//! oracle), and the `aud`/`nonce` are exposed on the [`SigningInput`] for host policy inspection.

use base64ct::{Base64UrlUnpadded, Encoding as _};
use p256::ecdsa::{signature::Signer as _, Signature, SigningKey};
use pkcs8::DecodePrivateKey as _;
use serde_json::{json, Value};

use super::{
    build_kb_jwt, build_pop_jwt, Ceremony, HolderContext, SignatureAlgorithm, Signer, SignerError,
    SigningInput,
};
use crate::issuance::device::build_device_signature;
use crate::sdjwtvc::test_issuer::{
    mint_sd_jwt, HOLDER_JWK_JSON, HOLDER_KEY_PK8, ISSUER_CERT_DER, ISSUER_KEY_PK8, NOW,
};

const AUDIENCE: &str = "https://verifier.example/cb";
/// The verifier's `response_uri` request parameter (OpenID4VP 1.0 §B.2.6 4th handover element).
const RESPONSE_URI: &str = "https://verifier.example/cb/response";
const NONCE: &str = "n-0S6_WzA2Mj";
const C_NONCE: &str = "issuer-c-nonce-xyz";
const ISSUER_ID: &str = "https://issuer.example/cb";

/// A stub HSM/KMS that signs the SDK-built `signing_input` out-of-process. **This** is the only place
/// a holder private key lives — supplied by the (test) host, never by the SDK. It signs the exact
/// bytes the SDK hands it and returns the raw `r‖s` ES256 signature.
struct StubHsm {
    key: SigningKey,
    /// Records the (handle, ceremony, aud, nonce) it was asked to sign, so a test can assert exactly
    /// what the SDK exposed to the host before blind-signing.
    seen: std::cell::RefCell<Vec<(String, Ceremony, String, String)>>,
}

impl StubHsm {
    fn new(pk8: &[u8]) -> Self {
        Self {
            key: SigningKey::from_pkcs8_der(pk8).expect("test holder key"),
            seen: std::cell::RefCell::new(Vec::new()),
        }
    }
}

impl Signer for StubHsm {
    type Error = String;
    fn sign(&self, handle: &str, input: &SigningInput) -> Result<Vec<u8>, String> {
        self.seen.borrow_mut().push((
            handle.to_owned(),
            input.ceremony(),
            input.audience().to_owned(),
            input.nonce().to_owned(),
        ));
        assert_eq!(input.algorithm(), SignatureAlgorithm::Es256);
        let sig: Signature = self.key.sign(input.to_be_signed());
        Ok(sig.to_bytes().to_vec())
    }
}

/// The holder context built from the test holder public JWK fixture (no private key present).
fn holder_ctx() -> HolderContext {
    let jwk: Value = serde_json::from_slice(HOLDER_JWK_JSON).expect("holder JWK");
    HolderContext::new(jwk, "holder-key-handle")
}

// --- The SDK never holds a private key -----------------------------------------------------------

#[test]
fn holder_context_carries_only_public_material_no_private_key() {
    let ctx = holder_ctx();
    assert_eq!(
        ctx.holder_public_jwk.get("kty").and_then(Value::as_str),
        Some("EC")
    );
    assert!(ctx.holder_public_jwk.get("x").is_some());
    assert!(ctx.holder_public_jwk.get("y").is_some());
    assert!(
        ctx.holder_public_jwk.get("d").is_none(),
        "a HolderContext must never carry the private scalar `d`"
    );
    // The cnf the issuer would bind is `{jwk: <public>}` — still no private material.
    assert!(ctx.cnf().get("jwk").is_some());
    assert!(ctx.cnf()["jwk"].get("d").is_none());
    // The public SEC1 point decodes to the uncompressed 65-byte form.
    assert_eq!(ctx.public_sec1().expect("sec1").len(), 65);
}

#[test]
fn private_jwk_members_are_stripped_before_embedding_in_pop_jwt_and_cnf() {
    // A common JWK-export mistake leaves private/symmetric members attached to a "public" JWK. The
    // SDK is the documented last line of defense (FR-010 / Constitution IV): it MUST strip them before
    // the JWK is embedded anywhere on the wire (the PoP-JWT JOSE header POSTed to the issuer, and the
    // `cnf` the issuer binds).
    let mut leaky = serde_json::from_slice::<Value>(HOLDER_JWK_JSON).expect("holder JWK");
    let obj = leaky.as_object_mut().expect("jwk object");
    // The EC private scalar plus every RSA CRT / symmetric member the SDK promises to drop.
    for member in ["d", "p", "q", "dp", "dq", "qi", "k", "oth"] {
        obj.insert(
            member.to_owned(),
            Value::String("LEAKED-PRIVATE".to_owned()),
        );
    }
    let ctx = HolderContext::new(leaky, "holder-key-handle");

    // public_jwk_only() / cnf() emit only the public key.
    let public = ctx.public_jwk_only();
    let cnf = ctx.cnf();
    for member in ["d", "p", "q", "dp", "dq", "qi", "k", "oth"] {
        assert!(
            public.get(member).is_none(),
            "public_jwk_only must strip `{member}`"
        );
        assert!(
            cnf["jwk"].get(member).is_none(),
            "cnf must strip `{member}`"
        );
    }
    // The public coordinates survive (the key is still usable).
    assert_eq!(public.get("kty").and_then(Value::as_str), Some("EC"));
    assert!(public.get("x").is_some() && public.get("y").is_some());

    // The PoP-JWT JOSE header carries the STRIPPED JWK — no private member rides to the issuer, and
    // the raw token text never contains the leaked sentinel.
    let build = build_pop_jwt(&ctx, ISSUER_ID, C_NONCE, NOW).expect("build PoP-JWT");
    let pop_jwt = build.assemble(&[0u8; 64]).expect("assemble PoP-JWT");
    let header_b64 = pop_jwt.split('.').next().expect("header");
    let header: Value =
        serde_json::from_slice(&Base64UrlUnpadded::decode_vec(header_b64).expect("hdr b64"))
            .expect("hdr json");
    let header_jwk = header.get("jwk").expect("header jwk");
    for member in ["d", "p", "q", "dp", "dq", "qi", "k", "oth"] {
        assert!(
            header_jwk.get(member).is_none(),
            "the PoP-JWT header JWK must not carry `{member}`"
        );
    }
    assert!(
        !pop_jwt.contains("LEAKED-PRIVATE"),
        "no private member value may appear anywhere in the PoP-JWT"
    );
}

#[test]
fn public_sec1_rejects_non_p256_jwk() {
    assert!(HolderContext::new(json!({"kty": "RSA"}), "h")
        .public_sec1()
        .is_none());
    assert!(HolderContext::new(
        json!({"kty": "EC", "crv": "P-384", "x": "AA", "y": "AA"}),
        "h"
    )
    .public_sec1()
    .is_none());
    let short = json!({"kty": "EC", "crv": "P-256", "x": "AA", "y": "AA"});
    assert!(HolderContext::new(short, "h").public_sec1().is_none());
}

// --- The SDK builds the exact signing_input and exposes aud/nonce --------------------------------

#[test]
fn pop_jwt_signing_input_exposes_aud_and_nonce_for_host_policy() {
    let ctx = holder_ctx();
    let build = build_pop_jwt(&ctx, ISSUER_ID, C_NONCE, NOW).expect("build PoP-JWT");
    // The host can inspect what it is about to blind-sign (the trust boundary, RCA-documented).
    assert_eq!(build.input.ceremony(), Ceremony::Oid4vciProof);
    assert_eq!(build.input.audience(), ISSUER_ID);
    assert_eq!(build.input.nonce(), C_NONCE);
    // The signing input is deterministic: the same call yields byte-identical to-be-signed bytes.
    let build2 = build_pop_jwt(&ctx, ISSUER_ID, C_NONCE, NOW).expect("build PoP-JWT again");
    assert_eq!(build.input.to_be_signed(), build2.input.to_be_signed());
}

#[test]
fn pop_jwt_round_trips_through_the_signer_hook() {
    // The SDK builds the input; the stub HSM signs it; the SDK splices → a verifiable compact JWS
    // whose header carries the holder public JWK (what the issuer binds as the credential `cnf`).
    let ctx = holder_ctx();
    let hsm = StubHsm::new(HOLDER_KEY_PK8);
    let build = build_pop_jwt(&ctx, ISSUER_ID, C_NONCE, NOW).expect("build PoP-JWT");
    let signature = hsm.sign(&ctx.key_handle, &build.input).expect("HSM signs");
    let pop_jwt = build.assemble(&signature).expect("splice PoP-JWT");

    // The HSM saw exactly the PoP ceremony with the issuer aud + c_nonce, under the holder handle.
    assert_eq!(
        hsm.seen.borrow().as_slice(),
        [(
            "holder-key-handle".to_owned(),
            Ceremony::Oid4vciProof,
            ISSUER_ID.to_owned(),
            C_NONCE.to_owned()
        )]
    );

    // Verify the produced PoP-JWT: typ/alg header, aud/nonce payload, and the ES256 signature over
    // `header.payload` under the holder public key from the header `jwk`.
    let (header, payload) = verify_compact_jws_with_header_jwk(&pop_jwt);
    assert_eq!(
        header.get("typ").and_then(Value::as_str),
        Some("openid4vci-proof+jwt")
    );
    assert_eq!(header.get("alg").and_then(Value::as_str), Some("ES256"));
    assert_eq!(payload.get("aud").and_then(Value::as_str), Some(ISSUER_ID));
    assert_eq!(payload.get("nonce").and_then(Value::as_str), Some(C_NONCE));
}

#[test]
fn bad_signature_length_is_rejected_on_splice() {
    let ctx = holder_ctx();
    let build = build_pop_jwt(&ctx, ISSUER_ID, C_NONCE, NOW).expect("build PoP-JWT");
    let err = build.assemble(&[0u8; 10]).unwrap_err();
    assert!(matches!(
        err,
        SignerError::BadSignatureLength(SignatureAlgorithm::Es256, 10)
    ));
    // The KB-JWT splice enforces the same invariant.
    let kb = build_kb_jwt(AUDIENCE, NONCE, NOW, "prefix~").expect("build KB-JWT");
    assert!(matches!(
        kb.assemble(&[0u8; 7]).unwrap_err(),
        SignerError::BadSignatureLength(SignatureAlgorithm::Es256, 7)
    ));
}

// --- The produced KB-JWT verifies under the US1 SD-JWT VC verifier -------------------------------

#[test]
fn kb_jwt_built_via_signer_hook_verifies_under_us1() {
    use crate::sdjwtvc::{verify_sd_jwt_vc, KeyBindingChallenge, SdJwtVcInput, StatusInput};
    use crate::trust::StaticTestAnchors;
    use crate::types::{Format, IssuerRole};

    // The SDK builds the KB-JWT signing input over the presentation prefix; the stub HSM signs; the
    // SDK splices. (The issuer side — minting the SD-JWT — is out of the hook's scope.)
    let sd_jwt = mint_sd_jwt(ISSUER_KEY_PK8, ISSUER_CERT_DER);
    let presentation_prefix = sd_jwt.presentation(); // issuer-JWS + disclosures + trailing `~`
    let hsm = StubHsm::new(HOLDER_KEY_PK8);
    let build = build_kb_jwt(AUDIENCE, NONCE, NOW, &presentation_prefix).expect("build KB-JWT");
    assert_eq!(build.input.ceremony(), Ceremony::KeyBinding);
    assert_eq!(build.input.audience(), AUDIENCE);
    assert_eq!(build.input.nonce(), NONCE);
    let signature = hsm
        .sign("holder-key-handle", &build.input)
        .expect("HSM signs KB-JWT");
    let kb_jwt = build.assemble(&signature).expect("splice KB-JWT");
    let presentation = format!("{presentation_prefix}{kb_jwt}");

    // The US1 verifier accepts it: full always-on bar + the KB-JWT holder binding over aud/nonce.
    let anchors = StaticTestAnchors::new().trust(IssuerRole::Pid, Format::SdJwtVc, ISSUER_CERT_DER);
    let result = verify_sd_jwt_vc(&SdJwtVcInput {
        presentation: &presentation,
        anchors: &anchors,
        role: IssuerRole::Pid,
        key_binding: Some(KeyBindingChallenge {
            audience: AUDIENCE,
            nonce: NONCE,
        }),
        now_unix: NOW,
        status: StatusInput::NoStatus,
    });
    assert!(
        result.valid,
        "KB-JWT from the hook must verify under US1; reasons {:?}",
        result.reasons
    );
    assert!(result.disclosed_attributes.contains_key("given_name"));
}

// --- The produced DeviceSignature verifies under the US1 mdoc verifier ---------------------------

#[test]
fn device_signature_built_via_signer_hook_verifies_under_us1_openid4vp() {
    use crate::mdoc::test_issuer::{mdoc_ds_cert_der, MdocBuilder};
    use crate::openid4vp::{
        oid4vp_handover_transcript, verify_response, Dcql, MdocVpToken, PresentationRequest,
        VpToken,
    };
    use crate::trust::StaticTestAnchors;
    use crate::types::{Format, IssuerRole, VerificationPolicy};

    // The request the holder binds to (audience + fresh nonce); the handover transcript folds them in.
    let request = PresentationRequest {
        dcql: Dcql::from_json("{}"),
        nonce: b"fresh-nonce-1234".to_vec(),
        audience: AUDIENCE.to_owned(),
        response_uri: RESPONSE_URI.to_owned(),
    };
    let transcript =
        oid4vp_handover_transcript(&request.audience, &request.nonce, &request.response_uri);

    // The SDK builds the DeviceSignature signing input over the DeviceAuthentication; the stub HSM
    // signs the COSE Sig_structure; the SDK splices → a detached COSE_Sign1.
    let doc_type = "org.iso.18013.5.1.mDL";
    // The test issuer's DeviceResponse carries an empty DeviceNameSpaces, so sign over the matching
    // empty `DeviceNameSpacesBytes` (the verifier rebuilds DeviceAuthentication from the document's
    // actual deviceSigned.nameSpaces).
    let device_name_spaces_bytes = crate::issuance::device::empty_device_name_spaces_bytes();
    let build = build_device_signature(
        doc_type,
        &transcript,
        &device_name_spaces_bytes,
        &request.audience,
        request.nonce_b64().as_str(),
    )
    .expect("build DeviceSignature");
    assert_eq!(build.input.ceremony(), Ceremony::DeviceSignature);
    assert_eq!(build.input.audience(), AUDIENCE);
    let hsm = StubHsm::new(HOLDER_KEY_PK8);
    let signature = hsm
        .sign("holder-key-handle", &build.input)
        .expect("HSM signs DeviceSignature");
    let device_signature_cbor = build.assemble(&signature).expect("splice DeviceSignature");

    // Splice the holder DeviceSignature into a DeviceResponse the conformant test issuer mints with
    // the matching session transcript, then verify the whole vp_token under US1 OpenID4VP.
    let device_response = MdocBuilder::new()
        .session_transcript(transcript)
        .with_device_signature_cbor(device_signature_cbor)
        .build();
    let anchors = StaticTestAnchors::new().trust(IssuerRole::Pid, Format::Mdoc, mdoc_ds_cert_der());
    let result = verify_response(
        &VpToken::Mdoc(MdocVpToken {
            audience: AUDIENCE,
            device_response: &device_response,
        }),
        &request,
        &VerificationPolicy::default(),
        &anchors,
        1_700_000_000,
        IssuerRole::Pid,
        &[crate::status::StatusOutcome::NoStatus],
    );
    assert!(
        result.valid,
        "DeviceSignature from the hook must verify under US1; reasons {:?}",
        result.reasons
    );
}

// --- A test-local verifier for the PoP-JWT (the only ceremony with no US1 verifier path) ---------

/// Verify a compact `header.payload.signature` ES256 JWS whose holder public key is in the header
/// `jwk` (the PoP-JWT shape), returning the decoded header + payload. Panics on any failure (a test).
fn verify_compact_jws_with_header_jwk(jws: &str) -> (Value, Value) {
    use p256::ecdsa::signature::Verifier as _;
    let mut parts = jws.split('.');
    let header_b64 = parts.next().expect("header");
    let payload_b64 = parts.next().expect("payload");
    let sig_b64 = parts.next().expect("signature");
    let header: Value =
        serde_json::from_slice(&Base64UrlUnpadded::decode_vec(header_b64).expect("hdr b64"))
            .expect("hdr json");
    let payload: Value =
        serde_json::from_slice(&Base64UrlUnpadded::decode_vec(payload_b64).expect("pl b64"))
            .expect("pl json");
    let jwk = header.get("jwk").expect("header jwk");
    let x = Base64UrlUnpadded::decode_vec(jwk["x"].as_str().expect("x")).expect("x b64");
    let y = Base64UrlUnpadded::decode_vec(jwk["y"].as_str().expect("y")).expect("y b64");
    let mut sec1 = vec![0x04];
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).expect("holder key");
    let sig = Signature::from_slice(&Base64UrlUnpadded::decode_vec(sig_b64).expect("sig b64"))
        .expect("sig");
    let signing_input = format!("{header_b64}.{payload_b64}");
    key.verify(signing_input.as_bytes(), &sig)
        .expect("PoP-JWT signature verifies");
    (header, payload)
}
