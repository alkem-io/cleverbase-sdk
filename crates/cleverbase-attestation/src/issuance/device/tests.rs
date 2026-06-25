//! Direct unit tests for the mdoc `DeviceSignature` ceremony builder (the error/edge paths the
//! end-to-end round-trip in `signer/tests.rs` does not exercise).

use crate::issuance::device::{build_device_signature, empty_device_name_spaces_bytes};
use crate::issuance::signer::{Ceremony, SignatureAlgorithm, SignerError};
use crate::openid4vp::oid4vp_handover_transcript;

const AUDIENCE: &str = "https://verifier.example/cb";
/// The verifier's `response_uri` request parameter (OpenID4VP 1.0 §B.2.6 4th handover element).
const RESPONSE_URI: &str = "https://verifier.example/cb/response";

fn a_build() -> crate::issuance::device::DeviceSignatureBuild {
    let transcript = oid4vp_handover_transcript(AUDIENCE, b"nonce-bytes-here", RESPONSE_URI);
    let device_ns = empty_device_name_spaces_bytes().expect("empty device namespaces");
    build_device_signature(
        "org.iso.18013.5.1.mDL",
        &transcript,
        &device_ns,
        AUDIENCE,
        "bm9uY2U",
    )
    .expect("build DeviceSignature")
}

#[test]
fn build_is_deterministic_and_exposes_aud_nonce() {
    let b1 = a_build();
    let b2 = a_build();
    assert_eq!(b1.input.to_be_signed(), b2.input.to_be_signed());
    assert_eq!(b1.device_auth_payload, b2.device_auth_payload);
    assert_eq!(b1.input.ceremony(), Ceremony::DeviceSignature);
    assert_eq!(b1.input.algorithm(), SignatureAlgorithm::Es256);
    assert_eq!(b1.input.audience(), AUDIENCE);
    assert_eq!(b1.input.nonce(), "bm9uY2U");
}

#[test]
fn assemble_rejects_a_wrong_length_signature() {
    let build = a_build();
    let err = build.assemble(&[0u8; 33]).unwrap_err();
    assert!(matches!(
        err,
        SignerError::BadSignatureLength(SignatureAlgorithm::Es256, 33)
    ));
}

#[test]
fn assemble_with_a_64_byte_signature_produces_decodable_cose_sign1() {
    use coset::{CborSerializable as _, CoseSign1};
    let build = a_build();
    // A syntactically valid (if cryptographically meaningless) 64-byte r‖s: assemble must produce a
    // decodable detached COSE_Sign1 carrying that signature (the crypto check is the verifier's job).
    let cose = build.assemble(&[7u8; 64]).expect("assemble");
    let sign1 = CoseSign1::from_slice(&cose).expect("decode COSE_Sign1");
    assert_eq!(sign1.signature, vec![7u8; 64]);
    assert!(sign1.payload.is_none(), "the DeviceSignature is detached");
}

#[test]
fn malformed_session_transcript_is_a_serialize_error_not_a_panic() {
    // A truncated/invalid CBOR transcript (an indefinite-length map header with no break) surfaces as
    // a clean error (never a panic — the strict bar forbids them).
    let device_ns = empty_device_name_spaces_bytes().expect("empty device namespaces");
    let err = build_device_signature("doc", &[0xbf, 0x00], &device_ns, AUDIENCE, "n").unwrap_err();
    assert!(matches!(err, SignerError::Serialize(_)));
}
