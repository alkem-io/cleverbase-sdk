//! T008 — fail-first tests for the ISO/IEC 18013-5 mdoc verifier (T012).
//!
//! Each test mints an mdoc with the test issuer helper, mutating exactly one property to drive a
//! single always-on-bar check, and asserts the verdict (VALID + disclosed attributes, or INVALID
//! with the specific [`ReasonCode`] — no false-accept).

use ciborium::value::Value as CborValue;

use super::test_issuer::{
    mdoc_ds_cert_der, wrong_issuer_cert_der, DigestAlg, Element, MdocBuilder,
};
use super::{verify, MdocVerifyParams};
use crate::status::StatusOutcome;
use crate::trust::StaticTestAnchors;
use crate::types::{AttributeValue, Format, IssuerRole, ReasonCode, TrustStatus};

/// The verification instant (2024-06-01T00:00:00Z) — inside the default issued window.
const NOW: i64 = 1_717_200_000;

/// Anchors trusting the test DS cert as a PID/mdoc issuer (the role the params use).
fn trusted_anchors() -> StaticTestAnchors {
    StaticTestAnchors::new().trust(IssuerRole::Pid, Format::Mdoc, mdoc_ds_cert_der())
}

/// Anchors that trust the wrong-issuer cert (so an untrusted-DS reject is *not* a "cert absent"
/// artifact — the wrong-issuer is genuinely off the configured anchor for this role/format).
fn anchors_without_ds() -> StaticTestAnchors {
    StaticTestAnchors::new()
}

fn params() -> MdocVerifyParams<'static> {
    MdocVerifyParams {
        now_unix: NOW,
        session_transcript: None,
        role: IssuerRole::Pid,
        status: StatusOutcome::NoStatus,
    }
}

#[test]
fn valid_mdoc_verifies_and_returns_disclosed_attributes() {
    let response = MdocBuilder::new().build();
    let result = verify(&response, &trusted_anchors(), &params());

    assert!(
        result.valid,
        "well-formed in-window trusted mdoc must verify"
    );
    assert!(
        result.reasons.is_empty(),
        "a clean VALID carries no reasons"
    );
    assert_eq!(result.trust_status, TrustStatus::Trusted);
    assert!(result.qualified_status.is_none());

    // The three disclosed elements are returned, decoded to AttributeValue.
    assert_eq!(
        result.disclosed_attributes.get("family_name"),
        Some(&AttributeValue::Text("Doe".to_owned()))
    );
    assert_eq!(
        result.disclosed_attributes.get("given_name"),
        Some(&AttributeValue::Text("Ada".to_owned()))
    );
    assert_eq!(
        result.disclosed_attributes.get("age_over_18"),
        Some(&AttributeValue::Boolean(true))
    );
}

#[test]
fn value_digest_mismatch_is_rejected_as_disclosure_integrity() {
    // A disclosed item whose recomputed digest does not match the MSO valueDigests entry.
    let response = MdocBuilder::new().corrupt_value_digest().build();
    let result = verify(&response, &trusted_anchors(), &params());

    assert!(!result.valid, "a tampered disclosure must not verify");
    assert_eq!(result.reasons, vec![ReasonCode::DisclosureIntegrity]);
    assert!(result.disclosed_attributes.is_empty());
}

#[test]
fn expired_validity_info_is_rejected_as_expired() {
    // Issue a window that has fully elapsed before NOW.
    let response = MdocBuilder::new()
        .validity("2020-01-01T00:00:00Z", "2021-01-01T00:00:00Z")
        .build();
    let result = verify(&response, &trusted_anchors(), &params());

    assert!(!result.valid, "an expired mdoc must not verify");
    assert_eq!(result.reasons, vec![ReasonCode::Expired]);
}

#[test]
fn not_yet_valid_validity_info_is_rejected_as_expired() {
    // A window that begins after NOW (validFrom in the future).
    let response = MdocBuilder::new()
        .validity("2029-01-01T00:00:00Z", "2030-01-01T00:00:00Z")
        .build();
    let result = verify(&response, &trusted_anchors(), &params());

    assert!(!result.valid, "a not-yet-valid mdoc must not verify");
    assert_eq!(result.reasons, vec![ReasonCode::Expired]);
}

#[test]
fn tampered_issuer_auth_signature_is_rejected_as_tamper() {
    let response = MdocBuilder::new().corrupt_issuer_auth().build();
    let result = verify(&response, &trusted_anchors(), &params());

    assert!(
        !result.valid,
        "a broken IssuerAuth signature must not verify"
    );
    assert_eq!(result.reasons, vec![ReasonCode::Tamper]);
}

#[test]
fn untrusted_document_signer_is_rejected_as_untrusted_issuer() {
    // The mdoc is signed by the wrong-issuer cert/key (a valid self-signed cert with a valid
    // signature), but that cert is not on the configured anchor → UntrustedIssuer.
    let response = MdocBuilder::new().use_wrong_issuer().build();
    let anchors = trusted_anchors(); // trusts mdoc-ds, NOT wrong-issuer
    let result = verify(&response, &anchors, &params());

    assert!(!result.valid, "an untrusted DS must not verify");
    assert_eq!(result.reasons, vec![ReasonCode::UntrustedIssuer]);
}

#[test]
fn trusted_ds_absent_from_anchors_is_untrusted_issuer() {
    // A well-formed, correctly-signed mdoc whose DS simply is not on the (empty) anchor set.
    let response = MdocBuilder::new().build();
    let result = verify(&response, &anchors_without_ds(), &params());

    assert!(!result.valid);
    assert_eq!(result.reasons, vec![ReasonCode::UntrustedIssuer]);
}

#[test]
fn bad_device_signature_is_rejected_as_holder_binding() {
    // The DeviceSignature is made by a non-holder key, so it does not verify against the MSO
    // DeviceKey → HolderBinding.
    let response = MdocBuilder::new().corrupt_device_signature().build();
    let result = verify(&response, &trusted_anchors(), &params());

    assert!(!result.valid, "a bad holder binding must not verify");
    assert_eq!(result.reasons, vec![ReasonCode::HolderBinding]);
}

#[test]
fn malformed_cbor_is_rejected_as_malformed_credential() {
    // Not CBOR at all.
    let result = verify(&[0xff, 0x00, 0x13, 0x37], &trusted_anchors(), &params());
    assert!(!result.valid);
    assert_eq!(result.reasons, vec![ReasonCode::MalformedCredential]);

    // Valid CBOR but not a DeviceResponse shape (no `documents`).
    let mut empty_map = Vec::new();
    ciborium::into_writer(&ciborium::value::Value::Map(vec![]), &mut empty_map).unwrap();
    let result = verify(&empty_map, &trusted_anchors(), &params());
    assert!(!result.valid);
    assert_eq!(result.reasons, vec![ReasonCode::MalformedCredential]);
}

#[test]
fn untrusted_check_uses_wrong_issuer_cert_fixture() {
    // Document the fixture identity used by the untrusted path so a fixture rotation that breaks the
    // chain is caught here rather than silently flipping a verdict.
    assert_ne!(mdoc_ds_cert_der(), wrong_issuer_cert_der());
}

#[test]
fn sha384_digest_algorithm_verifies() {
    // The MSO may name SHA-384; the verifier must recompute with the matching hash and still verify.
    let response = MdocBuilder::new()
        .digest_algorithm(DigestAlg::Sha384)
        .build();
    let result = verify(&response, &trusted_anchors(), &params());
    assert!(result.valid, "a SHA-384 MSO must verify");
    assert!(result.disclosed_attributes.contains_key("given_name"));
}

#[test]
fn unsupported_digest_algorithm_is_rejected_as_malformed() {
    // An unrecognized `digestAlgorithm` (here "SHA-1") must never be guessed — it is malformed.
    let response = MdocBuilder::new()
        .digest_algorithm(DigestAlg::Unsupported)
        .build();
    let result = verify(&response, &trusted_anchors(), &params());
    assert!(!result.valid);
    assert_eq!(result.reasons, vec![ReasonCode::MalformedCredential]);
}

#[test]
fn explicit_session_transcript_binds_the_device_signature() {
    // When the DeviceSignature is computed over a non-null transcript, passing the same transcript
    // bytes to the verifier verifies; the holder binding is bound to that transcript.
    let transcript = encode_cbor(&CborValue::Array(vec![
        CborValue::Text("DeviceEngagement".to_owned()),
        CborValue::Integer(7.into()),
    ]));
    let response = MdocBuilder::new()
        .session_transcript(transcript.clone())
        .build();
    let p = MdocVerifyParams {
        now_unix: NOW,
        session_transcript: Some(&transcript),
        role: IssuerRole::Pid,
        status: StatusOutcome::NoStatus,
    };
    let result = verify(&response, &trusted_anchors(), &p);
    assert!(result.valid, "matching session transcript must verify");
}

#[test]
fn session_transcript_mismatch_fails_holder_binding() {
    // A DeviceSignature bound to transcript A does not verify when the verifier is given transcript
    // B (replay/transport-binding protection surfaces as a holder-binding failure).
    let transcript_a = encode_cbor(&CborValue::Array(vec![CborValue::Integer(1.into())]));
    let transcript_b = encode_cbor(&CborValue::Array(vec![CborValue::Integer(2.into())]));
    let response = MdocBuilder::new().session_transcript(transcript_a).build();
    let p = MdocVerifyParams {
        now_unix: NOW,
        session_transcript: Some(&transcript_b),
        role: IssuerRole::Pid,
        status: StatusOutcome::NoStatus,
    };
    let result = verify(&response, &trusted_anchors(), &p);
    assert!(!result.valid);
    assert_eq!(result.reasons, vec![ReasonCode::HolderBinding]);
}

#[test]
fn device_signature_with_non_es256_alg_fails_holder_binding() {
    // The device-auth algorithm gate is ES256; a DeviceSignature with an ES384 header is rejected.
    let response = MdocBuilder::new().device_sig_wrong_alg().build();
    let result = verify(&response, &trusted_anchors(), &params());
    assert!(!result.valid);
    assert_eq!(result.reasons, vec![ReasonCode::HolderBinding]);
}

#[test]
fn heterogeneous_element_values_decode_to_attribute_values() {
    // Exercise every elementValue → AttributeValue projection: integer, bytes, array, map, null.
    let elements = vec![
        Element {
            digest_id: 0,
            identifier: "age",
            value: CborValue::Integer(42.into()),
        },
        Element {
            digest_id: 1,
            identifier: "portrait",
            value: CborValue::Bytes(vec![0xDE, 0xAD]),
        },
        Element {
            digest_id: 2,
            identifier: "tags",
            value: CborValue::Array(vec![CborValue::Text("a".to_owned()), CborValue::Null]),
        },
        Element {
            digest_id: 3,
            identifier: "address",
            value: CborValue::Map(vec![(
                CborValue::Text("city".to_owned()),
                CborValue::Text("London".to_owned()),
            )]),
        },
        Element {
            digest_id: 4,
            identifier: "absent",
            value: CborValue::Null,
        },
    ];
    let response = MdocBuilder::new().elements(elements).build();
    let result = verify(&response, &trusted_anchors(), &params());
    assert!(result.valid, "heterogeneous values must verify");

    let attrs = &result.disclosed_attributes;
    assert_eq!(attrs.get("age"), Some(&AttributeValue::Integer(42)));
    assert_eq!(
        attrs.get("portrait"),
        Some(&AttributeValue::Bytes(vec![0xDE, 0xAD]))
    );
    assert_eq!(
        attrs.get("tags"),
        Some(&AttributeValue::Array(vec![
            AttributeValue::Text("a".to_owned()),
            AttributeValue::Null,
        ]))
    );
    let mut want = std::collections::BTreeMap::new();
    want.insert("city".to_owned(), AttributeValue::Text("London".to_owned()));
    assert_eq!(attrs.get("address"), Some(&AttributeValue::Map(want)));
    assert_eq!(attrs.get("absent"), Some(&AttributeValue::Null));
}

#[test]
fn non_ec2_device_key_is_rejected_as_malformed() {
    // A COSE_Key with kty=OKP (1) instead of EC2 (2) is not a P-256 device key → malformed.
    let okp_key = CborValue::Map(vec![
        (CborValue::Integer(1.into()), CborValue::Integer(1.into())), // kty = OKP
        (
            CborValue::Integer((-1).into()),
            CborValue::Integer(6.into()),
        ), // crv = Ed25519
        (
            CborValue::Integer((-2).into()),
            CborValue::Bytes(vec![0u8; 32]),
        ),
    ]);
    let response = MdocBuilder::new().device_key_override(okp_key).build();
    let result = verify(&response, &trusted_anchors(), &params());
    assert!(!result.valid);
    assert_eq!(result.reasons, vec![ReasonCode::MalformedCredential]);
}

#[test]
fn wrong_curve_device_key_is_rejected_as_malformed() {
    // An EC2 key on a non-P-256 curve (crv=2 / P-384) is rejected.
    let p384_key = CborValue::Map(vec![
        (CborValue::Integer(1.into()), CborValue::Integer(2.into())), // kty = EC2
        (
            CborValue::Integer((-1).into()),
            CborValue::Integer(2.into()),
        ), // crv = P-384
        (
            CborValue::Integer((-2).into()),
            CborValue::Bytes(vec![0u8; 48]),
        ),
        (
            CborValue::Integer((-3).into()),
            CborValue::Bytes(vec![0u8; 48]),
        ),
    ]);
    let response = MdocBuilder::new().device_key_override(p384_key).build();
    let result = verify(&response, &trusted_anchors(), &params());
    assert!(!result.valid);
    assert_eq!(result.reasons, vec![ReasonCode::MalformedCredential]);
}

#[test]
fn short_coordinate_device_key_is_rejected_as_malformed() {
    // An EC2/P-256 key whose X coordinate is not 32 bytes is rejected.
    let short_key = CborValue::Map(vec![
        (CborValue::Integer(1.into()), CborValue::Integer(2.into())), // kty = EC2
        (
            CborValue::Integer((-1).into()),
            CborValue::Integer(1.into()),
        ), // crv = P-256
        (
            CborValue::Integer((-2).into()),
            CborValue::Bytes(vec![0u8; 10]),
        ),
        (
            CborValue::Integer((-3).into()),
            CborValue::Bytes(vec![0u8; 32]),
        ),
    ]);
    let response = MdocBuilder::new().device_key_override(short_key).build();
    let result = verify(&response, &trusted_anchors(), &params());
    assert!(!result.valid);
    assert_eq!(result.reasons, vec![ReasonCode::MalformedCredential]);
}

#[test]
fn default_params_are_offline_pid_at_epoch() {
    // The Default impl documents the offline-suite shape (no transcript, PID role, zero instant).
    let p = MdocVerifyParams::default();
    assert_eq!(p.now_unix, 0);
    assert!(p.session_transcript.is_none());
    assert_eq!(p.role, IssuerRole::Pid);
    assert_eq!(p.status, StatusOutcome::NoStatus);
}

#[test]
fn revoked_status_is_rejected_as_revoked() {
    // A well-formed mdoc whose status seam reports Revoked must be rejected (always-on bar T014).
    let response = MdocBuilder::new().build();
    let p = MdocVerifyParams {
        now_unix: NOW,
        session_transcript: None,
        role: IssuerRole::Pid,
        status: StatusOutcome::Revoked,
    };
    let result = verify(&response, &trusted_anchors(), &p);
    assert!(!result.valid);
    assert_eq!(result.reasons, vec![ReasonCode::Revoked]);
}

#[test]
fn unavailable_status_is_rejected_as_status_unavailable() {
    // An unreachable status under the fail-closed policy surfaces as StatusUnavailable.
    let response = MdocBuilder::new().build();
    let p = MdocVerifyParams {
        now_unix: NOW,
        session_transcript: None,
        role: IssuerRole::Pid,
        status: StatusOutcome::Unavailable,
    };
    let result = verify(&response, &trusted_anchors(), &p);
    assert!(!result.valid);
    assert_eq!(result.reasons, vec![ReasonCode::StatusUnavailable]);
}

#[test]
fn good_status_still_verifies() {
    // A reachable status that reports the credential current does not disturb a VALID verdict.
    let response = MdocBuilder::new().build();
    let p = MdocVerifyParams {
        now_unix: NOW,
        session_transcript: None,
        role: IssuerRole::Pid,
        status: StatusOutcome::Good,
    };
    let result = verify(&response, &trusted_anchors(), &p);
    assert!(
        result.valid,
        "a Good status must not disturb a VALID verdict"
    );
}

#[test]
fn sha512_digest_algorithm_verifies() {
    let response = MdocBuilder::new()
        .digest_algorithm(DigestAlg::Sha512)
        .build();
    let result = verify(&response, &trusted_anchors(), &params());
    assert!(result.valid, "a SHA-512 MSO must verify");
}

#[test]
fn issuer_auth_non_es256_alg_is_rejected_as_tamper() {
    // The IssuerAuth algorithm gate is ES256; an ES384 header is rejected before any verify attempt.
    let response = MdocBuilder::new().issuer_auth_wrong_alg().build();
    let result = verify(&response, &trusted_anchors(), &params());
    assert!(!result.valid);
    assert_eq!(result.reasons, vec![ReasonCode::Tamper]);
}

#[test]
fn tagged_issuer_auth_cose_sign1_verifies() {
    // The `#6.18`-tagged COSE_Sign1 form is accepted (defensive parse path).
    let response = MdocBuilder::new().tag_issuer_auth().build();
    let result = verify(&response, &trusted_anchors(), &params());
    assert!(result.valid, "a tagged IssuerAuth must verify");
}

#[test]
fn x5chain_as_array_resolves_the_leaf_cert() {
    // A one-element x5chain *array* resolves to the same leaf DS cert as the bare-bstr form.
    let response = MdocBuilder::new().x5chain_as_array().build();
    let result = verify(&response, &trusted_anchors(), &params());
    assert!(result.valid, "an array x5chain must resolve + verify");
}

#[test]
fn missing_x5chain_is_rejected_as_malformed() {
    let response = MdocBuilder::new().omit_x5chain().build();
    let result = verify(&response, &trusted_anchors(), &params());
    assert!(!result.valid);
    assert_eq!(result.reasons, vec![ReasonCode::MalformedCredential]);
}

#[test]
fn tdate_tagged_validity_dates_are_parsed() {
    // The `#6.0`-tagged tdate form (common on the wire) is decoded and the window enforced.
    let response = MdocBuilder::new().tdate_tagged().build();
    let result = verify(&response, &trusted_anchors(), &params());
    assert!(result.valid, "tdate-tagged validityInfo must verify");
}

#[test]
fn mso_doc_type_mismatch_is_rejected_as_tamper() {
    // The MSO docType must match the document docType; a mismatch is a structural tamper.
    let response = MdocBuilder::new().mso_doc_type_mismatch().build();
    let result = verify(&response, &trusted_anchors(), &params());
    assert!(!result.valid);
    assert_eq!(result.reasons, vec![ReasonCode::Tamper]);
}

#[test]
fn multi_document_response_with_a_forged_second_document_is_rejected() {
    // FALSE-ACCEPT PROBE: a DeviceResponse with TWO documents where `documents[1]` has a corrupted
    // IssuerAuth signature. Verifying only `documents[0]` (the old behavior) returns VALID while the
    // forged second document rides along unverified. The verifier MUST verify every document, so this
    // response is rejected on the forged document's IssuerAuth signature (Tamper).
    let response = MdocBuilder::new().append_forged_document().build();
    let result = verify(&response, &trusted_anchors(), &params());
    assert!(
        !result.valid,
        "a multi-document response with a forged second document must NOT be VALID"
    );
    assert_eq!(result.reasons, vec![ReasonCode::Tamper]);
    assert!(result.disclosed_attributes.is_empty());
}

#[test]
fn future_signed_mso_is_rejected_as_tamper() {
    // The MSO `validityInfo.signed` is the instant the issuer asserts it signed the MSO; it cannot be
    // after `now`. A `signed` of 2029 (verifying at 2024) is impossible for a genuinely issued
    // credential and must be rejected, not discarded.
    let response = MdocBuilder::new().signed("2029-01-01T00:00:00Z").build();
    let result = verify(&response, &trusted_anchors(), &params());
    assert!(!result.valid, "a future-signed MSO must not verify");
    assert_eq!(result.reasons, vec![ReasonCode::Tamper]);
}

#[test]
fn signed_after_valid_from_is_rejected_as_tamper() {
    // `signed` must not be after `validFrom`: the issuer cannot claim the credential was valid before
    // it was signed. signed=2023-06 with validFrom=2023-01 is an inconsistent window. (signed stays
    // before `now`=2024-06, so this isolates the signed<=validFrom consistency check.)
    let response = MdocBuilder::new()
        .validity("2023-01-01T00:00:00Z", "2030-01-01T00:00:00Z")
        .signed("2023-06-01T00:00:00Z")
        .build();
    let result = verify(&response, &trusted_anchors(), &params());
    assert!(!result.valid, "signed after validFrom must not verify");
    assert_eq!(result.reasons, vec![ReasonCode::Tamper]);
}

#[test]
fn non_zero_device_response_status_is_rejected() {
    // A non-zero top-level DeviceResponse.status (e.g. 10 = general error) means the device did not
    // return a clean success; it MUST NOT carry a VALID verdict.
    let response = MdocBuilder::new().status(10).build();
    let result = verify(&response, &trusted_anchors(), &params());
    assert!(
        !result.valid,
        "a non-zero DeviceResponse.status must not verify"
    );
    assert_eq!(result.reasons, vec![ReasonCode::MalformedCredential]);
}

#[test]
fn absent_device_response_status_is_rejected_as_malformed() {
    // `status` is a mandatory DeviceResponse field; an absent status is a structurally malformed
    // response (and must not be defaulted to success).
    let response = MdocBuilder::new().omit_status().build();
    let result = verify(&response, &trusted_anchors(), &params());
    assert!(!result.valid);
    assert_eq!(result.reasons, vec![ReasonCode::MalformedCredential]);
}

#[test]
fn issuer_signing_cert_der_reads_the_claimed_ds_leaf() {
    // The qualified-gate cert-matching helper reads the claimed DS leaf from `documents[0]`'s
    // IssuerAuth x5chain without verifying anything; a well-formed response yields the DS cert DER,
    // and unparseable bytes yield `None` (never a panic). This also covers the `first_document` read
    // path the helper relies on.
    let response = MdocBuilder::new().build();
    assert_eq!(
        super::issuer_signing_cert_der(&response).as_deref(),
        Some(mdoc_ds_cert_der())
    );
    // Not CBOR at all → no claimed cert (the helper is read-only and total).
    assert!(super::issuer_signing_cert_der(&[0xff, 0x00]).is_none());
    // Valid CBOR but no `documents` → no claimed cert.
    let mut empty = Vec::new();
    ciborium::into_writer(&CborValue::Map(vec![]), &mut empty).unwrap();
    assert!(super::issuer_signing_cert_der(&empty).is_none());
}

#[test]
fn empty_documents_array_is_rejected_as_malformed() {
    // A DeviceResponse with an empty `documents` array carries no credential to verify; a VALID
    // verdict over zero documents is meaningless and must be rejected.
    let response = MdocBuilder::new().empty_documents().build();
    let result = verify(&response, &trusted_anchors(), &params());
    assert!(!result.valid);
    assert_eq!(result.reasons, vec![ReasonCode::MalformedCredential]);
}

#[test]
fn document_errors_present_is_rejected_as_malformed() {
    // A `documentErrors` entry means the device could not return a requested document; the response
    // is not a complete success and must be rejected rather than partially accepted.
    let response = MdocBuilder::new().add_document_errors().build();
    let result = verify(&response, &trusted_anchors(), &params());
    assert!(!result.valid);
    assert_eq!(result.reasons, vec![ReasonCode::MalformedCredential]);
}

/// Encode a `ciborium` value to CBOR bytes (test helper).
fn encode_cbor(value: &CborValue) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).unwrap();
    buf
}
