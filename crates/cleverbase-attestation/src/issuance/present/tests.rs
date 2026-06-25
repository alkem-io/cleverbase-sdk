//! Holder OpenID4VP `present` round-trip tests (US2 — task T023, written test-first against T026).
//!
//! `present` with a disclosed subset → a `vp_token` the **US1 verifier accepts** (the round-trip
//! oracle, [`crate::openid4vp::verify_response`]), bound to the verifier's request, revealing **only
//! the disclosed attributes**. Both formats.

use std::collections::BTreeSet;

use p256::ecdsa::{signature::Signer as _, Signature, SigningKey};
use pkcs8::DecodePrivateKey as _;
use serde_json::Value;

use super::super::signer::{HolderContext, Signer, SigningInput};
use super::super::{present, HeldAttestation, PresentError};
use crate::openid4vp::{verify_response, Dcql, PresentationRequest};
use crate::trust::StaticTestAnchors;
use crate::types::{Format, IssuerRole, VerificationPolicy};

const AUDIENCE: &str = "https://verifier.example/cb";
const NOW: i64 = 1_700_000_000;

/// A stub holder HSM (the only holder of a private key) signing the SDK-built input.
struct StubHsm {
    key: SigningKey,
}
impl Signer for StubHsm {
    type Error = String;
    fn sign(&self, _handle: &str, input: &SigningInput) -> Result<Vec<u8>, String> {
        let sig: Signature = self.key.sign(input.to_be_signed());
        Ok(sig.to_bytes().to_vec())
    }
}

fn hsm() -> StubHsm {
    use crate::sdjwtvc::test_issuer::HOLDER_KEY_PK8;
    StubHsm {
        key: SigningKey::from_pkcs8_der(HOLDER_KEY_PK8).expect("holder key"),
    }
}

fn holder_ctx() -> HolderContext {
    use crate::sdjwtvc::test_issuer::HOLDER_JWK_JSON;
    let jwk: Value = serde_json::from_slice(HOLDER_JWK_JSON).expect("holder JWK");
    HolderContext::new(jwk, "holder-handle")
}

fn request(nonce: &[u8]) -> PresentationRequest {
    PresentationRequest {
        dcql: Dcql::from_json("{}"),
        nonce: nonce.to_vec(),
        audience: AUDIENCE.to_owned(),
    }
}

fn subset(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|s| (*s).to_owned()).collect()
}

// --- SD-JWT VC: present a disclosed subset, verify under US1 -------------------------------------

#[test]
fn sd_jwt_vc_present_discloses_only_the_subset_and_verifies_under_us1() {
    use crate::sdjwtvc::test_issuer::{mint_sd_jwt, ISSUER_CERT_DER, ISSUER_KEY_PK8};

    // The held credential: the issued SD-JWT VC (issuer JWS + all disclosures, no KB-JWT yet).
    let held = HeldAttestation::SdJwtVc {
        issued: mint_sd_jwt(ISSUER_KEY_PK8, ISSUER_CERT_DER).presentation(),
    };
    let request = request(b"vp-nonce-aaaa");

    // Present disclosing ONLY given_name (conceal family_name + birthdate).
    let vp = present(
        &held,
        &request,
        &holder_ctx(),
        &subset(&["given_name"]),
        &hsm(),
        NOW,
    )
    .expect("present SD-JWT VC");

    // The vp_token verifies under US1 OpenID4VP (bound to the request) and reveals only given_name.
    let anchors = StaticTestAnchors::new().trust(IssuerRole::Pid, Format::SdJwtVc, ISSUER_CERT_DER);
    let result = verify_response(
        &vp.as_vp_token(),
        &request,
        &VerificationPolicy::default(),
        &anchors,
        crate::sdjwtvc::test_issuer::NOW,
        IssuerRole::Pid,
        crate::status::StatusOutcome::NoStatus,
    );
    assert!(
        result.valid,
        "presentation must verify under US1; reasons {:?}",
        result.reasons
    );
    assert!(result.disclosed_attributes.contains_key("given_name"));
    assert!(
        !result.disclosed_attributes.contains_key("family_name"),
        "concealed claim must NOT be revealed"
    );
    assert!(!result.disclosed_attributes.contains_key("birthdate"));
}

#[test]
fn sd_jwt_vc_present_full_disclosure_verifies_with_all_attributes() {
    use crate::sdjwtvc::test_issuer::{mint_sd_jwt, ISSUER_CERT_DER, ISSUER_KEY_PK8};
    let held = HeldAttestation::SdJwtVc {
        issued: mint_sd_jwt(ISSUER_KEY_PK8, ISSUER_CERT_DER).presentation(),
    };
    let request = request(b"vp-nonce-bbbb");
    let vp = present(
        &held,
        &request,
        &holder_ctx(),
        &subset(&["given_name", "family_name", "birthdate"]),
        &hsm(),
        NOW,
    )
    .expect("present");
    let anchors = StaticTestAnchors::new().trust(IssuerRole::Pid, Format::SdJwtVc, ISSUER_CERT_DER);
    let result = verify_response(
        &vp.as_vp_token(),
        &request,
        &VerificationPolicy::default(),
        &anchors,
        crate::sdjwtvc::test_issuer::NOW,
        IssuerRole::Pid,
        crate::status::StatusOutcome::NoStatus,
    );
    assert!(result.valid, "reasons {:?}", result.reasons);
    assert_eq!(result.disclosed_attributes.len(), 3);
}

#[test]
fn sd_jwt_vc_present_rejects_a_non_disclosable_claim() {
    use crate::sdjwtvc::test_issuer::{mint_sd_jwt, ISSUER_CERT_DER, ISSUER_KEY_PK8};
    let held = HeldAttestation::SdJwtVc {
        issued: mint_sd_jwt(ISSUER_KEY_PK8, ISSUER_CERT_DER).presentation(),
    };
    let err = present(
        &held,
        &request(b"n"),
        &holder_ctx(),
        &subset(&["not_a_claim"]),
        &hsm(),
        NOW,
    )
    .unwrap_err();
    assert!(matches!(err, PresentError::UndisclosableClaim(c) if c == "not_a_claim"));
}

#[test]
fn sd_jwt_vc_present_wrong_nonce_is_rejected_by_the_verifier() {
    // A presentation built for one request must NOT verify against a DIFFERENT request nonce (replay).
    use crate::sdjwtvc::test_issuer::{mint_sd_jwt, ISSUER_CERT_DER, ISSUER_KEY_PK8};
    let held = HeldAttestation::SdJwtVc {
        issued: mint_sd_jwt(ISSUER_KEY_PK8, ISSUER_CERT_DER).presentation(),
    };
    let built_for = request(b"nonce-one");
    let vp = present(
        &held,
        &built_for,
        &holder_ctx(),
        &subset(&["given_name"]),
        &hsm(),
        NOW,
    )
    .expect("present");
    let anchors = StaticTestAnchors::new().trust(IssuerRole::Pid, Format::SdJwtVc, ISSUER_CERT_DER);
    let other_request = request(b"nonce-two");
    let result = verify_response(
        &vp.as_vp_token(),
        &other_request,
        &VerificationPolicy::default(),
        &anchors,
        crate::sdjwtvc::test_issuer::NOW,
        IssuerRole::Pid,
        crate::status::StatusOutcome::NoStatus,
    );
    assert!(!result.valid, "a replayed presentation must be rejected");
    assert_eq!(result.reasons, vec![crate::types::ReasonCode::Replay]);
}

#[test]
fn present_malformed_held_credential_is_an_error() {
    let held = HeldAttestation::SdJwtVc {
        issued: "not-an-sd-jwt".to_owned(),
    };
    let err = present(
        &held,
        &request(b"n"),
        &holder_ctx(),
        &subset(&[]),
        &hsm(),
        NOW,
    )
    .unwrap_err();
    assert!(matches!(err, PresentError::Malformed(_)));
}

// --- mdoc: present bound to the request, verify under US1 ----------------------------------------

#[test]
fn mdoc_present_binds_to_the_request_and_verifies_under_us1() {
    use crate::mdoc::test_issuer::{mdoc_ds_cert_der, MdocBuilder};

    // The held mdoc: an issued DeviceResponse (its placeholder DeviceSignature is replaced at
    // presentation time by the request-bound holder signature).
    let held = HeldAttestation::Mdoc {
        device_response: MdocBuilder::new().build(),
    };
    let request = request(b"mdoc-vp-nonce");

    let vp =
        present(&held, &request, &holder_ctx(), &subset(&[]), &hsm(), NOW).expect("present mdoc");

    let anchors = StaticTestAnchors::new().trust(IssuerRole::Pid, Format::Mdoc, mdoc_ds_cert_der());
    let result = verify_response(
        &vp.as_vp_token(),
        &request,
        &VerificationPolicy::default(),
        &anchors,
        1_700_000_000,
        IssuerRole::Pid,
        crate::status::StatusOutcome::NoStatus,
    );
    assert!(
        result.valid,
        "mdoc presentation must verify under US1; reasons {:?}",
        result.reasons
    );
    // The issued elements are revealed (family_name/given_name/age_over_18 from the issuer double).
    assert!(result.disclosed_attributes.contains_key("family_name"));
}

#[test]
fn mdoc_present_wrong_audience_is_rejected_by_the_verifier() {
    use crate::mdoc::test_issuer::{mdoc_ds_cert_der, MdocBuilder};
    let held = HeldAttestation::Mdoc {
        device_response: MdocBuilder::new().build(),
    };
    let built_for = request(b"mdoc-vp-nonce");
    let vp = present(&held, &built_for, &holder_ctx(), &subset(&[]), &hsm(), NOW).expect("present");
    let anchors = StaticTestAnchors::new().trust(IssuerRole::Pid, Format::Mdoc, mdoc_ds_cert_der());
    // A request for a different audience must reject (the addressed audience won't match).
    let other = PresentationRequest {
        dcql: Dcql::from_json("{}"),
        nonce: built_for.nonce,
        audience: "https://other-verifier.example".to_owned(),
    };
    let result = verify_response(
        &vp.as_vp_token(),
        &other,
        &VerificationPolicy::default(),
        &anchors,
        1_700_000_000,
        IssuerRole::Pid,
        crate::status::StatusOutcome::NoStatus,
    );
    assert!(!result.valid);
    assert_eq!(
        result.reasons,
        vec![crate::types::ReasonCode::WrongAudience]
    );
}

#[test]
fn present_malformed_held_mdoc_is_an_error() {
    let held = HeldAttestation::Mdoc {
        device_response: vec![0xbf, 0x00],
    };
    let err = present(
        &held,
        &request(b"n"),
        &holder_ctx(),
        &subset(&[]),
        &hsm(),
        NOW,
    )
    .unwrap_err();
    assert!(matches!(err, PresentError::Malformed(_)));
}

#[test]
fn present_mdoc_without_a_documents_array_is_an_error() {
    // A well-formed CBOR map that is not a DeviceResponse (no `documents`) → Malformed (first_doc_type
    // returns None), never a panic.
    let mut buf = Vec::new();
    ciborium::into_writer(
        &ciborium::value::Value::Map(vec![(
            ciborium::value::Value::Text("version".to_owned()),
            ciborium::value::Value::Text("1.0".to_owned()),
        )]),
        &mut buf,
    )
    .unwrap();
    let held = HeldAttestation::Mdoc {
        device_response: buf,
    };
    let err = present(
        &held,
        &request(b"n"),
        &holder_ctx(),
        &subset(&[]),
        &hsm(),
        NOW,
    )
    .unwrap_err();
    assert!(matches!(err, PresentError::Malformed(_)));
}

// --- The signer-hook seam: a host signer error surfaces; bad signatures are rejected on finish ----

/// A signer that always fails (a host HSM refusal / outage).
struct FailingSigner;
impl Signer for FailingSigner {
    type Error = String;
    fn sign(&self, _handle: &str, _input: &SigningInput) -> Result<Vec<u8>, String> {
        Err("HSM refused".to_owned())
    }
}

#[test]
fn present_propagates_a_signer_error() {
    use crate::sdjwtvc::test_issuer::{mint_sd_jwt, ISSUER_CERT_DER, ISSUER_KEY_PK8};
    let held = HeldAttestation::SdJwtVc {
        issued: mint_sd_jwt(ISSUER_KEY_PK8, ISSUER_CERT_DER).presentation(),
    };
    let err = present(
        &held,
        &request(b"n"),
        &holder_ctx(),
        &subset(&["given_name"]),
        &FailingSigner,
        NOW,
    )
    .unwrap_err();
    assert!(matches!(err, PresentError::Signer(m) if m.contains("HSM refused")));
}

#[test]
fn finish_rejects_a_wrong_length_signature_for_both_formats() {
    use super::super::prepare_present;
    use crate::mdoc::test_issuer::MdocBuilder;
    use crate::sdjwtvc::test_issuer::{mint_sd_jwt, ISSUER_CERT_DER, ISSUER_KEY_PK8};

    // SD-JWT VC: a too-short signature must not splice into a KB-JWT.
    let sd = HeldAttestation::SdJwtVc {
        issued: mint_sd_jwt(ISSUER_KEY_PK8, ISSUER_CERT_DER).presentation(),
    };
    let prepared = prepare_present(&sd, &request(b"n"), &subset(&["given_name"]), NOW).unwrap();
    assert!(matches!(
        prepared.finish(&[0u8; 10]).unwrap_err(),
        PresentError::Build(_)
    ));

    // mdoc: likewise.
    let md = HeldAttestation::Mdoc {
        device_response: MdocBuilder::new().build(),
    };
    let prepared = prepare_present(&md, &request(b"n"), &subset(&[]), NOW).unwrap();
    assert!(matches!(
        prepared.finish(&[0u8; 10]).unwrap_err(),
        PresentError::Build(_)
    ));
}
