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
use super::super::{present, HeldAttestation, HolderPresentation, PresentError};
use crate::openid4vp::{verify_response, Dcql, PresentationRequest};
use crate::trust::StaticTestAnchors;
use crate::types::{Format, IssuerRole, VerificationPolicy};

const AUDIENCE: &str = "https://verifier.example/cb";
/// The verifier's `response_uri` request parameter (OpenID4VP 1.0 §B.2.6 4th handover element).
const RESPONSE_URI: &str = "https://verifier.example/cb/response";
/// The holder's present-time clock (the KB-JWT `iat` the SD-JWT VC tests stamp). Aligned with the
/// SD-JWT issuer/verify clock ([`crate::sdjwtvc::test_issuer::NOW`]) so the KB-JWT `iat` sits inside the
/// verifier's acceptable-window check (RFC 9901 §7.3 step 5.e); the mdoc present path ignores `iat`.
const NOW: i64 = crate::sdjwtvc::test_issuer::NOW;

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

/// The opaque holder key handle the test [`HolderContext`] carries — the value `present` MUST thread
/// through to [`Signer::sign`] (so the HSM selects the right holder key, never the default).
const HOLDER_HANDLE: &str = "holder-handle";

fn holder_ctx() -> HolderContext {
    use crate::sdjwtvc::test_issuer::HOLDER_JWK_JSON;
    let jwk: Value = serde_json::from_slice(HOLDER_JWK_JSON).expect("holder JWK");
    HolderContext::new(jwk, HOLDER_HANDLE)
}

fn request(nonce: &[u8]) -> PresentationRequest {
    PresentationRequest {
        dcql: Dcql::from_json("{}"),
        nonce: nonce.to_vec(),
        audience: AUDIENCE.to_owned(),
        response_uri: RESPONSE_URI.to_owned(),
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
        &[crate::status::StatusOutcome::NoStatus],
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
        &[crate::status::StatusOutcome::NoStatus],
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
        &[crate::status::StatusOutcome::NoStatus],
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

#[test]
fn sd_jwt_vc_present_conceals_array_element_disclosures_outside_the_subset() {
    // A credential with ARRAY-ELEMENT disclosures (RFC 9901, no claim_name): `nationalities` is an
    // array of two concealable elements. A narrow `disclose` subset must keep them OFF the wire (no
    // over-disclosure). Before the present.rs fix the conceal set was built only from named
    // disclosures, so the array elements ALWAYS rode in the vp_token regardless of `disclose`.
    use crate::sdjwtvc::test_issuer::ISSUER_CERT_DER;

    let issued = mint_with_array_disclosures();
    let request = request(b"array-ns-nonce");

    // Disclose ONLY given_name → the array-element disclosures (NL / DE) must NOT be present.
    let vp = present(
        &HeldAttestation::SdJwtVc {
            issued: issued.clone(),
        },
        &request,
        &holder_ctx(),
        &subset(&["given_name"]),
        &hsm(),
        NOW,
    )
    .expect("present");
    let HolderPresentationVpToken(token) = vp_token(&vp);
    assert!(
        !disclosed_array_values(&issued, &token)
            .iter()
            .any(|v| v == "NL" || v == "DE"),
        "array-element disclosures must be concealed when not selected; token: {token}"
    );

    // It still verifies under US1, revealing only the disclosed named claim.
    let anchors = StaticTestAnchors::new().trust(IssuerRole::Pid, Format::SdJwtVc, ISSUER_CERT_DER);
    let result = verify_response(
        &vp.as_vp_token(),
        &request,
        &VerificationPolicy::default(),
        &anchors,
        crate::sdjwtvc::test_issuer::NOW,
        IssuerRole::Pid,
        &[crate::status::StatusOutcome::NoStatus],
    );
    assert!(
        result.valid,
        "must verify under US1; reasons {:?}",
        result.reasons
    );
    assert!(result.disclosed_attributes.contains_key("given_name"));

    // Disclosing `nationalities` brings the array-element disclosures back onto the wire.
    let vp_full = present(
        &HeldAttestation::SdJwtVc {
            issued: issued.clone(),
        },
        &request,
        &holder_ctx(),
        &subset(&["given_name", "nationalities"]),
        &hsm(),
        NOW,
    )
    .expect("present full");
    let HolderPresentationVpToken(token_full) = vp_token(&vp_full);
    let disclosed = disclosed_array_values(&issued, &token_full);
    assert!(
        disclosed.iter().any(|v| v == "NL") && disclosed.iter().any(|v| v == "DE"),
        "selecting the parent claim must disclose its array elements; token: {token_full}"
    );
}

/// Mint an SD-JWT VC with `given_name` (named object disclosure) + `nationalities` (an array of two
/// array-element disclosures), bound to the holder cnf so the holder KB-JWT verifies under US1.
fn mint_with_array_disclosures() -> String {
    use crate::sdjwtvc::test_issuer::{
        block_on, holder_cnf, Es256Signer, Sha2Hasher, ISSUER_CERT_DER, ISSUER_KEY_PK8, NOW,
    };
    use base64ct::{Base64, Encoding as _};
    use sd_jwt_payload::SdJwtBuilder;
    use serde_json::json;

    let cert_b64 = Base64::encode_string(ISSUER_CERT_DER);
    let claims = json!({
        "iss": "https://issuer.example/cb",
        "vct": "https://credentials.example/identity_credential",
        "nbf": NOW - 1_000,
        "exp": NOW + 1_000_000,
        "given_name": "Ada",
        "nationalities": ["NL", "DE"],
    });
    let signer = Es256Signer::from_pkcs8(ISSUER_KEY_PK8);
    block_on(
        SdJwtBuilder::new_with_hasher(claims, Sha2Hasher)
            .expect("builder")
            .header("x5c", json!([cert_b64]))
            // SD-JWT VC §3.2.1: the verifier requires the issuer JWS `typ` to be the SD-JWT VC media
            // type (`dc+sd-jwt`); this fixture is verified end-to-end via `verify_response`.
            .header("typ", json!("dc+sd-jwt"))
            .make_concealable("/given_name")
            .expect("conceal given_name")
            .make_concealable("/nationalities/0")
            .expect("conceal nationalities[0]")
            .make_concealable("/nationalities/1")
            .expect("conceal nationalities[1]")
            .require_key_binding(holder_cnf())
            .finish(&signer, "ES256"),
    )
    .expect("issuer signing")
    .presentation()
}

/// The compact SD-JWT VC `vp_token` string of a presentation (panics for an mdoc presentation).
struct HolderPresentationVpToken(String);
fn vp_token(vp: &HolderPresentation) -> HolderPresentationVpToken {
    match vp {
        HolderPresentation::SdJwtVc { vp_token } => HolderPresentationVpToken(vp_token.clone()),
        HolderPresentation::Mdoc { .. } => panic!("expected an SD-JWT VC presentation"),
    }
}

/// Decode the array-element disclosure VALUES (RFC 9901 two-element disclosures) present in `token`,
/// restricted to those the `issued` credential actually carried as array elements. A disclosure
/// present in `token` means it rode on the wire (was NOT concealed).
fn disclosed_array_values(_issued: &str, token: &str) -> Vec<String> {
    use base64ct::{Base64UrlUnpadded, Encoding as _};
    // The presentation is `<JWS>~<D.1>~…~<KB-JWT>`. Each `D.i` is a base64url JSON array; an
    // array-element disclosure decodes to `[salt, value]` (length 2, no claim name).
    token
        .split('~')
        .filter_map(|seg| Base64UrlUnpadded::decode_vec(seg).ok())
        .filter_map(|bytes| serde_json::from_slice::<Vec<Value>>(&bytes).ok())
        .filter(|arr| arr.len() == 2)
        .filter_map(|arr| arr.into_iter().nth(1))
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect()
}

#[test]
fn sd_jwt_vc_present_nested_pid_discloses_one_branch_without_leaking_its_sibling_leaf() {
    // FLAGSHIP PID SHAPE (EUDI ARF): nested SD claims sharing a leaf name under different parents —
    // `address.locality` = "London" and `place_of_birth.locality` = "Paris". Before the present.rs fix
    // the concealer used the disclosure's ROOT leaf pointer (`/locality`), which (a) does NOT resolve
    // for a nested claim (`sd_jwt_payload` → InvalidPath → the whole PID was unpresentable) and (b)
    // collapsed both `locality` leaves into ONE selector (disclosing one leaked its sibling). The fix
    // conceals by the FULL path (`/address/locality`, `/place_of_birth/locality`), so a nested PID is
    // presentable AND the two same-leaf siblings are independently selectable.
    use crate::sdjwtvc::test_issuer::{mint_nested_shared_leaf, ISSUER_CERT_DER, ISSUER_KEY_PK8};

    let held = HeldAttestation::SdJwtVc {
        issued: mint_nested_shared_leaf(ISSUER_KEY_PK8, ISSUER_CERT_DER).presentation(),
    };
    let request = request(b"nested-pid-nonce");

    // Disclose ONLY `address.locality` (its full-path selector), leaving `place_of_birth.locality`
    // concealed. This must SUCCEED (no InvalidPath) — the nested PID is presentable.
    let vp = present(
        &held,
        &request,
        &holder_ctx(),
        &subset(&["address/locality"]),
        &hsm(),
        NOW,
    )
    .expect("a nested PID must be presentable (no root-pointer InvalidPath)");

    let anchors = StaticTestAnchors::new().trust(IssuerRole::Pid, Format::SdJwtVc, ISSUER_CERT_DER);
    let result = verify_response(
        &vp.as_vp_token(),
        &request,
        &VerificationPolicy::default(),
        &anchors,
        crate::sdjwtvc::test_issuer::NOW,
        IssuerRole::Pid,
        &[crate::status::StatusOutcome::NoStatus],
    );
    assert!(
        result.valid,
        "the nested PID presentation must verify under US1; reasons {:?}",
        result.reasons
    );

    // `address` is disclosed with its `locality` = "London".
    let mut london = std::collections::BTreeMap::new();
    london.insert(
        "locality".to_owned(),
        crate::types::AttributeValue::Text("London".to_owned()),
    );
    assert_eq!(
        result.disclosed_attributes.get("address"),
        Some(&crate::types::AttributeValue::Map(london)),
        "the disclosed branch must carry address.locality"
    );
    // The same-leaf-name sibling must NOT leak: `place_of_birth` stays concealed entirely.
    assert!(
        !result.disclosed_attributes.contains_key("place_of_birth"),
        "disclosing address.locality must not leak the same-leaf-name place_of_birth.locality"
    );
}

// --- mdoc: present bound to the request, verify under US1 ----------------------------------------

#[test]
fn mdoc_present_discloses_only_the_requested_element_and_prunes_the_rest() {
    // OVER-DISCLOSURE FIX (privacy, FR-007): the held mdoc carries three issued elements (family_name,
    // given_name, age_over_18). Presenting with `disclose = {family_name}` MUST prune given_name +
    // age_over_18 off the wire (ISO/IEC 18013-5 selective disclosure). Before the fix `prepare_mdoc`
    // ignored `disclose` and copied the FULL issuerSigned.nameSpaces verbatim, so every issued element
    // rode on the wire regardless of the requested subset. The pruned presentation must still verify
    // VALID — the MSO/IssuerAuth are untouched and valueDigests pass for the kept item.
    use crate::mdoc::test_issuer::{mdoc_ds_cert_der, MdocBuilder};

    let held = HeldAttestation::Mdoc {
        device_response: MdocBuilder::new().build(),
    };
    let request = request(b"mdoc-prune-nonce");

    let vp = present(
        &held,
        &request,
        &holder_ctx(),
        &subset(&["org.iso.18013.5.1/family_name"]),
        &hsm(),
        NOW,
    )
    .expect("present mdoc");

    let anchors = StaticTestAnchors::new().trust(IssuerRole::Pid, Format::Mdoc, mdoc_ds_cert_der());
    let result = verify_response(
        &vp.as_vp_token(),
        &request,
        &VerificationPolicy::default(),
        &anchors,
        1_700_000_000,
        IssuerRole::Pid,
        &[crate::status::StatusOutcome::NoStatus],
    );
    assert!(
        result.valid,
        "the pruned presentation must still verify VALID (valueDigests pass for the kept item); \
         reasons {:?}",
        result.reasons
    );
    let Some(crate::types::AttributeValue::Map(ns)) =
        result.disclosed_attributes.get("org.iso.18013.5.1")
    else {
        panic!("expected the org.iso.18013.5.1 namespace map");
    };
    assert!(
        ns.contains_key("family_name"),
        "the requested element must be disclosed"
    );
    assert!(
        !ns.contains_key("given_name"),
        "an unrequested element must be pruned off the wire (no over-disclosure)"
    );
    assert!(
        !ns.contains_key("age_over_18"),
        "an unrequested element must be pruned off the wire (no over-disclosure)"
    );
    assert_eq!(ns.len(), 1, "exactly the requested element is disclosed");
}

#[test]
fn mdoc_present_rejects_a_non_disclosable_element() {
    // A `disclose` name that matches no issued `elementIdentifier` MUST be rejected (mirroring the
    // SD-JWT arm), never silently accepted. Before the fix `prepare_mdoc` ignored `disclose` entirely,
    // so a garbage element name was accepted and the full credential presented.
    use crate::mdoc::test_issuer::MdocBuilder;
    let held = HeldAttestation::Mdoc {
        device_response: MdocBuilder::new().build(),
    };
    let err = present(
        &held,
        &request(b"n"),
        &holder_ctx(),
        &subset(&["not_an_element"]),
        &hsm(),
        NOW,
    )
    .unwrap_err();
    assert!(
        matches!(&err, PresentError::UndisclosableClaim(c) if c == "not_an_element"),
        "an unknown element must be UndisclosableClaim, got {err:?}"
    );
}

#[test]
fn mdoc_present_binds_to_the_request_and_verifies_under_us1() {
    use crate::mdoc::test_issuer::{mdoc_ds_cert_der, MdocBuilder};

    // The held mdoc: an issued DeviceResponse (its placeholder DeviceSignature is replaced at
    // presentation time by the request-bound holder signature).
    let held = HeldAttestation::Mdoc {
        device_response: MdocBuilder::new().build(),
    };
    let request = request(b"mdoc-vp-nonce");

    // Disclose all three issued elements (the mdoc `present` seam now honors `disclose`; an empty set
    // would disclose nothing).
    let vp = present(
        &held,
        &request,
        &holder_ctx(),
        &subset(&[
            "org.iso.18013.5.1/family_name",
            "org.iso.18013.5.1/given_name",
            "org.iso.18013.5.1/age_over_18",
        ]),
        &hsm(),
        NOW,
    )
    .expect("present mdoc");

    let anchors = StaticTestAnchors::new().trust(IssuerRole::Pid, Format::Mdoc, mdoc_ds_cert_der());
    let result = verify_response(
        &vp.as_vp_token(),
        &request,
        &VerificationPolicy::default(),
        &anchors,
        1_700_000_000,
        IssuerRole::Pid,
        &[crate::status::StatusOutcome::NoStatus],
    );
    assert!(
        result.valid,
        "mdoc presentation must verify under US1; reasons {:?}",
        result.reasons
    );
    // The issued elements are revealed (family_name/given_name/age_over_18 from the issuer double).
    // mdoc disclosed attributes are GROUPED BY NAMESPACE (`{ ns: Map({ id: value }) }`); the default
    // namespace is `org.iso.18013.5.1`.
    assert!(
        matches!(
            result.disclosed_attributes.get("org.iso.18013.5.1"),
            Some(crate::types::AttributeValue::Map(ns)) if ns.contains_key("family_name")
        ),
        "family_name is disclosed under the org.iso.18013.5.1 namespace"
    );
}

#[test]
fn mdoc_present_with_non_empty_device_namespaces_verifies_under_us1() {
    // A device-disclosed mdoc: the held DeviceResponse carries a NON-EMPTY deviceSigned.nameSpaces.
    // The US1 verifier rebuilds DeviceAuthentication from the document's ACTUAL deviceSigned.nameSpaces,
    // so the fresh holder DeviceSignature MUST be computed over those same bytes (the device.rs fix).
    // Before the fix the signature was always over an EMPTY DeviceNameSpaces → the verifier rejected.
    use crate::mdoc::test_issuer::{mdoc_ds_cert_der, MdocBuilder};
    use ciborium::value::Value as CborValue;

    let held = HeldAttestation::Mdoc {
        device_response: with_device_namespaces(
            &MdocBuilder::new().build(),
            "org.iso.18013.5.1",
            "device_signed_marker",
            CborValue::Text("present".to_owned()),
        ),
    };
    let request = request(b"mdoc-dev-ns-nonce");

    let vp = present(
        &held,
        &request,
        &holder_ctx(),
        &subset(&[
            "org.iso.18013.5.1/family_name",
            "org.iso.18013.5.1/given_name",
            "org.iso.18013.5.1/age_over_18",
        ]),
        &hsm(),
        NOW,
    )
    .expect("present mdoc");

    let anchors = StaticTestAnchors::new().trust(IssuerRole::Pid, Format::Mdoc, mdoc_ds_cert_der());
    let result = verify_response(
        &vp.as_vp_token(),
        &request,
        &VerificationPolicy::default(),
        &anchors,
        1_700_000_000,
        IssuerRole::Pid,
        &[crate::status::StatusOutcome::NoStatus],
    );
    assert!(
        result.valid,
        "a device-disclosed (non-empty device namespaces) mdoc must verify under US1; reasons {:?}",
        result.reasons
    );
}

/// Replace the first document's `deviceSigned.nameSpaces` with a non-empty `DeviceNameSpacesBytes`
/// (`#6.24(bstr .cbor { namespace: { element: value } })`) and re-encode the `DeviceResponse`.
fn with_device_namespaces(
    device_response: &[u8],
    namespace: &str,
    element: &str,
    value: ciborium::value::Value,
) -> Vec<u8> {
    use ciborium::value::Value as CborValue;
    const TAG_ENCODED_CBOR: u64 = 24;

    let device_name_spaces = CborValue::Map(vec![(
        CborValue::Text(namespace.to_owned()),
        CborValue::Map(vec![(CborValue::Text(element.to_owned()), value)]),
    )]);
    let mut inner = Vec::new();
    ciborium::into_writer(&device_name_spaces, &mut inner).expect("encode DeviceNameSpaces");
    let tagged = CborValue::Tag(TAG_ENCODED_CBOR, Box::new(CborValue::Bytes(inner)));

    let response: CborValue =
        ciborium::from_reader(device_response).expect("decode DeviceResponse");
    let rebuilt = map_replace(&response, "documents", |documents| {
        let docs = documents.as_array().expect("documents array");
        let rebuilt_docs = docs
            .iter()
            .map(|doc| {
                map_replace(doc, "deviceSigned", |device_signed| {
                    map_replace(device_signed, "nameSpaces", |_| tagged.clone())
                })
            })
            .collect();
        CborValue::Array(rebuilt_docs)
    });
    let mut out = Vec::new();
    ciborium::into_writer(&rebuilt, &mut out).expect("encode DeviceResponse");
    out
}

/// Rebuild a CBOR map, replacing the value at text key `key` via `f` (leaving other entries as-is).
fn map_replace(
    value: &ciborium::value::Value,
    key: &str,
    f: impl FnOnce(&ciborium::value::Value) -> ciborium::value::Value,
) -> ciborium::value::Value {
    use ciborium::value::Value as CborValue;
    let map = value.as_map().expect("CBOR map");
    let mut f = Some(f);
    let entries = map
        .iter()
        .map(|(k, v)| {
            if k.as_text() == Some(key) {
                let f = f.take().expect("key appears once");
                (k.clone(), f(v))
            } else {
                (k.clone(), v.clone())
            }
        })
        .collect();
    assert!(
        f.is_none(),
        "map_replace: key `{key}` not found in CBOR map"
    );
    CborValue::Map(entries)
}

#[test]
fn mdoc_present_wrong_audience_is_rejected_by_the_verifier() {
    use crate::mdoc::test_issuer::{mdoc_ds_cert_der, MdocBuilder};
    let held = HeldAttestation::Mdoc {
        device_response: MdocBuilder::new().build(),
    };
    let built_for = request(b"mdoc-vp-nonce");
    let vp = present(
        &held,
        &built_for,
        &holder_ctx(),
        &subset(&[
            "org.iso.18013.5.1/family_name",
            "org.iso.18013.5.1/given_name",
            "org.iso.18013.5.1/age_over_18",
        ]),
        &hsm(),
        NOW,
    )
    .expect("present");
    let anchors = StaticTestAnchors::new().trust(IssuerRole::Pid, Format::Mdoc, mdoc_ds_cert_der());
    // A request for a different audience must reject (the addressed audience won't match).
    let other = PresentationRequest {
        dcql: Dcql::from_json("{}"),
        nonce: built_for.nonce,
        audience: "https://other-verifier.example".to_owned(),
        response_uri: RESPONSE_URI.to_owned(),
    };
    let result = verify_response(
        &vp.as_vp_token(),
        &other,
        &VerificationPolicy::default(),
        &anchors,
        1_700_000_000,
        IssuerRole::Pid,
        &[crate::status::StatusOutcome::NoStatus],
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
fn present_multi_document_held_mdoc_is_rejected() {
    // A held mdoc whose DeviceResponse carries TWO documents must be rejected: the present seam signs
    // ONE DeviceSignature and would splice it into BOTH documents, so documents[1] would carry a
    // signature over documents[0]'s data and FAIL the per-document verifier. The fix rejects this up
    // front with MultiDocumentMdoc rather than emitting a silently-invalid token (no false token).
    use crate::mdoc::test_issuer::MdocBuilder;
    use ciborium::value::Value as CborValue;

    // Two fully-valid documents (the second discloses a DISTINCT identifier, so it is a clean,
    // independently-valid second document — the multi-document case, not a tamper).
    let two_doc_response = MdocBuilder::new()
        .append_colliding_document("nationality", CborValue::Text("NL".to_owned()))
        .build();
    let held = HeldAttestation::Mdoc {
        device_response: two_doc_response,
    };
    let err = present(
        &held,
        &request(b"multi-doc-nonce"),
        &holder_ctx(),
        &subset(&[]),
        &hsm(),
        NOW,
    )
    .unwrap_err();
    assert!(
        matches!(err, PresentError::MultiDocumentMdoc(2)),
        "a 2-document held mdoc must be rejected as MultiDocumentMdoc(2), got {err:?}"
    );
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

/// A signer that signs with the holder key ONLY when handed the expected key handle, recording the
/// handle it actually received. It proves `present` threads `HolderContext::key_handle` through to
/// `Signer::sign` (the handle selects the holder key in the HSM) rather than the old empty handle.
struct HandleAssertingHsm {
    key: SigningKey,
    expected_handle: String,
    seen_handle: std::cell::RefCell<Option<String>>,
}
impl Signer for HandleAssertingHsm {
    type Error = String;
    fn sign(&self, handle: &str, input: &SigningInput) -> Result<Vec<u8>, String> {
        *self.seen_handle.borrow_mut() = Some(handle.to_owned());
        // A real HSM selects the private key by handle; here we refuse a wrong/empty handle outright so
        // a regression to `sign("", …)` is a hard failure, not a silently-wrong-key signature.
        if handle != self.expected_handle {
            return Err(format!(
                "wrong key handle: expected {:?}, got {handle:?}",
                self.expected_handle
            ));
        }
        let sig: Signature = self.key.sign(input.to_be_signed());
        Ok(sig.to_bytes().to_vec())
    }
}

#[test]
fn present_threads_the_holder_key_handle_to_the_signer() {
    // The holder key handle (HolderContext::key_handle) MUST reach Signer::sign so the HSM selects the
    // correct holder key. Before the fix `present` passed an EMPTY handle (`sign("", …)`), which an
    // in-process wrapper would map to the wrong/default key. This signer refuses any handle other than
    // the holder's, so a VALID round-trip proves the handle is threaded; it also records the exact
    // handle seen.
    use crate::sdjwtvc::test_issuer::{mint_sd_jwt, ISSUER_CERT_DER, ISSUER_KEY_PK8};

    let held = HeldAttestation::SdJwtVc {
        issued: mint_sd_jwt(ISSUER_KEY_PK8, ISSUER_CERT_DER).presentation(),
    };
    let request = request(b"handle-thread-nonce");
    let hsm = HandleAssertingHsm {
        key: {
            use crate::sdjwtvc::test_issuer::HOLDER_KEY_PK8;
            SigningKey::from_pkcs8_der(HOLDER_KEY_PK8).expect("holder key")
        },
        expected_handle: HOLDER_HANDLE.to_owned(),
        seen_handle: std::cell::RefCell::new(None),
    };

    let vp = present(
        &held,
        &request,
        &holder_ctx(),
        &subset(&["given_name"]),
        &hsm,
        NOW,
    )
    .expect("present must succeed when handed the holder's key handle");

    // The signer saw exactly the holder's key handle (not the empty string).
    assert_eq!(
        hsm.seen_handle.into_inner().as_deref(),
        Some(HOLDER_HANDLE),
        "present must thread HolderContext::key_handle to Signer::sign, not an empty handle"
    );

    // And the resulting presentation still verifies under US1 (the handle selected the right key).
    let anchors = StaticTestAnchors::new().trust(IssuerRole::Pid, Format::SdJwtVc, ISSUER_CERT_DER);
    let result = verify_response(
        &vp.as_vp_token(),
        &request,
        &VerificationPolicy::default(),
        &anchors,
        crate::sdjwtvc::test_issuer::NOW,
        IssuerRole::Pid,
        &[crate::status::StatusOutcome::NoStatus],
    );
    assert!(result.valid, "reasons {:?}", result.reasons);
}

#[test]
fn present_with_an_empty_handle_signer_fails_proving_the_handle_is_load_bearing() {
    // Defence in depth: a signer that REQUIRES the holder handle rejects an empty one. If `present`
    // regressed to `sign("", …)`, this would surface as a Signer error — so the test pins that the
    // handle `present` passes is non-empty and exactly the holder's.
    use crate::sdjwtvc::test_issuer::{mint_sd_jwt, ISSUER_CERT_DER, ISSUER_KEY_PK8};

    let held = HeldAttestation::SdJwtVc {
        issued: mint_sd_jwt(ISSUER_KEY_PK8, ISSUER_CERT_DER).presentation(),
    };
    // A HolderContext whose handle differs from what the signer demands → the signer refuses, proving
    // the handle `present` forwards is the HolderContext's, not a hard-coded/empty one.
    use crate::sdjwtvc::test_issuer::HOLDER_JWK_JSON;
    let jwk: Value = serde_json::from_slice(HOLDER_JWK_JSON).expect("holder JWK");
    let mismatched_ctx = HolderContext::new(jwk, "some-other-handle");
    let hsm = HandleAssertingHsm {
        key: {
            use crate::sdjwtvc::test_issuer::HOLDER_KEY_PK8;
            SigningKey::from_pkcs8_der(HOLDER_KEY_PK8).expect("holder key")
        },
        expected_handle: HOLDER_HANDLE.to_owned(), // demands "holder-handle"
        seen_handle: std::cell::RefCell::new(None),
    };
    let err = present(
        &held,
        &request(b"n"),
        &mismatched_ctx,
        &subset(&["given_name"]),
        &hsm,
        NOW,
    )
    .unwrap_err();
    assert!(
        matches!(&err, PresentError::Signer(m) if m.contains("wrong key handle")),
        "present must forward the HolderContext's handle (here 'some-other-handle'), so the signer \
         demanding 'holder-handle' refuses: {err:?}"
    );
    // It forwarded the mismatched context's handle, not the empty string.
    assert_eq!(
        hsm.seen_handle.into_inner().as_deref(),
        Some("some-other-handle")
    );
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

// --- Direct unit coverage of the device-namespaces + array-element helpers (the fix paths) --------

#[test]
fn reencode_device_name_spaces_rejects_a_non_tagged_or_non_bstr_value() {
    use super::reencode_device_name_spaces;
    use ciborium::value::Value as CborValue;

    // A bare (untagged) value is not a `#6.24`-wrapped DeviceNameSpacesBytes → Malformed.
    let bare = CborValue::Map(vec![]);
    assert!(matches!(
        reencode_device_name_spaces(&bare).unwrap_err(),
        PresentError::Malformed(_)
    ));
    // A `#6.24` tag over a non-bstr payload is also malformed.
    let tag_over_text = CborValue::Tag(24, Box::new(CborValue::Text("x".to_owned())));
    assert!(matches!(
        reencode_device_name_spaces(&tag_over_text).unwrap_err(),
        PresentError::Malformed(_)
    ));
}

#[test]
fn first_device_name_spaces_bytes_defaults_to_empty_when_absent() {
    use super::super::device::empty_device_name_spaces_bytes;
    use super::first_device_name_spaces_bytes;
    use ciborium::value::Value as CborValue;

    // A DeviceResponse whose document carries NO deviceSigned.nameSpaces → the empty map default.
    let response = CborValue::Map(vec![(
        CborValue::Text("documents".to_owned()),
        CborValue::Array(vec![CborValue::Map(vec![(
            CborValue::Text("deviceSigned".to_owned()),
            CborValue::Map(vec![]),
        )])]),
    )]);
    assert_eq!(
        first_device_name_spaces_bytes(&response).expect("default"),
        empty_device_name_spaces_bytes()
    );
}

#[test]
fn array_element_paths_recurse_through_nested_and_non_redaction_items() {
    // A credential with `given_name` (named) + a NESTED structure containing array-element
    // disclosures (`tags` is an array holding a redaction AND a plain element, and an object whose
    // own array holds a redaction) exercises the recursion fall-through in collect_array_element_paths.
    use crate::sdjwtvc::test_issuer::{
        block_on, holder_cnf, Es256Signer, Sha2Hasher, ISSUER_CERT_DER, ISSUER_KEY_PK8, NOW,
    };
    use base64ct::{Base64, Encoding as _};
    use sd_jwt_payload::SdJwtBuilder;
    use serde_json::json;

    let cert_b64 = Base64::encode_string(ISSUER_CERT_DER);
    let claims = json!({
        "iss": "https://issuer.example/cb",
        "vct": "https://credentials.example/identity_credential",
        "nbf": NOW - 1_000,
        "exp": NOW + 1_000_000,
        "given_name": "Ada",
        // A nested object whose array holds one concealable element + one plain element.
        "profile": { "tags": ["alpha", "beta"] },
    });
    let signer = Es256Signer::from_pkcs8(ISSUER_KEY_PK8);
    let issued = block_on(
        SdJwtBuilder::new_with_hasher(claims, Sha2Hasher)
            .expect("builder")
            .header("x5c", json!([cert_b64]))
            .make_concealable("/given_name")
            .expect("conceal given_name")
            // Conceal only the FIRST tag → the array holds a redaction object AND a plain string,
            // so the walker recurses past the non-redaction element.
            .make_concealable("/profile/tags/0")
            .expect("conceal profile.tags[0]")
            .require_key_binding(holder_cnf())
            .finish(&signer, "ES256"),
    )
    .expect("issuer signing")
    .presentation();

    let request = request(b"nested-array-nonce");
    // Disclose only given_name → the nested array-element disclosure (`alpha`) must be concealed.
    let vp = present(
        &HeldAttestation::SdJwtVc {
            issued: issued.clone(),
        },
        &request,
        &holder_ctx(),
        &subset(&["given_name"]),
        &hsm(),
        NOW,
    )
    .expect("present");
    let HolderPresentationVpToken(token) = vp_token(&vp);
    assert!(
        !disclosed_array_values(&issued, &token).iter().any(|v| v == "alpha"),
        "the nested array-element disclosure must be concealed when its parent claim is not selected"
    );

    // Disclosing the nested parent claim (`profile`) brings the array element back.
    let vp_full = present(
        &HeldAttestation::SdJwtVc {
            issued: issued.clone(),
        },
        &request,
        &holder_ctx(),
        &subset(&["given_name", "profile"]),
        &hsm(),
        NOW,
    )
    .expect("present full");
    let HolderPresentationVpToken(token_full) = vp_token(&vp_full);
    assert!(
        disclosed_array_values(&issued, &token_full)
            .iter()
            .any(|v| v == "alpha"),
        "selecting the nested parent claim must disclose its array element"
    );
}

#[test]
fn finish_rejects_a_wire_injected_multi_document_prepared_mdoc() {
    // DEFENSE-IN-DEPTH (holder-side robustness): prepare_mdoc rejects a multi-document held response,
    // but PreparedKind::Mdoc is Deserialize and carried verbatim across the C-ABI in FinishPresent, so a
    // caller could inject a 2+-document `device_response` straight into finish() → replace_device_signature,
    // bypassing the prepare-time guard and emitting documents[1..] with a DeviceSignature scoped to
    // documents[0]. The splice site must re-check and reject with MultiDocumentMdoc.
    use ciborium::value::Value as CborValue;
    let two_docs = CborValue::Map(vec![(
        CborValue::Text("documents".to_owned()),
        CborValue::Array(vec![CborValue::Map(Vec::new()), CborValue::Map(Vec::new())]),
    )]);
    let mut device_signature_cbor = Vec::new();
    ciborium::into_writer(&CborValue::Null, &mut device_signature_cbor).expect("encode");
    let err = super::replace_device_signature(&two_docs, &device_signature_cbor)
        .expect_err("a multi-document prepared mdoc must be rejected at the splice site");
    assert!(
        matches!(err, PresentError::MultiDocumentMdoc(2)),
        "expected MultiDocumentMdoc(2), got {err:?}"
    );
}

// --- FIX 1: mdoc `disclose` is NAMESPACE-QUALIFIED (no cross-namespace over-disclosure) -----------

/// Read a text-keyed CBOR map entry (a self-contained navigator for the wire-inspection helpers).
fn cbor_get<'a>(
    value: &'a ciborium::value::Value,
    key: &str,
) -> Option<&'a ciborium::value::Value> {
    value
        .as_map()?
        .iter()
        .find(|(k, _)| k.as_text() == Some(key))
        .map(|(_, v)| v)
}

/// Decode an mdoc presentation's on-wire `issuerSigned.nameSpaces` into
/// `{ namespace: {elementIdentifier, …} }` — what actually rode to the verifier after pruning.
fn wire_namespaces(
    vp: &HolderPresentation,
) -> std::collections::BTreeMap<String, BTreeSet<String>> {
    use ciborium::value::Value as CborValue;
    let HolderPresentation::Mdoc {
        device_response, ..
    } = vp
    else {
        panic!("expected an mdoc presentation");
    };
    let response: CborValue =
        ciborium::from_reader(device_response.as_slice()).expect("decode DeviceResponse");
    let mut out = std::collections::BTreeMap::<String, BTreeSet<String>>::new();
    let documents = cbor_get(&response, "documents").and_then(CborValue::as_array);
    for doc in documents.into_iter().flatten() {
        let name_spaces = cbor_get(doc, "issuerSigned")
            .and_then(|issuer_signed| cbor_get(issuer_signed, "nameSpaces"))
            .and_then(CborValue::as_map);
        for (ns, items) in name_spaces.into_iter().flatten() {
            let ns = ns.as_text().expect("namespace is text").to_owned();
            let entry = out.entry(ns).or_default();
            for item in items.as_array().into_iter().flatten() {
                if let Some(id) = super::issuer_signed_item_identifier(item) {
                    entry.insert(id);
                }
            }
        }
    }
    out
}

/// Inject a SECOND `issuerSigned` namespace into the first document, carrying one `IssuerSignedItem`
/// (`#6.24(bstr .cbor {digestID,random,elementIdentifier,elementValue})`) with `element_id` — so ONE
/// mdoc document holds the SAME `elementIdentifier` under two namespaces (the cross-namespace probe).
/// Built by hand via `ciborium` (no `test_issuer.rs` change): one document, two namespaces.
fn with_second_issuer_namespace(
    device_response: &[u8],
    namespace: &str,
    element_id: &str,
    value: ciborium::value::Value,
) -> Vec<u8> {
    use ciborium::value::Value as CborValue;
    const TAG_ENCODED_CBOR: u64 = 24;

    let item = CborValue::Map(vec![
        (
            CborValue::Text("digestID".to_owned()),
            CborValue::Integer(0.into()),
        ),
        (
            CborValue::Text("random".to_owned()),
            CborValue::Bytes(vec![0x11; 16]),
        ),
        (
            CborValue::Text("elementIdentifier".to_owned()),
            CborValue::Text(element_id.to_owned()),
        ),
        (CborValue::Text("elementValue".to_owned()), value),
    ]);
    let mut inner = Vec::new();
    ciborium::into_writer(&item, &mut inner).expect("encode IssuerSignedItem");
    let tagged = CborValue::Tag(TAG_ENCODED_CBOR, Box::new(CborValue::Bytes(inner)));

    let response: CborValue =
        ciborium::from_reader(device_response).expect("decode DeviceResponse");
    let rebuilt = map_replace(&response, "documents", |documents| {
        let docs = documents.as_array().expect("documents array");
        let rebuilt_docs = docs
            .iter()
            .map(|doc| {
                map_replace(doc, "issuerSigned", |issuer_signed| {
                    map_replace(issuer_signed, "nameSpaces", |name_spaces| {
                        let mut entries = name_spaces.as_map().expect("nameSpaces map").clone();
                        entries.push((
                            CborValue::Text(namespace.to_owned()),
                            CborValue::Array(vec![tagged.clone()]),
                        ));
                        CborValue::Map(entries)
                    })
                })
            })
            .collect();
        CborValue::Array(rebuilt_docs)
    });
    let mut out = Vec::new();
    ciborium::into_writer(&rebuilt, &mut out).expect("encode DeviceResponse");
    out
}

#[test]
fn mdoc_present_qualified_selector_prunes_the_same_id_in_a_sibling_namespace() {
    // FR-007 cross-namespace over-disclosure: ONE mdoc document carries the SAME `elementIdentifier`
    // (`family_name`) in TWO namespaces (`org.iso.18013.5.1` + a sibling). ISO/IEC 18013-5 element ids
    // are unique only WITHIN a namespace, so a bare-id `disclose` selector leaks BOTH. The fix makes
    // the mdoc `disclose` entry NAMESPACE-QUALIFIED (`namespace/elementIdentifier`): disclosing only the
    // ISO namespace's family_name keeps it on the wire and PRUNES the sibling namespace's same-id entry.
    use crate::mdoc::test_issuer::{mdoc_ds_cert_der, MdocBuilder};
    use ciborium::value::Value as CborValue;

    const SIBLING_NS: &str = "org.eu.test.shared";
    let held = HeldAttestation::Mdoc {
        device_response: with_second_issuer_namespace(
            &MdocBuilder::new().build(),
            SIBLING_NS,
            "family_name",
            CborValue::Text("Sibling".to_owned()),
        ),
    };
    let request = request(b"mdoc-xns-nonce");

    // Disclose ONLY the ISO namespace's family_name (namespace-qualified).
    let vp = present(
        &held,
        &request,
        &holder_ctx(),
        &subset(&["org.iso.18013.5.1/family_name"]),
        &hsm(),
        NOW,
    )
    .expect("present mdoc");

    let disclosed = wire_namespaces(&vp);
    assert!(
        disclosed
            .get("org.iso.18013.5.1")
            .is_some_and(|ids| ids.contains("family_name")),
        "the disclosed ISO-namespace family_name must be on the wire; got {disclosed:?}"
    );
    assert!(
        !disclosed.contains_key(SIBLING_NS),
        "the SAME id in a sibling namespace must be pruned (no cross-namespace over-disclosure); \
         got {disclosed:?}"
    );
    assert_eq!(
        disclosed.get("org.iso.18013.5.1").map(BTreeSet::len),
        Some(1),
        "exactly the one disclosed element rides on the wire (given_name/age_over_18 pruned); \
         got {disclosed:?}"
    );

    // Only the ISO family_name (which has a matching MSO digest) remains → the pruned presentation
    // still verifies VALID under US1.
    let anchors = StaticTestAnchors::new().trust(IssuerRole::Pid, Format::Mdoc, mdoc_ds_cert_der());
    let result = verify_response(
        &vp.as_vp_token(),
        &request,
        &VerificationPolicy::default(),
        &anchors,
        1_700_000_000,
        IssuerRole::Pid,
        &[crate::status::StatusOutcome::NoStatus],
    );
    assert!(result.valid, "reasons {:?}", result.reasons);

    // Directional: disclosing the SIBLING namespace's family_name keeps ITS entry and prunes the ISO
    // namespace's same-id entry — the selector targets the exact namespace, never the bare id.
    let sibling_selector = format!("{SIBLING_NS}/family_name");
    let vp_sibling = present(
        &held,
        &request,
        &holder_ctx(),
        &subset(&[sibling_selector.as_str()]),
        &hsm(),
        NOW,
    )
    .expect("present mdoc (sibling namespace)");
    let disclosed_sibling = wire_namespaces(&vp_sibling);
    assert!(
        disclosed_sibling
            .get(SIBLING_NS)
            .is_some_and(|ids| ids.contains("family_name")),
        "the sibling-namespace family_name must be disclosed; got {disclosed_sibling:?}"
    );
    assert!(
        !disclosed_sibling.contains_key("org.iso.18013.5.1"),
        "the ISO-namespace same-id entry must be pruned when only the sibling is disclosed; \
         got {disclosed_sibling:?}"
    );
}

#[test]
fn mdoc_present_rejects_an_unqualified_or_wrong_namespace_disclose_entry() {
    // A mdoc `disclose` entry MUST be namespace-qualified (`namespace/elementIdentifier`). A BARE
    // (unqualified) id, or a qualified id naming the WRONG namespace, matches no issued
    // `namespace/elementIdentifier` and is rejected as UndisclosableClaim — never silently matched
    // across namespaces (the pre-fix bare-id behavior that leaked siblings).
    use crate::mdoc::test_issuer::MdocBuilder;
    let held = HeldAttestation::Mdoc {
        device_response: MdocBuilder::new().build(),
    };

    // Bare id (no namespace) — the pre-fix selector; now rejected.
    let bare = present(
        &held,
        &request(b"n"),
        &holder_ctx(),
        &subset(&["family_name"]),
        &hsm(),
        NOW,
    )
    .unwrap_err();
    assert!(
        matches!(&bare, PresentError::UndisclosableClaim(c) if c == "family_name"),
        "a bare (unqualified) id must be UndisclosableClaim, got {bare:?}"
    );

    // Right id, wrong namespace — rejected (not matched against the id's real namespace).
    let wrong_ns = present(
        &held,
        &request(b"n"),
        &holder_ctx(),
        &subset(&["org.wrong.ns/family_name"]),
        &hsm(),
        NOW,
    )
    .unwrap_err();
    assert!(
        matches!(&wrong_ns, PresentError::UndisclosableClaim(c) if c == "org.wrong.ns/family_name"),
        "a wrong-namespace qualified id must be UndisclosableClaim, got {wrong_ns:?}"
    );
}

// --- FIX 2: finish() MUST splice into an EXISTING deviceAuth (never emit an UNSIGNED token) --------

/// Remove the `deviceAuth` entry from the first document's `deviceSigned` (the splice target `finish`
/// requires) and re-encode the `DeviceResponse` — the pure-Rust path that `prepare_mdoc` accepts (it
/// does not require `deviceAuth`) but `finish` must reject.
fn strip_device_auth(device_response: &[u8]) -> Vec<u8> {
    use ciborium::value::Value as CborValue;
    let response: CborValue =
        ciborium::from_reader(device_response).expect("decode DeviceResponse");
    let rebuilt = map_replace(&response, "documents", |documents| {
        let docs = documents.as_array().expect("documents array");
        let rebuilt_docs = docs
            .iter()
            .map(|doc| {
                map_replace(doc, "deviceSigned", |device_signed| {
                    let kept = device_signed
                        .as_map()
                        .expect("deviceSigned map")
                        .iter()
                        .filter(|(k, _)| k.as_text() != Some("deviceAuth"))
                        .cloned()
                        .collect();
                    CborValue::Map(kept)
                })
            })
            .collect();
        CborValue::Array(rebuilt_docs)
    });
    let mut out = Vec::new();
    ciborium::into_writer(&rebuilt, &mut out).expect("encode DeviceResponse");
    out
}

#[test]
fn replace_device_signature_requires_the_splice_targets_to_exist() {
    // FIX 2: the holder signature MUST be spliced into an EXISTING deviceAuth; replace_device_signature
    // must NEVER no-op-copy an UNSIGNED DeviceResponse through when a splice target is absent. A
    // single-document response lacking deviceAuth (or deviceSigned, or documents, or with an empty
    // documents array) must ERROR, not return Ok with no holder signature spliced.
    use ciborium::value::Value as CborValue;

    let mut sig_cbor = Vec::new();
    ciborium::into_writer(&CborValue::Null, &mut sig_cbor).expect("encode signature");

    // A well-formed #6.24 empty DeviceNameSpaces (so `deviceSigned` is otherwise plausible).
    let device_ns = {
        let mut inner = Vec::new();
        ciborium::into_writer(&CborValue::Map(vec![]), &mut inner).expect("encode");
        CborValue::Tag(24, Box::new(CborValue::Bytes(inner)))
    };
    let one_document = |device_signed: CborValue| {
        CborValue::Map(vec![(
            CborValue::Text("documents".to_owned()),
            CborValue::Array(vec![CborValue::Map(vec![
                (
                    CborValue::Text("docType".to_owned()),
                    CborValue::Text("x".to_owned()),
                ),
                (CborValue::Text("deviceSigned".to_owned()), device_signed),
            ])]),
        )])
    };

    // (1) deviceSigned present but deviceAuth ABSENT → the exact splice-target-absent bug.
    let no_device_auth = one_document(CborValue::Map(vec![(
        CborValue::Text("nameSpaces".to_owned()),
        device_ns,
    )]));
    assert!(
        matches!(
            super::replace_device_signature(&no_device_auth, &sig_cbor).unwrap_err(),
            PresentError::Malformed(_)
        ),
        "a document lacking deviceAuth must be rejected, not copied through unsigned"
    );

    // (2) deviceSigned ABSENT → Err.
    let no_device_signed = CborValue::Map(vec![(
        CborValue::Text("documents".to_owned()),
        CborValue::Array(vec![CborValue::Map(vec![(
            CborValue::Text("docType".to_owned()),
            CborValue::Text("x".to_owned()),
        )])]),
    )]);
    assert!(
        matches!(
            super::replace_device_signature(&no_device_signed, &sig_cbor).unwrap_err(),
            PresentError::Malformed(_)
        ),
        "a document lacking deviceSigned must be rejected"
    );

    // (3) EMPTY documents array → Err (require exactly one document to bind).
    let empty_documents = CborValue::Map(vec![(
        CborValue::Text("documents".to_owned()),
        CborValue::Array(vec![]),
    )]);
    assert!(
        matches!(
            super::replace_device_signature(&empty_documents, &sig_cbor).unwrap_err(),
            PresentError::Malformed(_)
        ),
        "an empty documents array must be rejected"
    );

    // (4) documents key ABSENT → Err (the top-level splice target is missing).
    let no_documents = CborValue::Map(vec![(
        CborValue::Text("version".to_owned()),
        CborValue::Text("1.0".to_owned()),
    )]);
    assert!(
        matches!(
            super::replace_device_signature(&no_documents, &sig_cbor).unwrap_err(),
            PresentError::Malformed(_)
        ),
        "an absent documents key must be rejected"
    );
}

#[test]
fn present_mdoc_lacking_device_auth_finishes_with_an_error_not_an_unsigned_token() {
    // The pure-Rust path: prepare_mdoc does NOT require deviceAuth, so a held mdoc whose document lacks
    // deviceSigned.deviceAuth prepares fine and reaches finish(). finish() MUST error (the holder
    // signature has no deviceAuth to splice into) rather than return Ok with an UNSIGNED DeviceResponse.
    use crate::mdoc::test_issuer::MdocBuilder;
    let held = HeldAttestation::Mdoc {
        device_response: strip_device_auth(&MdocBuilder::new().build()),
    };
    let err = present(
        &held,
        &request(b"no-device-auth-nonce"),
        &holder_ctx(),
        &subset(&["org.iso.18013.5.1/family_name"]),
        &hsm(),
        NOW,
    )
    .unwrap_err();
    assert!(
        matches!(err, PresentError::Malformed(_)),
        "a held mdoc lacking deviceAuth must fail finish (no unsigned token emitted), got {err:?}"
    );
}
