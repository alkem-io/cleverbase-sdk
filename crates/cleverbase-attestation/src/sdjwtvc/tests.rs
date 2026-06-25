//! Tests for the SD-JWT VC verifier (task T007 — written test-first against T011).
//!
//! These mint real SD-JWT VC presentations with `sd-jwt-payload`'s issuer side, signed by the test
//! issuer key, with selective disclosures + a holder KB-JWT, and assert the always-on bar: a
//! well-formed in-validity credential is VALID with only the disclosed attributes returned, and each
//! tampered/expired/untrusted/broken-KB/forged-disclosure/malformed case is INVALID with the
//! specific [`ReasonCode`] — no false-accept (SC-002).

use std::collections::BTreeMap;

use base64ct::{Base64UrlUnpadded, Encoding as _};
use sd_jwt_payload::{Hasher, KeyBindingJwt, RequiredKeyBinding, SdJwtBuilder};
use serde_json::{json, Value};

use super::test_issuer::{
    array_disclosure, attach_kb_jwt, block_on, disclosure_digest, mint_array_element_disclosures,
    mint_concealable_object_with_concealable_child, mint_dual_value_same_name,
    mint_nested_shared_leaf, mint_sd_jwt, mint_sd_jwt_with_validity, object_disclosure,
    sign_issuer_jws, Es256Signer, Sha2Hasher, HOLDER_JWK_JSON, HOLDER_KEY_PK8, ISSUER_CERT_DER,
    ISSUER_KEY_PK8, NOW, WRONG_ISSUER_CERT_DER, WRONG_ISSUER_KEY_PK8,
};
use super::{verify_sd_jwt_vc, KeyBindingChallenge, SdJwtVcInput, StatusInput};
use crate::trust::StaticTestAnchors;
use crate::types::{AttributeValue, Format, IssuerRole, ReasonCode, TrustStatus};

const AUDIENCE: &str = "https://verifier.example/cb";
const NONCE: &str = "n-0S6_WzA2Mj";

/// A trusted-anchor set that trusts the test issuer cert as a PID provider for SD-JWT VC.
fn trusted_anchors() -> StaticTestAnchors {
    StaticTestAnchors::new().trust(IssuerRole::Pid, Format::SdJwtVc, ISSUER_CERT_DER)
}

/// The default verifier input: trusted anchors, a holder-binding challenge, in-validity, no status.
fn input<'a>(
    presentation: &'a str,
    anchors: &'a StaticTestAnchors,
) -> SdJwtVcInput<'a, StaticTestAnchors> {
    SdJwtVcInput {
        presentation,
        anchors,
        role: IssuerRole::Pid,
        key_binding: Some(KeyBindingChallenge {
            audience: AUDIENCE,
            nonce: NONCE,
        }),
        now_unix: NOW,
        status: StatusInput::NoStatus,
    }
}

/// Mint the happy-path presentation: trusted issuer, holder KB over the expected aud/nonce.
fn happy_presentation() -> String {
    let sd_jwt = mint_sd_jwt(ISSUER_KEY_PK8, ISSUER_CERT_DER);
    attach_kb_jwt(sd_jwt, HOLDER_KEY_PK8, AUDIENCE, NONCE)
}

// --- VALID ---------------------------------------------------------------------------------------

#[test]
fn valid_credential_from_trusted_issuer_is_accepted_with_disclosed_attributes() {
    let presentation = happy_presentation();
    let anchors = trusted_anchors();
    let result = verify_sd_jwt_vc(&input(&presentation, &anchors));

    assert!(
        result.valid,
        "expected VALID, got reasons {:?}",
        result.reasons
    );
    assert!(result.reasons.is_empty());
    assert_eq!(result.trust_status, TrustStatus::Trusted);
    assert!(result.qualified_status.is_none());

    // All three concealable claims were disclosed (the builder discloses by default).
    assert_eq!(
        result.disclosed_attributes.get("given_name"),
        Some(&AttributeValue::Text("Ada".to_string()))
    );
    assert_eq!(
        result.disclosed_attributes.get("family_name"),
        Some(&AttributeValue::Text("Lovelace".to_string()))
    );
    assert_eq!(
        result.disclosed_attributes.get("birthdate"),
        Some(&AttributeValue::Text("1815-12-10".to_string()))
    );
}

#[test]
fn selective_disclosure_reveals_only_the_presented_subset() {
    // Mint, then conceal `family_name` + `birthdate` for the presentation (disclose only given_name).
    let sd_jwt = mint_sd_jwt(ISSUER_KEY_PK8, ISSUER_CERT_DER);
    let (mut presented, _withheld) = sd_jwt
        .into_presentation(&Sha2Hasher)
        .unwrap()
        .conceal("/family_name")
        .unwrap()
        .conceal("/birthdate")
        .unwrap()
        .finish();
    let holder = Es256Signer::from_pkcs8(HOLDER_KEY_PK8);
    let kb = block_on(
        KeyBindingJwt::builder()
            .iat(NOW)
            .aud(AUDIENCE)
            .nonce(NONCE)
            .finish(&presented, &Sha2Hasher, "ES256", &holder),
    )
    .unwrap();
    presented.attach_key_binding_jwt(kb);
    let presentation = presented.presentation();

    let anchors = trusted_anchors();
    let result = verify_sd_jwt_vc(&input(&presentation, &anchors));

    assert!(result.valid, "reasons {:?}", result.reasons);
    // Only `given_name` is revealed; the concealed claims are neither revealed nor required.
    assert_eq!(
        result.disclosed_attributes.get("given_name"),
        Some(&AttributeValue::Text("Ada".to_string()))
    );
    assert!(!result.disclosed_attributes.contains_key("family_name"));
    assert!(!result.disclosed_attributes.contains_key("birthdate"));
}

// --- INVALID: each with its specific reason, no false-accept ------------------------------------

/// Assert an INVALID result carrying exactly the expected reason.
fn assert_invalid(result: &crate::types::VerificationResult, expected: ReasonCode) {
    assert!(!result.valid, "expected INVALID for {expected:?}");
    assert!(
        result.disclosed_attributes.is_empty(),
        "an INVALID result must reveal no attributes"
    );
    assert_eq!(result.reasons, vec![expected]);
}

#[test]
fn tampered_issuer_signature_is_rejected_as_tamper() {
    // Flip the last base64url char of the issuer JWS signature segment.
    let presentation = happy_presentation();
    let tampered = flip_issuer_signature(&presentation);
    let anchors = trusted_anchors();
    let result = verify_sd_jwt_vc(&input(&tampered, &anchors));
    assert_invalid(&result, ReasonCode::Tamper);
}

#[test]
fn expired_credential_is_rejected_as_expired() {
    let presentation = happy_presentation();
    let anchors = trusted_anchors();
    // Verify at a time past `exp` (NOW + 1_000_000).
    let mut inp = input(&presentation, &anchors);
    inp.now_unix = NOW + 2_000_000;
    let result = verify_sd_jwt_vc(&inp);
    assert_invalid(&result, ReasonCode::Expired);
}

#[test]
fn not_yet_valid_credential_is_rejected_as_expired() {
    let presentation = happy_presentation();
    let anchors = trusted_anchors();
    // Verify at a time before `nbf` (NOW - 1_000).
    let mut inp = input(&presentation, &anchors);
    inp.now_unix = NOW - 2_000;
    let result = verify_sd_jwt_vc(&inp);
    assert_invalid(&result, ReasonCode::Expired);
}

#[test]
fn non_integer_string_exp_is_rejected_not_ignored() {
    // FALSE-ACCEPT PROBE: an `exp` that is a JSON string ("200") is not a NumericDate. The old code
    // read it via `as_i64()` → `None` and SKIPPED the check, accepting an expired credential as having
    // unbounded validity. A present-but-unparseable `exp` MUST reject, never be ignored.
    let sd_jwt = mint_sd_jwt_with_validity(
        ISSUER_KEY_PK8,
        ISSUER_CERT_DER,
        json!(NOW - 1_000),
        json!("200"),
    );
    let presentation = attach_kb_jwt(sd_jwt, HOLDER_KEY_PK8, AUDIENCE, NONCE);
    let anchors = trusted_anchors();
    // `now` is well past the (intended) 200-second epoch instant — the credential is expired, and the
    // verifier must not silently treat the unreadable `exp` as "no upper bound".
    let result = verify_sd_jwt_vc(&input(&presentation, &anchors));
    assert_invalid(&result, ReasonCode::MalformedCredential);
}

#[test]
fn non_integer_float_exp_is_rejected_not_ignored() {
    // FALSE-ACCEPT PROBE: a non-integer float `exp` (200.5) is not an `i64`; the old `as_i64()` path
    // returned `None` and skipped the bound. A present-but-non-integer NumericDate MUST reject.
    let sd_jwt = mint_sd_jwt_with_validity(
        ISSUER_KEY_PK8,
        ISSUER_CERT_DER,
        json!(NOW - 1_000),
        json!(200.5),
    );
    let presentation = attach_kb_jwt(sd_jwt, HOLDER_KEY_PK8, AUDIENCE, NONCE);
    let anchors = trusted_anchors();
    let result = verify_sd_jwt_vc(&input(&presentation, &anchors));
    assert_invalid(&result, ReasonCode::MalformedCredential);
}

#[test]
fn out_of_i64_range_exp_is_rejected_not_ignored() {
    // FALSE-ACCEPT PROBE: an `exp` of 2^64-1 (u64::MAX) is a JSON number but exceeds i64::MAX, so
    // `as_i64()` returns `None` and the old code skipped the bound — an effectively-unbounded credential
    // would be accepted. An out-of-range NumericDate MUST reject.
    let sd_jwt = mint_sd_jwt_with_validity(
        ISSUER_KEY_PK8,
        ISSUER_CERT_DER,
        json!(NOW - 1_000),
        json!(u64::MAX),
    );
    let presentation = attach_kb_jwt(sd_jwt, HOLDER_KEY_PK8, AUDIENCE, NONCE);
    let anchors = trusted_anchors();
    let result = verify_sd_jwt_vc(&input(&presentation, &anchors));
    assert_invalid(&result, ReasonCode::MalformedCredential);
}

#[test]
fn non_integer_string_nbf_is_rejected_not_ignored() {
    // The same false-accept hole applies to `nbf`: a present-but-unparseable not-before MUST reject
    // rather than be skipped (skipping a future `nbf` would accept a not-yet-valid credential).
    let sd_jwt = mint_sd_jwt_with_validity(
        ISSUER_KEY_PK8,
        ISSUER_CERT_DER,
        json!("not-a-date"),
        json!(NOW + 1_000_000),
    );
    let presentation = attach_kb_jwt(sd_jwt, HOLDER_KEY_PK8, AUDIENCE, NONCE);
    let anchors = trusted_anchors();
    let result = verify_sd_jwt_vc(&input(&presentation, &anchors));
    assert_invalid(&result, ReasonCode::MalformedCredential);
}

#[test]
fn credential_without_exp_or_nbf_is_accepted_with_no_temporal_bound() {
    // DOCUMENTED POLICY (#2): per RFC 9901 / SD-JWT VC, `nbf`/`exp` are OPTIONAL. A credential that
    // asserts neither bound carries no temporal window here and is accepted — intentionally, not
    // accidentally (the absent-vs-present distinction is what `numeric_date` encodes). A relying party
    // that requires an upper bound rejects a no-`exp` credential at the policy layer.
    let sd_jwt = mint_sd_jwt_with_validity(
        ISSUER_KEY_PK8,
        ISSUER_CERT_DER,
        Value::Null, // a null bound means "omit the claim entirely" → `nbf`/`exp` are ABSENT.
        Value::Null,
    );
    let presentation = attach_kb_jwt(sd_jwt, HOLDER_KEY_PK8, AUDIENCE, NONCE);
    let anchors = trusted_anchors();
    let result = verify_sd_jwt_vc(&input(&presentation, &anchors));
    assert!(
        result.valid,
        "an RFC-valid no-exp/no-nbf credential must still verify; reasons {:?}",
        result.reasons
    );
}

#[test]
fn check_validity_distinguishes_absent_from_malformed_bounds() {
    // Direct unit coverage of the absent-vs-present-but-malformed distinction the false-accept fix
    // turns on, exercised over `numeric_date` via `check_validity`.
    use super::check_validity;
    use sd_jwt_payload::SdJwtClaims;

    // Both bounds absent → no window, always OK.
    let none: SdJwtClaims = serde_json::from_value(json!({})).unwrap();
    assert!(check_validity(&none, NOW).is_ok());

    // A present integer window inside which `now` falls → OK.
    let ok: SdJwtClaims =
        serde_json::from_value(json!({ "nbf": NOW - 1, "exp": NOW + 1 })).unwrap();
    assert!(check_validity(&ok, NOW).is_ok());

    // A present-but-string `exp` → MalformedCredential (never skipped).
    let bad_exp: SdJwtClaims = serde_json::from_value(json!({ "exp": "200" })).unwrap();
    assert_eq!(
        check_validity(&bad_exp, NOW),
        Err(ReasonCode::MalformedCredential)
    );

    // A present float `nbf` → MalformedCredential.
    let bad_nbf: SdJwtClaims = serde_json::from_value(json!({ "nbf": 1.5 })).unwrap();
    assert_eq!(
        check_validity(&bad_nbf, NOW),
        Err(ReasonCode::MalformedCredential)
    );
}

#[test]
fn untrusted_issuer_certificate_is_rejected_as_untrusted_issuer() {
    // A credential validly self-signed by the wrong-issuer key+cert: its own signature verifies, but
    // the cert is NOT on the configured anchor → UntrustedIssuer (no false-accept).
    let sd_jwt = mint_sd_jwt(WRONG_ISSUER_KEY_PK8, WRONG_ISSUER_CERT_DER);
    let presentation = attach_kb_jwt(sd_jwt, HOLDER_KEY_PK8, AUDIENCE, NONCE);
    let anchors = trusted_anchors(); // trusts only the real issuer cert.
    let result = verify_sd_jwt_vc(&input(&presentation, &anchors));
    assert_invalid(&result, ReasonCode::UntrustedIssuer);
}

#[test]
fn broken_holder_binding_wrong_nonce_is_rejected_as_holder_binding() {
    // KB-JWT minted over a different nonce than the verifier's challenge.
    let sd_jwt = mint_sd_jwt(ISSUER_KEY_PK8, ISSUER_CERT_DER);
    let presentation = attach_kb_jwt(sd_jwt, HOLDER_KEY_PK8, AUDIENCE, "a-different-nonce");
    let anchors = trusted_anchors();
    let result = verify_sd_jwt_vc(&input(&presentation, &anchors));
    assert_invalid(&result, ReasonCode::HolderBinding);
}

#[test]
fn holder_binding_signed_by_wrong_key_is_rejected_as_holder_binding() {
    // Correct aud/nonce/sd_hash, but the KB-JWT is signed by the wrong-issuer key, not the holder
    // key bound in `cnf` → the signature does not verify under the `cnf` key.
    let sd_jwt = mint_sd_jwt(ISSUER_KEY_PK8, ISSUER_CERT_DER);
    let presentation = attach_kb_jwt(sd_jwt, WRONG_ISSUER_KEY_PK8, AUDIENCE, NONCE);
    let anchors = trusted_anchors();
    let result = verify_sd_jwt_vc(&input(&presentation, &anchors));
    assert_invalid(&result, ReasonCode::HolderBinding);
}

#[test]
fn missing_kb_jwt_when_required_is_rejected_as_holder_binding() {
    // A presentation with no KB-JWT, but the verifier requires holder binding.
    let sd_jwt = mint_sd_jwt(ISSUER_KEY_PK8, ISSUER_CERT_DER);
    let presentation = sd_jwt.presentation(); // trailing `~`, no KB segment.
    let anchors = trusted_anchors();
    let result = verify_sd_jwt_vc(&input(&presentation, &anchors));
    assert_invalid(&result, ReasonCode::HolderBinding);
}

#[test]
fn forged_disclosure_with_unsigned_digest_is_rejected_as_disclosure_integrity() {
    // Splice an extra, well-formed disclosure whose digest is NOT in any issuer-signed `_sd` array.
    // Use an issuer-only presentation (no holder binding) so the integrity check is the failing one
    // under test — splicing a disclosure into a KB-bound presentation would (correctly) also break
    // the KB `sd_hash`; here we isolate the disclosure-integrity path.
    let sd_jwt = mint_sd_jwt(ISSUER_KEY_PK8, ISSUER_CERT_DER);
    let presentation = sd_jwt.presentation();
    let forged = splice_forged_disclosure(&presentation);
    let anchors = trusted_anchors();
    let mut inp = input(&forged, &anchors);
    inp.key_binding = None;
    let result = verify_sd_jwt_vc(&inp);
    assert_invalid(&result, ReasonCode::DisclosureIntegrity);
}

#[test]
fn duplicate_disclosure_is_rejected_as_disclosure_integrity() {
    // RFC 9901 §7.3: a digest occurring more than once makes the SD-JWT invalid. Duplicate a
    // legitimately-issued disclosure (its digest IS signed, so it passes the membership check) — the
    // SECOND occurrence of the same digest must be rejected, not silently accepted. Use an issuer-only
    // presentation so disclosure integrity is the failing check under test (a KB-bound presentation
    // would also break the `sd_hash` over the mutated prefix).
    let sd_jwt = mint_sd_jwt(ISSUER_KEY_PK8, ISSUER_CERT_DER);
    let presentation = sd_jwt.presentation();
    let duplicated = duplicate_first_disclosure(&presentation);
    let anchors = trusted_anchors();
    let mut inp = input(&duplicated, &anchors);
    inp.key_binding = None;
    let result = verify_sd_jwt_vc(&inp);
    assert_invalid(&result, ReasonCode::DisclosureIntegrity);
}

#[test]
fn two_issuer_signed_disclosures_for_the_same_claim_name_are_rejected_both_orderings() {
    // RFC 9901 §9.3: the verifier MUST reject an SD-JWT that would populate a claim name more than
    // once. Both disclosures are issuer-signed (their digests are in `_sd`) and have DISTINCT digests
    // (distinct salts), so the membership and repeated-digest guards both pass — the only thing that
    // can catch this is the duplicate-claim-name guard. Without it, last-writer-wins lets the holder
    // choose which issuer-signed value the RP sees by REORDERING the disclosure segments; we prove the
    // reject holds in BOTH orderings (issuer-only presentation, so disclosure integrity is the failing
    // check under test). The mdoc path already closes this via `insert_no_shadow`; this is the parity.
    let (jws, disclosure_a, disclosure_b) =
        mint_dual_value_same_name(ISSUER_KEY_PK8, ISSUER_CERT_DER);
    let anchors = trusted_anchors();
    for (first, second) in [
        (&disclosure_a, &disclosure_b),
        (&disclosure_b, &disclosure_a),
    ] {
        let presentation = format!("{jws}~{first}~{second}~");
        let mut inp = input(&presentation, &anchors);
        inp.key_binding = None;
        let result = verify_sd_jwt_vc(&inp);
        assert_invalid(&result, ReasonCode::DisclosureIntegrity);
    }
}

#[test]
fn single_disclosure_for_a_dual_minted_claim_still_verifies() {
    // The conflict guard must NOT break the normal single-disclosure path: disclosing exactly ONE of
    // the issuer-signed `given_name` values is a valid, accepted presentation (only the disclosed
    // value is returned). This confirms the guard fires only on a *repeated* population, not a single
    // one.
    let (jws, disclosure_a, _disclosure_b) =
        mint_dual_value_same_name(ISSUER_KEY_PK8, ISSUER_CERT_DER);
    let presentation = format!("{jws}~{disclosure_a}~");
    let anchors = trusted_anchors();
    let mut inp = input(&presentation, &anchors);
    inp.key_binding = None;
    let result = verify_sd_jwt_vc(&inp);
    assert!(result.valid, "reasons {:?}", result.reasons);
    assert_eq!(
        result.disclosed_attributes.get("given_name"),
        Some(&AttributeValue::Text("Ada".to_string()))
    );
}

#[test]
fn distinct_nested_claims_sharing_a_leaf_name_are_both_disclosed() {
    // FALSE-REJECT PROBE (the regression the inner-3 collision guard introduced): a legitimate,
    // issuer-signed SD-JWT VC with two DISTINCT nested claims sharing a leaf name under different
    // parents — `address.locality` = "London" and `place_of_birth.locality` = "Paris" — is the routine
    // EUDI PID shape. RFC 9901 §7.1 scopes claim-name uniqueness to the level of the `_sd` key (per
    // object), NOT the leaf name, so this is VALID and BOTH distinct values are exposed in their nested
    // positions — never collapsed to a single bare `locality` (the old flat last-wins) nor rejected as
    // `DisclosureIntegrity` (the leaf-keyed guard's false-reject).
    let sd_jwt = mint_nested_shared_leaf(ISSUER_KEY_PK8, ISSUER_CERT_DER);
    let presentation = attach_kb_jwt(sd_jwt, HOLDER_KEY_PK8, AUDIENCE, NONCE);
    let anchors = trusted_anchors();
    let result = verify_sd_jwt_vc(&input(&presentation, &anchors));

    assert!(
        result.valid,
        "a nested SD-JWT VC with two distinct claims sharing a leaf name must be VALID; reasons {:?}",
        result.reasons
    );

    // The disclosed view reflects the NESTING: `address` and `place_of_birth` are distinct top-level
    // keys, each a nested map carrying its own `locality` — the two values are not collapsed.
    let mut london = BTreeMap::new();
    london.insert(
        "locality".to_string(),
        AttributeValue::Text("London".to_string()),
    );
    let mut paris = BTreeMap::new();
    paris.insert(
        "locality".to_string(),
        AttributeValue::Text("Paris".to_string()),
    );
    assert_eq!(
        result.disclosed_attributes.get("address"),
        Some(&AttributeValue::Map(london)),
    );
    assert_eq!(
        result.disclosed_attributes.get("place_of_birth"),
        Some(&AttributeValue::Map(paris)),
    );
    // Only the disclosed claims are surfaced — the always-visible registered claims are not returned.
    assert!(!result.disclosed_attributes.contains_key("iss"));
    assert!(!result.disclosed_attributes.contains_key("vct"));
}

#[test]
fn disclosed_concealable_object_reconstructs_its_nested_disclosed_child() {
    // A whole `address` object is concealable AND its `locality` child is concealable; disclosing both
    // means the `address` disclosure's VALUE is itself an object carrying an `_sd` for `locality`. The
    // reconstruction must substitute the nested disclosure inside the disclosed value, yielding
    // `address` = { locality, country } (country is a clear sub-property of the disclosed object).
    let sd_jwt = mint_concealable_object_with_concealable_child(ISSUER_KEY_PK8, ISSUER_CERT_DER);
    let presentation = attach_kb_jwt(sd_jwt, HOLDER_KEY_PK8, AUDIENCE, NONCE);
    let anchors = trusted_anchors();
    let result = verify_sd_jwt_vc(&input(&presentation, &anchors));

    assert!(result.valid, "reasons {:?}", result.reasons);
    let mut address = BTreeMap::new();
    address.insert(
        "locality".to_string(),
        AttributeValue::Text("London".to_string()),
    );
    address.insert(
        "country".to_string(),
        AttributeValue::Text("UK".to_string()),
    );
    assert_eq!(
        result.disclosed_attributes.get("address"),
        Some(&AttributeValue::Map(address)),
    );
}

#[test]
fn disclosed_array_elements_are_reconstructed_in_place() {
    // Array-element disclosures (RFC 9901 `{"...": "<digest>"}` redaction): disclosing all elements of
    // `nationalities` surfaces them by value in the array, in their issuer-signed order — exercising
    // the array-element reconstruction path.
    let sd_jwt = mint_array_element_disclosures(ISSUER_KEY_PK8, ISSUER_CERT_DER);
    let presentation = attach_kb_jwt(sd_jwt, HOLDER_KEY_PK8, AUDIENCE, NONCE);
    let anchors = trusted_anchors();
    let result = verify_sd_jwt_vc(&input(&presentation, &anchors));

    assert!(result.valid, "reasons {:?}", result.reasons);
    assert_eq!(
        result.disclosed_attributes.get("nationalities"),
        Some(&AttributeValue::Array(vec![
            AttributeValue::Text("DE".to_string()),
            AttributeValue::Text("FR".to_string()),
        ])),
    );
}

#[test]
fn undisclosed_array_element_is_dropped_from_the_disclosed_array() {
    // Conceal one of the two disclosable `nationalities` elements: the disclosed array carries only the
    // revealed element; the concealed redaction is dropped (not surfaced as a placeholder).
    let sd_jwt = mint_array_element_disclosures(ISSUER_KEY_PK8, ISSUER_CERT_DER);
    let (mut presented, _withheld) = sd_jwt
        .into_presentation(&Sha2Hasher)
        .unwrap()
        .conceal("/nationalities/1")
        .unwrap()
        .finish();
    let holder = Es256Signer::from_pkcs8(HOLDER_KEY_PK8);
    let kb = block_on(
        KeyBindingJwt::builder()
            .iat(NOW)
            .aud(AUDIENCE)
            .nonce(NONCE)
            .finish(&presented, &Sha2Hasher, "ES256", &holder),
    )
    .unwrap();
    presented.attach_key_binding_jwt(kb);
    let presentation = presented.presentation();

    let anchors = trusted_anchors();
    let result = verify_sd_jwt_vc(&input(&presentation, &anchors));

    assert!(result.valid, "reasons {:?}", result.reasons);
    assert_eq!(
        result.disclosed_attributes.get("nationalities"),
        Some(&AttributeValue::Array(vec![AttributeValue::Text(
            "DE".to_string()
        )])),
    );
}

#[test]
fn one_of_two_nested_shared_leaf_claims_disclosed_surfaces_only_that_branch() {
    // Disclose ONLY `place_of_birth.locality`, concealing `address.locality`. The disclosed view must
    // carry `place_of_birth.locality` = "Paris" at its nested position and must NOT carry `address` at
    // all (its sole disclosable child was concealed) — the per-level reconstruction includes a parent
    // only when it yields a disclosed child.
    let sd_jwt = mint_nested_shared_leaf(ISSUER_KEY_PK8, ISSUER_CERT_DER);
    let (mut presented, _withheld) = sd_jwt
        .into_presentation(&Sha2Hasher)
        .unwrap()
        .conceal("/address/locality")
        .unwrap()
        .finish();
    let holder = Es256Signer::from_pkcs8(HOLDER_KEY_PK8);
    let kb = block_on(
        KeyBindingJwt::builder()
            .iat(NOW)
            .aud(AUDIENCE)
            .nonce(NONCE)
            .finish(&presented, &Sha2Hasher, "ES256", &holder),
    )
    .unwrap();
    presented.attach_key_binding_jwt(kb);
    let presentation = presented.presentation();

    let anchors = trusted_anchors();
    let result = verify_sd_jwt_vc(&input(&presentation, &anchors));

    assert!(result.valid, "reasons {:?}", result.reasons);
    let mut paris = BTreeMap::new();
    paris.insert(
        "locality".to_string(),
        AttributeValue::Text("Paris".to_string()),
    );
    assert_eq!(
        result.disclosed_attributes.get("place_of_birth"),
        Some(&AttributeValue::Map(paris)),
    );
    // `address` carried only the concealed `locality`, so its parent is absent from the disclosed view.
    assert!(!result.disclosed_attributes.contains_key("address"));
}

#[test]
fn malformed_presentation_is_rejected_as_malformed_credential() {
    let anchors = trusted_anchors();
    // A single segment with no `~` is not a valid SD-JWT (needs at least 2 segments).
    let result = verify_sd_jwt_vc(&input("not-an-sd-jwt", &anchors));
    assert_invalid(&result, ReasonCode::MalformedCredential);
}

#[test]
fn unsupported_alg_is_rejected_as_unsupported_format() {
    // Rewrite the issuer JWS header `alg` to a non-ES256 value; the framing still parses, so this is
    // an unsupported-format reject rather than malformed.
    let presentation = happy_presentation();
    let rewritten = rewrite_issuer_alg(&presentation, "RS256");
    let anchors = trusted_anchors();
    let result = verify_sd_jwt_vc(&input(&rewritten, &anchors));
    assert_invalid(&result, ReasonCode::UnsupportedFormat);
}

#[test]
fn host_supplied_revoked_status_is_rejected_as_revoked() {
    let presentation = happy_presentation();
    let anchors = trusted_anchors();
    let mut inp = input(&presentation, &anchors);
    inp.status = StatusInput::Revoked;
    let result = verify_sd_jwt_vc(&inp);
    assert_invalid(&result, ReasonCode::Revoked);
}

#[test]
fn unavailable_status_is_rejected_as_status_unavailable() {
    let presentation = happy_presentation();
    let anchors = trusted_anchors();
    let mut inp = input(&presentation, &anchors);
    inp.status = StatusInput::Unavailable;
    let result = verify_sd_jwt_vc(&inp);
    assert_invalid(&result, ReasonCode::StatusUnavailable);
}

#[test]
fn presentation_without_holder_binding_is_accepted_when_not_required() {
    // No KB-JWT and no challenge → holder binding is not required (issuer-only credential).
    let sd_jwt = mint_sd_jwt(ISSUER_KEY_PK8, ISSUER_CERT_DER);
    let presentation = sd_jwt.presentation();
    let anchors = trusted_anchors();
    let mut inp = input(&presentation, &anchors);
    inp.key_binding = None;
    let result = verify_sd_jwt_vc(&inp);
    assert!(result.valid, "reasons {:?}", result.reasons);
    assert_eq!(
        result.disclosed_attributes.get("given_name"),
        Some(&AttributeValue::Text("Ada".to_string()))
    );
}

// --- presentation-mutation helpers --------------------------------------------------------------

/// Flip a byte in the middle of the issuer JWS signature (invalidating it while keeping the
/// base64url framing canonical, so the verifier reaches the signature check rather than a decode
/// error).
fn flip_issuer_signature(presentation: &str) -> String {
    let (jws, rest) = split_first_segment(presentation);
    let mut parts: Vec<&str> = jws.split('.').collect();
    let mut sig_bytes = Base64UrlUnpadded::decode_vec(parts[2]).unwrap();
    let mid = sig_bytes.len() / 2;
    sig_bytes[mid] ^= 0xFF;
    let new_sig = Base64UrlUnpadded::encode_string(&sig_bytes);
    parts[2] = &new_sig;
    format!("{}~{rest}", parts.join("."))
}

/// Rewrite the issuer JWS header `alg` claim to `new_alg`, re-encoding the header (signature now
/// won't verify, but the framing is intact so the verifier reaches the alg check first).
fn rewrite_issuer_alg(presentation: &str, new_alg: &str) -> String {
    let (jws, rest) = split_first_segment(presentation);
    let parts: Vec<&str> = jws.split('.').collect();
    let header_json = Base64UrlUnpadded::decode_vec(parts[0]).unwrap();
    let mut header: Value = serde_json::from_slice(&header_json).unwrap();
    header["alg"] = Value::String(new_alg.to_string());
    let new_header =
        Base64UrlUnpadded::encode_string(serde_json::to_vec(&header).unwrap().as_slice());
    format!("{new_header}.{}.{}~{rest}", parts[1], parts[2])
}

/// Splice a syntactically valid disclosure whose digest is NOT issuer-signed, inserted before the
/// KB-JWT (so the framing and KB-JWT remain otherwise intact). The KB `sd_hash` no longer matches,
/// but disclosure integrity is checked before holder binding's sd_hash — and a forged disclosure is
/// the precise failure under test, so we assert the integrity reason is raised first.
fn splice_forged_disclosure(presentation: &str) -> String {
    // A fresh, well-formed object-property disclosure: ["<salt>", "rogue_claim", "value"].
    let forged = Base64UrlUnpadded::encode_string(
        json!(["AAAAAAAAAAAAAAAAAAAAAA", "rogue_claim", "value"])
            .to_string()
            .as_bytes(),
    );
    // presentation = jws~D1~...~Dn~KB ; insert the forged disclosure just before the KB segment.
    let mut segments: Vec<&str> = presentation.split('~').collect();
    let kb_idx = segments.len() - 1;
    segments.insert(kb_idx, &forged);
    segments.join("~")
}

/// Duplicate the first disclosure segment, inserting a second copy before the (empty) KB segment so
/// the same issuer-signed digest appears twice (RFC 9901 §7.3 invalidates a repeated digest).
fn duplicate_first_disclosure(presentation: &str) -> String {
    // presentation = jws~D1~...~Dn~  (issuer-only: a trailing `~`, no KB segment).
    let segments: Vec<&str> = presentation.split('~').collect();
    assert!(
        segments.len() >= 3,
        "need at least one disclosure to duplicate"
    );
    let first_disclosure = segments[1].to_owned();
    let mut out: Vec<String> = segments.iter().map(ToString::to_string).collect();
    // Insert the duplicate right after the original disclosure (before the remaining segments / the
    // trailing empty KB slot).
    out.insert(2, first_disclosure);
    out.join("~")
}

/// Split off the first `~`-delimited segment (the issuer JWS) from the rest.
fn split_first_segment(presentation: &str) -> (&str, &str) {
    presentation
        .split_once('~')
        .expect("presentation has at least one ~")
}

// --- a focused unit test of the JSON→AttributeValue mapping (coverage of nested shapes) ----------

#[test]
fn json_value_maps_to_the_closed_attribute_value() {
    use super::json_to_attribute;
    assert_eq!(json_to_attribute(&json!(null)), AttributeValue::Null);
    assert_eq!(
        json_to_attribute(&json!(true)),
        AttributeValue::Boolean(true)
    );
    assert_eq!(json_to_attribute(&json!(42)), AttributeValue::Integer(42));
    // A non-integer number is preserved as text (no lossy float).
    assert_eq!(
        json_to_attribute(&json!(1.5)),
        AttributeValue::Text("1.5".to_string())
    );
    assert_eq!(
        json_to_attribute(&json!("hi")),
        AttributeValue::Text("hi".to_string())
    );
    assert_eq!(
        json_to_attribute(&json!(["a", 1])),
        AttributeValue::Array(vec![
            AttributeValue::Text("a".to_string()),
            AttributeValue::Integer(1),
        ])
    );
    let mut nested = BTreeMap::new();
    nested.insert("k".to_string(), AttributeValue::Boolean(false));
    assert_eq!(
        json_to_attribute(&json!({ "k": false })),
        AttributeValue::Map(nested)
    );
}

// --- focused unit tests of the verifier's internal reject branches ------------------------------

#[test]
fn issuer_jws_with_more_than_three_segments_is_malformed() {
    // A four-segment "JWS" (extra `.segment`) is not valid compact JWS framing.
    let presentation = happy_presentation();
    let (jws, rest) = presentation.split_once('~').unwrap();
    let mangled = format!("{jws}.extra~{rest}");
    let anchors = trusted_anchors();
    let result = verify_sd_jwt_vc(&input(&mangled, &anchors));
    assert_invalid(&result, ReasonCode::MalformedCredential);
}

#[test]
fn sd_hash_mismatch_is_rejected_as_holder_binding() {
    // Splice a forged disclosure into a KB-bound presentation: `aud`/`nonce` still match, but the
    // presentation prefix changed so the KB-JWT `sd_hash` no longer matches → HolderBinding (this
    // exercises the `sd_hash` branch, which precedes the integrity check for a KB-bound credential).
    let presentation = happy_presentation();
    let spliced = splice_forged_disclosure(&presentation);
    let anchors = trusted_anchors();
    let result = verify_sd_jwt_vc(&input(&spliced, &anchors));
    assert_invalid(&result, ReasonCode::HolderBinding);
}

#[test]
fn non_jwk_cnf_is_rejected_as_holder_binding() {
    use super::holder_key_from_cnf;
    // Mint with a `cnf` that is a `kid` (not a `jwk`); the holder-key extraction must reject it.
    let cert_b64 = base64ct::Base64::encode_string(ISSUER_CERT_DER);
    let signer = Es256Signer::from_pkcs8(ISSUER_KEY_PK8);
    let sd_jwt = block_on(
        SdJwtBuilder::new_with_hasher(json!({ "iss": "x", "given_name": "Ada" }), Sha2Hasher)
            .unwrap()
            .header("x5c", json!([cert_b64]))
            .make_concealable("/given_name")
            .unwrap()
            .require_key_binding(RequiredKeyBinding::Kid("key-1".to_string()))
            .finish(&signer, "ES256"),
    )
    .unwrap();
    assert_eq!(holder_key_from_cnf(&sd_jwt), Err(ReasonCode::HolderBinding));
}

#[test]
fn malformed_p256_jwks_are_rejected() {
    use super::verifying_key_from_p256_jwk;
    // Wrong kty.
    assert_eq!(
        verifying_key_from_p256_jwk(&json!({ "kty": "RSA", "crv": "P-256", "x": "", "y": "" })),
        Err(ReasonCode::HolderBinding)
    );
    // Wrong curve.
    assert_eq!(
        verifying_key_from_p256_jwk(&json!({ "kty": "EC", "crv": "P-384", "x": "", "y": "" })),
        Err(ReasonCode::HolderBinding)
    );
    // Missing `x`.
    assert_eq!(
        verifying_key_from_p256_jwk(&json!({ "kty": "EC", "crv": "P-256", "y": "AAAA" })),
        Err(ReasonCode::HolderBinding)
    );
    // Wrong-length coordinates (1 byte each, not 32).
    let one = Base64UrlUnpadded::encode_string(&[0x01]);
    assert_eq!(
        verifying_key_from_p256_jwk(&json!({ "kty": "EC", "crv": "P-256", "x": one, "y": one })),
        Err(ReasonCode::HolderBinding)
    );
    // The real holder JWK round-trips into a usable key.
    let holder: Value = serde_json::from_slice(HOLDER_JWK_JSON).unwrap();
    assert!(verifying_key_from_p256_jwk(&holder).is_ok());
}

#[test]
fn compact_es256_rejects_bad_framing_and_signatures() {
    use super::verify_compact_es256;
    let holder: Value = serde_json::from_slice(HOLDER_JWK_JSON).unwrap();
    let key = super::verifying_key_from_p256_jwk(&holder).unwrap();
    // Four segments → framing error.
    assert_eq!(verify_compact_es256("a.b.c.d", &key), Err(()));
    // Two segments → missing signature.
    assert_eq!(verify_compact_es256("a.b", &key), Err(()));
    // Non-base64url signature segment.
    assert_eq!(verify_compact_es256("aa.bb.!!", &key), Err(()));
    // Right-length but wrong signature bytes.
    let bogus = Base64UrlUnpadded::encode_string(&[0x01; 64]);
    assert_eq!(
        verify_compact_es256(&format!("aa.bb.{bogus}"), &key),
        Err(())
    );
}

#[test]
fn unsupported_sd_alg_is_rejected_as_unsupported_format() {
    use super::collect_disclosed_attributes;
    // A hasher that names itself "sha-512" makes the builder write `_sd_alg: "sha-512"`, which the
    // verifier rejects (only sha-256 is supported).
    #[derive(Debug)]
    struct Sha512NameHasher;
    impl Hasher for Sha512NameHasher {
        fn digest(&self, input: &[u8]) -> Vec<u8> {
            use sha2::Digest as _;
            sha2::Sha256::digest(input).to_vec()
        }
        fn alg_name(&self) -> &'static str {
            "sha-512"
        }
    }
    let signer = Es256Signer::from_pkcs8(ISSUER_KEY_PK8);
    let sd_jwt = block_on(
        SdJwtBuilder::new_with_hasher(json!({ "iss": "x", "given_name": "Ada" }), Sha512NameHasher)
            .unwrap()
            .make_concealable("/given_name")
            .unwrap()
            .finish(&signer, "ES256"),
    )
    .unwrap();
    assert_eq!(
        collect_disclosed_attributes(&sd_jwt),
        Err(ReasonCode::UnsupportedFormat)
    );
}

/// Parse a hand-built `<jws>~<D1>~…~<Dn>~` presentation (issuer-only) into an [`SdJwt`] and run the
/// disclosure-integrity reconstruction over it. The issuer signature is not checked by
/// `collect_disclosed_attributes`, so a crafted payload is enough to exercise its reject branches.
fn collect_over_crafted(payload: &Value, disclosures: &[&str]) -> Result<(), ReasonCode> {
    use super::collect_disclosed_attributes;
    let jws = sign_issuer_jws(ISSUER_KEY_PK8, ISSUER_CERT_DER, payload);
    let presentation = format!("{jws}~{}~", disclosures.join("~"));
    let sd_jwt = sd_jwt_payload::SdJwt::parse(&presentation).unwrap();
    collect_disclosed_attributes(&sd_jwt).map(drop)
}

#[test]
fn the_same_digest_referenced_twice_in_the_structure_is_rejected() {
    // RFC 9901 §7.1 step 4: a digest encountered more than once invalidates the SD-JWT. Here ONE
    // disclosure's digest is listed twice in the top-level `_sd` array (a malformed/forged structure) —
    // the second substitution sees an already-used digest and rejects (distinct from a repeated
    // *presented* disclosure, which is caught while indexing).
    let disclosure = object_disclosure("AAAAAAAAAAAAAAAAAAAAAA", "given_name", json!("Ada"));
    let digest = disclosure_digest(&disclosure);
    let payload = json!({
        "iss": "x", "vct": "y", "_sd_alg": "sha-256", "_sd": [digest, digest],
    });
    assert_eq!(
        collect_over_crafted(&payload, &[&disclosure]),
        Err(ReasonCode::DisclosureIntegrity)
    );
}

#[test]
fn an_sd_entry_resolving_to_an_array_element_disclosure_is_rejected() {
    // An object `_sd` entry MUST resolve to an object-property disclosure (`[salt, name, value]`). A
    // `_sd` digest that resolves to an array-element disclosure (`[salt, value]`, no claim name) is a
    // structurally invalid disclosure set → reject.
    let disclosure = array_disclosure("AAAAAAAAAAAAAAAAAAAAAA", json!("orphan"));
    let digest = disclosure_digest(&disclosure);
    let payload = json!({
        "iss": "x", "vct": "y", "_sd_alg": "sha-256", "_sd": [digest],
    });
    assert_eq!(
        collect_over_crafted(&payload, &[&disclosure]),
        Err(ReasonCode::DisclosureIntegrity)
    );
}

#[test]
fn an_array_element_redaction_resolving_to_a_named_disclosure_is_rejected() {
    // An array-element redaction `{"...": digest}` MUST resolve to an array-element disclosure (no
    // claim name). A digest that resolves to an object-property disclosure (`[salt, name, value]`) in
    // an array position is structurally invalid → reject.
    let disclosure = object_disclosure("AAAAAAAAAAAAAAAAAAAAAA", "given_name", json!("Ada"));
    let digest = disclosure_digest(&disclosure);
    let payload = json!({
        "iss": "x", "vct": "y", "_sd_alg": "sha-256",
        "nationalities": [ { "...": digest } ],
    });
    assert_eq!(
        collect_over_crafted(&payload, &[&disclosure]),
        Err(ReasonCode::DisclosureIntegrity)
    );
}

#[test]
fn the_same_digest_referenced_twice_in_an_array_is_rejected() {
    // The repeated-digest rule also covers array-element redactions: the same `{"...": digest}` listed
    // twice in an array → the second occurrence is an already-used digest → reject.
    let disclosure = array_disclosure("AAAAAAAAAAAAAAAAAAAAAA", json!("DE"));
    let digest = disclosure_digest(&disclosure);
    let payload = json!({
        "iss": "x", "vct": "y", "_sd_alg": "sha-256",
        "nationalities": [ { "...": digest }, { "...": digest } ],
    });
    assert_eq!(
        collect_over_crafted(&payload, &[&disclosure]),
        Err(ReasonCode::DisclosureIntegrity)
    );
}

#[test]
fn a_disclosed_array_claim_value_is_reconstructed_in_full() {
    use super::collect_disclosed_attributes;
    // A WHOLE array claim `tags` is concealable; its disclosed value carries a clear scalar element AND
    // a nested array-element redaction. Reconstructing the disclosed value keeps the clear element in
    // full and substitutes the presented redaction — exercising `reconstruct_array` (a disclosed array
    // *value*, distinct from disclosing individual elements of a clear array).
    let inner = array_disclosure("BBBBBBBBBBBBBBBBBBBBBB", json!("hidden-tag"));
    let inner_digest = disclosure_digest(&inner);
    let outer = object_disclosure(
        "AAAAAAAAAAAAAAAAAAAAAA",
        "tags",
        json!(["clear-tag", { "...": inner_digest }]),
    );
    let outer_digest = disclosure_digest(&outer);
    let payload = json!({
        "iss": "x", "vct": "y", "_sd_alg": "sha-256", "_sd": [outer_digest],
    });
    let jws = sign_issuer_jws(ISSUER_KEY_PK8, ISSUER_CERT_DER, &payload);
    let presentation = format!("{jws}~{outer}~{inner}~");
    let sd_jwt = sd_jwt_payload::SdJwt::parse(&presentation).unwrap();
    let disclosed = collect_disclosed_attributes(&sd_jwt).unwrap();

    assert_eq!(
        disclosed.get("tags"),
        Some(&AttributeValue::Array(vec![
            AttributeValue::Text("clear-tag".to_string()),
            AttributeValue::Text("hidden-tag".to_string()),
        ])),
    );
}

#[test]
fn a_clear_array_element_nesting_a_disclosed_claim_is_reconstructed() {
    use super::collect_disclosed_attributes;
    // A clear (non-redacted) array element that is itself an object nesting a disclosable claim must be
    // recursed into: the disclosed nested claim is surfaced inside that array element, exercising the
    // array's clear-element branch and the nested-object reconstruction within an array.
    let inner = object_disclosure("AAAAAAAAAAAAAAAAAAAAAA", "locality", json!("London"));
    let digest = disclosure_digest(&inner);
    let payload = json!({
        "iss": "x", "vct": "y", "_sd_alg": "sha-256",
        "addresses": [ { "_sd": [digest] } ],
    });
    let jws = sign_issuer_jws(ISSUER_KEY_PK8, ISSUER_CERT_DER, &payload);
    let presentation = format!("{jws}~{inner}~");
    let sd_jwt = sd_jwt_payload::SdJwt::parse(&presentation).unwrap();
    let disclosed = collect_disclosed_attributes(&sd_jwt).unwrap();

    let mut locality = BTreeMap::new();
    locality.insert(
        "locality".to_string(),
        AttributeValue::Text("London".to_string()),
    );
    assert_eq!(
        disclosed.get("addresses"),
        Some(&AttributeValue::Array(vec![AttributeValue::Map(locality)])),
    );
}
