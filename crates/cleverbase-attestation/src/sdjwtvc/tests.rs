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
    array_disclosure, attach_kb_jwt, attach_kb_jwt_with_iat, block_on, disclosure_digest,
    mint_array_element_disclosures, mint_concealable_object_with_concealable_child,
    mint_dual_value_same_name, mint_nested_shared_leaf, mint_sd_jwt,
    mint_sd_jwt_with_clear_subject_claim, mint_sd_jwt_with_typ, mint_sd_jwt_with_validity,
    mint_sd_jwt_without_vct, object_disclosure, sign_issuer_jws, Es256Signer, Sha2Hasher,
    HOLDER_JWK_JSON, HOLDER_KEY_PK8, ISSUER_CERT_DER, ISSUER_KEY_PK8, NOW, WRONG_ISSUER_CERT_DER,
    WRONG_ISSUER_KEY_PK8,
};
use super::{presented_claims, verify_sd_jwt_vc, KeyBindingChallenge, SdJwtVcInput, StatusInput};
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
        status_tokens: &crate::status::DEFAULT_STATUS_TOKENS,
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
fn fractional_past_exp_is_rounded_and_rejected_as_expired() {
    // RFC 7519 §2: "Non-integer values can be represented." A FRACTIONAL `exp` (200.5) is a valid
    // NumericDate — it is rounded up to 201 (no longer false-rejected as malformed), then honored as a
    // real upper bound: verifying at `now = NOW` (≫ 201) → Expired (NOT MalformedCredential).
    let sd_jwt = mint_sd_jwt_with_validity(
        ISSUER_KEY_PK8,
        ISSUER_CERT_DER,
        json!(NOW - 1_000),
        json!(200.5),
    );
    let presentation = attach_kb_jwt(sd_jwt, HOLDER_KEY_PK8, AUDIENCE, NONCE);
    let anchors = trusted_anchors();
    let result = verify_sd_jwt_vc(&input(&presentation, &anchors));
    assert_invalid(&result, ReasonCode::Expired);
}

#[test]
fn fractional_future_exp_is_accepted_not_false_rejected() {
    // FALSE-REJECT FIX (T7.1): a spec-valid fractional `exp` inside the window must VERIFY. `exp = 200.5`
    // rounds up to 201; verifying at `now = 100` (< 201) is in-window → VALID. (Issuer-only presentation
    // + no challenge so the KB-JWT `iat` freshness window — pinned to NOW — is not in play at `now=100`.)
    let sd_jwt =
        mint_sd_jwt_with_validity(ISSUER_KEY_PK8, ISSUER_CERT_DER, Value::Null, json!(200.5));
    let presentation = sd_jwt.presentation();
    let anchors = trusted_anchors();
    let mut inp = input(&presentation, &anchors);
    inp.key_binding = None;
    inp.now_unix = 100;
    let result = verify_sd_jwt_vc(&inp);
    assert!(
        result.valid,
        "a spec-valid fractional in-window exp must verify; reasons {:?}",
        result.reasons
    );
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

    // A present `null` `exp` → MalformedCredential (a present, uninterpretable bound, never skipped).
    let null_exp: SdJwtClaims = serde_json::from_value(json!({ "exp": null })).unwrap();
    assert_eq!(
        check_validity(&null_exp, NOW),
        Err(ReasonCode::MalformedCredential)
    );

    // RFC 7519 §2: a FRACTIONAL `nbf` is a valid NumericDate — rounded up (1.5 → 2) and honored, NOT
    // malformed. `now = NOW` (≫ 2) is at/after the not-before → OK.
    let frac_nbf: SdJwtClaims = serde_json::from_value(json!({ "nbf": 1.5 })).unwrap();
    assert!(check_validity(&frac_nbf, NOW).is_ok());
}

#[test]
fn fractional_bounds_round_up_so_a_sub_second_window_is_honored_exactly() {
    // FALSE-REJECT FIX (#2): a fractional NumericDate must reflect the issuer's true sub-second window
    // when compared against the whole-second `now` clock, never clip it a second early. Rounding BOTH
    // bounds UP reproduces RFC 7519 §4.1.4 (`now < exp`) and §4.1.5 (`now >= nbf`) exactly for integer
    // `now` — see `super::DateRounding::Up`. (`check_validity` reports a not-yet-valid `nbf` failure with
    // the same `Expired` reason as an `exp` failure.)
    use super::check_validity;
    use sd_jwt_payload::SdJwtClaims;

    // exp = T.5: VALID at now = T (RFC 7519 §4.1.4: 200 < 200.5 — the regression this fixes), Expired at
    // now = T + 1 (201 not < 200.5).
    let frac_exp: SdJwtClaims = serde_json::from_value(json!({ "exp": 200.5 })).unwrap();
    assert!(
        check_validity(&frac_exp, 200).is_ok(),
        "exp=200.5 must stay valid through second 200 (true expiry is 200.5)"
    );
    assert_eq!(
        check_validity(&frac_exp, 201),
        Err(ReasonCode::Expired),
        "exp=200.5 must be Expired once now is past it"
    );

    // nbf = T.5: not-yet-valid at now = T (RFC 7519 §4.1.5: 200 < 200.5 → reject), VALID at now = T + 1
    // (201 >= 200.5). Flooring nbf would have wrongly accepted it at 200 (a sub-second before its
    // issuer-asserted not-before).
    let frac_nbf: SdJwtClaims = serde_json::from_value(json!({ "nbf": 200.5 })).unwrap();
    assert_eq!(
        check_validity(&frac_nbf, 200),
        Err(ReasonCode::Expired),
        "nbf=200.5 must be not-yet-valid at second 200 (true not-before is 200.5)"
    );
    assert!(
        check_validity(&frac_nbf, 201).is_ok(),
        "nbf=200.5 must be valid once now reaches/passes it"
    );

    // INTEGER bounds are unchanged: exp = T is Expired at now = T (exclusive upper bound, §4.1.4) and
    // valid before; nbf = T is valid at now = T (inclusive lower bound, §4.1.5) and not-yet-valid before.
    let int_exp: SdJwtClaims = serde_json::from_value(json!({ "exp": 200 })).unwrap();
    assert_eq!(check_validity(&int_exp, 200), Err(ReasonCode::Expired));
    assert!(check_validity(&int_exp, 199).is_ok());
    let int_nbf: SdJwtClaims = serde_json::from_value(json!({ "nbf": 200 })).unwrap();
    assert!(check_validity(&int_nbf, 200).is_ok());
    assert_eq!(check_validity(&int_nbf, 199), Err(ReasonCode::Expired));
}

#[test]
fn presented_claims_merges_clear_and_disclosed_excluding_machinery() {
    // The FULL presented claim set (the DCQL gate's resolution input) is the issuer-signed CLEAR payload
    // MERGED with the selectively-disclosed claims — distinct from the privacy-minimal DISCLOSED set.
    let sd_jwt = mint_sd_jwt_with_clear_subject_claim(ISSUER_KEY_PK8, ISSUER_CERT_DER);
    let presentation = attach_kb_jwt(sd_jwt, HOLDER_KEY_PK8, AUDIENCE, NONCE);
    // `presented_claims` now takes the presentation ALREADY parsed (the caller parses once).
    let parsed = sd_jwt_payload::SdJwt::parse(&presentation).unwrap();

    let presented = presented_claims(&parsed);
    // The CLEAR subject claim is present alongside the DISCLOSED one.
    assert_eq!(
        presented.get("given_name"),
        Some(&AttributeValue::Text("Ada".into())),
        "the clear given_name must be in the presented set"
    );
    assert_eq!(
        presented.get("family_name"),
        Some(&AttributeValue::Text("Lovelace".into())),
        "the disclosed family_name must be in the presented set"
    );
    // Registered clear claims (e.g. `vct`) are "claims included in the presentation" and surfaced, but
    // the SD-JWT machinery / holder-binding control keys are NEVER surfaced as claims.
    assert!(presented.contains_key("vct"));
    assert!(!presented.contains_key("_sd"));
    assert!(!presented.contains_key("_sd_alg"));
    assert!(!presented.contains_key("cnf"));

    // The privacy-minimal disclosed set EXCLUDES the clear given_name — proving the two views differ
    // (reusing the single parse above — the disclosed-only walk over the same handle).
    let disclosed = super::collect_disclosed_attributes(&parsed).unwrap();
    assert!(
        !disclosed.contains_key("given_name"),
        "the disclosed-only view must omit the clear given_name"
    );
    assert!(disclosed.contains_key("family_name"));
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

#[test]
fn request_less_presentation_with_a_valid_kb_jwt_is_accepted() {
    // RFC 9901 §4.3: a PRESENT KB-JWT is verified (signature + `sd_hash`) even with no request; the
    // `aud`/`nonce` checks are the only thing a request gates. A request-less presentation carrying a
    // genuine, holder-signed KB-JWT therefore passes the cryptographic holder-binding check and is
    // VALID (the disclosed attributes are returned) — only the replay/audience binding is absent.
    let presentation = happy_presentation();
    let anchors = trusted_anchors();
    let mut inp = input(&presentation, &anchors);
    inp.key_binding = None; // no challenge ⇒ skip aud/nonce, but still verify sig + sd_hash.
    let result = verify_sd_jwt_vc(&inp);
    assert!(result.valid, "reasons {:?}", result.reasons);
    assert_eq!(
        result.disclosed_attributes.get("given_name"),
        Some(&AttributeValue::Text("Ada".to_string()))
    );
}

#[test]
fn request_less_presentation_with_a_forged_kb_signature_is_rejected_as_holder_binding() {
    // FALSE-ACCEPT PROBE (the request-less holder-binding hole): a present KB-JWT whose ES256
    // signature has been tampered must be rejected EVEN WITH NO CHALLENGE — the old code returned
    // `Ok(())` early when `key_binding = None`, waving a forged KB-JWT through (valid = true). A
    // present KB-JWT's signature is now always verified under the issuer-bound `cnf` key, so a forged
    // signature is `HolderBinding` on the request-less path too.
    let presentation = happy_presentation();
    let forged = flip_kb_signature(&presentation);
    let anchors = trusted_anchors();
    let mut inp = input(&forged, &anchors);
    inp.key_binding = None;
    let result = verify_sd_jwt_vc(&inp);
    assert_invalid(&result, ReasonCode::HolderBinding);
}

#[test]
fn request_less_presentation_with_a_tampered_kb_sd_hash_is_rejected_as_holder_binding() {
    // FALSE-ACCEPT PROBE (the request-less holder-binding hole, `sd_hash` arm): a present KB-JWT whose
    // `sd_hash` does not bind the presented issuer-JWS-plus-disclosures must be rejected even with no
    // challenge. The old early `Ok(())` skipped this; the `sd_hash` binding is now always verified for
    // a present KB-JWT, so a tampered `sd_hash` is `HolderBinding` on the request-less path too. (The
    // KB-JWT is re-signed by the holder over the wrong `sd_hash`, so the signature itself verifies —
    // isolating the `sd_hash` branch as the failing check.)
    let presentation = happy_presentation();
    let tampered = resign_kb_with_wrong_sd_hash(&presentation);
    let anchors = trusted_anchors();
    let mut inp = input(&tampered, &anchors);
    inp.key_binding = None;
    let result = verify_sd_jwt_vc(&inp);
    assert_invalid(&result, ReasonCode::HolderBinding);
}

#[test]
fn kb_jwt_with_lying_es384_alg_header_is_rejected_with_request() {
    // JOSE ALG-CONFUSION PROBE (with-request path): a PRESENT KB-JWT whose protected header lies as
    // `alg: ES384` — while the holder still ES256-signs with its P-256 key and the `sd_hash`/`aud`/
    // `nonce` all match — must be REJECTED. The alg-blind raw-P-256 verify would otherwise accept it
    // (signature valid over `header.payload`, `sd_hash` correct), violating this module's invariant
    // (ES256 for issuer AND KB-JWT signatures; HAIP 1.0 §7). The reject is `UnsupportedFormat`,
    // symmetric with the issuer JWS non-ES256 alg path — NOT a false-accept.
    let presentation = happy_presentation();
    let lying = resign_kb_with_alg(&presentation, "ES384");
    let anchors = trusted_anchors();
    let result = verify_sd_jwt_vc(&input(&lying, &anchors));
    assert_invalid(&result, ReasonCode::UnsupportedFormat);
}

#[test]
fn kb_jwt_with_lying_es384_alg_header_is_rejected_request_less() {
    // JOSE ALG-CONFUSION PROBE (request-less path): the same `alg: ES384` lie must be rejected even
    // with no challenge — a present KB-JWT is always cryptographically verified (sig + `sd_hash`), and
    // the alg header is part of that check. The old alg-blind path would wave this through on the
    // request-less path too (valid = true); now it is `UnsupportedFormat`.
    let presentation = happy_presentation();
    let lying = resign_kb_with_alg(&presentation, "ES384");
    let anchors = trusted_anchors();
    let mut inp = input(&lying, &anchors);
    inp.key_binding = None;
    let result = verify_sd_jwt_vc(&inp);
    assert_invalid(&result, ReasonCode::UnsupportedFormat);
}

#[test]
fn kb_jwt_with_lying_rs256_alg_header_is_rejected() {
    // A KB-JWT header lying as `alg: RS256` (any non-ES256, non-`none` value) is likewise rejected:
    // the verifier accepts ONLY ES256 for the holder binding, regardless of the raw P-256 signature
    // being valid. (`sd_jwt_payload`'s parse rejects only `alg=="none"`, not a specific alg.)
    let presentation = happy_presentation();
    let lying = resign_kb_with_alg(&presentation, "RS256");
    let anchors = trusted_anchors();
    let result = verify_sd_jwt_vc(&input(&lying, &anchors));
    assert_invalid(&result, ReasonCode::UnsupportedFormat);
}

#[test]
fn kb_jwt_resigned_with_honest_es256_alg_header_still_verifies() {
    // NO-FALSE-REJECT GUARD: re-signing the KB-JWT with an HONEST `alg: ES256` header (the same rewrite
    // path the lying-alg probe uses, only with the correct alg) must still VERIFY — the new alg check
    // fires ONLY on a non-ES256 alg, never on the legitimate ES256 holder binding.
    let presentation = happy_presentation();
    let honest = resign_kb_with_alg(&presentation, "ES256");
    let anchors = trusted_anchors();
    let result = verify_sd_jwt_vc(&input(&honest, &anchors));
    assert!(
        result.valid,
        "an honest ES256 KB-JWT must still verify; reasons {:?}",
        result.reasons
    );
    assert_eq!(
        result.disclosed_attributes.get("given_name"),
        Some(&AttributeValue::Text("Ada".to_string()))
    );
}

// --- conformance: JOSE crit / issuer typ / vct / KB-JWT iat / nested _sd_alg ---------------------

#[test]
fn issuer_jws_with_unknown_crit_header_is_rejected() {
    // RFC 7515 §4.1.11: a JWS whose `crit` lists an extension the recipient does not understand is
    // invalid. This verifier supports NO critical extension, so any `crit` member → reject. The `crit`
    // check runs before the issuer signature is verified (it does not re-sign), so it fires first.
    let presentation = happy_presentation();
    let with_crit = add_issuer_crit(&presentation, "urn:example:unknown-ext");
    let anchors = trusted_anchors();
    let result = verify_sd_jwt_vc(&input(&with_crit, &anchors));
    assert_invalid(&result, ReasonCode::UnsupportedFormat);
}

#[test]
fn kb_jwt_with_unknown_crit_header_is_rejected() {
    // RFC 7515 §4.1.11 applies to the holder KB-JWT too: a `crit` listing an unsupported extension →
    // reject. The KB-JWT is re-signed over the new header so everything else (sig/sd_hash/aud/nonce/
    // iat) holds — only the `crit` can be the failing check.
    let presentation = happy_presentation();
    let with_crit = resign_kb_with_crit(&presentation, "urn:example:unknown-ext");
    let anchors = trusted_anchors();
    let result = verify_sd_jwt_vc(&input(&with_crit, &anchors));
    assert_invalid(&result, ReasonCode::UnsupportedFormat);
}

#[test]
fn issuer_jws_with_wrong_or_absent_typ_is_rejected() {
    // SD-JWT VC §3.2.1 + RFC 9901 §9.11: the issuer JWS `typ` MUST be the SD-JWT VC media type. A
    // wrong `typ` (`"JWT"`) and an ABSENT `typ` are both rejected (the `typ` check runs before the
    // signature verify, so rewriting the header without re-signing still reaches it).
    let presentation = happy_presentation();
    let anchors = trusted_anchors();
    for typ in [Some("JWT"), None] {
        let mangled = rewrite_issuer_typ(&presentation, typ);
        let result = verify_sd_jwt_vc(&input(&mangled, &anchors));
        assert_invalid(&result, ReasonCode::UnsupportedFormat);
    }
}

#[test]
fn issuer_jws_with_transitional_vc_sd_jwt_typ_is_accepted() {
    // SD-JWT VC §3.2.1: the legacy `vc+sd-jwt` typ is accepted for the transitional period (alongside
    // the current `dc+sd-jwt`, which the happy path already covers). A real mint with `vc+sd-jwt`
    // verifies VALID.
    let sd_jwt = mint_sd_jwt_with_typ(ISSUER_KEY_PK8, ISSUER_CERT_DER, "vc+sd-jwt");
    let presentation = attach_kb_jwt(sd_jwt, HOLDER_KEY_PK8, AUDIENCE, NONCE);
    let anchors = trusted_anchors();
    let result = verify_sd_jwt_vc(&input(&presentation, &anchors));
    assert!(
        result.valid,
        "the transitional `vc+sd-jwt` typ must verify; reasons {:?}",
        result.reasons
    );
}

#[test]
fn missing_vct_is_rejected_as_malformed_credential() {
    // SD-JWT VC §type-claim: `vct` is REQUIRED. A credential omitting `vct` (otherwise well-formed,
    // trusted issuer, in-window, valid KB-JWT) is rejected as MalformedCredential.
    let sd_jwt = mint_sd_jwt_without_vct(ISSUER_KEY_PK8, ISSUER_CERT_DER);
    let presentation = attach_kb_jwt(sd_jwt, HOLDER_KEY_PK8, AUDIENCE, NONCE);
    let anchors = trusted_anchors();
    let result = verify_sd_jwt_vc(&input(&presentation, &anchors));
    assert_invalid(&result, ReasonCode::MalformedCredential);
}

#[test]
fn valid_crn_vct_is_accepted() {
    // The happy path already proves a URI `vct` (a Collision-Resistant Name) verifies VALID; this
    // asserts it explicitly as the positive arm of the `vct` requirement.
    let presentation = happy_presentation();
    let anchors = trusted_anchors();
    let result = verify_sd_jwt_vc(&input(&presentation, &anchors));
    assert!(
        result.valid,
        "a CRN `vct` must verify; reasons {:?}",
        result.reasons
    );
}

#[test]
fn vct_collision_resistant_name_shapes() {
    // RFC 7515 §2 Collision-Resistant Name shapes the verifier accepts (URI or reverse-domain) vs the
    // non-CRN values it rejects — unit coverage of `is_collision_resistant_name`.
    use super::is_collision_resistant_name;
    // URIs (scheme ":" non-empty remainder).
    assert!(is_collision_resistant_name(
        "https://credentials.example/identity_credential"
    ));
    assert!(is_collision_resistant_name("urn:eudi:pid:1"));
    assert!(is_collision_resistant_name(
        "urn:uuid:6ba7b810-9dad-11d1-80b4-00c04fd430c8"
    ));
    // Reverse-domain-style / domain names (≥2 dotted labels).
    assert!(is_collision_resistant_name("com.example.identity"));
    assert!(is_collision_resistant_name("example.com"));
    // Non-CRN: a bare token, a scheme with no remainder, a dangling-label dotted name, empty.
    assert!(!is_collision_resistant_name("identity"));
    assert!(!is_collision_resistant_name("https:"));
    assert!(!is_collision_resistant_name("example."));
    assert!(!is_collision_resistant_name(""));
}

#[test]
fn check_vct_rejects_missing_non_string_empty_and_non_crn() {
    // SD-JWT VC §type-claim: `vct` is REQUIRED, a (case-sensitive) STRING, and a Collision-Resistant
    // Name. `check_vct` reads it via the claims map, so a crafted payload exercises every reject arm.
    use super::check_vct;
    let check = |value: Value| {
        let claims: sd_jwt_payload::SdJwtClaims = serde_json::from_value(value).unwrap();
        check_vct(&claims)
    };
    // Missing entirely.
    assert_eq!(
        check(json!({ "iss": "x" })),
        Err(ReasonCode::MalformedCredential)
    );
    // Present but not a string.
    assert_eq!(
        check(json!({ "vct": 42 })),
        Err(ReasonCode::MalformedCredential)
    );
    // Present but empty.
    assert_eq!(
        check(json!({ "vct": "" })),
        Err(ReasonCode::MalformedCredential)
    );
    // Present, a non-empty string, but NOT a Collision-Resistant Name (a bare token).
    assert_eq!(
        check(json!({ "vct": "identity" })),
        Err(ReasonCode::MalformedCredential)
    );
    // A valid CRN → accepted.
    assert!(check(json!({ "vct": "https://credentials.example/id" })).is_ok());
}

#[test]
fn kb_jwt_iat_outside_the_acceptable_window_is_rejected() {
    // RFC 9901 §7.3 step 5.e: a present KB-JWT's `iat` MUST be within an acceptable window of the
    // verification time. A KB-JWT minted far in the FUTURE or absurdly in the PAST (relative to `now`)
    // is rejected as HolderBinding, even though its signature/sd_hash/aud/nonce are all otherwise valid.
    let anchors = trusted_anchors();
    for iat in [NOW + 10_000, NOW - 10_000] {
        let sd_jwt = mint_sd_jwt(ISSUER_KEY_PK8, ISSUER_CERT_DER);
        let presentation = attach_kb_jwt_with_iat(sd_jwt, HOLDER_KEY_PK8, AUDIENCE, NONCE, iat);
        let result = verify_sd_jwt_vc(&input(&presentation, &anchors));
        assert_invalid(&result, ReasonCode::HolderBinding);
    }
}

#[test]
fn kb_jwt_iat_within_the_acceptable_window_is_accepted() {
    // NO-FALSE-REJECT GUARD: a small skew (within the window) must still VERIFY — the `iat` check fires
    // only outside the conservative window, never on a genuine, near-now holder binding.
    let sd_jwt = mint_sd_jwt(ISSUER_KEY_PK8, ISSUER_CERT_DER);
    let presentation = attach_kb_jwt_with_iat(sd_jwt, HOLDER_KEY_PK8, AUDIENCE, NONCE, NOW + 100);
    let anchors = trusted_anchors();
    let result = verify_sd_jwt_vc(&input(&presentation, &anchors));
    assert!(
        result.valid,
        "a near-now KB-JWT iat must verify; reasons {:?}",
        result.reasons
    );
}

#[test]
fn request_less_kb_jwt_with_an_old_iat_is_accepted() {
    // NO-FALSE-REJECT: the KB-JWT `iat` freshness window binds the presentation to a verifier REQUEST
    // (RFC 9901 §7.3 step 5.e is nested under step 5 "If Key Binding is required" — the challenge
    // context). On the request-less path (no challenge) there is no freshness requirement, so a genuine,
    // holder-signed KB-JWT minted long ago (offline re-verification / batch / audit / clock skew) MUST
    // still verify — its signature + `sd_hash` prove holder possession. Enforcing the fixed window here
    // would false-reject an otherwise-valid stored presentation.
    let sd_jwt = mint_sd_jwt(ISSUER_KEY_PK8, ISSUER_CERT_DER);
    let presentation =
        attach_kb_jwt_with_iat(sd_jwt, HOLDER_KEY_PK8, AUDIENCE, NONCE, NOW - 10_000_000);
    let anchors = trusted_anchors();
    let mut inp = input(&presentation, &anchors);
    inp.key_binding = None; // request-less ⇒ no freshness requirement, so the old iat must not reject.
    let result = verify_sd_jwt_vc(&inp);
    assert!(
        result.valid,
        "a request-less KB-JWT with an old iat must verify; reasons {:?}",
        result.reasons
    );
}

#[test]
fn a_disclosure_named_sd_or_ellipsis_is_rejected() {
    // RFC 9901 §7.1 step 3.c.ii: a disclosure whose claim name is `_sd` or `...` MUST invalidate the
    // SD-JWT (those are SD-JWT machinery names, never legitimate object-property claim names).
    for bad_name in ["_sd", "..."] {
        let disclosure = object_disclosure("AAAAAAAAAAAAAAAAAAAAAA", bad_name, json!("x"));
        let digest = disclosure_digest(&disclosure);
        let payload = json!({ "iss": "x", "vct": "y", "_sd_alg": "sha-256", "_sd": [digest] });
        assert_eq!(
            collect_over_crafted(&payload, &[&disclosure]),
            Err(ReasonCode::DisclosureIntegrity)
        );
    }
}

#[test]
fn a_nested_sd_alg_in_the_issuer_payload_is_rejected() {
    use super::collect_disclosed_attributes;
    // RFC 9901 §4.1.1: `_sd_alg` MUST appear only at the top level — never nested. A nested `_sd_alg`
    // (here inside `address`) is rejected as MalformedCredential.
    let payload = json!({
        "iss": "x", "vct": "y", "_sd_alg": "sha-256",
        "address": { "_sd_alg": "sha-256", "country": "UK" },
    });
    let jws = sign_issuer_jws(ISSUER_KEY_PK8, ISSUER_CERT_DER, &payload);
    let presentation = format!("{jws}~");
    let sd_jwt = sd_jwt_payload::SdJwt::parse(&presentation).unwrap();
    assert_eq!(
        collect_disclosed_attributes(&sd_jwt),
        Err(ReasonCode::MalformedCredential)
    );
}

#[test]
fn a_nested_sd_alg_inside_a_disclosed_value_is_rejected() {
    // RFC 9901 §4.1.1: a disclosed object VALUE carrying an `_sd_alg` would place it in a nested
    // position once substituted — rejected as MalformedCredential.
    let disclosure = object_disclosure(
        "AAAAAAAAAAAAAAAAAAAAAA",
        "address",
        json!({ "_sd_alg": "sha-256" }),
    );
    let digest = disclosure_digest(&disclosure);
    let payload = json!({ "iss": "x", "vct": "y", "_sd_alg": "sha-256", "_sd": [digest] });
    assert_eq!(
        collect_over_crafted(&payload, &[&disclosure]),
        Err(ReasonCode::MalformedCredential)
    );
}

// --- presentation-mutation helpers --------------------------------------------------------------

/// Flip a byte in the middle of the KB-JWT signature (the final `~`-segment), invalidating the
/// holder-binding signature while keeping the base64url framing canonical so the verifier reaches the
/// signature check rather than a decode error.
fn flip_kb_signature(presentation: &str) -> String {
    let mut segments: Vec<&str> = presentation.split('~').collect();
    let kb_idx = segments.len() - 1;
    let mut parts: Vec<&str> = segments[kb_idx].split('.').collect();
    let mut sig_bytes = Base64UrlUnpadded::decode_vec(parts[2]).unwrap();
    let mid = sig_bytes.len() / 2;
    sig_bytes[mid] ^= 0xFF;
    let new_sig = Base64UrlUnpadded::encode_string(&sig_bytes);
    parts[2] = &new_sig;
    let new_kb = parts.join(".");
    segments[kb_idx] = &new_kb;
    segments.join("~")
}

/// Re-sign the KB-JWT (the final `~`-segment) by the holder over a corrupted `sd_hash`, so the
/// signature itself verifies but the `sd_hash` no longer binds the presented prefix. Isolates the
/// `sd_hash` branch of the holder-binding check (a present, holder-signed KB-JWT with a wrong binding).
fn resign_kb_with_wrong_sd_hash(presentation: &str) -> String {
    use p256::ecdsa::signature::Signer as _;
    use pkcs8::DecodePrivateKey as _;

    let mut segments: Vec<&str> = presentation.split('~').collect();
    let kb_idx = segments.len() - 1;
    let parts: Vec<&str> = segments[kb_idx].split('.').collect();
    // Corrupt the `sd_hash` claim in the KB-JWT payload, then re-sign with the holder key so only the
    // binding (not the signature) is wrong.
    let payload_json = Base64UrlUnpadded::decode_vec(parts[1]).unwrap();
    let mut payload: Value = serde_json::from_slice(&payload_json).unwrap();
    payload["sd_hash"] = Value::String("not-the-right-sd-hash".to_string());
    let header_b64 = parts[0].to_string();
    let payload_b64 =
        Base64UrlUnpadded::encode_string(serde_json::to_vec(&payload).unwrap().as_slice());
    let signing_input = format!("{header_b64}.{payload_b64}");
    let key = p256::ecdsa::SigningKey::from_pkcs8_der(HOLDER_KEY_PK8).unwrap();
    let sig: p256::ecdsa::Signature = key.sign(signing_input.as_bytes());
    let sig_b64 = Base64UrlUnpadded::encode_string(sig.to_bytes().as_slice());
    let new_kb = format!("{signing_input}.{sig_b64}");
    segments[kb_idx] = &new_kb;
    segments.join("~")
}

/// Re-sign the KB-JWT (the final `~`-segment) with the holder key after mutating its protected JOSE
/// header in place. The holder still ES256-signs with its P-256 key and the payload (sd_hash/aud/
/// nonce/iat) is left verbatim, so the result carries a VALID raw P-256 signature over its own
/// `header.payload` AND a matching `sd_hash` — isolating the mutated header field as the only thing a
/// header check can reject. Shared core for the alg-confusion and `crit` probes (DRY).
fn resign_kb_header(presentation: &str, mutate: impl FnOnce(&mut Value)) -> String {
    use p256::ecdsa::signature::Signer as _;
    use pkcs8::DecodePrivateKey as _;

    let mut segments: Vec<&str> = presentation.split('~').collect();
    let kb_idx = segments.len() - 1;
    let parts: Vec<&str> = segments[kb_idx].split('.').collect();
    let header_json = Base64UrlUnpadded::decode_vec(parts[0]).unwrap();
    let mut header: Value = serde_json::from_slice(&header_json).unwrap();
    mutate(&mut header);
    let header_b64 =
        Base64UrlUnpadded::encode_string(serde_json::to_vec(&header).unwrap().as_slice());
    let payload_b64 = parts[1].to_string();
    let signing_input = format!("{header_b64}.{payload_b64}");
    let key = p256::ecdsa::SigningKey::from_pkcs8_der(HOLDER_KEY_PK8).unwrap();
    let sig: p256::ecdsa::Signature = key.sign(signing_input.as_bytes());
    let sig_b64 = Base64UrlUnpadded::encode_string(sig.to_bytes().as_slice());
    let new_kb = format!("{signing_input}.{sig_b64}");
    segments[kb_idx] = &new_kb;
    segments.join("~")
}

/// Re-sign the KB-JWT over a **lying `alg` header** (`ES384`/`RS256`/…) — a VALID raw P-256 signature
/// over a header that lies about the alg; only an explicit `alg=ES256` header check can reject it (the
/// JOSE alg-confusion probe for [`super::check_kb_jwt_jose_header`]).
fn resign_kb_with_alg(presentation: &str, new_alg: &str) -> String {
    resign_kb_header(presentation, |header| {
        header["alg"] = Value::String(new_alg.to_string());
    })
}

/// Re-sign the KB-JWT after adding an unsupported `crit` member — the RFC 7515 §4.1.11 probe for
/// [`super::check_kb_jwt_jose_header`] (everything else stays valid, so only the `crit` can fail).
fn resign_kb_with_crit(presentation: &str, member: &str) -> String {
    resign_kb_header(presentation, |header| {
        header["crit"] = json!([member]);
    })
}

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

/// Add a `crit` member to the issuer JWS protected header, re-encoding the header (the signature now
/// won't verify, but the RFC 7515 §4.1.11 `crit` check runs before the signature verify so it fires
/// first).
fn add_issuer_crit(presentation: &str, member: &str) -> String {
    let (jws, rest) = split_first_segment(presentation);
    let parts: Vec<&str> = jws.split('.').collect();
    let header_json = Base64UrlUnpadded::decode_vec(parts[0]).unwrap();
    let mut header: Value = serde_json::from_slice(&header_json).unwrap();
    header["crit"] = json!([member]);
    let new_header =
        Base64UrlUnpadded::encode_string(serde_json::to_vec(&header).unwrap().as_slice());
    format!("{new_header}.{}.{}~{rest}", parts[1], parts[2])
}

/// Set (`Some`) or remove (`None`) the issuer JWS protected-header `typ`, re-encoding the header. The
/// `typ` check runs before the signature verify, so the (now-invalid) signature is never reached.
fn rewrite_issuer_typ(presentation: &str, typ: Option<&str>) -> String {
    let (jws, rest) = split_first_segment(presentation);
    let parts: Vec<&str> = jws.split('.').collect();
    let header_json = Base64UrlUnpadded::decode_vec(parts[0]).unwrap();
    let mut header: Value = serde_json::from_slice(&header_json).unwrap();
    match typ {
        Some(value) => {
            header["typ"] = Value::String(value.to_string());
        }
        None => {
            header.as_object_mut().unwrap().remove("typ");
        }
    }
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
fn a_non_string_sd_entry_inside_a_disclosed_value_is_rejected() {
    // RFC 9901 §7.1: `_sd` MUST be "an array of strings". A non-string `_sd` entry must reject the
    // SD-JWT rather than be silently `filter_map`-skipped (which would process a structure the spec
    // forbids). The TOP-LEVEL `_sd` is typed `Vec<String>` by `sd_jwt_payload`'s parser, so a non-
    // string there fails at parse time; the place a non-string `_sd` entry survives parsing is INSIDE
    // a disclosed object *value* (free-form issuer JSON reconstructed by `substitute_sd_array`). Here
    // the disclosed `address` value is `{"_sd": [<inner-digest>, 123]}`: reconstructing it hits the
    // non-string `123` and rejects. (Issuer-signed, so a conformance gap, not a forgery vector.)
    let inner = object_disclosure("BBBBBBBBBBBBBBBBBBBBBB", "locality", json!("London"));
    let inner_digest = disclosure_digest(&inner);
    let outer = object_disclosure(
        "AAAAAAAAAAAAAAAAAAAAAA",
        "address",
        json!({ "_sd": [inner_digest, 123] }),
    );
    let outer_digest = disclosure_digest(&outer);
    let payload = json!({
        "iss": "x", "vct": "y", "_sd_alg": "sha-256", "_sd": [outer_digest],
    });
    assert_eq!(
        collect_over_crafted(&payload, &[&outer, &inner]),
        Err(ReasonCode::DisclosureIntegrity)
    );
}

#[test]
fn an_array_redaction_object_with_an_extra_key_is_rejected() {
    // RFC 9901 §4.2.4.2: an array-element redaction object MUST have EXACTLY ONE key, the `...` key
    // ("There MUST NOT be any other keys in the object"). A `{"...": digest, "extra": 1}` object is a
    // malformed redaction → reject the SD-JWT, never silently process it (nor reinterpret it as a clear
    // array element). The disclosure IS presented, so only the extra key can fail the reconstruction.
    let disclosure = array_disclosure("AAAAAAAAAAAAAAAAAAAAAA", json!("DE"));
    let digest = disclosure_digest(&disclosure);
    let payload = json!({
        "iss": "x", "vct": "y", "_sd_alg": "sha-256",
        "nationalities": [ { "...": digest, "extra": 1 } ],
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

#[test]
fn issuance_time_unix_prefers_iat_then_nbf_then_none() {
    use super::issuance_time_unix;
    // Build a parseable issuer-only presentation (`<jws>~`) over a chosen payload, ALREADY parsed — the
    // reader now takes `&sd_jwt_payload::SdJwt` (the caller parses once), so this exercises the
    // qualified-gate relevant-time reader directly over the parsed handle.
    let present = |payload: &Value| -> sd_jwt_payload::SdJwt {
        let jws = sign_issuer_jws(ISSUER_KEY_PK8, ISSUER_CERT_DER, payload);
        sd_jwt_payload::SdJwt::parse(&format!("{jws}~")).unwrap()
    };
    // `iat` is the credential's issuance time and takes precedence over `nbf`.
    let both =
        present(&json!({ "iss": "x", "vct": "y", "iat": 1_700_000_000, "nbf": 1_600_000_000 }));
    assert_eq!(issuance_time_unix(&both), Some(1_700_000_000));
    // Absent `iat` → fall back to `nbf` (the earliest in-force instant).
    let nbf_only = present(&json!({ "iss": "x", "vct": "y", "nbf": 1_650_000_000 }));
    assert_eq!(issuance_time_unix(&nbf_only), Some(1_650_000_000));
    // Neither `iat` nor `nbf` → `None` (the gate then fails closed, never reading status at "now").
    let neither = present(&json!({ "iss": "x", "vct": "y" }));
    assert_eq!(issuance_time_unix(&neither), None);
    // A present-but-non-canonical `iat` (a JSON string, not a NumericDate) is treated as absent, and
    // a canonical `nbf` is used instead — never asserting qualification off an unreadable instant.
    let bad_iat = present(&json!({ "iss": "x", "vct": "y", "iat": "soon", "nbf": 1_640_000_000 }));
    assert_eq!(issuance_time_unix(&bad_iat), Some(1_640_000_000));
    // An unparseable presentation is now rejected at the parse boundary (the caller's parse), so the
    // reader is only ever handed a valid parsed handle — the fail-closed path lives at the call site.
    assert!(sd_jwt_payload::SdJwt::parse("not-a-sd-jwt").is_err());
}
