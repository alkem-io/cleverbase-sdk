//! Tests for the opt-in eIDAS qualified-status gate (T018 — written test-first against T019).
//!
//! Exercises the TS 119 615 v1.4.1 cl. 4.12 determination over the offline national-TL fixture
//! ([`QUALIFIED_TRUST_LIST_JSON`]): a qualified issuer (`EAA/Q` granted at the relevant time) →
//! [`QualifiedStatus::Qualified`]; a trusted-but-non-qualified issuer (a TL entry that is not an
//! `EAA/Q` service) → [`QualifiedStatus::NotQualified`]; a granted-then-withdrawn `EAA/Q` issuer →
//! `Qualified` before the withdrawal, `NotQualified` after (status read **at the relevant time**, not
//! "now"); and an issuer absent from the TL → [`QualifiedStatus::Indeterminate`] (never a false
//! "qualified" — SC-007). Plus the `verify()` gate-seam wiring: the gate populates
//! `qualified_status` only when enabled, and disabling it leaves the always-on verdict **byte-
//! identical** to the gate-off run.
//!
//! It also pins the load-bearing **fail-closed authentication** invariant (the false-trust bug fix):
//! before any status is read the gate chain-authenticates the national TL's signer against the
//! configured scheme-operator anchor and rejects a stale list — a forged / unsigned / unchained /
//! stale TL (or no scheme anchor) yields `Indeterminate`, **never** `Qualified`, even for an issuer
//! whose `EAA/Q` service is `granted` in the (untrusted) list.
//!
//! The qualified TL fixture is optional (cl. 4.12 is pre-operational); these tests **self-skip** when
//! it is absent — `qualified_trust_list_fixture()` returns `None` and each test returns early.

use super::{
    qualified_status, QualifiedTrustError, QualifiedTrustList, QualifiedTrustListError,
    EAA_Q_SERVICE_TYPE, SERVICE_STATUS_GRANTED, TS_119_615_VERSION,
};
use crate::sdjwtvc::test_issuer::{mint_sd_jwt, ISSUER_CERT_DER, ISSUER_KEY_PK8, NOW};
use crate::trust::chain::ChainError;
use crate::trust::StaticTestAnchors;
use crate::types::{Format, IssuerRole, QualifiedStatus, TrustStatus, VerificationPolicy};
use crate::verify::{verify, Presentation, VerifyContext};

/// The IACA root cert — the qualified TL's signer (scheme operator) AND the scheme-operator trust
/// anchor the gate authenticates the list against, and also the trusted-but-non-qualified (plain
/// `EAA`, no `/Q`) issuer in the fixture.
const CA_IACA: &[u8] = include_bytes!("../../../../tests/fixtures/attestation/ca-iaca.cert.der");
/// The mdoc DS cert — the granted-then-withdrawn `EAA/Q` issuer in the fixture. Issued by `ca-iaca`,
/// so it doubles as a TL signer that chain-validates to the scheme anchor by SIGNATURE (not a pin).
const MDOC_DS: &[u8] = include_bytes!("../../../../tests/fixtures/attestation/mdoc-ds.cert.der");
/// The SD-JWT VC issuer leaf — the granted `EAA/Q` issuer in the fixture. Issued by `ca-iaca`, so it
/// also serves as a properly-signed TL signer (chains to the scheme anchor by signature).
const SDJWT_ISSUER: &[u8] =
    include_bytes!("../../../../tests/fixtures/attestation/sdjwt-issuer.cert.der");
/// A self-signed issuer that does NOT chain to `ca-iaca` — the forged-TL-signer case AND the
/// `Indeterminate` (no entry) issuer path.
const WRONG_ISSUER: &[u8] =
    include_bytes!("../../../../tests/fixtures/attestation/wrong-issuer.cert.der");

/// The qualified-status national-TL fixture bytes (committed at the workspace fixture path).
const QUALIFIED_TRUST_LIST_JSON: &[u8] =
    include_bytes!("../../../../tests/fixtures/attestation/qualified-trust-list.json");

/// Relevant time INSIDE the `granted` window (after the 2020-01-01 grant) and BEFORE the mdoc-ds
/// withdrawal (2025-09-01T00:00:00Z = 1_756_684_800). Equals the SD-JWT test instant [`NOW`], so the
/// `verify()` gate tests can reuse it as the verification instant.
const RELEVANT_GRANTED: i64 = NOW; // 2025-06-15 — granted, not yet withdrawn.
/// Relevant time AFTER the mdoc-ds `withdrawn` starting time (2025-09-01T00:00:00Z = 1_756_684_800).
const RELEVANT_AFTER_WITHDRAWN: i64 = 1_800_000_000; // ~2027-01-15.
/// Relevant time BEFORE any `granted` entry started (the grants begin 2020-01-01T00:00:00Z =
/// 1_577_836_800).
const RELEVANT_BEFORE_GRANTED: i64 = 1_500_000_000; // 2017-07-14 — before the TL granted anything.

/// The scheme-operator trust anchor(s) the gate authenticates the national TL against: the IACA root
/// that signs the fixture. Helper so every determination call passes the authenticated anchor set.
fn scheme_anchors() -> Vec<Vec<u8>> {
    vec![CA_IACA.to_vec()]
}

/// Load + parse the optional qualified-TL fixture, or `None` if it is absent/empty (self-skip seam).
fn qualified_trust_list_fixture() -> Option<QualifiedTrustList> {
    if QUALIFIED_TRUST_LIST_JSON.is_empty() {
        return None;
    }
    Some(QualifiedTrustList::parse(QUALIFIED_TRUST_LIST_JSON).expect("qualified TL fixture parses"))
}

/// Build a national-TL JSON with a chosen `signer` cert (base64 DER, or `None` for unsigned), a
/// `next_update` instant, and a single granted `EAA/Q` service covering `issuer`. Used to exercise
/// the authentication gate (forged/unsigned/stale signers) against a list that WOULD otherwise report
/// the issuer `Qualified`.
fn tl_json(signer: Option<&[u8]>, next_update: &str, issuer: &[u8]) -> Vec<u8> {
    use base64ct::{Base64, Encoding as _};
    let issuer_b64 = Base64::encode_string(issuer);
    let signer_field = signer.map_or_else(String::new, |s| {
        format!(r#""signerCertDerB64":"{}","#, Base64::encode_string(s))
    });
    format!(
        r#"{{"nextUpdate":"{next_update}",{signer_field}"services":[
          {{"serviceName":"x","serviceTypeIdentifier":"{EAA_Q_SERVICE_TYPE}",
           "signingCertDerB64":"{issuer_b64}","statusHistory":[
             {{"status":"{SERVICE_STATUS_GRANTED}","startingTime":"2020-01-01T00:00:00Z"}}]}}]}}"#
    )
    .into_bytes()
}

// =================================================================================================
// The cl. 4.12 determination directly (the three outcome conditions).
// =================================================================================================

#[test]
fn qualified_issuer_granted_at_the_relevant_time_is_qualified() {
    let Some(tl) = qualified_trust_list_fixture() else {
        return; // self-skip: the qualified TL fixture is absent
    };
    // sdjwt-issuer is an EAA/Q service, granted from 2020-01-01 onward (so granted at NOW). The TL
    // authenticates (its signer chains to the scheme anchor + it is fresh) so the status is read.
    let status = qualified_status(ISSUER_CERT_DER, RELEVANT_GRANTED, &tl, &scheme_anchors());
    assert_eq!(status, QualifiedStatus::Qualified);
}

#[test]
fn trusted_but_non_qualified_issuer_is_not_qualified() {
    let Some(tl) = qualified_trust_list_fixture() else {
        return;
    };
    // ca-iaca is on the TL but only as a plain EAA (non-qualified) service — found, not EAA/Q-granted.
    let status = qualified_status(CA_IACA, RELEVANT_GRANTED, &tl, &scheme_anchors());
    assert_eq!(
        status,
        QualifiedStatus::NotQualified,
        "a trusted-but-non-qualified issuer must NOT be a false 'qualified'"
    );
}

#[test]
fn withdrawn_eaa_q_is_qualified_before_and_not_qualified_after_the_withdrawal() {
    let Some(tl) = qualified_trust_list_fixture() else {
        return;
    };
    // mdoc-ds: granted 2020-01-01, withdrawn 2025-09-01 — status is read AT the relevant time.
    assert_eq!(
        qualified_status(MDOC_DS, RELEVANT_GRANTED, &tl, &scheme_anchors()),
        QualifiedStatus::Qualified,
        "granted at a time before the withdrawal → Qualified"
    );
    assert_eq!(
        qualified_status(MDOC_DS, RELEVANT_AFTER_WITHDRAWN, &tl, &scheme_anchors()),
        QualifiedStatus::NotQualified,
        "withdrawn at the relevant time → NotQualified (status-at-time, not 'now')"
    );
}

#[test]
fn before_any_granted_entry_the_eaa_q_service_is_not_qualified() {
    let Some(tl) = qualified_trust_list_fixture() else {
        return;
    };
    // sdjwt-issuer's EAA/Q grant starts 2020-01-01; a relevant time before that is "found but not
    // granted at the relevant time" → NotQualified (the entry exists, the grant had not begun).
    assert_eq!(
        qualified_status(
            ISSUER_CERT_DER,
            RELEVANT_BEFORE_GRANTED,
            &tl,
            &scheme_anchors()
        ),
        QualifiedStatus::NotQualified
    );
}

#[test]
fn issuer_absent_from_the_trust_list_is_indeterminate() {
    let Some(tl) = qualified_trust_list_fixture() else {
        return;
    };
    // wrong-issuer is on no service entry at all → the trust-list data needed to decide is absent →
    // honest Indeterminate (NEVER assume qualified).
    assert_eq!(
        qualified_status(WRONG_ISSUER, RELEVANT_GRANTED, &tl, &scheme_anchors()),
        QualifiedStatus::Indeterminate
    );
}

#[test]
fn an_empty_or_unreachable_trust_list_is_indeterminate() {
    // An empty national TL (no services, no signer) carries no data to decide and cannot even
    // authenticate → Indeterminate, never qualified.
    let empty = QualifiedTrustList::empty();
    assert_eq!(
        qualified_status(ISSUER_CERT_DER, RELEVANT_GRANTED, &empty, &scheme_anchors()),
        QualifiedStatus::Indeterminate
    );
}

// =================================================================================================
// Fixture + parser sanity (the pinned version, the service-type URI, malformed inputs).
// =================================================================================================

#[test]
fn the_implementation_is_pinned_to_ts_119_615_v1_4_1() {
    assert_eq!(TS_119_615_VERSION, "1.4.1");
    assert_eq!(
        EAA_Q_SERVICE_TYPE,
        "http://uri.etsi.org/TrstSvc/Svctype/EAA/Q"
    );
    assert_eq!(
        SERVICE_STATUS_GRANTED,
        "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted"
    );
}

#[test]
fn parsed_fixture_exposes_the_signer_cert_and_next_update() {
    let Some(tl) = qualified_trust_list_fixture() else {
        return;
    };
    // The fixture is "signed" by the IACA root (its scheme operator) and carries a 2036 nextUpdate —
    // the chain-authentication + staleness hooks the always-on engine reuses.
    assert_eq!(tl.signer_cert_der(), Some(CA_IACA));
    assert!(tl.next_update_unix() > 2_000_000_000);
}

#[test]
fn a_list_without_a_signer_cert_parses_with_none() {
    // signerCertDerB64 is optional at the PARSER level; an unsigned offline list parses with
    // signer_cert_der() == None. The DETERMINATION over it is Indeterminate — an unsigned list cannot
    // authenticate (and this one carries no matching service anyway).
    let json = br#"{"nextUpdate":"2036-06-22T09:11:42Z","services":[]}"#;
    let tl = QualifiedTrustList::parse(json).expect("parses");
    assert!(tl.signer_cert_der().is_none());
    assert_eq!(
        qualified_status(ISSUER_CERT_DER, RELEVANT_GRANTED, &tl, &scheme_anchors()),
        QualifiedStatus::Indeterminate
    );
}

#[test]
fn malformed_qualified_trust_list_json_is_rejected() {
    assert!(matches!(
        QualifiedTrustList::parse(b"{ not json"),
        Err(QualifiedTrustListError::Json(_))
    ));
}

#[test]
fn invalid_next_update_is_rejected() {
    let bad = br#"{"nextUpdate":"not-a-timestamp","services":[]}"#;
    assert!(matches!(
        QualifiedTrustList::parse(bad),
        Err(QualifiedTrustListError::Time(_))
    ));
}

#[test]
fn invalid_signer_cert_base64_is_rejected() {
    let bad = br#"{"nextUpdate":"2036-06-22T09:11:42Z","signerCertDerB64":"!!!not base64!!!","services":[]}"#;
    assert!(matches!(
        QualifiedTrustList::parse(bad),
        Err(QualifiedTrustListError::Base64(_))
    ));
}

#[test]
fn invalid_base64_signing_cert_is_rejected() {
    let bad = br#"{"nextUpdate":"2036-06-22T09:11:42Z","signerCertDerB64":"AQID","services":[
      {"serviceName":"x","serviceTypeIdentifier":"http://uri.etsi.org/TrstSvc/Svctype/EAA/Q",
       "signingCertDerB64":"!!!not base64!!!","statusHistory":[]}]}"#;
    assert!(matches!(
        QualifiedTrustList::parse(bad),
        Err(QualifiedTrustListError::Base64(_))
    ));
}

#[test]
fn invalid_status_starting_time_is_rejected() {
    let bad = br#"{"nextUpdate":"2036-06-22T09:11:42Z","signerCertDerB64":"AQID","services":[
      {"serviceName":"x","serviceTypeIdentifier":"http://uri.etsi.org/TrstSvc/Svctype/EAA/Q",
       "signingCertDerB64":"AQID","statusHistory":[
         {"status":"http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted","startingTime":"nope"}]}]}"#;
    assert!(matches!(
        QualifiedTrustList::parse(bad),
        Err(QualifiedTrustListError::Time(_))
    ));
}

// =================================================================================================
// The verify() gate-seam wiring (the load-bearing SC-007 invariant).
// =================================================================================================

fn sd_jwt_anchors() -> StaticTestAnchors {
    StaticTestAnchors::new().trust(IssuerRole::Qeaa, Format::SdJwtVc, ISSUER_CERT_DER)
}

#[test]
fn gate_disabled_leaves_the_always_on_verdict_unchanged_and_qualified_status_none() {
    // The load-bearing SC-007 invariant: with the gate OFF the always-on VerificationResult is
    // byte-identical to a run that supplies NO qualified TL, and qualified_status stays None.
    let Some(tl) = qualified_trust_list_fixture() else {
        return;
    };
    let sd_jwt = mint_sd_jwt(ISSUER_KEY_PK8, ISSUER_CERT_DER);
    let presentation = sd_jwt.presentation();
    let anchors = sd_jwt_anchors();

    // Reference run: gate off, no qualified TL at all.
    let baseline_ctx = VerifyContext {
        now_unix: NOW,
        role: IssuerRole::Qeaa,
        ..VerifyContext::default()
    };
    let baseline = verify(
        &Presentation::SdJwtVc(&presentation),
        &VerificationPolicy::default(),
        &anchors,
        &baseline_ctx,
        None,
    );

    // Gate-off run that *does* carry a qualified TL but never enables the gate → must be identical.
    let gate_off_ctx = VerifyContext {
        now_unix: NOW,
        role: IssuerRole::Qeaa,
        qualified_gate: false,
        qualified_trust_list: Some(&tl),
        ..VerifyContext::default()
    };
    let gate_off = verify(
        &Presentation::SdJwtVc(&presentation),
        &VerificationPolicy::default(),
        &anchors,
        &gate_off_ctx,
        None,
    );

    assert_eq!(
        baseline, gate_off,
        "disabling the gate must not change the always-on verdict (SC-007)"
    );
    assert!(
        gate_off.qualified_status.is_none(),
        "gate off → qualified_status absent (never assumed)"
    );
}

#[test]
fn gate_enabled_populates_qualified_status_qualified_for_a_qualified_issuer() {
    let Some(tl) = qualified_trust_list_fixture() else {
        return;
    };
    let sd_jwt = mint_sd_jwt(ISSUER_KEY_PK8, ISSUER_CERT_DER);
    let presentation = sd_jwt.presentation();
    let anchors = sd_jwt_anchors();

    // The credential's leaf is sdjwt-issuer (granted EAA/Q); NOW (2025-06-15) is within the leaf's
    // validity, and the grant is read at the verification instant. The scheme anchor (the IACA root)
    // authenticates the national TL before the status is read.
    let scheme = scheme_anchors();
    let ctx = VerifyContext {
        now_unix: NOW,
        role: IssuerRole::Qeaa,
        qualified_gate: true,
        qualified_trust_list: Some(&tl),
        qualified_scheme_anchors: &scheme,
        ..VerifyContext::default()
    };
    let result = verify(
        &Presentation::SdJwtVc(&presentation),
        &VerificationPolicy::default(),
        &anchors,
        &ctx,
        None,
    );
    assert!(
        result.valid,
        "always-on bar still passes: {:?}",
        result.reasons
    );
    assert_eq!(result.trust_status, TrustStatus::Trusted);
    assert_eq!(result.qualified_status, Some(QualifiedStatus::Qualified));
}

#[test]
fn gate_enabled_but_no_trust_list_is_indeterminate_never_qualified() {
    // The gate is on but the host supplied no qualified TL → Indeterminate (unreachable data),
    // never a false "qualified", and the always-on verdict is otherwise unaffected.
    let sd_jwt = mint_sd_jwt(ISSUER_KEY_PK8, ISSUER_CERT_DER);
    let presentation = sd_jwt.presentation();
    let anchors = sd_jwt_anchors();
    let ctx = VerifyContext {
        now_unix: NOW,
        role: IssuerRole::Qeaa,
        qualified_gate: true,
        qualified_trust_list: None,
        ..VerifyContext::default()
    };
    let result = verify(
        &Presentation::SdJwtVc(&presentation),
        &VerificationPolicy::default(),
        &anchors,
        &ctx,
        None,
    );
    assert!(result.valid);
    assert_eq!(
        result.qualified_status,
        Some(QualifiedStatus::Indeterminate)
    );
}

#[test]
fn policy_qualified_gate_flag_also_enables_the_gate() {
    // T020: the opt-in gate is enabled via the verifier POLICY flag (VerificationPolicy.qualifiedGate),
    // not only the per-call context flag — the data-model surface. With the policy flag set and a TL
    // supplied, a granted EAA/Q issuer resolves to Qualified even though ctx.qualified_gate is false.
    let Some(tl) = qualified_trust_list_fixture() else {
        return;
    };
    let sd_jwt = mint_sd_jwt(ISSUER_KEY_PK8, ISSUER_CERT_DER);
    let presentation = sd_jwt.presentation();
    let anchors = sd_jwt_anchors();
    let policy = VerificationPolicy {
        qualified_gate: true, // enabled via the POLICY surface
        ..VerificationPolicy::default()
    };
    let scheme = scheme_anchors();
    let ctx = VerifyContext {
        now_unix: NOW,
        role: IssuerRole::Qeaa,
        qualified_gate: false, // the context flag is OFF; the policy flag drives the gate
        qualified_trust_list: Some(&tl),
        qualified_scheme_anchors: &scheme,
        ..VerifyContext::default()
    };
    let result = verify(
        &Presentation::SdJwtVc(&presentation),
        &policy,
        &anchors,
        &ctx,
        None,
    );
    assert!(result.valid);
    assert_eq!(result.qualified_status, Some(QualifiedStatus::Qualified));
}

// =================================================================================================
// Trust-list AUTHENTICATION — the false-trust bug fix (fail-closed, SC-007 "never false qualified").
//
// Before any status is read the national TL must authenticate: its embedded signer must chain to a
// configured scheme-operator anchor (reusing crate::trust::chain::verify_chain — DRY) AND the list
// must be fresh (now < NextUpdate). A forged / unsigned / unchained / stale list — or no scheme
// anchor at all — yields Indeterminate, NEVER Qualified, EVEN for an issuer the (untrusted) list
// reports as granted EAA/Q. This is the exact probe the reviewer used.
// =================================================================================================

/// A fresh `nextUpdate` (far future) and a stale one (long past) for the inline authentication TLs.
const FRESH_NEXT_UPDATE: &str = "2036-06-22T09:11:42Z";
const STALE_NEXT_UPDATE: &str = "2021-01-01T00:00:00Z";
/// An instant inside the CA-signed leaf certs' validity window (2026-06-25..2027-09-23) so a TL
/// signer that is a *leaf* (not the root) chain-validates by SIGNATURE — mirrors chain.rs's NOW.
const NOW_LEAF_VALID: i64 = 1_788_220_800; // 2026-09-01.

#[test]
fn a_forged_unchained_signer_is_indeterminate_not_qualified() {
    // THE PROBE: an attacker-supplied national TL signed by wrong-issuer (a self-signed cert that does
    // NOT chain to the scheme anchor ca-iaca), listing sdjwt-issuer as a GRANTED EAA/Q service. The
    // list WOULD report Qualified if read — but it must NOT authenticate → Indeterminate.
    let forged = QualifiedTrustList::parse(&tl_json(
        Some(WRONG_ISSUER),
        FRESH_NEXT_UPDATE,
        ISSUER_CERT_DER,
    ))
    .expect("parses");
    assert_eq!(
        qualified_status(
            ISSUER_CERT_DER,
            RELEVANT_GRANTED,
            &forged,
            &scheme_anchors()
        ),
        QualifiedStatus::Indeterminate,
        "a forged TL whose signer does not chain to the scheme anchor must NEVER be Qualified"
    );
    // And the authenticate() primitive itself surfaces the specific reason.
    assert!(matches!(
        forged.authenticate(&scheme_anchors(), RELEVANT_GRANTED),
        Err(QualifiedTrustError::SignerNotTrusted(_))
    ));
}

#[test]
fn an_unsigned_list_listing_a_granted_service_is_indeterminate_not_qualified() {
    // An unsigned national TL (no signerCertDerB64) listing sdjwt-issuer as granted EAA/Q cannot be
    // authenticated → Indeterminate, never Qualified.
    let unsigned = QualifiedTrustList::parse(&tl_json(None, FRESH_NEXT_UPDATE, ISSUER_CERT_DER))
        .expect("parses");
    assert!(unsigned.signer_cert_der().is_none());
    assert_eq!(
        qualified_status(
            ISSUER_CERT_DER,
            RELEVANT_GRANTED,
            &unsigned,
            &scheme_anchors()
        ),
        QualifiedStatus::Indeterminate
    );
    assert_eq!(
        unsigned.authenticate(&scheme_anchors(), RELEVANT_GRANTED),
        Err(QualifiedTrustError::Unsigned)
    );
}

#[test]
fn a_stale_list_past_next_update_is_indeterminate_not_qualified() {
    // A properly-SIGNED list (signer = ca-iaca, chains to the scheme anchor) listing sdjwt-issuer as
    // granted EAA/Q, but PAST its NextUpdate at the relevant time → stale → Indeterminate, never
    // Qualified (a stale list is not authoritative forever).
    let stale =
        QualifiedTrustList::parse(&tl_json(Some(CA_IACA), STALE_NEXT_UPDATE, ISSUER_CERT_DER))
            .expect("parses");
    assert_eq!(
        qualified_status(ISSUER_CERT_DER, RELEVANT_GRANTED, &stale, &scheme_anchors()),
        QualifiedStatus::Indeterminate,
        "a stale TL (now past NextUpdate) must NEVER be Qualified"
    );
    assert_eq!(
        stale.authenticate(&scheme_anchors(), RELEVANT_GRANTED),
        Err(QualifiedTrustError::Stale)
    );
}

#[test]
fn no_scheme_anchor_configured_is_indeterminate_not_qualified() {
    // The gate is enabled with a genuine, properly-signed fixture TL, but the host configured NO
    // scheme-operator anchor → the list cannot be authenticated → Indeterminate (can't authenticate
    // ⇒ can't assert qualified), never a false Qualified.
    let Some(tl) = qualified_trust_list_fixture() else {
        return;
    };
    assert_eq!(
        qualified_status(ISSUER_CERT_DER, RELEVANT_GRANTED, &tl, &[]),
        QualifiedStatus::Indeterminate
    );
    assert_eq!(
        tl.authenticate(&[], RELEVANT_GRANTED),
        Err(QualifiedTrustError::NoSchemeAnchor)
    );
}

#[test]
fn a_signer_that_chains_to_the_scheme_anchor_by_signature_authenticates_and_reads_qualified() {
    // The properly-signed positive case via the SIGNATURE path (not a direct pin): the TL signer is
    // sdjwt-issuer, a leaf ISSUED BY ca-iaca, so verify_chain authenticates it under the scheme
    // anchor at an instant inside the leaf's validity. A granted EAA/Q issuer then reads Qualified.
    let signed = QualifiedTrustList::parse(&tl_json(
        Some(SDJWT_ISSUER),
        FRESH_NEXT_UPDATE,
        MDOC_DS, // the listed granted EAA/Q issuer (any cert in the service is fine here)
    ))
    .expect("parses");
    assert!(
        signed
            .authenticate(&scheme_anchors(), NOW_LEAF_VALID)
            .is_ok(),
        "a leaf signer issued by the scheme anchor must authenticate by signature"
    );
    assert_eq!(
        qualified_status(MDOC_DS, NOW_LEAF_VALID, &signed, &scheme_anchors()),
        QualifiedStatus::Qualified
    );
}

#[test]
fn the_committed_fixture_signer_authenticates_against_the_scheme_anchor() {
    // The committed fixture is signed by ca-iaca (a direct DER-equal pin against the scheme anchor)
    // and is fresh at the test instants → it authenticates, which is why the determination tests
    // above can read status.
    let Some(tl) = qualified_trust_list_fixture() else {
        return;
    };
    assert!(tl.authenticate(&scheme_anchors(), RELEVANT_GRANTED).is_ok());
    // A signer that is NOT the scheme anchor (and not chained to it) fails authentication.
    assert!(matches!(
        tl.authenticate(&[WRONG_ISSUER.to_vec()], RELEVANT_GRANTED),
        Err(QualifiedTrustError::SignerNotTrusted(
            ChainError::IssuerMismatch
        ))
    ));
}

#[test]
fn the_verify_gate_with_a_forged_trust_list_is_indeterminate_not_qualified() {
    // End-to-end through verify(): the gate is enabled with a forged TL (signer = wrong-issuer, does
    // not chain to the scheme anchor) that lists the credential's issuer as granted EAA/Q. The
    // always-on bar still passes (the credential itself is genuine), but qualified_status is
    // Indeterminate — never a false Qualified from an unauthenticated list.
    let forged = QualifiedTrustList::parse(&tl_json(
        Some(WRONG_ISSUER),
        FRESH_NEXT_UPDATE,
        ISSUER_CERT_DER,
    ))
    .expect("parses");
    let sd_jwt = mint_sd_jwt(ISSUER_KEY_PK8, ISSUER_CERT_DER);
    let presentation = sd_jwt.presentation();
    let anchors = sd_jwt_anchors();
    let scheme = scheme_anchors();
    let ctx = VerifyContext {
        now_unix: NOW,
        role: IssuerRole::Qeaa,
        qualified_gate: true,
        qualified_trust_list: Some(&forged),
        qualified_scheme_anchors: &scheme,
        ..VerifyContext::default()
    };
    let result = verify(
        &Presentation::SdJwtVc(&presentation),
        &VerificationPolicy::default(),
        &anchors,
        &ctx,
        None,
    );
    assert!(
        result.valid,
        "always-on bar unaffected: {:?}",
        result.reasons
    );
    assert_eq!(
        result.qualified_status,
        Some(QualifiedStatus::Indeterminate),
        "a forged national TL must never make the gate report Qualified (SC-007)"
    );
}
