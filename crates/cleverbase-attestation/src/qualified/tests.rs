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
//! The qualified TL fixture is optional (cl. 4.12 is pre-operational); these tests **self-skip** when
//! it is absent — `qualified_trust_list_fixture()` returns `None` and each test returns early.

use super::{
    qualified_status, QualifiedTrustList, QualifiedTrustListError, EAA_Q_SERVICE_TYPE,
    SERVICE_STATUS_GRANTED, TS_119_615_VERSION,
};
use crate::sdjwtvc::test_issuer::{mint_sd_jwt, ISSUER_CERT_DER, ISSUER_KEY_PK8, NOW};
use crate::trust::StaticTestAnchors;
use crate::types::{Format, IssuerRole, QualifiedStatus, TrustStatus, VerificationPolicy};
use crate::verify::{verify, Presentation, VerifyContext};

/// The IACA root cert — the qualified TL's "signer" (scheme operator) and also the
/// trusted-but-non-qualified (plain `EAA`, no `/Q`) issuer in the fixture.
const CA_IACA: &[u8] = include_bytes!("../../../../tests/fixtures/attestation/ca-iaca.cert.der");
/// The mdoc DS cert — the granted-then-withdrawn `EAA/Q` issuer in the fixture.
const MDOC_DS: &[u8] = include_bytes!("../../../../tests/fixtures/attestation/mdoc-ds.cert.der");
/// A self-signed issuer absent from the qualified TL — the `Indeterminate` (no entry) path.
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

/// Load + parse the optional qualified-TL fixture, or `None` if it is absent/empty (self-skip seam).
fn qualified_trust_list_fixture() -> Option<QualifiedTrustList> {
    if QUALIFIED_TRUST_LIST_JSON.is_empty() {
        return None;
    }
    Some(QualifiedTrustList::parse(QUALIFIED_TRUST_LIST_JSON).expect("qualified TL fixture parses"))
}

// =================================================================================================
// The cl. 4.12 determination directly (the three outcome conditions).
// =================================================================================================

#[test]
fn qualified_issuer_granted_at_the_relevant_time_is_qualified() {
    let Some(tl) = qualified_trust_list_fixture() else {
        return; // self-skip: the qualified TL fixture is absent
    };
    // sdjwt-issuer is an EAA/Q service, granted from 2020-01-01 onward (so granted at NOW).
    let status = qualified_status(ISSUER_CERT_DER, RELEVANT_GRANTED, &tl);
    assert_eq!(status, QualifiedStatus::Qualified);
}

#[test]
fn trusted_but_non_qualified_issuer_is_not_qualified() {
    let Some(tl) = qualified_trust_list_fixture() else {
        return;
    };
    // ca-iaca is on the TL but only as a plain EAA (non-qualified) service — found, not EAA/Q-granted.
    let status = qualified_status(CA_IACA, RELEVANT_GRANTED, &tl);
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
        qualified_status(MDOC_DS, RELEVANT_GRANTED, &tl),
        QualifiedStatus::Qualified,
        "granted at a time before the withdrawal → Qualified"
    );
    assert_eq!(
        qualified_status(MDOC_DS, RELEVANT_AFTER_WITHDRAWN, &tl),
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
        qualified_status(ISSUER_CERT_DER, RELEVANT_BEFORE_GRANTED, &tl),
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
        qualified_status(WRONG_ISSUER, RELEVANT_GRANTED, &tl),
        QualifiedStatus::Indeterminate
    );
}

#[test]
fn an_empty_or_unreachable_trust_list_is_indeterminate() {
    // An empty national TL (no services) carries no data to decide → Indeterminate, never qualified.
    let empty = QualifiedTrustList::empty();
    assert_eq!(
        qualified_status(ISSUER_CERT_DER, RELEVANT_GRANTED, &empty),
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
    // signerCertDerB64 is optional; an unsigned offline list parses with signer_cert_der() == None
    // and still answers determinations.
    let json = br#"{"nextUpdate":"2036-06-22T09:11:42Z","services":[]}"#;
    let tl = QualifiedTrustList::parse(json).expect("parses");
    assert!(tl.signer_cert_der().is_none());
    assert_eq!(
        qualified_status(ISSUER_CERT_DER, RELEVANT_GRANTED, &tl),
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
    // validity, and the grant is read at the verification instant.
    let ctx = VerifyContext {
        now_unix: NOW,
        role: IssuerRole::Qeaa,
        qualified_gate: true,
        qualified_trust_list: Some(&tl),
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
    let ctx = VerifyContext {
        now_unix: NOW,
        role: IssuerRole::Qeaa,
        qualified_gate: false, // the context flag is OFF; the policy flag drives the gate
        qualified_trust_list: Some(&tl),
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
