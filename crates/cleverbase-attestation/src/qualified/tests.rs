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
use crate::sdjwtvc::test_issuer::{
    mint_sd_jwt_with_validity, ISSUER_CERT_DER, ISSUER_KEY_PK8, WRONG_ISSUER_KEY_PK8,
};
use crate::trust::chain::ChainError;
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

// RCA — the gate evaluates TWO distinct times. It AUTHENTICATES the national TL (freshness `now >=
// NextUpdate` + the TL-signer's chain validity) at the verification instant `now`, and only READS the
// issuer's granted/withdrawn status at the credential's relevant (issuance) time. A prior fix
// correctly derived the relevant time from the credential for the *status read*, but passed that same
// old time into `authenticate`, so a TL that is STALE at real `now` but fresh relative to an old
// credential's issuance time authenticated as fresh → false `Qualified`. The fix passes `now` to
// `authenticate` and the relevant time only to the status read; these tests therefore supply BOTH a
// verification instant ([`NOW_VERIFY`]) and a relevant time, and the dedicated now-vs-relevant probes
// below (`*_stale_at_now_but_fresh_at_issuance*`, `*_expired_signer_at_now*`) keep the two apart.
//
// Authentication also enforces the signer cert's validity window: `ca-iaca` (the committed fixture's
// signer) is valid 2026-06-25..2036 and the leaf issuer certs 2026-06-25..2027-09-23, so the
// verification instant must sit inside the relevant signer's window or authentication fails
// (Indeterminate). The fixture's granted/withdrawn `startingTime`s (grant 2026-07-01, withdrawal
// 2027-03-01) sit inside that window to preserve the granted→withdrawn ordering the determination
// tests exercise.

/// The verification instant ("now") the determination tests AUTHENTICATE the committed fixture at:
/// inside the `ca-iaca` signer window (2026-06-25..2036) and before the fixture's 2036 `NextUpdate`,
/// so the TL authenticates and the status read (at the per-test relevant time) is reached. Kept
/// distinct from the `RELEVANT_*` (issuance/relevant) times so the now-vs-relevant split is explicit.
const NOW_VERIFY: i64 = 1_788_220_800; // 2026-09-01 — TL-signer valid + list fresh at this instant.
/// Relevant time INSIDE the `granted` window (after the 2026-07-01 grant) and BEFORE the mdoc-ds
/// withdrawal (2027-03-01T00:00:00Z). Inside the signer + leaf cert validity windows so the TL
/// authenticates and the status is read as granted.
const RELEVANT_GRANTED: i64 = 1_788_220_800; // 2026-09-01 — granted, not yet withdrawn, in-window.
/// Relevant time AFTER the mdoc-ds `withdrawn` starting time (2027-03-01T00:00:00Z), still inside the
/// signer + leaf cert validity windows.
const RELEVANT_AFTER_WITHDRAWN: i64 = 1_811_808_000; // 2027-06-01.
/// Relevant time BEFORE any `granted` entry started (the grants begin 2026-07-01T00:00:00Z) yet
/// AFTER the signer cert's notBefore (2026-06-25), so the TL still authenticates but the grant has
/// not yet begun → NotQualified ("found, not granted at the relevant time").
const RELEVANT_BEFORE_GRANTED: i64 = 1_782_432_000; // 2026-06-26 — signer valid, grant not yet begun.

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
    // sdjwt-issuer is a granted EAA/Q service at RELEVANT_GRANTED. The TL authenticates at NOW_VERIFY
    // (its signer chains to the scheme anchor + it is fresh there) so the status is then read.
    let status = qualified_status(
        ISSUER_CERT_DER,
        NOW_VERIFY,
        RELEVANT_GRANTED,
        &tl,
        &scheme_anchors(),
    );
    assert_eq!(status, QualifiedStatus::Qualified);
}

#[test]
fn trusted_but_non_qualified_issuer_is_not_qualified() {
    let Some(tl) = qualified_trust_list_fixture() else {
        return;
    };
    // ca-iaca is on the TL but only as a plain EAA (non-qualified) service — found, not EAA/Q-granted.
    let status = qualified_status(
        CA_IACA,
        NOW_VERIFY,
        RELEVANT_GRANTED,
        &tl,
        &scheme_anchors(),
    );
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
    // mdoc-ds: granted 2026-07-01, withdrawn 2027-03-01 — status is read AT the relevant time, while
    // the TL is authenticated at the (fixed) NOW_VERIFY instant in both calls.
    assert_eq!(
        qualified_status(
            MDOC_DS,
            NOW_VERIFY,
            RELEVANT_GRANTED,
            &tl,
            &scheme_anchors()
        ),
        QualifiedStatus::Qualified,
        "granted at a relevant time before the withdrawal → Qualified"
    );
    assert_eq!(
        qualified_status(
            MDOC_DS,
            NOW_VERIFY,
            RELEVANT_AFTER_WITHDRAWN,
            &tl,
            &scheme_anchors()
        ),
        QualifiedStatus::NotQualified,
        "withdrawn at the relevant time → NotQualified (status-at-time, not 'now')"
    );
}

#[test]
fn before_any_granted_entry_the_eaa_q_service_is_not_qualified() {
    let Some(tl) = qualified_trust_list_fixture() else {
        return;
    };
    // sdjwt-issuer's EAA/Q grant starts 2026-07-01; a relevant time before that is "found but not
    // granted at the relevant time" → NotQualified (the entry exists, the grant had not begun). The TL
    // still authenticates at NOW_VERIFY (signer valid + fresh there).
    assert_eq!(
        qualified_status(
            ISSUER_CERT_DER,
            NOW_VERIFY,
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
        qualified_status(
            WRONG_ISSUER,
            NOW_VERIFY,
            RELEVANT_GRANTED,
            &tl,
            &scheme_anchors()
        ),
        QualifiedStatus::Indeterminate
    );
}

#[test]
fn an_empty_or_unreachable_trust_list_is_indeterminate() {
    // An empty national TL (no services, no signer) carries no data to decide and cannot even
    // authenticate → Indeterminate, never qualified.
    let empty = QualifiedTrustList::empty();
    assert_eq!(
        qualified_status(
            ISSUER_CERT_DER,
            NOW_VERIFY,
            RELEVANT_GRANTED,
            &empty,
            &scheme_anchors()
        ),
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
        qualified_status(
            ISSUER_CERT_DER,
            NOW_VERIFY,
            RELEVANT_GRANTED,
            &tl,
            &scheme_anchors()
        ),
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

/// The PRODUCTION chain-validating trust source (the C-ABI semantics), trusting the issuing IACA root
/// (`ca-iaca`) for `(PID, SD-JWT VC)` at the verification instant `now`. The credential leaf
/// (`sdjwt-issuer`, a PID SD-JWT VC issuer carrying the `id-etsi-qct-pid` QcStatement) chains to it, so
/// this validates the FULL RFC 5280 §6.1 path (incl. each cert's validity window at `now` and the
/// per-role QcStatement leaf check) — unlike the exact-DER pinning of `StaticTestAnchors` (which never
/// checks notBefore/notAfter or the leaf profile). The role is PID because `sdjwt-issuer` is a PID cert;
/// the qualified GATE is role-agnostic (it reads the EAA/Q service status by certificate, not by role),
/// so the gate still determines qualified status for the same `sdjwt-issuer` service. Used by the
/// end-to-end gate tests so the chain-validity hardening (`LeafExpired`/`AnchorExpired`) composes with
/// the qualified gate through `verify()` at a COHERENT `now`.
fn chain_validating_anchors(now: i64) -> crate::trust::ChainValidatingAnchors {
    crate::trust::ChainValidatingAnchors::new(now).trust(IssuerRole::Pid, Format::SdJwtVc, CA_IACA)
}

/// Mint an SD-JWT VC whose `nbf`/`exp` window straddles `RELEVANT_GRANTED` (2026-09-01), so the
/// always-on bar accepts it at the same in-window instant the qualified gate authenticates the
/// national TL signer (`ca-iaca`, valid 2026-06-25..). The canonical `mint_sd_jwt` credential is
/// pinned to the 2025 `NOW` instant, which is outside the signer cert's validity window — so the
/// `verify()` gate tests mint an in-window credential instead (see the RCA on the `RELEVANT_*`
/// constants).
fn mint_in_window_sd_jwt() -> sd_jwt_payload::SdJwt {
    mint_sd_jwt_with_validity(
        ISSUER_KEY_PK8,
        ISSUER_CERT_DER,
        serde_json::json!(RELEVANT_GRANTED - 1_000),
        serde_json::json!(RELEVANT_GRANTED + 1_000_000),
    )
}

#[test]
fn gate_disabled_leaves_the_always_on_verdict_unchanged_and_qualified_status_none() {
    // The load-bearing SC-007 invariant: with the gate OFF the always-on VerificationResult is
    // byte-identical to a run that supplies NO qualified TL, and qualified_status stays None. Run on a
    // COHERENT timeline — an in-window credential + the production chain-validating trust source at
    // `RELEVANT_GRANTED` (2026-09-01, inside every cert's window) — so the always-on bar's chain
    // validity actually composes here (not the 2025 `NOW` + exact-DER-pin shortcut that skipped it).
    let Some(tl) = qualified_trust_list_fixture() else {
        return;
    };
    let sd_jwt = mint_in_window_sd_jwt();
    let presentation = sd_jwt.presentation();
    let anchors = chain_validating_anchors(RELEVANT_GRANTED);

    // Reference run: gate off, no qualified TL at all.
    let baseline_ctx = VerifyContext {
        now_unix: RELEVANT_GRANTED,
        role: IssuerRole::Pid,
        ..VerifyContext::default()
    };
    let baseline = verify(
        &Presentation::SdJwtVc(&presentation),
        &VerificationPolicy::default(),
        &anchors,
        &baseline_ctx,
        None,
    );
    assert!(
        baseline.valid,
        "the in-window credential chain-validates to the IACA root: {:?}",
        baseline.reasons
    );

    // Gate-off run that *does* carry a qualified TL but never enables the gate → must be identical.
    let gate_off_ctx = VerifyContext {
        now_unix: RELEVANT_GRANTED,
        role: IssuerRole::Pid,
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
    let sd_jwt = mint_in_window_sd_jwt();
    let presentation = sd_jwt.presentation();
    // The PRODUCTION chain-validating trust source: the credential leaf chains to the IACA root, and
    // RELEVANT_GRANTED (2026-09-01) is inside every cert's validity window, so the always-on bar's
    // RFC 5280 §6.1 path validation passes end-to-end here — the chain-validity gate composes with the
    // qualified gate at a coherent `now`.
    let anchors = chain_validating_anchors(RELEVANT_GRANTED);

    // The credential's leaf is sdjwt-issuer (granted EAA/Q); RELEVANT_GRANTED (2026-09-01) is within
    // the leaf's validity AND the signer cert's validity, so the always-on bar accepts the credential
    // and the grant is read at the verification instant. The scheme anchor (the IACA root)
    // authenticates the national TL before the status is read.
    let scheme = scheme_anchors();
    let ctx = VerifyContext {
        now_unix: RELEVANT_GRANTED,
        role: IssuerRole::Pid,
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
    // never a false "qualified", and the always-on verdict is otherwise unaffected. Coherent timeline:
    // an in-window credential + the production chain-validating trust source at RELEVANT_GRANTED.
    let sd_jwt = mint_in_window_sd_jwt();
    let presentation = sd_jwt.presentation();
    let anchors = chain_validating_anchors(RELEVANT_GRANTED);
    let ctx = VerifyContext {
        now_unix: RELEVANT_GRANTED,
        role: IssuerRole::Pid,
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
    assert!(result.valid, "always-on bar passes: {:?}", result.reasons);
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
    let sd_jwt = mint_in_window_sd_jwt();
    let presentation = sd_jwt.presentation();
    let anchors = chain_validating_anchors(RELEVANT_GRANTED);
    let policy = VerificationPolicy {
        qualified_gate: true, // enabled via the POLICY surface
        ..VerificationPolicy::default()
    };
    let scheme = scheme_anchors();
    let ctx = VerifyContext {
        now_unix: RELEVANT_GRANTED, // in-window for both the credential and the TL signer
        role: IssuerRole::Pid,
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

// --- now-vs-relevant split probes (the exact false-`Qualified` bug) ------------------------------
// A TL must be AUTHENTICATED at the verification instant `now`, not at the credential's (older)
// relevant time. These constants keep a `NextUpdate` / signer-validity window that is satisfied at the
// credential's issuance/relevant time but NOT at real `now`, so a gate that (incorrectly) authenticated
// at the relevant time would read `Qualified`, while authenticating at `now` correctly fails closed.

/// A `nextUpdate` that is AFTER the credential's issuance/relevant time ([`ISSUANCE_BEFORE_STALE`])
/// but BEFORE the verification instant ([`NOW_STALE`]): the list is fresh relative to the old
/// credential yet STALE at real `now`. (2026-08-01.)
const STALE_AT_NOW_NEXT_UPDATE: &str = "2026-08-01T00:00:00Z";
/// The verification instant for the stale-at-now probe: PAST `STALE_AT_NOW_NEXT_UPDATE` (so the list
/// is stale now) yet still inside the `ca-iaca` signer window (valid ..2036), so the failure is
/// specifically staleness, not signer expiry. (2030-01-01.)
const NOW_STALE: i64 = 1_893_456_000; // 2030-01-01.
/// The credential's issuance/relevant time for the stale-at-now probe: AFTER the 2026-07-01 grant (so
/// the issuer IS granted at the relevant time) and BEFORE `STALE_AT_NOW_NEXT_UPDATE` (so a gate that
/// wrongly authenticated at this time would see the list as fresh → false `Qualified`). (2026-07-15.)
const ISSUANCE_BEFORE_STALE: i64 = 1_784_073_600; // 2026-07-15 — granted, list "fresh" at issuance.
/// The verification instant for the expired-signer probe: PAST the leaf TL-signer's notAfter
/// (2027-09-23), so the TL-signer cert is EXPIRED now and its chain validity fails — even though the
/// list's `NextUpdate` is fresh. (2028-01-01.)
const NOW_SIGNER_EXPIRED: i64 = 1_830_297_600; // 2028-01-01 — leaf TL-signer expired by now.

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
            NOW_VERIFY,
            RELEVANT_GRANTED,
            &forged,
            &scheme_anchors()
        ),
        QualifiedStatus::Indeterminate,
        "a forged TL whose signer does not chain to the scheme anchor must NEVER be Qualified"
    );
    // And the authenticate() primitive itself surfaces the specific reason (at the verification now).
    assert!(matches!(
        forged.authenticate(&scheme_anchors(), NOW_VERIFY),
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
            NOW_VERIFY,
            RELEVANT_GRANTED,
            &unsigned,
            &scheme_anchors()
        ),
        QualifiedStatus::Indeterminate
    );
    assert_eq!(
        unsigned.authenticate(&scheme_anchors(), NOW_VERIFY),
        Err(QualifiedTrustError::Unsigned)
    );
}

#[test]
fn a_stale_list_past_next_update_is_indeterminate_not_qualified() {
    // A properly-SIGNED list (signer = ca-iaca, chains to the scheme anchor) listing the issuer as
    // granted EAA/Q, but PAST its NextUpdate at the verification instant → stale → Indeterminate,
    // never Qualified (a stale list is not authoritative forever).
    let stale =
        QualifiedTrustList::parse(&tl_json(Some(CA_IACA), STALE_NEXT_UPDATE, ISSUER_CERT_DER))
            .expect("parses");
    assert_eq!(
        qualified_status(
            ISSUER_CERT_DER,
            NOW_VERIFY,
            RELEVANT_GRANTED,
            &stale,
            &scheme_anchors()
        ),
        QualifiedStatus::Indeterminate,
        "a stale TL (now past NextUpdate) must NEVER be Qualified"
    );
    assert_eq!(
        stale.authenticate(&scheme_anchors(), NOW_VERIFY),
        Err(QualifiedTrustError::Stale)
    );
}

#[test]
fn a_list_stale_at_now_but_fresh_at_issuance_is_indeterminate_not_qualified() {
    // THE now-vs-relevant PROBE (the exact false-`Qualified` bug). A properly-signed list (signer =
    // ca-iaca) listing sdjwt-issuer as a GRANTED EAA/Q service, whose NextUpdate (2026-08-01) is AFTER
    // the credential's issuance/relevant time (2026-07-15) but BEFORE real now (2030). The issuer IS
    // granted at the relevant time, so the only thing standing between this list and a `Qualified`
    // verdict is whether the staleness check uses `now` (correct → stale → Indeterminate) or the
    // credential's relevant time (the bug → "fresh" → false Qualified).
    let stale_at_now = QualifiedTrustList::parse(&tl_json(
        Some(CA_IACA),
        STALE_AT_NOW_NEXT_UPDATE,
        ISSUER_CERT_DER,
    ))
    .expect("parses");

    // Authenticate is a NOW property: stale at `now`, but (if the bug were present) "fresh" at issuance.
    assert_eq!(
        stale_at_now.authenticate(&scheme_anchors(), NOW_STALE),
        Err(QualifiedTrustError::Stale),
        "the list is stale at the verification instant"
    );
    assert!(
        stale_at_now
            .authenticate(&scheme_anchors(), ISSUANCE_BEFORE_STALE)
            .is_ok(),
        "the list WOULD authenticate at the (older) issuance time — which is exactly why \
         authentication must use `now`, not the relevant time"
    );

    // The determination authenticates at `now` (stale) → Indeterminate, even though the issuer is
    // granted at the relevant time. With the pre-fix code (authenticate at the relevant time) this
    // would have read a false `Qualified`.
    assert_eq!(
        qualified_status(
            ISSUER_CERT_DER,
            NOW_STALE,
            ISSUANCE_BEFORE_STALE,
            &stale_at_now,
            &scheme_anchors(),
        ),
        QualifiedStatus::Indeterminate,
        "a TL stale at `now` (even if fresh relative to an older credential) must NEVER be Qualified"
    );
}

#[test]
fn a_tl_signer_expired_at_now_but_valid_at_issuance_is_indeterminate_not_qualified() {
    // The TL-signer chain validity is also a NOW property. The list is signed by sdjwt-issuer (a leaf
    // ISSUED BY ca-iaca, valid 2026-06-25..2027-09-23) and lists mdoc-ds as granted EAA/Q with a FRESH
    // NextUpdate. At the credential's issuance/relevant time (2026-09-01) the signer cert is valid; at
    // real now (2028-01-01) it has EXPIRED, so its chain validity fails → the list cannot authenticate.
    let signer_expired =
        QualifiedTrustList::parse(&tl_json(Some(SDJWT_ISSUER), FRESH_NEXT_UPDATE, MDOC_DS))
            .expect("parses");

    // Valid at the issuance time, expired at now — the very contrast the split protects against.
    assert!(
        signer_expired
            .authenticate(&scheme_anchors(), NOW_LEAF_VALID)
            .is_ok(),
        "the TL-signer cert is valid at the issuance-era instant"
    );
    assert!(
        matches!(
            signer_expired.authenticate(&scheme_anchors(), NOW_SIGNER_EXPIRED),
            Err(QualifiedTrustError::SignerNotTrusted(
                ChainError::LeafExpired
            ))
        ),
        "the TL-signer cert has expired by the verification instant → chain validity fails"
    );

    // The determination authenticates at `now` (signer expired) → Indeterminate, even though mdoc-ds is
    // granted EAA/Q at the relevant time and the signer was valid then. Pre-fix (authenticate at the
    // relevant time) this would have read a false `Qualified`.
    assert_eq!(
        qualified_status(
            MDOC_DS,
            NOW_SIGNER_EXPIRED,
            NOW_LEAF_VALID,
            &signer_expired,
            &scheme_anchors(),
        ),
        QualifiedStatus::Indeterminate,
        "a TL whose signer cert has expired by `now` must NEVER be Qualified, even for a credential \
         issued while that signer was still valid"
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
        qualified_status(ISSUER_CERT_DER, NOW_VERIFY, RELEVANT_GRANTED, &tl, &[]),
        QualifiedStatus::Indeterminate
    );
    assert_eq!(
        tl.authenticate(&[], NOW_VERIFY),
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
        qualified_status(
            MDOC_DS,
            NOW_LEAF_VALID,
            NOW_LEAF_VALID,
            &signed,
            &scheme_anchors()
        ),
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
    assert!(tl.authenticate(&scheme_anchors(), NOW_VERIFY).is_ok());
    // A signer that is NOT the scheme anchor (and not chained to it) fails authentication.
    assert!(matches!(
        tl.authenticate(&[WRONG_ISSUER.to_vec()], NOW_VERIFY),
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
    // Coherent timeline: an in-window credential + the production chain-validating trust source at
    // RELEVANT_GRANTED (inside every cert's window), so the always-on bar's chain validity composes.
    let sd_jwt = mint_in_window_sd_jwt();
    let presentation = sd_jwt.presentation();
    let anchors = chain_validating_anchors(RELEVANT_GRANTED);
    let scheme = scheme_anchors();
    let ctx = VerifyContext {
        now_unix: RELEVANT_GRANTED,
        role: IssuerRole::Pid,
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

// =================================================================================================
// End-to-end chain-validity composing with the qualified gate (the test-fidelity fix).
//
// These run `verify()` through the PRODUCTION chain-validating trust source (`ChainValidatingAnchors`)
// at a COHERENT `now` so the newly-added RFC 5280 chain-validity hardening (LeafExpired / not-yet-valid
// / not-chained) is exercised end-to-end through verify()+the gate — the gap the prior tests (now =
// 2025 NOW, before the leaf's 2026 notBefore, + exact-DER pinning that ignores the X.509 window) left.
// A chain-validity failure → INVALID (no qualified status: the gate is gated on `valid`), proving the
// two gates compose.
// =================================================================================================

/// A verification instant PAST the leaf's notAfter (2027-09-23) but INSIDE the IACA root's window
/// (..2036): only the LEAF is expired, so the leaf-validity gate fires (not the anchor-validity gate).
const NOW_LEAF_EXPIRED: i64 = 1_893_456_000; // 2030-01-01.
/// A verification instant BEFORE every fixture cert's notBefore (2026-06-25): the leaf is not-yet-valid.
const NOW_BEFORE_NOT_BEFORE: i64 = 1_750_000_000; // 2025-06-15 — the old (incoherent) `NOW`.

#[test]
fn the_verify_gate_with_an_expired_leaf_is_invalid_expired_and_has_no_qualified_status() {
    // The chain-validity gate composes with the qualified gate: an in-window-MINTED credential whose
    // signing LEAF cert has expired by `now` (past its notAfter, root still valid) chain-fails as
    // `LeafExpired` → the always-on bar reports `Expired` (NOT a misleading `UntrustedIssuer`). The
    // qualified gate is gated on `valid`, so `qualified_status` stays absent — never a `Qualified` read
    // off an INVALID credential (SC-007). The credential's own `nbf`/`exp` straddle NOW_LEAF_EXPIRED so
    // the CREDENTIAL validity window is not what fails — only the cert chain validity is.
    let Some(tl) = qualified_trust_list_fixture() else {
        return;
    };
    let sd_jwt = mint_sd_jwt_with_validity(
        ISSUER_KEY_PK8,
        ISSUER_CERT_DER,
        serde_json::json!(NOW_LEAF_EXPIRED - 1_000),
        serde_json::json!(NOW_LEAF_EXPIRED + 1_000_000),
    );
    let presentation = sd_jwt.presentation();
    let anchors = chain_validating_anchors(NOW_LEAF_EXPIRED);
    let scheme = scheme_anchors();
    let ctx = VerifyContext {
        now_unix: NOW_LEAF_EXPIRED,
        role: IssuerRole::Pid,
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
    assert!(!result.valid, "an expired signing leaf must reject");
    assert_eq!(
        result.reasons,
        vec![crate::types::ReasonCode::Expired],
        "an expired (trusted) signing cert surfaces as Expired, not UntrustedIssuer"
    );
    assert!(
        result.qualified_status.is_none(),
        "the qualified gate never runs on an INVALID credential (SC-007)"
    );
}

#[test]
fn the_verify_gate_with_a_not_yet_valid_leaf_is_invalid_expired() {
    // The exact incoherence the prior tests masked: at `now` = 2025-06-15 the signing leaf is
    // not-yet-valid (its notBefore is 2026-06-25). The production chain-validating source enforces the
    // X.509 window the old exact-DER pin ignored, so the credential is INVALID — `Expired` (the
    // not-yet-valid boundary is also a validity-window failure). The credential's own `nbf`/`exp`
    // straddle this instant, so only the cert-chain validity is what fails.
    let sd_jwt = mint_sd_jwt_with_validity(
        ISSUER_KEY_PK8,
        ISSUER_CERT_DER,
        serde_json::json!(NOW_BEFORE_NOT_BEFORE - 1_000),
        serde_json::json!(NOW_BEFORE_NOT_BEFORE + 1_000_000),
    );
    let presentation = sd_jwt.presentation();
    let anchors = chain_validating_anchors(NOW_BEFORE_NOT_BEFORE);
    let ctx = VerifyContext {
        now_unix: NOW_BEFORE_NOT_BEFORE,
        role: IssuerRole::Pid,
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
    assert!(!result.valid, "a not-yet-valid signing leaf must reject");
    assert_eq!(result.reasons, vec![crate::types::ReasonCode::Expired]);
    assert!(result.qualified_status.is_none());
}

#[test]
fn the_verify_gate_with_a_leaf_that_does_not_chain_is_invalid_untrusted_issuer() {
    // A genuine absence of trust (vs an expiry): a credential signed by `wrong-issuer` (self-signed,
    // does NOT chain to the IACA root) is INVALID — `UntrustedIssuer` (NOT `Expired`), the other arm of
    // the resolve_chain failure-category fold. Proves the in-window credential is rejected on trust, not
    // on its own validity window (which straddles `now`).
    let sd_jwt = mint_sd_jwt_with_validity(
        WRONG_ISSUER_KEY_PK8,
        WRONG_ISSUER,
        serde_json::json!(RELEVANT_GRANTED - 1_000),
        serde_json::json!(RELEVANT_GRANTED + 1_000_000),
    );
    let presentation = sd_jwt.presentation();
    let anchors = chain_validating_anchors(RELEVANT_GRANTED);
    let ctx = VerifyContext {
        now_unix: RELEVANT_GRANTED,
        role: IssuerRole::Pid,
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
    assert!(!result.valid, "a leaf that reaches no anchor must reject");
    assert_eq!(
        result.reasons,
        vec![crate::types::ReasonCode::UntrustedIssuer],
        "a no-trust chain failure surfaces as UntrustedIssuer, not Expired"
    );
    assert!(result.qualified_status.is_none());
}
