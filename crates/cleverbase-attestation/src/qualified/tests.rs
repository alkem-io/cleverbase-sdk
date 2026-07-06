//! Tests for the opt-in eIDAS qualified-status gate (T018 — written test-first against T019).
//!
//! Exercises the TS 119 615 v1.4.1 cl. 4.12 determination over the offline national-TL fixture
//! ([`QUALIFIED_TRUST_LIST_JSON`]): a qualified issuer (`EAA/Q` granted at the relevant time, with the
//! PRO-4.12.4-03 self-declaration) → [`QualifiedStatus::Qualified`]; a trusted-but-non-qualified issuer
//! → [`QualifiedStatus::NotQualified`]; a granted-then-withdrawn `EAA/Q` issuer → `Qualified` before the
//! withdrawal, `NotQualified` after (status read **at the relevant time**, not "now"); and an issuer
//! absent from the TL → [`QualifiedStatus::Indeterminate`] (never a false "qualified" — SC-007). Plus
//! the `verify()` gate-seam wiring.
//!
//! It also pins the load-bearing **fail-closed authentication** invariant (the false-trust bug fix):
//! before any status is read the gate chain-authenticates the national TL's signer against the
//! configured scheme-operator anchor and rejects a stale list — a forged / unsigned / unchained /
//! stale TL (or no scheme anchor) yields `Indeterminate`, **never** `Qualified`.
//!
//! The T5.x conformance fixes are pinned here too: the PRO-4.12.4-03 **QEAA type-indication
//! precondition** (a credential whose declared type is not the URN `urn:etsi:esi:eaa:eu:qualified` →
//! `Indeterminate`, never `Qualified`); and the §5.5.3 **Sdi matching** (a QEAA whose service entry
//! lists the issuing CA / its SKI rather than the byte-identical leaf is still matched, not
//! false-rejected as `Indeterminate`).
//!
//! The qualified TL fixture is optional (cl. 4.12 is pre-operational); these tests **self-skip** when
//! it is absent — `qualified_trust_list_fixture()` returns `None` and each test returns early.

use super::{
    qualified_status, LeafIdentity, QualifiedTrustError, QualifiedTrustList,
    QualifiedTrustListError, ServiceEntry, EAA_EU_QUALIFIED_TYPE, EAA_Q_SERVICE_TYPE,
    SERVICE_STATUS_GRANTED, TS_119_615_VERSION,
};
use crate::sdjwtvc::test_issuer::{
    block_on, holder_cnf, mint_sd_jwt_with_validity, Es256Signer, Sha2Hasher, ISSUER_CERT_DER,
    ISSUER_KEY_PK8, WRONG_ISSUER_KEY_PK8,
};
use crate::trust::chain::ChainError;
use crate::types::{Format, IssuerRole, QualifiedStatus, TrustStatus, VerificationPolicy};
use crate::verify::{verify, Presentation, VerifyContext};
use base64ct::{Base64, Encoding as _};

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

/// The credential type-indication threaded for a self-declared **qualified** EAA (TS 119 615 v1.4.1
/// PRO-4.12.4-03): the URN `urn:etsi:esi:eaa:eu:qualified`. Determination tests that expect a
/// non-`Indeterminate` verdict pass this (the precondition is satisfied).
const QTYPE: Option<&str> = Some(EAA_EU_QUALIFIED_TYPE);

// RCA — the gate evaluates TWO distinct times. It AUTHENTICATES the national TL (freshness `now >=
// NextUpdate` + the TL-signer's chain validity) at the verification instant `now`, and only READS the
// issuer's granted/withdrawn status at the credential's relevant (issuance) time. A prior fix
// correctly derived the relevant time from the credential for the *status read*, but passed that same
// old time into `authenticate`, so a TL that is STALE at real `now` but fresh relative to an old
// credential's issuance time authenticated as fresh → false `Qualified`. The fix passes `now` to
// `authenticate` and the relevant time only to the status read; these tests therefore supply BOTH a
// verification instant ([`NOW_VERIFY`]) and a relevant time, and the dedicated now-vs-relevant probes
// below keep the two apart.
//
// Authentication also enforces the signer cert's validity window: `ca-iaca` (the committed fixture's
// signer) is valid 2026-06-25..2036 and the leaf issuer certs 2026-06-25..2027-09-23, so the
// verification instant must sit inside the relevant signer's window or authentication fails
// (Indeterminate). The fixture's granted/withdrawn `startingTime`s (grant 2026-07-01, withdrawal
// 2027-03-01) sit inside that window to preserve the granted→withdrawn ordering the tests exercise.

/// The verification instant ("now") the determination tests AUTHENTICATE the committed fixture at:
/// inside the `ca-iaca` signer window (2026-06-25..2036) and before the fixture's 2036 `NextUpdate`.
const NOW_VERIFY: i64 = 1_788_220_800; // 2026-09-01 — TL-signer valid + list fresh at this instant.
/// Relevant time INSIDE the `granted` window (after the 2026-07-01 grant) and BEFORE the mdoc-ds
/// withdrawal (2027-03-01T00:00:00Z), inside the signer + leaf cert validity windows.
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
/// `next_update` instant, and a single granted `EAA/Q` service whose Sdi `signingCertDerB64` is
/// `service_cert`. Used to exercise the authentication gate AND the §5.5.3 Sdi-matching (the
/// `service_cert` may be the issuing CA rather than the byte-identical leaf).
fn tl_json(signer: Option<&[u8]>, next_update: &str, service_cert: &[u8]) -> Vec<u8> {
    let cert_b64 = Base64::encode_string(service_cert);
    let signer_field = signer.map_or_else(String::new, |s| {
        format!(r#""signerCertDerB64":"{}","#, Base64::encode_string(s))
    });
    format!(
        r#"{{"nextUpdate":"{next_update}",{signer_field}"services":[
          {{"serviceName":"x","serviceTypeIdentifier":"{EAA_Q_SERVICE_TYPE}",
           "signingCertDerB64":"{cert_b64}","statusHistory":[
             {{"status":"{SERVICE_STATUS_GRANTED}","startingTime":"2020-01-01T00:00:00Z"}}]}}]}}"#
    )
    .into_bytes()
}

/// Build a national-TL JSON whose single granted `EAA/Q` service identifies its Sdi by a **bare
/// X509SKI** (`x509SkiB64`, TS 119 612 §5.5.3) rather than a full certificate. Signed by `ca-iaca`.
fn tl_json_ski(next_update: &str, ski: &[u8]) -> Vec<u8> {
    let ski_b64 = Base64::encode_string(ski);
    let signer_b64 = Base64::encode_string(CA_IACA);
    format!(
        r#"{{"nextUpdate":"{next_update}","signerCertDerB64":"{signer_b64}","services":[
          {{"serviceName":"x","serviceTypeIdentifier":"{EAA_Q_SERVICE_TYPE}",
           "x509SkiB64":"{ski_b64}","statusHistory":[
             {{"status":"{SERVICE_STATUS_GRANTED}","startingTime":"2020-01-01T00:00:00Z"}}]}}]}}"#
    )
    .into_bytes()
}

/// The `SubjectKeyIdentifier` octets of a DER certificate (test helper for the §5.5.3 X509SKI probe).
fn cert_ski(der: &[u8]) -> Vec<u8> {
    use der::Decode as _;
    use x509_cert::ext::pkix::SubjectKeyIdentifier;
    let cert = x509_cert::Certificate::from_der(der).expect("test cert parses");
    let (_critical, skid) = cert
        .tbs_certificate
        .get::<SubjectKeyIdentifier>()
        .expect("SKI decodes")
        .expect("the fixture leaf carries a SubjectKeyIdentifier");
    skid.0.as_bytes().to_vec()
}

// =================================================================================================
// The cl. 4.12 determination directly (the three outcome conditions).
// =================================================================================================

#[test]
fn qualified_issuer_granted_at_the_relevant_time_is_qualified() {
    let Some(tl) = qualified_trust_list_fixture() else {
        return; // self-skip: the qualified TL fixture is absent
    };
    // sdjwt-issuer is a granted EAA/Q service at RELEVANT_GRANTED; the TL authenticates at NOW_VERIFY,
    // and the credential self-declares the qualified-EAA type (QTYPE) → Qualified.
    let status = qualified_status(
        ISSUER_CERT_DER,
        NOW_VERIFY,
        RELEVANT_GRANTED,
        &tl,
        &scheme_anchors(),
        QTYPE,
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
        QTYPE,
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
            &scheme_anchors(),
            QTYPE
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
            &scheme_anchors(),
            QTYPE
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
    // granted at the relevant time" → NotQualified (the entry exists, the grant had not begun).
    assert_eq!(
        qualified_status(
            ISSUER_CERT_DER,
            NOW_VERIFY,
            RELEVANT_BEFORE_GRANTED,
            &tl,
            &scheme_anchors(),
            QTYPE
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
            &scheme_anchors(),
            QTYPE
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
            &scheme_anchors(),
            QTYPE
        ),
        QualifiedStatus::Indeterminate
    );
}

// =================================================================================================
// PRO-4.12.4-03 QEAA type-indication precondition (the T5.2 false-trust fix).
// =================================================================================================

#[test]
fn granted_issuer_without_the_qualified_type_indication_is_indeterminate() {
    // T5.2: a granted-EAA/Q issuer (sdjwt-issuer, granted at the relevant time) whose attestation does
    // NOT self-declare the qualified-EAA type (its `vct` is a normal PID URN, not the QEAA URN) must be
    // `Indeterminate`, NEVER `Qualified` — PRO-4.12.4-03 (`ERROR_NO_ETSI_QEAA_TYPE_INDICATION_FOUND`).
    let Some(tl) = qualified_trust_list_fixture() else {
        return;
    };
    assert_eq!(
        qualified_status(
            ISSUER_CERT_DER,
            NOW_VERIFY,
            RELEVANT_GRANTED,
            &tl,
            &scheme_anchors(),
            Some("urn:eudi:pid:1"),
        ),
        QualifiedStatus::Indeterminate,
        "a granted issuer whose attestation does not self-declare the QEAA URN is NOT Qualified"
    );
}

#[test]
fn granted_issuer_with_the_qualified_type_indication_is_qualified() {
    // T5.2 (positive): the SAME granted issuer, WITH the qualified-EAA URN self-declaration → Qualified.
    let Some(tl) = qualified_trust_list_fixture() else {
        return;
    };
    assert_eq!(
        qualified_status(
            ISSUER_CERT_DER,
            NOW_VERIFY,
            RELEVANT_GRANTED,
            &tl,
            &scheme_anchors(),
            Some(EAA_EU_QUALIFIED_TYPE),
        ),
        QualifiedStatus::Qualified
    );
}

#[test]
fn an_absent_type_indication_is_indeterminate() {
    // PRO-4.12.4-03 (per ETSI TS 119 472-1): a QEAA MUST self-declare the qualified-EAA type via the
    // `category` URN in BOTH formats (SD-JWT VC claim / mdoc data element). An ABSENT type indication
    // (`None` — no `category`, i.e. an ordinary EAA, OR an mdoc document that did not disclose the
    // element) is NOT a self-declared QEAA → the precondition fails closed → `Indeterminate`, even for a
    // granted EAA/Q issuer. (Previously `None` was an mdoc-only "precondition N/A" skip; now that mdoc
    // also carries `category`, absence fails closed for both formats — never a false "qualified".)
    let Some(tl) = qualified_trust_list_fixture() else {
        return;
    };
    assert_eq!(
        qualified_status(
            ISSUER_CERT_DER,
            NOW_VERIFY,
            RELEVANT_GRANTED,
            &tl,
            &scheme_anchors(),
            None,
        ),
        QualifiedStatus::Indeterminate
    );
}

// =================================================================================================
// §5.5.3 Service-digital-identity matching (the T5.4 false-reject fix).
// =================================================================================================

#[test]
fn qeaa_matched_by_issuing_ca_sdi_is_qualified() {
    // T5.4: a national TL whose granted EAA/Q service lists the **issuing CA** (`ca-iaca`) as its Sdi —
    // NOT the byte-identical leaf. The credential's leaf (`sdjwt-issuer`, issued by `ca-iaca`) must
    // still be MATCHED (by the issuing-CA relationship, §5.5.3) → Qualified, not false-rejected as
    // Indeterminate.
    let tl = QualifiedTrustList::parse(&tl_json(
        Some(CA_IACA),
        "2036-06-22T09:11:42Z",
        CA_IACA, // the service's Sdi is the ISSUING CA, not the leaf
    ))
    .expect("parses");
    assert_eq!(
        qualified_status(
            ISSUER_CERT_DER, // the leaf, issued by ca-iaca
            NOW_VERIFY,
            RELEVANT_GRANTED,
            &tl,
            &scheme_anchors(),
            QTYPE,
        ),
        QualifiedStatus::Qualified,
        "a leaf whose Sdi lists the issuing CA must be matched (not false-rejected)"
    );
}

#[test]
fn qeaa_matched_by_ski_sdi_is_qualified() {
    // T5.4: a national TL whose granted EAA/Q service identifies its Sdi by a bare **X509SKI** (§5.5.3)
    // — the leaf is matched by its SubjectKeyIdentifier, not the exact cert.
    let leaf_ski = cert_ski(ISSUER_CERT_DER);
    let tl =
        QualifiedTrustList::parse(&tl_json_ski("2036-06-22T09:11:42Z", &leaf_ski)).expect("parses");
    assert_eq!(
        qualified_status(
            ISSUER_CERT_DER,
            NOW_VERIFY,
            RELEVANT_GRANTED,
            &tl,
            &scheme_anchors(),
            QTYPE,
        ),
        QualifiedStatus::Qualified,
        "a leaf matched by its X509SKI must be matched (not false-rejected)"
    );
}

#[test]
fn issuing_ca_sdi_match_is_fail_closed_without_the_aki_ski_tie() {
    // FALSE-QUALIFIED PROBE (§5.5.3 Sdi-matching precision): the issuing-CA case (3) must NOT match on
    // issuer-DN byte-equality ALONE. A leaf whose `issuer` DN merely COLLIDES with a granted EAA/Q Sdi
    // cert's `subject` DN — with the AKI (leaf) or SKI (Sdi) absent so the key-identifier tie cannot be
    // established — must NOT be bound to that service. Chaining to *some* trusted anchor does not prove
    // the leaf was issued by *this* Sdi's CA, so a DN collision would otherwise mislabel a non-qualified
    // issuer's credential `Qualified`. Fail closed: no AKI==SKI tie ⇒ no issuing-CA match.
    let colliding_dn = vec![0x30, 0x0a, 0x31, 0x08, 0x06, 0x03, 0x55, 0x04, 0x0a];
    let entry = ServiceEntry {
        service_type: EAA_Q_SERVICE_TYPE.to_owned(),
        status_history: Vec::new(),
        sdi_cert_der: None, // no exact-DER Sdi
        sdi_subject_der: Some(colliding_dn.clone()),
        sdi_ski: None, // SKI absent on the Sdi side → tie unestablishable
    };
    let leaf = LeafIdentity {
        issuer_der: colliding_dn.clone(), // collides with the Sdi subject DN
        ski: Some(vec![0xAA, 0xBB]),      // present but irrelevant (Sdi carries no SKI)
        aki: None,                        // AKI absent on the leaf side → tie unestablishable
    };
    assert!(
        !entry.matches_leaf(b"an-unrelated-leaf-der", &leaf),
        "a bare issuer-DN collision without the AKI==SKI tie must not match a qualified service"
    );

    // Control: with the AKI==SKI tie present and equal, the issuing-CA match still holds (no over-tighten).
    let entry_tied = ServiceEntry {
        service_type: EAA_Q_SERVICE_TYPE.to_owned(),
        status_history: Vec::new(),
        sdi_cert_der: None,
        sdi_subject_der: Some(colliding_dn.clone()),
        sdi_ski: Some(vec![0xCA, 0xFE]),
    };
    let leaf_tied = LeafIdentity {
        issuer_der: colliding_dn,
        ski: None,
        aki: Some(vec![0xCA, 0xFE]),
    };
    assert!(
        entry_tied.matches_leaf(b"an-unrelated-leaf-der", &leaf_tied),
        "an issuing-CA match with a present, equal AKI==SKI tie must still match"
    );
}

#[test]
fn an_unparsable_leaf_can_still_exact_match_a_listed_raw_sdi() {
    // Defensive: a credential leaf that is not a parseable certificate (no derived issuer/SKI/AKI) can
    // still EXACT-match a listed Sdi by raw bytes. Build a granted EAA/Q service whose Sdi is the raw
    // bytes `[1,2,3]` (signed by ca-iaca so the list authenticates) and query that same raw leaf.
    let raw_leaf: &[u8] = &[1, 2, 3];
    let tl = QualifiedTrustList::parse(&tl_json(Some(CA_IACA), FRESH_NEXT_UPDATE, raw_leaf))
        .expect("parses");
    assert_eq!(
        qualified_status(
            raw_leaf,
            NOW_VERIFY,
            RELEVANT_GRANTED,
            &tl,
            &scheme_anchors(),
            QTYPE,
        ),
        QualifiedStatus::Qualified,
        "an unparsable leaf still exact-matches its listed raw Sdi bytes"
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
    // The pinned v1.4.1 QEAA self-declaration URN (the `esi:` segment distinguishes it from v1.3.1).
    assert_eq!(EAA_EU_QUALIFIED_TYPE, "urn:etsi:esi:eaa:eu:qualified");
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
            &scheme_anchors(),
            QTYPE
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
fn invalid_base64_ski_is_rejected() {
    let bad = br#"{"nextUpdate":"2036-06-22T09:11:42Z","signerCertDerB64":"AQID","services":[
      {"serviceName":"x","serviceTypeIdentifier":"http://uri.etsi.org/TrstSvc/Svctype/EAA/Q",
       "x509SkiB64":"!!!not base64!!!","statusHistory":[]}]}"#;
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
/// this validates the FULL RFC 5280 §6.1 path; the qualified GATE is role-agnostic (it reads the EAA/Q
/// service status by certificate, not by role), so the gate still determines qualified status for the
/// same `sdjwt-issuer` service.
fn chain_validating_anchors(now: i64) -> crate::trust::ChainValidatingAnchors {
    crate::trust::ChainValidatingAnchors::new(now).trust(IssuerRole::Pid, Format::SdJwtVc, CA_IACA)
}

/// Mint an in-window SD-JWT VC carrying the **default** PID-style `vct` (NOT the QEAA URN), so the
/// always-on bar accepts it but it does NOT self-declare the qualified-EAA type (PRO-4.12.4-03).
fn mint_in_window_sd_jwt() -> sd_jwt_payload::SdJwt {
    mint_sd_jwt_with_validity(
        ISSUER_KEY_PK8,
        ISSUER_CERT_DER,
        serde_json::json!(RELEVANT_GRANTED - 1_000),
        serde_json::json!(RELEVANT_GRANTED + 1_000_000),
    )
}

/// Mint an in-window SD-JWT VC that self-declares the qualified-EAA type via the issuer-signed
/// **`category`** claim ([`EAA_EU_QUALIFIED_TYPE`], per ETSI TS 119 472-1 — NOT the `vct`, which is the
/// credential-type identifier), so a granted EAA/Q issuer resolves to `Qualified` through `verify()`
/// (PRO-4.12.4-03 satisfied). Built from the shared test-issuer primitives (the canonical minters fix
/// either the `vct` or the validity window, never both — and `crate::sdjwtvc` test helpers must not be
/// modified for this task).
fn mint_in_window_qeaa_sd_jwt() -> sd_jwt_payload::SdJwt {
    use sd_jwt_payload::SdJwtBuilder;
    let cert_b64 = Base64::encode_string(ISSUER_CERT_DER);
    let claims = serde_json::json!({
        "iss": "https://issuer.example/cb",
        "vct": "urn:eudi:pid:1",
        "category": EAA_EU_QUALIFIED_TYPE,
        "nbf": RELEVANT_GRANTED - 1_000,
        "exp": RELEVANT_GRANTED + 1_000_000,
        "given_name": "Ada",
    });
    let signer = Es256Signer::from_pkcs8(ISSUER_KEY_PK8);
    block_on(
        SdJwtBuilder::new_with_hasher(claims, Sha2Hasher)
            .expect("builder")
            .header("x5c", serde_json::json!([cert_b64]))
            .header("typ", serde_json::json!("dc+sd-jwt"))
            .make_concealable("/given_name")
            .expect("concealable")
            .require_key_binding(holder_cnf())
            .finish(&signer, "ES256"),
    )
    .expect("issuer signing succeeds")
}

#[test]
fn gate_disabled_leaves_the_always_on_verdict_unchanged_and_qualified_status_none() {
    // The load-bearing SC-007 invariant: with the gate OFF the always-on VerificationResult is
    // byte-identical to a run that supplies NO qualified TL, and qualified_status stays None.
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
    // A credential that self-declares the QEAA URN `vct` (PRO-4.12.4-03), from the granted EAA/Q
    // `sdjwt-issuer`, in-window at RELEVANT_GRANTED → Qualified through verify().
    let sd_jwt = mint_in_window_qeaa_sd_jwt();
    let presentation = sd_jwt.presentation();
    let anchors = chain_validating_anchors(RELEVANT_GRANTED);
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
fn gate_enabled_credential_without_the_qualified_urn_is_indeterminate() {
    // T5.2 end-to-end: the gate is on, the granted EAA/Q `sdjwt-issuer` signs the credential, the TL
    // authenticates — but the credential's `vct` is the DEFAULT (not the QEAA URN), so PRO-4.12.4-03
    // is not satisfied → Indeterminate (never a false Qualified), while the always-on verdict is VALID.
    let Some(tl) = qualified_trust_list_fixture() else {
        return;
    };
    let sd_jwt = mint_in_window_sd_jwt(); // default vct, NOT the QEAA URN
    let presentation = sd_jwt.presentation();
    let anchors = chain_validating_anchors(RELEVANT_GRANTED);
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
    assert!(result.valid, "always-on bar passes: {:?}", result.reasons);
    assert_eq!(
        result.qualified_status,
        Some(QualifiedStatus::Indeterminate),
        "a credential that does not self-declare the QEAA URN is never Qualified (PRO-4.12.4-03)"
    );
}

#[test]
fn gate_enabled_but_no_trust_list_is_indeterminate_never_qualified() {
    // The gate is on but the host supplied no qualified TL → Indeterminate (unreachable data).
    let sd_jwt = mint_in_window_qeaa_sd_jwt();
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
    // not only the per-call context flag. With the policy flag set + a TL + a QEAA-URN credential, a
    // granted EAA/Q issuer resolves to Qualified even though ctx.qualified_gate is false.
    let Some(tl) = qualified_trust_list_fixture() else {
        return;
    };
    let sd_jwt = mint_in_window_qeaa_sd_jwt();
    let presentation = sd_jwt.presentation();
    let anchors = chain_validating_anchors(RELEVANT_GRANTED);
    let policy = VerificationPolicy {
        qualified_gate: true, // enabled via the POLICY surface
        ..VerificationPolicy::default()
    };
    let scheme = scheme_anchors();
    let ctx = VerifyContext {
        now_unix: RELEVANT_GRANTED,
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
// =================================================================================================

/// A fresh `nextUpdate` (far future) and a stale one (long past) for the inline authentication TLs.
const FRESH_NEXT_UPDATE: &str = "2036-06-22T09:11:42Z";
const STALE_NEXT_UPDATE: &str = "2021-01-01T00:00:00Z";
/// An instant inside the CA-signed leaf certs' validity window (2026-06-25..2027-09-23) so a TL
/// signer that is a *leaf* (not the root) chain-validates by SIGNATURE — mirrors chain.rs's NOW.
const NOW_LEAF_VALID: i64 = 1_788_220_800; // 2026-09-01.

// --- now-vs-relevant split probes (the exact false-`Qualified` bug) ------------------------------

/// A `nextUpdate` that is AFTER the credential's issuance/relevant time ([`ISSUANCE_BEFORE_STALE`])
/// but BEFORE the verification instant ([`NOW_STALE`]). (2026-08-01.)
const STALE_AT_NOW_NEXT_UPDATE: &str = "2026-08-01T00:00:00Z";
/// The verification instant for the stale-at-now probe: PAST `STALE_AT_NOW_NEXT_UPDATE` yet still
/// inside the `ca-iaca` signer window. (2030-01-01.)
const NOW_STALE: i64 = 1_893_456_000; // 2030-01-01.
/// The credential's issuance/relevant time for the stale-at-now probe: AFTER the 2026-07-01 grant and
/// BEFORE `STALE_AT_NOW_NEXT_UPDATE`. (2026-07-15.)
const ISSUANCE_BEFORE_STALE: i64 = 1_784_073_600; // 2026-07-15.
/// The verification instant for the expired-signer probe: PAST the leaf TL-signer's notAfter
/// (2027-09-23), so the TL-signer cert is EXPIRED now. (2028-01-01.)
const NOW_SIGNER_EXPIRED: i64 = 1_830_297_600; // 2028-01-01.

#[test]
fn a_forged_unchained_signer_is_indeterminate_not_qualified() {
    // THE PROBE: an attacker-supplied national TL signed by wrong-issuer (does NOT chain to the scheme
    // anchor ca-iaca), listing sdjwt-issuer as a GRANTED EAA/Q service. It must NOT authenticate →
    // Indeterminate, even with the QEAA self-declaration present.
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
            &scheme_anchors(),
            QTYPE
        ),
        QualifiedStatus::Indeterminate,
        "a forged TL whose signer does not chain to the scheme anchor must NEVER be Qualified"
    );
    assert!(matches!(
        forged.authenticate(&scheme_anchors(), NOW_VERIFY),
        Err(QualifiedTrustError::SignerNotTrusted(_))
    ));
}

#[test]
fn an_unsigned_list_listing_a_granted_service_is_indeterminate_not_qualified() {
    let unsigned = QualifiedTrustList::parse(&tl_json(None, FRESH_NEXT_UPDATE, ISSUER_CERT_DER))
        .expect("parses");
    assert!(unsigned.signer_cert_der().is_none());
    assert_eq!(
        qualified_status(
            ISSUER_CERT_DER,
            NOW_VERIFY,
            RELEVANT_GRANTED,
            &unsigned,
            &scheme_anchors(),
            QTYPE
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
    let stale =
        QualifiedTrustList::parse(&tl_json(Some(CA_IACA), STALE_NEXT_UPDATE, ISSUER_CERT_DER))
            .expect("parses");
    assert_eq!(
        qualified_status(
            ISSUER_CERT_DER,
            NOW_VERIFY,
            RELEVANT_GRANTED,
            &stale,
            &scheme_anchors(),
            QTYPE
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
    // THE now-vs-relevant PROBE: a properly-signed list (signer = ca-iaca) listing sdjwt-issuer as a
    // GRANTED EAA/Q service, whose NextUpdate (2026-08-01) is AFTER the credential's issuance/relevant
    // time (2026-07-15) but BEFORE real now (2030). Authentication uses `now` (stale) → Indeterminate.
    let stale_at_now = QualifiedTrustList::parse(&tl_json(
        Some(CA_IACA),
        STALE_AT_NOW_NEXT_UPDATE,
        ISSUER_CERT_DER,
    ))
    .expect("parses");

    assert_eq!(
        stale_at_now.authenticate(&scheme_anchors(), NOW_STALE),
        Err(QualifiedTrustError::Stale),
        "the list is stale at the verification instant"
    );
    assert!(
        stale_at_now
            .authenticate(&scheme_anchors(), ISSUANCE_BEFORE_STALE)
            .is_ok(),
        "the list WOULD authenticate at the (older) issuance time — which is why authentication must use `now`"
    );

    assert_eq!(
        qualified_status(
            ISSUER_CERT_DER,
            NOW_STALE,
            ISSUANCE_BEFORE_STALE,
            &stale_at_now,
            &scheme_anchors(),
            QTYPE,
        ),
        QualifiedStatus::Indeterminate,
        "a TL stale at `now` (even if fresh relative to an older credential) must NEVER be Qualified"
    );
}

#[test]
fn a_tl_signer_expired_at_now_but_valid_at_issuance_is_indeterminate_not_qualified() {
    // The TL-signer chain validity is also a NOW property. The list is signed by sdjwt-issuer (a leaf
    // ISSUED BY ca-iaca, valid 2026-06-25..2027-09-23) and lists mdoc-ds as granted EAA/Q with a FRESH
    // NextUpdate. At now (2028-01-01) the signer cert has EXPIRED → the list cannot authenticate.
    let signer_expired =
        QualifiedTrustList::parse(&tl_json(Some(SDJWT_ISSUER), FRESH_NEXT_UPDATE, MDOC_DS))
            .expect("parses");

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

    assert_eq!(
        qualified_status(
            MDOC_DS,
            NOW_SIGNER_EXPIRED,
            NOW_LEAF_VALID,
            &signer_expired,
            &scheme_anchors(),
            QTYPE,
        ),
        QualifiedStatus::Indeterminate,
        "a TL whose signer cert has expired by `now` must NEVER be Qualified"
    );
}

#[test]
fn no_scheme_anchor_configured_is_indeterminate_not_qualified() {
    // The gate is enabled with a genuine, properly-signed fixture TL, but the host configured NO
    // scheme-operator anchor → the list cannot be authenticated → Indeterminate.
    let Some(tl) = qualified_trust_list_fixture() else {
        return;
    };
    assert_eq!(
        qualified_status(
            ISSUER_CERT_DER,
            NOW_VERIFY,
            RELEVANT_GRANTED,
            &tl,
            &[],
            QTYPE
        ),
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
    // sdjwt-issuer, a leaf ISSUED BY ca-iaca. A granted EAA/Q issuer then reads Qualified.
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
            &scheme_anchors(),
            QTYPE
        ),
        QualifiedStatus::Qualified
    );
}

#[test]
fn the_committed_fixture_signer_authenticates_against_the_scheme_anchor() {
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
    // End-to-end through verify(): the gate is enabled with a forged TL (signer = wrong-issuer) that
    // lists the credential's issuer as granted EAA/Q. The always-on bar still passes, but
    // qualified_status is Indeterminate — never a false Qualified from an unauthenticated list.
    let forged = QualifiedTrustList::parse(&tl_json(
        Some(WRONG_ISSUER),
        FRESH_NEXT_UPDATE,
        ISSUER_CERT_DER,
    ))
    .expect("parses");
    let sd_jwt = mint_in_window_qeaa_sd_jwt();
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
// =================================================================================================

/// A verification instant PAST the leaf's notAfter (2027-09-23) but INSIDE the IACA root's window
/// (..2036): only the LEAF is expired, so the leaf-validity gate fires (not the anchor-validity gate).
const NOW_LEAF_EXPIRED: i64 = 1_893_456_000; // 2030-01-01.
/// A verification instant BEFORE every fixture cert's notBefore (2026-06-25): the leaf is not-yet-valid.
const NOW_BEFORE_NOT_BEFORE: i64 = 1_750_000_000; // 2025-06-15 — the old (incoherent) `NOW`.

#[test]
fn the_verify_gate_with_an_expired_leaf_is_invalid_expired_and_has_no_qualified_status() {
    // The chain-validity gate composes with the qualified gate: an in-window-MINTED credential whose
    // signing LEAF cert has expired by `now` chain-fails as `LeafExpired` → the always-on bar reports
    // `Expired`. The qualified gate is gated on `valid`, so `qualified_status` stays absent.
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
    // At `now` = 2025-06-15 the signing leaf is not-yet-valid (its notBefore is 2026-06-25). The
    // production chain-validating source enforces the X.509 window → INVALID (`Expired`).
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
    // A genuine absence of trust: a credential signed by `wrong-issuer` (does NOT chain to the IACA
    // root) is INVALID — `UntrustedIssuer`. Proves the in-window credential is rejected on trust.
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
