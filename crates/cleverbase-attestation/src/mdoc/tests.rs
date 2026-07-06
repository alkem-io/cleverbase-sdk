//! T008 — fail-first tests for the ISO/IEC 18013-5 mdoc verifier (T012).
//!
//! Each test mints an mdoc with the test issuer helper, mutating exactly one property to drive a
//! single always-on-bar check, and asserts the verdict (VALID + disclosed attributes, or INVALID
//! with the specific [`ReasonCode`] — no false-accept).

use ciborium::value::Value as CborValue;

use super::test_issuer::{
    default_session_transcript, mdoc_ds_cert_der, wrong_issuer_cert_der, DigestAlg, Element,
    MdocBuilder,
};
use super::{verify_with_meta, DeviceBindingMachinery, MdocVerifyParams};
use crate::status::StatusOutcome;
use crate::trust::{StaticTestAnchors, TrustAnchorSource};
use crate::types::{AttributeValue, Format, IssuerRole, ReasonCode, TrustStatus};

/// Run the always-on mdoc bar and take just the [`crate::types::VerificationResult`], discarding the
/// [`super::MdocVerifyMeta`] — the byproducts only the OpenID4VP/qualified callers consume. The
/// production entry point is [`verify_with_meta`]; these verdict-only tests take its `.0` through this
/// one helper rather than transcribing the projection at every call site (DRY).
fn verify<A: TrustAnchorSource + ?Sized>(
    device_response: &[u8],
    anchors: &A,
    params: &MdocVerifyParams<'_>,
) -> crate::types::VerificationResult {
    verify_with_meta(device_response, anchors, params).0
}

/// The verification instant (2024-06-01T00:00:00Z) — inside the default issued window.
const NOW: i64 = 1_717_200_000;

/// The default ISO/IEC 18013-5 namespace the test issuer mints elements under (`MdocBuilder::new`).
const DEFAULT_NS: &str = "org.iso.18013.5.1";

/// Read a disclosed attribute out of the namespace-grouped result map (`{ ns: Map({ id: value }) }`,
/// the mdoc disclosed-attributes shape) under the DEFAULT namespace. `None` when the namespace or id is
/// absent (or the namespace value is not a map).
fn disclosed_attr<'a>(
    result: &'a crate::types::VerificationResult,
    id: &str,
) -> Option<&'a AttributeValue> {
    disclosed_in(result, DEFAULT_NS, id)
}

/// Read a disclosed attribute under an EXPLICIT namespace from the namespace-grouped result map.
fn disclosed_in<'a>(
    result: &'a crate::types::VerificationResult,
    namespace: &str,
    id: &str,
) -> Option<&'a AttributeValue> {
    match result.disclosed_attributes.get(namespace) {
        Some(AttributeValue::Map(ns_map)) => ns_map.get(id),
        _ => None,
    }
}

/// Anchors trusting the test DS cert as a PID/mdoc issuer (the role the params use).
fn trusted_anchors() -> StaticTestAnchors {
    StaticTestAnchors::new().trust(IssuerRole::Pid, Format::Mdoc, mdoc_ds_cert_der())
}

/// Anchors that trust the wrong-issuer cert (so an untrusted-DS reject is *not* a "cert absent"
/// artifact — the wrong-issuer is genuinely off the configured anchor for this role/format).
fn anchors_without_ds() -> StaticTestAnchors {
    StaticTestAnchors::new()
}

/// The canonical default `SessionTranscript` with a `'static` lifetime, so [`params`] (which the bulk
/// of the suite shares) can hand the verifier the SAME transcript the test issuer signs the default
/// `DeviceSignature` over. The verifier no longer fabricates a transcript (§9.1.5), so a
/// default-transcript mdoc verifies ONLY when these exact bytes are supplied.
fn static_default_transcript() -> &'static [u8] {
    use std::sync::OnceLock;
    static TRANSCRIPT: OnceLock<Vec<u8>> = OnceLock::new();
    TRANSCRIPT.get_or_init(default_session_transcript)
}

/// The shared params for the bulk of the suite: the canonical default `SessionTranscript` (so the
/// default-transcript `DeviceSignature` the builder mints is genuinely confirmed — never a fabricated
/// no-op binding), PID role, no status, at [`NOW`].
fn params() -> MdocVerifyParams<'static> {
    MdocVerifyParams {
        now_unix: NOW,
        session_transcript: Some(static_default_transcript()),
        role: IssuerRole::Pid,
        statuses: &[StatusOutcome::NoStatus],
    }
}

/// Like [`params`] but carries one `NoStatus` entry per document of a TWO-document response (neither
/// document declares a status mechanism). The single-document [`params`] would leave the second
/// document without a positional status ⇒ fail closed (`Unavailable`), so multi-document tests use this.
fn params_two_docs() -> MdocVerifyParams<'static> {
    MdocVerifyParams {
        statuses: &[StatusOutcome::NoStatus, StatusOutcome::NoStatus],
        ..params()
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

    // The three disclosed elements are returned, decoded to AttributeValue, GROUPED under their
    // namespace (the namespace-grouped mdoc shape — `{ ns: Map({ id: value }) }`).
    assert_eq!(
        disclosed_attr(&result, "family_name"),
        Some(&AttributeValue::Text("Doe".to_owned()))
    );
    assert_eq!(
        disclosed_attr(&result, "given_name"),
        Some(&AttributeValue::Text("Ada".to_owned()))
    );
    assert_eq!(
        disclosed_attr(&result, "age_over_18"),
        Some(&AttributeValue::Boolean(true))
    );
    // The top-level result key is the NAMESPACE; the elements live in its sub-map.
    assert!(
        result.disclosed_attributes.contains_key(DEFAULT_NS),
        "disclosed attributes are grouped under the ISO namespace, not flat by id"
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
fn device_signature_with_attached_payload_is_rejected_not_a_panic() {
    // DoS guard: the mdoc is OTHERWISE issuer-valid (trusted DS, valid MSO, matching digests, valid
    // DeviceKey) but its `deviceSignature` COSE_Sign1 carries a NON-NIL (attached) payload instead of
    // the detached/nil payload ISO/IEC 18013-5 §9.1.3 mandates. `coset`'s `tbs_detached_data` asserts
    // `payload.is_none()` (an `assert!` that fires in release too), so verifying such a crafted
    // DeviceSignature on the detached path would PANIC/ABORT — an attacker-triggerable remote DoS.
    // The verifier MUST detect the attached payload up front and reject it cleanly as `HolderBinding`,
    // never reaching the coset assert (a verifier must never panic/abort on attacker-controlled input).
    let response = MdocBuilder::new()
        .device_signature_attached_payload()
        .build();
    let result = verify(&response, &trusted_anchors(), &params());

    assert!(
        !result.valid,
        "an attached-payload (non-detached) DeviceSignature must not verify"
    );
    assert_eq!(
        result.reasons,
        vec![ReasonCode::HolderBinding],
        "a non-detached DeviceSignature is a malformed holder binding (ISO/IEC 18013-5 §9.1.3)"
    );
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
    assert!(disclosed_attr(&result, "given_name").is_some());
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
        statuses: &[StatusOutcome::NoStatus],
    };
    let result = verify(&response, &trusted_anchors(), &p);
    assert!(result.valid, "matching session transcript must verify");
}

#[test]
fn device_signature_without_a_session_transcript_is_missing_request_binding() {
    // FAIL-CLOSED (ISO/IEC 18013-5 §9.1.5): a `DeviceSignature` is always computed over a real
    // `SessionTranscript`. When a document asserts holder binding (carries a `DeviceSignature`) and NO
    // transcript is supplied, the verifier CANNOT confirm the binding — it MUST NOT fabricate a
    // `[null, null, null]` transcript and silently "pass" (a zero-freshness no-op false-accept). It
    // rejects with `MissingRequestBinding`: an explicit transcript (or the OpenID4VP handover) is
    // required. The mdoc here is otherwise fully valid (trusted DS, valid MSO, matching digests, valid
    // DeviceKey, genuine holder `DeviceSignature`) — the SOLE reason for the reject is the absent
    // transcript.
    let response = MdocBuilder::new().build();
    let p = MdocVerifyParams {
        now_unix: NOW,
        session_transcript: None,
        role: IssuerRole::Pid,
        statuses: &[StatusOutcome::NoStatus],
    };
    let result = verify(&response, &trusted_anchors(), &p);
    assert!(
        !result.valid,
        "a DeviceSignature with no SessionTranscript must NOT silently pass holder binding"
    );
    assert_eq!(
        result.reasons,
        vec![ReasonCode::MissingRequestBinding],
        "an absent SessionTranscript for a DeviceSignature is a missing request/transport binding"
    );
    assert!(result.disclosed_attributes.is_empty());

    // Control: the SAME credential verifies once the default transcript it was signed over is supplied
    // — proving the only thing the reject above turned on is the missing transcript, not any other bar
    // check.
    assert!(
        verify(&response, &trusted_anchors(), &params()).valid,
        "supplying the explicit transcript the DeviceSignature was signed over verifies"
    );
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
        statuses: &[StatusOutcome::NoStatus],
    };
    let result = verify(&response, &trusted_anchors(), &p);
    assert!(!result.valid);
    assert_eq!(result.reasons, vec![ReasonCode::HolderBinding]);
}

#[test]
fn device_signature_with_non_es256_alg_fails_holder_binding() {
    // The device-auth algorithm gate is ES256; a DeviceSignature with an ES384 header is rejected.
    // This reason (`HolderBinding`) is SHARED with the signature-math failure
    // (`bad_device_signature_is_rejected_as_holder_binding`), so prove the ALGORITHM gate is the
    // discriminator: the ONLY difference from the VALID baseline below is the alg header — flipping it
    // back to ES256 (everything else identical) verifies, so the rejection is the alg gate, not bad
    // signature math. The `cose_alg_gate_accepts_only_es256` unit probe isolates the gate itself.
    let response = MdocBuilder::new().device_sig_wrong_alg().build();
    let result = verify(&response, &trusted_anchors(), &params());
    assert!(!result.valid);
    assert_eq!(result.reasons, vec![ReasonCode::HolderBinding]);

    // Baseline: the same builder WITHOUT the wrong-alg flip (an ES256 DeviceSignature) verifies — so
    // the algorithm header is the sole cause of the rejection above.
    let baseline = MdocBuilder::new().build();
    assert!(
        verify(&baseline, &trusted_anchors(), &params()).valid,
        "the only change driving HolderBinding above is the non-ES256 device-sig alg header"
    );
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

    assert_eq!(
        disclosed_attr(&result, "age"),
        Some(&AttributeValue::Integer(42))
    );
    assert_eq!(
        disclosed_attr(&result, "portrait"),
        Some(&AttributeValue::Bytes(vec![0xDE, 0xAD]))
    );
    assert_eq!(
        disclosed_attr(&result, "tags"),
        Some(&AttributeValue::Array(vec![
            AttributeValue::Text("a".to_owned()),
            AttributeValue::Null,
        ]))
    );
    let mut want = std::collections::BTreeMap::new();
    want.insert("city".to_owned(), AttributeValue::Text("London".to_owned()));
    assert_eq!(
        disclosed_attr(&result, "address"),
        Some(&AttributeValue::Map(want))
    );
    assert_eq!(
        disclosed_attr(&result, "absent"),
        Some(&AttributeValue::Null)
    );
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
    assert_eq!(p.statuses, [StatusOutcome::NoStatus]);
}

#[test]
fn revoked_status_is_rejected_as_revoked() {
    // A well-formed mdoc whose status seam reports Revoked must be rejected (always-on bar T014).
    let response = MdocBuilder::new().build();
    let p = MdocVerifyParams {
        now_unix: NOW,
        session_transcript: None,
        role: IssuerRole::Pid,
        statuses: &[StatusOutcome::Revoked],
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
        statuses: &[StatusOutcome::Unavailable],
    };
    let result = verify(&response, &trusted_anchors(), &p);
    assert!(!result.valid);
    assert_eq!(result.reasons, vec![ReasonCode::StatusUnavailable]);
}

#[test]
fn good_status_still_verifies() {
    // A reachable status that reports the credential current does not disturb a VALID verdict.
    let response = MdocBuilder::new().build();
    let transcript = default_session_transcript();
    let p = MdocVerifyParams {
        now_unix: NOW,
        session_transcript: Some(&transcript),
        role: IssuerRole::Pid,
        statuses: &[StatusOutcome::Good],
    };
    let result = verify(&response, &trusted_anchors(), &p);
    assert!(
        result.valid,
        "a Good status must not disturb a VALID verdict"
    );
}

#[test]
fn multi_document_second_document_revoked_is_rejected_not_false_accepted() {
    // FALSE-ACCEPT REGRESSION (conformance-audit, SC-002): a multi-document response where documents[0]
    // is current but documents[1] is REVOKED MUST be rejected. Revocation is now checked PER DOCUMENT
    // (statuses[i] is documents[i]'s outcome). The pre-fix bug applied a SINGLE outcome to every
    // document, so a host with one status slot could only pass `Good`/`NoStatus` for the whole response
    // → the revoked second document rode inside a VALID verdict. Here statuses = [NoStatus, Revoked].
    let response = MdocBuilder::new()
        .append_colliding_document("nationality", CborValue::Text("NL".to_owned()))
        .build();
    let p = MdocVerifyParams {
        statuses: &[StatusOutcome::NoStatus, StatusOutcome::Revoked],
        ..params()
    };
    let result = verify(&response, &trusted_anchors(), &p);
    assert!(
        !result.valid,
        "a revoked second document must never be accepted inside a multi-document response"
    );
    assert_eq!(result.reasons, vec![ReasonCode::Revoked]);
}

#[test]
fn multi_document_short_status_slice_fails_the_uncovered_document_closed() {
    // A multi-document response with a SINGLE status entry must NOT reuse it for documents[1]: the
    // uncovered document fails closed to StatusUnavailable (never a silent VALID via one-outcome-for-all).
    let response = MdocBuilder::new()
        .append_colliding_document("nationality", CborValue::Text("NL".to_owned()))
        .build();
    let p = MdocVerifyParams {
        statuses: &[StatusOutcome::Good], // covers documents[0] only; documents[1] is uncovered
        ..params()
    };
    let result = verify(&response, &trusted_anchors(), &p);
    assert!(
        !result.valid,
        "the uncovered second document must fail closed, not reuse documents[0]'s status"
    );
    assert_eq!(result.reasons, vec![ReasonCode::StatusUnavailable]);
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
    // This reason (`Tamper`) is SHARED with the signature-math failure
    // (`tampered_issuer_auth_signature_is_rejected_as_tamper`), so prove the ALGORITHM gate is the
    // discriminator: the ONLY difference from the VALID baseline below is the alg header. The
    // `cose_alg_gate_accepts_only_es256` unit probe isolates the gate predicate itself.
    let response = MdocBuilder::new().issuer_auth_wrong_alg().build();
    let result = verify(&response, &trusted_anchors(), &params());
    assert!(!result.valid);
    assert_eq!(result.reasons, vec![ReasonCode::Tamper]);

    // Baseline: the same builder WITHOUT the wrong-alg flip (an ES256 IssuerAuth) verifies — so the
    // algorithm header is the sole cause of the rejection above (not bad signature math).
    let baseline = MdocBuilder::new().build();
    assert!(
        verify(&baseline, &trusted_anchors(), &params()).valid,
        "the only change driving Tamper above is the non-ES256 IssuerAuth alg header"
    );
}

#[test]
fn cose_der_encoded_issuer_auth_signature_is_rejected_raw_accepted() {
    // RFC 9053 §2.1 (ECDSA, the COSE algorithm) mandates the signature be the fixed-width raw `r‖s`
    // concatenation (`I2OSP(R, n) | I2OSP(S, n)`), NEVER an ASN.1/DER `SEQUENCE`. A DER-encoded
    // COSE_Sign1 signature is a valid ECDSA signature but a non-conformant ENCODING — a reference COSE
    // validator rejects what a DER-tolerant verifier would accept. The SDK's COSE path must therefore
    // reject the DER form (`Tamper`): the shared `crate::crypto::p256_verify_es256` kernel accepts only
    // the raw `r‖s` form (`Signature::from_slice`), never `from_der`.
    let der = MdocBuilder::new().issuer_auth_der_signature().build();
    let result = verify(&der, &trusted_anchors(), &params());
    assert!(
        !result.valid,
        "a DER-encoded COSE_Sign1 ES256 signature must NOT verify (RFC 9053 §2.1 mandates raw r‖s)"
    );
    assert_eq!(
        result.reasons,
        vec![ReasonCode::Tamper],
        "a non-conformant DER signature encoding is a Tamper-class reject"
    );

    // Positive control: the SAME credential WITHOUT the DER re-encode (the default builder mints raw
    // `r‖s`) verifies — so the rejection above is the encoding, not any other bar check.
    let raw = MdocBuilder::new().build();
    assert!(
        verify(&raw, &trusted_anchors(), &params()).valid,
        "the raw fixed-width r‖s COSE signature is the accepted form"
    );
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
fn forged_item_reusing_a_genuine_digest_id_is_rejected_no_disclosure() {
    // CRITICAL FALSE-ACCEPT PROBE (SC-002, selective-disclosure integrity). A genuine issuer-signed
    // mdoc is given an APPENDED forged `IssuerSignedItem` that REUSES a real element's `digestID` (0,
    // the genuine `family_name`) but carries an attacker-chosen `elementIdentifier`/`elementValue`
    // ("forged_claim" → "EVIL") the issuer NEVER signed. The MSO `valueDigests[0]` still holds only
    // the genuine item's digest. A verifier that hashes a digestID-keyed wire slice but discloses a
    // DECOUPLED decoded item would hash the genuine bytes (digest matches) yet disclose the forged
    // claim — a false-accept. The fix ties the hashed bytes to the disclosed value (one record per
    // on-wire item) and rejects a `digestID` appearing on two on-wire items, so BOTH orderings (forged
    // first and forged last) are rejected as `DisclosureIntegrity` and "EVIL" is never disclosed.
    for forged_first in [true, false] {
        let response = MdocBuilder::new()
            .append_forged_item(
                0,
                "forged_claim",
                CborValue::Text("EVIL".to_owned()),
                forged_first,
            )
            .build();
        let result = verify(&response, &trusted_anchors(), &params());
        assert!(
            !result.valid,
            "a forged item reusing a genuine digestID must NOT be VALID (forged_first={forged_first})"
        );
        assert_eq!(
            result.reasons,
            vec![ReasonCode::DisclosureIntegrity],
            "the reused-digestID forgery is a disclosure-integrity failure (forged_first={forged_first})"
        );
        assert!(
            result.disclosed_attributes.is_empty(),
            "an INVALID verdict discloses nothing — the forged claim never surfaces"
        );
        assert!(
            disclosed_attr(&result, "forged_claim").is_none(),
            "the attacker-chosen claim the issuer never signed must NEVER be disclosed"
        );
        assert_ne!(
            disclosed_attr(&result, "family_name"),
            Some(&AttributeValue::Text("EVIL".to_owned())),
            "the forged value must never be served under any identifier"
        );
    }
}

#[test]
fn duplicate_digest_id_within_a_namespace_is_rejected() {
    // Two on-wire `IssuerSignedItem`s sharing the SAME `digestID` within one namespace is structurally
    // ambiguous (which item does `valueDigests[id]` attest?) and is the lever the false-accept above
    // rides on, so a duplicate `digestID` is rejected outright as `DisclosureIntegrity`.
    let response = MdocBuilder::new()
        .elements(vec![
            Element {
                digest_id: 0,
                identifier: "family_name",
                value: CborValue::Text("Doe".to_owned()),
            },
            Element {
                digest_id: 0, // DUPLICATE digestID on a second, distinct on-wire item
                identifier: "given_name",
                value: CborValue::Text("Ada".to_owned()),
            },
        ])
        .build();
    let result = verify(&response, &trusted_anchors(), &params());
    assert!(
        !result.valid,
        "two on-wire items with the same digestID must NOT be VALID"
    );
    assert_eq!(result.reasons, vec![ReasonCode::DisclosureIntegrity]);
    assert!(result.disclosed_attributes.is_empty());
}

#[test]
fn cross_document_attribute_collision_is_rejected_no_silent_shadow() {
    // SHADOWING PROBE: `documents[0]` discloses given_name="Ada"; a SECOND fully-VALID document
    // (signed by the SAME trusted DS) discloses given_name="EVIL". With a flat last-writer-wins merge
    // a consumer reading `given_name` would silently be served "EVIL". The verifier MUST make silent
    // shadowing impossible: a conflicting same-identifier value across documents is rejected as a
    // structurally untrustworthy disclosure set (never a quiet overwrite, never "EVIL").
    let response = MdocBuilder::new()
        .append_colliding_document("given_name", CborValue::Text("EVIL".to_owned()))
        .build();
    let result = verify(&response, &trusted_anchors(), &params_two_docs());
    assert!(
        !result.valid,
        "a cross-document claim collision must NOT be silently merged"
    );
    assert_eq!(result.reasons, vec![ReasonCode::DisclosureIntegrity]);
    assert!(
        result.disclosed_attributes.is_empty(),
        "an INVALID verdict discloses nothing — the shadowing value never surfaces"
    );
    // Prove the shadow specifically did NOT win (defence in depth against a future regression that
    // returns attributes on this path). Both documents disclose under the SAME default namespace, so
    // this is a genuine same-(namespace, id) conflict.
    assert_ne!(
        disclosed_attr(&result, "given_name"),
        Some(&AttributeValue::Text("EVIL".to_owned())),
        "the second document's value must never shadow the first"
    );
}

#[test]
fn cross_document_distinct_identifiers_merge_cleanly() {
    // Positive control: a second VALID document disclosing a DIFFERENT identifier (no collision) is
    // merged into the single result map — every document's identifiers are surfaced.
    let response = MdocBuilder::new()
        .append_colliding_document("nationality", CborValue::Text("NL".to_owned()))
        .build();
    let result = verify(&response, &trusted_anchors(), &params_two_docs());
    assert!(
        result.valid,
        "non-colliding documents must merge: {:?}",
        result.reasons
    );
    assert_eq!(
        disclosed_attr(&result, "given_name"),
        Some(&AttributeValue::Text("Ada".to_owned())),
        "the first document's claim is preserved"
    );
    assert_eq!(
        disclosed_attr(&result, "nationality"),
        Some(&AttributeValue::Text("NL".to_owned())),
        "the second document's distinct claim is surfaced too"
    );
}

#[test]
fn cross_document_identical_redisclosure_is_accepted() {
    // A second VALID document re-disclosing the SAME identifier with the SAME value is harmless (no
    // shadowing of a different value), so it merges cleanly rather than being rejected.
    let response = MdocBuilder::new()
        .append_colliding_document("given_name", CborValue::Text("Ada".to_owned()))
        .build();
    let result = verify(&response, &trusted_anchors(), &params_two_docs());
    assert!(
        result.valid,
        "an identical re-disclosure must not be treated as a conflict: {:?}",
        result.reasons
    );
    assert_eq!(
        disclosed_attr(&result, "given_name"),
        Some(&AttributeValue::Text("Ada".to_owned()))
    );
}

#[test]
fn multi_namespace_same_id_different_values_is_valid_and_namespace_distinguished() {
    // MULTI-NAMESPACE PROBE (fix #1): `documents[0]` discloses given_name="Ada" under the default ISO
    // namespace; a SECOND fully-VALID document (same trusted DS) discloses given_name="Grace" under a
    // DIFFERENT namespace. ISO/IEC 18013-5 `elementIdentifier`s are unique only WITHIN a namespace, so
    // the same id in two namespaces is a DISTINCT attribute — a flat bare-id merge would FALSE-REJECT
    // this legitimate presentation as `DisclosureIntegrity`. With namespace-grouped disclosure the
    // response is VALID and BOTH values are surfaced, each under its own namespace (never collided,
    // provenance preserved).
    const OTHER_NS: &str = "org.example.secondary";
    let response = MdocBuilder::new()
        .append_document_in_namespace(OTHER_NS, "given_name", CborValue::Text("Grace".to_owned()))
        .build();
    let result = verify(&response, &trusted_anchors(), &params_two_docs());
    assert!(
        result.valid,
        "the same id in two DIFFERENT namespaces is not a collision — must be VALID: {:?}",
        result.reasons
    );
    // Both `given_name`s are present, namespace-distinguished.
    assert_eq!(
        disclosed_in(&result, DEFAULT_NS, "given_name"),
        Some(&AttributeValue::Text("Ada".to_owned())),
        "the default-namespace given_name is preserved"
    );
    assert_eq!(
        disclosed_in(&result, OTHER_NS, "given_name"),
        Some(&AttributeValue::Text("Grace".to_owned())),
        "the second namespace's same-id given_name is a DISTINCT attribute, surfaced too"
    );
    // The two namespaces are distinct top-level keys (provenance preserved, never merged into one id).
    assert!(result.disclosed_attributes.contains_key(DEFAULT_NS));
    assert!(result.disclosed_attributes.contains_key(OTHER_NS));
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
fn empty_documents_array_is_rejected_as_malformed() {
    // A DeviceResponse with an empty `documents` array carries no credential to verify; a VALID
    // verdict over zero documents is meaningless and must be rejected.
    let response = MdocBuilder::new().empty_documents().build();
    let result = verify(&response, &trusted_anchors(), &params());
    assert!(!result.valid);
    assert_eq!(result.reasons, vec![ReasonCode::MalformedCredential]);
}

#[test]
fn document_errors_present_does_not_reject_valid_returned_documents() {
    // ISO/IEC 18013-5 §8.3 (conformance-audit T7.5): `documentErrors` is INFORMATIONAL — it names
    // docType(s) the device could NOT return, NOT a fault of the document(s) it DID return. A
    // partially-fulfilled multi-doc request whose returned document is present and valid must NOT be
    // rejected merely because some OTHER docType errored (the previous behavior was an over-strict
    // false-reject). The verdict stands on the documents that ARE present, and their attributes are
    // disclosed. (The builder's `documentErrors` names a DIFFERENT docType than the returned mDL.)
    let response = MdocBuilder::new().add_document_errors().build();
    let result = verify(&response, &trusted_anchors(), &params());
    assert!(
        result.valid,
        "a documentErrors entry for an UNRETURNED docType must not fail the valid returned mDL: {:?}",
        result.reasons
    );
    assert!(result.reasons.is_empty());
    assert_eq!(
        disclosed_attr(&result, "given_name"),
        Some(&AttributeValue::Text("Ada".to_owned())),
        "the present, valid document's attributes are still disclosed"
    );
}

#[test]
fn a_response_with_no_documents_array_is_rejected_as_malformed() {
    // A clean-status `DeviceResponse` carrying NO `documents` array at all has nothing to verify and
    // is structurally malformed — the bar rejects it (and the surfaced meta is empty: the failure is
    // not a `HolderBinding`, so no binding-machinery is computed).
    let response = encode_cbor(&CborValue::Map(vec![(
        CborValue::Text("status".to_owned()),
        CborValue::Integer(0.into()),
    )]));
    let result = verify(&response, &trusted_anchors(), &params());
    assert!(!result.valid);
    assert_eq!(result.reasons, vec![ReasonCode::MalformedCredential]);
}

#[test]
fn device_binding_machinery_classifies_sound_vs_faulty() {
    use super::device_binding_machinery;

    // A well-formed (sound) binding — ES256 DeviceSignature, parseable DeviceKey, well-formed
    // signature bytes — is `Sound` (a binding FAILURE on such a response is the fresh-nonce mismatch).
    // The default builder mints exactly this, and even a wrong-KEY signature stays well-formed → Sound
    // (a wrong-key signature is cryptographically indistinguishable from a stale-nonce one; only the
    // signature MACHINERY is classified here, not the signature's correctness).
    assert_eq!(
        device_binding_machinery(&MdocBuilder::new().build()),
        DeviceBindingMachinery::Sound
    );
    assert_eq!(
        device_binding_machinery(&MdocBuilder::new().corrupt_device_signature().build()),
        DeviceBindingMachinery::Sound,
        "a wrong-key but well-formed signature is structurally sound (machinery intact)"
    );

    // A structurally-broken signature (garbled/truncated bytes) is `Faulty` — a transcript-independent
    // holder-binding fault that must never be downgraded to a replay.
    assert_eq!(
        device_binding_machinery(&MdocBuilder::new().mangle_device_signature().build()),
        DeviceBindingMachinery::Faulty
    );
    // A non-ES256 DeviceSignature alg is also `Faulty` (the binding machinery is wrong).
    assert_eq!(
        device_binding_machinery(&MdocBuilder::new().device_sig_wrong_alg().build()),
        DeviceBindingMachinery::Faulty
    );
    // Garbage / non-DeviceResponse bytes are conservatively `Faulty` (never a silent replay).
    assert_eq!(
        device_binding_machinery(&[0xff, 0x00]),
        DeviceBindingMachinery::Faulty
    );
}

#[test]
fn verify_with_meta_surfaces_claimed_issuers_on_valid_and_binding_machinery_on_holder_failure() {
    // VALID → the same verdict as `verify`, PLUS the cached per-document `(ds_cert_der, issuance_time)`
    // the qualified gate folds: one document, the DS leaf, and the MSO `signed` (2023-01-01T00:00:00Z =
    // 1_672_531_200). No `HolderBinding` failure ⇒ `binding_machinery` is `None`.
    let response = MdocBuilder::new().build();
    let (result, meta) = verify_with_meta(&response, &trusted_anchors(), &params());
    assert!(result.valid, "the meta path returns the same VALID verdict");
    assert_eq!(meta.document_count, 1);
    assert_eq!(meta.claimed_issuers.len(), 1);
    assert_eq!(meta.claimed_issuers[0].0, mdoc_ds_cert_der());
    assert_eq!(meta.claimed_issuers[0].1, 1_672_531_200, "the MSO `signed`");
    assert!(
        meta.binding_machinery.is_none(),
        "binding-machinery is computed only on a HolderBinding failure"
    );

    // A `HolderBinding` failure (here: a sound default binding verified against a DIFFERENT, present
    // transcript — the fresh-nonce/replay shape) surfaces `binding_machinery: Some(Sound)` so the
    // OpenID4VP classifier can read it without re-decoding; no document is verified ⇒ no claimed issuer.
    let wrong_transcript = encode_cbor(&CborValue::Array(vec![
        CborValue::Null,
        CborValue::Null,
        CborValue::Text("a-different-handover".to_owned()),
    ]));
    let mismatched = MdocVerifyParams {
        session_transcript: Some(&wrong_transcript),
        ..params()
    };
    let (result, meta) = verify_with_meta(&response, &trusted_anchors(), &mismatched);
    assert!(!result.valid);
    assert_eq!(result.reasons, vec![ReasonCode::HolderBinding]);
    assert_eq!(meta.document_count, 1);
    assert!(meta.claimed_issuers.is_empty());
    assert_eq!(meta.binding_machinery, Some(DeviceBindingMachinery::Sound));

    // A structurally-broken (mangled) DeviceSignature also fails `HolderBinding`, but the binding
    // machinery is `Faulty` (a transcript-INDEPENDENT fault the classifier must never call a replay).
    let mangled = MdocBuilder::new().mangle_device_signature().build();
    let (result, meta) = verify_with_meta(&mangled, &trusted_anchors(), &params());
    assert!(!result.valid);
    assert_eq!(result.reasons, vec![ReasonCode::HolderBinding]);
    assert_eq!(meta.binding_machinery, Some(DeviceBindingMachinery::Faulty));
}

#[test]
fn cose_sign1_with_unknown_critical_header_is_rejected_both_paths() {
    // RFC 9052 §3.1 (conformance-audit T2.1): the COSE `crit` parameter "indicate[s] which protected
    // header parameters an application that is processing a message is required to understand"; a
    // recipient that does not process a header listed there cannot process the message ("this is a
    // fatal error in processing the message"). This verifier processes ONLY the standard `alg`, so a
    // COSE_Sign1 marking ANY other header critical MUST be rejected — proven on BOTH COSE_Sign1 paths,
    // which inherit the check from the single `parse_cose_sign1` chokepoint.

    // (1) IssuerAuth carries `crit:[content type]` (a header the verifier does not process).
    let issuer_crit = MdocBuilder::new().issuer_auth_unknown_crit().build();
    let result = verify(&issuer_crit, &trusted_anchors(), &params());
    assert!(
        !result.valid,
        "an IssuerAuth marking an unprocessed header critical must not verify"
    );
    assert_eq!(result.reasons, vec![ReasonCode::MalformedCredential]);

    // (2) DeviceSignature carries `crit:[content type]` (the holder-binding COSE_Sign1 path).
    let device_crit = MdocBuilder::new().device_sig_unknown_crit().build();
    let result = verify(&device_crit, &trusted_anchors(), &params());
    assert!(
        !result.valid,
        "a DeviceSignature marking an unprocessed header critical must not verify"
    );
    assert_eq!(result.reasons, vec![ReasonCode::MalformedCredential]);

    // Baseline: the SAME builder WITHOUT any crit injection (no critical header) verifies — so the
    // unprocessed critical header is the sole cause of each rejection above.
    assert!(
        verify(&MdocBuilder::new().build(), &trusted_anchors(), &params()).valid,
        "the only change driving the rejects above is the unprocessed critical header"
    );
}

#[test]
fn indefinite_length_device_response_is_rejected_as_malformed_no_panic() {
    // ISO/IEC 18013-5 §9.1.1 mandates deterministic (definite-length) CBOR; RFC 8949 §4.2.1:
    // "Indefinite-length items MUST NOT appear." (conformance-audit T7.2). `ciborium` itself ACCEPTS
    // indefinite-length encoding, so the verifier MUST reject it with its own definite-length pre-scan.
    // Hand-build an indefinite-length top-level map (0xBF … 0xFF) carrying a DeviceResponse-shaped body
    // and prove (a) ciborium decodes it (it IS valid CBOR ciborium accepts) yet (b) the verifier
    // rejects it as MalformedCredential WITHOUT panicking.
    let mut wire = vec![0xBF_u8]; // map(*) — indefinite-length head
    for (key, value) in [
        ("version", CborValue::Text("1.0".to_owned())),
        ("status", CborValue::Integer(0.into())),
    ] {
        wire.extend(encode_cbor(&CborValue::Text(key.to_owned())));
        wire.extend(encode_cbor(&value));
    }
    wire.push(0xFF); // break — closes the indefinite-length map

    // Precondition: this IS well-formed CBOR that ciborium accepts (so the rejection below is OUR
    // deterministic-encoding pre-scan, not a ciborium parse failure of malformed bytes).
    assert!(
        ciborium::from_reader::<CborValue, _>(wire.as_slice()).is_ok(),
        "the indefinite-length encoding is valid CBOR ciborium accepts"
    );

    let result = verify(&wire, &trusted_anchors(), &params());
    assert!(
        !result.valid,
        "an indefinite-length DeviceResponse must not verify"
    );
    assert_eq!(
        result.reasons,
        vec![ReasonCode::MalformedCredential],
        "indefinite-length encoding is rejected fail-closed, never a panic"
    );
}

#[test]
fn device_response_version_must_be_present_and_1_0() {
    // ISO/IEC 18013-5 §8.3.2.1.2.2 fixes `DeviceResponse.version` to the text string "1.0". A different
    // version is an unrecognized schema, and an absent version is structurally malformed — both reject
    // (never up-converted/guessed).
    let wrong = MdocBuilder::new().device_response_version("2.0").build();
    let result = verify(&wrong, &trusted_anchors(), &params());
    assert!(
        !result.valid,
        "a DeviceResponse version != 1.0 must not verify"
    );
    assert_eq!(result.reasons, vec![ReasonCode::MalformedCredential]);

    let absent = MdocBuilder::new().omit_device_response_version().build();
    let result = verify(&absent, &trusted_anchors(), &params());
    assert!(
        !result.valid,
        "an absent DeviceResponse version must not verify"
    );
    assert_eq!(result.reasons, vec![ReasonCode::MalformedCredential]);

    // Baseline: the same builder with the spec "1.0" verifies — so the version is the sole cause above.
    assert!(verify(&MdocBuilder::new().build(), &trusted_anchors(), &params()).valid);
}

#[test]
fn mso_version_must_be_present_and_1_0() {
    // ISO/IEC 18013-5 §9.1.2.4 fixes the MobileSecurityObject `version` to the text string "1.0". A
    // different/absent MSO version is an unrecognized MSO schema and is rejected as malformed.
    let wrong = MdocBuilder::new().mso_version("2.0").build();
    let result = verify(&wrong, &trusted_anchors(), &params());
    assert!(!result.valid, "an MSO version != 1.0 must not verify");
    assert_eq!(result.reasons, vec![ReasonCode::MalformedCredential]);

    let absent = MdocBuilder::new().omit_mso_version().build();
    let result = verify(&absent, &trusted_anchors(), &params());
    assert!(!result.valid, "an absent MSO version must not verify");
    assert_eq!(result.reasons, vec![ReasonCode::MalformedCredential]);

    // Baseline: the spec "1.0" MSO verifies — so the MSO version is the sole cause above.
    assert!(verify(&MdocBuilder::new().build(), &trusted_anchors(), &params()).valid);
}

/// Encode a `ciborium` value to CBOR bytes (test helper).
fn encode_cbor(value: &CborValue) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).unwrap();
    buf
}
