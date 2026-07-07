//! Tests for the attestation wire envelope (T016 — the real verifier wiring, schema v2).
//!
//! A well-formed request runs the always-on [`crate::verify`] bar and carries the verdict back; a
//! malformed request or a wrong schema version is rejected with a clear message.

use super::{
    decode_verify_request, decode_vp_token_request, encode_verify_response, process_verify_bytes,
    process_vp_token_bytes, VerifyOutcome, VerifyRequest, VerifyResponse, WireContext,
    WirePresentation, WireSchemeAnchor, WireTrustAnchor, WireVpTokenOutcome, WireVpTokenRequest,
    WireVpTokenResponse, ATTESTATION_SCHEMA_VERSION,
};
use crate::mdoc::test_issuer::{default_session_transcript, MdocBuilder};
use crate::openid4vp::{oid4vp_handover_transcript, Dcql, PresentationRequest};
use crate::qualified::EAA_EU_QUALIFIED_TYPE;
use crate::sdjwtvc::test_issuer::{
    attach_kb_jwt_with_iat, block_on, holder_cnf, mint_sd_jwt_with_status_and_validity,
    mint_sd_jwt_with_validity, mint_status_list_jwt, Es256Signer, Sha2Hasher, DEFAULT_VCT,
    HOLDER_KEY_PK8, ISSUER_CERT_DER, ISSUER_KEY_PK8,
};
use crate::status::StatusOutcome;
use crate::types::{Format, IssuerRole, VerificationPolicy};

/// The issuing IACA root (`ca-iaca`) the test issuer/DS leaves chain to. The C-ABI trust path is
/// chain-validating (chain-to-root), so the well-formed requests pin this CA, not the leaf.
const CA_IACA: &[u8] = include_bytes!("../../../../tests/fixtures/attestation/ca-iaca.cert.der");
/// A verification instant INSIDE the leaf + IACA-root validity windows (2026-06-25 .. 2027-09-23):
/// 2026-09-01. The chain-validating C-ABI trust path enforces the leaf's validity window at the
/// verification instant, so the well-formed requests must run in-window (the 2025 `NOW` is before the
/// leaf's notBefore and would now correctly fail chain validation).
const IN_WINDOW_NOW: i64 = 1_788_220_800; // 2026-09-01.

fn encode(req: &VerifyRequest) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::into_writer(req, &mut buf).unwrap();
    buf
}

/// A well-formed SD-JWT VC verify request whose issuer is trusted (a VALID verdict end-to-end).
///
/// The C-ABI trust path is chain-validating, so the credential is minted IN-WINDOW (nbf 2026-08-01,
/// at [`IN_WINDOW_NOW`]) and the anchor is the issuing **IACA root** (`ca-iaca`): the leaf chains to
/// the CA (chain-to-root), exercising the production trust rather than an exact-leaf pin.
fn valid_sd_jwt_request() -> VerifyRequest {
    let sd_jwt = mint_sd_jwt_with_validity(
        ISSUER_KEY_PK8,
        ISSUER_CERT_DER,
        serde_json::json!(1_785_542_400), // nbf = 2026-08-01 (in the leaf cert's window)
        serde_json::json!(1_790_000_000), // exp = 2026-09-21 (still in-window, after IN_WINDOW_NOW)
    );
    VerifyRequest {
        schema_version: ATTESTATION_SCHEMA_VERSION,
        presentation: WirePresentation::SdJwtVc {
            presentation: sd_jwt.presentation(),
        },
        policy: VerificationPolicy::default(),
        anchors: vec![WireTrustAnchor {
            role: IssuerRole::Pid,
            format: Format::SdJwtVc,
            // The issuing CA root: the leaf chains to it (chain-to-root), not an exact-leaf pin.
            cert_der: CA_IACA.to_vec(),
        }],
        context: WireContext {
            now_unix: IN_WINDOW_NOW,
            role: IssuerRole::Pid,
            statuses: vec![StatusOutcome::NoStatus],
            status_tokens: std::collections::BTreeMap::new(),
            session_transcript: None,
            qualified_gate: false,
            qualified_trust_list: None,
            qualified_scheme_anchors: Vec::new(),
        },
        request: None,
    }
}

#[test]
fn well_formed_sd_jwt_request_verifies_valid() {
    // The anchor is the issuing IACA root: the C-ABI trust path CHAIN-VALIDATES the leaf to the CA
    // (chain-to-root — the EUDI model), proving a host passing a CA/root trusts a chaining leaf.
    let out = process_verify_bytes(&encode(&valid_sd_jwt_request()));
    let resp: VerifyResponse = ciborium::from_reader(&out[..]).unwrap();
    assert_eq!(resp.schema_version, ATTESTATION_SCHEMA_VERSION);
    match resp.outcome {
        VerifyOutcome::Ok { result } => {
            assert!(result.valid, "reasons {:?}", result.reasons);
            assert!(result.disclosed_attributes.contains_key("given_name"));
        }
        VerifyOutcome::Err { message } => panic!("unexpected error: {message}"),
    }
}

#[test]
fn expired_pinned_leaf_anchor_is_rejected_as_expired_over_the_c_abi() {
    // FALSE-ACCEPT FIX (C-ABI trust): a host pins the issuer LEAF directly as the anchor, but the
    // verification instant is PAST the leaf cert's notAfter. The chain-validating C-ABI trust path
    // enforces the leaf's validity window (reusing `verify_chain`), so the issuer is REJECTED — NOT
    // silently accepted as the old exact-DER-equality (`StaticTestAnchors`) path would. The reason is
    // `Expired` (a trusted-but-lapsed signing cert), not a misleading `UntrustedIssuer`: the
    // `ChainError::LeafExpired` is folded to `TrustFailure::Expired` → `ReasonCode::Expired`.
    let mut req = valid_sd_jwt_request();
    // Pin the leaf itself as the anchor (a direct pin), and run far past its notAfter (≈2096).
    req.anchors = vec![WireTrustAnchor {
        role: IssuerRole::Pid,
        format: Format::SdJwtVc,
        cert_der: ISSUER_CERT_DER.to_vec(),
    }];
    req.context.now_unix = 4_000_000_000;
    let out = process_verify_bytes(&encode(&req));
    let resp: VerifyResponse = ciborium::from_reader(&out[..]).unwrap();
    match resp.outcome {
        VerifyOutcome::Ok { result } => {
            assert!(!result.valid, "an expired pinned leaf must NOT be accepted");
            assert_eq!(result.reasons, vec![crate::types::ReasonCode::Expired]);
        }
        VerifyOutcome::Err { message } => panic!("unexpected error: {message}"),
    }
}

#[test]
fn leaf_pinned_directly_within_validity_is_trusted_over_the_c_abi() {
    // The direct-pin path still works WITHIN the leaf's validity window: pinning the leaf at an
    // in-window instant is trusted (so the expired-pin rejection above is the validity gate firing,
    // not a blanket direct-pin failure).
    let mut req = valid_sd_jwt_request();
    req.anchors = vec![WireTrustAnchor {
        role: IssuerRole::Pid,
        format: Format::SdJwtVc,
        cert_der: ISSUER_CERT_DER.to_vec(),
    }];
    // now_unix already IN_WINDOW from the base request.
    let out = process_verify_bytes(&encode(&req));
    let resp: VerifyResponse = ciborium::from_reader(&out[..]).unwrap();
    match resp.outcome {
        VerifyOutcome::Ok { result } => assert!(result.valid, "reasons {:?}", result.reasons),
        VerifyOutcome::Err { message } => panic!("unexpected error: {message}"),
    }
}

#[test]
fn untrusted_issuer_request_verifies_invalid_with_reason() {
    // Same credential, but no anchors configured → UntrustedIssuer (a real INVALID verdict).
    let mut req = valid_sd_jwt_request();
    req.anchors.clear();
    let out = process_verify_bytes(&encode(&req));
    let resp: VerifyResponse = ciborium::from_reader(&out[..]).unwrap();
    match resp.outcome {
        VerifyOutcome::Ok { result } => {
            assert!(!result.valid);
            assert_eq!(
                result.reasons,
                vec![crate::types::ReasonCode::UntrustedIssuer]
            );
        }
        VerifyOutcome::Err { message } => panic!("unexpected error: {message}"),
    }
}

#[test]
fn well_formed_mdoc_request_verifies_valid() {
    // The C-ABI trust path chain-validates the DS leaf to the passed anchor and enforces the leaf
    // cert's validity window at `now`, so the credential is minted IN-WINDOW (MSO validityInfo inside
    // the mdoc-ds leaf cert window) and the anchor is the issuing IACA root (chain-to-root).
    let response = MdocBuilder::new()
        .signed("2026-08-01T00:00:00Z")
        .validity("2026-08-01T00:00:00Z", "2027-02-01T00:00:00Z")
        .build();
    let req = VerifyRequest {
        schema_version: ATTESTATION_SCHEMA_VERSION,
        presentation: WirePresentation::Mdoc {
            device_response: response,
            audience: None,
        },
        policy: VerificationPolicy::default(),
        anchors: vec![WireTrustAnchor {
            role: IssuerRole::Pid,
            format: Format::Mdoc,
            // The issuing CA root: the DS leaf chains to it (chain-to-root), not an exact-leaf pin.
            cert_der: CA_IACA.to_vec(),
        }],
        context: WireContext {
            now_unix: IN_WINDOW_NOW,
            role: IssuerRole::Pid,
            statuses: vec![StatusOutcome::NoStatus],
            status_tokens: std::collections::BTreeMap::new(),
            // The mdoc `DeviceSignature` is signed over the builder's default transcript; a request-less
            // verify must be handed that same transcript (§9.1.5 — the verifier no longer fabricates
            // one) for the holder binding to verify.
            session_transcript: Some(default_session_transcript()),
            qualified_gate: false,
            qualified_trust_list: None,
            qualified_scheme_anchors: Vec::new(),
        },
        request: None,
    };
    let out = process_verify_bytes(&encode(&req));
    let resp: VerifyResponse = ciborium::from_reader(&out[..]).unwrap();
    match resp.outcome {
        VerifyOutcome::Ok { result } => assert!(result.valid, "reasons {:?}", result.reasons),
        VerifyOutcome::Err { message } => panic!("unexpected error: {message}"),
    }
}

#[test]
fn garbage_input_yields_err_outcome() {
    let out = process_verify_bytes(&[0xff, 0x00, 0x13, 0x37]);
    let resp: VerifyResponse = ciborium::from_reader(&out[..]).unwrap();
    assert!(matches!(resp.outcome, VerifyOutcome::Err { .. }));
}

#[test]
fn wrong_schema_version_is_rejected() {
    let mut req = valid_sd_jwt_request();
    req.schema_version = ATTESTATION_SCHEMA_VERSION + 1;
    let err = decode_verify_request(&encode(&req)).unwrap_err();
    assert!(err.contains("unsupported attestation schema_version"));
}

#[test]
fn a_misspelled_request_key_fails_closed_not_silently_bare() {
    // FOOTGUN GUARD (#5): a typo'd top-level key must be a hard decode error (`deny_unknown_fields`),
    // NOT silently ignored. Otherwise a misspelled `request` key would drop to `None` and downgrade to
    // the request-LESS path (no replay/audience protection) while still reporting valid — with no
    // signal. Build a valid request map, then rename `request` → `reqeust` and confirm the decode fails.
    let req = valid_sd_jwt_request();
    // Round-trip through a generic CBOR value so we can rename a key (the struct can't express a typo).
    let mut value: ciborium::value::Value = ciborium::de::from_reader(&encode(&req)[..]).unwrap();
    // Add an unknown top-level key to the request map.
    if let ciborium::value::Value::Map(entries) = &mut value {
        entries.push((
            ciborium::value::Value::Text("reqeust".to_owned()), // deliberate typo of `request`
            ciborium::value::Value::Null,
        ));
    } else {
        panic!("VerifyRequest must encode as a CBOR map");
    }
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&value, &mut bytes).unwrap();
    assert!(
        decode_verify_request(&bytes).is_err(),
        "an unknown/misspelled top-level key must fail the decode (deny_unknown_fields), never be ignored"
    );
}

#[test]
fn request_bound_signal_reflects_whether_a_request_was_supplied() {
    // OBSERVABILITY (#5): `VerificationResult.request_bound` lets a caller confirm request binding
    // actually ran. A request-less verify (no `request`) is VALID but NOT request-bound; supplying the
    // matching OpenID4VP request flips it true.
    let bare = valid_sd_jwt_request(); // valid_sd_jwt_request supplies no `request`
    assert!(
        bare.request.is_none(),
        "the baseline request is request-less"
    );
    let out = process_verify_bytes(&encode(&bare));
    let resp: VerifyResponse = ciborium::from_reader(&out[..]).unwrap();
    match resp.outcome {
        VerifyOutcome::Ok { result } => {
            assert!(result.valid, "reasons {:?}", result.reasons);
            assert!(
                !result.request_bound,
                "a request-less verification must report request_bound = false (no replay/audience \
                 protection was applied)"
            );
        }
        VerifyOutcome::Err { message } => panic!("unexpected error: {message}"),
    }
}

#[test]
fn response_round_trips_through_cbor() {
    let bytes = encode_verify_response(VerifyOutcome::Err {
        message: "x".to_owned(),
    });
    let resp: VerifyResponse = ciborium::from_reader(&bytes[..]).unwrap();
    assert!(matches!(resp.outcome, VerifyOutcome::Err { .. }));
}

/// The optional national-TL fixture the opt-in C-ABI gate reads (qualified EAA/Q services).
const QUALIFIED_TRUST_LIST_JSON: &[u8] =
    include_bytes!("../../../../tests/fixtures/attestation/qualified-trust-list.json");
/// A self-signed cert that does NOT chain to `ca-iaca` — a forged national-TL signer over the wire.
const WRONG_ISSUER: &[u8] =
    include_bytes!("../../../../tests/fixtures/attestation/wrong-issuer.cert.der");

/// The relevant/verification instant the qualified-gate wire test runs at — the shared in-window
/// instant (2026-09-01), inside both the credential leaf's and the national-TL signer's (`ca-iaca`)
/// validity windows. The gate authenticates the TL signer at the verification instant (enforced
/// against the signer cert's window), so the gate test mints an in-window credential and runs here.
const QUALIFIED_RELEVANT_GRANTED: i64 = IN_WINDOW_NOW; // 2026-09-01.

/// Mint an SD-JWT VC that self-declares the TS 119 615 v1.4.1 QEAA type indication via the
/// issuer-signed **`category`** claim ([`EAA_EU_QUALIFIED_TYPE`], PRO-4.12.4-03, per ETSI TS 119 472-1 —
/// NOT the `vct`, which is the credential-TYPE identifier), with caller-chosen `nbf`/`exp`. The
/// canonical `mint_sd_jwt_with_*` helpers fix either the `vct` or the validity window (never both), so
/// the qualified-gate wire test — which needs BOTH a self-declared QEAA type AND an in-window
/// credential — builds it here from the shared test-issuer primitives.
fn mint_qeaa_sd_jwt(nbf: i64, exp: i64) -> sd_jwt_payload::SdJwt {
    use base64ct::{Base64, Encoding as _};
    use sd_jwt_payload::SdJwtBuilder;
    let cert_b64 = Base64::encode_string(ISSUER_CERT_DER);
    let claims = serde_json::json!({
        "iss": "https://issuer.example/cb",
        "vct": "urn:eudi:pid:1",
        "category": EAA_EU_QUALIFIED_TYPE,
        "nbf": nbf,
        "exp": exp,
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
fn opt_in_gate_over_the_c_abi_populates_qualified_status_and_is_additive() {
    // T020: the wire envelope additively carries the gate flag, the national TL bytes, and the
    // scheme-operator anchor. Driving the SAME credential with the gate OFF vs ON yields an identical
    // always-on verdict; only ON carries the qualified_status (sdjwt-issuer is a granted EAA/Q issuer
    // at the relevant time, and the TL authenticates against the supplied scheme anchor → Qualified).
    // The credential + verification instant are in-window for both the leaf and the TL signer certs.
    let base = {
        let mut req = valid_sd_jwt_request();
        // The credential self-declares the QEAA type (vct = the TS 119 615 v1.4.1 URN) so the
        // PRO-4.12.4-03 precondition is satisfied; in-window for both the leaf and the TL signer.
        let sd_jwt = mint_qeaa_sd_jwt(
            QUALIFIED_RELEVANT_GRANTED - 1_000,
            QUALIFIED_RELEVANT_GRANTED + 1_000_000,
        );
        req.presentation = WirePresentation::SdJwtVc {
            presentation: sd_jwt.presentation(),
        };
        req.context.now_unix = QUALIFIED_RELEVANT_GRANTED;
        req
    };

    let gate_on = {
        let mut req = base.clone();
        req.context.qualified_gate = true;
        req.context.qualified_trust_list = Some(QUALIFIED_TRUST_LIST_JSON.to_vec());
        req.context.qualified_scheme_anchors = vec![WireSchemeAnchor {
            cert_der: CA_IACA.to_vec(),
        }];
        req
    };

    let decode = |bytes: &[u8]| -> crate::types::VerificationResult {
        let resp: VerifyResponse = ciborium::from_reader(bytes).unwrap();
        match resp.outcome {
            VerifyOutcome::Ok { result } => result,
            VerifyOutcome::Err { message } => panic!("unexpected error: {message}"),
        }
    };

    let off = decode(&process_verify_bytes(&encode(&base)));
    let on = decode(&process_verify_bytes(&encode(&gate_on)));

    // Always-on verdict identical; gate is purely additive (SC-007).
    assert!(off.valid && on.valid);
    assert_eq!(off.reasons, on.reasons);
    assert_eq!(off.disclosed_attributes, on.disclosed_attributes);
    assert!(off.qualified_status.is_none(), "gate off → absent");
    assert_eq!(
        on.qualified_status,
        Some(crate::types::QualifiedStatus::Qualified),
        "gate on over the C-ABI → Qualified for a granted EAA/Q issuer"
    );
}

#[test]
fn opt_in_gate_over_the_c_abi_with_malformed_trust_list_is_indeterminate_not_an_error() {
    // A malformed national-TL blob fails CLOSED inside the gate (Indeterminate), never failing the
    // always-on verdict nor erroring the whole verify — no false "qualified".
    let mut req = valid_sd_jwt_request();
    req.context.qualified_gate = true;
    req.context.qualified_trust_list = Some(b"{ not a trust list".to_vec());
    let resp: VerifyResponse =
        ciborium::from_reader(&process_verify_bytes(&encode(&req))[..]).expect("response decodes");
    match resp.outcome {
        VerifyOutcome::Ok { result } => {
            assert!(result.valid, "always-on bar unaffected by a bad TL");
            assert_eq!(
                result.qualified_status,
                Some(crate::types::QualifiedStatus::Indeterminate)
            );
        }
        VerifyOutcome::Err { message } => panic!("a bad TL must not error the verify: {message}"),
    }
}

#[test]
fn opt_in_gate_over_the_c_abi_with_a_forged_trust_list_signer_is_indeterminate() {
    // A genuine fixture TL but driven with a FORGED scheme anchor (wrong-issuer, which the fixture's
    // ca-iaca signer does not chain to) over the wire → the gate cannot authenticate the TL →
    // Indeterminate, never Qualified (the false-trust bug fix, end-to-end through the C-ABI envelope).
    let mut req = valid_sd_jwt_request();
    req.context.qualified_gate = true;
    req.context.qualified_trust_list = Some(QUALIFIED_TRUST_LIST_JSON.to_vec());
    req.context.qualified_scheme_anchors = vec![WireSchemeAnchor {
        cert_der: WRONG_ISSUER.to_vec(),
    }];
    let resp: VerifyResponse =
        ciborium::from_reader(&process_verify_bytes(&encode(&req))[..]).expect("response decodes");
    match resp.outcome {
        VerifyOutcome::Ok { result } => {
            assert!(result.valid, "always-on bar unaffected");
            assert_eq!(
                result.qualified_status,
                Some(crate::types::QualifiedStatus::Indeterminate),
                "an unauthenticated TL must never report Qualified over the C-ABI"
            );
        }
        VerifyOutcome::Err { message } => panic!("must not error: {message}"),
    }
}

#[test]
fn opt_in_gate_over_the_c_abi_without_a_scheme_anchor_is_indeterminate() {
    // The gate is on with a genuine fixture TL but NO scheme anchor supplied over the wire → the TL
    // cannot be authenticated → Indeterminate (can't authenticate ⇒ can't assert qualified).
    let mut req = valid_sd_jwt_request();
    req.context.qualified_gate = true;
    req.context.qualified_trust_list = Some(QUALIFIED_TRUST_LIST_JSON.to_vec());
    // qualified_scheme_anchors left empty (the default).
    let resp: VerifyResponse =
        ciborium::from_reader(&process_verify_bytes(&encode(&req))[..]).expect("response decodes");
    match resp.outcome {
        VerifyOutcome::Ok { result } => {
            assert!(result.valid);
            assert_eq!(
                result.qualified_status,
                Some(crate::types::QualifiedStatus::Indeterminate)
            );
        }
        VerifyOutcome::Err { message } => panic!("must not error: {message}"),
    }
}

// =================================================================================================
// Set-level `verify_vp_token` wire envelope (schema v5, additive) — the multi-credential surface.
//
// These drive `process_vp_token_bytes` end-to-end: a well-formed 2-credential request satisfying a
// `credential_sets` required option verifies SATISFIED with per-credential VALID; a required credential
// REVOKED via an in-core-AUTHENTICATED signed status token is NOT satisfied (proving in-core status auth
// runs on the set-level path); and the envelope's decode discipline (`deny_unknown_fields` + schema
// version) matches `VerifyRequest`. The credentials are minted IN-WINDOW (the C-ABI trust path is
// chain-validating) and request-bound (a KB-JWT over the request `aud`/`nonce`, `iat` in-window).
// =================================================================================================

/// The set-level tests' OpenID4VP request parameters (distinct `client_id` vs `response_uri`, a fixed
/// nonce so the KB-JWT binds deterministically).
const VP_AUDIENCE: &str = "https://verifier.example/cb";
const VP_RESPONSE_URI: &str = "https://verifier.example/cb/response";
const VP_NONCE: &[u8] = &[7u8; 16];

/// Build the set-level OpenID4VP request carrying `dcql_json`, bound to the shared audience/nonce.
fn vp_request(dcql_json: &str) -> PresentationRequest {
    PresentationRequest {
        dcql: Dcql::from_json(dcql_json),
        nonce: VP_NONCE.to_vec(),
        audience: VP_AUDIENCE.to_owned(),
        response_uri: VP_RESPONSE_URI.to_owned(),
    }
}

/// A 2-SD-JWT-credential DCQL (`a`, `b` both of [`DEFAULT_VCT`]) whose single REQUIRED credential set
/// option demands BOTH — so the request is satisfied only when `a` AND `b` are.
fn two_credential_vp_dcql() -> String {
    format!(
        r#"{{"credentials":[{{"id":"a","format":"dc+sd-jwt","meta":{{"vct_values":["{DEFAULT_VCT}"]}}}},{{"id":"b","format":"dc+sd-jwt","meta":{{"vct_values":["{DEFAULT_VCT}"]}}}}],"credential_sets":[{{"options":[["a","b"]],"required":true}}]}}"#
    )
}

/// Mint an in-window (nbf 2026-08-01, exp inside the leaf window), request-bound SD-JWT VC of the
/// default vct — the KB-JWT `iat` at [`IN_WINDOW_NOW`] so it is within the freshness window.
fn bound_sd_jwt(request: &PresentationRequest) -> String {
    let sd_jwt = mint_sd_jwt_with_validity(
        ISSUER_KEY_PK8,
        ISSUER_CERT_DER,
        serde_json::json!(1_785_542_400),
        serde_json::json!(1_790_000_000),
    );
    attach_kb_jwt_with_iat(
        sd_jwt,
        HOLDER_KEY_PK8,
        VP_AUDIENCE,
        &request.nonce_b64(),
        IN_WINDOW_NOW,
    )
}

/// Like [`bound_sd_jwt`] but the credential declares a Token Status List reference at `idx`/`uri`.
fn bound_status_sd_jwt(request: &PresentationRequest, idx: u64, uri: &str) -> String {
    let sd_jwt = mint_sd_jwt_with_status_and_validity(
        ISSUER_KEY_PK8,
        ISSUER_CERT_DER,
        idx,
        uri,
        1_785_542_400,
        1_790_000_000,
    );
    attach_kb_jwt_with_iat(
        sd_jwt,
        HOLDER_KEY_PK8,
        VP_AUDIENCE,
        &request.nonce_b64(),
        IN_WINDOW_NOW,
    )
}

/// A one-`NoStatus`-document positional statuses map for each `(id, [tokens])` — the positional seam a
/// non-status-declaring credential (or the fallback) reads.
fn vp_no_status(
    vp_token: &std::collections::BTreeMap<String, Vec<WirePresentation>>,
) -> std::collections::BTreeMap<String, Vec<Vec<StatusOutcome>>> {
    vp_token
        .iter()
        .map(|(id, presentations)| {
            (
                id.clone(),
                presentations
                    .iter()
                    .map(|_| vec![StatusOutcome::NoStatus])
                    .collect(),
            )
        })
        .collect()
}

/// Assemble a `WireVpTokenRequest` at the current schema version, pinning the issuing IACA root and the
/// in-window instant (the fields the set-level tests share).
fn vp_envelope(
    request: PresentationRequest,
    vp_token: std::collections::BTreeMap<String, Vec<WirePresentation>>,
    statuses: std::collections::BTreeMap<String, Vec<Vec<StatusOutcome>>>,
    status_tokens: std::collections::BTreeMap<String, serde_bytes::ByteBuf>,
) -> WireVpTokenRequest {
    WireVpTokenRequest {
        schema_version: ATTESTATION_SCHEMA_VERSION,
        request,
        vp_token,
        policy: VerificationPolicy::default(),
        anchors: vec![WireTrustAnchor {
            role: IssuerRole::Pid,
            format: Format::SdJwtVc,
            cert_der: CA_IACA.to_vec(),
        }],
        now_unix: IN_WINDOW_NOW,
        role: IssuerRole::Pid,
        statuses,
        status_tokens,
    }
}

fn encode_vp(req: &WireVpTokenRequest) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::into_writer(req, &mut buf).unwrap();
    buf
}

#[test]
fn wire_vp_token_request_round_trips_through_cbor() {
    // A skeletal request (a bogus presentation is enough — this asserts the CBOR shape, not a verdict)
    // survives an encode → decode unchanged, including the additive `status_tokens` map.
    let mut vp_token = std::collections::BTreeMap::new();
    vp_token.insert(
        "a".to_owned(),
        vec![WirePresentation::SdJwtVc {
            presentation: "eyJhbGciOiJFUzI1NiJ9.eyJ2Y3QiOiJ4In0.AAAA~".to_owned(),
        }],
    );
    let mut status_tokens = std::collections::BTreeMap::new();
    status_tokens.insert(
        "https://issuer.example/statuslists/1".to_owned(),
        serde_bytes::ByteBuf::from(vec![1u8, 2, 3]),
    );
    let req = vp_envelope(
        vp_request(&two_credential_vp_dcql()),
        vp_token.clone(),
        vp_no_status(&vp_token),
        status_tokens,
    );
    let decoded: WireVpTokenRequest = ciborium::from_reader(&encode_vp(&req)[..]).unwrap();
    assert_eq!(
        decoded, req,
        "WireVpTokenRequest must round-trip through CBOR"
    );
}

#[test]
fn process_vp_token_bytes_satisfied_set_end_to_end() {
    // A well-formed set-level request: two trusted, in-window, request-bound credentials satisfying the
    // required option [["a","b"]] → SATISFIED, each per-credential VALID.
    let request = vp_request(&two_credential_vp_dcql());
    let pres_a = bound_sd_jwt(&request);
    let pres_b = bound_sd_jwt(&request);
    let mut vp_token = std::collections::BTreeMap::new();
    vp_token.insert(
        "a".to_owned(),
        vec![WirePresentation::SdJwtVc {
            presentation: pres_a,
        }],
    );
    vp_token.insert(
        "b".to_owned(),
        vec![WirePresentation::SdJwtVc {
            presentation: pres_b,
        }],
    );
    let statuses = vp_no_status(&vp_token);
    let req = vp_envelope(
        request,
        vp_token,
        statuses,
        std::collections::BTreeMap::new(),
    );

    let out = process_vp_token_bytes(&encode_vp(&req));
    let resp: WireVpTokenResponse = ciborium::from_reader(&out[..]).unwrap();
    assert_eq!(resp.schema_version, ATTESTATION_SCHEMA_VERSION);
    match resp.outcome {
        WireVpTokenOutcome::Ok { result } => {
            assert!(result.satisfied, "the required set [a,b] is satisfied");
            for id in ["a", "b"] {
                let credential = &result.credentials[id];
                assert!(
                    credential.satisfied,
                    "credential {id} must satisfy its query"
                );
                assert!(
                    credential.presentations[0].valid,
                    "credential {id} presentation must be VALID: {:?}",
                    credential.presentations[0].reasons
                );
            }
        }
        WireVpTokenOutcome::Err { message } => panic!("unexpected error: {message}"),
    }
}

#[test]
fn process_vp_token_bytes_revoked_via_in_core_status_token_is_unsatisfied() {
    // The set-level path AUTHENTICATES a supplied signed Token Status List token IN-CORE: required
    // credential "a" declares a list AND a REVOKED, issuer-signed token is supplied for its URI → "a"
    // fails (Revoked) → the required option [["a","b"]] is NOT satisfied, even though "b" is current.
    // Proves in-core status authentication runs on the set-level wire path (not just the positional seam).
    const LIST_URI: &str = "https://issuer.example/statuslists/wire-set-level";
    const IDX: u64 = 5;
    let request = vp_request(&two_credential_vp_dcql());
    let pres_a = bound_status_sd_jwt(&request, IDX, LIST_URI);
    let pres_b = bound_sd_jwt(&request);
    let mut vp_token = std::collections::BTreeMap::new();
    vp_token.insert(
        "a".to_owned(),
        vec![WirePresentation::SdJwtVc {
            presentation: pres_a,
        }],
    );
    vp_token.insert(
        "b".to_owned(),
        vec![WirePresentation::SdJwtVc {
            presentation: pres_b,
        }],
    );
    let statuses = vp_no_status(&vp_token);
    // A REVOKED signed token (issuer-signed, kid-only) for "a"'s list URI, fresh at the verify instant.
    let mut status_tokens = std::collections::BTreeMap::new();
    status_tokens.insert(
        LIST_URI.to_owned(),
        serde_bytes::ByteBuf::from(
            mint_status_list_jwt(ISSUER_KEY_PK8, LIST_URI, IDX, true, IN_WINDOW_NOW).into_bytes(),
        ),
    );
    let req = vp_envelope(request, vp_token, statuses, status_tokens);

    let out = process_vp_token_bytes(&encode_vp(&req));
    let resp: WireVpTokenResponse = ciborium::from_reader(&out[..]).unwrap();
    match resp.outcome {
        WireVpTokenOutcome::Ok { result } => {
            assert!(
                !result.satisfied,
                "a required credential revoked by an in-core-authenticated status token must not \
                 satisfy the set"
            );
            let a = &result.credentials["a"];
            assert!(
                !a.satisfied,
                "the revoked credential must not satisfy its query"
            );
            assert_eq!(
                a.presentations[0].reasons,
                vec![crate::types::ReasonCode::Revoked],
                "the revocation is read from the in-core-authenticated token"
            );
            assert!(
                result.credentials["b"].satisfied,
                "the current credential b still satisfies its query"
            );
        }
        WireVpTokenOutcome::Err { message } => panic!("unexpected error: {message}"),
    }
}

#[test]
fn wire_vp_token_misspelled_key_fails_closed_deny_unknown_fields() {
    // A typo'd top-level key must be a hard decode error (`deny_unknown_fields`), never silently
    // ignored — the same footgun guard as `VerifyRequest`.
    let mut vp_token = std::collections::BTreeMap::new();
    vp_token.insert(
        "a".to_owned(),
        vec![WirePresentation::SdJwtVc {
            presentation: "eyJhbGciOiJFUzI1NiJ9.eyJ2Y3QiOiJ4In0.AAAA~".to_owned(),
        }],
    );
    let req = vp_envelope(
        vp_request(&two_credential_vp_dcql()),
        vp_token.clone(),
        vp_no_status(&vp_token),
        std::collections::BTreeMap::new(),
    );
    // Round-trip through a generic CBOR value to inject a misspelled key the struct cannot express.
    let mut value: ciborium::value::Value =
        ciborium::de::from_reader(&encode_vp(&req)[..]).unwrap();
    if let ciborium::value::Value::Map(entries) = &mut value {
        entries.push((
            ciborium::value::Value::Text("vp_tokenn".to_owned()), // deliberate typo of `vp_token`
            ciborium::value::Value::Null,
        ));
    } else {
        panic!("WireVpTokenRequest must encode as a CBOR map");
    }
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&value, &mut bytes).unwrap();
    assert!(
        decode_vp_token_request(&bytes).is_err(),
        "an unknown/misspelled top-level key must fail the decode (deny_unknown_fields)"
    );
}

#[test]
fn wire_vp_token_wrong_schema_version_is_rejected() {
    let mut vp_token = std::collections::BTreeMap::new();
    vp_token.insert(
        "a".to_owned(),
        vec![WirePresentation::SdJwtVc {
            presentation: "eyJhbGciOiJFUzI1NiJ9.eyJ2Y3QiOiJ4In0.AAAA~".to_owned(),
        }],
    );
    let mut req = vp_envelope(
        vp_request(&two_credential_vp_dcql()),
        vp_token.clone(),
        vp_no_status(&vp_token),
        std::collections::BTreeMap::new(),
    );
    req.schema_version = ATTESTATION_SCHEMA_VERSION + 1;
    let err = decode_vp_token_request(&encode_vp(&req)).unwrap_err();
    assert!(err.contains("unsupported attestation schema_version"));
}

// =================================================================================================
// GROUP 2 — the set-level surface does NOT run the opt-in qualified gate: `policy.qualified_gate = true`
// must FAIL LOUD (a clear `Err`), never silently run no determination while still reporting satisfied.
// =================================================================================================

#[test]
fn process_vp_token_bytes_rejects_qualified_gate_as_unsupported() {
    // A set-level request with `policy.qualified_gate = true` carries no national Trusted List / scheme
    // anchors, so the gate cannot run — the surface must reject it rather than let the flag be a silent
    // no-op (`qualified_status` absent) while still folding a `satisfied` verdict.
    let request = vp_request(&two_credential_vp_dcql());
    let pres_a = bound_sd_jwt(&request);
    let pres_b = bound_sd_jwt(&request);
    let mut vp_token = std::collections::BTreeMap::new();
    vp_token.insert(
        "a".to_owned(),
        vec![WirePresentation::SdJwtVc {
            presentation: pres_a,
        }],
    );
    vp_token.insert(
        "b".to_owned(),
        vec![WirePresentation::SdJwtVc {
            presentation: pres_b,
        }],
    );
    let statuses = vp_no_status(&vp_token);
    let mut req = vp_envelope(
        request,
        vp_token,
        statuses,
        std::collections::BTreeMap::new(),
    );
    req.policy.qualified_gate = true;

    let out = process_vp_token_bytes(&encode_vp(&req));
    let resp: WireVpTokenResponse = ciborium::from_reader(&out[..]).unwrap();
    match resp.outcome {
        WireVpTokenOutcome::Err { message } => assert!(
            message.contains("qualified"),
            "the error must name the unsupported qualified gate: {message}"
        ),
        WireVpTokenOutcome::Ok { .. } => {
            panic!("qualified_gate = true must FAIL LOUD on the set-level surface, not silently satisfy")
        }
    }

    // Control: the SAME request with `qualified_gate = false` (the default) is unaffected — it runs the
    // set-level verdict normally and is SATISFIED (proving the rejection above is the gate flag, not the
    // request itself).
    req.policy.qualified_gate = false;
    let out = process_vp_token_bytes(&encode_vp(&req));
    let resp: WireVpTokenResponse = ciborium::from_reader(&out[..]).unwrap();
    match resp.outcome {
        WireVpTokenOutcome::Ok { result } => assert!(
            result.satisfied,
            "with the gate unset the set verifies normally: {:?}",
            result.credentials
        ),
        WireVpTokenOutcome::Err { message } => panic!("gate-off request must not error: {message}"),
    }
}

// =================================================================================================
// GROUP 1 (+ GROUP 6 set-level-mdoc WIRE coverage) — an mdoc presentation with NO addressed audience on
// the set-level wire path must fail closed as `MissingRequestBinding` (mirroring the single-presentation
// `verify()` path), NOT be coerced to an empty-string audience → `WrongAudience`; a correctly-addressed
// mdoc verifies VALID through the same wire mapping.
// =================================================================================================

/// A single-`mdl` mdoc DCQL whose one REQUIRED credential-set option demands `mdl`.
fn mdl_vp_dcql() -> &'static str {
    r#"{"credentials":[{"id":"mdl","format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.mDL"}}],"credential_sets":[{"options":[["mdl"]],"required":true}]}"#
}

/// Build an mdoc set-level envelope pinning the issuing IACA root under `(Pid, Mdoc)` (the DS leaf
/// chains to it), with a single `mdl` presentation `presentation`, bound to `request`.
fn mdoc_vp_envelope(
    request: PresentationRequest,
    presentation: WirePresentation,
) -> WireVpTokenRequest {
    let mut vp_token = std::collections::BTreeMap::new();
    vp_token.insert("mdl".to_owned(), vec![presentation]);
    let statuses = vp_no_status(&vp_token);
    let mut req = vp_envelope(
        request,
        vp_token,
        statuses,
        std::collections::BTreeMap::new(),
    );
    // The mdoc DS leaf chains to the IACA root under (Pid, Mdoc) — replace the SD-JWT anchor.
    req.anchors = vec![WireTrustAnchor {
        role: IssuerRole::Pid,
        format: Format::Mdoc,
        cert_der: CA_IACA.to_vec(),
    }];
    req
}

/// Drive `process_vp_token_bytes` for a single-`mdl` mdoc presentation with NO addressed audience, bound
/// to a request whose `client_id` is `request_audience`, and return the set-level result.
fn no_audience_mdoc_result(request_audience: &str) -> crate::openid4vp::VpTokenVerification {
    let mut request = vp_request(mdl_vp_dcql());
    request.audience = request_audience.to_owned();
    // The device_response is deliberately GARBAGE: a no-audience mdoc must NEVER reach the crypto bar, so
    // these bytes are never decoded (a MalformedCredential/Tamper reason would prove the opposite).
    let presentation = WirePresentation::Mdoc {
        device_response: vec![0xff, 0x00, 0x13, 0x37],
        audience: None,
    };
    let req = mdoc_vp_envelope(request, presentation);
    let out = process_vp_token_bytes(&encode_vp(&req));
    let resp: WireVpTokenResponse = ciborium::from_reader(&out[..]).unwrap();
    match resp.outcome {
        WireVpTokenOutcome::Ok { result } => result,
        WireVpTokenOutcome::Err { message } => panic!("unexpected error: {message}"),
    }
}

#[test]
fn process_vp_token_bytes_mdoc_without_audience_is_missing_request_binding_not_wrong_audience() {
    let result = no_audience_mdoc_result(VP_AUDIENCE);
    assert!(
        !result.satisfied,
        "a no-audience mdoc cannot satisfy the required set"
    );
    let mdl = &result.credentials["mdl"];
    assert!(
        !mdl.satisfied,
        "the no-audience mdoc must not satisfy its query"
    );
    assert_eq!(
        mdl.presentations[0].reasons,
        vec![crate::types::ReasonCode::MissingRequestBinding],
        "an mdoc with no addressed audience is MissingRequestBinding, NEVER WrongAudience"
    );
}

#[test]
fn process_vp_token_bytes_mdoc_without_audience_fails_closed_even_with_empty_client_id() {
    // REGRESSION for the empty-`client_id` edge: even when the verifier's own `client_id` is "" (so an
    // empty-string audience WOULD pass the `token.audience != request.audience` gate), a no-audience mdoc
    // still fails closed as MissingRequestBinding — never coerced to "" and waved past the audience gate.
    let result = no_audience_mdoc_result("");
    assert!(!result.satisfied);
    assert_eq!(
        result.credentials["mdl"].presentations[0].reasons,
        vec![crate::types::ReasonCode::MissingRequestBinding],
        "an empty verifier client_id must not let a no-audience mdoc bypass the audience gate"
    );
}

#[test]
fn process_vp_token_bytes_mdoc_with_audience_verifies_valid() {
    // Companion positive: a set-level mdoc WITH the correct addressed audience verifies VALID through the
    // same wire mapping (so the no-audience rejection is the audience-absence gate, not a blanket
    // set-level mdoc failure). In-window (the C-ABI trust path is chain-validating) + request-bound (the
    // DeviceAuth signs the OpenID4VP handover the verifier reconstructs from the request).
    let request = vp_request(mdl_vp_dcql());
    let transcript = oid4vp_handover_transcript(VP_AUDIENCE, VP_NONCE, VP_RESPONSE_URI);
    let device_response = MdocBuilder::new()
        .signed("2026-08-01T00:00:00Z")
        .validity("2026-08-01T00:00:00Z", "2027-02-01T00:00:00Z")
        .session_transcript(transcript)
        .build();
    let presentation = WirePresentation::Mdoc {
        device_response,
        audience: Some(VP_AUDIENCE.to_owned()),
    };
    let req = mdoc_vp_envelope(request, presentation);

    let out = process_vp_token_bytes(&encode_vp(&req));
    let resp: WireVpTokenResponse = ciborium::from_reader(&out[..]).unwrap();
    match resp.outcome {
        WireVpTokenOutcome::Ok { result } => {
            assert!(
                result.satisfied,
                "a correctly-addressed in-window mdoc satisfies the required set"
            );
            let mdl = &result.credentials["mdl"];
            assert!(mdl.satisfied, "the mdoc must satisfy its query");
            assert!(
                mdl.presentations[0].valid,
                "the mdoc presentation must be VALID: {:?}",
                mdl.presentations[0].reasons
            );
        }
        WireVpTokenOutcome::Err { message } => panic!("unexpected error: {message}"),
    }
}
