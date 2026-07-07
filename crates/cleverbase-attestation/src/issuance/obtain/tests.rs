//! OpenID4VCI `obtain` gating + round-trip tests (US2 — task T022, written test-first against T025).
//!
//! Drive the sans-IO `obtain` state machine against an **in-test issuer double** — the OID4VCI
//! responses are constructed in-test (no external `eudi-srv-pid-issuer` required) — and assert:
//!  * `kind = None` → the flow is **skipped** (a clear skipped outcome, never a failure), AND
//!  * `kind = Reference` → the flow yields a conformant SD-JWT VC that **verifies under US1** (the
//!    obtained credential is presentable + cross-checkable via the T017 harness).
//!
//! The in-test double speaks **OpenID4VCI 1.0 final** (verified online): the Token Response carries no
//! `c_nonce` (§6.1), a dedicated Nonce Endpoint returns the `c_nonce` (§7 `#nonce-endpoint`), the
//! Credential Request carries `proofs: { jwt: [...] }` (§8.2 `#credential-request`), and the Credential
//! Response carries `credentials: [{ credential }]` (§8.3 `#credential-response`).

use base64ct::{Base64UrlUnpadded, Encoding as _};
use p256::ecdsa::{signature::Signer as _, Signature, SigningKey};
use pkcs8::DecodePrivateKey as _;
use serde_json::{json, Value};

use super::super::signer::{HolderContext, Signer, SigningInput};
use super::super::{HeldAttestation, ObtainStep, ResumeObtain};
use super::{begin_obtain, resume_obtain, CredentialOffer, IssuerBackend, IssuerBackendKind};
use crate::sdjwtvc::test_issuer::{
    mint_sd_jwt, HOLDER_JWK_JSON, HOLDER_KEY_PK8, ISSUER_CERT_DER, ISSUER_KEY_PK8, NOW,
};
use crate::types::Format;

const CREDENTIAL_ISSUER: &str = "https://issuer.example/cb";

/// A stub holder HSM (the only holder of a private key in the test) signing the SDK-built input.
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

fn holder_ctx() -> HolderContext {
    let jwk: Value = serde_json::from_slice(HOLDER_JWK_JSON).expect("holder JWK");
    HolderContext::new(jwk, "holder-handle")
}

fn reference_backend() -> IssuerBackend {
    IssuerBackend {
        kind: IssuerBackendKind::Reference,
        token_endpoint: "https://issuer.example/token".to_owned(),
        nonce_endpoint: "https://issuer.example/nonce".to_owned(),
        credential_endpoint: "https://issuer.example/credential".to_owned(),
        credential_issuer: CREDENTIAL_ISSUER.to_owned(),
    }
}

fn an_offer() -> CredentialOffer {
    CredentialOffer {
        pre_authorized_code: crate::secret::Secret::new("pre-auth-code-xyz"),
        credential_configuration_id: "eu.europa.ec.eudi.pid_vc_sd_jwt".to_owned(),
        format: Format::SdJwtVc,
        tx_code: None,
    }
}

/// An OpenID4VCI 1.0 Token Response body (§6.1) — `access_token` + `token_type`, but **no** `c_nonce`
/// (1.0 moved the nonce to the Nonce Endpoint).
fn token_response() -> Vec<u8> {
    serde_json::to_vec(
        &json!({ "access_token": "issuer-access-token", "token_type": "Bearer", "expires_in": 86400 }),
    )
    .unwrap()
}

/// An OpenID4VCI 1.0 Nonce Response body (§7.2 `#nonce-response`) — the REQUIRED top-level `c_nonce`.
fn nonce_response(c_nonce: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({ "c_nonce": c_nonce })).unwrap()
}

/// An HTTP 200 resume carrying `body`.
fn http_ok(body: Vec<u8>) -> ResumeObtain {
    ResumeObtain::Http { status: 200, body }
}

// --- Gating: kind = None → skipped, never failed ------------------------------------------------

#[test]
fn none_backend_skips_cleanly_never_fails() {
    let (session, step) = begin_obtain(an_offer(), IssuerBackend::none(), holder_ctx(), NOW);
    assert_eq!(step, ObtainStep::Skipped);
    assert!(step.is_terminal());
    // Resuming a skipped (terminal) session is an explicit usage error, not a silent re-drive.
    let err = resume_obtain(
        session,
        ResumeObtain::Http {
            status: 200,
            body: vec![],
        },
    )
    .unwrap_err();
    assert!(matches!(err, super::ObtainError::AlreadyTerminal));
}

// --- Reference backend: the full round-trip against the in-test issuer double --------------------

#[test]
fn reference_backend_obtains_a_credential_that_verifies_under_us1() {
    use crate::sdjwtvc::{verify_sd_jwt_vc, SdJwtVcInput, StatusInput};
    use crate::trust::StaticTestAnchors;
    use crate::types::IssuerRole;

    let hsm = StubHsm {
        key: SigningKey::from_pkcs8_der(HOLDER_KEY_PK8).expect("holder key"),
    };

    // 1. begin → the token-endpoint POST (pre-authorized-code grant).
    let (session, step) = begin_obtain(an_offer(), reference_backend(), holder_ctx(), NOW);
    let effect = expect_http(step);
    assert!(effect.url.ends_with("/token"));
    assert!(String::from_utf8_lossy(&effect.body).contains("pre-authorized_code"));

    // 2. token response (1.0: no c_nonce) → the Nonce-Endpoint POST (§7 `#nonce-endpoint`).
    let (session, step) = resume_obtain(session, http_ok(token_response())).unwrap();
    let effect = expect_http(step);
    assert!(effect.url.ends_with("/nonce"));
    assert!(effect.body.is_empty(), "the nonce request body is empty");
    assert!(
        !effect
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("authorization")),
        "the Nonce Endpoint is unauthenticated — no access token is sent",
    );

    // 3. nonce response → the Sign effect (the PoP proof input bound to the fresh c_nonce).
    let (session, step) =
        resume_obtain(session, http_ok(nonce_response("issuer-c-nonce-1"))).unwrap();
    let sign_input = expect_sign(step);
    // The PoP proof exposes the credential-issuer aud + the Nonce-Endpoint c_nonce for host inspection.
    assert_eq!(sign_input.audience(), CREDENTIAL_ISSUER);
    assert_eq!(sign_input.nonce(), "issuer-c-nonce-1");

    // 4. the host (stub HSM) signs the PoP input → the credential-endpoint POST with the proof.
    let signature = hsm.sign("holder-handle", &sign_input).unwrap();
    let (session, step) = resume_obtain(session, ResumeObtain::Signature(signature)).unwrap();
    let effect = expect_http(step);
    assert!(effect.url.ends_with("/credential"));
    let req: Value = serde_json::from_slice(&effect.body).unwrap();
    // 1.0 §8.2: the proof travels in `proofs` (object keyed by proof type → non-empty array), NOT the
    // draft singular `proof`/`proof_type`.
    assert!(
        req.get("proof").is_none(),
        "the draft-13 singular `proof` member must be gone: {req}"
    );
    let proofs = req["proofs"]["jwt"]
        .as_array()
        .expect("proofs.jwt is an array");
    assert_eq!(
        proofs.len(),
        1,
        "exactly one holder PoP in the proofs array"
    );
    let proof_jwt = proofs[0].as_str().expect("jwt proof string");
    // Verify the proof is a real, holder-signed compact JWS over the issuer aud/c_nonce (the issuer
    // double would check this).
    assert_proof_jwt_valid(proof_jwt, CREDENTIAL_ISSUER, "issuer-c-nonce-1");

    // 5. the issuer double mints + returns a conformant SD-JWT VC bound to the holder cnf, in the 1.0
    //    `credentials` array (§8.3 `#credential-response`).
    let minted = mint_sd_jwt(ISSUER_KEY_PK8, ISSUER_CERT_DER).presentation();
    let credential_response = json!({ "credentials": [{ "credential": minted }] });
    let (_session, step) = resume_obtain(
        session,
        http_ok(serde_json::to_vec(&credential_response).unwrap()),
    )
    .unwrap();
    let held = expect_obtained(step);
    let HeldAttestation::SdJwtVc { issued } = &held else {
        panic!("expected an SD-JWT VC");
    };

    // The obtained credential verifies under US1 (issuer-only bar — no holder challenge at issuance).
    let anchors = StaticTestAnchors::new().trust(IssuerRole::Pid, Format::SdJwtVc, ISSUER_CERT_DER);
    let result = verify_sd_jwt_vc(&SdJwtVcInput {
        presentation: issued,
        anchors: &anchors,
        role: IssuerRole::Pid,
        key_binding: None,
        now_unix: NOW,
        status: StatusInput::NoStatus,
        status_tokens: &crate::status::DEFAULT_STATUS_TOKENS,
    });
    assert!(
        result.valid,
        "obtained credential must verify under US1; reasons {:?}",
        result.reasons
    );
    assert!(result.disclosed_attributes.contains_key("given_name"));
}

// --- tx_code (Token Request, §6.1 `#token-request`) ---------------------------------------------

#[test]
fn token_request_includes_tx_code_only_when_the_offer_carries_one() {
    // No tx_code object in the offer → no `tx_code` parameter in the Token Request.
    let (_session, step) = begin_obtain(an_offer(), reference_backend(), holder_ctx(), NOW);
    let body = String::from_utf8(expect_http(step).body).unwrap();
    assert!(
        !body.contains("tx_code"),
        "no tx_code parameter when the offer carries no transaction code: {body}"
    );

    // The offer carried a tx_code object → the End-User-supplied code is sent (§6.1: "MUST be present
    // if a `tx_code` object was present in the Credential Offer"), percent-encoded.
    let offer = CredentialOffer {
        tx_code: Some(crate::secret::Secret::new("493536")),
        ..an_offer()
    };
    let (_session, step) = begin_obtain(offer, reference_backend(), holder_ctx(), NOW);
    let body = String::from_utf8(expect_http(step).body).unwrap();
    assert!(
        body.contains("&tx_code=493536"),
        "the transaction code must be sent in the Token Request: {body}"
    );
}

#[test]
fn tx_code_never_leaks_via_debug_on_the_offer() {
    // The Transaction Code is a low-entropy bearer secret → held as a redacting `Secret`.
    let code = "super-secret-tx-code-987654";
    let offer = CredentialOffer {
        tx_code: Some(crate::secret::Secret::new(code)),
        ..an_offer()
    };
    let dbg = format!("{offer:?}");
    assert!(
        !dbg.contains(code),
        "the transaction code must never appear in Debug output: {dbg}"
    );
    // The live code is still percent-encoded into the token-endpoint body.
    let (_session, step) = begin_obtain(offer, reference_backend(), holder_ctx(), NOW);
    let body = String::from_utf8(expect_http(step).body).unwrap();
    assert!(
        body.contains(code),
        "the live tx_code is carried on the wire"
    );
}

// --- Secret handling: the bearer token never leaks via Debug (FR-010 / Constitution IV) ----------

#[test]
fn obtain_session_debug_does_not_leak_the_access_token() {
    // Drive begin → token → nonce, so the session holds the OAuth access token (a redacting `Secret`).
    // The Nonce-Endpoint `c_nonce` is now carried inside the built `PopJwtBuild` — the exact public
    // `SigningInput` the SDK also hands the host via the `Sign` effect (which by design exposes
    // `aud`/`nonce` for policy inspection) — so it is deliberately NOT a session secret; only the
    // bearer access token (and the pre-authorized code) are redacted.
    let access_token = "super-secret-bearer-token-xyz";
    let c_nonce = "issuer-one-time-c-nonce-abc";
    let (session, _step) = begin_obtain(an_offer(), reference_backend(), holder_ctx(), NOW);
    let token = json!({ "access_token": access_token, "token_type": "Bearer" });
    let (session, _step) =
        resume_obtain(session, http_ok(serde_json::to_vec(&token).unwrap())).unwrap();
    let (session, _step) = resume_obtain(session, http_ok(nonce_response(c_nonce))).unwrap();

    // Formatting the session (a log line / panic message) must NOT print the bearer token — it is held
    // as a redacting `Secret`.
    let dbg = format!("{session:?}");
    assert!(
        !dbg.contains(access_token),
        "the access token must never appear in Debug output: {dbg}"
    );
    assert!(
        dbg.contains("Secret(***)"),
        "the redacted secret marker must be present: {dbg}"
    );
}

#[test]
fn pre_authorized_code_never_leaks_via_debug_on_the_offer_or_session() {
    // The OpenID4VCI pre-authorized code is a bearer grant (redeemable for the credential), so it is
    // held as a redacting `Secret`: it must NOT appear in `Debug` output of the offer, nor of the
    // `ObtainSession` that carries it (a log line / panic message of either). The legitimate
    // round-trip (percent-encode at the redemption site) is unaffected — only `Debug` is redacted.
    let code = "super-secret-pre-authorized-code-xyz";
    let offer = CredentialOffer {
        pre_authorized_code: crate::secret::Secret::new(code),
        credential_configuration_id: "eu.europa.ec.eudi.pid_vc_sd_jwt".to_owned(),
        format: Format::SdJwtVc,
        tx_code: None,
    };
    let offer_dbg = format!("{offer:?}");
    assert!(
        !offer_dbg.contains(code),
        "the pre-authorized code must never appear in the offer's Debug output: {offer_dbg}"
    );
    assert!(
        offer_dbg.contains("Secret(***)"),
        "the redacted secret marker must be present: {offer_dbg}"
    );

    let (session, _step) = begin_obtain(offer, reference_backend(), holder_ctx(), NOW);
    let session_dbg = format!("{session:?}");
    assert!(
        !session_dbg.contains(code),
        "the pre-authorized code must never appear in the session's Debug output: {session_dbg}"
    );

    // The redemption site still percent-encodes the LIVE code into the token-endpoint body.
    let (_session, step) = begin_obtain(
        CredentialOffer {
            pre_authorized_code: crate::secret::Secret::new(code),
            credential_configuration_id: "cfg".to_owned(),
            format: Format::SdJwtVc,
            tx_code: None,
        },
        reference_backend(),
        holder_ctx(),
        NOW,
    );
    let ObtainStep::PerformHttp(effect) = step else {
        panic!("expected the token-endpoint POST")
    };
    assert!(
        String::from_utf8_lossy(&effect.body).contains(code),
        "the live pre-authorized code must be carried in the token-endpoint body"
    );
}

// --- Protocol failure paths (no false success) --------------------------------------------------

#[test]
fn token_endpoint_failure_is_a_terminal_failure_not_a_panic() {
    let (session, _step) = begin_obtain(an_offer(), reference_backend(), holder_ctx(), NOW);
    let (_session, step) = resume_obtain(
        session,
        ResumeObtain::Http {
            status: 401,
            body: b"{}".to_vec(),
        },
    )
    .unwrap();
    assert!(matches!(
        step,
        ObtainStep::Failed(super::ObtainError::TokenRequest(_))
    ));
}

#[test]
fn nonce_endpoint_failure_is_a_terminal_failure() {
    // begin → token (200) → nonce (500) → a clean NonceRequest failure (never a panic / silent accept).
    let (session, _step) = begin_obtain(an_offer(), reference_backend(), holder_ctx(), NOW);
    let (session, _step) = resume_obtain(session, http_ok(token_response())).unwrap();
    let (_session, step) = resume_obtain(
        session,
        ResumeObtain::Http {
            status: 500,
            body: b"{}".to_vec(),
        },
    )
    .unwrap();
    assert!(matches!(
        step,
        ObtainStep::Failed(super::ObtainError::NonceRequest(_))
    ));
}

#[test]
fn nonce_response_without_a_c_nonce_fails() {
    // 200 but no `c_nonce` (the REQUIRED member) → NonceRequest failure.
    let (session, _step) = begin_obtain(an_offer(), reference_backend(), holder_ctx(), NOW);
    let (session, _step) = resume_obtain(session, http_ok(token_response())).unwrap();
    let (_session, step) = resume_obtain(session, http_ok(b"{}".to_vec())).unwrap();
    assert!(matches!(
        step,
        ObtainStep::Failed(super::ObtainError::NonceRequest(_))
    ));
}

#[test]
fn credential_endpoint_failure_is_a_terminal_failure() {
    let session = drive_to_credential_pending();
    let (_session, step) = resume_obtain(
        session,
        ResumeObtain::Http {
            status: 500,
            body: b"{}".to_vec(),
        },
    )
    .unwrap();
    assert!(matches!(
        step,
        ObtainStep::Failed(super::ObtainError::CredentialRequest(_))
    ));
}

#[test]
fn deferred_202_credential_response_is_a_distinct_terminal_failure() {
    // 1.0 §8.3: a deferred Credential Response is HTTP 202 + a `transaction_id`. We do not model the
    // Deferred Credential Endpoint (documented scope cut) → a distinct `Deferred` failure, never a
    // confusing "missing credentials" parse error and never a silent accept.
    let session = drive_to_credential_pending();
    let (_session, step) = resume_obtain(
        session,
        ResumeObtain::Http {
            status: 202,
            body: serde_json::to_vec(&json!({ "transaction_id": "8xLOxBtZp8", "interval": 3600 }))
                .unwrap(),
        },
    )
    .unwrap();
    let ObtainStep::Failed(super::ObtainError::Deferred(tx)) = step else {
        panic!("expected a Deferred failure, got {step:?}");
    };
    assert_eq!(tx, "8xLOxBtZp8");
}

#[test]
fn an_unexpected_resume_input_is_a_usage_error() {
    let (session, _) = begin_obtain(an_offer(), reference_backend(), holder_ctx(), NOW);
    // TokenPending awaits an HTTP result; a Signature is the wrong input.
    let err = resume_obtain(session, ResumeObtain::Signature(vec![0u8; 64])).unwrap_err();
    assert!(matches!(err, super::ObtainError::UnexpectedInput));
}

#[test]
fn mdoc_credential_response_is_parsed_from_base64url() {
    // The issuer double returns an mdoc credential as base64url CBOR inside the 1.0 `credentials`
    // array; the SDK decodes it to a held mdoc (the obtain path is format-aware via the offer).
    use crate::mdoc::test_issuer::MdocBuilder;
    let device_response = MdocBuilder::new().build();
    let offer = CredentialOffer {
        pre_authorized_code: crate::secret::Secret::new("p"),
        credential_configuration_id: "eu.europa.ec.eudi.pid_mdoc".to_owned(),
        format: Format::Mdoc,
        tx_code: None,
    };
    let session = drive_offer_to_credential_pending(offer);
    let credential = json!({
        "credentials": [{ "credential": Base64UrlUnpadded::encode_string(&device_response) }]
    });
    let (_session, step) =
        resume_obtain(session, http_ok(serde_json::to_vec(&credential).unwrap())).unwrap();
    match expect_obtained(step) {
        HeldAttestation::Mdoc {
            device_response: dr,
        } => assert_eq!(dr, device_response),
        HeldAttestation::SdJwtVc { .. } => panic!("expected an mdoc"),
    }
}

#[test]
fn token_response_without_an_access_token_fails() {
    let (session, _) = begin_obtain(an_offer(), reference_backend(), holder_ctx(), NOW);
    // 200 but no access_token → a clean TokenRequest failure (never a panic / silent accept).
    let (_session, step) = resume_obtain(
        session,
        http_ok(serde_json::to_vec(&json!({ "token_type": "Bearer" })).unwrap()),
    )
    .unwrap();
    assert!(matches!(
        step,
        ObtainStep::Failed(super::ObtainError::TokenRequest(_))
    ));
}

#[test]
fn token_response_with_non_json_body_fails() {
    let (session, _) = begin_obtain(an_offer(), reference_backend(), holder_ctx(), NOW);
    let (_session, step) = resume_obtain(session, http_ok(b"not json".to_vec())).unwrap();
    assert!(matches!(
        step,
        ObtainStep::Failed(super::ObtainError::TokenRequest(_))
    ));
}

#[test]
fn credential_response_without_a_credential_member_fails() {
    let session = drive_to_credential_pending();
    let (_session, step) = resume_obtain(
        session,
        http_ok(serde_json::to_vec(&json!({ "foo": "bar" })).unwrap()),
    )
    .unwrap();
    assert!(matches!(
        step,
        ObtainStep::Failed(super::ObtainError::CredentialRequest(_))
    ));
}

#[test]
fn mdoc_credential_with_bad_base64url_fails() {
    let offer = CredentialOffer {
        pre_authorized_code: crate::secret::Secret::new("p"),
        credential_configuration_id: "cfg".to_owned(),
        format: Format::Mdoc,
        tx_code: None,
    };
    let session = drive_offer_to_credential_pending(offer);
    let body =
        serde_json::to_vec(&json!({ "credentials": [{ "credential": "@@not-base64url@@" }] }))
            .unwrap();
    let (_session, step) = resume_obtain(session, http_ok(body)).unwrap();
    assert!(matches!(
        step,
        ObtainStep::Failed(super::ObtainError::CredentialRequest(_))
    ));
}

/// Drive an SD-JWT VC offer through begin → token → nonce → sign → to the credential-pending phase.
fn drive_to_credential_pending() -> super::ObtainSession {
    drive_offer_to_credential_pending(an_offer())
}

/// Drive the given offer through begin → token → nonce → sign, returning the session at
/// credential-pending. Exercises the full 1.0 leg sequence (token → Nonce Endpoint → PoP).
fn drive_offer_to_credential_pending(offer: CredentialOffer) -> super::ObtainSession {
    let hsm = StubHsm {
        key: SigningKey::from_pkcs8_der(HOLDER_KEY_PK8).expect("holder key"),
    };
    let (session, _) = begin_obtain(offer, reference_backend(), holder_ctx(), NOW);
    let (session, step) = resume_obtain(session, http_ok(token_response())).unwrap();
    let effect = expect_http(step);
    assert!(effect.url.ends_with("/nonce"));
    let (session, step) = resume_obtain(session, http_ok(nonce_response("n"))).unwrap();
    let sig = hsm.sign("h", &expect_sign(step)).unwrap();
    let (session, _) = resume_obtain(session, ResumeObtain::Signature(sig)).unwrap();
    session
}

// --- helpers -------------------------------------------------------------------------------------

fn expect_http(step: ObtainStep) -> super::HttpEffect {
    match step {
        ObtainStep::PerformHttp(e) => e,
        other => panic!("expected PerformHttp, got {other:?}"),
    }
}
fn expect_sign(step: ObtainStep) -> SigningInput {
    match step {
        ObtainStep::Sign(i) => i,
        other => panic!("expected Sign, got {other:?}"),
    }
}
fn expect_obtained(step: ObtainStep) -> HeldAttestation {
    match step {
        ObtainStep::Obtained(h) => h,
        other => panic!("expected Obtained, got {other:?}"),
    }
}

/// Assert a PoP-JWT proof is a valid holder-signed compact JWS over the expected aud/nonce.
fn assert_proof_jwt_valid(jwt: &str, expected_aud: &str, expected_nonce: &str) {
    use p256::ecdsa::signature::Verifier as _;
    let mut parts = jwt.split('.');
    let header_b64 = parts.next().unwrap();
    let payload_b64 = parts.next().unwrap();
    let sig_b64 = parts.next().unwrap();
    let header: Value =
        serde_json::from_slice(&Base64UrlUnpadded::decode_vec(header_b64).unwrap()).unwrap();
    let payload: Value =
        serde_json::from_slice(&Base64UrlUnpadded::decode_vec(payload_b64).unwrap()).unwrap();
    assert_eq!(header["typ"], "openid4vci-proof+jwt");
    assert_eq!(payload["aud"], expected_aud);
    assert_eq!(payload["nonce"], expected_nonce);
    let jwk = &header["jwk"];
    let px = Base64UrlUnpadded::decode_vec(jwk["x"].as_str().unwrap()).unwrap();
    let py = Base64UrlUnpadded::decode_vec(jwk["y"].as_str().unwrap()).unwrap();
    let mut sec1 = vec![0x04];
    sec1.extend_from_slice(&px);
    sec1.extend_from_slice(&py);
    let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).unwrap();
    let sig = Signature::from_slice(&Base64UrlUnpadded::decode_vec(sig_b64).unwrap()).unwrap();
    key.verify(format!("{header_b64}.{payload_b64}").as_bytes(), &sig)
        .expect("proof JWS verifies under the holder key");
}
