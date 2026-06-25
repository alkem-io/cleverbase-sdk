//! OpenID4VCI `obtain` gating + round-trip tests (US2 — task T022, written test-first against T025).
//!
//! Drive the sans-IO `obtain` state machine against an **in-test issuer double** — the OID4VCI
//! responses are constructed in-test (no external `eudi-srv-pid-issuer` required) — and assert:
//!  * `kind = None` → the flow is **skipped** (a clear skipped outcome, never a failure), AND
//!  * `kind = Reference` → the flow yields a conformant SD-JWT VC that **verifies under US1** (the
//!    obtained credential is presentable + cross-checkable via the T017 harness).

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
        credential_endpoint: "https://issuer.example/credential".to_owned(),
        credential_issuer: CREDENTIAL_ISSUER.to_owned(),
    }
}

fn an_offer() -> CredentialOffer {
    CredentialOffer {
        pre_authorized_code: "pre-auth-code-xyz".to_owned(),
        credential_configuration_id: "eu.europa.ec.eudi.pid_vc_sd_jwt".to_owned(),
        format: Format::SdJwtVc,
    }
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

    // 2. token response (in-test issuer double) → the Sign effect (the PoP proof input).
    let token = json!({ "access_token": "issuer-access-token", "c_nonce": "issuer-c-nonce-1" });
    let (session, step) = resume_obtain(
        session,
        ResumeObtain::Http {
            status: 200,
            body: serde_json::to_vec(&token).unwrap(),
        },
    )
    .unwrap();
    let sign_input = expect_sign(step);
    // The PoP proof exposes the credential-issuer aud + the issuer c_nonce for host inspection.
    assert_eq!(sign_input.audience(), CREDENTIAL_ISSUER);
    assert_eq!(sign_input.nonce(), "issuer-c-nonce-1");

    // 3. the host (stub HSM) signs the PoP input → the credential-endpoint POST with the proof.
    let signature = hsm.sign("holder-handle", &sign_input).unwrap();
    let (session, step) = resume_obtain(session, ResumeObtain::Signature(signature)).unwrap();
    let effect = expect_http(step);
    assert!(effect.url.ends_with("/credential"));
    let req: Value = serde_json::from_slice(&effect.body).unwrap();
    // The credential request carries the holder PoP as a `jwt` proof; verify the proof is a real,
    // holder-signed compact JWS over the issuer aud/c_nonce (the issuer double would check this).
    let proof_jwt = req["proof"]["jwt"].as_str().expect("jwt proof");
    assert_proof_jwt_valid(proof_jwt, CREDENTIAL_ISSUER, "issuer-c-nonce-1");

    // 4. the issuer double mints + returns a conformant SD-JWT VC bound to the holder cnf.
    let minted = mint_sd_jwt(ISSUER_KEY_PK8, ISSUER_CERT_DER).presentation();
    let credential_response = json!({ "credential": minted });
    let (_session, step) = resume_obtain(
        session,
        ResumeObtain::Http {
            status: 200,
            body: serde_json::to_vec(&credential_response).unwrap(),
        },
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
    });
    assert!(
        result.valid,
        "obtained credential must verify under US1; reasons {:?}",
        result.reasons
    );
    assert!(result.disclosed_attributes.contains_key("given_name"));
}

// --- Secret handling: the bearer token never leaks via Debug (FR-010 / Constitution IV) ----------

#[test]
fn obtain_session_debug_does_not_leak_the_access_token_or_c_nonce() {
    // Drive begin → token, so the session holds the OAuth access token + the issuer c_nonce.
    let (session, _step) = begin_obtain(an_offer(), reference_backend(), holder_ctx(), NOW);
    let access_token = "super-secret-bearer-token-xyz";
    let c_nonce = "issuer-one-time-c-nonce-abc";
    let token = json!({ "access_token": access_token, "c_nonce": c_nonce });
    let (session, _step) = resume_obtain(
        session,
        ResumeObtain::Http {
            status: 200,
            body: serde_json::to_vec(&token).unwrap(),
        },
    )
    .unwrap();

    // Formatting the session (a log line / panic message) must NOT print the bearer token or the
    // one-time nonce — they are held as redacting `Secret`s.
    let dbg = format!("{session:?}");
    assert!(
        !dbg.contains(access_token),
        "the access token must never appear in Debug output: {dbg}"
    );
    assert!(
        !dbg.contains(c_nonce),
        "the one-time c_nonce must never appear in Debug output: {dbg}"
    );
    assert!(
        dbg.contains("Secret(***)"),
        "the redacted secret marker must be present: {dbg}"
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
fn credential_endpoint_failure_is_a_terminal_failure() {
    let hsm = StubHsm {
        key: SigningKey::from_pkcs8_der(HOLDER_KEY_PK8).expect("holder key"),
    };
    let (session, _) = begin_obtain(an_offer(), reference_backend(), holder_ctx(), NOW);
    let token = json!({ "access_token": "t", "c_nonce": "n" });
    let (session, step) = resume_obtain(
        session,
        ResumeObtain::Http {
            status: 200,
            body: serde_json::to_vec(&token).unwrap(),
        },
    )
    .unwrap();
    let sig = hsm.sign("h", &expect_sign(step)).unwrap();
    let (session, _) = resume_obtain(session, ResumeObtain::Signature(sig)).unwrap();
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
fn an_unexpected_resume_input_is_a_usage_error() {
    let (session, _) = begin_obtain(an_offer(), reference_backend(), holder_ctx(), NOW);
    // TokenPending awaits an HTTP result; a Signature is the wrong input.
    let err = resume_obtain(session, ResumeObtain::Signature(vec![0u8; 64])).unwrap_err();
    assert!(matches!(err, super::ObtainError::UnexpectedInput));
}

#[test]
fn mdoc_credential_response_is_parsed_from_base64url() {
    // The issuer double returns an mdoc credential as base64url CBOR; the SDK decodes it to a held
    // mdoc (the obtain path is format-aware via the offer).
    use crate::mdoc::test_issuer::MdocBuilder;
    let device_response = MdocBuilder::new().build();
    let offer = CredentialOffer {
        pre_authorized_code: "p".to_owned(),
        credential_configuration_id: "eu.europa.ec.eudi.pid_mdoc".to_owned(),
        format: Format::Mdoc,
    };
    let hsm = StubHsm {
        key: SigningKey::from_pkcs8_der(HOLDER_KEY_PK8).expect("holder key"),
    };
    let (session, _) = begin_obtain(offer, reference_backend(), holder_ctx(), NOW);
    let token = json!({ "access_token": "t", "c_nonce": "n" });
    let (session, step) = resume_obtain(
        session,
        ResumeObtain::Http {
            status: 200,
            body: serde_json::to_vec(&token).unwrap(),
        },
    )
    .unwrap();
    let sig = hsm.sign("h", &expect_sign(step)).unwrap();
    let (session, _) = resume_obtain(session, ResumeObtain::Signature(sig)).unwrap();
    let credential = json!({ "credential": Base64UrlUnpadded::encode_string(&device_response) });
    let (_session, step) = resume_obtain(
        session,
        ResumeObtain::Http {
            status: 200,
            body: serde_json::to_vec(&credential).unwrap(),
        },
    )
    .unwrap();
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
        ResumeObtain::Http {
            status: 200,
            body: serde_json::to_vec(&json!({ "c_nonce": "n" })).unwrap(),
        },
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
    let (_session, step) = resume_obtain(
        session,
        ResumeObtain::Http {
            status: 200,
            body: b"not json".to_vec(),
        },
    )
    .unwrap();
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
        ResumeObtain::Http {
            status: 200,
            body: serde_json::to_vec(&json!({ "foo": "bar" })).unwrap(),
        },
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
        pre_authorized_code: "p".to_owned(),
        credential_configuration_id: "cfg".to_owned(),
        format: Format::Mdoc,
    };
    let session = drive_offer_to_credential_pending(offer);
    let (_session, step) = resume_obtain(
        session,
        ResumeObtain::Http {
            status: 200,
            body: serde_json::to_vec(&json!({ "credential": "@@not-base64url@@" })).unwrap(),
        },
    )
    .unwrap();
    assert!(matches!(
        step,
        ObtainStep::Failed(super::ObtainError::CredentialRequest(_))
    ));
}

/// Drive an SD-JWT VC offer through begin → token → sign → to the credential-pending phase.
fn drive_to_credential_pending() -> super::ObtainSession {
    drive_offer_to_credential_pending(an_offer())
}

/// Drive the given offer through begin → token → sign, returning the session at credential-pending.
fn drive_offer_to_credential_pending(offer: CredentialOffer) -> super::ObtainSession {
    let hsm = StubHsm {
        key: SigningKey::from_pkcs8_der(HOLDER_KEY_PK8).expect("holder key"),
    };
    let (session, _) = begin_obtain(offer, reference_backend(), holder_ctx(), NOW);
    let token = json!({ "access_token": "t", "c_nonce": "n" });
    let (session, step) = resume_obtain(
        session,
        ResumeObtain::Http {
            status: 200,
            body: serde_json::to_vec(&token).unwrap(),
        },
    )
    .unwrap();
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
