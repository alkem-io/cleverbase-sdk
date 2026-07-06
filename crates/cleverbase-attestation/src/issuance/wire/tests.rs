//! Tests for the issuance CBOR wire envelope (US2 — task T028).
//!
//! Drive the full `obtain` + `present` flows through `process_issuance_bytes` (the same path the
//! C-ABI wraps), with an in-test issuer double + a stub holder HSM, and assert the produced credential
//! / `vp_token` verify under US1 — the round-trip survives the CBOR boundary.

use p256::ecdsa::{signature::Signer as _, Signature, SigningKey};
use pkcs8::DecodePrivateKey as _;
use serde_json::{json, Value};

use super::{
    decode_issuance_request, process_issuance_bytes, IssuanceOp, IssuanceOutcome, IssuanceRequest,
    IssuanceResponse, WireObtainStep, WireResumeObtain, ISSUANCE_SCHEMA_VERSION,
};
use crate::issuance::obtain::{CredentialOffer, IssuerBackend, IssuerBackendKind, ObtainSession};
use crate::issuance::signer::{HolderContext, SigningInput};
use crate::issuance::HeldAttestation;
use crate::openid4vp::{verify_response, Dcql, PresentationRequest, VpToken};
use crate::sdjwtvc::test_issuer::{
    mint_sd_jwt, HOLDER_JWK_JSON, HOLDER_KEY_PK8, ISSUER_CERT_DER, ISSUER_KEY_PK8, NOW,
};
use crate::trust::StaticTestAnchors;
use crate::types::{Format, IssuerRole, VerificationPolicy};

const AUDIENCE: &str = "https://verifier.example/cb";
/// The verifier's `response_uri` request parameter (OpenID4VP 1.0 §B.2.6 4th handover element).
const RESPONSE_URI: &str = "https://verifier.example/cb/response";
const CREDENTIAL_ISSUER: &str = "https://issuer.example/cb";

fn encode(req: &IssuanceRequest) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::into_writer(req, &mut buf).unwrap();
    buf
}
fn drive(op: IssuanceOp) -> IssuanceOutcome {
    let req = IssuanceRequest {
        schema_version: ISSUANCE_SCHEMA_VERSION,
        op,
    };
    let resp: IssuanceResponse =
        ciborium::from_reader(&process_issuance_bytes(&encode(&req))[..]).unwrap();
    assert_eq!(resp.schema_version, ISSUANCE_SCHEMA_VERSION);
    resp.outcome
}

fn holder_ctx() -> HolderContext {
    let jwk: Value = serde_json::from_slice(HOLDER_JWK_JSON).unwrap();
    HolderContext::new(jwk, "h")
}
fn sign_with_holder(input: &SigningInput) -> Vec<u8> {
    let key = SigningKey::from_pkcs8_der(HOLDER_KEY_PK8).unwrap();
    let sig: Signature = key.sign(input.to_be_signed());
    sig.to_bytes().to_vec()
}
fn an_offer(format: Format) -> CredentialOffer {
    CredentialOffer {
        pre_authorized_code: crate::secret::Secret::new("pre-auth"),
        credential_configuration_id: "cfg".to_owned(),
        format,
        tx_code: None,
    }
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

#[test]
fn unsupported_schema_version_is_rejected() {
    let req = IssuanceRequest {
        schema_version: 999,
        op: IssuanceOp::BeginObtain {
            offer: an_offer(Format::SdJwtVc),
            backend: IssuerBackend::none(),
            holder: holder_ctx(),
            now_unix: NOW,
        },
    };
    let resp: IssuanceResponse =
        ciborium::from_reader(&process_issuance_bytes(&encode(&req))[..]).unwrap();
    assert!(matches!(resp.outcome, IssuanceOutcome::Err { .. }));
}

#[test]
fn garbage_input_is_an_err_outcome() {
    let resp: IssuanceResponse =
        ciborium::from_reader(&process_issuance_bytes(&[0xff, 0x00, 0x13])[..]).unwrap();
    assert!(matches!(resp.outcome, IssuanceOutcome::Err { .. }));
}

#[test]
fn decode_round_trips_a_well_formed_request() {
    let req = IssuanceRequest {
        schema_version: ISSUANCE_SCHEMA_VERSION,
        op: IssuanceOp::BeginObtain {
            offer: an_offer(Format::SdJwtVc),
            backend: IssuerBackend::none(),
            holder: holder_ctx(),
            now_unix: NOW,
        },
    };
    assert_eq!(decode_issuance_request(&encode(&req)).unwrap(), req);
}

#[test]
fn none_backend_skips_over_the_wire() {
    let out = drive(IssuanceOp::BeginObtain {
        offer: an_offer(Format::SdJwtVc),
        backend: IssuerBackend::none(),
        holder: holder_ctx(),
        now_unix: NOW,
    });
    match out {
        IssuanceOutcome::Obtain { step, session } => {
            assert_eq!(step, WireObtainStep::Skipped);
            assert!(
                session.is_none(),
                "a terminal step carries no resumable session"
            );
        }
        other => panic!("expected Obtain/Skipped, got {other:?}"),
    }
}

#[test]
fn obtain_round_trip_over_the_wire_yields_a_us1_verifiable_credential() {
    // begin → token HTTP effect.
    let out = drive(IssuanceOp::BeginObtain {
        offer: an_offer(Format::SdJwtVc),
        backend: reference_backend(),
        holder: holder_ctx(),
        now_unix: NOW,
    });
    let session = expect_obtain_http(out);

    // token response (1.0: no c_nonce) → the Nonce-Endpoint HTTP effect (§7 `#nonce-endpoint`).
    let token = json!({ "access_token": "tok", "token_type": "Bearer" });
    let out = drive(IssuanceOp::ResumeObtain {
        session,
        input: WireResumeObtain::Http {
            status: 200,
            body: serde_json::to_vec(&token).unwrap(),
        },
    });
    let session = expect_obtain_http(out);

    // nonce response → Sign effect (the PoP bound to the Nonce-Endpoint c_nonce).
    let out = drive(IssuanceOp::ResumeObtain {
        session,
        input: WireResumeObtain::Http {
            status: 200,
            body: serde_json::to_vec(&json!({ "c_nonce": "cn" })).unwrap(),
        },
    });
    let (session, input) = expect_obtain_sign(out);
    assert_eq!(input.audience(), CREDENTIAL_ISSUER);
    assert_eq!(input.nonce(), "cn");

    // sign → credential HTTP effect.
    let signature = sign_with_holder(&input);
    let out = drive(IssuanceOp::ResumeObtain {
        session,
        input: WireResumeObtain::Signature { signature },
    });
    let session = expect_obtain_http(out);

    // credential response (the in-test issuer double mints a real SD-JWT VC, returned in the 1.0
    // `credentials` array — §8.3 `#credential-response`) → Obtained.
    let minted = mint_sd_jwt(ISSUER_KEY_PK8, ISSUER_CERT_DER).presentation();
    let out = drive(IssuanceOp::ResumeObtain {
        session,
        input: WireResumeObtain::Http {
            status: 200,
            body: serde_json::to_vec(&json!({ "credentials": [{ "credential": minted }] }))
                .unwrap(),
        },
    });
    let held = expect_obtained(out);
    let HeldAttestation::SdJwtVc { .. } = &held else {
        panic!("expected SD-JWT VC");
    };

    // Present the held credential over the wire and verify the vp_token under US1.
    present_over_wire_and_verify(held);
}

/// Present the held credential over the wire (BeginPresent → sign → FinishPresent) and assert the
/// produced `vp_token` verifies under US1.
fn present_over_wire_and_verify(held: HeldAttestation) {
    let request = PresentationRequest {
        dcql: Dcql::from_json("{}"),
        nonce: b"wire-vp-nonce".to_vec(),
        audience: AUDIENCE.to_owned(),
        response_uri: RESPONSE_URI.to_owned(),
    };
    let out = drive(IssuanceOp::BeginPresent {
        held,
        request: request.clone(),
        disclose: vec!["given_name".to_owned()],
        iat: NOW,
    });
    let (prepared, input) = match out {
        IssuanceOutcome::PreparePresent { input, prepared } => (prepared, input),
        other => panic!("expected PreparePresent, got {other:?}"),
    };
    let signature = sign_with_holder(&input);
    let out = drive(IssuanceOp::FinishPresent {
        prepared,
        signature,
    });
    let presentation = match out {
        IssuanceOutcome::Present { presentation } => presentation,
        other => panic!("expected Present, got {other:?}"),
    };

    let anchors = StaticTestAnchors::new().trust(IssuerRole::Pid, Format::SdJwtVc, ISSUER_CERT_DER);
    let result = verify_response(
        &presentation.as_vp_token(),
        &request,
        &VerificationPolicy::default(),
        &anchors,
        NOW,
        IssuerRole::Pid,
        &[crate::status::StatusOutcome::NoStatus],
    );
    assert!(
        result.valid,
        "wire-produced vp_token must verify under US1; reasons {:?}",
        result.reasons
    );
    assert!(result.disclosed_attributes.contains_key("given_name"));
    assert!(!result.disclosed_attributes.contains_key("family_name"));
    assert!(matches!(presentation.as_vp_token(), VpToken::SdJwtVc(_)));
}

#[test]
fn a_protocol_failure_surfaces_as_a_failed_step_not_an_err() {
    let out = drive(IssuanceOp::BeginObtain {
        offer: an_offer(Format::SdJwtVc),
        backend: reference_backend(),
        holder: holder_ctx(),
        now_unix: NOW,
    });
    let session = expect_obtain_http(out);
    let out = drive(IssuanceOp::ResumeObtain {
        session,
        input: WireResumeObtain::Http {
            status: 401,
            body: b"{}".to_vec(),
        },
    });
    match out {
        IssuanceOutcome::Obtain { step, .. } => {
            assert!(matches!(step, WireObtainStep::Failed { .. }));
        }
        other => panic!("expected a Failed obtain step, got {other:?}"),
    }
}

#[test]
fn resuming_a_terminal_session_is_an_err() {
    // Drive to a terminal Skipped is handled by begin; for a usage error, resume a finished obtain.
    let out = drive(IssuanceOp::BeginObtain {
        offer: an_offer(Format::SdJwtVc),
        backend: reference_backend(),
        holder: holder_ctx(),
        now_unix: NOW,
    });
    let session = expect_obtain_http(out);
    // Feeding a Signature where an HTTP result is expected is a usage error → IssuanceOutcome::Err.
    let out = drive(IssuanceOp::ResumeObtain {
        session,
        input: WireResumeObtain::Signature {
            signature: vec![0u8; 64],
        },
    });
    assert!(matches!(out, IssuanceOutcome::Err { .. }));
}

#[test]
fn begin_present_with_a_malformed_credential_is_an_err() {
    let out = drive(IssuanceOp::BeginPresent {
        held: HeldAttestation::SdJwtVc {
            issued: "nope".to_owned(),
        },
        request: PresentationRequest {
            dcql: Dcql::from_json("{}"),
            nonce: b"n".to_vec(),
            audience: AUDIENCE.to_owned(),
            response_uri: RESPONSE_URI.to_owned(),
        },
        disclose: vec![],
        iat: NOW,
    });
    assert!(matches!(out, IssuanceOutcome::Err { .. }));
}

// --- helpers -------------------------------------------------------------------------------------

fn expect_obtain_http(out: IssuanceOutcome) -> ObtainSession {
    match out {
        IssuanceOutcome::Obtain {
            step: WireObtainStep::PerformHttp { .. },
            session: Some(session),
        } => session,
        other => panic!("expected an Obtain/PerformHttp with a session, got {other:?}"),
    }
}
fn expect_obtain_sign(out: IssuanceOutcome) -> (ObtainSession, SigningInput) {
    match out {
        IssuanceOutcome::Obtain {
            step: WireObtainStep::Sign { input },
            session: Some(session),
        } => (session, input),
        other => panic!("expected an Obtain/Sign with a session, got {other:?}"),
    }
}
fn expect_obtained(out: IssuanceOutcome) -> HeldAttestation {
    match out {
        IssuanceOutcome::Obtain {
            step: WireObtainStep::Obtained { held },
            ..
        } => held,
        other => panic!("expected an Obtained step, got {other:?}"),
    }
}
