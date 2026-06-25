//! Versioned CBOR wire envelope for the **issuance** C-ABI surface (US2 — task T028).
//!
//! Mirrors the `verify` envelope (`crate::wire`) and `cleverbase_core::wire`: the C-ABI and the
//! non-native bindings exchange these CBOR-encoded envelopes; native callers use the typed Rust API
//! ([`super::begin_obtain`] / [`super::resume_obtain`] / [`super::prepare_present`]) directly.
//!
//! The issuance flow is **sans-IO + host-effect-driven** (mirroring the signing core's begin/resume),
//! so the wire carries the same shape: an [`IssuanceOp`] (one of `BeginObtain`, `ResumeObtain`,
//! `BeginPresent`, `FinishPresent`) in, and the next step ([`WireObtainStep`], or the `PreparePresent`
//! / `Present` outcome) plus the opaque session/prepared **handle** out. The holder key never crosses
//! this boundary: a `Sign` effect surfaces the [`SigningInput`] the host signs out-of-process, and
//! the host feeds the raw `r‖s` signature back via a resume op.
//!
//! This is a **separate, additive** envelope from the `verify` one (which stays at its own schema
//! version), surfaced by a new C-ABI function — so the verifier surface is untouched (Principle VII).

use serde::{Deserialize, Serialize};

use super::obtain::{
    begin_obtain, resume_obtain, CredentialOffer, HttpEffect, IssuerBackend, ObtainSession,
    ObtainStep, ResumeObtain,
};
use super::present::{prepare_present, HeldAttestation, HolderPresentation, PreparedPresentation};
use super::signer::{HolderContext, SigningInput};
use crate::openid4vp::PresentationRequest;

/// Wire schema version of the **issuance** envelope (independent of the `verify` envelope's
/// `ATTESTATION_SCHEMA_VERSION` and the signing core's `SCHEMA_VERSION`). Version 1 is the initial
/// `obtain`/`present` surface.
pub const ISSUANCE_SCHEMA_VERSION: u32 = 1;

/// An issuance operation carried on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssuanceOp {
    /// Begin an OpenID4VCI `obtain` flow (the offer + the configured backend + the holder context).
    BeginObtain {
        /// The OpenID4VCI credential offer (pre-authorized-code path).
        offer: CredentialOffer,
        /// The configured issuer backend (`None` → the flow is skipped).
        backend: IssuerBackend,
        /// The holder context (public key + key handle; no private key).
        holder: HolderContext,
        /// The issuance instant (Unix seconds) — the PoP-JWT `iat`.
        now_unix: i64,
    },
    /// Resume an `obtain` flow with the result of the last effect (an HTTP response, or the holder
    /// PoP signature).
    ResumeObtain {
        /// The opaque session handle returned by the previous `obtain` step.
        session: ObtainSession,
        /// The resume input (HTTP response or holder signature).
        input: WireResumeObtain,
    },
    /// Begin a holder OpenID4VP `present` flow — prepare the presentation up to the holder signature
    /// (the returned `Sign` effect).
    BeginPresent {
        /// The held attestation to present.
        held: HeldAttestation,
        /// The verifier's OpenID4VP request (`nonce` + `audience`) to bind to.
        request: PresentationRequest,
        /// The claim names to disclose (only these are revealed).
        disclose: Vec<String>,
        /// The holder's signing instant (the KB-JWT `iat`).
        iat: i64,
    },
    /// Finish a `present` flow by splicing the holder signature into the `vp_token`.
    FinishPresent {
        /// The opaque prepared-presentation handle returned by `BeginPresent`.
        prepared: PreparedPresentation,
        /// The raw `r‖s` ES256 holder signature over the prepared signing input.
        #[serde(with = "serde_bytes")]
        signature: Vec<u8>,
    },
}

/// The resume input for an `obtain` flow, on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WireResumeObtain {
    /// The response to a prior HTTP effect.
    Http {
        /// HTTP status code.
        status: u16,
        /// Response body bytes.
        #[serde(with = "serde_bytes")]
        body: Vec<u8>,
    },
    /// The raw `r‖s` ES256 holder PoP signature for a prior `Sign` effect.
    Signature {
        /// The signature bytes.
        #[serde(with = "serde_bytes")]
        signature: Vec<u8>,
    },
}

/// The next step of an `obtain` flow, on the wire (the CBOR mirror of [`ObtainStep`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WireObtainStep {
    /// Perform this HTTP request, then resume with the response.
    PerformHttp {
        /// The HTTP effect.
        effect: HttpEffect,
    },
    /// Sign this PoP input with the holder key, then resume with the signature.
    Sign {
        /// The signing input (exposes the issuer `aud`/`c_nonce`).
        input: SigningInput,
    },
    /// Terminal: the flow was skipped (no issuer API configured).
    Skipped,
    /// Terminal: the obtained credential.
    Obtained {
        /// The held attestation.
        held: HeldAttestation,
    },
    /// Terminal: a protocol failure (rendered as a message).
    Failed {
        /// The failure message.
        message: String,
    },
}

impl WireObtainStep {
    fn from_step(step: ObtainStep) -> Self {
        match step {
            ObtainStep::PerformHttp(effect) => Self::PerformHttp { effect },
            ObtainStep::Sign(input) => Self::Sign { input },
            ObtainStep::Skipped => Self::Skipped,
            ObtainStep::Obtained(held) => Self::Obtained { held },
            ObtainStep::Failed(e) => Self::Failed {
                message: e.to_string(),
            },
        }
    }
}

/// The outcome of an issuance operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssuanceOutcome {
    /// An `obtain` step: the next step + the (opaque) session handle to carry into the next resume.
    Obtain {
        /// The next step / terminal outcome.
        step: WireObtainStep,
        /// The session handle to carry into the next `ResumeObtain` (absent on a terminal step).
        session: Option<ObtainSession>,
    },
    /// A `BeginPresent` step: the `Sign` input + the opaque prepared handle to carry into
    /// `FinishPresent`.
    PreparePresent {
        /// The signing input the host must sign.
        input: SigningInput,
        /// The prepared-presentation handle to carry into `FinishPresent`.
        prepared: PreparedPresentation,
    },
    /// A `FinishPresent` step: the produced `vp_token`.
    Present {
        /// The holder presentation (`vp_token`).
        presentation: HolderPresentation,
    },
    /// A decode/usage error rendered as a message.
    Err {
        /// Human-readable error message.
        message: String,
    },
}

/// An issuance request envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuanceRequest {
    /// Wire schema version.
    pub schema_version: u32,
    /// The issuance operation.
    pub op: IssuanceOp,
}

/// An issuance response envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuanceResponse {
    /// Wire schema version.
    pub schema_version: u32,
    /// The operation outcome.
    pub outcome: IssuanceOutcome,
}

/// Decode an issuance request envelope, rejecting unknown schema versions.
///
/// # Errors
///
/// Returns the decode error (or a schema-version mismatch message) as a `String`.
pub fn decode_issuance_request(bytes: &[u8]) -> Result<IssuanceRequest, String> {
    let req: IssuanceRequest = ciborium::from_reader(bytes).map_err(|e| e.to_string())?;
    if req.schema_version != ISSUANCE_SCHEMA_VERSION {
        return Err(format!(
            "unsupported issuance schema_version {} (this core speaks {ISSUANCE_SCHEMA_VERSION})",
            req.schema_version
        ));
    }
    Ok(req)
}

/// Encode an issuance response envelope at the current schema version.
#[must_use]
pub fn encode_issuance_response(outcome: IssuanceOutcome) -> Vec<u8> {
    let resp = IssuanceResponse {
        schema_version: ISSUANCE_SCHEMA_VERSION,
        outcome,
    };
    // Infallible (no error channel on this helper): the shared `cbor_to_vec` encodes a plain serde
    // value into an in-memory Vec, which cannot fail (DRY — one authoritative CBOR-into-Vec helper).
    crate::cbor_to_vec(&resp)
}

/// Map a wire resume input to the typed [`ResumeObtain`].
fn resume_from_wire(input: WireResumeObtain) -> ResumeObtain {
    match input {
        WireResumeObtain::Http { status, body } => ResumeObtain::Http { status, body },
        WireResumeObtain::Signature { signature } => ResumeObtain::Signature(signature),
    }
}

/// Run one issuance operation, returning its outcome.
fn dispatch(op: IssuanceOp) -> IssuanceOutcome {
    match op {
        IssuanceOp::BeginObtain {
            offer,
            backend,
            holder,
            now_unix,
        } => {
            let (session, step) = begin_obtain(offer, backend, holder, now_unix);
            obtain_outcome(session, step)
        }
        IssuanceOp::ResumeObtain { session, input } => {
            match resume_obtain(session, resume_from_wire(input)) {
                Ok((session, step)) => obtain_outcome(session, step),
                Err(e) => IssuanceOutcome::Err {
                    message: e.to_string(),
                },
            }
        }
        IssuanceOp::BeginPresent {
            held,
            request,
            disclose,
            iat,
        } => {
            let disclose_set = disclose.into_iter().collect();
            match prepare_present(&held, &request, &disclose_set, iat) {
                Ok(prepared) => IssuanceOutcome::PreparePresent {
                    input: prepared.signing_input().clone(),
                    prepared,
                },
                Err(e) => IssuanceOutcome::Err {
                    message: e.to_string(),
                },
            }
        }
        IssuanceOp::FinishPresent {
            prepared,
            signature,
        } => match prepared.finish(&signature) {
            Ok(presentation) => IssuanceOutcome::Present { presentation },
            Err(e) => IssuanceOutcome::Err {
                message: e.to_string(),
            },
        },
    }
}

/// Build an `Obtain` outcome, dropping the session handle on a terminal step (nothing to resume).
fn obtain_outcome(session: ObtainSession, step: ObtainStep) -> IssuanceOutcome {
    let terminal = step.is_terminal();
    IssuanceOutcome::Obtain {
        step: WireObtainStep::from_step(step),
        session: if terminal { None } else { Some(session) },
    }
}

/// Decode → dispatch → encode. Pure; shared by the C-ABI, language bindings, and tests (single source
/// of truth — Principle III).
#[must_use]
pub fn process_issuance_bytes(input: &[u8]) -> Vec<u8> {
    let outcome = match decode_issuance_request(input) {
        Ok(req) => dispatch(req.op),
        Err(message) => IssuanceOutcome::Err { message },
    };
    encode_issuance_response(outcome)
}

#[cfg(test)]
mod tests;
