//! OpenID4VCI `obtain` — a sans-IO, host-effect-driven issuance state machine (US2 — task T025).
//!
//! Mirrors the signing core's `begin`/`resume` + `Step`/effect shape (research D8, Principle III):
//! [`begin_obtain`] starts the OpenID4VCI ceremony and [`resume_obtain`] advances it given the result
//! of the last host effect. The core performs **no I/O**; it returns an [`ObtainStep`] describing what
//! the host must do next — an HTTP request, or a **holder sign** (the PoP proof, the exact analogue of
//! the CSC `signHash` effect: the host's HSM signs the SDK-built `signing_input` and feeds the bytes
//! back; the SDK splices them).
//!
//! ## Configurable backend + skip-when-`None` gating (FR-008)
//!
//! The issuer is an [`IssuerBackend`] with a [`kind`](IssuerBackendKind): `None` (default) → the flow
//! is **skipped** ([`ObtainStep::Skipped`], a clear skipped outcome, **never a failure**); `Reference`
//! → the EU `eudi-srv-pid-issuer` test double; `Cleverbase` → a future drop-in (enabled by
//! configuration only). The flow logic is identical across `Reference`/`Cleverbase` — only the
//! endpoints differ — so a future Cleverbase issuer needs no rework of the holder flow (SC-005).
//!
//! ## Flow (pre-authorized-code grant)
//!
//! `credential offer (pre-authorized_code)` → POST token endpoint → `Sign` the OpenID4VCI proof-JWT
//! (PoP) via the signer-hook → POST credential endpoint with the proof → parse the issued SD-JWT VC /
//! mdoc into a [`HeldAttestation`]. The pre-authorized-code grant is the self-contained flow the
//! reference issuer supports without an interactive browser leg.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::secret::Secret;

use super::present::HeldAttestation;
use super::signer::{HolderContext, SigningInput};
use crate::types::Format;

/// HTTP method for an [`HttpEffect`] (the issuance flow uses POST for both endpoints).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    /// HTTP GET.
    Get,
    /// HTTP POST.
    Post,
}

/// An HTTP request the host must perform on the core's behalf (mirrors the signing core's
/// `HttpEffect`; the core stays sans-IO). The host performs it and feeds the response back via
/// [`resume_obtain`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpEffect {
    /// HTTP method.
    pub method: HttpMethod,
    /// Absolute request URL.
    pub url: String,
    /// Request headers as `(name, value)` pairs.
    pub headers: Vec<(String, String)>,
    /// Request body bytes (form-encoded for the token endpoint; JSON for the credential endpoint).
    #[serde(default, with = "serde_bytes")]
    pub body: Vec<u8>,
}

/// Which issuer API the flow targets (data-model.md `IssuerBackend.kind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssuerBackendKind {
    /// No issuer API configured — the issuance path is **skipped** (the default; Cleverbase ships no
    /// EUDI issuer API today, so this is the honest default — FR-008/SC-006).
    #[default]
    None,
    /// The EU `eudi-srv-pid-issuer` reference test double (issues SD-JWT VC + mso_mdoc).
    Reference,
    /// A future Cleverbase EUDI issuer API — a drop-in enabled by configuration only (SC-005).
    Cleverbase,
}

/// The configured issuer backend: the [`kind`](IssuerBackendKind) plus the OpenID4VCI endpoints the
/// flow drives (ignored when `kind = None`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuerBackend {
    /// Which issuer API this backend targets.
    pub kind: IssuerBackendKind,
    /// The OpenID4VCI **token** endpoint (the pre-authorized-code grant is exchanged here).
    pub token_endpoint: String,
    /// The OpenID4VCI **credential** endpoint (the credential request — with the PoP proof — is POSTed
    /// here).
    pub credential_endpoint: String,
    /// The credential-issuer identifier the PoP-JWT `aud` must be addressed to.
    pub credential_issuer: String,
}

impl IssuerBackend {
    /// A `None` backend — issuance is skipped (the default; no endpoints needed).
    #[must_use]
    pub fn none() -> Self {
        Self {
            kind: IssuerBackendKind::None,
            token_endpoint: String::new(),
            credential_endpoint: String::new(),
            credential_issuer: String::new(),
        }
    }
}

/// An OpenID4VCI credential offer (the pre-authorized-code path — the self-contained grant the
/// reference issuer supports). The `credential_configuration_id` selects which credential to request
/// (and its [`Format`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialOffer {
    /// The OpenID4VCI `pre-authorized_code` from the offer's grant. It is a bearer grant (redeemable
    /// for the credential), so it is held as a redacting [`Secret`] — it never appears in
    /// `Debug`/log/panic output (FR-010, Constitution Principle IV), yet still (de)serializes
    /// transparently so the offer round-trips on the wire and the redemption site percent-encodes the
    /// live value (only the `Debug` exposure was the leak).
    pub pre_authorized_code: Secret,
    /// The credential configuration id to request (e.g. `eu.europa.ec.eudi.pid_vc_sd_jwt`).
    pub credential_configuration_id: String,
    /// The format of the credential this configuration issues (so the SDK parses the right shape).
    pub format: Format,
}

/// The next host effect (or terminal outcome) of an `obtain` step — mirrors the signing core's
/// `Step`. The core returns exactly one of these and advances only when the host feeds the result
/// back via [`resume_obtain`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObtainStep {
    /// Perform this HTTP request, then [`resume_obtain`] with the response.
    PerformHttp(HttpEffect),
    /// **Sign** this PoP-JWT signing input with the holder key (the signer-hook effect — the SDK
    /// never holds the key), then [`resume_obtain`] with the raw `r‖s` ES256 signature. The
    /// [`SigningInput`] exposes the issuer `aud`/`c_nonce` for host policy inspection.
    Sign(SigningInput),
    /// Terminal: the issuance path is **skipped** because no issuer API is configured
    /// (`kind = None`) — a clear skipped outcome, never a failure (FR-008).
    Skipped,
    /// Terminal success: the issued, parsed [`HeldAttestation`] (verifiable under US1).
    Obtained(HeldAttestation),
    /// Terminal failure (a protocol error from the issuer, or a malformed response).
    Failed(ObtainError),
}

impl ObtainStep {
    /// Whether this step is terminal (the flow does not resume past [`Self::Skipped`] /
    /// [`Self::Obtained`] / [`Self::Failed`]).
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Skipped | Self::Obtained(_) | Self::Failed(_))
    }
}

/// A usage/protocol error from the `obtain` flow (distinct from the terminal [`ObtainStep::Failed`]
/// outcome, which carries this).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ObtainError {
    /// The [`ResumeObtain`] input did not match what the current phase expects.
    #[error("unexpected resume input for the current obtain phase")]
    UnexpectedInput,
    /// The session was resumed past a terminal phase.
    #[error("obtain session is already terminal")]
    AlreadyTerminal,
    /// The token endpoint returned a non-success status or an unparseable body.
    #[error("token request failed: {0}")]
    TokenRequest(String),
    /// The credential endpoint returned a non-success status or an unparseable body.
    #[error("credential request failed: {0}")]
    CredentialRequest(String),
    /// The PoP-JWT signing input could not be built.
    #[error("failed to build the proof-of-possession JWT: {0}")]
    Proof(String),
}

/// The result the host feeds back into [`resume_obtain`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResumeObtain {
    /// The response to a prior [`ObtainStep::PerformHttp`].
    Http {
        /// HTTP status code.
        status: u16,
        /// Response body bytes.
        body: Vec<u8>,
    },
    /// The raw `r‖s` ES256 signature for a prior [`ObtainStep::Sign`] (the holder PoP proof).
    Signature(Vec<u8>),
}

/// The phase of an in-flight `obtain` session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum ObtainPhase {
    /// Awaiting the token-endpoint response.
    TokenPending,
    /// Awaiting the holder PoP signature (the `Sign` effect).
    ProofPending,
    /// Awaiting the credential-endpoint response.
    CredentialPending,
    /// Terminal — skipped, obtained, or failed; the flow does not resume past this.
    Terminal,
}

/// An in-flight `obtain` session: the carried state between effects (the analogue of the signing
/// core's `SigningSessionHandle`). Holds **no** private key — only the holder public context, the
/// backend config, and the OpenID4VCI access token + the in-progress PoP material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObtainSession {
    phase: ObtainPhase,
    backend: IssuerBackend,
    holder: HolderContext,
    offer: CredentialOffer,
    now_unix: i64,
    /// The OpenID4VCI access token (set after the token exchange). Held as a redacting [`Secret`] so
    /// the bearer token never appears in `Debug`/log/panic output (FR-010, Constitution Principle IV);
    /// the host still receives it on the wire when the session is CBOR-serialized (by design in the
    /// sans-IO model — only the `Debug` exposure was the leak).
    access_token: Option<Secret>,
    /// The issuer `c_nonce` the PoP-JWT must echo (carried from the token response to the `Sign`
    /// resume, where the deterministic PoP-JWT is rebuilt and the host signature spliced in). Held as
    /// a redacting [`Secret`] so the one-time nonce never appears in `Debug`/log output.
    pending_c_nonce: Option<Secret>,
    /// The compact PoP-JWT spliced after the holder signed its input (set after the `Sign` step).
    proof_jwt: Option<String>,
}

/// Begin an OpenID4VCI `obtain` flow.
///
/// When `backend.kind == None`, returns [`ObtainStep::Skipped`] (the issuance path is skipped, never
/// failed — FR-008) and a session that is already terminal. Otherwise returns the first effect: the
/// token-endpoint POST (the pre-authorized-code grant).
#[must_use]
pub fn begin_obtain(
    offer: CredentialOffer,
    backend: IssuerBackend,
    holder: HolderContext,
    now_unix: i64,
) -> (ObtainSession, ObtainStep) {
    let session = ObtainSession {
        phase: ObtainPhase::TokenPending,
        backend: backend.clone(),
        holder,
        offer: offer.clone(),
        now_unix,
        access_token: None,
        pending_c_nonce: None,
        proof_jwt: None,
    };
    if backend.kind == IssuerBackendKind::None {
        // Gated: no issuer API configured → skip cleanly (the verification suite is unaffected).
        let mut skipped = session;
        skipped.phase = ObtainPhase::Terminal;
        return (skipped, ObtainStep::Skipped);
    }
    let effect = token_request(&backend, &offer);
    (session, ObtainStep::PerformHttp(effect))
}

/// Advance an `obtain` flow given the result of the last effect.
///
/// # Errors
///
/// Returns [`ObtainError`] for a usage error (a resume that does not match the current phase, or a
/// resume past a terminal step). A *protocol* failure (issuer error, malformed response) is the
/// terminal [`ObtainStep::Failed`] outcome, not an `Err`.
pub fn resume_obtain(
    mut session: ObtainSession,
    input: ResumeObtain,
) -> Result<(ObtainSession, ObtainStep), ObtainError> {
    match session.phase {
        ObtainPhase::TokenPending => {
            let (status, body) = require_http(input)?;
            if !(200..300).contains(&status) {
                return Ok(fail(
                    session,
                    ObtainError::TokenRequest(format!("status {status}")),
                ));
            }
            let token = match parse_token_response(&body) {
                Ok(t) => t,
                Err(e) => return Ok(fail(session, ObtainError::TokenRequest(e))),
            };
            session.access_token = Some(Secret::new(token.access_token));
            // Build the PoP-JWT signing input bound to the credential-issuer `aud` + the issuer
            // `c_nonce`; the host signs it next (the signer-hook effect). The build is deterministic,
            // so the `Sign` arm re-derives the identical PoP-JWT and splices the returned signature —
            // we carry only the `c_nonce` (no private material) across the effect.
            let pop = match super::signer::build_pop_jwt(
                &session.holder,
                &session.backend.credential_issuer,
                &token.c_nonce,
                session.now_unix,
            ) {
                Ok(p) => p,
                Err(e) => return Ok(fail(session, ObtainError::Proof(e.to_string()))),
            };
            session.phase = ObtainPhase::ProofPending;
            session.pending_c_nonce = Some(Secret::new(token.c_nonce));
            Ok((session, ObtainStep::Sign(pop.input)))
        }
        ObtainPhase::ProofPending => {
            let signature = require_signature(input)?;
            let c_nonce = session
                .pending_c_nonce
                .as_ref()
                .ok_or(ObtainError::UnexpectedInput)?
                .expose()
                .to_owned();
            let pop = super::signer::build_pop_jwt(
                &session.holder,
                &session.backend.credential_issuer,
                &c_nonce,
                session.now_unix,
            )
            .map_err(|e| ObtainError::Proof(e.to_string()))?;
            let proof_jwt = pop
                .assemble(&signature)
                .map_err(|e| ObtainError::Proof(e.to_string()))?;
            session.proof_jwt = Some(proof_jwt.clone());
            session.phase = ObtainPhase::CredentialPending;
            let access_token = session
                .access_token
                .as_ref()
                .ok_or(ObtainError::UnexpectedInput)?
                .expose()
                .to_owned();
            let effect =
                credential_request(&session.backend, &session.offer, &access_token, &proof_jwt)?;
            Ok((session, ObtainStep::PerformHttp(effect)))
        }
        ObtainPhase::CredentialPending => {
            let (status, body) = require_http(input)?;
            if !(200..300).contains(&status) {
                return Ok(fail(
                    session,
                    ObtainError::CredentialRequest(format!("status {status}")),
                ));
            }
            match parse_credential_response(&body, session.offer.format) {
                Ok(held) => {
                    session.phase = ObtainPhase::Terminal;
                    Ok((session, ObtainStep::Obtained(held)))
                }
                Err(e) => Ok(fail(session, ObtainError::CredentialRequest(e))),
            }
        }
        ObtainPhase::Terminal => Err(ObtainError::AlreadyTerminal),
    }
}

/// Set the session to a terminal failure with the given error.
fn fail(mut session: ObtainSession, error: ObtainError) -> (ObtainSession, ObtainStep) {
    session.phase = ObtainPhase::Terminal;
    (session, ObtainStep::Failed(error))
}

fn require_http(input: ResumeObtain) -> Result<(u16, Vec<u8>), ObtainError> {
    match input {
        ResumeObtain::Http { status, body } => Ok((status, body)),
        ResumeObtain::Signature(_) => Err(ObtainError::UnexpectedInput),
    }
}

fn require_signature(input: ResumeObtain) -> Result<Vec<u8>, ObtainError> {
    match input {
        ResumeObtain::Signature(sig) => Ok(sig),
        ResumeObtain::Http { .. } => Err(ObtainError::UnexpectedInput),
    }
}

/// Build the OpenID4VCI token-endpoint request (the pre-authorized-code grant, form-encoded).
fn token_request(backend: &IssuerBackend, offer: &CredentialOffer) -> HttpEffect {
    let body = format!(
        "grant_type={}&pre-authorized_code={}",
        percent_encode("urn:ietf:params:oauth:grant-type:pre-authorized_code"),
        percent_encode(offer.pre_authorized_code.expose()),
    );
    HttpEffect {
        method: HttpMethod::Post,
        url: backend.token_endpoint.clone(),
        headers: vec![(
            "Content-Type".to_owned(),
            "application/x-www-form-urlencoded".to_owned(),
        )],
        body: body.into_bytes(),
    }
}

/// Build the OpenID4VCI credential-endpoint request: the credential configuration id + the holder
/// `jwt` proof, as JSON, with the access token as the Bearer.
///
/// # Errors
///
/// [`ObtainError::CredentialRequest`] on the (impossible) JSON-serialization failure of the in-memory
/// request body. Serializing a plain `serde_json::Value` of owned strings cannot fail in practice, but
/// the failure is **propagated** rather than swallowed with `unwrap_or_default()` (which would POST an
/// EMPTY body the issuer rejects with an opaque error far from the cause — Constitution VIII RCA). This
/// mirrors [`super::signer`]'s `to_json_bytes`, which surfaces the same impossible failure on the
/// error channel.
fn credential_request(
    backend: &IssuerBackend,
    offer: &CredentialOffer,
    access_token: &str,
    proof_jwt: &str,
) -> Result<HttpEffect, ObtainError> {
    let body = serde_json::json!({
        "credential_configuration_id": offer.credential_configuration_id,
        "proof": { "proof_type": "jwt", "jwt": proof_jwt },
    });
    let body_bytes = serde_json::to_vec(&body).map_err(|e| {
        ObtainError::CredentialRequest(format!("failed to serialize request body: {e}"))
    })?;
    Ok(HttpEffect {
        method: HttpMethod::Post,
        url: backend.credential_endpoint.clone(),
        headers: vec![
            ("Authorization".to_owned(), format!("Bearer {access_token}")),
            ("Content-Type".to_owned(), "application/json".to_owned()),
        ],
        body: body_bytes,
    })
}

/// The parsed OpenID4VCI token response (`access_token` + the `c_nonce` the PoP-JWT must echo).
struct TokenResponse {
    access_token: String,
    c_nonce: String,
}

/// Parse the OpenID4VCI token-endpoint JSON response.
fn parse_token_response(body: &[u8]) -> Result<TokenResponse, String> {
    let json: Value = serde_json::from_slice(body).map_err(|e| e.to_string())?;
    let access_token = json
        .get("access_token")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing access_token".to_owned())?
        .to_owned();
    // The `c_nonce` may be returned at the token endpoint (OpenID4VCI 1.0) or via a nonce endpoint;
    // the reference issuer returns it at the token endpoint. Default to empty if absent (the issuer
    // then rejects the proof, surfacing as a credential-request failure — never a silent accept).
    let c_nonce = json
        .get("c_nonce")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    Ok(TokenResponse {
        access_token,
        c_nonce,
    })
}

/// Parse the OpenID4VCI credential-endpoint response into a [`HeldAttestation`]. The credential is
/// carried in the `credential` member (a compact SD-JWT VC string, or base64url mdoc CBOR).
fn parse_credential_response(body: &[u8], format: Format) -> Result<HeldAttestation, String> {
    let json: Value = serde_json::from_slice(body).map_err(|e| e.to_string())?;
    let credential = json
        .get("credential")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing credential".to_owned())?;
    match format {
        Format::SdJwtVc => Ok(HeldAttestation::SdJwtVc {
            issued: credential.to_owned(),
        }),
        Format::Mdoc => {
            use base64ct::{Base64UrlUnpadded, Encoding as _};
            let device_response = Base64UrlUnpadded::decode_vec(credential)
                .map_err(|e| format!("mdoc credential base64url: {e}"))?;
            Ok(HeldAttestation::Mdoc { device_response })
        }
    }
}

/// Percent-encode a value for a URL query / form body (RFC 3986 unreserved set kept literal).
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for &b in value.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests;
