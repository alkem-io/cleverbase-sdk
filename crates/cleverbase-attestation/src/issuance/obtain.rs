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
//! `credential offer (pre-authorized_code)` → POST token endpoint → POST the **Nonce Endpoint** for a
//! fresh `c_nonce` (OpenID4VCI 1.0 §7 `#nonce-endpoint`) → `Sign` the OpenID4VCI proof-JWT (PoP) via
//! the signer-hook → POST credential endpoint with the `proofs` object → parse the issued SD-JWT VC /
//! mdoc out of the `credentials` array into a [`HeldAttestation`]. The pre-authorized-code grant is
//! the self-contained flow the reference issuer supports without an interactive browser leg.
//!
//! ## OpenID4VCI 1.0 wire shapes (verified online against the 1.0 final text)
//!
//! This path tracks **OpenID4VCI 1.0 final**
//! (<https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html>; source
//! `openid/OpenID4VCI` `1.0/openid-4-verifiable-credential-issuance-1_0.md`), which made three
//! breaking changes over the early `~draft-13` shapes this code originally tracked:
//!
//! 1. **Credential Request** carries `proofs` — an object keyed by proof type whose value is a
//!    **non-empty array** (`{"proofs":{"jwt":[<jwt>]}}`), replacing the draft singular
//!    `proof`/`proof_type` (§8.2 `#credential-request`).
//! 2. The one-time `c_nonce` is fetched from a dedicated **Nonce Endpoint** rather than read from the
//!    Token Response (§7 `#nonce-endpoint`; the Token Response no longer carries `c_nonce`).
//! 3. **Credential Response** returns `credentials` — an array of objects, each with a `credential`
//!    member — replacing the draft top-level `credential` string (§8.3 `#credential-response`).

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
    /// The OpenID4VCI **Nonce Endpoint** (`nonce_endpoint` Credential Issuer Metadata, OpenID4VCI 1.0
    /// §7 `#nonce-endpoint`). 1.0 moved the one-time `c_nonce` out of the Token Response: the flow
    /// POSTs here (unauthenticated, empty body) for a fresh `c_nonce` before building the PoP proof. A
    /// Credential Issuer that requires `c_nonce` values in the proof MUST offer this endpoint
    /// (`#nonce-endpoint`); the EUDI reference issuer does.
    pub nonce_endpoint: String,
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
            nonce_endpoint: String::new(),
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
    /// The End-User-supplied **Transaction Code** value to send in the Token Request, present only
    /// when the offer's pre-authorized-code grant carried a `tx_code` object (OpenID4VCI 1.0 §6.1 +
    /// §Token-Request `#token-request`: "This value MUST be present if a `tx_code` object was present
    /// in the Credential Offer"). It is a low-entropy one-time code (typically a PIN delivered out of
    /// band), so it is held as a redacting [`Secret`] (never in `Debug`/log output — FR-010) yet
    /// (de)serializes transparently so the offer round-trips and the token-request site percent-encodes
    /// the live value. `None` when the offer carried no `tx_code` object (the default).
    #[serde(default)]
    pub tx_code: Option<Secret>,
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
    /// The Nonce Endpoint (OpenID4VCI 1.0 §7 `#nonce-endpoint`) returned a non-success status or a
    /// body without the REQUIRED `c_nonce`.
    #[error("nonce request failed: {0}")]
    NonceRequest(String),
    /// The credential endpoint returned a non-success status or an unparseable body.
    #[error("credential request failed: {0}")]
    CredentialRequest(String),
    /// The issuer returned a **deferred** Credential Response (HTTP 202 + a `transaction_id`,
    /// OpenID4VCI 1.0 §8.3 `#credential-response`). Deferred issuance — polling the Deferred Credential
    /// Endpoint (§9 `#deferred-credential-issuance`) — is a documented scope cut (see
    /// `standards-conformance.md`), so it is surfaced as a clear, distinct terminal failure rather than
    /// a confusing "missing credentials" parse error.
    #[error("issuer deferred credential issuance (transaction_id {0:?}); the deferred endpoint is not supported")]
    Deferred(String),
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
    /// Awaiting the Nonce-Endpoint response (the fresh `c_nonce` for the PoP proof — OpenID4VCI 1.0 §7
    /// `#nonce-endpoint`).
    NoncePending,
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
    /// The issuer `c_nonce` the PoP-JWT must echo (carried from the **Nonce Endpoint** response to the
    /// `Sign` resume, where the deterministic PoP-JWT is rebuilt and the host signature spliced in).
    /// Held as a redacting [`Secret`] so the one-time nonce never appears in `Debug`/log output.
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
            let access_token = match parse_token_response(&body) {
                Ok(t) => t,
                Err(e) => return Ok(fail(session, ObtainError::TokenRequest(e))),
            };
            session.access_token = Some(Secret::new(access_token));
            // OpenID4VCI 1.0 moved the one-time `c_nonce` out of the Token Response into a dedicated
            // Nonce Endpoint (§7 `#nonce-endpoint`). Fetch a fresh `c_nonce` next — before building the
            // PoP proof — via an unauthenticated POST to the Nonce Endpoint.
            session.phase = ObtainPhase::NoncePending;
            let effect = nonce_request(&session.backend);
            Ok((session, ObtainStep::PerformHttp(effect)))
        }
        ObtainPhase::NoncePending => {
            let (status, body) = require_http(input)?;
            if !(200..300).contains(&status) {
                return Ok(fail(
                    session,
                    ObtainError::NonceRequest(format!("status {status}")),
                ));
            }
            let c_nonce = match parse_nonce_response(&body) {
                Ok(n) => n,
                Err(e) => return Ok(fail(session, ObtainError::NonceRequest(e))),
            };
            // Build the PoP-JWT signing input bound to the credential-issuer `aud` + the fresh
            // `c_nonce`; the host signs it next (the signer-hook effect). The build is deterministic,
            // so the `ProofPending` arm re-derives the identical PoP-JWT and splices the returned
            // signature — we carry only the `c_nonce` (no private material) across the effect.
            let pop = match super::signer::build_pop_jwt(
                &session.holder,
                &session.backend.credential_issuer,
                &c_nonce,
                session.now_unix,
            ) {
                Ok(p) => p,
                Err(e) => return Ok(fail(session, ObtainError::Proof(e.to_string()))),
            };
            session.phase = ObtainPhase::ProofPending;
            session.pending_c_nonce = Some(Secret::new(c_nonce));
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
            match parse_credential_response(&body, session.offer.format, status) {
                Ok(CredentialResponse::Immediate(held)) => {
                    session.phase = ObtainPhase::Terminal;
                    Ok((session, ObtainStep::Obtained(held)))
                }
                Ok(CredentialResponse::Deferred(transaction_id)) => {
                    Ok(fail(session, ObtainError::Deferred(transaction_id)))
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
///
/// When the offer carried a `tx_code` object, the End-User-supplied Transaction Code is appended as
/// the `tx_code` parameter — OpenID4VCI 1.0 §Token-Request (`#token-request`): "This value MUST be
/// present if a `tx_code` object was present in the Credential Offer ... This parameter MUST only be
/// used if the `grant_type` is `urn:ietf:params:oauth:grant-type:pre-authorized_code`" (which it
/// always is on this path).
fn token_request(backend: &IssuerBackend, offer: &CredentialOffer) -> HttpEffect {
    let mut body = format!(
        "grant_type={}&pre-authorized_code={}",
        percent_encode("urn:ietf:params:oauth:grant-type:pre-authorized_code"),
        percent_encode(offer.pre_authorized_code.expose()),
    );
    if let Some(tx_code) = &offer.tx_code {
        body.push_str("&tx_code=");
        body.push_str(&percent_encode(tx_code.expose()));
    }
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

/// Build the OpenID4VCI credential-endpoint request: the `credential_configuration_id` + the holder
/// PoP in the `proofs` object, as JSON, with the access token as the Bearer.
///
/// OpenID4VCI 1.0 §8.2 (`#credential-request`): `proofs` is "an object [that] contains exactly one
/// parameter named as the proof type ... the value set for this parameter is a **non-empty array**" —
/// here `{"proofs":{"jwt":[<jwt>]}}`, replacing the early-draft singular `proof`/`proof_type`. We send
/// the `credential_configuration_id` (never `credential_identifier`): §8.2 requires the two be
/// mutually exclusive ("When this parameter is used, the `credential_identifier` MUST NOT be
/// present"), which we satisfy by construction (the `credential_identifier`/`authorization_details`
/// request path is a documented scope cut — see `standards-conformance.md`).
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
        "proofs": { "jwt": [proof_jwt] },
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

/// Parse the OpenID4VCI Token Response, returning the `access_token`.
///
/// OpenID4VCI 1.0 §Token-Response (`#token-response`) no longer carries `c_nonce` (it moved to the
/// Nonce Endpoint, §7 `#nonce-endpoint`), so this reads only the REQUIRED `access_token`. The
/// `token_type` (always `Bearer` on this path) and DPoP are documented scope cuts — see
/// `standards-conformance.md`.
fn parse_token_response(body: &[u8]) -> Result<String, String> {
    let json: Value = serde_json::from_slice(body).map_err(|e| e.to_string())?;
    json.get("access_token")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| "missing access_token".to_owned())
}

/// Build the OpenID4VCI Nonce-Endpoint request (OpenID4VCI 1.0 §7.1 `#nonce-request`): an HTTP POST
/// with an **empty body** and **no access token** — "The Nonce Endpoint is not a protected resource,
/// meaning the Wallet does not need to supply an access token to access it."
fn nonce_request(backend: &IssuerBackend) -> HttpEffect {
    HttpEffect {
        method: HttpMethod::Post,
        url: backend.nonce_endpoint.clone(),
        headers: Vec::new(),
        body: Vec::new(),
    }
}

/// Parse the OpenID4VCI Nonce Response (OpenID4VCI 1.0 §7.2 `#nonce-response`): a JSON object carrying
/// the REQUIRED top-level `c_nonce` string.
fn parse_nonce_response(body: &[u8]) -> Result<String, String> {
    let json: Value = serde_json::from_slice(body).map_err(|e| e.to_string())?;
    json.get("c_nonce")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| "missing c_nonce".to_owned())
}

/// The parsed outcome of an OpenID4VCI Credential Response: an immediately-issued credential, or a
/// deferred-issuance signal we surface as a distinct terminal failure (see [`ObtainError::Deferred`]).
enum CredentialResponse {
    /// An immediately-issued credential (HTTP 200 + a `credentials` array).
    Immediate(HeldAttestation),
    /// A deferred Credential Response (HTTP 202 + a `transaction_id`); carries the `transaction_id`
    /// (or empty if the issuer omitted it) for the failure detail.
    Deferred(String),
}

/// Parse the OpenID4VCI Credential Response (OpenID4VCI 1.0 §8.3 `#credential-response`).
///
/// 1.0 returns `credentials` — "an array of one or more issued Credentials ... The elements of the
/// array MUST be objects ... `credential`: REQUIRED. Contains one issued Credential" — replacing the
/// early-draft top-level `credential` string. The credential is taken from `credentials[0].credential`
/// (this path requests a single proof, so the issuer binds at most one credential). A deferred
/// response (HTTP 202, or a top-level `transaction_id`) is reported as [`CredentialResponse::Deferred`]
/// rather than mis-parsed as a malformed body (RCA: a clear, distinct outcome — never a silent accept).
fn parse_credential_response(
    body: &[u8],
    format: Format,
    status: u16,
) -> Result<CredentialResponse, String> {
    let json: Value = serde_json::from_slice(body).map_err(|e| e.to_string())?;
    // Deferred issuance: HTTP 202 + a `transaction_id` (§8.3). Detect either signal so a deferred
    // response is surfaced as `Deferred`, not as a confusing "missing credentials" parse error.
    let transaction_id = json.get("transaction_id").and_then(Value::as_str);
    if status == 202 || transaction_id.is_some() {
        return Ok(CredentialResponse::Deferred(
            transaction_id.unwrap_or_default().to_owned(),
        ));
    }
    let credential = json
        .get("credentials")
        .and_then(Value::as_array)
        .and_then(|credentials| credentials.first())
        .and_then(|first| first.get("credential"))
        .and_then(Value::as_str)
        .ok_or_else(|| "missing credentials[0].credential".to_owned())?;
    let held = match format {
        Format::SdJwtVc => HeldAttestation::SdJwtVc {
            issued: credential.to_owned(),
        },
        Format::Mdoc => {
            use base64ct::{Base64UrlUnpadded, Encoding as _};
            let device_response = Base64UrlUnpadded::decode_vec(credential)
                .map_err(|e| format!("mdoc credential base64url: {e}"))?;
            HeldAttestation::Mdoc { device_response }
        }
    };
    Ok(CredentialResponse::Immediate(held))
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
