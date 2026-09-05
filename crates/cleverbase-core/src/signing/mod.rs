//! The sans-IO signing state machine (contracts/sdk-api.md, data-model.md).
//!
//! `begin` starts a signing flow; `resume` advances it given the result of the last effect. The
//! core performs no I/O — it returns a [`Step`] describing what the host must do next. The full
//! CSC/OIDC flow is wired here: service authorization → credential discovery → identity check →
//! PDF preparation → hash-bound credential authorization → `signHash` → CMS assembly → embed.
//! PAdES B-B and B-T are both implemented.

use serde::{Deserialize, Serialize};

pub mod csc;

use crate::crypto::cms;
use crate::effects::{HttpEffect, HttpMethod, RedirectEffect, Step};
use crate::evidence::{SignerIdentity, SigningEvidenceRecord, SigningOutcome, TimestampInfo};
use crate::pades::container;
use crate::session::{SigningPhase, SigningSessionHandle};
use crate::timestamp;
use crate::types::{ConformanceLevel, SignedDocument, SigningRequest, TrustServiceConfiguration};
use crate::{crypto, util, SCHEMA_VERSION};

use crate::crypto::SHA256_OID_STR as SHA256_OID;

/// Host-provided context for a single call (keeps the core deterministic).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostContext {
    /// Current time, Unix seconds.
    pub now_unix: i64,
    /// Fresh random bytes (OAuth `state`, correlation id). Provide ≥ 16 bytes.
    #[serde(with = "serde_bytes")]
    pub entropy: Vec<u8>,
}

/// The result the host feeds back into `resume`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ResumeInput {
    /// Response to a prior [`Step::PerformHttp`].
    HttpResult {
        /// HTTP status code.
        status: u16,
        /// Response headers as `(name, value)` pairs.
        #[serde(default)]
        headers: Vec<(String, String)>,
        /// Response body bytes.
        #[serde(default, with = "serde_bytes")]
        body: Vec<u8>,
    },
    /// Code+state received at the integrator's `redirect_uri` after a [`Step::Redirect`].
    RedirectReturn {
        /// The OAuth authorization `code`.
        code: String,
        /// The `state` echoed back (validated against the pending state for CSRF).
        state: String,
    },
    /// An OAuth error received at the `redirect_uri` instead of a code (e.g. `access_denied` when
    /// the signer declines in the wallet), with the `state` for CSRF validation.
    RedirectError {
        /// The OAuth error code (e.g. `access_denied`).
        error: String,
        /// The `state` echoed back (validated against the pending state for CSRF).
        state: String,
    },
}

/// Usage/programmer errors (not protocol outcomes, which are `Step::Failed`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CoreError {
    /// B-T was requested but no TSA is configured.
    #[error("B-T conformance requires a configured TSA")]
    MissingTsaConfig,
    /// A required configuration value was missing or invalid.
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
    /// The returned OAuth `state` did not match the pending one (CSRF check failed).
    #[error("OAuth state mismatch")]
    StateMismatch,
    /// The session handle was malformed, tampered, or carried an unsupported schema version.
    #[error("unsupported or malformed session handle: {0}")]
    BadHandle(String),
    /// The supplied [`ResumeInput`] did not match what the current phase expects.
    #[error("unexpected resume input for the current phase")]
    UnexpectedInput,
    /// A trust-service response could not be parsed.
    #[error("failed to parse trust-service response: {0}")]
    ProtocolParse(String),
    /// An internal invariant failed while assembling the signature/container.
    #[error("internal signing error: {0}")]
    Internal(String),
}

/// Format a UTC date/time for a visible appearance (civil-from-days; no external date dep).
fn fmt_date(now_unix: i64) -> String {
    let days = now_unix.div_euclid(86400);
    let secs = now_unix.rem_euclid(86400);
    let (hh, mm, ss) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    let (y, m, d) = util::civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02} {hh:02}:{mm:02}:{ss:02} UTC")
}

/// Resolve a request's optional visible appearance into drawable text lines (FR-016).
fn build_visible_appearance(
    request: &SigningRequest,
    identity: &SignerIdentity,
    now_unix: i64,
) -> Option<container::VisibleAppearance> {
    let a = request.appearance.as_ref()?;
    let mut lines = Vec::new();
    if a.show.signer_name {
        let name = if identity.common_name.is_empty() {
            identity.raw_subject.clone()
        } else {
            identity.common_name.clone()
        };
        lines.push(format!("Signed by: {name}"));
    }
    if a.show.reason {
        if let Some(r) = request
            .signature_meta
            .as_ref()
            .and_then(|m| m.reason.as_ref())
        {
            lines.push(format!("Reason: {r}"));
        }
    }
    if a.show.location {
        if let Some(l) = request
            .signature_meta
            .as_ref()
            .and_then(|m| m.location.as_ref())
        {
            lines.push(format!("Location: {l}"));
        }
    }
    if a.show.signing_time {
        lines.push(format!("Date: {}", fmt_date(now_unix)));
    }
    if lines.is_empty() {
        lines.push("Digitally signed".to_string());
    }
    Some(container::VisibleAppearance {
        page: a.page,
        rect: (a.rect.x, a.rect.y, a.rect.w, a.rect.h),
        lines,
    })
}

fn correlation_from(ctx: &HostContext) -> String {
    // Derive a short correlation id from the first 8 entropy bytes; `.get` avoids a panicking index
    // and falls back to the host clock when too little entropy was supplied.
    ctx.entropy
        .get(..8)
        .map_or_else(|| format!("corr-{}", ctx.now_unix), util::to_hex)
}

fn csc_base(config: &TrustServiceConfiguration) -> String {
    let version = match config.csc_api {
        crate::types::CscApi::V1Rsa => "v1",
        crate::types::CscApi::V2Ecdsa => "v2",
    };
    format!("{}/csc/{}", config.base_url(), version)
}

fn json_post(url: String, bearer: &str, body: serde_json::Value) -> HttpEffect {
    HttpEffect {
        method: HttpMethod::Post,
        url,
        headers: vec![
            ("Authorization".into(), format!("Bearer {bearer}")),
            ("Content-Type".into(), "application/json".into()),
        ],
        // `body` is always a serde_json::Value built from json!(), so serialization to a Vec is
        // infallible; expect (not unwrap_or_default) so an impossible failure surfaces rather than
        // silently producing an empty request body. There is no error channel on this helper.
        #[allow(clippy::expect_used)] // infallible: serializing an in-memory Value into a Vec
        body: Some(serde_json::to_vec(&body).expect("json! Value serialization is infallible")),
    }
}

fn token_exchange(config: &TrustServiceConfiguration, code: &str) -> HttpEffect {
    let basic = util::base64_std(
        format!("{}:{}", config.client_id, config.client_secret.expose()).as_bytes(),
    );
    let body = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}",
        util::percent_encode(code),
        util::percent_encode(&config.redirect_uri),
    );
    HttpEffect {
        method: HttpMethod::Post,
        url: config.token_url(),
        headers: vec![
            ("Authorization".into(), format!("Basic {basic}")),
            (
                "Content-Type".into(),
                "application/x-www-form-urlencoded".into(),
            ),
        ],
        body: Some(body.into_bytes()),
    }
}

fn evidence_failure(
    handle: &SigningSessionHandle,
    outcome: SigningOutcome,
    reason: impl Into<String>,
) -> SigningEvidenceRecord {
    SigningEvidenceRecord {
        request_digest: handle.request_digest.clone(),
        outcome,
        conformance_level: handle.conformance_level,
        signer: handle.signer.clone(),
        signing_time: None,
        timestamp: None,
        failure_reason: Some(reason.into()),
        correlation_id: handle.correlation_id.clone(),
    }
}

/// Clear all sensitive carried state from a terminal handle. The flow never resumes past a terminal
/// phase, so the Bearer/SAD token, the document/config (which holds the client secret), and the
/// assembled signing bytes must not linger in a serializable handle — on success OR failure.
fn scrub_sensitive(handle: &mut SigningSessionHandle) {
    handle.state = None;
    handle.credential_id = None;
    handle.service_token = None;
    handle.cert_chain = None;
    handle.signed_attrs_der = None;
    handle.staged_pdf = None;
    handle.cms_der = None;
    handle.request = None;
    handle.config = None;
}

fn fail(
    mut handle: SigningSessionHandle,
    outcome: SigningOutcome,
    reason: impl Into<String>,
) -> (SigningSessionHandle, Step) {
    let evidence = evidence_failure(&handle, outcome, reason);
    handle.phase = SigningPhase::Failed;
    scrub_sensitive(&mut handle);
    (handle, Step::Failed { evidence })
}

/// Build the terminal success result, dropping heavy/sensitive carried state.
fn finalize(
    mut handle: SigningSessionHandle,
    pdf: Vec<u8>,
    timestamp: Option<TimestampInfo>,
) -> Result<(SigningSessionHandle, Step), CoreError> {
    let evidence = SigningEvidenceRecord {
        request_digest: handle.request_digest.clone(),
        outcome: SigningOutcome::Signed,
        conformance_level: handle.conformance_level,
        signer: handle.signer.clone(),
        signing_time: handle.signing_time_unix,
        timestamp,
        failure_reason: None,
        correlation_id: handle.correlation_id.clone(),
    };
    let signed = SignedDocument {
        pdf,
        conformance_level: handle.conformance_level,
        pdf_a: handle.pdf_a.unwrap_or(false),
    };
    handle.phase = SigningPhase::Completed;
    scrub_sensitive(&mut handle);
    Ok((handle, Step::Done { signed, evidence }))
}

fn require_http(input: ResumeInput) -> Result<(u16, Vec<u8>), CoreError> {
    match input {
        ResumeInput::HttpResult { status, body, .. } => Ok((status, body)),
        _ => Err(CoreError::UnexpectedInput),
    }
}

fn require_redirect(input: ResumeInput) -> Result<(String, String), CoreError> {
    match input {
        ResumeInput::RedirectReturn { code, state } => Ok((code, state)),
        _ => Err(CoreError::UnexpectedInput),
    }
}

/// Begin a signing flow. Returns the session handle plus the first [`Step`].
pub fn begin(
    request: SigningRequest,
    config: TrustServiceConfiguration,
    ctx: HostContext,
) -> Result<(SigningSessionHandle, Step), CoreError> {
    if config.client_id.is_empty() || config.redirect_uri.is_empty() {
        return Err(CoreError::InvalidConfig(
            "client_id and redirect_uri are required".into(),
        ));
    }
    config.validate().map_err(CoreError::InvalidConfig)?;
    // The OAuth `state` CSRF token is derived from entropy; too little makes it guessable/empty.
    if ctx.entropy.len() < 16 {
        return Err(CoreError::InvalidConfig(
            "entropy must be at least 16 bytes".into(),
        ));
    }
    if request.conformance_level == ConformanceLevel::BT && config.tsa.is_none() {
        return Err(CoreError::MissingTsaConfig);
    }

    let digest_hex = util::to_hex(&crypto::sha256(&request.document));
    let correlation_id = correlation_from(&ctx);

    // Reject up front anything we cannot soundly sign: non-PDF input, or an already-signed PDF
    // (multi-signature is a later phase — signing it now would corrupt the existing signature).
    let invalid_reason = if !request.document.starts_with(b"%PDF-") {
        Some("document is not a PDF")
    } else if container::is_already_signed(&request.document) {
        Some(
            "document already contains a signature; multi-signature is not supported in this phase",
        )
    } else {
        None
    };
    if let Some(reason) = invalid_reason {
        let mut handle = SigningSessionHandle::terminal(
            SigningPhase::Failed,
            digest_hex,
            request.conformance_level,
            correlation_id,
        );
        let evidence = evidence_failure(&handle, SigningOutcome::InvalidDocument, reason);
        handle.phase = SigningPhase::Failed;
        return Ok((handle, Step::Failed { evidence }));
    }

    let state = util::to_hex(&ctx.entropy);
    let url = format!(
        "{}?response_type=code&scope=service&client_id={}&redirect_uri={}&state={}",
        config.authorize_url(),
        util::percent_encode(&config.client_id),
        util::percent_encode(&config.redirect_uri),
        util::percent_encode(&state),
    );
    let conformance_level = request.conformance_level;
    let mut handle = SigningSessionHandle::terminal(
        SigningPhase::ServiceAuthPending,
        digest_hex,
        conformance_level,
        correlation_id,
    );
    handle.state = Some(state.clone());
    handle.request = Some(request);
    handle.config = Some(config);
    Ok((handle, Step::Redirect(RedirectEffect { url, state })))
}

/// Advance a signing flow given the result of the last effect.
pub fn resume(
    mut handle: SigningSessionHandle,
    input: ResumeInput,
    ctx: HostContext,
) -> Result<(SigningSessionHandle, Step), CoreError> {
    if handle.schema_version != SCHEMA_VERSION {
        return Err(CoreError::BadHandle(format!(
            "unsupported schema_version {}",
            handle.schema_version
        )));
    }
    // The credential-scope OAuth `state` (CSRF token) is regenerated here from entropy, so resume
    // must enforce the same minimum as `begin` — otherwise the security-critical second round-trip
    // could get an empty/guessable state.
    if ctx.entropy.len() < 16 {
        return Err(CoreError::InvalidConfig(
            "entropy must be at least 16 bytes".into(),
        ));
    }
    let config = handle
        .config
        .clone()
        .ok_or_else(|| CoreError::BadHandle("missing config".into()))?;

    // A signer decline / OAuth error arrives at the redirect with an `error` and no code; it is only
    // meaningful while awaiting a redirect. Validate state (CSRF), then map to a terminal outcome so
    // decline is distinguished from timeout/expiry (FR-007). The OAuth error code is not a secret.
    if let ResumeInput::RedirectError { error, state } = &input {
        if !matches!(
            handle.phase,
            SigningPhase::ServiceAuthPending | SigningPhase::CredentialAuthPending
        ) {
            return Err(CoreError::UnexpectedInput);
        }
        if handle.state.as_deref() != Some(state.as_str()) {
            return Err(CoreError::StateMismatch);
        }
        let outcome = if error == "access_denied" {
            SigningOutcome::Declined
        } else {
            SigningOutcome::AuthorizationExpired
        };
        return Ok(fail(
            handle,
            outcome,
            format!("authorization not completed ({error})"),
        ));
    }

    match handle.phase {
        SigningPhase::ServiceAuthPending => {
            let (code, state) = require_redirect(input)?;
            if handle.state.as_deref() != Some(state.as_str()) {
                return Err(CoreError::StateMismatch);
            }
            handle.state = None;
            handle.phase = SigningPhase::ServiceTokenPending;
            Ok((handle, Step::PerformHttp(token_exchange(&config, &code))))
        }

        SigningPhase::ServiceTokenPending => {
            let (status, body) = require_http(input)?;
            if !(200..300).contains(&status) {
                return Ok(fail(
                    handle,
                    SigningOutcome::CredentialUnavailable,
                    "service token request failed",
                ));
            }
            let token = csc::parse_token_response(&body)?;
            handle.service_token = Some(crate::types::Secret::new(token.access_token));
            handle.phase = SigningPhase::ListPending;
            let bearer = handle
                .service_token
                .as_ref()
                .ok_or_else(|| CoreError::BadHandle("missing service token".into()))?
                .expose()
                .to_string();
            Ok((
                handle,
                Step::PerformHttp(json_post(
                    format!("{}/credentials/list", csc_base(&config)),
                    &bearer,
                    serde_json::json!({}),
                )),
            ))
        }

        SigningPhase::ListPending => {
            let (status, body) = require_http(input)?;
            if !(200..300).contains(&status) {
                return Ok(fail(
                    handle,
                    SigningOutcome::CredentialUnavailable,
                    "credentials/list failed",
                ));
            }
            let list = csc::parse_credentials_list(&body)?;
            let credential_id = match list.credential_ids.into_iter().next() {
                Some(id) => id,
                None => {
                    return Ok(fail(
                        handle,
                        SigningOutcome::CredentialUnavailable,
                        "no signing credential",
                    ))
                }
            };
            handle.credential_id = Some(credential_id.clone());
            handle.phase = SigningPhase::InfoPending;
            let bearer = handle
                .service_token
                .as_ref()
                .ok_or_else(|| CoreError::BadHandle("missing service token".into()))?
                .expose()
                .to_string();
            Ok((
                handle,
                Step::PerformHttp(json_post(
                    format!("{}/credentials/info", csc_base(&config)),
                    &bearer,
                    serde_json::json!({"credentialID": credential_id, "certificates": "chain", "certInfo": true}),
                )),
            ))
        }

        SigningPhase::InfoPending => {
            let (status, body) = require_http(input)?;
            if !(200..300).contains(&status) {
                return Ok(fail(
                    handle,
                    SigningOutcome::CredentialUnavailable,
                    "credentials/info failed",
                ));
            }
            let info = csc::parse_credentials_info(&body)?;
            if matches!(info.key_algo, csc::KeyAlgo::Other) {
                return Ok(fail(
                    handle,
                    SigningOutcome::CredentialUnavailable,
                    "unsupported signing key algorithm",
                ));
            }
            // Phase 1 relies on SCAL2 (per-signature sole control with the document hash bound in).
            // Reject a credential that explicitly advertises a different SCAL level.
            if !info.scal.is_empty() && info.scal != "2" {
                return Ok(fail(
                    handle,
                    SigningOutcome::CredentialUnavailable,
                    "credential does not support SCAL2 (per-signature sole control)",
                ));
            }

            // Decode the certificate chain (base64 DER).
            let mut chain = Vec::new();
            for c in &info.certificates {
                match util::base64_decode(c) {
                    Ok(der) => chain.push(der),
                    Err(e) => {
                        return Err(CoreError::ProtocolParse(format!("certificate base64: {e}")))
                    }
                }
            }
            if chain.is_empty() {
                return Ok(fail(
                    handle,
                    SigningOutcome::CredentialUnavailable,
                    "no certificate in credentials/info",
                ));
            }

            let identity = csc::signer_identity(&info);
            handle.signer = Some(identity.clone());

            // Enforce expected-signer binding (FR-014).
            if let Some(expected) = handle
                .request
                .as_ref()
                .and_then(|r| r.expected_signer.as_ref())
            {
                if !csc::matches_expected(expected, &identity) {
                    return Ok(fail(
                        handle,
                        SigningOutcome::IdentityMismatch,
                        "authorizing signer does not match expected identity",
                    ));
                }
            }

            // Prepare the PDF (ByteRange + placeholder) and the signed attributes.
            let request = handle
                .request
                .clone()
                .ok_or_else(|| CoreError::BadHandle("missing request".into()))?;
            let (reason, location) = request
                .signature_meta
                .as_ref()
                .map_or((None, None), |m| (m.reason.clone(), m.location.clone()));
            // PDF/A is preserved for invisible signatures; a visible appearance uses a non-embedded
            // base font, which is not PDF/A-conformant (font embedding is a later enhancement).
            let visible = build_visible_appearance(&request, &identity, ctx.now_unix);
            let prepared = match container::prepare(
                &request.document,
                reason.as_deref(),
                location.as_deref(),
                visible.as_ref(),
            ) {
                Ok(p) => p,
                Err(container::PadesError::NoPages) => {
                    return Ok(fail(
                        handle,
                        SigningOutcome::InvalidDocument,
                        "PDF has no pages",
                    ));
                }
                Err(container::PadesError::InvalidPlacement) => {
                    return Ok(fail(
                        handle,
                        SigningOutcome::AppearancePlacementError,
                        "invalid signature appearance placement",
                    ));
                }
                Err(container::PadesError::AlreadySigned) => {
                    return Ok(fail(
                        handle,
                        SigningOutcome::InvalidDocument,
                        "document already contains a signature; multi-signature is not supported in this phase",
                    ));
                }
                Err(e) => return Err(CoreError::Internal(e.to_string())),
            };
            // Report PDF/A best-effort from the OUTPUT marker — we do not independently validate
            // conformance (see docs/limitations.md), so never assert unverified preservation.
            handle.pdf_a =
                Some(container::is_pdf_a(&prepared.staged_pdf) && request.appearance.is_none());
            // The empty-chain case failed above, so `first()` is Some; `.get`/`ok_or` avoids a
            // panicking index while keeping the impossible case a clean error.
            let leaf_cert = chain
                .first()
                .ok_or_else(|| CoreError::BadHandle("empty certificate chain".into()))?;
            let signed_attrs =
                cms::build_signed_attrs(&prepared.content_hash, leaf_cert, ctx.now_unix)
                    .map_err(|e| CoreError::Internal(e.to_string()))?;
            let tbs = cms::tbs_hash(&signed_attrs);

            handle.cert_chain = Some(chain);
            handle.key_algo = Some(info.key_algo);
            handle.signed_attrs_der = Some(signed_attrs);
            handle.staged_pdf = Some(prepared.staged_pdf);
            handle.contents_span = Some(prepared.contents_span);
            handle.signing_time_unix = Some(ctx.now_unix);

            // Credential-scope authorization, hash bound into consent (WYSIWYS).
            let state = util::to_hex(&ctx.entropy);
            let credential_id = handle
                .credential_id
                .clone()
                .ok_or_else(|| CoreError::BadHandle("missing credentialID".into()))?;
            let url = format!(
                "{}?response_type=code&scope=credential&client_id={}&redirect_uri={}&state={}&credentialID={}&numSignatures=1&hash={}",
                config.authorize_url(),
                util::percent_encode(&config.client_id),
                util::percent_encode(&config.redirect_uri),
                util::percent_encode(&state),
                util::percent_encode(&credential_id),
                util::percent_encode(&util::base64url_nopad(&tbs)),
            );
            handle.state = Some(state.clone());
            handle.phase = SigningPhase::CredentialAuthPending;
            Ok((handle, Step::Redirect(RedirectEffect { url, state })))
        }

        SigningPhase::CredentialAuthPending => {
            let (code, state) = require_redirect(input)?;
            if handle.state.as_deref() != Some(state.as_str()) {
                return Err(CoreError::StateMismatch);
            }
            handle.state = None;
            handle.phase = SigningPhase::CredentialTokenPending;
            Ok((handle, Step::PerformHttp(token_exchange(&config, &code))))
        }

        SigningPhase::CredentialTokenPending => {
            let (status, body) = require_http(input)?;
            if !(200..300).contains(&status) {
                return Ok(fail(
                    handle,
                    SigningOutcome::AuthorizationExpired,
                    "credential authorization not completed",
                ));
            }
            let sad = csc::parse_token_response(&body)?.access_token;
            let credential_id = handle
                .credential_id
                .clone()
                .ok_or_else(|| CoreError::BadHandle("missing credentialID".into()))?;
            let signed_attrs = handle
                .signed_attrs_der
                .clone()
                .ok_or_else(|| CoreError::BadHandle("missing signed attrs".into()))?;
            let key_algo = handle
                .key_algo
                .ok_or_else(|| CoreError::BadHandle("missing key algo".into()))?;
            let tbs = cms::tbs_hash(&signed_attrs);
            let bearer = handle
                .service_token
                .as_ref()
                .ok_or_else(|| CoreError::BadHandle("missing service token".into()))?
                .expose()
                .to_string();

            let effect = json_post(
                format!("{}/signatures/signHash", csc_base(&config)),
                &bearer,
                serde_json::json!({
                    "credentialID": credential_id,
                    "SAD": sad,
                    "hash": [util::base64_std(&tbs)],
                    "hashAlgo": SHA256_OID,
                    "signAlgo": key_algo.sign_algo_oid(),
                }),
            );
            handle.phase = SigningPhase::SignPending;
            Ok((handle, Step::PerformHttp(effect)))
        }

        SigningPhase::SignPending => {
            let (status, body) = require_http(input)?;
            if !(200..300).contains(&status) {
                return Ok(fail(
                    handle,
                    SigningOutcome::CredentialUnavailable,
                    "signHash failed",
                ));
            }
            let sigs = csc::parse_signatures(&body)?;
            let sig_b64 = match sigs.signatures.into_iter().next() {
                Some(s) => s,
                None => {
                    return Ok(fail(
                        handle,
                        SigningOutcome::CredentialUnavailable,
                        "no signature returned",
                    ))
                }
            };
            let signature = util::base64_decode(&sig_b64)
                .map_err(|e| CoreError::ProtocolParse(format!("signature base64: {e}")))?;

            let chain = handle
                .cert_chain
                .clone()
                .ok_or_else(|| CoreError::BadHandle("missing cert chain".into()))?;
            let signed_attrs = handle
                .signed_attrs_der
                .clone()
                .ok_or_else(|| CoreError::BadHandle("missing signed attrs".into()))?;
            let key_algo = handle
                .key_algo
                .ok_or_else(|| CoreError::BadHandle("missing key algo".into()))?;
            let cms_der = cms::assemble_signed_data(&chain, &signed_attrs, &signature, key_algo)
                .map_err(|e| CoreError::Internal(e.to_string()))?;
            // Self-verify the assembled signature against the signer's certificate before declaring
            // success — a malformed/wrong/empty signature from the trust service must never be
            // reported as Signed (defense-in-depth; FR: no silently-invalid success). The verifier
            // returns the message-digest attribute so we can bind it without re-parsing the CMS.
            let message_digest = match cms::verify_signed_data(&cms_der, key_algo) {
                Ok(md) => md,
                Err(_) => {
                    return Ok(fail(
                        handle,
                        SigningOutcome::SignatureInvalid,
                        "assembled signature failed verification against the signer certificate",
                    ));
                }
            };
            // Bind the signature to THIS document: the CMS message-digest attribute must equal the
            // ByteRange hash of the staged PDF we are about to embed (WYSIWYS defense-in-depth).
            {
                let staged = handle
                    .staged_pdf
                    .as_deref()
                    .ok_or_else(|| CoreError::BadHandle("missing staged pdf".into()))?;
                let span = handle
                    .contents_span
                    .ok_or_else(|| CoreError::BadHandle("missing contents span".into()))?;
                let expected_md = container::byte_range_digest(staged, span)
                    .ok_or_else(|| CoreError::BadHandle("invalid contents span".into()))?;
                if message_digest != expected_md {
                    return Ok(fail(
                        handle,
                        SigningOutcome::SignatureInvalid,
                        "signed content digest does not match the document",
                    ));
                }
            }

            if handle.conformance_level == ConformanceLevel::BT {
                // Request a signature timestamp over the signature value (B-T).
                let tsa = config.tsa.as_ref().ok_or(CoreError::MissingTsaConfig)?;
                // The signature timestamp must cover the SignerInfo signature value as STORED in
                // the CMS (DER for ECDSA), not the raw signHash bytes — otherwise a validator that
                // recomputes the imprint over the stored value would reject the B-T timestamp.
                let stored_signature = cms::signer_signature(&cms_der)
                    .map_err(|e| CoreError::Internal(e.to_string()))?;
                let imprint = crypto::sha256(&stored_signature);
                let req = timestamp::build_request(&imprint, tsa.policy_oid.as_deref())
                    .map_err(|e| CoreError::Internal(e.to_string()))?;
                let mut headers = vec![(
                    "Content-Type".to_string(),
                    "application/timestamp-query".to_string(),
                )];
                if let Some(auth) = &tsa.auth {
                    headers.push(("Authorization".to_string(), auth.expose().to_string()));
                }
                let effect = HttpEffect {
                    method: HttpMethod::Post,
                    url: tsa.url.clone(),
                    headers,
                    body: Some(req),
                };
                handle.cms_der = Some(cms_der);
                handle.phase = SigningPhase::TimestampPending;
                return Ok((handle, Step::PerformHttp(effect)));
            }

            let mut staged = handle
                .staged_pdf
                .clone()
                .ok_or_else(|| CoreError::BadHandle("missing staged pdf".into()))?;
            let span = handle
                .contents_span
                .ok_or_else(|| CoreError::BadHandle("missing contents span".into()))?;
            container::embed_cms(&mut staged, span, &cms_der)
                .map_err(|e| CoreError::Internal(e.to_string()))?;
            finalize(handle, staged, None)
        }

        SigningPhase::TimestampPending => {
            let (status, body) = require_http(input)?;
            if !(200..300).contains(&status) {
                return Ok(fail(
                    handle,
                    SigningOutcome::TimestampFailed,
                    "timestamp authority request failed",
                ));
            }
            let token = match timestamp::parse_response(&body) {
                Ok(t) => t,
                Err(_) => {
                    return Ok(fail(
                        handle,
                        SigningOutcome::TimestampFailed,
                        "timestamp authority did not grant a token",
                    ))
                }
            };
            let cms_der = handle
                .cms_der
                .clone()
                .ok_or_else(|| CoreError::BadHandle("missing cms".into()))?;
            // The token MUST be bound to OUR signature: its messageImprint must equal the hash we
            // submitted (sha256 of the stored signature value). Rejects a MITM'd / replayed token
            // that carries an unrelated or forged time.
            let stored_signature =
                cms::signer_signature(&cms_der).map_err(|e| CoreError::Internal(e.to_string()))?;
            let expected_imprint = crypto::sha256(&stored_signature);
            if timestamp::parse_message_imprint(&token).as_deref()
                != Some(expected_imprint.as_slice())
            {
                return Ok(fail(
                    handle,
                    SigningOutcome::TimestampFailed,
                    "timestamp imprint does not match the signature",
                ));
            }
            let cms_ts = cms::embed_timestamp(&cms_der, &token)
                .map_err(|e| CoreError::Internal(e.to_string()))?;
            let mut staged = handle
                .staged_pdf
                .clone()
                .ok_or_else(|| CoreError::BadHandle("missing staged pdf".into()))?;
            let span = handle
                .contents_span
                .ok_or_else(|| CoreError::BadHandle("missing contents span".into()))?;
            container::embed_cms(&mut staged, span, &cms_ts)
                .map_err(|e| CoreError::Internal(e.to_string()))?;
            let tsa_cfg = config.tsa.as_ref();
            let ts_info = TimestampInfo {
                tsa: tsa_cfg.map(|t| t.url.clone()).unwrap_or_default(),
                // Prefer the TSA's own genTime from the token; fall back to host time if unparsable.
                gen_time: timestamp::parse_gen_time(&token).unwrap_or(ctx.now_unix),
                policy_oid: tsa_cfg.and_then(|t| t.policy_oid.clone()),
            };
            finalize(handle, staged, Some(ts_info))
        }
        SigningPhase::Completed | SigningPhase::Failed => {
            Err(CoreError::BadHandle("session is already terminal".into()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        AppearanceShow, CscApi, Environment, ExpectedSignerIdentity, MatchOn, Rect, Secret,
        SignatureAppearance, SignatureMeta, TsaConfiguration,
    };
    use pkcs8::DecodePrivateKey;

    const RSA_CERT: &[u8] = include_bytes!("../../../../tests/fixtures/pki/signer-rsa.cert.der");
    const RSA_KEY: &[u8] = include_bytes!("../../../../tests/fixtures/pki/signer-rsa.key.pk8");

    // Match-or-panic helpers: keep the (uncovered) panic arm in one place rather than per test.
    fn expect_redirect(step: Step) -> RedirectEffect {
        match step {
            Step::Redirect(r) => r,
            other => panic!("expected redirect, got {other:?}"),
        }
    }
    fn expect_failed(step: Step) -> SigningEvidenceRecord {
        match step {
            Step::Failed { evidence } => evidence,
            other => panic!("expected failed, got {other:?}"),
        }
    }
    fn http_err(status: u16) -> ResumeInput {
        ResumeInput::HttpResult {
            status,
            headers: vec![],
            body: b"{}".to_vec(),
        }
    }
    fn http_bytes(status: u16, body: Vec<u8>) -> ResumeInput {
        ResumeInput::HttpResult {
            status,
            headers: vec![],
            body,
        }
    }

    #[test]
    fn unit_helpers_cover_branches() {
        // csc_base: both API generations.
        let mut v2 = cfg();
        v2.csc_api = CscApi::V2Ecdsa;
        assert!(csc_base(&v2).contains("/csc/v2"));
        assert!(csc_base(&cfg()).contains("/csc/v1"));
        // correlation_from: full-entropy (hex) and short-entropy (fallback) branches.
        assert_eq!(correlation_from(&ctx()).len(), 16);
        let short = HostContext {
            now_unix: 42,
            entropy: vec![1, 2, 3],
        };
        assert_eq!(correlation_from(&short), "corr-42");
        // require_http / require_redirect reject the wrong ResumeInput variant.
        assert!(matches!(
            require_http(ResumeInput::RedirectReturn {
                code: "c".into(),
                state: "s".into()
            }),
            Err(CoreError::UnexpectedInput)
        ));
        assert!(matches!(
            require_redirect(http_err(200)),
            Err(CoreError::UnexpectedInput)
        ));
    }

    #[test]
    fn build_visible_appearance_covers_all_branches() {
        let id = SignerIdentity {
            serial_number: "s".into(),
            common_name: String::new(),
            given_name: None,
            surname: None,
            raw_subject: "CN=Raw Subject".into(),
        };
        let mut req = request(ConformanceLevel::BB, None);
        req.appearance = Some(SignatureAppearance {
            page: 2,
            rect: Rect {
                x: 1.0,
                y: 2.0,
                w: 3.0,
                h: 4.0,
            },
            show: AppearanceShow {
                signer_name: true,
                reason: true,
                location: true,
                signing_time: true,
            },
        });
        req.signature_meta = Some(SignatureMeta {
            reason: Some("Approval".into()),
            location: Some("NL".into()),
        });
        let va = build_visible_appearance(&req, &id, 1_700_000_000).unwrap();
        assert_eq!(va.page, 2);
        assert!(va.lines.iter().any(|l| l.contains("CN=Raw Subject"))); // empty CN → raw_subject
        assert!(va.lines.iter().any(|l| l.starts_with("Reason: Approval")));
        assert!(va.lines.iter().any(|l| l.starts_with("Location: NL")));
        assert!(va.lines.iter().any(|l| l.starts_with("Date: "))); // exercises fmt_date

        // All show flags off → the default "Digitally signed" line.
        req.appearance = Some(SignatureAppearance {
            page: 1,
            rect: Rect {
                x: 0.0,
                y: 0.0,
                w: 1.0,
                h: 1.0,
            },
            show: AppearanceShow::default(),
        });
        req.signature_meta = None;
        let va2 = build_visible_appearance(&req, &id, 0).unwrap();
        assert_eq!(va2.lines, vec!["Digitally signed".to_string()]);

        // No appearance → None.
        let mut none_req = request(ConformanceLevel::BB, None);
        none_req.appearance = None;
        assert!(build_visible_appearance(&none_req, &id, 0).is_none());

        // A non-empty common name is used verbatim (the other `signer_name` branch).
        let named = SignerIdentity {
            common_name: "Jane Doe".into(),
            ..id
        };
        let mut named_req = request(ConformanceLevel::BB, None);
        named_req.appearance = Some(SignatureAppearance {
            page: 1,
            rect: Rect {
                x: 0.0,
                y: 0.0,
                w: 1.0,
                h: 1.0,
            },
            show: AppearanceShow {
                signer_name: true,
                ..AppearanceShow::default()
            },
        });
        let va3 = build_visible_appearance(&named_req, &named, 0).unwrap();
        assert!(va3.lines.iter().any(|l| l == "Signed by: Jane Doe"));
    }

    #[test]
    fn begin_rejects_bad_config() {
        let mut c = cfg();
        c.client_id = String::new();
        assert!(matches!(
            begin(request(ConformanceLevel::BB, None), c, ctx()),
            Err(CoreError::InvalidConfig(_))
        ));
        let mut c = cfg();
        c.redirect_uri = String::new();
        assert!(matches!(
            begin(request(ConformanceLevel::BB, None), c, ctx()),
            Err(CoreError::InvalidConfig(_))
        ));
        let short = HostContext {
            now_unix: 1_700_000_000,
            entropy: vec![0u8; 4],
        };
        assert!(matches!(
            begin(request(ConformanceLevel::BB, None), cfg(), short),
            Err(CoreError::InvalidConfig(_))
        ));
        let mut c = cfg();
        c.upstream_base_url = Some("http://not-loopback.example".into());
        assert!(matches!(
            begin(request(ConformanceLevel::BB, None), c, ctx()),
            Err(CoreError::InvalidConfig(_))
        ));
    }

    #[test]
    fn upstream_base_url_drives_oauth_and_csc_effects() {
        let origin = "https://trust-driver-stub-hash-signing.cleverbase.com";
        let mut config = cfg();
        config.upstream_base_url = Some(origin.into());

        let (handle, step) = begin(request(ConformanceLevel::BB, None), config, ctx()).unwrap();
        let redirect = expect_redirect(step);
        assert!(redirect
            .url
            .starts_with(&format!("{origin}/oauth2/authorize?")));

        let (handle, step) = resume(
            handle,
            ResumeInput::RedirectReturn {
                code: "service-code".into(),
                state: redirect.state,
            },
            ctx(),
        )
        .unwrap();
        let Step::PerformHttp(token) = step else {
            panic!("expected service token exchange");
        };
        assert_eq!(token.url, format!("{origin}/oauth2/token"));

        let (_handle, step) = resume(
            handle,
            http_ok(serde_json::json!({"access_token":"bearer","token_type":"Bearer"})),
            ctx(),
        )
        .unwrap();
        let Step::PerformHttp(list) = step else {
            panic!("expected credential discovery");
        };
        assert_eq!(list.url, format!("{origin}/csc/v1/credentials/list"));
    }

    /// Drive begin → redirect-return → the named HTTP-awaiting phase, returning the handle there.
    fn advance_to(phase: SigningPhase) -> SigningSessionHandle {
        let (h, s) = begin(request(ConformanceLevel::BB, None), cfg(), ctx()).unwrap();
        let state = expect_redirect(s).state;
        let (h, _) = resume(
            h,
            ResumeInput::RedirectReturn {
                code: "c".into(),
                state,
            },
            ctx(),
        )
        .unwrap();
        // h is now at ServiceTokenPending.
        if phase == SigningPhase::ServiceTokenPending {
            return h;
        }
        let (h, _) = resume(
            h,
            http_ok(serde_json::json!({"access_token":"b","token_type":"Bearer"})),
            ctx(),
        )
        .unwrap();
        // ListPending.
        if phase == SigningPhase::ListPending {
            return h;
        }
        let (h, _) = resume(
            h,
            http_ok(serde_json::json!({"credentialIDs":["cred-1"]})),
            ctx(),
        )
        .unwrap();
        h // InfoPending
    }

    #[test]
    fn service_token_http_failure_is_credential_unavailable() {
        let h = advance_to(SigningPhase::ServiceTokenPending);
        let (h, step) = resume(h, http_err(500), ctx()).unwrap();
        assert_eq!(h.phase, SigningPhase::Failed);
        assert_eq!(
            expect_failed(step).outcome,
            SigningOutcome::CredentialUnavailable
        );
    }

    #[test]
    fn credentials_list_http_failure_is_credential_unavailable() {
        let h = advance_to(SigningPhase::ListPending);
        let (_h, step) = resume(h, http_err(500), ctx()).unwrap();
        assert_eq!(
            expect_failed(step).outcome,
            SigningOutcome::CredentialUnavailable
        );
    }

    #[test]
    fn credentials_info_http_failure_is_credential_unavailable() {
        let h = advance_to(SigningPhase::InfoPending);
        let (_h, step) = resume(h, http_err(500), ctx()).unwrap();
        assert_eq!(
            expect_failed(step).outcome,
            SigningOutcome::CredentialUnavailable
        );
    }

    #[test]
    fn terminal_handle_is_scrubbed_of_secrets() {
        // Failure after the service token is obtained: the terminal handle must carry no secrets
        // (Bearer token, client-secret-bearing config, document, or assembled bytes).
        let h = advance_to(SigningPhase::InfoPending);
        assert!(h.service_token.is_some(), "precondition: token is set here");
        let (failed, _) = resume(h, http_err(500), ctx()).unwrap();
        assert_eq!(failed.phase, SigningPhase::Failed);
        assert!(failed.service_token.is_none(), "service token scrubbed");
        assert!(failed.config.is_none(), "config (client secret) scrubbed");
        assert!(failed.request.is_none() && failed.cert_chain.is_none());
        assert!(failed.staged_pdf.is_none() && failed.cms_der.is_none());
        // The success path is scrubbed too.
        let (done, _) = run_full_flow(request(ConformanceLevel::BB, None));
        assert_eq!(done.phase, SigningPhase::Completed);
        assert!(done.service_token.is_none() && done.config.is_none());
        assert!(done.staged_pdf.is_none() && done.request.is_none());
    }

    #[test]
    fn credential_token_http_failure_is_authorization_expired() {
        // Drive to CredentialTokenPending, then fail the token exchange.
        let h = advance_to(SigningPhase::InfoPending);
        let (h, s) = resume(h, http_ok(info_json()), ctx()).unwrap();
        let state = expect_redirect(s).state;
        let (h, _) = resume(
            h,
            ResumeInput::RedirectReturn {
                code: "c2".into(),
                state,
            },
            ctx(),
        )
        .unwrap();
        let (h, step) = resume(h, http_err(400), ctx()).unwrap();
        assert_eq!(h.phase, SigningPhase::Failed);
        assert_eq!(
            expect_failed(step).outcome,
            SigningOutcome::AuthorizationExpired
        );
    }

    #[test]
    fn signhash_empty_signatures_is_signature_invalid() {
        let (h, _req) = advance_to_sign_pending(request(ConformanceLevel::BB, None));
        // signHash returns 200 but an empty signature element.
        let (h, step) = resume(h, http_ok(serde_json::json!({"signatures":[""]})), ctx()).unwrap();
        assert_eq!(h.phase, SigningPhase::Failed);
        assert_eq!(
            expect_failed(step).outcome,
            SigningOutcome::SignatureInvalid
        );
    }

    #[test]
    fn timestamp_http_failure_and_bad_token_are_timestamp_failed() {
        // B-T flow to TimestampPending: non-2xx TSA response → TimestampFailed.
        let h = drive_bt_to_timestamp_pending();
        let (h, step) = resume(h, http_err(500), ctx()).unwrap();
        assert_eq!(h.phase, SigningPhase::Failed);
        assert_eq!(expect_failed(step).outcome, SigningOutcome::TimestampFailed);

        // A 200 with an unparseable TSA body → TimestampFailed (parse_response error).
        let h = drive_bt_to_timestamp_pending();
        let (_h, step) = resume(h, http_bytes(200, b"not a TSR".to_vec()), ctx()).unwrap();
        assert_eq!(expect_failed(step).outcome, SigningOutcome::TimestampFailed);
    }

    /// Drive a B-T flow to TimestampPending (signs with the RSA fixture key, then awaits the TSA).
    fn drive_bt_to_timestamp_pending() -> SigningSessionHandle {
        let mut c = cfg();
        c.tsa = Some(TsaConfiguration {
            url: "https://tsa.example/tsr".into(),
            auth: Some(Secret::new("Bearer t")),
            policy_oid: None,
        });
        let (h, s) = begin(request(ConformanceLevel::BT, None), c, ctx()).unwrap();
        let state = expect_redirect(s).state;
        let (h, _) = resume(
            h,
            ResumeInput::RedirectReturn {
                code: "c".into(),
                state,
            },
            ctx(),
        )
        .unwrap();
        let (h, _) = resume(
            h,
            http_ok(serde_json::json!({"access_token":"b","token_type":"Bearer"})),
            ctx(),
        )
        .unwrap();
        let (h, _) = resume(
            h,
            http_ok(serde_json::json!({"credentialIDs":["cred-1"]})),
            ctx(),
        )
        .unwrap();
        let (h, s) = resume(h, http_ok(info_json()), ctx()).unwrap();
        let state = expect_redirect(s).state;
        let (h, _) = resume(
            h,
            ResumeInput::RedirectReturn {
                code: "c2".into(),
                state,
            },
            ctx(),
        )
        .unwrap();
        let (h, s) = resume(
            h,
            http_ok(serde_json::json!({"access_token":"SAD","token_type":"SAD"})),
            ctx(),
        )
        .unwrap();
        let sign_req = match s {
            Step::PerformHttp(e) => e,
            other => panic!("expected signHash, got {other:?}"),
        };
        let (h, s) = resume(
            h,
            http_ok(serde_json::json!({"signatures":[fixture_sign(&sign_req)]})),
            ctx(),
        )
        .unwrap();
        assert!(matches!(s, Step::PerformHttp(_)));
        assert_eq!(h.phase, SigningPhase::TimestampPending);
        h
    }

    #[test]
    fn tampered_handle_fields_yield_bad_handle() {
        // Missing cert chain at SignPending.
        let (mut h, req) = advance_to_sign_pending(request(ConformanceLevel::BB, None));
        let sig = fixture_sign(&req);
        h.cert_chain = None;
        let err = resume(h, http_ok(serde_json::json!({"signatures":[sig]})), ctx()).unwrap_err();
        assert!(matches!(err, CoreError::BadHandle(_)));

        // Missing config (any phase) → BadHandle.
        let (mut h, _) = advance_to_sign_pending(request(ConformanceLevel::BB, None));
        h.config = None;
        let err = resume(
            h,
            ResumeInput::RedirectError {
                error: "x".into(),
                state: "s".into(),
            },
            ctx(),
        )
        .unwrap_err();
        assert!(matches!(err, CoreError::BadHandle(_)));

        // Wrong schema version.
        let mut h = SigningSessionHandle::terminal(
            SigningPhase::ServiceAuthPending,
            "d".into(),
            ConformanceLevel::BB,
            "c".into(),
        );
        h.schema_version = 999;
        let err = resume(
            h,
            ResumeInput::RedirectReturn {
                code: "c".into(),
                state: "s".into(),
            },
            ctx(),
        )
        .unwrap_err();
        assert!(matches!(err, CoreError::BadHandle(_)));
    }

    #[test]
    fn resume_on_terminal_handle_is_rejected() {
        let (h, _) = run_full_flow(request(ConformanceLevel::BB, None));
        assert_eq!(h.phase, SigningPhase::Completed);
        let err = resume(h, http_err(200), ctx()).unwrap_err();
        assert!(matches!(err, CoreError::BadHandle(_)));
    }

    #[test]
    fn unexpected_input_for_phase_is_rejected() {
        // ServiceAuthPending awaits a redirect; feeding an HttpResult is UnexpectedInput.
        let (h, _) = begin(request(ConformanceLevel::BB, None), cfg(), ctx()).unwrap();
        let err = resume(h, http_err(200), ctx()).unwrap_err();
        assert!(matches!(err, CoreError::UnexpectedInput));
    }

    #[test]
    fn redirect_error_in_wrong_phase_is_unexpected_input() {
        let h = advance_to(SigningPhase::ServiceTokenPending); // not a redirect-awaiting phase
        let err = resume(
            h,
            ResumeInput::RedirectError {
                error: "access_denied".into(),
                state: "s".into(),
            },
            ctx(),
        )
        .unwrap_err();
        assert!(matches!(err, CoreError::UnexpectedInput));
    }

    #[test]
    fn non_access_denied_redirect_error_is_authorization_expired() {
        let (h, s) = begin(request(ConformanceLevel::BB, None), cfg(), ctx()).unwrap();
        let state = expect_redirect(s).state;
        let (_h, step) = resume(
            h,
            ResumeInput::RedirectError {
                error: "server_error".into(),
                state,
            },
            ctx(),
        )
        .unwrap();
        assert_eq!(
            expect_failed(step).outcome,
            SigningOutcome::AuthorizationExpired
        );
    }

    fn info_with(certs: serde_json::Value, algo: &str) -> serde_json::Value {
        serde_json::json!({
            "key": {"algo": [algo]},
            "cert": {"certificates": certs, "subjectDN": "CN=x", "serialNumber": "s"},
            "SCAL": "2"
        })
    }

    #[test]
    fn unsupported_key_algo_is_credential_unavailable() {
        let h = advance_to(SigningPhase::InfoPending);
        // Ed25519 — neither RSA nor EC P-256 → KeyAlgo::Other.
        let info = info_with(
            serde_json::json!([util::base64_std(RSA_CERT)]),
            "1.3.101.112",
        );
        let (_h, step) = resume(h, http_ok(info), ctx()).unwrap();
        assert_eq!(
            expect_failed(step).outcome,
            SigningOutcome::CredentialUnavailable
        );
    }

    #[test]
    fn malformed_certificate_base64_is_protocol_parse() {
        let h = advance_to(SigningPhase::InfoPending);
        let info = info_with(
            serde_json::json!(["@@not-base64@@"]),
            "1.2.840.113549.1.1.1",
        );
        let err = resume(h, http_ok(info), ctx()).unwrap_err();
        assert!(matches!(err, CoreError::ProtocolParse(_)));
    }

    #[test]
    fn empty_certificate_chain_is_credential_unavailable() {
        let h = advance_to(SigningPhase::InfoPending);
        let info = info_with(serde_json::json!([]), "1.2.840.113549.1.1.1");
        let (_h, step) = resume(h, http_ok(info), ctx()).unwrap();
        assert_eq!(
            expect_failed(step).outcome,
            SigningOutcome::CredentialUnavailable
        );
    }

    fn zero_page_pdf() -> Vec<u8> {
        let mut doc = lopdf::Document::with_version("1.7");
        let pages_id = doc.new_object_id();
        let mut pages = lopdf::Dictionary::new();
        pages.set("Type", lopdf::Object::Name(b"Pages".to_vec()));
        pages.set("Kids", lopdf::Object::Array(vec![]));
        pages.set("Count", lopdf::Object::Integer(0));
        doc.objects
            .insert(pages_id, lopdf::Object::Dictionary(pages));
        let mut catalog = lopdf::Dictionary::new();
        catalog.set("Type", lopdf::Object::Name(b"Catalog".to_vec()));
        catalog.set("Pages", lopdf::Object::Reference(pages_id));
        let cat_id = doc.add_object(lopdf::Object::Dictionary(catalog));
        doc.trailer.set("Root", lopdf::Object::Reference(cat_id));
        let mut buf = Vec::new();
        doc.save_to(&mut buf).unwrap();
        buf
    }

    #[test]
    fn zero_page_document_is_invalid_document() {
        let mut req = request(ConformanceLevel::BB, None);
        req.document = zero_page_pdf();
        let (h, s) = begin(req, cfg(), ctx()).unwrap();
        let state = expect_redirect(s).state;
        let (h, _) = resume(
            h,
            ResumeInput::RedirectReturn {
                code: "c".into(),
                state,
            },
            ctx(),
        )
        .unwrap();
        let (h, _) = resume(
            h,
            http_ok(serde_json::json!({"access_token":"b","token_type":"Bearer"})),
            ctx(),
        )
        .unwrap();
        let (h, _) = resume(
            h,
            http_ok(serde_json::json!({"credentialIDs":["cred-1"]})),
            ctx(),
        )
        .unwrap();
        let (_h, step) = resume(h, http_ok(info_json()), ctx()).unwrap();
        assert_eq!(expect_failed(step).outcome, SigningOutcome::InvalidDocument);
    }

    fn cfg() -> TrustServiceConfiguration {
        TrustServiceConfiguration {
            environment: Environment::Acceptance,
            csc_api: CscApi::V1Rsa,
            client_id: "client-123".into(),
            client_secret: Secret::new("shh"),
            redirect_uri: "https://app.example/callback".into(),
            upstream_base_url: None,
            tsa: None,
        }
    }

    fn minimal_pdf() -> Vec<u8> {
        use lopdf::{Dictionary, Document, Object};
        let mut doc = Document::with_version("1.7");
        let pages_id = doc.new_object_id();
        let mut page = Dictionary::new();
        page.set("Type", Object::Name(b"Page".to_vec()));
        page.set("Parent", Object::Reference(pages_id));
        page.set(
            "MediaBox",
            Object::Array(
                vec![0, 0, 612, 792]
                    .into_iter()
                    .map(Object::Integer)
                    .collect(),
            ),
        );
        let page_id = doc.add_object(Object::Dictionary(page));
        let mut pages = Dictionary::new();
        pages.set("Type", Object::Name(b"Pages".to_vec()));
        pages.set("Kids", Object::Array(vec![Object::Reference(page_id)]));
        pages.set("Count", Object::Integer(1));
        doc.objects.insert(pages_id, Object::Dictionary(pages));
        let mut catalog = Dictionary::new();
        catalog.set("Type", Object::Name(b"Catalog".to_vec()));
        catalog.set("Pages", Object::Reference(pages_id));
        let catalog_id = doc.add_object(Object::Dictionary(catalog));
        doc.trailer.set("Root", Object::Reference(catalog_id));
        let mut buf = Vec::new();
        doc.save_to(&mut buf).unwrap();
        buf
    }

    fn ctx() -> HostContext {
        HostContext {
            now_unix: 1_700_000_000,
            entropy: (0u8..16).collect(),
        }
    }

    fn http_ok(json: serde_json::Value) -> ResumeInput {
        ResumeInput::HttpResult {
            status: 200,
            headers: vec![],
            body: serde_json::to_vec(&json).unwrap(),
        }
    }

    fn info_json() -> serde_json::Value {
        let cert_b64 = util::base64_std(RSA_CERT);
        serde_json::json!({
            "key": {"status": "enabled", "algo": ["1.2.840.113549.1.1.1"], "len": 2048},
            "cert": {"status": "valid", "certificates": [cert_b64],
                     "subjectDN": "CN=Jane Doe,serialNumber=PNONL-123", "serialNumber": "PNONL-123"},
            "SCAL": "2"
        })
    }

    /// Drive begin → … → the `signHash` step, returning the handle (at `SignPending`) plus the
    /// signHash request effect. The caller plays Cleverbase's signHash response.
    fn advance_to_sign_pending(request: SigningRequest) -> (SigningSessionHandle, HttpEffect) {
        let (h, s) = begin(request, cfg(), ctx()).unwrap();
        let state = match &s {
            Step::Redirect(r) => r.state.clone(),
            _ => panic!("expected service redirect"),
        };
        let (h, _) = resume(
            h,
            ResumeInput::RedirectReturn {
                code: "svc-code".into(),
                state,
            },
            ctx(),
        )
        .unwrap();
        let (h, _) = resume(h, http_ok(serde_json::json!({"access_token":"svc-bearer","token_type":"Bearer","expires_in":3600})), ctx()).unwrap();
        let (h, _) = resume(
            h,
            http_ok(serde_json::json!({"credentialIDs":["cred-1"]})),
            ctx(),
        )
        .unwrap();
        let (h, s) = resume(h, http_ok(info_json()), ctx()).unwrap();
        let state = match &s {
            Step::Redirect(r) => {
                assert!(r.url.contains("scope=credential"));
                assert!(r.url.contains("hash="));
                r.state.clone()
            }
            _ => panic!("expected credential redirect"),
        };
        let (h, _) = resume(
            h,
            ResumeInput::RedirectReturn {
                code: "cred-code".into(),
                state,
            },
            ctx(),
        )
        .unwrap();
        let (h, s) = resume(
            h,
            http_ok(
                serde_json::json!({"access_token":"SAD-xyz","token_type":"SAD","expires_in":300}),
            ),
            ctx(),
        )
        .unwrap();
        let sign_req = match s {
            Step::PerformHttp(e) => e,
            _ => panic!("expected signHash"),
        };
        (h, sign_req)
    }

    /// Sign the `signHash` request's hash with the RSA fixture key (plays Cleverbase honestly).
    fn fixture_sign(sign_req: &HttpEffect) -> String {
        let body: serde_json::Value =
            serde_json::from_slice(sign_req.body.as_ref().unwrap()).unwrap();
        let tbs = util::base64_decode(body["hash"][0].as_str().unwrap()).unwrap();
        let key = rsa::RsaPrivateKey::from_pkcs8_der(RSA_KEY).unwrap();
        let sig = key
            .sign(rsa::Pkcs1v15Sign::new::<sha2::Sha256>(), &tbs)
            .unwrap();
        util::base64_std(&sig)
    }

    /// Drive the whole flow, acting as host + Cleverbase (the signHash step signs with the fixture key).
    fn run_full_flow(request: SigningRequest) -> (SigningSessionHandle, Step) {
        let (h, sign_req) = advance_to_sign_pending(request);
        resume(
            h,
            http_ok(serde_json::json!({"signatures": [fixture_sign(&sign_req)]})),
            ctx(),
        )
        .unwrap()
    }

    #[test]
    fn invalid_signature_yields_signature_invalid() {
        // Cleverbase returns a structurally-valid base64 but cryptographically-wrong signature.
        let (h, _sign_req) = advance_to_sign_pending(request(ConformanceLevel::BB, None));
        let garbage = util::base64_std(&[0u8; 256]);
        let (h, step) = resume(
            h,
            http_ok(serde_json::json!({"signatures": [garbage]})),
            ctx(),
        )
        .unwrap();
        assert_eq!(h.phase, SigningPhase::Failed);
        match step {
            Step::Failed { evidence } => {
                assert_eq!(evidence.outcome, SigningOutcome::SignatureInvalid);
            }
            _ => panic!("expected failed step"),
        }
    }

    #[test]
    fn non_scal2_credential_is_rejected() {
        let (h, s) = begin(request(ConformanceLevel::BB, None), cfg(), ctx()).unwrap();
        let state = match &s {
            Step::Redirect(r) => r.state.clone(),
            _ => panic!(),
        };
        let (h, _) = resume(
            h,
            ResumeInput::RedirectReturn {
                code: "c".into(),
                state,
            },
            ctx(),
        )
        .unwrap();
        let (h, _) = resume(
            h,
            http_ok(serde_json::json!({"access_token":"b","token_type":"Bearer"})),
            ctx(),
        )
        .unwrap();
        let (h, _) = resume(
            h,
            http_ok(serde_json::json!({"credentialIDs":["cred-1"]})),
            ctx(),
        )
        .unwrap();
        let mut info = info_json();
        info["SCAL"] = serde_json::json!("1");
        let (h, step) = resume(h, http_ok(info), ctx()).unwrap();
        assert_eq!(h.phase, SigningPhase::Failed);
        match step {
            Step::Failed { evidence } => {
                assert_eq!(evidence.outcome, SigningOutcome::CredentialUnavailable);
            }
            _ => panic!("expected failed step"),
        }
    }

    #[test]
    fn short_entropy_on_resume_is_rejected() {
        let (h, _) = begin(request(ConformanceLevel::BB, None), cfg(), ctx()).unwrap();
        let short_ctx = HostContext {
            now_unix: 1_700_000_000,
            entropy: vec![0u8; 4],
        };
        let err = resume(
            h,
            ResumeInput::RedirectReturn {
                code: "c".into(),
                state: "s".into(),
            },
            short_ctx,
        )
        .unwrap_err();
        assert!(matches!(err, CoreError::InvalidConfig(_)));
    }

    fn request(
        level: ConformanceLevel,
        expected: Option<ExpectedSignerIdentity>,
    ) -> SigningRequest {
        SigningRequest {
            document: minimal_pdf(),
            conformance_level: level,
            expected_signer: expected,
            appearance: None,
            signature_meta: None,
        }
    }

    #[test]
    fn full_b_b_flow_produces_signed_pdf() {
        let (handle, step) = run_full_flow(request(ConformanceLevel::BB, None));
        assert_eq!(handle.phase, SigningPhase::Completed);
        match step {
            Step::Done { signed, evidence } => {
                assert_eq!(signed.conformance_level, ConformanceLevel::BB);
                lopdf::Document::load_mem(&signed.pdf).expect("signed PDF loads");
                assert_eq!(evidence.outcome, SigningOutcome::Signed);
                assert_eq!(evidence.signer.unwrap().serial_number, "PNONL-123");
                // The embedded CMS verifies over the ByteRange digest.
                let contents = extract_contents_cms(&signed.pdf);
                let (_a, _md, _s, certs) = cms::reparse_for_verify(&contents).unwrap();
                assert_eq!(certs.len(), 1);
            }
            other => panic!("expected Done, got {other:?}"),
        }
    }

    #[test]
    fn signer_decline_yields_declined_outcome() {
        // FR-007: a wallet decline (OAuth access_denied) must be distinguished from expiry.
        let (h, s) = begin(request(ConformanceLevel::BB, None), cfg(), ctx()).unwrap();
        let state = match s {
            Step::Redirect(r) => r.state,
            _ => panic!("expected redirect"),
        };
        let (h, step) = resume(
            h,
            ResumeInput::RedirectError {
                error: "access_denied".into(),
                state,
            },
            ctx(),
        )
        .unwrap();
        assert_eq!(h.phase, SigningPhase::Failed);
        match step {
            Step::Failed { evidence } => assert_eq!(evidence.outcome, SigningOutcome::Declined),
            _ => panic!("expected failed step"),
        }
    }

    #[test]
    fn redirect_error_with_bad_state_is_rejected() {
        let (h, _s) = begin(request(ConformanceLevel::BB, None), cfg(), ctx()).unwrap();
        let err = resume(
            h,
            ResumeInput::RedirectError {
                error: "access_denied".into(),
                state: "forged".into(),
            },
            ctx(),
        )
        .unwrap_err();
        assert!(matches!(err, CoreError::StateMismatch));
    }

    #[test]
    fn identity_mismatch_fails_without_signing() {
        let expected = ExpectedSignerIdentity {
            match_on: MatchOn::CertificateSerialNumber,
            value: "PNONL-WRONG".into(),
        };
        // Run up to credentials/info, then assert IdentityMismatch (no signing happens).
        let (h0, s0) = begin(request(ConformanceLevel::BB, Some(expected)), cfg(), ctx()).unwrap();
        let state = match &s0 {
            Step::Redirect(r) => r.state.clone(),
            _ => panic!(),
        };
        let (h1, _) = resume(
            h0,
            ResumeInput::RedirectReturn {
                code: "c".into(),
                state,
            },
            ctx(),
        )
        .unwrap();
        let (h2, _) = resume(
            h1,
            http_ok(serde_json::json!({"access_token":"b","token_type":"Bearer"})),
            ctx(),
        )
        .unwrap();
        let (h3, _) = resume(
            h2,
            http_ok(serde_json::json!({"credentialIDs":["cred-1"]})),
            ctx(),
        )
        .unwrap();
        let (h4, step) = resume(h3, http_ok(info_json()), ctx()).unwrap();
        assert_eq!(h4.phase, SigningPhase::Failed);
        match step {
            Step::Failed { evidence } => {
                assert_eq!(evidence.outcome, SigningOutcome::IdentityMismatch);
            }
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn bt_without_tsa_is_usage_error() {
        let err = begin(request(ConformanceLevel::BT, None), cfg(), ctx()).unwrap_err();
        assert_eq!(err, CoreError::MissingTsaConfig);
    }

    #[test]
    fn bt_with_tsa_begins_successfully() {
        let mut c = cfg();
        c.tsa = Some(TsaConfiguration {
            url: "https://tsa.example/tsr".into(),
            auth: None,
            policy_oid: None,
        });
        // begin accepts B-T (TSA configured) and emits the first service-auth redirect.
        let (h, s) = begin(request(ConformanceLevel::BT, None), c, ctx()).unwrap();
        assert_eq!(h.phase, SigningPhase::ServiceAuthPending);
        assert!(matches!(s, Step::Redirect(_)));
    }

    #[test]
    fn resume_state_mismatch_is_rejected() {
        let (handle, _step) = begin(request(ConformanceLevel::BB, None), cfg(), ctx()).unwrap();
        let err = resume(
            handle,
            ResumeInput::RedirectReturn {
                code: "c".into(),
                state: "wrong".into(),
            },
            ctx(),
        )
        .unwrap_err();
        assert_eq!(err, CoreError::StateMismatch);
    }

    #[test]
    fn begin_rejects_non_pdf() {
        let mut r = request(ConformanceLevel::BB, None);
        r.document = b"not a pdf".to_vec();
        let (handle, step) = begin(r, cfg(), ctx()).unwrap();
        assert_eq!(handle.phase, SigningPhase::Failed);
        assert!(matches!(step, Step::Failed { .. }));
    }

    #[test]
    fn begin_rejects_already_signed_pdf() {
        // An already-signed PDF (carries a /ByteRange) must be rejected cleanly, not silently
        // corrupted by signing into the existing signature's slot.
        let mut r = request(ConformanceLevel::BB, None);
        r.document = b"%PDF-1.7\n/Type /Sig /ByteRange [0 840 960 490] /Contents <0000>".to_vec();
        let (handle, step) = begin(r, cfg(), ctx()).unwrap();
        assert_eq!(handle.phase, SigningPhase::Failed);
        match step {
            Step::Failed { evidence } => {
                assert_eq!(evidence.outcome, SigningOutcome::InvalidDocument);
            }
            _ => panic!("expected failed step"),
        }
    }

    #[test]
    fn stateless_resume_survives_handle_serialization() {
        let (h, s) = begin(request(ConformanceLevel::BB, None), cfg(), ctx()).unwrap();
        let state = match &s {
            Step::Redirect(r) => r.state.clone(),
            _ => panic!(),
        };
        let (h, _) = resume(
            h,
            ResumeInput::RedirectReturn {
                code: "c".into(),
                state,
            },
            ctx(),
        )
        .unwrap();
        // Persist the handle (as the integrator would), discard in-memory state, reload, continue.
        let mut buf = Vec::new();
        ciborium::into_writer(&h, &mut buf).unwrap();
        drop(h);
        let reloaded: SigningSessionHandle = ciborium::from_reader(&buf[..]).unwrap();
        let (h2, s2) = resume(
            reloaded,
            http_ok(serde_json::json!({"access_token": "b", "token_type": "Bearer"})),
            ctx(),
        )
        .unwrap();
        assert_eq!(h2.phase, SigningPhase::ListPending);
        assert!(matches!(s2, Step::PerformHttp(_)));
    }

    #[test]
    fn credential_authorization_binds_the_signed_hash() {
        let (h, s) = begin(request(ConformanceLevel::BB, None), cfg(), ctx()).unwrap();
        let state = match &s {
            Step::Redirect(r) => r.state.clone(),
            _ => panic!(),
        };
        let (h, _) = resume(
            h,
            ResumeInput::RedirectReturn {
                code: "c".into(),
                state,
            },
            ctx(),
        )
        .unwrap();
        let (h, _) = resume(
            h,
            http_ok(serde_json::json!({"access_token": "b", "token_type": "Bearer"})),
            ctx(),
        )
        .unwrap();
        let (h, _) = resume(
            h,
            http_ok(serde_json::json!({"credentialIDs": ["cred-1"]})),
            ctx(),
        )
        .unwrap();
        let (h, s) = resume(h, http_ok(info_json()), ctx()).unwrap();
        let (url, state) = match &s {
            Step::Redirect(r) => (r.url.clone(), r.state.clone()),
            _ => panic!(),
        };
        let auth_hash = url
            .split("hash=")
            .nth(1)
            .unwrap()
            .split('&')
            .next()
            .unwrap()
            .to_string();
        let (h, _) = resume(
            h,
            ResumeInput::RedirectReturn {
                code: "c2".into(),
                state,
            },
            ctx(),
        )
        .unwrap();
        let (_h, s) = resume(
            h,
            http_ok(serde_json::json!({"access_token": "SAD", "token_type": "SAD"})),
            ctx(),
        )
        .unwrap();
        let body: serde_json::Value = match &s {
            Step::PerformHttp(e) => serde_json::from_slice(e.body.as_ref().unwrap()).unwrap(),
            _ => panic!(),
        };
        // The hash authorized (WYSIWYS, base64url) is exactly the hash sent to signHash (base64).
        let authorized =
            util::base64_decode(&auth_hash.replace('-', "+").replace('_', "/")).unwrap();
        let signed = util::base64_decode(body["hash"][0].as_str().unwrap()).unwrap();
        assert_eq!(authorized, signed);
        assert_eq!(body["hashAlgo"], "2.16.840.1.101.3.4.2.1");
        // CSC receives a key algorithm here; CMS also carries rsaEncryption with SHA-256 in
        // digestAlgorithm.
        assert_eq!(body["signAlgo"], "1.2.840.113549.1.1.1");
    }

    #[test]
    fn no_signing_credential_fails() {
        let (h, s) = begin(request(ConformanceLevel::BB, None), cfg(), ctx()).unwrap();
        let state = match &s {
            Step::Redirect(r) => r.state.clone(),
            _ => panic!(),
        };
        let (h, _) = resume(
            h,
            ResumeInput::RedirectReturn {
                code: "c".into(),
                state,
            },
            ctx(),
        )
        .unwrap();
        let (h, _) = resume(
            h,
            http_ok(serde_json::json!({"access_token": "b", "token_type": "Bearer"})),
            ctx(),
        )
        .unwrap();
        let (h, s) = resume(h, http_ok(serde_json::json!({"credentialIDs": []})), ctx()).unwrap();
        assert_eq!(h.phase, SigningPhase::Failed);
        match s {
            Step::Failed { evidence } => {
                assert_eq!(evidence.outcome, SigningOutcome::CredentialUnavailable);
            }
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn signhash_http_error_fails() {
        let (h, s) = begin(request(ConformanceLevel::BB, None), cfg(), ctx()).unwrap();
        let state = match &s {
            Step::Redirect(r) => r.state.clone(),
            _ => panic!(),
        };
        let (h, _) = resume(
            h,
            ResumeInput::RedirectReturn {
                code: "c".into(),
                state,
            },
            ctx(),
        )
        .unwrap();
        let (h, _) = resume(
            h,
            http_ok(serde_json::json!({"access_token": "b", "token_type": "Bearer"})),
            ctx(),
        )
        .unwrap();
        let (h, _) = resume(
            h,
            http_ok(serde_json::json!({"credentialIDs": ["cred-1"]})),
            ctx(),
        )
        .unwrap();
        let (h, s) = resume(h, http_ok(info_json()), ctx()).unwrap();
        let state = match &s {
            Step::Redirect(r) => r.state.clone(),
            _ => panic!(),
        };
        let (h, _) = resume(
            h,
            ResumeInput::RedirectReturn {
                code: "c2".into(),
                state,
            },
            ctx(),
        )
        .unwrap();
        let (h, _) = resume(
            h,
            http_ok(serde_json::json!({"access_token": "SAD", "token_type": "SAD"})),
            ctx(),
        )
        .unwrap();
        let (h, s) = resume(
            h,
            ResumeInput::HttpResult {
                status: 500,
                headers: vec![],
                body: b"error".to_vec(),
            },
            ctx(),
        )
        .unwrap();
        assert_eq!(h.phase, SigningPhase::Failed);
        match s {
            Step::Failed { evidence } => {
                assert_eq!(evidence.outcome, SigningOutcome::CredentialUnavailable);
            }
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn invalid_appearance_placement_fails() {
        let mut req = request(ConformanceLevel::BB, None);
        req.appearance = Some(SignatureAppearance {
            page: 9, // out of range for a 1-page document
            rect: Rect {
                x: 10.0,
                y: 10.0,
                w: 100.0,
                h: 50.0,
            },
            show: AppearanceShow::default(),
        });
        let (h, s) = begin(req, cfg(), ctx()).unwrap();
        let state = match &s {
            Step::Redirect(r) => r.state.clone(),
            _ => panic!(),
        };
        let (h, _) = resume(
            h,
            ResumeInput::RedirectReturn {
                code: "c".into(),
                state,
            },
            ctx(),
        )
        .unwrap();
        let (h, _) = resume(
            h,
            http_ok(serde_json::json!({"access_token": "b", "token_type": "Bearer"})),
            ctx(),
        )
        .unwrap();
        let (h, _) = resume(
            h,
            http_ok(serde_json::json!({"credentialIDs": ["cred-1"]})),
            ctx(),
        )
        .unwrap();
        let (h, s) = resume(h, http_ok(info_json()), ctx()).unwrap();
        assert_eq!(h.phase, SigningPhase::Failed);
        match s {
            Step::Failed { evidence } => {
                assert_eq!(evidence.outcome, SigningOutcome::AppearancePlacementError);
            }
            o => panic!("{o:?}"),
        }
    }

    // Helper: pull the CMS DER out of the signed PDF's /Contents, trimming the zero padding.
    fn extract_contents_cms(pdf: &[u8]) -> Vec<u8> {
        let ck = pdf.windows(9).position(|w| w == b"/Contents").unwrap();
        let lt = pdf[ck..].iter().position(|&b| b == b'<').unwrap() + ck + 1;
        let gt = pdf[lt..].iter().position(|&b| b == b'>').unwrap() + lt;
        let hex = &pdf[lt..gt];
        let bytes = (0..hex.len() / 2)
            .map(|i| {
                u8::from_str_radix(std::str::from_utf8(&hex[i * 2..i * 2 + 2]).unwrap(), 16)
                    .unwrap()
            })
            .collect::<Vec<u8>>();
        // DER total length from the SEQUENCE header.
        let len = der_total_len(&bytes);
        bytes[..len].to_vec()
    }

    fn der_total_len(b: &[u8]) -> usize {
        let l0 = b[1];
        if l0 < 0x80 {
            2 + l0 as usize
        } else {
            let n = (l0 & 0x7f) as usize;
            let mut len = 0usize;
            for &x in &b[2..2 + n] {
                len = (len << 8) | x as usize;
            }
            2 + n + len
        }
    }
}
