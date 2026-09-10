//! Node/TypeScript (napi-rs) binding for the Cleverbase SDK.
//!
//! Thin idiomatic wrapper: native args in, a CBOR `{handle, step}` Buffer out (callers only decode
//! CBOR). All protocol/crypto logic — including the wire envelope and wire-string enum parsing —
//! lives in the Rust core (Constitution Principle III/VIII).

use cleverbase_core::wire::{decode_handle, encode_handle_step};
use cleverbase_core::{
    begin, resume, ConformanceLevel, CscApi, Environment, HostContext, RequestOptions, ResumeInput,
    Secret, SigningRequest, TrustServiceConfiguration, TsaConfiguration, VerificationReason,
};
use napi::bindgen_prelude::{Buffer, Either, Error, Null, Result};
use napi_derive::napi;

fn e(msg: impl ToString) -> Error {
    Error::from_reason(msg.to_string())
}

fn wire_reason(reason: &VerificationReason) -> Result<String> {
    serde_json::to_value(reason)
        .map_err(e)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| e("verification reason did not serialize as a string"))
}

fn wire_profile(profile: ConformanceLevel) -> Result<String> {
    serde_json::to_value(profile)
        .map_err(e)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| e("verification profile did not serialize as a string"))
}

/// Identity read from the embedded signer certificate.
#[napi(object)]
#[derive(Debug)]
pub struct PdfSigner {
    /// Canonical uppercase certificate serial without separators.
    pub serial: String,
    /// Subject common name.
    pub cn: String,
}

/// Integrity-only verdict for one PDF signature.
#[napi(object)]
#[derive(Debug)]
pub struct PdfVerification {
    /// Whether the CMS signature and signed PDF bytes are internally consistent.
    pub integrity: bool,
    /// PAdES profile, or null when integrity is false.
    pub profile: Either<String, Null>,
    /// Embedded signer identity, or null when integrity is false.
    pub signer: Either<PdfSigner, Null>,
    /// Machine-readable snake_case failure codes; empty when integrity is true.
    pub reasons: Vec<String>,
}

// The scalar list is the binding contract; a private options struct would duplicate the core model.
#[allow(clippy::too_many_arguments)]
fn build_config(
    environment: String,
    csc_api: String,
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    tsa_url: Option<String>,
    upstream_base_url: Option<String>,
    tsa_auth: Option<String>,
    tsa_policy_oid: Option<String>,
) -> Result<TrustServiceConfiguration> {
    Ok(TrustServiceConfiguration {
        environment: Environment::from_wire(&environment)
            .ok_or_else(|| e("environment must be 'acceptance' or 'production'"))?,
        csc_api: CscApi::from_wire(&csc_api)
            .ok_or_else(|| e("csc_api must be 'v1_rsa' or 'v2_ecdsa'"))?,
        client_id,
        client_secret: Secret::new(client_secret),
        redirect_uri,
        upstream_base_url,
        tsa: tsa_url.map(|url| TsaConfiguration {
            url,
            auth: tsa_auth.map(Secret::new),
            policy_oid: tsa_policy_oid,
        }),
    })
}

/// Validate signing configuration without creating a signing session. Request-dependent rules are
/// checked later by `beginSigning`, which validates the configuration again.
#[napi]
#[allow(clippy::too_many_arguments)]
pub fn validate_config(
    environment: String,
    csc_api: String,
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    tsa_url: Option<String>,
    upstream_base_url: Option<String>,
    tsa_auth: Option<String>,
    tsa_policy_oid: Option<String>,
) -> Result<()> {
    build_config(
        environment,
        csc_api,
        client_id,
        client_secret,
        redirect_uri,
        tsa_url,
        upstream_base_url,
        tsa_auth,
        tsa_policy_oid,
    )?
    .validate()
    .map_err(e)
}

/// Begin a signing flow. Returns a CBOR handle/step Buffer (decode-only for the caller).
///
/// nowUnix must have a UTC year in 0000..9999. entropy must contain at least 16 fresh random bytes
/// for this call.
#[napi]
// FFI entry point: the individual scalar args cross the napi boundary cleanly, where a params
// struct would not; the signature mirrors the SDK's begin inputs.
#[allow(clippy::too_many_arguments)]
pub fn begin_signing(
    document: Buffer,
    environment: String,
    csc_api: String,
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    conformance: String,
    now_unix: f64,
    entropy: Buffer,
    tsa_url: Option<String>,
    options_json: Option<String>,
    upstream_base_url: Option<String>,
    tsa_auth: Option<String>,
    tsa_policy_oid: Option<String>,
) -> Result<Buffer> {
    // Optional expected_signer / appearance / signature_meta as a single JSON object (FR-014/FR-016).
    let options = RequestOptions::from_json(options_json.as_deref().unwrap_or("")).map_err(e)?;
    let request = SigningRequest {
        document: document.to_vec(),
        conformance_level: ConformanceLevel::from_wire(&conformance)
            .ok_or_else(|| e("conformance must be 'B-B' or 'B-T'"))?,
        expected_signer: options.expected_signer,
        appearance: options.appearance,
        signature_meta: options.signature_meta,
    };
    let config = build_config(
        environment,
        csc_api,
        client_id,
        client_secret,
        redirect_uri,
        tsa_url,
        upstream_base_url,
        tsa_auth,
        tsa_policy_oid,
    )?;
    let ctx = HostContext {
        now_unix: now_unix as i64,
        entropy: entropy.to_vec(),
    };
    let (handle, step) = begin(request, config, ctx).map_err(e)?;
    Ok(encode_handle_step(&handle, &step).into())
}

/// Resume after an OAuth code and state redirect. Returns a CBOR handle/step Buffer.
///
/// nowUnix and entropy follow beginSigning's host-context contract; entropy must be fresh for this
/// call.
#[napi]
pub fn resume_redirect(
    handle: Buffer,
    code: String,
    state: String,
    now_unix: f64,
    entropy: Buffer,
) -> Result<Buffer> {
    let h = decode_handle(handle.as_ref()).map_err(e)?;
    let ctx = HostContext {
        now_unix: now_unix as i64,
        entropy: entropy.to_vec(),
    };
    let (handle, step) = resume(h, ResumeInput::RedirectReturn { code, state }, ctx).map_err(e)?;
    Ok(encode_handle_step(&handle, &step).into())
}

/// Resume after an OAuth error redirect. Returns a CBOR handle/step Buffer.
///
/// nowUnix and entropy follow beginSigning's host-context contract; entropy must be fresh for this
/// call.
#[napi]
pub fn resume_redirect_error(
    handle: Buffer,
    error: String,
    state: String,
    now_unix: f64,
    entropy: Buffer,
) -> Result<Buffer> {
    let h = decode_handle(handle.as_ref()).map_err(e)?;
    let ctx = HostContext {
        now_unix: now_unix as i64,
        entropy: entropy.to_vec(),
    };
    let (handle, step) = resume(h, ResumeInput::RedirectError { error, state }, ctx).map_err(e)?;
    Ok(encode_handle_step(&handle, &step).into())
}

/// Resume after performing an HTTP effect (status + body). Returns a CBOR handle/step Buffer.
///
/// nowUnix and entropy follow beginSigning's host-context contract; entropy must be fresh for this
/// call.
#[napi]
pub fn resume_http(
    handle: Buffer,
    status: u16,
    body: Buffer,
    now_unix: f64,
    entropy: Buffer,
) -> Result<Buffer> {
    let h = decode_handle(handle.as_ref()).map_err(e)?;
    let ctx = HostContext {
        now_unix: now_unix as i64,
        entropy: entropy.to_vec(),
    };
    let input = ResumeInput::HttpResult {
        status,
        headers: vec![],
        body: body.to_vec(),
    };
    let (handle, step) = resume(h, input, ctx).map_err(e)?;
    Ok(encode_handle_step(&handle, &step).into())
}

/// Verify one PDF's ByteRange and embedded CMS signature.
///
/// Invalid input returns a typed verdict with integrity false; this operation does not establish
/// certificate-chain trust, revocation status, signer authorization, TSA trust, or TSA policy.
#[napi]
pub fn verify_pdf(document: Buffer) -> Result<PdfVerification> {
    let verification = cleverbase_core::verify_pdf(&document);
    Ok(PdfVerification {
        integrity: verification.integrity,
        profile: match verification.profile {
            Some(profile) => Either::A(wire_profile(profile)?),
            None => Either::B(Null),
        },
        signer: match verification.signer {
            Some(signer) => Either::A(PdfSigner {
                serial: signer.serial_number,
                cn: signer.common_name,
            }),
            None => Either::B(Null),
        },
        reasons: verification
            .reasons
            .iter()
            .map(wire_reason)
            .collect::<Result<Vec<_>>>()?,
    })
}

/// Verify an EUDI attestation presentation.
///
/// CBOR-through: takes a CBOR-encoded `VerifyRequest` (attestation wire schema v5 — the presented
/// SD-JWT VC / mdoc, verifier policy, host-resolved trust anchors, and verification context) and
/// returns a CBOR-encoded `VerifyResponse` (schema v5) carrying the `outcome`. The always-on verdict
/// (`VerificationResult` — `valid` plus machine-readable reason codes) and any decode/usage error
/// ride *inside* the response body, not through this call's error channel; a malformed request
/// fails closed to an `err` outcome rather than throwing. The holder's private key never crosses
/// this boundary — the verifier only inspects the presentation the holder already produced. All
/// protocol/crypto logic lives in `cleverbase-attestation` (Constitution Principle III/VIII); this
/// wrapper is bytes-in / bytes-out only.
#[napi]
pub fn attestation_verify(request: Buffer) -> Result<Buffer> {
    Ok(cleverbase_attestation::wire::process_verify_bytes(&request).into())
}

/// Verify a set-level OpenID4VP `vp_token` (the multi-credential presentation).
///
/// CBOR-through: takes a CBOR-encoded `WireVpTokenRequest` (attestation wire schema v5 — the OpenID4VP
/// request, the whole `{credential_id: [presentations]}` `vp_token`, verifier policy, host-resolved
/// trust anchors, per-credential statuses, and any signed Token Status List tokens) and returns a
/// CBOR-encoded `WireVpTokenResponse` (schema v5) carrying the `outcome`. Unlike `attestation_verify`
/// (a single presentation), this folds the OpenID4VP set-level DCQL semantics (`credential_sets` +
/// `multiple` cardinality) AND authenticates supplied status tokens in-core across the set. The
/// set-level verdict (`satisfied` + per-credential results) and any decode/usage error ride *inside*
/// the response body, not through this call's error channel; a malformed request fails closed to an
/// `err` outcome rather than throwing. All protocol/crypto logic lives in `cleverbase-attestation`
/// (Constitution Principle III/VIII); this wrapper is bytes-in / bytes-out only.
///
/// The set-level surface does NOT run the opt-in eIDAS qualified-status gate: a request with
/// `policy.qualified_gate = true` yields an `err` outcome (verify each presentation via
/// `attestation_verify` if the qualified gate is required).
#[napi]
pub fn attestation_verify_vp_token(request: Buffer) -> Result<Buffer> {
    Ok(cleverbase_attestation::wire::process_vp_token_bytes(&request).into())
}

/// Drive an EUDI attestation issuance / holder-presentation step.
///
/// CBOR-through: takes a CBOR-encoded `IssuanceRequest` (issuance wire schema v1 — one `obtain` /
/// `prepare-present` / `finish-present` operation plus its opaque carried session/prepared handle)
/// and returns a CBOR-encoded `IssuanceResponse` (schema v1) carrying the `outcome` (the next step,
/// the produced `vp_token`, or an `err`). As with `attestation_verify`, errors ride inside the
/// response — a malformed request fails closed to an `err` outcome — and the holder key never
/// crosses this boundary (the host signs the returned `SigningInput` out-of-band and hands the
/// signature back on the next step). All protocol/crypto logic lives in `cleverbase-attestation`
/// (Constitution Principle III/VIII); this wrapper is bytes-in / bytes-out only.
#[napi]
pub fn attestation_issuance(request: Buffer) -> Result<Buffer> {
    Ok(cleverbase_attestation::issuance::wire::process_issuance_bytes(&request).into())
}
