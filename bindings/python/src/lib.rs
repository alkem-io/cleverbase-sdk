//! Python (PyO3) binding for the Cleverbase SDK.
//!
//! Thin idiomatic wrapper: native Python args in; signing returns a CBOR `{handle, step}` envelope,
//! PDF verification returns a typed dictionary, and attestation operations remain CBOR-through.
//! All protocol/crypto logic — including the wire envelope and wire-string enum parsing — lives in
//! the Rust core (Constitution Principle III/VIII). The opaque signing `handle` is passed back
//! verbatim to resume.

use cleverbase_core::wire::{decode_handle, encode_handle_step};
use cleverbase_core::{
    begin, resume, ConformanceLevel, CscApi, Environment, HostContext, RequestOptions, ResumeInput,
    Secret, SigningRequest, TrustServiceConfiguration, TsaConfiguration, VerificationReason,
};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyDict;

fn err(e: impl ToString) -> PyErr {
    PyValueError::new_err(e.to_string())
}

fn wire_reason(reason: &VerificationReason) -> PyResult<String> {
    serde_json::to_value(reason)
        .map_err(err)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| err("verification reason did not serialize as a string"))
}

fn wire_profile(profile: ConformanceLevel) -> PyResult<String> {
    serde_json::to_value(profile)
        .map_err(err)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| err("verification profile did not serialize as a string"))
}

// The scalar list is the binding contract; a private options struct would duplicate the core model.
#[allow(clippy::too_many_arguments)]
fn build_config(
    environment: &str,
    csc_api: &str,
    client_id: &str,
    client_secret: &str,
    redirect_uri: &str,
    tsa_url: Option<String>,
    upstream_base_url: Option<String>,
    tsa_auth: Option<String>,
    tsa_policy_oid: Option<String>,
) -> PyResult<TrustServiceConfiguration> {
    Ok(TrustServiceConfiguration {
        environment: Environment::from_wire(environment)
            .ok_or_else(|| err("environment must be 'acceptance' or 'production'"))?,
        csc_api: CscApi::from_wire(csc_api)
            .ok_or_else(|| err("csc_api must be 'v1_rsa' or 'v2_ecdsa'"))?,
        client_id: client_id.to_string(),
        client_secret: Secret::new(client_secret),
        redirect_uri: redirect_uri.to_string(),
        upstream_base_url,
        tsa: tsa_url.map(|url| TsaConfiguration {
            url,
            auth: tsa_auth.map(Secret::new),
            policy_oid: tsa_policy_oid,
        }),
    })
}

/// Validate signing configuration without creating a signing session. Request-dependent rules are
/// checked later by `begin_signing`, which validates the configuration again.
#[pyfunction]
#[pyo3(signature = (environment, csc_api, client_id, client_secret, redirect_uri, tsa_url=None, *, upstream_base_url=None, tsa_auth=None, tsa_policy_oid=None))]
#[allow(clippy::too_many_arguments)]
fn validate_config(
    environment: &str,
    csc_api: &str,
    client_id: &str,
    client_secret: &str,
    redirect_uri: &str,
    tsa_url: Option<String>,
    upstream_base_url: Option<String>,
    tsa_auth: Option<String>,
    tsa_policy_oid: Option<String>,
) -> PyResult<()> {
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
    .map_err(err)
}

/// Begin a signing flow and return a CBOR handle/step envelope.
///
/// now_unix must have a UTC year in 0000..9999.
/// entropy must contain at least 16 fresh random bytes for this call.
#[pyfunction]
#[pyo3(signature = (document, environment, csc_api, client_id, client_secret, redirect_uri, conformance, now_unix, entropy, tsa_url=None, options_json=None, *, upstream_base_url=None, tsa_auth=None, tsa_policy_oid=None))]
// FFI entry point: the individual scalar args cross the pyo3 boundary cleanly, where a params
// struct would not; the signature mirrors the SDK's begin inputs.
#[allow(clippy::too_many_arguments)]
fn begin_signing(
    document: Vec<u8>,
    environment: &str,
    csc_api: &str,
    client_id: &str,
    client_secret: &str,
    redirect_uri: &str,
    conformance: &str,
    now_unix: i64,
    entropy: Vec<u8>,
    tsa_url: Option<String>,
    options_json: Option<String>,
    upstream_base_url: Option<String>,
    tsa_auth: Option<String>,
    tsa_policy_oid: Option<String>,
) -> PyResult<Vec<u8>> {
    // Optional expected_signer / appearance / signature_meta as a single JSON object (FR-014/FR-016).
    let options = RequestOptions::from_json(options_json.as_deref().unwrap_or("")).map_err(err)?;
    let request = SigningRequest {
        document,
        conformance_level: ConformanceLevel::from_wire(conformance)
            .ok_or_else(|| err("conformance must be 'B-B' or 'B-T'"))?,
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
    let (handle, step) = begin(request, config, HostContext { now_unix, entropy }).map_err(err)?;
    Ok(encode_handle_step(&handle, &step))
}

/// Resume after an OAuth code and state redirect.
///
/// now_unix and entropy follow begin_signing's host-context contract; entropy must be fresh for
/// this call.
#[pyfunction]
fn resume_redirect(
    handle: Vec<u8>,
    code: &str,
    state: &str,
    now_unix: i64,
    entropy: Vec<u8>,
) -> PyResult<Vec<u8>> {
    let h = decode_handle(&handle).map_err(err)?;
    let input = ResumeInput::RedirectReturn {
        code: code.to_string(),
        state: state.to_string(),
    };
    let (handle, step) = resume(h, input, HostContext { now_unix, entropy }).map_err(err)?;
    Ok(encode_handle_step(&handle, &step))
}

/// Resume after an OAuth error redirect.
///
/// now_unix and entropy follow begin_signing's host-context contract; entropy must be fresh for
/// this call.
#[pyfunction]
fn resume_redirect_error(
    handle: Vec<u8>,
    error: &str,
    state: &str,
    now_unix: i64,
    entropy: Vec<u8>,
) -> PyResult<Vec<u8>> {
    let h = decode_handle(&handle).map_err(err)?;
    let input = ResumeInput::RedirectError {
        error: error.to_string(),
        state: state.to_string(),
    };
    let (handle, step) = resume(h, input, HostContext { now_unix, entropy }).map_err(err)?;
    Ok(encode_handle_step(&handle, &step))
}

/// Resume after a performed HTTP effect.
///
/// now_unix and entropy follow begin_signing's host-context contract; entropy must be fresh for
/// this call.
#[pyfunction]
fn resume_http(
    handle: Vec<u8>,
    status: u16,
    body: Vec<u8>,
    now_unix: i64,
    entropy: Vec<u8>,
) -> PyResult<Vec<u8>> {
    let h = decode_handle(&handle).map_err(err)?;
    let input = ResumeInput::HttpResult {
        status,
        headers: vec![],
        body,
    };
    let (handle, step) = resume(h, input, HostContext { now_unix, entropy }).map_err(err)?;
    Ok(encode_handle_step(&handle, &step))
}

/// Verify one PDF's ByteRange and embedded CMS signature.
///
/// Invalid input returns a typed verdict with integrity false; this operation does not establish
/// certificate-chain trust, revocation status, signer authorization, TSA trust, or TSA policy.
#[pyfunction]
fn verify_pdf(py: Python<'_>, document: Vec<u8>) -> PyResult<Py<PyDict>> {
    let verification = cleverbase_core::verify_pdf(&document);
    let result = PyDict::new(py);
    result.set_item("integrity", verification.integrity)?;
    result.set_item(
        "profile",
        verification.profile.map(wire_profile).transpose()?,
    )?;
    if let Some(signer) = verification.signer {
        let mapped = PyDict::new(py);
        mapped.set_item("serial", signer.serial_number)?;
        mapped.set_item("cn", signer.common_name)?;
        result.set_item("signer", mapped)?;
    } else {
        result.set_item("signer", py.None())?;
    }
    let reasons = verification
        .reasons
        .iter()
        .map(wire_reason)
        .collect::<PyResult<Vec<_>>>()?;
    result.set_item("reasons", reasons)?;
    Ok(result.unbind())
}

/// Run the EUDI attestation verifier over a CBOR `VerifyRequest` envelope (attestation schema
/// version 5) and return the CBOR `VerifyResponse`.
///
/// Unlike the signing surface, the attestation surface is CBOR-in / CBOR-out: the caller builds the
/// `VerifyRequest` and decodes the `VerifyResponse` (see the wire schema). The VALID/INVALID verdict
/// (and any decode/usage error) rides *inside* the response envelope — a malformed request yields a
/// well-formed response carrying an `err` outcome rather than raising. The holder key never crosses
/// this boundary.
#[pyfunction]
// CBOR-through: every outcome (verdict or decode/usage error) rides inside the response envelope, so
// this never raises — but the fallible `PyResult` signature is kept uniform with the rest of the
// module (and reserves the Python error channel) rather than diverging to a bare return.
#[allow(clippy::unnecessary_wraps)]
fn attestation_verify(request: Vec<u8>) -> PyResult<Vec<u8>> {
    Ok(cleverbase_attestation::wire::process_verify_bytes(&request))
}

/// Run the EUDI attestation SET-LEVEL OpenID4VP verifier over a CBOR `WireVpTokenRequest` envelope
/// (attestation schema version 5) and return the CBOR `WireVpTokenResponse`.
///
/// Unlike [`attestation_verify`] (a single presentation), this carries the whole multi-credential
/// `vp_token` (`{credential_id: [presentations]}`) so the core folds the OpenID4VP set-level DCQL
/// semantics (`credential_sets` required option-sets + `multiple` cardinality) AND authenticates
/// supplied signed Token Status List tokens in-core across the set. CBOR-in / CBOR-out: the set-level
/// verdict (`satisfied` + per-credential results) and any decode/usage error ride *inside* the
/// response envelope — a malformed request yields a well-formed response carrying an `err` outcome
/// rather than raising. The holder key never crosses this boundary.
///
/// The set-level surface does NOT run the opt-in eIDAS qualified-status gate: a request with
/// `policy.qualified_gate = true` yields an `err` outcome (verify each presentation via
/// `attestation_verify` if the qualified gate is required).
#[pyfunction]
// CBOR-through: every outcome rides inside the response envelope (see [`attestation_verify`]).
#[allow(clippy::unnecessary_wraps)]
fn attestation_verify_vp_token(request: Vec<u8>) -> PyResult<Vec<u8>> {
    Ok(cleverbase_attestation::wire::process_vp_token_bytes(
        &request,
    ))
}

/// Drive the EUDI attestation issuance / presentation sans-IO state machine over a CBOR
/// `IssuanceRequest` envelope (issuance schema version 1) and return the CBOR `IssuanceResponse`.
///
/// Like [`attestation_verify`] it is CBOR-in / CBOR-out (see the wire schema): the next step / outcome
/// (and any decode/usage error) rides *inside* the response envelope. The holder's private key never
/// crosses this boundary.
#[pyfunction]
// CBOR-through: see [`attestation_verify`] — the outcome rides inside the response envelope, so this
// never raises; the `PyResult` signature is kept uniform with the rest of the module.
#[allow(clippy::unnecessary_wraps)]
fn attestation_issuance(request: Vec<u8>) -> PyResult<Vec<u8>> {
    Ok(cleverbase_attestation::issuance::wire::process_issuance_bytes(&request))
}

#[pymodule]
fn cleverbase(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("SCHEMA_VERSION", cleverbase_core::SCHEMA_VERSION)?;
    m.add_function(wrap_pyfunction!(validate_config, m)?)?;
    m.add_function(wrap_pyfunction!(begin_signing, m)?)?;
    m.add_function(wrap_pyfunction!(resume_redirect, m)?)?;
    m.add_function(wrap_pyfunction!(resume_redirect_error, m)?)?;
    m.add_function(wrap_pyfunction!(resume_http, m)?)?;
    m.add_function(wrap_pyfunction!(verify_pdf, m)?)?;
    m.add_function(wrap_pyfunction!(attestation_verify, m)?)?;
    m.add_function(wrap_pyfunction!(attestation_verify_vp_token, m)?)?;
    m.add_function(wrap_pyfunction!(attestation_issuance, m)?)?;
    Ok(())
}
