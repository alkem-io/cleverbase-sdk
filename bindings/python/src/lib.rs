//! Python (PyO3) binding for the Cleverbase SDK.
//!
//! Thin idiomatic wrapper: native Python args in, and a CBOR `{handle, step}` result out (so
//! callers only ever *decode* CBOR, never hand-build it). All protocol/crypto logic — including the
//! wire envelope and the wire-string enum parsing — lives in the Rust core (Constitution
//! Principle III/VIII). The opaque `handle` is passed back verbatim to resume.

use cleverbase_core::wire::{decode_handle, encode_handle_step};
use cleverbase_core::{
    begin, resume, ConformanceLevel, CscApi, Environment, HostContext, RequestOptions, ResumeInput,
    Secret, SigningRequest, TrustServiceConfiguration, TsaConfiguration,
};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

fn err(e: impl ToString) -> PyErr {
    PyValueError::new_err(e.to_string())
}

#[pyfunction]
#[pyo3(signature = (document, environment, csc_api, client_id, client_secret, redirect_uri, conformance, now_unix, entropy, tsa_url=None, options_json=None))]
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
    let config = TrustServiceConfiguration {
        environment: Environment::from_wire(environment)
            .ok_or_else(|| err("environment must be 'acceptance' or 'production'"))?,
        csc_api: CscApi::from_wire(csc_api).ok_or_else(|| err("csc_api must be 'v1_rsa' or 'v2_ecdsa'"))?,
        client_id: client_id.to_string(),
        client_secret: Secret::new(client_secret),
        redirect_uri: redirect_uri.to_string(),
        tsa: tsa_url.map(|url| TsaConfiguration { url, auth: None, policy_oid: None }),
    };
    let (handle, step) = begin(request, config, HostContext { now_unix, entropy }).map_err(err)?;
    Ok(encode_handle_step(&handle, &step))
}

#[pyfunction]
fn resume_redirect(handle: Vec<u8>, code: &str, state: &str, now_unix: i64, entropy: Vec<u8>) -> PyResult<Vec<u8>> {
    let h = decode_handle(&handle).map_err(err)?;
    let input = ResumeInput::RedirectReturn { code: code.to_string(), state: state.to_string() };
    let (handle, step) = resume(h, input, HostContext { now_unix, entropy }).map_err(err)?;
    Ok(encode_handle_step(&handle, &step))
}

#[pyfunction]
fn resume_redirect_error(handle: Vec<u8>, error: &str, state: &str, now_unix: i64, entropy: Vec<u8>) -> PyResult<Vec<u8>> {
    let h = decode_handle(&handle).map_err(err)?;
    let input = ResumeInput::RedirectError { error: error.to_string(), state: state.to_string() };
    let (handle, step) = resume(h, input, HostContext { now_unix, entropy }).map_err(err)?;
    Ok(encode_handle_step(&handle, &step))
}

#[pyfunction]
fn resume_http(handle: Vec<u8>, status: u16, body: Vec<u8>, now_unix: i64, entropy: Vec<u8>) -> PyResult<Vec<u8>> {
    let h = decode_handle(&handle).map_err(err)?;
    let input = ResumeInput::HttpResult { status, headers: vec![], body };
    let (handle, step) = resume(h, input, HostContext { now_unix, entropy }).map_err(err)?;
    Ok(encode_handle_step(&handle, &step))
}

#[pymodule]
fn cleverbase(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("SCHEMA_VERSION", cleverbase_core::SCHEMA_VERSION)?;
    m.add_function(wrap_pyfunction!(begin_signing, m)?)?;
    m.add_function(wrap_pyfunction!(resume_redirect, m)?)?;
    m.add_function(wrap_pyfunction!(resume_redirect_error, m)?)?;
    m.add_function(wrap_pyfunction!(resume_http, m)?)?;
    Ok(())
}
