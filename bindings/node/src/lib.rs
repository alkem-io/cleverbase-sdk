//! Node/TypeScript (napi-rs) binding for the Cleverbase SDK.
//!
//! Thin idiomatic wrapper: native args in, a CBOR `{handle, step}` Buffer out (callers only decode
//! CBOR). All protocol/crypto logic — including the wire envelope and wire-string enum parsing —
//! lives in the Rust core (Constitution Principle III/VIII).

use cleverbase_core::wire::{decode_handle, encode_handle_step};
use cleverbase_core::{
    begin, resume, ConformanceLevel, CscApi, Environment, HostContext, RequestOptions, ResumeInput,
    Secret, SigningRequest, TrustServiceConfiguration, TsaConfiguration,
};
use napi::bindgen_prelude::{Buffer, Error, Result};
use napi_derive::napi;

fn e(msg: impl ToString) -> Error {
    Error::from_reason(msg.to_string())
}

#[napi]
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
    let config = TrustServiceConfiguration {
        environment: Environment::from_wire(&environment)
            .ok_or_else(|| e("environment must be 'acceptance' or 'production'"))?,
        csc_api: CscApi::from_wire(&csc_api).ok_or_else(|| e("csc_api must be 'v1_rsa' or 'v2_ecdsa'"))?,
        client_id,
        client_secret: Secret::new(client_secret),
        redirect_uri,
        tsa: tsa_url.map(|url| TsaConfiguration { url, auth: None, policy_oid: None }),
    };
    let ctx = HostContext { now_unix: now_unix as i64, entropy: entropy.to_vec() };
    let (handle, step) = begin(request, config, ctx).map_err(e)?;
    Ok(encode_handle_step(&handle, &step).into())
}

#[napi]
pub fn resume_redirect(handle: Buffer, code: String, state: String, now_unix: f64, entropy: Buffer) -> Result<Buffer> {
    let h = decode_handle(handle.as_ref()).map_err(e)?;
    let ctx = HostContext { now_unix: now_unix as i64, entropy: entropy.to_vec() };
    let (handle, step) = resume(h, ResumeInput::RedirectReturn { code, state }, ctx).map_err(e)?;
    Ok(encode_handle_step(&handle, &step).into())
}

#[napi]
pub fn resume_redirect_error(handle: Buffer, error: String, state: String, now_unix: f64, entropy: Buffer) -> Result<Buffer> {
    let h = decode_handle(handle.as_ref()).map_err(e)?;
    let ctx = HostContext { now_unix: now_unix as i64, entropy: entropy.to_vec() };
    let (handle, step) = resume(h, ResumeInput::RedirectError { error, state }, ctx).map_err(e)?;
    Ok(encode_handle_step(&handle, &step).into())
}

#[napi]
pub fn resume_http(handle: Buffer, status: u16, body: Buffer, now_unix: f64, entropy: Buffer) -> Result<Buffer> {
    let h = decode_handle(handle.as_ref()).map_err(e)?;
    let ctx = HostContext { now_unix: now_unix as i64, entropy: entropy.to_vec() };
    let input = ResumeInput::HttpResult { status, headers: vec![], body: body.to_vec() };
    let (handle, step) = resume(h, input, ctx).map_err(e)?;
    Ok(encode_handle_step(&handle, &step).into())
}
