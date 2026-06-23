//! Versioned CBOR wire envelope for the C-ABI (Go) and WASM boundaries (contracts/sdk-api.md).
//!
//! Native bindings (PyO3, napi-rs) call the typed Rust API directly; Go and WASM exchange these
//! CBOR-encoded envelopes. The envelope carries a `schema_version` so a binding can refuse a
//! payload it cannot read (Constitution Principle VII).

use serde::{Deserialize, Serialize};

use crate::effects::Step;
use crate::session::SigningSessionHandle;
use crate::signing::{HostContext, ResumeInput};
use crate::types::{SigningRequest, TrustServiceConfiguration};
use crate::SCHEMA_VERSION;

/// A decoded operation request from a non-native binding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
pub enum WireOp {
    Begin {
        request: SigningRequest,
        config: TrustServiceConfiguration,
        ctx: HostContext,
    },
    Resume {
        handle: SigningSessionHandle,
        input: ResumeInput,
        ctx: HostContext,
    },
}

/// Versioned request envelope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WireRequest {
    pub schema_version: u32,
    pub op: WireOp,
}

/// Versioned response envelope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WireResponse {
    pub schema_version: u32,
    pub result: WireResult,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
pub enum WireResult {
    Ok {
        handle: SigningSessionHandle,
        step: Step,
    },
    Err {
        message: String,
    },
}

/// Decode a CBOR request envelope, rejecting unknown schema versions.
pub fn decode_request(bytes: &[u8]) -> Result<WireRequest, String> {
    let req: WireRequest = ciborium::from_reader(bytes).map_err(|e| e.to_string())?;
    if req.schema_version != SCHEMA_VERSION {
        return Err(format!(
            "unsupported schema_version {} (this core speaks {})",
            req.schema_version, SCHEMA_VERSION
        ));
    }
    Ok(req)
}

/// Encode a CBOR response envelope at the current schema version.
pub fn encode_response(result: WireResult) -> Vec<u8> {
    let resp = WireResponse {
        schema_version: SCHEMA_VERSION,
        result,
    };
    let mut buf = Vec::new();
    ciborium::into_writer(&resp, &mut buf)
        .expect("CBOR serialization of WireResponse is infallible");
    buf
}

/// Binding envelope: the session handle as opaque CBOR bytes plus the next step. The native
/// bindings (Python/Node) return this so callers only ever *decode* CBOR and pass the handle back
/// verbatim. Single source of truth shared by all bindings (Constitution Principle III/VIII).
#[derive(Serialize)]
struct HandleStepPair {
    #[serde(with = "serde_bytes")]
    handle: Vec<u8>,
    step: Step,
}

/// Encode `(handle, step)` as the binding envelope CBOR.
pub fn encode_handle_step(handle: &SigningSessionHandle, step: &Step) -> Vec<u8> {
    let mut handle_cbor = Vec::new();
    ciborium::into_writer(handle, &mut handle_cbor)
        .expect("CBOR serialization of the session handle is infallible");
    let pair = HandleStepPair {
        handle: handle_cbor,
        step: step.clone(),
    };
    let mut out = Vec::new();
    ciborium::into_writer(&pair, &mut out).expect("CBOR serialization of the pair is infallible");
    out
}

/// Decode an opaque handle (from the binding envelope) back into a session handle.
pub fn decode_handle(bytes: &[u8]) -> Result<SigningSessionHandle, String> {
    ciborium::from_reader(bytes).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        ConformanceLevel, CscApi, Environment, Secret, SigningRequest, TrustServiceConfiguration,
    };

    fn sample_begin() -> WireRequest {
        WireRequest {
            schema_version: SCHEMA_VERSION,
            op: WireOp::Begin {
                request: SigningRequest {
                    document: b"%PDF-1.7".to_vec(),
                    conformance_level: ConformanceLevel::BB,
                    expected_signer: None,
                    appearance: None,
                    signature_meta: None,
                },
                config: TrustServiceConfiguration {
                    environment: Environment::Acceptance,
                    csc_api: CscApi::V1Rsa,
                    client_id: "c".into(),
                    client_secret: Secret::new("s"),
                    redirect_uri: "https://app/cb".into(),
                    tsa: None,
                },
                ctx: HostContext {
                    now_unix: 1,
                    entropy: vec![0u8; 16],
                },
            },
        }
    }

    #[test]
    fn request_roundtrip() {
        let req = sample_begin();
        let mut buf = Vec::new();
        ciborium::into_writer(&req, &mut buf).unwrap();
        let decoded = decode_request(&buf).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn decode_rejects_wrong_version() {
        let mut req = sample_begin();
        req.schema_version = 999;
        let mut buf = Vec::new();
        ciborium::into_writer(&req, &mut buf).unwrap();
        let err = decode_request(&buf).unwrap_err();
        assert!(err.contains("unsupported schema_version 999"));
    }

    #[test]
    fn response_encode_decode() {
        let bytes = encode_response(WireResult::Err {
            message: "boom".into(),
        });
        let resp: WireResponse = ciborium::from_reader(&bytes[..]).unwrap();
        assert_eq!(resp.schema_version, SCHEMA_VERSION);
        assert_eq!(
            resp.result,
            WireResult::Err {
                message: "boom".into()
            }
        );
    }
}
