//! Versioned CBOR wire envelope for the attestation C-ABI (and WASM) boundary.
//!
//! Mirrors `cleverbase-core::wire`: the C-ABI and non-native bindings exchange these CBOR-encoded
//! envelopes; native bindings can call the typed Rust API directly. The envelope carries an
//! [`ATTESTATION_SCHEMA_VERSION`] so a binding can refuse a payload it cannot read (Principle VII).
//!
//! Protocol logic lives **here, in the core** — the `cleverbase-ffi` C-ABI only wraps
//! [`process_verify_bytes`] in the pointer/length/free dance (Principle III: no protocol logic in
//! bindings). The `verify` operation is the always-on bar (contracts/verifier.md); its full
//! implementation lands in task **T016**. Until then this returns a structured
//! [`VerifyOutcome::NotImplemented`] so the bindings can link and exercise the CBOR seam now.

use serde::{Deserialize, Serialize};

use crate::types::{VerificationPolicy, VerificationResult};

/// Wire schema version of the attestation envelope. Bumped on a breaking CBOR-shape change within a
/// SemVer major (independent of the signing core's `SCHEMA_VERSION`).
pub const ATTESTATION_SCHEMA_VERSION: u32 = 1;

/// A `verify` request: the presented credential plus the verifier policy.
///
/// `presentation` is the encoded credential as received (compact SD-JWT(+KB) or CBOR
/// `DeviceResponse`). The configured trust anchors and the OpenID4VP `request` binding are carried by
/// the fuller envelope that lands with the verifier implementation (task T016); the foundation seam
/// carries the policy so the shape is stable and the not-implemented path is exercisable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyRequest {
    /// Wire schema version of this envelope.
    pub schema_version: u32,
    /// The presented credential, encoded.
    #[serde(with = "serde_bytes")]
    pub presentation: Vec<u8>,
    /// The verifier policy.
    pub policy: VerificationPolicy,
}

/// The outcome of a `verify` operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifyOutcome {
    /// The verdict (the always-on bar). Produced once task T016 lands the verifier.
    Ok {
        /// The verification result.
        result: VerificationResult,
    },
    /// A decode/usage error rendered as a message (e.g. an unsupported schema version).
    Err {
        /// Human-readable error message.
        message: String,
    },
    /// The verifier is not yet implemented (the current foundation state). Distinct from `Err` so a
    /// caller can tell "not built yet" from "your request was rejected".
    NotImplemented,
}

/// A versioned `verify` response envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyResponse {
    /// Wire schema version of this envelope.
    pub schema_version: u32,
    /// The operation outcome.
    pub outcome: VerifyOutcome,
}

/// Decode a `verify` request envelope, rejecting unknown schema versions.
///
/// # Errors
///
/// Returns the decode error (or a schema-version mismatch message) as a `String`.
pub fn decode_verify_request(bytes: &[u8]) -> Result<VerifyRequest, String> {
    let req: VerifyRequest = ciborium::from_reader(bytes).map_err(|e| e.to_string())?;
    if req.schema_version != ATTESTATION_SCHEMA_VERSION {
        return Err(format!(
            "unsupported attestation schema_version {} (this core speaks {ATTESTATION_SCHEMA_VERSION})",
            req.schema_version
        ));
    }
    Ok(req)
}

/// Encode a `verify` response envelope at the current schema version.
#[must_use]
pub fn encode_verify_response(outcome: VerifyOutcome) -> Vec<u8> {
    let resp = VerifyResponse {
        schema_version: ATTESTATION_SCHEMA_VERSION,
        outcome,
    };
    let mut buf = Vec::new();
    // Infallible: writing CBOR into an in-memory Vec cannot fail, and VerifyResponse is a plain serde
    // type. There is no error channel on this helper, so an impossible failure should surface.
    #[allow(clippy::expect_used)] // infallible: CBOR into a Vec writer
    {
        ciborium::into_writer(&resp, &mut buf)
            .expect("CBOR serialization of VerifyResponse is infallible");
    }
    buf
}

/// Decode → verify → encode. Pure; shared by the C-ABI, language bindings, and tests (single source
/// of truth — Principle III). The verifier itself lands in task T016; until then a well-formed
/// request yields [`VerifyOutcome::NotImplemented`] and a malformed one yields [`VerifyOutcome::Err`].
#[must_use]
pub fn process_verify_bytes(input: &[u8]) -> Vec<u8> {
    let outcome = match decode_verify_request(input) {
        Ok(_req) => VerifyOutcome::NotImplemented,
        Err(message) => VerifyOutcome::Err { message },
    };
    encode_verify_response(outcome)
}

#[cfg(test)]
mod tests {
    use super::{
        decode_verify_request, encode_verify_response, process_verify_bytes, VerifyOutcome,
        VerifyRequest, VerifyResponse, ATTESTATION_SCHEMA_VERSION,
    };
    use crate::types::VerificationPolicy;

    fn encode(req: &VerifyRequest) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::into_writer(req, &mut buf).unwrap();
        buf
    }

    fn well_formed_request() -> VerifyRequest {
        VerifyRequest {
            schema_version: ATTESTATION_SCHEMA_VERSION,
            presentation: b"eyJ...~WyJ...~".to_vec(),
            policy: VerificationPolicy::default(),
        }
    }

    #[test]
    fn well_formed_request_yields_not_implemented() {
        let out = process_verify_bytes(&encode(&well_formed_request()));
        let resp: VerifyResponse = ciborium::from_reader(&out[..]).unwrap();
        assert_eq!(resp.schema_version, ATTESTATION_SCHEMA_VERSION);
        assert_eq!(resp.outcome, VerifyOutcome::NotImplemented);
    }

    #[test]
    fn garbage_input_yields_err_outcome() {
        let out = process_verify_bytes(&[0xff, 0x00, 0x13, 0x37]);
        let resp: VerifyResponse = ciborium::from_reader(&out[..]).unwrap();
        assert!(matches!(resp.outcome, VerifyOutcome::Err { .. }));
    }

    #[test]
    fn wrong_schema_version_is_rejected() {
        let mut req = well_formed_request();
        req.schema_version = ATTESTATION_SCHEMA_VERSION + 1;
        let err = decode_verify_request(&encode(&req)).unwrap_err();
        assert!(err.contains("unsupported attestation schema_version"));
    }

    #[test]
    fn response_round_trips_through_cbor() {
        let bytes = encode_verify_response(VerifyOutcome::NotImplemented);
        let resp: VerifyResponse = ciborium::from_reader(&bytes[..]).unwrap();
        assert_eq!(resp.outcome, VerifyOutcome::NotImplemented);
    }
}
