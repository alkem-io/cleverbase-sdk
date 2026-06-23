//! The serializable, versioned signing session handle (FR-013, data-model).
//!
//! The integrator persists this between the authorization round-trip and finalization. It carries
//! short-lived authorization material and the request/config, so it MUST be stored securely
//! server-side (encrypted at rest).

use serde::{Deserialize, Serialize};

use crate::evidence::SignerIdentity;
use crate::signing::csc::KeyAlgo;
use crate::types::{ConformanceLevel, Secret, SigningRequest, TrustServiceConfiguration};

/// Phase of the signing state machine. Each `*Pending` phase awaits a specific `ResumeInput`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigningPhase {
    /// Awaiting the service-scope authorization redirect return.
    ServiceAuthPending,
    /// Awaiting the service-scope token-exchange HTTP response.
    ServiceTokenPending,
    /// Awaiting the credentials/list HTTP response.
    ListPending,
    /// Awaiting the credentials/info HTTP response.
    InfoPending,
    /// Awaiting the credential-scope authorization redirect return.
    CredentialAuthPending,
    /// Awaiting the credential-scope token (SAD) HTTP response.
    CredentialTokenPending,
    /// Awaiting the signatures/signHash HTTP response.
    SignPending,
    /// Awaiting the timestamp-authority HTTP response (B-T only).
    TimestampPending,
    Completed,
    Failed,
}

/// Opaque-to-the-integrator, serializable session state.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SigningSessionHandle {
    pub schema_version: u32,
    pub phase: SigningPhase,
    /// SHA-256 of the document bytes (hex), for correlation.
    pub request_digest: String,
    pub conformance_level: ConformanceLevel,
    pub correlation_id: String,
    /// OAuth `state` for the currently pending redirect, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<String>,

    // ---- carried signing state (sensitive; encrypt at rest) ----
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_token: Option<Secret>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_chain: Option<Vec<Vec<u8>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_algo: Option<KeyAlgo>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "serde_bytes")]
    pub signed_attrs_der: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "serde_bytes")]
    pub staged_pdf: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contents_span: Option<(usize, usize)>,
    /// Assembled CMS (without timestamp), carried from signing to the B-T timestamp step.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "serde_bytes")]
    pub cms_der: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_time_unix: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<SignerIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pdf_a: Option<bool>,

    /// Carried so the flow can resume statelessly. Contains the document; treat as sensitive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<SigningRequest>,
    /// Carried so the flow can resume statelessly. Contains secrets; encrypt at rest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<TrustServiceConfiguration>,
}

impl SigningSessionHandle {
    /// Build a terminal (Completed/Failed) handle that carries no further state.
    pub fn terminal(
        phase: SigningPhase,
        request_digest: String,
        conformance_level: ConformanceLevel,
        correlation_id: String,
    ) -> Self {
        SigningSessionHandle {
            schema_version: crate::SCHEMA_VERSION,
            phase,
            request_digest,
            conformance_level,
            correlation_id,
            state: None,
            credential_id: None,
            service_token: None,
            cert_chain: None,
            key_algo: None,
            signed_attrs_der: None,
            staged_pdf: None,
            contents_span: None,
            cms_der: None,
            signing_time_unix: None,
            signer: None,
            pdf_a: None,
            request: None,
            config: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_roundtrips_and_carries_version() {
        let h = SigningSessionHandle::terminal(
            SigningPhase::Failed,
            "abcd".into(),
            ConformanceLevel::BB,
            "corr-1".into(),
        );
        assert_eq!(h.schema_version, crate::SCHEMA_VERSION);
        let mut buf = Vec::new();
        ciborium::into_writer(&h, &mut buf).unwrap();
        let back: SigningSessionHandle = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(h, back);
    }
}
