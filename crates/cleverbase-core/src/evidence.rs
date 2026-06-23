//! Per-operation signing evidence record, returned on success AND failure (FR-015).

use serde::{Deserialize, Serialize};

use crate::types::ConformanceLevel;

/// Terminal outcome of a signing attempt (data-model: SigningOutcome).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigningOutcome {
    Signed,
    Declined,
    AuthorizationExpired,
    CredentialUnavailable,
    IdentityMismatch,
    TimestampFailed,
    InvalidDocument,
    AppearancePlacementError,
    /// The signature returned by the trust service failed verification against the signer's
    /// certificate — the core refuses to report `Signed` for a signature it cannot verify.
    SignatureInvalid,
}

impl SigningOutcome {
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Signed)
    }
}

/// The signer's identity, derived from their qualified certificate subject.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerIdentity {
    pub serial_number: String,
    pub common_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub surname: Option<String>,
    pub raw_subject: String,
}

/// Trusted-timestamp summary recorded in the evidence (B-T).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimestampInfo {
    pub tsa: String,
    /// The TSA's own `genTime` from the timestamp token (Unix seconds).
    pub gen_time: i64,
    /// The TSA policy OID, when the caller requested a specific one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_oid: Option<String>,
}

/// Structured evidence emitted for every signing attempt (FR-015). Not persisted by the SDK.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigningEvidenceRecord {
    /// SHA-256 of the to-be-signed content (hex).
    pub request_digest: String,
    pub outcome: SigningOutcome,
    pub conformance_level: ConformanceLevel,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<SignerIdentity>,
    /// Signing time (Unix seconds), present on success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_time: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<TimestampInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
    pub correlation_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcome_success_predicate() {
        assert!(SigningOutcome::Signed.is_success());
        assert!(!SigningOutcome::Declined.is_success());
        assert!(!SigningOutcome::IdentityMismatch.is_success());
    }

    #[test]
    fn failure_record_roundtrips() {
        let rec = SigningEvidenceRecord {
            request_digest: "abcd".into(),
            outcome: SigningOutcome::InvalidDocument,
            conformance_level: ConformanceLevel::BB,
            signer: None,
            signing_time: None,
            timestamp: None,
            failure_reason: Some("document is not a PDF".into()),
            correlation_id: "corr-1".into(),
        };
        assert!(rec.signer.is_none());
        assert!(rec.signing_time.is_none());
        let mut buf = Vec::new();
        ciborium::into_writer(&rec, &mut buf).unwrap();
        let back: SigningEvidenceRecord = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(rec, back);
    }

    #[test]
    fn all_outcomes_serialize_snake_case() {
        use SigningOutcome::*;
        let cases = [
            (Signed, "signed"),
            (Declined, "declined"),
            (AuthorizationExpired, "authorization_expired"),
            (CredentialUnavailable, "credential_unavailable"),
            (IdentityMismatch, "identity_mismatch"),
            (TimestampFailed, "timestamp_failed"),
            (InvalidDocument, "invalid_document"),
            (AppearancePlacementError, "appearance_placement_error"),
            (SignatureInvalid, "signature_invalid"),
        ];
        for (outcome, wire) in cases {
            assert_eq!(
                serde_json::to_value(outcome).unwrap(),
                serde_json::json!(wire)
            );
            assert_eq!(outcome.is_success(), matches!(outcome, Signed));
        }
    }
}
