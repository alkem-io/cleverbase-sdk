//! Sans-IO effect types: what the host must do next (contracts/sdk-api.md).
//!
//! The core never performs I/O. It returns a [`Step`]; the host performs the described effect and
//! calls `resume` with the result.

use serde::{Deserialize, Serialize};

use crate::evidence::SigningEvidenceRecord;
use crate::types::SignedDocument;

/// HTTP method for an [`HttpEffect`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    /// HTTP GET.
    Get,
    /// HTTP POST.
    Post,
}

/// An HTTP request the host must perform on the core's behalf. The core does not advance until it
/// receives a result. Retry-safety is NOT blanket-guaranteed — it depends on the operation:
/// idempotent reads (`credentials/list`, `credentials/info`) may be retried freely, but a token
/// exchange or `signHash` can consume a one-time authorization (SAD) or produce a signature, so
/// retry those only on a pure transport failure (no response received), never after a server reply.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HttpEffect {
    /// HTTP method to use.
    pub method: HttpMethod,
    /// Absolute request URL.
    pub url: String,
    /// Request headers as `(name, value)` pairs.
    pub headers: Vec<(String, String)>,
    /// Optional request body bytes.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "serde_bytes")]
    pub body: Option<Vec<u8>>,
}

/// A browser redirect the host must issue to the signer; on return, resume with the `code`+`state`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedirectEffect {
    /// URL to send the signer's browser to.
    pub url: String,
    /// OAuth `state` (CSRF token); echoed back on return and validated by `resume`.
    pub state: String,
}

/// The result of one `begin`/`resume` call: exactly one next action or a terminal outcome.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Step {
    /// Perform this HTTP request, then `resume` with the response.
    PerformHttp(HttpEffect),
    /// Send the signer's browser here, then `resume` with the returned code+state.
    Redirect(RedirectEffect),
    /// Terminal success.
    Done {
        /// The signed PDF and its produced conformance level.
        signed: SignedDocument,
        /// Structured signing evidence (FR-015).
        evidence: SigningEvidenceRecord,
    },
    /// Terminal failure; `evidence.outcome` is never `Signed`.
    Failed {
        /// Structured signing evidence describing the failure (FR-015).
        evidence: SigningEvidenceRecord,
    },
}

impl Step {
    /// `true` for terminal steps ([`Step::Done`] / [`Step::Failed`]); the flow does not resume past them.
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Done { .. } | Self::Failed { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn step_terminality() {
        let http = Step::PerformHttp(HttpEffect {
            method: HttpMethod::Get,
            url: "https://x".into(),
            headers: vec![],
            body: None,
        });
        assert!(!http.is_terminal());
        let redirect = Step::Redirect(RedirectEffect {
            url: "https://x".into(),
            state: "s".into(),
        });
        assert!(!redirect.is_terminal());
    }

    #[test]
    fn http_effect_cbor_roundtrip() {
        let e = HttpEffect {
            method: HttpMethod::Post,
            url: "https://connect.cleverbase.com/oauth2/token".into(),
            headers: vec![(
                "Content-Type".into(),
                "application/x-www-form-urlencoded".into(),
            )],
            body: Some(b"grant_type=authorization_code".to_vec()),
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&e, &mut buf).unwrap();
        let back: HttpEffect = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(e, back);
    }
}
