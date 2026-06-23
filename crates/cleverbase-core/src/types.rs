//! Input/output value types for the signing API (see contracts/sdk-api.md, data-model.md).

use serde::{Deserialize, Serialize};

/// A secret string whose contents never appear in `Debug` output (Constitution Principle IV).
/// It still (de)serializes its inner value so a session handle can round-trip authorization
/// material; the integrator is responsible for encrypting handles at rest.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Secret(String);

impl Secret {
    pub fn new(s: impl Into<String>) -> Self {
        Secret(s.into())
    }
    /// Reveal the secret. Call sites should keep the result on the server only.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Debug for Secret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Secret(***)")
    }
}

impl From<&str> for Secret {
    fn from(s: &str) -> Self {
        Secret(s.to_string())
    }
}

/// PAdES conformance level requested for a signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConformanceLevel {
    #[serde(rename = "B-B")]
    BB,
    #[serde(rename = "B-T")]
    BT,
}

/// Which Cleverbase environment to target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Environment {
    Acceptance,
    Production,
}

/// Which CSC API generation (selects signature algorithm + host).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CscApi {
    /// CSC v1 (production), RSA signatures.
    #[serde(rename = "v1_rsa")]
    V1Rsa,
    /// CSC v2 (beta), ECDSA P-256 signatures.
    #[serde(rename = "v2_ecdsa")]
    V2Ecdsa,
}

// Wire-string parsers for the language bindings (so each binding doesn't re-spell the literals).
// These mirror the `#[serde(rename = ...)]` values above; the `from_wire_matches_serde` test
// asserts they stay in sync (Constitution Principle VIII).
impl ConformanceLevel {
    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            "B-B" => Some(Self::BB),
            "B-T" => Some(Self::BT),
            _ => None,
        }
    }
}

impl Environment {
    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            "acceptance" => Some(Self::Acceptance),
            "production" => Some(Self::Production),
            _ => None,
        }
    }
}

impl CscApi {
    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            "v1_rsa" => Some(Self::V1Rsa),
            "v2_ecdsa" => Some(Self::V2Ecdsa),
            _ => None,
        }
    }
}

/// How an expected signer identity is matched against the authorizing certificate.
/// `name_and_dob` is deferred to a later phase (see data-model.md) and intentionally absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchOn {
    /// The credential certificate's serial number as reported by CSC `credentials/info`
    /// (`cert.serialNumber`). Default.
    #[default]
    CertificateSerialNumber,
    /// The subject DN's `serialNumber` RDN — the stable natural-person identifier (e.g. `PNONL-…`).
    CleverbaseSubject,
}

/// Optional binding of a request to a specific expected signer (FR-014).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectedSignerIdentity {
    #[serde(default)]
    pub match_on: MatchOn,
    pub value: String,
}

/// A rectangle on a PDF page, in PDF points.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Rect {
    pub x: f64,
    pub y: f64,
    pub w: f64,
    pub h: f64,
}

/// Which fields a visible appearance should render.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppearanceShow {
    #[serde(default)]
    pub signer_name: bool,
    #[serde(default)]
    pub reason: bool,
    #[serde(default)]
    pub location: bool,
    #[serde(default)]
    pub signing_time: bool,
}

/// Optional visible signature appearance (FR-016). Absent ⇒ invisible signature.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignatureAppearance {
    /// 1-based page number.
    pub page: u32,
    pub rect: Rect,
    #[serde(default)]
    pub show: AppearanceShow,
}

/// PAdES signature dictionary metadata (FR-016).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureMeta {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
}

/// An application's intent to sign a document (data-model: SigningRequest).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SigningRequest {
    /// The PDF to sign. Stays in the integrator's infra; only its hash leaves (FR-002).
    #[serde(with = "serde_bytes")]
    pub document: Vec<u8>,
    #[serde(default = "default_level")]
    pub conformance_level: ConformanceLevel,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_signer: Option<ExpectedSignerIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub appearance: Option<SignatureAppearance>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_meta: Option<SignatureMeta>,
}

fn default_level() -> ConformanceLevel {
    ConformanceLevel::BB
}

/// Configuration for reaching an external qualified Time-Stamping Authority (required for B-T).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TsaConfiguration {
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<Secret>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_oid: Option<String>,
}

/// How to reach the Cleverbase trust service (data-model: TrustServiceConfiguration).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrustServiceConfiguration {
    pub environment: Environment,
    pub csc_api: CscApi,
    pub client_id: String,
    pub client_secret: Secret,
    pub redirect_uri: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tsa: Option<TsaConfiguration>,
}

impl TrustServiceConfiguration {
    /// Base URL for the selected API generation and environment.
    pub fn base_url(&self) -> &'static str {
        match (self.csc_api, self.environment) {
            (CscApi::V1Rsa, Environment::Production) => "https://connect.cleverbase.com",
            (CscApi::V1Rsa, Environment::Acceptance) => "https://connect.acc.cleverbase.com",
            // v2 beta is a single lab host regardless of environment.
            (CscApi::V2Ecdsa, _) => "https://signing.lab.cleverbase.io",
        }
    }

    pub fn authorize_url(&self) -> String {
        format!("{}/oauth2/authorize", self.base_url())
    }

    pub fn token_url(&self) -> String {
        format!("{}/oauth2/token", self.base_url())
    }
}

/// The optional parts of a [`SigningRequest`] that the language bindings accept as a single JSON
/// object (so a binding needs one `options_json` argument rather than one parameter per nested
/// field). All fields are optional; the JSON shape mirrors the serde representation of the types.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RequestOptions {
    #[serde(default)]
    pub expected_signer: Option<ExpectedSignerIdentity>,
    #[serde(default)]
    pub appearance: Option<SignatureAppearance>,
    #[serde(default)]
    pub signature_meta: Option<SignatureMeta>,
}

impl RequestOptions {
    /// Parse from a JSON object string. Empty/whitespace input yields all-none defaults.
    pub fn from_json(s: &str) -> Result<Self, String> {
        if s.trim().is_empty() {
            return Ok(Self::default());
        }
        serde_json::from_str(s).map_err(|e| e.to_string())
    }
}

/// The signed result returned on success (data-model: SignedDocument).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedDocument {
    #[serde(with = "serde_bytes")]
    pub pdf: Vec<u8>,
    pub conformance_level: ConformanceLevel,
    /// Best-effort PDF/A indicator: true when the signed output still carries the PDF/A marker and
    /// an invisible signature was used. Conformance is NOT independently validated in Phase 1 (no
    /// veraPDF — see docs/limitations.md); do not treat this as a guarantee.
    pub pdf_a: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_debug_is_redacted() {
        let s = Secret::new("super-secret-value");
        assert_eq!(format!("{s:?}"), "Secret(***)");
        assert!(!format!("{s:?}").contains("super-secret"));
        assert_eq!(s.expose(), "super-secret-value");
    }

    #[test]
    fn from_wire_matches_serde() {
        // from_wire must accept exactly the serde-rename wire strings (guards against drift).
        for v in [ConformanceLevel::BB, ConformanceLevel::BT] {
            let wire = serde_json::to_value(v).unwrap();
            assert_eq!(ConformanceLevel::from_wire(wire.as_str().unwrap()), Some(v));
        }
        for v in [Environment::Acceptance, Environment::Production] {
            let wire = serde_json::to_value(v).unwrap();
            assert_eq!(Environment::from_wire(wire.as_str().unwrap()), Some(v));
        }
        for v in [CscApi::V1Rsa, CscApi::V2Ecdsa] {
            let wire = serde_json::to_value(v).unwrap();
            assert_eq!(CscApi::from_wire(wire.as_str().unwrap()), Some(v));
        }
    }

    #[test]
    fn conformance_level_serializes_with_hyphen() {
        let mut buf = Vec::new();
        ciborium::into_writer(&ConformanceLevel::BT, &mut buf).unwrap();
        let back: ConformanceLevel = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(back, ConformanceLevel::BT);
    }

    #[test]
    fn match_on_defaults_to_serial_number() {
        assert_eq!(MatchOn::default(), MatchOn::CertificateSerialNumber);
    }

    #[test]
    fn base_url_selection() {
        let mk = |api, env| TrustServiceConfiguration {
            environment: env,
            csc_api: api,
            client_id: "c".into(),
            client_secret: Secret::new("s"),
            redirect_uri: "https://app/cb".into(),
            tsa: None,
        };
        assert_eq!(
            mk(CscApi::V1Rsa, Environment::Production).base_url(),
            "https://connect.cleverbase.com"
        );
        assert_eq!(
            mk(CscApi::V1Rsa, Environment::Acceptance).base_url(),
            "https://connect.acc.cleverbase.com"
        );
        assert_eq!(
            mk(CscApi::V2Ecdsa, Environment::Production).base_url(),
            "https://signing.lab.cleverbase.io"
        );
    }
}
