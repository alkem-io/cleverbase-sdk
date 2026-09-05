//! Input/output value types for the signing API (see contracts/sdk-api.md, data-model.md).

use http::Uri;
use serde::{Deserialize, Serialize};

/// A secret string whose contents never appear in `Debug` output (Constitution Principle IV).
/// It still (de)serializes its inner value so a session handle can round-trip authorization
/// material; the integrator is responsible for encrypting handles at rest.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Secret(String);

impl Secret {
    /// Wrap a value as a redacted secret.
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
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
        Self(s.to_string())
    }
}

/// PAdES conformance level requested for a signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConformanceLevel {
    /// PAdES-B-B (basic): signed attributes, signing certificate, no trusted timestamp.
    #[serde(rename = "B-B")]
    BB,
    /// PAdES-B-T: B-B plus an RFC 3161 signature timestamp from a qualified TSA.
    #[serde(rename = "B-T")]
    BT,
}

/// Which Cleverbase environment to target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Environment {
    /// Cleverbase acceptance (test) environment.
    Acceptance,
    /// Cleverbase production environment.
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
    /// Parse the wire string (`"B-B"` / `"B-T"`) used by the language bindings. `None` if unknown.
    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            "B-B" => Some(Self::BB),
            "B-T" => Some(Self::BT),
            _ => None,
        }
    }
}

impl Environment {
    /// Parse the wire string (`"acceptance"` / `"production"`). `None` if unknown.
    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            "acceptance" => Some(Self::Acceptance),
            "production" => Some(Self::Production),
            _ => None,
        }
    }
}

impl CscApi {
    /// Parse the wire string (`"v1_rsa"` / `"v2_ecdsa"`). `None` if unknown.
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
#[serde(deny_unknown_fields)]
pub struct ExpectedSignerIdentity {
    /// Which identity field the `value` is compared against.
    #[serde(default)]
    pub match_on: MatchOn,
    /// The expected value (e.g. a certificate serial number or a `PNONL-…` subject identifier).
    pub value: String,
}

/// A rectangle on a PDF page, in PDF points.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rect {
    /// Lower-left x coordinate, in PDF points.
    pub x: f64,
    /// Lower-left y coordinate, in PDF points.
    pub y: f64,
    /// Width, in PDF points.
    pub w: f64,
    /// Height, in PDF points.
    pub h: f64,
}

/// Which fields a visible appearance should render.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppearanceShow {
    /// Render the signer's name (common name, or the raw subject DN as fallback).
    #[serde(default)]
    pub signer_name: bool,
    /// Render the signing reason (from [`SignatureMeta::reason`]).
    #[serde(default)]
    pub reason: bool,
    /// Render the signing location (from [`SignatureMeta::location`]).
    #[serde(default)]
    pub location: bool,
    /// Render the signing time (UTC).
    #[serde(default)]
    pub signing_time: bool,
}

/// Optional visible signature appearance (FR-016). Absent ⇒ invisible signature.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureAppearance {
    /// 1-based page number.
    pub page: u32,
    /// Where to draw the appearance, in PDF points.
    pub rect: Rect,
    /// Which fields to render inside the rectangle.
    #[serde(default)]
    pub show: AppearanceShow,
}

/// PAdES signature dictionary metadata (FR-016).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureMeta {
    /// Optional signing reason (PDF signature dictionary `/Reason`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Optional signing location (PDF signature dictionary `/Location`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
}

/// An application's intent to sign a document (data-model: SigningRequest).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SigningRequest {
    /// The PDF to sign. Stays in the integrator's infra; only its hash leaves (FR-002).
    #[serde(with = "serde_bytes")]
    pub document: Vec<u8>,
    /// Requested PAdES conformance level (defaults to B-B).
    #[serde(default = "default_level")]
    pub conformance_level: ConformanceLevel,
    /// Optional binding to a specific expected signer (FR-014).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_signer: Option<ExpectedSignerIdentity>,
    /// Optional visible signature appearance; absent ⇒ invisible signature (FR-016).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub appearance: Option<SignatureAppearance>,
    /// Optional signature dictionary metadata (`/Reason`, `/Location`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_meta: Option<SignatureMeta>,
}

fn default_level() -> ConformanceLevel {
    ConformanceLevel::BB
}

/// Configuration for reaching an external qualified Time-Stamping Authority (required for B-T).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TsaConfiguration {
    /// RFC 3161 TSA endpoint URL the host POSTs the timestamp query to.
    pub url: String,
    /// Optional `Authorization` header value for the TSA (sent verbatim).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<Secret>,
    /// Optional TSA policy OID to constrain the timestamp request to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_oid: Option<String>,
}

/// How to reach the Cleverbase trust service (data-model: TrustServiceConfiguration).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrustServiceConfiguration {
    /// Which Cleverbase environment to target.
    pub environment: Environment,
    /// Which CSC API generation (selects host + signature algorithm).
    pub csc_api: CscApi,
    /// OAuth2 client id issued by Cleverbase.
    pub client_id: String,
    /// OAuth2 client secret (redacted in `Debug`).
    pub client_secret: Secret,
    /// OAuth2 redirect URI registered for this client.
    pub redirect_uri: String,
    /// Optional alternate Cleverbase origin for a documented developer/stub service. It replaces
    /// the selected environment host for both OAuth and CSC endpoints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_base_url: Option<String>,
    /// TSA configuration; required when requesting B-T.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tsa: Option<TsaConfiguration>,
}

impl TrustServiceConfiguration {
    /// Base URL for the selected API generation and environment.
    pub fn base_url(&self) -> &str {
        self.upstream_base_url
            .as_deref()
            .unwrap_or(match (self.csc_api, self.environment) {
                (CscApi::V1Rsa, Environment::Production) => "https://connect.cleverbase.com",
                (CscApi::V1Rsa, Environment::Acceptance) => "https://connect.acc.cleverbase.com",
                // v2 beta is a single lab host regardless of environment.
                (CscApi::V2Ecdsa, _) => "https://signing.lab.cleverbase.io",
            })
            .trim_end_matches('/')
    }

    /// The OAuth2 authorization endpoint for the selected API generation and environment.
    pub fn authorize_url(&self) -> String {
        format!("{}/oauth2/authorize", self.base_url())
    }

    /// The OAuth2 token endpoint for the selected API generation and environment.
    pub fn token_url(&self) -> String {
        format!("{}/oauth2/token", self.base_url())
    }

    /// Validate the optional alternate Cleverbase origin before a signing session starts.
    ///
    /// Alternate origins are for documented developer environments only. They must be absolute,
    /// omit credentials, query, and fragment, and use HTTPS except for an explicitly loopback
    /// HTTP endpoint used in local development. A path is permitted as a service base path.
    pub fn validate(&self) -> Result<(), String> {
        let Some(value) = self.upstream_base_url.as_deref() else {
            return Ok(());
        };
        let parsed: Uri = value
            .parse()
            .map_err(|e| format!("upstream_base_url must be an absolute URL: {e}"))?;
        let Some(authority) = parsed.authority() else {
            return Err("upstream_base_url must be an absolute URL with a host".into());
        };
        if parsed.scheme_str().is_none() {
            return Err("upstream_base_url must be an absolute URL with a scheme".into());
        }
        if authority.host().is_empty() {
            return Err("upstream_base_url must be an absolute URL with a host".into());
        }
        if authority.as_str().contains('@') {
            return Err("upstream_base_url must not contain credentials".into());
        }
        // `http::Uri` keeps a literal fragment in the path because HTTP request targets normally
        // never carry one, so reject it from the original absolute URL explicitly.
        if parsed.query().is_some() || value.contains('#') {
            return Err("upstream_base_url must not contain a query or fragment".into());
        }
        if parsed
            .scheme_str()
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https"))
        {
            return Ok(());
        }
        if parsed
            .scheme_str()
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case("http"))
            && is_loopback_host(authority.host())
        {
            return Ok(());
        }
        Err("upstream_base_url must use https, except http on a loopback host".into())
    }
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

/// The optional parts of a [`SigningRequest`] that the language bindings accept as a single JSON
/// object (so a binding needs one `options_json` argument rather than one parameter per nested
/// field). All fields are optional; the JSON shape mirrors the serde representation of the types.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestOptions {
    /// Optional expected-signer binding (FR-014).
    #[serde(default)]
    pub expected_signer: Option<ExpectedSignerIdentity>,
    /// Optional visible signature appearance (FR-016).
    #[serde(default)]
    pub appearance: Option<SignatureAppearance>,
    /// Optional signature dictionary metadata.
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
    /// The signed PDF bytes (signature embedded into the `/Contents` placeholder).
    #[serde(with = "serde_bytes")]
    pub pdf: Vec<u8>,
    /// The conformance level actually produced.
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
            upstream_base_url: None,
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

    #[test]
    fn upstream_base_url_override_drives_oauth_endpoints() {
        // The developer stub has one origin for both OAuth and CSC. Deserializing the public wire
        // shape here ensures bindings can carry the optional override without each reimplementing
        // endpoint selection.
        let config: TrustServiceConfiguration = serde_json::from_value(serde_json::json!({
            "environment": "acceptance",
            "csc_api": "v1_rsa",
            "client_id": "client",
            "client_secret": "secret",
            "redirect_uri": "https://app.example/callback",
            "upstream_base_url": "https://trust-driver-stub-hash-signing.cleverbase.com/api"
        }))
        .unwrap();

        assert_eq!(
            config.base_url(),
            "https://trust-driver-stub-hash-signing.cleverbase.com/api"
        );
        assert_eq!(
            config.authorize_url(),
            "https://trust-driver-stub-hash-signing.cleverbase.com/api/oauth2/authorize"
        );
        assert_eq!(
            config.token_url(),
            "https://trust-driver-stub-hash-signing.cleverbase.com/api/oauth2/token"
        );
    }

    #[test]
    fn upstream_base_url_validation_allows_https_and_loopback_http_only() {
        let config = |upstream_base_url| TrustServiceConfiguration {
            environment: Environment::Acceptance,
            csc_api: CscApi::V1Rsa,
            client_id: "client".into(),
            client_secret: Secret::new("secret"),
            redirect_uri: "https://app.example/callback".into(),
            upstream_base_url,
            tsa: None,
        };

        for value in [
            "https://trust-driver-stub-hash-signing.cleverbase.com",
            "HTTPS://example.test",
            "https://example.test/service-base",
            "http://localhost:8080",
            "http://127.0.0.1:8080/service-base",
            "http://[::1]:8080",
        ] {
            assert!(config(Some(value.into())).validate().is_ok(), "{value}");
        }
        for value in [
            "not a URL",
            "/relative",
            "https://:443",
            "ftp://example.test",
            "http://example.test",
            "https://user:password@example.test",
            "https://example.test/path?query=value",
            "https://example.test/path#fragment",
        ] {
            assert!(config(Some(value.into())).validate().is_err(), "{value}");
        }
    }

    #[test]
    fn secret_from_str_and_expose() {
        let s: Secret = "abc".into();
        assert_eq!(s.expose(), "abc");
        assert_eq!(Secret::new(String::from("x")).expose(), "x");
    }

    #[test]
    fn from_wire_rejects_unknown_values() {
        assert_eq!(ConformanceLevel::from_wire("nope"), None);
        assert_eq!(Environment::from_wire("nope"), None);
        assert_eq!(CscApi::from_wire("nope"), None);
    }

    #[test]
    fn request_options_from_json() {
        // Empty / whitespace → all-none defaults.
        let d = RequestOptions::from_json("   ").unwrap();
        assert!(
            d.expected_signer.is_none() && d.appearance.is_none() && d.signature_meta.is_none()
        );
        // A populated object parses into the typed parts.
        let o = RequestOptions::from_json(
            r#"{"expected_signer":{"value":"PNONL-1"},
                "signature_meta":{"reason":"R"},
                "appearance":{"page":1,"rect":{"x":1,"y":2,"w":3,"h":4}}}"#,
        )
        .unwrap();
        assert_eq!(o.expected_signer.unwrap().value, "PNONL-1");
        assert_eq!(o.signature_meta.unwrap().reason.as_deref(), Some("R"));
        assert_eq!(o.appearance.unwrap().page, 1);
        // Malformed JSON → Err (not a panic).
        assert!(RequestOptions::from_json("{not json").is_err());
        // A typo'd field is rejected, not silently dropped — so a misspelled security-relevant
        // option (e.g. `expected_signer`) can't downgrade enforcement unnoticed.
        assert!(RequestOptions::from_json(r#"{"expected_signor":{"value":"x"}}"#).is_err());
        assert!(RequestOptions::from_json(
            r#"{"appearance":{"page":1,"rect":{"x":1,"y":2,"w":3,"h":4},"colour":"red"}}"#
        )
        .is_err());
    }

    #[test]
    fn signed_document_round_trips() {
        let doc = SignedDocument {
            pdf: b"%PDF".to_vec(),
            conformance_level: ConformanceLevel::BT,
            pdf_a: true,
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&doc, &mut buf).unwrap();
        let back: SignedDocument = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(doc, back);
    }
}
