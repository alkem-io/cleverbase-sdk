//! CSC / OAuth response parsers and signer-identity derivation (FR-014).
//!
//! Cleverbase responses are JSON. These are pure parse functions over the response bytes the host
//! feeds back via `ResumeInput::HttpResult`. Identity matching is derived from `credentials/info`,
//! which returns the subject DN and serial number directly (no certificate parsing needed for the
//! default match key).

use serde::Deserialize;

use super::CoreError;
use crate::evidence::SignerIdentity;
use crate::types::{ExpectedSignerIdentity, MatchOn};

/// OAuth2 token response (service-scope Bearer, or credential-scope SAD).
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    #[serde(default)]
    pub token_type: String,
    #[serde(default)]
    pub expires_in: Option<i64>,
}

/// `credentials/list` response.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct CredentialList {
    #[serde(rename = "credentialIDs", default)]
    pub credential_ids: Vec<String>,
}

/// Signing key algorithm family, derived from the credential's advertised OIDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum KeyAlgo {
    Rsa,
    EcdsaP256,
    Other,
}

impl KeyAlgo {
    /// The `signAlgo` OID to request from CSC `signatures/signHash`.
    pub fn sign_algo_oid(&self) -> &'static str {
        match self {
            KeyAlgo::Rsa => "1.2.840.113549.1.1.11", // sha256WithRSAEncryption
            KeyAlgo::EcdsaP256 => "1.2.840.10045.4.3.2", // ecdsa-with-SHA256
            KeyAlgo::Other => "",
        }
    }
}

/// `signatures/signHash` response (raw signature values, base64).
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct SignaturesResponse {
    #[serde(default)]
    pub signatures: Vec<String>,
}

/// Flattened, useful view of `credentials/info`.
#[derive(Debug, Clone, PartialEq)]
pub struct CredentialInfo {
    /// Certificate chain, base64-encoded DER (leaf first).
    pub certificates: Vec<String>,
    pub subject_dn: String,
    pub serial_number: String,
    pub scal: String,
    pub key_algo: KeyAlgo,
}

#[derive(Deserialize)]
struct RawInfo {
    #[serde(default)]
    key: RawKey,
    cert: RawCert,
    #[serde(rename = "SCAL", default)]
    scal: String,
}

#[derive(Deserialize, Default)]
struct RawKey {
    #[serde(default)]
    algo: Vec<String>,
}

#[derive(Deserialize)]
struct RawCert {
    #[serde(default)]
    certificates: Vec<String>,
    #[serde(rename = "subjectDN", default)]
    subject_dn: String,
    #[serde(rename = "serialNumber", default)]
    serial_number: String,
}

fn parse<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, CoreError> {
    serde_json::from_slice(body).map_err(|e| CoreError::ProtocolParse(e.to_string()))
}

pub fn parse_token_response(body: &[u8]) -> Result<TokenResponse, CoreError> {
    parse(body)
}

pub fn parse_credentials_list(body: &[u8]) -> Result<CredentialList, CoreError> {
    parse(body)
}

pub fn parse_signatures(body: &[u8]) -> Result<SignaturesResponse, CoreError> {
    parse(body)
}

pub fn parse_credentials_info(body: &[u8]) -> Result<CredentialInfo, CoreError> {
    let raw: RawInfo = parse(body)?;
    Ok(CredentialInfo {
        certificates: raw.cert.certificates,
        subject_dn: raw.cert.subject_dn,
        serial_number: raw.cert.serial_number,
        scal: raw.scal,
        key_algo: key_algo_from_oids(&raw.key.algo),
    })
}

fn key_algo_from_oids(oids: &[String]) -> KeyAlgo {
    for o in oids {
        if o.starts_with("1.2.840.113549.1.1") {
            return KeyAlgo::Rsa;
        }
        if o.starts_with("1.2.840.10045") {
            return KeyAlgo::EcdsaP256;
        }
    }
    KeyAlgo::Other
}

/// Split an RFC 4514 DN into RDN components on UNescaped `,`/`+` (a `\,` inside a value, e.g.
/// `CN=Doe\, Jane`, is not a separator).
fn split_rdns(dn: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut chars = dn.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                cur.push('\\');
                if let Some(next) = chars.next() {
                    cur.push(next);
                }
            }
            ',' | '+' => parts.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    parts.push(cur);
    parts
}

/// Remove RFC 4514 backslash escapes from an RDN value (`Doe\, Jane` → `Doe, Jane`).
fn unescape_rdn_value(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(next) = chars.next() {
                out.push(next);
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Extract an attribute value (e.g. `CN`) from an RFC 4514 distinguished name, honoring escaping.
fn extract_attr(dn: &str, attr: &str) -> Option<String> {
    let needle = format!("{}=", attr.to_ascii_uppercase());
    for part in split_rdns(dn) {
        let trimmed = part.trim();
        if trimmed.to_ascii_uppercase().starts_with(&needle) {
            return Some(unescape_rdn_value(trimmed[needle.len()..].trim()));
        }
    }
    None
}

/// Derive the signer's identity from `credentials/info` (subject DN + serial number).
pub fn signer_identity(info: &CredentialInfo) -> SignerIdentity {
    SignerIdentity {
        serial_number: info.serial_number.clone(),
        common_name: extract_attr(&info.subject_dn, "CN").unwrap_or_default(),
        given_name: extract_attr(&info.subject_dn, "GN")
            .or_else(|| extract_attr(&info.subject_dn, "givenName")),
        surname: extract_attr(&info.subject_dn, "SN")
            .or_else(|| extract_attr(&info.subject_dn, "surname")),
        raw_subject: info.subject_dn.clone(),
    }
}

/// Check the authorizing signer against an expected identity (FR-014). The default match key is the
/// certificate serial number; `cleverbase_subject` matches the stable subject identifier — the
/// subject DN's `serialNumber` RDN (e.g. `PNONL-…`), per data-model.md — not the whole DN.
/// `name_and_dob` is deferred (see data-model.md) and not a variant here.
pub fn matches_expected(expected: &ExpectedSignerIdentity, identity: &SignerIdentity) -> bool {
    match expected.match_on {
        MatchOn::CertificateSerialNumber => expected.value == identity.serial_number,
        MatchOn::CleverbaseSubject => {
            extract_attr(&identity.raw_subject, "serialNumber").is_some_and(|s| s == expected.value)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_response_parses() {
        let body = br#"{"access_token":"tok-abc","token_type":"Bearer","expires_in":3600}"#;
        let t = parse_token_response(body).unwrap();
        assert_eq!(t.access_token, "tok-abc");
        assert_eq!(t.token_type, "Bearer");
        assert_eq!(t.expires_in, Some(3600));
    }

    #[test]
    fn sad_token_response_parses() {
        let body = br#"{"access_token":"SAD-xyz","token_type":"SAD","expires_in":300}"#;
        let t = parse_token_response(body).unwrap();
        assert_eq!(t.token_type, "SAD");
    }

    #[test]
    fn credentials_list_parses() {
        let body = br#"{"credentialIDs":["cred-1","cred-2"]}"#;
        let l = parse_credentials_list(body).unwrap();
        assert_eq!(l.credential_ids, vec!["cred-1", "cred-2"]);
    }

    #[test]
    fn signatures_response_parses() {
        let body = br#"{"signatures":["YmFzZTY0c2ln"]}"#;
        let s = parse_signatures(body).unwrap();
        assert_eq!(s.signatures, vec!["YmFzZTY0c2ln"]);
    }

    #[test]
    fn credentials_info_parses_rsa_and_identity() {
        let body = br#"{
            "key": {"status":"enabled","algo":["1.2.840.113549.1.1.1"],"len":2048},
            "cert": {"status":"valid","certificates":["QkFTRTY0REVS"],
                     "subjectDN":"CN=Jane Doe,SN=Doe,GN=Jane,serialNumber=PNONL-123",
                     "serialNumber":"PNONL-123"},
            "SCAL":"2"
        }"#;
        let info = parse_credentials_info(body).unwrap();
        assert_eq!(info.key_algo, KeyAlgo::Rsa);
        assert_eq!(info.serial_number, "PNONL-123");
        assert_eq!(info.scal, "2");
        assert_eq!(info.certificates, vec!["QkFTRTY0REVS"]);

        let id = signer_identity(&info);
        assert_eq!(id.common_name, "Jane Doe");
        assert_eq!(id.surname.as_deref(), Some("Doe"));
        assert_eq!(id.given_name.as_deref(), Some("Jane"));
        assert_eq!(id.serial_number, "PNONL-123");
    }

    #[test]
    fn credentials_info_detects_ecdsa() {
        let body = br#"{"key":{"algo":["1.2.840.10045.2.1"]},
            "cert":{"certificates":[],"subjectDN":"CN=x","serialNumber":"s"}}"#;
        assert_eq!(
            parse_credentials_info(body).unwrap().key_algo,
            KeyAlgo::EcdsaP256
        );
    }

    #[test]
    fn dn_parsing_handles_escaped_comma() {
        let dn = "CN=Doe\\, Jane,serialNumber=PNONL-9";
        assert_eq!(extract_attr(dn, "CN").as_deref(), Some("Doe, Jane"));
        assert_eq!(extract_attr(dn, "serialNumber").as_deref(), Some("PNONL-9"));
    }

    #[test]
    fn identity_matching_serial_and_subject() {
        let id = SignerIdentity {
            serial_number: "PNONL-123".into(),
            common_name: "Jane Doe".into(),
            given_name: None,
            surname: None,
            raw_subject: "CN=Jane Doe,serialNumber=PNONL-123".into(),
        };
        let by_serial = ExpectedSignerIdentity {
            match_on: MatchOn::CertificateSerialNumber,
            value: "PNONL-123".into(),
        };
        assert!(matches_expected(&by_serial, &id));

        let wrong = ExpectedSignerIdentity {
            match_on: MatchOn::CertificateSerialNumber,
            value: "PNONL-999".into(),
        };
        assert!(!matches_expected(&wrong, &id));

        // cleverbase_subject matches the subject DN's serialNumber RDN (the stable identifier),
        // NOT the whole DN.
        let by_subject = ExpectedSignerIdentity {
            match_on: MatchOn::CleverbaseSubject,
            value: "PNONL-123".into(),
        };
        assert!(matches_expected(&by_subject, &id));

        let by_full_dn = ExpectedSignerIdentity {
            match_on: MatchOn::CleverbaseSubject,
            value: "CN=Jane Doe,serialNumber=PNONL-123".into(),
        };
        assert!(!matches_expected(&by_full_dn, &id));
    }

    #[test]
    fn parse_error_is_protocol_parse() {
        let err = parse_token_response(b"not json").unwrap_err();
        assert!(matches!(err, CoreError::ProtocolParse(_)));
    }
}
