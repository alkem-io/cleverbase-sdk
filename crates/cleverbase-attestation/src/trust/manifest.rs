//! The offline JSON trust-list manifest (`tests/fixtures/attestation/trust-list.json`).
//!
//! For the fully-offline test suite (research D9 / SC-003) the configured trust anchor is seeded
//! from a small JSON manifest: per `(role, format)` it lists the trusted anchor certificate(s) as
//! base64 DER, plus a `nextUpdate` timestamp so the **stale-list** policy (past `NextUpdate` →
//! fail-closed) has a value to exercise. This is the JSON counterpart of the production TS 119 612
//! XML path ([`super::xml`]); both feed the same in-memory anchor cache in
//! [`super::NativeTrustEngine`]. It is **not** a production trust source — there is no signature on
//! the JSON manifest (the offline suite trusts the bytes it ships); the *XML* path carries the
//! enveloped-signature authentication.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::types::{Format, IssuerRole};

/// An error parsing the JSON trust-list manifest.
#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    /// The manifest bytes were not valid JSON of the expected shape.
    #[error("trust-list manifest is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// An anchor entry's `anchorCertDerB64` was not valid base64.
    #[error("anchor certificate is not valid base64: {0}")]
    Base64(String),
    /// The manifest's `nextUpdate` was not an RFC 3339 / ISO 8601 UTC timestamp.
    #[error("nextUpdate is not a valid RFC 3339 UTC timestamp: {0}")]
    NextUpdate(String),
    /// An anchor entry named a role the SDK does not recognise.
    #[error("unknown issuer role in manifest: {0}")]
    UnknownRole(String),
    /// An anchor entry named a credential format the SDK does not recognise.
    #[error("unknown credential format in manifest: {0}")]
    UnknownFormat(String),
}

/// A parsed, in-memory trust-list manifest: the per-`(role, format)` anchor certificates plus the
/// `nextUpdate` instant after which the list is stale.
///
/// Carries only issuer-public anchor certificates (no secret), so deriving `Debug` is safe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustListManifest {
    /// The trusted anchor certificates (DER), keyed by `(role, format)`.
    anchors: BTreeMap<(IssuerRole, Format), Vec<Vec<u8>>>,
    /// The instant (Unix seconds) at or after which the list is stale (past its `NextUpdate`).
    next_update_unix: i64,
}

/// The on-disk JSON shape (`cleverbase-sdk/test-trust-list/v1`).
#[derive(Debug, Deserialize)]
struct RawManifest {
    #[serde(rename = "nextUpdate")]
    next_update: String,
    anchors: Vec<RawAnchor>,
}

/// One per-`(role, format)` anchor entry in the JSON manifest.
///
/// The manifest uses the human-readable PascalCase role/format spellings (`"Pid"`, `"Qeaa"`,
/// `"SdJwtVc"`, `"Mdoc"`) — distinct from the snake_case the CBOR wire contract uses for
/// [`IssuerRole`]/[`Format`] — so they are parsed as plain strings and mapped explicitly. Keeping
/// the manifest grammar independent of the wire enum's serde spelling avoids coupling the test
/// fixture to the C-ABI rename.
#[derive(Debug, Deserialize)]
struct RawAnchor {
    role: String,
    format: String,
    #[serde(rename = "anchorCertDerB64")]
    anchor_cert_der_b64: String,
}

/// Map the manifest's PascalCase role spelling to [`IssuerRole`].
fn parse_role(s: &str) -> Result<IssuerRole, ManifestError> {
    Ok(match s {
        "Qeaa" => IssuerRole::Qeaa,
        "Pid" => IssuerRole::Pid,
        "PubEaa" => IssuerRole::PubEaa,
        "NonQualifiedEaa" => IssuerRole::NonQualifiedEaa,
        other => return Err(ManifestError::UnknownRole(other.to_string())),
    })
}

/// Map the manifest's PascalCase format spelling to [`Format`].
fn parse_format(s: &str) -> Result<Format, ManifestError> {
    Ok(match s {
        "SdJwtVc" => Format::SdJwtVc,
        "Mdoc" => Format::Mdoc,
        other => return Err(ManifestError::UnknownFormat(other.to_string())),
    })
}

impl TrustListManifest {
    /// Parse a JSON trust-list manifest from its raw bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError`] when the JSON is malformed, an anchor certificate is not valid
    /// base64, or `nextUpdate` is not a valid RFC 3339 UTC timestamp.
    pub fn parse(bytes: &[u8]) -> Result<Self, ManifestError> {
        let raw: RawManifest = serde_json::from_slice(bytes)?;
        let next_update_unix = crate::datetime::parse_rfc3339_utc(&raw.next_update)
            .ok_or_else(|| ManifestError::NextUpdate(raw.next_update.clone()))?;
        let mut anchors: BTreeMap<(IssuerRole, Format), Vec<Vec<u8>>> = BTreeMap::new();
        for entry in raw.anchors {
            let role = parse_role(&entry.role)?;
            let format = parse_format(&entry.format)?;
            // The crate's single strict trim-only base64 decode (DRY — Principle III).
            let der = crate::crypto::decode_base64_strict(&entry.anchor_cert_der_b64)
                .map_err(|e| ManifestError::Base64(e.to_string()))?;
            anchors.entry((role, format)).or_default().push(der);
        }
        Ok(Self {
            anchors,
            next_update_unix,
        })
    }

    /// The anchor certificates (DER) trusted for a given `(role, format)`, or an empty slice if the
    /// manifest lists none.
    #[must_use]
    pub fn anchors_for(&self, role: IssuerRole, format: Format) -> &[Vec<u8>] {
        self.anchors.get(&(role, format)).map_or(&[], Vec::as_slice)
    }

    /// The `nextUpdate` instant (Unix seconds): at or after this time the list is **stale**.
    #[must_use]
    pub const fn next_update_unix(&self) -> i64 {
        self.next_update_unix
    }

    /// All `(role, format)` keys carried by the manifest (so the engine can enumerate its cache).
    pub(crate) fn keys(&self) -> impl Iterator<Item = (IssuerRole, Format)> + '_ {
        self.anchors.keys().copied()
    }
}

#[cfg(test)]
mod tests {
    use super::{ManifestError, TrustListManifest};
    use crate::datetime::parse_rfc3339_utc;
    use crate::types::{Format, IssuerRole};

    const TRUST_LIST_JSON: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/trust-list.json");
    const CA_IACA: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/ca-iaca.cert.der");

    #[test]
    fn parses_the_fixture_manifest_into_per_role_format_anchors() {
        let manifest = TrustListManifest::parse(TRUST_LIST_JSON).expect("manifest parses");
        // The fixture lists three entries: (Pid, SdJwtVc), (Qeaa, SdJwtVc), (Pid, Mdoc), all = IACA.
        for (role, format) in [
            (IssuerRole::Pid, Format::SdJwtVc),
            (IssuerRole::Qeaa, Format::SdJwtVc),
            (IssuerRole::Pid, Format::Mdoc),
        ] {
            let anchors = manifest.anchors_for(role, format);
            assert_eq!(anchors.len(), 1, "{role:?}/{format:?} has one anchor");
            assert_eq!(
                anchors[0], CA_IACA,
                "{role:?}/{format:?} anchor is the IACA root"
            );
        }
    }

    #[test]
    fn unlisted_role_format_has_no_anchors() {
        let manifest = TrustListManifest::parse(TRUST_LIST_JSON).expect("manifest parses");
        assert!(manifest
            .anchors_for(IssuerRole::PubEaa, Format::SdJwtVc)
            .is_empty());
        assert!(manifest
            .anchors_for(IssuerRole::Qeaa, Format::Mdoc)
            .is_empty());
    }

    #[test]
    fn next_update_parses_to_a_future_instant() {
        let manifest = TrustListManifest::parse(TRUST_LIST_JSON).expect("manifest parses");
        // The fixture's nextUpdate is in 2036 (~3650 days out from minting).
        assert!(manifest.next_update_unix() > 2_000_000_000);
    }

    #[test]
    fn keys_enumerate_every_role_format_pair() {
        let manifest = TrustListManifest::parse(TRUST_LIST_JSON).expect("manifest parses");
        let keys: Vec<_> = manifest.keys().collect();
        assert_eq!(keys.len(), 3);
        assert!(keys.contains(&(IssuerRole::Pid, Format::SdJwtVc)));
        assert!(keys.contains(&(IssuerRole::Qeaa, Format::SdJwtVc)));
        assert!(keys.contains(&(IssuerRole::Pid, Format::Mdoc)));
    }

    #[test]
    fn malformed_json_is_rejected() {
        assert!(TrustListManifest::parse(b"{ not json").is_err());
    }

    #[test]
    fn invalid_base64_anchor_is_rejected() {
        let bad = br#"{"nextUpdate":"2036-06-22T09:11:42Z","anchors":[{"role":"Pid","format":"SdJwtVc","anchorCertDerB64":"!!!not base64!!!"}]}"#;
        assert!(TrustListManifest::parse(bad).is_err());
    }

    #[test]
    fn invalid_next_update_is_rejected() {
        let bad = br#"{"nextUpdate":"not-a-timestamp","anchors":[]}"#;
        assert!(TrustListManifest::parse(bad).is_err());
    }

    #[test]
    fn rfc3339_parser_matches_known_epochs() {
        assert_eq!(parse_rfc3339_utc("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_rfc3339_utc("2000-01-01T00:00:00Z"), Some(946_684_800));
        assert_eq!(
            parse_rfc3339_utc("2021-11-14T22:13:20Z"),
            Some(1_636_928_000)
        );
        // Malformed forms fail closed (None), never a wrong instant.
        assert_eq!(parse_rfc3339_utc("2021-11-14 22:13:20Z"), None); // space, not 'T'
        assert_eq!(parse_rfc3339_utc("2021-11-14T22:13:20"), None); // no 'Z'
        assert_eq!(parse_rfc3339_utc("2021-13-01T00:00:00Z"), None); // month 13
        assert_eq!(parse_rfc3339_utc("2021-11-14T25:00:00Z"), None); // hour 25
        assert_eq!(parse_rfc3339_utc("2021-11-14-01T00:00:00Z"), None); // 4 date segments
        assert_eq!(parse_rfc3339_utc("2021-11-14T00:00:00:00Z"), None); // 4 time segments
        assert_eq!(parse_rfc3339_utc("2021-00-14T00:00:00Z"), None); // month 0
        assert_eq!(parse_rfc3339_utc("2021-11-00T00:00:00Z"), None); // day 0
        assert_eq!(parse_rfc3339_utc("xxxx-11-14T00:00:00Z"), None); // non-numeric year
    }

    #[test]
    fn all_roles_and_formats_map_from_their_pascalcase_spelling() {
        // Cover every role/format mapping arm (incl. PubEaa / NonQualifiedEaa).
        let json = br#"{
          "nextUpdate":"2036-06-22T09:11:42Z",
          "anchors":[
            {"role":"PubEaa","format":"SdJwtVc","anchorCertDerB64":"AQID"},
            {"role":"NonQualifiedEaa","format":"Mdoc","anchorCertDerB64":"BAUG"}
          ]
        }"#;
        let manifest = TrustListManifest::parse(json).expect("manifest parses");
        assert_eq!(
            manifest.anchors_for(IssuerRole::PubEaa, Format::SdJwtVc),
            &[vec![1, 2, 3]]
        );
        assert_eq!(
            manifest.anchors_for(IssuerRole::NonQualifiedEaa, Format::Mdoc),
            &[vec![4, 5, 6]]
        );
    }

    #[test]
    fn unknown_role_is_rejected() {
        let bad = br#"{"nextUpdate":"2036-06-22T09:11:42Z","anchors":[{"role":"Sorcerer","format":"SdJwtVc","anchorCertDerB64":"AQID"}]}"#;
        assert!(matches!(
            TrustListManifest::parse(bad),
            Err(ManifestError::UnknownRole(_))
        ));
    }

    #[test]
    fn unknown_format_is_rejected() {
        let bad = br#"{"nextUpdate":"2036-06-22T09:11:42Z","anchors":[{"role":"Pid","format":"Hologram","anchorCertDerB64":"AQID"}]}"#;
        assert!(matches!(
            TrustListManifest::parse(bad),
            Err(ManifestError::UnknownFormat(_))
        ));
    }
}
