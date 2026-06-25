//! TS 119 612 trust-list XML parsing + signature-authentication path (`quick-xml`, research D5).
//!
//! The production EU trust model is a **signed XML** LOTL / national Trusted List (ETSI TS 119 612
//! v2.4.1 / TLv6): a `<TrustServiceStatusList>` whose `<SchemeInformation>` carries a
//! `<NextUpdate>`, whose `<TrustServiceProviderList>` carries per-service
//! `<ServiceDigitalIdentity>` → `<X509Certificate>` anchor certificates, and which is sealed with an
//! enveloped XML-DSig `<ds:Signature>` whose `<X509Certificate>` is the trust-list operator's
//! signing certificate. This module parses that structure with `quick-xml` and exposes the per-list
//! anchor certificates + `NextUpdate` to the engine, and **authenticates** the list by chain-
//! validating its embedded signing certificate against a configured scheme-operator trust anchor
//! (the SDK's X.509 stack — [`super::chain`]).
//!
//! ## What is complete vs. remaining production hardening (honest scope — research D5 caveat)
//!
//! - **Complete now**: the `quick-xml` parse path (anchor certs per service + `NextUpdate`), and the
//!   X.509 **chain** authentication of the list's embedded signing certificate against a configured
//!   scheme-operator anchor. A list whose signing certificate does not chain to a configured anchor
//!   is **rejected** (`SignerUntrusted`).
//! - **Remaining production hardening** (deliberately not yet done — and it **fails closed**): the
//!   full enveloped XML-DSig cryptographic check — exclusive C14N (XML-EXC-C14N), `<Reference>`
//!   digest recomputation over the canonicalised `SignedInfo`/document, and the RSA/ECDSA
//!   `SignatureValue` verification. Until that lands, [`XmlTrustList::authenticate`] requires the
//!   caller to opt in to "chain-only" authentication explicitly; the default path returns
//!   [`XmlTrustListError::SignatureUnverified`] so a real LOTL is **not silently trusted** on the
//!   chain alone. This matches the fail-closed default the contract mandates.

use std::collections::BTreeMap;

use quick_xml::events::Event;
use quick_xml::reader::Reader;

use super::chain::{verify_chain, ChainError};
use crate::types::{Format, IssuerRole};

/// An error parsing or authenticating a TS 119 612 trust-list XML.
#[derive(Debug, thiserror::Error)]
pub enum XmlTrustListError {
    /// The bytes were not well-formed XML.
    #[error("trust-list XML is malformed: {0}")]
    Xml(String),
    /// A `<X509Certificate>` element body was not valid base64.
    #[error("trust-list X509Certificate is not valid base64: {0}")]
    Base64(String),
    /// The `<NextUpdate>` element was missing or not an RFC 3339 UTC timestamp.
    #[error("trust-list NextUpdate is missing or invalid: {0}")]
    NextUpdate(String),
    /// The trust list carried no `<ds:Signature>` to authenticate.
    #[error("trust-list is not signed (no ds:Signature)")]
    Unsigned,
    /// The trust-list signing certificate did not chain to a configured scheme-operator anchor.
    #[error("trust-list signing certificate is untrusted: {0}")]
    SignerUntrusted(ChainError),
    /// The full enveloped XML-DSig cryptographic check is not yet implemented; authenticating on the
    /// chain alone must be explicitly opted into (fail-closed default — see the module docs).
    #[error(
        "trust-list XML-DSig SignatureValue/C14N verification is not yet implemented; \
         pass `chain_only = true` to authenticate on the signing-cert chain alone (fail-closed default)"
    )]
    SignatureUnverified,
}

/// A parsed TS 119 612 trust list: per-`(role, format)` anchor certificates, the list's `NextUpdate`,
/// and (when present) the list's own signing certificate from the enveloped `<ds:Signature>`.
///
/// Carries only issuer-public anchor + signer certificates (no secret), so deriving `Debug` is safe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XmlTrustList {
    anchors: BTreeMap<(IssuerRole, Format), Vec<Vec<u8>>>,
    next_update_unix: i64,
    /// The DER signing certificate from the enveloped `<ds:Signature>`'s `<ds:X509Certificate>`, if
    /// the list was signed.
    signer_cert_der: Option<Vec<u8>>,
}

/// Where the parser currently is, so element bodies are attributed to the right collection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Section {
    /// Outside any service identity / signature (e.g. scheme information).
    Scheme,
    /// Inside a `<ServiceDigitalIdentity>` — `<X509Certificate>` bodies are service anchors.
    ServiceIdentity,
    /// Inside the enveloped `<ds:Signature>` — `<X509Certificate>` bodies are the signer cert.
    Signature,
}

impl XmlTrustList {
    /// Parse a TS 119 612 trust-list XML from its raw bytes, with the role/format every service maps
    /// to supplied by the caller (the production engine derives this from the service `ServiceType`
    /// URIs — `…/Svctype/EAA/Q` etc.; the parse path collects every service anchor under the given
    /// role/format so the engine can anchor against them).
    ///
    /// # Errors
    ///
    /// Returns [`XmlTrustListError`] when the XML is malformed, a certificate body is not valid
    /// base64, or `<NextUpdate>` is missing/invalid.
    pub fn parse(
        bytes: &[u8],
        role: IssuerRole,
        format: Format,
    ) -> Result<Self, XmlTrustListError> {
        let text = core::str::from_utf8(bytes)
            .map_err(|e| XmlTrustListError::Xml(format!("not UTF-8: {e}")))?;
        let mut reader = Reader::from_str(text);
        reader.config_mut().trim_text(true);

        let mut section = Section::Scheme;
        let mut service_anchors: Vec<Vec<u8>> = Vec::new();
        let mut signer_cert_der: Option<Vec<u8>> = None;
        let mut next_update_unix: Option<i64> = None;
        // The element whose Text body we are about to read (local name, lowercased).
        let mut pending: Option<String> = None;
        // Depth-tracked flag: we are inside a `<NextUpdate>` element (its body — directly or via a
        // nested `<dateTime>` child, the TS 119 612 shape — is the next-update timestamp).
        let mut in_next_update = false;

        loop {
            match reader
                .read_event()
                .map_err(|e| XmlTrustListError::Xml(e.to_string()))?
            {
                Event::Start(e) => {
                    let local = local_name(e.name().as_ref());
                    match local.as_str() {
                        "servicedigitalidentity" => section = Section::ServiceIdentity,
                        "signature" => section = Section::Signature,
                        "nextupdate" => {
                            in_next_update = true;
                            pending = Some(local);
                        }
                        "x509certificate" => pending = Some(local),
                        // The TS 119 612 `<NextUpdate>` wraps its instant in a `<dateTime>` child.
                        "datetime" if in_next_update => pending = Some("nextupdate".into()),
                        _ => {}
                    }
                }
                Event::End(e) => {
                    let local = local_name(e.name().as_ref());
                    match local.as_str() {
                        "servicedigitalidentity" | "signature" => section = Section::Scheme,
                        "nextupdate" => in_next_update = false,
                        _ => {}
                    }
                    pending = None;
                }
                Event::Text(t) => {
                    if let Some(tag) = pending.take() {
                        let body = t
                            .decode()
                            .map_err(|e| XmlTrustListError::Xml(e.to_string()))?;
                        match tag.as_str() {
                            "x509certificate" => {
                                let der = decode_b64_cert(body.as_ref())?;
                                match section {
                                    Section::Signature => signer_cert_der = Some(der),
                                    Section::ServiceIdentity => service_anchors.push(der),
                                    Section::Scheme => {}
                                }
                            }
                            "nextupdate" => {
                                // Take the first non-empty timestamp body seen inside NextUpdate
                                // (a bare `<NextUpdate>ts</NextUpdate>` or a `<dateTime>` child).
                                if next_update_unix.is_none() {
                                    next_update_unix =
                                        super::manifest::parse_rfc3339_utc_pub(body.trim());
                                }
                            }
                            _ => {}
                        }
                    }
                }
                Event::Eof => break,
                _ => {}
            }
        }

        let next_update_unix = next_update_unix
            .ok_or_else(|| XmlTrustListError::NextUpdate("missing or unparseable".into()))?;
        let mut anchors: BTreeMap<(IssuerRole, Format), Vec<Vec<u8>>> = BTreeMap::new();
        if !service_anchors.is_empty() {
            anchors.insert((role, format), service_anchors);
        }
        Ok(Self {
            anchors,
            next_update_unix,
            signer_cert_der,
        })
    }

    /// Authenticate the trust list: chain-validate its embedded signing certificate against a
    /// configured scheme-operator trust anchor.
    ///
    /// `chain_only` is the explicit opt-in to authenticate on the signing-cert chain **alone**
    /// (the enveloped XML-DSig `SignatureValue`/C14N digest check is the remaining production
    /// hardening — see the module docs). When `chain_only` is `false`, this fails closed with
    /// [`XmlTrustListError::SignatureUnverified`] so a real LOTL is never trusted on the chain
    /// alone by default.
    ///
    /// # Errors
    ///
    /// Returns [`XmlTrustListError::Unsigned`] if the list carried no `<ds:Signature>`,
    /// [`XmlTrustListError::SignerUntrusted`] if its signing certificate does not chain to a
    /// configured scheme anchor, or [`XmlTrustListError::SignatureUnverified`] when `chain_only` is
    /// `false`.
    pub fn authenticate(
        &self,
        scheme_anchors_der: &[Vec<u8>],
        now_unix: i64,
        chain_only: bool,
    ) -> Result<(), XmlTrustListError> {
        let signer = self
            .signer_cert_der
            .as_deref()
            .ok_or(XmlTrustListError::Unsigned)?;
        verify_chain(signer, scheme_anchors_der, now_unix)
            .map_err(XmlTrustListError::SignerUntrusted)?;
        if chain_only {
            Ok(())
        } else {
            Err(XmlTrustListError::SignatureUnverified)
        }
    }

    /// The anchor certificates (DER) the parsed list carries for a `(role, format)`.
    #[must_use]
    pub fn anchors_for(&self, role: IssuerRole, format: Format) -> &[Vec<u8>] {
        self.anchors.get(&(role, format)).map_or(&[], Vec::as_slice)
    }

    /// The list's `NextUpdate` instant (Unix seconds); at or after it the list is stale.
    #[must_use]
    pub const fn next_update_unix(&self) -> i64 {
        self.next_update_unix
    }

    /// The list's own signing certificate (DER) from the enveloped `<ds:Signature>`, if signed.
    #[must_use]
    pub fn signer_cert_der(&self) -> Option<&[u8]> {
        self.signer_cert_der.as_deref()
    }
}

/// The local (namespace-stripped, lowercased) name of an XML tag, e.g. `ds:X509Certificate` →
/// `x509certificate`. TS 119 612 elements live in several namespaces; matching on the local name is
/// the robust, prefix-agnostic approach.
fn local_name(qname: &[u8]) -> String {
    let local = qname.rsplit(|&b| b == b':').next().unwrap_or(qname);
    String::from_utf8_lossy(local).to_ascii_lowercase()
}

/// Decode a `<X509Certificate>` base64 body (which may contain PEM-style line breaks / whitespace)
/// into DER bytes, via the crate's single whitespace-tolerant cert-body decode (DRY — Principle III).
fn decode_b64_cert(body: &str) -> Result<Vec<u8>, XmlTrustListError> {
    crate::crypto::decode_base64_cert_lenient(body)
        .map_err(|e| XmlTrustListError::Base64(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::{XmlTrustList, XmlTrustListError};
    use crate::types::{Format, IssuerRole};
    use base64ct::{Base64, Encoding as _};

    const CA_IACA: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/ca-iaca.cert.der");
    const SDJWT_ISSUER: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/sdjwt-issuer.cert.der");
    const WRONG_ISSUER: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/wrong-issuer.cert.der");
    // Inside the fixtures' validity window (leaf 2026-06-25..2027-09-23).
    const NOW: i64 = 1_788_220_800; // 2026-09-01

    /// Build a minimal but structurally-faithful TS 119 612 trust-list XML: one service whose
    /// `<ServiceDigitalIdentity>` lists `service_cert`, sealed with an enveloped `<ds:Signature>`
    /// whose `<ds:X509Certificate>` is `signer_cert`.
    fn build_xml(service_cert: &[u8], signer_cert: &[u8], next_update: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <SchemeInformation>
    <NextUpdate><dateTime>{next_update}</dateTime></NextUpdate>
  </SchemeInformation>
  <TrustServiceProviderList>
    <TrustServiceProvider>
      <TSPServices>
        <TSPService>
          <ServiceInformation>
            <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/EAA/Q</ServiceTypeIdentifier>
            <ServiceDigitalIdentity>
              <DigitalId>
                <X509Certificate>{service}</X509Certificate>
              </DigitalId>
            </ServiceDigitalIdentity>
          </ServiceInformation>
        </TSPService>
      </TSPServices>
    </TrustServiceProvider>
  </TrustServiceProviderList>
  <ds:Signature>
    <ds:KeyInfo>
      <ds:X509Data>
        <ds:X509Certificate>{signer}</ds:X509Certificate>
      </ds:X509Data>
    </ds:KeyInfo>
  </ds:Signature>
</TrustServiceStatusList>"#,
            next_update = next_update,
            service = Base64::encode_string(service_cert),
            signer = Base64::encode_string(signer_cert),
        )
    }

    #[test]
    fn parses_service_anchors_and_next_update() {
        let xml = build_xml(SDJWT_ISSUER, CA_IACA, "2036-06-22T09:11:42Z");
        let list = XmlTrustList::parse(xml.as_bytes(), IssuerRole::Qeaa, Format::SdJwtVc)
            .expect("XML parses");
        let anchors = list.anchors_for(IssuerRole::Qeaa, Format::SdJwtVc);
        assert_eq!(anchors.len(), 1);
        assert_eq!(anchors[0], SDJWT_ISSUER);
        assert!(list.next_update_unix() > 2_000_000_000);
        assert_eq!(list.signer_cert_der(), Some(CA_IACA));
    }

    #[test]
    fn authenticate_chain_only_accepts_a_signer_that_chains_to_the_scheme_anchor() {
        // The list is "signed" by the IACA root; the scheme anchor is the IACA root itself
        // (self-issued direct pin) → chain-only authentication succeeds.
        let xml = build_xml(SDJWT_ISSUER, CA_IACA, "2036-06-22T09:11:42Z");
        let list = XmlTrustList::parse(xml.as_bytes(), IssuerRole::Qeaa, Format::SdJwtVc).unwrap();
        let scheme_anchors = vec![CA_IACA.to_vec()];
        assert!(list.authenticate(&scheme_anchors, NOW, true).is_ok());
    }

    #[test]
    fn authenticate_default_fails_closed_pending_full_xmldsig() {
        // Without the chain_only opt-in, the default fails closed (XML-DSig SignatureValue/C14N is
        // the remaining production hardening).
        let xml = build_xml(SDJWT_ISSUER, CA_IACA, "2036-06-22T09:11:42Z");
        let list = XmlTrustList::parse(xml.as_bytes(), IssuerRole::Qeaa, Format::SdJwtVc).unwrap();
        let scheme_anchors = vec![CA_IACA.to_vec()];
        assert!(matches!(
            list.authenticate(&scheme_anchors, NOW, false),
            Err(XmlTrustListError::SignatureUnverified)
        ));
    }

    #[test]
    fn authenticate_rejects_a_signer_that_does_not_chain_to_the_scheme_anchor() {
        // List "signed" by the wrong-issuer (self-signed, not chained) → SignerUntrusted even with
        // the chain_only opt-in.
        let xml = build_xml(SDJWT_ISSUER, WRONG_ISSUER, "2036-06-22T09:11:42Z");
        let list = XmlTrustList::parse(xml.as_bytes(), IssuerRole::Qeaa, Format::SdJwtVc).unwrap();
        let scheme_anchors = vec![CA_IACA.to_vec()];
        assert!(matches!(
            list.authenticate(&scheme_anchors, NOW, true),
            Err(XmlTrustListError::SignerUntrusted(_))
        ));
    }

    #[test]
    fn unsigned_list_cannot_be_authenticated() {
        let xml = r#"<?xml version="1.0"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
  <SchemeInformation><NextUpdate><dateTime>2036-06-22T09:11:42Z</dateTime></NextUpdate></SchemeInformation>
  <TrustServiceProviderList></TrustServiceProviderList>
</TrustServiceStatusList>"#;
        let list = XmlTrustList::parse(xml.as_bytes(), IssuerRole::Qeaa, Format::SdJwtVc).unwrap();
        assert!(list.signer_cert_der().is_none());
        assert!(matches!(
            list.authenticate(&[CA_IACA.to_vec()], NOW, true),
            Err(XmlTrustListError::Unsigned)
        ));
    }

    #[test]
    fn malformed_xml_is_rejected() {
        let bad = b"<TrustServiceStatusList><NextUpdate>oops";
        assert!(XmlTrustList::parse(bad, IssuerRole::Qeaa, Format::SdJwtVc).is_err());
    }

    #[test]
    fn missing_next_update_is_rejected() {
        let xml = r#"<?xml version="1.0"?><TrustServiceStatusList></TrustServiceStatusList>"#;
        assert!(matches!(
            XmlTrustList::parse(xml.as_bytes(), IssuerRole::Qeaa, Format::SdJwtVc),
            Err(XmlTrustListError::NextUpdate(_))
        ));
    }

    #[test]
    fn invalid_base64_certificate_is_rejected() {
        let xml = r#"<?xml version="1.0"?>
<TrustServiceStatusList xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <NextUpdate>2036-06-22T09:11:42Z</NextUpdate>
  <ServiceDigitalIdentity><X509Certificate>!!!not-base64!!!</X509Certificate></ServiceDigitalIdentity>
</TrustServiceStatusList>"#;
        assert!(matches!(
            XmlTrustList::parse(xml.as_bytes(), IssuerRole::Qeaa, Format::SdJwtVc),
            Err(XmlTrustListError::Base64(_))
        ));
    }

    #[test]
    fn x509_certificate_outside_a_service_or_signature_is_ignored() {
        // A stray `<X509Certificate>` directly under the scheme (not in a ServiceDigitalIdentity nor
        // a ds:Signature) is neither a service anchor nor the signer — it is ignored (no anchors,
        // no signer), so the list is parseable but unsigned and carries no anchors.
        let xml = format!(
            r#"<?xml version="1.0"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
  <SchemeInformation>
    <NextUpdate><dateTime>2036-06-22T09:11:42Z</dateTime></NextUpdate>
    <X509Certificate>{stray}</X509Certificate>
  </SchemeInformation>
</TrustServiceStatusList>"#,
            stray = Base64::encode_string(CA_IACA),
        );
        let list = XmlTrustList::parse(xml.as_bytes(), IssuerRole::Qeaa, Format::SdJwtVc).unwrap();
        assert!(list
            .anchors_for(IssuerRole::Qeaa, Format::SdJwtVc)
            .is_empty());
        assert!(list.signer_cert_der().is_none());
    }
}
