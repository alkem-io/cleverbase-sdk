//! TS 119 612 trust-list XML parsing + signature-authentication path (`quick-xml`, research D5).
//!
//! The production EU trust model is a **signed XML** LOTL / national Trusted List (ETSI TS 119 612
//! V2.4.1 / TLv6): a `<TrustServiceStatusList>` whose `<SchemeInformation>` carries a
//! `<NextUpdate>`, whose `<TrustServiceProviderList>` carries per-`<TSPService>`
//! `<ServiceInformation>` blocks — each with a `<ServiceTypeIdentifier>` (cl. 5.5.1), a
//! `<ServiceDigitalIdentity>` → `<X509Certificate>` anchor (cl. 5.5.3), and a `<ServiceStatus>`
//! (cl. 5.5.4) — and which is sealed with an enveloped XAdES `<ds:Signature>` whose
//! `<X509Certificate>` is the trust-list operator's signing certificate. This module parses that
//! structure with `quick-xml` and exposes the per-list anchor certificates + `NextUpdate` to the
//! engine.
//!
//! ## Service status + type gating (cl. 5.5.1 / 5.5.4 — the T5.1 false-trust fix)
//!
//! A trust service's `<X509Certificate>` is ingested as a trust anchor **only when its
//! `<ServiceStatus>` is `…/Svcstatus/granted`** ([`SVCSTATUS_GRANTED`], TS 119 612 V2.4.1 §5.5.4
//! item i / Annex D.5) — a **withdrawn**/suspended/absent-status service MUST NOT anchor trust (a
//! withdrawn QTSP cert is no longer a trust root). When the engine configures a specific expected
//! service type (e.g. [`SVCTYPE_EAA_Q`], §5.5.1.1), only `granted` services **of that type** are
//! ingested. (Verified online against the TS 119 612 V2.4.1 PDF, §5.5.1.1 (k) / §5.5.4 / Annex D.5.)
//!
//! ## Trust-list signature authentication (the T5.3 scope cut — fail-closed)
//!
//! TS 119 612 V2.4.1 §5.7.1 requires the list to be sealed with a **XAdES-B-B** enveloped signature
//! (EN 319 132-1), and Annex B.1.0 fixes its profile: a `<ds:Signature>` enveloped in
//! `<TrustServiceStatusList>` whose data-object `<ds:Reference>` carries an *enveloped-signature*
//! transform **then exclusive canonicalization** (`http://www.w3.org/2001/10/xml-exc-c14n#`), with
//! `<ds:CanonicalizationMethod>` over `<ds:SignedInfo>` also exclusive-C14N. A faithful verification
//! therefore needs full XML **exclusive canonicalization** + `<ds:Reference>` digest recomputation +
//! `SignatureValue` verification — there is **no shortcut** (Annex B.1.0). Implementing exclusive
//! C14N correctly is a large, security-critical undertaking that the in-tree `quick-xml` does not
//! provide, so it is a **documented scope cut** (see `standards-conformance.md` §1.5).
//!
//! Until full XAdES verification lands, [`XmlTrustList::authenticate`] **fails closed**: it returns
//! [`XmlTrustListError::SignatureUnverified`] for every list, even one whose embedded signing
//! certificate chains to a configured scheme anchor. Accepting a list on the signing-cert **chain
//! alone** is unsound — the signing certificate is public and copyable, so there is no binding
//! between the (unverified) signature and the list body, and a forged body would be accepted. That
//! chain-only acceptance is therefore **not reachable in production**: it exists only behind a
//! `#[cfg(test)]` seam (`XmlTrustList::authenticate_chain_only`) so the parse/anchor wiring stays
//! exercised by tests, while the production engine path is always fail-closed.

use std::collections::BTreeMap;

use quick_xml::events::Event;
use quick_xml::reader::Reader;

use super::chain::{verify_chain, ChainError};
use crate::types::{Format, IssuerRole};

/// TS 119 612 V2.4.1 §5.5.4 item i / Annex D.5 — the URI of a trust service whose current status is
/// **`granted`** (the qualified status is in force). Only a `granted` service anchors trust
/// (cl. 5.5.4); a `withdrawn` / suspended / absent status MUST NOT. Authoritative source for the
/// TS 119 612 status/type URIs across the crate (DRY — re-exported by [`crate::qualified`]).
pub const SVCSTATUS_GRANTED: &str = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted";

/// TS 119 612 V2.4.1 §5.5.4 item i / Annex D.5 — the URI of a **`withdrawn`** trust service (the
/// qualified status was never granted, or has been withdrawn). A withdrawn service MUST NOT anchor
/// trust (the T5.1 false-trust fix).
pub const SVCSTATUS_WITHDRAWN: &str = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn";

/// TS 119 612 V2.4.1 §5.5.1.1 (k) — the trust-service **type** URI for a *qualified* electronic
/// attestation of attributes (QEAA) issuing service. The qualified-status gate ([`crate::qualified`])
/// re-exports this as `EAA_Q_SERVICE_TYPE`.
pub const SVCTYPE_EAA_Q: &str = "http://uri.etsi.org/TrstSvc/Svctype/EAA/Q";

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
    /// The full enveloped XAdES `SignatureValue` / exclusive-C14N / `<ds:Reference>`-digest check is
    /// a documented scope cut (TS 119 612 V2.4.1 §5.7 / Annex B.1.0; EN 319 132-1), so the XML
    /// trust-list path **fails closed**: a list is never trusted on its signing-cert chain alone (a
    /// public signer cert + forged body would otherwise be accepted). See the module docs +
    /// `standards-conformance.md`.
    #[error(
        "trust-list XAdES SignatureValue / exclusive-C14N verification is a documented scope cut; \
         the XML trust-list path fails closed (a list is never trusted on the signing-cert chain alone)"
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
    /// Inside a `<ServiceDigitalIdentity>` — `<X509Certificate>` bodies are the current service's
    /// digital-identity (Sdi) certificates (cl. 5.5.3).
    ServiceIdentity,
    /// Inside the enveloped `<ds:Signature>` — `<X509Certificate>` bodies are the signer cert.
    Signature,
}

/// Per-`<ServiceInformation>` accumulation (TS 119 612 §5.5): a trust service's type (§5.5.1),
/// current status (§5.5.4), and its Sdi certificates (§5.5.3). Committed to the list's anchors only
/// when the service is `granted` (and matches the configured expected type) — see [`commit_service`].
#[derive(Debug, Default)]
struct ServiceAccum {
    /// The `<ServiceTypeIdentifier>` URI (§5.5.1), when seen.
    service_type: Option<String>,
    /// The `<ServiceStatus>` URI (§5.5.4), when seen.
    status: Option<String>,
    /// The `<ServiceDigitalIdentity>` → `<X509Certificate>` certs (DER) collected for this service.
    certs: Vec<Vec<u8>>,
}

impl XmlTrustList {
    /// Parse a TS 119 612 trust-list XML from its raw bytes. Every service whose `<ServiceStatus>` is
    /// [`SVCSTATUS_GRANTED`] (cl. 5.5.4) — and, when `expected_service_type` is `Some`, whose
    /// `<ServiceTypeIdentifier>` (cl. 5.5.1) matches it — contributes its `<ServiceDigitalIdentity>`
    /// certificate(s) as anchors for the caller-supplied `(role, format)`. A **withdrawn** / suspended
    /// / absent-status service is parsed but **never** anchors trust (the T5.1 false-trust fix).
    ///
    /// `expected_service_type` is the optional service-type filter (e.g. [`SVCTYPE_EAA_Q`]); `None`
    /// ingests every `granted` service regardless of type.
    ///
    /// # Errors
    ///
    /// Returns [`XmlTrustListError`] when the XML is malformed, a certificate body is not valid
    /// base64, or `<NextUpdate>` is missing/invalid.
    pub fn parse(
        bytes: &[u8],
        role: IssuerRole,
        format: Format,
        expected_service_type: Option<&str>,
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
        // The trust service currently being parsed (between `<ServiceInformation>` start/end).
        let mut cur_service: Option<ServiceAccum> = None;

        loop {
            match reader
                .read_event()
                .map_err(|e| XmlTrustListError::Xml(e.to_string()))?
            {
                Event::Start(e) => {
                    let local = local_name(e.name().as_ref());
                    match local.as_str() {
                        "serviceinformation" => cur_service = Some(ServiceAccum::default()),
                        "servicedigitalidentity" => section = Section::ServiceIdentity,
                        "signature" => section = Section::Signature,
                        // The service type (§5.5.1) and current status (§5.5.4) live at the
                        // `<ServiceInformation>` level (siblings of `<ServiceDigitalIdentity>`); their
                        // bodies — like an `<X509Certificate>` body — are attributed by their pending tag
                        // (the service type/status to the current service regardless of `section`).
                        "servicetypeidentifier" | "servicestatus" | "x509certificate" => {
                            pending = Some(local);
                        }
                        "nextupdate" => {
                            in_next_update = true;
                            pending = Some(local);
                        }
                        // The TS 119 612 `<NextUpdate>` wraps its instant in a `<dateTime>` child.
                        "datetime" if in_next_update => pending = Some("nextupdate".into()),
                        _ => {}
                    }
                }
                Event::End(e) => {
                    let local = local_name(e.name().as_ref());
                    match local.as_str() {
                        // Commit the finished service: ingest its certs only when `granted` (and of the
                        // expected type, if configured) — cl. 5.5.1 / 5.5.4.
                        "serviceinformation" => commit_service(
                            cur_service.take(),
                            expected_service_type,
                            &mut service_anchors,
                        ),
                        "servicedigitalidentity" | "signature" => section = Section::Scheme,
                        "nextupdate" => in_next_update = false,
                        _ => {}
                    }
                    pending = None;
                }
                Event::Text(t) => {
                    if let Some(tag) = pending.take() {
                        handle_text_event(
                            &t,
                            &tag,
                            section,
                            &mut signer_cert_der,
                            &mut cur_service,
                            &mut next_update_unix,
                        )?;
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

    /// Authenticate the trust list. **Production: fail-closed.**
    ///
    /// The full enveloped XAdES verification (exclusive C14N + `<ds:Reference>` digest recomputation +
    /// `SignatureValue` check) required by TS 119 612 V2.4.1 §5.7 / Annex B.1.0 (EN 319 132-1) is a
    /// documented scope cut (no XML-C14N is available in-tree, and there is no sound shortcut — Annex
    /// B.1.0). This method therefore surfaces the specific [`XmlTrustListError::Unsigned`] /
    /// [`XmlTrustListError::SignerUntrusted`] reason when applicable and then **always** returns
    /// [`XmlTrustListError::SignatureUnverified`]: a list is **never** trusted on its signing-cert
    /// chain alone (the signing cert is public and copyable; a forged body would otherwise be
    /// accepted). See the module docs + `standards-conformance.md`.
    ///
    /// # Errors
    ///
    /// Returns [`XmlTrustListError::Unsigned`] if the list carried no `<ds:Signature>`,
    /// [`XmlTrustListError::SignerUntrusted`] if its signing certificate does not chain to a
    /// configured scheme anchor, otherwise [`XmlTrustListError::SignatureUnverified`] (fail-closed).
    pub fn authenticate(
        &self,
        scheme_anchors_der: &[Vec<u8>],
        now_unix: i64,
    ) -> Result<(), XmlTrustListError> {
        // Surface the precise unsigned/unchained reason first (so a malformed list is not opaque),
        // then fail closed on the missing XAdES cryptographic verification.
        self.verify_signer_chains(scheme_anchors_der, now_unix)?;
        Err(XmlTrustListError::SignatureUnverified)
    }

    /// Chain-validate the embedded signing certificate against the configured scheme-operator anchors
    /// (the structural §6.1 path), the shared body behind [`Self::authenticate`] and the test-only
    /// chain seam. A trust-list signer is governed by a separate ETSI profile (not the credential-leaf
    /// rules), so it carries [`crate::trust::chain::LeafPurpose::TrustListSigner`] (no leaf-purpose
    /// constraint) and its window is checked at `now_unix`.
    fn verify_signer_chains(
        &self,
        scheme_anchors_der: &[Vec<u8>],
        now_unix: i64,
    ) -> Result<(), XmlTrustListError> {
        let signer = self
            .signer_cert_der
            .as_deref()
            .ok_or(XmlTrustListError::Unsigned)?;
        verify_chain(
            &[signer],
            scheme_anchors_der,
            now_unix,
            None,
            crate::trust::chain::LeafPurpose::TrustListSigner,
        )
        .map_err(XmlTrustListError::SignerUntrusted)
    }

    /// Test-only seam: authenticate on the signing-cert **chain alone** (the structural §6.1 path,
    /// WITHOUT the full XAdES `SignatureValue`/C14N verification). This is the forgeable acceptance the
    /// T5.3 fix removed from production; it is `#[cfg(test)]` so it can never be reached by an
    /// integrator, and exists only to keep the parse → anchor-ingest wiring exercised by tests.
    ///
    /// # Errors
    ///
    /// Returns [`XmlTrustListError::Unsigned`] / [`XmlTrustListError::SignerUntrusted`] as
    /// [`Self::authenticate`] does, but returns `Ok(())` when the signer chains to a scheme anchor.
    #[cfg(test)]
    pub(crate) fn authenticate_chain_only(
        &self,
        scheme_anchors_der: &[Vec<u8>],
        now_unix: i64,
    ) -> Result<(), XmlTrustListError> {
        self.verify_signer_chains(scheme_anchors_der, now_unix)
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
}

/// Commit a finished `<ServiceInformation>` block: ingest its Sdi certificate(s) as anchors **only**
/// when the service's current status is [`SVCSTATUS_GRANTED`] (TS 119 612 §5.5.4) — a withdrawn /
/// suspended / absent-status service never anchors trust — and, when `expected_service_type` is
/// configured, only when the service's `<ServiceTypeIdentifier>` (§5.5.1) matches it.
fn commit_service(
    service: Option<ServiceAccum>,
    expected_service_type: Option<&str>,
    anchors: &mut Vec<Vec<u8>>,
) {
    let Some(service) = service else {
        return;
    };
    // §5.5.4: only `granted` anchors trust. A withdrawn/suspended/absent status MUST NOT.
    if service.status.as_deref() != Some(SVCSTATUS_GRANTED) {
        return;
    }
    // §5.5.1: when the engine is configured for a specific service type, only that type is ingested.
    if let Some(expected) = expected_service_type {
        if service.service_type.as_deref() != Some(expected) {
            return;
        }
    }
    anchors.extend(service.certs);
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

/// Attribute one element's `Text` body (`text`, for the pending `tag` in `section`) to the right
/// collection:
///
/// - `<X509Certificate>` → the signer cert ([`Section::Signature`]) or the current service's Sdi cert
///   ([`Section::ServiceIdentity`], when a service is open); a scheme-section / no-service cert is
///   ignored. The body is base64-decoded eagerly (so an invalid encoding is rejected regardless of
///   service status).
/// - `<ServiceTypeIdentifier>` / `<ServiceStatus>` → the current service's type / status (§5.5.1 /
///   §5.5.4), when a service is open.
/// - `<NextUpdate>` → the first non-empty timestamp seen (a bare body or a `<dateTime>` child).
///
/// Any other pending tag is a no-op.
fn handle_text_event(
    text: &quick_xml::events::BytesText<'_>,
    tag: &str,
    section: Section,
    signer_cert_der: &mut Option<Vec<u8>>,
    cur_service: &mut Option<ServiceAccum>,
    next_update_unix: &mut Option<i64>,
) -> Result<(), XmlTrustListError> {
    let body = text
        .decode()
        .map_err(|e| XmlTrustListError::Xml(e.to_string()))?;
    match tag {
        "x509certificate" => {
            // Decode eagerly so an invalid base64 body is rejected even for a non-granted service.
            let der = decode_b64_cert(body.as_ref())?;
            match section {
                Section::Signature => *signer_cert_der = Some(der),
                Section::ServiceIdentity => {
                    if let Some(service) = cur_service.as_mut() {
                        service.certs.push(der);
                    }
                }
                Section::Scheme => {}
            }
        }
        "servicetypeidentifier" => {
            if let Some(service) = cur_service.as_mut() {
                service.service_type = Some(body.trim().to_owned());
            }
        }
        "servicestatus" => {
            if let Some(service) = cur_service.as_mut() {
                service.status = Some(body.trim().to_owned());
            }
        }
        "nextupdate" => {
            // Take the first non-empty timestamp body seen inside NextUpdate (a bare
            // `<NextUpdate>ts</NextUpdate>` or a `<dateTime>` child).
            if next_update_unix.is_none() {
                *next_update_unix = super::manifest::parse_rfc3339_utc_pub(body.trim());
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        XmlTrustList, XmlTrustListError, SVCSTATUS_GRANTED, SVCSTATUS_WITHDRAWN, SVCTYPE_EAA_Q,
    };
    use crate::types::{Format, IssuerRole};
    use base64ct::{Base64, Encoding as _};

    const CA_IACA: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/ca-iaca.cert.der");
    const SDJWT_ISSUER: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/sdjwt-issuer.cert.der");
    const MDOC_DS: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/mdoc-ds.cert.der");
    const WRONG_ISSUER: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/wrong-issuer.cert.der");
    // Inside the fixtures' validity window (leaf 2026-06-25..2027-09-23).
    const NOW: i64 = 1_788_220_800; // 2026-09-01

    /// Build a minimal but structurally-faithful TS 119 612 trust-list XML: one `granted` EAA/Q
    /// service whose `<ServiceDigitalIdentity>` lists `service_cert`, sealed with an enveloped
    /// `<ds:Signature>` whose `<ds:X509Certificate>` is `signer_cert`.
    fn build_xml(service_cert: &[u8], signer_cert: &[u8], next_update: &str) -> String {
        build_xml_with_status(service_cert, signer_cert, next_update, SVCSTATUS_GRANTED)
    }

    /// Like [`build_xml`] but with a caller-chosen `<ServiceStatus>` URI (granted/withdrawn probe).
    fn build_xml_with_status(
        service_cert: &[u8],
        signer_cert: &[u8],
        next_update: &str,
        status: &str,
    ) -> String {
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
            <ServiceTypeIdentifier>{svctype}</ServiceTypeIdentifier>
            <ServiceDigitalIdentity>
              <DigitalId>
                <X509Certificate>{service}</X509Certificate>
              </DigitalId>
            </ServiceDigitalIdentity>
            <ServiceStatus>{status}</ServiceStatus>
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
            svctype = SVCTYPE_EAA_Q,
            status = status,
            service = Base64::encode_string(service_cert),
            signer = Base64::encode_string(signer_cert),
        )
    }

    #[test]
    fn parses_granted_service_anchors_and_next_update() {
        let xml = build_xml(SDJWT_ISSUER, CA_IACA, "2036-06-22T09:11:42Z");
        let list = XmlTrustList::parse(xml.as_bytes(), IssuerRole::Qeaa, Format::SdJwtVc, None)
            .expect("XML parses");
        let anchors = list.anchors_for(IssuerRole::Qeaa, Format::SdJwtVc);
        assert_eq!(anchors.len(), 1);
        assert_eq!(anchors[0], SDJWT_ISSUER);
        assert!(list.next_update_unix() > 2_000_000_000);
        // The enveloped signer is the IACA root: chain-only authentication against the IACA scheme
        // anchor succeeds via the test-only seam (the production `authenticate` always fails closed).
        assert!(list
            .authenticate_chain_only(&[CA_IACA.to_vec()], NOW)
            .is_ok());
    }

    #[test]
    fn a_withdrawn_service_cert_does_not_anchor_trust_while_a_granted_one_does() {
        // T5.1 false-trust fix: a WITHDRAWN service's cert MUST NOT become a trust anchor (a withdrawn
        // QTSP cert is no longer a trust root), while a GRANTED service's cert is ingested. Build a
        // two-service list — one withdrawn (mdoc-ds), one granted (sdjwt-issuer) — and assert only the
        // granted cert anchors.
        let xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <SchemeInformation><NextUpdate><dateTime>2036-06-22T09:11:42Z</dateTime></NextUpdate></SchemeInformation>
  <TrustServiceProviderList><TrustServiceProvider><TSPServices>
    <TSPService><ServiceInformation>
      <ServiceTypeIdentifier>{svctype}</ServiceTypeIdentifier>
      <ServiceDigitalIdentity><DigitalId><X509Certificate>{withdrawn}</X509Certificate></DigitalId></ServiceDigitalIdentity>
      <ServiceStatus>{withdrawn_status}</ServiceStatus>
    </ServiceInformation></TSPService>
    <TSPService><ServiceInformation>
      <ServiceTypeIdentifier>{svctype}</ServiceTypeIdentifier>
      <ServiceDigitalIdentity><DigitalId><X509Certificate>{granted}</X509Certificate></DigitalId></ServiceDigitalIdentity>
      <ServiceStatus>{granted_status}</ServiceStatus>
    </ServiceInformation></TSPService>
  </TSPServices></TrustServiceProvider></TrustServiceProviderList>
  <ds:Signature><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{signer}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>
</TrustServiceStatusList>"#,
            svctype = SVCTYPE_EAA_Q,
            withdrawn = Base64::encode_string(MDOC_DS),
            withdrawn_status = SVCSTATUS_WITHDRAWN,
            granted = Base64::encode_string(SDJWT_ISSUER),
            granted_status = SVCSTATUS_GRANTED,
            signer = Base64::encode_string(CA_IACA),
        );
        let list = XmlTrustList::parse(xml.as_bytes(), IssuerRole::Qeaa, Format::SdJwtVc, None)
            .expect("XML parses");
        let anchors = list.anchors_for(IssuerRole::Qeaa, Format::SdJwtVc);
        assert_eq!(anchors.len(), 1, "only the granted service's cert anchors");
        assert_eq!(anchors[0], SDJWT_ISSUER, "the granted cert is trusted");
        assert!(
            !anchors.iter().any(|c| c == MDOC_DS),
            "the withdrawn service's cert must NOT anchor trust"
        );
    }

    #[test]
    fn a_service_with_no_status_does_not_anchor_trust() {
        // Fail-closed: a service with NO `<ServiceStatus>` is not `granted`, so it MUST NOT anchor.
        let xml = format!(
            r#"<?xml version="1.0"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
  <SchemeInformation><NextUpdate><dateTime>2036-06-22T09:11:42Z</dateTime></NextUpdate></SchemeInformation>
  <TrustServiceProviderList><TrustServiceProvider><TSPServices><TSPService><ServiceInformation>
    <ServiceTypeIdentifier>{svctype}</ServiceTypeIdentifier>
    <ServiceDigitalIdentity><DigitalId><X509Certificate>{svc}</X509Certificate></DigitalId></ServiceDigitalIdentity>
  </ServiceInformation></TSPService></TSPServices></TrustServiceProvider></TrustServiceProviderList>
</TrustServiceStatusList>"#,
            svctype = SVCTYPE_EAA_Q,
            svc = Base64::encode_string(SDJWT_ISSUER),
        );
        let list = XmlTrustList::parse(xml.as_bytes(), IssuerRole::Qeaa, Format::SdJwtVc, None)
            .expect("XML parses");
        assert!(list
            .anchors_for(IssuerRole::Qeaa, Format::SdJwtVc)
            .is_empty());
    }

    #[test]
    fn the_service_type_filter_only_ingests_the_matching_type() {
        // §5.5.1: when an expected service type is configured, only `granted` services OF THAT TYPE
        // anchor. A granted CA/QC service is excluded when the engine expects EAA/Q.
        let other_type = "http://uri.etsi.org/TrstSvc/Svctype/CA/QC";
        let xml = format!(
            r#"<?xml version="1.0"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
  <SchemeInformation><NextUpdate><dateTime>2036-06-22T09:11:42Z</dateTime></NextUpdate></SchemeInformation>
  <TrustServiceProviderList><TrustServiceProvider><TSPServices>
    <TSPService><ServiceInformation>
      <ServiceTypeIdentifier>{other}</ServiceTypeIdentifier>
      <ServiceDigitalIdentity><DigitalId><X509Certificate>{ca}</X509Certificate></DigitalId></ServiceDigitalIdentity>
      <ServiceStatus>{granted}</ServiceStatus>
    </ServiceInformation></TSPService>
    <TSPService><ServiceInformation>
      <ServiceTypeIdentifier>{eaaq}</ServiceTypeIdentifier>
      <ServiceDigitalIdentity><DigitalId><X509Certificate>{leaf}</X509Certificate></DigitalId></ServiceDigitalIdentity>
      <ServiceStatus>{granted}</ServiceStatus>
    </ServiceInformation></TSPService>
  </TSPServices></TrustServiceProvider></TrustServiceProviderList>
</TrustServiceStatusList>"#,
            other = other_type,
            eaaq = SVCTYPE_EAA_Q,
            granted = SVCSTATUS_GRANTED,
            ca = Base64::encode_string(MDOC_DS),
            leaf = Base64::encode_string(SDJWT_ISSUER),
        );
        let list = XmlTrustList::parse(
            xml.as_bytes(),
            IssuerRole::Qeaa,
            Format::SdJwtVc,
            Some(SVCTYPE_EAA_Q),
        )
        .expect("XML parses");
        let anchors = list.anchors_for(IssuerRole::Qeaa, Format::SdJwtVc);
        assert_eq!(
            anchors,
            &[SDJWT_ISSUER.to_vec()],
            "only the EAA/Q service anchors"
        );
    }

    #[test]
    fn authenticate_always_fails_closed_pending_full_xades() {
        // T5.3 scope-cut: the production `authenticate` fails closed for EVERY list — even one whose
        // signer chains to the scheme anchor — because the full XAdES SignatureValue/exclusive-C14N
        // verification is a documented scope cut (a public signer cert + forged body is not accepted).
        let xml = build_xml(SDJWT_ISSUER, CA_IACA, "2036-06-22T09:11:42Z");
        let list =
            XmlTrustList::parse(xml.as_bytes(), IssuerRole::Qeaa, Format::SdJwtVc, None).unwrap();
        assert!(matches!(
            list.authenticate(&[CA_IACA.to_vec()], NOW),
            Err(XmlTrustListError::SignatureUnverified)
        ));
    }

    #[test]
    fn authenticate_surfaces_unsigned_before_failing_closed() {
        // An unsigned list fails with the specific `Unsigned` reason (not the generic SignatureUnverified).
        let xml = r#"<?xml version="1.0"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
  <SchemeInformation><NextUpdate><dateTime>2036-06-22T09:11:42Z</dateTime></NextUpdate></SchemeInformation>
  <TrustServiceProviderList></TrustServiceProviderList>
</TrustServiceStatusList>"#;
        let list =
            XmlTrustList::parse(xml.as_bytes(), IssuerRole::Qeaa, Format::SdJwtVc, None).unwrap();
        assert!(matches!(
            list.authenticate(&[CA_IACA.to_vec()], NOW),
            Err(XmlTrustListError::Unsigned)
        ));
    }

    #[test]
    fn authenticate_surfaces_signer_untrusted_before_failing_closed() {
        // A signer that does not chain to the scheme anchor fails with the specific `SignerUntrusted`
        // reason (surfaced before the fail-closed SignatureUnverified).
        let xml = build_xml(SDJWT_ISSUER, WRONG_ISSUER, "2036-06-22T09:11:42Z");
        let list =
            XmlTrustList::parse(xml.as_bytes(), IssuerRole::Qeaa, Format::SdJwtVc, None).unwrap();
        assert!(matches!(
            list.authenticate(&[CA_IACA.to_vec()], NOW),
            Err(XmlTrustListError::SignerUntrusted(_))
        ));
    }

    #[test]
    fn chain_only_seam_accepts_a_signer_that_chains_to_the_scheme_anchor() {
        // The test-only chain seam still validates the signer chain (used to exercise the
        // parse → anchor-ingest wiring); production cannot reach it.
        let xml = build_xml(SDJWT_ISSUER, CA_IACA, "2036-06-22T09:11:42Z");
        let list =
            XmlTrustList::parse(xml.as_bytes(), IssuerRole::Qeaa, Format::SdJwtVc, None).unwrap();
        assert!(list
            .authenticate_chain_only(&[CA_IACA.to_vec()], NOW)
            .is_ok());
    }

    #[test]
    fn chain_only_seam_rejects_a_signer_that_does_not_chain() {
        let xml = build_xml(SDJWT_ISSUER, WRONG_ISSUER, "2036-06-22T09:11:42Z");
        let list =
            XmlTrustList::parse(xml.as_bytes(), IssuerRole::Qeaa, Format::SdJwtVc, None).unwrap();
        assert!(matches!(
            list.authenticate_chain_only(&[CA_IACA.to_vec()], NOW),
            Err(XmlTrustListError::SignerUntrusted(_))
        ));
    }

    #[test]
    fn unsigned_list_chain_seam_is_unsigned() {
        let xml = r#"<?xml version="1.0"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
  <SchemeInformation><NextUpdate><dateTime>2036-06-22T09:11:42Z</dateTime></NextUpdate></SchemeInformation>
  <TrustServiceProviderList></TrustServiceProviderList>
</TrustServiceStatusList>"#;
        let list =
            XmlTrustList::parse(xml.as_bytes(), IssuerRole::Qeaa, Format::SdJwtVc, None).unwrap();
        assert!(matches!(
            list.authenticate_chain_only(&[CA_IACA.to_vec()], NOW),
            Err(XmlTrustListError::Unsigned)
        ));
    }

    #[test]
    fn malformed_xml_is_rejected() {
        let bad = b"<TrustServiceStatusList><NextUpdate>oops";
        assert!(XmlTrustList::parse(bad, IssuerRole::Qeaa, Format::SdJwtVc, None).is_err());
    }

    #[test]
    fn missing_next_update_is_rejected() {
        let xml = r#"<?xml version="1.0"?><TrustServiceStatusList></TrustServiceStatusList>"#;
        assert!(matches!(
            XmlTrustList::parse(xml.as_bytes(), IssuerRole::Qeaa, Format::SdJwtVc, None),
            Err(XmlTrustListError::NextUpdate(_))
        ));
    }

    #[test]
    fn invalid_base64_certificate_is_rejected() {
        // The cert body is decoded eagerly, so an invalid base64 Sdi cert is rejected at parse time
        // regardless of the service status.
        let xml = format!(
            r#"<?xml version="1.0"?>
<TrustServiceStatusList xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <NextUpdate>2036-06-22T09:11:42Z</NextUpdate>
  <ServiceInformation>
    <ServiceStatus>{SVCSTATUS_GRANTED}</ServiceStatus>
    <ServiceDigitalIdentity><X509Certificate>!!!not-base64!!!</X509Certificate></ServiceDigitalIdentity>
  </ServiceInformation>
</TrustServiceStatusList>"#,
        );
        assert!(matches!(
            XmlTrustList::parse(xml.as_bytes(), IssuerRole::Qeaa, Format::SdJwtVc, None),
            Err(XmlTrustListError::Base64(_))
        ));
    }

    #[test]
    fn x509_certificate_outside_a_service_or_signature_is_ignored() {
        // A stray `<X509Certificate>` directly under the scheme (not in a ServiceDigitalIdentity nor a
        // ds:Signature) is neither a service anchor nor the signer — it is ignored (no anchors, no
        // signer), so the list is parseable but unsigned and carries no anchors.
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
        let list =
            XmlTrustList::parse(xml.as_bytes(), IssuerRole::Qeaa, Format::SdJwtVc, None).unwrap();
        assert!(list
            .anchors_for(IssuerRole::Qeaa, Format::SdJwtVc)
            .is_empty());
        // The stray cert is neither a service anchor nor the signer: with no signer parsed,
        // authentication fails closed as `Unsigned`.
        assert!(matches!(
            list.authenticate(&[CA_IACA.to_vec()], NOW),
            Err(XmlTrustListError::Unsigned)
        ));
    }
}
