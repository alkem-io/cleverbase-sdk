//! Opt-in eIDAS qualified-status determination (ETSI TS 119 615 v1.4.1 cl. 4.12) — T019.
//!
//! Over the always-on bar (which is never replaced by this), an **opt-in**, version-pinned
//! determination of whether an attestation issuer is a **qualified** EAA provider: authenticate the
//! LOTL → select the national Trusted List → confirm the attestation self-declares the qualified-EAA
//! type ([`EAA_EU_QUALIFIED_TYPE`], TS 119 615 PRO-4.12.4-03) → match the issuer's signing certificate
//! against a trust-service entry of type [`EAA_Q_SERVICE_TYPE`] (`…/Svctype/EAA/Q`) → read the
//! `granted`/`withdrawn` service status **at the relevant time** (the credential's issuance/relevant
//! time, NOT "now"). The reusable trust-list primitives ([`crate::trust`]) anchor the same PKI (DRY).
//!
//! ## Outcome conditions (pinned — tasks T018/T019, analyze A1)
//!
//! - [`QualifiedStatus::Qualified`] — the attestation self-declares the qualified-EAA type AND the
//!   issuer's `EAA/Q` service entry is **`granted`** at the relevant time.
//! - [`QualifiedStatus::NotQualified`] — the entry is **found but not granted** (its status at the
//!   relevant time is withdrawn/suspended, the grant had not yet begun, or the issuer is on the TL
//!   only under a non-`EAA/Q` service type), with the self-declaration present.
//! - [`QualifiedStatus::Indeterminate`] — the trust-list data needed to decide is **absent,
//!   ambiguous, or unreachable** (the issuer is on no service entry, or there is no TL at all), the
//!   TL fails authentication, **or the attestation does not self-declare the qualified-EAA type**
//!   (PRO-4.12.4-03). The gate **never assumes qualified** (no false "qualified" — SC-007).
//!
//! ## QEAA type-indication precondition (TS 119 615 v1.4.1 PRO-4.12.4-03 — the T5.2 false-trust fix)
//!
//! Before the issuer's `EAA/Q` service status is read, the determination requires the **EAA content
//! to self-declare the qualified-EAA type**. PRO-4.12.4-03 (verified online against the v1.4.1 PDF)
//! mandates: *"check whether the URN `'urn:etsi:esi:eaa:eu:qualified'` is present within the content
//! of EAA and if this URN is not present"* → set the result to `Indeterminate`
//! (`ERROR_NO_ETSI_QEAA_TYPE_INDICATION_FOUND`) and **stop**. So an attestation whose declared type
//! does not carry [`EAA_EU_QUALIFIED_TYPE`] is `Indeterminate`, **never** `Qualified`, even if its
//! issuer is a granted `EAA/Q` QTSP. The type indication is threaded from
//! [`verify`](crate::verify()) as `type_indication`:
//!
//! - **SD-JWT VC** — the issuer-signed `vct` (the credential's type claim). When it is not
//!   [`EAA_EU_QUALIFIED_TYPE`] the determination is `Indeterminate`.
//! - **ISO mdoc** — `None`: cl. 4.12's URN is an EAA-content (SD-JWT VC / JWT-VC `vct`/`type`)
//!   construct, and TS 119 615 cl. 4.12 defines **no** mapping of this URN into ISO 18013-5 mdoc
//!   content (an mdoc declares its type via `docType`, a reverse-domain ISO identifier). The mdoc
//!   path therefore passes `None` and the precondition is **not enforced** for it; its qualified
//!   determination uses the cert→granted-`EAA/Q`-service status (TS 119 612 §5.5.4). A non-`None`
//!   indication that is not the URN always fails closed to `Indeterminate` (conservative — never a
//!   false "qualified").
//!
//! **Version note (the doc-nit reconciliation):** cl. 4.12 was introduced in TS 119 615 **v1.3.1**
//! (2026-01) and is retained in the pinned **v1.4.1** (2026-05). The QEAA self-declaration URN was
//! **renamed between the two**: v1.3.1 used `urn:etsi:eaa:eu:qualified`; v1.4.1 inserts an `esi:`
//! segment → `urn:etsi:esi:eaa:eu:qualified`. This implementation pins [`TS_119_615_VERSION`]
//! (`1.4.1`) and therefore uses the v1.4.1 URN (verified online against the v1.4.1 PDF —
//! not training data).
//!
//! ## Experimental + version-pinned
//!
//! cl. 4.12 (QEAA qualified-status determination) is **pre-operational**: national Trusted Lists are
//! only beginning to carry `EAA/Q` entries (post CIR (EU) 2025/1569). This implementation is pinned to
//! [`TS_119_615_VERSION`] (`1.4.1`) and is **off by default** ([`crate::verify::VerifyContext::qualified_gate`])
//! — enabling it is opt-in, and absent fixtures honestly yield `Indeterminate`.
//!
//! ## Service-digital-identity matching (TS 119 612 V2.4.1 §5.5.3 — the T5.4 false-reject fix)
//!
//! A credential's signing leaf is matched against a trust-service's digital identity (Sdi) by any of
//! (verified online against TS 119 612 V2.4.1 §5.5.3 + the EU DSS `DigitalIdentityListTypeConverter`):
//!
//! 1. **Exact X509Certificate DER** — the mandatory, machine-processable Sdi form (DSS matches on this
//!    alone);
//! 2. **X509SKI** — the leaf shares the Sdi's `SubjectKeyIdentifier` (a renewed/re-encoded cert with
//!    the same key); §5.5.3 lists X509SKI as an optional machine-usable identifier;
//! 3. **Issuing-CA** — the Sdi lists the **issuing CA** (the common national-TL shape — the Sdi is the
//!    CA, not the byte-identical leaf), matched by the leaf's `issuer` DN == the Sdi cert's `subject`
//!    DN, tightened by the leaf's AKI == the Sdi's SKI when both are present.
//!
//! `X509SubjectName` (a bare Distinguished Name) is **deliberately not** machine-matched: §5.5.3 states
//! it *"should not be used by applications in machine processable way"*, and EU DSS does not consume it.
//! (The issuing-CA rule compares the leaf's `issuer` field to the Sdi **certificate's** subject — a
//! chain relationship — not a bare X509SubjectName element.) This closes the false-reject where a valid
//! QEAA whose Sdi lists the issuing CA / its SKI (not the exact leaf) was reported `Indeterminate`.
//!
//! ## Trust-list authentication (fail-closed — SC-007)
//!
//! Before any status is read, the national TL is **authenticated** by
//! [`QualifiedTrustList::authenticate`]: it chain-validates the list's embedded signer certificate
//! ([`QualifiedTrustList::signer_cert_der`]) against a host-configured **scheme-operator trust
//! anchor**, reusing [`crate::trust::chain::verify_chain`] (the same X.509 primitive the always-on
//! bar uses — DRY; no re-implemented crypto), and rejects a **stale** list (`now_unix` at/after its
//! `NextUpdate`). An unsigned list (no signer), a signer that does not chain to the scheme anchor,
//! and a stale list all **fail** authentication. [`qualified_status`] runs `authenticate` first and
//! returns [`QualifiedStatus::Indeterminate`] (NEVER [`QualifiedStatus::Qualified`]) on any failure
//! — fail-closed, consistent with the always-on engine's stale/auth policy ([`crate::trust::engine`])
//! and the spec-003 pattern. A forged / attacker-supplied / unsigned TL can therefore never make an
//! unchained issuer report `Qualified`.
//!
//! Staleness in this cl. 4.12 determination is **fail-closed** (a stale snapshot → `Indeterminate`),
//! which is intentionally stricter than the general national-TL staleness handling (a non-fatal
//! warning, TS 119 615 PRO-4.2.4-10, applied in [`crate::trust::engine`]): the qualified-status
//! determination must never assert `Qualified` from a stale or expired-signer trust snapshot (the
//! now-vs-relevant-time SC-007 invariant below), so it does not relax staleness the way the always-on
//! membership engine does for a national TL.
//!
//! The full enveloped XAdES `SignatureValue`/C14N check is a documented scope cut
//! ([`crate::trust::xml`], `standards-conformance.md`); the offline JSON form here carries the signer
//! cert so the gate exercises the same chain-authentication seam against the same X.509 stack.

#[cfg(test)]
mod tests;

use base64ct::{Base64, Encoding as _};
use der::{Decode as _, Encode as _};
use serde::Deserialize;
use x509_cert::ext::pkix::{AuthorityKeyIdentifier, SubjectKeyIdentifier};
use x509_cert::Certificate;

use crate::trust::manifest::parse_rfc3339_utc_pub;
use crate::types::QualifiedStatus;

/// The pinned TS 119 615 version this determination implements (research D6 — experimental,
/// pre-operational). Surfaced so a consumer can record exactly which clause-4.12 revision produced a
/// verdict.
pub const TS_119_615_VERSION: &str = "1.4.1";

/// The TS 119 612 V2.4.1 §5.5.1.1 (k) trust-service **type** URI for a *qualified* electronic
/// attestation of attributes (QEAA) issuing service. Only a service of this exact type can make an
/// issuer [`QualifiedStatus::Qualified`] (a plain `…/Svctype/EAA` — non-qualified EAA — never does).
/// Re-exported from the TS 119 612 module ([`crate::trust::xml`]) — one authoritative source (DRY).
pub use crate::trust::xml::SVCTYPE_EAA_Q as EAA_Q_SERVICE_TYPE;

/// The TS 119 612 V2.4.1 §5.5.4 / Annex D.5 trust-service **status** URI for a `granted` service (in
/// force). An `EAA/Q` service whose effective status at the relevant time is `granted` makes its
/// issuer [`QualifiedStatus::Qualified`]. Re-exported from [`crate::trust::xml`] (DRY).
pub use crate::trust::xml::SVCSTATUS_GRANTED as SERVICE_STATUS_GRANTED;

/// The TS 119 615 **v1.4.1** PRO-4.12.4-03 QEAA self-declaration URN: the URN that MUST be present
/// within the EAA content for the attestation to be a *qualified* EAA. (v1.3.1 used the shorter
/// `urn:etsi:eaa:eu:qualified`; v1.4.1 — the pinned version — inserts the `esi:` segment. Verified
/// online against the v1.4.1 PDF.) When the credential's type indication is not this URN, the
/// determination is [`QualifiedStatus::Indeterminate`], never `Qualified`.
pub const EAA_EU_QUALIFIED_TYPE: &str = "urn:etsi:esi:eaa:eu:qualified";

/// An error parsing the qualified-status national Trusted List.
#[derive(Debug, thiserror::Error)]
pub enum QualifiedTrustListError {
    /// The bytes were not valid JSON of the expected national-TL shape.
    #[error("qualified trust list is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// A signing/signer/SKI value was not valid base64.
    #[error("qualified trust list certificate or SKI is not valid base64: {0}")]
    Base64(String),
    /// A `nextUpdate` or status `startingTime` was not an RFC 3339 UTC timestamp.
    #[error("qualified trust list timestamp is not a valid RFC 3339 UTC instant: {0}")]
    Time(String),
}

/// Why authenticating a national Trusted List failed (before any status is read).
///
/// Every failure is fail-closed: [`qualified_status`] maps any of these onto
/// [`QualifiedStatus::Indeterminate`] (never [`QualifiedStatus::Qualified`] — SC-007). The variants
/// keep the rejection specific so a forged / unsigned / unchained / stale list is never opaque.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum QualifiedTrustError {
    /// No scheme-operator trust anchor was configured, so the list's authenticity cannot be
    /// established (can't authenticate ⇒ can't assert qualified).
    #[error("no scheme-operator trust anchor configured to authenticate the qualified trust list")]
    NoSchemeAnchor,
    /// The list carries no embedded signer certificate (an unsigned list cannot be authenticated).
    #[error("qualified trust list is unsigned (no embedded signer certificate)")]
    Unsigned,
    /// The list's signer certificate did not chain-validate to any configured scheme-operator anchor.
    #[error("qualified trust list signer does not chain to a scheme-operator anchor: {0}")]
    SignerNotTrusted(crate::trust::chain::ChainError),
    /// The list is stale: `now` is at or after its `NextUpdate` (or it carries no `NextUpdate`).
    #[error("qualified trust list is stale (now is at/after its NextUpdate)")]
    Stale,
}

/// One status-history record of a trust service: a status URI in force from `starting_time` onward
/// (until the next, later-starting record supersedes it). Mirrors the TS 119 612
/// `ServiceHistoryInstance` / current-`ServiceStatus` model.
#[derive(Debug, Clone, PartialEq, Eq)]
struct StatusRecord {
    /// The TS 119 612 status URI (e.g. [`SERVICE_STATUS_GRANTED`]).
    status: String,
    /// The instant (Unix seconds) from which this status took effect.
    starting_time_unix: i64,
}

/// One trust-service entry on the national TL: its service type, status history, and the service
/// digital identity (Sdi) it covers (TS 119 612 §5.5.3 — an X509Certificate and/or an X509SKI).
/// Carries only issuer-public data (no secret), so deriving `Debug` is safe.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ServiceEntry {
    /// The TS 119 612 service-type URI (only [`EAA_Q_SERVICE_TYPE`] qualifies).
    service_type: String,
    /// The status history, **sorted ascending** by starting time (so the effective status at a
    /// relevant time is the last record whose starting time is at/before it).
    status_history: Vec<StatusRecord>,
    /// The Sdi's listed `X509Certificate` (DER), when present (§5.5.3 — the mandatory machine id).
    sdi_cert_der: Option<Vec<u8>>,
    /// The Sdi cert's `subject` DN (DER-encoded `Name`), derived from `sdi_cert_der` — used for the
    /// issuing-CA match (the leaf's `issuer` == this subject).
    sdi_subject_der: Option<Vec<u8>>,
    /// The Sdi's `SubjectKeyIdentifier` octets (§5.5.3 X509SKI) — from a bare `x509SkiB64` field or
    /// derived from `sdi_cert_der`.
    sdi_ski: Option<Vec<u8>>,
}

impl ServiceEntry {
    /// The effective status URI at `relevant_time_unix`: the latest record whose starting time is at
    /// or before it, or `None` if every record begins after the relevant time (the service had no
    /// status yet).
    fn effective_status_at(&self, relevant_time_unix: i64) -> Option<&str> {
        // The history is sorted ascending by starting time, so the latest applicable record is the
        // last one whose starting time is at/before the relevant time (`rfind` scans from the end).
        self.status_history
            .iter()
            .rfind(|r| r.starting_time_unix <= relevant_time_unix)
            .map(|r| r.status.as_str())
    }

    /// Whether this service's Sdi (§5.5.3) matches the credential's signing `leaf` (pre-parsed into
    /// [`LeafIdentity`], `leaf_der` its raw DER) by any of: exact X509Certificate DER, X509SKI, or the
    /// issuing-CA relationship (the leaf's `issuer` == the Sdi cert's `subject`, with AKI==SKI when
    /// both present). See the module docs for why X509SubjectName is not machine-matched (§5.5.3).
    fn matches_leaf(&self, leaf_der: &[u8], leaf: &LeafIdentity) -> bool {
        // (1) Exact X509Certificate DER equality — the mandatory, machine-processable Sdi.
        if self.sdi_cert_der.as_deref() == Some(leaf_der) {
            return true;
        }
        // (2) X509SKI: the leaf shares the Sdi's SubjectKeyIdentifier (same key).
        if let (Some(sdi_ski), Some(leaf_ski)) = (&self.sdi_ski, &leaf.ski) {
            if sdi_ski == leaf_ski {
                return true;
            }
        }
        // (3) Issuing-CA: the Sdi lists the CA that issued the leaf. Match the leaf's `issuer` DN to
        // the Sdi cert's `subject` DN; when both AKI (leaf) and SKI (Sdi) are present, also require
        // they match (so a mere DN collision is insufficient).
        if let Some(sdi_subject) = &self.sdi_subject_der {
            if &leaf.issuer_der == sdi_subject {
                let aki_ski_consistent = match (&leaf.aki, &self.sdi_ski) {
                    (Some(aki), Some(ski)) => aki == ski,
                    // One side absent → fall back to the issuer/subject DN match (the gate runs only
                    // on a VALID, chain-verified credential, so the leaf genuinely chains to a CA).
                    _ => true,
                };
                if aki_ski_consistent {
                    return true;
                }
            }
        }
        false
    }
}

/// The matching-relevant fields of a credential's signing leaf (TS 119 612 §5.5.3 Sdi matching),
/// parsed once per [`QualifiedTrustList::services_for`] call.
struct LeafIdentity {
    /// The leaf's `issuer` DN (DER-encoded `Name`) — for the issuing-CA match.
    issuer_der: Vec<u8>,
    /// The leaf's `SubjectKeyIdentifier` octets, when present — for the X509SKI match.
    ski: Option<Vec<u8>>,
    /// The leaf's `AuthorityKeyIdentifier` key id octets, when present — tightens the issuing-CA match.
    aki: Option<Vec<u8>>,
}

/// A parsed national Trusted List for the qualified-status gate: the trust-service entries, the
/// embedded signer certificate (for chain-authentication), and the `nextUpdate` instant.
///
/// Carries only issuer-public certificate data (no secret), so deriving `Debug` is safe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualifiedTrustList {
    /// Trust-service entries (a flat list — matched against a credential leaf by [`ServiceEntry::matches_leaf`]).
    services: Vec<ServiceEntry>,
    /// The list's own signing certificate (DER) from its enveloped signature, when present.
    signer_cert_der: Option<Vec<u8>>,
    /// The `nextUpdate` instant (Unix seconds); at or after it the list is stale.
    next_update_unix: i64,
}

/// The on-disk JSON shape (`cleverbase-sdk/test-qualified-trust-list/v1`) — the offline counterpart
/// of a signed TS 119 612 national TL.
#[derive(Debug, Deserialize)]
struct RawList {
    #[serde(rename = "nextUpdate")]
    next_update: String,
    #[serde(rename = "signerCertDerB64", default)]
    signer_cert_der_b64: Option<String>,
    services: Vec<RawService>,
}

/// One raw service entry in the JSON national TL. The service digital identity (§5.5.3) may be a full
/// `signingCertDerB64` (X509Certificate) and/or a bare `x509SkiB64` (X509SKI octets, base64) — at
/// least one identifies the service.
#[derive(Debug, Deserialize)]
struct RawService {
    #[serde(rename = "serviceTypeIdentifier")]
    service_type: String,
    #[serde(rename = "signingCertDerB64", default)]
    signing_cert_der_b64: Option<String>,
    #[serde(rename = "x509SkiB64", default)]
    x509_ski_b64: Option<String>,
    #[serde(rename = "statusHistory", default)]
    status_history: Vec<RawStatus>,
}

/// One raw status-history record in the JSON national TL.
#[derive(Debug, Deserialize)]
struct RawStatus {
    status: String,
    #[serde(rename = "startingTime")]
    starting_time: String,
}

/// Decode a base64 DER certificate body (tolerating PEM-style whitespace) to DER bytes, via the
/// crate's single whitespace-tolerant cert-body decode (DRY — Principle III).
fn decode_b64_cert(body: &str) -> Result<Vec<u8>, QualifiedTrustListError> {
    crate::crypto::decode_base64_cert_lenient(body)
        .map_err(|e| QualifiedTrustListError::Base64(e.to_string()))
}

/// Decode a base64 X509SKI (SubjectKeyIdentifier octets) body to bytes.
fn decode_b64_ski(body: &str) -> Result<Vec<u8>, QualifiedTrustListError> {
    Base64::decode_vec(body.trim()).map_err(|e| QualifiedTrustListError::Base64(e.to_string()))
}

/// Extract the `subject` DN (DER) + `SubjectKeyIdentifier` octets from a DER certificate, or
/// `(None, None)` if the bytes are not a parseable certificate (a non-cert Sdi placeholder still
/// supports exact-DER matching via the raw bytes; the derived fields are simply absent).
fn cert_subject_and_ski(der: &[u8]) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
    let Ok(cert) = Certificate::from_der(der) else {
        return (None, None);
    };
    let subject = cert.tbs_certificate.subject.to_der().ok();
    let ski = subject_key_identifier(&cert);
    (subject, ski)
}

/// The certificate's `SubjectKeyIdentifier` extension octets, when present/parsable.
fn subject_key_identifier(cert: &Certificate) -> Option<Vec<u8>> {
    cert.tbs_certificate
        .get::<SubjectKeyIdentifier>()
        .ok()
        .flatten()
        .map(|(_critical, skid)| skid.0.as_bytes().to_vec())
}

/// The matching-relevant fields of a credential leaf (its `issuer` DN, `SubjectKeyIdentifier`, and
/// `AuthorityKeyIdentifier` key id), or `None` if the bytes are not a parseable certificate.
fn leaf_identity(leaf_der: &[u8]) -> Option<LeafIdentity> {
    let cert = Certificate::from_der(leaf_der).ok()?;
    let issuer_der = cert.tbs_certificate.issuer.to_der().ok()?;
    let ski = subject_key_identifier(&cert);
    let aki = cert
        .tbs_certificate
        .get::<AuthorityKeyIdentifier>()
        .ok()
        .flatten()
        .and_then(|(_critical, akid)| akid.key_identifier.map(|k| k.as_bytes().to_vec()));
    Some(LeafIdentity {
        issuer_der,
        ski,
        aki,
    })
}

impl QualifiedTrustList {
    /// An empty national TL (no services, no signer) — the offline "no qualified data" case that
    /// yields [`QualifiedStatus::Indeterminate`] for every issuer.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            services: Vec::new(),
            signer_cert_der: None,
            next_update_unix: 0,
        }
    }

    /// Parse a qualified-status national Trusted List from its raw JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns [`QualifiedTrustListError`] when the JSON is malformed, a certificate/SKI body is not
    /// valid base64, or a `nextUpdate` / status `startingTime` is not an RFC 3339 UTC timestamp.
    pub fn parse(bytes: &[u8]) -> Result<Self, QualifiedTrustListError> {
        let raw: RawList = serde_json::from_slice(bytes)?;
        let next_update_unix = parse_rfc3339_utc_pub(raw.next_update.trim())
            .ok_or_else(|| QualifiedTrustListError::Time(raw.next_update.clone()))?;
        let signer_cert_der = match raw.signer_cert_der_b64 {
            Some(b64) => Some(decode_b64_cert(&b64)?),
            None => None,
        };

        let mut services = Vec::with_capacity(raw.services.len());
        for svc in raw.services {
            // Service digital identity (§5.5.3): an X509Certificate and/or a bare X509SKI.
            let sdi_cert_der = match svc.signing_cert_der_b64 {
                Some(b64) => Some(decode_b64_cert(&b64)?),
                None => None,
            };
            let bare_ski = match svc.x509_ski_b64 {
                Some(b64) => Some(decode_b64_ski(&b64)?),
                None => None,
            };
            let (sdi_subject_der, cert_ski) = sdi_cert_der
                .as_deref()
                .map_or((None, None), cert_subject_and_ski);
            // The effective Sdi SKI: a bare X509SKI takes precedence, else the cert-derived SKI.
            let sdi_ski = bare_ski.or(cert_ski);

            let mut status_history = Vec::with_capacity(svc.status_history.len());
            for st in svc.status_history {
                let starting_time_unix = parse_rfc3339_utc_pub(st.starting_time.trim())
                    .ok_or_else(|| QualifiedTrustListError::Time(st.starting_time.clone()))?;
                status_history.push(StatusRecord {
                    status: st.status,
                    starting_time_unix,
                });
            }
            // Sort ascending by starting time so `effective_status_at` reads the latest applicable
            // record deterministically (regardless of the source ordering).
            status_history.sort_by_key(|r| r.starting_time_unix);

            services.push(ServiceEntry {
                service_type: svc.service_type,
                status_history,
                sdi_cert_der,
                sdi_subject_der,
                sdi_ski,
            });
        }

        Ok(Self {
            services,
            signer_cert_der,
            next_update_unix,
        })
    }

    /// The list's own signing certificate (DER) from its enveloped signature, if present.
    #[must_use]
    pub fn signer_cert_der(&self) -> Option<&[u8]> {
        self.signer_cert_der.as_deref()
    }

    /// The list's `nextUpdate` instant (Unix seconds); at or after it the list is stale.
    #[must_use]
    pub const fn next_update_unix(&self) -> i64 {
        self.next_update_unix
    }

    /// Authenticate the national Trusted List **before** any status is read (the fail-closed gate —
    /// SC-007).
    ///
    /// Authentication has two parts, both mandatory:
    ///
    /// 1. **Signer chain** — the list's embedded signer certificate
    ///    ([`Self::signer_cert_der`]) must chain-validate to one of the host-configured
    ///    `scheme_anchors` (the scheme-operator / national-TL-operator trust anchors), at `now_unix`,
    ///    via [`crate::trust::chain::verify_chain`] (DRY — the same X.509 primitive the always-on bar
    ///    uses; no re-implemented crypto). An **unsigned** list (no signer) or a signer that does not
    ///    chain fails. When `scheme_anchors` is empty the list cannot be authenticated at all
    ///    ([`QualifiedTrustError::NoSchemeAnchor`]).
    /// 2. **Freshness** — the list must not be **stale**: `now_unix` must be strictly before its
    ///    `NextUpdate` (a list with an absent/zero `NextUpdate` is treated as stale). For this cl. 4.12
    ///    determination staleness is **fail-closed** (stricter than the general national-TL warning of
    ///    PRO-4.2.4-10 — see the module docs): a stale snapshot must never assert `Qualified`.
    ///
    /// # Errors
    ///
    /// Returns [`QualifiedTrustError`] when no scheme anchor is configured, the list is unsigned, the
    /// signer does not chain to a scheme anchor, or the list is stale. Every variant is mapped to
    /// [`QualifiedStatus::Indeterminate`] by [`qualified_status`] (never `Qualified`).
    pub fn authenticate(
        &self,
        scheme_anchors: &[Vec<u8>],
        now_unix: i64,
    ) -> Result<(), QualifiedTrustError> {
        // Can't authenticate ⇒ can't assert qualified: an empty scheme-anchor set fails closed.
        if scheme_anchors.is_empty() {
            return Err(QualifiedTrustError::NoSchemeAnchor);
        }
        // An unsigned list (no embedded signer) cannot be authenticated.
        let signer = self
            .signer_cert_der
            .as_deref()
            .ok_or(QualifiedTrustError::Unsigned)?;
        // Chain-validate the signer against the scheme-operator anchor(s) — reuse the always-on X.509
        // primitive (DRY); a forged/attacker-supplied signer that does not chain is rejected. The list
        // carries a single signer certificate, so the supplied path is the one-element `[signer]`. A
        // trust-list signer is not a credential leaf (separate ETSI profile), so it carries no
        // credential-leaf key-purpose constraint.
        crate::trust::chain::verify_chain(
            &[signer],
            scheme_anchors,
            now_unix,
            // A trust-list signer has no distinct signing instant — its window is checked at `now_unix`.
            None,
            crate::trust::chain::LeafPurpose::TrustListSigner,
        )
        .map_err(QualifiedTrustError::SignerNotTrusted)?;
        // Freshness: a list at/after its NextUpdate (or with none) is stale — never authoritative.
        if self.next_update_unix <= 0 || now_unix >= self.next_update_unix {
            return Err(QualifiedTrustError::Stale);
        }
        Ok(())
    }

    /// The trust-service entries whose digital identity (§5.5.3) matches an issuer signing certificate
    /// — by exact X509Certificate DER, X509SKI, or the issuing-CA relationship
    /// ([`ServiceEntry::matches_leaf`]) — or an empty vector if none match (or the leaf is unparsable).
    fn services_for(&self, issuer_cert_der: &[u8]) -> Vec<&ServiceEntry> {
        let Some(leaf) = leaf_identity(issuer_cert_der) else {
            // An unparsable leaf can still exact-match a listed cert by raw bytes (no derived fields).
            return self
                .services
                .iter()
                .filter(|s| s.sdi_cert_der.as_deref() == Some(issuer_cert_der))
                .collect();
        };
        self.services
            .iter()
            .filter(|s| s.matches_leaf(issuer_cert_der, &leaf))
            .collect()
    }
}

/// Determine the eIDAS qualified status of an attestation issuer at a relevant time (TS 119 615
/// v1.4.1 cl. 4.12 — the opt-in gate, research D6).
///
/// ## Two distinct times — authenticate at `now`, read status at the relevant time
///
/// Trust-list **authentication** and the issuer **status read** are evaluated at *different* instants
/// (the load-bearing split — RCA below):
///
/// - **`now_unix`** — the verification instant ("real now"). Used to **authenticate the TL**
///   ([`QualifiedTrustList::authenticate`]): the freshness check (`now >= NextUpdate ⇒ stale`) AND the
///   TL-signer certificate's chain validity ([`crate::trust::chain::verify_chain`] `notBefore`/
///   `notAfter`). Whether the LOTL/national-TL snapshot in hand is itself **currently** fresh and
///   signed by a **currently** valid scheme operator is a *now* property — a stale or expired-signer TL
///   must never be trusted just because the credential being checked is old.
/// - **`relevant_time_unix`** — the credential's issuance/relevant time. Used only to **read the
///   issuer's granted/withdrawn `EAA/Q` status** (the effective status at that instant); per eIDAS the
///   status read is "status at the relevant time" (an issuer not yet granted when it signed a
///   credential, but granted later, is NOT `Qualified` for that earlier credential).
///
/// **RCA — why the split matters (the false-`Qualified` bug this fixes):** a prior fix correctly
/// derived the relevant time for the *status read* from the credential's issuance time, but then passed
/// that SAME old time into `authenticate`, so the TL freshness/signer-validity checks were evaluated at
/// the credential's issuance time instead of `now`. A TL whose `NextUpdate` is in the past relative to
/// real `now` (stale) but in the future relative to an old credential's issuance time was treated as
/// fresh, yielding a false `Qualified` from a stale/withdrawn-since trust snapshot. Authentication MUST
/// use `now_unix`; only the status read uses `relevant_time_unix`.
///
/// ## QEAA type-indication precondition (PRO-4.12.4-03)
///
/// `type_indication` is the credential's self-declared type (SD-JWT VC `vct`; `None` for ISO mdoc —
/// see the module docs). Per PRO-4.12.4-03 the EAA must self-declare the qualified-EAA type
/// ([`EAA_EU_QUALIFIED_TYPE`]) before a `Qualified` verdict: a `Some` indication that is **not** that
/// URN yields [`QualifiedStatus::Indeterminate`] (`ERROR_NO_ETSI_QEAA_TYPE_INDICATION_FOUND`),
/// **before** any service status is read; `None` (a format with no cl. 4.12 URN construct, i.e. mdoc)
/// does not enforce it.
///
/// ## Flow
///
/// **Authenticates the national TL first** (against `scheme_anchors` at `now_unix`): an unsigned /
/// forged / unchained / stale list yields [`QualifiedStatus::Indeterminate`] (fail-closed). Then it
/// enforces the type-indication precondition. Only then does it match `issuer_cert_der` against the
/// trust-service entries (§5.5.3 Sdi matching) and read the effective service status **at
/// `relevant_time_unix`**:
///
/// - [`QualifiedStatus::Qualified`] — some matched [`EAA_Q_SERVICE_TYPE`] service is
///   [`SERVICE_STATUS_GRANTED`] at the relevant time.
/// - [`QualifiedStatus::NotQualified`] — the issuer is **found** on the TL, but no `EAA/Q` service is
///   granted at the relevant time.
/// - [`QualifiedStatus::Indeterminate`] — the TL did not authenticate, the type indication is absent
///   (PRO-4.12.4-03), **or** the issuer is on **no** matching service entry. Never assumes qualified
///   (no false "qualified" — SC-007).
#[must_use]
pub fn qualified_status(
    issuer_cert_der: &[u8],
    now_unix: i64,
    relevant_time_unix: i64,
    trust_list: &QualifiedTrustList,
    scheme_anchors: &[Vec<u8>],
    type_indication: Option<&str>,
) -> QualifiedStatus {
    // Authenticate the list against the scheme-operator anchor BEFORE reading any status, at `now_unix`
    // (the verification instant) — NOT the credential's relevant time. A forged / unsigned / unchained /
    // stale-at-now list cannot be authoritative → Indeterminate, never Qualified.
    if trust_list.authenticate(scheme_anchors, now_unix).is_err() {
        return QualifiedStatus::Indeterminate;
    }

    // PRO-4.12.4-03: the EAA must self-declare the qualified-EAA type via the URN. A present type
    // indication that is not EAA_EU_QUALIFIED_TYPE stops the process → Indeterminate (never Qualified).
    // `None` (ISO mdoc — no cl. 4.12 URN construct) does not enforce the precondition (see module docs).
    if let Some(declared) = type_indication {
        if declared != EAA_EU_QUALIFIED_TYPE {
            return QualifiedStatus::Indeterminate;
        }
    }

    let services = trust_list.services_for(issuer_cert_der);
    if services.is_empty() {
        // The issuer matches no service entry — the trust-list data needed to decide is absent.
        return QualifiedStatus::Indeterminate;
    }

    // Found on the TL: qualified iff some EAA/Q service is `granted` at the relevant time.
    let granted_qualified = services.iter().any(|svc| {
        svc.service_type == EAA_Q_SERVICE_TYPE
            && svc.effective_status_at(relevant_time_unix) == Some(SERVICE_STATUS_GRANTED)
    });

    if granted_qualified {
        QualifiedStatus::Qualified
    } else {
        // Found but not granted-EAA/Q at the relevant time (withdrawn/suspended, pre-grant, or only
        // a non-qualified service) — VALID-but-not-QUALIFIED, never a false "qualified".
        QualifiedStatus::NotQualified
    }
}
