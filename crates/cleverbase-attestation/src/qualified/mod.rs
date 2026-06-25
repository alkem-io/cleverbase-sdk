//! Opt-in eIDAS qualified-status determination (ETSI TS 119 615 v1.4.1 cl. 4.12) — T019.
//!
//! Over the always-on bar (which is never replaced by this), an **opt-in**, version-pinned
//! determination of whether an attestation issuer is a **qualified** EAA provider: authenticate the
//! LOTL → select the national Trusted List → match the issuer's signing certificate against a
//! trust-service entry of type [`EAA_Q_SERVICE_TYPE`] (`…/Svctype/EAA/Q`) → read the
//! `granted`/`withdrawn` service status **at the relevant time** (the credential's issuance/relevant
//! time, NOT "now"). The reusable trust-list primitives ([`crate::trust`]) anchor the same PKI (DRY).
//!
//! ## Outcome conditions (pinned — tasks T018/T019, analyze A1)
//!
//! - [`QualifiedStatus::Qualified`] — the issuer's `EAA/Q` service entry is **`granted`** at the
//!   relevant time.
//! - [`QualifiedStatus::NotQualified`] — the entry is **found but not granted** (its status at the
//!   relevant time is withdrawn/suspended, the grant had not yet begun, or the issuer is on the TL
//!   only under a non-`EAA/Q` service type).
//! - [`QualifiedStatus::Indeterminate`] — the trust-list data needed to decide is **absent,
//!   ambiguous, or unreachable** (the issuer is on no service entry, or there is no TL at all). The
//!   gate **never assumes qualified** (no false "qualified" — SC-007).
//!
//! ## Experimental + version-pinned
//!
//! cl. 4.12 (QEAA qualified-status determination) was newly standardized (TS 119 615 v1.3.1, Jan
//! 2026) and is **pre-operational**: national Trusted Lists are only beginning to carry `EAA/Q`
//! entries (post CIR (EU) 2025/1569). This implementation is pinned to [`TS_119_615_VERSION`]
//! (`1.4.1`) and is **off by default** ([`crate::verify::VerifyContext::qualified_gate`]) — enabling
//! it is opt-in, and absent fixtures honestly yield `Indeterminate`.
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
//! The full enveloped XML-DSig `SignatureValue`/C14N check is the always-on engine's remaining
//! production hardening ([`crate::trust::xml`]); the offline JSON form here carries the signer cert
//! so the gate exercises the same chain-authentication seam against the same X.509 stack.

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;

use base64ct::{Base64, Encoding as _};
use serde::Deserialize;

use crate::trust::manifest::parse_rfc3339_utc_pub;
use crate::types::QualifiedStatus;

/// The pinned TS 119 615 version this determination implements (research D6 — experimental,
/// pre-operational). Surfaced so a consumer can record exactly which clause-4.12 revision produced a
/// verdict.
pub const TS_119_615_VERSION: &str = "1.4.1";

/// The TS 119 612 trust-service **type** URI for a *qualified* electronic attestation of attributes
/// (QEAA) issuing service. Only a service of this exact type can make an issuer
/// [`QualifiedStatus::Qualified`] (a plain `…/Svctype/EAA` — non-qualified EAA — never does).
pub const EAA_Q_SERVICE_TYPE: &str = "http://uri.etsi.org/TrstSvc/Svctype/EAA/Q";

/// The TS 119 612 trust-service **status** URI for a `granted` service (in force). An `EAA/Q` service
/// whose effective status at the relevant time is `granted` makes its issuer
/// [`QualifiedStatus::Qualified`].
pub const SERVICE_STATUS_GRANTED: &str =
    "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted";

/// An error parsing the qualified-status national Trusted List.
#[derive(Debug, thiserror::Error)]
pub enum QualifiedTrustListError {
    /// The bytes were not valid JSON of the expected national-TL shape.
    #[error("qualified trust list is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// A signing/signer certificate body was not valid base64 DER.
    #[error("qualified trust list certificate is not valid base64: {0}")]
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

/// One trust-service entry on the national TL: its service type and the chronological status
/// history. (The issuer signing certificate it covers is the [`QualifiedTrustList::services_by_cert`]
/// map key, so it is not duplicated here.) Carries only issuer-public data (no secret), so deriving
/// `Debug` is safe.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ServiceEntry {
    /// The TS 119 612 service-type URI (only [`EAA_Q_SERVICE_TYPE`] qualifies).
    service_type: String,
    /// The status history, **sorted ascending** by starting time (so the effective status at a
    /// relevant time is the last record whose starting time is at/before it).
    status_history: Vec<StatusRecord>,
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
}

/// A parsed national Trusted List for the qualified-status gate: the per-issuer-cert trust-service
/// entries (keyed by signing-cert DER, since a cert may appear under several services), the embedded
/// signer certificate (for chain-authentication), and the `nextUpdate` instant.
///
/// Carries only issuer-public certificate data (no secret), so deriving `Debug` is safe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualifiedTrustList {
    /// Trust-service entries keyed by the DER signing certificate they cover (one cert → many
    /// services, e.g. an `EAA/Q` plus a plain `EAA`).
    services_by_cert: BTreeMap<Vec<u8>, Vec<ServiceEntry>>,
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

/// One raw service entry in the JSON national TL.
#[derive(Debug, Deserialize)]
struct RawService {
    #[serde(rename = "serviceTypeIdentifier")]
    service_type: String,
    #[serde(rename = "signingCertDerB64")]
    signing_cert_der_b64: String,
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

/// Decode a base64 DER certificate body (tolerating PEM-style whitespace) to DER bytes.
fn decode_b64_cert(body: &str) -> Result<Vec<u8>, QualifiedTrustListError> {
    let compact: String = body.split_whitespace().collect();
    Base64::decode_vec(&compact).map_err(|e| QualifiedTrustListError::Base64(e.to_string()))
}

impl QualifiedTrustList {
    /// An empty national TL (no services, no signer) — the offline "no qualified data" case that
    /// yields [`QualifiedStatus::Indeterminate`] for every issuer.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            services_by_cert: BTreeMap::new(),
            signer_cert_der: None,
            next_update_unix: 0,
        }
    }

    /// Parse a qualified-status national Trusted List from its raw JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns [`QualifiedTrustListError`] when the JSON is malformed, a certificate body is not
    /// valid base64 DER, or a `nextUpdate` / status `startingTime` is not an RFC 3339 UTC timestamp.
    pub fn parse(bytes: &[u8]) -> Result<Self, QualifiedTrustListError> {
        let raw: RawList = serde_json::from_slice(bytes)?;
        let next_update_unix = parse_rfc3339_utc_pub(raw.next_update.trim())
            .ok_or_else(|| QualifiedTrustListError::Time(raw.next_update.clone()))?;
        let signer_cert_der = match raw.signer_cert_der_b64 {
            Some(b64) => Some(decode_b64_cert(&b64)?),
            None => None,
        };

        let mut services_by_cert: BTreeMap<Vec<u8>, Vec<ServiceEntry>> = BTreeMap::new();
        for svc in raw.services {
            let signing_cert_der = decode_b64_cert(&svc.signing_cert_der_b64)?;
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
            services_by_cert
                .entry(signing_cert_der)
                .or_default()
                .push(ServiceEntry {
                    service_type: svc.service_type,
                    status_history,
                });
        }

        Ok(Self {
            services_by_cert,
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
    ///    `NextUpdate` (a list with an absent/zero `NextUpdate` is treated as stale). This mirrors the
    ///    always-on engine's `now >= NextUpdate ⇒ stale` policy ([`crate::trust::engine`]).
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
        // primitive (DRY); a forged/attacker-supplied signer that does not chain is rejected.
        crate::trust::chain::verify_chain(signer, scheme_anchors, now_unix)
            .map_err(QualifiedTrustError::SignerNotTrusted)?;
        // Freshness: a list at/after its NextUpdate (or with none) is stale — never authoritative.
        if self.next_update_unix <= 0 || now_unix >= self.next_update_unix {
            return Err(QualifiedTrustError::Stale);
        }
        Ok(())
    }

    /// The trust-service entries covering an issuer signing certificate (matched by exact DER
    /// equality — the trust-list entry pins the signing cert), or an empty slice if absent.
    fn services_for(&self, issuer_cert_der: &[u8]) -> &[ServiceEntry] {
        self.services_by_cert
            .get(issuer_cert_der)
            .map_or(&[], Vec::as_slice)
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
/// **Authenticates the national TL first** ([`QualifiedTrustList::authenticate`] against the
/// host-configured scheme-operator `scheme_anchors`, at `now_unix`): an unsigned / forged / unchained /
/// stale list yields [`QualifiedStatus::Indeterminate`] before any status is read (fail-closed — a
/// forged TL can never make an unchained issuer report `Qualified`, SC-007). Only an authenticated list
/// is consulted.
///
/// On an authenticated list it then matches `issuer_cert_der` (the credential's signing certificate)
/// against the trust-service entries and reads the effective service status **at
/// `relevant_time_unix`** (the credential's issuance/relevant time, NOT "now"):
///
/// - [`QualifiedStatus::Qualified`] — some matched [`EAA_Q_SERVICE_TYPE`] service is
///   [`SERVICE_STATUS_GRANTED`] at the relevant time.
/// - [`QualifiedStatus::NotQualified`] — the issuer is **found** on the TL, but no `EAA/Q` service is
///   granted at the relevant time (it is withdrawn/suspended, the grant had not begun, or the only
///   matched service is non-`EAA/Q`).
/// - [`QualifiedStatus::Indeterminate`] — the TL did not authenticate, **or** the issuer is on **no**
///   service entry (the data needed to decide is absent/unreachable). Never assumes qualified (no
///   false "qualified" — SC-007).
#[must_use]
pub fn qualified_status(
    issuer_cert_der: &[u8],
    now_unix: i64,
    relevant_time_unix: i64,
    trust_list: &QualifiedTrustList,
    scheme_anchors: &[Vec<u8>],
) -> QualifiedStatus {
    // Authenticate the list against the scheme-operator anchor BEFORE reading any status, at `now_unix`
    // (the verification instant) — NOT the credential's relevant time: TL freshness (`now >=
    // NextUpdate`) and the TL-signer's chain validity are "now" properties. A forged / unsigned /
    // unchained / stale-at-now list cannot be authoritative → Indeterminate, never Qualified.
    if trust_list.authenticate(scheme_anchors, now_unix).is_err() {
        return QualifiedStatus::Indeterminate;
    }

    let services = trust_list.services_for(issuer_cert_der);
    if services.is_empty() {
        // The issuer is on no service entry — the trust-list data needed to decide is absent.
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
