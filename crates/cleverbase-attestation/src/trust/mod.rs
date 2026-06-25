//! Pluggable trust-anchor source for issuer trust (contracts/trust-anchor-source.md).
//!
//! Verification anchors issuer trust **per role/format**: a QEAA issuer is found on the EU LOTL +
//! national Trusted Lists, a PID provider on the eIDAS Art. 5a(18) Commission list, a PuB-EAA
//! provider on the Art. 45f(3) list, and an mdoc issuer on an IACA root. This module defines the
//! pluggable seam — the [`TrustAnchorSource`] trait — plus the [`TrustDecision`] / [`TrustListEntry`]
//! types, the fail-closed [`Reachability`] policy, and a configured offline [`StaticTestAnchors`]
//! implementation for the offline test suite.
//!
//! The **native EU trust-list engine** (fetch + authenticate the LOTL and national Trusted Lists via
//! `quick-xml` + the SDK's X.509 stack) is the largest single build and lands in task **T013**; this
//! module provides only the trait + the test anchor (task **T005**, preceded by **T009**).
//!
//! ## Sans-IO contract
//!
//! [`TrustAnchorSource::resolve`] is **pure**: it works only against the already-fetched, cached,
//! in-memory anchors and performs no I/O. [`TrustAnchorSource::refresh`] is where the production
//! engine fetches/caches the signed trust-list XML/JSON; it is **host-driven** (not per-verification)
//! and is the point at which the [`Reachability`] policy applies.

use std::collections::BTreeSet;

use crate::types::{Format, IssuerRole};

/// The reachability policy for fetching/refreshing a trust list (contracts/trust-anchor-source.md).
///
/// The default is **fail-closed**: an unreachable or stale (past its `NextUpdate`) LOTL / national
/// Trusted List makes [`TrustAnchorSource::refresh`] fail rather than silently serve stale or empty
/// anchors that could let an untrusted issuer through. This is distinct from the per-credential
/// revocation/status reachability ([`crate::types::StatusReachability`]) and from an
/// expired/withdrawn issuer *entry* (which surfaces as [`TrustStatus::Untrusted`] at `resolve` time).
///
/// [`TrustStatus::Untrusted`]: crate::types::TrustStatus::Untrusted
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Reachability {
    /// An unreachable or stale trust list fails the refresh (the secure default).
    #[default]
    FailClosed,
    /// An unreachable or stale trust list serves the last-known-good cached anchors (opt-in; for
    /// environments that accept the weaker guarantee).
    BestEffort,
}

/// A matched entry on a trust list — the in-force record under which an issuer is trusted
/// (contracts/trust-anchor-source.md).
///
/// Carries only issuer-public trust-list data (no secret), so deriving `Debug` is safe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustListEntry {
    /// The issuer role under which this entry was matched.
    pub role: IssuerRole,
    /// The credential format this anchor covers.
    pub format: Format,
    /// The DER-encoded issuer/anchor certificate that the credential's signer chained to.
    pub anchor_cert_der: Vec<u8>,
    /// A human-readable label for the trust-list service (e.g. a national TL service name), if
    /// known. The test anchor leaves this empty.
    pub service_name: Option<String>,
}

/// The outcome of resolving an issuer against the configured anchors
/// (contracts/trust-anchor-source.md).
///
/// `trusted` is the always-on-bar trust decision; `entry` carries the matched [`TrustListEntry`] when
/// `trusted` is `true` (it is `None` for an untrusted issuer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustDecision {
    /// Whether the issuer is on the configured trust anchor for its role/format.
    pub trusted: bool,
    /// The matched trust-list entry, present iff `trusted`.
    pub entry: Option<TrustListEntry>,
}

impl TrustDecision {
    /// A trusted decision carrying its matched entry.
    #[must_use]
    pub const fn trusted(entry: TrustListEntry) -> Self {
        Self {
            trusted: true,
            entry: Some(entry),
        }
    }

    /// An untrusted decision (no matched entry).
    #[must_use]
    pub const fn untrusted() -> Self {
        Self {
            trusted: false,
            entry: None,
        }
    }
}

/// An error from refreshing the trust anchors.
///
/// The production engine fetches and authenticates signed trust-list XML/JSON in `refresh`; this
/// surfaces the fail-closed outcomes. The offline [`StaticTestAnchors`] never fails to refresh.
#[derive(Debug, thiserror::Error)]
pub enum TrustError {
    /// A trust list could not be fetched (the fail-closed reachability outcome).
    #[error("trust list unreachable: {0}")]
    Unreachable(String),
    /// A fetched trust list is stale (past its `NextUpdate`) and the policy is fail-closed.
    #[error("trust list stale (past NextUpdate): {0}")]
    Stale(String),
    /// A fetched trust list failed signature authentication.
    #[error("trust list signature authentication failed: {0}")]
    Authentication(String),
}

/// The pluggable trust-anchor source (contracts/trust-anchor-source.md).
///
/// Implementations range from the offline [`StaticTestAnchors`] to the native EU trust-list engine
/// (task T013). `resolve` MUST be pure (sans-IO) — it works on cached, in-memory anchors only.
pub trait TrustAnchorSource {
    /// Resolve whether an issuer is trusted for a given role/format, matching its DER-encoded signing
    /// certificate against the configured anchors. **Pure / sans-IO** — never performs I/O.
    ///
    /// `issuer_cert_der` is the credential's signing certificate (the mdoc `IssuerAuth` x5chain leaf,
    /// or the SD-JWT VC JWS `x5c` leaf).
    fn resolve(&self, role: IssuerRole, format: Format, issuer_cert_der: &[u8]) -> TrustDecision;

    /// Fetch and cache the signed trust lists (host-driven, **not** per-verification). The native
    /// engine applies the [`Reachability`] policy here; the offline anchors are infallible.
    ///
    /// # Errors
    ///
    /// Returns [`TrustError`] when a trust list is unreachable/stale (under [`Reachability::FailClosed`])
    /// or fails signature authentication.
    fn refresh(&mut self) -> Result<(), TrustError>;
}

/// A configured, offline trust anchor for the test suite (task T005).
///
/// Trusts exactly the set of issuer certificates it was configured with, keyed by `(role, format)` so
/// that per-role/format anchoring is exercised (an issuer trusted as a PID provider is not thereby
/// trusted as a QEAA). It performs no I/O — [`StaticTestAnchors::refresh`] is a no-op — so the
/// offline suite needs no network and no EU lists. It is **not** a production trust source.
///
/// Carries only issuer-public certificates (no secret), so deriving `Debug` is safe.
#[derive(Debug, Clone, Default)]
pub struct StaticTestAnchors {
    /// The trusted issuer certificates, keyed by `(role, format)` → set of DER-encoded certs.
    anchors: std::collections::BTreeMap<(IssuerRole, Format), BTreeSet<Vec<u8>>>,
}

impl StaticTestAnchors {
    /// Construct an empty test anchor set (trusts nothing until certificates are added).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Trust the given DER-encoded issuer certificate for a specific role/format.
    ///
    /// Returns `self` for builder-style configuration.
    #[must_use]
    pub fn trust(mut self, role: IssuerRole, format: Format, issuer_cert_der: &[u8]) -> Self {
        self.anchors
            .entry((role, format))
            .or_default()
            .insert(issuer_cert_der.to_vec());
        self
    }

    /// Whether a given certificate is configured as trusted for the role/format (the matching rule:
    /// exact DER equality against the configured set).
    #[must_use]
    pub fn is_trusted(&self, role: IssuerRole, format: Format, issuer_cert_der: &[u8]) -> bool {
        self.anchors
            .get(&(role, format))
            .is_some_and(|set| set.contains(issuer_cert_der))
    }
}

impl TrustAnchorSource for StaticTestAnchors {
    fn resolve(&self, role: IssuerRole, format: Format, issuer_cert_der: &[u8]) -> TrustDecision {
        if self.is_trusted(role, format, issuer_cert_der) {
            TrustDecision::trusted(TrustListEntry {
                role,
                format,
                anchor_cert_der: issuer_cert_der.to_vec(),
                service_name: None,
            })
        } else {
            TrustDecision::untrusted()
        }
    }

    /// A no-op: the offline anchors are configured in-memory and need no fetch.
    fn refresh(&mut self) -> Result<(), TrustError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{Reachability, StaticTestAnchors, TrustAnchorSource};
    use crate::types::{Format, IssuerRole};

    const ISSUER_A: &[u8] = b"-----DER-issuer-A-----";
    const ISSUER_B: &[u8] = b"-----DER-issuer-B-----";

    #[test]
    fn reachability_defaults_to_fail_closed() {
        assert_eq!(Reachability::default(), Reachability::FailClosed);
    }

    #[test]
    fn configured_issuer_is_trusted_for_its_role_and_format() {
        let anchors = StaticTestAnchors::new().trust(IssuerRole::Qeaa, Format::SdJwtVc, ISSUER_A);
        let decision = anchors.resolve(IssuerRole::Qeaa, Format::SdJwtVc, ISSUER_A);
        assert!(decision.trusted);
        let entry = decision.entry.expect("trusted decision carries an entry");
        assert_eq!(entry.role, IssuerRole::Qeaa);
        assert_eq!(entry.format, Format::SdJwtVc);
        assert_eq!(entry.anchor_cert_der, ISSUER_A);
    }

    #[test]
    fn unconfigured_issuer_is_untrusted() {
        let anchors = StaticTestAnchors::new().trust(IssuerRole::Qeaa, Format::SdJwtVc, ISSUER_A);
        let decision = anchors.resolve(IssuerRole::Qeaa, Format::SdJwtVc, ISSUER_B);
        assert!(!decision.trusted);
        assert!(decision.entry.is_none());
    }

    #[test]
    fn trust_is_anchored_per_role_and_format() {
        // Trusted as a PID provider for SD-JWT VC only.
        let anchors = StaticTestAnchors::new().trust(IssuerRole::Pid, Format::SdJwtVc, ISSUER_A);
        // Same cert, different role → untrusted (per-role anchoring).
        assert!(
            !anchors
                .resolve(IssuerRole::Qeaa, Format::SdJwtVc, ISSUER_A)
                .trusted
        );
        // Same cert + role, different format → untrusted (per-format anchoring).
        assert!(
            !anchors
                .resolve(IssuerRole::Pid, Format::Mdoc, ISSUER_A)
                .trusted
        );
        // Exact role+format → trusted.
        assert!(
            anchors
                .resolve(IssuerRole::Pid, Format::SdJwtVc, ISSUER_A)
                .trusted
        );
    }

    #[test]
    fn refresh_is_infallible_for_the_offline_anchor() {
        let mut anchors = StaticTestAnchors::new();
        assert!(anchors.refresh().is_ok());
    }
}
