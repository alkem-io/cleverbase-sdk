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

use std::collections::{BTreeMap, BTreeSet};

use crate::trust::chain::verify_chain;
use crate::types::{Format, IssuerRole};

// The native trust-list engine, split into focused modules (the X.509 [`chain`] primitive, the
// offline JSON [`manifest`] path, the TS 119 612 [`xml`] path, and the [`engine`] that composes
// them). They are public modules (matching the core crate's convention — a `pub fn` in a `pub mod`
// is genuinely reachable, satisfying both `unreachable_pub` and clippy's `redundant_pub_crate`);
// the curated names below are re-exported at `crate::trust` for ergonomics.
pub mod chain;
pub mod engine;
pub mod manifest;
pub mod xml;

pub use engine::{NativeTrustEngine, TrustListFetcher};
pub use manifest::{ManifestError, TrustListManifest};
pub use xml::{XmlTrustList, XmlTrustListError};

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

/// Resolve an issuer leaf against a set of trusted anchors for one `(role, format)` by
/// **chain-validation** — the single authoritative `resolve` body shared by every chain-validating
/// [`TrustAnchorSource`] (the [`NativeTrustEngine`] and the C-ABI [`ChainValidatingAnchors`]), so the
/// trust rule is defined once (DRY — Principle III).
///
/// The leaf is trusted iff it chains to one of `anchors_for_key` at `now_unix` via
/// [`crate::trust::chain::verify_chain`] (issued-by-anchor name + signature, or a direct DER-equal
/// pin — and in **both** cases the leaf must be within its own validity window at `now_unix`, so an
/// expired pinned leaf is rejected). An empty/absent anchor set is untrusted (fail-closed). On
/// success the matched [`TrustListEntry`] carries the leaf as its `anchor_cert_der` (matching the
/// other sources; the entry is informational — the bar reads only `trusted`).
fn resolve_chain(
    anchors_for_key: Option<&Vec<Vec<u8>>>,
    role: IssuerRole,
    format: Format,
    issuer_cert_der: &[u8],
    now_unix: i64,
) -> TrustDecision {
    let Some(anchors) = anchors_for_key else {
        return TrustDecision::untrusted();
    };
    if verify_chain(issuer_cert_der, anchors, now_unix).is_ok() {
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

/// The chain-validating trust source for the **C-ABI / binding** verify path (contracts/verifier.md
/// step 3; data-model.md `TrustAnchorSource`).
///
/// The host's trust-refresh step resolves the in-force anchors (EU LOTL / national Trusted Lists /
/// IACA roots) out-of-process and passes them in as `(role, format, cert)` wire entries; this source
/// treats each as a **trusted anchor/root** and, at `resolve` time, **chain-validates** the
/// credential's signing leaf against the anchors configured for its role/format via
/// [`crate::trust::chain::verify_chain`] (DRY — the same X.509 primitive the always-on bar and the
/// [`NativeTrustEngine`] use; no re-implemented crypto). The core stays **sans-IO**: it does not
/// fetch or refresh the trust list — it only chain-validates against the host-supplied anchors.
///
/// This is the production C-ABI trust semantics — distinct from [`StaticTestAnchors`] (exact DER
/// equality only, an offline test seam):
///
/// - A host passing an **issuing CA / IACA root** trusts every credential whose leaf chains to it
///   (the EUDI chain-to-root model), where exact-leaf-match would reject every real credential.
/// - The leaf's **validity window** (and a directly-pinned anchor's) is enforced at the verification
///   instant, so an expired/withdrawn pinned issuer leaf is rejected ([`crate::trust::chain::ChainError::LeafExpired`]),
///   not silently accepted.
///
/// The verification instant `now_unix` (the relevant time the leaf-validity window is checked at) is
/// carried on the source because [`TrustAnchorSource::resolve`] is sans-clock; the C-ABI builds one
/// per verify call from the wire context.
///
/// Carries only issuer-public certificates (no secret), so deriving `Debug` is safe.
#[derive(Debug, Clone)]
pub struct ChainValidatingAnchors {
    /// Trusted anchor/root certificates (DER), keyed by `(role, format)` so per-role/format anchoring
    /// is preserved (an issuer trusted as a PID provider is not thereby trusted as a QEAA).
    anchors: BTreeMap<(IssuerRole, Format), Vec<Vec<u8>>>,
    /// The verification instant (Unix seconds) the leaf-validity window is enforced at.
    now_unix: i64,
}

impl ChainValidatingAnchors {
    /// Construct an empty source for the verification instant `now_unix` (trusts nothing until anchors
    /// are added).
    #[must_use]
    pub fn new(now_unix: i64) -> Self {
        Self {
            anchors: BTreeMap::new(),
            now_unix,
        }
    }

    /// Add a host-resolved trusted anchor/root certificate (DER) for a `(role, format)`. A credential
    /// whose leaf chains to it (or is a valid direct pin) for that role/format is trusted. Returns
    /// `self` for builder-style configuration.
    #[must_use]
    pub fn trust(mut self, role: IssuerRole, format: Format, anchor_cert_der: &[u8]) -> Self {
        self.anchors
            .entry((role, format))
            .or_default()
            .push(anchor_cert_der.to_vec());
        self
    }
}

impl TrustAnchorSource for ChainValidatingAnchors {
    fn resolve(&self, role: IssuerRole, format: Format, issuer_cert_der: &[u8]) -> TrustDecision {
        // Chain-validate the credential's leaf against the host-supplied anchors for its role/format
        // (the shared, single-source resolve body — DRY).
        resolve_chain(
            self.anchors.get(&(role, format)),
            role,
            format,
            issuer_cert_der,
            self.now_unix,
        )
    }

    /// A no-op: the host resolved + passed in the anchors out-of-process; the core stays sans-IO and
    /// never fetches a trust list itself.
    fn refresh(&mut self) -> Result<(), TrustError> {
        Ok(())
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
    anchors: BTreeMap<(IssuerRole, Format), BTreeSet<Vec<u8>>>,
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

    // =============================================================================================
    // ChainValidatingAnchors (the production C-ABI trust source — chain-to-root + leaf validity).
    // =============================================================================================

    use super::ChainValidatingAnchors;

    /// The issuing IACA root the leaves below chain to.
    const CA_IACA: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/ca-iaca.cert.der");
    /// An SD-JWT VC issuer leaf signed by `ca-iaca`.
    const SDJWT_ISSUER: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/sdjwt-issuer.cert.der");
    /// A self-signed leaf that does NOT chain to `ca-iaca`.
    const WRONG_ISSUER: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/wrong-issuer.cert.der");
    /// A time inside every fixture leaf's validity window (2026-06-25 .. 2027-09-23).
    const IN_WINDOW: i64 = 1_788_220_800; // 2026-09-01.
    /// A time long past every fixture leaf's `notAfter` (≈2096).
    const EXPIRED: i64 = 4_000_000_000;

    #[test]
    fn chain_validating_trusts_a_leaf_that_chains_to_the_passed_ca_root() {
        // The EUDI chain-to-root model: a host passing the issuing CA/IACA root trusts every
        // credential whose leaf chains to it (where exact-leaf-match would reject every real one).
        let anchors =
            ChainValidatingAnchors::new(IN_WINDOW).trust(IssuerRole::Pid, Format::SdJwtVc, CA_IACA);
        let decision = anchors.resolve(IssuerRole::Pid, Format::SdJwtVc, SDJWT_ISSUER);
        assert!(decision.trusted, "leaf chains to the passed CA root");
        let entry = decision.entry.expect("trusted decision carries an entry");
        assert_eq!(entry.role, IssuerRole::Pid);
        assert_eq!(entry.format, Format::SdJwtVc);
    }

    #[test]
    fn chain_validating_rejects_an_expired_pinned_leaf_as_untrusted() {
        // A directly-pinned leaf (anchor == leaf) is STILL subject to its validity window: at a time
        // past the leaf's notAfter it is rejected (UntrustedIssuer), never silently accepted — the
        // false-accept `StaticTestAnchors` would allow (it ignores notAfter).
        let anchors = ChainValidatingAnchors::new(EXPIRED).trust(
            IssuerRole::Pid,
            Format::SdJwtVc,
            SDJWT_ISSUER, // pin the leaf directly
        );
        let decision = anchors.resolve(IssuerRole::Pid, Format::SdJwtVc, SDJWT_ISSUER);
        assert!(
            !decision.trusted,
            "an expired pinned leaf must be untrusted, not accepted"
        );
        assert!(decision.entry.is_none());
    }

    #[test]
    fn chain_validating_rejects_a_leaf_that_does_not_chain() {
        // A leaf that does not chain to the passed root (self-signed under a different name) is
        // untrusted, even in-window.
        let anchors =
            ChainValidatingAnchors::new(IN_WINDOW).trust(IssuerRole::Pid, Format::SdJwtVc, CA_IACA);
        assert!(
            !anchors
                .resolve(IssuerRole::Pid, Format::SdJwtVc, WRONG_ISSUER)
                .trusted
        );
    }

    #[test]
    fn chain_validating_is_anchored_per_role_and_format() {
        // The CA is configured for (PID, SD-JWT VC) only: the same leaf is untrusted under a different
        // role or format (per-role/format anchoring, like the test anchor).
        let anchors =
            ChainValidatingAnchors::new(IN_WINDOW).trust(IssuerRole::Pid, Format::SdJwtVc, CA_IACA);
        assert!(
            !anchors
                .resolve(IssuerRole::Qeaa, Format::SdJwtVc, SDJWT_ISSUER)
                .trusted
        );
        assert!(
            !anchors
                .resolve(IssuerRole::Pid, Format::Mdoc, SDJWT_ISSUER)
                .trusted
        );
        // No anchor configured at all → untrusted (fail-closed).
        let empty = ChainValidatingAnchors::new(IN_WINDOW);
        assert!(
            !empty
                .resolve(IssuerRole::Pid, Format::SdJwtVc, SDJWT_ISSUER)
                .trusted
        );
    }

    #[test]
    fn chain_validating_refresh_is_infallible() {
        // The host resolved the anchors out-of-process; the core's refresh is a sans-IO no-op.
        let mut anchors = ChainValidatingAnchors::new(IN_WINDOW);
        assert!(anchors.refresh().is_ok());
    }
}
