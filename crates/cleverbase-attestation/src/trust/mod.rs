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

use crate::trust::chain::{verify_chain, ChainError, LeafPurpose};
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
    /// The DER-encoded **trust anchor** the credential's signer chained to: for a chain-validating
    /// source ([`ChainValidatingAnchors`] / [`NativeTrustEngine`]) the matched ROOT the path terminated
    /// at (or, for a direct DER-equal pin, that pinned certificate — which IS the anchor); for the
    /// exact-pin [`StaticTestAnchors`] the pinned leaf certificate (the pin is the anchor). This is the
    /// specific root a distinct in-core Token Status List signer must ALSO chain to (see
    /// the [`mod@crate::verify`] status-signer authorization) — so it MUST be the anchor, not the leaf.
    pub anchor_cert_der: Vec<u8>,
}

/// Why an issuer resolved as **untrusted** — a coarse-but-accurate category so the verifier attributes
/// a precise [`crate::types::ReasonCode`] (the verdict is identically INVALID either way).
///
/// A chain-validating source ([`ChainValidatingAnchors`] / [`NativeTrustEngine`]) gets a specific
/// [`crate::trust::chain::ChainError`] back from [`crate::trust::chain::verify_chain`]; collapsing it to
/// a bare `trusted: false` would mislabel an EXPIRED (but otherwise trusted) signing cert as
/// "untrusted issuer". This enum preserves the load-bearing distinction the verifier needs:
///
/// - [`TrustFailure::Expired`] — the path failed **only** because a certificate on it (the leaf, an
///   intermediate, or the anchor) was outside its validity window at the verification instant
///   ([`ChainError::LeafExpired`]/[`ChainError::AnchorExpired`]). The credential's signer would
///   otherwise chain to a trusted anchor — it is an expiry, not an absence of trust → the verifier maps
///   it to [`crate::types::ReasonCode::Expired`].
/// - [`TrustFailure::NotTrusted`] — every other reason the path does not reach a configured anchor (no
///   matching issuer, bad signature, a non-CA on the path, an unsupported algorithm, a malformed cert,
///   an over-long chain, an exact-pin miss, or a stale cache) → [`crate::types::ReasonCode::UntrustedIssuer`].
///   It carries the **source** [`ChainError`] (`Some`) when a chain-validating source produced one, so a
///   debugging integrator can drill into the precise no-trust cause (signature-invalid vs not-a-CA vs
///   wrong-leaf-purpose vs issuer-mismatch vs …) WITHOUT changing the coarse verdict mapping — closing the
///   asymmetry with the qualified gate, which already keeps the full [`ChainError`] on
///   [`crate::qualified::QualifiedTrustError::SignerNotTrusted`]. It is `None` for a no-trust that is NOT a
///   chain-validation failure: an exact-DER-pin miss ([`StaticTestAnchors`]), an empty/absent anchor set, or
///   a stale-cache fail-closed default.
///
/// [`ChainError`]: crate::trust::chain::ChainError
/// [`ChainError::LeafExpired`]: crate::trust::chain::ChainError::LeafExpired
/// [`ChainError::AnchorExpired`]: crate::trust::chain::ChainError::AnchorExpired
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustFailure {
    /// A certificate on the signing path is outside its validity window (expired / not-yet-valid),
    /// distinct from an absence of trust — surfaced as [`crate::types::ReasonCode::Expired`].
    Expired,
    /// The signer does not chain to any configured anchor for the role/format (or the cache is stale)
    /// — surfaced as [`crate::types::ReasonCode::UntrustedIssuer`]. Carries the source
    /// [`crate::trust::chain::ChainError`] (`Some`) when a chain-validating source produced one, so the
    /// reason can be drilled into for diagnostics; `None` for a non-chain no-trust (exact-pin miss /
    /// empty anchors / fail-closed default). The verdict mapping stays coarse either way.
    NotTrusted(Option<ChainError>),
}

impl TrustFailure {
    /// The [`crate::types::ReasonCode`] this untrusted-failure category maps to — the **one**
    /// authoritative mapping (DRY — Principle III), shared by both per-format bars so an expired
    /// signing cert reports `Expired` and a genuine no-trust reports `UntrustedIssuer` identically.
    /// The carried [`crate::trust::chain::ChainError`] on `NotTrusted` is diagnostic only — it never
    /// changes the coarse `UntrustedIssuer` verdict.
    #[must_use]
    pub const fn reason_code(&self) -> crate::types::ReasonCode {
        match self {
            Self::Expired => crate::types::ReasonCode::Expired,
            Self::NotTrusted(_) => crate::types::ReasonCode::UntrustedIssuer,
        }
    }

    /// A no-trust failure that is NOT a chain-validation result (an exact-DER-pin miss, an empty/absent
    /// anchor set, or a fail-closed default): [`TrustFailure::NotTrusted`] with no source
    /// [`crate::trust::chain::ChainError`]. The single authoritative constructor for the sourceless
    /// no-trust case (DRY) — every fail-closed default routes through it.
    #[must_use]
    pub const fn not_trusted() -> Self {
        Self::NotTrusted(None)
    }
}

/// The outcome of resolving an issuer against the configured anchors
/// (contracts/trust-anchor-source.md).
///
/// `trusted` is the always-on-bar trust decision; `entry` carries the matched [`TrustListEntry`] when
/// `trusted` is `true` (it is `None` for an untrusted issuer). `failure` carries the coarse-but-accurate
/// [`TrustFailure`] category when `trusted` is `false` (so the verifier attributes `Expired` vs
/// `UntrustedIssuer`); it is `None` for a trusted decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustDecision {
    /// Whether the issuer is on the configured trust anchor for its role/format.
    pub trusted: bool,
    /// The matched trust-list entry, present iff `trusted`.
    pub entry: Option<TrustListEntry>,
    /// The untrusted-failure category, present iff `!trusted` (so the reason is never opaque).
    pub failure: Option<TrustFailure>,
}

impl TrustDecision {
    /// A trusted decision carrying its matched entry.
    #[must_use]
    pub const fn trusted(entry: TrustListEntry) -> Self {
        Self {
            trusted: true,
            entry: Some(entry),
            failure: None,
        }
    }

    /// An untrusted decision (no matched entry), carrying the [`TrustFailure`] category so the verifier
    /// can attribute a precise reason.
    #[must_use]
    pub const fn untrusted_because(failure: TrustFailure) -> Self {
        Self {
            trusted: false,
            entry: None,
            failure: Some(failure),
        }
    }

    /// An untrusted decision with no specific category (the exact-DER-pin miss / fail-closed default):
    /// the signer is simply not among the configured anchors → [`TrustFailure::not_trusted`] (no source
    /// [`crate::trust::chain::ChainError`]).
    #[must_use]
    pub const fn untrusted() -> Self {
        Self::untrusted_because(TrustFailure::not_trusted())
    }
}

/// Resolve a credential's signing chain against a set of trusted anchors for one `(role, format)` by
/// RFC 5280 **path validation** — the single authoritative `resolve` body shared by every
/// chain-validating [`TrustAnchorSource`] (the [`NativeTrustEngine`] and the C-ABI
/// [`ChainValidatingAnchors`]), so the trust rule is defined once (DRY — Principle III).
///
/// `issuer_cert_der` is the credential's signing leaf and `supplied_intermediates` are the remaining
/// `x5c` / `x5chain` certificates (leaf-first order overall). The chain is trusted iff the path
/// `leaf → intermediate₁ → … → a configured anchor` validates at `now_unix` via
/// [`crate::trust::chain::verify_chain`] (name chaining + signature + CA constraints + validity at
/// every hop, or a direct DER-equal pin). The supplied intermediates are attacker-controlled
/// path-building material — the path is trusted only if it reaches a configured anchor. An empty/absent
/// anchor set is untrusted (fail-closed). On success the matched [`TrustListEntry`] carries the matched
/// **trust anchor** (the ROOT the path terminated at — or the pinned cert for a direct pin) as its
/// `anchor_cert_der`, surfaced by [`verify_chain`]'s `Ok` payload. The always-on bar reads only
/// `trusted`, but the in-core status-signer authorization binds a distinct status signer to THIS exact
/// root, so it MUST be the anchor, not the leaf.
///
/// On failure the specific [`crate::trust::chain::ChainError`] is folded to a coarse-but-accurate
/// [`TrustFailure`] on the returned [`TrustDecision`] (NOT widened to the verdict, which stays INVALID):
/// a cert outside its validity window on the path → [`TrustFailure::Expired`] (so the verifier reports
/// `Expired`, not a misleading `UntrustedIssuer`); every other reason the path reaches no anchor →
/// [`TrustFailure::NotTrusted`].
/// The leaf key purpose the chain validator enforces on a CREDENTIAL signing leaf, from its format +
/// role (mdoc → the ISO 18013-5 Annex B Table B.3 DS profile; SD-JWT VC → the EN 319 412-2/-3 base
/// floor + the per-role eIDAS QcStatement keyed by `role`) — the single mapping shared by both
/// chain-validating sources' `resolve` (DRY — Principle III). Distinct from a status-list *signer*
/// leaf, which chains with [`LeafPurpose::TrustListSigner`] (no credential-leaf purpose) and is instead
/// gated by the status-signing EKU (see [`TrustAnchorSource::resolve_status_signer`]).
pub(super) const fn credential_leaf_purpose(role: IssuerRole, format: Format) -> LeafPurpose {
    match format {
        Format::Mdoc => LeafPurpose::MdocDocumentSigner,
        Format::SdJwtVc => LeafPurpose::SdJwtVcIssuer(role),
    }
}

/// How [`resolve_chain`] checks the signing **leaf** during path validation: the instant its OWN
/// validity window is enforced at, and the role/format key purpose it must carry. Bundled so the
/// resolve body stays under the argument-count bar and the "leaf policy" travels as one unit.
pub(super) struct LeafCheck {
    /// The instant the leaf's own validity window is checked at: `None` = the source clock (`now_unix`),
    /// `Some(t)` = the mdoc DS `validityInfo.signed` seam (ISO/IEC 18013-5 §9.3.1).
    pub validity_time: Option<i64>,
    /// The key purpose the leaf must carry ([`credential_leaf_purpose`] for a credential signing leaf;
    /// [`LeafPurpose::TrustListSigner`] for a distinct status-list signer — no credential-leaf profile).
    pub purpose: LeafPurpose,
}

fn resolve_chain(
    anchors_for_key: Option<&Vec<Vec<u8>>>,
    role: IssuerRole,
    format: Format,
    issuer_cert_der: &[u8],
    supplied_intermediates: &[Vec<u8>],
    now_unix: i64,
    leaf: LeafCheck,
) -> TrustDecision {
    let Some(anchors) = anchors_for_key else {
        return TrustDecision::untrusted();
    };
    // Assemble the leaf-first supplied path: [leaf, intermediate₁, …]. The intermediates come from the
    // credential's own x5c/x5chain and are untrusted path-building material (verify_chain only trusts a
    // path that terminates at a configured anchor).
    let mut chain: Vec<&[u8]> = Vec::with_capacity(1 + supplied_intermediates.len());
    chain.push(issuer_cert_der);
    chain.extend(supplied_intermediates.iter().map(Vec::as_slice));
    // `leaf.purpose` fixes the key purpose the chain validator enforces on the signing leaf — a
    // genuinely-chained-but-WRONG-PURPOSE leaf is rejected (no "right chain, wrong purpose"
    // false-accept). For a credential leaf it is [`credential_leaf_purpose`]; for a distinct status-list
    // signer it is [`LeafPurpose::TrustListSigner`] (no credential-leaf profile — the status-signing EKU
    // is the caller's separate gate). `leaf.validity_time` (Some for the mdoc DS leaf at the MSO `signed`
    // time, None elsewhere) is the seam for ISO §9.3.1.
    match verify_chain(&chain, anchors, now_unix, leaf.validity_time, leaf.purpose) {
        // `verify_chain` returns a BORROW of the trust anchor the path terminated at (the matched ROOT
        // for a chain-to-root path; the pinned cert for a direct pin), into the caller-supplied anchor
        // set. Clone it HERE (`.to_vec()`) to OWN it in the entry's `anchor_cert_der` — NOT the leaf: the
        // in-core status-signer authorization binds a distinct status signer to the credential's SAME
        // specific root, which only works if this is the root. (Alloc-neutral: `verify_chain` no longer
        // clones; the single `.to_vec()` moved here — the two discarding callers now allocate nothing.)
        Ok(anchor_der) => TrustDecision::trusted(TrustListEntry {
            role,
            format,
            anchor_cert_der: anchor_der.to_vec(),
        }),
        // Map the specific ChainError to the coarse-but-accurate TrustFailure the verifier needs: a
        // cert outside its validity window on the path (the leaf, an intermediate, or the anchor) is an
        // EXPIRY (→ `Expired`), distinct from an absence of trust (→ `UntrustedIssuer`). The verdict is
        // identically INVALID either way; only the surfaced reason differs (accurate diagnostics).
        Err(ChainError::LeafExpired | ChainError::AnchorExpired) => {
            TrustDecision::untrusted_because(TrustFailure::Expired)
        }
        // Every other reason the path reaches no anchor → `NotTrusted`, carrying the SOURCE `ChainError`
        // so a debugging integrator can drill into the precise no-trust cause (the verdict stays the
        // coarse `UntrustedIssuer`). This is the asymmetry the qualified gate already avoided.
        Err(other) => TrustDecision::untrusted_because(TrustFailure::NotTrusted(Some(other))),
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
///   not silently accepted. An expiry-driven chain failure carries [`TrustFailure::Expired`] on the
///   [`TrustDecision`] (so the verifier reports `Expired`, not `UntrustedIssuer`); every other path
///   failure carries [`TrustFailure::NotTrusted`].
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
    fn resolve(
        &self,
        role: IssuerRole,
        format: Format,
        issuer_cert_der: &[u8],
        supplied_intermediates: &[Vec<u8>],
        leaf_validity_time: Option<i64>,
    ) -> TrustDecision {
        // Validate the credential's signing path (leaf + supplied intermediates) against the
        // host-supplied anchors for its role/format (the shared, single-source resolve body — DRY).
        resolve_chain(
            self.anchors.get(&(role, format)),
            role,
            format,
            issuer_cert_der,
            supplied_intermediates,
            self.now_unix,
            LeafCheck {
                validity_time: leaf_validity_time,
                purpose: credential_leaf_purpose(role, format),
            },
        )
    }

    fn resolve_status_signer(
        &self,
        role: IssuerRole,
        format: Format,
        signer_leaf_der: &[u8],
        supplied_intermediates: &[Vec<u8>],
    ) -> TrustDecision {
        // Chain-validate a DISTINCT status-list signer to the SAME anchors as the credential's issuer,
        // with NO credential-leaf purpose (`TrustListSigner`) — the status-signing EKU is the caller's
        // separate gate. The signer leaf's window is checked at `now_unix` (no distinct signing instant).
        resolve_chain(
            self.anchors.get(&(role, format)),
            role,
            format,
            signer_leaf_der,
            supplied_intermediates,
            self.now_unix,
            LeafCheck {
                validity_time: None,
                purpose: LeafPurpose::TrustListSigner,
            },
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
    /// Resolve whether an issuer is trusted for a given role/format, validating the credential's
    /// signing certification path against the configured anchors. **Pure / sans-IO** — never performs
    /// I/O.
    ///
    /// `issuer_cert_der` is the credential's signing leaf (the mdoc `IssuerAuth` x5chain leaf, or the
    /// SD-JWT VC JWS `x5c` leaf) and `supplied_intermediates` are the remaining `x5c` / `x5chain`
    /// certificates the credential carries (leaf-first order overall: leaf, then intermediate sub-CAs).
    /// A chain-validating source builds the RFC 5280 §6.1 path `leaf → intermediate₁ → … → anchor`; the
    /// supplied intermediates are untrusted path-building material, so the path is trusted only if it
    /// reaches a configured anchor. An exact-match source ignores the intermediates (it pins the leaf).
    ///
    /// `leaf_validity_time` is the instant the **leaf's own** validity window is checked at (the
    /// chain-authentication validity stays at the source's verification clock). It is `None` for the
    /// SD-JWT VC issuer and the trust-list signer (no distinct signing instant — the leaf is checked at
    /// "now"); the mdoc verifier passes `Some(mso.validityInfo.signed)` so the Document Signer
    /// certificate's window is checked against the MSO signing time per ISO/IEC 18013-5 §9.3.1 (DS certs
    /// rotate while mDLs live for years — a conformant mDL must not be false-rejected once its DS cert
    /// expires). An exact-match source ignores it.
    fn resolve(
        &self,
        role: IssuerRole,
        format: Format,
        issuer_cert_der: &[u8],
        supplied_intermediates: &[Vec<u8>],
        leaf_validity_time: Option<i64>,
    ) -> TrustDecision;

    /// Authorize a Token Status List **signer** leaf that is DISTINCT from the credential's own issuer:
    /// chain-validate the signer leaf (+ its supplied intermediates) to the SAME configured anchor set
    /// the credential's issuer chains to for `(role, format)`, WITHOUT imposing the credential-leaf key
    /// purpose. A status-list signer follows its own profile (draft-ietf-oauth-status-list §13), so the
    /// credential-leaf QcStatement / mdlDS-EKU floor MUST NOT be applied here; the status-signing EKU is
    /// enforced separately by the caller (the [`mod@crate::verify`] status-signer glue). **Pure / sans-IO.**
    ///
    /// Used ONLY on the distinct-signer branch of the in-core Token Status List check: the primary path
    /// (the issuer signs its own status list) resolves the key from the credential's already-verified
    /// issuer leaf by byte-equality and never calls this. Returns a [`TrustDecision`]; `trusted` iff the
    /// signer leaf chains to a configured anchor.
    ///
    /// **Default: fail-closed** (`untrusted`). An exact-DER-pin source ([`StaticTestAnchors`]) cannot
    /// chain-validate a signer that is not itself pinned, so it authorizes NO distinct status signer —
    /// only the same-issuer key-reuse path applies there. The chain-validating production sources
    /// ([`ChainValidatingAnchors`] / [`NativeTrustEngine`]) override this.
    fn resolve_status_signer(
        &self,
        role: IssuerRole,
        format: Format,
        signer_leaf_der: &[u8],
        supplied_intermediates: &[Vec<u8>],
    ) -> TrustDecision {
        // Fail-closed: a source that does not chain-validate authorizes no distinct status signer.
        let _ = (role, format, signer_leaf_der, supplied_intermediates);
        TrustDecision::untrusted()
    }

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
///
/// **⚠ Not a production trust source.** Its [`resolve`](TrustAnchorSource::resolve) does **exact-DER
/// pinning ONLY** — NO certificate validity-window check, NO path building, and it ignores the supplied
/// intermediates and `leaf_validity_time`. It is therefore strictly WEAKER than the production
/// [`ChainValidatingAnchors`]/[`NativeTrustEngine`], which reject an expired/withdrawn pinned leaf for
/// the same `resolve` call. Wiring this into a production verifier would trust a pinned-but-expired
/// issuer certificate (a trust false-accept). Use it only for the offline test suite / conformance
/// vectors; a production integrator MUST use [`ChainValidatingAnchors`] or [`NativeTrustEngine`].
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
    fn resolve(
        &self,
        role: IssuerRole,
        format: Format,
        issuer_cert_der: &[u8],
        _supplied_intermediates: &[Vec<u8>],
        _leaf_validity_time: Option<i64>,
    ) -> TrustDecision {
        // Exact-DER-equality pinning of the leaf — the supplied intermediates and leaf-validity time are
        // not consulted (an offline test seam that lists the leaf certificate itself, not a
        // chain-to-root source; it performs no validity-window check at all).
        if self.is_trusted(role, format, issuer_cert_der) {
            TrustDecision::trusted(TrustListEntry {
                role,
                format,
                // Exact-DER pin: the pinned leaf IS the trust anchor here, so storing `issuer_cert_der`
                // as `anchor_cert_der` is correct (the anchor == the leaf for a direct pin — the same
                // invariant a chain-validating source records for its own direct-pin termination).
                anchor_cert_der: issuer_cert_der.to_vec(),
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
    use super::{Reachability, StaticTestAnchors, TrustAnchorSource, TrustFailure};
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
        let decision = anchors.resolve(IssuerRole::Qeaa, Format::SdJwtVc, ISSUER_A, &[], None);
        assert!(decision.trusted);
        let entry = decision.entry.expect("trusted decision carries an entry");
        assert_eq!(entry.role, IssuerRole::Qeaa);
        assert_eq!(entry.format, Format::SdJwtVc);
        assert_eq!(entry.anchor_cert_der, ISSUER_A);
    }

    #[test]
    fn unconfigured_issuer_is_untrusted() {
        let anchors = StaticTestAnchors::new().trust(IssuerRole::Qeaa, Format::SdJwtVc, ISSUER_A);
        let decision = anchors.resolve(IssuerRole::Qeaa, Format::SdJwtVc, ISSUER_B, &[], None);
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
                .resolve(IssuerRole::Qeaa, Format::SdJwtVc, ISSUER_A, &[], None)
                .trusted
        );
        // Same cert + role, different format → untrusted (per-format anchoring).
        assert!(
            !anchors
                .resolve(IssuerRole::Pid, Format::Mdoc, ISSUER_A, &[], None)
                .trusted
        );
        // Exact role+format → trusted.
        assert!(
            anchors
                .resolve(IssuerRole::Pid, Format::SdJwtVc, ISSUER_A, &[], None)
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
    /// An mdoc Document Signer leaf signed by `ca-iaca` (mdlDS EKU + digitalSignature + cA=FALSE).
    const MDOC_DS: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/mdoc-ds.cert.der");
    /// A time inside every fixture leaf's validity window.
    const IN_WINDOW: i64 = 1_788_220_800; // 2026-09-01.
    /// A time past the ~15-month leaf `notAfter` but inside the `ca-iaca` root window (notAfter 2036) —
    /// the seam scenario: the DS leaf has expired at "now" but the issuing root is still valid.
    const NOW_AFTER_LEAF: i64 = 1_893_456_000; // 2030-01-01.
    /// A time long past every fixture leaf's `notAfter` (≈2096).
    const EXPIRED: i64 = 4_000_000_000;

    #[test]
    fn chain_validating_trusts_a_leaf_that_chains_to_the_passed_ca_root() {
        // The EUDI chain-to-root model: a host passing the issuing CA/IACA root trusts every
        // credential whose leaf chains to it (where exact-leaf-match would reject every real one).
        let anchors =
            ChainValidatingAnchors::new(IN_WINDOW).trust(IssuerRole::Pid, Format::SdJwtVc, CA_IACA);
        let decision = anchors.resolve(IssuerRole::Pid, Format::SdJwtVc, SDJWT_ISSUER, &[], None);
        assert!(decision.trusted, "leaf chains to the passed CA root");
        let entry = decision.entry.expect("trusted decision carries an entry");
        assert_eq!(entry.role, IssuerRole::Pid);
        assert_eq!(entry.format, Format::SdJwtVc);
    }

    #[test]
    fn chain_validating_rejects_an_expired_pinned_leaf_as_expired() {
        // A directly-pinned leaf (anchor == leaf) is STILL subject to its validity window: at a time
        // past the leaf's notAfter it is rejected, never silently accepted — the false-accept
        // `StaticTestAnchors` would allow (it ignores notAfter). The failure category is `Expired`
        // (a valid signer that has lapsed), NOT `NotTrusted` (an absence of trust): the verifier maps it
        // to `ReasonCode::Expired`, not a misleading `UntrustedIssuer`.
        let anchors = ChainValidatingAnchors::new(EXPIRED).trust(
            IssuerRole::Pid,
            Format::SdJwtVc,
            SDJWT_ISSUER, // pin the leaf directly
        );
        let decision = anchors.resolve(IssuerRole::Pid, Format::SdJwtVc, SDJWT_ISSUER, &[], None);
        assert!(
            !decision.trusted,
            "an expired pinned leaf must be untrusted, not accepted"
        );
        assert!(decision.entry.is_none());
        assert_eq!(
            decision.failure,
            Some(TrustFailure::Expired),
            "an expired (but otherwise trusted) signer is an expiry, not an absence of trust"
        );
        assert_eq!(
            decision.failure.as_ref().map(TrustFailure::reason_code),
            Some(crate::types::ReasonCode::Expired),
            "the verifier maps an expiry-driven chain failure to Expired"
        );
    }

    #[test]
    fn chain_validating_rejects_a_leaf_that_does_not_chain() {
        // A leaf that does not chain to the passed root (self-signed under a different name) is
        // untrusted, even in-window. This is a genuine absence of trust (no path to an anchor), so the
        // failure category is `NotTrusted` → the verifier reports `UntrustedIssuer` (NOT `Expired`). The
        // failure also CARRIES the source `ChainError::IssuerMismatch` (the path reaches no name-matching
        // anchor) so a debugging integrator can drill into the precise no-trust cause. The role is
        // NonQualifiedEaa (no QcStatement requirement) so the leaf-purpose floor passes and the failure
        // is the path-build IssuerMismatch, not a wrong-purpose reject before the walk.
        let anchors = ChainValidatingAnchors::new(IN_WINDOW).trust(
            IssuerRole::NonQualifiedEaa,
            Format::SdJwtVc,
            CA_IACA,
        );
        let decision = anchors.resolve(
            IssuerRole::NonQualifiedEaa,
            Format::SdJwtVc,
            WRONG_ISSUER,
            &[],
            None,
        );
        assert!(!decision.trusted);
        assert_eq!(
            decision.failure,
            Some(TrustFailure::NotTrusted(Some(
                crate::trust::chain::ChainError::IssuerMismatch
            ))),
            "a leaf that reaches no anchor is an absence of trust, not an expiry, and surfaces the source ChainError"
        );
        assert_eq!(
            decision.failure.as_ref().map(TrustFailure::reason_code),
            Some(crate::types::ReasonCode::UntrustedIssuer)
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
                .resolve(IssuerRole::Qeaa, Format::SdJwtVc, SDJWT_ISSUER, &[], None)
                .trusted
        );
        assert!(
            !anchors
                .resolve(IssuerRole::Pid, Format::Mdoc, SDJWT_ISSUER, &[], None)
                .trusted
        );
        // No anchor configured at all → untrusted (fail-closed).
        let empty = ChainValidatingAnchors::new(IN_WINDOW);
        assert!(
            !empty
                .resolve(IssuerRole::Pid, Format::SdJwtVc, SDJWT_ISSUER, &[], None)
                .trusted
        );
    }

    #[test]
    fn chain_validating_refresh_is_infallible() {
        // The host resolved the anchors out-of-process; the core's refresh is a sans-IO no-op.
        let mut anchors = ChainValidatingAnchors::new(IN_WINDOW);
        assert!(anchors.refresh().is_ok());
    }

    #[test]
    fn resolve_threads_the_leaf_validity_time_seam_for_the_mdoc_ds_leaf() {
        // ISO/IEC 18013-5 §9.3.1 through the trait seam: a host trusts the IACA root for (PID, mdoc) at a
        // verification instant (2030) PAST the DS leaf's window but inside the root's. With
        // `leaf_validity_time = Some(signed)` inside the leaf window, the DS leaf is checked at its
        // signing time → trusted (the conformant-mDL false-reject the seam fixes); with `None` the leaf
        // is checked at "now" (2030, expired) → untrusted with the `Expired` failure category.
        let anchors = ChainValidatingAnchors::new(NOW_AFTER_LEAF).trust(
            IssuerRole::Pid,
            Format::Mdoc,
            CA_IACA,
        );
        let trusted = anchors.resolve(IssuerRole::Pid, Format::Mdoc, MDOC_DS, &[], Some(IN_WINDOW));
        assert!(
            trusted.trusted,
            "a DS leaf expired at now but valid at the MSO signed time must be trusted (§9.3.1)"
        );
        let rejected = anchors.resolve(IssuerRole::Pid, Format::Mdoc, MDOC_DS, &[], None);
        assert!(!rejected.trusted);
        assert_eq!(
            rejected.failure,
            Some(TrustFailure::Expired),
            "checked at now (None), the expired DS leaf surfaces as Expired"
        );
        // The other direction: a signing time OUTSIDE the leaf window is rejected even at an in-window
        // verification instant (the DS cert was not valid when it claims to have signed).
        let bad_signed =
            ChainValidatingAnchors::new(IN_WINDOW).trust(IssuerRole::Pid, Format::Mdoc, CA_IACA);
        let d = bad_signed.resolve(
            IssuerRole::Pid,
            Format::Mdoc,
            MDOC_DS,
            &[],
            Some(NOW_AFTER_LEAF),
        );
        assert!(
            !d.trusted,
            "a DS cert not valid at the signing time is rejected"
        );
        assert_eq!(d.failure, Some(TrustFailure::Expired));
    }
}
