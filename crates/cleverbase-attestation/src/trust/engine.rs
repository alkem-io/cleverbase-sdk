//! The native EU trust-list engine (research D5 — the biggest single build).
//!
//! [`NativeTrustEngine`] is the production [`TrustAnchorSource`]: a host-driven
//! [`NativeTrustEngine::refresh`]
//! **fetches → parses → authenticates → caches** the signed trust lists (the offline JSON manifest
//! now; a TS 119 612 XML LOTL / national TL via [`super::xml`]), and a pure, sans-IO
//! [`NativeTrustEngine::resolve`] answers issuer-trust questions against the **cached** anchors by
//! chain-
//! validating the issuer's signing certificate ([`super::chain`]).
//!
//! ## Reachability / stale policy (U1 — fail-closed for the LOTL; ETSI warning for a national TL)
//!
//! [`refresh`](NativeTrustEngine::refresh) is where the [`Reachability`] policy applies. Outcomes are
//! kept distinct (the contract's U1 requirement):
//!
//! - **Unreachable** — the [`TrustListFetcher`] could not return bytes ([`TrustError::Unreachable`]).
//! - **Authentication failure** — a fetched XML list's signing certificate did not authenticate
//!   ([`TrustError::Authentication`]). (Per the T5.3 scope cut the XML path fails closed by default —
//!   see [`super::xml`].)
//! - **Stale** — the fetched list parsed but its `NextUpdate` is at/before the current clock. **Staleness
//!   is fatal only for a LOTL** (`ListKind::Lotl`): ETSI TS 119 615 v1.4.1 PRO-4.1.4-13 voids the LOTL
//!   and **stops the process** when its `NextUpdate` has passed ([`TrustError::Stale`]). For a **national
//!   / member-state TL** (`ListKind::National`) a passed `NextUpdate` is a **non-fatal WARNING**
//!   (PRO-4.2.4-10/12, `WARNING_EUTL_NEXTUPDATE_PASSED`): the list still authenticates and remains usable,
//!   and the engine records a warning ([`NativeTrustEngine::warnings`]) rather than failing. This aligns
//!   with the EU DSS reference (`TLExpirationDetection` → a configurable, default-log **warning**).
//!   Verified online against TS 119 615 v1.4.1 PRO-4.1.4-13 / PRO-4.2.4-10/12 and esig/dss `master`.
//!
//! Under [`Reachability::FailClosed`] (the default) an unreachable / authentication-failed / **LOTL**-stale
//! refresh fails **and** clears the cached anchors, so a subsequent `resolve` cannot serve stale/empty
//! trust (no silent VALID). Under [`Reachability::BestEffort`] an unreachable / LOTL-stale list keeps the
//! last-known-good cache. A national-TL staleness is never a hard failure under either policy. All of
//! these are distinct from an **expired/withdrawn entry** (a present-but-out-of-window issuer leaf, or a
//! withdrawn TS 119 612 service → `resolve` returns untrusted) and from the per-credential status endpoint
//! ([`crate::types::StatusReachability`]).

use std::collections::BTreeMap;

use super::manifest::TrustListManifest;
use super::xml::XmlTrustList;
use super::{Reachability, TrustAnchorSource, TrustDecision, TrustError};
use crate::types::{Format, IssuerRole};

/// A host-driven source of raw trust-list bytes (keeps the core sans-IO — research D5 / Principle
/// III).
///
/// The core never performs network I/O; the host supplies the fetched bytes (or signals
/// unreachable) so the engine can parse/authenticate/cache them. A fetcher returns the raw
/// trust-list document for a logical list name (e.g. a LOTL URL the host configured), or `None`
/// when that list is unreachable.
pub trait TrustListFetcher {
    /// Fetch the raw bytes of the named trust list, or `None` if it is unreachable.
    ///
    /// `list_name` is the engine-configured logical name of a list (the host maps it to a URL /
    /// cache). The returned bytes are the JSON manifest or TS 119 612 XML the engine will
    /// parse+authenticate.
    fn fetch(&mut self, list_name: &str) -> Option<Vec<u8>>;
}

/// The encoding of a configured trust list — selects the parse path.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ListFormat {
    /// The offline JSON test manifest ([`TrustListManifest`]).
    JsonManifest,
    /// A TS 119 612 trust-list XML ([`XmlTrustList`]); the `(role, format)` every ingested service maps
    /// to, plus the optional expected `<ServiceTypeIdentifier>` (§5.5.1) filter (`None` = ingest any
    /// `granted` service). The enveloped XAdES `SignatureValue`/exclusive-C14N check is a documented
    /// scope cut, so the XML path fails closed in production — see [`super::xml`].
    Xml {
        role: IssuerRole,
        format: Format,
        service_type: Option<String>,
    },
}

/// Whether a configured list is the **LOTL** (List of Trusted Lists) or a **national / member-state
/// Trusted List** — which decides how a passed `NextUpdate` is handled (TS 119 615 v1.4.1):
///
/// - [`ListKind::Lotl`] — a passed `NextUpdate` is **fatal** (PRO-4.1.4-13: void the LOTL, stop).
/// - [`ListKind::National`] — a passed `NextUpdate` is a **non-fatal WARNING** (PRO-4.2.4-10/12): the
///   list still authenticates and remains usable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListKind {
    /// The List of Trusted Lists: a passed `NextUpdate` is fatal (TS 119 615 PRO-4.1.4-13).
    Lotl,
    /// A national / member-state TL: a passed `NextUpdate` is a non-fatal warning (PRO-4.2.4-10/12).
    National,
}

/// One configured trust list: its logical name, encoding, kind (LOTL / national), and (for XML) the
/// scheme-operator anchors that authenticate it.
#[derive(Debug, Clone)]
struct ConfiguredList {
    name: String,
    format: ListFormat,
    /// The scheme-operator trust anchors (DER) that an XML list's signing cert must chain to. Empty
    /// for the JSON manifest (which carries no signature — the offline suite trusts its bytes).
    scheme_anchors_der: Vec<Vec<u8>>,
    /// LOTL vs national — decides fatal-vs-warning staleness (TS 119 615 PRO-4.1.4-13 / 4.2.4-10).
    kind: ListKind,
    /// **Test-only seam**: when set, an XML list is authenticated on the signing-cert chain alone
    /// (the `#[cfg(test)]` `XmlTrustList::authenticate_chain_only`) instead of the production
    /// fail-closed [`XmlTrustList::authenticate`]. The full enveloped XAdES verification is a
    /// documented scope cut (T5.3), so production XML authentication always fails closed; this seam
    /// only keeps the parse → anchor-ingest wiring exercised by tests and is unreachable in production.
    #[cfg(test)]
    test_chain_only: bool,
}

/// The cached, authenticated anchors plus the LOTL freshness bound + any non-fatal refresh warnings.
#[derive(Debug, Clone, Default)]
struct Cache {
    /// Trusted anchor certificates (DER), keyed by `(role, format)`.
    anchors: BTreeMap<(IssuerRole, Format), Vec<Vec<u8>>>,
    /// The earliest `NextUpdate` (Unix seconds) across the cached **LOTL** lists — the **fatal**
    /// freshness bound that gates [`NativeTrustEngine::resolve`]. `None` when no (non-stale) LOTL list
    /// is configured (e.g. a national-only engine), in which case staleness never blocks `resolve`
    /// (national-TL staleness is a non-fatal warning — TS 119 615 PRO-4.2.4-10).
    lotl_next_update: Option<i64>,
    /// Whether a refresh has populated this cache (distinguishes "never refreshed" from "refreshed
    /// with no LOTL freshness bound").
    populated: bool,
    /// Non-fatal warnings recorded during the last refresh (e.g. a national TL past its `NextUpdate`,
    /// `WARNING_EUTL_NEXTUPDATE_PASSED` — TS 119 615 PRO-4.2.4-10). Surfaced via
    /// [`NativeTrustEngine::warnings`].
    warnings: Vec<String>,
}

impl Cache {
    /// Append `anchors` (DER) to the cached set for `(role, format)`, creating the entry if absent.
    /// The **one** anchor-insertion step shared by the JSON-manifest and XML refresh arms (DRY —
    /// Principle III): both previously transcribed the identical
    /// `entry((role, format)).or_default().extend(...)`.
    fn add_anchors(
        &mut self,
        role: IssuerRole,
        format: Format,
        anchors: impl IntoIterator<Item = Vec<u8>>,
    ) {
        self.anchors
            .entry((role, format))
            .or_default()
            .extend(anchors);
    }
}

/// The native EU trust-list engine ([`TrustAnchorSource`]).
///
/// Configure it with one or more trust lists, then [`refresh`](Self::refresh) (host-driven) to
/// fetch/authenticate/cache them; [`resolve`](Self::resolve) is pure and works on the cache.
///
/// Carries only issuer-public anchor data + a clock (no secret), so deriving `Debug` is safe.
#[derive(Debug)]
pub struct NativeTrustEngine {
    lists: Vec<ConfiguredList>,
    cache: Cache,
    reachability: Reachability,
    /// The clock seam: returns "now" as Unix seconds. Fixed-clock in tests for determinism; the
    /// host wires a real clock in production.
    now_unix: i64,
}

impl NativeTrustEngine {
    /// Construct an engine with the given [`Reachability`] policy and a fixed clock (Unix seconds).
    ///
    /// The clock is an explicit input (the seam) so validity/staleness are deterministic; the host
    /// advances it via [`Self::set_now`] before each refresh in production.
    #[must_use]
    pub fn new(reachability: Reachability, now_unix: i64) -> Self {
        Self {
            lists: Vec::new(),
            cache: Cache::default(),
            reachability,
            now_unix,
        }
    }

    /// Set the engine clock (Unix seconds) — the deterministic clock seam (U1 staleness).
    pub fn set_now(&mut self, now_unix: i64) {
        self.now_unix = now_unix;
    }

    /// Append a configured list (the single push site, so the `#[cfg(test)]` `test_chain_only` field
    /// is defaulted in one place).
    fn push_list(
        &mut self,
        name: String,
        format: ListFormat,
        scheme_anchors_der: Vec<Vec<u8>>,
        kind: ListKind,
    ) {
        self.lists.push(ConfiguredList {
            name,
            format,
            scheme_anchors_der,
            kind,
            #[cfg(test)]
            test_chain_only: false,
        });
    }

    /// Configure the offline JSON manifest list under the given logical name, as the **LOTL** (a passed
    /// `NextUpdate` is fatal — TS 119 615 PRO-4.1.4-13). Builder-style.
    #[must_use]
    pub fn with_json_manifest(mut self, name: impl Into<String>) -> Self {
        self.push_list(
            name.into(),
            ListFormat::JsonManifest,
            Vec::new(),
            ListKind::Lotl,
        );
        self
    }

    /// Configure the offline JSON manifest list under the given logical name, as a **national /
    /// member-state TL** (a passed `NextUpdate` is a non-fatal WARNING — TS 119 615 PRO-4.2.4-10/12;
    /// the list stays usable). Builder-style.
    #[must_use]
    pub fn with_national_json_manifest(mut self, name: impl Into<String>) -> Self {
        self.push_list(
            name.into(),
            ListFormat::JsonManifest,
            Vec::new(),
            ListKind::National,
        );
        self
    }

    /// Configure a TS 119 612 XML LOTL under the given logical name, mapping every **`granted`**
    /// service it carries to `(role, format)` and authenticating its signing cert against
    /// `scheme_anchors_der` (builder-style). `expected_service_type` optionally restricts ingestion to
    /// `granted` services of one `<ServiceTypeIdentifier>` (§5.5.1; `None` = any granted service).
    ///
    /// The enveloped XAdES `SignatureValue`/exclusive-C14N verification is a documented scope cut
    /// (T5.3 — see [`super::xml`]), so an XML list configured this way **fails authentication closed**
    /// in production: a real LOTL is never trusted on the signing-cert chain alone.
    #[must_use]
    pub fn with_xml_list(
        mut self,
        name: impl Into<String>,
        role: IssuerRole,
        format: Format,
        scheme_anchors_der: Vec<Vec<u8>>,
        expected_service_type: Option<String>,
    ) -> Self {
        self.push_list(
            name.into(),
            ListFormat::Xml {
                role,
                format,
                service_type: expected_service_type,
            },
            scheme_anchors_der,
            ListKind::Lotl,
        );
        self
    }

    /// **Test-only** seam: configure an XML list authenticated on the signing-cert chain alone (the
    /// `#[cfg(test)]` `XmlTrustList::authenticate_chain_only`), so the parse → anchor-ingest wiring
    /// stays exercised by tests. Production code cannot reach this (the full XAdES check is a scope
    /// cut, so [`Self::with_xml_list`] always fails closed — T5.3).
    #[cfg(test)]
    pub(crate) fn with_xml_list_chain_only(
        mut self,
        name: impl Into<String>,
        role: IssuerRole,
        format: Format,
        scheme_anchors_der: Vec<Vec<u8>>,
        expected_service_type: Option<String>,
    ) -> Self {
        self.lists.push(ConfiguredList {
            name: name.into(),
            format: ListFormat::Xml {
                role,
                format,
                service_type: expected_service_type,
            },
            scheme_anchors_der,
            kind: ListKind::Lotl,
            test_chain_only: true,
        });
        self
    }

    /// Non-fatal warnings recorded during the last successful refresh (e.g. a national TL past its
    /// `NextUpdate`, `WARNING_EUTL_NEXTUPDATE_PASSED` — TS 119 615 PRO-4.2.4-10). Empty after a clean
    /// refresh, and cleared when a fail-closed refresh drops the cache.
    #[must_use]
    pub fn warnings(&self) -> &[String] {
        &self.cache.warnings
    }

    /// Authenticate a parsed XML list. **Production: fail-closed** ([`XmlTrustList::authenticate`] — the
    /// full XAdES verification is a scope cut, T5.3). Under `#[cfg(test)]`, a list configured via
    /// [`Self::with_xml_list_chain_only`] uses the chain-only seam so the ingest wiring is testable.
    fn authenticate_xml(
        &self,
        parsed: &XmlTrustList,
        list: &ConfiguredList,
    ) -> Result<(), TrustError> {
        let outcome = {
            #[cfg(test)]
            {
                if list.test_chain_only {
                    parsed.authenticate_chain_only(&list.scheme_anchors_der, self.now_unix)
                } else {
                    parsed.authenticate(&list.scheme_anchors_der, self.now_unix)
                }
            }
            #[cfg(not(test))]
            {
                parsed.authenticate(&list.scheme_anchors_der, self.now_unix)
            }
        };
        outcome.map_err(|e| TrustError::Authentication(format!("{}: {e}", list.name)))
    }

    /// Fetch → parse → authenticate → cache every configured list, applying the reachability/stale
    /// policy. Returns the freshly-built cache, or the fail-closed error.
    fn refresh_into_cache(&self, fetcher: &mut dyn TrustListFetcher) -> Result<Cache, TrustError> {
        let mut cache = Cache::default();
        for list in &self.lists {
            let Some(bytes) = fetcher.fetch(&list.name) else {
                return Err(TrustError::Unreachable(list.name.clone()));
            };
            let next_update = match &list.format {
                ListFormat::JsonManifest => {
                    let manifest = TrustListManifest::parse(&bytes)
                        .map_err(|e| TrustError::Authentication(format!("{}: {e}", list.name)))?;
                    for (role, format) in manifest.keys() {
                        cache.add_anchors(
                            role,
                            format,
                            manifest.anchors_for(role, format).iter().cloned(),
                        );
                    }
                    manifest.next_update_unix()
                }
                ListFormat::Xml {
                    role,
                    format,
                    service_type,
                } => {
                    let parsed =
                        XmlTrustList::parse(&bytes, *role, *format, service_type.as_deref())
                            .map_err(|e| {
                                TrustError::Authentication(format!("{}: {e}", list.name))
                            })?;
                    self.authenticate_xml(&parsed, list)?;
                    cache.add_anchors(
                        *role,
                        *format,
                        parsed.anchors_for(*role, *format).iter().cloned(),
                    );
                    parsed.next_update_unix()
                }
            };
            // Stale check (TS 119 612 cl. 5.3.15 NextUpdate). The handling is asymmetric by list kind
            // (verified online against TS 119 615 v1.4.1):
            // - LOTL (PRO-4.1.4-13): a passed NextUpdate is FATAL — void the LOTL and stop.
            // - National TL (PRO-4.2.4-10/12): a passed NextUpdate is a non-fatal WARNING — the list
            //   still authenticates and stays usable, so the engine records a warning and keeps the
            //   anchors. (Mirrors EU DSS `TLExpirationDetection`'s configurable warning.)
            if self.now_unix >= next_update {
                match list.kind {
                    ListKind::Lotl => return Err(TrustError::Stale(list.name.clone())),
                    ListKind::National => cache.warnings.push(format!(
                        "national trusted list '{}' is past its NextUpdate \
                         (non-fatal WARNING_EUTL_NEXTUPDATE_PASSED — TS 119 615 v1.4.1 PRO-4.2.4-10)",
                        list.name
                    )),
                }
            } else if matches!(list.kind, ListKind::Lotl) {
                // Only a non-stale LOTL contributes the fatal freshness bound that gates `resolve`.
                cache.lotl_next_update = Some(
                    cache
                        .lotl_next_update
                        .map_or(next_update, |e| e.min(next_update)),
                );
            }
        }
        cache.populated = true;
        Ok(cache)
    }

    /// Whether the cache is currently usable: a refresh populated it AND no **LOTL** freshness bound has
    /// passed (`now` before the earliest LOTL `NextUpdate`). A national-only cache (no LOTL bound) stays
    /// usable past a national `NextUpdate` — that staleness is a non-fatal warning (TS 119 615
    /// PRO-4.2.4-10), not a resolve-blocking condition.
    fn cache_is_fresh(&self) -> bool {
        self.cache.populated
            && self
                .cache
                .lotl_next_update
                .is_none_or(|next| self.now_unix < next)
    }
}

impl NativeTrustEngine {
    /// Host-driven refresh against a supplied [`TrustListFetcher`].
    ///
    /// This is the production refresh entry point: the trait's [`TrustAnchorSource::refresh`] takes
    /// no fetcher (it is the sans-IO seam), so the host calls this with its own fetcher.
    ///
    /// # Errors
    ///
    /// Returns [`TrustError::Unreachable`] / [`TrustError::Stale`] / [`TrustError::Authentication`]
    /// per the reachability/stale policy. Under [`Reachability::FailClosed`] the cache is cleared on
    /// any failure (no stale trust); under [`Reachability::BestEffort`] the last-known-good cache is
    /// kept on an unreachable/LOTL-stale list. A national-TL staleness is never a failure (it is a
    /// recorded warning — [`Self::warnings`]).
    pub fn refresh_with(&mut self, fetcher: &mut dyn TrustListFetcher) -> Result<(), TrustError> {
        match self.refresh_into_cache(fetcher) {
            Ok(cache) => {
                self.cache = cache;
                Ok(())
            }
            Err(err) => {
                match (self.reachability, &err) {
                    // Best-effort tolerates unreachable/stale by keeping the last-known-good cache;
                    // an authentication failure is never tolerated (a forged list must not stand).
                    (
                        Reachability::BestEffort,
                        TrustError::Unreachable(_) | TrustError::Stale(_),
                    ) => {}
                    // Fail-closed (default), or any authentication failure: drop the cache so a
                    // later resolve cannot serve stale/empty/forged trust.
                    _ => self.cache = Cache::default(),
                }
                Err(err)
            }
        }
    }
}

impl TrustAnchorSource for NativeTrustEngine {
    fn resolve(
        &self,
        role: IssuerRole,
        format: Format,
        issuer_cert_der: &[u8],
        supplied_intermediates: &[Vec<u8>],
        leaf_validity_time: Option<i64>,
    ) -> TrustDecision {
        // Fail-closed at resolve time too: if the cache is not usable (never refreshed, or a LOTL
        // freshness bound has passed at the current clock), do not serve it — an out-of-date LOTL
        // cannot anchor trust.
        if !self.cache_is_fresh() {
            return TrustDecision::untrusted();
        }
        // Validate the credential's signing path (leaf + supplied intermediates) against the cached
        // anchors for its role/format (the shared, single-source resolve body — DRY).
        super::resolve_chain(
            self.cache.anchors.get(&(role, format)),
            role,
            format,
            issuer_cert_der,
            supplied_intermediates,
            self.now_unix,
            super::LeafCheck {
                validity_time: leaf_validity_time,
                purpose: super::credential_leaf_purpose(role, format),
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
        // Fail-closed at resolve time (as `resolve`): a stale/never-refreshed cache anchors nothing.
        if !self.cache_is_fresh() {
            return TrustDecision::untrusted();
        }
        // Chain-validate a DISTINCT status-list signer to the SAME cached anchors, with NO
        // credential-leaf purpose (`TrustListSigner`); the status-signing EKU is the caller's gate.
        super::resolve_chain(
            self.cache.anchors.get(&(role, format)),
            role,
            format,
            signer_leaf_der,
            supplied_intermediates,
            self.now_unix,
            super::LeafCheck {
                validity_time: None,
                purpose: crate::trust::chain::LeafPurpose::TrustListSigner,
            },
        )
    }

    /// The sans-IO trait refresh has no fetcher seam, so it cannot fetch; production refresh goes
    /// through [`Self::refresh_with`]. Calling this without a prior `refresh_with` leaves the cache
    /// empty (fail-closed): a refresh that cannot reach any list is, by definition, unreachable.
    fn refresh(&mut self) -> Result<(), TrustError> {
        if self.lists.is_empty() {
            return Ok(());
        }
        // No fetcher was supplied via the trait method; the host must use `refresh_with`. Treat the
        // bare trait call as "no list reachable" → fail-closed.
        Err(TrustError::Unreachable(
            "NativeTrustEngine::refresh requires a host fetcher (use refresh_with)".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{NativeTrustEngine, TrustListFetcher};
    use crate::trust::{Reachability, TrustAnchorSource, TrustError};
    use crate::types::{Format, IssuerRole};
    use base64ct::{Base64, Encoding as _};
    use std::collections::HashMap;

    const TRUST_LIST_JSON: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/trust-list.json");
    const CA_IACA: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/ca-iaca.cert.der");
    // A QEAA SD-JWT VC issuer leaf (QcCompliance + QcType id-etsi-qct-eseal), chains to ca-iaca. The
    // engine resolves SD-JWT VC issuers under IssuerRole::Qeaa, so the per-role QcStatement guard
    // requires a qualified-EAA cert here (the PID `sdjwt-issuer` would be rejected as a QEAA).
    const QEAA_ISSUER: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/qc-qeaa-issuer.cert.der");
    const MDOC_DS: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/mdoc-ds.cert.der");
    const WRONG_ISSUER: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/wrong-issuer.cert.der");

    // A `now` comfortably inside the fixtures' validity (leaf 2026-06-25..2027-09-23) and before
    // the 2036 NextUpdate.
    const NOW: i64 = 1_788_220_800; // 2026-09-01
                                    // Past the fixture's NextUpdate (2036) → stale.
    const NOW_STALE: i64 = 2_200_000_000; // year ~2039

    /// A canned in-memory fetcher: maps list names → bytes (absence = unreachable).
    #[derive(Default)]
    struct MapFetcher(HashMap<String, Vec<u8>>);
    impl MapFetcher {
        fn with(mut self, name: &str, bytes: &[u8]) -> Self {
            self.0.insert(name.to_string(), bytes.to_vec());
            self
        }
    }
    impl TrustListFetcher for MapFetcher {
        fn fetch(&mut self, list_name: &str) -> Option<Vec<u8>> {
            self.0.get(list_name).cloned()
        }
    }

    /// An always-unreachable fetcher.
    struct DeadFetcher;
    impl TrustListFetcher for DeadFetcher {
        fn fetch(&mut self, _: &str) -> Option<Vec<u8>> {
            None
        }
    }

    fn json_engine(now: i64, reach: Reachability) -> NativeTrustEngine {
        NativeTrustEngine::new(reach, now).with_json_manifest("test-lotl")
    }

    // --- issuer PRESENT on the anchor → trusted -----------------------------------------------

    #[test]
    fn issuer_present_on_the_anchor_is_trusted() {
        let mut engine = json_engine(NOW, Reachability::FailClosed);
        let mut fetcher = MapFetcher::default().with("test-lotl", TRUST_LIST_JSON);
        engine.refresh_with(&mut fetcher).expect("refresh succeeds");

        // sdjwt-issuer chains to ca-iaca, which is the anchor for (Qeaa, SdJwtVc) + (Pid, SdJwtVc).
        let d = engine.resolve(IssuerRole::Qeaa, Format::SdJwtVc, QEAA_ISSUER, &[], None);
        assert!(d.trusted, "sdjwt-issuer is trusted as QEAA SD-JWT VC");
        let entry = d.entry.expect("trusted carries an entry");
        assert_eq!(entry.role, IssuerRole::Qeaa);
        assert_eq!(entry.format, Format::SdJwtVc);

        // mdoc-ds chains to ca-iaca, the anchor for (Pid, Mdoc).
        assert!(
            engine
                .resolve(IssuerRole::Pid, Format::Mdoc, MDOC_DS, &[], None)
                .trusted
        );
        // The IACA root itself is a direct pin too.
        assert!(
            engine
                .resolve(IssuerRole::Pid, Format::SdJwtVc, CA_IACA, &[], None)
                .trusted
        );
    }

    // --- issuer ABSENT / untrusted → untrusted with reason ------------------------------------

    #[test]
    fn untrusted_issuer_not_chained_is_untrusted() {
        let mut engine = json_engine(NOW, Reachability::FailClosed);
        let mut fetcher = MapFetcher::default().with("test-lotl", TRUST_LIST_JSON);
        engine.refresh_with(&mut fetcher).unwrap();
        // wrong-issuer is self-signed, does not chain to ca-iaca → untrusted, no entry.
        let d = engine.resolve(IssuerRole::Qeaa, Format::SdJwtVc, WRONG_ISSUER, &[], None);
        assert!(!d.trusted);
        assert!(d.entry.is_none());
    }

    #[test]
    fn issuer_trusted_for_one_role_format_is_not_trusted_for_an_unlisted_one() {
        let mut engine = json_engine(NOW, Reachability::FailClosed);
        let mut fetcher = MapFetcher::default().with("test-lotl", TRUST_LIST_JSON);
        engine.refresh_with(&mut fetcher).unwrap();
        // The manifest lists no (PubEaa, SdJwtVc) or (Qeaa, Mdoc) anchor → untrusted there even
        // though the same leaf is trusted for its listed role/format.
        assert!(
            !engine
                .resolve(IssuerRole::PubEaa, Format::SdJwtVc, QEAA_ISSUER, &[], None)
                .trusted
        );
        assert!(
            !engine
                .resolve(IssuerRole::Qeaa, Format::Mdoc, MDOC_DS, &[], None)
                .trusted
        );
    }

    // --- expired/withdrawn ENTRY → untrusted (distinct from stale list) -----------------------

    #[test]
    fn expired_issuer_entry_is_untrusted_while_the_list_stays_fresh() {
        // The list is fresh (NextUpdate 2036), but we evaluate the issuer at a time past the LEAF's
        // own validity window (~15 months from minting). That is an expired *entry*, distinct from a
        // stale list: the list resolves fine, the issuer leaf does not. Use a clock that is still
        // before NextUpdate so the list is NOT stale.
        let now_leaf_expired = 1_900_000_000; // ~2030: before 2036 NextUpdate, past the 15mo leaf.
        let mut engine = json_engine(now_leaf_expired, Reachability::FailClosed);
        let mut fetcher = MapFetcher::default().with("test-lotl", TRUST_LIST_JSON);
        engine
            .refresh_with(&mut fetcher)
            .expect("list is still fresh at 2030");
        let d = engine.resolve(IssuerRole::Qeaa, Format::SdJwtVc, QEAA_ISSUER, &[], None);
        assert!(
            !d.trusted,
            "the issuer leaf is past its validity → untrusted entry"
        );
    }

    // --- unreachable list → fail-closed -------------------------------------------------------

    #[test]
    fn unreachable_list_fails_closed_by_default() {
        let mut engine = json_engine(NOW, Reachability::FailClosed);
        let mut dead = DeadFetcher;
        let err = engine
            .refresh_with(&mut dead)
            .expect_err("unreachable fails closed");
        assert!(matches!(err, TrustError::Unreachable(_)));
        // And the cache is empty → resolve is untrusted (no silent trust).
        assert!(
            !engine
                .resolve(IssuerRole::Qeaa, Format::SdJwtVc, QEAA_ISSUER, &[], None)
                .trusted
        );
    }

    #[test]
    fn unreachable_list_best_effort_keeps_last_known_good() {
        let mut engine = json_engine(NOW, Reachability::BestEffort);
        // First, a good refresh populates the cache.
        let mut good = MapFetcher::default().with("test-lotl", TRUST_LIST_JSON);
        engine.refresh_with(&mut good).unwrap();
        assert!(
            engine
                .resolve(IssuerRole::Qeaa, Format::SdJwtVc, QEAA_ISSUER, &[], None)
                .trusted
        );
        // Then the list goes unreachable: best-effort surfaces the error but keeps the cache.
        let mut dead = DeadFetcher;
        assert!(matches!(
            engine.refresh_with(&mut dead),
            Err(TrustError::Unreachable(_))
        ));
        assert!(
            engine
                .resolve(IssuerRole::Qeaa, Format::SdJwtVc, QEAA_ISSUER, &[], None)
                .trusted,
            "best-effort still serves the last-known-good anchors"
        );
    }

    // --- stale LOTL (reachable, past NextUpdate) → fail-closed (distinct from unreachable) ----

    #[test]
    fn stale_lotl_fails_closed_even_when_reachable() {
        // The list is reachable and parses, but `now` is past its 2036 NextUpdate → Stale, distinct
        // from Unreachable and from an expired entry. It is configured as the LOTL (the default
        // `with_json_manifest`), so a passed NextUpdate is FATAL (TS 119 615 PRO-4.1.4-13).
        let mut engine = json_engine(NOW_STALE, Reachability::FailClosed);
        let mut fetcher = MapFetcher::default().with("test-lotl", TRUST_LIST_JSON);
        let err = engine
            .refresh_with(&mut fetcher)
            .expect_err("stale fails closed");
        assert!(matches!(err, TrustError::Stale(_)), "got {err:?}");
        assert!(
            !engine
                .resolve(IssuerRole::Qeaa, Format::SdJwtVc, QEAA_ISSUER, &[], None)
                .trusted
        );
    }

    #[test]
    fn stale_distinct_from_unreachable_and_expired_entry() {
        // Stale (reachable, past NextUpdate) is a different error than Unreachable...
        let mut stale_engine = json_engine(NOW_STALE, Reachability::FailClosed);
        let mut reachable = MapFetcher::default().with("test-lotl", TRUST_LIST_JSON);
        let stale_err = stale_engine.refresh_with(&mut reachable).unwrap_err();
        assert!(matches!(stale_err, TrustError::Stale(_)));

        let mut unreach_engine = json_engine(NOW_STALE, Reachability::FailClosed);
        let mut dead = DeadFetcher;
        let unreach_err = unreach_engine.refresh_with(&mut dead).unwrap_err();
        assert!(matches!(unreach_err, TrustError::Unreachable(_)));

        // ...and both differ from an expired ENTRY, which is not a refresh error at all (the refresh
        // succeeds; only `resolve` returns untrusted for the out-of-window leaf).
        let mut entry_engine = json_engine(1_900_000_000, Reachability::FailClosed);
        let mut fresh = MapFetcher::default().with("test-lotl", TRUST_LIST_JSON);
        assert!(entry_engine.refresh_with(&mut fresh).is_ok());
        assert!(
            !entry_engine
                .resolve(IssuerRole::Qeaa, Format::SdJwtVc, QEAA_ISSUER, &[], None)
                .trusted
        );
    }

    #[test]
    fn stale_lotl_best_effort_keeps_last_known_good_but_resolve_still_fails_closed() {
        // Best-effort keeps the cache on a stale LOTL refresh, but resolve's own freshness gate (now >=
        // earliest LOTL NextUpdate) still refuses to serve a stale cache → no silent trust.
        let mut engine =
            NativeTrustEngine::new(Reachability::BestEffort, NOW).with_json_manifest("test-lotl");
        let mut fetcher = MapFetcher::default().with("test-lotl", TRUST_LIST_JSON);
        engine.refresh_with(&mut fetcher).unwrap();
        assert!(
            engine
                .resolve(IssuerRole::Qeaa, Format::SdJwtVc, QEAA_ISSUER, &[], None)
                .trusted
        );
        // Advance the clock past NextUpdate; a best-effort stale refresh keeps the cache...
        engine.set_now(NOW_STALE);
        let mut still_reachable = MapFetcher::default().with("test-lotl", TRUST_LIST_JSON);
        assert!(matches!(
            engine.refresh_with(&mut still_reachable),
            Err(TrustError::Stale(_))
        ));
        // ...but resolve refuses the stale cache.
        assert!(
            !engine
                .resolve(IssuerRole::Qeaa, Format::SdJwtVc, QEAA_ISSUER, &[], None)
                .trusted
        );
    }

    // --- national-TL staleness = non-fatal WARNING (TS 119 615 PRO-4.2.4-10/12) — the T5.5 fix ----

    /// Build an offline JSON manifest with a chosen `nextUpdate`, anchoring `ca-iaca` for
    /// `(Qeaa, SdJwtVc)` — used to exercise the national-vs-LOTL staleness asymmetry.
    fn manifest_json(next_update: &str) -> Vec<u8> {
        format!(
            r#"{{"nextUpdate":"{next_update}","anchors":[
              {{"role":"Qeaa","format":"SdJwtVc","anchorCertDerB64":"{ca}"}}]}}"#,
            ca = Base64::encode_string(CA_IACA),
        )
        .into_bytes()
    }

    // 2027-06-01: past a 2027-01 national NextUpdate, but the QEAA leaf (..2027-09-23) is still valid.
    const NOW_2027_06: i64 = 1_811_808_000;
    const STALE_2027_01: &str = "2027-01-01T00:00:00Z";

    #[test]
    fn national_tl_past_next_update_is_a_warning_not_fatal_and_still_resolves() {
        // TS 119 615 PRO-4.2.4-10/12: a national TL past its NextUpdate is a NON-FATAL warning — the
        // list still authenticates + stays usable. The refresh succeeds (no Stale error), records a
        // warning, and `resolve` still serves the (still-valid) QEAA leaf.
        let mut engine = NativeTrustEngine::new(Reachability::FailClosed, NOW_2027_06)
            .with_national_json_manifest("nl-tl");
        let mut fetcher = MapFetcher::default().with("nl-tl", &manifest_json(STALE_2027_01));
        engine
            .refresh_with(&mut fetcher)
            .expect("a stale NATIONAL TL is a warning, not a fatal refresh failure");
        assert!(
            !engine.warnings().is_empty(),
            "the passed national NextUpdate is recorded as a warning"
        );
        assert!(
            engine
                .resolve(IssuerRole::Qeaa, Format::SdJwtVc, QEAA_ISSUER, &[], None)
                .trusted,
            "a stale national TL is still usable (PRO-4.2.4-12 EUTL_VERIFICATION_PASSED)"
        );
    }

    #[test]
    fn the_same_stale_list_as_a_lotl_is_fatal() {
        // The asymmetry (PRO-4.1.4-13): the SAME stale list configured as the LOTL fails closed.
        let mut engine = NativeTrustEngine::new(Reachability::FailClosed, NOW_2027_06)
            .with_json_manifest("eu-lotl");
        let mut fetcher = MapFetcher::default().with("eu-lotl", &manifest_json(STALE_2027_01));
        assert!(matches!(
            engine.refresh_with(&mut fetcher),
            Err(TrustError::Stale(_))
        ));
        assert!(
            !engine
                .resolve(IssuerRole::Qeaa, Format::SdJwtVc, QEAA_ISSUER, &[], None)
                .trusted
        );
    }

    #[test]
    fn a_fresh_refresh_records_no_warnings() {
        let mut engine = json_engine(NOW, Reachability::FailClosed);
        let mut fetcher = MapFetcher::default().with("test-lotl", TRUST_LIST_JSON);
        engine.refresh_with(&mut fetcher).unwrap();
        assert!(
            engine.warnings().is_empty(),
            "a fresh LOTL records no warnings"
        );
    }

    // --- list-signature authentication (tampered/badly-signed list rejected) ------------------

    /// Build a TS 119 612 XML list with one `granted` EAA/Q service listing `service` as the anchor,
    /// signed by `signer`.
    fn xml_list(service: &[u8], signer: &[u8], next_update: &str) -> Vec<u8> {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <SchemeInformation><NextUpdate><dateTime>{nu}</dateTime></NextUpdate></SchemeInformation>
  <TrustServiceProviderList><TrustServiceProvider><TSPServices><TSPService><ServiceInformation>
    <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/EAA/Q</ServiceTypeIdentifier>
    <ServiceDigitalIdentity><DigitalId><X509Certificate>{svc}</X509Certificate></DigitalId></ServiceDigitalIdentity>
    <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus>
  </ServiceInformation></TSPService></TSPServices></TrustServiceProvider></TrustServiceProviderList>
  <ds:Signature><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{sig}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>
</TrustServiceStatusList>"#,
            nu = next_update,
            svc = Base64::encode_string(service),
            sig = Base64::encode_string(signer),
        )
        .into_bytes()
    }

    #[test]
    fn xml_list_signed_by_trusted_scheme_anchor_is_accepted_and_anchors_granted_issuers() {
        // The XML LOTL is "signed" by the IACA root and lists qc-qeaa-issuer as a GRANTED EAA/Q service
        // anchor; the scheme anchor is the IACA root → the test-only chain-only seam accepts the list
        // (production fails closed pending full XAdES — T5.3). The granted service anchor then anchors
        // its own leaf directly (direct pin).
        let xml = xml_list(QEAA_ISSUER, CA_IACA, "2036-06-22T09:11:42Z");
        let mut engine = NativeTrustEngine::new(Reachability::FailClosed, NOW)
            .with_xml_list_chain_only(
                "eu-lotl",
                IssuerRole::Qeaa,
                Format::SdJwtVc,
                vec![CA_IACA.to_vec()],
                None,
            );
        let mut fetcher = MapFetcher::default().with("eu-lotl", &xml);
        engine
            .refresh_with(&mut fetcher)
            .expect("trusted-signer list authenticates via the test chain seam");
        assert!(
            engine
                .resolve(IssuerRole::Qeaa, Format::SdJwtVc, QEAA_ISSUER, &[], None)
                .trusted
        );
    }

    #[test]
    fn xml_list_signed_by_untrusted_signer_is_rejected() {
        // Same list, but "signed" by the wrong-issuer (does not chain to the scheme anchor) →
        // authentication fails (even via the chain seam), fail-closed clears the cache.
        let xml = xml_list(QEAA_ISSUER, WRONG_ISSUER, "2036-06-22T09:11:42Z");
        let mut engine = NativeTrustEngine::new(Reachability::FailClosed, NOW)
            .with_xml_list_chain_only(
                "eu-lotl",
                IssuerRole::Qeaa,
                Format::SdJwtVc,
                vec![CA_IACA.to_vec()],
                None,
            );
        let mut fetcher = MapFetcher::default().with("eu-lotl", &xml);
        let err = engine
            .refresh_with(&mut fetcher)
            .expect_err("untrusted signer rejected");
        assert!(matches!(err, TrustError::Authentication(_)), "got {err:?}");
        assert!(
            !engine
                .resolve(IssuerRole::Qeaa, Format::SdJwtVc, QEAA_ISSUER, &[], None)
                .trusted
        );
    }

    #[test]
    fn xml_list_production_authentication_always_fails_closed() {
        // T5.3: the PRODUCTION `with_xml_list` path fails authentication closed for EVERY XML list —
        // even one whose signer chains to the scheme anchor — because the full enveloped XAdES
        // SignatureValue/exclusive-C14N verification is a documented scope cut. A real LOTL is never
        // trusted on the signing-cert chain alone.
        let xml = xml_list(QEAA_ISSUER, CA_IACA, "2036-06-22T09:11:42Z");
        let mut engine = NativeTrustEngine::new(Reachability::FailClosed, NOW).with_xml_list(
            "eu-lotl",
            IssuerRole::Qeaa,
            Format::SdJwtVc,
            vec![CA_IACA.to_vec()],
            None,
        );
        let mut fetcher = MapFetcher::default().with("eu-lotl", &xml);
        assert!(matches!(
            engine.refresh_with(&mut fetcher),
            Err(TrustError::Authentication(_))
        ));
        assert!(
            !engine
                .resolve(IssuerRole::Qeaa, Format::SdJwtVc, QEAA_ISSUER, &[], None)
                .trusted
        );
    }

    #[test]
    fn xml_list_withdrawn_service_does_not_anchor_via_the_chain_seam() {
        // Even via the test chain seam, a WITHDRAWN service's cert must NOT anchor (T5.1): a list whose
        // only EAA/Q service is `withdrawn` authenticates (signer ok) but carries no anchors → resolve
        // is untrusted.
        let xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <SchemeInformation><NextUpdate><dateTime>2036-06-22T09:11:42Z</dateTime></NextUpdate></SchemeInformation>
  <TrustServiceProviderList><TrustServiceProvider><TSPServices><TSPService><ServiceInformation>
    <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/EAA/Q</ServiceTypeIdentifier>
    <ServiceDigitalIdentity><DigitalId><X509Certificate>{svc}</X509Certificate></DigitalId></ServiceDigitalIdentity>
    <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn</ServiceStatus>
  </ServiceInformation></TSPService></TSPServices></TrustServiceProvider></TrustServiceProviderList>
  <ds:Signature><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{sig}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>
</TrustServiceStatusList>"#,
            svc = Base64::encode_string(QEAA_ISSUER),
            sig = Base64::encode_string(CA_IACA),
        )
        .into_bytes();
        let mut engine = NativeTrustEngine::new(Reachability::FailClosed, NOW)
            .with_xml_list_chain_only(
                "eu-lotl",
                IssuerRole::Qeaa,
                Format::SdJwtVc,
                vec![CA_IACA.to_vec()],
                None,
            );
        let mut fetcher = MapFetcher::default().with("eu-lotl", &xml);
        engine
            .refresh_with(&mut fetcher)
            .expect("the list authenticates (signer ok) — it just carries no granted anchors");
        assert!(
            !engine
                .resolve(IssuerRole::Qeaa, Format::SdJwtVc, QEAA_ISSUER, &[], None)
                .trusted,
            "a withdrawn service must not anchor trust"
        );
    }

    #[test]
    fn tampered_json_manifest_is_rejected_as_authentication_failure() {
        // A manifest that is not parseable surfaces as an authentication failure (fail-closed).
        let mut engine = json_engine(NOW, Reachability::FailClosed);
        let mut fetcher = MapFetcher::default().with("test-lotl", b"{ tampered, not json");
        assert!(matches!(
            engine.refresh_with(&mut fetcher),
            Err(TrustError::Authentication(_))
        ));
    }

    // --- trait-method behaviour ---------------------------------------------------------------

    #[test]
    fn bare_trait_refresh_without_fetcher_fails_closed_when_lists_configured() {
        let mut engine = json_engine(NOW, Reachability::FailClosed);
        assert!(matches!(engine.refresh(), Err(TrustError::Unreachable(_))));
    }

    #[test]
    fn bare_trait_refresh_is_ok_with_no_lists_configured() {
        let mut engine = NativeTrustEngine::new(Reachability::FailClosed, NOW);
        assert!(engine.refresh().is_ok());
    }

    #[test]
    fn resolve_before_any_refresh_is_untrusted() {
        let engine = json_engine(NOW, Reachability::FailClosed);
        assert!(
            !engine
                .resolve(IssuerRole::Qeaa, Format::SdJwtVc, QEAA_ISSUER, &[], None)
                .trusted
        );
    }

    #[test]
    fn clock_seam_advances_staleness_evaluation() {
        // The clock is a behavioral seam (U1): the SAME reachable list refreshes fresh at `NOW`
        // (before its 2036 NextUpdate) but fails closed as Stale once `set_now` advances the clock
        // past NextUpdate — observed through the refresh outcome + a subsequent resolve, not a getter.
        let mut engine = json_engine(NOW, Reachability::FailClosed);
        let mut fetcher = MapFetcher::default().with("test-lotl", TRUST_LIST_JSON);
        engine.refresh_with(&mut fetcher).expect("fresh at NOW");
        assert!(
            engine
                .resolve(IssuerRole::Qeaa, Format::SdJwtVc, QEAA_ISSUER, &[], None)
                .trusted,
            "a fresh list resolves a trusted issuer"
        );

        // Advance the clock past the list's NextUpdate via the seam; the next refresh now sees Stale.
        engine.set_now(NOW_STALE);
        let err = engine
            .refresh_with(&mut fetcher)
            .expect_err("stale once the clock is past NextUpdate");
        assert!(matches!(err, TrustError::Stale(_)), "got {err:?}");
        assert!(
            !engine
                .resolve(IssuerRole::Qeaa, Format::SdJwtVc, QEAA_ISSUER, &[], None)
                .trusted,
            "a fail-closed stale refresh clears trust"
        );
    }
}
