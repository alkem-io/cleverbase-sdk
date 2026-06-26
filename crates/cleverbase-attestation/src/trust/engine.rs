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
//! ## Reachability / stale policy (U1, fail-closed by default)
//!
//! [`refresh`](NativeTrustEngine::refresh) is where the [`Reachability`] policy applies. Three outcomes are kept
//! distinct (the contract's U1 requirement):
//!
//! - **Unreachable** — the [`TrustListFetcher`] could not return bytes ([`TrustError::Unreachable`]).
//! - **Stale** — the fetched list parsed, but its `NextUpdate` is at/before the current clock
//!   ([`TrustError::Stale`]).
//! - **Authentication failure** — a fetched XML list's signing certificate did not chain to a
//!   configured scheme anchor ([`TrustError::Authentication`]).
//!
//! Under [`Reachability::FailClosed`] (the default) any of these fails `refresh` **and** clears the
//! cached anchors, so a subsequent `resolve` cannot serve stale/empty trust (no silent VALID). Under
//! [`Reachability::BestEffort`] an unreachable/stale list keeps the last-known-good cache. All three
//! are distinct from an **expired/withdrawn entry** (a present-but-out-of-window issuer leaf →
//! `resolve` returns untrusted) and from the per-credential status endpoint
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListFormat {
    /// The offline JSON test manifest ([`TrustListManifest`]).
    JsonManifest,
    /// A TS 119 612 trust-list XML ([`XmlTrustList`]); the `(role, format)` every service maps to,
    /// and whether to authenticate on the signing-cert chain alone (the enveloped XML-DSig
    /// `SignatureValue`/C14N check is the remaining production hardening — see [`super::xml`]).
    Xml {
        role: IssuerRole,
        format: Format,
        chain_only: bool,
    },
}

/// One configured trust list: its logical name, encoding, and (for XML) the scheme-operator anchors
/// that authenticate it.
#[derive(Debug, Clone)]
struct ConfiguredList {
    name: String,
    format: ListFormat,
    /// The scheme-operator trust anchors (DER) that an XML list's signing cert must chain to. Empty
    /// for the JSON manifest (which carries no signature — the offline suite trusts its bytes).
    scheme_anchors_der: Vec<Vec<u8>>,
}

/// The cached, authenticated anchors plus the earliest `NextUpdate` across the configured lists.
#[derive(Debug, Clone, Default)]
struct Cache {
    /// Trusted anchor certificates (DER), keyed by `(role, format)`.
    anchors: BTreeMap<(IssuerRole, Format), Vec<Vec<u8>>>,
    /// The earliest `NextUpdate` (Unix seconds) across all cached lists; `None` until first
    /// refresh.
    earliest_next_update: Option<i64>,
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

    /// Configure the offline JSON manifest list under the given logical name (builder-style).
    #[must_use]
    pub fn with_json_manifest(mut self, name: impl Into<String>) -> Self {
        self.lists.push(ConfiguredList {
            name: name.into(),
            format: ListFormat::JsonManifest,
            scheme_anchors_der: Vec::new(),
        });
        self
    }

    /// Configure a TS 119 612 XML trust list under the given logical name, mapping every service it
    /// carries to `(role, format)` and authenticating its signing cert against `scheme_anchors_der`
    /// (builder-style).
    ///
    /// `chain_only` opts into authenticating on the signing-cert chain alone (the enveloped
    /// XML-DSig `SignatureValue`/C14N check is the remaining production hardening — see
    /// [`super::xml`]); with `false`, the list fails authentication closed by default.
    #[must_use]
    pub fn with_xml_list(
        mut self,
        name: impl Into<String>,
        role: IssuerRole,
        format: Format,
        scheme_anchors_der: Vec<Vec<u8>>,
        chain_only: bool,
    ) -> Self {
        self.lists.push(ConfiguredList {
            name: name.into(),
            format: ListFormat::Xml {
                role,
                format,
                chain_only,
            },
            scheme_anchors_der,
        });
        self
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
                    chain_only,
                } => {
                    let parsed = XmlTrustList::parse(&bytes, *role, *format)
                        .map_err(|e| TrustError::Authentication(format!("{}: {e}", list.name)))?;
                    parsed
                        .authenticate(&list.scheme_anchors_der, self.now_unix, *chain_only)
                        .map_err(|e| TrustError::Authentication(format!("{}: {e}", list.name)))?;
                    cache.add_anchors(
                        *role,
                        *format,
                        parsed.anchors_for(*role, *format).iter().cloned(),
                    );
                    parsed.next_update_unix()
                }
            };
            // Stale check (U1): a list at/after its NextUpdate is stale.
            if self.now_unix >= next_update {
                return Err(TrustError::Stale(list.name.clone()));
            }
            cache.earliest_next_update = Some(
                cache
                    .earliest_next_update
                    .map_or(next_update, |e| e.min(next_update)),
            );
        }
        Ok(cache)
    }

    /// Whether the cache is currently fresh (a refresh succeeded and `now` is before the earliest
    /// `NextUpdate`).
    fn cache_is_fresh(&self) -> bool {
        self.cache
            .earliest_next_update
            .is_some_and(|next| self.now_unix < next)
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
    /// kept on an unreachable/stale list.
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
    ) -> TrustDecision {
        // Fail-closed at resolve time too: if the cache is stale (past NextUpdate at the current
        // clock), do not serve it — an out-of-date list cannot anchor trust.
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
    use std::collections::HashMap;

    const TRUST_LIST_JSON: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/trust-list.json");
    const CA_IACA: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/ca-iaca.cert.der");
    const SDJWT_ISSUER: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/sdjwt-issuer.cert.der");
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
        let d = engine.resolve(IssuerRole::Qeaa, Format::SdJwtVc, SDJWT_ISSUER, &[]);
        assert!(d.trusted, "sdjwt-issuer is trusted as QEAA SD-JWT VC");
        let entry = d.entry.expect("trusted carries an entry");
        assert_eq!(entry.role, IssuerRole::Qeaa);
        assert_eq!(entry.format, Format::SdJwtVc);

        // mdoc-ds chains to ca-iaca, the anchor for (Pid, Mdoc).
        assert!(
            engine
                .resolve(IssuerRole::Pid, Format::Mdoc, MDOC_DS, &[])
                .trusted
        );
        // The IACA root itself is a direct pin too.
        assert!(
            engine
                .resolve(IssuerRole::Pid, Format::SdJwtVc, CA_IACA, &[])
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
        let d = engine.resolve(IssuerRole::Qeaa, Format::SdJwtVc, WRONG_ISSUER, &[]);
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
                .resolve(IssuerRole::PubEaa, Format::SdJwtVc, SDJWT_ISSUER, &[])
                .trusted
        );
        assert!(
            !engine
                .resolve(IssuerRole::Qeaa, Format::Mdoc, MDOC_DS, &[])
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
        let d = engine.resolve(IssuerRole::Qeaa, Format::SdJwtVc, SDJWT_ISSUER, &[]);
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
                .resolve(IssuerRole::Qeaa, Format::SdJwtVc, SDJWT_ISSUER, &[])
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
                .resolve(IssuerRole::Qeaa, Format::SdJwtVc, SDJWT_ISSUER, &[])
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
                .resolve(IssuerRole::Qeaa, Format::SdJwtVc, SDJWT_ISSUER, &[])
                .trusted,
            "best-effort still serves the last-known-good anchors"
        );
    }

    // --- stale list (reachable, past NextUpdate) → fail-closed (distinct from unreachable) ----

    #[test]
    fn stale_list_fails_closed_even_when_reachable() {
        // The list is reachable and parses, but `now` is past its 2036 NextUpdate → Stale, distinct
        // from Unreachable and from an expired entry.
        let mut engine = json_engine(NOW_STALE, Reachability::FailClosed);
        let mut fetcher = MapFetcher::default().with("test-lotl", TRUST_LIST_JSON);
        let err = engine
            .refresh_with(&mut fetcher)
            .expect_err("stale fails closed");
        assert!(matches!(err, TrustError::Stale(_)), "got {err:?}");
        assert!(
            !engine
                .resolve(IssuerRole::Qeaa, Format::SdJwtVc, SDJWT_ISSUER, &[])
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
                .resolve(IssuerRole::Qeaa, Format::SdJwtVc, SDJWT_ISSUER, &[])
                .trusted
        );
    }

    #[test]
    fn stale_best_effort_keeps_last_known_good_but_resolve_still_fails_closed() {
        // Best-effort keeps the cache on a stale refresh, but resolve's own freshness gate (now >=
        // earliest NextUpdate) still refuses to serve a stale cache → no silent trust.
        let mut engine =
            NativeTrustEngine::new(Reachability::BestEffort, NOW).with_json_manifest("test-lotl");
        let mut fetcher = MapFetcher::default().with("test-lotl", TRUST_LIST_JSON);
        engine.refresh_with(&mut fetcher).unwrap();
        assert!(
            engine
                .resolve(IssuerRole::Qeaa, Format::SdJwtVc, SDJWT_ISSUER, &[])
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
                .resolve(IssuerRole::Qeaa, Format::SdJwtVc, SDJWT_ISSUER, &[])
                .trusted
        );
    }

    // --- list-signature authentication (tampered/badly-signed list rejected) ------------------

    /// Build a TS 119 612 XML list signed by `signer`, listing `service` as the anchor.
    fn xml_list(service: &[u8], signer: &[u8], next_update: &str) -> Vec<u8> {
        use base64ct::{Base64, Encoding as _};
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <SchemeInformation><NextUpdate><dateTime>{nu}</dateTime></NextUpdate></SchemeInformation>
  <TrustServiceProviderList><TrustServiceProvider><TSPServices><TSPService><ServiceInformation>
    <ServiceDigitalIdentity><DigitalId><X509Certificate>{svc}</X509Certificate></DigitalId></ServiceDigitalIdentity>
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
    fn xml_list_signed_by_trusted_scheme_anchor_is_accepted_and_anchors_issuers() {
        // The XML LOTL is "signed" by the IACA root and lists sdjwt-issuer as a QEAA service anchor;
        // the scheme anchor is the IACA root → chain-only authentication accepts the list.
        let xml = xml_list(SDJWT_ISSUER, CA_IACA, "2036-06-22T09:11:42Z");
        let mut engine = NativeTrustEngine::new(Reachability::FailClosed, NOW).with_xml_list(
            "eu-lotl",
            IssuerRole::Qeaa,
            Format::SdJwtVc,
            vec![CA_IACA.to_vec()],
            true, // chain_only opt-in (XML-DSig SignatureValue/C14N is the remaining hardening)
        );
        let mut fetcher = MapFetcher::default().with("eu-lotl", &xml);
        engine
            .refresh_with(&mut fetcher)
            .expect("trusted-signer list authenticates");
        // The listed service anchor (sdjwt-issuer) now anchors its own leaf directly (direct pin).
        assert!(
            engine
                .resolve(IssuerRole::Qeaa, Format::SdJwtVc, SDJWT_ISSUER, &[])
                .trusted
        );
    }

    #[test]
    fn xml_list_signed_by_untrusted_signer_is_rejected() {
        // Same list, but "signed" by the wrong-issuer (does not chain to the scheme anchor) →
        // authentication fails, fail-closed clears the cache.
        let xml = xml_list(SDJWT_ISSUER, WRONG_ISSUER, "2036-06-22T09:11:42Z");
        let mut engine = NativeTrustEngine::new(Reachability::FailClosed, NOW).with_xml_list(
            "eu-lotl",
            IssuerRole::Qeaa,
            Format::SdJwtVc,
            vec![CA_IACA.to_vec()],
            true,
        );
        let mut fetcher = MapFetcher::default().with("eu-lotl", &xml);
        let err = engine
            .refresh_with(&mut fetcher)
            .expect_err("untrusted signer rejected");
        assert!(matches!(err, TrustError::Authentication(_)), "got {err:?}");
        assert!(
            !engine
                .resolve(IssuerRole::Qeaa, Format::SdJwtVc, SDJWT_ISSUER, &[])
                .trusted
        );
    }

    #[test]
    fn xml_list_default_authentication_fails_closed_without_chain_only_optin() {
        // The default (chain_only = false) fails closed pending the full enveloped XML-DSig check,
        // even when the signer chains — a real LOTL is never trusted on the chain alone by default.
        let xml = xml_list(SDJWT_ISSUER, CA_IACA, "2036-06-22T09:11:42Z");
        let mut engine = NativeTrustEngine::new(Reachability::FailClosed, NOW).with_xml_list(
            "eu-lotl",
            IssuerRole::Qeaa,
            Format::SdJwtVc,
            vec![CA_IACA.to_vec()],
            false,
        );
        let mut fetcher = MapFetcher::default().with("eu-lotl", &xml);
        assert!(matches!(
            engine.refresh_with(&mut fetcher),
            Err(TrustError::Authentication(_))
        ));
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
                .resolve(IssuerRole::Qeaa, Format::SdJwtVc, SDJWT_ISSUER, &[])
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
                .resolve(IssuerRole::Qeaa, Format::SdJwtVc, SDJWT_ISSUER, &[])
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
                .resolve(IssuerRole::Qeaa, Format::SdJwtVc, SDJWT_ISSUER, &[])
                .trusted,
            "a fail-closed stale refresh clears trust"
        );
    }
}
