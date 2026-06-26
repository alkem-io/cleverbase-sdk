//! X.509 certification-path validation against trusted anchors (RFC 5280 §6.1; research D5, no
//! hand-rolled crypto).
//!
//! Trust anchoring asks one question: does the credential's signing certificate (the mdoc
//! `IssuerAuth` x5chain leaf or the SD-JWT VC JWS `x5c` leaf) **chain to** a certificate that the
//! configured trust anchor lists for the credential's role/format? This module answers it by
//! reusing the SDK's vetted X.509 stack — `x509-cert` for parsing, `p256`/`ecdsa` + `rsa` for the
//! signature math, `sha2` for the digest — and never hand-rolls crypto (Principle IV / research D1).
//!
//! ## Multi-tier path validation (RFC 5280 §6.1)
//!
//! A credential carries its full signing chain leaf-first: `x5c` / `x5chain = [leaf, intermediate₁,
//! …]`. eIDAS QTSP / EUDI issuer PKIs commonly issue the leaf from an **intermediate sub-CA** that
//! itself chains to the trust-list-pinned root (RFC 5280 permits a path length > 1; ETSI EN 319
//! 411), so a one-hop "anchor must directly issue the leaf" check would **false-reject** a conformant
//! credential. [`verify_chain`] therefore builds and validates a certification path
//! `leaf → intermediate₁ → … → a CONFIGURED ANCHOR` over the **supplied** chain plus the configured
//! anchors, enforcing the §6.1 rules at every hop:
//!
//! - **name chaining (§6.1.3 (a)(4))** — each certificate's `issuer` equals the next-up certificate's
//!   `subject`;
//! - **signature (§6.1.3 (a)(1))** — each certificate's signature verifies under the next-up
//!   certificate's subject public key;
//! - **validity (§6.1.3 (a)(2))** — **every** certificate on the path (leaf, each intermediate, and
//!   the terminating anchor) is within its own `notBefore..notAfter` window at the relevant time;
//! - **CA constraints (§6.1.4 (k)/(n), §4.2.1.9, §4.2.1.3)** — every certificate that **issues** the
//!   next one down (each intermediate and the anchor) is a CA: `basicConstraints` present, **marked
//!   critical**, `cA=TRUE`, and (when `keyUsage` is present) the `keyCertSign` bit set;
//! - **path length (§6.1.4 (m), §4.2.1.9)** — an issuing CA's `pathLenConstraint`, when present,
//!   bounds the number of intermediates that may follow it toward the leaf.
//!
//! The supplied intermediates are **attacker-controlled** path-building material: they are honoured
//! only as candidate issuers and the path is trusted **iff it terminates at a configured anchor**.
//! An attacker who supplies arbitrary intermediates that never reach a trusted anchor is rejected
//! ([`ChainError::IssuerMismatch`] / `SignatureInvalid`), so an attacker cannot manufacture trust by
//! presenting their own chain. The path length is also capped ([`MAX_PATH_LEN`]) so an absurdly long
//! supplied chain cannot turn validation into a denial-of-service.
//!
//! ## Direct pin
//!
//! The matcher also accepts an exact DER-equal certificate (a trusted-list entry that pins a specific
//! certificate — the leaf, or one of the supplied certs — directly). The direct-pin path still
//! enforces that pinned certificate's validity window (an expired pinned cert is rejected, never
//! trusted) but is deliberately **exempt from the CA constraint**: pinning a specific end-entity
//! certificate as trusted is an intentional, distinct trust model.

use der::{Decode as _, Encode as _};
use x509_cert::Certificate;

/// The role/format-appropriate **key purpose** the leaf (the credential's signing certificate) must
/// carry — enforced once, on the leaf, before the path walk, so a genuinely-chained-but-WRONG-PURPOSE
/// leaf is rejected (e.g. a TLS `serverAuth` cert issued under the same trusted root, or an mdoc DS
/// cert presented as the SD-JWT VC issuer leaf).
///
/// A chain that validates structurally (name/signature/CA/validity) is **not** sufficient: RFC 5280
/// and the format profiles constrain *what the leaf may be used for*. The verifier threads the
/// credential's format here (mdoc → [`Self::MdocDocumentSigner`], SD-JWT VC →
/// [`Self::SdJwtVcIssuer`]); the trust-list-signer-authentication call sites (the LOTL / national-TL
/// signer in `trust::xml` and `qualified`) pass [`Self::TrustListSigner`], which imposes no
/// credential-leaf purpose (a TL signer is governed by a different ETSI profile, not the credential
/// leaf profiles below).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeafPurpose {
    /// **ISO/IEC 18013-5:2021 Annex B (Table B.3, mDL document signer certificate).** The Document
    /// Signer leaf MUST carry an `extendedKeyUsage` that includes the mDL-DS key-purpose OID
    /// `id-mso-mdl-DS` = `1.0.18013.5.1.2` ([`OID_MDL_DS`]). The EKU extension is **mandatory** (field
    /// type `m` in Table B.3); ISO does **not** require it marked critical (only the `keyUsage` /
    /// `basicConstraints` rows are `mc`), and RFC 5280 §4.2.1.12 leaves EKU criticality at the issuer's
    /// option, so the criticality is not asserted here — only the OID's presence. A DS leaf lacking the
    /// mdlDS EKU (or carrying only a foreign purpose such as `serverAuth`) is rejected
    /// ([`ChainError::WrongLeafPurpose`]).
    MdocDocumentSigner,
    /// **SD-JWT VC issuer (PID / (Q)EAA) leaf.** No governing specification mandates a specific EKU for
    /// the SD-JWT VC issuer certificate referenced by the JWS `x5c` (verified online: IETF
    /// `draft-ietf-oauth-sd-jwt-vc` §2.5 / RFC 9901 are silent on EKU/keyUsage; OpenID4VC HAIP 1.0
    /// §6.1.1 mandates only chain-to-anchor structure; the EUDI ARF / Commission IRs distinguish issuer
    /// certs by **QcStatement** OIDs and `keyUsage`, never by an EKU; ETSI EN 319 412-2 §4.3.10 even
    /// forbids marking EKU critical and assigns no EKU value). So the enforced policy is the spec's
    /// minimum sensible floor: the leaf **MUST NOT be a CA** (`basicConstraints cA=TRUE` is rejected — a
    /// CA certificate must not double as an end-entity signer), and **if** a `keyUsage` extension is
    /// present it **MUST** assert `digitalSignature` (or `nonRepudiation`/content-commitment — the
    /// signing bits ETSI EN 319 412-2 Types A/B/C all carry); a `keyUsage` that asserts only unrelated
    /// bits (e.g. `keyEncipherment` only) is rejected. No EKU is required.
    SdJwtVcIssuer,
    /// **Trust-list signer authentication** (the LOTL / national Trusted List signer, not a credential
    /// leaf). Imposes no credential-leaf key-purpose constraint — the only requirement is that the
    /// signer chains to a configured scheme-operator anchor (the structural §6.1 path). Used by
    /// `trust::xml` and `qualified` when authenticating a signed trust list.
    TrustListSigner,
}

/// The ISO/IEC 18013-5 mDL Document Signer extended-key-usage OID `id-mso-mdl-DS`
/// (`{iso(1) standard(0) driving-licence(18013) part-5(5) kp(1) mdlDS(2)}`). A conformant mdoc DS leaf
/// MUST list this OID in its `extendedKeyUsage` (ISO/IEC 18013-5:2021 Annex B, Table B.3); it is the
/// purpose [`LeafPurpose::MdocDocumentSigner`] enforces.
pub const OID_MDL_DS: &str = "1.0.18013.5.1.2";

/// Why a candidate issuer certificate failed to chain to a trusted anchor.
///
/// Every rejection carries a specific reason so an untrusted verdict is never opaque. `resolve_chain`
/// folds these to a coarse-but-accurate [`crate::trust::TrustFailure`] on the [`crate::trust::TrustDecision`],
/// which the verifier maps to a [`crate::types::ReasonCode`]: [`Self::LeafExpired`]/[`Self::AnchorExpired`]
/// (a cert outside its validity window) → [`crate::types::ReasonCode::Expired`]; every other variant (no
/// path, bad signature, non-CA, wrong leaf purpose, unsupported algorithm, malformed, over-long) →
/// [`crate::types::ReasonCode::UntrustedIssuer`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainError {
    /// A certificate (leaf, supplied intermediate, or anchor) could not be parsed as DER X.509.
    Malformed(String),
    /// No path could be built: at some hop the current certificate's `issuer` name matched no
    /// candidate issuer's `subject` (neither a supplied intermediate nor a configured anchor), so the
    /// path does not reach a trusted anchor. Also returned when the supplied chain is empty.
    IssuerMismatch,
    /// A certificate's signature did not verify under the name-matching candidate issuer's public key
    /// at some hop on the path (a supplied intermediate or a configured anchor whose subject matched
    /// but whose key did not produce the signature).
    SignatureInvalid,
    /// The supplied certification path is longer than [`MAX_PATH_LEN`] hops — rejected to bound the
    /// validation work an attacker-supplied chain can demand (a denial-of-service guard).
    PathTooLong,
    /// A certificate on the path carries a signature algorithm the SDK does not implement (outside the
    /// EUDI baseline: ES256/384/512 + RSA-PKCS#1v1.5 over SHA-256/384/512).
    UnsupportedAlgorithm(String),
    /// The leaf is outside its own validity window at the relevant time.
    LeafExpired,
    /// An issuing certificate on the path (an intermediate sub-CA or the terminating anchor) is itself
    /// outside its own validity window at the relevant time. Per RFC 5280 §6.1.3 (a)(2) **every**
    /// certificate in the path — each issuing CA included — must be valid at the validation time, so
    /// an expired (or not-yet-valid) intermediate/anchor cannot vouch for an otherwise-in-window
    /// certificate below it.
    AnchorExpired,
    /// An issuing certificate on the path (an intermediate sub-CA or the terminating anchor) does not
    /// assert the CA constraints required to issue certificates: per RFC 5280 §6.1.4 (k)/(n) and
    /// §4.2.1.9 an issuer MUST carry `basicConstraints` **marked critical** with `cA=TRUE`, (when
    /// `keyUsage` is present) the `keyCertSign` bit, and a `pathLenConstraint` (if present) wide enough
    /// for the intermediates that follow it. This closes the "any cert is a CA" gap — a non-CA
    /// (end-entity) certificate cannot act as a path intermediate or anchor. (The direct-pin path,
    /// where the configured anchor *is* the pinned certificate, is exempt: pinning a specific
    /// end-entity certificate as trusted is an intentional, distinct model.)
    NotACa,
    /// The leaf (the credential's signing certificate) does not carry the role/format-appropriate
    /// **key purpose** required by [`LeafPurpose`], so it is genuinely chained to a trusted anchor but
    /// **not fit for the purpose presented**: an mdoc Document Signer leaf lacking the mdlDS EKU
    /// (`1.0.18013.5.1.2`, ISO/IEC 18013-5:2021 Annex B Table B.3), or carrying a foreign purpose (e.g.
    /// TLS `serverAuth`); or an SD-JWT VC issuer leaf that is a CA, or whose present `keyUsage` asserts
    /// no signing bit. This closes the "right chain, wrong purpose" false-accept. Fail-closed on a
    /// malformed/duplicate `extendedKeyUsage` / `keyUsage` extension.
    WrongLeafPurpose,
}

/// The maximum certification-path length [`verify_chain`] will validate: the leaf plus up to seven
/// issuing certificates (intermediates + anchor). RFC 5280 places no hard ceiling on path length, but
/// the EUDI / eIDAS PKIs in scope are shallow (root → at most a small handful of sub-CAs → leaf), so a
/// small cap rejects an absurdly long **attacker-supplied** chain — bounding the validation work it
/// can demand — without rejecting any conformant credential.
pub const MAX_PATH_LEN: usize = 8;

/// A hard ceiling on the **total** number of issued-by ATTEMPTS (the dominant per-candidate
/// signature-verify work) the backtracking path-walk will perform across the whole search, independent
/// of the per-branch [`MAX_PATH_LEN`] depth cap.
///
/// The walk **backtracks** over candidate issuers, so when an attacker supplies many intermediates that
/// all name-match each other (e.g. dozens of mutually-issuing self-issued certs / cross-certificates),
/// the depth-bounded DFS could otherwise explore a combinatorial (worst-case factorial) number of
/// branches — an attacker-multiplied denial-of-service the depth cap alone does not bound. This global
/// budget bounds the total verify work to a fixed ceiling: a conformant credential reaches its anchor
/// after at most a handful of attempts (≤ [`MAX_PATH_LEN`] hops × the few configured anchors +
/// supplied intermediates), far under this budget, so it is never rejected; an adversarial branchy
/// chain that would blow up is cut off as [`ChainError::PathTooLong`]. The value is generous (thousands
/// of attempts) so only a genuinely pathological supplied chain can hit it.
const MAX_NODE_VISITS: u32 = 4096;

impl core::fmt::Display for ChainError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Malformed(e) => write!(f, "certificate is not valid DER X.509: {e}"),
            Self::IssuerMismatch => write!(
                f,
                "certification path does not reach a trusted anchor (an issuer name matched no candidate)"
            ),
            Self::SignatureInvalid => {
                write!(f, "a certificate signature did not verify under its issuer on the path")
            }
            Self::PathTooLong => write!(
                f,
                "certification path exceeds the maximum permitted length ({MAX_PATH_LEN} certificates)"
            ),
            Self::UnsupportedAlgorithm(oid) => {
                write!(f, "unsupported certificate signature algorithm: {oid}")
            }
            Self::LeafExpired => write!(f, "leaf certificate is outside its validity window"),
            Self::AnchorExpired => {
                write!(f, "issuing anchor is outside its own validity window")
            }
            Self::NotACa => write!(
                f,
                "issuing anchor is not a CA (basicConstraints cA=TRUE / keyUsage keyCertSign required)"
            ),
            Self::WrongLeafPurpose => write!(
                f,
                "leaf certificate lacks the required key purpose for its role/format (e.g. mdoc DS EKU id-mso-mdl-DS, or an SD-JWT VC issuer that is a CA / has no signing keyUsage)"
            ),
        }
    }
}

impl std::error::Error for ChainError {}

/// The supported certificate signature algorithms — the EUDI cryptographic baseline (HAIP 1.0 §7;
/// ECCG Agreed Cryptographic Mechanisms v2; ARF Annex 2).
///
/// The mandatory baseline is **ES256** (ECDSA / P-256 / SHA-256) for both formats, with RSA-PKCS#1
/// v1.5 over SHA-256/384/512 allowed. The SDK's vendored EC stack is P-256 (research D1), so
/// ES384/512 (which use P-384/P-521) surface as [`ChainError::UnsupportedAlgorithm`] — an honest
/// "not implemented", never a silent accept; they are deferrable until a Member-State profile needs
/// them (a new curve crate, not hand-rolled crypto). EdDSA is likewise deferred (outside the
/// mandatory baseline).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SigAlg {
    EcdsaP256Sha256,
    RsaSha256,
    RsaSha384,
    RsaSha512,
}

impl SigAlg {
    /// Classify an X.509 `AlgorithmIdentifier` OID against the supported baseline.
    fn from_oid(oid: der::asn1::ObjectIdentifier) -> Result<Self, ChainError> {
        use const_oid::db::rfc5912;
        Ok(match oid {
            x if x == rfc5912::ECDSA_WITH_SHA_256 => Self::EcdsaP256Sha256,
            x if x == rfc5912::SHA_256_WITH_RSA_ENCRYPTION => Self::RsaSha256,
            x if x == rfc5912::SHA_384_WITH_RSA_ENCRYPTION => Self::RsaSha384,
            x if x == rfc5912::SHA_512_WITH_RSA_ENCRYPTION => Self::RsaSha512,
            other => return Err(ChainError::UnsupportedAlgorithm(other.to_string())),
        })
    }
}

/// Whether the supplied certification path `supplied_chain` (leaf-first: `[leaf, intermediate₁, …]`)
/// builds a valid RFC 5280 §6.1 path to **any** of the trusted `anchor_certs_der`, valid at
/// `now_unix`, with the leaf carrying the `leaf_purpose`-appropriate key purpose.
///
/// This is the trust-anchoring primitive. A path is trusted iff, starting from the leaf
/// (`supplied_chain[0]`), it can be walked up — through zero or more of the supplied intermediates —
/// to a certificate that **is** a configured anchor (a direct DER-equal pin) or is **issued by** a
/// configured anchor, enforcing:
///
/// - **leaf key purpose** — the leaf carries the role/format-appropriate purpose required by
///   [`LeafPurpose`] (mdoc DS EKU `id-mso-mdl-DS`; SD-JWT VC issuer not-a-CA + signing `keyUsage`),
///   else [`ChainError::WrongLeafPurpose`]. Checked once, on the leaf, before the walk — a genuinely
///   chained but wrong-purpose leaf (e.g. a TLS `serverAuth` cert under the same root) is rejected;
/// - **direct pin** — a cert byte-equal to a configured anchor terminates the path as trusted, still
///   subject to that cert's own validity window (an expired pinned cert is [`ChainError::LeafExpired`],
///   never trusted), but exempt from the CA constraint (pinning a specific end-entity cert is a
///   deliberate trust model);
/// - **issued-by** — the child's `issuer` equals the issuer's `subject`, the child's signature
///   verifies under the issuer's subject public key, the issuer is a CA (`basicConstraints` present,
///   critical, `cA=TRUE`, `keyCertSign` when `keyUsage` is present, and a `pathLenConstraint` wide
///   enough for the **non-self-issued** intermediates that follow — [`ChainError::NotACa`] otherwise),
///   the issuer is within its validity window
///   ([`ChainError::AnchorExpired`] otherwise), and the child is within its own
///   ([`ChainError::LeafExpired`] for the leaf).
///
/// The walk is a **bounded depth-first search that backtracks** over candidate issuers: when several
/// supplied intermediates name-match the current certificate (e.g. a cross-certificate or an alternate
/// sub-CA), each is tried in turn, and a branch that dead-ends is unwound so an alternate is explored.
/// A conformant credential whose chain reaches a configured anchor via **some** valid path is therefore
/// accepted, even when a greedy first-match would have committed to a dead-end branch. Per RFC 5280
/// §6.1.4 (l) / §4.2.1.9 a **self-issued** intermediate (subject DN == issuer DN, e.g. a key-rollover
/// cert) does not consume path-length budget, so it is not counted toward a CA's `pathLenConstraint`.
///
/// The supplied intermediates are **attacker-controlled**: they are honoured only as candidate
/// issuers, never as trust roots, so a path that never reaches a configured anchor is rejected. The
/// path length is capped at [`MAX_PATH_LEN`] ([`ChainError::PathTooLong`]) to bound the work an
/// attacker-supplied chain can demand. Returns the most specific [`ChainError`] when no path validates.
///
/// # Errors
///
/// Returns [`ChainError`] when the supplied chain is empty or a certificate is malformed, the leaf has
/// the wrong key purpose ([`ChainError::WrongLeafPurpose`]), the path reaches no configured anchor
/// ([`ChainError::IssuerMismatch`]), a signature does not verify, an algorithm is unsupported, an
/// issuing certificate is not a CA or is outside its validity window, the leaf is outside its validity
/// window, or the path exceeds [`MAX_PATH_LEN`].
pub fn verify_chain(
    supplied_chain: &[&[u8]],
    anchor_certs_der: &[Vec<u8>],
    now_unix: i64,
    leaf_purpose: LeafPurpose,
) -> Result<(), ChainError> {
    // The leaf is the head of the supplied chain; the tail are candidate path-building intermediates.
    let (leaf_der, intermediates_der) = supplied_chain
        .split_first()
        .ok_or(ChainError::IssuerMismatch)?;
    let leaf =
        Certificate::from_der(leaf_der).map_err(|e| ChainError::Malformed(format!("leaf: {e}")))?;

    // Parse the supplied intermediates up front (a malformed supplied cert is a hard reject — it is
    // the credential's own claimed path material, not a configuration anchor we can skip past). Each is
    // kept as its `(DER slice, parsed cert)` so the walk can both compare-by-bytes (direct pin) and
    // verify-by-key (issued-by) without re-parsing.
    let mut intermediates: Vec<(&[u8], Certificate)> = Vec::with_capacity(intermediates_der.len());
    for (i, &der) in intermediates_der.iter().enumerate() {
        let cert = Certificate::from_der(der)
            .map_err(|e| ChainError::Malformed(format!("supplied intermediate {i}: {e}")))?;
        intermediates.push((der, cert));
    }

    // Pre-parse the configured anchors ONCE (like the intermediates) so each hop reuses the parsed
    // form instead of re-decoding every anchor per hop (efficiency: the anchors are invariant across
    // the whole walk). A malformed anchor is a CONFIGURATION fault, recorded in `last_err` only if
    // nothing more specific is known but skipped so it cannot mask a valid match (the documented
    // "only-unusable anchors ⇒ IssuerMismatch" contract).
    let mut last_err = ChainError::IssuerMismatch;
    let mut anchors: Vec<(&[u8], Certificate)> = Vec::with_capacity(anchor_certs_der.len());
    for anchor_der in anchor_certs_der {
        match Certificate::from_der(anchor_der) {
            Ok(cert) => anchors.push((anchor_der.as_slice(), cert)),
            Err(e) => {
                record_more_specific(&mut last_err, ChainError::Malformed(format!("anchor: {e}")));
            }
        }
    }

    // The leaf must carry the role/format-appropriate key purpose (mdoc DS EKU / SD-JWT VC issuer
    // not-a-CA + signing keyUsage) — enforced ONCE, on the leaf, before the walk, so a
    // genuinely-chained-but-WRONG-PURPOSE leaf is rejected up front (closing the "right chain, wrong
    // purpose" false-accept). EXCEPTION — a leaf byte-equal to a configured anchor is a deliberate
    // DIRECT PIN: the operator pinned this exact certificate as trusted for this role/format, an
    // intentional, distinct trust decision (the same model that exempts a directly-pinned cert from the
    // issued-by CA constraint). A direct pin is therefore exempt from the leaf-purpose check too — e.g.
    // an operator may pin an IACA root directly. (The pin still enforces the cert's validity window
    // below, so an expired pin is rejected; only the key-purpose floor is the operator's to waive.)
    let leaf_is_direct_pin = anchors.iter().any(|(a, _)| a == leaf_der);
    if !leaf_is_direct_pin {
        leaf_has_purpose(&leaf, leaf_purpose)?;
    }

    // The leaf's own validity is enforced once, before the walk (the issued-by step enforces each
    // promoted intermediate's window as it is promoted).
    if !cert_is_valid_at(&leaf, now_unix) {
        return Err(ChainError::LeafExpired);
    }

    // Walk the path leaf → intermediate → … → anchor as a bounded, BACKTRACKING depth-first search.
    // `used` marks supplied intermediates already on the current branch so a cycle cannot reuse one
    // (and `MAX_PATH_LEN` is a hard ceiling regardless). The walk threads two counters from the leaf
    // (both 0): `pathlen_depth` (non-self-issued intermediates, the input to a CA's `pathLenConstraint`)
    // and `hops` (every promotion, the DoS cap) — see [`walk`].
    let mut used = vec![false; intermediates.len()];
    let ctx = WalkCtx {
        anchors: &anchors,
        intermediates: &intermediates,
        now_unix,
    };
    let mut state = WalkState {
        used: &mut used,
        budget: MAX_NODE_VISITS,
        last_err,
    };
    match walk(&ctx, leaf_der, &leaf, 0, 0, &mut state) {
        WalkResult::Reached => Ok(()),
        WalkResult::DeadEnd => Err(state.last_err),
        WalkResult::TooLong => Err(ChainError::PathTooLong),
    }
}

/// Read-only context shared across every recursive [`walk`] frame: the pre-parsed anchors and
/// supplied intermediates (each as `(DER slice, parsed cert)`) plus the validation instant. Bundling
/// these keeps the recursive signature small and avoids re-threading four invariants through the DFS.
struct WalkCtx<'a> {
    /// Pre-parsed configured anchors (DER slice + parsed cert); a path terminates at any of these.
    anchors: &'a [(&'a [u8], Certificate)],
    /// Pre-parsed supplied intermediates (DER slice + parsed cert) — attacker-controlled path material.
    intermediates: &'a [(&'a [u8], Certificate)],
    /// The verification instant (Unix seconds) every certificate's validity window is checked at.
    now_unix: i64,
}

/// The mutable search state threaded by `&mut` through the recursive [`walk`] (kept in one struct so
/// the DFS signature stays small): the per-branch `used` flags (cycle guard), the global work `budget`
/// (the DoS ceiling, [`MAX_NODE_VISITS`]), and the most-specific failure reason seen so far.
struct WalkState<'a> {
    /// Per-branch consumed-intermediate flags (index-aligned with [`WalkCtx::intermediates`]); set on
    /// descent and cleared on backtrack so a cert is never revisited on the current branch (no cycle).
    used: &'a mut [bool],
    /// The remaining global issued-by-attempt budget; charged per attempt, exhaustion ⇒ `TooLong`.
    budget: u32,
    /// The most specific [`ChainError`] seen across all candidate issuers (surfaced when no path validates).
    last_err: ChainError,
}

/// The outcome of one [`walk`] branch.
enum WalkResult {
    /// A configured anchor was reached on this branch — the path is trusted.
    Reached,
    /// This branch dead-ended (no anchor, every candidate issuer exhausted); `last_err` records why.
    DeadEnd,
    /// This branch hit the [`MAX_PATH_LEN`] cap before reaching an anchor — a hard reject.
    TooLong,
}

/// One recursion of the backtracking certification-path DFS: resolve the issuer of `current`
/// (`current_der` its DER), having already promoted `hops` intermediates below it of which
/// `pathlen_depth` were non-self-issued.
///
/// Two distinct counters are threaded because they answer two distinct questions (RFC 5280
/// distinguishes them — verified online):
/// - **`pathlen_depth`** is the number of **non-self-issued** intermediates already traversed below
///   `current` — the input to an issuing CA's `pathLenConstraint` check (§6.1.4 (l)/(m), §4.2.1.9: a
///   self-issued cert "is not counted when evaluating path length", so it does not consume budget);
/// - **`hops`** is the total number of intermediates promoted on this branch (self-issued **included**)
///   — the denial-of-service guard, bounded by [`MAX_PATH_LEN`] so an attacker cannot make the walk run
///   unbounded by stuffing the supplied chain with self-issued certs (which would never grow
///   `pathlen_depth`). The two must be separate: tying the DoS cap to `pathlen_depth` would let a chain
///   of self-issued certs evade it.
///
/// Termination, in order, mirroring the §6.1 path-build:
/// 1. **direct pin** — `current` is byte-equal to a configured anchor → [`WalkResult::Reached`]
///    (exempt from the CA constraint by design; `current`'s validity is already enforced before this
///    frame).
/// 2. **issued-by an anchor** — a configured anchor name-matches and validly issued `current`
///    (signature + CA constraint for the `pathlen_depth` non-self-issued intermediates below it + the
///    anchor's own validity) → [`WalkResult::Reached`].
/// 3. **issued-by a supplied intermediate** — for EACH unused supplied intermediate that validly issued
///    `current`, recurse with it as the new `current`. A self-issued promoted intermediate increments
///    `hops` but NOT `pathlen_depth` (§6.1.4 (l)). If a branch dead-ends, the intermediate is released
///    (backtrack) and the next candidate is tried; only when every candidate is exhausted does the
///    frame report [`WalkResult::DeadEnd`].
///
/// `state.used` prevents revisiting a supplied cert on the current branch (no cycle), the `hops` cap
/// bounds branch length, and the global `state.budget` (decremented per issued-by attempt) bounds TOTAL
/// work across all branches, so the backtracking search is finite — and cheaply so — even on
/// attacker-supplied material that name-matches combinatorially.
fn walk(
    ctx: &WalkCtx<'_>,
    current_der: &[u8],
    current: &Certificate,
    pathlen_depth: usize,
    hops: usize,
    state: &mut WalkState<'_>,
) -> WalkResult {
    // (a) Direct pin: `current` is byte-equal to a configured anchor → terminate as trusted.
    if ctx.anchors.iter().any(|(a, _)| *a == current_der) {
        return WalkResult::Reached;
    }

    // (b) Issued-by a configured anchor → terminate as trusted (the path reaches a trust root). Compute
    // `current`'s TBS DER ONCE here: it is invariant across every candidate issuer at this hop, so the
    // signature check reuses it rather than re-encoding per candidate (efficiency).
    let Ok(tbs_der) = current.tbs_certificate.to_der() else {
        record_more_specific(
            &mut state.last_err,
            ChainError::Malformed("re-encode TBSCertificate".into()),
        );
        return WalkResult::DeadEnd;
    };
    for (_, anchor) in ctx.anchors {
        // Global work budget: charge one unit per issued-by ATTEMPT (the signature verify is the
        // dominant cost). Exhausting it means the supplied chain × anchors forced more path-building
        // work than any conformant credential needs → a denial-of-service reject.
        match state.budget.checked_sub(1) {
            Some(remaining) => state.budget = remaining,
            None => return WalkResult::TooLong,
        }
        match issued_by(current, &tbs_der, anchor, ctx.now_unix, pathlen_depth) {
            Ok(()) => return WalkResult::Reached,
            Err(e) => record_more_specific(&mut state.last_err, e),
        }
    }

    // DoS cap: stepping to a further intermediate would exceed MAX_PATH_LEN total hops. Report TooLong
    // only when there is in fact an unused intermediate that name-matches (an actual over-long branch);
    // otherwise this is a plain dead-end (no candidate to step to), which must NOT masquerade as
    // PathTooLong.
    if hops >= MAX_PATH_LEN {
        let has_unused_candidate =
            state
                .used
                .iter()
                .zip(ctx.intermediates)
                .any(|(is_used, (_, cand))| {
                    !*is_used && current.tbs_certificate.issuer == cand.tbs_certificate.subject
                });
        return if has_unused_candidate {
            WalkResult::TooLong
        } else {
            WalkResult::DeadEnd
        };
    }

    // (c) Issued-by a supplied intermediate → try EACH unused candidate that validly issued `current`,
    // recursing into it, and BACKTRACK over the rest if a branch dead-ends.
    let mut saw_too_long = false;
    for idx in 0..ctx.intermediates.len() {
        // Resolve through `.get()` (no panicking index — the crate forbids `clippy::indexing_slicing`).
        let Some((cand_der, candidate)) = ctx.intermediates.get(idx) else {
            continue;
        };
        let Some(&is_used) = state.used.get(idx) else {
            continue;
        };
        if is_used {
            continue;
        }
        // Charge the global work budget per issued-by ATTEMPT (the dominant signature-verify cost),
        // bounding the TOTAL work the backtracking search can do across all branches.
        match state.budget.checked_sub(1) {
            Some(remaining) => state.budget = remaining,
            None => return WalkResult::TooLong,
        }
        if let Err(e) = issued_by(current, &tbs_der, candidate, ctx.now_unix, pathlen_depth) {
            record_more_specific(&mut state.last_err, e);
            continue;
        }
        // The candidate validly issued `current` and becomes the new `current`. It always consumes one
        // DoS hop; it consumes a pathLen unit only when it is NOT self-issued (subject DN == issuer DN
        // ⇒ a key-rollover / policy cert that §6.1.4 (l) does not count toward path length).
        let next_pathlen_depth = if is_self_issued(candidate) {
            pathlen_depth
        } else {
            pathlen_depth + 1
        };
        if let Some(flag) = state.used.get_mut(idx) {
            *flag = true;
        }
        match walk(
            ctx,
            cand_der,
            candidate,
            next_pathlen_depth,
            hops + 1,
            state,
        ) {
            WalkResult::Reached => return WalkResult::Reached,
            WalkResult::TooLong => saw_too_long = true,
            WalkResult::DeadEnd => {}
        }
        // Backtrack: release this intermediate so an alternate branch may consider it again.
        if let Some(flag) = state.used.get_mut(idx) {
            *flag = false;
        }
    }
    // No candidate issuer reached an anchor on any branch. Surface TooLong only if the sole obstacle
    // was the length cap (a deeper branch existed but was capped); otherwise this is a dead-end whose
    // specific reason is in `last_err`.
    if saw_too_long {
        WalkResult::TooLong
    } else {
        WalkResult::DeadEnd
    }
}

/// Whether `cert` is **self-issued** per RFC 5280 §6.1: the same distinguished name appears in its
/// `subject` and `issuer` fields (a CA cert issued to itself for key rollover / policy change). A
/// self-issued intermediate is not counted against a CA's `pathLenConstraint` (§6.1.4 (l) / §4.2.1.9).
fn is_self_issued(cert: &Certificate) -> bool {
    cert.tbs_certificate.subject == cert.tbs_certificate.issuer
}

/// Record `candidate` into `last_err` only when it is **more specific** than the current value, so a
/// generic "this isn't the issuer" reason never masks an actionable one already seen. `IssuerMismatch`
/// (a plain name mismatch) and a malformed *anchor* (a configuration fault, not a credential defect)
/// are the least specific: they must not overwrite a recorded `SignatureInvalid` / `NotACa` /
/// `AnchorExpired` / `LeafExpired` / `UnsupportedAlgorithm` from a real name-matching candidate. This
/// preserves the documented contract that a set containing **only** unusable anchors (all name
/// mismatches, or all malformed) yields the "no trusted anchor reached" verdict [`ChainError::IssuerMismatch`].
fn record_more_specific(last_err: &mut ChainError, candidate: ChainError) {
    let is_generic = |e: &ChainError| {
        matches!(e, ChainError::IssuerMismatch)
            || matches!(e, ChainError::Malformed(m) if m.starts_with("anchor:"))
    };
    // Record `candidate` only when it is actionable (NOT generic) and nothing actionable is recorded
    // yet: a generic candidate (a plain name mismatch, or a malformed *anchor* config fault) must
    // neither overwrite an actionable reason nor downgrade the `IssuerMismatch` default — so a set of
    // only-unusable anchors still surfaces "no trusted anchor reached".
    if !is_generic(&candidate) && is_generic(last_err) {
        *last_err = candidate;
    }
}

/// Whether `issuer` validly issued `child` per the RFC 5280 §6.1 issued-by requirements: the child's
/// `issuer` name equals the issuer's `subject` (§6.1.3 (a)(4)), the child's signature verifies under
/// the issuer's subject public key (§6.1.3 (a)(1)), the issuer is a CA wide enough for the
/// `intermediates_following` certs below it (§6.1.4 (k)/(m)/(n), §4.2.1.9, §4.2.1.3), and the issuer is
/// within its own validity window at `now_unix` (§6.1.3 (a)(2)). `child_tbs_der` is the child's
/// re-encoded `TBSCertificate` — computed ONCE per hop by the caller and reused across every candidate
/// issuer (it is invariant of the issuer). The order matters for error specificity: a name mismatch is
/// "not this issuer" (leave `IssuerMismatch`), then signature, then CA constraint, then validity.
fn issued_by(
    child: &Certificate,
    child_tbs_der: &[u8],
    issuer: &Certificate,
    now_unix: i64,
    intermediates_following: usize,
) -> Result<(), ChainError> {
    if child.tbs_certificate.issuer != issuer.tbs_certificate.subject {
        return Err(ChainError::IssuerMismatch);
    }
    verify_signed_under(child, child_tbs_der, issuer)?;
    // The issuer really signed the child — now it must be a CA permitted to do so (basicConstraints
    // critical cA=TRUE + keyCertSign, and a pathLenConstraint wide enough for the intermediates that
    // follow it toward the leaf), and itself be within its validity window at the relevant time.
    if !anchor_asserts_ca(issuer, intermediates_following) {
        return Err(ChainError::NotACa);
    }
    if !cert_is_valid_at(issuer, now_unix) {
        return Err(ChainError::AnchorExpired);
    }
    Ok(())
}

/// Verify `child`'s signature over its (already re-encoded) `child_tbs_der` `TBSCertificate` under the
/// `issuer`'s subject public key, routing the digest+signature through the SDK's existing RustCrypto
/// stack (no hand-rolled crypto). `child_tbs_der` is passed in (computed once per hop) so it is not
/// re-encoded per candidate issuer.
fn verify_signed_under(
    child: &Certificate,
    child_tbs_der: &[u8],
    issuer: &Certificate,
) -> Result<(), ChainError> {
    let alg = SigAlg::from_oid(child.signature_algorithm.oid)?;
    let signature = child
        .signature
        .as_bytes()
        .ok_or_else(|| ChainError::Malformed("certificate signature is not byte-aligned".into()))?;
    let spki_der = issuer
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| ChainError::Malformed(format!("issuer SPKI: {e}")))?;

    match alg {
        SigAlg::EcdsaP256Sha256 => verify_ecdsa_p256(&spki_der, child_tbs_der, signature),
        SigAlg::RsaSha256 => verify_rsa::<sha2::Sha256>(&spki_der, child_tbs_der, signature),
        SigAlg::RsaSha384 => verify_rsa::<sha2::Sha384>(&spki_der, child_tbs_der, signature),
        SigAlg::RsaSha512 => verify_rsa::<sha2::Sha512>(&spki_der, child_tbs_der, signature),
    }
}

/// Whether the leaf carries the role/format-appropriate **key purpose** ([`LeafPurpose`]), using
/// `x509-cert`'s typed `ExtendedKeyUsage` / `KeyUsage` / `BasicConstraints` decoders (no hand-rolled
/// ASN.1). Fail-closed: a malformed or duplicate `extendedKeyUsage` / `keyUsage` / `basicConstraints`
/// extension is rejected (a leaf whose purpose cannot be parsed is not trusted to act in that role).
///
/// - **[`LeafPurpose::MdocDocumentSigner`]** — ISO/IEC 18013-5:2021 Annex B Table B.3: the DS leaf MUST
///   carry `extendedKeyUsage` containing `id-mso-mdl-DS` ([`OID_MDL_DS`]). Absent / unparsable EKU, or
///   an EKU not listing the OID (e.g. only `serverAuth`), is [`ChainError::WrongLeafPurpose`].
///   Criticality is not required (RFC 5280 §4.2.1.12 leaves it at the issuer's option; ISO marks the
///   row `m`, not `mc`).
/// - **[`LeafPurpose::SdJwtVcIssuer`]** — no spec mandates an EKU (verified online). The enforced floor
///   is: the leaf MUST NOT be a CA (`basicConstraints cA=TRUE` ⇒ [`ChainError::WrongLeafPurpose`]); and
///   IF a `keyUsage` extension is present it MUST assert a signing bit (`digitalSignature` or
///   `nonRepudiation`/content-commitment) — a present `keyUsage` with neither is rejected. An absent
///   `keyUsage` is permitted (the spec leaves all usages allowed).
/// - **[`LeafPurpose::TrustListSigner`]** — no credential-leaf purpose constraint (a TL signer is
///   governed by a separate ETSI profile); always accepted by this check.
fn leaf_has_purpose(leaf: &Certificate, purpose: LeafPurpose) -> Result<(), ChainError> {
    use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage};

    match purpose {
        LeafPurpose::TrustListSigner => Ok(()),
        LeafPurpose::MdocDocumentSigner => {
            // The mdlDS key-purpose OID the DS leaf's extendedKeyUsage MUST list.
            let mdl_ds: der::asn1::ObjectIdentifier = OID_MDL_DS
                .parse()
                .map_err(|_| ChainError::WrongLeafPurpose)?;
            match leaf.tbs_certificate.get::<ExtendedKeyUsage>() {
                // EKU present and parsable: it MUST list id-mso-mdl-DS.
                Ok(Some((_critical, eku))) if eku.0.contains(&mdl_ds) => Ok(()),
                // EKU present but does not list the OID, EKU absent, or a parse error (duplicate /
                // malformed) ⇒ not a conformant DS leaf (fail closed).
                _ => Err(ChainError::WrongLeafPurpose),
            }
        }
        LeafPurpose::SdJwtVcIssuer => {
            // The issuer leaf MUST NOT be a CA: a basicConstraints with cA=TRUE (parsable) is rejected;
            // an absent basicConstraints (cA defaults FALSE) or cA=FALSE is fine. A parse error ⇒ fail
            // closed (a leaf whose basicConstraints cannot be decoded is not trusted as an end entity).
            match leaf.tbs_certificate.get::<BasicConstraints>() {
                Ok(Some((_critical, bc))) if bc.ca => return Err(ChainError::WrongLeafPurpose),
                Ok(_) => {}
                Err(_) => return Err(ChainError::WrongLeafPurpose),
            }
            // If keyUsage is present it MUST assert a signing bit (digitalSignature or the
            // content-commitment / nonRepudiation bit — ETSI EN 319 412-2 issuer Types A/B/C). A
            // present keyUsage asserting neither, or an unparsable (duplicate) one, is rejected. Absent
            // keyUsage is permitted (the spec leaves all usages allowed).
            match leaf.tbs_certificate.get::<KeyUsage>() {
                Ok(Some((_critical, ku))) if ku.digital_signature() || ku.non_repudiation() => {
                    Ok(())
                }
                Ok(None) => Ok(()),
                _ => Err(ChainError::WrongLeafPurpose),
            }
        }
    }
}

/// Verify a P-256 / SHA-256 ECDSA certificate signature (DER-encoded `r,s`) over `message` — the
/// EUDI mandatory ES256 baseline. A non-P-256 ECDSA key surfaces as
/// [`ChainError::SignatureInvalid`] (it will not parse as a P-256 verifying key) rather than a
/// silent accept.
fn verify_ecdsa_p256(spki_der: &[u8], message: &[u8], signature: &[u8]) -> Result<(), ChainError> {
    use p256::ecdsa::signature::Verifier as _;
    use spki::DecodePublicKey as _;
    let vk = p256::ecdsa::VerifyingKey::from_public_key_der(spki_der)
        .map_err(|_| ChainError::SignatureInvalid)?;
    let sig =
        p256::ecdsa::Signature::from_der(signature).map_err(|_| ChainError::SignatureInvalid)?;
    vk.verify(message, &sig)
        .map_err(|_| ChainError::SignatureInvalid)
}

/// Verify an RSA-PKCS#1v1.5 certificate signature over `message`, hashed with `D`.
fn verify_rsa<D>(spki_der: &[u8], message: &[u8], signature: &[u8]) -> Result<(), ChainError>
where
    D: sha2::Digest + const_oid::AssociatedOid,
{
    use rsa::signature::Verifier as _;
    use spki::DecodePublicKey as _;
    let pk = rsa::RsaPublicKey::from_public_key_der(spki_der)
        .map_err(|_| ChainError::SignatureInvalid)?;
    let vk = rsa::pkcs1v15::VerifyingKey::<D>::new(pk);
    let sig =
        rsa::pkcs1v15::Signature::try_from(signature).map_err(|_| ChainError::SignatureInvalid)?;
    vk.verify(message, &sig)
        .map_err(|_| ChainError::SignatureInvalid)
}

/// Whether `cert` (leaf **or** issuing anchor) is within its `notBefore..=notAfter` validity window
/// at `now_unix`. Per RFC 5280 §6.1.3 (a)(2) every certificate in the path must satisfy this at the
/// validation time, so the same check applies to the leaf and to the issuing CA.
fn cert_is_valid_at(cert: &Certificate, now_unix: i64) -> bool {
    let validity = &cert.tbs_certificate.validity;
    let not_before = unix_secs_not_before(validity.not_before);
    let not_after = unix_secs_not_after(validity.not_after);
    now_unix >= not_before && now_unix <= not_after
}

/// Whether `anchor` asserts the CA constraints RFC 5280 requires of a certificate that issues other
/// certificates, parsed via `x509-cert`'s typed extension decoders (no hand-rolled ASN.1), where
/// `intermediates_following` is the number of intermediate certificates that follow this one toward
/// the leaf (the input to its `pathLenConstraint` check):
///
/// - **§6.1.4 (k) / §4.2.1.9** — `basicConstraints` MUST be present, **marked critical**, with
///   `cA=TRUE`. §4.2.1.9 states "Conforming CAs MUST include this extension in all CA certificates …
///   and MUST mark this extension as critical", so a non-critical `cA=TRUE` is NOT a conforming CA and
///   is rejected (closing the criticality-ignored gap). A certificate without `basicConstraints`, with
///   `cA=FALSE`, or with a non-critical `basicConstraints` is not a CA and may not issue certificates.
/// - **§6.1.4 (m) / §4.2.1.9** — a present `pathLenConstraint` bounds "the maximum number of
///   non-self-issued intermediate certificates that may follow this certificate in a valid
///   certification path"; reject when `intermediates_following` exceeds it.
/// - **§6.1.4 (n) / §4.2.1.3** — *if* a `keyUsage` extension is present, the `keyCertSign` bit MUST be
///   set. §4.2.1.3 says conforming CAs SHOULD mark `keyUsage` critical, so criticality is not required
///   here (a SHOULD); the load-bearing rule is the `keyCertSign` bit. (When `keyUsage` is absent the
///   spec leaves all usages permitted, so the bit is not required.)
///
/// A malformed or duplicate `basicConstraints` / `keyUsage` extension fails closed (treated as not a
/// CA): a certificate whose constraints cannot be parsed must not be trusted to issue.
fn anchor_asserts_ca(anchor: &Certificate, intermediates_following: usize) -> bool {
    use x509_cert::ext::pkix::{BasicConstraints, KeyUsage};

    // basicConstraints present, CRITICAL, AND cA=TRUE (a parse error, duplicate, absence, non-critical,
    // or cA=FALSE ⇒ not a CA). RFC 5280 §4.2.1.9 requires the extension be marked critical in a CA cert.
    let bc = match anchor.tbs_certificate.get::<BasicConstraints>() {
        Ok(Some((critical, bc))) if critical && bc.ca => bc,
        _ => return false,
    };

    // pathLenConstraint, if present, bounds how many intermediates may follow this CA toward the leaf.
    if let Some(max_following) = bc.path_len_constraint {
        if intermediates_following > usize::from(max_following) {
            return false;
        }
    }

    // keyUsage, if present, MUST assert keyCertSign (parse error ⇒ fail closed; absence ⇒ allowed).
    match anchor.tbs_certificate.get::<KeyUsage>() {
        Ok(Some((_critical, ku))) => ku.key_cert_sign(),
        Ok(None) => true,
        Err(_) => false,
    }
}

/// Clamp an unsigned-seconds X.509 time to `i64`, saturating an unrepresentable value to a supplied
/// **fail-closed** sentinel rather than fail-open.
///
/// A `notAfter` whose seconds overflow `i64` previously saturated to `i64::MAX` — "never expires" —
/// which is fail-OPEN on a validity boundary. The secure default is fail-CLOSED: the caller passes
/// `i64::MAX` for a `notBefore` (an unrepresentable lower bound reads "not yet valid") and `i64::MIN`
/// for a `notAfter` (an unrepresentable upper bound reads "already expired"), so neither boundary can
/// widen validity. Within standard X.509 (`UTCTime`/`GeneralizedTime`, year ≤ 9999) the seconds
/// always fit, so this never fires in practice; it is the boundary's secure default, mirroring the
/// fail-closed datetime parser ([`crate::datetime`]).
fn clamp_secs(secs: u64, on_overflow: i64) -> i64 {
    i64::try_from(secs).unwrap_or(on_overflow)
}

/// X.509 `notBefore` → Unix seconds, failing closed (unrepresentable ⇒ `i64::MAX` = not yet valid).
fn unix_secs_not_before(time: x509_cert::time::Time) -> i64 {
    clamp_secs(time.to_unix_duration().as_secs(), i64::MAX)
}

/// X.509 `notAfter` → Unix seconds, failing closed (unrepresentable ⇒ `i64::MIN` = already expired).
fn unix_secs_not_after(time: x509_cert::time::Time) -> i64 {
    clamp_secs(time.to_unix_duration().as_secs(), i64::MIN)
}

#[cfg(test)]
mod tests {
    use super::{clamp_secs, verify_chain, ChainError, LeafPurpose, SigAlg, MAX_PATH_LEN};
    use der::{Decode as _, Encode as _};
    use x509_cert::Certificate;

    // The structural path-validation tests below predate the leaf key-purpose gate; their leaves are
    // generic CA:FALSE + digitalSignature end-entities (which satisfy the SD-JWT VC issuer purpose), so
    // they exercise the §6.1 path machinery without the EKU gate interfering. The dedicated EKU/purpose
    // tests use the format-specific purposes (`MdocDocumentSigner` / `SdJwtVcIssuer`) explicitly.
    const SDJWT: LeafPurpose = LeafPurpose::SdJwtVcIssuer;
    // The mdoc Document Signer leaf purpose (requires the id-mso-mdl-DS EKU).
    const MDOC: LeafPurpose = LeafPurpose::MdocDocumentSigner;
    // A CA certificate presented directly as the "leaf" (a direct-pin of a root/sub-CA) carries CA
    // semantics, not a credential-leaf purpose; the trust-list-signer purpose imposes no leaf-purpose
    // constraint, the correct gate for these direct-pin-of-a-CA structural tests.
    const SIGNER: LeafPurpose = LeafPurpose::TrustListSigner;

    const CA_IACA: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/ca-iaca.cert.der");
    const SDJWT_ISSUER: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/sdjwt-issuer.cert.der");
    const MDOC_DS: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/mdoc-ds.cert.der");
    const WRONG_ISSUER: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/wrong-issuer.cert.der");
    // Chain-validation negative anchors (RFC 5280 §6.1.3 / §6.1.4): an EXPIRED issuing CA whose leaf
    // is itself in-window (only the anchor is out of its validity window), and a NON-CA "issuer"
    // (basicConstraints CA:FALSE, no keyCertSign) that nonetheless signs a leaf carrying its subject
    // as issuer. The genuine `ca-iaca` set cannot exercise these gates because it is a valid,
    // in-window CA. See tests/fixtures/attestation/gen.sh.
    const EXPIRED_CA: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/expired-ca.cert.der");
    const EXPIRED_CA_LEAF: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/expired-ca-leaf.cert.der");
    const NON_CA: &[u8] = include_bytes!("../../../../tests/fixtures/attestation/non-ca.cert.der");
    const NON_CA_LEAF: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/non-ca-leaf.cert.der");
    // Multi-tier (sub-CA) path fixtures (RFC 5280 §6.1 path length > 1): a dedicated root `mt-root`
    // (CA:TRUE,pathlen:1) anchoring a sub-CA `mt-intermediate` that issues `mt-leaf`, plus broken-hop
    // variants (non-CA intermediate, expired intermediate) and an attacker chain rooted at a
    // self-signed rogue CA. See tests/fixtures/attestation/gen.sh.
    const MT_ROOT: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/mt-root.cert.der");
    const MT_INTERMEDIATE: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/mt-intermediate.cert.der");
    const MT_LEAF: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/mt-leaf.cert.der");
    const MT_NOCA_INTERMEDIATE: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/mt-noca-intermediate.cert.der");
    const MT_NOCA_LEAF: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/mt-noca-leaf.cert.der");
    const MT_EXPIRED_INTERMEDIATE: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/mt-expired-intermediate.cert.der");
    const MT_EXPIRED_LEAF: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/mt-expired-leaf.cert.der");
    const ATTACKER_CA: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/attacker-ca.cert.der");
    const ATTACKER_LEAF: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/attacker-leaf.cert.der");
    // A self-signed CA with NO pathLenConstraint (CA:TRUE + keyCertSign), reusable as the issuer at
    // every hop of a synthetic over-cap chain — the pathLen gate does not short-circuit it, so the
    // length cap (PathTooLong) is the gate that fires. See tests/fixtures/attestation/gen.sh.
    const NOLEN_CA: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/nolen-ca.cert.der");
    const NOLEN_LEAF: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/nolen-leaf.cert.der");
    // Leaf key-purpose (EKU) fixtures, all issued by `mt-root` (a same-root trio): `mt-mdoc-ds` carries
    // the CORRECT mdlDS EKU (1.0.18013.5.1.2), `mt-mdoc-ds-serverauth` carries a FOREIGN serverAuth EKU,
    // and `mt-mdoc-ds-no-eku` carries NO EKU — isolating the leaf-purpose gate (only the EKU differs).
    // See tests/fixtures/attestation/gen.sh.
    const MT_MDOC_DS: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/mt-mdoc-ds.cert.der");
    const MT_MDOC_DS_SERVERAUTH: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/mt-mdoc-ds-serverauth.cert.der");
    const MT_MDOC_DS_NO_EKU: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/mt-mdoc-ds-no-eku.cert.der");
    // Cross-certificate / alternate-intermediate fixtures (backtracking path-walk): `xc-intermediate`
    // and `xc-deadend` share the SAME subject DN and key (so both validly issue `xc-leaf`) but have
    // DIFFERENT issuers — `xc-intermediate` is issued by `mt-root` (reaches the anchor), `xc-deadend` by
    // the rogue `attacker-ca` (a dead-end). Only a backtracking walk reaches mt-root when the dead-end is
    // tried first. See tests/fixtures/attestation/gen.sh.
    const XC_LEAF: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/xc-leaf.cert.der");
    const XC_INTERMEDIATE: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/xc-intermediate.cert.der");
    const XC_DEADEND: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/xc-deadend.cert.der");
    // Self-issued (key-rollover) fixtures (RFC 5280 §6.1.4 (l) / §4.2.1.9: self-issued certs are NOT
    // counted toward pathLenConstraint). Path si-leaf → si-subca → si-rollover → si-root: `si-root`
    // (pathlen:1) and `si-rollover` (SELF-ISSUED — subject DN == issuer DN — pathlen:1) precede the one
    // NON-self-issued sub-CA `si-subca`. Counting the rollover would exceed si-root's pathlen:1; excluding
    // it (per §6.1.4 (l)) the path validates. See tests/fixtures/attestation/gen.sh.
    const SI_ROOT: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/si-root.cert.der");
    const SI_ROLLOVER: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/si-rollover.cert.der");
    const SI_SUBCA: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/si-subca.cert.der");
    const SI_LEAF: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/si-leaf.cert.der");
    // The signing-core RSA PKI (`sha256WithRSAEncryption`): an RSA CA that signs an RSA leaf —
    // exercises the RSA-PKCS#1v1.5 certificate-signature path, which the EC-only attestation
    // fixtures cannot. Reused (DRY) rather than minting a parallel RSA fixture set.
    const RSA_CA: &[u8] = include_bytes!("../../../../tests/fixtures/pki/ca.cert.der");
    const RSA_LEAF: &[u8] = include_bytes!("../../../../tests/fixtures/pki/signer-rsa.cert.der");

    // The fixtures are minted 2026-06-25 and the leaves are valid ~15 months (notBefore
    // 2026-06-25, notAfter 2027-09-23); pick a `now` inside every fixture's window (research D9 /
    // gen.sh DAYS_LEAF=455). The RSA leaf's window (2026-06-22..2028-09-24) also covers this. The
    // negative anchors' in-window leaves use a fixed 2026-01-01..2027-01-01 window that also covers
    // this instant, and the expired CA's window is 2018-01-01..2019-01-01 (long past).
    const NOW: i64 = 1_788_220_800; // 2026-09-01, comfortably inside the fixtures' validity.

    #[test]
    fn issuer_leaf_chains_to_trusted_iaca_root() {
        let anchors = vec![CA_IACA.to_vec()];
        assert!(verify_chain(&[SDJWT_ISSUER], &anchors, NOW, SDJWT).is_ok());
        assert!(verify_chain(&[MDOC_DS], &anchors, NOW, MDOC).is_ok());
    }

    #[test]
    fn self_issued_anchor_is_trusted_as_a_direct_pin() {
        // The root chained against itself: DER-equal direct pin (no issuer step needed).
        let anchors = vec![CA_IACA.to_vec()];
        assert!(verify_chain(&[CA_IACA], &anchors, NOW, SIGNER).is_ok());
    }

    #[test]
    fn expired_direct_pinned_leaf_is_rejected_not_trusted() {
        // A leaf that is byte-equal to a configured anchor (the direct-pin path — reachable for the
        // qualified-gate's TL-signer cert, pinned as both signer and scheme anchor) must STILL be
        // within its validity window. At a time past the cert's notAfter the direct pin must be
        // rejected as expired, not silently trusted (regression guard for the skipped-window bug).
        let anchors = vec![CA_IACA.to_vec()];
        let far_future = 4_000_000_000; // year ~2096, past every fixture's validity.
        assert_eq!(
            verify_chain(&[CA_IACA], &anchors, far_future, SIGNER),
            Err(ChainError::LeafExpired)
        );
    }

    #[test]
    fn leaf_chaining_to_an_expired_ca_anchor_is_rejected_not_trusted() {
        // RFC 5280 §6.1.3 (a)(2): EVERY certificate in the path (the issuing CA included) must be
        // valid at the time of interest. `expired-ca-leaf` is itself in-window at NOW, and its
        // signature verifies under `expired-ca` whose subject matches the leaf's issuer — but the
        // ANCHOR (expired-ca) is past its own notAfter (2018..2019). The leaf must be REJECTED as
        // `AnchorExpired`, never trusted (the anchor-validity-not-enforced fix).
        let anchors = vec![EXPIRED_CA.to_vec()];
        assert_eq!(
            verify_chain(&[EXPIRED_CA_LEAF], &anchors, NOW, SDJWT),
            Err(ChainError::AnchorExpired)
        );
    }

    #[test]
    fn leaf_chaining_to_a_non_ca_anchor_is_rejected_not_trusted() {
        // RFC 5280 §6.1.4 (k)/(n) + §4.2.1.9: an issuing certificate MUST assert basicConstraints
        // cA=TRUE and (if keyUsage is present) keyCertSign. `non-ca` is CA:FALSE with keyUsage
        // digitalSignature only, yet it signs `non-ca-leaf` (whose issuer is the non-ca subject and
        // whose signature verifies under it). The leaf must be REJECTED as `NotACa` — the classic
        // "any cert is a CA" gap — never trusted on the issued-by path.
        let anchors = vec![NON_CA.to_vec()];
        assert_eq!(
            verify_chain(&[NON_CA_LEAF], &anchors, NOW, SDJWT),
            Err(ChainError::NotACa)
        );
    }

    #[test]
    fn direct_pinned_end_entity_leaf_is_trusted_without_a_ca_constraint() {
        // The DIRECT-PIN model (anchor byte-equals the leaf) is a legitimate, distinct trust model:
        // pinning a specific END-ENTITY certificate as trusted is intentional and MUST NOT require
        // cA=TRUE. `sdjwt-issuer` is a CA:FALSE leaf; pinned directly and within its validity window
        // it is trusted as-is (no issued-by CA-constraint applies to the direct pin).
        let anchors = vec![SDJWT_ISSUER.to_vec()];
        assert!(verify_chain(&[SDJWT_ISSUER], &anchors, NOW, SDJWT).is_ok());
        // The non-CA fixture, pinned directly, is likewise trusted (CA constraint is issued-by only).
        let anchors = vec![NON_CA.to_vec()];
        assert!(verify_chain(&[NON_CA], &anchors, NOW, SDJWT).is_ok());
    }

    #[test]
    fn untrusted_leaf_not_chained_is_rejected_with_issuer_mismatch() {
        // wrong-issuer is self-signed under a different name → no anchor subject matches its issuer.
        let anchors = vec![CA_IACA.to_vec()];
        assert_eq!(
            verify_chain(&[WRONG_ISSUER], &anchors, NOW, SDJWT),
            Err(ChainError::IssuerMismatch)
        );
    }

    #[test]
    fn leaf_is_rejected_when_no_anchors_configured() {
        assert_eq!(
            verify_chain(&[SDJWT_ISSUER], &[], NOW, SDJWT),
            Err(ChainError::IssuerMismatch)
        );
    }

    #[test]
    fn empty_supplied_chain_is_rejected() {
        // A supplied chain with no leaf at all cannot validate (defensive: the production callers
        // always supply at least the leaf, but verify_chain must not panic on an empty slice).
        let anchors = vec![CA_IACA.to_vec()];
        assert_eq!(
            verify_chain(&[], &anchors, NOW, SDJWT),
            Err(ChainError::IssuerMismatch)
        );
    }

    #[test]
    fn leaf_outside_its_validity_window_is_rejected_as_expired() {
        // A time past the ~15-month leaf validity (notAfter 2027-09-23) but still WITHIN the IACA
        // root's window (notAfter 2036-06-22) → only the LEAF is expired, so the leaf-validity gate
        // fires (not the anchor-validity gate). The root still matches by name + signature.
        let anchors = vec![CA_IACA.to_vec()];
        let leaf_expired_root_valid = 1_893_456_000; // 2030-01-01: past the leaf, inside the root.
        assert_eq!(
            verify_chain(&[SDJWT_ISSUER], &anchors, leaf_expired_root_valid, SDJWT),
            Err(ChainError::LeafExpired)
        );
    }

    #[test]
    fn malformed_leaf_is_rejected() {
        let anchors = vec![CA_IACA.to_vec()];
        let not_a_cert: &[u8] = b"not a certificate";
        match verify_chain(&[not_a_cert], &anchors, NOW, SDJWT) {
            Err(ChainError::Malformed(_)) => {}
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn tampered_leaf_signature_is_rejected() {
        // Flip the last byte of the issuer leaf's DER (inside its signature BIT STRING) → the
        // signature no longer verifies under the root. Re-parsing succeeds (DER still well-formed
        // enough), but the math fails.
        let mut tampered = SDJWT_ISSUER.to_vec();
        let last = tampered.len() - 1;
        tampered[last] ^= 0xFF;
        let anchors = vec![CA_IACA.to_vec()];
        // Either the DER re-parse fails (Malformed) or the signature fails (SignatureInvalid);
        // both are correct rejections. The fixture flips a signature byte, so it must NOT be Ok.
        assert!(verify_chain(&[tampered.as_slice()], &anchors, NOW, SDJWT).is_err());
    }

    #[test]
    fn error_display_is_specific() {
        assert!(ChainError::IssuerMismatch.to_string().contains("anchor"));
        assert!(ChainError::SignatureInvalid.to_string().contains("verify"));
        assert!(ChainError::PathTooLong.to_string().contains("length"));
        assert!(ChainError::LeafExpired.to_string().contains("validity"));
        assert!(ChainError::AnchorExpired.to_string().contains("validity"));
        assert!(ChainError::NotACa.to_string().contains("CA"));
        assert!(ChainError::WrongLeafPurpose
            .to_string()
            .contains("key purpose"));
        assert!(ChainError::UnsupportedAlgorithm("1.2.3".into())
            .to_string()
            .contains("1.2.3"));
        assert!(ChainError::Malformed("x".into())
            .to_string()
            .contains("DER"));
    }

    #[test]
    fn unrepresentable_validity_bounds_fail_closed() {
        // RFC 5280 §6.1.3 (a)(2) at the i64 boundary: a bound whose seconds overflow i64 must fail
        // CLOSED, never fail OPEN. `clamp_secs` saturates an unrepresentable bound to the supplied
        // rejecting sentinel: notBefore → i64::MAX (reads "not yet valid", since `now >= MAX` is
        // false for every real `now`), notAfter → i64::MIN (reads "already expired", since
        // `now <= MIN` is false). This is the boundary the prior `unwrap_or(i64::MAX)` got WRONG for
        // notAfter (an unrepresentable notAfter saturated to MAX = "never expires" = fail-open).
        // Representable seconds pass through unchanged (the common path).
        assert_eq!(clamp_secs(0, i64::MAX), 0);
        assert_eq!(clamp_secs(1_788_220_800, i64::MIN), 1_788_220_800);
        assert_eq!(
            clamp_secs(i64::MAX as u64, i64::MAX),
            i64::MAX,
            "the largest representable i64 second value round-trips"
        );
        // Unrepresentable seconds (> i64::MAX) saturate to the rejecting sentinel — fail closed.
        let overflow = (i64::MAX as u64) + 1;
        assert_eq!(
            clamp_secs(overflow, i64::MAX),
            i64::MAX,
            "notBefore that overflows i64 → i64::MAX (not-yet-valid) → reject"
        );
        assert_eq!(
            clamp_secs(overflow, i64::MIN),
            i64::MIN,
            "notAfter that overflows i64 → i64::MIN (already-expired) → reject"
        );
        assert_eq!(clamp_secs(u64::MAX, i64::MIN), i64::MIN);
        // End-to-end polarity (documented, not asserted to avoid a constant-assertion lint): a
        // notBefore sentinel of i64::MAX and a notAfter sentinel of i64::MIN both reject every real
        // `now` — `now >= i64::MAX` and `now <= i64::MIN` are both false for any finite instant such
        // as `NOW` — so the window collapses to empty and an unrepresentable bound never widens it.
    }

    #[test]
    fn rsa_leaf_chains_to_trusted_rsa_ca() {
        // Exercises the RSA-PKCS#1v1.5 (SHA-256) certificate-signature verification path.
        let anchors = vec![RSA_CA.to_vec()];
        assert!(verify_chain(&[RSA_LEAF], &anchors, NOW, SDJWT).is_ok());
    }

    #[test]
    fn rsa_leaf_with_wrong_anchor_is_issuer_mismatch() {
        // The RSA leaf's issuer is the RSA CA, not the EC IACA → no name match.
        let anchors = vec![CA_IACA.to_vec()];
        assert_eq!(
            verify_chain(&[RSA_LEAF], &anchors, NOW, SDJWT),
            Err(ChainError::IssuerMismatch)
        );
    }

    #[test]
    fn unsupported_signature_algorithm_is_rejected() {
        // Re-encode the issuer leaf with its signatureAlgorithm OID swapped to Ed25519
        // (1.3.101.112) — outside the implemented baseline → UnsupportedAlgorithm (never a silent
        // accept). The name still matches the root, so the algorithm gate is what fires.
        let mut cert = Certificate::from_der(SDJWT_ISSUER).expect("parse leaf");
        let ed25519: der::asn1::ObjectIdentifier = "1.3.101.112".parse().expect("oid");
        cert.signature_algorithm.oid = ed25519;
        let mangled = cert.to_der().expect("re-encode");
        let anchors = vec![CA_IACA.to_vec()];
        match verify_chain(&[mangled.as_slice()], &anchors, NOW, SDJWT) {
            Err(ChainError::UnsupportedAlgorithm(oid)) => assert_eq!(oid, "1.3.101.112"),
            other => panic!("expected UnsupportedAlgorithm, got {other:?}"),
        }
    }

    #[test]
    fn malformed_anchor_is_skipped_and_a_good_anchor_still_matches() {
        // A malformed anchor in the set must not mask a valid match from a good anchor (the parser
        // records the malformed-anchor error but keeps scanning).
        let anchors = vec![b"garbage anchor".to_vec(), CA_IACA.to_vec()];
        assert!(verify_chain(&[SDJWT_ISSUER], &anchors, NOW, SDJWT).is_ok());
    }

    #[test]
    fn only_a_malformed_anchor_yields_a_specific_error() {
        // With *only* a malformed anchor, no name match is ever seen → IssuerMismatch (the engine
        // surfaces "no trusted anchor", not a parse panic).
        let anchors = vec![b"garbage anchor".to_vec()];
        assert_eq!(
            verify_chain(&[SDJWT_ISSUER], &anchors, NOW, SDJWT),
            Err(ChainError::IssuerMismatch)
        );
    }

    #[test]
    fn verify_rsa_supports_sha256_384_512_digests() {
        use super::verify_rsa;
        use der::Encode as _;
        // The RSA leaf is RSA-SHA256-signed; its TBS verifies under the CA's RSA key with SHA-256.
        let leaf = Certificate::from_der(RSA_LEAF).expect("parse rsa leaf");
        let ca = Certificate::from_der(RSA_CA).expect("parse rsa ca");
        let tbs = leaf.tbs_certificate.to_der().expect("tbs der");
        let sig = leaf.signature.as_bytes().expect("sig bytes");
        let spki = ca
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .expect("spki");
        // SHA-256 path: the genuine signature verifies.
        assert!(verify_rsa::<sha2::Sha256>(&spki, &tbs, sig).is_ok());
        // SHA-384 / SHA-512 paths: the function body runs end-to-end (key+sig parse), and the
        // wrong-digest signature is correctly rejected — covering the generic monomorphisations.
        assert!(verify_rsa::<sha2::Sha384>(&spki, &tbs, sig).is_err());
        assert!(verify_rsa::<sha2::Sha512>(&spki, &tbs, sig).is_err());
        // A malformed SPKI is rejected (not a panic).
        assert!(verify_rsa::<sha2::Sha256>(b"not spki", &tbs, sig).is_err());
    }

    #[test]
    fn verify_ecdsa_p256_rejects_a_non_p256_key() {
        use super::verify_ecdsa_p256;
        // Feeding an RSA SPKI to the P-256 path is a parse failure → SignatureInvalid, never panic.
        let ca = Certificate::from_der(RSA_CA).expect("parse rsa ca");
        let spki = der::Encode::to_der(&ca.tbs_certificate.subject_public_key_info).expect("spki");
        assert_eq!(
            verify_ecdsa_p256(&spki, b"msg", b"sig"),
            Err(ChainError::SignatureInvalid)
        );
    }

    #[test]
    fn anchor_asserts_ca_classifies_ca_and_non_ca_certs() {
        use super::anchor_asserts_ca;
        // The genuine IACA root asserts CRITICAL basicConstraints cA=TRUE + keyUsage keyCertSign → a
        // CA (with no intermediate following it, depth 0).
        let ca = Certificate::from_der(CA_IACA).expect("parse ca-iaca");
        assert!(
            anchor_asserts_ca(&ca, 0),
            "ca-iaca asserts critical cA=TRUE + keyCertSign"
        );
        // The RSA signing CA likewise asserts the CA constraints.
        let rsa_ca = Certificate::from_der(RSA_CA).expect("parse rsa ca");
        assert!(anchor_asserts_ca(&rsa_ca, 0), "the RSA test CA is a CA");
        // The non-CA fixture (CA:FALSE, keyUsage digitalSignature only) is NOT a CA.
        let non_ca = Certificate::from_der(NON_CA).expect("parse non-ca");
        assert!(!anchor_asserts_ca(&non_ca, 0), "CA:FALSE is not a CA");
        // The end-entity leaves (CA:FALSE) are not CAs either.
        let leaf = Certificate::from_der(SDJWT_ISSUER).expect("parse sdjwt-issuer");
        assert!(
            !anchor_asserts_ca(&leaf, 0),
            "an end-entity leaf is not a CA"
        );
    }

    #[test]
    fn anchor_asserts_ca_enforces_path_len_constraint() {
        use super::anchor_asserts_ca;
        // `ca-iaca` carries basicConstraints pathlen:0 → it may issue ONLY end-entity leaves (no
        // intermediate may follow it). depth 0 (issues a leaf directly) is permitted; depth 1 (one
        // intermediate below) exceeds pathLenConstraint and is rejected (§6.1.4 (m) / §4.2.1.9).
        let iaca = Certificate::from_der(CA_IACA).expect("parse ca-iaca");
        assert!(
            anchor_asserts_ca(&iaca, 0),
            "pathlen:0 permits 0 intermediates following"
        );
        assert!(
            !anchor_asserts_ca(&iaca, 1),
            "pathlen:0 rejects 1 intermediate following"
        );
        // `mt-root` carries pathlen:1 → at most one intermediate may follow it. depth 0 and depth 1 are
        // permitted; depth 2 exceeds the constraint and is rejected.
        let mt_root = Certificate::from_der(MT_ROOT).expect("parse mt-root");
        assert!(
            anchor_asserts_ca(&mt_root, 0),
            "pathlen:1 permits 0 intermediates following"
        );
        assert!(
            anchor_asserts_ca(&mt_root, 1),
            "pathlen:1 permits 1 intermediate following"
        );
        assert!(
            !anchor_asserts_ca(&mt_root, 2),
            "pathlen:1 rejects 2 intermediates following (§6.1.4 (m) / §4.2.1.9)"
        );
    }

    #[test]
    fn anchor_asserts_ca_rejects_non_critical_basic_constraints() {
        use super::anchor_asserts_ca;
        use const_oid::db::rfc5280::ID_CE_BASIC_CONSTRAINTS;
        // RFC 5280 §4.2.1.9: a conforming CA MUST mark basicConstraints CRITICAL. Take the genuine IACA
        // root (critical cA=TRUE) and clear the critical flag on its basicConstraints — it must then be
        // rejected as not-a-CA (a non-critical cA=TRUE is not a conforming CA; the criticality-ignored
        // gap fix).
        let mut ca = Certificate::from_der(CA_IACA).expect("parse ca-iaca");
        assert!(
            anchor_asserts_ca(&ca, 0),
            "baseline: critical cA=TRUE is a CA"
        );
        let bc = ca
            .tbs_certificate
            .extensions
            .as_mut()
            .expect("ca-iaca carries extensions")
            .iter_mut()
            .find(|e| e.extn_id == ID_CE_BASIC_CONSTRAINTS)
            .expect("ca-iaca carries basicConstraints");
        assert!(
            bc.critical,
            "fixture invariant: basicConstraints is minted critical"
        );
        bc.critical = false; // make it non-critical (the non-conforming shape §4.2.1.9 forbids).
        assert!(
            !anchor_asserts_ca(&ca, 0),
            "a NON-critical basicConstraints cA=TRUE must NOT be accepted as a CA (§4.2.1.9)"
        );
    }

    #[test]
    fn sig_alg_classifies_the_baseline_oids() {
        use const_oid::db::rfc5912;
        assert_eq!(
            SigAlg::from_oid(rfc5912::ECDSA_WITH_SHA_256),
            Ok(SigAlg::EcdsaP256Sha256)
        );
        assert_eq!(
            SigAlg::from_oid(rfc5912::SHA_256_WITH_RSA_ENCRYPTION),
            Ok(SigAlg::RsaSha256)
        );
        assert_eq!(
            SigAlg::from_oid(rfc5912::SHA_384_WITH_RSA_ENCRYPTION),
            Ok(SigAlg::RsaSha384)
        );
        assert_eq!(
            SigAlg::from_oid(rfc5912::SHA_512_WITH_RSA_ENCRYPTION),
            Ok(SigAlg::RsaSha512)
        );
        // ES384 (P-384) is outside the vendored P-256 stack → unsupported, honestly.
        assert!(matches!(
            SigAlg::from_oid(rfc5912::ECDSA_WITH_SHA_384),
            Err(ChainError::UnsupportedAlgorithm(_))
        ));
    }

    #[test]
    fn anchor_with_an_unparseable_key_usage_fails_closed_as_not_a_ca() {
        use super::anchor_asserts_ca;
        use const_oid::db::rfc5280::ID_CE_KEY_USAGE;
        // A CA whose basicConstraints say cA=TRUE but whose keyUsage extension cannot be decoded must
        // fail CLOSED (treated as not-a-CA), never trusted to issue. `x509-cert`'s typed
        // `get::<KeyUsage>()` returns Err when two keyUsage extensions are present, so duplicate the
        // extension on the genuine IACA root to drive the `Err(_) => false` fail-closed arm.
        let mut ca = Certificate::from_der(CA_IACA).expect("parse ca-iaca");
        let exts = ca
            .tbs_certificate
            .extensions
            .as_mut()
            .expect("ca-iaca carries extensions");
        let ku = exts
            .iter()
            .find(|e| e.extn_id == ID_CE_KEY_USAGE)
            .expect("ca-iaca carries keyUsage")
            .clone();
        exts.push(ku); // a second keyUsage ⇒ get::<KeyUsage>() is Err ⇒ fail closed.
        assert!(
            !anchor_asserts_ca(&ca, 0),
            "a cert with an unparseable (duplicate) keyUsage must fail closed as not-a-CA"
        );
    }

    // =============================================================================================
    // Multi-tier (sub-CA) path validation — RFC 5280 §6.1 path length > 1 over the SUPPLIED chain.
    // =============================================================================================

    #[test]
    fn two_tier_chain_through_intermediate_to_root_is_trusted() {
        // The conformant EUDI shape: x5c/x5chain = [leaf, intermediate] where the leaf is issued by an
        // intermediate sub-CA that chains to the trust-list-pinned root. The full supplied chain must
        // validate to the configured `mt-root` anchor (leaf → intermediate → root). This is the
        // one-hop-only regression: before path validation this was FALSE-REJECTED.
        let anchors = vec![MT_ROOT.to_vec()];
        assert!(
            verify_chain(&[MT_LEAF, MT_INTERMEDIATE], &anchors, NOW, SDJWT).is_ok(),
            "leaf → intermediate sub-CA → configured root must be trusted"
        );
    }

    #[test]
    fn two_tier_chain_rejected_when_root_not_configured() {
        // Same conformant chain, but the configured anchor is the unrelated `ca-iaca`, not `mt-root` —
        // the path cannot reach a configured anchor, so it is untrusted (no false-accept).
        let anchors = vec![CA_IACA.to_vec()];
        assert_eq!(
            verify_chain(&[MT_LEAF, MT_INTERMEDIATE], &anchors, NOW, SDJWT),
            Err(ChainError::IssuerMismatch)
        );
    }

    #[test]
    fn two_tier_chain_without_supplied_intermediate_cannot_reach_the_root() {
        // If the credential omits the intermediate (supplies only the leaf) the path cannot be built:
        // the leaf's issuer is the intermediate, which is neither supplied nor a configured anchor.
        let anchors = vec![MT_ROOT.to_vec()];
        assert_eq!(
            verify_chain(&[MT_LEAF], &anchors, NOW, SDJWT),
            Err(ChainError::IssuerMismatch)
        );
    }

    #[test]
    fn two_tier_chain_with_a_broken_intermediate_signature_is_rejected() {
        // Tamper the intermediate's DER (flip a signature byte) so its OWN signature under mt-root no
        // longer verifies. The leaf still chains to the (tampered) intermediate by name+signature, but
        // the intermediate→root hop fails → the path does not reach the anchor (rejected, not trusted).
        let mut bad_intermediate = MT_INTERMEDIATE.to_vec();
        let last = bad_intermediate.len() - 1;
        bad_intermediate[last] ^= 0xFF;
        let anchors = vec![MT_ROOT.to_vec()];
        assert!(
            verify_chain(
                &[MT_LEAF, bad_intermediate.as_slice()],
                &anchors,
                NOW,
                SDJWT
            )
            .is_err(),
            "a broken intermediate→root signature must not yield a trusted path"
        );
    }

    #[test]
    fn two_tier_chain_with_a_non_ca_intermediate_is_rejected_as_not_a_ca() {
        // RFC 5280 §6.1.4 (k)/(n): a path intermediate MUST be a CA. `mt-noca-intermediate` is CA:FALSE
        // (issued by mt-root) yet issues `mt-noca-leaf`. The leaf chains to it by name+signature, but
        // it cannot act as a path intermediate → NotACa (the CA-constraint gate on the intermediate).
        let anchors = vec![MT_ROOT.to_vec()];
        assert_eq!(
            verify_chain(&[MT_NOCA_LEAF, MT_NOCA_INTERMEDIATE], &anchors, NOW, SDJWT),
            Err(ChainError::NotACa)
        );
    }

    #[test]
    fn two_tier_chain_with_an_expired_intermediate_is_rejected_as_anchor_expired() {
        // RFC 5280 §6.1.3 (a)(2): EVERY certificate on the path must be valid at the time of interest.
        // `mt-expired-intermediate` is a valid CA issued by mt-root but past its own window (2018..2019);
        // its leaf is in-window. The expired intermediate must reject the path (AnchorExpired), even
        // though the leaf's own window is current.
        let anchors = vec![MT_ROOT.to_vec()];
        assert_eq!(
            verify_chain(
                &[MT_EXPIRED_LEAF, MT_EXPIRED_INTERMEDIATE],
                &anchors,
                NOW,
                SDJWT
            ),
            Err(ChainError::AnchorExpired)
        );
    }

    #[test]
    fn attacker_supplied_intermediate_not_reaching_an_anchor_is_untrusted() {
        // The core security property: a supplied intermediate is attacker-controlled path-building
        // material, NEVER a trust root. The attacker presents [attacker-leaf, attacker-ca] where
        // attacker-ca is a self-signed CA that signs attacker-leaf — internally consistent (each hop
        // name-matches + verifies, attacker-ca is a CA) but terminating at a NON-anchor. It must be
        // rejected (the path never reaches the configured mt-root), so an attacker cannot manufacture
        // trust by supplying their own chain.
        let anchors = vec![MT_ROOT.to_vec()];
        assert_eq!(
            verify_chain(&[ATTACKER_LEAF, ATTACKER_CA], &anchors, NOW, SDJWT),
            Err(ChainError::IssuerMismatch),
            "an attacker chain that never reaches a configured anchor must be untrusted"
        );
        // Even configuring ca-iaca as well does not help the attacker — still no reachable anchor.
        let anchors = vec![MT_ROOT.to_vec(), CA_IACA.to_vec()];
        assert!(verify_chain(&[ATTACKER_LEAF, ATTACKER_CA], &anchors, NOW, SDJWT).is_err());
    }

    #[test]
    fn attacker_supplied_intermediate_is_ignored_when_the_leaf_directly_chains_to_an_anchor() {
        // A single-tier leaf that chains DIRECTLY to a configured anchor stays trusted even if the
        // attacker appends a bogus extra "intermediate": the path terminates at the anchor at the first
        // hop, so the trailing junk is never consulted (it is unreachable past the termination).
        let anchors = vec![CA_IACA.to_vec()];
        assert!(
            verify_chain(&[SDJWT_ISSUER, ATTACKER_CA], &anchors, NOW, SDJWT).is_ok(),
            "leaf chaining directly to the anchor is trusted; trailing supplied junk is ignored"
        );
    }

    #[test]
    fn intermediate_directly_pinned_as_an_anchor_is_trusted() {
        // A trusted-list entry may pin the INTERMEDIATE directly (anchor byte-equals mt-intermediate).
        // The leaf chains to the intermediate, which IS a configured anchor → trusted (direct pin of a
        // supplied cert terminates the path).
        let anchors = vec![MT_INTERMEDIATE.to_vec()];
        assert!(
            verify_chain(&[MT_LEAF, MT_INTERMEDIATE], &anchors, NOW, SDJWT).is_ok(),
            "an intermediate pinned directly as an anchor terminates the path as trusted"
        );
    }

    #[test]
    fn single_tier_chains_still_trusted_after_path_validation() {
        // Regression: the existing single-tier sdjwt-issuer / mdoc-ds → ca-iaca chains (the production
        // direct-IACA shape) remain trusted under the new path-validation primitive.
        let anchors = vec![CA_IACA.to_vec()];
        assert!(verify_chain(&[SDJWT_ISSUER], &anchors, NOW, SDJWT).is_ok());
        assert!(verify_chain(&[MDOC_DS], &anchors, NOW, MDOC).is_ok());
    }

    #[test]
    fn an_overlong_supplied_chain_is_rejected_as_path_too_long() {
        // DoS guard: a supplied chain longer than MAX_PATH_LEN must be rejected before the walk runs
        // unbounded. `nolen-ca` is SELF-SIGNED with NO pathLenConstraint (subject == issuer, and it
        // signed itself), so each copy supplied as a fresh entry name-matches AND signature-verifies as
        // the issuer of the previous one and, being a CA the pathLen gate never short-circuits, is
        // promoted — driving the `hops` DoS counter up one per hop. Because nolen-ca is SELF-ISSUED its
        // promotions do NOT grow the pathLen counter (RFC 5280 §6.1.4 (l)), which is exactly why the
        // DoS cap must be a SEPARATE total-hops counter: a self-issued-cert flood would otherwise evade
        // a pathLen-tied cap. With more than MAX_PATH_LEN such promotions and NO configured anchor to
        // terminate at, the hop cap (PathTooLong) fires (rather than NotACa/IssuerMismatch).
        let mut chain: Vec<&[u8]> = vec![NOLEN_LEAF];
        chain.extend(core::iter::repeat_n(NOLEN_CA, MAX_PATH_LEN + 2));
        let anchors = vec![MT_ROOT.to_vec()]; // present but never reached (rogue self-signed chain).
        assert_eq!(
            verify_chain(&chain, &anchors, NOW, SDJWT),
            Err(ChainError::PathTooLong),
            "a supplied chain longer than MAX_PATH_LEN must be rejected as PathTooLong"
        );
    }

    #[test]
    fn a_self_signed_nolen_ca_pinned_directly_is_trusted_but_not_via_an_issued_path() {
        // Coverage anchor for the nolen fixture's positive direction: pinned directly as an anchor the
        // self-signed CA is trusted (direct pin), and its leaf chains to it when it is the configured
        // anchor — confirming the fixture is a well-formed, usable CA (so the cap test's rejection is
        // the LENGTH cap, not a malformed/unusable cert).
        let anchors = vec![NOLEN_CA.to_vec()];
        assert!(verify_chain(&[NOLEN_LEAF, NOLEN_CA], &anchors, NOW, SDJWT).is_ok());
        assert!(verify_chain(&[NOLEN_LEAF], &anchors, NOW, SDJWT).is_ok());
    }

    // =============================================================================================
    // Leaf key-purpose (EKU) enforcement — ISO/IEC 18013-5:2021 Annex B (mdoc DS) + SD-JWT VC issuer.
    // =============================================================================================

    #[test]
    fn genuine_mdoc_ds_with_mdl_ds_eku_is_trusted_as_a_document_signer() {
        // The genuine ca-iaca-rooted DS fixture carries the critical mdlDS EKU (1.0.18013.5.1.2); under
        // the MdocDocumentSigner purpose it chains and is trusted (the EKU-present happy path).
        let anchors = vec![CA_IACA.to_vec()];
        assert!(verify_chain(&[MDOC_DS], &anchors, NOW, MDOC).is_ok());
        // The mt-root-rooted DS fixture (same correct EKU) is likewise trusted under its own root.
        let anchors = vec![MT_ROOT.to_vec()];
        assert!(verify_chain(&[MT_MDOC_DS], &anchors, NOW, MDOC).is_ok());
    }

    #[test]
    fn mdoc_ds_leaf_with_serverauth_eku_is_rejected_as_wrong_purpose() {
        // FALSE-ACCEPT guard: `mt-mdoc-ds-serverauth` chains PERFECTLY to the configured mt-root (same
        // root as the trusted `mt-mdoc-ds`), differing ONLY in its EKU — a foreign TLS serverAuth purpose
        // instead of mdlDS. Presented as an mdoc Document Signer leaf it MUST be rejected as
        // WrongLeafPurpose (ISO/IEC 18013-5 Annex B Table B.3 requires the DS EKU id-mso-mdl-DS), never
        // trusted just because the chain is sound.
        let anchors = vec![MT_ROOT.to_vec()];
        assert_eq!(
            verify_chain(&[MT_MDOC_DS_SERVERAUTH], &anchors, NOW, MDOC),
            Err(ChainError::WrongLeafPurpose),
            "a serverAuth leaf chained to the trusted root is NOT a valid mdoc DS"
        );
    }

    #[test]
    fn mdoc_ds_leaf_without_any_eku_is_rejected_as_wrong_purpose() {
        // The DS EKU is MANDATORY (ISO 18013-5 Annex B field type `m`); a DS leaf with NO EKU at all is
        // rejected even though it chains to the trusted root.
        let anchors = vec![MT_ROOT.to_vec()];
        assert_eq!(
            verify_chain(&[MT_MDOC_DS_NO_EKU], &anchors, NOW, MDOC),
            Err(ChainError::WrongLeafPurpose)
        );
    }

    #[test]
    fn serverauth_leaf_is_accepted_under_the_sdjwt_vc_issuer_purpose() {
        // The SAME serverAuth-EKU leaf, presented as an SD-JWT VC issuer (not an mdoc DS), is NOT
        // rejected for its EKU: no spec mandates an EKU for the SD-JWT VC issuer (verified online), and
        // the floor (not-a-CA + a signing keyUsage) is satisfied (it is CA:FALSE with digitalSignature).
        // This proves the purpose gate is FORMAT-SPECIFIC, not a blanket "must be mdlDS".
        let anchors = vec![MT_ROOT.to_vec()];
        assert!(
            verify_chain(&[MT_MDOC_DS_SERVERAUTH], &anchors, NOW, SDJWT).is_ok(),
            "a serverAuth EKU does not disqualify an SD-JWT VC issuer leaf (no mandated EKU)"
        );
    }

    #[test]
    fn genuine_sdjwt_issuer_is_trusted_under_the_issuer_purpose() {
        // The genuine SD-JWT VC issuer leaf (CA:FALSE, critical digitalSignature keyUsage, no EKU) is
        // trusted under the SdJwtVcIssuer purpose — the not-a-CA + signing-keyUsage floor is met.
        let anchors = vec![CA_IACA.to_vec()];
        assert!(verify_chain(&[SDJWT_ISSUER], &anchors, NOW, SDJWT).is_ok());
    }

    #[test]
    fn a_ca_certificate_presented_as_an_sdjwt_issuer_leaf_is_rejected() {
        // A CA certificate presented as an SD-JWT VC issuer LEAF is rejected (the issuer leaf MUST NOT be
        // a CA — a CA cert must not double as an end-entity signer). `mt-intermediate` is a CA:TRUE sub-CA
        // that CHAINS to the configured `mt-root` (so it is NOT a direct pin — the purpose floor applies);
        // under the SdJwtVcIssuer purpose it is WrongLeafPurpose despite the sound chain.
        let anchors = vec![MT_ROOT.to_vec()];
        assert_eq!(
            verify_chain(&[MT_INTERMEDIATE], &anchors, NOW, SDJWT),
            Err(ChainError::WrongLeafPurpose),
            "a CA certificate that chains to the anchor is still not a valid SD-JWT VC issuer leaf"
        );
    }

    #[test]
    fn a_directly_pinned_ca_root_is_exempt_from_the_leaf_purpose_check() {
        // The DIRECT-PIN exemption: a leaf byte-equal to a configured anchor is a deliberate operator
        // pin, exempt from the leaf-purpose floor (the same model that exempts a direct pin from the CA
        // constraint). An IACA / multi-tier root pinned directly is trusted under the SD-JWT VC issuer
        // purpose even though it is a CA (which the purpose floor would otherwise reject). The validity
        // window is still enforced — only the key-purpose floor is the operator's to waive.
        let anchors = vec![MT_ROOT.to_vec()];
        assert!(
            verify_chain(&[MT_ROOT], &anchors, NOW, SDJWT).is_ok(),
            "a directly-pinned CA root is trusted (purpose check waived for a direct pin)"
        );
        // And a directly-pinned CA root presented under the mdoc DS purpose is likewise exempt from the
        // mandatory-mdlDS-EKU floor (the operator pinned this exact cert).
        assert!(verify_chain(&[MT_ROOT], &anchors, NOW, MDOC).is_ok());
    }

    #[test]
    fn the_trust_list_signer_purpose_imposes_no_leaf_key_purpose_constraint() {
        // The TrustListSigner purpose (used for LOTL / national-TL signer authentication) imposes no
        // credential-leaf key purpose: a CA root pinned directly is trusted, and the serverAuth leaf
        // chained to mt-root is trusted — neither the not-a-CA nor the mdlDS-EKU rule applies.
        let anchors = vec![MT_ROOT.to_vec()];
        assert!(verify_chain(&[MT_ROOT], &anchors, NOW, SIGNER).is_ok());
        assert!(verify_chain(&[MT_MDOC_DS_SERVERAUTH], &anchors, NOW, SIGNER).is_ok());
    }

    #[test]
    fn a_malformed_or_duplicate_leaf_basic_constraints_fails_closed_under_the_issuer_purpose() {
        // Fail-closed: a leaf whose basicConstraints cannot be decoded (two basicConstraints extensions
        // ⇒ the typed `get::<BasicConstraints>()` returns Err) must be rejected under the SD-JWT VC
        // issuer purpose (we cannot prove it is not a CA), never trusted. Duplicate the extension on the
        // genuine issuer leaf and re-encode; it still chains by name+signature, but the purpose gate
        // fails closed first.
        use const_oid::db::rfc5280::ID_CE_BASIC_CONSTRAINTS;
        let mut cert = Certificate::from_der(SDJWT_ISSUER).expect("parse sdjwt-issuer");
        let exts = cert
            .tbs_certificate
            .extensions
            .as_mut()
            .expect("sdjwt-issuer carries extensions");
        let bc = exts
            .iter()
            .find(|e| e.extn_id == ID_CE_BASIC_CONSTRAINTS)
            .expect("sdjwt-issuer carries basicConstraints")
            .clone();
        exts.push(bc); // a second basicConstraints ⇒ get::<BasicConstraints>() is Err ⇒ fail closed.
        let mangled = cert.to_der().expect("re-encode");
        let anchors = vec![CA_IACA.to_vec()];
        assert_eq!(
            verify_chain(&[mangled.as_slice()], &anchors, NOW, SDJWT),
            Err(ChainError::WrongLeafPurpose)
        );
    }

    #[test]
    fn a_malformed_or_duplicate_leaf_key_usage_fails_closed_under_the_issuer_purpose() {
        // Fail-closed: a leaf whose keyUsage cannot be decoded (two keyUsage extensions ⇒ the typed
        // `get::<KeyUsage>()` returns Err) must be rejected under the SD-JWT VC issuer purpose, never
        // trusted. Duplicate the keyUsage extension on the genuine issuer leaf and re-encode.
        use const_oid::db::rfc5280::ID_CE_KEY_USAGE;
        let mut cert = Certificate::from_der(SDJWT_ISSUER).expect("parse sdjwt-issuer");
        let exts = cert
            .tbs_certificate
            .extensions
            .as_mut()
            .expect("sdjwt-issuer carries extensions");
        let ku = exts
            .iter()
            .find(|e| e.extn_id == ID_CE_KEY_USAGE)
            .expect("sdjwt-issuer carries keyUsage")
            .clone();
        exts.push(ku); // a second keyUsage ⇒ get::<KeyUsage>() is Err ⇒ fail closed.
        let mangled = cert.to_der().expect("re-encode");
        // The leaf still chains by name+signature to the root, but the purpose gate fails closed first.
        let anchors = vec![CA_IACA.to_vec()];
        assert_eq!(
            verify_chain(&[mangled.as_slice()], &anchors, NOW, SDJWT),
            Err(ChainError::WrongLeafPurpose)
        );
    }

    // =============================================================================================
    // Backtracking path-walk — an alternate / cross-certified intermediate must not false-reject.
    // =============================================================================================

    #[test]
    fn cross_certified_alternate_intermediate_is_found_by_backtracking() {
        // FALSE-REJECT guard: the supplied x5chain carries TWO intermediates that both validly issue the
        // leaf (same subject DN + same key) — `xc-deadend` (issued by the rogue attacker-ca, reaches no
        // anchor) and `xc-intermediate` (issued by mt-root, reaches the configured anchor). A greedy walk
        // that commits to the FIRST name-matching issuer (xc-deadend, supplied first) dead-ends and
        // false-rejects; a backtracking walk explores xc-intermediate and reaches mt-root. The dead-end
        // is supplied FIRST so the test fails without backtracking.
        let anchors = vec![MT_ROOT.to_vec()];
        assert!(
            verify_chain(
                &[XC_LEAF, XC_DEADEND, XC_INTERMEDIATE],
                &anchors,
                NOW,
                SDJWT
            )
            .is_ok(),
            "a credential reaching the anchor via SOME valid path must be trusted (backtracking)"
        );
        // Order-independence: the same chain with the reaching intermediate first is also trusted.
        assert!(verify_chain(
            &[XC_LEAF, XC_INTERMEDIATE, XC_DEADEND],
            &anchors,
            NOW,
            SDJWT
        )
        .is_ok());
    }

    #[test]
    fn cross_certified_chain_with_only_the_dead_end_intermediate_is_untrusted() {
        // Control: supplying ONLY the dead-end cross-cert (no path to mt-root) is correctly untrusted —
        // backtracking finds NO reaching path, so it does not manufacture trust.
        let anchors = vec![MT_ROOT.to_vec()];
        assert!(
            verify_chain(&[XC_LEAF, XC_DEADEND], &anchors, NOW, SDJWT).is_err(),
            "with no reaching intermediate the cross-cert leaf must stay untrusted"
        );
    }

    #[test]
    fn a_combinatorially_branchy_supplied_chain_is_bounded_not_exponential() {
        // DoS guard for the BACKTRACKING walk: an attacker supplies MANY MUTUALLY-name-matching certs —
        // `nolen-ca` is self-signed (subject DN == issuer DN), so EVERY supplied copy name-matches AND
        // signature-verifies as the issuer of EVERY other copy. A depth-bounded DFS that backtracks over
        // all of them would explore a FACTORIAL number of ordered branches (here ~30!/(30-8)! ≈ 10¹¹).
        // The global MAX_NODE_VISITS budget caps the TOTAL frames visited, so the walk terminates
        // promptly with a reject (PathTooLong) rather than hanging — and never trusts (no anchor is
        // reached). A hang here would be the unbounded-backtracking regression.
        let mut chain: Vec<&[u8]> = vec![NOLEN_LEAF];
        chain.extend(core::iter::repeat_n(NOLEN_CA, 30));
        let anchors = vec![MT_ROOT.to_vec()]; // present but never reached.
        assert_eq!(
            verify_chain(&chain, &anchors, NOW, SDJWT),
            Err(ChainError::PathTooLong),
            "a factorially-branchy attacker chain must be bounded-rejected, not hang or trust"
        );
    }

    // =============================================================================================
    // Self-issued (key-rollover) certificate path-length exclusion — RFC 5280 §6.1.4 (l) / §4.2.1.9.
    // =============================================================================================

    #[test]
    fn a_self_issued_rollover_cert_does_not_count_toward_path_length() {
        // FALSE-REJECT guard (RFC 5280 §6.1.4 (l) / §4.2.1.9): the path
        // si-leaf → si-subca → si-rollover → si-root has TWO intermediates following the pathlen:1 root,
        // but `si-rollover` is SELF-ISSUED (a key-rollover cert: subject DN == issuer DN), which is NOT
        // counted toward pathLenConstraint. The ONLY non-self-issued intermediate is si-subca (1 ≤ 1), so
        // the path validates. Counting the rollover (the bug) would make it 2 > 1 → a wrong NotACa reject.
        let anchors = vec![SI_ROOT.to_vec()];
        assert!(
            verify_chain(&[SI_LEAF, SI_SUBCA, SI_ROLLOVER], &anchors, NOW, SDJWT).is_ok(),
            "a self-issued rollover cert mid-chain must not consume pathLen budget"
        );
    }

    #[test]
    fn the_self_issued_rollover_cert_is_classified_self_issued() {
        use super::is_self_issued;
        // The rollover cert's subject DN equals its issuer DN ⇒ self-issued; si-subca (a normal sub-CA)
        // is not. This is the property the pathLen-exclusion hinges on.
        let rollover = Certificate::from_der(SI_ROLLOVER).expect("parse si-rollover");
        assert!(is_self_issued(&rollover), "si-rollover is self-issued");
        let subca = Certificate::from_der(SI_SUBCA).expect("parse si-subca");
        assert!(!is_self_issued(&subca), "si-subca is not self-issued");
    }
}
