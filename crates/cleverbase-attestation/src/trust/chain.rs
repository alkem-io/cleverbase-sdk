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

/// Why a candidate issuer certificate failed to chain to a trusted anchor.
///
/// Every rejection carries a specific reason so an untrusted verdict is never opaque (the engine
/// maps these onto [`crate::types::ReasonCode::UntrustedIssuer`] / `Expired`).
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
}

/// The maximum certification-path length [`verify_chain`] will validate: the leaf plus up to seven
/// issuing certificates (intermediates + anchor). RFC 5280 places no hard ceiling on path length, but
/// the EUDI / eIDAS PKIs in scope are shallow (root → at most a small handful of sub-CAs → leaf), so a
/// small cap rejects an absurdly long **attacker-supplied** chain — bounding the validation work it
/// can demand — without rejecting any conformant credential.
pub const MAX_PATH_LEN: usize = 8;

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
/// `now_unix`.
///
/// This is the trust-anchoring primitive. A path is trusted iff, starting from the leaf
/// (`supplied_chain[0]`), it can be walked up — through zero or more of the supplied intermediates —
/// to a certificate that **is** a configured anchor (a direct DER-equal pin) or is **issued by** a
/// configured anchor, enforcing at every hop:
///
/// - **direct pin** — a cert byte-equal to a configured anchor terminates the path as trusted, still
///   subject to that cert's own validity window (an expired pinned cert is [`ChainError::LeafExpired`],
///   never trusted), but exempt from the CA constraint (pinning a specific end-entity cert is a
///   deliberate trust model);
/// - **issued-by** — the child's `issuer` equals the issuer's `subject`, the child's signature
///   verifies under the issuer's subject public key, the issuer is a CA (`basicConstraints` present,
///   critical, `cA=TRUE`, `keyCertSign` when `keyUsage` is present, and a `pathLenConstraint` wide
///   enough for the intermediates that follow — [`ChainError::NotACa`] otherwise), the issuer is
///   within its validity window
///   ([`ChainError::AnchorExpired`] otherwise), and the child is within its own
///   ([`ChainError::LeafExpired`] for the leaf).
///
/// The supplied intermediates are **attacker-controlled**: they are honoured only as candidate
/// issuers, never as trust roots, so a path that never reaches a configured anchor is rejected. The
/// path length is capped at [`MAX_PATH_LEN`] ([`ChainError::PathTooLong`]) to bound the work an
/// attacker-supplied chain can demand. Returns the most specific [`ChainError`] when no path validates.
///
/// # Errors
///
/// Returns [`ChainError`] when the supplied chain is empty or a certificate is malformed, the path
/// reaches no configured anchor ([`ChainError::IssuerMismatch`]), a signature does not verify, an
/// algorithm is unsupported, an issuing certificate is not a CA or is outside its validity window, the
/// leaf is outside its validity window, or the path exceeds [`MAX_PATH_LEN`].
pub fn verify_chain(
    supplied_chain: &[&[u8]],
    anchor_certs_der: &[Vec<u8>],
    now_unix: i64,
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

    // Walk the path leaf → intermediate → … → anchor. `current` is the certificate whose issuer we are
    // resolving; `depth` is the number of intermediates already traversed below it (= the number of
    // intermediates that follow a CA which issues `current`, the input to its pathLenConstraint check).
    // `used` marks supplied intermediates already consumed so a cycle cannot reuse one (and the cap is
    // a hard ceiling regardless). The leaf's own validity is enforced once, before the walk.
    if !cert_is_valid_at(&leaf, now_unix) {
        return Err(ChainError::LeafExpired);
    }
    let mut current_der: &[u8] = leaf_der;
    let mut current = leaf;
    let mut depth: usize = 0;
    let mut used = vec![false; intermediates.len()];
    // Track the most specific failure across all candidate issuers at the current hop.
    let mut last_err = ChainError::IssuerMismatch;

    loop {
        // (a) Direct pin: `current` is byte-equal to a configured anchor → terminate as trusted. The
        // anchor pins this exact certificate; `current`'s validity is already enforced (the leaf
        // before the loop, each promoted intermediate at the issued-by step that promoted it). Exempt
        // from the CA constraint by design.
        if anchor_certs_der.iter().any(|a| a.as_slice() == current_der) {
            return Ok(());
        }

        // (b) Issued-by a configured anchor → terminate as trusted (the path reaches a trust root).
        match issued_by_any(&current, anchor_certs_der, now_unix, depth, &mut last_err) {
            IssuedBy::Verified => return Ok(()),
            IssuedBy::Rejected => {}
        }

        // (c) Issued-by a supplied intermediate → promote it to `current` and continue walking up.
        // The promoted intermediate must itself be a CA, in-window, and have signed `current`.
        let Some(idx) = promote_intermediate(
            &current,
            &intermediates,
            &used,
            now_unix,
            depth,
            &mut last_err,
        ) else {
            // No configured anchor and no unused supplied intermediate issued `current` → the path
            // cannot reach a trusted anchor. Surface the most specific reason seen.
            return Err(last_err);
        };
        // `idx` was just produced by `promote_intermediate` so it indexes a real, unused entry; resolve
        // it through `.get()` (no panicking index — the crate forbids `clippy::indexing_slicing`) and
        // mark it consumed so the walk cannot reuse the same supplied cert.
        let Some(used_flag) = used.get_mut(idx) else {
            return Err(last_err);
        };
        *used_flag = true;
        let Some((next_der, next_cert)) = intermediates.get(idx) else {
            return Err(last_err);
        };
        current_der = next_der;
        current = next_cert.clone();
        depth += 1;
        if depth >= MAX_PATH_LEN {
            return Err(ChainError::PathTooLong);
        }
    }
}

/// Outcome of trying to terminate the path at a configured anchor that issued `current`.
enum IssuedBy {
    /// A configured anchor issued `current` and satisfied every §6.1 requirement — the path is trusted.
    Verified,
    /// No configured anchor both name-matched and satisfied the requirements (`last_err` records why).
    Rejected,
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

/// Try to terminate the path: does **any** configured anchor issue `current` and satisfy the RFC 5280
/// §6.1 issued-by requirements (name chaining, signature, CA constraint incl. `pathLenConstraint` for
/// the `intermediates_following` certs below it, and the anchor's own validity window)? A malformed
/// anchor is a configuration fault recorded in `last_err` (only if nothing more specific is known) but
/// skipped so it cannot mask a valid match.
fn issued_by_any(
    current: &Certificate,
    anchor_certs_der: &[Vec<u8>],
    now_unix: i64,
    intermediates_following: usize,
    last_err: &mut ChainError,
) -> IssuedBy {
    for anchor_der in anchor_certs_der {
        let anchor = match Certificate::from_der(anchor_der) {
            Ok(c) => c,
            Err(e) => {
                record_more_specific(last_err, ChainError::Malformed(format!("anchor: {e}")));
                continue;
            }
        };
        match issued_by(current, &anchor, now_unix, intermediates_following) {
            Ok(()) => return IssuedBy::Verified,
            Err(e) => record_more_specific(last_err, e),
        }
    }
    IssuedBy::Rejected
}

/// Try to promote a supplied intermediate to the next `current`: find an **unused** supplied
/// intermediate that issues `current` (name + signature) and satisfies the issuer requirements (CA
/// constraint incl. `pathLenConstraint`, and its own validity window). Returns its index, recording the
/// most specific failure in `last_err` when a name match is found but a later check rejects it.
fn promote_intermediate(
    current: &Certificate,
    intermediates: &[(&[u8], Certificate)],
    used: &[bool],
    now_unix: i64,
    intermediates_following: usize,
    last_err: &mut ChainError,
) -> Option<usize> {
    for (idx, (is_used, (_, candidate))) in used.iter().zip(intermediates.iter()).enumerate() {
        if *is_used {
            continue;
        }
        match issued_by(current, candidate, now_unix, intermediates_following) {
            Ok(()) => return Some(idx),
            Err(e) => record_more_specific(last_err, e),
        }
    }
    None
}

/// Whether `issuer` validly issued `child` per the RFC 5280 §6.1 issued-by requirements: the child's
/// `issuer` name equals the issuer's `subject` (§6.1.3 (a)(4)), the child's signature verifies under
/// the issuer's subject public key (§6.1.3 (a)(1)), the issuer is a CA wide enough for the
/// `intermediates_following` certs below it (§6.1.4 (k)/(m)/(n), §4.2.1.9, §4.2.1.3), and the issuer is
/// within its own validity window at `now_unix` (§6.1.3 (a)(2)). The order matters for error
/// specificity: a name mismatch is "not this issuer" (leave `IssuerMismatch`), then signature, then CA
/// constraint, then validity.
fn issued_by(
    child: &Certificate,
    issuer: &Certificate,
    now_unix: i64,
    intermediates_following: usize,
) -> Result<(), ChainError> {
    if child.tbs_certificate.issuer != issuer.tbs_certificate.subject {
        return Err(ChainError::IssuerMismatch);
    }
    verify_signed_under(child, issuer)?;
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

/// Verify `child`'s signature over its TBSCertificate under the `issuer`'s subject public key, routing
/// the digest+signature through the SDK's existing RustCrypto stack (no hand-rolled crypto).
fn verify_signed_under(child: &Certificate, issuer: &Certificate) -> Result<(), ChainError> {
    let alg = SigAlg::from_oid(child.signature_algorithm.oid)?;
    let tbs_der = child
        .tbs_certificate
        .to_der()
        .map_err(|e| ChainError::Malformed(format!("re-encode TBSCertificate: {e}")))?;
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
        SigAlg::EcdsaP256Sha256 => verify_ecdsa_p256(&spki_der, &tbs_der, signature),
        SigAlg::RsaSha256 => verify_rsa::<sha2::Sha256>(&spki_der, &tbs_der, signature),
        SigAlg::RsaSha384 => verify_rsa::<sha2::Sha384>(&spki_der, &tbs_der, signature),
        SigAlg::RsaSha512 => verify_rsa::<sha2::Sha512>(&spki_der, &tbs_der, signature),
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
    use super::{clamp_secs, verify_chain, ChainError, SigAlg, MAX_PATH_LEN};
    use der::{Decode as _, Encode as _};
    use x509_cert::Certificate;

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
        assert!(verify_chain(&[SDJWT_ISSUER], &anchors, NOW).is_ok());
        assert!(verify_chain(&[MDOC_DS], &anchors, NOW).is_ok());
    }

    #[test]
    fn self_issued_anchor_is_trusted_as_a_direct_pin() {
        // The root chained against itself: DER-equal direct pin (no issuer step needed).
        let anchors = vec![CA_IACA.to_vec()];
        assert!(verify_chain(&[CA_IACA], &anchors, NOW).is_ok());
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
            verify_chain(&[CA_IACA], &anchors, far_future),
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
            verify_chain(&[EXPIRED_CA_LEAF], &anchors, NOW),
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
            verify_chain(&[NON_CA_LEAF], &anchors, NOW),
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
        assert!(verify_chain(&[SDJWT_ISSUER], &anchors, NOW).is_ok());
        // The non-CA fixture, pinned directly, is likewise trusted (CA constraint is issued-by only).
        let anchors = vec![NON_CA.to_vec()];
        assert!(verify_chain(&[NON_CA], &anchors, NOW).is_ok());
    }

    #[test]
    fn untrusted_leaf_not_chained_is_rejected_with_issuer_mismatch() {
        // wrong-issuer is self-signed under a different name → no anchor subject matches its issuer.
        let anchors = vec![CA_IACA.to_vec()];
        assert_eq!(
            verify_chain(&[WRONG_ISSUER], &anchors, NOW),
            Err(ChainError::IssuerMismatch)
        );
    }

    #[test]
    fn leaf_is_rejected_when_no_anchors_configured() {
        assert_eq!(
            verify_chain(&[SDJWT_ISSUER], &[], NOW),
            Err(ChainError::IssuerMismatch)
        );
    }

    #[test]
    fn empty_supplied_chain_is_rejected() {
        // A supplied chain with no leaf at all cannot validate (defensive: the production callers
        // always supply at least the leaf, but verify_chain must not panic on an empty slice).
        let anchors = vec![CA_IACA.to_vec()];
        assert_eq!(
            verify_chain(&[], &anchors, NOW),
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
            verify_chain(&[SDJWT_ISSUER], &anchors, leaf_expired_root_valid),
            Err(ChainError::LeafExpired)
        );
    }

    #[test]
    fn malformed_leaf_is_rejected() {
        let anchors = vec![CA_IACA.to_vec()];
        let not_a_cert: &[u8] = b"not a certificate";
        match verify_chain(&[not_a_cert], &anchors, NOW) {
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
        assert!(verify_chain(&[tampered.as_slice()], &anchors, NOW).is_err());
    }

    #[test]
    fn error_display_is_specific() {
        assert!(ChainError::IssuerMismatch.to_string().contains("anchor"));
        assert!(ChainError::SignatureInvalid.to_string().contains("verify"));
        assert!(ChainError::PathTooLong.to_string().contains("length"));
        assert!(ChainError::LeafExpired.to_string().contains("validity"));
        assert!(ChainError::AnchorExpired.to_string().contains("validity"));
        assert!(ChainError::NotACa.to_string().contains("CA"));
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
        assert!(verify_chain(&[RSA_LEAF], &anchors, NOW).is_ok());
    }

    #[test]
    fn rsa_leaf_with_wrong_anchor_is_issuer_mismatch() {
        // The RSA leaf's issuer is the RSA CA, not the EC IACA → no name match.
        let anchors = vec![CA_IACA.to_vec()];
        assert_eq!(
            verify_chain(&[RSA_LEAF], &anchors, NOW),
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
        match verify_chain(&[mangled.as_slice()], &anchors, NOW) {
            Err(ChainError::UnsupportedAlgorithm(oid)) => assert_eq!(oid, "1.3.101.112"),
            other => panic!("expected UnsupportedAlgorithm, got {other:?}"),
        }
    }

    #[test]
    fn malformed_anchor_is_skipped_and_a_good_anchor_still_matches() {
        // A malformed anchor in the set must not mask a valid match from a good anchor (the parser
        // records the malformed-anchor error but keeps scanning).
        let anchors = vec![b"garbage anchor".to_vec(), CA_IACA.to_vec()];
        assert!(verify_chain(&[SDJWT_ISSUER], &anchors, NOW).is_ok());
    }

    #[test]
    fn only_a_malformed_anchor_yields_a_specific_error() {
        // With *only* a malformed anchor, no name match is ever seen → IssuerMismatch (the engine
        // surfaces "no trusted anchor", not a parse panic).
        let anchors = vec![b"garbage anchor".to_vec()];
        assert_eq!(
            verify_chain(&[SDJWT_ISSUER], &anchors, NOW),
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
            verify_chain(&[MT_LEAF, MT_INTERMEDIATE], &anchors, NOW).is_ok(),
            "leaf → intermediate sub-CA → configured root must be trusted"
        );
    }

    #[test]
    fn two_tier_chain_rejected_when_root_not_configured() {
        // Same conformant chain, but the configured anchor is the unrelated `ca-iaca`, not `mt-root` —
        // the path cannot reach a configured anchor, so it is untrusted (no false-accept).
        let anchors = vec![CA_IACA.to_vec()];
        assert_eq!(
            verify_chain(&[MT_LEAF, MT_INTERMEDIATE], &anchors, NOW),
            Err(ChainError::IssuerMismatch)
        );
    }

    #[test]
    fn two_tier_chain_without_supplied_intermediate_cannot_reach_the_root() {
        // If the credential omits the intermediate (supplies only the leaf) the path cannot be built:
        // the leaf's issuer is the intermediate, which is neither supplied nor a configured anchor.
        let anchors = vec![MT_ROOT.to_vec()];
        assert_eq!(
            verify_chain(&[MT_LEAF], &anchors, NOW),
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
            verify_chain(&[MT_LEAF, bad_intermediate.as_slice()], &anchors, NOW).is_err(),
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
            verify_chain(&[MT_NOCA_LEAF, MT_NOCA_INTERMEDIATE], &anchors, NOW),
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
            verify_chain(&[MT_EXPIRED_LEAF, MT_EXPIRED_INTERMEDIATE], &anchors, NOW),
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
            verify_chain(&[ATTACKER_LEAF, ATTACKER_CA], &anchors, NOW),
            Err(ChainError::IssuerMismatch),
            "an attacker chain that never reaches a configured anchor must be untrusted"
        );
        // Even configuring ca-iaca as well does not help the attacker — still no reachable anchor.
        let anchors = vec![MT_ROOT.to_vec(), CA_IACA.to_vec()];
        assert!(verify_chain(&[ATTACKER_LEAF, ATTACKER_CA], &anchors, NOW).is_err());
    }

    #[test]
    fn attacker_supplied_intermediate_is_ignored_when_the_leaf_directly_chains_to_an_anchor() {
        // A single-tier leaf that chains DIRECTLY to a configured anchor stays trusted even if the
        // attacker appends a bogus extra "intermediate": the path terminates at the anchor at the first
        // hop, so the trailing junk is never consulted (it is unreachable past the termination).
        let anchors = vec![CA_IACA.to_vec()];
        assert!(
            verify_chain(&[SDJWT_ISSUER, ATTACKER_CA], &anchors, NOW).is_ok(),
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
            verify_chain(&[MT_LEAF, MT_INTERMEDIATE], &anchors, NOW).is_ok(),
            "an intermediate pinned directly as an anchor terminates the path as trusted"
        );
    }

    #[test]
    fn single_tier_chains_still_trusted_after_path_validation() {
        // Regression: the existing single-tier sdjwt-issuer / mdoc-ds → ca-iaca chains (the production
        // direct-IACA shape) remain trusted under the new path-validation primitive.
        let anchors = vec![CA_IACA.to_vec()];
        assert!(verify_chain(&[SDJWT_ISSUER], &anchors, NOW).is_ok());
        assert!(verify_chain(&[MDOC_DS], &anchors, NOW).is_ok());
    }

    #[test]
    fn an_overlong_supplied_chain_is_rejected_as_path_too_long() {
        // DoS guard: a supplied chain longer than MAX_PATH_LEN must be rejected before the walk runs
        // unbounded. `nolen-ca` is SELF-SIGNED with NO pathLenConstraint (subject == issuer, and it
        // signed itself), so each copy supplied as a fresh entry name-matches AND signature-verifies as
        // the issuer of the previous one and, being a CA the pathLen gate never short-circuits, is
        // promoted — driving `depth` up one per hop. With more than MAX_PATH_LEN such promotions and NO
        // configured anchor to terminate at, the length cap fires (rather than NotACa/IssuerMismatch).
        let mut chain: Vec<&[u8]> = vec![NOLEN_LEAF];
        chain.extend(core::iter::repeat_n(NOLEN_CA, MAX_PATH_LEN + 2));
        let anchors = vec![MT_ROOT.to_vec()]; // present but never reached (rogue self-signed chain).
        assert_eq!(
            verify_chain(&chain, &anchors, NOW),
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
        assert!(verify_chain(&[NOLEN_LEAF, NOLEN_CA], &anchors, NOW).is_ok());
        assert!(verify_chain(&[NOLEN_LEAF], &anchors, NOW).is_ok());
    }
}
