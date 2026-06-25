//! X.509 chain validation against trusted anchors (research D5, no hand-rolled crypto).
//!
//! Trust anchoring asks one question: does the credential's signing certificate (the mdoc
//! `IssuerAuth` x5chain leaf or the SD-JWT VC JWS `x5c` leaf) **chain to** a certificate that the
//! configured trust anchor lists for the credential's role/format? This module answers it by
//! reusing the SDK's vetted X.509 stack — `x509-cert` for parsing, `p256`/`ecdsa` + `rsa` for the
//! signature math, `sha2` for the digest — and never hand-rolls crypto (Principle IV / research D1).
//!
//! The validation is intentionally a **direct-issuer** check sized for the EUDI trust model: an
//! issuer leaf is trusted iff it is signed by (or *is*) an anchor certificate, the leaf's `issuer`
//! name matches the anchor's `subject` name, and the leaf is within its validity window at the
//! relevant time. ISO 18013-5 IACA hierarchies and the eIDAS trusted lists are one-level (root →
//! document-signer / service); a configured anchor *is* the root, so a one-hop chain is the
//! production shape. The matcher also accepts an exact DER-equal leaf (a self-issued anchor that is
//! itself the listed entry), which covers a trusted-list entry that pins the leaf directly — but
//! even that direct-pin path still enforces the leaf's validity window, so an expired pinned leaf
//! is rejected rather than trusted.
//!
//! On the **issued-by** path the check enforces the RFC 5280 §6.1 path requirements a one-hop chain
//! still owes: the issuing anchor must be a CA (`basicConstraints cA=TRUE`, and `keyUsage`'s
//! `keyCertSign` bit when `keyUsage` is present — §6.1.4 (k)/(n), §4.2.1.9, §4.2.1.3), and **every**
//! certificate in the path — the issuing CA *and* the leaf — must be within its own validity window
//! at the relevant time (§6.1.3 (a)(2)). So a non-CA anchor cannot "issue" trusted leaves and an
//! expired/not-yet-valid issuing CA cannot vouch for an otherwise-in-window leaf. The **direct-pin**
//! path is deliberately exempt from the CA constraint: pinning a specific end-entity certificate as
//! trusted is an intentional, distinct trust model.

use der::{Decode as _, Encode as _};
use x509_cert::Certificate;

/// Why a candidate issuer certificate failed to chain to a trusted anchor.
///
/// Every rejection carries a specific reason so an untrusted verdict is never opaque (the engine
/// maps these onto [`crate::types::ReasonCode::UntrustedIssuer`] / `Expired`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainError {
    /// A certificate (leaf or anchor) could not be parsed as DER X.509.
    Malformed(String),
    /// The leaf's issuer name does not match any candidate anchor's subject name.
    IssuerMismatch,
    /// The leaf's signature did not verify under any name-matching anchor's public key.
    SignatureInvalid,
    /// The leaf carries a signature algorithm the SDK does not implement (outside the EUDI
    /// baseline: ES256/384/512 + RSA-PKCS#1v1.5 over SHA-256/384/512).
    UnsupportedAlgorithm(String),
    /// The leaf is outside its own validity window at the relevant time.
    LeafExpired,
    /// The issuing anchor (CA) is itself outside its own validity window at the relevant time. Per
    /// RFC 5280 §6.1.3 (a)(2) **every** certificate in the path — the issuing CA included — must be
    /// valid at the validation time, so an expired (or not-yet-valid) anchor cannot issue trusted
    /// leaves even when the leaf's own window is current.
    AnchorExpired,
    /// The issuing anchor does not assert the CA constraints required to issue certificates: per RFC
    /// 5280 §6.1.4 (k)/(n) and §4.2.1.9 an issuer MUST carry `basicConstraints` with `cA=TRUE` and
    /// (when `keyUsage` is present) the `keyCertSign` bit. This closes the "any cert is a CA" gap —
    /// a non-CA (end-entity) certificate listed as an anchor cannot issue trusted leaves on the
    /// issued-by path. (The direct-pin path, where the anchor *is* the pinned leaf, is exempt:
    /// pinning a specific end-entity certificate as trusted is an intentional, distinct model.)
    NotACa,
}

impl core::fmt::Display for ChainError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Malformed(e) => write!(f, "certificate is not valid DER X.509: {e}"),
            Self::IssuerMismatch => {
                write!(f, "leaf issuer does not match any trusted anchor subject")
            }
            Self::SignatureInvalid => {
                write!(f, "leaf signature did not verify under any trusted anchor")
            }
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

/// Whether `leaf_cert_der` chains to **any** of the trusted `anchor_certs_der`, valid at
/// `now_unix`.
///
/// This is the trust-anchoring primitive: a leaf is trusted iff some anchor either (a) is DER-equal
/// to the leaf (the anchor pins the leaf directly), or (b) issued the leaf — the leaf's `issuer`
/// name equals the anchor's `subject` name **and** the leaf's signature verifies under the anchor's
/// public key. On the issued-by path (b) the issuing anchor must additionally be a CA
/// ([`ChainError::NotACa`] otherwise — RFC 5280 §6.1.4) and itself be within its validity window at
/// `now_unix` ([`ChainError::AnchorExpired`] otherwise — §6.1.3 (a)(2)). In **both** paths the leaf
/// must be within its own validity window at `now_unix` (an expired directly-pinned leaf is rejected
/// as [`ChainError::LeafExpired`], never trusted). Returns the first specific [`ChainError`] when no
/// anchor matches.
///
/// # Errors
///
/// Returns [`ChainError`] when the leaf is malformed, no anchor's subject matches the leaf's issuer,
/// the signature does not verify, the algorithm is unsupported, the issuing anchor is not a CA or is
/// itself outside its validity window, or the leaf is outside its validity window.
pub fn verify_chain(
    leaf_cert_der: &[u8],
    anchor_certs_der: &[Vec<u8>],
    now_unix: i64,
) -> Result<(), ChainError> {
    let leaf = Certificate::from_der(leaf_cert_der)
        .map_err(|e| ChainError::Malformed(format!("leaf: {e}")))?;

    // (a) Direct pin: an anchor that is byte-for-byte the leaf is trusted as-is (a trusted-list
    // entry that lists the leaf certificate itself), no signature step needed — but the leaf must
    // still be within its own validity window at `now_unix`. Otherwise an EXPIRED directly-pinned
    // leaf (e.g. the qualified-gate's TL-signer cert, which the fixtures pin as both signer and
    // scheme anchor) would authenticate, contradicting the documented "within its validity window
    // at the relevant time" contract. This path is intentionally exempt from the issued-by CA
    // constraint: pinning a specific end-entity certificate as trusted is a deliberate trust model.
    if anchor_certs_der
        .iter()
        .any(|a| a.as_slice() == leaf_cert_der)
    {
        if cert_is_valid_at(&leaf, now_unix) {
            return Ok(());
        }
        return Err(ChainError::LeafExpired);
    }

    // (b) Issued-by-anchor: find name-matching anchors, then verify the leaf signature under one.
    // Track the most specific failure so the caller gets an actionable reason.
    let mut saw_name_match = false;
    let mut last_err = ChainError::IssuerMismatch;

    for anchor_der in anchor_certs_der {
        let anchor = match Certificate::from_der(anchor_der) {
            Ok(c) => c,
            Err(e) => {
                // A malformed *anchor* is a configuration fault, but must not mask a valid match
                // from another anchor — record and continue.
                last_err = ChainError::Malformed(format!("anchor: {e}"));
                continue;
            }
        };
        if leaf.tbs_certificate.issuer != anchor.tbs_certificate.subject {
            continue;
        }
        saw_name_match = true;
        match verify_leaf_under_anchor(&leaf, &anchor) {
            Ok(()) => {
                // The anchor's signature over the leaf verifies — it really issued this leaf. Now
                // enforce the remaining RFC 5280 §6.1 path requirements on the *issued-by* relation:
                //
                //   1. The issuing anchor must be a CA — §6.1.4 (k)/(n) + §4.2.1.9: basicConstraints
                //      cA=TRUE AND (if keyUsage is present) the keyCertSign bit. This closes the
                //      "any cert is a CA" gap; a non-CA anchor cannot issue trusted leaves.
                //   2. The issuing anchor must itself be within its validity window at `now_unix` —
                //      §6.1.3 (a)(2): EVERY certificate in the path (the CA included) must be valid
                //      at the validation time, so an expired/not-yet-valid anchor is rejected.
                //   3. The leaf must be within its own validity window at `now_unix` (as before).
                //
                // These apply ONLY to this issued-by path; the direct-pin path above pins a specific
                // certificate intentionally and is exempt from the CA constraint.
                if !anchor_asserts_ca(&anchor) {
                    last_err = ChainError::NotACa;
                } else if !cert_is_valid_at(&anchor, now_unix) {
                    last_err = ChainError::AnchorExpired;
                } else if cert_is_valid_at(&leaf, now_unix) {
                    return Ok(());
                } else {
                    last_err = ChainError::LeafExpired;
                }
            }
            Err(e) => last_err = e,
        }
    }

    if !saw_name_match {
        return Err(ChainError::IssuerMismatch);
    }
    Err(last_err)
}

/// Verify the leaf's signature over its TBSCertificate under the anchor's subject public key,
/// routing the digest+signature through the SDK's existing RustCrypto stack (no hand-rolled crypto).
fn verify_leaf_under_anchor(leaf: &Certificate, anchor: &Certificate) -> Result<(), ChainError> {
    let alg = SigAlg::from_oid(leaf.signature_algorithm.oid)?;
    let tbs_der = leaf
        .tbs_certificate
        .to_der()
        .map_err(|e| ChainError::Malformed(format!("re-encode TBSCertificate: {e}")))?;
    let signature = leaf
        .signature
        .as_bytes()
        .ok_or_else(|| ChainError::Malformed("leaf signature is not byte-aligned".into()))?;
    let spki_der = anchor
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| ChainError::Malformed(format!("anchor SPKI: {e}")))?;

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
/// certificates, parsed via `x509-cert`'s typed extension decoders (no hand-rolled ASN.1):
///
/// - **§6.1.4 (k) / §4.2.1.9** — `basicConstraints` MUST be present with `cA=TRUE`. A certificate
///   without `basicConstraints`, or with `cA=FALSE`, is an end entity and may not issue certificates.
/// - **§6.1.4 (n) / §4.2.1.3** — *if* a `keyUsage` extension is present, the `keyCertSign` bit MUST
///   be set. (When `keyUsage` is absent the spec leaves all usages permitted, so the bit is not
///   required.)
///
/// A malformed or duplicate `basicConstraints` / `keyUsage` extension fails closed (treated as not a
/// CA): a certificate whose constraints cannot be parsed must not be trusted to issue.
fn anchor_asserts_ca(anchor: &Certificate) -> bool {
    use x509_cert::ext::pkix::{BasicConstraints, KeyUsage};

    // basicConstraints present AND cA=TRUE (a parse error, duplicate, or absence ⇒ not a CA).
    match anchor.tbs_certificate.get::<BasicConstraints>() {
        Ok(Some((_critical, bc))) if bc.ca => {}
        _ => return false,
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
    use super::{clamp_secs, verify_chain, ChainError, SigAlg};
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
        assert!(verify_chain(SDJWT_ISSUER, &anchors, NOW).is_ok());
        assert!(verify_chain(MDOC_DS, &anchors, NOW).is_ok());
    }

    #[test]
    fn self_issued_anchor_is_trusted_as_a_direct_pin() {
        // The root chained against itself: DER-equal direct pin (no issuer step needed).
        let anchors = vec![CA_IACA.to_vec()];
        assert!(verify_chain(CA_IACA, &anchors, NOW).is_ok());
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
            verify_chain(CA_IACA, &anchors, far_future),
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
            verify_chain(EXPIRED_CA_LEAF, &anchors, NOW),
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
            verify_chain(NON_CA_LEAF, &anchors, NOW),
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
        assert!(verify_chain(SDJWT_ISSUER, &anchors, NOW).is_ok());
        // The non-CA fixture, pinned directly, is likewise trusted (CA constraint is issued-by only).
        let anchors = vec![NON_CA.to_vec()];
        assert!(verify_chain(NON_CA, &anchors, NOW).is_ok());
    }

    #[test]
    fn untrusted_leaf_not_chained_is_rejected_with_issuer_mismatch() {
        // wrong-issuer is self-signed under a different name → no anchor subject matches its issuer.
        let anchors = vec![CA_IACA.to_vec()];
        assert_eq!(
            verify_chain(WRONG_ISSUER, &anchors, NOW),
            Err(ChainError::IssuerMismatch)
        );
    }

    #[test]
    fn leaf_is_rejected_when_no_anchors_configured() {
        assert_eq!(
            verify_chain(SDJWT_ISSUER, &[], NOW),
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
            verify_chain(SDJWT_ISSUER, &anchors, leaf_expired_root_valid),
            Err(ChainError::LeafExpired)
        );
    }

    #[test]
    fn malformed_leaf_is_rejected() {
        let anchors = vec![CA_IACA.to_vec()];
        match verify_chain(b"not a certificate", &anchors, NOW) {
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
        assert!(verify_chain(&tampered, &anchors, NOW).is_err());
    }

    #[test]
    fn error_display_is_specific() {
        assert!(ChainError::IssuerMismatch.to_string().contains("issuer"));
        assert!(ChainError::SignatureInvalid.to_string().contains("verify"));
        assert!(ChainError::LeafExpired.to_string().contains("validity"));
        assert!(ChainError::AnchorExpired.to_string().contains("validity"));
        assert!(ChainError::AnchorExpired.to_string().contains("anchor"));
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
        assert!(verify_chain(RSA_LEAF, &anchors, NOW).is_ok());
    }

    #[test]
    fn rsa_leaf_with_wrong_anchor_is_issuer_mismatch() {
        // The RSA leaf's issuer is the RSA CA, not the EC IACA → no name match.
        let anchors = vec![CA_IACA.to_vec()];
        assert_eq!(
            verify_chain(RSA_LEAF, &anchors, NOW),
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
        match verify_chain(&mangled, &anchors, NOW) {
            Err(ChainError::UnsupportedAlgorithm(oid)) => assert_eq!(oid, "1.3.101.112"),
            other => panic!("expected UnsupportedAlgorithm, got {other:?}"),
        }
    }

    #[test]
    fn malformed_anchor_is_skipped_and_a_good_anchor_still_matches() {
        // A malformed anchor in the set must not mask a valid match from a good anchor (the parser
        // records the malformed-anchor error but keeps scanning).
        let anchors = vec![b"garbage anchor".to_vec(), CA_IACA.to_vec()];
        assert!(verify_chain(SDJWT_ISSUER, &anchors, NOW).is_ok());
    }

    #[test]
    fn only_a_malformed_anchor_yields_a_specific_error() {
        // With *only* a malformed anchor, no name match is ever seen → IssuerMismatch (the engine
        // surfaces "no trusted anchor", not a parse panic).
        let anchors = vec![b"garbage anchor".to_vec()];
        assert_eq!(
            verify_chain(SDJWT_ISSUER, &anchors, NOW),
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
        // The genuine IACA root asserts basicConstraints cA=TRUE + keyUsage keyCertSign → a CA.
        let ca = Certificate::from_der(CA_IACA).expect("parse ca-iaca");
        assert!(
            anchor_asserts_ca(&ca),
            "ca-iaca asserts cA=TRUE + keyCertSign"
        );
        // The RSA signing CA likewise asserts the CA constraints.
        let rsa_ca = Certificate::from_der(RSA_CA).expect("parse rsa ca");
        assert!(anchor_asserts_ca(&rsa_ca), "the RSA test CA is a CA");
        // The non-CA fixture (CA:FALSE, keyUsage digitalSignature only) is NOT a CA.
        let non_ca = Certificate::from_der(NON_CA).expect("parse non-ca");
        assert!(!anchor_asserts_ca(&non_ca), "CA:FALSE is not a CA");
        // The end-entity leaves (CA:FALSE) are not CAs either.
        let leaf = Certificate::from_der(SDJWT_ISSUER).expect("parse sdjwt-issuer");
        assert!(!anchor_asserts_ca(&leaf), "an end-entity leaf is not a CA");
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
            !anchor_asserts_ca(&ca),
            "a cert with an unparseable (duplicate) keyUsage must fail closed as not-a-CA"
        );
    }
}
