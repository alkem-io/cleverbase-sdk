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
//! itself the listed entry), which covers a trusted-list entry that pins the leaf directly.

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
/// public key — and in case (b) the leaf is within its own validity window at `now_unix`. Returns
/// the first specific [`ChainError`] when no anchor matches.
///
/// # Errors
///
/// Returns [`ChainError`] when the leaf is malformed, no anchor's subject matches the leaf's issuer,
/// the signature does not verify, the algorithm is unsupported, or the leaf is expired.
pub fn verify_chain(
    leaf_cert_der: &[u8],
    anchor_certs_der: &[Vec<u8>],
    now_unix: i64,
) -> Result<(), ChainError> {
    let leaf = Certificate::from_der(leaf_cert_der)
        .map_err(|e| ChainError::Malformed(format!("leaf: {e}")))?;

    // (a) Direct pin: an anchor that is byte-for-byte the leaf is trusted as-is (a trusted-list
    // entry that lists the leaf certificate itself), no signature step needed.
    if anchor_certs_der
        .iter()
        .any(|a| a.as_slice() == leaf_cert_der)
    {
        return Ok(());
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
                // Signature is good; the leaf must also be within its own validity window.
                if leaf_is_valid_at(&leaf, now_unix) {
                    return Ok(());
                }
                last_err = ChainError::LeafExpired;
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

/// Whether the leaf is within its `notBefore..=notAfter` validity window at `now_unix`.
fn leaf_is_valid_at(leaf: &Certificate, now_unix: i64) -> bool {
    let validity = &leaf.tbs_certificate.validity;
    let not_before = unix_secs(validity.not_before);
    let not_after = unix_secs(validity.not_after);
    now_unix >= not_before && now_unix <= not_after
}

/// X.509 `Time` → Unix seconds (saturating to `i64`).
fn unix_secs(time: x509_cert::time::Time) -> i64 {
    i64::try_from(time.to_unix_duration().as_secs()).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::{verify_chain, ChainError, SigAlg};
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
    // The signing-core RSA PKI (`sha256WithRSAEncryption`): an RSA CA that signs an RSA leaf —
    // exercises the RSA-PKCS#1v1.5 certificate-signature path, which the EC-only attestation
    // fixtures cannot. Reused (DRY) rather than minting a parallel RSA fixture set.
    const RSA_CA: &[u8] = include_bytes!("../../../../tests/fixtures/pki/ca.cert.der");
    const RSA_LEAF: &[u8] = include_bytes!("../../../../tests/fixtures/pki/signer-rsa.cert.der");

    // The fixtures are minted 2026-06-25 and the leaves are valid ~15 months (notBefore
    // 2026-06-25, notAfter 2027-09-23); pick a `now` inside every fixture's window (research D9 /
    // gen.sh DAYS_LEAF=455). The RSA leaf's window (2026-06-22..2028-09-24) also covers this.
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
        // A time far in the future, past the ~15-month leaf validity (but the root still matches by
        // name + signature) → the leaf-validity gate fires.
        let anchors = vec![CA_IACA.to_vec()];
        let far_future = 4_000_000_000; // year ~2096
        assert_eq!(
            verify_chain(SDJWT_ISSUER, &anchors, far_future),
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
        assert!(ChainError::UnsupportedAlgorithm("1.2.3".into())
            .to_string()
            .contains("1.2.3"));
        assert!(ChainError::Malformed("x".into())
            .to_string()
            .contains("DER"));
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
}
