//! Shared crate-internal crypto helpers (DRY — Constitution Principle III): the **one** SHA-256
//! digest, the **one** P-256 JWK → SEC1 decode, the **one** cert-DER → P-256 verifying-key path, and
//! the IANA hash-algorithm name the verifier supports.
//!
//! The JWK decode + digest were previously copy-pasted across [`crate::sdjwtvc`] (the SD-JWT VC
//! verifier), [`crate::issuance::signer`] (the holder context), and [`mod@crate::issuance::present`]
//! (the `_sd_alg` name) — three independent transcriptions of the same `kty=EC`/`crv=P-256` guard,
//! base64url `x`/`y` decode, 32-byte-length check, and `0x04 ‖ X ‖ Y` SEC1 assembly, plus two copies
//! of `sha256(&[u8]) -> [u8; 32]` and a stray `"sha-256"` literal. The cert-DER → verifying-key
//! `Certificate::from_der → subject_public_key_info.to_der() → from_public_key_der` sequence was
//! likewise transcribed in both issuer-signature verifiers ([`crate::sdjwtvc`]'s JWS `x5c` leaf and
//! [`crate::mdoc`]'s COSE_Sign1 `IssuerAuth` `x5chain` leaf). All are consolidated here so there is
//! one authoritative source.
//!
//! No hand-rolled crypto (Principle IV): the digest is the SDK's vetted `sha2`, the public-point
//! decode ends in `p256::ecdsa::VerifyingKey::from_sec1_bytes`, and the cert path ends in
//! `from_public_key_der` — each crate's own on-curve check is preserved.

use base64ct::{Base64, Base64UrlUnpadded, Encoding as _};
use serde_json::Value;

/// The SD-JWT `_sd_alg` / IANA "Named Information Hash Algorithm" registry name for SHA-256. Per
/// RFC 9901 the default when `_sd_alg` is absent is `sha-256`; it is also the only digest the
/// verifier and the holder-presentation builder support.
pub(crate) const SHA_256: &str = "sha-256";

/// Decode a **standard** base64 certificate body to DER, tolerating PEM-style whitespace (internal
/// line breaks / spaces are stripped before decoding). The **one** authoritative whitespace-tolerant
/// `<X509Certificate>`-body decode (DRY — Principle III): the TS 119 612 trust-list XML
/// ([`crate::trust::xml`]) and the qualified-status national TL JSON ([`crate::qualified`]) both carry
/// PEM-wrapped base64 certificate bodies and previously transcribed the identical
/// `split_whitespace().collect()` → `Base64::decode_vec` step. Returns the underlying
/// [`base64ct::Error`] so each caller maps it into its own error variant (preserving its existing
/// `Base64(e.to_string())` message).
///
/// Deliberately distinct from the two stricter cert decodes that are NOT folded in (they would change
/// behaviour): the JSON manifest ([`crate::trust::manifest`]) trims only leading/trailing whitespace,
/// and the SD-JWT VC JWS `x5c` leaf ([`crate::sdjwtvc`]) is a compact RFC 7515 array element decoded
/// with no whitespace tolerance at all.
pub(crate) fn decode_base64_cert_lenient(body: &str) -> Result<Vec<u8>, base64ct::Error> {
    let compact: String = body.split_whitespace().collect();
    Base64::decode_vec(&compact)
}

/// Decode a **standard** base64 body to bytes, trimming ONLY leading/trailing whitespace (no
/// internal-whitespace tolerance). The **one** authoritative strict trim-only base64 decode (DRY —
/// Principle III): the qualified-status national TL JSON SKI field ([`crate::qualified`]) and the JSON
/// trust manifest anchor-cert body ([`crate::trust::manifest`]) both carried the identical
/// `Base64::decode_vec(s.trim())` step. Returns the underlying [`base64ct::Error`] so each caller maps
/// it into its own error variant (mirroring [`decode_base64_cert_lenient`]).
///
/// Deliberately distinct from [`decode_base64_cert_lenient`], which strips ALL internal whitespace for
/// PEM-wrapped certificate bodies; this trims only the ends.
pub(crate) fn decode_base64_strict(s: &str) -> Result<Vec<u8>, base64ct::Error> {
    Base64::decode_vec(s.trim())
}

/// The byte length of a single P-256 affine coordinate (and of the raw `r`/`s` scalars).
const P256_COORD_LEN: usize = 32;

/// SHA-256 of `input` (the SDK's own `sha2` — research D1, no second crypto stack). The single
/// authoritative digest helper for the crate.
pub(crate) fn sha256(input: &[u8]) -> [u8; 32] {
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    hasher.update(input);
    hasher.finalize().into()
}

/// The SD-JWT VC `sd_hash` (RFC 9901 §4.3): the base64url-unpadded SHA-256 digest of the presentation
/// prefix bytes (the issuer-JWS-plus-selected-disclosures, up to and including the final `~` that
/// precedes the KB-JWT). The **one** authoritative `sd_hash` formula for the crate (DRY — Principle
/// III): the SD-JWT VC verifier ([`crate::sdjwtvc`]) recomputes it to check a presented KB-JWT and the
/// holder KB-JWT builder ([`crate::issuance::signer`]) computes the same value to embed — both call
/// this so the digest is identical on both sides (a verifier MUST recompute the byte-identical value
/// the holder bound).
pub(crate) fn sd_hash(prefix: &str) -> String {
    Base64UrlUnpadded::encode_string(&sha256(prefix.as_bytes()))
}

/// Assemble the uncompressed SEC1 public point (`0x04 ‖ X ‖ Y`, 65 bytes) from raw P-256 affine
/// coordinates, returning `None` unless each coordinate is exactly 32 bytes. This is the **byte-level**
/// half shared by the JWK decode and the mdoc COSE-coordinate path (which reads `X`/`Y` from COSE
/// labels rather than a JWK).
pub(crate) fn p256_sec1_from_coords(x: &[u8], y: &[u8]) -> Option<Vec<u8>> {
    if x.len() != P256_COORD_LEN || y.len() != P256_COORD_LEN {
        return None;
    }
    let mut sec1 = Vec::with_capacity(1 + 2 * P256_COORD_LEN);
    sec1.push(0x04);
    sec1.extend_from_slice(x);
    sec1.extend_from_slice(y);
    Some(sec1)
}

/// Decode the uncompressed SEC1 public point (`0x04 ‖ X ‖ Y`) from a JWK object (`kty=EC`,
/// `crv=P-256`, base64url-unpadded `x`/`y`), returning `None` on any deviation (wrong `kty`/`crv`,
/// missing/un-decodable/wrong-length coordinate).
///
/// This is the point-bytes step; [`p256_verifying_key_from_jwk`] layers the `from_sec1_bytes`
/// on-curve check on top. Kept separate so a caller that needs the raw SEC1 bytes (the mdoc
/// `DeviceKey` derivation) reuses the identical guard.
pub(crate) fn p256_sec1_from_jwk(jwk: &Value) -> Option<Vec<u8>> {
    if jwk.get("kty").and_then(Value::as_str) != Some("EC")
        || jwk.get("crv").and_then(Value::as_str) != Some("P-256")
    {
        return None;
    }
    let x = jwk
        .get("x")
        .and_then(Value::as_str)
        .and_then(|s| Base64UrlUnpadded::decode_vec(s).ok())?;
    let y = jwk
        .get("y")
        .and_then(Value::as_str)
        .and_then(|s| Base64UrlUnpadded::decode_vec(s).ok())?;
    p256_sec1_from_coords(&x, &y)
}

/// Build a P-256 verifying key from a JWK object (`kty=EC`, `crv=P-256`, base64url `x`/`y`),
/// returning `None` on any deviation. The final `from_sec1_bytes` performs the on-curve point
/// validation (so a syntactically valid but off-curve point is rejected).
pub(crate) fn p256_verifying_key_from_jwk(jwk: &Value) -> Option<p256::ecdsa::VerifyingKey> {
    let sec1 = p256_sec1_from_jwk(jwk)?;
    p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).ok()
}

/// Extract the P-256 ECDSA verifying key from a DER certificate's `SubjectPublicKeyInfo`, returning
/// `None` when the certificate does not parse, its SPKI cannot be re-encoded, or the key is not a
/// valid P-256 public key. This is the **one** cert-DER → `VerifyingKey` path for the crate (DRY —
/// Principle III): both issuer-signature verifiers — the SD-JWT VC JWS (`x5c` leaf) and the mdoc
/// COSE_Sign1 `IssuerAuth` (`x5chain` leaf) — previously transcribed the identical
/// `Certificate::from_der → tbs.subject_public_key_info.to_der() → from_public_key_der` sequence; they
/// now share this. The terminal `from_public_key_der` performs the on-curve point validation (the SDK's
/// vetted X.509 + `p256` stack — the same path `cleverbase-core` uses for CMS leaf verification; no
/// hand-rolled crypto, Principle IV). Callers map the `None` to their own format-specific reason.
pub(crate) fn p256_verifying_key_from_cert_der(
    cert_der: &[u8],
) -> Option<p256::ecdsa::VerifyingKey> {
    use der::{Decode as _, Encode as _};
    use x509_cert::spki::DecodePublicKey as _;
    let cert = x509_cert::Certificate::from_der(cert_der).ok()?;
    let spki_der = cert.tbs_certificate.subject_public_key_info.to_der().ok()?;
    p256::ecdsa::VerifyingKey::from_public_key_der(&spki_der).ok()
}

/// Verify a P-256 **ES256** signature `raw_sig` over `msg` under `vk`, accepting ONLY the fixed-width
/// raw `r‖s` COSE/JOSE form. Returns `Err(())` on a non-raw/malformed signature encoding or a failed
/// verification. The **one** ES256 verify-out kernel for the crate (DRY — Principle III): the
/// JOSE/SD-JWT VC compact-JWS verifier ([`crate::sdjwtvc`]) and both COSE_Sign1 mdoc verifiers
/// ([`crate::mdoc`], the attached `IssuerAuth` and detached `DeviceSignature`) previously transcribed
/// the identical `Signature::from_slice(raw) → vk.verify(msg, &sig)` body; they now share this.
///
/// RFC 9053 §2.1 (ECDSA, the COSE algorithm definition) and RFC 7515/7518 (JOSE) both mandate the
/// signature be the concatenation of `R` and `S` as fixed-width octet strings —
/// `Signature = I2OSP(R, n) | I2OSP(S, n)`, `n = ceil(key_length / 8)` — i.e. the raw 64-byte `r‖s`
/// for P-256, NEVER an ASN.1/DER `SEQUENCE`. `p256::ecdsa::Signature::from_slice` is exactly that
/// raw-only parse (a DER-encoded signature is rejected here, matching what a reference COSE/JOSE
/// validator accepts). No hand-rolled crypto (Principle IV): the SDK's vetted `p256`/`ecdsa`.
pub(crate) fn p256_verify_es256(
    vk: &p256::ecdsa::VerifyingKey,
    msg: &[u8],
    raw_sig: &[u8],
) -> Result<(), ()> {
    use p256::ecdsa::signature::Verifier as _;
    let signature = p256::ecdsa::Signature::from_slice(raw_sig).map_err(|_| ())?;
    vk.verify(msg, &signature).map_err(|_| ())
}
