//! Shared crate-internal crypto helpers (DRY — Constitution Principle III): the **one** SHA-256
//! digest, the **one** P-256 JWK → SEC1 decode, and the IANA hash-algorithm name the verifier
//! supports.
//!
//! These were previously copy-pasted across [`crate::sdjwtvc`] (the SD-JWT VC verifier),
//! [`crate::issuance::signer`] (the holder context), and [`mod@crate::issuance::present`] (the
//! `_sd_alg` name) — three independent transcriptions of the same `kty=EC`/`crv=P-256` guard,
//! base64url `x`/`y` decode, 32-byte-length check, and `0x04 ‖ X ‖ Y` SEC1 assembly, plus two
//! copies of `sha256(&[u8]) -> [u8; 32]` and a stray `"sha-256"` literal. They are consolidated
//! here so there is one authoritative source.
//!
//! No hand-rolled crypto (Principle IV): the digest is the SDK's vetted `sha2`, and the public-point
//! decode ends in `p256::ecdsa::VerifyingKey::from_sec1_bytes`, whose on-curve check is preserved.

use base64ct::{Base64UrlUnpadded, Encoding as _};
use serde_json::Value;

/// The SD-JWT `_sd_alg` / IANA "Named Information Hash Algorithm" registry name for SHA-256. Per
/// RFC 9901 the default when `_sd_alg` is absent is `sha-256`; it is also the only digest the
/// verifier and the holder-presentation builder support.
pub(crate) const SHA_256: &str = "sha-256";

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
