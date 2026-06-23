//! Cryptographic primitives. Only vetted RustCrypto implementations are used — no hand-rolled
//! crypto (Constitution Principle IV). SHA-256 lives here; CMS / RSA / ECDSA-P256 assembly and the
//! ESS structures are in `cms`/`ess`, and RFC 3161 timestamping in `crate::timestamp`.

pub mod cms;
pub mod ess;

use sha2::{Digest, Sha256};

/// The SHA-256 algorithm OID — the single source for the string and parsed forms, shared by the
/// `signHash` request, the CMS digest algorithm, and the RFC 3161 message imprint (Principle VIII).
/// SHA-256 is the only hash Cleverbase's CSC service advertises.
pub const SHA256_OID_STR: &str = "2.16.840.1.101.3.4.2.1";
pub const SHA256_OID: der::oid::ObjectIdentifier =
    der::oid::ObjectIdentifier::new_unwrap(SHA256_OID_STR);

/// SHA-256 digest of `data`. (SHA-256 is the only hash Cleverbase's CSC service advertises.)
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::to_hex;

    #[test]
    fn sha256_known_vector_abc() {
        // FIPS 180-2 test vector for "abc".
        assert_eq!(
            to_hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha256_empty() {
        assert_eq!(
            to_hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
