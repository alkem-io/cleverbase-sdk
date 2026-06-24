//! Minimal ESS structures for the `signing-certificate-v2` signed attribute (RFC 5035), required
//! by CAdES-B / PAdES-B.

use der::asn1::OctetString;
use der::Sequence;

/// `ESSCertIDv2` with the default SHA-256 hash algorithm (hashAlgorithm omitted ⇒ sha256) and no
/// issuerSerial. `cert_hash` is `sha256(DER(signer certificate))`.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct EssCertIdV2 {
    /// `sha256(DER(signer certificate))`.
    pub cert_hash: OctetString,
}

/// `SigningCertificateV2 ::= SEQUENCE { certs SEQUENCE OF ESSCertIDv2 }` (policies omitted).
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SigningCertificateV2 {
    /// The `ESSCertIDv2` entries (the signer leaf certificate).
    pub certs: Vec<EssCertIdV2>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::{Decode, Encode};

    #[test]
    fn signing_certificate_v2_round_trips() {
        let scv2 = SigningCertificateV2 {
            certs: vec![EssCertIdV2 {
                cert_hash: OctetString::new(vec![7u8; 32]).unwrap(),
            }],
        };
        let der = scv2.to_der().unwrap();
        let back = SigningCertificateV2::from_der(&der).unwrap();
        assert_eq!(scv2, back);
        assert_eq!(back.certs[0].cert_hash.as_bytes().len(), 32);
    }
}
