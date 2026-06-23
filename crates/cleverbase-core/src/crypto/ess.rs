//! Minimal ESS structures for the `signing-certificate-v2` signed attribute (RFC 5035), required
//! by CAdES-B / PAdES-B.

use der::asn1::OctetString;
use der::Sequence;

/// `ESSCertIDv2` with the default SHA-256 hash algorithm (hashAlgorithm omitted ⇒ sha256) and no
/// issuerSerial. `cert_hash` is `sha256(DER(signer certificate))`.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct EssCertIdV2 {
    pub cert_hash: OctetString,
}

/// `SigningCertificateV2 ::= SEQUENCE { certs SEQUENCE OF ESSCertIDv2 }` (policies omitted).
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SigningCertificateV2 {
    pub certs: Vec<EssCertIdV2>,
}
