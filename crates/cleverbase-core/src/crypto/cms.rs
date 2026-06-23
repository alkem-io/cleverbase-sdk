//! CAdES/PAdES-B CMS (PKCS#7) SignedData assembly with an **external** signature.
//!
//! This mirrors how Cleverbase signs: we build the signed attributes, the host obtains a signature
//! over `sha256(DER(signedAttrs))` (Cleverbase `signHash`), and we assemble a detached
//! `SignedData`. No private key ever lives in the core. Built only on vetted RustCrypto crates
//! (Constitution Principle IV).

use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use cms::content_info::{CmsVersion, ContentInfo};
use cms::signed_data::{
    CertificateSet, EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo, SignerInfos,
};
use der::asn1::{Any, GeneralizedTime, Null, OctetString, SetOfVec, UtcTime};
use der::oid::ObjectIdentifier;
use der::{Decode, Encode};
use x509_cert::attr::Attribute;
use x509_cert::spki::AlgorithmIdentifierOwned;
use x509_cert::Certificate;

use super::ess::{EssCertIdV2, SigningCertificateV2};
use super::sha256;
use crate::signing::csc::KeyAlgo;

// Object identifiers (avoid depending on const-oid db layout).
const ID_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
const ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
const ID_CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
const ID_MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
const ID_SIGNING_TIME: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.5");
const ID_SIGNING_CERTIFICATE_V2: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.47");
use super::SHA256_OID as ID_SHA256;
const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

// 2050-01-01T00:00:00Z in Unix seconds — UTCTime covers up to (not incl.) this; later uses GeneralizedTime.
const UTC_TIME_UPPER_BOUND_SECS: u64 = 2_524_608_000;

/// Errors from CMS assembly/verification.
#[derive(Debug, thiserror::Error)]
pub enum CmsError {
    #[error("DER error: {0}")]
    Der(#[from] der::Error),
    #[error("unsupported key algorithm for CMS assembly")]
    UnsupportedAlgo,
    #[error("empty certificate chain")]
    EmptyChain,
    #[error("verification failed: {0}")]
    Verify(String),
}

/// Wrap any DER-encodable value as an `Any` (robust across der versions).
fn any_of<T: Encode>(value: &T) -> Result<Any, CmsError> {
    Ok(Any::from_der(&value.to_der()?)?)
}

fn single_value_attr(oid: ObjectIdentifier, value: Any) -> Result<Attribute, CmsError> {
    let mut values = SetOfVec::new();
    values.insert(value)?;
    Ok(Attribute { oid, values })
}

fn signing_time_value(now_unix: i64) -> Result<Any, CmsError> {
    let secs = now_unix.max(0) as u64;
    let dur = core::time::Duration::from_secs(secs);
    if secs < UTC_TIME_UPPER_BOUND_SECS {
        any_of(&UtcTime::from_unix_duration(dur)?)
    } else {
        any_of(&GeneralizedTime::from_unix_duration(dur)?)
    }
}

/// Build the DER of the signed attributes as a `SET OF` (tag `0x31`) — the bytes whose SHA-256 the
/// signer authorizes and signs (`signHash`). `content_hash` is sha256 of the PDF ByteRange bytes.
pub fn build_signed_attrs(
    content_hash: &[u8],
    leaf_cert_der: &[u8],
    now_unix: i64,
) -> Result<Vec<u8>, CmsError> {
    let content_type = single_value_attr(ID_CONTENT_TYPE, any_of(&ID_DATA)?)?;
    let message_digest = single_value_attr(
        ID_MESSAGE_DIGEST,
        any_of(&OctetString::new(content_hash.to_vec())?)?,
    )?;
    let signing_time = single_value_attr(ID_SIGNING_TIME, signing_time_value(now_unix)?)?;

    let cert_hash = sha256(leaf_cert_der);
    let scv2 = SigningCertificateV2 {
        certs: vec![EssCertIdV2 {
            cert_hash: OctetString::new(cert_hash.to_vec())?,
        }],
    };
    let signing_cert = single_value_attr(ID_SIGNING_CERTIFICATE_V2, any_of(&scv2)?)?;

    let mut attrs: SetOfVec<Attribute> = SetOfVec::new();
    attrs.insert(content_type)?;
    attrs.insert(message_digest)?;
    attrs.insert(signing_time)?;
    attrs.insert(signing_cert)?;
    Ok(attrs.to_der()?)
}

/// SHA-256 of the signed-attributes DER — the hash sent to the signing service.
pub fn tbs_hash(signed_attrs_der: &[u8]) -> [u8; 32] {
    sha256(signed_attrs_der)
}

fn algorithm(
    oid: ObjectIdentifier,
    null_params: bool,
) -> Result<AlgorithmIdentifierOwned, CmsError> {
    let parameters = if null_params {
        Some(any_of(&Null)?)
    } else {
        None
    };
    Ok(AlgorithmIdentifierOwned { oid, parameters })
}

/// `ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }` (RFC 5480 §A.1).
#[derive(der::Sequence)]
struct EcdsaSigValue {
    r: der::asn1::Uint,
    s: der::asn1::Uint,
}

/// Convert a raw fixed-width ECDSA P-256 signature (`r‖s`, 64 bytes — the form CSC v2
/// `signatures/signHash` returns) into the DER `ECDSA-Sig-Value` that CMS requires. Input that is
/// already DER (does not have the raw 64-byte length) is returned unchanged.
fn ecdsa_signature_to_der(signature: &[u8]) -> Result<Vec<u8>, CmsError> {
    // If it already parses as a DER ECDSA-Sig-Value, leave it untouched (avoids a length-based
    // heuristic that could collide with a genuinely-64-byte DER signature).
    if EcdsaSigValue::from_der(signature).is_ok() {
        return Ok(signature.to_vec());
    }
    // CSC v2 returns raw fixed-width r‖s (64 bytes for P-256); DER-encode it.
    if signature.len() == 64 {
        let sig = EcdsaSigValue {
            r: der::asn1::Uint::new(&signature[..32])?,
            s: der::asn1::Uint::new(&signature[32..])?,
        };
        return Ok(sig.to_der()?);
    }
    Ok(signature.to_vec())
}

/// Assemble a detached CMS `SignedData` (wrapped in a `ContentInfo`) from the signer's certificate
/// chain (DER, leaf first), the signed-attributes DER, and the raw signature value from the signer.
pub fn assemble_signed_data(
    cert_chain_der: &[Vec<u8>],
    signed_attrs_der: &[u8],
    signature: &[u8],
    key_algo: KeyAlgo,
) -> Result<Vec<u8>, CmsError> {
    let leaf_der = cert_chain_der.first().ok_or(CmsError::EmptyChain)?;
    let leaf = Certificate::from_der(leaf_der)?;
    let sid = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
        issuer: leaf.tbs_certificate.issuer.clone(),
        serial_number: leaf.tbs_certificate.serial_number,
    });

    let digest_alg = algorithm(ID_SHA256, false)?;
    let signature_algorithm = match key_algo {
        KeyAlgo::Rsa => algorithm(RSA_ENCRYPTION, true)?,
        KeyAlgo::EcdsaP256 => algorithm(ECDSA_WITH_SHA256, false)?,
        KeyAlgo::Other => return Err(CmsError::UnsupportedAlgo),
    };

    // CMS carries ECDSA signatures as a DER ECDSA-Sig-Value; CSC v2 returns raw r‖s, so normalize.
    let signature_value = match key_algo {
        KeyAlgo::EcdsaP256 => ecdsa_signature_to_der(signature)?,
        _ => signature.to_vec(),
    };
    let signed_attrs = SetOfVec::<Attribute>::from_der(signed_attrs_der)?;
    let signer_info = SignerInfo {
        version: CmsVersion::V1,
        sid,
        digest_alg: digest_alg.clone(),
        signed_attrs: Some(signed_attrs),
        signature_algorithm,
        signature: OctetString::new(signature_value)?,
        unsigned_attrs: None,
    };

    let mut digest_algorithms = SetOfVec::new();
    digest_algorithms.insert(digest_alg)?;

    let mut certs = SetOfVec::new();
    for der_bytes in cert_chain_der {
        certs.insert(CertificateChoices::Certificate(Certificate::from_der(
            der_bytes,
        )?))?;
    }

    let mut signer_infos = SetOfVec::new();
    signer_infos.insert(signer_info)?;

    let signed_data = SignedData {
        version: CmsVersion::V1,
        digest_algorithms,
        encap_content_info: EncapsulatedContentInfo {
            econtent_type: ID_DATA,
            econtent: None,
        },
        certificates: Some(CertificateSet(certs)),
        crls: None,
        signer_infos: SignerInfos(signer_infos),
    };

    let content_info = ContentInfo {
        content_type: ID_SIGNED_DATA,
        content: any_of(&signed_data)?,
    };
    Ok(content_info.to_der()?)
}

/// Re-parse an assembled CMS, returning `(signed_attrs_der, message_digest, signature, cert_chain)`
/// — the SET OF re-encoding is exactly what was signed.
#[allow(clippy::type_complexity)]
pub fn reparse_for_verify(
    content_info_der: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<Vec<u8>>), CmsError> {
    let ci = ContentInfo::from_der(content_info_der)?;
    let sd = SignedData::from_der(&ci.content.to_der()?)?;
    let si = sd
        .signer_infos
        .0
        .as_slice()
        .first()
        .ok_or_else(|| CmsError::Verify("no SignerInfo".into()))?
        .clone();
    let attrs = si
        .signed_attrs
        .ok_or_else(|| CmsError::Verify("no signed attributes".into()))?;
    let signed_attrs_der = attrs.to_der()?;

    let mut message_digest = Vec::new();
    for attr in attrs.as_slice() {
        if attr.oid == ID_MESSAGE_DIGEST {
            if let Some(v) = attr.values.as_slice().first() {
                let os = OctetString::from_der(&v.to_der()?)?;
                message_digest = os.as_bytes().to_vec();
            }
        }
    }

    let signature = si.signature.as_bytes().to_vec();

    let mut certs = Vec::new();
    if let Some(set) = sd.certificates {
        for choice in set.0.as_slice() {
            if let CertificateChoices::Certificate(c) = choice {
                certs.push(c.to_der()?);
            }
        }
    }
    Ok((signed_attrs_der, message_digest, signature, certs))
}

const ID_AA_SIGNATURE_TIME_STAMP_TOKEN: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.14");

/// Return the SignerInfo signature value of an assembled CMS (the bytes a B-T timestamp covers).
pub fn signer_signature(content_info_der: &[u8]) -> Result<Vec<u8>, CmsError> {
    let ci = ContentInfo::from_der(content_info_der)?;
    let sd = SignedData::from_der(&ci.content.to_der()?)?;
    let si = sd
        .signer_infos
        .0
        .as_slice()
        .first()
        .ok_or_else(|| CmsError::Verify("no SignerInfo".into()))?;
    Ok(si.signature.as_bytes().to_vec())
}

/// Embed an RFC 3161 timestamp token as the `signature-time-stamp` unsigned attribute (PAdES B-T).
pub fn embed_timestamp(content_info_der: &[u8], token_der: &[u8]) -> Result<Vec<u8>, CmsError> {
    let ci = ContentInfo::from_der(content_info_der)?;
    let mut sd = SignedData::from_der(&ci.content.to_der()?)?;
    let mut si = sd
        .signer_infos
        .0
        .as_slice()
        .first()
        .ok_or_else(|| CmsError::Verify("no SignerInfo".into()))?
        .clone();

    let mut values = SetOfVec::new();
    values.insert(Any::from_der(token_der)?)?;
    let attr = Attribute {
        oid: ID_AA_SIGNATURE_TIME_STAMP_TOKEN,
        values,
    };
    let mut uattrs = SetOfVec::new();
    uattrs.insert(attr)?;
    si.unsigned_attrs = Some(uattrs);

    let mut sinfos = SetOfVec::new();
    sinfos.insert(si)?;
    sd.signer_infos = SignerInfos(sinfos);

    let new_ci = ContentInfo {
        content_type: ci.content_type,
        content: any_of(&sd)?,
    };
    Ok(new_ci.to_der()?)
}

/// True if the CMS SignerInfo carries a `signature-time-stamp` unsigned attribute (B-T).
pub fn has_signature_timestamp(content_info_der: &[u8]) -> Result<bool, CmsError> {
    let ci = ContentInfo::from_der(content_info_der)?;
    let sd = SignedData::from_der(&ci.content.to_der()?)?;
    let si = sd
        .signer_infos
        .0
        .as_slice()
        .first()
        .ok_or_else(|| CmsError::Verify("no SignerInfo".into()))?;
    Ok(si.unsigned_attrs.as_ref().is_some_and(|a| {
        a.as_slice()
            .iter()
            .any(|attr| attr.oid == ID_AA_SIGNATURE_TIME_STAMP_TOKEN)
    }))
}

/// Verify the assembled CMS signature against the signer's leaf certificate (defense-in-depth: the
/// core must never report `Signed` for a signature it cannot itself verify). On success returns the
/// `message-digest` signed attribute so the caller can bind it to the document without re-parsing.
pub fn verify_signed_data(cms_der: &[u8], key_algo: KeyAlgo) -> Result<Vec<u8>, CmsError> {
    use x509_cert::spki::DecodePublicKey;
    let (signed_attrs_der, message_digest, signature, certs) = reparse_for_verify(cms_der)?;
    let leaf_der = certs.first().ok_or(CmsError::EmptyChain)?;
    let leaf = Certificate::from_der(leaf_der)?;
    let spki_der = leaf.tbs_certificate.subject_public_key_info.to_der()?;
    match key_algo {
        KeyAlgo::Rsa => {
            use rsa::signature::Verifier;
            let pk = rsa::RsaPublicKey::from_public_key_der(&spki_der)
                .map_err(|e| CmsError::Verify(e.to_string()))?;
            let vk = rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(pk);
            let sig = rsa::pkcs1v15::Signature::try_from(signature.as_slice())
                .map_err(|e| CmsError::Verify(e.to_string()))?;
            vk.verify(&signed_attrs_der, &sig)
                .map_err(|e| CmsError::Verify(e.to_string()))?;
        }
        KeyAlgo::EcdsaP256 => {
            use p256::ecdsa::signature::Verifier;
            let vk = p256::ecdsa::VerifyingKey::from_public_key_der(&spki_der)
                .map_err(|e| CmsError::Verify(e.to_string()))?;
            let sig = p256::ecdsa::Signature::from_der(&signature)
                .map_err(|e| CmsError::Verify(e.to_string()))?;
            vk.verify(&signed_attrs_der, &sig)
                .map_err(|e| CmsError::Verify(e.to_string()))?;
        }
        KeyAlgo::Other => return Err(CmsError::UnsupportedAlgo),
    }
    Ok(message_digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{
        signature::Signer as _, signature::Verifier as _, Signature as P256Sig,
        SigningKey as P256Key,
    };
    use pkcs8::DecodePrivateKey;
    use rsa::signature::SignatureEncoding;
    use sha2::Sha256;
    use x509_cert::spki::DecodePublicKey;

    const RSA_CERT: &[u8] = include_bytes!("../../../../tests/fixtures/pki/signer-rsa.cert.der");
    const RSA_KEY: &[u8] = include_bytes!("../../../../tests/fixtures/pki/signer-rsa.key.pk8");
    const EC_CERT: &[u8] = include_bytes!("../../../../tests/fixtures/pki/signer-ec.cert.der");
    const EC_KEY: &[u8] = include_bytes!("../../../../tests/fixtures/pki/signer-ec.key.pk8");

    #[test]
    fn rsa_signed_data_assembles_and_verifies() {
        let content_hash = sha256(b"the PDF byte-range content");
        let attrs = build_signed_attrs(&content_hash, RSA_CERT, 1_700_000_000).unwrap();
        assert_eq!(tbs_hash(&attrs).len(), 32);

        // Simulate Cleverbase signHash: PKCS#1 v1.5 over sha256(signedAttrs).
        let key = rsa::RsaPrivateKey::from_pkcs8_der(RSA_KEY).unwrap();
        let signer = rsa::pkcs1v15::SigningKey::<Sha256>::new(key);
        let signature = signer.sign(&attrs).to_bytes();

        let cms =
            assemble_signed_data(&[RSA_CERT.to_vec()], &attrs, &signature, KeyAlgo::Rsa).unwrap();

        let (re_attrs, md, sig, certs) = reparse_for_verify(&cms).unwrap();
        assert_eq!(md, content_hash);
        assert_eq!(certs.len(), 1);

        let leaf = Certificate::from_der(&certs[0]).unwrap();
        let spki_der = leaf
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .unwrap();
        let vk = rsa::pkcs1v15::VerifyingKey::<Sha256>::new(
            rsa::RsaPublicKey::from_public_key_der(&spki_der).unwrap(),
        );
        let parsed = rsa::pkcs1v15::Signature::try_from(sig.as_slice()).unwrap();
        vk.verify(&re_attrs, &parsed).unwrap();

        // The production self-check accepts this valid signature.
        verify_signed_data(&cms, KeyAlgo::Rsa).unwrap();
    }

    #[test]
    fn verify_signed_data_rejects_bad_signatures() {
        let content_hash = sha256(b"a document");
        let attrs = build_signed_attrs(&content_hash, RSA_CERT, 1_700_000_000).unwrap();
        // A garbage 256-byte signature assembles structurally but must fail verification.
        let cms_garbage =
            assemble_signed_data(&[RSA_CERT.to_vec()], &attrs, &[0u8; 256], KeyAlgo::Rsa).unwrap();
        assert!(verify_signed_data(&cms_garbage, KeyAlgo::Rsa).is_err());
        // An empty signature (e.g. signHash returned `[""]`) must also fail, not pass.
        let cms_empty =
            assemble_signed_data(&[RSA_CERT.to_vec()], &attrs, &[], KeyAlgo::Rsa).unwrap();
        assert!(verify_signed_data(&cms_empty, KeyAlgo::Rsa).is_err());
    }

    #[test]
    fn ecdsa_signed_data_assembles_and_verifies() {
        let content_hash = sha256(b"another document");
        let attrs = build_signed_attrs(&content_hash, EC_CERT, 1_700_000_000).unwrap();

        let key = P256Key::from_pkcs8_der(EC_KEY).unwrap();
        let sig: P256Sig = key.sign(&attrs);
        let sig_der = sig.to_der().to_bytes();

        let cms = assemble_signed_data(&[EC_CERT.to_vec()], &attrs, &sig_der, KeyAlgo::EcdsaP256)
            .unwrap();
        let (re_attrs, md, sig_bytes, certs) = reparse_for_verify(&cms).unwrap();
        assert_eq!(md, content_hash);

        let leaf = Certificate::from_der(&certs[0]).unwrap();
        let spki_der = leaf
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .unwrap();
        let vk = p256::ecdsa::VerifyingKey::from_public_key_der(&spki_der).unwrap();
        let parsed = P256Sig::from_der(&sig_bytes).unwrap();
        vk.verify(&re_attrs, &parsed).unwrap();

        // The production self-check accepts this valid ECDSA signature.
        verify_signed_data(&cms, KeyAlgo::EcdsaP256).unwrap();
    }

    #[test]
    fn ecdsa_raw_signature_is_normalized_to_der() {
        // CSC v2 returns ECDSA signatures as raw r‖s (64 bytes); we must DER-encode for CMS.
        let content_hash = sha256(b"raw ecdsa doc");
        let attrs = build_signed_attrs(&content_hash, EC_CERT, 1_700_000_000).unwrap();
        let key = P256Key::from_pkcs8_der(EC_KEY).unwrap();
        let sig: P256Sig = key.sign(&attrs);
        let raw = sig.to_bytes();
        assert_eq!(raw.as_slice().len(), 64);

        let cms = assemble_signed_data(
            &[EC_CERT.to_vec()],
            &attrs,
            raw.as_slice(),
            KeyAlgo::EcdsaP256,
        )
        .unwrap();
        let (re_attrs, _md, sig_bytes, certs) = reparse_for_verify(&cms).unwrap();
        // The stored signature must now be valid DER and verify.
        let leaf = Certificate::from_der(&certs[0]).unwrap();
        let spki_der = leaf
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .unwrap();
        let vk = p256::ecdsa::VerifyingKey::from_public_key_der(&spki_der).unwrap();
        let parsed = P256Sig::from_der(&sig_bytes).unwrap();
        vk.verify(&re_attrs, &parsed).unwrap();
    }

    #[test]
    fn signer_signature_returns_stored_der_for_ecdsa() {
        // For ECDSA the CMS stores the DER signature, so a B-T timestamp must hash THAT, not the
        // raw r‖s. signer_signature() must return the stored (DER) value.
        let content_hash = sha256(b"bt ecdsa");
        let attrs = build_signed_attrs(&content_hash, EC_CERT, 1_700_000_000).unwrap();
        let key = P256Key::from_pkcs8_der(EC_KEY).unwrap();
        let sig: P256Sig = key.sign(&attrs);
        let raw = sig.to_bytes();
        let cms = assemble_signed_data(
            &[EC_CERT.to_vec()],
            &attrs,
            raw.as_slice(),
            KeyAlgo::EcdsaP256,
        )
        .unwrap();
        let stored = signer_signature(&cms).unwrap();
        assert_ne!(
            stored.as_slice(),
            raw.as_slice(),
            "stored signature must be DER, not raw"
        );
        assert_eq!(
            stored[0], 0x30,
            "stored ECDSA signature must be a DER SEQUENCE"
        );
    }

    #[test]
    fn signing_time_uses_generalized_time_past_2050() {
        // now_unix at/after 2050-01-01 must encode signing-time as GeneralizedTime (not UTCTime).
        let attrs = build_signed_attrs(&sha256(b"x"), RSA_CERT, 2_524_608_000).unwrap();
        // The signed-attrs SET OF must still parse, and the GeneralizedTime branch (0x18) is present.
        assert!(SetOfVec::<Attribute>::from_der(&attrs).is_ok());
        assert!(attrs.windows(1).any(|w| w == [0x18]));
    }

    #[test]
    fn unsupported_algo_is_rejected() {
        let attrs = build_signed_attrs(&sha256(b"x"), RSA_CERT, 1_700_000_000).unwrap();
        let err = assemble_signed_data(&[RSA_CERT.to_vec()], &attrs, b"sig", KeyAlgo::Other);
        assert!(matches!(err, Err(CmsError::UnsupportedAlgo)));
    }
}
