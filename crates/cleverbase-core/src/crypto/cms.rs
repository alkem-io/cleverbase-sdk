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
use super::{CMS_SIGNED_DATA_OID as ID_SIGNED_DATA, RFC3161_TST_INFO_OID as ID_CT_TST_INFO};
use crate::signing::csc::KeyAlgo;

// Object identifiers (avoid depending on const-oid db layout).
const ID_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
const ID_CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
const ID_MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
const ID_SIGNING_TIME: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.5");
const ID_SIGNING_CERTIFICATE_V2: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.47");
use super::SHA256_OID as ID_SHA256;
const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const SHA256_WITH_RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

// 2050-01-01T00:00:00Z in Unix seconds — UTCTime covers up to (not incl.) this; later uses GeneralizedTime.
const UTC_TIME_UPPER_BOUND_SECS: u64 = 2_524_608_000;

/// Errors from CMS assembly/verification.
#[derive(Debug, thiserror::Error)]
pub enum CmsError {
    /// A DER encode/decode error.
    #[error("DER error: {0}")]
    Der(#[from] der::Error),
    /// A key, digest, or signature algorithm is not supported for CMS assembly or verification.
    #[error("unsupported algorithm for CMS assembly or verification")]
    UnsupportedAlgo,
    /// The certificate chain was empty.
    #[error("empty certificate chain")]
    EmptyChain,
    /// The CMS is parseable DER but is not a supported CAdES or timestamp-token shape.
    #[error("invalid CMS structure: {0}")]
    Structure(&'static str),
    /// No embedded certificate matched the CMS SignerInfo identifier.
    #[error("SignerInfo certificate is absent")]
    SignerCertificateAbsent,
    /// Signature verification failed.
    #[error("verification failed: {0}")]
    Verify(String),
    /// An RFC 3161 signature-time-stamp token is malformed, foreign, or invalidly signed.
    #[error("invalid signature-time-stamp token")]
    TimestampInvalid,
    /// An RFC 3161 signature-time-stamp token uses an unsupported algorithm.
    #[error("unsupported signature-time-stamp token algorithm")]
    TimestampUnsupported,
}

/// Verified material extracted from a detached CMS signature.
pub(crate) struct VerifiedSignedData {
    /// The signed `message-digest` attribute.
    pub message_digest: Vec<u8>,
    /// Certificate selected by SignerInfo issuer-and-serial.
    pub signer_certificate: Certificate,
    /// Key family asserted by the CMS signature AlgorithmIdentifier.
    pub key_algo: KeyAlgo,
    /// Whether a cryptographically valid RFC 3161 signature-time-stamp attribute is present.
    pub has_signature_timestamp: bool,
}

#[derive(Clone, Copy)]
enum SignedDataProfile {
    PadesDetached,
    TimestampToken,
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
    // CSC v2 returns raw fixed-width r‖s (64 bytes for P-256); DER-encode it. Split with `.split_at`
    // guarded by the length check (no panicking `[..]` index).
    if signature.len() == 64 {
        let (r_bytes, s_bytes) = signature.split_at(32);
        let sig = EcdsaSigValue {
            r: der::asn1::Uint::new(r_bytes)?,
            s: der::asn1::Uint::new(s_bytes)?,
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
// The 4-tuple is exactly the re-parsed CMS material; a named struct would obscure the 1:1 mapping
// to the values the caller verifies and is used only at this single call site.
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

/// True if the CMS SignerInfo carries a valid, signature-bound `signature-time-stamp` attribute.
pub fn has_signature_timestamp(content_info_der: &[u8]) -> Result<bool, CmsError> {
    let ci = ContentInfo::from_der(content_info_der)?;
    let sd = SignedData::from_der(&ci.content.to_der()?)?;
    let si = sd
        .signer_infos
        .0
        .as_slice()
        .first()
        .ok_or_else(|| CmsError::Verify("no SignerInfo".into()))?;
    signer_has_signature_timestamp(si)
}

fn signer_has_signature_timestamp(signer_info: &SignerInfo) -> Result<bool, CmsError> {
    let mut timestamp_attributes = signer_info
        .unsigned_attrs
        .as_ref()
        .into_iter()
        .flat_map(SetOfVec::as_slice)
        .filter(|attribute| attribute.oid == ID_AA_SIGNATURE_TIME_STAMP_TOKEN);
    let timestamp_attribute = timestamp_attributes.next();
    if timestamp_attributes.next().is_some() {
        return Err(CmsError::TimestampInvalid);
    }
    let Some(timestamp_attribute) = timestamp_attribute else {
        return Ok(false);
    };
    let [timestamp_value] = timestamp_attribute.values.as_slice() else {
        return Err(CmsError::TimestampInvalid);
    };
    let token_der = timestamp_value
        .to_der()
        .map_err(|_| CmsError::TimestampInvalid)?;
    verify_timestamp_token(&token_der, signer_info.signature.as_bytes())?;
    Ok(true)
}

fn verify_timestamp_token(token_der: &[u8], signature_value: &[u8]) -> Result<(), CmsError> {
    match verify_signed_data_profile(token_der, SignedDataProfile::TimestampToken) {
        Ok(_) => {}
        Err(CmsError::UnsupportedAlgo) => return Err(CmsError::TimestampUnsupported),
        Err(_) => return Err(CmsError::TimestampInvalid),
    }
    if crate::timestamp::parse_gen_time(token_der).is_none() {
        return Err(CmsError::TimestampInvalid);
    }
    let Some((imprint_algorithm, imprint)) =
        crate::timestamp::parse_message_imprint_with_algorithm(token_der)
    else {
        return Err(CmsError::TimestampInvalid);
    };
    let expected = crate::timestamp::hash_message_imprint(imprint_algorithm, signature_value)
        .ok_or(CmsError::TimestampUnsupported)?;
    if imprint != expected {
        return Err(CmsError::TimestampInvalid);
    }
    Ok(())
}

/// Verify the assembled CMS signature against the signer's leaf certificate (defense-in-depth: the
/// core must never report `Signed` for a signature it cannot itself verify). On success returns the
/// `message-digest` signed attribute so the caller can bind it to the document without re-parsing.
pub fn verify_signed_data(cms_der: &[u8], key_algo: KeyAlgo) -> Result<Vec<u8>, CmsError> {
    let verified = verify_signed_data_auto(cms_der)?;
    if verified.key_algo != key_algo {
        return Err(CmsError::UnsupportedAlgo);
    }
    Ok(verified.message_digest)
}

/// Verify a detached CMS using the algorithm and certificate identified by its SignerInfo.
///
/// Verification accepts the SHA-256 profile emitted by this SDK: `rsaEncryption` with PKCS #1
/// v1.5 or P-256 ECDSA with SHA-256 (`ecdsa-with-SHA256`), plus `ESSCertIDv2` with its default
/// SHA-256 algorithm and without `issuerSerial`. Other digest/signature algorithms return
/// [`CmsError::UnsupportedAlgo`]; other well-formed CMS profiles are outside this integrity
/// verifier's contract.
pub(crate) fn verify_signed_data_auto(cms_der: &[u8]) -> Result<VerifiedSignedData, CmsError> {
    verify_signed_data_profile(cms_der, SignedDataProfile::PadesDetached)
}

fn verify_signed_data_profile(
    cms_der: &[u8],
    profile: SignedDataProfile,
) -> Result<VerifiedSignedData, CmsError> {
    use x509_cert::spki::DecodePublicKey;
    let ci = ContentInfo::from_der(cms_der)?;
    if ci.content_type != ID_SIGNED_DATA {
        return Err(CmsError::Structure("ContentInfo is not signed-data"));
    }
    let sd = SignedData::from_der(&ci.content.to_der()?)?;
    let expected_content_type = match profile {
        SignedDataProfile::PadesDetached => ID_DATA,
        SignedDataProfile::TimestampToken => ID_CT_TST_INFO,
    };
    if sd.encap_content_info.econtent_type != expected_content_type {
        return Err(CmsError::Structure("unexpected encapsulated content type"));
    }
    let encapsulated_content = match (profile, sd.encap_content_info.econtent.as_ref()) {
        (SignedDataProfile::PadesDetached, None) => None,
        (SignedDataProfile::TimestampToken, Some(content)) => Some(
            OctetString::from_der(&content.to_der()?)?
                .as_bytes()
                .to_vec(),
        ),
        (SignedDataProfile::PadesDetached, Some(_)) => {
            return Err(CmsError::Structure("signature is not detached data"));
        }
        (SignedDataProfile::TimestampToken, None) => {
            return Err(CmsError::Structure("timestamp token has no TSTInfo"));
        }
    };
    let digest_algorithms = sd.digest_algorithms.as_slice();
    if digest_algorithms.len() != 1
        || digest_algorithms
            .first()
            .is_none_or(|algorithm| algorithm.oid != ID_SHA256)
    {
        return Err(CmsError::UnsupportedAlgo);
    }
    let signer_infos = sd.signer_infos.0.as_slice();
    if signer_infos.len() != 1 {
        return Err(CmsError::Structure("expected exactly one SignerInfo"));
    }
    let si = signer_infos
        .first()
        .ok_or_else(|| CmsError::Verify("no SignerInfo".into()))?;
    if si.digest_alg.oid != ID_SHA256 {
        return Err(CmsError::UnsupportedAlgo);
    }
    let key_algo = match (profile, si.signature_algorithm.oid) {
        (SignedDataProfile::PadesDetached, RSA_ENCRYPTION)
        | (SignedDataProfile::TimestampToken, RSA_ENCRYPTION | SHA256_WITH_RSA_ENCRYPTION) => {
            KeyAlgo::Rsa
        }
        (_, ECDSA_WITH_SHA256) => KeyAlgo::EcdsaP256,
        _ => return Err(CmsError::UnsupportedAlgo),
    };
    let attrs = si
        .signed_attrs
        .as_ref()
        .ok_or(CmsError::Structure("no signed attributes"))?;
    let signed_attrs_der = attrs.to_der()?;
    let signature = si.signature.as_bytes();
    let signer_certificate = signer_certificate_from(&sd, si)?;
    let message_digest = validate_signed_attributes(
        attrs,
        &signer_certificate,
        expected_content_type,
        matches!(profile, SignedDataProfile::PadesDetached),
    )?;
    let spki_der = signer_certificate
        .tbs_certificate
        .subject_public_key_info
        .to_der()?;
    if key_algo == KeyAlgo::Rsa {
        use rsa::signature::Verifier;
        let pk = rsa::RsaPublicKey::from_public_key_der(&spki_der)
            .map_err(|e| CmsError::Verify(e.to_string()))?;
        let vk = rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(pk);
        let sig = rsa::pkcs1v15::Signature::try_from(signature)
            .map_err(|e| CmsError::Verify(e.to_string()))?;
        vk.verify(&signed_attrs_der, &sig)
            .map_err(|e| CmsError::Verify(e.to_string()))?;
    } else {
        use p256::ecdsa::signature::Verifier;
        let vk = p256::ecdsa::VerifyingKey::from_public_key_der(&spki_der)
            .map_err(|e| CmsError::Verify(e.to_string()))?;
        let sig = p256::ecdsa::Signature::from_der(signature)
            .map_err(|e| CmsError::Verify(e.to_string()))?;
        vk.verify(&signed_attrs_der, &sig)
            .map_err(|e| CmsError::Verify(e.to_string()))?;
    }
    if encapsulated_content
        .as_deref()
        .is_some_and(|content| sha256(content).as_slice() != message_digest)
    {
        return Err(CmsError::Structure(
            "encapsulated content message-digest mismatch",
        ));
    }
    let has_signature_timestamp = match profile {
        SignedDataProfile::PadesDetached => signer_has_signature_timestamp(si)?,
        SignedDataProfile::TimestampToken => false,
    };
    Ok(VerifiedSignedData {
        message_digest,
        signer_certificate,
        key_algo,
        has_signature_timestamp,
    })
}

fn signer_certificate_from(sd: &SignedData, si: &SignerInfo) -> Result<Certificate, CmsError> {
    let SignerIdentifier::IssuerAndSerialNumber(sid) = &si.sid else {
        return Err(CmsError::Verify("unsupported SignerInfo identifier".into()));
    };
    let certs = sd.certificates.as_ref().ok_or(CmsError::EmptyChain)?;
    certs
        .0
        .as_slice()
        .iter()
        .filter_map(|choice| match choice {
            CertificateChoices::Certificate(cert) => Some(cert),
            CertificateChoices::Other(_) => None,
        })
        .find(|cert| {
            cert.tbs_certificate.issuer == sid.issuer
                && cert.tbs_certificate.serial_number == sid.serial_number
        })
        .cloned()
        .ok_or(CmsError::SignerCertificateAbsent)
}

fn single_attribute<'a>(
    attrs: &'a SetOfVec<Attribute>,
    oid: ObjectIdentifier,
    name: &'static str,
) -> Result<&'a Attribute, CmsError> {
    let mut matches = attrs
        .as_slice()
        .iter()
        .filter(|attribute| attribute.oid == oid);
    let Some(attribute) = matches.next() else {
        return Err(CmsError::Structure(name));
    };
    if matches.next().is_some() || attribute.values.as_slice().len() != 1 {
        return Err(CmsError::Structure(name));
    }
    Ok(attribute)
}

fn validate_signed_attributes(
    attrs: &SetOfVec<Attribute>,
    signer_certificate: &Certificate,
    expected_content_type: ObjectIdentifier,
    require_pades_attributes: bool,
) -> Result<Vec<u8>, CmsError> {
    let content_type = single_attribute(attrs, ID_CONTENT_TYPE, "invalid content-type attribute")?;
    let content_type_value = content_type
        .values
        .as_slice()
        .first()
        .ok_or(CmsError::Structure("invalid content-type attribute"))?;
    if ObjectIdentifier::from_der(&content_type_value.to_der()?)? != expected_content_type {
        return Err(CmsError::Structure("signed content-type does not match"));
    }

    let digest = single_attribute(attrs, ID_MESSAGE_DIGEST, "invalid message-digest attribute")?;
    let digest_value = digest
        .values
        .as_slice()
        .first()
        .ok_or(CmsError::Structure("invalid message-digest attribute"))?;
    let message_digest = OctetString::from_der(&digest_value.to_der()?)?
        .as_bytes()
        .to_vec();
    if message_digest.len() != 32 {
        return Err(CmsError::Structure("message-digest is not SHA-256 length"));
    }

    if require_pades_attributes {
        validate_pades_attributes(attrs, signer_certificate)?;
    }
    Ok(message_digest)
}

fn validate_pades_attributes(
    attrs: &SetOfVec<Attribute>,
    signer_certificate: &Certificate,
) -> Result<(), CmsError> {
    let signing_time = single_attribute(attrs, ID_SIGNING_TIME, "invalid signing-time attribute")?;
    let signing_time_der = signing_time
        .values
        .as_slice()
        .first()
        .ok_or(CmsError::Structure("invalid signing-time attribute"))?
        .to_der()?;
    if UtcTime::from_der(&signing_time_der).is_err()
        && GeneralizedTime::from_der(&signing_time_der).is_err()
    {
        return Err(CmsError::Structure("invalid signing-time attribute"));
    }

    let signing_certificate = single_attribute(
        attrs,
        ID_SIGNING_CERTIFICATE_V2,
        "invalid signing-certificate-v2 attribute",
    )?;
    let signing_certificate_value =
        signing_certificate
            .values
            .as_slice()
            .first()
            .ok_or(CmsError::Structure(
                "invalid signing-certificate-v2 attribute",
            ))?;
    let parsed = SigningCertificateV2::from_der(&signing_certificate_value.to_der()?)?;
    let signer_certificate_der = signer_certificate.to_der()?;
    if parsed.certs.len() != 1
        || parsed
            .certs
            .first()
            .is_none_or(|cert| cert.cert_hash.as_bytes() != sha256(&signer_certificate_der))
    {
        return Err(CmsError::Structure(
            "signing-certificate-v2 does not identify the signer",
        ));
    }
    Ok(())
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
    const RSA_TIMESTAMP_TOKEN: &[u8] =
        include_bytes!("../../../../tests/fixtures/pades-bt/rsa-token.der");

    fn valid_rsa_cms() -> Vec<u8> {
        let content_hash = sha256(b"CMS verifier structural fixture");
        let attrs = build_signed_attrs(&content_hash, RSA_CERT, 1_700_000_000).unwrap();
        let key = rsa::RsaPrivateKey::from_pkcs8_der(RSA_KEY).unwrap();
        let signature = rsa::pkcs1v15::SigningKey::<Sha256>::new(key)
            .sign(&attrs)
            .to_bytes();
        assemble_signed_data(&[RSA_CERT.to_vec()], &attrs, &signature, KeyAlgo::Rsa).unwrap()
    }

    fn rewrite_signed_data(
        cms: &[u8],
        mutate: impl FnOnce(&mut ContentInfo, &mut SignedData),
    ) -> Vec<u8> {
        let mut content_info = ContentInfo::from_der(cms).unwrap();
        let mut signed_data =
            SignedData::from_der(&content_info.content.to_der().unwrap()).unwrap();
        mutate(&mut content_info, &mut signed_data);
        content_info.content = any_of(&signed_data).unwrap();
        content_info.to_der().unwrap()
    }

    fn rewrite_signer_info(signed_data: &mut SignedData, mutate: impl FnOnce(&mut SignerInfo)) {
        let mut signer_info = signed_data
            .signer_infos
            .0
            .as_slice()
            .first()
            .unwrap()
            .clone();
        mutate(&mut signer_info);
        let mut signer_infos = SetOfVec::new();
        signer_infos.insert(signer_info).unwrap();
        signed_data.signer_infos = SignerInfos(signer_infos);
    }

    fn replace_signed_attribute(
        signer_info: &mut SignerInfo,
        oid: ObjectIdentifier,
        replacement: Option<Attribute>,
    ) {
        let mut attributes = SetOfVec::new();
        for attribute in signer_info.signed_attrs.as_ref().unwrap().as_slice() {
            if attribute.oid != oid {
                attributes.insert(attribute.clone()).unwrap();
            }
        }
        if let Some(attribute) = replacement {
            attributes.insert(attribute).unwrap();
        }
        signer_info.signed_attrs = Some(attributes);
    }

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
    fn signer_certificate_is_resolved_when_leaf_is_not_first_in_der_set() {
        let content_hash = sha256(b"certificate SET ordering is not chain ordering");
        let attrs = build_signed_attrs(&content_hash, RSA_CERT, 1_700_000_000).unwrap();
        let key = rsa::RsaPrivateKey::from_pkcs8_der(RSA_KEY).unwrap();
        let signer = rsa::pkcs1v15::SigningKey::<Sha256>::new(key);
        let signature = signer.sign(&attrs).to_bytes();

        // DER SET ordering places the shorter EC certificate before the RSA signer certificate.
        let cms = assemble_signed_data(
            &[RSA_CERT.to_vec(), EC_CERT.to_vec()],
            &attrs,
            &signature,
            KeyAlgo::Rsa,
        )
        .unwrap();
        let (_, _, _, encoded_order) = reparse_for_verify(&cms).unwrap();
        assert_eq!(encoded_order.first().map(Vec::as_slice), Some(EC_CERT));

        let verified = verify_signed_data_auto(&cms).unwrap();
        assert_eq!(verified.signer_certificate.to_der().unwrap(), RSA_CERT);
        assert_eq!(verified.key_algo, KeyAlgo::Rsa);
    }

    #[test]
    fn verifier_rejects_non_detached_or_ambiguous_cms_shapes() {
        let cms = valid_rsa_cms();
        let wrong_content_type = rewrite_signed_data(&cms, |content_info, _| {
            content_info.content_type = ID_DATA;
        });
        assert!(matches!(
            verify_signed_data_auto(&wrong_content_type),
            Err(CmsError::Structure("ContentInfo is not signed-data"))
        ));

        let attached_content = rewrite_signed_data(&cms, |_, signed_data| {
            signed_data.encap_content_info.econtent =
                Some(any_of(&OctetString::new(b"attached".to_vec()).unwrap()).unwrap());
        });
        assert!(matches!(
            verify_signed_data_auto(&attached_content),
            Err(CmsError::Structure("signature is not detached data"))
        ));

        let no_digest_algorithm = rewrite_signed_data(&cms, |_, signed_data| {
            signed_data.digest_algorithms = SetOfVec::new();
        });
        assert!(matches!(
            verify_signed_data_auto(&no_digest_algorithm),
            Err(CmsError::UnsupportedAlgo)
        ));

        let no_signer = rewrite_signed_data(&cms, |_, signed_data| {
            signed_data.signer_infos = SignerInfos(SetOfVec::new());
        });
        assert!(matches!(
            verify_signed_data_auto(&no_signer),
            Err(CmsError::Structure("expected exactly one SignerInfo"))
        ));
    }

    #[test]
    fn verifier_rejects_unsupported_algorithms_and_missing_signer_material() {
        let cms = valid_rsa_cms();
        let wrong_digest = rewrite_signed_data(&cms, |_, signed_data| {
            rewrite_signer_info(signed_data, |signer_info| {
                signer_info.digest_alg.oid = ID_DATA;
            });
        });
        assert!(matches!(
            verify_signed_data_auto(&wrong_digest),
            Err(CmsError::UnsupportedAlgo)
        ));

        let wrong_signature_algorithm = rewrite_signed_data(&cms, |_, signed_data| {
            rewrite_signer_info(signed_data, |signer_info| {
                signer_info.signature_algorithm.oid = ID_DATA;
            });
        });
        assert!(matches!(
            verify_signed_data_auto(&wrong_signature_algorithm),
            Err(CmsError::UnsupportedAlgo)
        ));

        let pades_rsa_digest_algorithm = rewrite_signed_data(&cms, |_, signed_data| {
            rewrite_signer_info(signed_data, |signer_info| {
                signer_info.signature_algorithm.oid = SHA256_WITH_RSA_ENCRYPTION;
            });
        });
        assert!(matches!(
            verify_signed_data_auto(&pades_rsa_digest_algorithm),
            Err(CmsError::UnsupportedAlgo)
        ));

        let no_signed_attributes = rewrite_signed_data(&cms, |_, signed_data| {
            rewrite_signer_info(signed_data, |signer_info| signer_info.signed_attrs = None);
        });
        assert!(matches!(
            verify_signed_data_auto(&no_signed_attributes),
            Err(CmsError::Structure("no signed attributes"))
        ));

        let no_certificates = rewrite_signed_data(&cms, |_, signed_data| {
            signed_data.certificates = None;
        });
        assert!(matches!(
            verify_signed_data_auto(&no_certificates),
            Err(CmsError::EmptyChain)
        ));

        assert!(matches!(
            verify_signed_data(&cms, KeyAlgo::EcdsaP256),
            Err(CmsError::UnsupportedAlgo)
        ));
    }

    #[test]
    fn verifier_rejects_missing_or_malformed_signed_attributes() {
        let cms = valid_rsa_cms();

        let missing_content_type = rewrite_signed_data(&cms, |_, signed_data| {
            rewrite_signer_info(signed_data, |signer_info| {
                replace_signed_attribute(signer_info, ID_CONTENT_TYPE, None);
            });
        });
        assert!(matches!(
            verify_signed_data_auto(&missing_content_type),
            Err(CmsError::Structure("invalid content-type attribute"))
        ));

        let wrong_content_type = rewrite_signed_data(&cms, |_, signed_data| {
            rewrite_signer_info(signed_data, |signer_info| {
                replace_signed_attribute(
                    signer_info,
                    ID_CONTENT_TYPE,
                    Some(
                        single_value_attr(ID_CONTENT_TYPE, any_of(&ID_SIGNED_DATA).unwrap())
                            .unwrap(),
                    ),
                );
            });
        });
        assert!(matches!(
            verify_signed_data_auto(&wrong_content_type),
            Err(CmsError::Structure("signed content-type does not match"))
        ));

        let short_digest = rewrite_signed_data(&cms, |_, signed_data| {
            rewrite_signer_info(signed_data, |signer_info| {
                replace_signed_attribute(
                    signer_info,
                    ID_MESSAGE_DIGEST,
                    Some(
                        single_value_attr(
                            ID_MESSAGE_DIGEST,
                            any_of(&OctetString::new(vec![0; 31]).unwrap()).unwrap(),
                        )
                        .unwrap(),
                    ),
                );
            });
        });
        assert!(matches!(
            verify_signed_data_auto(&short_digest),
            Err(CmsError::Structure("message-digest is not SHA-256 length"))
        ));

        let invalid_signing_time = rewrite_signed_data(&cms, |_, signed_data| {
            rewrite_signer_info(signed_data, |signer_info| {
                replace_signed_attribute(
                    signer_info,
                    ID_SIGNING_TIME,
                    Some(single_value_attr(ID_SIGNING_TIME, any_of(&Null).unwrap()).unwrap()),
                );
            });
        });
        assert!(matches!(
            verify_signed_data_auto(&invalid_signing_time),
            Err(CmsError::Structure("invalid signing-time attribute"))
        ));

        let wrong_signing_certificate = rewrite_signed_data(&cms, |_, signed_data| {
            rewrite_signer_info(signed_data, |signer_info| {
                let signing_certificate = SigningCertificateV2 {
                    certs: vec![EssCertIdV2 {
                        cert_hash: OctetString::new(vec![0; 32]).unwrap(),
                    }],
                };
                replace_signed_attribute(
                    signer_info,
                    ID_SIGNING_CERTIFICATE_V2,
                    Some(
                        single_value_attr(
                            ID_SIGNING_CERTIFICATE_V2,
                            any_of(&signing_certificate).unwrap(),
                        )
                        .unwrap(),
                    ),
                );
            });
        });
        assert!(matches!(
            verify_signed_data_auto(&wrong_signing_certificate),
            Err(CmsError::Structure(
                "signing-certificate-v2 does not identify the signer"
            ))
        ));
    }

    #[test]
    fn verifier_rejects_ambiguous_timestamp_attribute() {
        let cms = valid_rsa_cms();
        let ambiguous_timestamp = rewrite_signed_data(&cms, |_, signed_data| {
            rewrite_signer_info(signed_data, |signer_info| {
                let mut values = SetOfVec::new();
                values.insert(any_of(&Null).unwrap()).unwrap();
                values
                    .insert(any_of(&OctetString::new(vec![1]).unwrap()).unwrap())
                    .unwrap();
                let mut unsigned_attributes = SetOfVec::new();
                unsigned_attributes
                    .insert(Attribute {
                        oid: ID_AA_SIGNATURE_TIME_STAMP_TOKEN,
                        values,
                    })
                    .unwrap();
                signer_info.unsigned_attrs = Some(unsigned_attributes);
            });
        });
        assert!(matches!(
            verify_signed_data_auto(&ambiguous_timestamp),
            Err(CmsError::TimestampInvalid)
        ));
    }

    #[test]
    fn timestamp_attribute_must_contain_a_bound_rfc3161_token() {
        let cms = valid_rsa_cms();
        let timestamp_with_arbitrary_value = embed_timestamp(&cms, &[0x05, 0x00]).unwrap();

        assert!(matches!(
            verify_signed_data_auto(&timestamp_with_arbitrary_value),
            Err(CmsError::TimestampInvalid)
        ));

        let data_content_token = rewrite_signed_data(RSA_TIMESTAMP_TOKEN, |_, signed_data| {
            signed_data.encap_content_info.econtent_type = ID_DATA;
        });
        let timestamp_with_data_content = embed_timestamp(&cms, &data_content_token).unwrap();
        assert!(matches!(
            verify_signed_data_auto(&timestamp_with_data_content),
            Err(CmsError::TimestampInvalid)
        ));
    }

    #[test]
    fn timestamp_token_with_an_unsupported_cms_digest_is_distinguished() {
        let unsupported_token = rewrite_signed_data(RSA_TIMESTAMP_TOKEN, |_, signed_data| {
            let mut digest_algorithms = SetOfVec::new();
            digest_algorithms
                .insert(algorithm(ID_DATA, false).unwrap())
                .unwrap();
            signed_data.digest_algorithms = digest_algorithms;
        });

        assert!(matches!(
            verify_timestamp_token(&unsupported_token, b"a signature value"),
            Err(CmsError::TimestampUnsupported)
        ));
    }

    #[test]
    fn timestamp_token_signer_must_come_from_its_own_certificate_set() {
        let token_without_its_signer =
            rewrite_signed_data(RSA_TIMESTAMP_TOKEN, |_, signed_data| {
                signed_data.certificates = None;
            });
        assert!(matches!(
            verify_timestamp_token(&token_without_its_signer, b"a signature value"),
            Err(CmsError::TimestampInvalid)
        ));
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

    /// ASN.1 tag of the signing-time attribute's value in freshly built signed attributes.
    fn signing_time_tag(now_unix: i64) -> der::Tag {
        use der::Tagged;
        let der = build_signed_attrs(&sha256(b"x"), RSA_CERT, now_unix).unwrap();
        let attrs = SetOfVec::<Attribute>::from_der(&der).unwrap();
        let st = attrs
            .iter()
            .find(|a| a.oid == ID_SIGNING_TIME)
            .expect("signing-time attribute present");
        st.values.iter().next().expect("a signing-time value").tag()
    }

    #[test]
    fn signing_time_switches_to_generalized_time_at_2050() {
        // CMS/X.509 require UTCTime for years < 2050 and GeneralizedTime from 2050 on. Assert the
        // signing-time value's *tag* switches at the boundary — not merely that some 0x18 byte
        // appears in the DER (which is true regardless of the encoding chosen).
        assert_eq!(signing_time_tag(1_700_000_000), der::Tag::UtcTime); // 2023
        assert_eq!(signing_time_tag(2_524_608_000), der::Tag::GeneralizedTime); // 2050-01-01
    }

    #[test]
    fn unsupported_algo_is_rejected() {
        let attrs = build_signed_attrs(&sha256(b"x"), RSA_CERT, 1_700_000_000).unwrap();
        let err = assemble_signed_data(&[RSA_CERT.to_vec()], &attrs, b"sig", KeyAlgo::Other);
        assert!(matches!(err, Err(CmsError::UnsupportedAlgo)));
    }
}
