//! Integrity-only verification of a single PAdES signature.
//!
//! This intentionally verifies only the embedded CMS against the document's `/ByteRange` and
//! signer certificate. It accepts the SHA-256 CMS profile emitted by this SDK: `rsaEncryption`
//! with PKCS #1 v1.5 or `ecdsa-with-SHA256`, and the SDK's minimal `ESSCertIDv2` form. Other valid
//! CMS profiles may return an unsupported or malformed verdict rather than an integrity verdict.
//! It does not establish certificate trust, trusted-list or revocation status, signer
//! authorization, or RFC 3161 token validity; `integrity = true` is not qualified validation.

use core::mem::size_of;
use lopdf::{Document, Object};
use serde::{Deserialize, Serialize};

use crate::types::ConformanceLevel;

/// A machine-readable limitation or failure observed while verifying a PDF.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationReason {
    /// The input does not start with a PDF header.
    NotPdf,
    /// The input starts with a PDF header but is not a parseable PDF.
    MalformedPdf,
    /// No signature dictionary was found.
    MissingSignature,
    /// The PDF has more than one signature; co-signing validation is a later phase.
    MultipleSignaturesUnsupported,
    /// The signature's `/ByteRange` is malformed or inconsistent with `/Contents`.
    MalformedByteRange,
    /// The signature uses a detached-signature subfilter this verifier does not support.
    UnsupportedSubfilter,
    /// Bytes appear after the final signed range.
    UnsignedSuffix,
    /// The signature `/Contents` value is not valid hex-encoded CMS data.
    InvalidContents,
    /// The embedded CMS cannot be parsed.
    MalformedCms,
    /// The CMS has no certificate matching its SignerInfo.
    MissingSignerCertificate,
    /// The CMS digest or signature algorithm is not supported by this verifier.
    UnsupportedSignatureAlgorithm,
    /// The CMS signature does not verify against the embedded signer certificate.
    InvalidSignature,
    /// The CMS message-digest differs from the PDF ByteRange digest.
    MessageDigestMismatch,
}

/// Identity fields read from the embedded signer certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PdfSigner {
    /// Canonical uppercase certificate serial without separators or DER sign padding.
    pub serial_number: String,
    /// Subject common name (`CN`), or empty if the certificate has none.
    pub common_name: String,
}

/// The integrity-only result for one PDF signature.
///
/// A malformed, unsupported, or invalid document is represented as `integrity = false`, not as
/// an API error, so callers can safely display a deterministic validation verdict. An integrity
/// verdict establishes neither certificate trust nor signer authorization and MUST NOT be
/// presented as qualified validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PdfVerification {
    /// Whether the CMS signature and signed document bytes are internally consistent.
    pub integrity: bool,
    /// The detected PAdES profile, only when integrity is true.
    pub profile: Option<ConformanceLevel>,
    /// The embedded signer's identity, only when integrity is true.
    pub signer: Option<PdfSigner>,
    /// Failure codes. Empty if and only if `integrity` is true.
    pub reasons: Vec<VerificationReason>,
}

/// Verify one unsigned-or-singly-signed PDF against the SHA-256 CMS profile emitted by this SDK.
///
/// This operation establishes document/CMS integrity only. It does not establish certificate
/// trust, trusted-list or revocation status, signer authorization, or RFC 3161 token validity.
pub fn verify_pdf(document: &[u8]) -> PdfVerification {
    if !document.starts_with(b"%PDF-") {
        return PdfVerification {
            integrity: false,
            profile: None,
            signer: None,
            reasons: vec![VerificationReason::NotPdf],
        };
    }

    let extracted = match extract_cms(document) {
        Ok(extracted) => extracted,
        Err(reason) => {
            return PdfVerification {
                integrity: false,
                profile: None,
                signer: None,
                reasons: vec![reason],
            };
        }
    };

    let (cms_der, byte_range_digest) = extracted;
    let verified = match crate::crypto::cms::verify_signed_data_auto(&cms_der) {
        Ok(verified) => verified,
        Err(error) => return invalid(cms_failure_reason(&error)),
    };
    if verified.message_digest.as_slice() != byte_range_digest {
        return invalid(VerificationReason::MessageDigestMismatch);
    }
    let signer =
        crate::signing::csc::signer_identity_from_certificate(&verified.signer_certificate);
    PdfVerification {
        integrity: true,
        profile: Some(if verified.has_signature_timestamp {
            ConformanceLevel::BT
        } else {
            ConformanceLevel::BB
        }),
        signer: Some(PdfSigner {
            serial_number: signer.serial_number,
            common_name: signer.common_name,
        }),
        reasons: Vec::new(),
    }
}

fn cms_failure_reason(error: &crate::crypto::cms::CmsError) -> VerificationReason {
    match error {
        crate::crypto::cms::CmsError::Der(_) | crate::crypto::cms::CmsError::Structure(_) => {
            VerificationReason::MalformedCms
        }
        crate::crypto::cms::CmsError::UnsupportedAlgo => {
            VerificationReason::UnsupportedSignatureAlgorithm
        }
        crate::crypto::cms::CmsError::EmptyChain
        | crate::crypto::cms::CmsError::SignerCertificateAbsent => {
            VerificationReason::MissingSignerCertificate
        }
        crate::crypto::cms::CmsError::Verify(_) => VerificationReason::InvalidSignature,
    }
}

fn invalid(reason: VerificationReason) -> PdfVerification {
    PdfVerification {
        integrity: false,
        profile: None,
        signer: None,
        reasons: vec![reason],
    }
}

/// Extract the padded DER CMS from the one detached PDF signature.
///
/// The parser is deliberately anchored on ByteRange offsets, never on the first `/Contents`
/// keyword: a regular PDF page may contain unrelated content streams. The gap is raw hex; its
/// `<` and `>` delimiters are part of the signed ranges immediately outside that gap.
fn extract_cms(document: &[u8]) -> Result<(Vec<u8>, [u8; 32]), VerificationReason> {
    let parsed = Document::load_mem(document).map_err(|_| VerificationReason::MalformedPdf)?;
    let mut signatures = parsed.objects.values().filter_map(|object| {
        let dictionary = object.as_dict().ok()?;
        crate::pades::container::is_signature_dictionary(dictionary).then_some(dictionary)
    });
    let signature = signatures
        .next()
        .ok_or(VerificationReason::MissingSignature)?;
    if signatures.next().is_some() {
        return Err(VerificationReason::MultipleSignaturesUnsupported);
    }
    let signature_type = signature
        .get_deref(b"Type", &parsed)
        .and_then(Object::as_name)
        .map_err(|_| VerificationReason::MalformedCms)?;
    let sub_filter = signature
        .get_deref(b"SubFilter", &parsed)
        .and_then(Object::as_name)
        .map_err(|_| VerificationReason::MalformedCms)?;
    if signature_type != b"Sig" {
        return Err(VerificationReason::MalformedCms);
    }
    if sub_filter != b"ETSI.CAdES.detached" {
        return Err(VerificationReason::UnsupportedSubfilter);
    }
    let byte_range = signature
        .get_deref(b"ByteRange", &parsed)
        .and_then(Object::as_array)
        .map_err(|_| VerificationReason::MalformedByteRange)?;
    let values = byte_range
        .iter()
        .map(|value| {
            parsed
                .dereference(value)
                .and_then(|(_, value)| value.as_i64())
                .ok()
                .and_then(|value| usize::try_from(value).ok())
                .ok_or(VerificationReason::MalformedByteRange)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let [zero, first_len, second_start, second_len] = values.as_slice() else {
        return Err(VerificationReason::MalformedByteRange);
    };
    if *zero != 0 || *first_len == 0 || first_len >= second_start {
        return Err(VerificationReason::MalformedByteRange);
    }
    let end = second_start
        .checked_add(*second_len)
        .ok_or(VerificationReason::MalformedByteRange)?;
    if end < document.len() {
        return Err(VerificationReason::UnsignedSuffix);
    }
    if end > document.len() {
        return Err(VerificationReason::MalformedByteRange);
    }
    // Equality above proves second_start <= end == len, and first_len < second_start was checked.
    let (first_and_gap, second_range) = document.split_at(*second_start);
    let (first_range, hex) = first_and_gap.split_at(*first_len);
    if first_range.last() != Some(&b'<') || second_range.first() != Some(&b'>') {
        return Err(VerificationReason::MalformedByteRange);
    }
    let decoded = decode_hex(hex)?;
    let parsed_contents = signature
        .get_deref(b"Contents", &parsed)
        .and_then(Object::as_str)
        .map_err(|_| VerificationReason::InvalidContents)?;
    if parsed_contents != decoded {
        return Err(VerificationReason::InvalidContents);
    }
    let der_len = der_length(&decoded).ok_or(VerificationReason::InvalidContents)?;
    if decoded
        .get(der_len..)
        .is_none_or(|padding| padding.iter().any(|byte| *byte != 0))
    {
        return Err(VerificationReason::InvalidContents);
    }
    let cms_der = decoded
        .get(..der_len)
        .map(ToOwned::to_owned)
        .ok_or(VerificationReason::InvalidContents)?;
    let byte_range_digest =
        crate::pades::container::byte_range_digest(document, (*first_len, *second_start))
            .ok_or(VerificationReason::MalformedByteRange)?;
    Ok((cms_der, byte_range_digest))
}

fn decode_hex(input: &[u8]) -> Result<Vec<u8>, VerificationReason> {
    if input.is_empty() || input.len() % 2 != 0 {
        return Err(VerificationReason::InvalidContents);
    }
    input
        .chunks_exact(2)
        .map(|pair| {
            let high = pair
                .first()
                .copied()
                .and_then(crate::util::hex_value)
                .ok_or(VerificationReason::InvalidContents)?;
            let low = pair
                .get(1)
                .copied()
                .and_then(crate::util::hex_value)
                .ok_or(VerificationReason::InvalidContents)?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn der_length(der: &[u8]) -> Option<usize> {
    der.first()?;
    let length_octet = *der.get(1)?;
    if length_octet & 0x80 == 0 {
        return 2usize.checked_add(usize::from(length_octet));
    }
    let width = usize::from(length_octet & 0x7f);
    if width == 0 || width > size_of::<usize>() {
        return None;
    }
    let bytes = der.get(2..2usize.checked_add(width)?)?;
    let content_len = bytes.iter().try_fold(0usize, |acc, byte| {
        acc.checked_mul(256)?.checked_add(usize::from(*byte))
    })?;
    2usize.checked_add(width)?.checked_add(content_len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::cms::CmsError;
    use lopdf::{Dictionary, Object};
    use pkcs8::DecodePrivateKey;
    use rsa::signature::{SignatureEncoding, Signer};

    const RSA_CERT: &[u8] = include_bytes!("../../../tests/fixtures/pki/signer-rsa.cert.der");
    const RSA_KEY: &[u8] = include_bytes!("../../../tests/fixtures/pki/signer-rsa.key.pk8");

    fn signed_pdf_parts(with_timestamp: bool) -> (Vec<u8>, Vec<u8>, (usize, usize)) {
        let mut document = Document::with_version("1.7");
        let pages_id = document.new_object_id();
        let mut page = Dictionary::new();
        page.set("Type", Object::Name(b"Page".to_vec()));
        page.set("Parent", Object::Reference(pages_id));
        page.set(
            "MediaBox",
            Object::Array(
                vec![0, 0, 612, 792]
                    .into_iter()
                    .map(Object::Integer)
                    .collect(),
            ),
        );
        let page_id = document.add_object(Object::Dictionary(page));
        let mut pages = Dictionary::new();
        pages.set("Type", Object::Name(b"Pages".to_vec()));
        pages.set("Kids", Object::Array(vec![Object::Reference(page_id)]));
        pages.set("Count", Object::Integer(1));
        document.objects.insert(pages_id, Object::Dictionary(pages));
        let mut catalog = Dictionary::new();
        catalog.set("Type", Object::Name(b"Catalog".to_vec()));
        catalog.set("Pages", Object::Reference(pages_id));
        let catalog_id = document.add_object(Object::Dictionary(catalog));
        document.trailer.set("Root", Object::Reference(catalog_id));
        let mut unsigned = Vec::new();
        document.save_to(&mut unsigned).unwrap();

        let prepared = crate::pades::container::prepare(&unsigned, None, None, None).unwrap();
        let attrs =
            crate::crypto::cms::build_signed_attrs(&prepared.content_hash, RSA_CERT, 1_781_000_000)
                .unwrap();
        let key = rsa::RsaPrivateKey::from_pkcs8_der(RSA_KEY).unwrap();
        let signature = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(key)
            .sign(&attrs)
            .to_bytes();
        let mut cms = crate::crypto::cms::assemble_signed_data(
            &[RSA_CERT.to_vec()],
            &attrs,
            &signature,
            crate::signing::csc::KeyAlgo::Rsa,
        )
        .unwrap();
        if with_timestamp {
            // The integrity-only verifier records the presence of a timestamp attribute but never
            // treats this deliberately minimal DER value as a verified RFC 3161 token.
            cms = crate::crypto::cms::embed_timestamp(&cms, &[0x05, 0x00]).unwrap();
        }
        let mut signed = prepared.staged_pdf;
        crate::pades::container::embed_cms(&mut signed, prepared.contents_span, &cms).unwrap();
        (signed, signature.to_vec(), prepared.contents_span)
    }

    fn signed_pdf(with_timestamp: bool) -> Vec<u8> {
        signed_pdf_parts(with_timestamp).0
    }

    fn rewrite_signature_dictionary(pdf: &[u8], mutate: impl FnOnce(&mut Dictionary)) -> Vec<u8> {
        let mut document = Document::load_mem(pdf).unwrap();
        let signature = document
            .objects
            .values_mut()
            .find_map(|object| {
                let dictionary = object.as_dict_mut().ok()?;
                dictionary.get(b"ByteRange").is_ok().then_some(dictionary)
            })
            .unwrap();
        mutate(signature);
        let mut rewritten = Vec::new();
        document.save_to(&mut rewritten).unwrap();
        rewritten
    }

    #[test]
    fn valid_b_b_and_b_t_results_cover_the_public_verdict() {
        let b_b = verify_pdf(&signed_pdf(false));
        assert!(b_b.integrity);
        assert_eq!(b_b.profile, Some(ConformanceLevel::BB));
        assert!(b_b.reasons.is_empty());
        assert_eq!(b_b.signer.as_ref().unwrap().common_name, "Jane Doe");

        let b_t = verify_pdf(&signed_pdf(true));
        assert!(b_t.integrity);
        assert_eq!(b_t.profile, Some(ConformanceLevel::BT));
        assert!(b_t.reasons.is_empty());
    }

    #[test]
    fn changed_signed_bytes_report_a_digest_mismatch() {
        let mut signed = signed_pdf(false);
        signed[7] = b'6';

        assert_eq!(
            verify_pdf(&signed).reasons,
            vec![VerificationReason::MessageDigestMismatch]
        );
    }

    #[test]
    fn malformed_signature_dictionary_shapes_are_rejected() {
        let signed = signed_pdf(false);
        let cases = [
            rewrite_signature_dictionary(&signed, |signature| {
                signature.set("Type", Object::Name(b"NotSig".to_vec()));
            }),
            rewrite_signature_dictionary(&signed, |signature| {
                signature.set(
                    "ByteRange",
                    Object::String(b"no array".to_vec(), lopdf::StringFormat::Literal),
                );
            }),
            rewrite_signature_dictionary(&signed, |signature| {
                signature.set(
                    "ByteRange",
                    Object::Array(vec![0, 1, 2].into_iter().map(Object::Integer).collect()),
                );
            }),
            rewrite_signature_dictionary(&signed, |signature| {
                signature.set(
                    "ByteRange",
                    Object::Array(vec![0, -1, 2, 3].into_iter().map(Object::Integer).collect()),
                );
            }),
            rewrite_signature_dictionary(&signed, |signature| {
                signature.set(
                    "ByteRange",
                    Object::Array(vec![1, 1, 2, 3].into_iter().map(Object::Integer).collect()),
                );
            }),
            rewrite_signature_dictionary(&signed, |signature| {
                signature.set(
                    "ByteRange",
                    Object::Array(
                        vec![0, 1, i64::MAX, i64::MAX]
                            .into_iter()
                            .map(Object::Integer)
                            .collect(),
                    ),
                );
            }),
        ];
        for malformed in cases {
            let verdict = verify_pdf(&malformed);
            assert!(!verdict.integrity);
            assert!(matches!(
                verdict.reasons.as_slice(),
                [VerificationReason::MalformedCms | VerificationReason::MalformedByteRange]
            ));
        }
    }

    #[test]
    fn a_well_formed_but_unsupported_subfilter_is_distinguished() {
        let signed = rewrite_signature_dictionary(&signed_pdf(false), |signature| {
            signature.set("SubFilter", Object::Name(b"adbe.pkcs7.detached".to_vec()));
        });

        assert_eq!(
            verify_pdf(&signed).reasons,
            vec![VerificationReason::UnsupportedSubfilter]
        );
    }

    #[test]
    fn one_valid_hex_byte_flip_inside_contents_invalidates_the_signature() {
        let (mut signed, signature, contents_span) = signed_pdf_parts(false);
        let (cms_der, _) = extract_cms(&signed).unwrap();
        let signature_offset = cms_der
            .windows(signature.len())
            .position(|window| window == signature)
            .unwrap();
        let changed_byte = signature_offset + signature.len() / 2;
        let high_nibble = contents_span.0 + changed_byte * 2;
        signed[high_nibble] = if signed[high_nibble] == b'0' {
            b'1'
        } else {
            b'0'
        };

        assert_eq!(
            verify_pdf(&signed).reasons,
            vec![VerificationReason::InvalidSignature]
        );
    }

    #[test]
    fn hexadecimal_and_der_length_parsers_cover_their_strict_contract() {
        assert_eq!(decode_hex(b"00aAFF").unwrap(), vec![0x00, 0xaa, 0xff]);
        assert!(decode_hex(b"").is_err());
        assert!(decode_hex(b"0").is_err());
        assert!(decode_hex(b"GG").is_err());

        assert_eq!(der_length(&[0x30, 0x01, 0x00]), Some(3));
        assert_eq!(der_length(&[0x30, 0x81, 0x01, 0x00]), Some(4));
        assert_eq!(der_length(&[]), None);
        assert_eq!(der_length(&[0x30]), None);
        assert_eq!(der_length(&[0x30, 0x80]), None);
        assert_eq!(der_length(&[0x30, 0x89]), None);
        assert_eq!(der_length(&[0x30, 0x82, 0xff]), None);
    }

    #[test]
    fn cms_failures_map_to_the_public_reason_taxonomy() {
        let cases = [
            (
                CmsError::Structure("bad shape"),
                VerificationReason::MalformedCms,
            ),
            (
                CmsError::UnsupportedAlgo,
                VerificationReason::UnsupportedSignatureAlgorithm,
            ),
            (
                CmsError::EmptyChain,
                VerificationReason::MissingSignerCertificate,
            ),
            (
                CmsError::SignerCertificateAbsent,
                VerificationReason::MissingSignerCertificate,
            ),
            (
                CmsError::Verify("bad signature".into()),
                VerificationReason::InvalidSignature,
            ),
        ];
        for (error, expected) in cases {
            assert_eq!(cms_failure_reason(&error), expected);
        }
    }

    #[test]
    fn verification_result_roundtrips_every_public_reason() {
        let reasons = vec![
            VerificationReason::NotPdf,
            VerificationReason::MalformedPdf,
            VerificationReason::MissingSignature,
            VerificationReason::MultipleSignaturesUnsupported,
            VerificationReason::MalformedByteRange,
            VerificationReason::UnsupportedSubfilter,
            VerificationReason::UnsignedSuffix,
            VerificationReason::InvalidContents,
            VerificationReason::MalformedCms,
            VerificationReason::MissingSignerCertificate,
            VerificationReason::UnsupportedSignatureAlgorithm,
            VerificationReason::InvalidSignature,
            VerificationReason::MessageDigestMismatch,
        ];
        let expected = PdfVerification {
            integrity: true,
            profile: Some(ConformanceLevel::BT),
            signer: Some(PdfSigner {
                serial_number: "5AAC41CD8FA22B953640".into(),
                common_name: "Jane Doe".into(),
            }),
            reasons,
        };
        let mut encoded = Vec::new();
        ciborium::into_writer(&expected, &mut encoded).unwrap();
        let decoded: PdfVerification = ciborium::from_reader(encoded.as_slice()).unwrap();

        assert_eq!(decoded, expected);
        let cloned = expected.clone();
        assert!(format!("{cloned:?}").contains("MalformedPdf"));
    }
}
