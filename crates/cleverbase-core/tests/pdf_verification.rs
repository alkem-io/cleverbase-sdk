//! Public integrity-verifier contract tests.

#![allow(clippy::indexing_slicing, clippy::unwrap_used)]

use cleverbase_core::{verify_pdf, VerificationReason};
use lopdf::{Dictionary, Document, Object};

fn minimal_pdf() -> Vec<u8> {
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
    let mut bytes = Vec::new();
    document.save_to(&mut bytes).unwrap();
    bytes
}

#[test]
fn non_pdf_is_an_invalid_verdict_not_an_api_error() {
    let verification = verify_pdf(b"not a PDF");

    assert!(!verification.integrity);
    assert_eq!(verification.profile, None);
    assert_eq!(verification.signer, None);
    assert_eq!(verification.reasons, vec![VerificationReason::NotPdf]);
}

#[test]
fn unsigned_pdf_reports_a_missing_signature() {
    let verification = verify_pdf(&minimal_pdf());

    assert!(!verification.integrity);
    assert_eq!(
        verification.reasons,
        vec![VerificationReason::MissingSignature]
    );
}

#[test]
fn malformed_embedded_cms_is_distinguished_from_a_missing_signature() {
    // `30 00` is valid DER but not a CMS ContentInfo, so parsing reaches the CMS layer.
    let mut prepared =
        cleverbase_core::pades::container::prepare(&minimal_pdf(), None, None, None).unwrap();
    prepared.staged_pdf[prepared.contents_span.0..prepared.contents_span.0 + 4]
        .copy_from_slice(b"3000");

    let verification = verify_pdf(&prepared.staged_pdf);

    assert!(!verification.integrity);
    assert_eq!(verification.reasons, vec![VerificationReason::MalformedCms]);
}

#[test]
fn invalid_contents_hex_is_rejected() {
    let mut prepared =
        cleverbase_core::pades::container::prepare(&minimal_pdf(), None, None, None).unwrap();
    // PDF parsers permit whitespace in a hexadecimal string. The integrity verifier deliberately
    // requires the excluded gap itself to be hex-only so the ByteRange-to-Contents binding is exact.
    prepared.staged_pdf[prepared.contents_span.0] = b' ';

    let verification = verify_pdf(&prepared.staged_pdf);

    assert_eq!(
        verification.reasons,
        vec![VerificationReason::InvalidContents]
    );
}

#[test]
fn nonzero_bytes_after_the_cms_der_are_rejected() {
    let mut prepared =
        cleverbase_core::pades::container::prepare(&minimal_pdf(), None, None, None).unwrap();
    prepared.staged_pdf[prepared.contents_span.0..prepared.contents_span.0 + 4]
        .copy_from_slice(b"3000");
    let last = prepared.contents_span.1 - 1;
    prepared.staged_pdf[last] = b'1';

    let verification = verify_pdf(&prepared.staged_pdf);

    assert_eq!(
        verification.reasons,
        vec![VerificationReason::InvalidContents]
    );
}

#[test]
fn contents_delimiters_must_be_immediately_outside_the_unsigned_gap() {
    let mut prepared =
        cleverbase_core::pades::container::prepare(&minimal_pdf(), None, None, None).unwrap();
    prepared.staged_pdf[prepared.contents_span.0 - 1] = b'(';
    prepared.staged_pdf[prepared.contents_span.1] = b')';

    let verification = verify_pdf(&prepared.staged_pdf);

    assert_eq!(
        verification.reasons,
        vec![VerificationReason::MalformedByteRange]
    );
}

#[test]
fn bytes_after_the_second_range_are_rejected_as_unsigned_suffix() {
    let mut prepared =
        cleverbase_core::pades::container::prepare(&minimal_pdf(), None, None, None).unwrap();
    prepared.staged_pdf.extend_from_slice(b"unsigned");

    let verification = verify_pdf(&prepared.staged_pdf);

    assert_eq!(
        verification.reasons,
        vec![VerificationReason::UnsignedSuffix]
    );
}

#[test]
fn multiple_signature_dictionaries_are_explicitly_unsupported() {
    let prepared =
        cleverbase_core::pades::container::prepare(&minimal_pdf(), None, None, None).unwrap();
    let mut document = Document::load_mem(&prepared.staged_pdf).unwrap();
    let signature = document
        .objects
        .values()
        .find(|object| {
            object
                .as_dict()
                .is_ok_and(|dictionary| dictionary.get(b"ByteRange").is_ok())
        })
        .cloned()
        .unwrap();
    document.add_object(signature);
    let mut two_signatures = Vec::new();
    document.save_to(&mut two_signatures).unwrap();

    let verification = verify_pdf(&two_signatures);

    assert_eq!(
        verification.reasons,
        vec![VerificationReason::MultipleSignaturesUnsupported]
    );
}
