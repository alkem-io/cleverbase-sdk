//! PAdES (PDF) signature container: incremental signature dictionary + `/ByteRange` + `/Contents`
//! placeholder, hash over the ByteRange, CMS embedding, and an optional visible appearance.
//!
//! Cleverbase signs only a hash; we own the container (Constitution Principle V). The to-be-signed
//! digest is `sha256` over the whole PDF except the `/Contents` value (the standard PAdES
//! ByteRange). After the signer's signature is wrapped into a detached CMS (see
//! [`crate::crypto::cms`]), the CMS DER is written into the `/Contents` placeholder.

use lopdf::{Dictionary, Document, Object, Stream, StringFormat};

use crate::crypto::sha256;

/// Size of the `/Contents` placeholder, in bytes (hex string is twice this). Must comfortably fit
/// the detached CMS (cert chain + signature + signed attributes + optional timestamp token).
const CONTENTS_PLACEHOLDER_BYTES: usize = 16384;
/// Minimum length of the `'0'` run that identifies the `/Contents` placeholder. Comfortably below
/// the placeholder's `2 * CONTENTS_PLACEHOLDER_BYTES` (= 32768) hex zeros, yet far above any
/// incidental short zero run, so the placeholder is located unambiguously.
const MIN_CONTENTS_ZERO_RUN: usize = 4096;
/// Wide dummy ByteRange integers, so real (smaller) offsets fit when patched with space padding.
const BYTE_RANGE_DUMMY: i64 = 9_999_999_999;

/// Errors from PAdES container operations.
#[derive(Debug, thiserror::Error)]
pub enum PadesError {
    #[error("PDF error: {0}")]
    Pdf(#[from] lopdf::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("document has no pages")]
    NoPages,
    #[error("invalid signature appearance placement")]
    InvalidPlacement,
    #[error("could not locate {0} placeholder in serialized PDF")]
    Placeholder(&'static str),
    #[error("CMS too large for the /Contents placeholder ({0} > {1} bytes)")]
    CmsTooLarge(usize, usize),
    #[error("document already contains a signature")]
    AlreadySigned,
}

/// Structurally detect whether a loaded PDF already carries a signature: any object that is a
/// signature dictionary (`/Type /Sig`) or carries a `/ByteRange`. Unlike a raw-bytes substring
/// scan, this works even when the signature dictionary lives inside a compressed object stream
/// (PDF 1.5+), because lopdf decompresses object streams on load.
fn document_is_signed(doc: &Document) -> bool {
    doc.objects.values().any(|obj| {
        obj.as_dict().is_ok_and(|d| {
            d.get(b"ByteRange").is_ok()
                || d.get(b"Type")
                    .and_then(|t| t.as_name())
                    .is_ok_and(|n| n == b"Sig")
        })
    })
}

/// A resolved visible signature appearance: where to draw and the text lines to render (FR-016).
#[derive(Debug, Clone)]
pub struct VisibleAppearance {
    /// 1-based page number.
    pub page: u32,
    /// (x, y, width, height) in PDF points.
    pub rect: (f64, f64, f64, f64),
    /// Text lines, top to bottom.
    pub lines: Vec<String>,
}

/// A PDF staged for signing.
#[derive(Debug, Clone)]
pub struct PreparedSignature {
    /// The PDF bytes with `/ByteRange` finalized and a zeroed `/Contents` placeholder.
    pub staged_pdf: Vec<u8>,
    /// SHA-256 over the ByteRange (the CMS `message-digest`).
    pub content_hash: [u8; 32],
    /// Byte span (start, end) of the hex digits inside `/Contents` (exclusive of `< >`).
    pub contents_span: (usize, usize),
}

fn find_from(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if from >= hay.len() {
        return None;
    }
    hay[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + from)
}

fn find_byte_from(hay: &[u8], b: u8, from: usize) -> Option<usize> {
    hay[from..].iter().position(|&x| x == b).map(|p| p + from)
}

/// Find the first run of at least `min_len` ASCII `'0'` bytes starting at/after `from` — our
/// `/Contents` hex placeholder. Searching from just after the (unique) `/ByteRange` keyword means a
/// pre-existing long zero run in the original document content (which is serialized earlier) can
/// never be mistaken for the placeholder.
fn find_zero_run(hay: &[u8], from: usize, min_len: usize) -> Option<(usize, usize)> {
    let mut i = from;
    while i < hay.len() {
        if hay[i] == b'0' {
            let start = i;
            while i < hay.len() && hay[i] == b'0' {
                i += 1;
            }
            if i - start >= min_len {
                return Some((start, i));
            }
        } else {
            i += 1;
        }
    }
    None
}

fn escape_pdf_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '(' | ')' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            '\n' | '\r' => out.push(' '),
            c if c.is_ascii() => out.push(c),
            _ => out.push('?'), // non-WinAnsi glyphs not supported with the base font
        }
    }
    out
}

/// Add a visible appearance to `field`: a form XObject drawing the text lines, referenced via `/AP`.
fn add_visible_appearance(
    doc: &mut Document,
    field: &mut Dictionary,
    appearance: &VisibleAppearance,
) -> Result<(), PadesError> {
    let (x, y, w, h) = appearance.rect;
    if w <= 0.0 || h <= 0.0 {
        return Err(PadesError::InvalidPlacement);
    }

    let mut font = Dictionary::new();
    font.set("Type", Object::Name(b"Font".to_vec()));
    font.set("Subtype", Object::Name(b"Type1".to_vec()));
    font.set("BaseFont", Object::Name(b"Helvetica".to_vec()));
    let font_id = doc.add_object(Object::Dictionary(font));

    let mut fonts = Dictionary::new();
    fonts.set("F1", Object::Reference(font_id));
    let mut resources = Dictionary::new();
    resources.set("Font", Object::Dictionary(fonts));

    let font_size = 9.0_f64;
    let line_gap = font_size + 2.0;
    let mut content = String::from("q\nBT\n/F1 9 Tf\n0 g\n");
    let mut ty = h - line_gap;
    for line in &appearance.lines {
        content.push_str(&format!(
            "1 0 0 1 2 {:.2} Tm\n({}) Tj\n",
            ty.max(2.0),
            escape_pdf_text(line)
        ));
        ty -= line_gap;
    }
    content.push_str("ET\nQ\n");

    let mut form = Dictionary::new();
    form.set("Type", Object::Name(b"XObject".to_vec()));
    form.set("Subtype", Object::Name(b"Form".to_vec()));
    form.set("FormType", Object::Integer(1));
    form.set(
        "BBox",
        Object::Array(vec![
            Object::Real(0.0),
            Object::Real(0.0),
            Object::Real(w as f32),
            Object::Real(h as f32),
        ]),
    );
    form.set("Resources", Object::Dictionary(resources));
    let xobj_id = doc.add_object(Object::Stream(Stream::new(form, content.into_bytes())));

    field.set(
        "Rect",
        Object::Array(vec![
            Object::Real(x as f32),
            Object::Real(y as f32),
            Object::Real((x + w) as f32),
            Object::Real((y + h) as f32),
        ]),
    );
    let mut ap = Dictionary::new();
    ap.set("N", Object::Reference(xobj_id));
    field.set("AP", Object::Dictionary(ap));
    Ok(())
}

/// Prepare a PDF for signing. Adds a signature field + dictionary (invisible, or visible when an
/// appearance is given) and returns the staged bytes, the ByteRange digest, and the `/Contents`
/// span to embed into.
pub fn prepare(
    original_pdf: &[u8],
    reason: Option<&str>,
    location: Option<&str>,
    appearance: Option<&VisibleAppearance>,
) -> Result<PreparedSignature, PadesError> {
    let mut doc = Document::load_mem(original_pdf)?;

    // Reject an already-signed PDF structurally (catches compressed-object-stream signatures the
    // raw-bytes scan in `begin` misses) — re-saving it would silently corrupt the prior signature.
    if document_is_signed(&doc) {
        return Err(PadesError::AlreadySigned);
    }

    let pages = doc.get_pages();
    if pages.is_empty() {
        return Err(PadesError::NoPages);
    }
    let page_id = match appearance {
        Some(a) => *pages.get(&a.page).ok_or(PadesError::InvalidPlacement)?,
        None => *pages.values().next().unwrap(),
    };

    // Signature dictionary (PAdES detached).
    let mut sig = Dictionary::new();
    sig.set("Type", Object::Name(b"Sig".to_vec()));
    sig.set("Filter", Object::Name(b"Adobe.PPKLite".to_vec()));
    sig.set("SubFilter", Object::Name(b"ETSI.CAdES.detached".to_vec()));
    sig.set(
        "ByteRange",
        Object::Array(vec![
            Object::Integer(0),
            Object::Integer(BYTE_RANGE_DUMMY),
            Object::Integer(BYTE_RANGE_DUMMY),
            Object::Integer(BYTE_RANGE_DUMMY),
        ]),
    );
    sig.set(
        "Contents",
        Object::String(
            vec![0u8; CONTENTS_PLACEHOLDER_BYTES],
            StringFormat::Hexadecimal,
        ),
    );
    if let Some(r) = reason {
        sig.set(
            "Reason",
            Object::String(r.as_bytes().to_vec(), StringFormat::Literal),
        );
    }
    if let Some(l) = location {
        sig.set(
            "Location",
            Object::String(l.as_bytes().to_vec(), StringFormat::Literal),
        );
    }
    let sig_id = doc.add_object(Object::Dictionary(sig));

    // Signature widget / form field.
    let mut field = Dictionary::new();
    field.set("Type", Object::Name(b"Annot".to_vec()));
    field.set("Subtype", Object::Name(b"Widget".to_vec()));
    field.set("FT", Object::Name(b"Sig".to_vec()));
    field.set(
        "T",
        Object::String(b"Signature1".to_vec(), StringFormat::Literal),
    );
    field.set("V", Object::Reference(sig_id));
    field.set("P", Object::Reference(page_id));
    field.set("F", Object::Integer(132));
    match appearance {
        Some(a) => add_visible_appearance(&mut doc, &mut field, a)?,
        None => field.set(
            "Rect",
            Object::Array(vec![
                Object::Integer(0),
                Object::Integer(0),
                Object::Integer(0),
                Object::Integer(0),
            ]),
        ),
    }
    let field_id = doc.add_object(Object::Dictionary(field));

    // Attach the widget to the page's annotations.
    let mut annots = match doc.get_object(page_id) {
        Ok(Object::Dictionary(d)) => match d.get(b"Annots") {
            Ok(Object::Array(a)) => a.clone(),
            _ => Vec::new(),
        },
        _ => Vec::new(),
    };
    annots.push(Object::Reference(field_id));
    doc.get_object_mut(page_id)?
        .as_dict_mut()?
        .set("Annots", Object::Array(annots));

    // AcroForm with the signature field.
    let catalog_id = doc.trailer.get(b"Root")?.as_reference()?;
    let mut acro = Dictionary::new();
    acro.set("Fields", Object::Array(vec![Object::Reference(field_id)]));
    acro.set("SigFlags", Object::Integer(3));
    doc.get_object_mut(catalog_id)?
        .as_dict_mut()?
        .set("AcroForm", Object::Dictionary(acro));

    let mut buf = Vec::new();
    doc.save_to(&mut buf)?;

    // /ByteRange is unique to a signature dictionary (a fresh PDF has none); find it first.
    let br_key = find_from(&buf, b"/ByteRange", 0).ok_or(PadesError::Placeholder("/ByteRange"))?;
    let br_open =
        find_byte_from(&buf, b'[', br_key).ok_or(PadesError::Placeholder("/ByteRange ["))?;
    let br_close =
        find_byte_from(&buf, b']', br_open).ok_or(PadesError::Placeholder("/ByteRange ]"))?;

    // The /Contents value is the long zero-run AFTER the ByteRange (within our sig dict), so a
    // pre-existing zero run in the original document content cannot be mistaken for it.
    let (z0, z1) = find_zero_run(&buf, br_key, MIN_CONTENTS_ZERO_RUN)
        .ok_or(PadesError::Placeholder("/Contents"))?;
    if z0 == 0 || buf[z0 - 1] != b'<' || buf.get(z1) != Some(&b'>') {
        return Err(PadesError::Placeholder("/Contents delimiters"));
    }

    let region1_len = z0; // through and including '<'
    let region2_start = z1; // from '>' to EOF
    let region2_len = buf.len() - z1;
    let inner = format!("0 {region1_len} {region2_start} {region2_len}");
    let span = br_close - br_open - 1;
    if inner.len() > span {
        return Err(PadesError::Placeholder("/ByteRange (too small)"));
    }
    let mut padded = inner.into_bytes();
    padded.resize(span, b' ');
    buf[br_open + 1..br_close].copy_from_slice(&padded);

    let mut hasher_input = Vec::with_capacity(region1_len + region2_len);
    hasher_input.extend_from_slice(&buf[..region1_len]);
    hasher_input.extend_from_slice(&buf[region2_start..]);
    let content_hash = sha256(&hasher_input);

    Ok(PreparedSignature {
        staged_pdf: buf,
        content_hash,
        contents_span: (z0, z1),
    })
}

/// Heuristic PDF/A detection: PDF/A documents carry XMP metadata in the `pdfaid` namespace.
pub fn is_pdf_a(pdf: &[u8]) -> bool {
    pdf.windows(6).any(|w| w == b"pdfaid")
}

/// True if the PDF already carries a signature — detected by `/ByteRange`, which appears only in
/// signature dictionaries. Phase 1 signs only previously-unsigned documents; adding a signature to
/// an already-signed PDF (multi-signature via incremental update, FR-010) is a later phase, so such
/// input is rejected up front rather than risk corrupting the existing signature.
pub fn is_already_signed(pdf: &[u8]) -> bool {
    pdf.windows(b"/ByteRange".len()).any(|w| w == b"/ByteRange")
}

/// SHA-256 over the signed byte range of a staged PDF: everything except the `/Contents` hex value
/// between `span.0` and `span.1`. This is the value the CMS `message-digest` attribute must equal,
/// binding the signature to exactly this document (WYSIWYS). Returns `None` if `span` is out of
/// bounds (e.g. a corrupted/tampered handle).
pub fn byte_range_digest(staged: &[u8], span: (usize, usize)) -> Option<[u8; 32]> {
    let (lo, hi) = span;
    let head = staged.get(..lo)?;
    let tail = staged.get(hi..)?;
    let mut input = Vec::with_capacity(head.len() + tail.len());
    input.extend_from_slice(head);
    input.extend_from_slice(tail);
    Some(sha256(&input))
}

/// Write the detached CMS (DER) into the `/Contents` placeholder as hex. Remaining placeholder
/// bytes stay zero (excluded from the ByteRange, so they do not affect the signature).
pub fn embed_cms(
    staged_pdf: &mut [u8],
    contents_span: (usize, usize),
    cms_der: &[u8],
) -> Result<(), PadesError> {
    let (start, end) = contents_span;
    // The span comes from the (possibly persisted/tampered) session handle; validate it so a
    // corrupted span can never underflow the capacity or index out of bounds (it returns a clean
    // error instead of panicking).
    if end < start || end > staged_pdf.len() {
        return Err(PadesError::Placeholder("/Contents span"));
    }
    let capacity = end - start;
    let hex_len = cms_der.len() * 2;
    if hex_len > capacity {
        return Err(PadesError::CmsTooLarge(cms_der.len(), capacity / 2));
    }
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (i, byte) in cms_der.iter().enumerate() {
        staged_pdf[start + i * 2] = HEX[(byte >> 4) as usize];
        staged_pdf[start + i * 2 + 1] = HEX[(byte & 0x0f) as usize];
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::cms;
    use crate::signing::csc::KeyAlgo;
    use crate::util::to_hex;
    use pkcs8::DecodePrivateKey;
    use rsa::signature::{SignatureEncoding, Signer as _};
    use sha2::Sha256;

    const RSA_CERT: &[u8] = include_bytes!("../../../../tests/fixtures/pki/signer-rsa.cert.der");
    const RSA_KEY: &[u8] = include_bytes!("../../../../tests/fixtures/pki/signer-rsa.key.pk8");

    fn minimal_pdf() -> Vec<u8> {
        let mut doc = Document::with_version("1.7");
        let pages_id = doc.new_object_id();
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
        let page_id = doc.add_object(Object::Dictionary(page));
        let mut pages = Dictionary::new();
        pages.set("Type", Object::Name(b"Pages".to_vec()));
        pages.set("Kids", Object::Array(vec![Object::Reference(page_id)]));
        pages.set("Count", Object::Integer(1));
        doc.objects.insert(pages_id, Object::Dictionary(pages));
        let mut catalog = Dictionary::new();
        catalog.set("Type", Object::Name(b"Catalog".to_vec()));
        catalog.set("Pages", Object::Reference(pages_id));
        let catalog_id = doc.add_object(Object::Dictionary(catalog));
        doc.trailer.set("Root", Object::Reference(catalog_id));
        let mut buf = Vec::new();
        doc.save_to(&mut buf).unwrap();
        buf
    }

    #[test]
    fn escape_pdf_text_covers_branches() {
        assert_eq!(escape_pdf_text("a(b)\\c"), "a\\(b\\)\\\\c"); // parens + backslash escaped
        assert_eq!(escape_pdf_text("x\ny\rz"), "x y z"); // newlines → space
        assert_eq!(escape_pdf_text("café"), "caf?"); // non-ASCII → '?'
    }

    #[test]
    fn is_pdf_a_detects_marker() {
        assert!(is_pdf_a(b"<x:xmpmeta><pdfaid:part>1</pdfaid:part>"));
        assert!(!is_pdf_a(b"%PDF-1.7 plain document"));
    }

    #[test]
    fn prepare_rejects_zero_page_pdf() {
        // A loadable PDF with an empty Pages tree → NoPages (not a panic / not a malformed sign).
        let mut doc = Document::with_version("1.7");
        let pages_id = doc.new_object_id();
        let mut pages = Dictionary::new();
        pages.set("Type", Object::Name(b"Pages".to_vec()));
        pages.set("Kids", Object::Array(vec![]));
        pages.set("Count", Object::Integer(0));
        doc.objects.insert(pages_id, Object::Dictionary(pages));
        let mut catalog = Dictionary::new();
        catalog.set("Type", Object::Name(b"Catalog".to_vec()));
        catalog.set("Pages", Object::Reference(pages_id));
        let cat_id = doc.add_object(Object::Dictionary(catalog));
        doc.trailer.set("Root", Object::Reference(cat_id));
        let mut buf = Vec::new();
        doc.save_to(&mut buf).unwrap();
        assert!(matches!(
            prepare(&buf, None, None, None),
            Err(PadesError::NoPages)
        ));
    }

    #[test]
    fn prepare_rejects_already_signed_pdf() {
        // Build a PDF carrying a signature dictionary (an object with /ByteRange).
        let mut doc = Document::load_mem(&minimal_pdf()).unwrap();
        let mut sig = Dictionary::new();
        sig.set("Type", Object::Name(b"Sig".to_vec()));
        sig.set(
            "ByteRange",
            Object::Array(
                vec![0, 100, 200, 50]
                    .into_iter()
                    .map(Object::Integer)
                    .collect(),
            ),
        );
        doc.add_object(Object::Dictionary(sig));
        let mut buf = Vec::new();
        doc.save_to(&mut buf).unwrap();

        assert!(document_is_signed(&Document::load_mem(&buf).unwrap()));
        assert!(matches!(
            prepare(&buf, None, None, None),
            Err(PadesError::AlreadySigned)
        ));
    }

    #[test]
    fn embed_cms_rejects_invalid_span() {
        // A corrupted/tampered contents_span must yield a clean error, never a panic.
        let mut buf = vec![0u8; 100];
        assert!(embed_cms(&mut buf, (50, 10), b"data").is_err()); // end < start
        assert!(embed_cms(&mut buf, (0, 200), b"data").is_err()); // end > len
    }

    #[test]
    fn prepare_embed_and_verify_b_b_invisible() {
        let prep = prepare(&minimal_pdf(), Some("Approval"), Some("NL"), None).unwrap();
        Document::load_mem(&prep.staged_pdf).unwrap();

        let attrs = cms::build_signed_attrs(&prep.content_hash, RSA_CERT, 1_700_000_000).unwrap();
        let key = rsa::RsaPrivateKey::from_pkcs8_der(RSA_KEY).unwrap();
        let signer = rsa::pkcs1v15::SigningKey::<Sha256>::new(key);
        let signature = signer.sign(&attrs).to_bytes();
        let cms_der =
            cms::assemble_signed_data(&[RSA_CERT.to_vec()], &attrs, &signature, KeyAlgo::Rsa)
                .unwrap();
        let (_re, md, _s, _c) = cms::reparse_for_verify(&cms_der).unwrap();
        assert_eq!(md, prep.content_hash);

        let mut staged = prep.staged_pdf.clone();
        embed_cms(&mut staged, prep.contents_span, &cms_der).unwrap();
        let (start, _end) = prep.contents_span;
        assert_eq!(
            &staged[start..start + cms_der.len() * 2],
            to_hex(&cms_der).as_bytes()
        );
        assert_eq!(staged.len(), prep.staged_pdf.len());
    }

    #[test]
    fn prepare_with_visible_appearance() {
        let appearance = VisibleAppearance {
            page: 1,
            rect: (72.0, 72.0, 220.0, 64.0),
            lines: vec!["Signed by: Jane Doe".into(), "Reason: Approval".into()],
        };
        let prep = prepare(&minimal_pdf(), Some("Approval"), None, Some(&appearance)).unwrap();
        Document::load_mem(&prep.staged_pdf).unwrap();
        assert!(
            find_from(&prep.staged_pdf, b"/AP", 0).is_some(),
            "visible signature must have an /AP entry"
        );
        assert!(find_from(&prep.staged_pdf, b"Helvetica", 0).is_some());
        assert!(find_from(&prep.staged_pdf, b"Signed by: Jane Doe", 0).is_some());
    }

    #[test]
    fn appearance_on_missing_page_is_placement_error() {
        let appearance = VisibleAppearance {
            page: 7,
            rect: (10.0, 10.0, 100.0, 50.0),
            lines: vec!["x".into()],
        };
        assert!(matches!(
            prepare(&minimal_pdf(), None, None, Some(&appearance)),
            Err(PadesError::InvalidPlacement)
        ));
    }

    #[test]
    fn appearance_with_zero_size_is_placement_error() {
        let appearance = VisibleAppearance {
            page: 1,
            rect: (10.0, 10.0, 0.0, 50.0),
            lines: vec!["x".into()],
        };
        assert!(matches!(
            prepare(&minimal_pdf(), None, None, Some(&appearance)),
            Err(PadesError::InvalidPlacement)
        ));
    }

    #[test]
    fn embed_rejects_oversized_cms() {
        let prep = prepare(&minimal_pdf(), None, None, None).unwrap();
        let mut staged = prep.staged_pdf.clone();
        let too_big = vec![0u8; CONTENTS_PLACEHOLDER_BYTES + 1];
        assert!(matches!(
            embed_cms(&mut staged, prep.contents_span, &too_big),
            Err(PadesError::CmsTooLarge(_, _))
        ));
    }
}
