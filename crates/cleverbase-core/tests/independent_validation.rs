//! Independent validation of a produced PAdES B-B signature (Constitution Principle VI).
//!
//! Drives the public `begin`/`resume` API to produce a signed PDF (the test plays Cleverbase's
//! `signHash` with the synthetic fixture key), then verifies the embedded detached CMS with
//! **OpenSSL** — an entirely independent implementation. OpenSSL checks: the CMS parses, the
//! signature over the signed attributes is valid, the `message-digest` matches the ByteRange
//! content, and the signer certificate chains to the test CA. Skipped if `openssl` is unavailable.

// This is a test binary: unwrap/expect/panic/indexing are the intended assertion mechanism,
// matching the `cfg(test)` allow the library crates apply to their inline test modules.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::print_stderr // the openssl-unavailable skip notices print to stderr
)]

use std::path::{Path, PathBuf};
use std::process::Command;

use cleverbase_core::util::{base64_decode, base64_std};
use cleverbase_core::{
    begin, resume, ConformanceLevel, CscApi, Environment, HostContext, ResumeInput, Secret,
    SignedDocument, SigningRequest, Step, TrustServiceConfiguration, TsaConfiguration,
};
use lopdf::{Dictionary, Document, Object};
use pkcs8::DecodePrivateKey;

const RSA_CERT: &[u8] = include_bytes!("../../../tests/fixtures/pki/signer-rsa.cert.der");
const RSA_KEY: &[u8] = include_bytes!("../../../tests/fixtures/pki/signer-rsa.key.pk8");

fn openssl_available() -> bool {
    Command::new("openssl")
        .arg("version")
        .output()
        .is_ok_and(|o| o.status.success())
}

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

fn ctx() -> HostContext {
    // Signing time within the fixture certificate's validity window (issued 2026).
    HostContext {
        now_unix: 1_781_000_000,
        entropy: (0u8..16).collect(),
    }
}

fn http_ok(json: serde_json::Value) -> ResumeInput {
    ResumeInput::HttpResult {
        status: 200,
        headers: vec![],
        body: serde_json::to_vec(&json).unwrap(),
    }
}

fn produce_signed_pdf() -> SignedDocument {
    let cfg = TrustServiceConfiguration {
        environment: Environment::Acceptance,
        csc_api: CscApi::V1Rsa,
        client_id: "client-123".into(),
        client_secret: Secret::new("shh"),
        redirect_uri: "https://app.example/cb".into(),
        tsa: None,
    };
    let request = SigningRequest {
        document: minimal_pdf(),
        conformance_level: ConformanceLevel::BB,
        expected_signer: None,
        appearance: None,
        signature_meta: None,
    };
    let info = signer_info();

    let (h, s) = begin(request, cfg, ctx()).unwrap();
    let state = match &s {
        Step::Redirect(r) => r.state.clone(),
        _ => panic!(),
    };
    let (h, _) = resume(
        h,
        ResumeInput::RedirectReturn {
            code: "c".into(),
            state,
        },
        ctx(),
    )
    .unwrap();
    let (h, _) = resume(h, http_ok(upstream_fixture("service_token")), ctx()).unwrap();
    let (h, _) = resume(h, http_ok(upstream_fixture("credentials_list")), ctx()).unwrap();
    let (h, s) = resume(h, http_ok(info), ctx()).unwrap();
    let state = match &s {
        Step::Redirect(r) => r.state.clone(),
        _ => panic!(),
    };
    let (h, _) = resume(
        h,
        ResumeInput::RedirectReturn {
            code: "c2".into(),
            state,
        },
        ctx(),
    )
    .unwrap();
    let (h, s) = resume(h, http_ok(upstream_fixture("credential_token")), ctx()).unwrap();
    let sign_req = match &s {
        Step::PerformHttp(e) => e.clone(),
        _ => panic!(),
    };
    let body: serde_json::Value = serde_json::from_slice(sign_req.body.as_ref().unwrap()).unwrap();
    let tbs = base64_decode(body["hash"][0].as_str().unwrap()).unwrap();
    let key = rsa::RsaPrivateKey::from_pkcs8_der(RSA_KEY).unwrap();
    let sig = key
        .sign(rsa::Pkcs1v15Sign::new::<sha2::Sha256>(), &tbs)
        .unwrap();
    let (_h, step) = resume(
        h,
        http_ok(serde_json::json!({"signatures": [base64_std(&sig)]})),
        ctx(),
    )
    .unwrap();
    match step {
        Step::Done { signed, .. } => signed,
        other => panic!("expected Done, got {other:?}"),
    }
}

/// Parse `/ByteRange [a b c d]` and `/Contents <hex>` from the signed PDF.
fn extract(pdf: &[u8]) -> (Vec<u8>, Vec<u8>) {
    // ByteRange content = pdf[a..a+b] ++ pdf[c..c+d].
    let br = find(pdf, b"/ByteRange").unwrap();
    let open = br + pdf[br..].iter().position(|&b| b == b'[').unwrap() + 1;
    let close = open + pdf[open..].iter().position(|&b| b == b']').unwrap();
    let nums: Vec<usize> = std::str::from_utf8(&pdf[open..close])
        .unwrap()
        .split_whitespace()
        .map(|x| x.parse().unwrap())
        .collect();
    let (a, b, c, d) = (nums[0], nums[1], nums[2], nums[3]);
    let mut content = Vec::new();
    content.extend_from_slice(&pdf[a..a + b]);
    content.extend_from_slice(&pdf[c..c + d]);

    // CMS DER from /Contents hex (trim trailing zero padding by DER length).
    let ck = find(pdf, b"/Contents").unwrap();
    let lt = ck + pdf[ck..].iter().position(|&x| x == b'<').unwrap() + 1;
    let gt = lt + pdf[lt..].iter().position(|&x| x == b'>').unwrap();
    let hex = &pdf[lt..gt];
    let bytes: Vec<u8> = (0..hex.len() / 2)
        .map(|i| {
            u8::from_str_radix(std::str::from_utf8(&hex[i * 2..i * 2 + 2]).unwrap(), 16).unwrap()
        })
        .collect();
    let len = der_total_len(&bytes);
    (content, bytes[..len].to_vec())
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn der_total_len(b: &[u8]) -> usize {
    let l0 = b[1];
    if l0 < 0x80 {
        2 + l0 as usize
    } else {
        let n = (l0 & 0x7f) as usize;
        let len = b[2..2 + n]
            .iter()
            .fold(0usize, |acc, &x| (acc << 8) | x as usize);
        2 + n + len
    }
}

#[test]
fn produced_b_b_signature_verifies_with_openssl() {
    if !openssl_available() {
        eprintln!("openssl not available; skipping independent validation");
        return;
    }
    let signed = produce_signed_pdf();
    let (content, cms_der) = extract(&signed.pdf);

    let dir = std::env::temp_dir();
    let cms_path = dir.join("cleverbase_it_cms.der");
    let content_path = dir.join("cleverbase_it_content.bin");
    std::fs::write(&cms_path, &cms_der).unwrap();
    std::fs::write(&content_path, &content).unwrap();
    let ca = materialize_ca_pem();

    let out = Command::new("openssl")
        .args([
            "cms", "-verify", "-inform", "DER", "-binary", "-purpose", "any",
        ])
        .arg("-in")
        .arg(&cms_path)
        .arg("-content")
        .arg(&content_path)
        .arg("-CAfile")
        .arg(&ca)
        .arg("-out")
        .arg(dir.join("cleverbase_it_out.bin"))
        .output()
        .expect("run openssl");

    let _ = std::fs::remove_file(&cms_path);
    let _ = std::fs::remove_file(&content_path);
    let _ = std::fs::remove_file(&ca);

    assert!(
        out.status.success(),
        "openssl cms -verify failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

fn upstream_dir() -> PathBuf {
    PathBuf::from(format!(
        "{}/../../tests/fixtures/upstream",
        env!("CARGO_MANIFEST_DIR")
    ))
}

/// Load a shared upstream-response fixture (the single source the Go mock also reads — FR-015),
/// substituting the synthetic signer certificate for the `{{signer_rsa_cert_b64}}` placeholder.
fn upstream_fixture(name: &str) -> serde_json::Value {
    let raw = std::fs::read_to_string(upstream_dir().join(format!("{name}.json")))
        .unwrap_or_else(|e| panic!("read upstream fixture {name}: {e}"));
    let substituted = raw.replace("{{signer_rsa_cert_b64}}", &base64_std(RSA_CERT));
    serde_json::from_str(&substituted).unwrap()
}

fn signer_info() -> serde_json::Value {
    upstream_fixture("credentials_info")
}

fn http_ok_bytes(body: Vec<u8>) -> ResumeInput {
    ResumeInput::HttpResult {
        status: 200,
        headers: vec![],
        body,
    }
}

fn pki_dir() -> PathBuf {
    PathBuf::from(format!(
        "{}/../../tests/fixtures/pki",
        env!("CARGO_MANIFEST_DIR")
    ))
}

/// Unique temp path stem (pid + atomic counter) so concurrent tests never collide on temp files.
fn unique_tag(prefix: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    format!(
        "{prefix}_{}_{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    )
}

fn der_to_pem_cert(der: &Path, pem: &Path) {
    let out = Command::new("openssl")
        .arg("x509")
        .args(["-inform", "DER", "-in"])
        .arg(der)
        .arg("-out")
        .arg(pem)
        .output()
        .expect("run openssl x509");
    assert!(
        out.status.success(),
        "der->pem cert failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Materialize the test CA certificate as a PEM file (from the committed DER) for `-CAfile`.
/// The caller removes the returned path.
fn materialize_ca_pem() -> PathBuf {
    let out = std::env::temp_dir().join(format!("{}.pem", unique_tag("cb_it_ca")));
    der_to_pem_cert(&pki_dir().join("ca.cert.der"), &out);
    out
}

/// Play an RFC 3161 TSA using `openssl ts -reply`, fully self-contained in a per-call temp dir: the
/// public certs + the TSA key are materialized from the committed DER / PKCS#8 material, and a fresh
/// per-call serial file is used — so there is no committed-fixture mutation and no parallel-test
/// race on a shared serial (the on-disk `tests/fixtures/pki` is read-only here).
fn openssl_timestamp(req_der: &[u8]) -> Vec<u8> {
    let pki = pki_dir();
    let work = std::env::temp_dir().join(unique_tag("cb_it_tsa"));
    std::fs::create_dir_all(&work).unwrap();
    let ca = work.join("ca.cert.pem");
    let cert = work.join("tsa.cert.pem");
    let key = work.join("tsa.key.pem");
    der_to_pem_cert(&pki.join("ca.cert.der"), &ca);
    der_to_pem_cert(&pki.join("tsa.cert.der"), &cert);
    let key_out = Command::new("openssl")
        .arg("pkey")
        .args(["-inform", "DER", "-in"])
        .arg(pki.join("tsa.key.pk8"))
        .arg("-out")
        .arg(&key)
        .output()
        .expect("run openssl pkey");
    assert!(
        key_out.status.success(),
        "pk8->pem key failed: {}",
        String::from_utf8_lossy(&key_out.stderr)
    );
    std::fs::write(work.join("serial"), b"01").unwrap();
    let cnf = format!(
        "[tsa]\ndefault_tsa = c\n[c]\nserial = {serial}\ncrypto_device = builtin\n\
         signer_cert = {cert}\ncerts = {ca}\nsigner_key = {key}\n\
         default_policy = 1.3.6.1.4.1.99999.1.1\nsigner_digest = sha256\n\
         digests = sha256, sha384, sha512\naccuracy = secs:1\nclock_precision_digits = 0\n\
         ordering = yes\ntsa_name = yes\ness_cert_id_chain = no\ness_cert_id_alg = sha256\n",
        serial = work.join("serial").display(),
        cert = cert.display(),
        ca = ca.display(),
        key = key.display(),
    );
    std::fs::write(work.join("tsa.cnf"), cnf).unwrap();
    std::fs::write(work.join("req.tsq"), req_der).unwrap();
    let out = Command::new("openssl")
        .arg("ts")
        .arg("-reply")
        .arg("-config")
        .arg(work.join("tsa.cnf"))
        .arg("-queryfile")
        .arg(work.join("req.tsq"))
        .arg("-out")
        .arg(work.join("resp.tsr"))
        .output()
        .expect("run openssl ts");
    assert!(
        out.status.success(),
        "openssl ts -reply failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let resp = std::fs::read(work.join("resp.tsr")).unwrap();
    let _ = std::fs::remove_dir_all(&work);
    resp
}

#[test]
fn tsa_token_gen_time_is_parsed() {
    // Drive a real openssl TSA and confirm we extract its genTime from the issued token (so the
    // evidence reports the TSA's trusted time, not the host clock).
    if !openssl_available() {
        eprintln!("openssl not available; skipping TSA genTime test");
        return;
    }
    let imprint = cleverbase_core::crypto::sha256(b"some signature value");
    let req = cleverbase_core::timestamp::build_request(&imprint, None).unwrap();
    let tsr = openssl_timestamp(&req);
    let token = cleverbase_core::timestamp::parse_response(&tsr).unwrap();
    let gen_time = cleverbase_core::timestamp::parse_gen_time(&token)
        .expect("genTime should be parsed from a valid TSA token");
    // A real openssl-issued timestamp is a recent, plausible Unix time (well past 2023).
    assert!(gen_time > 1_700_000_000, "implausible genTime: {gen_time}");
    // The token's messageImprint must echo exactly the hash we submitted (binding check).
    assert_eq!(
        cleverbase_core::timestamp::parse_message_imprint(&token).as_deref(),
        Some(imprint.as_slice()),
        "token messageImprint must match the submitted hash"
    );
}

/// Drive a B-T flow up to the TSA request; return the handle (at TimestampPending) + the TSA query.
fn drive_bt_to_timestamp() -> (cleverbase_core::SigningSessionHandle, Vec<u8>) {
    let cfg = TrustServiceConfiguration {
        environment: Environment::Acceptance,
        csc_api: CscApi::V1Rsa,
        client_id: "client-123".into(),
        client_secret: Secret::new("shh"),
        redirect_uri: "https://app.example/cb".into(),
        tsa: Some(TsaConfiguration {
            url: "https://tsa.example/tsr".into(),
            auth: None,
            policy_oid: None,
        }),
    };
    let request = SigningRequest {
        document: minimal_pdf(),
        conformance_level: ConformanceLevel::BT,
        expected_signer: None,
        appearance: None,
        signature_meta: None,
    };
    let (h, s) = begin(request, cfg, ctx()).unwrap();
    let state = match &s {
        Step::Redirect(r) => r.state.clone(),
        _ => panic!(),
    };
    let (h, _) = resume(
        h,
        ResumeInput::RedirectReturn {
            code: "c".into(),
            state,
        },
        ctx(),
    )
    .unwrap();
    let (h, _) = resume(h, http_ok(upstream_fixture("service_token")), ctx()).unwrap();
    let (h, _) = resume(h, http_ok(upstream_fixture("credentials_list")), ctx()).unwrap();
    let (h, s) = resume(h, http_ok(signer_info()), ctx()).unwrap();
    let state = match &s {
        Step::Redirect(r) => r.state.clone(),
        _ => panic!(),
    };
    let (h, _) = resume(
        h,
        ResumeInput::RedirectReturn {
            code: "c2".into(),
            state,
        },
        ctx(),
    )
    .unwrap();
    let (h, s) = resume(h, http_ok(upstream_fixture("credential_token")), ctx()).unwrap();
    let sign_req = match &s {
        Step::PerformHttp(e) => e.clone(),
        _ => panic!("expected signHash"),
    };
    let body: serde_json::Value = serde_json::from_slice(sign_req.body.as_ref().unwrap()).unwrap();
    let tbs = base64_decode(body["hash"][0].as_str().unwrap()).unwrap();
    let key = rsa::RsaPrivateKey::from_pkcs8_der(RSA_KEY).unwrap();
    let sig = key
        .sign(rsa::Pkcs1v15Sign::new::<sha2::Sha256>(), &tbs)
        .unwrap();
    let (h, s) = resume(
        h,
        http_ok(serde_json::json!({"signatures": [base64_std(&sig)]})),
        ctx(),
    )
    .unwrap();
    // The B-T flow now requests a timestamp.
    let tsa_req = match &s {
        Step::PerformHttp(e) => {
            assert!(e.url.contains("tsa.example"));
            e.body.clone().unwrap()
        }
        other => panic!("expected TSA request, got {other:?}"),
    };
    (h, tsa_req)
}

fn produce_signed_pdf_bt() -> SignedDocument {
    let (h, tsa_req) = drive_bt_to_timestamp();
    // Play the TSA with OpenSSL over the real request.
    let resp = openssl_timestamp(&tsa_req);
    match resume(h, http_ok_bytes(resp), ctx()).unwrap().1 {
        Step::Done { signed, .. } => signed,
        other => panic!("expected Done, got {other:?}"),
    }
}

#[test]
fn b_t_rejects_timestamp_with_wrong_imprint() {
    if !openssl_available() {
        eprintln!("openssl not available; skipping");
        return;
    }
    let (h, _tsa_req) = drive_bt_to_timestamp();
    // Feed a token bound to an UNRELATED imprint (as a MITM'd/replayed TSA would) — it must be
    // rejected, not embedded, because it does not cover our signature value.
    let bogus_req = cleverbase_core::timestamp::build_request(
        &cleverbase_core::crypto::sha256(b"some unrelated bytes"),
        None,
    )
    .unwrap();
    let resp = openssl_timestamp(&bogus_req);
    let (handle, step) = resume(h, http_ok_bytes(resp), ctx()).unwrap();
    assert_eq!(handle.phase, cleverbase_core::SigningPhase::Failed);
    match step {
        Step::Failed { evidence } => {
            assert_eq!(
                evidence.outcome,
                cleverbase_core::SigningOutcome::TimestampFailed
            );
        }
        other => panic!("expected TimestampFailed, got {other:?}"),
    }
}

#[test]
fn produced_b_t_signature_has_timestamp_and_verifies() {
    if !openssl_available() {
        eprintln!("openssl not available; skipping B-T validation");
        return;
    }
    let signed = produce_signed_pdf_bt();
    assert_eq!(signed.conformance_level, ConformanceLevel::BT);
    Document::load_mem(&signed.pdf).unwrap();

    let (content, cms_der) = extract(&signed.pdf);
    assert!(
        cleverbase_core::crypto::cms::has_signature_timestamp(&cms_der).unwrap(),
        "B-T signature must carry a signature-time-stamp unsigned attribute"
    );

    // The base signature still verifies independently after timestamp embedding.
    let dir = std::env::temp_dir();
    let cms_path = dir.join("cb_it_bt_cms.der");
    let content_path = dir.join("cb_it_bt_content.bin");
    std::fs::write(&cms_path, &cms_der).unwrap();
    std::fs::write(&content_path, &content).unwrap();
    let ca = materialize_ca_pem();
    let out = Command::new("openssl")
        .args([
            "cms", "-verify", "-inform", "DER", "-binary", "-purpose", "any",
        ])
        .arg("-in")
        .arg(&cms_path)
        .arg("-content")
        .arg(&content_path)
        .arg("-CAfile")
        .arg(&ca)
        .arg("-out")
        .arg(dir.join("cb_it_bt_out.bin"))
        .output()
        .expect("run openssl");
    let _ = std::fs::remove_file(&cms_path);
    let _ = std::fs::remove_file(&content_path);
    let _ = std::fs::remove_file(&ca);
    assert!(
        out.status.success(),
        "B-T base signature verify failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
