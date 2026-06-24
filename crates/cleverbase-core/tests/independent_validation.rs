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
const EC_CERT: &[u8] = include_bytes!("../../../tests/fixtures/pki/signer-ec.cert.der");
const EC_KEY: &[u8] = include_bytes!("../../../tests/fixtures/pki/signer-ec.key.pk8");

/// Signature algorithm the harness drives end-to-end. ONE parametrized producer path covers both
/// arms (FR-004) — no RSA/ECDSA copy-paste. Each arm pins the matching CSC API base, the
/// `credentials/info` substitution values (cert + key.algo OID + subject), and the `signHash`
/// simulator's signing routine.
#[derive(Clone, Copy)]
enum KeyAlgo {
    Rsa,
    EcdsaP256,
}

impl KeyAlgo {
    fn csc_api(self) -> CscApi {
        match self {
            Self::Rsa => CscApi::V1Rsa,
            Self::EcdsaP256 => CscApi::V2Ecdsa,
        }
    }

    /// The signer certificate (DER) the matching `credentials/info` advertises — the same key whose
    /// private half the `signHash` simulator signs with (no drift).
    fn cert_der(self) -> &'static [u8] {
        match self {
            Self::Rsa => RSA_CERT,
            Self::EcdsaP256 => EC_CERT,
        }
    }

    /// The `key.algo` OID the `credentials/info` advertises so the core detects this `KeyAlgo`.
    fn algo_oid(self) -> &'static str {
        match self {
            Self::Rsa => "1.2.840.113549.1.1.1",    // rsaEncryption
            Self::EcdsaP256 => "1.2.840.10045.2.1", // id-ecPublicKey
        }
    }

    /// The subject DN + serial the real fixture cert carries (kept honest with the cert above).
    fn subject_dn(self) -> &'static str {
        match self {
            Self::Rsa => "CN=Jane Doe,serialNumber=PNONL-123",
            Self::EcdsaP256 => "CN=John Roe,serialNumber=PNONL-456",
        }
    }

    fn serial(self) -> &'static str {
        match self {
            Self::Rsa => "PNONL-123",
            Self::EcdsaP256 => "PNONL-456",
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Rsa => "RSA",
            Self::EcdsaP256 => "ECDSA P-256",
        }
    }

    /// Simulate Cleverbase's `signHash`: sign the 32-byte to-be-signed digest of the signedAttrs
    /// with the fixture private key. RSA → PKCS#1 v1.5(SHA-256); ECDSA P-256 → the raw 64-byte
    /// `r‖s` wire form CSC v2 returns (the core's `ecdsa_signature_to_der` normalizes it).
    fn sign_hash(self, tbs: &[u8]) -> Vec<u8> {
        match self {
            Self::Rsa => {
                let key = rsa::RsaPrivateKey::from_pkcs8_der(RSA_KEY).unwrap();
                key.sign(rsa::Pkcs1v15Sign::new::<sha2::Sha256>(), tbs)
                    .unwrap()
            }
            Self::EcdsaP256 => ec_sign_raw(tbs),
        }
    }
}

/// Sign a prehashed 32-byte digest with the EC fixture key, returning the raw fixed-width 64-byte
/// `r‖s` (the CSC v2 wire form). Uses `sign_prehash` because the core feeds the SHA-256 of the
/// signedAttrs (already a digest), not the message.
fn ec_sign_raw(tbs: &[u8]) -> Vec<u8> {
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    use p256::ecdsa::{Signature, SigningKey};
    use p256::pkcs8::DecodePrivateKey;
    let key = SigningKey::from_pkcs8_der(EC_KEY).unwrap();
    let sig: Signature = key.sign_prehash(tbs).unwrap();
    sig.to_bytes().to_vec()
}

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

fn produce_signed_pdf(algo: KeyAlgo) -> SignedDocument {
    let cfg = TrustServiceConfiguration {
        environment: Environment::Acceptance,
        csc_api: algo.csc_api(),
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
    let info = signer_info(algo);

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
    let (h, _) = resume(h, http_ok(upstream_fixture("service_token", algo)), ctx()).unwrap();
    let (h, _) = resume(
        h,
        http_ok(upstream_fixture("credentials_list", algo)),
        ctx(),
    )
    .unwrap();
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
    let (h, s) = resume(
        h,
        http_ok(upstream_fixture("credential_token", algo)),
        ctx(),
    )
    .unwrap();
    let sign_req = match &s {
        Step::PerformHttp(e) => e.clone(),
        _ => panic!(),
    };
    let body: serde_json::Value = serde_json::from_slice(sign_req.body.as_ref().unwrap()).unwrap();
    let tbs = base64_decode(body["hash"][0].as_str().unwrap()).unwrap();
    let sig = algo.sign_hash(&tbs);
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

/// Run `openssl cms -verify` on a detached CMS over its ByteRange content against the test CA.
/// Returns whether OpenSSL accepted the signature (an entirely independent implementation).
fn openssl_cms_verify(content: &[u8], cms_der: &[u8]) -> bool {
    let dir = std::env::temp_dir();
    let cms_path = dir.join(format!("{}.der", unique_tag("cb_it_cms")));
    let content_path = dir.join(format!("{}.bin", unique_tag("cb_it_content")));
    let out_path = dir.join(format!("{}.bin", unique_tag("cb_it_out")));
    std::fs::write(&cms_path, cms_der).unwrap();
    std::fs::write(&content_path, content).unwrap();
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
        .arg(&out_path)
        .output()
        .expect("run openssl");

    let _ = std::fs::remove_file(&cms_path);
    let _ = std::fs::remove_file(&content_path);
    let _ = std::fs::remove_file(&out_path);
    let _ = std::fs::remove_file(&ca);
    out.status.success()
}

#[test]
fn produced_b_b_signature_verifies_with_openssl() {
    if !openssl_available() {
        eprintln!("openssl not available; skipping independent validation");
        return;
    }
    // One parametrized path, both algorithms (FR-004): each produced B-B CMS is accepted by the
    // independent OpenSSL validator.
    for algo in [KeyAlgo::Rsa, KeyAlgo::EcdsaP256] {
        let signed = produce_signed_pdf(algo);
        let (content, cms_der) = extract(&signed.pdf);
        assert!(
            openssl_cms_verify(&content, &cms_der),
            "openssl cms -verify rejected a valid {} B-B signature",
            algo.name(),
        );
    }
}

/// A produced ECDSA B-B CMS whose embedded signature has been corrupted MUST be rejected by the
/// always-on OpenSSL bar — no false-accept (F1 / FR-012 / SC-006). We produce a real signature, then
/// locate the `SignerInfo.signature` OCTET STRING in the assembled CMS and flip a bit inside it, so
/// the surrounding DER still parses but the signature no longer matches the signed attributes.
#[test]
fn tampered_ecdsa_signature_is_rejected_by_openssl() {
    if !openssl_available() {
        eprintln!("openssl not available; skipping tamper test");
        return;
    }
    let signed = produce_signed_pdf(KeyAlgo::EcdsaP256);
    let (content, cms_der) = extract(&signed.pdf);
    // Sanity: the untampered signature verifies, so a later rejection is due to the tamper.
    assert!(
        openssl_cms_verify(&content, &cms_der),
        "baseline ECDSA signature should verify before tampering",
    );
    let tampered = flip_signature_byte(&cms_der);
    assert_ne!(tampered, cms_der, "tamper must change the CMS bytes");
    assert!(
        !openssl_cms_verify(&content, &tampered),
        "openssl cms -verify MUST reject a tampered ECDSA signature (no false-accept)",
    );
}

/// Locate the `SignerInfo.signature` OCTET STRING in a detached CMS `SignedData` and flip a bit in
/// its last content byte. Parses the CMS with the `cms`/`der` crates (test-only) to find the exact
/// span — no `src/` change, no brittle byte scanning.
fn flip_signature_byte(cms_der: &[u8]) -> Vec<u8> {
    use cms::content_info::ContentInfo;
    use cms::signed_data::SignedData;
    use der::{Decode, Encode};

    let ci = ContentInfo::from_der(cms_der).expect("parse ContentInfo");
    let sd = ci
        .content
        .decode_as::<SignedData>()
        .expect("decode SignedData");
    let signer = sd.signer_infos.0.as_slice().first().expect("a SignerInfo");
    let sig = signer.signature.as_bytes();
    // The OCTET STRING content is a unique byte run in the CMS DER (it is the raw signature value);
    // find it and flip the last byte in place. Using the exact decoded bytes as the needle keeps
    // this robust against any incidental repetition elsewhere in the structure.
    let needle = sig.to_vec();
    let _ = signer.to_der().expect("re-encode SignerInfo"); // sanity: structure is well-formed
    let pos = cms_der
        .windows(needle.len())
        .position(|w| w == needle.as_slice())
        .expect("signature bytes present in CMS DER");
    let mut t = cms_der.to_vec();
    let last = pos + needle.len() - 1;
    t[last] ^= 0x01;
    t
}

fn upstream_dir() -> PathBuf {
    PathBuf::from(format!(
        "{}/../../tests/fixtures/upstream",
        env!("CARGO_MANIFEST_DIR")
    ))
}

/// Load a shared upstream-response fixture (the single source the Go mock also reads — FR-015),
/// substituting the selected algorithm's signer cert + `key.algo` OID + subject into the one
/// `credentials/info` template (per-algorithm substitution, no second committed copy — N1). The
/// cert and OID come from the SAME `algo` the `signHash` simulator signs with, so they never drift.
fn upstream_fixture(name: &str, algo: KeyAlgo) -> serde_json::Value {
    let raw = std::fs::read_to_string(upstream_dir().join(format!("{name}.json")))
        .unwrap_or_else(|e| panic!("read upstream fixture {name}: {e}"));
    let substituted = raw
        .replace("{{signer_cert_b64}}", &base64_std(algo.cert_der()))
        .replace("{{key_algo_oid}}", algo.algo_oid())
        .replace("{{signer_subject_dn}}", algo.subject_dn())
        .replace("{{signer_serial}}", algo.serial());
    serde_json::from_str(&substituted).unwrap()
}

fn signer_info(algo: KeyAlgo) -> serde_json::Value {
    upstream_fixture("credentials_info", algo)
}

/// Build a `credentials/info` value advertising an arbitrary `key.algo` OID + cert — for the
/// unsupported-OID rejection test (T008). Reuses the one template so there is no second copy.
fn signer_info_with_oid(oid: &str, cert_der: &[u8]) -> serde_json::Value {
    let raw = std::fs::read_to_string(upstream_dir().join("credentials_info.json"))
        .expect("read credentials_info template");
    let substituted = raw
        .replace("{{signer_cert_b64}}", &base64_std(cert_der))
        .replace("{{key_algo_oid}}", oid)
        .replace(
            "{{signer_subject_dn}}",
            "CN=Ed Wards,serialNumber=PNONL-789",
        )
        .replace("{{signer_serial}}", "PNONL-789");
    serde_json::from_str(&substituted).unwrap()
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
fn drive_bt_to_timestamp(algo: KeyAlgo) -> (cleverbase_core::SigningSessionHandle, Vec<u8>) {
    let cfg = TrustServiceConfiguration {
        environment: Environment::Acceptance,
        csc_api: algo.csc_api(),
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
    let (h, _) = resume(h, http_ok(upstream_fixture("service_token", algo)), ctx()).unwrap();
    let (h, _) = resume(
        h,
        http_ok(upstream_fixture("credentials_list", algo)),
        ctx(),
    )
    .unwrap();
    let (h, s) = resume(h, http_ok(signer_info(algo)), ctx()).unwrap();
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
    let (h, s) = resume(
        h,
        http_ok(upstream_fixture("credential_token", algo)),
        ctx(),
    )
    .unwrap();
    let sign_req = match &s {
        Step::PerformHttp(e) => e.clone(),
        _ => panic!("expected signHash"),
    };
    let body: serde_json::Value = serde_json::from_slice(sign_req.body.as_ref().unwrap()).unwrap();
    let tbs = base64_decode(body["hash"][0].as_str().unwrap()).unwrap();
    let sig = algo.sign_hash(&tbs);
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

fn produce_signed_pdf_bt(algo: KeyAlgo) -> SignedDocument {
    let (h, tsa_req) = drive_bt_to_timestamp(algo);
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
    let (h, _tsa_req) = drive_bt_to_timestamp(KeyAlgo::Rsa);
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
    // Both algorithms, one path (FR-004): each B-T signature carries a timestamp token AND the base
    // signature still verifies independently after timestamp embedding.
    for algo in [KeyAlgo::Rsa, KeyAlgo::EcdsaP256] {
        let signed = produce_signed_pdf_bt(algo);
        assert_eq!(signed.conformance_level, ConformanceLevel::BT);
        Document::load_mem(&signed.pdf).unwrap();

        let (content, cms_der) = extract(&signed.pdf);
        assert!(
            cleverbase_core::crypto::cms::has_signature_timestamp(&cms_der).unwrap(),
            "{} B-T signature must carry a signature-time-stamp unsigned attribute",
            algo.name(),
        );
        assert!(
            openssl_cms_verify(&content, &cms_der),
            "{} B-T base signature failed independent verification",
            algo.name(),
        );
    }
}

/// T007 (core arm) / F1: a tampered ECDSA B-T CMS is ALSO rejected by the always-on bar — the
/// timestamp embedding must not create a false-accept window.
#[test]
fn tampered_ecdsa_b_t_signature_is_rejected_by_openssl() {
    if !openssl_available() {
        eprintln!("openssl not available; skipping B-T tamper test");
        return;
    }
    let signed = produce_signed_pdf_bt(KeyAlgo::EcdsaP256);
    let (content, cms_der) = extract(&signed.pdf);
    assert!(
        openssl_cms_verify(&content, &cms_der),
        "baseline ECDSA B-T signature should verify before tampering",
    );
    let tampered = flip_signature_byte(&cms_der);
    assert!(
        !openssl_cms_verify(&content, &tampered),
        "openssl cms -verify MUST reject a tampered ECDSA B-T signature",
    );
}

/// T008 / F2: a `credentials/info` advertising an unsupported key OID (Ed25519, `1.3.101.112`) —
/// neither RSA nor P-256 — MUST terminate the flow with a specific credential-unavailable error and
/// produce NO signature (the core never guesses an algorithm). Exercises the core's existing
/// `KeyAlgo::Other` rejection end-to-end; no `src/` change.
#[test]
fn unsupported_key_oid_fails_with_no_signature() {
    let request = SigningRequest {
        document: minimal_pdf(),
        conformance_level: ConformanceLevel::BB,
        expected_signer: None,
        appearance: None,
        signature_meta: None,
    };
    let cfg = TrustServiceConfiguration {
        environment: Environment::Acceptance,
        csc_api: CscApi::V2Ecdsa,
        client_id: "client-123".into(),
        client_secret: Secret::new("shh"),
        redirect_uri: "https://app.example/cb".into(),
        tsa: None,
    };
    // Ed25519 (id-Ed25519, 1.3.101.112) is a valid key OID the SDK does not support in this phase.
    let info = signer_info_with_oid("1.3.101.112", EC_CERT);

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
    let (h, _) = resume(
        h,
        http_ok(upstream_fixture("service_token", KeyAlgo::EcdsaP256)),
        ctx(),
    )
    .unwrap();
    let (h, _) = resume(
        h,
        http_ok(upstream_fixture("credentials_list", KeyAlgo::EcdsaP256)),
        ctx(),
    )
    .unwrap();
    // The credentials/info advertising the unsupported OID must terminate the flow immediately.
    let (handle, step) = resume(h, http_ok(info), ctx()).unwrap();
    assert_eq!(
        handle.phase,
        cleverbase_core::SigningPhase::Failed,
        "an unsupported key OID must fail the flow, not proceed",
    );
    // Reaching `Step::Failed` (never `Step::Done { signed, .. }`) is itself the "no signature
    // produced" guarantee — the evidence record carries no signed document on failure.
    match step {
        Step::Failed { evidence } => {
            assert_eq!(
                evidence.outcome,
                cleverbase_core::SigningOutcome::CredentialUnavailable,
                "unsupported key OID must be a specific credential-unavailable outcome",
            );
            assert!(
                evidence.failure_reason.is_some(),
                "the failure must carry a specific human-readable reason",
            );
        }
        other => panic!("expected Failed (no signature), got {other:?}"),
    }
}

/// T009 / F3 (A1 — injection point is THIS Rust simulator): when the `signHash` simulator returns an
/// ECDSA signature of an unexpected raw length (not 64 bytes and not valid DER), the core MUST reject
/// it rather than mis-encode a malformed CMS. Exercises `ecdsa_signature_to_der`'s reject path +
/// the post-assembly self-verify, end-to-end; no `src/` change.
#[test]
fn malformed_raw_ecdsa_length_is_rejected_by_core() {
    for bad_len in [63usize, 65] {
        let algo = KeyAlgo::EcdsaP256;
        let cfg = TrustServiceConfiguration {
            environment: Environment::Acceptance,
            csc_api: algo.csc_api(),
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
        let (h, _) = resume(h, http_ok(upstream_fixture("service_token", algo)), ctx()).unwrap();
        let (h, _) = resume(
            h,
            http_ok(upstream_fixture("credentials_list", algo)),
            ctx(),
        )
        .unwrap();
        let (h, s) = resume(h, http_ok(signer_info(algo)), ctx()).unwrap();
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
        let (h, _s) = resume(
            h,
            http_ok(upstream_fixture("credential_token", algo)),
            ctx(),
        )
        .unwrap();
        // Return a raw signature of the WRONG length: neither 64 bytes nor valid DER. A genuine
        // P-256 signature truncated/extended to bad_len cannot be a valid ECDSA-Sig-Value, so the
        // core cannot normalize it and the self-verify must fail.
        let bad_sig = vec![0x7Au8; bad_len];
        let (handle, step) = resume(
            h,
            http_ok(serde_json::json!({"signatures": [base64_std(&bad_sig)]})),
            ctx(),
        )
        .unwrap();
        assert_eq!(
            handle.phase,
            cleverbase_core::SigningPhase::Failed,
            "a {bad_len}-byte raw ECDSA signature must be rejected, not embedded",
        );
        // Reaching `Step::Failed` (not `Step::Done`) proves no malformed CMS was produced.
        match step {
            Step::Failed { evidence } => {
                assert_eq!(
                    evidence.outcome,
                    cleverbase_core::SigningOutcome::SignatureInvalid,
                    "a malformed ({bad_len}-byte) signature must fail self-verification",
                );
            }
            other => panic!("expected Failed for {bad_len}-byte sig, got {other:?}"),
        }
    }
}
