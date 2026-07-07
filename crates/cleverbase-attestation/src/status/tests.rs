//! Tests for the revocation/status check (T014 — written test-first against the implementation).
//!
//! The status check is sans-IO: a credential references its status mechanism, the host supplies the
//! fetched status document through the [`StatusSource`] seam, and the core evaluates it under the
//! fail-closed reachability policy. These assert: no-status → NoStatus; a reachable list/CRL →
//! Good/Revoked per the entry; and an **unreachable** document → Unavailable (fail-closed) or Good
//! (best-effort) per the policy — never a silent VALID under the default.

use std::collections::BTreeMap;

use super::{check_status, StatusOutcome, StatusReference, StatusSource};
use crate::types::StatusReachability;

/// A configurable in-memory status source for the tests (the host seam): maps URIs to either a
/// status-list byte array or a CRL revoked-serial set, and can be made to report a URI as
/// unreachable (returning `None`).
#[derive(Default)]
struct TestStatusSource {
    status_lists: BTreeMap<String, Vec<u8>>,
    crls: BTreeMap<String, Vec<Vec<u8>>>,
}

impl TestStatusSource {
    fn with_status_list(mut self, uri: &str, entries: Vec<u8>) -> Self {
        self.status_lists.insert(uri.to_owned(), entries);
        self
    }

    fn with_crl(mut self, uri: &str, revoked: Vec<Vec<u8>>) -> Self {
        self.crls.insert(uri.to_owned(), revoked);
        self
    }
}

impl StatusSource for TestStatusSource {
    fn fetch_status_list(&self, uri: &str) -> Option<Vec<u8>> {
        self.status_lists.get(uri).cloned()
    }
    fn fetch_crl_revoked_serials(&self, uri: &str) -> Option<Vec<Vec<u8>>> {
        self.crls.get(uri).cloned()
    }
}

const URI: &str = "https://issuer.example/status/1";

#[test]
fn no_status_reference_is_no_status() {
    let source = TestStatusSource::default();
    let outcome = check_status(
        &StatusReference::None,
        &source,
        StatusReachability::FailClosed,
    );
    assert_eq!(outcome, StatusOutcome::NoStatus);
}

#[test]
fn malformed_status_reference_fails_closed_regardless_of_reachability() {
    // A present-but-uninterpretable status reference is NEVER a silent VALID: it fails closed to
    // `Unavailable` under BOTH reachability policies (the credential declared a mechanism the core
    // cannot evaluate). This is what stops a malformed `status_list` falling through to a host `Good`.
    let source = TestStatusSource::default();
    assert_eq!(
        check_status(
            &StatusReference::Malformed,
            &source,
            StatusReachability::FailClosed
        ),
        StatusOutcome::Unavailable
    );
    assert_eq!(
        check_status(
            &StatusReference::Malformed,
            &source,
            StatusReachability::BestEffort
        ),
        StatusOutcome::Unavailable
    );
}

#[test]
fn current_entry_in_a_reachable_status_list_is_good() {
    // Entry 2 holds 0 (valid).
    let source = TestStatusSource::default().with_status_list(URI, vec![1, 0, 0, 1]);
    let outcome = check_status(
        &StatusReference::StatusList {
            index: 2,
            uri: URI.to_owned(),
        },
        &source,
        StatusReachability::FailClosed,
    );
    assert_eq!(outcome, StatusOutcome::Good);
}

#[test]
fn revoked_entry_in_a_reachable_status_list_is_revoked() {
    // Entry 0 holds 1 (revoked); any non-zero value is revoked/suspended.
    let source = TestStatusSource::default().with_status_list(URI, vec![1, 0, 0]);
    let outcome = check_status(
        &StatusReference::StatusList {
            index: 0,
            uri: URI.to_owned(),
        },
        &source,
        StatusReachability::FailClosed,
    );
    assert_eq!(outcome, StatusOutcome::Revoked);
}

#[test]
fn suspended_nonzero_status_value_is_treated_as_revoked() {
    // A 2-bit status list can carry value 2 (suspended); the always-on bar fails it like revoked.
    let source = TestStatusSource::default().with_status_list(URI, vec![0, 2]);
    let outcome = check_status(
        &StatusReference::StatusList {
            index: 1,
            uri: URI.to_owned(),
        },
        &source,
        StatusReachability::FailClosed,
    );
    assert_eq!(outcome, StatusOutcome::Revoked);
}

#[test]
fn unreachable_status_list_fails_closed_by_default() {
    // The URI is not in the source → unreachable. Fail-closed (default) → Unavailable.
    let source = TestStatusSource::default();
    let outcome = check_status(
        &StatusReference::StatusList {
            index: 0,
            uri: URI.to_owned(),
        },
        &source,
        StatusReachability::FailClosed,
    );
    assert_eq!(outcome, StatusOutcome::Unavailable);
}

#[test]
fn unreachable_status_list_is_tolerated_under_best_effort() {
    let source = TestStatusSource::default();
    let outcome = check_status(
        &StatusReference::StatusList {
            index: 0,
            uri: URI.to_owned(),
        },
        &source,
        StatusReachability::BestEffort,
    );
    assert_eq!(outcome, StatusOutcome::Good);
}

#[test]
fn out_of_range_index_fails_closed() {
    // A short/malformed list that does not cover the credential's index cannot prove it current.
    let source = TestStatusSource::default().with_status_list(URI, vec![0, 0]);
    let outcome = check_status(
        &StatusReference::StatusList {
            index: 99,
            uri: URI.to_owned(),
        },
        &source,
        StatusReachability::FailClosed,
    );
    assert_eq!(outcome, StatusOutcome::Unavailable);
}

#[test]
fn crl_with_the_serial_is_revoked() {
    let serial = vec![0x01, 0x02, 0x03];
    let source = TestStatusSource::default().with_crl(URI, vec![vec![0xAA], serial.clone()]);
    let outcome = check_status(
        &StatusReference::Crl {
            serial,
            uri: URI.to_owned(),
        },
        &source,
        StatusReachability::FailClosed,
    );
    assert_eq!(outcome, StatusOutcome::Revoked);
}

#[test]
fn crl_without_the_serial_is_good() {
    let source = TestStatusSource::default().with_crl(URI, vec![vec![0xAA], vec![0xBB]]);
    let outcome = check_status(
        &StatusReference::Crl {
            serial: vec![0x01],
            uri: URI.to_owned(),
        },
        &source,
        StatusReachability::FailClosed,
    );
    assert_eq!(outcome, StatusOutcome::Good);
}

#[test]
fn unreachable_crl_fails_closed_by_default() {
    let source = TestStatusSource::default();
    let outcome = check_status(
        &StatusReference::Crl {
            serial: vec![0x01],
            uri: URI.to_owned(),
        },
        &source,
        StatusReachability::FailClosed,
    );
    assert_eq!(outcome, StatusOutcome::Unavailable);
}

#[test]
fn unreachable_crl_is_tolerated_under_best_effort() {
    let source = TestStatusSource::default();
    let outcome = check_status(
        &StatusReference::Crl {
            serial: vec![0x01],
            uri: URI.to_owned(),
        },
        &source,
        StatusReachability::BestEffort,
    );
    assert_eq!(outcome, StatusOutcome::Good);
}

// =================================================================================================
// IN-CORE Token Status List verifier tests (draft-ietf-oauth-status-list-21).
//
// These mint REAL signed Status List Tokens with a test P-256 key (JWS by hand; COSE_Sign1 via
// `coset`), then drive [`verify_status_list_token`] end-to-end. The `resolve_key` closure stands in
// for layer 2's trust/EKU decision: it simply returns the key the token was signed with (or a wrong
// key / `Err` to exercise the signature / authorization rejects). Every negative asserts `Unavailable`
// (never `Good`).
// =================================================================================================

use base64ct::{Base64UrlUnpadded, Encoding as _};
use ciborium::value::Value as CborValue;
use coset::{
    iana, CborSerializable as _, CoseMac0Builder, CoseSign1Builder, HeaderBuilder,
    TaggedCborSerializable as _,
};
use p256::ecdsa::{signature::Signer as _, Signature, SigningKey, VerifyingKey};
use serde_json::json;

use super::{
    decompress_status_list, extract_status_value, status_reference_from_mdoc_status,
    status_reference_from_sd_jwt_claim, status_value_to_outcome, validate_bits,
    verify_status_list_token, SignerKeyMaterial,
};

const LIST_URI: &str = "https://issuer.example/statuslists/1";
const NOW: i64 = 1_700_000_000;

/// The Status List Token signing key used across these tests.
fn signer() -> SigningKey {
    SigningKey::from_slice(&[0x11u8; 32]).expect("valid non-zero P-256 scalar")
}

/// A DIFFERENT key, for the wrong-key (bad-signature) negatives.
fn other_signer() -> SigningKey {
    SigningKey::from_slice(&[0x22u8; 32]).expect("valid non-zero P-256 scalar")
}

/// zlib-compress (RFC 1950) a status bitstring, mirroring what a status provider produces for `lst`.
fn zlib(bytes: &[u8]) -> Vec<u8> {
    miniz_oxide::deflate::compress_to_vec_zlib(bytes, 6)
}

// --- JWS (JOSE) minting ---------------------------------------------------------------------------

/// Sign a compact JWS (`header.payload.signature`) with `sk` over the ASCII signing input.
fn sign_jws(sk: &SigningKey, header: &serde_json::Value, payload: &serde_json::Value) -> String {
    let h = Base64UrlUnpadded::encode_string(&serde_json::to_vec(header).unwrap());
    let p = Base64UrlUnpadded::encode_string(&serde_json::to_vec(payload).unwrap());
    let signing_input = format!("{h}.{p}");
    let sig: Signature = sk.sign(signing_input.as_bytes());
    let s = Base64UrlUnpadded::encode_string(sig.to_bytes().as_slice());
    format!("{signing_input}.{s}")
}

/// The conformant Status List Token JOSE header (`alg=ES256`, `typ=statuslist+jwt`, a `kid` hint).
fn jwt_header() -> serde_json::Value {
    json!({ "alg": "ES256", "typ": "statuslist+jwt", "kid": "status-key-1" })
}

/// Build a Status List Token JWT payload; `lst` is base64url of the zlib-compressed bitstring.
fn jwt_payload(
    sub: &str,
    iat: i64,
    exp: Option<i64>,
    ttl: Option<i64>,
    bits: u64,
    lst_compressed: &[u8],
) -> serde_json::Value {
    let mut payload = json!({
        "sub": sub,
        "iat": iat,
        "status_list": {
            "bits": bits,
            "lst": Base64UrlUnpadded::encode_string(lst_compressed),
        },
    });
    if let Some(exp) = exp {
        payload["exp"] = json!(exp);
    }
    if let Some(ttl) = ttl {
        payload["ttl"] = json!(ttl);
    }
    payload
}

/// A conformant JWT Status List Token over `bitstring` at `bits`, signed by [`signer`].
fn valid_jwt(bits: u64, bitstring: &[u8]) -> String {
    sign_jws(
        &signer(),
        &jwt_header(),
        &jwt_payload(
            LIST_URI,
            NOW - 100,
            Some(NOW + 1000),
            Some(3600),
            bits,
            &zlib(bitstring),
        ),
    )
}

// --- CWT (COSE) minting ---------------------------------------------------------------------------

fn cbor_int(n: i64) -> CborValue {
    CborValue::Integer(n.into())
}

/// Build the CWT Claims Set CBOR (integer keys; `status_list` sub-map has TEXT keys, `lst` a raw bstr).
fn cwt_claims(
    sub: &str,
    iat: i64,
    exp: Option<i64>,
    ttl: Option<i64>,
    bits: u64,
    lst_compressed: &[u8],
) -> Vec<u8> {
    let status_list = CborValue::Map(vec![
        (
            CborValue::Text("bits".to_owned()),
            CborValue::Integer(bits.into()),
        ),
        (
            CborValue::Text("lst".to_owned()),
            CborValue::Bytes(lst_compressed.to_vec()),
        ),
    ]);
    let mut entries = vec![
        (cbor_int(2), CborValue::Text(sub.to_owned())),
        (cbor_int(6), cbor_int(iat)),
        (cbor_int(65_533), status_list),
    ];
    if let Some(exp) = exp {
        entries.push((cbor_int(4), cbor_int(exp)));
    }
    if let Some(ttl) = ttl {
        entries.push((cbor_int(65_534), cbor_int(ttl)));
    }
    let mut buf = Vec::new();
    ciborium::into_writer(&CborValue::Map(entries), &mut buf).unwrap();
    buf
}

/// Sign a tagged `COSE_Sign1` Status List Token with `sk`, stamping the protected `typ` (label 16).
fn sign_cwt(sk: &SigningKey, typ: &str, payload: Vec<u8>) -> Vec<u8> {
    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::ES256)
        .value(16, CborValue::Text(typ.to_owned()))
        .build();
    CoseSign1Builder::new()
        .protected(protected)
        .payload(payload)
        .create_signature(&[], |tbs| {
            let sig: Signature = sk.sign(tbs);
            sig.to_bytes().as_slice().to_vec()
        })
        .build()
        .to_tagged_vec()
        .unwrap()
}

/// A conformant CWT Status List Token over `bitstring` at `bits`, signed by [`signer`].
fn valid_cwt(bits: u64, bitstring: &[u8]) -> Vec<u8> {
    sign_cwt(
        &signer(),
        "application/statuslist+cwt",
        cwt_claims(
            LIST_URI,
            NOW - 100,
            Some(NOW + 1000),
            Some(3600),
            bits,
            &zlib(bitstring),
        ),
    )
}

/// The `resolve_key` closure layer 2 will supply — here it simply authorizes `vk`.
fn accept(vk: VerifyingKey) -> impl FnOnce(&SignerKeyMaterial) -> Result<VerifyingKey, ()> {
    move |_material| Ok(vk)
}

fn verify_jwt(token: &str, idx: u64) -> StatusOutcome {
    verify_status_list_token(
        token.as_bytes(),
        LIST_URI,
        idx,
        NOW,
        accept(*signer().verifying_key()),
    )
}

fn verify_cwt(token: &[u8], idx: u64) -> StatusOutcome {
    verify_status_list_token(token, LIST_URI, idx, NOW, accept(*signer().verifying_key()))
}

// --- (1) Valid JWT — Good / Revoked / Suspended per the byte -------------------------------------

#[test]
fn valid_jwt_reads_good_revoked_and_suspended() {
    // bits=1: byte 0b0000_0010 → entry0=0 (VALID), entry1=1 (INVALID/revoked); LSB-first.
    let token = valid_jwt(1, &[0b0000_0010]);
    assert_eq!(verify_jwt(&token, 0), StatusOutcome::Good);
    assert_eq!(verify_jwt(&token, 1), StatusOutcome::Revoked);

    // bits=2: byte 0b00_00_10_00 → entry0=0 (VALID), entry1=2 (SUSPENDED→Revoked).
    let token = valid_jwt(2, &[0b0000_1000]);
    assert_eq!(verify_jwt(&token, 0), StatusOutcome::Good);
    assert_eq!(verify_jwt(&token, 1), StatusOutcome::Revoked);
}

// --- (2) Valid CWT — Good / Revoked / Suspended per the byte -------------------------------------

#[test]
fn valid_cwt_reads_good_revoked_and_suspended() {
    let token = valid_cwt(1, &[0b0000_0010]);
    assert_eq!(verify_cwt(&token, 0), StatusOutcome::Good);
    assert_eq!(verify_cwt(&token, 1), StatusOutcome::Revoked);

    // bits=2, entry1 = 2 (SUSPENDED) → Revoked.
    let token = valid_cwt(2, &[0b0000_1000]);
    assert_eq!(verify_cwt(&token, 1), StatusOutcome::Revoked);
}

// --- (3) Wrong `sub` (byte-exact URI binding) → Unavailable --------------------------------------

#[test]
fn jwt_sub_not_matching_expected_uri_is_unavailable() {
    // A perfectly valid, correctly-signed list — but for a DIFFERENT URI than the credential's.
    let token = sign_jws(
        &signer(),
        &jwt_header(),
        &jwt_payload(
            "https://issuer.example/statuslists/OTHER",
            NOW - 100,
            Some(NOW + 1000),
            None,
            1,
            &zlib(&[0b0000_0010]),
        ),
    );
    assert_eq!(verify_jwt(&token, 1), StatusOutcome::Unavailable);
}

#[test]
fn cwt_sub_not_matching_expected_uri_is_unavailable() {
    let token = sign_cwt(
        &signer(),
        "application/statuslist+cwt",
        cwt_claims(
            "https://issuer.example/statuslists/OTHER",
            NOW - 100,
            Some(NOW + 1000),
            None,
            1,
            &zlib(&[0b0000_0010]),
        ),
    );
    assert_eq!(verify_cwt(&token, 1), StatusOutcome::Unavailable);
}

// --- (4) Bad signature → Unavailable -------------------------------------------------------------

#[test]
fn jwt_signature_not_verifying_under_resolved_key_is_unavailable() {
    // Signed with `other_signer`, but the closure authorizes `signer`'s key → signature fails.
    let token = sign_jws(
        &other_signer(),
        &jwt_header(),
        &jwt_payload(
            LIST_URI,
            NOW - 100,
            Some(NOW + 1000),
            None,
            1,
            &zlib(&[0b0000_0001]),
        ),
    );
    assert_eq!(verify_jwt(&token, 0), StatusOutcome::Unavailable);
}

#[test]
fn jwt_tampered_signature_bytes_are_unavailable() {
    let mut token = valid_jwt(1, &[0b0000_0001]);
    // Flip the last base64url char of the signature segment.
    let last = token.pop().unwrap();
    token.push(if last == 'A' { 'B' } else { 'A' });
    assert_eq!(verify_jwt(&token, 0), StatusOutcome::Unavailable);
}

#[test]
fn cwt_signature_not_verifying_under_resolved_key_is_unavailable() {
    let token = sign_cwt(
        &other_signer(),
        "application/statuslist+cwt",
        cwt_claims(
            LIST_URI,
            NOW - 100,
            Some(NOW + 1000),
            None,
            1,
            &zlib(&[0b0000_0001]),
        ),
    );
    assert_eq!(verify_cwt(&token, 0), StatusOutcome::Unavailable);
}

// --- (5) Expired `exp` → Unavailable -------------------------------------------------------------

#[test]
fn jwt_expired_exp_is_unavailable() {
    // exp strictly in the past (and exp == now is also expired: the bound is exclusive).
    let token = sign_jws(
        &signer(),
        &jwt_header(),
        &jwt_payload(
            LIST_URI,
            NOW - 1000,
            Some(NOW - 1),
            None,
            1,
            &zlib(&[0b0000_0000]),
        ),
    );
    assert_eq!(verify_jwt(&token, 0), StatusOutcome::Unavailable);

    let at_boundary = sign_jws(
        &signer(),
        &jwt_header(),
        &jwt_payload(
            LIST_URI,
            NOW - 1000,
            Some(NOW),
            None,
            1,
            &zlib(&[0b0000_0000]),
        ),
    );
    assert_eq!(verify_jwt(&at_boundary, 0), StatusOutcome::Unavailable);
}

#[test]
fn cwt_expired_exp_is_unavailable() {
    let token = sign_cwt(
        &signer(),
        "application/statuslist+cwt",
        cwt_claims(
            LIST_URI,
            NOW - 1000,
            Some(NOW - 1),
            None,
            1,
            &zlib(&[0b0000_0000]),
        ),
    );
    assert_eq!(verify_cwt(&token, 0), StatusOutcome::Unavailable);
}

#[test]
fn jwt_stale_ttl_is_unavailable() {
    // iat + ttl < now → the cached token is stale (exp absent / far future is irrelevant).
    let token = sign_jws(
        &signer(),
        &jwt_header(),
        &jwt_payload(
            LIST_URI,
            NOW - 10_000,
            Some(NOW + 100_000),
            Some(60),
            1,
            &zlib(&[0b0000_0000]),
        ),
    );
    assert_eq!(verify_jwt(&token, 0), StatusOutcome::Unavailable);
}

// --- (5b) Fractional NumericDate `exp`/`iat`/`ttl` verify (RFC 7519 §2 / RFC 8392) ---------------

#[test]
fn jwt_fractional_exp_and_iat_verify_not_false_rejected() {
    // RFC 7519 §2 permits a FRACTIONAL NumericDate. A conformant token whose `iat`/`exp` carry a
    // sub-second fraction must NOT be false-rejected (it was, when the parser demanded an integer):
    // `iat`/`exp`/`ttl` now round through the shared numeric-date core.
    // Exact-in-f64 literals tied to `NOW` (1_700_000_000): iat = NOW-100+0.5, exp = NOW+1000+0.5.
    let payload = json!({
        "sub": LIST_URI,
        "iat": 1_699_999_900.5f64, // NOW - 100 + 0.5 (fractional iat)
        "exp": 1_700_001_000.5f64, // NOW + 1000 + 0.5 (fractional exp, well after `now`)
        "ttl": 3_600.5f64,         // fractional ttl (deadline iat+ttl is well after `now`)
        "status_list": {
            "bits": 1,
            "lst": Base64UrlUnpadded::encode_string(&zlib(&[0b0000_0000])),
        },
    });
    let token = sign_jws(&signer(), &jwt_header(), &payload);
    assert_eq!(verify_jwt(&token, 0), StatusOutcome::Good);
}

#[test]
fn cwt_fractional_exp_and_iat_verify_not_false_rejected() {
    // The CWT mirror: `iat`/`exp` as CBOR floats (RFC 8392 fractional NumericDate) must verify.
    let status_list = CborValue::Map(vec![
        (
            CborValue::Text("bits".to_owned()),
            CborValue::Integer(1.into()),
        ),
        (
            CborValue::Text("lst".to_owned()),
            CborValue::Bytes(zlib(&[0b0000_0000])),
        ),
    ]);
    let claims = CborValue::Map(vec![
        (cbor_int(2), CborValue::Text(LIST_URI.to_owned())),
        (cbor_int(6), CborValue::Float(1_699_999_900.5)), // NOW - 100 + 0.5 (fractional iat)
        (cbor_int(4), CborValue::Float(1_700_001_000.5)), // NOW + 1000 + 0.5 (fractional exp)
        (cbor_int(65_533), status_list),
    ]);
    let mut buf = Vec::new();
    ciborium::into_writer(&claims, &mut buf).unwrap();
    let token = sign_cwt(&signer(), "application/statuslist+cwt", buf);
    assert_eq!(verify_cwt(&token, 0), StatusOutcome::Good);
}

// --- (5c) Per-URI inflate memoization (DoS-amplification cap) -------------------------------------

#[test]
fn inflate_is_memoized_per_uri_and_each_read_uses_its_own_idx() {
    // Within one verify sharing an inflate cache, a status list several documents reference is
    // zlib-inflated ONCE per URI (the amplification cap), while each read applies its OWN idx.
    // bits=1 byte 0b0000_0010: entry0 = VALID, entry1 = INVALID (revoked).
    let token = valid_jwt(1, &[0b0000_0010]);
    let mut cache = super::StatusListInflateCache::new();

    // First document (idx 0) inflates + caches; returns Good, leaving exactly one cached URI.
    let out0 = super::verify_status_list_token_cached(
        token.as_bytes(),
        LIST_URI,
        0,
        NOW,
        accept(*signer().verifying_key()),
        &mut cache,
    );
    assert_eq!(out0, StatusOutcome::Good);
    assert_eq!(
        cache.len(),
        1,
        "the URI's inflated list is cached after the first document"
    );

    // Second document (idx 1, SAME uri) reuses the cached inflate; its OWN idx reads Revoked, and the
    // cache still holds exactly one entry (the same URI was not re-inflated).
    let out1 = super::verify_status_list_token_cached(
        token.as_bytes(),
        LIST_URI,
        1,
        NOW,
        accept(*signer().verifying_key()),
        &mut cache,
    );
    assert_eq!(out1, StatusOutcome::Revoked);
    assert_eq!(cache.len(), 1, "the same URI is not re-inflated");
}

#[test]
fn a_cache_hit_short_circuits_the_inflate() {
    // Proof the memo genuinely REPLACES the inflate on a hit (not just tracks it): pre-seed the cache
    // for the URI with a DIFFERENT decompressed list (entry0 = INVALID) and verify a token whose real
    // `lst` has entry0 = VALID. A cache hit returns Revoked (the seeded bytes); a re-inflate would
    // return Good. The token still passes signature/`sub`/freshness before the memo is consulted.
    let token = valid_jwt(1, &[0b0000_0000]); // real list: entry0 = VALID
    let mut seeded = super::StatusListInflateCache::new();
    seeded.insert(LIST_URI.to_owned(), Some(vec![0b0000_0001])); // seeded: entry0 = INVALID
    let out = super::verify_status_list_token_cached(
        token.as_bytes(),
        LIST_URI,
        0,
        NOW,
        accept(*signer().verifying_key()),
        &mut seeded,
    );
    assert_eq!(
        out,
        StatusOutcome::Revoked,
        "a cache hit short-circuits the inflate: the bit is read from the cached bytes"
    );
}

// --- (6) Out-of-range `idx` → Unavailable (never Good) -------------------------------------------

#[test]
fn jwt_out_of_range_idx_is_unavailable() {
    // One byte at bits=1 covers entries 0..=7; idx 8 and beyond is uncovered.
    let token = valid_jwt(1, &[0b0000_0000]);
    assert_eq!(verify_jwt(&token, 8), StatusOutcome::Unavailable);
    assert_eq!(verify_jwt(&token, 10_000), StatusOutcome::Unavailable);
}

#[test]
fn cwt_out_of_range_idx_is_unavailable() {
    let token = valid_cwt(1, &[0b0000_0000]);
    assert_eq!(verify_cwt(&token, 8), StatusOutcome::Unavailable);
}

// --- (7) COSE_Mac0 (tag 17) rejected -------------------------------------------------------------

#[test]
fn cwt_cose_mac0_is_rejected() {
    // A tagged COSE_Mac0 (CBOR tag 17) — no third-party verifiability — MUST be rejected outright,
    // regardless of its (dummy) tag bytes or claims.
    let mac0 = CoseMac0Builder::new()
        .protected(
            HeaderBuilder::new()
                .value(16, CborValue::Text("application/statuslist+cwt".to_owned()))
                .build(),
        )
        .payload(cwt_claims(
            LIST_URI,
            NOW - 100,
            Some(NOW + 1000),
            None,
            1,
            &zlib(&[0b0000_0000]),
        ))
        .create_tag(&[], |_data| vec![0u8; 32])
        .build()
        .to_tagged_vec()
        .unwrap();
    assert_eq!(verify_cwt(&mac0, 0), StatusOutcome::Unavailable);
}

#[test]
fn cwt_untagged_cose_sign1_is_rejected() {
    // The spec REQUIRES the tag-18 wrapper; an untagged COSE_Sign1 array is ambiguous → rejected.
    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::ES256)
        .value(16, CborValue::Text("application/statuslist+cwt".to_owned()))
        .build();
    let untagged = CoseSign1Builder::new()
        .protected(protected)
        .payload(cwt_claims(
            LIST_URI,
            NOW - 100,
            Some(NOW + 1000),
            None,
            1,
            &zlib(&[0b0000_0000]),
        ))
        .create_signature(&[], |tbs| {
            let sig: Signature = signer().sign(tbs);
            sig.to_bytes().as_slice().to_vec()
        })
        .build()
        .to_vec()
        .unwrap();
    assert_eq!(verify_cwt(&untagged, 0), StatusOutcome::Unavailable);
}

// --- (8) Wrong `typ` rejected --------------------------------------------------------------------

#[test]
fn jwt_wrong_typ_is_rejected() {
    let token = sign_jws(
        &signer(),
        &json!({ "alg": "ES256", "typ": "jwt" }),
        &jwt_payload(
            LIST_URI,
            NOW - 100,
            Some(NOW + 1000),
            None,
            1,
            &zlib(&[0b0000_0000]),
        ),
    );
    assert_eq!(verify_jwt(&token, 0), StatusOutcome::Unavailable);
}

#[test]
fn jwt_wrong_alg_is_rejected() {
    let token = sign_jws(
        &signer(),
        &json!({ "alg": "RS256", "typ": "statuslist+jwt" }),
        &jwt_payload(
            LIST_URI,
            NOW - 100,
            Some(NOW + 1000),
            None,
            1,
            &zlib(&[0b0000_0000]),
        ),
    );
    assert_eq!(verify_jwt(&token, 0), StatusOutcome::Unavailable);
}

#[test]
fn jwt_present_crit_is_rejected() {
    let token = sign_jws(
        &signer(),
        &json!({ "alg": "ES256", "typ": "statuslist+jwt", "crit": ["exp"] }),
        &jwt_payload(
            LIST_URI,
            NOW - 100,
            Some(NOW + 1000),
            None,
            1,
            &zlib(&[0b0000_0000]),
        ),
    );
    assert_eq!(verify_jwt(&token, 0), StatusOutcome::Unavailable);
}

#[test]
fn cwt_wrong_typ_is_rejected() {
    let token = sign_cwt(
        &signer(),
        "application/cwt",
        cwt_claims(
            LIST_URI,
            NOW - 100,
            Some(NOW + 1000),
            None,
            1,
            &zlib(&[0b0000_0000]),
        ),
    );
    assert_eq!(verify_cwt(&token, 0), StatusOutcome::Unavailable);
}

// --- Unknown status value → Unavailable (never coerced to Good) ----------------------------------

#[test]
fn unknown_status_value_is_unavailable() {
    // bits=4, entry0 = 0x03 (application-specific / not in {VALID,INVALID,SUSPENDED}).
    let token = valid_jwt(4, &[0x03]);
    assert_eq!(verify_jwt(&token, 0), StatusOutcome::Unavailable);
}

// --- Signer-authorization closure rejects → Unavailable ------------------------------------------

#[test]
fn resolve_key_rejection_is_unavailable() {
    // Even a perfectly-signed, in-window token is Unavailable if layer 2's closure declines the signer.
    let token = valid_jwt(1, &[0b0000_0000]);
    let outcome = verify_status_list_token(token.as_bytes(), LIST_URI, 0, NOW, |_material| Err(()));
    assert_eq!(outcome, StatusOutcome::Unavailable);
}

// --- The signer hint is parsed and handed to the closure -----------------------------------------

#[test]
fn jose_signer_material_carries_x5c_and_ignores_kid() {
    let cert_a = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let cert_b = vec![0x01, 0x02, 0x03];
    // The header carries a `kid` — which the reworked authorization ignores; only the `x5c` chain is
    // surfaced in `SignerKeyMaterial` (the `kid` grants no authorization, so it is not parsed).
    let header = json!({
        "alg": "ES256",
        "typ": "statuslist+jwt",
        "kid": "key-42",
        "x5c": [
            base64ct::Base64::encode_string(&cert_a),
            base64ct::Base64::encode_string(&cert_b),
        ],
    });
    let token = sign_jws(
        &signer(),
        &header,
        &jwt_payload(
            LIST_URI,
            NOW - 100,
            Some(NOW + 1000),
            None,
            1,
            &zlib(&[0b0000_0000]),
        ),
    );
    let seen = std::cell::RefCell::new(None);
    let outcome = verify_status_list_token(token.as_bytes(), LIST_URI, 0, NOW, |material| {
        *seen.borrow_mut() = Some(material.clone());
        Ok(*signer().verifying_key())
    });
    assert_eq!(outcome, StatusOutcome::Good);
    let material = seen.into_inner().expect("closure invoked");
    assert_eq!(material.x5chain, vec![cert_a, cert_b]);
}

#[test]
fn cose_signer_material_carries_x5chain_and_ignores_kid() {
    let cert = vec![0xCA, 0xFE, 0xBA, 0xBE];
    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::ES256)
        .value(16, CborValue::Text("application/statuslist+cwt".to_owned()))
        .build();
    // A `kid` (label 4) is present in the unprotected header but is NOT surfaced — only the `x5chain`.
    let unprotected = HeaderBuilder::new()
        .key_id(b"cose-kid".to_vec())
        .value(33, CborValue::Bytes(cert.clone()))
        .build();
    let token = CoseSign1Builder::new()
        .protected(protected)
        .unprotected(unprotected)
        .payload(cwt_claims(
            LIST_URI,
            NOW - 100,
            Some(NOW + 1000),
            None,
            1,
            &zlib(&[0b0000_0000]),
        ))
        .create_signature(&[], |tbs| {
            let sig: Signature = signer().sign(tbs);
            sig.to_bytes().as_slice().to_vec()
        })
        .build()
        .to_tagged_vec()
        .unwrap();
    let seen = std::cell::RefCell::new(None);
    let outcome = verify_status_list_token(&token, LIST_URI, 0, NOW, |material| {
        *seen.borrow_mut() = Some(material.clone());
        Ok(*signer().verifying_key())
    });
    assert_eq!(outcome, StatusOutcome::Good);
    let material = seen.into_inner().expect("closure invoked");
    assert_eq!(material.x5chain, vec![cert]);
}

// --- (9) zlib round-trip + LSB-first bit extraction at bits=1 and bits=2 --------------------------

#[test]
fn zlib_round_trip_and_lsb_first_extraction() {
    // Two bytes so byte-index math is exercised: 0xAC = 0b1010_1100, 0xE4 = 0b1110_0100.
    let original = vec![0b1010_1100u8, 0b1110_0100u8];
    let compressed = zlib(&original);
    let decompressed = decompress_status_list(&compressed).expect("zlib round-trips");
    assert_eq!(
        decompressed, original,
        "zlib inflate must reproduce the exact bitstring"
    );

    // bits=1, LSB-first within byte 0 (0xAC): entries [0,0,1,1,0,1,0,1]; byte 1 (0xE4): [0,0,1,0,0,1,1,1].
    let expected_1bit = [
        0, 0, 1, 1, 0, 1, 0, 1, /* byte 1 */ 0, 0, 1, 0, 0, 1, 1, 1,
    ];
    for (idx, want) in expected_1bit.iter().enumerate() {
        assert_eq!(
            extract_status_value(&decompressed, idx as u64, 1),
            Some(*want),
            "bits=1 LSB-first entry {idx}"
        );
    }

    // bits=2, LSB-first: byte 0 (0b1010_1100) → entries [0b00, 0b11, 0b10, 0b10] = [0,3,2,2];
    //                    byte 1 (0b1110_0100) → entries [0b00, 0b01, 0b10, 0b11] = [0,1,2,3].
    let expected_2bit = [0, 3, 2, 2, /* byte 1 */ 0, 1, 2, 3];
    for (idx, want) in expected_2bit.iter().enumerate() {
        assert_eq!(
            extract_status_value(&decompressed, idx as u64, 2),
            Some(*want),
            "bits=2 LSB-first entry {idx}"
        );
    }

    // Out-of-range idx → None (the fail-closed signal, never a spurious 0/Good).
    assert_eq!(extract_status_value(&decompressed, 16, 1), None);
    assert_eq!(extract_status_value(&decompressed, 8, 2), None);
}

#[test]
fn validate_bits_accepts_only_1_2_4_8() {
    for good in [1u64, 2, 4, 8] {
        assert_eq!(validate_bits(good), Some(good as u8));
    }
    for bad in [0u64, 3, 5, 7, 9, 16, 255] {
        assert_eq!(validate_bits(bad), None);
    }
}

#[test]
fn status_registry_mapping() {
    assert_eq!(status_value_to_outcome(0x00), StatusOutcome::Good);
    assert_eq!(status_value_to_outcome(0x01), StatusOutcome::Revoked);
    assert_eq!(status_value_to_outcome(0x02), StatusOutcome::Revoked);
    for unknown in [0x03u8, 0x04, 0x0F, 0xFF] {
        assert_eq!(status_value_to_outcome(unknown), StatusOutcome::Unavailable);
    }
}

#[test]
fn corrupt_zlib_lst_fails_closed() {
    // A valid signature over a payload whose `lst` is not valid zlib → decompression fails → Unavailable.
    let token = sign_jws(
        &signer(),
        &jwt_header(),
        &jwt_payload(
            LIST_URI,
            NOW - 100,
            Some(NOW + 1000),
            None,
            1,
            &[0xFF, 0x00, 0x13, 0x37],
        ),
    );
    assert_eq!(verify_jwt(&token, 0), StatusOutcome::Unavailable);
}

// --- (11) Fine-grained fail-closed branch coverage (coverage-review gaps) ------------------------

#[test]
fn negative_ttl_is_unavailable() {
    // A `ttl` is a non-negative number of seconds; a negative one is malformed → fail closed.
    let token = sign_jws(
        &signer(),
        &jwt_header(),
        &jwt_payload(
            LIST_URI,
            NOW - 100,
            Some(NOW + 1000),
            Some(-1),
            1,
            &zlib(&[0b0000_0000]),
        ),
    );
    assert_eq!(verify_jwt(&token, 0), StatusOutcome::Unavailable);
}

#[test]
fn iat_plus_ttl_overflow_is_unavailable() {
    // `iat + ttl` overflowing `i64` is malformed (a `checked_add` failure) → fail closed, never a panic.
    // `exp` is checked before `ttl`, so a far-future `exp` lets the freshness (ttl) branch run.
    let token = sign_jws(
        &signer(),
        &jwt_header(),
        &jwt_payload(
            LIST_URI,
            i64::MAX,
            Some(NOW + 1000),
            Some(1),
            1,
            &zlib(&[0b0000_0000]),
        ),
    );
    assert_eq!(verify_jwt(&token, 0), StatusOutcome::Unavailable);
}

#[test]
fn genuinely_non_numeric_exp_is_unavailable() {
    // With fractional NumericDates now accepted (1b), a PRESENT `exp`/`ttl` that is not a number at all
    // (e.g. a JSON string) is still malformed → the bound is uninterpretable → fail closed (never
    // silently ignored, which would read as unbounded validity — a false-accept).
    let payload = json!({
        "sub": LIST_URI,
        "iat": NOW - 100,
        "exp": "not-a-number",
        "status_list": {
            "bits": 1,
            "lst": Base64UrlUnpadded::encode_string(&zlib(&[0b0000_0000])),
        },
    });
    let token = sign_jws(&signer(), &jwt_header(), &payload);
    assert_eq!(verify_jwt(&token, 0), StatusOutcome::Unavailable);

    // A non-numeric `ttl` likewise.
    let payload = json!({
        "sub": LIST_URI,
        "iat": NOW - 100,
        "exp": NOW + 1000,
        "ttl": ["not", "a", "number"],
        "status_list": {
            "bits": 1,
            "lst": Base64UrlUnpadded::encode_string(&zlib(&[0b0000_0000])),
        },
    });
    let token = sign_jws(&signer(), &jwt_header(), &payload);
    assert_eq!(verify_jwt(&token, 0), StatusOutcome::Unavailable);
}

#[test]
fn cwt_wrong_alg_is_rejected() {
    // The CWT protected `alg` MUST be ES256 (COSE −7); an ES384 header is rejected on the algorithm
    // alone (before any signature math), even though the signature bytes are a valid ES256 signature.
    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::ES384)
        .value(16, CborValue::Text("application/statuslist+cwt".to_owned()))
        .build();
    let token = CoseSign1Builder::new()
        .protected(protected)
        .payload(cwt_claims(
            LIST_URI,
            NOW - 100,
            Some(NOW + 1000),
            None,
            1,
            &zlib(&[0b0000_0000]),
        ))
        .create_signature(&[], |tbs| {
            let sig: Signature = signer().sign(tbs);
            sig.to_bytes().as_slice().to_vec()
        })
        .build()
        .to_tagged_vec()
        .unwrap();
    assert_eq!(verify_cwt(&token, 0), StatusOutcome::Unavailable);
}

#[test]
fn cwt_present_crit_is_rejected() {
    // A protected `crit` (label 2) listing a header beyond `alg` is an unprocessed critical header
    // (RFC 9052 §3.1) → fatal → fail closed.
    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::ES256)
        .add_critical(iana::HeaderParameter::ContentType)
        .value(16, CborValue::Text("application/statuslist+cwt".to_owned()))
        .build();
    let token = CoseSign1Builder::new()
        .protected(protected)
        .payload(cwt_claims(
            LIST_URI,
            NOW - 100,
            Some(NOW + 1000),
            None,
            1,
            &zlib(&[0b0000_0000]),
        ))
        .create_signature(&[], |tbs| {
            let sig: Signature = signer().sign(tbs);
            sig.to_bytes().as_slice().to_vec()
        })
        .build()
        .to_tagged_vec()
        .unwrap();
    assert_eq!(verify_cwt(&token, 0), StatusOutcome::Unavailable);
}

#[test]
fn decompression_beyond_the_cap_fails_closed() {
    // The zlib bomb guard: an `lst` that would inflate beyond `MAX_STATUS_LIST_BYTES` (64 MiB) fails
    // closed to Unavailable rather than risking OOM — even though everything else (signature, `sub`,
    // freshness) is valid. A highly-compressible over-cap bitstring compresses to a tiny `lst`.
    let over_cap = vec![0u8; super::MAX_STATUS_LIST_BYTES + 1];
    let compressed = zlib(&over_cap);
    let token = sign_jws(
        &signer(),
        &jwt_header(),
        &jwt_payload(LIST_URI, NOW - 100, Some(NOW + 1000), None, 1, &compressed),
    );
    assert_eq!(verify_jwt(&token, 0), StatusOutcome::Unavailable);
}

// --- (10) The two `status_reference_of` parsers on sample claims ---------------------------------

#[test]
fn sd_jwt_status_reference_parser() {
    // status → status_list → { idx, uri }  (wire key is `idx`, mapped onto the `index` field).
    let claim = json!({ "status_list": { "idx": 42, "uri": LIST_URI } });
    assert_eq!(
        status_reference_from_sd_jwt_claim(&claim),
        StatusReference::StatusList {
            index: 42,
            uri: LIST_URI.to_owned(),
        }
    );

    // No `status_list` object at all → None (genuinely no Token Status List mechanism).
    assert_eq!(
        status_reference_from_sd_jwt_claim(&json!({ "other": true })),
        StatusReference::None
    );

    // A `status_list` object IS present but unusable → Malformed (MUST fail closed, never fall through
    // to a positional `Good`): missing idx, empty uri, non-integer idx, non-object status_list.
    assert_eq!(
        status_reference_from_sd_jwt_claim(&json!({ "status_list": { "uri": LIST_URI } })),
        StatusReference::Malformed,
        "missing idx → Malformed"
    );
    assert_eq!(
        status_reference_from_sd_jwt_claim(&json!({ "status_list": { "idx": 1, "uri": "" } })),
        StatusReference::Malformed,
        "empty uri → Malformed"
    );
    assert_eq!(
        status_reference_from_sd_jwt_claim(
            &json!({ "status_list": { "idx": "1", "uri": LIST_URI } })
        ),
        StatusReference::Malformed,
        "idx as a string → Malformed"
    );
    assert_eq!(
        status_reference_from_sd_jwt_claim(&json!({ "status_list": "nonsense" })),
        StatusReference::Malformed,
        "status_list not an object → Malformed"
    );
}

#[test]
fn mdoc_status_reference_parser() {
    let status = CborValue::Map(vec![(
        CborValue::Text("status_list".to_owned()),
        CborValue::Map(vec![
            (
                CborValue::Text("idx".to_owned()),
                CborValue::Integer(7u64.into()),
            ),
            (
                CborValue::Text("uri".to_owned()),
                CborValue::Text(LIST_URI.to_owned()),
            ),
        ]),
    )]);
    assert_eq!(
        status_reference_from_mdoc_status(&status),
        StatusReference::StatusList {
            index: 7,
            uri: LIST_URI.to_owned(),
        }
    );

    // No `status_list` element → None.
    let empty = CborValue::Map(vec![]);
    assert_eq!(
        status_reference_from_mdoc_status(&empty),
        StatusReference::None
    );

    // A `status_list` element IS present but unusable → Malformed (fail closed): idx a text string
    // (non-integer), and an empty uri.
    let idx_is_text = CborValue::Map(vec![(
        CborValue::Text("status_list".to_owned()),
        CborValue::Map(vec![
            (
                CborValue::Text("idx".to_owned()),
                CborValue::Text("7".to_owned()),
            ),
            (
                CborValue::Text("uri".to_owned()),
                CborValue::Text(LIST_URI.to_owned()),
            ),
        ]),
    )]);
    assert_eq!(
        status_reference_from_mdoc_status(&idx_is_text),
        StatusReference::Malformed,
        "non-integer idx → Malformed"
    );
    let empty_uri = CborValue::Map(vec![(
        CborValue::Text("status_list".to_owned()),
        CborValue::Map(vec![
            (
                CborValue::Text("idx".to_owned()),
                CborValue::Integer(7u64.into()),
            ),
            (
                CborValue::Text("uri".to_owned()),
                CborValue::Text(String::new()),
            ),
        ]),
    )]);
    assert_eq!(
        status_reference_from_mdoc_status(&empty_uri),
        StatusReference::Malformed,
        "empty uri → Malformed"
    );
}
