//! Test-only SD-JWT VC issuer + holder helpers, shared across the crate's tests (the SD-JWT VC side
//! of the always-on bar and the OpenID4VP binding tests) and the `test-vectors` feature.
//!
//! Mints real SD-JWT VC presentations with `sd-jwt-payload`'s issuer side, signed by the test issuer
//! key, with selective disclosures + a holder KB-JWT over a configurable `aud`/`nonce`. Synthetic
//! test material only (mirrors `tests/fixtures/attestation/gen.sh`).
//!
//! This is test-support code (compiled under `cfg(test)` or the `test-vectors` feature), so the
//! strict workspace `restriction` lints that forbid `unwrap`/`expect`/`panic` in library code are
//! relaxed here — a panic IS the intended failure signal when the fixed test fixtures are wrong.
//! Under the `test-vectors` feature only a subset of these helpers is used (the rest serve the
//! in-crate `cfg(test)` suite), so `dead_code` is permitted here.
//! These items are deliberately `pub(crate)` for cross-module reuse by the SD-JWT VC, OpenID4VP, and
//! wire test suites (and the `test-vectors` feature), so `redundant_pub_crate` is allowed here.
#![allow(
    dead_code,
    clippy::redundant_pub_crate,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::future::Future;
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use base64ct::{Base64UrlUnpadded, Encoding as _};
use p256::ecdsa::signature::Signer as _;
use pkcs8::DecodePrivateKey as _;
use sd_jwt_payload::{
    Hasher, JsonObject, JwsSigner, KeyBindingJwt, RequiredKeyBinding, SdJwt, SdJwtBuilder,
};
use serde_json::{json, Value};

/// The trusted test issuer signing key (PKCS#8) + its certificate (DER, carried in the JWS `x5c`).
pub(crate) const ISSUER_KEY_PK8: &[u8] =
    include_bytes!("../../../../tests/fixtures/attestation/sdjwt-issuer.key.pk8");
/// The trusted test issuer certificate (DER).
pub(crate) const ISSUER_CERT_DER: &[u8] =
    include_bytes!("../../../../tests/fixtures/attestation/sdjwt-issuer.cert.der");
/// The test holder signing key (PKCS#8) that the KB-JWT is signed with.
pub(crate) const HOLDER_KEY_PK8: &[u8] =
    include_bytes!("../../../../tests/fixtures/attestation/holder.key.pk8");
/// The test holder public key as a JWK (the issuer-bound `cnf`).
pub(crate) const HOLDER_JWK_JSON: &[u8] =
    include_bytes!("../../../../tests/fixtures/attestation/holder.jwk.json");
/// An untrusted issuer signing key (PKCS#8) for the wrong-issuer negative path.
pub(crate) const WRONG_ISSUER_KEY_PK8: &[u8] =
    include_bytes!("../../../../tests/fixtures/attestation/wrong-issuer.key.pk8");
/// An untrusted issuer certificate (DER) for the wrong-issuer negative path.
pub(crate) const WRONG_ISSUER_CERT_DER: &[u8] =
    include_bytes!("../../../../tests/fixtures/attestation/wrong-issuer.cert.der");

/// A time inside the minted credential's validity window (the canonical test instant).
pub(crate) const NOW: i64 = 1_750_000_000;

/// Drive a synchronous future to completion with a no-op waker (the test signer never awaits I/O,
/// so the future is `Ready` on the first poll) — avoids pulling an async runtime into dev-deps.
pub(crate) fn block_on<F: Future>(future: F) -> F::Output {
    fn noop_clone(_: *const ()) -> RawWaker {
        RawWaker::new(std::ptr::null(), &VTABLE)
    }
    fn noop(_: *const ()) {}
    static VTABLE: RawWakerVTable = RawWakerVTable::new(noop_clone, noop, noop, noop);
    let waker = unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) };
    let mut cx = Context::from_waker(&waker);
    let mut future = Box::pin(future);
    match future.as_mut().poll(&mut cx) {
        Poll::Ready(out) => out,
        Poll::Pending => panic!("test signer future unexpectedly pended"),
    }
}

/// A `sha-256` [`Hasher`] over the SDK's own `sha2` (the crate's `Sha256Hasher` is feature-gated off).
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Sha2Hasher;

impl Hasher for Sha2Hasher {
    fn digest(&self, input: &[u8]) -> Vec<u8> {
        use sha2::Digest as _;
        sha2::Sha256::digest(input).to_vec()
    }
    fn alg_name(&self) -> &'static str {
        "sha-256"
    }
}

/// A test ES256 [`JwsSigner`] over a `p256` key (the issuer / holder signing side).
pub(crate) struct Es256Signer {
    key: p256::ecdsa::SigningKey,
}

impl Es256Signer {
    /// Load a signer from a PKCS#8 P-256 key.
    pub(crate) fn from_pkcs8(pk8: &[u8]) -> Self {
        Self {
            key: p256::ecdsa::SigningKey::from_pkcs8_der(pk8).expect("valid PKCS#8 P-256 key"),
        }
    }
}

#[async_trait::async_trait]
impl JwsSigner for Es256Signer {
    type Error = String;
    async fn sign(&self, header: &JsonObject, payload: &JsonObject) -> Result<Vec<u8>, String> {
        let header_b64 =
            Base64UrlUnpadded::encode_string(serde_json::to_vec(header).unwrap().as_slice());
        let payload_b64 =
            Base64UrlUnpadded::encode_string(serde_json::to_vec(payload).unwrap().as_slice());
        let signing_input = format!("{header_b64}.{payload_b64}");
        let sig: p256::ecdsa::Signature = self.key.sign(signing_input.as_bytes());
        let sig_b64 = Base64UrlUnpadded::encode_string(sig.to_bytes().as_slice());
        Ok(format!("{signing_input}.{sig_b64}").into_bytes())
    }
}

/// Build the holder `cnf` confirmation from the test holder JWK fixture.
pub(crate) fn holder_cnf() -> RequiredKeyBinding {
    let jwk: Value = serde_json::from_slice(HOLDER_JWK_JSON).unwrap();
    let Value::Object(map) = jwk else {
        panic!("holder JWK is a JSON object")
    };
    RequiredKeyBinding::Jwk(map)
}

/// Mint a fresh SD-JWT VC (no KB-JWT yet) from the given issuer key/cert, with `given_name`,
/// `family_name`, `birthdate` as selective disclosures + `iss`/`nbf`/`exp`/`vct` + a `cnf` binding.
pub(crate) fn mint_sd_jwt(issuer_pk8: &[u8], issuer_cert_der: &[u8]) -> SdJwt {
    mint_sd_jwt_with_validity(
        issuer_pk8,
        issuer_cert_der,
        json!(NOW - 1_000),
        json!(NOW + 1_000_000),
    )
}

/// Mint an SD-JWT VC with caller-supplied `nbf`/`exp` JSON values, so the issuer signature is valid
/// over a *non-canonical* `NumericDate` (a JSON string, a non-integer float, or an out-of-`i64`-range
/// integer) — the false-accept probes for [`super::check_validity`]. The non-canonical bound is
/// signed by the real issuer key, so the credential clears the signature/trust checks and reaches the
/// validity check, exactly as a forged credential with a non-canonical `exp` would.
pub(crate) fn mint_sd_jwt_with_validity(
    issuer_pk8: &[u8],
    issuer_cert_der: &[u8],
    nbf: Value,
    exp: Value,
) -> SdJwt {
    let cert_b64 = base64ct::Base64::encode_string(issuer_cert_der);
    let mut claims = json!({
        "iss": "https://issuer.example/cb",
        "vct": "https://credentials.example/identity_credential",
        "given_name": "Ada",
        "family_name": "Lovelace",
        "birthdate": "1815-12-10",
    });
    let object = claims.as_object_mut().expect("claims is a JSON object");
    // A `null` bound means "omit the claim entirely" — the way to mint a credential that ASSERTS no
    // `nbf`/`exp` (the absent case), distinct from a present-but-malformed bound (any other value).
    if !nbf.is_null() {
        object.insert("nbf".to_owned(), nbf);
    }
    if !exp.is_null() {
        object.insert("exp".to_owned(), exp);
    }
    let signer = Es256Signer::from_pkcs8(issuer_pk8);
    block_on(
        SdJwtBuilder::new_with_hasher(claims, Sha2Hasher)
            .unwrap()
            .header("x5c", json!([cert_b64]))
            .make_concealable("/given_name")
            .unwrap()
            .make_concealable("/family_name")
            .unwrap()
            .make_concealable("/birthdate")
            .unwrap()
            .require_key_binding(holder_cnf())
            .finish(&signer, "ES256"),
    )
    .expect("issuer signing succeeds")
}

/// Mint a presentation whose issuer JWS signs **two different disclosures for the SAME claim name**
/// (`given_name` = `"Ada"` and `given_name` = `"Mallory"`), both with their digests in the top-level
/// `_sd` array, returning `<issuer-JWS>~<D-Ada>~<D-Mallory>~` (issuer-only, trailing `~`).
///
/// Both disclosures are issuer-signed (their digests are in `_sd`), so each passes the membership
/// check and they have *distinct* digests (distinct salts), so the repeated-digest guard does NOT
/// fire — the only thing that catches this is the duplicate-claim-name guard (RFC 9901 §9.3). The
/// caller appends the two disclosures in either order to prove the holder cannot pick which value the
/// RP sees.
pub(crate) fn mint_dual_value_same_name(
    issuer_pk8: &[u8],
    issuer_cert_der: &[u8],
) -> (String, String, String) {
    // Two object-property disclosures: ["<salt>", "given_name", <value>], distinct salts.
    let disclosure_a = Base64UrlUnpadded::encode_string(
        json!(["AAAAAAAAAAAAAAAAAAAAAA", "given_name", "Ada"])
            .to_string()
            .as_bytes(),
    );
    let disclosure_b = Base64UrlUnpadded::encode_string(
        json!(["BBBBBBBBBBBBBBBBBBBBBB", "given_name", "Mallory"])
            .to_string()
            .as_bytes(),
    );
    let digest_a = Base64UrlUnpadded::encode_string(&Sha2Hasher.digest(disclosure_a.as_bytes()));
    let digest_b = Base64UrlUnpadded::encode_string(&Sha2Hasher.digest(disclosure_b.as_bytes()));

    let cert_b64 = base64ct::Base64::encode_string(issuer_cert_der);
    let header = json!({ "alg": "ES256", "x5c": [cert_b64] });
    let payload = json!({
        "iss": "https://issuer.example/cb",
        "vct": "https://credentials.example/identity_credential",
        "nbf": NOW - 1_000,
        "exp": NOW + 1_000_000,
        "_sd_alg": "sha-256",
        "_sd": [digest_a, digest_b],
    });
    let header_b64 =
        Base64UrlUnpadded::encode_string(serde_json::to_vec(&header).unwrap().as_slice());
    let payload_b64 =
        Base64UrlUnpadded::encode_string(serde_json::to_vec(&payload).unwrap().as_slice());
    let signing_input = format!("{header_b64}.{payload_b64}");
    let key = p256::ecdsa::SigningKey::from_pkcs8_der(issuer_pk8).expect("valid PKCS#8 P-256 key");
    let sig: p256::ecdsa::Signature = key.sign(signing_input.as_bytes());
    let sig_b64 = Base64UrlUnpadded::encode_string(sig.to_bytes().as_slice());
    let jws = format!("{signing_input}.{sig_b64}");
    (jws, disclosure_a, disclosure_b)
}

/// Attach a holder KB-JWT (signed by `holder_pk8`) over the given `aud`/`nonce` to a minted SD-JWT,
/// returning the full compact presentation string.
pub(crate) fn attach_kb_jwt(
    mut sd_jwt: SdJwt,
    holder_pk8: &[u8],
    aud: &str,
    nonce: &str,
) -> String {
    let holder = Es256Signer::from_pkcs8(holder_pk8);
    let kb = block_on(
        KeyBindingJwt::builder()
            .iat(NOW)
            .aud(aud)
            .nonce(nonce)
            .finish(&sd_jwt, &Sha2Hasher, "ES256", &holder),
    )
    .expect("KB-JWT signing succeeds");
    sd_jwt.attach_key_binding_jwt(kb);
    sd_jwt.presentation()
}
