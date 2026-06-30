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
    clippy::panic
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

/// A `sha-256` [`Hasher`] for the `sd-jwt-payload` issuer/holder minters, routed through the crate's
/// single authoritative SHA-256 ([`crate::crypto::sha256`]) and its IANA name ([`crate::crypto::SHA_256`])
/// — the SAME digest the production holder-presentation `Hasher` ([`crate::issuance::present`]) and
/// verifier use, so there is no second crypto stack and no re-inlined `"sha-256"` literal (DRY —
/// Principle III). (The production `Hasher` impl lives in `crate::issuance::present` and is private to
/// that module; this is the matching test-support adapter, delegating to the same `crate::crypto`.)
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Sha2Hasher;

impl Hasher for Sha2Hasher {
    fn digest(&self, input: &[u8]) -> Vec<u8> {
        crate::crypto::sha256(input).to_vec()
    }
    fn alg_name(&self) -> &'static str {
        crate::crypto::SHA_256
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

/// The default SD-JWT VC `vct` the test mints carry — a Collision-Resistant Name (an HTTPS URI), per
/// SD-JWT VC §type-claim / RFC 7515 §2.
pub(crate) const DEFAULT_VCT: &str = "https://credentials.example/identity_credential";

/// Mint an SD-JWT VC with caller-supplied `nbf`/`exp` JSON values — used to exercise
/// [`super::check_validity`] / [`super::numeric_date`] across the spectrum: a canonical integer, a
/// spec-valid FRACTIONAL number (RFC 7519 §2; a validity bound rounds up — see `super::DateRounding`),
/// and a *non-canonical* bound (a JSON string or an out-of-`i64`-range integer) that must reject. A
/// `null` value omits the claim (the absent case).
/// The bound is signed by the real issuer key, so the credential clears the signature/trust checks and
/// reaches the validity check, exactly as a credential with that `exp` would.
pub(crate) fn mint_sd_jwt_with_validity(
    issuer_pk8: &[u8],
    issuer_cert_der: &[u8],
    nbf: Value,
    exp: Value,
) -> SdJwt {
    mint_with(
        issuer_pk8,
        issuer_cert_der,
        nbf,
        exp,
        Some(DEFAULT_VCT),
        "dc+sd-jwt",
    )
}

/// Mint a happy-path SD-JWT VC whose issuer JWS protected header declares the given `typ` — the SD-JWT
/// VC media-type probe (draft-ietf-oauth-sd-jwt-vc-16 §3.2.1: `dc+sd-jwt`, transitionally `vc+sd-jwt`).
/// `typ` must be a value the `sd_jwt_payload` builder accepts (it requires a `+sd-jwt` suffix).
pub(crate) fn mint_sd_jwt_with_typ(issuer_pk8: &[u8], issuer_cert_der: &[u8], typ: &str) -> SdJwt {
    mint_with(
        issuer_pk8,
        issuer_cert_der,
        json!(NOW - 1_000),
        json!(NOW + 1_000_000),
        Some(DEFAULT_VCT),
        typ,
    )
}

/// Mint a happy-path SD-JWT VC carrying a caller-supplied `vct` — the DCQL `vct_values` match +
/// role-derivation probe (e.g. a EUDI PID `vct` `urn:eudi:pid:1`). Everything else (trusted issuer
/// signature + window + holder binding) is sound, so it clears the always-on bar and reaches the gate.
pub(crate) fn mint_sd_jwt_with_vct(issuer_pk8: &[u8], issuer_cert_der: &[u8], vct: &str) -> SdJwt {
    mint_with(
        issuer_pk8,
        issuer_cert_der,
        json!(NOW - 1_000),
        json!(NOW + 1_000_000),
        Some(vct),
        "dc+sd-jwt",
    )
}

/// Mint an SD-JWT VC carrying a **clear** subject claim alongside a **selectively-disclosable** one:
/// `given_name = "Ada"` is left in the issuer-signed CLEAR payload (NOT made concealable) while
/// `family_name = "Lovelace"` is concealable. Used by the DCQL clear-claim regression: a query for the
/// clear `given_name` must resolve against the FULL presented claim set (clear + disclosed), exactly as
/// one for the disclosed `family_name` does (OpenID4VP 1.0 §8.6 step 2.2 / §6.4). Everything else
/// (trusted issuer signature + window + `cnf` holder binding) is sound, so it clears the always-on bar.
pub(crate) fn mint_sd_jwt_with_clear_subject_claim(
    issuer_pk8: &[u8],
    issuer_cert_der: &[u8],
) -> SdJwt {
    let cert_b64 = base64ct::Base64::encode_string(issuer_cert_der);
    let claims = json!({
        "iss": "https://issuer.example/cb",
        "vct": DEFAULT_VCT,
        "given_name": "Ada",       // CLEAR — never made concealable, so it stays in the issuer payload.
        "family_name": "Lovelace", // selectively disclosable (concealable below).
        "nbf": NOW - 1_000,
        "exp": NOW + 1_000_000,
    });
    let signer = Es256Signer::from_pkcs8(issuer_pk8);
    block_on(
        SdJwtBuilder::new_with_hasher(claims, Sha2Hasher)
            .unwrap()
            .header("x5c", json!([cert_b64]))
            .header("typ", json!("dc+sd-jwt"))
            .make_concealable("/family_name")
            .unwrap()
            .require_key_binding(holder_cnf())
            .finish(&signer, "ES256"),
    )
    .expect("issuer signing succeeds")
}

/// Mint an SD-JWT VC OMITTING the REQUIRED `vct` type claim — the missing-`vct` probe for the always-on
/// bar's [`super::check_vct`] (everything else, incl. the trusted issuer signature + window, is sound).
pub(crate) fn mint_sd_jwt_without_vct(issuer_pk8: &[u8], issuer_cert_der: &[u8]) -> SdJwt {
    mint_with(
        issuer_pk8,
        issuer_cert_der,
        json!(NOW - 1_000),
        json!(NOW + 1_000_000),
        None,
        "dc+sd-jwt",
    )
}

/// Shared minting core (DRY — one body for every happy-path variant): `iss` + optional `vct` +
/// `given_name`/`family_name`/`birthdate` (all concealable) + optional `nbf`/`exp` + a `cnf` holder
/// binding, signed by `issuer_pk8` with the issuer JWS protected-header `typ`.
fn mint_with(
    issuer_pk8: &[u8],
    issuer_cert_der: &[u8],
    nbf: Value,
    exp: Value,
    vct: Option<&str>,
    typ: &str,
) -> SdJwt {
    let cert_b64 = base64ct::Base64::encode_string(issuer_cert_der);
    let mut claims = json!({
        "iss": "https://issuer.example/cb",
        "given_name": "Ada",
        "family_name": "Lovelace",
        "birthdate": "1815-12-10",
    });
    let object = claims.as_object_mut().expect("claims is a JSON object");
    if let Some(vct) = vct {
        object.insert("vct".to_owned(), json!(vct));
    }
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
            // SD-JWT VC §3.2.1: the issuer JWS `typ` identifies the SD-JWT VC media type.
            .header("typ", json!(typ))
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
    let header = json!({ "alg": "ES256", "typ": "dc+sd-jwt", "x5c": [cert_b64] });
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

/// Mint an SD-JWT VC whose payload carries two **distinct nested claims that share a leaf name**:
/// `address.locality` and `place_of_birth.locality`, with different values, each made concealable at
/// its own JSON-pointer path. This is the legitimate EUDI PID shape (nested `address`/`place_of_birth`
/// objects) that a crate-wide leaf-keyed collision guard false-rejects: the leaf `locality` appears
/// under two different parents (RFC 9901 §7.1 scopes claim-name uniqueness to the level of the `_sd`
/// key, not the leaf name). Both `locality` disclosures are issuer-signed and have distinct digests.
pub(crate) fn mint_nested_shared_leaf(issuer_pk8: &[u8], issuer_cert_der: &[u8]) -> SdJwt {
    let cert_b64 = base64ct::Base64::encode_string(issuer_cert_der);
    let claims = json!({
        "iss": "https://issuer.example/cb",
        "vct": "https://credentials.example/identity_credential",
        "nbf": NOW - 1_000,
        "exp": NOW + 1_000_000,
        "address": { "locality": "London" },
        "place_of_birth": { "locality": "Paris" },
    });
    let signer = Es256Signer::from_pkcs8(issuer_pk8);
    block_on(
        SdJwtBuilder::new_with_hasher(claims, Sha2Hasher)
            .unwrap()
            .header("x5c", json!([cert_b64]))
            .header("typ", json!("dc+sd-jwt"))
            .make_concealable("/address/locality")
            .unwrap()
            .make_concealable("/place_of_birth/locality")
            .unwrap()
            .require_key_binding(holder_cnf())
            .finish(&signer, "ES256"),
    )
    .expect("issuer signing succeeds")
}

/// Mint an SD-JWT VC where a whole object claim is concealable AND so is a claim nested inside it:
/// `/address` and `/address/locality` are both made concealable. Disclosing both means the `address`
/// disclosure's *value* is itself an object carrying its own `_sd` for `locality` — exercising the
/// nested-value reconstruction (a disclosed claim whose value contains further disclosures).
pub(crate) fn mint_concealable_object_with_concealable_child(
    issuer_pk8: &[u8],
    issuer_cert_der: &[u8],
) -> SdJwt {
    let cert_b64 = base64ct::Base64::encode_string(issuer_cert_der);
    let claims = json!({
        "iss": "https://issuer.example/cb",
        "vct": "https://credentials.example/identity_credential",
        "nbf": NOW - 1_000,
        "exp": NOW + 1_000_000,
        "address": { "locality": "London", "country": "UK" },
    });
    let signer = Es256Signer::from_pkcs8(issuer_pk8);
    block_on(
        SdJwtBuilder::new_with_hasher(claims, Sha2Hasher)
            .unwrap()
            .header("x5c", json!([cert_b64]))
            .header("typ", json!("dc+sd-jwt"))
            // Make the nested claim concealable first, then the whole object: disclosing both yields a
            // disclosed `address` value that still carries an `_sd` for `locality`.
            .make_concealable("/address/locality")
            .unwrap()
            .make_concealable("/address")
            .unwrap()
            .require_key_binding(holder_cnf())
            .finish(&signer, "ES256"),
    )
    .expect("issuer signing succeeds")
}

/// Sign an arbitrary issuer JWS payload with the test issuer key, returning the compact JWS string
/// (`header.payload.signature`). The header is `alg=ES256` + the issuer `x5c`. Used to craft hand-built
/// SD-JWT structures (repeated digests, mis-typed disclosures) for the verifier's reject-branch tests;
/// the structure is what is under test, not the signature, so callers parse — not cryptographically
/// verify — the result via `collect_disclosed_attributes`.
pub(crate) fn sign_issuer_jws(
    issuer_pk8: &[u8],
    issuer_cert_der: &[u8],
    payload: &Value,
) -> String {
    let cert_b64 = base64ct::Base64::encode_string(issuer_cert_der);
    let header = json!({ "alg": "ES256", "typ": "dc+sd-jwt", "x5c": [cert_b64] });
    let header_b64 =
        Base64UrlUnpadded::encode_string(serde_json::to_vec(&header).unwrap().as_slice());
    let payload_b64 =
        Base64UrlUnpadded::encode_string(serde_json::to_vec(payload).unwrap().as_slice());
    let signing_input = format!("{header_b64}.{payload_b64}");
    let key = p256::ecdsa::SigningKey::from_pkcs8_der(issuer_pk8).expect("valid PKCS#8 P-256 key");
    let sig: p256::ecdsa::Signature = key.sign(signing_input.as_bytes());
    let sig_b64 = Base64UrlUnpadded::encode_string(sig.to_bytes().as_slice());
    format!("{signing_input}.{sig_b64}")
}

/// Base64url-encode an object-property disclosure `[salt, name, value]`.
pub(crate) fn object_disclosure(salt: &str, name: &str, value: Value) -> String {
    Base64UrlUnpadded::encode_string(json!([salt, name, value]).to_string().as_bytes())
}

/// Base64url-encode an array-element disclosure `[salt, value]`.
pub(crate) fn array_disclosure(salt: &str, value: Value) -> String {
    Base64UrlUnpadded::encode_string(json!([salt, value]).to_string().as_bytes())
}

/// The `sha-256` digest (base64url) of a disclosure string — its `_sd` / `{"...":}` reference.
pub(crate) fn disclosure_digest(disclosure: &str) -> String {
    Base64UrlUnpadded::encode_string(&Sha2Hasher.digest(disclosure.as_bytes()))
}

/// Mint an SD-JWT VC carrying a `nationalities` array whose **elements** are selectively disclosable
/// (RFC 9901 array-element redaction `{"...": "<digest>"}`), plus a concealable scalar `given_name`.
/// Exercises the array-element reconstruction path: a disclosed element is surfaced by value, an
/// undisclosed element is dropped from the disclosed array.
pub(crate) fn mint_array_element_disclosures(issuer_pk8: &[u8], issuer_cert_der: &[u8]) -> SdJwt {
    let cert_b64 = base64ct::Base64::encode_string(issuer_cert_der);
    let claims = json!({
        "iss": "https://issuer.example/cb",
        "vct": "https://credentials.example/identity_credential",
        "nbf": NOW - 1_000,
        "exp": NOW + 1_000_000,
        "nationalities": ["DE", "FR"],
    });
    let signer = Es256Signer::from_pkcs8(issuer_pk8);
    block_on(
        SdJwtBuilder::new_with_hasher(claims, Sha2Hasher)
            .unwrap()
            .header("x5c", json!([cert_b64]))
            .header("typ", json!("dc+sd-jwt"))
            .make_concealable("/nationalities/0")
            .unwrap()
            .make_concealable("/nationalities/1")
            .unwrap()
            .require_key_binding(holder_cnf())
            .finish(&signer, "ES256"),
    )
    .expect("issuer signing succeeds")
}

/// Attach a holder KB-JWT (signed by `holder_pk8`) over the given `aud`/`nonce` to a minted SD-JWT,
/// returning the full compact presentation string. The KB-JWT `iat` is the canonical [`NOW`].
pub(crate) fn attach_kb_jwt(sd_jwt: SdJwt, holder_pk8: &[u8], aud: &str, nonce: &str) -> String {
    attach_kb_jwt_with_iat(sd_jwt, holder_pk8, aud, nonce, NOW)
}

/// Like [`attach_kb_jwt`] but stamps a caller-chosen KB-JWT `iat` — the freshness-window probe for the
/// verifier's RFC 9901 §7.3 step 5.e `iat` check (a KB-JWT minted far from the verification time).
pub(crate) fn attach_kb_jwt_with_iat(
    mut sd_jwt: SdJwt,
    holder_pk8: &[u8],
    aud: &str,
    nonce: &str,
    iat: i64,
) -> String {
    let holder = Es256Signer::from_pkcs8(holder_pk8);
    let kb = block_on(
        KeyBindingJwt::builder()
            .iat(iat)
            .aud(aud)
            .nonce(nonce)
            .finish(&sd_jwt, &Sha2Hasher, "ES256", &holder),
    )
    .expect("KB-JWT signing succeeds");
    sd_jwt.attach_key_binding_jwt(kb);
    sd_jwt.presentation()
}
