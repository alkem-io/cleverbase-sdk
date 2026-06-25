//! SD-JWT VC (RFC 9901 / draft-ietf-oauth-sd-jwt-vc-16) verification.
//!
//! Verifies a presented SD-JWT VC against the always-on bar (contracts/verifier.md): the
//! issuer-signed compact JWS, issuer trust (via the pluggable [`crate::trust::TrustAnchorSource`]),
//! the `nbf`/`exp` validity window, the holder Key-Binding JWT (`aud`/`nonce`/`sd_hash`), and
//! selective-disclosure integrity (each disclosed claim must match an issuer-signed digest). A
//! failed check yields `valid = false` with a specific [`ReasonCode`] — never a false-accept
//! (SC-002).
//!
//! ## Layering (research D2/D1)
//!
//! - The **format layer** (issuer-JWS framing, disclosures, the optional KB-JWT) is parsed with
//!   [`sd_jwt_payload`].
//! - The **crypto** is the SDK's own RustCrypto stack: the issuer ES256 JWS and the holder ES256
//!   KB-JWT are both verified **in-house** over `p256`/`ecdsa`/`sha2` (the SDK has no JOSE crate, and
//!   `sd-jwt-payload` parses the KB-JWT but does **not** verify its signature — so the holder-binding
//!   signature check is built here). No new JOSE dependency, no hand-rolled crypto (Principle IV).
//! - **Selective-disclosure digests** are recomputed with `sha2` (the `_sd_alg`, `sha-256`) and
//!   matched against the issuer-signed `_sd` arrays.
//!
//! ## Status seam (T014)
//!
//! The revocation/status check is owned by [`crate::status`]; this module takes its canonical
//! [`StatusOutcome`] (re-exported here as [`StatusInput`]) so the always-on bar is honoured without
//! re-implementing the status fetch here — the single authoritative status type (DRY). The
//! always-on [`crate::verify`] entry point resolves the credential's status reference through the
//! host [`crate::status::StatusSource`] seam and passes the outcome in.

use std::collections::BTreeMap;

use base64ct::{Base64UrlUnpadded, Encoding as _};
use p256::ecdsa::signature::Verifier as _;
use serde_json::Value;
use x509_cert::spki::DecodePublicKey as _;

use crate::trust::TrustAnchorSource;
use crate::types::{
    AttributeValue, IssuerRole, ReasonCode, TrustStatus, Validity, VerificationResult,
};

/// The JOSE `alg` the EUDI baseline mandates for SD-JWT VC issuer and KB-JWT signatures (ES256 =
/// ECDSA / P-256 / SHA-256 — HAIP 1.0 §7; research D1). Any other `alg` is rejected as unsupported.
const ES256: &str = "ES256";

/// The SD-JWT `_sd_alg` digest algorithm this verifier supports (IANA "Named Information Hash
/// Algorithm" registry name). Per RFC 9901 the default when `_sd_alg` is absent is `sha-256`.
const SHA_256: &str = "sha-256";

/// The revocation/status input to the verifier — the canonical [`crate::status::StatusOutcome`]
/// (one authoritative status type, DRY). The [`crate::verify`] entry point resolves the credential's
/// status reference through the host status seam and passes the outcome in; this module maps it onto
/// the always-on bar (revoked → `Revoked`, unreachable-under-fail-closed → `StatusUnavailable`).
pub use crate::status::StatusOutcome as StatusInput;

/// The verifier inputs for an SD-JWT VC presentation (the per-format slice of the always-on
/// `verify` entry point that task T016 assembles).
///
/// Sans-IO: every input — the presentation, the trust anchors, the holder-binding challenge, and the
/// status outcome — is passed in; this performs no network I/O.
#[derive(Debug, Clone, Copy)]
pub struct SdJwtVcInput<'a, A: TrustAnchorSource + ?Sized> {
    /// The compact SD-JWT VC presentation: `<issuer-JWS>~<D.1>~…~<D.N>~<optional KB-JWT>`.
    pub presentation: &'a str,
    /// The configured trust anchors; the issuer's signing certificate is resolved against these.
    pub anchors: &'a A,
    /// The issuer role under which to anchor trust (selects the trust list — research D5).
    pub role: IssuerRole,
    /// The holder-binding challenge the KB-JWT must echo (`aud` = verifier `client_id`, `nonce`),
    /// or `None` to accept a presentation without holder binding (e.g. an issuer-only credential).
    pub key_binding: Option<KeyBindingChallenge<'a>>,
    /// The current time (Unix seconds) the `nbf`/`exp` window is checked against.
    pub now_unix: i64,
    /// The revocation/status outcome (the T014 seam).
    pub status: StatusInput,
}

/// The holder-binding challenge a presented KB-JWT must satisfy (RFC 9901 §4.3).
#[derive(Debug, Clone, Copy)]
pub struct KeyBindingChallenge<'a> {
    /// The expected `aud` — the verifier's `client_id`.
    pub audience: &'a str,
    /// The expected fresh `nonce`.
    pub nonce: &'a str,
}

/// Verify a presented SD-JWT VC against the always-on bar, returning a [`VerificationResult`].
///
/// On any failed check the result has `valid = false` and carries the single specific
/// [`ReasonCode`] for the **first** check that failed; only a credential that clears every check is
/// `valid = true`, with the disclosed (and only the disclosed) attributes returned.
#[must_use]
pub fn verify_sd_jwt_vc<A: TrustAnchorSource + ?Sized>(
    input: &SdJwtVcInput<'_, A>,
) -> VerificationResult {
    match verify_inner(input) {
        Ok(ok) => ok,
        Err(reason) => VerificationResult::invalid(reason),
    }
}

/// Extract the `aud` and `nonce` a presented SD-JWT VC's KB-JWT echoes, without verifying anything
/// (the [`crate::openid4vp`] layer uses this to attribute a request-binding failure to the specific
/// [`ReasonCode::Replay`] / [`ReasonCode::WrongAudience`] before delegating to the full bar).
///
/// Returns `None` when the presentation does not parse or carries no KB-JWT. The values are *claimed*
/// (their cryptographic verification is the always-on holder-binding check in [`verify_sd_jwt_vc`]);
/// this read is only for failure attribution, never for acceptance.
#[must_use]
pub fn kb_jwt_aud_nonce(presentation: &str) -> Option<(String, String)> {
    let sd_jwt = sd_jwt_payload::SdJwt::parse(presentation).ok()?;
    let kb = sd_jwt.key_binding_jwt()?;
    let claims = kb.claims();
    Some((claims.aud.clone(), claims.nonce.clone()))
}

/// Extract the issuer signing certificate (DER) a presented SD-JWT VC claims in its JWS `x5c` header,
/// without verifying anything (the opt-in [`crate::qualified`] gate matches this leaf against the
/// national Trusted List's `EAA/Q` service entries).
///
/// Returns `None` when the presentation does not parse or carries no `x5c` leaf. The value is
/// *claimed* (its trust + signature are decided by the always-on bar in [`verify_sd_jwt_vc`]); this
/// read is only the gate's cert-matching input, never an acceptance.
#[must_use]
pub fn issuer_signing_cert_der(presentation: &str) -> Option<Vec<u8>> {
    let sd_jwt = sd_jwt_payload::SdJwt::parse(presentation).ok()?;
    let jws = sd_jwt.presentation();
    let header_b64 = jws.split('~').next()?.split('.').next()?;
    let header_json = Base64UrlUnpadded::decode_vec(header_b64).ok()?;
    let header: Value = serde_json::from_slice(&header_json).ok()?;
    issuer_cert_from_header(&header).ok()
}

/// The verified, accepted view of a presentation, assembled once every always-on check has passed.
fn accept(disclosed: BTreeMap<String, AttributeValue>) -> VerificationResult {
    VerificationResult {
        valid: true,
        disclosed_attributes: disclosed,
        trust_status: TrustStatus::Trusted,
        qualified_status: None,
        reasons: Vec::new(),
    }
}

/// The fallible body of the verifier; each `?` short-circuits to the specific reject reason.
fn verify_inner<A: TrustAnchorSource + ?Sized>(
    input: &SdJwtVcInput<'_, A>,
) -> Result<VerificationResult, ReasonCode> {
    // 1. Format / parse. A structurally invalid presentation is malformed; we never guess.
    let sd_jwt = sd_jwt_payload::SdJwt::parse(input.presentation)
        .map_err(|_| ReasonCode::MalformedCredential)?;

    // 2. Issuer signature (in-house ES256 over the compact JWS) + the signing certificate.
    let issuer_cert_der = verify_issuer_signature(&sd_jwt)?;

    // 3. Issuer trust — the signing cert must be on the configured anchor for its role/format.
    if !input
        .anchors
        .resolve(input.role, crate::types::Format::SdJwtVc, &issuer_cert_der)
        .trusted
    {
        return Err(ReasonCode::UntrustedIssuer);
    }

    // 4. Validity window (`nbf`/`exp`).
    check_validity(sd_jwt.claims(), input.now_unix)?;

    // 5. Revocation / status (the T014 seam).
    match input.status {
        StatusInput::NoStatus | StatusInput::Good => {}
        StatusInput::Revoked => return Err(ReasonCode::Revoked),
        StatusInput::Unavailable => return Err(ReasonCode::StatusUnavailable),
    }

    // 6. Holder binding (KB-JWT over `aud`/`nonce`/`sd_hash`, verified against the `cnf` key).
    check_holder_binding(&sd_jwt, input.presentation, input.key_binding.as_ref())?;

    // 7. Selective-disclosure integrity — every disclosed claim matches an issuer-signed digest, and
    //    the disclosed claim set is what we return (undisclosed attributes are never revealed).
    let disclosed = collect_disclosed_attributes(&sd_jwt)?;

    Ok(accept(disclosed))
}

/// Verify the issuer compact-JWS signature in-house and return the DER of the signing certificate.
///
/// Framing: `header.payload.signature` (each base64url). The header MUST be `alg=ES256` and carry an
/// `x5c` whose leaf is the signing certificate; the ES256 signature (raw `r||s`) is verified over the
/// ASCII `header.payload` signing input with the certificate's P-256 public key. The cert DER is
/// returned for the trust-anchor resolution step (it is the credential's own claimed signer; trust is
/// decided separately in step 3 — a self-signed cert verifies its own signature but is rejected as
/// untrusted unless it is on the configured anchor).
fn verify_issuer_signature(sd_jwt: &sd_jwt_payload::SdJwt) -> Result<Vec<u8>, ReasonCode> {
    // The issuer JWS is the first `~`-separated segment of the re-serialized presentation.
    let presentation = sd_jwt.presentation();
    let jws = presentation
        .split('~')
        .next()
        .ok_or(ReasonCode::MalformedCredential)?;
    let mut parts = jws.split('.');
    let header_b64 = parts.next().ok_or(ReasonCode::MalformedCredential)?;
    let payload_b64 = parts.next().ok_or(ReasonCode::MalformedCredential)?;
    let sig_b64 = parts.next().ok_or(ReasonCode::MalformedCredential)?;
    if parts.next().is_some() {
        return Err(ReasonCode::MalformedCredential);
    }

    // Header: require alg=ES256 and read the x5c leaf certificate.
    let header_json =
        Base64UrlUnpadded::decode_vec(header_b64).map_err(|_| ReasonCode::MalformedCredential)?;
    let header: Value =
        serde_json::from_slice(&header_json).map_err(|_| ReasonCode::MalformedCredential)?;
    if header.get("alg").and_then(Value::as_str) != Some(ES256) {
        return Err(ReasonCode::UnsupportedFormat);
    }
    let cert_der = issuer_cert_from_header(&header)?;

    // Signing input is the ASCII bytes of `header.payload`; the signature is raw r||s (ES256).
    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig_bytes =
        Base64UrlUnpadded::decode_vec(sig_b64).map_err(|_| ReasonCode::MalformedCredential)?;
    let signature =
        p256::ecdsa::Signature::from_slice(&sig_bytes).map_err(|_| ReasonCode::Tamper)?;

    let verifying_key = verifying_key_from_cert_der(&cert_der)?;
    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| ReasonCode::Tamper)?;

    Ok(cert_der)
}

/// Extract the leaf signing certificate (DER) from a JWS header's `x5c` (RFC 7515 §4.1.6): a JSON
/// array of base64 (standard, **not** url) DER certificates, leaf first.
fn issuer_cert_from_header(header: &Value) -> Result<Vec<u8>, ReasonCode> {
    let leaf_b64 = header
        .get("x5c")
        .and_then(Value::as_array)
        .and_then(|chain| chain.first())
        .and_then(Value::as_str)
        .ok_or(ReasonCode::MalformedCredential)?;
    base64ct::Base64::decode_vec(leaf_b64).map_err(|_| ReasonCode::MalformedCredential)
}

/// Parse a DER certificate and extract its P-256 ECDSA verifying key (the SDK's vetted X.509 +
/// `p256` stack — the same path `cleverbase-core` uses for CMS leaf verification).
fn verifying_key_from_cert_der(cert_der: &[u8]) -> Result<p256::ecdsa::VerifyingKey, ReasonCode> {
    use der::{Decode as _, Encode as _};
    let cert =
        x509_cert::Certificate::from_der(cert_der).map_err(|_| ReasonCode::MalformedCredential)?;
    let spki_der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| ReasonCode::MalformedCredential)?;
    p256::ecdsa::VerifyingKey::from_public_key_der(&spki_der).map_err(|_| ReasonCode::Tamper)
}

/// Check the `nbf`/`exp` validity window against `now` (RFC 9901 carries the JWT `nbf`/`exp` claims).
fn check_validity(claims: &sd_jwt_payload::SdJwtClaims, now: i64) -> Result<Validity, ReasonCode> {
    let not_before = claims.get("nbf").and_then(Value::as_i64);
    let not_after = claims.get("exp").and_then(Value::as_i64);
    if let Some(nbf) = not_before {
        if now < nbf {
            return Err(ReasonCode::Expired);
        }
    }
    if let Some(exp) = not_after {
        if now >= exp {
            return Err(ReasonCode::Expired);
        }
    }
    Ok(Validity {
        not_before,
        not_after,
    })
}

/// Verify the holder Key-Binding JWT (RFC 9901 §4.3): the KB-JWT MUST be present when a challenge is
/// required, be `typ=kb+jwt` / `alg=ES256`, echo the expected `aud`/`nonce`, carry the correct
/// `sd_hash` over the issuer-JWS-plus-disclosures prefix, and verify under the issuer-bound `cnf` key.
fn check_holder_binding(
    sd_jwt: &sd_jwt_payload::SdJwt,
    presentation: &str,
    challenge: Option<&KeyBindingChallenge<'_>>,
) -> Result<(), ReasonCode> {
    let Some(challenge) = challenge else {
        // No holder binding required for this presentation.
        return Ok(());
    };
    let kb = sd_jwt.key_binding_jwt().ok_or(ReasonCode::HolderBinding)?;
    let claims = kb.claims();

    // `aud`/`nonce` must match the verifier's challenge.
    let aud_ok = claims.aud == challenge.audience;
    let nonce_ok = claims.nonce == challenge.nonce;
    if !aud_ok || !nonce_ok {
        return Err(ReasonCode::HolderBinding);
    }

    // `sd_hash` MUST be the SHA-256 (base64url) digest of the presentation prefix up to and including
    // the final `~` that precedes the KB-JWT (RFC 9901 §4.3).
    let kb_compact = kb.to_string();
    let prefix = presentation
        .strip_suffix(&kb_compact)
        .ok_or(ReasonCode::HolderBinding)?;
    let expected_sd_hash = Base64UrlUnpadded::encode_string(&sha256(prefix.as_bytes()));
    if claims.sd_hash != expected_sd_hash {
        return Err(ReasonCode::HolderBinding);
    }

    // Verify the KB-JWT ES256 signature under the holder key bound by the issuer in `cnf`.
    let holder_key = holder_key_from_cnf(sd_jwt)?;
    verify_compact_es256(&kb_compact, &holder_key).map_err(|()| ReasonCode::HolderBinding)
}

/// Extract the holder's P-256 verifying key from the issuer-signed `cnf` confirmation (RFC 7800):
/// `cnf` MUST carry a `jwk` with an EC P-256 public key (`crv=P-256`, base64url `x`/`y`).
fn holder_key_from_cnf(
    sd_jwt: &sd_jwt_payload::SdJwt,
) -> Result<p256::ecdsa::VerifyingKey, ReasonCode> {
    let cnf = sd_jwt
        .required_key_bind()
        .ok_or(ReasonCode::HolderBinding)?;
    let sd_jwt_payload::RequiredKeyBinding::Jwk(jwk) = cnf else {
        return Err(ReasonCode::HolderBinding);
    };
    verifying_key_from_p256_jwk(&Value::Object(jwk.clone()))
}

/// Build a P-256 verifying key from a JWK object (`kty=EC`, `crv=P-256`, base64url `x`/`y`).
fn verifying_key_from_p256_jwk(jwk: &Value) -> Result<p256::ecdsa::VerifyingKey, ReasonCode> {
    if jwk.get("kty").and_then(Value::as_str) != Some("EC")
        || jwk.get("crv").and_then(Value::as_str) != Some("P-256")
    {
        return Err(ReasonCode::HolderBinding);
    }
    let x = jwk
        .get("x")
        .and_then(Value::as_str)
        .and_then(|s| Base64UrlUnpadded::decode_vec(s).ok())
        .ok_or(ReasonCode::HolderBinding)?;
    let y = jwk
        .get("y")
        .and_then(Value::as_str)
        .and_then(|s| Base64UrlUnpadded::decode_vec(s).ok())
        .ok_or(ReasonCode::HolderBinding)?;
    if x.len() != 32 || y.len() != 32 {
        return Err(ReasonCode::HolderBinding);
    }
    // Uncompressed SEC1 point: 0x04 || X || Y.
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| ReasonCode::HolderBinding)
}

/// Verify a compact `header.payload.signature` ES256 JWS under `key`. Returns `Err(())` on any
/// framing/decoding/signature failure (the caller maps this to the relevant [`ReasonCode`]).
fn verify_compact_es256(jws: &str, key: &p256::ecdsa::VerifyingKey) -> Result<(), ()> {
    let mut parts = jws.split('.');
    let header_b64 = parts.next().ok_or(())?;
    let payload_b64 = parts.next().ok_or(())?;
    let sig_b64 = parts.next().ok_or(())?;
    if parts.next().is_some() {
        return Err(());
    }
    let sig_bytes = Base64UrlUnpadded::decode_vec(sig_b64).map_err(|_| ())?;
    let signature = p256::ecdsa::Signature::from_slice(&sig_bytes).map_err(|_| ())?;
    let signing_input = format!("{header_b64}.{payload_b64}");
    key.verify(signing_input.as_bytes(), &signature)
        .map_err(|_| ())
}

/// Recompute the SD-JWT disclosure digests with `sha2` and match them against the issuer-signed
/// `_sd` arrays, returning the disclosed attribute map.
///
/// Selective-disclosure integrity (FR-003): the verifier accepts only disclosed claims whose
/// disclosure digest appears in an issuer-signed `_sd` array (top-level or nested). A presented
/// disclosure whose digest is *not* signed is a tampered/forged disclosure → `DisclosureIntegrity`.
fn collect_disclosed_attributes(
    sd_jwt: &sd_jwt_payload::SdJwt,
) -> Result<BTreeMap<String, AttributeValue>, ReasonCode> {
    // The `_sd_alg` MUST be sha-256 (the only registered alg we support); reject otherwise.
    if let Some(alg) = sd_jwt.claims()._sd_alg.as_deref() {
        if alg != SHA_256 {
            return Err(ReasonCode::UnsupportedFormat);
        }
    }

    // Gather every issuer-signed digest from the JWS claims (top-level `_sd` + nested `_sd` arrays +
    // array-element `{"...": digest}` entries). A disclosure whose digest is absent is unsigned.
    let claims_value =
        serde_json::to_value(sd_jwt.claims()).map_err(|_| ReasonCode::MalformedCredential)?;
    let mut signed_digests = std::collections::BTreeSet::new();
    collect_signed_digests(&claims_value, &mut signed_digests);

    let mut disclosed = BTreeMap::new();
    for disclosure in sd_jwt.disclosures() {
        let digest = Base64UrlUnpadded::encode_string(&sha256(disclosure.as_str().as_bytes()));
        if !signed_digests.contains(&digest) {
            return Err(ReasonCode::DisclosureIntegrity);
        }
        // Object-property disclosures carry a claim name; array-element disclosures do not — the
        // latter are sub-values of a named claim and are surfaced via that claim's value, so only
        // named top-level/object disclosures become returned attributes here.
        if let Some(name) = disclosure.claim_name.as_deref() {
            disclosed.insert(name.to_string(), json_to_attribute(&disclosure.claim_value));
        }
    }
    Ok(disclosed)
}

/// Walk a JSON value collecting every SD digest: object `_sd` arrays (strings) and array-element
/// `{ "...": "<digest>" }` redactions, recursing into nested objects/arrays.
fn collect_signed_digests(value: &Value, out: &mut std::collections::BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            if let Some(Value::Array(sd)) = map.get("_sd") {
                for d in sd.iter().filter_map(Value::as_str) {
                    out.insert(d.to_string());
                }
            }
            for v in map.values() {
                collect_signed_digests(v, out);
            }
        }
        Value::Array(items) => {
            for item in items {
                if let Value::Object(map) = item {
                    if let Some(Value::String(d)) = map.get("...") {
                        out.insert(d.clone());
                    }
                }
                collect_signed_digests(item, out);
            }
        }
        _ => {}
    }
}

/// SHA-256 of `input` (the SDK's own `sha2`, not a second crypto stack — research D1).
fn sha256(input: &[u8]) -> [u8; 32] {
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    hasher.update(input);
    hasher.finalize().into()
}

/// Map a disclosed `serde_json::Value` claim into the SDK's closed [`AttributeValue`] (the CBOR wire
/// type). Numbers that are not integers are surfaced as text (the EUDI claim set is integer/string/
/// boolean-shaped; a non-integer number is preserved losslessly as its JSON text rather than coerced
/// to a lossy float).
fn json_to_attribute(value: &Value) -> AttributeValue {
    match value {
        Value::Null => AttributeValue::Null,
        Value::Bool(b) => AttributeValue::Boolean(*b),
        Value::Number(n) => n.as_i64().map_or_else(
            || AttributeValue::Text(n.to_string()),
            AttributeValue::Integer,
        ),
        Value::String(s) => AttributeValue::Text(s.clone()),
        Value::Array(items) => AttributeValue::Array(items.iter().map(json_to_attribute).collect()),
        Value::Object(map) => AttributeValue::Map(
            map.iter()
                .map(|(k, v)| (k.clone(), json_to_attribute(v)))
                .collect(),
        ),
    }
}

#[cfg(any(test, feature = "test-vectors"))]
pub(crate) mod test_issuer;
#[cfg(test)]
mod tests;
