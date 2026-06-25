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
//! [`crate::status::StatusOutcome`] (re-exported here as [`StatusInput`]) so the always-on bar is
//! honoured without re-implementing the status fetch here — the single authoritative status type
//! (DRY). The always-on [`verify()`](crate::verify()) entry point resolves the credential's status
//! reference through the host [`crate::status::StatusSource`] seam and passes the outcome in.

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

use crate::crypto::{sha256, SHA_256};

/// The revocation/status input to the verifier — the canonical [`crate::status::StatusOutcome`]
/// (one authoritative status type, DRY). The [`verify()`](crate::verify()) entry point resolves the credential's
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

/// The issuance/relevant time (Unix seconds) a presented SD-JWT VC asserts: the JWT `iat` (RFC 7519
/// §4.1.6 — "the time at which the JWT was issued", the credential's issuance instant), falling back
/// to `nbf` when `iat` is absent (the not-before bound is the earliest instant the issuer asserts the
/// credential is in force, the closest available proxy for the relevant time).
///
/// Returns `None` when the presentation does not parse or carries **neither** `iat` nor `nbf` — the
/// opt-in [`crate::qualified`] gate then fails closed ([`crate::types::QualifiedStatus::Indeterminate`])
/// rather than read the issuer's status at the verification instant ("now"), which would falsely report
/// `Qualified` for an issuer granted only AFTER it signed the credential (contracts/qualified-status-
/// gate.md: the status is read **at the credential's issuance/relevant time, NOT "now"**). A present-
/// but-non-canonical `iat`/`nbf` (RFC 7519 NumericDate must be a JSON number that fits `i64`) is
/// likewise treated as absent — the gate must not assert qualification off an unreadable instant.
#[must_use]
pub fn issuance_time_unix(presentation: &str) -> Option<i64> {
    let sd_jwt = sd_jwt_payload::SdJwt::parse(presentation).ok()?;
    let claims = sd_jwt.claims();
    // `iat` is the credential's issuance time; `nbf` (not-before) is the fallback relevant time. Only
    // a canonical NumericDate (a JSON integer that fits `i64`) is accepted; anything else → `None`.
    numeric_date(claims.get("iat"))
        .ok()
        .flatten()
        .or_else(|| numeric_date(claims.get("nbf")).ok().flatten())
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
///
/// `nbf`/`exp` are JWT `NumericDate`s (RFC 7519 §2): a JSON number of seconds since the epoch. A
/// **present** bound MUST be a NumericDate this verifier can evaluate; a present-but-unparseable bound
/// (a JSON string `"200"`, a non-integer float `200.5`, or a magnitude outside `i64`) is NOT silently
/// ignored — that would let an expired credential with a non-canonical `exp` be accepted as having
/// unbounded validity (a false-accept). Instead it rejects: a malformed bound is `MalformedCredential`
/// (we cannot trust a window we cannot read).
///
/// A bound that is **absent** is permitted (RFC 9901 / SD-JWT VC make `exp`/`nbf` optional). This is
/// an intentional, documented policy: a credential with no `exp` carries no upper temporal bound here.
/// A relying party that requires an upper bound MUST reject a no-`exp` credential at the
/// [`crate::status`] / policy layer (the seam where reachability/qualified policy already lives); the
/// always-on bar does not fabricate a bound the issuer did not assert.
fn check_validity(claims: &sd_jwt_payload::SdJwtClaims, now: i64) -> Result<Validity, ReasonCode> {
    let not_before = numeric_date(claims.get("nbf"))?;
    let not_after = numeric_date(claims.get("exp"))?;
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

/// Read an optional JWT `NumericDate` claim (`nbf`/`exp`), distinguishing **absent** from
/// **present-but-malformed**.
///
/// - `None` (claim absent) → `Ok(None)`: the bound is optional and simply not asserted.
/// - A JSON integer that fits `i64` → `Ok(Some(_))`: the canonical NumericDate.
/// - A claim that is **present** but is not an `i64`-representable integer (a JSON string, a
///   non-integer float, `null`, or a number outside `i64`) → `Err(MalformedCredential)`: the window
///   is uninterpretable and MUST NOT be skipped (skipping is a false-accept — an expired credential
///   with a non-canonical `exp` would read as unbounded). RFC 7519 §2 defines NumericDate as a JSON
///   number; we reject anything we cannot evaluate against `now` rather than ignore it.
fn numeric_date(claim: Option<&Value>) -> Result<Option<i64>, ReasonCode> {
    claim.map_or(Ok(None), |value| {
        value
            .as_i64()
            .map(Some)
            .ok_or(ReasonCode::MalformedCredential)
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

/// Build a P-256 verifying key from a JWK object (`kty=EC`, `crv=P-256`, base64url `x`/`y`),
/// mapping any deviation to [`ReasonCode::HolderBinding`]. The decode + on-curve check is the shared
/// [`crate::crypto::p256_verifying_key_from_jwk`] (DRY); only the module-specific reason mapping lives
/// here.
fn verifying_key_from_p256_jwk(jwk: &Value) -> Result<p256::ecdsa::VerifyingKey, ReasonCode> {
    crate::crypto::p256_verifying_key_from_jwk(jwk).ok_or(ReasonCode::HolderBinding)
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

/// Recompute the SD-JWT disclosure digests with `sha2`, match them against the issuer-signed `_sd`
/// arrays, and reconstruct the **disclosed** claims preserving their nesting (RFC 9901 §7.1).
///
/// Selective-disclosure integrity (FR-003): the verifier accepts only disclosed claims whose
/// disclosure digest appears in an issuer-signed `_sd` array (top-level or nested). A presented
/// disclosure whose digest is *not* signed is a tampered/forged disclosure → `DisclosureIntegrity`.
///
/// The disclosed claims are returned at their **actual positions in the credential structure**, not
/// flattened onto their leaf name: per RFC 9901 §7.1 a disclosed object property is inserted at the
/// level of the `_sd` key that referenced it. So `address.locality` and `place_of_birth.locality` are
/// two *distinct* nested values — `{"address": {"locality": …}, "place_of_birth": {"locality": …}}` —
/// not a single collapsed `locality` (which both silently lost data *and*, when the leaf-keyed
/// collision guard was added, false-rejected the legitimate EUDI PID shape as `DisclosureIntegrity`).
/// Only the disclosed (selectively-disclosable) claims are surfaced; the always-visible registered
/// claims (`iss`/`vct`/`nbf`/`exp`/…) are not "disclosed attributes" and are not returned here.
fn collect_disclosed_attributes(
    sd_jwt: &sd_jwt_payload::SdJwt,
) -> Result<BTreeMap<String, AttributeValue>, ReasonCode> {
    // The `_sd_alg` MUST be sha-256 (the only registered alg we support); reject otherwise.
    if let Some(alg) = sd_jwt.claims()._sd_alg.as_deref() {
        if alg != SHA_256 {
            return Err(ReasonCode::UnsupportedFormat);
        }
    }

    // Index every presented disclosure by its digest. Two presented disclosures hashing to the same
    // digest are the same disclosure repeated — that digest is then "encountered more than once" and
    // RFC 9901 §7.1 step 4 invalidates the SD-JWT, so a repeated presented digest is rejected here
    // (the in-structure repeat — the same digest in two `_sd` arrays — is caught during the walk).
    // A disclosure whose digest is not referenced by any issuer-signed `_sd`/array-element entry is
    // never substituted below, so it is rejected as forged by the unused-disclosure check after the
    // walk (membership / `DisclosureIntegrity`).
    let mut disclosures_by_digest = BTreeMap::new();
    for disclosure in sd_jwt.disclosures() {
        let digest = Base64UrlUnpadded::encode_string(&sha256(disclosure.as_str().as_bytes()));
        if disclosures_by_digest.insert(digest, disclosure).is_some() {
            return Err(ReasonCode::DisclosureIntegrity);
        }
    }

    // Reconstruct the disclosed subtree by substituting digests at their position in the issuer-signed
    // structure (RFC 9901 §7.1): per-object claim-name uniqueness and the global "digest seen more than
    // once" rule are enforced as we walk. `used_digests` records every digest we substitute, so a
    // presented-but-unreferenced (forged) disclosure can be detected after the walk.
    let claims_value =
        serde_json::to_value(sd_jwt.claims()).map_err(|_| ReasonCode::MalformedCredential)?;
    // `SdJwtClaims` always serializes to a JSON object; a non-object is a serializer contract break.
    let claims_object = claims_value
        .as_object()
        .ok_or(ReasonCode::MalformedCredential)?;
    let mut used_digests = std::collections::BTreeSet::new();
    let disclosed = disclosed_object(claims_object, &disclosures_by_digest, &mut used_digests)?;

    // Membership (FR-003): every presented disclosure's digest MUST appear in the issuer-signed
    // structure. Any digest we never substituted is a disclosure the issuer did not sign — forged.
    if used_digests.len() != disclosures_by_digest.len() {
        return Err(ReasonCode::DisclosureIntegrity);
    }
    Ok(disclosed)
}

/// Reconstruct the **disclosed** claims of one object level (RFC 9901 §7.1), preserving nesting.
///
/// For each digest in this object's `_sd` array that has a matching presented disclosure, insert the
/// disclosed object property *at this level* (the level of the `_sd` key — the spec's nesting rule),
/// recursing into the disclosed value so nested disclosures are reconstructed too. Clear (always-
/// present) object/array properties are recursed into so a disclosed claim nested under a non-
/// concealable parent (e.g. `address.locality`) is surfaced under that parent — a property is included
/// only when it (recursively) yields at least one disclosed claim.
///
/// Two RFC 9901 §7.1 invariants are enforced here:
/// - **Claim-name uniqueness at the level of the `_sd` key** (per-object, *not* a crate-wide leaf
///   name): a claim name already populated at this level by another disclosure → reject. This is the
///   real reorder attack — two issuer-signed disclosures for the same claim at the same level let a
///   malicious holder pick which value the relying party sees by reordering the segments.
/// - **A digest encountered more than once** (`used_digests`) anywhere in the structure → reject.
///
/// Both reject as [`ReasonCode::DisclosureIntegrity`].
fn disclosed_object(
    object: &serde_json::Map<String, Value>,
    disclosures_by_digest: &BTreeMap<String, &sd_jwt_payload::Disclosure>,
    used_digests: &mut std::collections::BTreeSet<String>,
) -> Result<BTreeMap<String, AttributeValue>, ReasonCode> {
    // Disclosable object properties: substitute this object's `_sd` entries (DRY with the full-value
    // reconstruction; this is the shared per-object `_sd`/uniqueness/repeated-digest logic).
    let mut disclosed = substitute_sd_array(object, disclosures_by_digest, used_digests)?;

    // Clear properties may nest disclosable claims (e.g. a non-concealable `address` carrying a
    // concealable `locality`); recurse and keep the property only when it yields disclosed claims. A
    // clear *scalar* holds no disclosure, so it is NOT surfaced here — only the credential's disclosed
    // claims are returned at top level (the always-visible registered claims are not disclosures).
    for (key, child) in object {
        if is_sd_reserved_key(key) {
            continue;
        }
        if let Some(nested) = disclosed_subtree(child, disclosures_by_digest, used_digests)? {
            insert_unique_at_level(&mut disclosed, key, nested)?;
        }
    }

    Ok(disclosed)
}

/// Substitute the `_sd` array of one object: each digest with a matching *presented* disclosure
/// becomes that disclosed object property, inserted at this level (RFC 9901 §7.1). A withheld digest
/// (no presented disclosure) is skipped; a repeated digest or a same-level claim-name collision is
/// rejected. Shared by the disclosed-only top-level walk and the full disclosed-value reconstruction.
fn substitute_sd_array(
    object: &serde_json::Map<String, Value>,
    disclosures_by_digest: &BTreeMap<String, &sd_jwt_payload::Disclosure>,
    used_digests: &mut std::collections::BTreeSet<String>,
) -> Result<BTreeMap<String, AttributeValue>, ReasonCode> {
    let mut out = BTreeMap::new();
    let Some(Value::Array(sd)) = object.get("_sd") else {
        return Ok(out);
    };
    for digest in sd.iter().filter_map(Value::as_str) {
        let Some(disclosure) = disclosures_by_digest.get(digest) else {
            // The digest is signed but not disclosed — a withheld claim; nothing to surface.
            continue;
        };
        if !used_digests.insert(digest.to_string()) {
            // RFC 9901 §7.1 step 4: a digest encountered more than once invalidates the SD-JWT.
            return Err(ReasonCode::DisclosureIntegrity);
        }
        // An `_sd` entry MUST resolve to an object-property disclosure (`[salt, name, value]`); an
        // array-element disclosure (`[salt, value]`, no claim name) referenced from `_sd` is invalid.
        let name = disclosure
            .claim_name
            .as_deref()
            .ok_or(ReasonCode::DisclosureIntegrity)?;
        let value =
            reconstruct_value(&disclosure.claim_value, disclosures_by_digest, used_digests)?;
        insert_unique_at_level(&mut out, name, value)?;
    }
    Ok(out)
}

/// The reserved SD-JWT keys that are never reconstructed as claim values: the `_sd` digest array, the
/// `_sd_alg` selector, and the `cnf` holder-binding key (RFC 9901 / SD-JWT VC machinery, not claims).
fn is_sd_reserved_key(key: &str) -> bool {
    matches!(key, "_sd" | "_sd_alg" | "cnf")
}

/// Reconstruct a disclosed object value **in full** (RFC 9901 §7.1 recursive processing): keep every
/// clear property the issuer signed (scalars included), substitute this object's disclosed `_sd`
/// entries, and recurse into clear object/array properties for their own nested disclosures. This is
/// the disclosed *value* of a revealed claim, distinct from the disclosed-only top-level walk.
fn reconstruct_object(
    object: &serde_json::Map<String, Value>,
    disclosures_by_digest: &BTreeMap<String, &sd_jwt_payload::Disclosure>,
    used_digests: &mut std::collections::BTreeSet<String>,
) -> Result<BTreeMap<String, AttributeValue>, ReasonCode> {
    let mut out = substitute_sd_array(object, disclosures_by_digest, used_digests)?;
    for (key, child) in object {
        if is_sd_reserved_key(key) {
            continue;
        }
        // A clear property of a disclosed value is part of that value: keep it, reconstructing any
        // nested disclosures within it.
        let value = reconstruct_value(child, disclosures_by_digest, used_digests)?;
        insert_unique_at_level(&mut out, key, value)?;
    }
    Ok(out)
}

/// Reconstruct any disclosed claims nested under a clear property's value, returning `None` when the
/// value contains no disclosed claim (so the property is omitted from the disclosed view) and
/// `Some(value)` carrying only the disclosed nested claims otherwise.
fn disclosed_subtree(
    value: &Value,
    disclosures_by_digest: &BTreeMap<String, &sd_jwt_payload::Disclosure>,
    used_digests: &mut std::collections::BTreeSet<String>,
) -> Result<Option<AttributeValue>, ReasonCode> {
    match value {
        Value::Object(object) => {
            let nested = disclosed_object(object, disclosures_by_digest, used_digests)?;
            Ok((!nested.is_empty()).then_some(AttributeValue::Map(nested)))
        }
        Value::Array(items) => {
            let disclosed = disclosed_array(items, disclosures_by_digest, used_digests)?;
            Ok((!disclosed.is_empty()).then_some(AttributeValue::Array(disclosed)))
        }
        // A scalar clear property holds no disclosable claim.
        _ => Ok(None),
    }
}

/// Reconstruct the disclosed elements of an array for the **top-level disclosed-only walk** (RFC 9901
/// §7.1): an `{"...": "<digest>"}` redaction whose disclosure is presented becomes that disclosed
/// element; an undisclosed redaction is dropped (the element was not revealed). A clear element is
/// surfaced only when it nests a disclosed claim — a clear scalar carries no disclosure.
fn disclosed_array(
    items: &[Value],
    disclosures_by_digest: &BTreeMap<String, &sd_jwt_payload::Disclosure>,
    used_digests: &mut std::collections::BTreeSet<String>,
) -> Result<Vec<AttributeValue>, ReasonCode> {
    let mut disclosed = Vec::new();
    for item in items {
        if let Some(element) = disclosed_array_redaction(item, disclosures_by_digest, used_digests)?
        {
            // A revealed redacted element.
            disclosed.push(element);
        } else if !is_array_redaction(item) {
            // A clear element: surface it only when it nests a disclosed claim (mirrors a clear
            // property in the disclosed-only walk).
            if let Some(nested) = disclosed_subtree(item, disclosures_by_digest, used_digests)? {
                disclosed.push(nested);
            }
        }
    }
    Ok(disclosed)
}

/// Reconstruct an array value **in full** (RFC 9901 §7.1 recursive processing of a disclosed array):
/// a presented redaction becomes its disclosed element, an undisclosed redaction is dropped, and a
/// clear element is kept in full (with any nested disclosures within it substituted).
fn reconstruct_array(
    items: &[Value],
    disclosures_by_digest: &BTreeMap<String, &sd_jwt_payload::Disclosure>,
    used_digests: &mut std::collections::BTreeSet<String>,
) -> Result<Vec<AttributeValue>, ReasonCode> {
    let mut out = Vec::new();
    for item in items {
        if let Some(element) = disclosed_array_redaction(item, disclosures_by_digest, used_digests)?
        {
            out.push(element);
        } else if !is_array_redaction(item) {
            // A clear element of a disclosed array is part of that value: keep it in full.
            out.push(reconstruct_value(
                item,
                disclosures_by_digest,
                used_digests,
            )?);
        }
    }
    Ok(out)
}

/// Whether an array element is a selective-disclosure redaction object `{"...": "<digest>"}`.
fn is_array_redaction(item: &Value) -> bool {
    item.as_object()
        .and_then(|map| map.get("..."))
        .is_some_and(Value::is_string)
}

/// Resolve an array-element redaction `{"...": "<digest>"}`: `Ok(Some(value))` when the disclosure is
/// presented (the revealed element value), `Ok(None)` when the element is not a redaction or the
/// redaction was not disclosed. Enforces the repeated-digest rule and that an array-element disclosure
/// carries no claim name (`[salt, value]`); both violations reject as [`ReasonCode::DisclosureIntegrity`].
fn disclosed_array_redaction(
    item: &Value,
    disclosures_by_digest: &BTreeMap<String, &sd_jwt_payload::Disclosure>,
    used_digests: &mut std::collections::BTreeSet<String>,
) -> Result<Option<AttributeValue>, ReasonCode> {
    let Some(Value::String(digest)) = item.as_object().and_then(|map| map.get("...")) else {
        return Ok(None);
    };
    let Some(disclosure) = disclosures_by_digest.get(digest.as_str()) else {
        // Undisclosed array element — not revealed in this presentation.
        return Ok(None);
    };
    if !used_digests.insert(digest.clone()) {
        return Err(ReasonCode::DisclosureIntegrity);
    }
    // An array-element disclosure is `[salt, value]` — it MUST NOT carry a claim name.
    if disclosure.claim_name.is_some() {
        return Err(ReasonCode::DisclosureIntegrity);
    }
    Ok(Some(reconstruct_value(
        &disclosure.claim_value,
        disclosures_by_digest,
        used_digests,
    )?))
}

/// Reconstruct a disclosed claim's *value* in full (RFC 9901 §7.1 "recursively process the value").
///
/// Unlike the [`disclosed_object`] top-level walk — which surfaces *only* the disclosed claims of the
/// credential — a disclosed value is revealed in full: when the holder discloses a whole object (e.g.
/// the entire `address`), every clear sub-property the issuer signed (`country`, …) is part of that
/// disclosed value and is kept, alongside any nested `_sd`/array-element disclosures substituted in
/// place. A nested redaction the holder did *not* present is dropped (that sub-claim stays concealed).
fn reconstruct_value(
    value: &Value,
    disclosures_by_digest: &BTreeMap<String, &sd_jwt_payload::Disclosure>,
    used_digests: &mut std::collections::BTreeSet<String>,
) -> Result<AttributeValue, ReasonCode> {
    match value {
        Value::Object(object) => Ok(AttributeValue::Map(reconstruct_object(
            object,
            disclosures_by_digest,
            used_digests,
        )?)),
        Value::Array(items) => Ok(AttributeValue::Array(reconstruct_array(
            items,
            disclosures_by_digest,
            used_digests,
        )?)),
        scalar => Ok(json_to_attribute(scalar)),
    }
}

/// Insert a disclosed claim at the current object level, enforcing per-level claim-name uniqueness
/// (RFC 9901 §7.1: "if the claim name already exists at the level of the `_sd` key, the SD-JWT MUST be
/// rejected"). The check is scoped to **this** level (the `BTreeMap` being built), never a crate-wide
/// leaf name — so two distinct nested claims sharing a leaf under different parents are both kept.
///
/// A genuine same-level collision is the reorder attack (two issuer-signed disclosures populating one
/// claim name; the holder picks the value by reordering the segments): rejected as
/// [`ReasonCode::DisclosureIntegrity`]. A clear property and a disclosure cannot both target the same
/// name at one level under a well-formed issuer payload, so the check fires only on that attack.
fn insert_unique_at_level(
    map: &mut BTreeMap<String, AttributeValue>,
    name: &str,
    value: AttributeValue,
) -> Result<(), ReasonCode> {
    if map.contains_key(name) {
        return Err(ReasonCode::DisclosureIntegrity);
    }
    map.insert(name.to_string(), value);
    Ok(())
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
