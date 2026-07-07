//! Holder signer-hook + `HolderContext` (US2 — task T024).
//!
//! The SDK is **not a wallet** (FR-009): it never generates, imports, holds, or sees the holder
//! private key. This module is the **signer-hook** — a direct reuse of the spec-001 remote-signing
//! pattern (research D8, Principle III/VIII): the integrator supplies (1) the holder **public** key
//! and (2) a [`Signer`] callback that signs out-of-process (their HSM/KMS), exactly as the CSC
//! `signHash` flow signs the SDK-built CMS `SignedAttributes` digest off-box.
//!
//! The SDK builds the **exact, deterministic** [`SigningInput`] for each EUDI ceremony —
//!
//! - the **OpenID4VCI** proof-of-possession JWT (`typ: openid4vci-proof+jwt`),
//! - the **SD-JWT VC** holder Key-Binding JWT (`typ: kb+jwt`), and
//! - the **mdoc** `DeviceAuth` `DeviceSignature` (a detached COSE_Sign1 over `DeviceAuthentication`)
//!
//! — and splices the host-returned signature back into the envelope (the compact JWS, or the
//! COSE_Sign1). Each [`SigningInput`] exposes the `aud`/`nonce` it binds ([`SigningInput::audience`]
//! / [`SigningInput::nonce`]) so the host can apply policy before it blind-signs (the same
//! blind-signing trust boundary the CSC flow documents — RCA: a deterministic input + exposed
//! `aud`/`nonce` is what lets the host refuse a mis-scoped request).
//!
//! ## Sans-IO seam
//!
//! [`Signer::sign`] is synchronous (the core is sans-IO and never blocks on I/O): a host with an
//! async HSM drives its future to completion behind this seam, exactly as the signing core's host
//! performs the `signHash` HTTP effect and feeds the bytes back. The signature is the raw fixed-width
//! `r‖s` ES256 form (64 bytes) — the encoding both the compact-JWS and COSE_Sign1 envelopes carry.

use base64ct::{Base64UrlUnpadded, Encoding as _};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// The signature algorithm the holder key signs with. The EUDI baseline mandates **ES256** (ECDSA /
/// P-256 / SHA-256 — HAIP 1.0 §7; research D1) for both the JOSE (PoP-JWT / KB-JWT) and the COSE
/// (`DeviceSignature`) ceremonies, so it is the only variant the signer-hook builds inputs for; any
/// other algorithm is a future extension (kept a closed enum so an unsupported `alg` is a type error,
/// never a guess).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureAlgorithm {
    /// ECDSA over P-256 with SHA-256 (the EUDI mandatory baseline).
    Es256,
}

impl SignatureAlgorithm {
    /// The JOSE `alg` header value (RFC 7518) for a compact JWS signed with this algorithm.
    #[must_use]
    pub const fn jose_alg(self) -> &'static str {
        match self {
            Self::Es256 => "ES256",
        }
    }
}

/// The ceremony a [`SigningInput`] belongs to (so a host policy can branch on it, and so the splice
/// helpers reject a mismatched signature). Each ceremony binds `aud`/`nonce` differently — exposed
/// uniformly via [`SigningInput::audience`] / [`SigningInput::nonce`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ceremony {
    /// The OpenID4VCI proof-of-possession JWT (`typ: openid4vci-proof+jwt`) — binds the issuer's
    /// `aud` and the issuer-supplied `c_nonce`.
    Oid4vciProof,
    /// The SD-JWT VC holder Key-Binding JWT (`typ: kb+jwt`) — binds the verifier's `aud` and the
    /// request `nonce`.
    KeyBinding,
    /// The mdoc `DeviceAuth` `DeviceSignature` (detached COSE_Sign1 over `DeviceAuthentication`) —
    /// binds the verifier's `aud` and `nonce` cryptographically inside the session-transcript
    /// handover the signed payload covers (so they are surfaced here for host inspection even though
    /// the COSE payload carries them as a hash, not as cleartext fields).
    DeviceSignature,
}

/// The exact, deterministic bytes the host signs for one ceremony, plus the `aud`/`nonce` it binds
/// (exposed for host-side policy inspection — the blind-signing trust boundary, RCA-documented).
///
/// The SDK builds this; the host signs [`SigningInput::to_be_signed`] out-of-process and the SDK
/// splices the signature back via the matching builder. The struct **carries no private key** — it
/// is pure public material (the bytes to sign + the bound `aud`/`nonce`), so logging it leaks nothing
/// secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigningInput {
    ceremony: Ceremony,
    algorithm: SignatureAlgorithm,
    #[serde(with = "serde_bytes")]
    to_be_signed: Vec<u8>,
    audience: String,
    nonce: String,
}

impl SigningInput {
    /// Construct the mdoc `DeviceSignature` ceremony input over the COSE `Sig_structure` bytes (used
    /// by [`super::device::build_device_signature`], which owns the COSE encoding). ES256 only.
    pub(crate) fn for_device_signature(
        to_be_signed: Vec<u8>,
        audience: String,
        nonce: String,
    ) -> Self {
        Self {
            ceremony: Ceremony::DeviceSignature,
            algorithm: SignatureAlgorithm::Es256,
            to_be_signed,
            audience,
            nonce,
        }
    }

    /// The ceremony this input belongs to.
    #[must_use]
    pub const fn ceremony(&self) -> Ceremony {
        self.ceremony
    }

    /// The algorithm the host must sign with.
    #[must_use]
    pub const fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    /// The exact bytes to sign (the JOSE `header.payload` ASCII signing input, or the COSE `Sig_structure`
    /// `to_be_signed`). The host signs **these bytes verbatim**; the SDK splices the result.
    #[must_use]
    pub fn to_be_signed(&self) -> &[u8] {
        &self.to_be_signed
    }

    /// The `aud` this input binds (the issuer's identifier for a PoP-JWT; the verifier's `client_id`
    /// for a KB-JWT / `DeviceSignature`) — exposed so the host can refuse a mis-scoped request before
    /// it blind-signs.
    #[must_use]
    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// The `nonce` this input binds (the issuer `c_nonce` for a PoP-JWT; the verifier's request nonce
    /// for a KB-JWT / `DeviceSignature`) — exposed for the same host-policy reason as
    /// [`Self::audience`].
    #[must_use]
    pub fn nonce(&self) -> &str {
        &self.nonce
    }
}

/// The holder key-custody seam (research D8). The integrator implements this over their HSM/KMS; the
/// SDK calls [`Signer::sign`] with a SDK-built [`SigningInput`] and never touches a private key.
///
/// Implementations sign [`SigningInput::to_be_signed`] and return the **raw fixed-width `r‖s`** ES256
/// signature (64 bytes for P-256) — the encoding both the compact JWS and the COSE_Sign1 envelopes
/// carry. The method is synchronous (sans-IO): a host with an async signer drives its future to
/// completion behind this call.
pub trait Signer {
    /// The host signer's error type (surfaced to the caller unchanged).
    type Error;

    /// Sign `input.to_be_signed()` with the holder key bound to `handle`, returning the raw `r‖s`
    /// ES256 signature.
    ///
    /// # Errors
    ///
    /// Returns the host signer's error when the signature cannot be produced (key unavailable, policy
    /// refusal after inspecting `input.audience()`/`input.nonce()`, transport failure, …).
    fn sign(&self, handle: &str, input: &SigningInput) -> Result<Vec<u8>, Self::Error>;
}

/// The integrator-supplied holder context (data-model.md `HolderContext`).
///
/// Carries the holder **public** key (a JWK, the issuer-bound `cnf` for SD-JWT VC / the source of the
/// mdoc `DeviceKey` COSE_Key) and an opaque `handle` the host's [`Signer`] uses to select the
/// matching private key in its HSM/KMS. **No private key** is present — the SDK never holds one
/// (FR-009).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HolderContext {
    /// The holder's public key as a JWK (`kty=EC`, `crv=P-256`, base64url `x`/`y`). This is what the
    /// issuer binds in the credential's `cnf` (SD-JWT VC) / MSO `deviceKey` (mdoc); the SDK reads the
    /// public point from it but never a private component.
    pub holder_public_jwk: Value,
    /// An opaque handle the host's [`Signer`] maps to the holder private key in its HSM/KMS (the SDK
    /// passes it through to [`Signer::sign`] and never interprets it).
    pub key_handle: String,
}

impl HolderContext {
    /// Construct a holder context from a public JWK and a host key handle.
    #[must_use]
    pub fn new(holder_public_jwk: Value, key_handle: impl Into<String>) -> Self {
        Self {
            holder_public_jwk,
            key_handle: key_handle.into(),
        }
    }

    /// The holder JWK with **every private/symmetric member stripped** (`d`, `p`, `q`, `dp`, `dq`,
    /// `qi`, `k`, `oth`) so only the public key is ever emitted on the wire (FR-010, Constitution
    /// Principle IV — the SDK MUST NEVER leak secrets).
    ///
    /// A [`HolderContext`] is supposed to carry only the holder *public* JWK, but a common JWK-export
    /// mistake leaves the private scalar `d` (or the RSA CRT params) attached. The SDK is the
    /// documented last line of defense, so it strips them here rather than trusting the integrator to
    /// have done so — used at **every** embed site (the PoP-JWT JOSE header and the `cnf`).
    #[must_use]
    pub fn public_jwk_only(&self) -> Value {
        public_jwk_only(&self.holder_public_jwk)
    }

    /// The holder public key as a `cnf` confirmation object (`{"jwk": <public JWK>}`, RFC 7800) — the
    /// shape an SD-JWT VC issuer embeds so the verifier can check the KB-JWT against the bound key. The
    /// embedded JWK is stripped of any private members via [`Self::public_jwk_only`] (FR-010).
    #[must_use]
    pub fn cnf(&self) -> Value {
        json!({ "jwk": self.public_jwk_only() })
    }

    /// The raw uncompressed SEC1 public point (`0x04 ‖ X ‖ Y`, 65 bytes) of the holder key, decoded
    /// from its JWK `x`/`y`, or `None` when the JWK is not a P-256 EC public key. Used to derive the
    /// mdoc `DeviceKey` COSE_Key.
    #[must_use]
    pub fn public_sec1(&self) -> Option<Vec<u8>> {
        // The `kty=EC`/`crv=P-256` guard + base64url `x`/`y` decode + `0x04 ‖ X ‖ Y` assembly is the
        // shared [`crate::crypto::p256_sec1_from_jwk`] (DRY — one authoritative JWK→SEC1 decode).
        crate::crypto::p256_sec1_from_jwk(&self.holder_public_jwk)
    }
}

/// An error building a signing input or splicing a signature back into an envelope.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SignerError {
    /// The host returned a signature of the wrong length for the algorithm (ES256 raw `r‖s` is 64
    /// bytes).
    #[error("unexpected signature length for {0:?}: got {1} bytes")]
    BadSignatureLength(SignatureAlgorithm, usize),
    /// A JSON value could not be serialized while building the input (an impossible failure on plain
    /// in-memory `serde_json::Value`s; surfaced rather than swallowed).
    #[error("failed to serialize a signing input: {0}")]
    Serialize(String),
}

/// The raw `r‖s` length of an ES256 (P-256) signature.
const ES256_SIG_LEN: usize = 64;

/// Validate that a host-returned signature is the expected length for `algorithm`. The **one**
/// signature-length gate the JOSE (`PopJwtBuild`/`KbJwtBuild`) and mdoc
/// ([`super::device::DeviceSignatureBuild`]) assemble paths share (DRY — Principle III).
pub(crate) fn check_sig_len(
    algorithm: SignatureAlgorithm,
    signature: &[u8],
) -> Result<(), SignerError> {
    match algorithm {
        SignatureAlgorithm::Es256 => {
            if signature.len() == ES256_SIG_LEN {
                Ok(())
            } else {
                Err(SignerError::BadSignatureLength(algorithm, signature.len()))
            }
        }
    }
}

/// Serialize a JSON value to its compact bytes, mapping the (impossible) failure to [`SignerError`].
fn to_json_bytes(value: &Value) -> Result<Vec<u8>, SignerError> {
    serde_json::to_vec(value).map_err(|e| SignerError::Serialize(e.to_string()))
}

/// Build the compact-JWS `header.payload` signing input (base64url of each), returning the
/// to-be-signed ASCII bytes. The splice prefix (`header.payload`) is these same bytes as UTF-8, so
/// each builder's `assemble` derives it from [`SigningInput::to_be_signed`] rather than storing a
/// byte-identical copy (DRY — one authoritative signing-input buffer).
fn jws_signing_input(header: &Value, payload: &Value) -> Result<Vec<u8>, SignerError> {
    let header_b64 = Base64UrlUnpadded::encode_string(&to_json_bytes(header)?);
    let payload_b64 = Base64UrlUnpadded::encode_string(&to_json_bytes(payload)?);
    Ok(format!("{header_b64}.{payload_b64}").into_bytes())
}

/// Splice a raw `r‖s` ES256 signature onto a compact-JWS `header.payload` prefix, yielding the full
/// `header.payload.signature` compact JWS.
fn splice_compact_jws(prefix: &str, signature: &[u8]) -> String {
    let sig_b64 = Base64UrlUnpadded::encode_string(signature);
    format!("{prefix}.{sig_b64}")
}

/// Assemble a compact JWS from a signing input and the host-returned signature — the shared body of
/// [`PopJwtBuild::assemble`] and [`KbJwtBuild::assemble`] (DRY, Constitution Principle III): validate
/// the signature length, then splice it onto the signing input verbatim as the `header.payload`
/// prefix (derived from the one authoritative buffer, not a stored byte-identical copy).
///
/// # Errors
///
/// [`SignerError::BadSignatureLength`] if the signature is not the algorithm's expected length;
/// [`SignerError::Serialize`] if the to-be-signed buffer is not valid UTF-8 (impossible for an
/// SDK-built input — it is ASCII base64url `header.payload` — but checked rather than assumed).
fn assemble_compact_jws(input: &SigningInput, signature: &[u8]) -> Result<String, SignerError> {
    check_sig_len(input.algorithm, signature)?;
    let prefix = std::str::from_utf8(&input.to_be_signed)
        .map_err(|e| SignerError::Serialize(e.to_string()))?;
    Ok(splice_compact_jws(prefix, signature))
}

/// A built OpenID4VCI proof-of-possession JWT input, plus the splice context to assemble the compact
/// JWS once the host has signed it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PopJwtBuild {
    /// The signing input the host must sign (exposes `aud`/`nonce`).
    pub input: SigningInput,
}

impl PopJwtBuild {
    /// Splice the host-returned `r‖s` ES256 signature into the compact PoP-JWT.
    ///
    /// # Errors
    ///
    /// [`SignerError::BadSignatureLength`] if the signature is not the algorithm's expected length;
    /// [`SignerError::Serialize`] if the to-be-signed buffer is not valid UTF-8 (impossible for an
    /// SDK-built input — it is ASCII base64url `header.payload` — but checked rather than assumed).
    pub fn assemble(&self, signature: &[u8]) -> Result<String, SignerError> {
        assemble_compact_jws(&self.input, signature)
    }
}

/// Build the OpenID4VCI **proof-of-possession** JWT signing input (the `jwt` proof type, OpenID4VCI
/// 1.0 §F.1 `#jwt-proof-type`). The header carries `typ` (REQUIRED, `openid4vci-proof+jwt`), `alg`
/// (REQUIRED, ES256), and the holder public key in the `jwk` header (so the issuer binds it as the
/// credential's `cnf`); the body carries `aud` (REQUIRED, the Credential Issuer Identifier), `iat`
/// (REQUIRED), and `nonce` (the `c_nonce` from the Nonce Endpoint, §7 `#nonce-endpoint`). `iss` is
/// omitted: §F.1 requires it omitted "if the access token ... was obtained from a Pre-Authorized Code
/// Flow through anonymous access to the token endpoint", which is this path.
///
/// The host signs [`PopJwtBuild::input`] and [`PopJwtBuild::assemble`] splices the result.
///
/// # Errors
///
/// [`SignerError::Serialize`] on the (impossible) JSON-serialization failure of an in-memory value.
pub fn build_pop_jwt(
    holder: &HolderContext,
    audience: &str,
    c_nonce: &str,
    iat: i64,
) -> Result<PopJwtBuild, SignerError> {
    let alg = SignatureAlgorithm::Es256;
    let header = json!({
        "typ": "openid4vci-proof+jwt",
        "alg": alg.jose_alg(),
        // Strip any private members before the holder JWK travels in the JOSE header POSTed to the
        // issuer (FR-010 — never leak a private scalar a mis-exported HolderContext might carry).
        "jwk": holder.public_jwk_only(),
    });
    let payload = json!({
        "aud": audience,
        "nonce": c_nonce,
        "iat": iat,
    });
    let to_be_signed = jws_signing_input(&header, &payload)?;
    Ok(PopJwtBuild {
        input: SigningInput {
            ceremony: Ceremony::Oid4vciProof,
            algorithm: alg,
            to_be_signed,
            audience: audience.to_owned(),
            nonce: c_nonce.to_owned(),
        },
    })
}

/// A built SD-JWT VC Key-Binding JWT input, plus the splice context to assemble the compact KB-JWT
/// (`typ: kb+jwt`) and append it to the SD-JWT presentation prefix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KbJwtBuild {
    /// The signing input the host must sign (exposes the verifier `aud`/`nonce`).
    pub input: SigningInput,
}

impl KbJwtBuild {
    /// Splice the host-returned `r‖s` ES256 signature into the compact KB-JWT.
    ///
    /// # Errors
    ///
    /// [`SignerError::BadSignatureLength`] if the signature is not the algorithm's expected length;
    /// [`SignerError::Serialize`] if the to-be-signed buffer is not valid UTF-8 (impossible for an
    /// SDK-built input — it is ASCII base64url `header.payload` — but checked rather than assumed).
    pub fn assemble(&self, signature: &[u8]) -> Result<String, SignerError> {
        assemble_compact_jws(&self.input, signature)
    }
}

/// Build the SD-JWT VC **Key-Binding JWT** signing input (`typ: kb+jwt`, RFC 9901 §4.3). Binds the
/// verifier's `audience` (`aud`) and request `nonce`, plus the `sd_hash` over the presentation prefix
/// (the issuer-JWS-plus-selected-disclosures, up to and including the final `~`).
///
/// `sd_hash` is computed as the base64url SHA-256 of `presentation_prefix` (the bytes the verifier
/// recomputes — see [`crate::sdjwtvc`]'s holder-binding check). The host signs [`KbJwtBuild::input`]
/// and [`KbJwtBuild::assemble`] produces the compact KB-JWT to append after the prefix.
///
/// # Errors
///
/// [`SignerError::Serialize`] on the (impossible) JSON-serialization failure of an in-memory value.
pub fn build_kb_jwt(
    audience: &str,
    nonce: &str,
    iat: i64,
    presentation_prefix: &str,
) -> Result<KbJwtBuild, SignerError> {
    let alg = SignatureAlgorithm::Es256;
    // The crate's single `sd_hash` formula (DRY — the SD-JWT VC verifier recomputes the same value).
    let sd_hash = crate::crypto::sd_hash(presentation_prefix);
    let header = json!({
        "typ": "kb+jwt",
        "alg": alg.jose_alg(),
    });
    let payload = json!({
        "iat": iat,
        "aud": audience,
        "nonce": nonce,
        "sd_hash": sd_hash,
    });
    let to_be_signed = jws_signing_input(&header, &payload)?;
    Ok(KbJwtBuild {
        input: SigningInput {
            ceremony: Ceremony::KeyBinding,
            algorithm: alg,
            to_be_signed,
            audience: audience.to_owned(),
            nonce: nonce.to_owned(),
        },
    })
}

/// The JWK members that carry **private** or **symmetric** key material (RFC 7517 §4 / RFC 7518
/// §6) — the EC private scalar, the RSA private exponent + CRT factors, and the `oct` symmetric key.
/// Stripped before a JWK is embedded anywhere on the wire so a private key can never leak (FR-010).
const JWK_PRIVATE_MEMBERS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "k", "oth"];

/// Return a copy of `jwk` with every private/symmetric member removed (see [`JWK_PRIVATE_MEMBERS`]),
/// leaving only the public key. A non-object value is returned unchanged (there is nothing to strip).
fn public_jwk_only(jwk: &Value) -> Value {
    let mut jwk = jwk.clone();
    if let Some(obj) = jwk.as_object_mut() {
        for member in JWK_PRIVATE_MEMBERS {
            obj.remove(*member);
        }
    }
    jwk
}

#[cfg(test)]
mod tests;
