//! OpenID4VP 1.0 verifier binding (DCQL request build + `vp_token` binding verify).
//!
//! The SDK is a **full verifier** (contracts/openid4vp-verifier.md): it builds the OpenID4VP
//! presentation request (a DCQL query + a fresh `nonce` + the verifier's `audience`/`client_id`) AND
//! verifies that a returned `vp_token` is cryptographically **bound** to it. Owning both halves makes
//! replay / audience binding **correct by construction** — the verifier never accepts a presentation
//! it did not request.
//!
//! ## Operations
//!
//! - [`build_request`] — `(dcql, audience) -> PresentationRequest { dcql, nonce (fresh), audience }`.
//!   The fresh `nonce` comes from the host RNG seam [`NonceSource`] (the core is sans-IO; entropy is
//!   host-provided exactly as the signing core takes it via `HostContext.entropy`).
//! - [`verify_response`] — `(vp_token, request, policy, anchors) -> VerificationResult`. Runs the
//!   per-format always-on bar ([`crate::sdjwtvc`] / [`crate::mdoc`]) **plus** the binding checks.
//!
//! ## Binding checks (FR-015 / SC-008)
//!
//! - **Nonce**: the presentation echoes the request's fresh `nonce` — SD-JWT VC in the KB-JWT
//!   (`nonce`); mdoc in the `SessionTranscript` / OID4VPHandover the `DeviceAuth` signs over. A
//!   missing/mismatched nonce ⇒ INVALID [`ReasonCode::Replay`] (a replayed presentation cannot
//!   satisfy a fresh nonce).
//! - **Audience**: the presentation is addressed to this verifier's `client_id` — SD-JWT VC KB-JWT
//!   `aud`; mdoc the handover/`client_id`. Wrong audience ⇒ INVALID [`ReasonCode::WrongAudience`].
//!
//! For mdoc the response is delivered to a verifier-controlled address, so the **audience** is an
//! observable cleartext field (compared directly → `WrongAudience`) while **freshness** is purely
//! cryptographic (the nonce is folded into the signed handover transcript → a mismatch surfaces as a
//! failed holder binding, attributed to `Replay`). For SD-JWT VC both `aud` and `nonce` are carried
//! in the (signed, but here pre-verification read) KB-JWT, so both are attributed precisely before
//! the full cryptographic bar runs.

use ciborium::value::Value as CborValue;
use serde::{Deserialize, Serialize};

use crate::mdoc::{self, MdocVerifyParams};
use crate::sdjwtvc::{self, KeyBindingChallenge, SdJwtVcInput};
use crate::status::StatusOutcome;
use crate::trust::TrustAnchorSource;
use crate::types::{IssuerRole, ReasonCode, VerificationPolicy, VerificationResult};

/// A host-driven source of fresh entropy for the request `nonce` (keeps the core sans-IO — the
/// entropy is host-provided, mirroring `cleverbase_core::HostContext.entropy`).
///
/// [`build_request`] draws a fresh nonce per request; the host wires a CSPRNG in production and a
/// deterministic sequence in tests. The trait takes `&mut self` so a counter/CSPRNG can advance.
pub trait NonceSource {
    /// Return fresh random bytes for a new request nonce (≥ 16 bytes recommended). Each call MUST
    /// return a distinct, unpredictable value (no reuse — replay protection depends on it).
    fn fresh_nonce(&mut self) -> Vec<u8>;
}

/// A DCQL (Digital Credentials Query Language — OpenID4VP 1.0) query.
///
/// OpenID4VP 1.0 removed Presentation-Exchange `presentation_definition`; the query is **DCQL**. The
/// binding verifier does not interpret the query's selection semantics (that is the holder/wallet's
/// job when building the presentation) — it carries the query opaquely as its canonical JSON so the
/// issued request is reproducible and auditable. Carrying it as a structured-but-opaque value keeps
/// the wire contract explicit without re-implementing DCQL evaluation in the verifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dcql {
    /// The DCQL query as its canonical JSON text (what a wallet receives in the request).
    pub query_json: String,
}

impl Dcql {
    /// Wrap a DCQL query given as JSON text.
    #[must_use]
    pub fn from_json(query_json: impl Into<String>) -> Self {
        Self {
            query_json: query_json.into(),
        }
    }
}

/// A verifier-built OpenID4VP presentation request (data-model.md `PresentationRequest`).
///
/// Built by [`build_request`] with a **fresh** `nonce` per request; the SDK tracks it to verify a
/// returned `vp_token` is bound to exactly this `nonce` + `audience`. Carries only verifier-side data
/// (no secret), so deriving `Debug` is safe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresentationRequest {
    /// The DCQL query of which attributes/credentials are requested.
    pub dcql: Dcql,
    /// The fresh per-request nonce the presentation MUST echo (replay protection).
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
    /// The verifier's `client_id` the presentation MUST be addressed to (audience binding).
    pub audience: String,
}

impl PresentationRequest {
    /// The request `nonce` as a base64url-unpadded string (the form an SD-JWT VC KB-JWT echoes).
    #[must_use]
    pub fn nonce_b64(&self) -> String {
        use base64ct::{Base64UrlUnpadded, Encoding as _};
        Base64UrlUnpadded::encode_string(&self.nonce)
    }
}

/// Build an OpenID4VP presentation request: the DCQL query, a **fresh** nonce drawn from the host
/// [`NonceSource`], and the verifier's audience (`client_id`).
///
/// A fresh nonce per call is the replay-protection invariant (contracts/openid4vp-verifier.md): the
/// SDK keeps the returned [`PresentationRequest`] and only accepts a `vp_token` bound to it.
pub fn build_request<N: NonceSource + ?Sized>(
    nonce_source: &mut N,
    dcql: Dcql,
    audience: impl Into<String>,
) -> PresentationRequest {
    PresentationRequest {
        dcql,
        nonce: nonce_source.fresh_nonce(),
        audience: audience.into(),
    }
}

/// An mdoc OpenID4VP `vp_token` envelope: the ISO 18013-5 `DeviceResponse` plus the audience the
/// response was addressed to.
///
/// In an OpenID4VP flow the mdoc response is delivered to a verifier-controlled `response_uri` for a
/// specific `client_id`, so the **audience** is an observable (cleartext, comparable) field, while
/// **freshness** is bound cryptographically inside the handover transcript the `DeviceAuth` signs
/// over. This envelope makes that explicit on the wire: `audience` is compared to the request
/// (→ [`ReasonCode::WrongAudience`]); the `device_response` is verified against the handover the
/// verifier reconstructs from the request `nonce` (a mismatch → [`ReasonCode::Replay`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MdocVpToken {
    /// The audience (`client_id`) the response was addressed to.
    pub audience: String,
    /// The CBOR-encoded ISO 18013-5 `DeviceResponse`.
    pub device_response: Vec<u8>,
}

/// The presented credential, in the format carried by an OpenID4VP `vp_token`.
///
/// OpenID4VP carries either a compact SD-JWT VC presentation string or an mdoc `DeviceResponse`
/// (wrapped here with its addressed audience — see [`MdocVpToken`]). Detected by the caller; the
/// verifier never guesses (an unrecognized shape would be [`ReasonCode::UnsupportedFormat`] at the
/// [`crate::verify`] entry point).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VpToken<'a> {
    /// A compact SD-JWT VC presentation (`<issuer-JWS>~<D>…~<KB-JWT>`).
    SdJwtVc(&'a str),
    /// An mdoc `DeviceResponse` plus its addressed audience.
    Mdoc(MdocVpToken),
}

/// Verify an OpenID4VP `vp_token` is cryptographically bound to an issued request, running the
/// per-format always-on bar **plus** the nonce/audience binding (contracts/openid4vp-verifier.md).
///
/// - SD-JWT VC: attributes the binding to [`ReasonCode::WrongAudience`] / [`ReasonCode::Replay`] from
///   the KB-JWT `aud`/`nonce`, then runs the full bar with the request as the holder-binding
///   challenge (so the binding is also cryptographically enforced — correct by construction).
/// - mdoc: compares the addressed audience (→ `WrongAudience`), then runs the bar against the
///   handover transcript reconstructed from the request nonce/audience (a fresh-nonce mismatch
///   surfaces as a failed holder binding, attributed to `Replay`).
///
/// `now_unix`/`role`/`status` are the remaining per-format-bar inputs the [`crate::verify`] entry
/// point supplies (the validity instant, the trust-anchor role, and the resolved status outcome).
pub fn verify_response<A: TrustAnchorSource + ?Sized>(
    vp_token: &VpToken<'_>,
    request: &PresentationRequest,
    _policy: &VerificationPolicy,
    anchors: &A,
    now_unix: i64,
    role: IssuerRole,
    status: StatusOutcome,
) -> VerificationResult {
    match vp_token {
        VpToken::SdJwtVc(presentation) => {
            verify_sd_jwt_vc_bound(presentation, request, anchors, now_unix, role, status)
        }
        VpToken::Mdoc(token) => verify_mdoc_bound(token, request, anchors, now_unix, role, status),
    }
}

/// SD-JWT VC binding: attribute a nonce/audience mismatch precisely (from the KB-JWT), then run the
/// full always-on bar with the request as the holder-binding challenge.
fn verify_sd_jwt_vc_bound<A: TrustAnchorSource + ?Sized>(
    presentation: &str,
    request: &PresentationRequest,
    anchors: &A,
    now_unix: i64,
    role: IssuerRole,
    status: StatusOutcome,
) -> VerificationResult {
    let expected_nonce = request.nonce_b64();

    // Read the KB-JWT's claimed aud/nonce for precise failure attribution. A presentation with no
    // KB-JWT cannot be bound to a request → MissingRequestBinding.
    let Some((aud, nonce)) = sdjwtvc::kb_jwt_aud_nonce(presentation) else {
        return VerificationResult::invalid(ReasonCode::MissingRequestBinding);
    };
    // Audience first (a wrong-audience presentation was never meant for us), then nonce (replay).
    if aud != request.audience {
        return VerificationResult::invalid(ReasonCode::WrongAudience);
    }
    if nonce != expected_nonce {
        return VerificationResult::invalid(ReasonCode::Replay);
    }

    // Now run the full always-on bar; the request is the holder-binding challenge, so the matched
    // nonce/aud are also cryptographically enforced (the KB-JWT signature over them must verify).
    let input = SdJwtVcInput {
        presentation,
        anchors,
        role,
        key_binding: Some(KeyBindingChallenge {
            audience: &request.audience,
            nonce: &expected_nonce,
        }),
        now_unix,
        status,
    };
    sdjwtvc::verify_sd_jwt_vc(&input)
}

/// mdoc binding: compare the addressed audience (→ `WrongAudience`), then run the always-on bar
/// against the handover transcript reconstructed from the request (a nonce mismatch → `Replay`).
fn verify_mdoc_bound<A: TrustAnchorSource + ?Sized>(
    token: &MdocVpToken,
    request: &PresentationRequest,
    anchors: &A,
    now_unix: i64,
    role: IssuerRole,
    status: StatusOutcome,
) -> VerificationResult {
    if token.audience != request.audience {
        return VerificationResult::invalid(ReasonCode::WrongAudience);
    }

    // Reconstruct the OID4VP handover transcript the holder must have signed over (from the request
    // nonce + audience). If the DeviceAuth does not verify against it, the presentation is not bound
    // to this fresh request → a replay.
    let transcript = oid4vp_handover_transcript(&request.audience, &request.nonce);
    let params = MdocVerifyParams {
        now_unix,
        session_transcript: Some(&transcript),
        role,
        status,
    };
    let result = mdoc::verify(&token.device_response, anchors, &params);
    // A holder-binding failure here is the fresh-nonce mismatch (audience already matched in
    // cleartext above) → attribute it to Replay; every other reason passes through unchanged.
    if !result.valid && result.reasons == [ReasonCode::HolderBinding] {
        return VerificationResult::invalid(ReasonCode::Replay);
    }
    result
}

/// Build the OpenID4VP handover `SessionTranscript` bytes for an mdoc presentation from the
/// `audience` (`client_id`) and `nonce`.
///
/// Modelled as the ISO 18013-5 `SessionTranscript` shape `[null, null, OID4VPHandover]` where the
/// handover is `["OID4VPHandover", clientIdHash, nonceHash]` (SHA-256 over the audience and nonce) —
/// the holder folds the same handover into the `DeviceAuthentication` it signs, so reconstructing it
/// here binds the device signature to this exact request. Both the holder (test issuer) and the
/// verifier MUST build it identically.
#[must_use]
pub fn oid4vp_handover_transcript(audience: &str, nonce: &[u8]) -> Vec<u8> {
    use sha2::{Digest as _, Sha256};
    let client_id_hash = Sha256::digest(audience.as_bytes()).to_vec();
    let nonce_hash = Sha256::digest(nonce).to_vec();
    let handover = CborValue::Array(vec![
        CborValue::Text("OID4VPHandover".to_owned()),
        CborValue::Bytes(client_id_hash),
        CborValue::Bytes(nonce_hash),
    ]);
    let transcript = CborValue::Array(vec![CborValue::Null, CborValue::Null, handover]);
    let mut buf = Vec::new();
    // Infallible: encoding a plain CBOR value into an in-memory Vec cannot fail.
    #[allow(clippy::expect_used)] // infallible: CBOR into a Vec writer
    {
        ciborium::into_writer(&transcript, &mut buf)
            .expect("CBOR encode of the handover transcript");
    }
    buf
}

#[cfg(test)]
mod tests;
