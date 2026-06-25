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
//! - [`build_request`] — `(dcql, audience, response_uri) -> PresentationRequest { dcql, nonce
//!   (fresh), audience, response_uri }`. The fresh `nonce` comes from the host RNG seam
//!   [`NonceSource`] (the core is sans-IO; entropy is host-provided exactly as the signing core takes
//!   it via `HostContext.entropy`). The `response_uri` is the verifier's response endpoint — a
//!   first-class request parameter the mdoc handover binds (OpenID4VP 1.0 §B.2.6).
//! - [`verify_response`] — `(vp_token, request, policy, anchors) -> VerificationResult`. Runs the
//!   per-format always-on bar ([`crate::sdjwtvc`] / [`crate::mdoc`]) **plus** the binding checks.
//!
//! ## Binding checks (FR-015 / SC-008)
//!
//! - **Nonce**: the presentation echoes the request's fresh `nonce` — SD-JWT VC in the KB-JWT
//!   (`nonce`); mdoc in the `SessionTranscript` / `OpenID4VPHandover` (OpenID4VP 1.0 §B.2.6)
//!   the `DeviceAuth` signs over. A missing/mismatched nonce ⇒ INVALID
//!   [`ReasonCode::Replay`] (a replayed presentation cannot satisfy a fresh nonce).
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
use crate::types::{Format, IssuerRole, ReasonCode, VerificationPolicy, VerificationResult};

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
    /// The verifier's `response_uri` (or `redirect_uri`) request parameter — the endpoint the
    /// presentation is returned to. This is the **4th element** of the mdoc `OpenID4VPHandoverInfo`
    /// (OpenID4VP 1.0 §B.2.6), a distinct request parameter from the `client_id` (`audience`); the
    /// holder folds it into the signed handover, so the verifier MUST reconstruct the handover with
    /// the same value. A direct-`response_uri` deployment uses the absolute response endpoint; a
    /// `redirect_uri` deployment its redirect target (the spec accepts either, by Response Mode).
    pub response_uri: String,
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
/// [`NonceSource`], the verifier's audience (`client_id`), and the verifier's `response_uri`.
///
/// A fresh nonce per call is the replay-protection invariant (contracts/openid4vp-verifier.md): the
/// SDK keeps the returned [`PresentationRequest`] and only accepts a `vp_token` bound to it. The
/// `response_uri` is the verifier's response endpoint (or `redirect_uri`); it is the 4th element of
/// the mdoc handover (OpenID4VP 1.0 §B.2.6) and is therefore part of what the holder cryptographically
/// binds — distinct from the `audience`/`client_id`.
pub fn build_request<N: NonceSource + ?Sized>(
    nonce_source: &mut N,
    dcql: Dcql,
    audience: impl Into<String>,
    response_uri: impl Into<String>,
) -> PresentationRequest {
    PresentationRequest {
        dcql,
        nonce: nonce_source.fresh_nonce(),
        audience: audience.into(),
        response_uri: response_uri.into(),
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
/// [`verify()`](crate::verify()) entry point).
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
/// `policy` carries the accepted-format restriction (`policy.formats`); a `vp_token` whose format the
/// policy excludes is rejected with [`ReasonCode::UnsupportedFormat`] BEFORE any bar runs, so this
/// public entry honors the gate even when a native caller invokes it directly (not only via the
/// [`verify()`](crate::verify()) wrapper). `now_unix`/`role`/`status` are the remaining per-format-bar
/// inputs (the validity instant, the trust-anchor role, and the resolved status outcome).
pub fn verify_response<A: TrustAnchorSource + ?Sized>(
    vp_token: &VpToken<'_>,
    request: &PresentationRequest,
    policy: &VerificationPolicy,
    anchors: &A,
    now_unix: i64,
    role: IssuerRole,
    status: StatusOutcome,
) -> VerificationResult {
    // Format gate (identical to the `verify()` entry point's, so the public `verify_response` honors
    // the `policy` it takes): the policy may restrict accepted formats (an empty set = both). A
    // presented format the policy excludes is rejected up front — never run through the bar.
    let format = match vp_token {
        VpToken::SdJwtVc(_) => Format::SdJwtVc,
        VpToken::Mdoc(_) => Format::Mdoc,
    };
    if !policy.formats.is_empty() && !policy.formats.contains(&format) {
        return VerificationResult::invalid(ReasonCode::UnsupportedFormat);
    }

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

    // Reconstruct the conformant OpenID4VP-1.0 `OpenID4VPHandover` transcript the holder must have
    // signed over (from the request nonce + audience + response_uri). If the DeviceAuth does not
    // verify against it, the presentation is not bound to this fresh request → a replay.
    let transcript =
        oid4vp_handover_transcript(&request.audience, &request.nonce, &request.response_uri);
    let params = MdocVerifyParams {
        now_unix,
        session_transcript: Some(&transcript),
        role,
        status,
    };
    let result = mdoc::verify(&token.device_response, anchors, &params);
    // A holder-binding failure here is AMBIGUOUS: it can be the fresh-nonce mismatch we want to
    // surface as Replay (the verifier rebuilt `DeviceAuthentication` over a different transcript than
    // the holder signed — the audience already matched in cleartext above), OR a genuine
    // DeviceKey/DeviceSignature fault (a corrupt/garbled signature, non-ES256 alg, unparseable
    // DeviceKey, DeviceMac-only DeviceAuth, or a multi-document doc[1] binding failure). Blindly
    // re-attributing every `HolderBinding` to `Replay` would MASK those real faults.
    //
    // Distinguish them by the transcript-INDEPENDENT binding machinery: a fresh-nonce mismatch fails
    // ONLY the signature-over-transcript check while leaving the machinery intact (ES256
    // DeviceSignature + parseable DeviceKey + well-formed signature bytes), whereas a genuine fault
    // breaks the machinery itself (it would fail for ANY transcript). Only re-attribute to `Replay`
    // when the machinery is sound; a structural fault keeps `HolderBinding`.
    if !result.valid && result.reasons == [ReasonCode::HolderBinding] {
        return match mdoc::device_binding_machinery(&token.device_response) {
            // Sound machinery + a binding failure ⇒ the rebuilt transcript (fresh nonce) is the only
            // thing that can differ ⇒ a replay.
            mdoc::DeviceBindingMachinery::Sound => VerificationResult::invalid(ReasonCode::Replay),
            // A structurally-broken binding is a genuine holder-binding fault, never a replay.
            mdoc::DeviceBindingMachinery::Faulty => result,
        };
    }
    result
}

/// Build the conformant OpenID4VP-1.0 / ISO 18013-7 mdoc `SessionTranscript` bytes for a
/// redirect-invoked presentation, from the verifier's `client_id` (`audience`), request `nonce`, and
/// `response_uri`.
///
/// This is the **`OpenID4VPHandover`** of OpenID4VP 1.0 §B.2.6 ("`Handover` and `SessionTranscript`
/// Definitions"), NOT a custom structure — a conformant EUDI wallet signs `DeviceAuth` over exactly
/// this `SessionTranscript`, so the verifier reconstructs it identically (CDDL reproduced verbatim):
///
/// ```text
/// SessionTranscript = [null, null, OpenID4VPHandover]   ; ISO 18013-5 §9.1.5.1, with
///                                                       ; DeviceEngagementBytes = EReaderKeyBytes = null
/// OpenID4VPHandover = ["OpenID4VPHandover", OpenID4VPHandoverInfoHash]
/// OpenID4VPHandoverInfoHash  = bstr            ; SHA-256 of OpenID4VPHandoverInfoBytes
/// OpenID4VPHandoverInfoBytes = bstr .cbor OpenID4VPHandoverInfo
/// OpenID4VPHandoverInfo = [clientId, nonce, jwkThumbprint, responseUri]
///   clientId      = tstr   ; the `client_id` request parameter (the audience)
///   nonce         = tstr   ; the `nonce` request parameter value
///   jwkThumbprint = bstr / null  ; RFC 7638 thumbprint of the response-encryption key, else null
///   responseUri   = tstr   ; the `response_uri` (or `redirect_uri`) request parameter
/// ```
///
/// The handover folds **one** SHA-256 over the CBOR-encoded inner `OpenID4VPHandoverInfo` array
/// (not a per-field hash): every request parameter is therefore bound, and any tampered field
/// changes the single hash. The holder (here the test issuer) and the verifier MUST build the
/// transcript identically, so this one function is the single authoritative source for both halves.
///
/// Per OpenID4VP 1.0 §B.2.6 the four `OpenID4VPHandoverInfo` elements map to the SDK as:
/// - `clientId` — the `client_id` request parameter (the verifier's `audience`).
/// - `nonce` — the `nonce` request parameter is a text string; the SDK carries the nonce as bytes,
///   so the conformant text value is its base64url-unpadded form (identical to the value an SD-JWT VC
///   KB-JWT echoes), keeping the two formats' nonce-on-the-wire byte-identical.
/// - `jwkThumbprint` — `null`: this SDK does not negotiate response encryption (no `direct_post.jwt`),
///   so there is no verifier encryption key to thumbprint; the spec mandates `null` in that case.
/// - `responseUri` — the **actual** `response_uri` (or `redirect_uri`) request parameter, a value
///   distinct from `clientId`. The spec's §B.2.6 fourth element MUST be this real endpoint, NOT the
///   `client_id`, so the SDK carries it as the first-class [`PresentationRequest::response_uri`].
#[must_use]
pub fn oid4vp_handover_transcript(audience: &str, nonce: &[u8], response_uri: &str) -> Vec<u8> {
    use base64ct::{Base64UrlUnpadded, Encoding as _};

    // OpenID4VPHandoverInfo = [clientId, nonce, jwkThumbprint, responseUri] (OpenID4VP 1.0 §B.2.6).
    // `nonce` is the text `nonce` request parameter; the SDK's bytes map to their base64url form.
    let nonce_text = Base64UrlUnpadded::encode_string(nonce);
    let handover_info = CborValue::Array(vec![
        CborValue::Text(audience.to_owned()),
        CborValue::Text(nonce_text),
        // jwkThumbprint: null — no response encryption negotiated (unencrypted flow, §B.2.6).
        CborValue::Null,
        // responseUri: the actual `response_uri` request parameter — §B.2.6's 4th element, distinct
        // from the client_id.
        CborValue::Text(response_uri.to_owned()),
    ]);
    let handover_info_bytes = encode_cbor(&handover_info);
    // The crate's single authoritative SHA-256 (DRY — `crate::crypto` is the one digest helper),
    // adapting its fixed `[u8; 32]` to the `Vec<u8>` the CBOR `bstr` carries.
    let handover_info_hash = crate::crypto::sha256(&handover_info_bytes).to_vec();

    // OpenID4VPHandover = ["OpenID4VPHandover", OpenID4VPHandoverInfoHash].
    let handover = CborValue::Array(vec![
        CborValue::Text("OpenID4VPHandover".to_owned()),
        CborValue::Bytes(handover_info_hash),
    ]);
    // SessionTranscript = [null, null, OpenID4VPHandover].
    let transcript = CborValue::Array(vec![CborValue::Null, CborValue::Null, handover]);
    encode_cbor(&transcript)
}

/// Encode a plain CBOR value into an in-memory `Vec` (infallible — a `Vec` writer never errors). The
/// one authoritative CBOR-into-Vec helper [`crate::cbor_to_vec`] (DRY — Principle III).
fn encode_cbor(value: &CborValue) -> Vec<u8> {
    crate::cbor_to_vec(value)
}

#[cfg(test)]
mod tests;
