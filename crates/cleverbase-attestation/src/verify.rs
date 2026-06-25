//! The always-on `verify` entry point (contracts/verifier.md) — T016.
//!
//! The global verifier: detect the credential format (SD-JWT VC or ISO mdoc; unsupported →
//! [`ReasonCode::UnsupportedFormat`]), run the matching per-format always-on bar (issuer signature +
//! issuer **trust** via the [`TrustAnchorSource`], validity window, revocation/**status**, holder
//! binding, selective-disclosure integrity), and — when an OpenID4VP `request` is supplied — the
//! request **binding** (nonce echo + audience) via [`crate::openid4vp`]. Any failed check yields
//! `valid = false` with a specific [`ReasonCode`] (no false-accept — SC-002).
//!
//! ## Sans-IO
//!
//! Like the rest of the core, this performs no network I/O: the trust anchors are passed in
//! (refreshed by a host-driven step beforehand), the validity instant is supplied, and the
//! revocation/**status** outcome is resolved by the host through [`crate::status`] and passed in as
//! a [`StatusOutcome`]. The format verifiers ([`crate::sdjwtvc`], [`crate::mdoc`]) own the crypto.
//!
//! ## Qualified-status gate (T019 — not built yet)
//!
//! The opt-in eIDAS qualified-status determination ([`crate::qualified`]) is a separate, off-by-
//! default gate (T019). [`VerifyContext::qualified_gate`] is the seam: it is **off by default**, the
//! always-on bar runs and returns a complete verdict without it, and `qualified_status` stays `None`
//! until the gate lands. Enabling it today is a no-op (clearly marked below), never a false
//! "qualified" (SC-007).

use crate::mdoc::{self, MdocVerifyParams};
use crate::openid4vp::{self, MdocVpToken, PresentationRequest, VpToken};
use crate::sdjwtvc::{self, KeyBindingChallenge, SdJwtVcInput};
use crate::status::StatusOutcome;
use crate::trust::TrustAnchorSource;
use crate::types::{Format, IssuerRole, ReasonCode, VerificationPolicy, VerificationResult};

/// A presented credential, in one of the two mandated formats (the typed input the C-ABI wire maps
/// to; native callers build it directly).
///
/// SD-JWT VC is a compact text presentation; mdoc is a CBOR `DeviceResponse` paired with the audience
/// it was addressed to in an OpenID4VP flow (`None` for a bare offline presentation with no request
/// binding). Use [`detect_format`] to classify raw bytes before constructing this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Presentation<'a> {
    /// A compact SD-JWT VC presentation (`<issuer-JWS>~<D>…~<optional KB-JWT>`).
    SdJwtVc(&'a str),
    /// An ISO/IEC 18013-5 mdoc `DeviceResponse`, with the OpenID4VP addressed audience when one
    /// applies (the verifier's `client_id`); `None` for a bare presentation verified without a
    /// request binding.
    Mdoc {
        /// The CBOR-encoded `DeviceResponse`.
        device_response: &'a [u8],
        /// The audience (`client_id`) the response was addressed to, when verifying against an
        /// OpenID4VP request.
        audience: Option<&'a str>,
    },
}

impl Presentation<'_> {
    /// The credential format of this presentation.
    #[must_use]
    pub const fn format(&self) -> Format {
        match self {
            Self::SdJwtVc(_) => Format::SdJwtVc,
            Self::Mdoc { .. } => Format::Mdoc,
        }
    }
}

/// The remaining per-format-bar inputs the host supplies to [`verify`] (the validity instant, the
/// trust-anchor role, the resolved status outcome, and the mdoc session transcript / qualified-gate
/// seam).
///
/// These are sans-IO inputs: `now_unix` is the verification instant; `role` selects the trust anchor
/// (research D5); `status` is the [`crate::status`] outcome the host already resolved; and
/// `session_transcript` is the mdoc `DeviceAuth` transport binding for a **non-OpenID4VP**
/// presentation (an OpenID4VP `request` overrides it with the reconstructed handover).
#[derive(Debug, Clone)]
pub struct VerifyContext<'a> {
    /// The verification instant (Unix seconds) the validity window is checked against.
    pub now_unix: i64,
    /// The issuer role under which trust is anchored.
    pub role: IssuerRole,
    /// The revocation/status outcome resolved by the host (via [`crate::status::check_status`]).
    pub status: StatusOutcome,
    /// The mdoc `SessionTranscript` the `DeviceAuth` is bound to, for a presentation **without** an
    /// OpenID4VP request (with a request, the handover is reconstructed from the request instead).
    pub session_transcript: Option<&'a [u8]>,
    /// **Off by default** seam for the opt-in eIDAS qualified-status gate (T019, not built yet).
    /// When `false` (the default) the always-on bar runs unchanged and `qualified_status` stays
    /// `None`. The gate is wired in T019; enabling it today is a no-op (the always-on bar must work
    /// without it — SC-007).
    pub qualified_gate: bool,
}

impl Default for VerifyContext<'_> {
    /// The offline-suite default: epoch instant, PID role, no status, no transcript, gate off.
    fn default() -> Self {
        Self {
            now_unix: 0,
            role: IssuerRole::Pid,
            status: StatusOutcome::NoStatus,
            session_transcript: None,
            qualified_gate: false,
        }
    }
}

/// Detect the credential format of raw presentation bytes, or `None` if neither format is
/// recognized (the caller maps `None` → [`ReasonCode::UnsupportedFormat`] — never a guess).
///
/// - **SD-JWT VC**: valid UTF-8 beginning with a compact JWS (`header.payload.signature`, base64url)
///   followed by a `~` (the disclosure separator). The first segment must have exactly two `.`.
/// - **mdoc**: a CBOR map carrying a `documents` array (the ISO/IEC 18013-5 `DeviceResponse` shape).
#[must_use]
pub fn detect_format(presentation: &[u8]) -> Option<Format> {
    if let Ok(text) = core::str::from_utf8(presentation) {
        if looks_like_sd_jwt_vc(text) {
            return Some(Format::SdJwtVc);
        }
    }
    if looks_like_mdoc(presentation) {
        return Some(Format::Mdoc);
    }
    None
}

/// Whether `text` is a compact SD-JWT VC: a `~`-bearing string whose first `~`-segment is a
/// three-part (`header.payload.signature`) compact JWS.
fn looks_like_sd_jwt_vc(text: &str) -> bool {
    let Some((jws, _rest)) = text.split_once('~') else {
        return false;
    };
    jws.split('.').count() == 3 && !jws.starts_with('.') && !jws.contains('~')
}

/// Whether `bytes` decode as a CBOR `DeviceResponse` (a map with a `documents` entry).
fn looks_like_mdoc(bytes: &[u8]) -> bool {
    let Ok(value) = ciborium::from_reader::<ciborium::value::Value, _>(bytes) else {
        return false;
    };
    value
        .as_map()
        .is_some_and(|map| map.iter().any(|(k, _)| k.as_text() == Some("documents")))
}

/// The always-on `verify` entry point (contracts/verifier.md).
///
/// Detects the format (rejecting an unsupported one, or one the `policy` does not enable, as
/// [`ReasonCode::UnsupportedFormat`]), runs the matching per-format always-on bar against the
/// configured `anchors`, and — when `request` is supplied — the OpenID4VP binding (nonce + audience).
/// Returns a [`VerificationResult`] that is `valid = true` only when every check passed, else
/// `valid = false` with a specific [`ReasonCode`] (no false-accept — SC-002).
#[must_use]
pub fn verify<A: TrustAnchorSource + ?Sized>(
    presentation: &Presentation<'_>,
    policy: &VerificationPolicy,
    anchors: &A,
    ctx: &VerifyContext<'_>,
    request: Option<&PresentationRequest>,
) -> VerificationResult {
    // Format gate: the policy may restrict which formats are accepted (an empty set = both).
    let format = presentation.format();
    if !policy.formats.is_empty() && !policy.formats.contains(&format) {
        return VerificationResult::invalid(ReasonCode::UnsupportedFormat);
    }

    let result = match (presentation, request) {
        // --- With an OpenID4VP request: run the binding verifier (bar + nonce/audience). ----------
        (Presentation::SdJwtVc(p), Some(req)) => openid4vp::verify_response(
            &VpToken::SdJwtVc(p),
            req,
            policy,
            anchors,
            ctx.now_unix,
            ctx.role,
            ctx.status,
        ),
        (
            Presentation::Mdoc {
                device_response,
                audience,
            },
            Some(req),
        ) => {
            // An mdoc verified against a request must carry the addressed audience (the OpenID4VP
            // delivery channel's `client_id`); without it the binding cannot be checked.
            let Some(audience) = audience else {
                return VerificationResult::invalid(ReasonCode::MissingRequestBinding);
            };
            openid4vp::verify_response(
                &VpToken::Mdoc(MdocVpToken {
                    audience: (*audience).to_owned(),
                    device_response: (*device_response).to_vec(),
                }),
                req,
                policy,
                anchors,
                ctx.now_unix,
                ctx.role,
                ctx.status,
            )
        }

        // --- Without a request: the per-format always-on bar alone. -------------------------------
        (Presentation::SdJwtVc(p), None) => {
            let input = SdJwtVcInput {
                presentation: p,
                anchors,
                role: ctx.role,
                // No request ⇒ no holder-binding challenge required (an issuer-only presentation is
                // accepted; a KB-bound one is still verified for signature integrity downstream).
                key_binding: kb_challenge_without_request(p),
                now_unix: ctx.now_unix,
                status: ctx.status,
            };
            sdjwtvc::verify_sd_jwt_vc(&input)
        }
        (
            Presentation::Mdoc {
                device_response, ..
            },
            None,
        ) => {
            let params = MdocVerifyParams {
                now_unix: ctx.now_unix,
                session_transcript: ctx.session_transcript,
                role: ctx.role,
                status: ctx.status,
            };
            mdoc::verify(device_response, anchors, &params)
        }
    };

    // Qualified-status gate (T019) — OFF by default and not built yet. The seam is here so the
    // always-on verdict above is complete on its own; when `qualified_gate` is enabled (T019), the
    // gate would populate `result.qualified_status`. Until then it is a no-op that never asserts
    // "qualified" (SC-007).
    if ctx.qualified_gate {
        // Intentionally a no-op pending T019: the always-on bar already produced the verdict, and we
        // must never fabricate a qualified status. T019 wires `crate::qualified` here.
    }

    result
}

/// For a request-less SD-JWT VC, do not impose a holder-binding challenge: a presentation that omits
/// the KB-JWT is an issuer-only credential (accepted), and one that carries a KB-JWT still has its
/// signature/`sd_hash` integrity checked by the bar — only the `aud`/`nonce` *challenge* match is
/// skipped (there is no request to bind to). Returns `None` always; kept as a named seam so the
/// intent is explicit at the call site.
const fn kb_challenge_without_request(_presentation: &str) -> Option<KeyBindingChallenge<'static>> {
    None
}

#[cfg(test)]
mod tests;
