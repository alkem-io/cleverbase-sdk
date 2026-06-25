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
//! ## Qualified-status gate (T019)
//!
//! The opt-in eIDAS qualified-status determination ([`crate::qualified`]) is a separate, off-by-
//! default gate. [`VerifyContext::qualified_gate`] is the seam: it is **off by default**, in which
//! case the always-on bar runs and returns a complete verdict and `qualified_status` stays `None`.
//! When enabled (and a [`VerifyContext::qualified_trust_list`] is supplied), the gate populates
//! `VerificationResult.qualified_status` via [`crate::qualified::qualified_status`], which first
//! **authenticates** the national TL (chain-validates its signer against
//! [`VerifyContext::qualified_scheme_anchors`] + checks `NextUpdate` staleness): a forged / unsigned /
//! unchained / stale TL — or no scheme anchor configured — yields `Indeterminate`, never `Qualified`
//! (fail-closed). Disabling the gate leaves the always-on verdict **byte-identical** to a gate-off run
//! (no false "qualified" — SC-007).

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
    /// **Off by default** seam for the opt-in eIDAS qualified-status gate (T019). When `false` (the
    /// default) the always-on bar runs unchanged and `qualified_status` stays `None`. When `true`
    /// **and** a [`Self::qualified_trust_list`] is supplied, the gate populates
    /// `qualified_status`; the always-on verdict is byte-identical either way (SC-007).
    pub qualified_gate: bool,
    /// The national Trusted List the opt-in qualified gate reads (off-path unless `qualified_gate` is
    /// set). `None` with the gate enabled yields an honest [`QualifiedStatus::Indeterminate`]
    /// (unreachable data — never a false "qualified"). Host-supplied (the core stays sans-IO).
    ///
    /// [`QualifiedStatus::Indeterminate`]: crate::types::QualifiedStatus::Indeterminate
    pub qualified_trust_list: Option<&'a crate::qualified::QualifiedTrustList>,
    /// The scheme-operator trust anchor(s) (DER) the opt-in gate authenticates the national TL
    /// against (off-path unless `qualified_gate` is set). The gate chain-validates the TL's embedded
    /// signer against these before reading status; an empty set (the default) with the gate enabled
    /// means the TL cannot be authenticated → [`QualifiedStatus::Indeterminate`] (can't authenticate
    /// ⇒ can't assert qualified — never a false "qualified"). Host-supplied (the core stays sans-IO).
    ///
    /// [`QualifiedStatus::Indeterminate`]: crate::types::QualifiedStatus::Indeterminate
    pub qualified_scheme_anchors: &'a [Vec<u8>],
}

impl Default for VerifyContext<'_> {
    /// The offline-suite default: epoch instant, PID role, no status, no transcript, gate off, no
    /// qualified trust list.
    fn default() -> Self {
        Self {
            now_unix: 0,
            role: IssuerRole::Pid,
            status: StatusOutcome::NoStatus,
            session_transcript: None,
            qualified_gate: false,
            qualified_trust_list: None,
            qualified_scheme_anchors: &[],
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

    let mut result = match (presentation, request) {
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

    // Qualified-status gate (T019) — OFF by default. The seam is here so the always-on verdict above
    // is complete on its own; when the opt-in gate is enabled — via the verifier
    // [`VerificationPolicy::qualified_gate`] OR the per-call [`VerifyContext::qualified_gate`] flag —
    // it ADDITIVELY populates `result.qualified_status` (never changing the always-on
    // `valid`/reasons — SC-007). It runs independently of the always-on verdict (even an INVALID
    // credential can report its issuer's qualified status), and never fabricates "qualified": absent
    // data → `Indeterminate`.
    if policy.qualified_gate || ctx.qualified_gate {
        result.qualified_status = Some(qualified_status_for(presentation, ctx));
    }

    result
}

/// Run the opt-in TS 119 615 cl. 4.12 determination for the presentation's issuer at the relevant
/// time (`ctx.now_unix`), reading the host-supplied national Trusted List ([`VerifyContext::
/// qualified_trust_list`]) only after it **authenticates** against the host-configured
/// scheme-operator anchors ([`VerifyContext::qualified_scheme_anchors`]).
///
/// Resolves the credential's claimed signing certificate (the SD-JWT VC JWS `x5c` leaf / the mdoc
/// `IssuerAuth` x5chain leaf) and delegates to [`crate::qualified::qualified_status`], which
/// chain-authenticates the TL's signer against the scheme anchors and checks `NextUpdate` staleness
/// before reading any status. When the cert cannot be read, no trust list was supplied, or the list
/// fails to authenticate, it returns [`QualifiedStatus::Indeterminate`] — the data needed to decide
/// is absent or untrustworthy (never a false "qualified", SC-007).
///
/// [`QualifiedStatus::Indeterminate`]: crate::types::QualifiedStatus::Indeterminate
fn qualified_status_for(
    presentation: &Presentation<'_>,
    ctx: &VerifyContext<'_>,
) -> crate::types::QualifiedStatus {
    use crate::types::QualifiedStatus;
    let Some(trust_list) = ctx.qualified_trust_list else {
        // The gate is enabled but the host supplied no national TL → the data is unreachable.
        return QualifiedStatus::Indeterminate;
    };
    let issuer_cert_der = match presentation {
        Presentation::SdJwtVc(p) => sdjwtvc::issuer_signing_cert_der(p),
        Presentation::Mdoc {
            device_response, ..
        } => mdoc::issuer_signing_cert_der(device_response),
    };
    // The signing cert cannot be read from the presentation → the data needed is absent. Otherwise
    // the determination authenticates the TL (signer chains to a scheme anchor + not stale) BEFORE
    // reading status — a forged/unsigned/unchained/stale TL yields Indeterminate, never Qualified.
    issuer_cert_der.map_or(QualifiedStatus::Indeterminate, |cert_der| {
        crate::qualified::qualified_status(
            &cert_der,
            ctx.now_unix,
            trust_list,
            ctx.qualified_scheme_anchors,
        )
    })
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
