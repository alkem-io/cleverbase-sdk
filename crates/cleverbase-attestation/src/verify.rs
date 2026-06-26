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
//!
//! `qualified_status` is **only meaningful for a VALID credential** and is therefore only computed
//! when `valid == true`. The determination matches the credential's CLAIMED `x5c`/`x5chain` leaf
//! against the TL **without re-verifying its signature**; since X.509 certificates are public, an
//! attacker could embed a real qualified issuer's leaf and sign with their own key. Only a VALID
//! verdict means the always-on bar has signature-verified AND trust-anchored that exact leaf, so the
//! qualified status is trustworthy. On an INVALID credential `qualified_status` stays `None` (never a
//! `Qualified` read off an unverified claimed cert — SC-002/SC-007). The status is read **at the
//! credential's issuance/relevant time** (SD-JWT VC `iat`/`nbf`; mdoc MSO `signed`/`validFrom`), not
//! at the verification instant.

use crate::mdoc::{self, MdocVerifyMeta, MdocVerifyParams};
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

    // The per-format bar produces the verdict AND, for mdoc, the `MdocVerifyMeta` byproducts (the
    // per-document claimed `(cert, issuance_time)` the qualified gate folds) the SAME decode already
    // computed — so the gate reads those cached values rather than re-decoding the `DeviceResponse`.
    // SD-JWT VC has no mdoc meta (`None`).
    let (mut result, mdoc_meta): (VerificationResult, Option<MdocVerifyMeta>) =
        match (presentation, request) {
            // --- With an OpenID4VP request: run the binding verifier (bar + nonce/audience). ------
            (Presentation::SdJwtVc(p), Some(req)) => (
                openid4vp::verify_response(
                    &VpToken::SdJwtVc(p),
                    req,
                    policy,
                    anchors,
                    ctx.now_unix,
                    ctx.role,
                    ctx.status,
                ),
                None,
            ),
            (
                Presentation::Mdoc {
                    device_response,
                    audience,
                },
                Some(req),
            ) => {
                // An mdoc verified against a request must carry the addressed audience (the OpenID4VP
                // delivery channel's `client_id`); without it the OpenID4VP handover cannot be
                // reconstructed and the binding cannot be checked. This is `MissingRequestBinding`
                // condition (1) — the addressed-audience-absent case (see the `ReasonCode` rustdoc; one
                // of three distinct "binding material absent" conditions the code intentionally covers).
                let Some(audience) = audience else {
                    return VerificationResult::invalid(ReasonCode::MissingRequestBinding);
                };
                openid4vp::verify_response_with_meta(
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

            // --- Without a request: the per-format always-on bar alone. ---------------------------
            (Presentation::SdJwtVc(p), None) => {
                let input = SdJwtVcInput {
                    presentation: p,
                    anchors,
                    role: ctx.role,
                    // No request ⇒ no `aud`/`nonce` challenge (so no replay/audience protection). A
                    // present KB-JWT is STILL signature- and `sd_hash`-verified by the bar; only the
                    // request-binding (`aud`/`nonce`) checks are skipped. See `kb_challenge_without_request`.
                    key_binding: kb_challenge_without_request(p),
                    now_unix: ctx.now_unix,
                    status: ctx.status,
                };
                (sdjwtvc::verify_sd_jwt_vc(&input), None)
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
                let (result, meta) = mdoc::verify_with_meta(device_response, anchors, &params);
                (result, Some(meta))
            }
        };

    // Qualified-status gate (T019) — OFF by default. The seam is here so the always-on verdict above
    // is complete on its own; when the opt-in gate is enabled — via the verifier
    // [`VerificationPolicy::qualified_gate`] OR the per-call [`VerifyContext::qualified_gate`] flag —
    // it ADDITIVELY populates `result.qualified_status` (never changing the always-on
    // `valid`/reasons — SC-007), and never fabricates "qualified": absent data → `Indeterminate`.
    //
    // It is gated on `result.valid`: qualified status is computed ONLY for a VALID credential. The
    // determination resolves the issuer cert from the credential's CLAIMED `x5c`/`x5chain` leaf
    // WITHOUT re-verifying its signature — X.509 certs are public, so an attacker could embed a real
    // qualified issuer's leaf in `x5c` and sign with their own key. On an INVALID credential the
    // always-on bar already set `valid = false` (e.g. `Tamper`), so reporting `Qualified` off that
    // claimed leaf would be a false "qualified". Only when `valid == true` has the always-on bar
    // signature-verified AND trust-anchored that exact leaf, so the qualified status is meaningful;
    // otherwise `qualified_status` stays `None` (SC-007). For mdoc the gate folds the cached
    // `mdoc_meta.claimed_issuers` the VALID bar pass surfaced (no second `DeviceResponse` decode).
    if (policy.qualified_gate || ctx.qualified_gate) && result.valid {
        result.qualified_status = Some(qualified_status_for(presentation, ctx, mdoc_meta.as_ref()));
    }

    result
}

/// Run the opt-in TS 119 615 cl. 4.12 determination for the presentation's issuer(s) at the
/// **relevant time derived from the CREDENTIAL** — NOT the verification instant `ctx.now_unix` —
/// reading the host-supplied national Trusted List ([`VerifyContext::qualified_trust_list`]) only
/// after it **authenticates** against the host-configured scheme-operator anchors
/// ([`VerifyContext::qualified_scheme_anchors`]).
///
/// ## Relevant time = the credential's issuance time (contracts/qualified-status-gate.md)
///
/// The status MUST be read **at the credential's issuance/relevant time, NOT "now"**: an issuer not
/// yet granted `EAA/Q` when it signed a credential, but granted later, must NOT be reported
/// `Qualified` for that credential (a false "qualified"). The relevant time is therefore derived from
/// the credential itself — SD-JWT VC `iat` (fallback `nbf`) via [`sdjwtvc::issuance_time_unix`]; mdoc
/// MSO `validityInfo.signed` per document, surfaced by the always-on bar pass in
/// [`MdocVerifyMeta::claimed_issuers`] — and passed as `relevant_time_unix`. A credential
/// that carries **no** issuance time fails closed ([`QualifiedStatus::Indeterminate`]); `ctx.now_unix`
/// is never silently substituted.
///
/// ## Multi-document fold
///
/// SD-JWT VC carries a single credential, so its claimed JWS `x5c` leaf + `iat` decide the status
/// directly. An mdoc `DeviceResponse` MAY carry MORE THAN ONE document (the always-on bar verifies +
/// merges the attributes of every one, possibly from different issuers), so the determination is
/// computed PER DOCUMENT — each against that document's own issuer cert AND its own issuance time —
/// and folded so a `Qualified` verdict requires **every** document to qualify: a single `Qualified`
/// read from `documents[0]` must never under-cover a result that also surfaces a non-qualified
/// `documents[1]`'s attributes (SC-007). The fold is fail-closed: `Qualified` only if all qualify;
/// else `Indeterminate` if any document is undecidable; else `NotQualified`.
///
/// Each per-document/credential delegate authenticates the TL (signer chains to a scheme anchor + not
/// stale) **at `ctx.now_unix`** (the verification instant) BEFORE reading status, then reads the
/// issuer's granted/withdrawn status **at that credential's/document's own relevant time**. The two
/// times are deliberately distinct: TL freshness and the TL-signer's chain validity are "now"
/// properties — a stale or expired-signer trust snapshot must never be trusted just because the
/// credential being checked is old — whereas the status read is "status at the relevant time". When a
/// signing cert OR the issuance time cannot be read, no trust list was supplied, or the list fails to
/// authenticate, it yields [`QualifiedStatus::Indeterminate`] — the data needed to decide is absent or
/// untrustworthy (never a false "qualified", SC-007).
///
/// [`QualifiedStatus::Indeterminate`]: crate::types::QualifiedStatus::Indeterminate
fn qualified_status_for(
    presentation: &Presentation<'_>,
    ctx: &VerifyContext<'_>,
    mdoc_meta: Option<&MdocVerifyMeta>,
) -> crate::types::QualifiedStatus {
    use crate::types::QualifiedStatus;
    let Some(trust_list) = ctx.qualified_trust_list else {
        // The gate is enabled but the host supplied no national TL → the data is unreachable.
        return QualifiedStatus::Indeterminate;
    };
    // Resolve the status of one claimed signing cert. TWO distinct times are threaded (the load-
    // bearing split): the TL is AUTHENTICATED at `ctx.now_unix` (the verification instant — TL
    // freshness `now >= NextUpdate` and the TL-signer's chain validity are "now" properties), while the
    // issuer's granted/withdrawn status is READ at the credential's OWN relevant time. A missing cert OR
    // a missing issuance time fails closed (Indeterminate) — the status is never read at "now".
    let status_of = |cert: Option<Vec<u8>>, relevant_time: Option<i64>| -> QualifiedStatus {
        match (cert, relevant_time) {
            (Some(cert_der), Some(relevant_time_unix)) => crate::qualified::qualified_status(
                &cert_der,
                ctx.now_unix,
                relevant_time_unix,
                trust_list,
                ctx.qualified_scheme_anchors,
            ),
            // No signing cert, or no issuance time to read the status at → undecidable, fail closed.
            _ => QualifiedStatus::Indeterminate,
        }
    };
    match presentation {
        Presentation::SdJwtVc(p) => status_of(
            sdjwtvc::issuer_signing_cert_der(p),
            sdjwtvc::issuance_time_unix(p),
        ),
        Presentation::Mdoc { .. } => {
            // Decide over EVERY document's issuer at that document's OWN issuance time; fold so
            // `Qualified` requires all to qualify. The gate runs only on a VALID credential, where the
            // always-on bar already extracted EACH document's `(ds_cert_der, signed)` and surfaced them
            // in `mdoc_meta.claimed_issuers` — fold those CACHED pairs (the bar's single decode; no
            // second `DeviceResponse` decode + per-document COSE/MSO re-parse). On a VALID mdoc `signed`
            // is mandatory, so the cached `(cert, signed)` pairs are the single authoritative issuer
            // view. A `None` meta (no claimed issuers to fold) fails closed — empty fold →
            // `Indeterminate` — never a false "qualified".
            let claimed = mdoc_meta.map(|meta| meta.claimed_issuers.as_slice());
            fold_qualified(
                claimed
                    .unwrap_or(&[])
                    .iter()
                    .map(|(cert, issued)| status_of(Some(cert.clone()), Some(*issued))),
            )
        }
    }
}

/// Fold the per-document qualified statuses of a multi-document response into one verdict, fail-closed:
/// `Qualified` only if **every** document qualifies; otherwise `Indeterminate` if any document is
/// undecidable; otherwise `NotQualified`. An empty iterator yields `Indeterminate` (nothing to
/// decide). This guarantees a `Qualified` verdict never under-covers a response whose merged
/// attributes include a non-qualified document (SC-007).
///
/// The fold keeps the **most severe** status seen, by the precedence `Indeterminate` (undecidable —
/// most severe) > `NotQualified` > `Qualified` (every document must clear to land here). The empty
/// case has no status to start from, so it defaults — explicitly and fail-closed — to `Indeterminate`.
fn fold_qualified<I>(statuses: I) -> crate::types::QualifiedStatus
where
    I: IntoIterator<Item = crate::types::QualifiedStatus>,
{
    use crate::types::QualifiedStatus;
    // Most-severe-wins: `max_by_key` over the severity rank folds the per-document statuses to the
    // single dominating one. Empty (no documents) → fail-closed `Indeterminate` (nothing to assert).
    let severity = |status: &QualifiedStatus| match status {
        QualifiedStatus::Qualified => 0u8,
        QualifiedStatus::NotQualified => 1,
        QualifiedStatus::Indeterminate => 2,
    };
    statuses
        .into_iter()
        .max_by_key(|status| severity(status))
        .unwrap_or(QualifiedStatus::Indeterminate)
}

/// For a request-less SD-JWT VC, supply **no** holder-binding challenge (always `None`). This gates
/// **only** the `aud`/`nonce` request-binding checks — there is no request to bind to, so a request-less
/// verify provides **no replay/audience protection**. It does NOT relax the cryptographic holder check:
/// when the presentation carries a KB-JWT, the always-on bar
/// ([`sdjwtvc::check_holder_binding`](crate::sdjwtvc)) STILL verifies its ES256 signature (under the
/// issuer-bound `cnf` key) AND its `sd_hash` binding to the presented issuer-JWS-plus-disclosures — so a
/// present-but-forged/tampered KB-JWT is rejected ([`ReasonCode::HolderBinding`]) even with no request.
/// A presentation that simply omits the KB-JWT is an issuer-only credential and is accepted. Kept as a
/// named seam so the request-less intent is explicit at the call site.
const fn kb_challenge_without_request(_presentation: &str) -> Option<KeyBindingChallenge<'static>> {
    None
}

#[cfg(test)]
mod tests;
