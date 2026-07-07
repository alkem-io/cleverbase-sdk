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
use crate::sdjwtvc::{self, SdJwtVcInput};
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
    /// The revocation/status outcomes resolved by the host (via [`crate::status::check_status`]), one
    /// **per presented document**, positional. SD-JWT VC carries a single credential (index `0`); an mdoc
    /// `DeviceResponse` MAY carry more than one document, each with its own status pointer, so `statuses[i]`
    /// is `documents[i]`'s outcome. A document with no covering entry fails closed to
    /// [`StatusOutcome::Unavailable`] — one outcome is never silently reused across documents (SC-002). The
    /// default [`crate::status::DEFAULT_STATUSES`] covers exactly one document.
    pub statuses: &'a [StatusOutcome],
    /// The host-fetched **signed** Token Status List tokens, keyed by list URI (the credential's
    /// `status.status_list.uri`) → the raw token bytes (a `statuslist+jwt` compact JWS or an
    /// `application/statuslist+cwt` tagged `COSE_Sign1`). When a presented credential declares a Token
    /// Status List reference AND a token is supplied here for its URI, the core AUTHENTICATES that token
    /// in-core ([`crate::status::verify_status_list_token`]) — verifying its signature against a key
    /// authorized by the credential's own trust anchor, binding `sub` to the URI, checking freshness,
    /// and reading the revocation bit itself — and that outcome OVERRIDES the positional
    /// [`Self::statuses`] entry for that credential/document. With no token supplied for a URI (or for a
    /// CRL / no reference), the positional `statuses` outcome is used exactly as before. Host-supplied
    /// (the core stays sans-IO: the host does the fetch; the core does the authentication). The default
    /// [`crate::status::DEFAULT_STATUS_TOKENS`] is empty (⇒ the positional seam alone, unchanged).
    pub status_tokens: &'a std::collections::BTreeMap<String, Vec<u8>>,
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
    /// The offline-suite default: epoch instant, PID role, no status (positional + no signed tokens),
    /// no transcript, gate off, no qualified trust list.
    fn default() -> Self {
        Self {
            now_unix: 0,
            role: IssuerRole::Pid,
            statuses: crate::status::DEFAULT_STATUSES,
            status_tokens: &crate::status::DEFAULT_STATUS_TOKENS,
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
    // `jws` is the segment BEFORE the first `~`, so it cannot contain a `~` (no redundant re-check).
    jws.split('.').count() == 3 && !jws.starts_with('.')
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
///
/// **DCQL scope (single presentation).** When `request` carries a DCQL query, this enforces it at the
/// single-Credential-Query level: `valid = true` means the presentation matched **at least one**
/// Credential Query of its format (format + `meta` + `claims`/`claim_sets`/`values`). It does NOT
/// assert the request's **set-level completeness** — `credential_sets` (required option-sets) and
/// `multiple` cardinality — which is the job of the native [`crate::openid4vp::verify_vp_token`] over a
/// multi-presentation `vp_token`. An integrator answering a `credential_sets` request across several
/// presentations MUST fold set-level completeness itself; a per-presentation `valid = true` does not
/// mean "the whole DCQL request is satisfied".
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
    //
    // The request-less SD-JWT VC bar takes a SINGLE status outcome (one credential): `status_head` is
    // `statuses[0]`, failing closed to `Unavailable` on an empty slice. Every OTHER arm threads the FULL
    // positional slice `ctx.statuses` (SD-JWT VC reads index 0 inside the binding path; mdoc checks
    // `documents[i]` against `statuses[i]`), so a multi-document response is verified per document —
    // one outcome is never silently reused across documents (SC-002).
    let status_head = ctx
        .statuses
        .first()
        .copied()
        .unwrap_or(StatusOutcome::Unavailable);
    let (mut result, mdoc_meta): (VerificationResult, Option<MdocVerifyMeta>) =
        match (presentation, request) {
            // --- With an OpenID4VP request: run the binding verifier (bar + nonce/audience). ------
            (Presentation::SdJwtVc(p), Some(req)) => (
                // Delegate to the meta-returning entry (dropping the always-`None` SD-JWT meta) so the
                // in-core `status_tokens` reach the bound bar — the public `verify_response` keeps its
                // status-token-less signature for its many native callers (DRY: one bound bar body).
                openid4vp::verify_response_with_meta(
                    &VpToken::SdJwtVc(p),
                    req,
                    policy,
                    anchors,
                    ctx.now_unix,
                    ctx.role,
                    openid4vp::StatusInputs {
                        positional: ctx.statuses,
                        tokens: ctx.status_tokens,
                    },
                )
                .0,
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
                        // Borrowed, not cloned: `device_response` is an attacker-sized buffer, and the
                        // verifier only reads it.
                        audience,
                        device_response,
                    }),
                    req,
                    policy,
                    anchors,
                    ctx.now_unix,
                    ctx.role,
                    openid4vp::StatusInputs {
                        positional: ctx.statuses,
                        tokens: ctx.status_tokens,
                    },
                )
            }

            // --- Without a request: the per-format always-on bar alone. ---------------------------
            (Presentation::SdJwtVc(p), None) => {
                let input = SdJwtVcInput {
                    presentation: p,
                    anchors,
                    role: ctx.role,
                    // No request ⇒ no `aud`/`nonce` challenge, so no replay/audience protection (and the
                    // KB-JWT `iat` freshness window is not enforced). A present KB-JWT is STILL signature-
                    // and `sd_hash`-verified by the bar (see `sdjwtvc::check_holder_binding`); only the
                    // request-binding checks are skipped.
                    key_binding: None,
                    now_unix: ctx.now_unix,
                    status: status_head,
                    status_tokens: ctx.status_tokens,
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
                    // The request-less mdoc path carries the FULL positional slice, so a multi-document
                    // response is checked per document (documents[i] against statuses[i]).
                    statuses: ctx.statuses,
                    status_tokens: ctx.status_tokens,
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
/// The TL is authenticated (signer chains to a scheme anchor + not stale) **once at `ctx.now_unix`**
/// (the verification instant) BEFORE any status read — it is invariant across the response's documents,
/// so authenticating per document would be wasted work (finding #8). Each document's issuer status is
/// then read **at that document's own relevant time**. The two times are deliberately distinct: TL
/// freshness and the TL-signer's chain validity are "now" properties — a stale or expired-signer trust
/// snapshot must never be trusted just because the credential being checked is old — whereas the status
/// read is "status at the relevant time". The PRO-4.12.4-03 type indication is the credential's
/// issuer-signed **`category`** (SD-JWT VC claim / mdoc `category` data element per ETSI TS 119 472-1),
/// enforced for BOTH formats. When a signing cert OR the issuance time OR the qualifying `category`
/// cannot be read, no trust list was supplied, or the list fails to authenticate, it yields
/// [`QualifiedStatus::Indeterminate`] — the data needed to decide is absent or untrustworthy (never a
/// false "qualified", SC-007).
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
    // AUTHENTICATE the national TL ONCE, at `ctx.now_unix` (the verification instant — TL freshness
    // `now >= NextUpdate` and the TL-signer's chain validity are "now" properties, invariant across the
    // documents of a response). A forged / unsigned / unchained / stale-at-now list cannot be
    // authoritative → Indeterminate. Doing this once (rather than inside the per-document fold) avoids
    // re-running the full signer chain-validation + freshness check per document — an
    // attacker-multipliable soft-DoS on the `documents[]` count when the gate is enabled (finding #8).
    if trust_list
        .authenticate(ctx.qualified_scheme_anchors, ctx.now_unix)
        .is_err()
    {
        return QualifiedStatus::Indeterminate;
    }
    // Resolve one claimed signing cert against the ALREADY-AUTHENTICATED list: the issuer's
    // granted/withdrawn status is READ at the credential's OWN relevant time (NOT "now"). A missing cert
    // OR a missing issuance time fails closed (Indeterminate).
    //
    // `type_indication` is the credential's self-declared **`category`** — the TS 119 615 PRO-4.12.4-03
    // QEAA self-declaration precondition (the URN `urn:etsi:esi:eaa:eu:qualified` must be present before
    // a `Qualified` verdict, else `Indeterminate`). Per ETSI TS 119 472-1 it is the issuer-signed
    // `category` claim (SD-JWT VC) / the `category` data element in namespace `org.etsi.01947201.010101`
    // (mdoc) — NOT the `vct`/`docType`, which is the credential-TYPE identifier and never the qualified
    // URN. `None` (absent/undisclosed category) fails the precondition closed.
    let status_of = |cert: Option<Vec<u8>>,
                     relevant_time: Option<i64>,
                     type_indication: Option<&str>|
     -> QualifiedStatus {
        match (cert, relevant_time) {
            (Some(cert_der), Some(relevant_time_unix)) => {
                crate::qualified::read_status_authenticated(
                    &cert_der,
                    relevant_time_unix,
                    trust_list,
                    type_indication,
                )
            }
            // No signing cert, or no issuance time to read the status at → undecidable, fail closed.
            _ => QualifiedStatus::Indeterminate,
        }
    };
    match presentation {
        Presentation::SdJwtVc(p) => {
            // Parse the presentation ONCE (the `category`/cert/issuance-time reads previously each
            // re-parsed the same string — 3 parses → 1). An unparseable presentation here fails closed
            // (`Indeterminate`), matching the helpers' prior `None`/absent behavior; this arm runs only
            // on a VALID credential, which always parses.
            let Ok(sd_jwt) = sd_jwt_payload::SdJwt::parse(p) else {
                return QualifiedStatus::Indeterminate;
            };
            // The SD-JWT VC issuer-signed `category` claim is the type indication (PRO-4.12.4-03) — NOT
            // the `vct` (the credential-type id). `None` (no category) fails the precondition closed.
            let category = sdjwtvc::issuer_category(&sd_jwt);
            status_of(
                sdjwtvc::issuer_signing_cert_der(&sd_jwt),
                sdjwtvc::issuance_time_unix(&sd_jwt),
                category.as_deref(),
            )
        }
        Presentation::Mdoc { .. } => {
            // Decide over EVERY document's issuer at that document's OWN issuance time; fold so
            // `Qualified` requires all to qualify. The gate runs only on a VALID credential, where the
            // always-on bar already extracted EACH document's `(ds_cert_der, signed)` + its `category`
            // and surfaced them in `mdoc_meta` — fold those CACHED values (the bar's single decode; no
            // second `DeviceResponse` decode). On a VALID mdoc `signed` is mandatory. A `None` meta (no
            // claimed issuers) fails closed — empty fold → `Indeterminate` — never a false "qualified".
            let Some(meta) = mdoc_meta else {
                return QualifiedStatus::Indeterminate;
            };
            fold_qualified(meta.claimed_issuers.iter().map(|(cert, issued, category)| {
                // Read each document's `(leaf, signed, category)` directly from the one tuple the bar
                // paired (no `enumerate` + `.get(index)` realignment across parallel arrays). The mdoc
                // `category` data element (TS 119 472-1 cl. 6.2.2) is the PRO-4.12.4-03 type indication.
                status_of(Some(cert.clone()), Some(*issued), category.as_deref())
            }))
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

/// Resolve a credential's revocation/status outcome, preferring the IN-CORE authenticated Token Status
/// List path over the host-supplied positional outcome (the shared status step for BOTH per-format bars
/// — DRY, Principle III).
///
/// The credential's own [`crate::status::StatusReference`] (parsed in-core from its issuer-signed status
/// claim / MSO element) decides the source:
/// - **`StatusList { index, uri }` with a supplied signed token** — the token is AUTHENTICATED in-core
///   ([`crate::status::verify_status_list_token`]): its signature is verified under a key
///   [`authorize_status_signer`] authorizes against the credential's OWN trust context, `sub` is bound
///   to `uri`, freshness is enforced, and the bit at `index` is read. This outcome OVERRIDES the
///   positional one (the core no longer trusts a host-supplied *outcome* for a token it can check).
/// - **`StatusList` with NO supplied token, or `Crl`, or `None`** — the positional `positional` outcome
///   (host pre-resolved via [`crate::status::check_status`]) is used, exactly as before.
/// - **`Malformed`** (a `status_list` object IS declared but its `idx`/`uri` are unusable) →
///   [`StatusOutcome::Unavailable`], fail-closed: the credential declared a revocation mechanism the
///   core cannot evaluate, so it never falls through to a positional `Good`.
///
/// Fail-closed: a supplied-but-unverifiable token yields [`StatusOutcome::Unavailable`]
/// ([`crate::status::verify_status_list_token`] never returns `Good` on any doubt), which the bars map to
/// [`ReasonCode::StatusUnavailable`] — NEVER a silent fall-back to the positional outcome for a token
/// that was supplied but failed authentication.
pub(crate) fn resolve_status_outcome<A: TrustAnchorSource + ?Sized>(
    reference: &crate::status::StatusReference,
    positional: StatusOutcome,
    status_tokens: &std::collections::BTreeMap<String, Vec<u8>>,
    now_unix: i64,
    trust: &StatusTrust<'_, A>,
    inflate_cache: &mut crate::status::StatusListInflateCache,
) -> StatusOutcome {
    use crate::status::StatusReference;
    match reference {
        StatusReference::StatusList { index, uri } => status_tokens.get(uri).map_or_else(
            // No signed token supplied for THIS declared list. Fall back to the host-pre-resolved
            // positional outcome — EXCEPT `NoStatus`: a credential that declares a status list is never
            // legitimately "no status mechanism", so a positional `NoStatus` here means the declared
            // list was left UNRESOLVED (host fetch failed / not wired). Fail closed to `Unavailable`
            // rather than continue the bar with no revocation check (the core parsed the reference and
            // knows a list is declared — a declared-but-unresolved contradiction must not read as VALID).
            || match positional {
                StatusOutcome::NoStatus => StatusOutcome::Unavailable,
                resolved => resolved,
            },
            // A signed token supplied for THIS list is authenticated in-core (authoritative). The
            // per-URI `inflate_cache` shares only the trust-context-independent zlib inflate across a
            // multi-document response's documents; the authorization + signature + `sub` + freshness are
            // re-checked per document (see [`crate::status::StatusListInflateCache`]).
            |token| {
                crate::status::verify_status_list_token_cached(
                    token,
                    uri,
                    *index,
                    now_unix,
                    |material| authorize_status_signer(material, trust),
                    inflate_cache,
                )
            },
        ),
        // A present-but-malformed status reference (a `status_list` object IS declared but its
        // `idx`/`uri` are unusable) fails closed: the credential declared a revocation mechanism the
        // core cannot evaluate, so it MUST NOT fall through to a host-supplied positional `Good`
        // (a well-formed-but-untokened declared list already fails closed via the `NoStatus` arm above;
        // a malformed one must too — SC-002).
        StatusReference::Malformed => StatusOutcome::Unavailable,
        // CRL is host-resolved; `None` → the host's NoStatus. Positional either way (unchanged).
        StatusReference::Crl { .. } | StatusReference::None => positional,
    }
}

/// The credential's OWN trust context, bundled so it travels to the status-signer authorization as one
/// unit (keeping [`resolve_status_outcome`] under the argument-count bar). It carries exactly what
/// [`authorize_status_signer`] needs to decide whether a Token Status List signer is authorized to sign
/// THIS credential's list: the already-verified issuer leaf (for the same-issuer key-reuse check) and
/// the anchors/role/format the bar anchored the credential against (for the distinct-signer chain check).
pub(crate) struct StatusTrust<'a, A: TrustAnchorSource + ?Sized> {
    /// The credential's already signature- and trust-verified issuer leaf (SD-JWT VC `x5c` leaf / mdoc
    /// DS cert). The same-issuer path resolves the issuer's public KEY from this leaf and authorizes a
    /// status signer whose key equals it (kid-only, or a rolled-over cert) — a KEY match, not a cert-DER
    /// byte match.
    pub issuer_leaf_der: &'a [u8],
    /// The SPECIFIC trust anchor (DER) the credential's issuer chained to: the matched ROOT the path
    /// terminated at (or the pinned cert for a direct pin), carried as
    /// [`crate::trust::TrustListEntry::anchor_cert_der`]. A distinct status signer must chain to THIS
    /// SAME root — not merely any anchor in the `(role, format)` set: in a federated set holding several
    /// issuers' roots, binding only to the set would let a status signer trusted under issuer A's root
    /// sign a list for issuer B's credential (cross-issuer un-revocation). Empty when the issuer's
    /// matched entry carried no anchor (then the distinct-signer path cannot match → fail-closed).
    pub issuer_anchor_der: &'a [u8],
    /// The trust anchors the credential's issuer chained to — a distinct status signer must chain to the
    /// SAME set for `(role, format)`, AND (see [`Self::issuer_anchor_der`]) to the same specific anchor.
    pub anchors: &'a A,
    /// The (reconciled) issuer role the credential anchored under.
    pub role: IssuerRole,
    /// The credential's format.
    pub format: Format,
}

/// The trust-authorization closure for the in-core Token Status List verifier (security-critical): given
/// the token's embedded [`crate::status::SignerKeyMaterial`], decide whether its signer is authorized to
/// sign THIS credential's status list, and if so return the [`VerifyingKey`] to verify the token under.
/// Fail-closed — any doubt is `Err(())`, which folds to [`StatusOutcome::Unavailable`].
///
/// Two authorization paths (a key is NEVER authorized merely because it is embedded in the token —
/// self-authorization would defeat the check):
/// 1. **Same-issuer key reuse (primary path), keyed on the KEY (not the cert DER).** The credential's
///    issuer public key is resolved ONCE from the already-verified issuer leaf (`issuer_leaf_der`). The
///    issuer signs its own status list when EITHER: the token carries **no** chain (empty `x5chain` — a
///    `kid`-only token) — resolved to the issuer key, so the token then verifies iff the issuer's key
///    produced its signature; OR the token's `x5chain` leaf parses to a public key **equal** to the
///    issuer key — the SAME key, possibly a ROLLED-OVER certificate (a different DER at renewal). Either
///    case authorizes the issuer key with no EKU / chain check — it IS the credential's issuer, already
///    signature- and trust-verified by the bar. This replaces the earlier cert-DER byte-equality, which
///    false-rejected both a kid-only token and a routine cert roll-over (same key, new DER).
/// 2. **Distinct status-signer.** Otherwise (the token's leaf key differs from the issuer key) the leaf
///    must BOTH (a) chain to the credential's issuer's SAME SPECIFIC ROOT —
///    [`TrustAnchorSource::resolve_status_signer`] for the same `(role, format)`, WITHOUT the
///    credential-leaf purpose, with the matched-root DER equal to `issuer_anchor_der` — AND (b) bear
///    EXACTLY the status-signing EKU ([`crate::trust::chain::leaf_has_status_signing_eku`], the
///    placeholder id-kp OID). Only then is the key resolved from the (authorized) leaf.
fn authorize_status_signer<A: TrustAnchorSource + ?Sized>(
    material: &crate::status::SignerKeyMaterial,
    trust: &StatusTrust<'_, A>,
) -> Result<p256::ecdsa::VerifyingKey, ()> {
    // Resolve the credential issuer's public key ONCE (the same-issuer paths all authorize THIS key).
    let issuer_key =
        crate::crypto::p256_verifying_key_from_cert_der(trust.issuer_leaf_der).ok_or(())?;

    // (1) Same-issuer key reuse (by KEY, not DER). A token with NO chain (`kid`-only) is authorized to
    // the issuer key — it then verifies ONLY if the issuer's key produced the signature (a bare `kid`
    // grants nothing on its own; the signature is the real gate). This handles kid-only tokens the old
    // `split_first().ok_or(())?` fail-closed rejected outright.
    let Some((leaf, intermediates)) = material.x5chain.split_first() else {
        return Ok(issuer_key);
    };
    // A leaf whose public key EQUALS the issuer key is the same signer — possibly a rolled-over cert
    // (different DER, same key). `p256::ecdsa::VerifyingKey: PartialEq` compares the actual key.
    if crate::crypto::p256_verifying_key_from_cert_der(leaf) == Some(issuer_key) {
        return Ok(issuer_key);
    }

    // (2) Distinct status-signer: (a) chain to the credential's issuer's SAME SPECIFIC ROOT (not just
    // any anchor in the (role, format) set — see `issuer_anchor_der`), structural (no credential-leaf
    // purpose), AND (b) bear the status-signing EKU. Either check failing is fail-closed (`Err`), NEVER a
    // fall-through that would authorize an embedded-but-untrusted key.
    let decision =
        trust
            .anchors
            .resolve_status_signer(trust.role, trust.format, leaf, intermediates);
    // Bind to the issuer's OWN ROOT: the signer must chain to the exact anchor the credential chained to.
    // Both sides are now the matched ROOT (the leaf/root confusion that made this branch dead is fixed).
    // A signer chaining to a DIFFERENT root in the same set (a federated cross-issuer signer) is
    // rejected. An empty `issuer_anchor_der` (issuer entry carried no anchor) matches nothing → Err.
    let same_root = decision
        .entry
        .as_ref()
        .is_some_and(|entry| entry.anchor_cert_der == trust.issuer_anchor_der);
    if !(decision.trusted && same_root) {
        return Err(());
    }
    if !crate::trust::chain::leaf_has_status_signing_eku(leaf) {
        return Err(());
    }
    crate::crypto::p256_verifying_key_from_cert_der(leaf).ok_or(())
}

#[cfg(test)]
mod tests;
