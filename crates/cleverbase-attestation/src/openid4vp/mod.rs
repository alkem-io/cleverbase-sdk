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

use std::collections::{BTreeMap, BTreeSet};

use ciborium::value::Value as CborValue;
use serde::{Deserialize, Serialize};

use crate::mdoc::{self, MdocVerifyMeta, MdocVerifyParams};
use crate::sdjwtvc::{self, KeyBindingChallenge, SdJwtVcInput};
use crate::status::StatusOutcome;
use crate::trust::TrustAnchorSource;
use crate::types::{
    AttributeValue, Format, IssuerRole, ReasonCode, VerificationPolicy, VerificationResult,
};

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

/// A DCQL (Digital Credentials Query Language — OpenID4VP 1.0 §6) query.
///
/// OpenID4VP 1.0 removed Presentation-Exchange `presentation_definition`; the query is **DCQL**. The
/// query is carried on the wire as its canonical JSON text (so the issued request stays reproducible
/// and auditable) AND is now **evaluated in-core** ([`parse`](Self::parse) → [`crate::dcql::DcqlQuery`]):
/// the verifier no longer treats it opaquely — after the always-on bar accepts a presentation it checks
/// the credential SATISFIES the query (correct `vct`/`docType`, requested claims present, values
/// matched) per OpenID4VP 1.0 §"VP Token Validation" step 2.2, closing the "did I get what I requested"
/// gap (conformance-audit T4.1). This was the explicit product decision — full DCQL evaluation in-core,
/// not delegated to the wallet (§"Security Checks on the Returned Credentials and Presentations":
/// *"the Verifier MUST NOT rely on the Wallet to enforce these constraints"*).
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

    /// Parse this query into the structured [`crate::dcql::DcqlQuery`] the in-core evaluator uses
    /// (OpenID4VP 1.0 §6). See [`crate::dcql::DcqlQuery::parse`] for the (lenient) parsing contract.
    ///
    /// # Errors
    ///
    /// [`crate::dcql::DcqlError`] when the query text is not JSON or not a JSON object.
    pub fn parse(&self) -> Result<crate::dcql::DcqlQuery, crate::dcql::DcqlError> {
        crate::dcql::DcqlQuery::parse(&self.query_json)
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MdocVpToken<'a> {
    /// The audience (`client_id`) the response was addressed to.
    pub audience: &'a str,
    /// The CBOR-encoded ISO 18013-5 `DeviceResponse` — borrowed (not owned), so a multi-KB attacker-
    /// sized `DeviceResponse` is never cloned to build the token (the verifier only reads it).
    pub device_response: &'a [u8],
}

/// The presented credential, in the format carried by an OpenID4VP `vp_token`.
///
/// OpenID4VP carries either a compact SD-JWT VC presentation string or an mdoc `DeviceResponse`
/// (wrapped here with its addressed audience — see [`MdocVpToken`]). Detected by the caller; the
/// verifier never guesses (an unrecognized shape would be [`ReasonCode::UnsupportedFormat`] at the
/// [`verify()`](crate::verify()) entry point).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VpToken<'a> {
    /// A compact SD-JWT VC presentation (`<issuer-JWS>…~<KB-JWT>`).
    SdJwtVc(&'a str),
    /// An mdoc `DeviceResponse` plus its addressed audience.
    Mdoc(MdocVpToken<'a>),
}

impl VpToken<'_> {
    /// The credential format this `vp_token` carries.
    #[must_use]
    pub const fn format(&self) -> Format {
        match self {
            Self::SdJwtVc(_) => Format::SdJwtVc,
            Self::Mdoc(_) => Format::Mdoc,
        }
    }
}

/// The claim set a DCQL Claims Query resolves against for a VALID presentation — the FULL set of claims
/// PRESENT in the presentation (OpenID4VP 1.0 §8.6 "VP Token Validation" step 2.2: the query is
/// validated against the "Claims included in the presentation", which §6.4 notes legitimately includes
/// non-selectively-disclosable claims). A claim present in the presentation satisfies the request
/// whether it was selectively disclosed OR carried in the clear.
///
/// - **SD-JWT VC**: `disclosed_attributes` carries only the selectively-DISCLOSED subset, so a clear
///   subject claim would never resolve. The resolution set is the FULL presented claim set — the clear
///   issuer-signed claims MERGED with the disclosed claims ([`sdjwtvc::presented_claims`]).
/// - **mdoc**: the namespace-grouped `disclosed_attributes` is already the full presented set (the
///   `IssuerSignedItems` the holder released), so it is BORROWED as-is (no clone — the DCQL evaluator
///   only reads it).
///
/// Returned as a [`Cow`](std::borrow::Cow) so the mdoc path avoids deep-cloning the whole
/// namespace-grouped map (the SD-JWT VC path owns the freshly-merged clear+disclosed set).
/// Computed only when `result.valid` (the only branch where the DCQL gate runs).
///
/// The SD-JWT VC presentation is passed ALREADY parsed (`Option<&sd_jwt_payload::SdJwt>` — `None` for
/// the mdoc arm, which reads its byproducts from `result`): the caller parses ONCE per token and threads
/// the handle, so the DCQL type/claims reads never re-parse. A `None` handle on the SD-JWT arm (an
/// unparseable presentation) yields the empty set — but this runs only for a VALID presentation, which
/// always parses.
fn dcql_resolution_set<'a>(
    vp_token: &VpToken<'_>,
    sd_jwt: Option<&sd_jwt_payload::SdJwt>,
    result: &'a VerificationResult,
) -> std::borrow::Cow<'a, BTreeMap<String, AttributeValue>> {
    match vp_token {
        VpToken::SdJwtVc(_) => {
            std::borrow::Cow::Owned(sd_jwt.map(sdjwtvc::presented_claims).unwrap_or_default())
        }
        VpToken::Mdoc(_) => std::borrow::Cow::Borrowed(&result.disclosed_attributes),
    }
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
/// [`verify()`](crate::verify()) wrapper). `now_unix`/`role`/`statuses` are the remaining
/// per-format-bar inputs (the validity instant, the trust-anchor role, and the per-document resolved
/// status outcomes — SD-JWT VC reads index 0; an mdoc `DeviceResponse` checks `documents[i]` against
/// `statuses[i]`).
///
/// **Qualified-status gate:** this entry NEVER populates `VerificationResult.qualified_status`,
/// regardless of `policy.qualified_gate`. The opt-in eIDAS qualified gate (TS 119 615 cl. 4.12) runs
/// ONLY via the [`crate::verify::verify()`] entry point, which carries the `qualified_trust_list` +
/// `qualified_scheme_anchors` inputs this function does not receive; `None` here is the honest value.
pub fn verify_response<A: TrustAnchorSource + ?Sized>(
    vp_token: &VpToken<'_>,
    request: &PresentationRequest,
    policy: &VerificationPolicy,
    anchors: &A,
    now_unix: i64,
    role: IssuerRole,
    statuses: &[StatusOutcome],
) -> VerificationResult {
    // This public entry carries no signed Token Status List tokens (its many native/test callers pass
    // only the host-pre-resolved positional `statuses`), so the in-core token seam is empty here — the
    // positional outcome is authoritative, exactly as before. The C-ABI `verify()` request-bound path
    // reaches [`verify_response_with_meta`] directly with `ctx.status_tokens` for the in-core path.
    verify_response_with_meta(
        vp_token,
        request,
        policy,
        anchors,
        now_unix,
        role,
        StatusInputs {
            positional: statuses,
            tokens: &crate::status::DEFAULT_STATUS_TOKENS,
        },
    )
    .0
}

/// The per-bar revocation/status inputs threaded through the OpenID4VP bound bar as one unit (keeping
/// the bound-bar functions under the argument-count bar): the host-pre-resolved **positional** outcomes
/// (one per presented document — [`crate::status::check_status`]) AND the host-fetched signed Token
/// Status List **tokens** (uri → raw token bytes) that drive the in-core authenticated path. `pub(crate)`
/// so the [`crate::verify`] entry point can build it from its `VerifyContext`.
#[derive(Clone, Copy)]
pub(crate) struct StatusInputs<'a> {
    /// The host-pre-resolved per-document positional outcomes (the fallback when no signed token covers
    /// a credential's list URI, or for a CRL / no reference).
    pub positional: &'a [StatusOutcome],
    /// The host-fetched signed Token Status List tokens, keyed by list URI → raw token bytes.
    pub tokens: &'a BTreeMap<String, Vec<u8>>,
}

/// Verify an OpenID4VP `vp_token` exactly as [`verify_response`] AND surface the mdoc
/// [`MdocVerifyMeta`] the bar pass produced (when the token is an mdoc), so the [`crate::verify`]
/// entry point feeds the opt-in qualified gate from those cached per-document `(cert, issuance_time)`
/// pairs instead of re-decoding the `DeviceResponse`. The [`VerificationResult`] is byte-identical to
/// [`verify_response`]'s (that public entry delegates here and drops the meta); an SD-JWT VC token has
/// no mdoc meta (`None`).
pub(crate) fn verify_response_with_meta<A: TrustAnchorSource + ?Sized>(
    vp_token: &VpToken<'_>,
    request: &PresentationRequest,
    policy: &VerificationPolicy,
    anchors: &A,
    now_unix: i64,
    role: IssuerRole,
    status: StatusInputs<'_>,
) -> (VerificationResult, Option<MdocVerifyMeta>) {
    // Format gate (identical to the `verify()` entry point's, so the public `verify_response` honors
    // the `policy` it takes): the policy may restrict accepted formats (an empty set = both). A
    // presented format the policy excludes is rejected up front — never run through the bar.
    let format = vp_token.format();
    if !policy.formats.is_empty() && !policy.formats.contains(&format) {
        return (
            VerificationResult::invalid(ReasonCode::UnsupportedFormat),
            None,
        );
    }

    // Parse the SD-JWT VC presentation ONCE for the whole SD-JWT path — the binding attribution
    // (`kb_jwt_aud_nonce`) AND the post-bar DCQL type/claims reads (`verified_vct`/`presented_claims`)
    // all share this single handle, so the redundant per-helper re-parses are gone (the always-on bar
    // still parses once more internally — the separate request-agnostic bar entry). The mdoc arm carries
    // no SD-JWT (`None`); an unparseable SD-JWT (`None`) fails closed downstream (`MissingRequestBinding`
    // in the bound bar, empty type/claims reads).
    let sd_jwt = match vp_token {
        VpToken::SdJwtVc(presentation) => sd_jwt_payload::SdJwt::parse(presentation).ok(),
        VpToken::Mdoc(_) => None,
    };

    // Run the per-format always-on bar + request binding.
    let (mut result, meta) = match vp_token {
        VpToken::SdJwtVc(presentation) => {
            let result = verify_sd_jwt_vc_bound(
                presentation,
                sd_jwt.as_ref(),
                request,
                anchors,
                now_unix,
                role,
                status,
            );
            (result, None)
        }
        VpToken::Mdoc(token) => {
            let (result, meta) = verify_mdoc_bound(token, request, anchors, now_unix, role, status);
            (result, Some(meta))
        }
    };
    // Surface the verified credential type the DCQL gate keys on (SD-JWT VC `vct`; mdoc `docType`s)
    // from what the bar already produced — via the single [`credential_type_of`] helper (DRY; no inline
    // copy that could drift from the multi-credential caller's).
    let credential_type = credential_type_of(vp_token, sd_jwt.as_ref(), &result, meta.as_ref());

    // DCQL "did I get what I requested" gate (OpenID4VP 1.0 §"VP Token Validation" step 2.2 + §6 DCQL).
    // Runs ONLY on a presentation the always-on bar already accepted, and ONLY when the request carries
    // an enforceable DCQL query (an empty/legacy/opaque query is `Inactive` — the prior behavior). A
    // sound, trusted, request-bound credential that does NOT satisfy the query (wrong `vct`/`docType`,
    // missing requested claim, or value mismatch) is rejected as `QueryNotSatisfied` (the credential is
    // sound but is not the one requested — distinct from `Tamper`/`UntrustedIssuer`/`HolderBinding`).
    if result.valid {
        // Resolve the DCQL claims against the FULL presented claim set (§8.6 step 2.2): for SD-JWT VC
        // that is the clear issuer-signed claims merged with the disclosed claims — a clear subject claim
        // must resolve, not only a selectively-disclosed one (see [`dcql_resolution_set`]).
        let presented = dcql_resolution_set(vp_token, sd_jwt.as_ref(), &result);
        if crate::dcql::evaluate_single(
            &request.dcql.query_json,
            format,
            &credential_type,
            &presented,
        ) == crate::dcql::DcqlGate::NotSatisfied
        {
            result = VerificationResult::invalid(ReasonCode::QueryNotSatisfied);
        }
    }
    // This path ran the OpenID4VP request binding (nonce/audience + KB-JWT freshness for SD-JWT VC, the
    // handover transcript for mdoc), so the result IS request-bound — the observable signal that lets a
    // caller confirm a request was actually applied (vs the request-less bare path, which leaves it
    // `false`). Stamped on any outcome of this fn (VALID or a binding/query INVALID).
    result.request_bound = true;
    (result, meta)
}

/// SD-JWT VC binding: attribute a nonce/audience mismatch precisely (from the KB-JWT), then run the
/// full always-on bar with the request as the holder-binding challenge.
///
/// `sd_jwt` is the presentation parsed ONCE by the caller ([`verify_response_with_meta`]) — `None` when
/// the presentation did not parse, which carries no KB-JWT `aud`/`nonce` to bind → `MissingRequestBinding`
/// (identical to the prior `kb_jwt_aud_nonce` returning `None` on an unparseable presentation). The
/// original `presentation` string is still passed for the always-on bar's own input (it parses once more
/// internally — the request-agnostic bar entry).
fn verify_sd_jwt_vc_bound<A: TrustAnchorSource + ?Sized>(
    presentation: &str,
    sd_jwt: Option<&sd_jwt_payload::SdJwt>,
    request: &PresentationRequest,
    anchors: &A,
    now_unix: i64,
    role: IssuerRole,
    status: StatusInputs<'_>,
) -> VerificationResult {
    let expected_nonce = request.nonce_b64();

    // Read the KB-JWT's claimed aud/nonce for precise failure attribution. A presentation with no
    // KB-JWT (or one that did not parse → `sd_jwt` is `None`) carries no `aud`/`nonce` to bind to a
    // request → MissingRequestBinding. This is `MissingRequestBinding` condition (3) — the
    // SD-JWT-VC-no-KB-JWT case (see the `ReasonCode` rustdoc; one of three distinct "binding material
    // absent" conditions the code intentionally covers — distinct from a present-but-mismatched
    // binding, which is `WrongAudience`/`Replay`).
    let Some((aud, nonce)) = sd_jwt.and_then(sdjwtvc::kb_jwt_aud_nonce) else {
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
        // SD-JWT VC is a single credential — its one positional outcome is `positional[0]` (fail closed
        // on an empty slice); the signed-token map drives the in-core path when it covers the list URI.
        status: status
            .positional
            .first()
            .copied()
            .unwrap_or(StatusOutcome::Unavailable),
        status_tokens: status.tokens,
    };
    sdjwtvc::verify_sd_jwt_vc(&input)
}

/// mdoc binding: compare the addressed audience (→ `WrongAudience`), then run the always-on bar
/// against the handover transcript reconstructed from the request (a nonce mismatch → `Replay`).
/// Returns the [`MdocVerifyMeta`] the bar pass produced so the caller can feed the qualified gate the
/// cached per-document `(cert, issuance_time)` instead of re-decoding the response.
fn verify_mdoc_bound<A: TrustAnchorSource + ?Sized>(
    token: &MdocVpToken,
    request: &PresentationRequest,
    anchors: &A,
    now_unix: i64,
    role: IssuerRole,
    status: StatusInputs<'_>,
) -> (VerificationResult, MdocVerifyMeta) {
    if token.audience != request.audience.as_str() {
        return (
            VerificationResult::invalid(ReasonCode::WrongAudience),
            MdocVerifyMeta::default(),
        );
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
        // Per-document positional statuses (documents[i] against statuses[i]); a document with no
        // covering entry fails closed (`Unavailable`) — one outcome is never reused across documents.
        statuses: status.positional,
        status_tokens: status.tokens,
    };
    // Run the bar ONCE and read the byproducts it already computed (document count + binding-machinery
    // soundness) from the returned meta — no second `DeviceResponse` decode for the replay classifier.
    let (result, meta) = mdoc::verify_with_meta(token.device_response, anchors, &params);
    // A holder-binding failure here is AMBIGUOUS: it can be the fresh-nonce mismatch we want to
    // surface as Replay (the verifier rebuilt `DeviceAuthentication` over a different transcript than
    // the holder signed — the audience already matched in cleartext above), OR a genuine
    // DeviceKey/DeviceSignature fault (a corrupt/garbled signature, non-ES256 alg, unparseable
    // DeviceKey, DeviceMac-only DeviceAuth, or a WRONG-KEY DeviceSignature). Blindly re-attributing
    // every `HolderBinding` to `Replay` would MASK those real faults.
    //
    // The Replay re-attribution is only SOUND for a SINGLE-document response. There the only
    // transcript-dependent variable is the request nonce (the audience already matched in cleartext),
    // and the binding machinery is the cheap structural discriminator: a fresh-nonce mismatch fails
    // ONLY the signature-over-transcript check while leaving the machinery intact (ES256
    // DeviceSignature + parseable DeviceKey + well-formed signature bytes), whereas a corrupt/garbled
    // signature, a non-ES256 alg, or an unparseable DeviceKey breaks the machinery itself.
    //
    // RESIDUAL (documented): the machinery classifier verifies NO payload, so a WRONG-KEY but
    // well-formed ES256 DeviceSignature classifies as `Sound` — structurally indistinguishable from a
    // stale-nonce one. In a single-document response that residual is acceptable: a wrong-key signature
    // and a fresh-nonce mismatch are both "this presentation is not the one we requested", and Replay is
    // a reasonable single-document attribution. But in a MULTI-document response a real wrong-key fault
    // on `documents[1]` must NOT be laundered into `Replay` (it would mis-report a genuine holder-
    // binding fault as a freshness replay). So restrict the Replay re-attribution to `documents.len()
    // == 1`; for more than one document KEEP `HolderBinding`. (On a `HolderBinding` failure the bar
    // decoded a non-empty `documents`, so `meta.document_count` is the read count and
    // `meta.binding_machinery` is `Some(..)` — both cached from that decode.)
    if !result.valid && result.reasons == [ReasonCode::HolderBinding] {
        let single_document = meta.document_count == 1;
        if single_document && meta.binding_machinery == Some(mdoc::DeviceBindingMachinery::Sound) {
            // Single document + sound machinery + a binding failure ⇒ the rebuilt transcript (fresh
            // nonce) is the only thing that can differ ⇒ a replay.
            return (VerificationResult::invalid(ReasonCode::Replay), meta);
        }
        // Multi-document or a structurally-broken binding ⇒ a genuine holder-binding fault, never
        // laundered into `Replay`.
        return (result, meta);
    }
    (result, meta)
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
    let handover_info_bytes = crate::cbor_to_vec(&handover_info);
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
    crate::cbor_to_vec(&transcript)
}

/// The per-credential outcome within a [`verify_vp_token`] evaluation.
///
/// `presentations` carries the [`VerificationResult`] of EACH Presentation returned under this
/// Credential Query `id` (in input order); `satisfied` is whether this Credential Query is fulfilled —
/// at least one returned Presentation both verified (always-on bar + binding) AND matched this query
/// (format + `meta` + claims), honoring the `multiple` cardinality (a `multiple:false` query MUST carry
/// at most one Presentation — OpenID4VP 1.0 §"Response Parameters").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialVerification {
    /// The verification result of each Presentation returned under this Credential Query `id`.
    pub presentations: Vec<VerificationResult>,
    /// Whether this Credential Query is satisfied (≥1 verified-and-matching Presentation; cardinality
    /// respected).
    pub satisfied: bool,
}

/// The outcome of evaluating a whole OpenID4VP `vp_token` against its DCQL query (OpenID4VP 1.0 §"VP
/// Token Validation" steps 2 + 3): the per-credential results plus the set-level verdict.
///
/// `satisfied` is the overall set-level decision (§"VP Token Validation" step 3 + §"Selecting
/// Credentials"): with no `credential_sets`, EVERY Credential Query in `credentials` must be satisfied;
/// otherwise EVERY **required** Credential Set Query must have at least one fully-satisfied `option`
/// (non-required sets are optional).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpTokenVerification {
    /// Whether the returned set of Presentations satisfies the request's set-level requirements.
    pub satisfied: bool,
    /// The per-credential outcomes, keyed by the Credential Query `id` the Presentations were returned
    /// under.
    pub credentials: BTreeMap<String, CredentialVerification>,
}

/// Evaluate a full OpenID4VP `vp_token` (the `{ credential_id: [presentations] }` shape — OpenID4VP 1.0
/// §"Response Parameters") against the DCQL query carried in `request`, enforcing the complete
/// §"VP Token Validation" + §6 DCQL semantics **in-core** (the explicit product decision — not delegated
/// to the wallet, §"Security Checks on the Returned Credentials and Presentations").
///
/// For EACH `(credential_id, presentations)` entry it runs, per Presentation, the always-on bar + the
/// request binding ([`verify_response`]) AND the per-query DCQL match (format + `meta` + claims/values),
/// then folds the per-credential satisfaction into the set-level verdict (the [`crate::dcql`] set fold):
/// step 3 — every required Credential Set Query has a fully-satisfied option (or, with no
/// `credential_sets`, every Credential Query is satisfied).
///
/// The per-credential trust-anchoring **role** is derived from the matching Credential Query's expected
/// type (`meta`) when it names a EUDI PID type (conformance-audit T4.3 — the verifier's own query states
/// the type it expects), falling back to the supplied `role` otherwise; the per-format bar then
/// validates the credential's ACTUAL claimed type against that role (rejecting a contradiction as
/// [`ReasonCode::RoleMismatch`]). `now_unix` is the shared per-bar instant. `statuses` carries the
/// host-resolved revocation outcomes keyed by credential id → per **token** (presentation) → per
/// **document** (positional), so EACH credential and EACH document is checked against its OWN outcome —
/// one outcome is never silently reused across credentials or documents (SC-002). A credential id /
/// token / document with no supplied outcome fails closed to [`StatusOutcome::Unavailable`].
///
/// This is the ONLY entry that enforces the **set-level** DCQL semantics (`credential_sets` required
/// option-sets + `multiple` cardinality); the single-presentation [`verify_response`] / the C-ABI
/// `verify()` surface enforce only the per-presentation single-query match. It is native-Rust-only (no
/// C-ABI wire shape carries the multi-credential `{credential_id: [presentations]}` map). Like
/// [`verify_response`], it NEVER populates `qualified_status` — the opt-in qualified gate runs only via
/// [`crate::verify::verify()`].
pub fn verify_vp_token<A: TrustAnchorSource + ?Sized>(
    request: &PresentationRequest,
    vp_token: &BTreeMap<String, Vec<VpToken<'_>>>,
    policy: &VerificationPolicy,
    anchors: &A,
    now_unix: i64,
    role: IssuerRole,
    statuses: &BTreeMap<String, Vec<Vec<StatusOutcome>>>,
) -> VpTokenVerification {
    // Parse the DCQL once. An unparseable query has no enforceable structure → nothing is satisfied
    // (the explicit multi-credential entry needs a real query; the single-presentation gate is the
    // lenient/backward-compatible path).
    let query = request.dcql.parse().unwrap_or_default();
    let by_id: BTreeMap<&str, &crate::dcql::CredentialQuery> = query
        .credentials
        .iter()
        .map(|candidate| (candidate.id.as_str(), candidate))
        .collect();

    let mut credentials = BTreeMap::new();
    let mut satisfied_ids: BTreeSet<String> = BTreeSet::new();
    for (credential_id, tokens) in vp_token {
        let credential_query = by_id.get(credential_id.as_str()).copied();
        // Per-credential anchoring role derived from the query's EXPECTED type (PID), else the caller's.
        let credential_role = credential_query
            .and_then(|candidate| crate::dcql::role_from_meta(&candidate.meta))
            .unwrap_or(role);
        // `multiple:false` (default) ⇒ at most one Presentation per Credential Query (§"Response
        // Parameters": "When `multiple` is omitted, or set to `false`, the array MUST contain only one
        // Presentation.").
        let multiple_allowed = credential_query.is_some_and(|candidate| candidate.multiple);
        let cardinality_ok = multiple_allowed || tokens.len() <= 1;

        // This credential's per-token status outcomes (each token is one Presentation, itself possibly a
        // multi-document mdoc `DeviceResponse` ⇒ a positional per-document slice). A credential_id / token
        // the host supplied no statuses for yields an empty slice ⇒ each document fails closed to
        // `Unavailable` (never a single outcome silently reused across credentials/documents — SC-002).
        let credential_statuses = statuses.get(credential_id);
        let mut presentations = Vec::with_capacity(tokens.len());
        let mut matched = 0usize;
        for (token_index, token) in tokens.iter().enumerate() {
            let token_statuses: &[StatusOutcome] = credential_statuses
                .and_then(|per_token| per_token.get(token_index))
                .map_or(&[], Vec::as_slice);
            let (result, meta) = verify_response_with_meta(
                token,
                request,
                policy,
                anchors,
                now_unix,
                credential_role,
                // The native multi-credential entry carries only host-pre-resolved positional statuses
                // (no per-credential signed-token map on this surface); the in-core token seam is empty
                // here, so the positional outcome stays authoritative — unchanged behavior.
                StatusInputs {
                    positional: token_statuses,
                    tokens: &crate::status::DEFAULT_STATUS_TOKENS,
                },
            );
            // The Presentation counts toward THIS Credential Query only if it both verified AND matches
            // this specific query (by id) — format + `meta` + claims/`claim_sets`/`values`.
            let matches_query = result.valid
                && credential_query.is_some_and(|candidate| {
                    // Parse the SD-JWT presentation ONCE for this token's DCQL type/claims reads (the
                    // mdoc arm is `None`) — reached only when the always-on bar already accepted it and
                    // a matching Credential Query exists, so no wasted parse on rejected/unqueried tokens.
                    let token_sd_jwt = match token {
                        VpToken::SdJwtVc(presentation) => {
                            sd_jwt_payload::SdJwt::parse(presentation).ok()
                        }
                        VpToken::Mdoc(_) => None,
                    };
                    let credential_type =
                        credential_type_of(token, token_sd_jwt.as_ref(), &result, meta.as_ref());
                    // Resolve claims against the FULL presented claim set (§8.6 step 2.2 — clear +
                    // disclosed for SD-JWT VC); see [`dcql_resolution_set`].
                    let presented = dcql_resolution_set(token, token_sd_jwt.as_ref(), &result);
                    crate::dcql::query_satisfied_by(
                        candidate,
                        token.format(),
                        &credential_type,
                        &presented,
                    )
                });
            if matches_query {
                matched += 1;
            }
            presentations.push(result);
        }

        let satisfied = credential_query.is_some() && cardinality_ok && matched >= 1;
        if satisfied {
            satisfied_ids.insert(credential_id.clone());
        }
        credentials.insert(
            credential_id.clone(),
            CredentialVerification {
                presentations,
                satisfied,
            },
        );
    }

    let satisfied_refs: BTreeSet<&str> = satisfied_ids.iter().map(String::as_str).collect();
    let satisfied = crate::dcql::credential_sets_satisfied(&query, &satisfied_refs);
    VpTokenVerification {
        satisfied,
        credentials,
    }
}

/// The verified credential type the DCQL `meta` match keys on, read from what the always-on bar already
/// produced: the SD-JWT VC `vct` (re-read from the now-verified presentation) or the mdoc `docType`s
/// (from the bar's [`MdocVerifyMeta`]). Empty/`None` on an INVALID presentation (nothing verified).
///
/// The SD-JWT VC presentation is passed ALREADY parsed (`Option<&sd_jwt_payload::SdJwt>` — `None` for the
/// mdoc arm, which reads `doc_types` from `meta`): the caller parses ONCE per token and threads the
/// handle, so the `vct` re-read never re-parses.
fn credential_type_of(
    token: &VpToken<'_>,
    sd_jwt: Option<&sd_jwt_payload::SdJwt>,
    result: &VerificationResult,
    meta: Option<&MdocVerifyMeta>,
) -> crate::dcql::CredentialType {
    match token {
        VpToken::SdJwtVc(_) => crate::dcql::CredentialType::Vct(
            result
                .valid
                .then(|| sd_jwt.and_then(sdjwtvc::verified_vct))
                .flatten(),
        ),
        VpToken::Mdoc(_) => crate::dcql::CredentialType::DocTypes(
            meta.map(|meta| meta.doc_types.clone()).unwrap_or_default(),
        ),
    }
}

#[cfg(test)]
mod tests;
